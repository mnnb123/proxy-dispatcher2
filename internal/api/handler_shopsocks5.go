package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"proxy-dispatcher/internal/config"
	"proxy-dispatcher/internal/shopsocks5"
)

// ShopSocks5 integration for session groups: socks are taken from the
// provider's plan and placed straight into a history-enabled group, with
// the exit IP the provider reports stored as the proxy's public IP so it
// can be searched and re-attached later.

// ssFetchMu serialises fetches: two overlapping requests could otherwise
// both pass the capacity check and pay for socks that do not fit.
var ssFetchMu sync.Mutex

// GET /api/config/shopsocks5 — never returns the token.
func (s *Server) handleGetShopSocks5(w http.ResponseWriter, r *http.Request) {
	c := s.cfg.ShopSocks5
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"user_name": c.UserName,
		"token_set": c.APIToken != "",
	})
}

// POST /api/config/shopsocks5  {"user_name": "...", "api_token": "..."}
// An empty api_token keeps the stored one.
func (s *Server) handlePostShopSocks5(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserName string `json:"user_name"`
		APIToken string `json:"api_token"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	prev := s.cfg.ShopSocks5
	next := prev
	next.UserName = strings.TrimSpace(req.UserName)
	if t := strings.TrimSpace(req.APIToken); t != "" {
		next.APIToken = t
	}
	if next.UserName == "" {
		next.APIToken = ""
	}
	s.cfg.ShopSocks5 = next
	if err := config.SaveConfig(s.cfgPath, s.cfg); err != nil {
		s.cfg.ShopSocks5 = prev
		respondError(w, http.StatusInternalServerError, "save failed")
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "token_set": next.APIToken != ""})
}

// ssClient builds a client from the stored account. Takes the read lock:
// only for routes that cfgLockFor leaves unlocked.
func (s *Server) ssClient() (*shopsocks5.Client, error) {
	s.cfgMu.RLock()
	c := s.cfg.ShopSocks5
	s.cfgMu.RUnlock()
	if c.UserName == "" || c.APIToken == "" {
		return nil, fmt.Errorf("chua nhap tai khoan ShopSocks5 (user_name va api_token)")
	}
	return shopsocks5.New(c.BaseURL, c.UserName, c.APIToken), nil
}

// GET /api/config/shopsocks5/account — plan and remaining quota (free call).
func (s *Server) handleShopSocks5Account(w http.ResponseWriter, r *http.Request) {
	cl, err := s.ssClient()
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	acc, err := cl.Account(ctx)
	if err != nil {
		respondError(w, http.StatusBadGateway, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, acc)
}

type ssFetchReq struct {
	Qty      int    `json:"qty"`
	Mode     string `json:"mode"` // "append" (default), "replace" or "port"
	Port     int    `json:"output_port"`
	Country  string `json:"country"`
	State    string `json:"state"`
	City     string `json:"city"`
	SockType string `json:"sock_type"`
	Level    string `json:"level"`
	IPReal   string `json:"ip_real"`
	// Unique drops socks whose public IP the group already had (live or in
	// history) and asks the provider again for the shortfall.
	Unique bool `json:"unique"`
}

// ssUniqueRounds caps provider calls per request when duplicates are being
// replaced: every returned sock costs quota, duplicate or not.
const ssUniqueRounds = 3

// knownIPs returns every public IP the group has now or has in history.
// Caller holds the config lock (read or write).
func (s *Server) knownIPs(group string) map[string]bool {
	known := make(map[string]bool)
	if idx := s.findGroup(group); idx >= 0 {
		for _, p := range s.cfg.ProxyGroups[idx].Proxies {
			if p.ExternalIP != "" {
				known[p.ExternalIP] = true
			}
		}
	}
	for _, sn := range s.loadHistory(group).Snapshots {
		for _, p := range sn.Proxies {
			if p.ExternalIP != "" {
				known[p.ExternalIP] = true
			}
		}
	}
	return known
}

// fetchUniqueSocks asks the provider for qty socks. With known == nil it is
// a single call. Otherwise socks whose ip_real is in known (or repeated
// within the answer) are dropped and the shortfall is requested again, up
// to ssUniqueRounds calls. spent counts every sock the provider returned.
func fetchUniqueSocks(ctx context.Context, cl *shopsocks5.Client, qty int, filters map[string]string, known map[string]bool) (out []shopsocks5.Sock, spent, dups int, err error) {
	for round := 0; round < ssUniqueRounds && len(out) < qty; round++ {
		socks, e := cl.GetSocks(ctx, qty-len(out), filters)
		if e != nil {
			if spent == 0 {
				return nil, 0, 0, e
			}
			break
		}
		if len(socks) == 0 {
			break
		}
		spent += len(socks)
		for _, sk := range socks {
			if known != nil && sk.IPReal != "" {
				if known[sk.IPReal] {
					dups++
					continue
				}
				known[sk.IPReal] = true
			}
			out = append(out, sk)
		}
		if known == nil {
			break
		}
	}
	return out, spent, dups, nil
}

var ssSockTypes = map[string]bool{"": true, "residential": true, "business": true, "cellular": true, "hosting": true}

func (q *ssFetchReq) normalize() error {
	q.Country = strings.ToUpper(strings.TrimSpace(q.Country))
	q.State = strings.TrimSpace(q.State)
	q.City = strings.TrimSpace(q.City)
	q.SockType = strings.ToLower(strings.TrimSpace(q.SockType))
	q.Level = strings.TrimSpace(q.Level)
	q.IPReal = strings.TrimSpace(q.IPReal)
	if q.Mode == "" {
		q.Mode = "append"
	}
	if q.Mode != "append" && q.Mode != "replace" && q.Mode != "port" {
		return fmt.Errorf("mode must be append, replace or port")
	}
	if q.Mode == "port" || q.IPReal != "" {
		q.Qty = 1
	}
	if q.Qty < 1 || q.Qty > 500 {
		return fmt.Errorf("qty must be 1-500")
	}
	if q.Country != "" && len(q.Country) != 2 {
		return fmt.Errorf("country must be a 2-letter code, e.g. US")
	}
	if !ssSockTypes[q.SockType] {
		return fmt.Errorf("sock_type must be residential, business, cellular or hosting")
	}
	if q.Level != "" {
		if n, err := strconv.Atoi(q.Level); err != nil || n < 1 || n > 4 {
			return fmt.Errorf("level must be 1-4")
		}
	}
	if q.IPReal != "" && net.ParseIP(q.IPReal) == nil {
		return fmt.Errorf("ip_real is not a valid IP")
	}
	if len(q.State) > 80 || len(q.City) > 80 {
		return fmt.Errorf("state/city too long")
	}
	return nil
}

// ssRoom checks, before any quota is spent, that the request fits the
// group. Caller holds the config lock (read or write).
func (s *Server) ssRoom(name string, q *ssFetchReq) error {
	idx := s.findGroup(name)
	if idx < 0 {
		return fmt.Errorf("group not found")
	}
	g := s.cfg.ProxyGroups[idx]
	if !g.KeepHistory {
		return fmt.Errorf("list history is not enabled for this group")
	}
	m, mapped := s.groupMapping(name)
	if !mapped {
		return fmt.Errorf("group has no port range")
	}
	capacity := m.PortEnd - m.PortStart + 1
	switch q.Mode {
	case "replace":
		if q.Qty > capacity {
			return fmt.Errorf("nhom chi co %d port, khong du cho %d sock", capacity, q.Qty)
		}
	case "append":
		if free := capacity - len(g.Proxies); q.Qty > free {
			return fmt.Errorf("nhom chi con %d port trong, khong du cho %d sock", free, q.Qty)
		}
	case "port":
		if q.Port < m.PortStart || q.Port > m.PortEnd {
			return fmt.Errorf("port must be within the group's range %d-%d", m.PortStart, m.PortEnd)
		}
	}
	return nil
}

func socksToEntries(socks []shopsocks5.Sock) []config.ProxyEntry {
	out := make([]config.ProxyEntry, 0, len(socks))
	for _, sk := range socks {
		host, portStr, err := net.SplitHostPort(sk.SockIP)
		port, perr := strconv.Atoi(portStr)
		if err != nil || perr != nil || host == "" || port < 1 || port > 65535 {
			continue
		}
		out = append(out, config.ProxyEntry{
			Host: host, Port: port, User: sk.User, Pass: sk.Pass, Type: "socks5",
			Status: "unknown", ExternalIP: sk.IPReal, Country: sk.Country, IPv4Only: true,
		})
	}
	return out
}

// placeAtPort binds one proxy to one output port of group idx. Only that
// port changes: the proxy currently there (if any) is archived as a
// one-row "swap" snapshot. Caller holds the config write lock.
func (s *Server) placeAtPort(idx int, entry config.ProxyEntry, outputPort int) (replaced string, status int, err error) {
	g := s.cfg.ProxyGroups[idx]
	m, mapped := s.groupMapping(g.Name)
	if !mapped {
		return "", http.StatusBadRequest, fmt.Errorf("group has no port range")
	}
	if outputPort < m.PortStart || outputPort > m.PortEnd {
		return "", http.StatusBadRequest, fmt.Errorf("port must be within the group's range %d-%d", m.PortStart, m.PortEnd)
	}
	pos := outputPort - m.PortStart
	proxies := make([]config.ProxyEntry, len(g.Proxies), max(len(g.Proxies), pos+1))
	copy(proxies, g.Proxies)
	// Ports between the end of the list and the target stay unassigned.
	for len(proxies) <= pos {
		proxies = append(proxies, config.ProxyEntry{Type: "socks5", Status: "empty"})
	}
	if old := proxies[pos]; !old.IsEmpty() {
		replaced = fmt.Sprintf("%s:%d", old.Host, old.Port)
		if err := s.pushHistory(g.Name, "swap", s.snapshotProxies(g.Name, []config.ProxyEntry{old}, pos)); err != nil {
			return "", http.StatusInternalServerError, fmt.Errorf("could not archive the replaced proxy: %w", err)
		}
	}
	proxies[pos] = entry
	if err := s.setGroupProxies(idx, proxies); err != nil {
		return "", http.StatusInternalServerError, err
	}
	s.probeAsync(g.Name, pos, 1)
	return replaced, http.StatusOK, nil
}

// probeAsync health-checks n proxies of a group starting at index from, in
// the background, so freshly placed proxies do not sit at "unknown" until
// the next periodic check (which may be disabled).
func (s *Server) probeAsync(group string, from, n int) {
	if s.healthChecker == nil || s.groupMgr == nil {
		return
	}
	go func() {
		ptrs := s.groupMgr.GroupProxies()[group]
		if from >= len(ptrs) {
			return
		}
		s.healthChecker.CheckProxiesPriority(ptrs[from:min(from+n, len(ptrs))])
	}()
}

// setGroupProxies installs a new list for group idx and applies it; on
// failure the previous list stays. Caller holds the config write lock.
func (s *Server) setGroupProxies(idx int, proxies []config.ProxyEntry) error {
	for len(proxies) > 0 && proxies[len(proxies)-1].IsEmpty() {
		proxies = proxies[:len(proxies)-1]
	}
	prev := s.cfg.ProxyGroups
	groups := make([]config.ProxyGroup, len(prev))
	copy(groups, prev)
	g := groups[idx]
	g.Proxies = proxies
	groups[idx] = g
	s.cfg.ProxyGroups = groups
	if err := s.applyGroupChange(); err != nil {
		s.cfg.ProxyGroups = prev
		return err
	}
	return nil
}

// POST /api/groups/{name}/shopsocks5
// Takes socks from the plan and puts them into the session group. Runs
// without the config lock while talking to the provider.
func (s *Server) handleShopSocks5Fetch(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var q ssFetchReq
	if err := decodeJSON(r, &q); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	if err := q.normalize(); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	cl, err := s.ssClient()
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	ssFetchMu.Lock()
	defer ssFetchMu.Unlock()

	s.cfgMu.RLock()
	err = s.ssRoom(name, &q)
	s.cfgMu.RUnlock()
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 150*time.Second)
	defer cancel()
	// Asking for one specific IP back skips both duplicate filters.
	var known map[string]bool
	if q.IPReal == "" {
		if known, err = s.ssKnown(ctx, name, q.Unique); err != nil {
			respondError(w, http.StatusBadGateway, err.Error())
			return
		}
	}
	socks, spent, dups, err := fetchUniqueSocks(ctx, cl, q.Qty, map[string]string{
		"country": q.Country, "state": q.State, "city": q.City,
		"sock_type": q.SockType, "level": q.Level, "ip_real": q.IPReal,
	}, known)
	if err != nil {
		respondError(w, http.StatusBadGateway, err.Error())
		return
	}
	entries := socksToEntries(socks)
	if len(entries) == 0 {
		if dups > 0 {
			respondError(w, http.StatusBadGateway, fmt.Sprintf("ShopSocks5 chi tra ve IP trung (nhom da tung co hoac nam trong danh sach loai tru): %d sock, da tru %d luot. Thu doi bo loc vi tri.", dups, spent))
			return
		}
		respondError(w, http.StatusBadGateway, "ShopSocks5 khong tra ve sock nao phu hop bo loc")
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	// The socks are paid for from here on. If they can no longer be placed
	// (group changed meanwhile, save failed), keep them in history so they
	// can still be attached by hand.
	stash := func(cause error) {
		msg := cause.Error()
		if idx := s.findGroup(name); idx >= 0 && s.cfg.ProxyGroups[idx].KeepHistory {
			rows := make([]histProxy, len(entries))
			for i, p := range entries {
				rows[i] = histProxy{Host: p.Host, Port: p.Port, User: p.User, Pass: p.Pass, Type: p.Type, ExternalIP: p.ExternalIP, Country: p.Country, IPv4Only: p.IPv4Only}
			}
			if s.pushHistory(name, "fetched", rows) == nil {
				msg += fmt.Sprintf(" — %d sock da lay duoc luu vao lich su, co the gan lai tu do", len(rows))
			}
		}
		respondError(w, http.StatusConflict, msg)
	}

	requested := q.Qty
	q.Qty = len(entries)
	if err := s.ssRoom(name, &q); err != nil {
		stash(err)
		return
	}
	idx := s.findGroup(name)
	g := s.cfg.ProxyGroups[idx]
	m, _ := s.groupMapping(name)
	firstPort := m.PortStart
	switch q.Mode {
	case "replace":
		if err = s.replaceGroupProxies(idx, entries, "replace"); err == nil {
			s.probeAsync(name, 0, len(entries))
		}
	case "port":
		firstPort = q.Port
		_, _, err = s.placeAtPort(idx, entries[0], q.Port)
	default:
		firstPort = m.PortStart + len(g.Proxies)
		all := make([]config.ProxyEntry, 0, len(g.Proxies)+len(entries))
		all = append(append(all, g.Proxies...), entries...)
		if err = s.setGroupProxies(idx, all); err == nil {
			s.probeAsync(name, len(g.Proxies), len(entries))
		}
	}
	if err != nil {
		stash(err)
		return
	}

	type row struct {
		OutputPort int    `json:"output_port"`
		ExternalIP string `json:"external_ip"`
		Country    string `json:"country,omitempty"`
		State      string `json:"state,omitempty"`
		City       string `json:"city,omitempty"`
		ISP        string `json:"isp,omitempty"`
		SockType   string `json:"sock_type,omitempty"`
		Level      string `json:"level,omitempty"`
	}
	rows := make([]row, 0, len(entries))
	byIP := make(map[string]shopsocks5.Sock, len(socks))
	for _, sk := range socks {
		byIP[sk.SockIP+"|"+sk.User] = sk
	}
	for i, p := range entries {
		sk := byIP[net.JoinHostPort(p.Host, strconv.Itoa(p.Port))+"|"+p.User]
		rows = append(rows, row{
			OutputPort: firstPort + i, ExternalIP: p.ExternalIP, Country: sk.Country,
			State: sk.State, City: sk.City, ISP: sk.ISP, SockType: sk.SockType, Level: sk.SockLevel,
		})
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"status": "ok", "requested": requested, "count": len(entries), "mode": q.Mode, "socks": rows,
		"spent": spent, "duplicates": dups,
	})
}
