package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"proxy-dispatcher/internal/config"
)

// Customer-facing API for session groups ("/api/pub/port/{port}/...").
//
// It is authenticated by a key in the query string instead of a panel
// login, so a customer can change the IP of the port they rent:
//
//	.../new     take a fresh sock from ShopSocks5 and put it on the port
//	.../recall  put the proxy that used to have a given public IP back
//	(no verb)   show what the port currently serves
//
// Each port has its own key, HMAC(group secret, port), so a customer cannot
// touch other ports. The group secret itself works for every port of the
// group (for the operator's own automation).
//
// These routes run without the config lock (they talk to the provider) and
// lock around the parts that read or change the config.

var (
	pubPortLocks sync.Map // port -> *sync.Mutex, one change at a time per port
	pubLastMu    sync.Mutex
	pubLastNew   = map[int]time.Time{} // port -> last successful "new"
)

func portAPIKey(secret string, port int) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("port:" + strconv.Itoa(port)))
	return hex.EncodeToString(mac.Sum(nil))[:24]
}

func newAPISecret() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GET /api/groups/{name}/session-api
func (s *Server) handleGetSessionAPI(w http.ResponseWriter, r *http.Request) {
	idx, ok := s.historyGroup(w, r)
	if !ok {
		return
	}
	g := s.cfg.ProxyGroups[idx]
	c := config.SessionAPIConfig{}
	if g.SessionAPI != nil {
		c = *g.SessionAPI
	}
	out := map[string]interface{}{
		"enabled": c.Enabled, "key": c.Secret,
		"country": c.Country, "state": c.State, "city": c.City,
		"sock_type": c.SockType, "level": c.Level,
		"min_interval_sec": c.MinIntervalSec,
		"unique":           c.Unique,
		"keys":             append([]config.SessionAPIKey{}, c.Keys...),
	}
	if m, mapped := s.groupMapping(g.Name); mapped && c.Secret != "" {
		keys := make(map[string]string, m.PortEnd-m.PortStart+1)
		for p := m.PortStart; p <= m.PortEnd; p++ {
			keys[strconv.Itoa(p)] = portAPIKey(c.Secret, p)
		}
		out["port_keys"] = keys
		out["port_start"], out["port_end"] = m.PortStart, m.PortEnd
	}
	respondJSON(w, http.StatusOK, out)
}

// POST /api/groups/{name}/session-api
func (s *Server) handlePostSessionAPI(w http.ResponseWriter, r *http.Request) {
	idx, ok := s.historyGroup(w, r)
	if !ok {
		return
	}
	var req struct {
		Enabled        bool   `json:"enabled"`
		Country        string `json:"country"`
		State          string `json:"state"`
		City           string `json:"city"`
		SockType       string `json:"sock_type"`
		Level          string `json:"level"`
		MinIntervalSec int    `json:"min_interval_sec"`
		Unique         bool   `json:"unique"`
		Regenerate     bool   `json:"regenerate"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	// Validate the default filter with the same rules as a manual fetch.
	f := ssFetchReq{Qty: 1, Country: req.Country, State: req.State, City: req.City, SockType: req.SockType, Level: req.Level}
	if err := f.normalize(); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.MinIntervalSec < 0 || req.MinIntervalSec > 86400 {
		respondError(w, http.StatusBadRequest, "min_interval_sec must be 0-86400")
		return
	}
	g := s.cfg.ProxyGroups[idx]
	c := config.SessionAPIConfig{}
	if g.SessionAPI != nil {
		c = *g.SessionAPI
	}
	c.Enabled = req.Enabled
	c.Country, c.State, c.City, c.SockType, c.Level = f.Country, f.State, f.City, f.SockType, f.Level
	c.MinIntervalSec = req.MinIntervalSec
	c.Unique = req.Unique
	if c.Secret == "" || req.Regenerate {
		secret, err := newAPISecret()
		if err != nil {
			respondError(w, http.StatusInternalServerError, "could not generate key")
			return
		}
		c.Secret = secret
	}
	prev := s.cfg.ProxyGroups
	groups := make([]config.ProxyGroup, len(prev))
	copy(groups, prev)
	g.SessionAPI = &c
	groups[idx] = g
	s.cfg.ProxyGroups = groups
	if err := config.SaveConfig(s.cfgPath, s.cfg); err != nil {
		s.cfg.ProxyGroups = prev
		respondError(w, http.StatusInternalServerError, "save failed")
		return
	}
	if s.onConfigSave != nil {
		s.onConfigSave()
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "enabled": c.Enabled})
}

// parsePortSpec parses "40000-40004,40010" into inclusive ranges.
func parsePortSpec(spec string) ([][2]int, error) {
	var out [][2]int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(strings.TrimSpace(lo))
		b := a
		if err == nil && isRange {
			b, err = strconv.Atoi(strings.TrimSpace(hi))
		}
		if err != nil || a < 1 || b > 65535 || a > b {
			return nil, fmt.Errorf("invalid port list %q (example: 40000-40004,40010)", part)
		}
		out = append(out, [2]int{a, b})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("port list is empty")
	}
	return out, nil
}

func portInSpec(spec string, port int) bool {
	ranges, err := parsePortSpec(spec)
	if err != nil {
		return false
	}
	for _, r := range ranges {
		if port >= r[0] && port <= r[1] {
			return true
		}
	}
	return false
}

// POST /api/groups/{name}/session-api/keys  {"ports": "40000-40004", "note": "khach A"}
// Creates one key valid for all listed ports.
func (s *Server) handlePostSessionAPIKey(w http.ResponseWriter, r *http.Request) {
	idx, ok := s.historyGroup(w, r)
	if !ok {
		return
	}
	var req struct {
		Ports string `json:"ports"`
		Note  string `json:"note"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	g := s.cfg.ProxyGroups[idx]
	m, mapped := s.groupMapping(g.Name)
	if !mapped {
		respondError(w, http.StatusBadRequest, "group has no port range")
		return
	}
	ranges, err := parsePortSpec(req.Ports)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	parts := make([]string, 0, len(ranges))
	for _, rg := range ranges {
		if rg[0] < m.PortStart || rg[1] > m.PortEnd {
			respondError(w, http.StatusBadRequest, fmt.Sprintf("ports must be within the group's range %d-%d", m.PortStart, m.PortEnd))
			return
		}
		if rg[0] == rg[1] {
			parts = append(parts, strconv.Itoa(rg[0]))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", rg[0], rg[1]))
		}
	}
	c := config.SessionAPIConfig{}
	if g.SessionAPI != nil {
		c = *g.SessionAPI
	}
	if len(c.Keys) >= 500 {
		respondError(w, http.StatusBadRequest, "too many keys (max 500)")
		return
	}
	key, err := newAPISecret()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "could not generate key")
		return
	}
	if c.Secret == "" {
		if c.Secret, err = newAPISecret(); err != nil {
			respondError(w, http.StatusInternalServerError, "could not generate key")
			return
		}
	}
	nk := config.SessionAPIKey{Key: key, Ports: strings.Join(parts, ","), Note: strings.TrimSpace(req.Note)}
	c.Keys = append(append([]config.SessionAPIKey{}, c.Keys...), nk)
	if !s.saveSessionAPI(w, idx, c) {
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "key": nk})
}

// DELETE /api/groups/{name}/session-api/keys  {"key": "..."}
func (s *Server) handleDeleteSessionAPIKey(w http.ResponseWriter, r *http.Request) {
	idx, ok := s.historyGroup(w, r)
	if !ok {
		return
	}
	var req struct {
		Key string `json:"key"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	g := s.cfg.ProxyGroups[idx]
	if g.SessionAPI == nil {
		respondError(w, http.StatusNotFound, "key not found")
		return
	}
	c := *g.SessionAPI
	keys := make([]config.SessionAPIKey, 0, len(c.Keys))
	for _, k := range c.Keys {
		if k.Key != req.Key {
			keys = append(keys, k)
		}
	}
	if len(keys) == len(c.Keys) {
		respondError(w, http.StatusNotFound, "key not found")
		return
	}
	c.Keys = keys
	if !s.saveSessionAPI(w, idx, c) {
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// saveSessionAPI stores c on group idx. Caller holds the write lock.
func (s *Server) saveSessionAPI(w http.ResponseWriter, idx int, c config.SessionAPIConfig) bool {
	prev := s.cfg.ProxyGroups
	groups := make([]config.ProxyGroup, len(prev))
	copy(groups, prev)
	g := groups[idx]
	g.SessionAPI = &c
	groups[idx] = g
	s.cfg.ProxyGroups = groups
	if err := config.SaveConfig(s.cfgPath, s.cfg); err != nil {
		s.cfg.ProxyGroups = prev
		respondError(w, http.StatusInternalServerError, "save failed")
		return false
	}
	if s.onConfigSave != nil {
		s.onConfigSave()
	}
	return true
}

// pubTarget is what a public request resolved to.
type pubTarget struct {
	group string
	idx   int
	port  int
	pos   int // index of the port inside the group's range
	api   config.SessionAPIConfig
}

// pubResolve maps port+key to a session group. Every failure looks the
// same to the caller so ports and groups cannot be probed. Caller holds the
// config lock.
func (s *Server) pubResolve(port int, key string) (pubTarget, bool) {
	for _, m := range s.cfg.PortMappings {
		if port < m.PortStart || port > m.PortEnd {
			continue
		}
		idx := s.findGroup(m.GroupName)
		if idx < 0 {
			return pubTarget{}, false
		}
		g := s.cfg.ProxyGroups[idx]
		if !g.KeepHistory || g.SessionAPI == nil || !g.SessionAPI.Enabled || g.SessionAPI.Secret == "" {
			return pubTarget{}, false
		}
		a := *g.SessionAPI
		okPort := subtle.ConstantTimeCompare([]byte(key), []byte(portAPIKey(a.Secret, port))) == 1
		okMaster := subtle.ConstantTimeCompare([]byte(key), []byte(a.Secret)) == 1
		okShared := false
		for _, k := range a.Keys {
			if subtle.ConstantTimeCompare([]byte(key), []byte(k.Key)) == 1 && portInSpec(k.Ports, port) {
				okShared = true
			}
		}
		if !okPort && !okMaster && !okShared {
			return pubTarget{}, false
		}
		return pubTarget{group: g.Name, idx: idx, port: port, pos: port - m.PortStart, api: a}, true
	}
	return pubTarget{}, false
}

func pubFail(w http.ResponseWriter, status int, msg string) {
	respondJSON(w, status, map[string]interface{}{"success": false, "error": msg})
}

func pubParams(r *http.Request) (port int, key string, ok bool) {
	port, err := strconv.Atoi(r.PathValue("port"))
	key = r.URL.Query().Get("key")
	if key == "" {
		key = r.Header.Get("X-API-Key")
	}
	return port, key, err == nil && key != ""
}

// pubLockPort takes the per-port lock or reports that a change is running.
func pubLockPort(port int) (*sync.Mutex, bool) {
	v, _ := pubPortLocks.LoadOrStore(port, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	return mu, mu.TryLock()
}

func (s *Server) pubProxyAddr(port int) string {
	return net.JoinHostPort(s.cfg.VpsIp, strconv.Itoa(port))
}

// /api/pub/port/{port}?key=...
func (s *Server) handlePubPortStatus(w http.ResponseWriter, r *http.Request) {
	port, key, ok := pubParams(r)
	s.cfgMu.RLock()
	t, found := s.pubResolve(port, key)
	addr := s.pubProxyAddr(port)
	s.cfgMu.RUnlock()
	if !ok || !found {
		pubFail(w, http.StatusForbidden, "invalid port or key")
		return
	}
	out := map[string]interface{}{"success": true, "port": port, "proxy": addr, "assigned": false}
	if s.groupMgr != nil {
		if ptrs := s.groupMgr.GroupProxies()[t.group]; t.pos < len(ptrs) && ptrs[t.pos] != nil && !ptrs[t.pos].IsEmpty() {
			p := ptrs[t.pos]
			out["assigned"] = true
			out["ip"], out["country"], out["status"] = p.ExternalIP, p.Country, p.Status
		}
	}
	respondJSON(w, http.StatusOK, out)
}

// /api/pub/port/{port}/new?key=...[&country=US&state=...&city=...]
// Replaces the proxy on the port with a fresh sock from ShopSocks5.
func (s *Server) handlePubPortNew(w http.ResponseWriter, r *http.Request) {
	port, key, ok := pubParams(r)
	s.cfgMu.RLock()
	t, found := s.pubResolve(port, key)
	s.cfgMu.RUnlock()
	if !ok || !found {
		pubFail(w, http.StatusForbidden, "invalid port or key")
		return
	}
	mu, got := pubLockPort(port)
	if !got {
		pubFail(w, http.StatusTooManyRequests, "a change is already running for this port")
		return
	}
	defer mu.Unlock()

	if wait := t.api.MinIntervalSec; wait > 0 {
		pubLastMu.Lock()
		left := time.Duration(wait)*time.Second - time.Since(pubLastNew[port])
		pubLastMu.Unlock()
		if left > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(int(left.Seconds())+1))
			respondJSON(w, http.StatusTooManyRequests, map[string]interface{}{
				"success": false, "error": "too soon, wait before asking for a new IP", "retry_after_sec": int(left.Seconds()) + 1,
			})
			return
		}
	}

	// Location may be chosen per request; type and risk level stay as the
	// operator configured them.
	q := ssFetchReq{Qty: 1, Mode: "port", Port: port, Country: t.api.Country, State: t.api.State, City: t.api.City, SockType: t.api.SockType, Level: t.api.Level}
	qs := r.URL.Query()
	if v := qs.Get("country"); v != "" {
		q.Country, q.State, q.City = v, "", ""
	}
	if v := qs.Get("state"); v != "" {
		q.State, q.City = v, ""
	}
	if v := qs.Get("city"); v != "" {
		q.City = v
	}
	if err := q.normalize(); err != nil {
		pubFail(w, http.StatusBadRequest, err.Error())
		return
	}
	cl, err := s.ssClient()
	if err != nil {
		pubFail(w, http.StatusServiceUnavailable, "provider is not configured")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 150*time.Second)
	defer cancel()
	known, err := s.ssKnown(ctx, t.group, t.api.Unique, true)
	if err != nil {
		s.logger.Warn("session api: exclude list unavailable", "port", port, "error", err)
		pubFail(w, http.StatusBadGateway, "the exclude list is unavailable, try again later")
		return
	}
	socks, _, dups, err := s.fetchSocks(ctx, cl, 1, map[string]string{
		"country": q.Country, "state": q.State, "city": q.City, "sock_type": q.SockType, "level": q.Level,
	}, known)
	if err == nil && len(socks) == 0 && dups > 0 {
		s.logger.Warn("session api: only duplicate IPs returned", "port", port, "duplicates", dups)
		pubFail(w, http.StatusBadGateway, "only IPs that were already used came back; try again or pick another location")
		return
	}
	if err != nil {
		s.logger.Warn("session api: provider error", "port", port, "error", err)
		s.notifyProblem("pub", 30*time.Minute, fmt.Sprintf("API cho khach (port %d) khong lay duoc sock: %s", port, err))
		pubFail(w, http.StatusBadGateway, "provider error: "+strings.TrimPrefix(err.Error(), "shopsocks5: "))
		return
	}
	entries := socksToEntries(socks)
	if len(entries) == 0 {
		pubFail(w, http.StatusBadGateway, "no sock available for this filter")
		return
	}
	sk := socks[0]

	s.cfgMu.Lock()
	t2, still := s.pubResolve(port, key)
	if !still || t2.group != t.group {
		s.stashFetched(t.group, entries[:1])
		s.cfgMu.Unlock()
		pubFail(w, http.StatusConflict, "port changed while the request was running")
		return
	}
	_, status, err := s.placeAtPort(t2.idx, entries[0], port)
	addr := s.pubProxyAddr(port)
	if err != nil {
		s.stashFetched(t.group, entries[:1])
	}
	s.cfgMu.Unlock()
	if err != nil {
		s.logger.Warn("session api: could not place sock", "port", port, "error", err)
		pubFail(w, status, "could not apply the new proxy")
		return
	}
	pubLastMu.Lock()
	pubLastNew[port] = time.Now()
	pubLastMu.Unlock()
	s.logger.Info("session api: new IP", "group", t.group, "port", port, "ip", entries[0].ExternalIP)
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true, "port": port, "proxy": addr, "ip": entries[0].ExternalIP,
		"country": sk.Country, "state": sk.State, "city": sk.City, "isp": sk.ISP, "sock_type": sk.SockType,
	})
}

// stashFetched keeps paid-for socks that could not be placed in the group's
// history so they can be attached by hand. Caller holds the write lock.
func (s *Server) stashFetched(group string, entries []config.ProxyEntry) bool {
	idx := s.findGroup(group)
	if idx < 0 || !s.cfg.ProxyGroups[idx].KeepHistory {
		return false
	}
	rows := make([]histProxy, len(entries))
	for i, p := range entries {
		rows[i] = histProxy{Host: p.Host, Port: p.Port, User: p.User, Pass: p.Pass, Type: p.Type, ExternalIP: p.ExternalIP, Country: p.Country, IPv4Only: p.IPv4Only}
	}
	return s.pushHistory(group, "fetched", rows) == nil
}

// /api/pub/port/{port}/recall?key=...&ip=1.2.3.4
// Puts the proxy that had this public IP (from the group's history) back
// on the port, then probes it and reports whether it still works.
func (s *Server) handlePubPortRecall(w http.ResponseWriter, r *http.Request) {
	port, key, ok := pubParams(r)
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ok && net.ParseIP(ip) == nil {
		// Still answer 403 first for bad keys: checked below.
		ip = ""
	}
	mu, got := pubLockPort(port)
	if !got {
		pubFail(w, http.StatusTooManyRequests, "a change is already running for this port")
		return
	}
	defer mu.Unlock()

	s.cfgMu.Lock()
	t, found := s.pubResolve(port, key)
	if !ok || !found {
		s.cfgMu.Unlock()
		pubFail(w, http.StatusForbidden, "invalid port or key")
		return
	}
	if ip == "" {
		s.cfgMu.Unlock()
		pubFail(w, http.StatusBadRequest, "ip is required, e.g. ?ip=1.2.3.4")
		return
	}
	addr := s.pubProxyAddr(port)
	g := s.cfg.ProxyGroups[t.idx]
	already := false
	for i, p := range g.Proxies {
		if p.ExternalIP != ip {
			continue
		}
		if i == t.pos {
			already = true
			break
		}
		s.cfgMu.Unlock()
		pubFail(w, http.StatusConflict, "this IP is in use on another port")
		return
	}
	if !already {
		var src *histProxy
		for _, sn := range s.loadHistory(t.group).Snapshots {
			for i := range sn.Proxies {
				if sn.Proxies[i].ExternalIP == ip {
					src = &sn.Proxies[i]
					break
				}
			}
			if src != nil {
				break
			}
		}
		if src == nil {
			s.cfgMu.Unlock()
			pubFail(w, http.StatusNotFound, "this IP was never used in this group")
			return
		}
		if _, status, err := s.placeAtPort(t.idx, histToEntries([]histProxy{*src})[0], port); err != nil {
			s.cfgMu.Unlock()
			s.logger.Warn("session api: recall failed", "port", port, "error", err)
			pubFail(w, status, "could not apply the proxy")
			return
		}
		s.logger.Info("session api: recalled IP", "group", t.group, "port", port, "ip", ip)
	}
	s.cfgMu.Unlock()

	out := map[string]interface{}{"success": true, "port": port, "proxy": addr, "ip": ip, "restored": !already}
	// Probe so the caller learns whether the old session is still alive
	// and whether it still exits from the same IP.
	if s.healthChecker != nil && s.groupMgr != nil {
		if ptrs := s.groupMgr.GroupProxies()[t.group]; t.pos < len(ptrs) && ptrs[t.pos] != nil {
			p := ptrs[t.pos]
			res := s.healthChecker.CheckProxies([]*config.ProxyEntry{p})
			if len(res) == 1 {
				alive := res[0].NewStatus != "dead"
				out["alive"] = alive
				if res[0].ExternalIP != "" {
					out["current_ip"] = res[0].ExternalIP
					out["same_ip"] = res[0].ExternalIP == ip
				}
				if !alive {
					out["note"] = "the old proxy no longer responds; request a new IP instead"
				}
			}
		}
	}
	respondJSON(w, http.StatusOK, out)
}
