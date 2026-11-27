package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"proxy-dispatcher/internal/config"
)

// Auto-keep ("luon giu N port song") for session groups.
//
// The first Target ports of the group are probed every CheckSec seconds
// with a dedicated worker pool. A port that is empty, or whose sock failed
// DeadChecks probes in a row, gets a fresh sock from ShopSocks5; the dead
// one goes to the group's history. MaxPerDay caps how many socks this may
// take per day: a filter that only returns dead socks must not drain the
// plan.

const (
	akMinCheckSec = 30
	akTick        = 5 * time.Second
)

// akGroup is the runtime state of one group. Guarded by akMu, which is a
// leaf lock: never take the config lock while holding it.
type akGroup struct {
	next  time.Time
	fails map[string]int // "pos|host:port|user" -> dead probes in a row

	Day      string `json:"day"`
	Spent    int    `json:"spent"`    // socks taken from the plan today
	Replaced int    `json:"replaced"` // dead socks swapped out today

	alive, dead, empty int
	lastRun            int64
	lastErr            string
	lastErrAt          int64
	running            bool
}

var (
	akMu     sync.Mutex
	akGroups = map[string]*akGroup{}
	akLoaded bool
)

func (s *Server) akStatePath() string {
	return filepath.Join(filepath.Dir(s.cfgPath), "autokeep-state.json")
}

// akGet returns the state of a group, loading the persisted daily counters
// on first use and rolling them over at midnight. Caller holds akMu.
func (s *Server) akGet(group string) *akGroup {
	if !akLoaded {
		akLoaded = true
		if data, err := os.ReadFile(s.akStatePath()); err == nil {
			saved := map[string]*akGroup{}
			if json.Unmarshal(data, &saved) == nil {
				for name, g := range saved {
					if g != nil {
						akGroups[name] = &akGroup{Day: g.Day, Spent: g.Spent, Replaced: g.Replaced}
					}
				}
			}
		}
	}
	g := akGroups[group]
	if g == nil {
		g = &akGroup{}
		akGroups[group] = g
	}
	if g.fails == nil {
		g.fails = map[string]int{}
	}
	if today := time.Now().Format("2006-01-02"); g.Day != today {
		g.Day, g.Spent, g.Replaced = today, 0, 0
	}
	return g
}

// akSave persists the daily counters. Caller holds akMu.
func (s *Server) akSave() {
	data, err := json.Marshal(akGroups)
	if err != nil {
		return
	}
	tmp := s.akStatePath() + ".tmp"
	if os.WriteFile(tmp, data, 0o600) == nil {
		_ = os.Rename(tmp, s.akStatePath())
	}
}

func akID(p *config.ProxyEntry) string {
	if p == nil || p.IsEmpty() {
		return ""
	}
	return p.Host + ":" + strconv.Itoa(p.Port) + "|" + p.User
}

// testHostReachable reports whether the health-check target answers a
// direct TCP connection from this server.
func testHostReachable(testURL string) bool {
	u, err := url.Parse(testURL)
	if err != nil || u.Hostname() == "" {
		return true // nothing to compare against: trust the probes
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(u.Hostname(), port), 5*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// akPositions returns the positions (index inside the group's port range)
// auto-keep looks after: the listed ports, or the first Target ports.
func akPositions(ak config.AutoKeepConfig, m config.PortMapping) []int {
	capacity := m.PortEnd - m.PortStart + 1
	var out []int
	if ak.Ports != "" {
		ranges, err := parsePortSpec(ak.Ports)
		if err != nil {
			return nil
		}
		seen := map[int]bool{}
		for _, r := range ranges {
			for p := max(r[0], m.PortStart); p <= min(r[1], m.PortEnd) && len(out) < 500; p++ {
				if !seen[p] {
					seen[p] = true
					out = append(out, p-m.PortStart)
				}
			}
		}
		sort.Ints(out)
		return out
	}
	for pos := 0; pos < min(ak.Target, capacity); pos++ {
		out = append(out, pos)
	}
	return out
}

// StartAutoKeep runs the auto-keep loop until ctx is done.
func (s *Server) StartAutoKeep(ctx context.Context) {
	go func() {
		t := time.NewTicker(akTick)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.akRunDue(ctx)
			}
		}
	}()
}

// akRunDue runs every enabled group whose check is due, one after another.
func (s *Server) akRunDue(ctx context.Context) {
	if s.groupMgr == nil || s.healthChecker == nil {
		return
	}
	type job struct {
		name  string
		every time.Duration
	}
	var jobs []job
	s.cfgMu.RLock()
	for _, g := range s.cfg.ProxyGroups {
		if g.KeepHistory && g.AutoKeep != nil && g.AutoKeep.Enabled {
			jobs = append(jobs, job{g.Name, time.Duration(max(g.AutoKeep.CheckSec, akMinCheckSec)) * time.Second})
		}
	}
	s.cfgMu.RUnlock()
	for _, j := range jobs {
		akMu.Lock()
		st := s.akGet(j.name)
		due := !time.Now().Before(st.next)
		if due {
			st.running = true
		}
		akMu.Unlock()
		if !due {
			continue
		}
		err := s.akRunGroup(ctx, j.name)
		akMu.Lock()
		st = s.akGet(j.name)
		st.running = false
		st.next = time.Now().Add(j.every)
		st.lastRun = time.Now().Unix()
		if err != nil {
			st.lastErr, st.lastErrAt = err.Error(), time.Now().Unix()
		} else if time.Now().Unix()-st.lastErrAt > 3600 {
			st.lastErr = ""
		}
		akMu.Unlock()
		if err != nil {
			s.logger.Warn("auto-keep", "group", j.name, "error", err)
		}
	}
}

// akRunGroup probes the kept ports of one group and refills what is empty
// or dead. Runs without the config lock while probing and fetching.
func (s *Server) akRunGroup(ctx context.Context, name string) error {
	s.cfgMu.RLock()
	idx := s.findGroup(name)
	if idx < 0 || s.cfg.ProxyGroups[idx].AutoKeep == nil || !s.cfg.ProxyGroups[idx].AutoKeep.Enabled {
		s.cfgMu.RUnlock()
		return nil
	}
	g := s.cfg.ProxyGroups[idx]
	ak := *g.AutoKeep
	m, mapped := s.groupMapping(name)
	if !mapped {
		s.cfgMu.RUnlock()
		return fmt.Errorf("nhom khong co dai port")
	}
	testURL := s.cfg.HealthCheck.TestURL
	ids := map[int]string{} // position -> proxy identity, "" = empty port
	for _, pos := range akPositions(ak, m) {
		ids[pos] = ""
		if pos < len(g.Proxies) {
			ids[pos] = akID(&g.Proxies[pos])
		}
	}
	s.cfgMu.RUnlock()

	// Probe what is there.
	ptrs := s.groupMgr.GroupProxies()[name]
	var probe []*config.ProxyEntry
	posOf := map[*config.ProxyEntry]int{}
	for pos, id := range ids {
		if id != "" && pos < len(ptrs) && akID(ptrs[pos]) == id {
			probe = append(probe, ptrs[pos])
			posOf[ptrs[pos]] = pos
		}
	}
	results := s.healthChecker.CheckProxiesPriority(probe)

	deadChecks := max(ak.DeadChecks, 1)
	akMu.Lock()
	st := s.akGet(name)
	fails := map[string]int{}
	alive, dead := 0, 0
	var need []int
	for _, res := range results {
		pos := posOf[res.Proxy]
		key := strconv.Itoa(pos) + "|" + ids[pos]
		if res.NewStatus != "dead" {
			alive++
			continue
		}
		dead++
		fails[key] = st.fails[key] + 1
		if fails[key] >= deadChecks {
			need = append(need, pos)
		}
	}
	empty := 0
	for pos, id := range ids {
		if id == "" {
			empty++
			need = append(need, pos)
		}
	}
	st.fails = fails
	st.alive, st.dead, st.empty = alive, dead, empty
	left := ak.MaxPerDay - st.Spent
	akMu.Unlock()

	if len(need) == 0 {
		return nil
	}
	// Many socks dying in the same round usually means the server lost its
	// network or the test URL is down, not that the socks are gone. Do not
	// pay for replacements unless the test host is reachable directly.
	if dead >= 3 && dead*2 > len(results) && !testHostReachable(testURL) {
		return fmt.Errorf("%d/%d port bao chet cung luc nhung may chu khong ket noi duoc toi URL kiem tra: chua thay sock (nghi loi mang hoac URL kiem tra)", dead, len(results))
	}
	sort.Ints(need)
	if left <= 0 {
		return fmt.Errorf("da dung het gioi han %d sock/ngay cua chuc nang tu giu port, con %d port can sock", ak.MaxPerDay, len(need))
	}
	n := min(len(need), left)

	cl, err := s.ssClient()
	if err != nil {
		return err
	}
	ssFetchMu.Lock()
	defer ssFetchMu.Unlock()
	fctx, cancel := context.WithTimeout(ctx, 150*time.Second)
	defer cancel()
	// Auto-keep only avoids IPs the group holds right now: checking the whole
	// history made a third of the paid socks duplicates (each still costs a
	// sock from the daily quota) once the history grew to thousands of IPs.
	known, err := s.ssKnown(fctx, name, ak.Unique, false)
	if err != nil {
		return err
	}
	socks, spent, dups, err := fetchUniqueSocks(fctx, cl, n, map[string]string{
		"country": ak.Country, "state": ak.State, "city": ak.City, "sock_type": ak.SockType, "level": ak.Level,
	}, known)
	if spent > 0 {
		akMu.Lock()
		s.akGet(name).Spent += spent
		s.akSave()
		akMu.Unlock()
	}
	if err != nil {
		return err
	}
	entries := socksToEntries(socks)
	if len(entries) == 0 {
		if dups > 0 {
			return fmt.Errorf("ShopSocks5 chi tra ve IP trung / IP loai tru (%d sock, da tru %d luot)", dups, spent)
		}
		return fmt.Errorf("ShopSocks5 khong tra ve sock nao phu hop bo loc")
	}

	// Place them. A port that changed while we were fetching (customer API,
	// manual edit) is left alone.
	s.cfgMu.Lock()
	at := map[int]config.ProxyEntry{}
	idx = s.findGroup(name)
	if idx >= 0 && s.cfg.ProxyGroups[idx].KeepHistory && s.cfg.ProxyGroups[idx].AutoKeep != nil && s.cfg.ProxyGroups[idx].AutoKeep.Enabled {
		cur := s.cfg.ProxyGroups[idx].Proxies
		next := 0
		for _, pos := range need {
			if next >= len(entries) {
				break
			}
			now := ""
			if pos < len(cur) {
				now = akID(&cur[pos])
			}
			if now != ids[pos] {
				continue
			}
			at[pos] = entries[next]
			next++
		}
		if len(at) > 0 {
			err = s.placeAtPorts(idx, at)
		}
		if err != nil {
			s.stashFetched(name, entries)
			at = nil
		} else if next < len(entries) {
			s.stashFetched(name, entries[next:])
		}
	} else {
		s.stashFetched(name, entries)
		err = fmt.Errorf("nhom thay doi trong luc lay sock; %d sock da luu vao lich su", len(entries))
	}
	s.cfgMu.Unlock()
	if err != nil {
		return err
	}

	replaced := 0
	for pos := range at {
		if ids[pos] != "" {
			replaced++
		}
		s.probeAsync(name, pos, 1)
	}
	akMu.Lock()
	st = s.akGet(name)
	st.Replaced += replaced
	for pos := range at {
		delete(st.fails, strconv.Itoa(pos)+"|"+ids[pos])
	}
	s.akSave()
	akMu.Unlock()
	s.logger.Info("auto-keep: refilled", "group", name, "placed", len(at), "replaced_dead", replaced, "spent", spent, "duplicates", dups)
	if len(at) < len(need) && len(entries) < n {
		return fmt.Errorf("can %d sock nhung ShopSocks5 chi tra ve %d", n, len(entries))
	}
	return nil
}

// placeAtPorts binds several proxies to positions of group idx in one
// save. Proxies they replace are archived together as one snapshot. Caller
// holds the config write lock.
func (s *Server) placeAtPorts(idx int, at map[int]config.ProxyEntry) error {
	g := s.cfg.ProxyGroups[idx]
	m, mapped := s.groupMapping(g.Name)
	if !mapped {
		return fmt.Errorf("group has no port range")
	}
	capacity := m.PortEnd - m.PortStart + 1
	positions := make([]int, 0, len(at))
	for pos := range at {
		if pos < 0 || pos >= capacity {
			return fmt.Errorf("position %d is outside the group's range", pos)
		}
		positions = append(positions, pos)
	}
	sort.Ints(positions)
	proxies := make([]config.ProxyEntry, len(g.Proxies))
	copy(proxies, g.Proxies)
	var archived []histProxy
	for _, pos := range positions {
		for len(proxies) <= pos {
			proxies = append(proxies, config.ProxyEntry{Type: "socks5", Status: "empty"})
		}
		if old := proxies[pos]; !old.IsEmpty() {
			archived = append(archived, s.snapshotProxies(g.Name, []config.ProxyEntry{old}, pos)...)
		}
		proxies[pos] = at[pos]
	}
	if err := s.pushHistory(g.Name, "auto", archived); err != nil {
		return fmt.Errorf("could not archive the replaced proxies: %w", err)
	}
	return s.setGroupProxies(idx, proxies)
}

// GET /api/groups/{name}/auto-keep
func (s *Server) handleGetAutoKeep(w http.ResponseWriter, r *http.Request) {
	idx, ok := s.historyGroup(w, r)
	if !ok {
		return
	}
	g := s.cfg.ProxyGroups[idx]
	c := config.AutoKeepConfig{Target: 30, SockType: "residential", Level: "1", Unique: true, CheckSec: 60, DeadChecks: 2, MaxPerDay: 200}
	if g.AutoKeep != nil {
		c = *g.AutoKeep
	}
	out := map[string]interface{}{"config": c, "configured": g.AutoKeep != nil}
	if m, mapped := s.groupMapping(g.Name); mapped {
		out["port_start"], out["capacity"] = m.PortStart, m.PortEnd-m.PortStart+1
	}
	akMu.Lock()
	st := s.akGet(g.Name)
	status := map[string]interface{}{
		"alive": st.alive, "dead": st.dead, "empty": st.empty,
		"spent_today": st.Spent, "replaced_today": st.Replaced,
		"last_run": st.lastRun, "last_error": st.lastErr, "last_error_at": st.lastErrAt,
		"running": st.running,
	}
	akMu.Unlock()
	out["status"] = status
	respondJSON(w, http.StatusOK, out)
}

// POST /api/groups/{name}/auto-keep
func (s *Server) handlePostAutoKeep(w http.ResponseWriter, r *http.Request) {
	idx, ok := s.historyGroup(w, r)
	if !ok {
		return
	}
	var c config.AutoKeepConfig
	if err := decodeJSON(r, &c); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	f := ssFetchReq{Qty: 1, Country: c.Country, State: c.State, City: c.City, SockType: c.SockType, Level: c.Level}
	if err := f.normalize(); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	c.Country, c.State, c.City, c.SockType, c.Level = f.Country, f.State, f.City, f.SockType, f.Level
	g := s.cfg.ProxyGroups[idx]
	m, mapped := s.groupMapping(g.Name)
	if !mapped {
		respondError(w, http.StatusBadRequest, "group has no port range")
		return
	}
	capacity := m.PortEnd - m.PortStart + 1
	c.Ports = strings.Join(strings.Fields(c.Ports), "")
	if c.Ports != "" {
		ranges, err := parsePortSpec(c.Ports)
		if err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		for _, rg := range ranges {
			if rg[0] < m.PortStart || rg[1] > m.PortEnd {
				respondError(w, http.StatusBadRequest, fmt.Sprintf("port can giu phai nam trong dai cua nhom %d-%d", m.PortStart, m.PortEnd))
				return
			}
		}
		c.Target = len(akPositions(c, m))
	}
	switch {
	case c.Target < 1 || c.Target > capacity || c.Target > 500:
		respondError(w, http.StatusBadRequest, fmt.Sprintf("so port phai tu 1 den %d", min(capacity, 500)))
		return
	case c.CheckSec < akMinCheckSec || c.CheckSec > 3600:
		respondError(w, http.StatusBadRequest, fmt.Sprintf("chu ky kiem tra phai tu %d den 3600 giay", akMinCheckSec))
		return
	case c.DeadChecks < 1 || c.DeadChecks > 10:
		respondError(w, http.StatusBadRequest, "so lan chet lien tiep phai tu 1 den 10")
		return
	case c.MaxPerDay < 1 || c.MaxPerDay > 5000:
		respondError(w, http.StatusBadRequest, "gioi han sock/ngay phai tu 1 den 5000")
		return
	}
	if c.Enabled && (s.cfg.ShopSocks5.UserName == "" || s.cfg.ShopSocks5.APIToken == "") {
		respondError(w, http.StatusBadRequest, "chua nhap tai khoan ShopSocks5")
		return
	}
	prev := s.cfg.ProxyGroups
	groups := make([]config.ProxyGroup, len(prev))
	copy(groups, prev)
	g.AutoKeep = &c
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
	akMu.Lock()
	st := s.akGet(g.Name)
	st.next = time.Time{} // run on the next tick
	st.fails = map[string]int{}
	st.lastErr = ""
	akMu.Unlock()
	respondJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "enabled": c.Enabled})
}
