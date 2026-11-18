package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"proxy-dispatcher/internal/config"
)

// List history for "session" groups (ProxyGroup.KeepHistory).
//
// Every time such a group's list is replaced, the outgoing list is stored
// as a snapshot together with the public IP the health check recorded for
// each proxy and the output port it was bound to. Snapshots live in one
// JSON file per group next to the config file (not inside it: lists with
// thousands of proxies would bloat every config save, backup and sync).
//
// All functions here run under the API server's config lock (ServeHTTP):
// writers are exclusive, so the files need no extra locking.

// History size: the newest keepHistorySnapshots snapshots are always kept
// (whole lists can be large). Beyond that, older ones survive only while
// the file stays under maxHistorySnapshots / maxHistoryRows, which is what
// lets thousands of one-row "swap" snapshots (one per IP change) pile up.
const (
	keepHistorySnapshots = 100
	maxHistorySnapshots  = 5000
	maxHistoryRows       = 50000
)

type histProxy struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	User       string `json:"user,omitempty"`
	Pass       string `json:"pass,omitempty"`
	Type       string `json:"type"`
	ExternalIP string `json:"external_ip,omitempty"`
	Country    string `json:"country,omitempty"`
	IPv4Only   bool   `json:"ipv4_only,omitempty"`
	OutputPort int    `json:"output_port,omitempty"`
}

type histSnapshot struct {
	ID      string      `json:"id"`
	At      int64       `json:"at"`
	Reason  string      `json:"reason"` // "replace", "restore" or "swap"
	Proxies []histProxy `json:"proxies"`
}

type histFile struct {
	Snapshots []histSnapshot `json:"snapshots"` // newest first
}

func (s *Server) historyPath(group string) string {
	return filepath.Join(filepath.Dir(s.cfgPath), "group-history", group+".json")
}

func (s *Server) loadHistory(group string) histFile {
	var hf histFile
	data, err := os.ReadFile(s.historyPath(group))
	if err != nil {
		return hf
	}
	_ = json.Unmarshal(data, &hf)
	return hf
}

func (s *Server) saveHistory(group string, hf histFile) error {
	p := s.historyPath(group)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(&hf)
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return os.WriteFile(p, data, 0o600)
	}
	return nil
}

func (s *Server) removeHistory(group string) {
	_ = os.Remove(s.historyPath(group))
}

// snapshotProxies converts live entries into history rows, recording the
// output port each one occupies in the group's range.
func (s *Server) snapshotProxies(group string, proxies []config.ProxyEntry, firstIndex int) []histProxy {
	m, mapped := s.groupMapping(group)
	out := make([]histProxy, 0, len(proxies))
	for i, p := range proxies {
		if p.IsEmpty() {
			continue
		}
		hp := histProxy{Host: p.Host, Port: p.Port, User: p.User, Pass: p.Pass, Type: p.Type, ExternalIP: p.ExternalIP, Country: p.Country, IPv4Only: p.IPv4Only}
		if port := m.PortStart + firstIndex + i; mapped && port <= m.PortEnd {
			hp.OutputPort = port
		}
		out = append(out, hp)
	}
	return out
}

// pushHistory prepends a snapshot of proxies to the group's history.
func (s *Server) pushHistory(group, reason string, rows []histProxy) error {
	if len(rows) == 0 {
		return nil
	}
	hf := s.loadHistory(group)
	snap := histSnapshot{
		ID:      strconv.FormatInt(time.Now().UnixNano(), 36),
		At:      time.Now().Unix(),
		Reason:  reason,
		Proxies: rows,
	}
	hf.Snapshots = append([]histSnapshot{snap}, hf.Snapshots...)
	total, keep := 0, len(hf.Snapshots)
	for i, sn := range hf.Snapshots {
		total += len(sn.Proxies)
		if i >= keepHistorySnapshots && (i >= maxHistorySnapshots || total > maxHistoryRows) {
			keep = i
			break
		}
	}
	hf.Snapshots = hf.Snapshots[:keep]
	return s.saveHistory(group, hf)
}

// findGroup returns the index of the named group, or -1.
func (s *Server) findGroup(name string) int {
	for i := range s.cfg.ProxyGroups {
		if s.cfg.ProxyGroups[i].Name == name {
			return i
		}
	}
	return -1
}

// historyGroup resolves the {name} path value to a history-enabled group.
func (s *Server) historyGroup(w http.ResponseWriter, r *http.Request) (int, bool) {
	idx := s.findGroup(r.PathValue("name"))
	if idx < 0 {
		respondError(w, http.StatusNotFound, "group not found")
		return 0, false
	}
	if !s.cfg.ProxyGroups[idx].KeepHistory {
		respondError(w, http.StatusBadRequest, "list history is not enabled for this group")
		return 0, false
	}
	return idx, true
}

// publicRow is a history row as sent to the panel: no password.
type publicRow struct {
	Index      int    `json:"index"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	User       string `json:"user,omitempty"`
	Type       string `json:"type"`
	ExternalIP string `json:"external_ip,omitempty"`
	Country    string `json:"country,omitempty"`
	OutputPort int    `json:"output_port,omitempty"`
}

func toPublicRows(rows []histProxy) []publicRow {
	out := make([]publicRow, len(rows))
	for i, p := range rows {
		out[i] = publicRow{Index: i, Host: p.Host, Port: p.Port, User: p.User, Type: p.Type, ExternalIP: p.ExternalIP, Country: p.Country, OutputPort: p.OutputPort}
	}
	return out
}

// GET /api/groups/{name}/ips
// Every distinct public IP the group has had: the ones serving a port now
// first (by port), then the ones only left in history, newest first. A
// history IP carries the snapshot row to re-attach it from.
func (s *Server) handleGetGroupIPs(w http.ResponseWriter, r *http.Request) {
	idx, ok := s.historyGroup(w, r)
	if !ok {
		return
	}
	g := &s.cfg.ProxyGroups[idx]
	type ipRow struct {
		InUse      bool   `json:"in_use"`
		SnapshotID string `json:"snapshot_id,omitempty"`
		LastAt     int64  `json:"last_at,omitempty"`  // newest history snapshot holding it
		FirstAt    int64  `json:"first_at,omitempty"` // oldest history snapshot holding it
		publicRow
	}
	rows := make([]*ipRow, 0, len(g.Proxies))
	byIP := make(map[string]*ipRow)
	noIP := 0
	for _, hp := range s.snapshotProxies(g.Name, g.Proxies, 0) {
		if hp.ExternalIP == "" {
			noIP++
			continue
		}
		if byIP[hp.ExternalIP] != nil {
			continue
		}
		row := &ipRow{InUse: true, publicRow: toPublicRows([]histProxy{hp})[0]}
		byIP[hp.ExternalIP] = row
		rows = append(rows, row)
	}
	inUse := len(rows)
	for _, sn := range s.loadHistory(g.Name).Snapshots {
		for i, hp := range sn.Proxies {
			if hp.ExternalIP == "" {
				continue
			}
			row := byIP[hp.ExternalIP]
			if row == nil {
				row = &ipRow{SnapshotID: sn.ID, publicRow: toPublicRows([]histProxy{hp})[0]}
				row.Index = i
				byIP[hp.ExternalIP] = row
				rows = append(rows, row)
			}
			if row.LastAt == 0 {
				row.LastAt = sn.At
			}
			if row.Country == "" {
				row.Country = hp.Country
			}
			row.FirstAt = sn.At
		}
	}
	sort.SliceStable(rows[:inUse], func(a, b int) bool { return rows[a].OutputPort < rows[b].OutputPort })
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"ips": rows, "total": len(rows), "in_use": inUse, "history": len(rows) - inUse, "current_without_ip": noIP,
	})
}

// GET /api/groups/{name}/history[?id=<snapshot>]
// Without id: the snapshot list (id, time, reason, count). With id: its rows.
func (s *Server) handleGetGroupHistory(w http.ResponseWriter, r *http.Request) {
	idx, ok := s.historyGroup(w, r)
	if !ok {
		return
	}
	name := s.cfg.ProxyGroups[idx].Name
	hf := s.loadHistory(name)
	if id := r.URL.Query().Get("id"); id != "" {
		for _, sn := range hf.Snapshots {
			if sn.ID == id {
				respondJSON(w, http.StatusOK, map[string]interface{}{
					"id": sn.ID, "at": sn.At, "reason": sn.Reason, "proxies": toPublicRows(sn.Proxies),
				})
				return
			}
		}
		respondError(w, http.StatusNotFound, "snapshot not found")
		return
	}
	type item struct {
		ID     string `json:"id"`
		At     int64  `json:"at"`
		Reason string `json:"reason"`
		Count  int    `json:"count"`
		WithIP int    `json:"with_ip"`
	}
	items := make([]item, 0, len(hf.Snapshots))
	for _, sn := range hf.Snapshots {
		withIP := 0
		for _, p := range sn.Proxies {
			if p.ExternalIP != "" {
				withIP++
			}
		}
		items = append(items, item{ID: sn.ID, At: sn.At, Reason: sn.Reason, Count: len(sn.Proxies), WithIP: withIP})
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{"snapshots": items})
}

// GET /api/groups/{name}/search?ip=1.2.3.4
// Finds proxies by public IP (or by upstream host / username fragment) in
// the current list and in every history snapshot.
func (s *Server) handleSearchGroupIP(w http.ResponseWriter, r *http.Request) {
	idx, ok := s.historyGroup(w, r)
	if !ok {
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("ip")))
	if len(q) < 3 {
		respondError(w, http.StatusBadRequest, "enter at least 3 characters")
		return
	}
	g := &s.cfg.ProxyGroups[idx]
	match := func(host, user, ext string) bool {
		return strings.Contains(strings.ToLower(ext), q) || strings.Contains(strings.ToLower(host), q) || strings.Contains(strings.ToLower(user), q)
	}
	type hit struct {
		Where      string `json:"where"` // "current" or "history"
		SnapshotID string `json:"snapshot_id,omitempty"`
		At         int64  `json:"at,omitempty"`
		publicRow
	}
	const maxHits = 200
	hits := make([]hit, 0, 16)
	for i, row := range s.snapshotProxies(g.Name, g.Proxies, 0) {
		if match(row.Host, row.User, row.ExternalIP) {
			pr := toPublicRows([]histProxy{row})[0]
			pr.Index = i
			hits = append(hits, hit{Where: "current", publicRow: pr})
		}
	}
	for _, sn := range s.loadHistory(g.Name).Snapshots {
		for i, row := range sn.Proxies {
			if len(hits) >= maxHits {
				break
			}
			if match(row.Host, row.User, row.ExternalIP) {
				pr := toPublicRows([]histProxy{row})[0]
				pr.Index = i
				hits = append(hits, hit{Where: "history", SnapshotID: sn.ID, At: sn.At, publicRow: pr})
			}
		}
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{"hits": hits, "truncated": len(hits) >= maxHits})
}

func histToEntries(rows []histProxy) []config.ProxyEntry {
	out := make([]config.ProxyEntry, len(rows))
	for i, p := range rows {
		out[i] = config.ProxyEntry{
			Host: p.Host, Port: p.Port, User: p.User, Pass: p.Pass, Type: p.Type,
			Status: "unknown", ExternalIP: p.ExternalIP, Country: p.Country, IPv4Only: p.IPv4Only,
		}
	}
	return out
}

// replaceGroupProxies swaps in a new list for group idx, archiving the old
// one first when the group keeps history. On failure nothing is changed.
func (s *Server) replaceGroupProxies(idx int, proxies []config.ProxyEntry, reason string) error {
	g := s.cfg.ProxyGroups[idx]
	if m, ok := s.groupMapping(g.Name); ok {
		if capacity := m.PortEnd - m.PortStart + 1; len(proxies) > capacity {
			return fmt.Errorf("%d proxies do not fit in %d-%d (%d ports); widen the port range", len(proxies), m.PortStart, m.PortEnd, capacity)
		}
	}
	if g.KeepHistory {
		if err := s.pushHistory(g.Name, reason, s.snapshotProxies(g.Name, g.Proxies, 0)); err != nil {
			return fmt.Errorf("could not archive the current list: %w", err)
		}
	}
	prev := s.cfg.ProxyGroups
	groups := make([]config.ProxyGroup, len(prev))
	copy(groups, prev)
	g.Proxies = proxies
	groups[idx] = g
	s.cfg.ProxyGroups = groups
	if err := s.applyGroupChange(); err != nil {
		s.cfg.ProxyGroups = prev
		return err
	}
	return nil
}

// POST /api/groups/{name}/history/restore  {"id": "<snapshot>"}
// Makes a snapshot the live list again (the current list is archived).
func (s *Server) handleRestoreGroupHistory(w http.ResponseWriter, r *http.Request) {
	idx, ok := s.historyGroup(w, r)
	if !ok {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	name := s.cfg.ProxyGroups[idx].Name
	for _, sn := range s.loadHistory(name).Snapshots {
		if sn.ID != req.ID {
			continue
		}
		if err := s.replaceGroupProxies(idx, histToEntries(sn.Proxies), "restore"); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		respondJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "count": len(sn.Proxies)})
		return
	}
	respondError(w, http.StatusNotFound, "snapshot not found")
}

// POST /api/groups/{name}/attach  {"id": "<snapshot>", "index": 3, "output_port": 30007}
// Binds one proxy from history to one output port. Only that port changes:
// the proxy currently there (if any) is archived as a one-row snapshot.
func (s *Server) handleAttachHistoryProxy(w http.ResponseWriter, r *http.Request) {
	idx, ok := s.historyGroup(w, r)
	if !ok {
		return
	}
	var req struct {
		ID         string `json:"id"`
		Index      int    `json:"index"`
		OutputPort int    `json:"output_port"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	g := s.cfg.ProxyGroups[idx]

	var src *histProxy
	for _, sn := range s.loadHistory(g.Name).Snapshots {
		if sn.ID == req.ID {
			if req.Index < 0 || req.Index >= len(sn.Proxies) {
				respondError(w, http.StatusBadRequest, "row not found in snapshot")
				return
			}
			row := sn.Proxies[req.Index]
			src = &row
			break
		}
	}
	if src == nil {
		respondError(w, http.StatusNotFound, "snapshot not found")
		return
	}

	replaced, status, err := s.placeAtPort(idx, histToEntries([]histProxy{*src})[0], req.OutputPort)
	if err != nil {
		respondError(w, status, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"status": "ok", "output_port": req.OutputPort, "replaced": replaced,
	})
}

// POST /api/groups/{name}/check-ip
// Probes every proxy of the group now so public IPs are known before a
// list is archived. Runs without the config lock (network I/O).
func (s *Server) handleCheckGroupIP(w http.ResponseWriter, r *http.Request) {
	if s.healthChecker == nil || s.groupMgr == nil {
		respondError(w, http.StatusServiceUnavailable, "health checker unavailable")
		return
	}
	ptrs, ok := s.groupMgr.GroupProxies()[r.PathValue("name")]
	if !ok {
		respondError(w, http.StatusNotFound, "group not found")
		return
	}
	results := s.healthChecker.CheckProxies(ptrs)
	alive, withIP := 0, 0
	for _, res := range results {
		if res.NewStatus != "dead" {
			alive++
		}
		if res.ExternalIP != "" {
			withIP++
		}
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"checked": len(results), "alive": alive, "with_ip": withIP,
	})
}
