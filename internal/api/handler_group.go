package api

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"proxy-dispatcher/internal/config"
	"proxy-dispatcher/internal/parser"
)

// maxGroupPortRange caps how many ports a single group may reserve.
const maxGroupPortRange = 20000

// groupMapping returns the first port mapping bound to group name.
func (s *Server) groupMapping(name string) (config.PortMapping, bool) {
	for _, m := range s.cfg.PortMappings {
		if m.GroupName == name {
			return m, true
		}
	}
	return config.PortMapping{}, false
}

// checkPortRange validates [start,end] for group name against the legal
// port window, the web panel port and every other group's mappings.
func (s *Server) checkPortRange(name string, start, end int) error {
	if start < 1024 || end > 65535 {
		return fmt.Errorf("ports must be within 1024-65535")
	}
	if end < start {
		return fmt.Errorf("port_end (%d) < port_start (%d)", end, start)
	}
	if end-start+1 > maxGroupPortRange {
		return fmt.Errorf("range too large (max %d ports per group)", maxGroupPortRange)
	}
	if p := s.cfg.WebPanelPort; p >= start && p <= end {
		return fmt.Errorf("range %d-%d contains the web panel port %d", start, end, p)
	}
	for _, m := range s.cfg.PortMappings {
		if m.GroupName == name {
			continue
		}
		if !(end < m.PortStart || start > m.PortEnd) {
			return fmt.Errorf("range %d-%d overlaps group %q (%d-%d)", start, end, m.GroupName, m.PortStart, m.PortEnd)
		}
	}
	return nil
}

// setGroupMapping makes [start,end] the single mapping of group name.
func (s *Server) setGroupMapping(name string, start, end int) {
	out := make([]config.PortMapping, 0, len(s.cfg.PortMappings)+1)
	for _, m := range s.cfg.PortMappings {
		if m.GroupName != name {
			out = append(out, m)
		}
	}
	out = append(out, config.PortMapping{PortStart: start, PortEnd: end, GroupName: name})
	sort.Slice(out, func(i, j int) bool { return out[i].PortStart < out[j].PortStart })
	s.cfg.PortMappings = out
}

// removeGroupMappings drops every mapping bound to group name.
func (s *Server) removeGroupMappings(name string) {
	out := make([]config.PortMapping, 0, len(s.cfg.PortMappings))
	for _, m := range s.cfg.PortMappings {
		if m.GroupName != name {
			out = append(out, m)
		}
	}
	s.cfg.PortMappings = out
}

// applyGroupChange persists the config and applies groups, port mappings
// and listeners live (no restart needed).
func (s *Server) applyGroupChange() error {
	if err := config.SaveConfig(s.cfgPath, s.cfg); err != nil {
		return fmt.Errorf("save failed: %w", err)
	}
	if s.onConfigReload != nil {
		if err := s.onConfigReload(); err != nil {
			return fmt.Errorf("saved, but apply failed: %w", err)
		}
	} else if s.groupMgr != nil {
		if err := s.groupMgr.Reload(s.cfg.ProxyGroups, s.cfg.PortMappings); err != nil {
			return fmt.Errorf("saved, but apply failed: %w", err)
		}
	}
	if s.onConfigSave != nil {
		s.onConfigSave()
	}
	return nil
}

func proxyKey(p *config.ProxyEntry) string {
	return fmt.Sprintf("%s:%d:%s", p.Host, p.Port, p.User)
}

func validGroupName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, c := range name {
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'
		if !ok {
			return false
		}
	}
	return true
}

func (s *Server) handleGetGroups(w http.ResponseWriter, r *http.Request) {
	type groupView struct {
		Name         string `json:"name"`
		RotationMode string `json:"rotation_mode"`
		ProxyCount   int    `json:"proxy_count"`
		AliveCount   int    `json:"alive_count"`
		DeadCount    int    `json:"dead_count"`
		PortRange    string `json:"port_range,omitempty"`
		PortStart    int    `json:"port_start,omitempty"`
		PortEnd      int    `json:"port_end,omitempty"`
		Capacity     int    `json:"capacity"`
		Free         int    `json:"free"`
		KeepHistory  bool   `json:"keep_history"`
	}
	portRanges := make(map[string]string)
	for _, m := range s.cfg.PortMappings {
		r := fmt.Sprintf("%d-%d", m.PortStart, m.PortEnd)
		if existing, ok := portRanges[m.GroupName]; ok {
			portRanges[m.GroupName] = existing + "," + r
		} else {
			portRanges[m.GroupName] = r
		}
	}
	out := make([]groupView, 0, len(s.cfg.ProxyGroups))
	for i := range s.cfg.ProxyGroups {
		g := &s.cfg.ProxyGroups[i]
		dead := 0
		for _, p := range g.Proxies {
			if p.Status == "dead" {
				dead++
			}
		}
		gv := groupView{
			Name: g.Name, RotationMode: g.RotationMode,
			ProxyCount: len(g.Proxies), AliveCount: len(g.Proxies) - dead, DeadCount: dead,
			PortRange: portRanges[g.Name], KeepHistory: g.KeepHistory,
		}
		if m, ok := s.groupMapping(g.Name); ok {
			gv.PortStart, gv.PortEnd = m.PortStart, m.PortEnd
			gv.Capacity = m.PortEnd - m.PortStart + 1
			if gv.Capacity > len(g.Proxies) {
				gv.Free = gv.Capacity - len(g.Proxies)
			}
		}
		out = append(out, gv)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].PortStart == 0) != (out[j].PortStart == 0) {
			return out[i].PortStart != 0
		}
		return out[i].PortStart < out[j].PortStart
	})
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"groups":        out,
		"port_mappings": s.cfg.PortMappings,
		"vps_ip":        s.cfg.VpsIp,
	})
}

// handleGetGroupProxies lists a group's proxies with the output port each
// one is bound to (1:1 by position within the group's port range).
func (s *Server) handleGetGroupProxies(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	type row struct {
		Index      int    `json:"index"`
		Host       string `json:"host"`
		Port       int    `json:"port"`
		User       string `json:"user,omitempty"`
		Type       string `json:"type"`
		Status     string `json:"status"`
		LatencyMs  int64  `json:"latency_ms"`
		ExternalIP string `json:"external_ip,omitempty"`
		OutputPort int    `json:"output_port,omitempty"`
		OutputAddr string `json:"output_addr,omitempty"`
	}
	for i := range s.cfg.ProxyGroups {
		g := &s.cfg.ProxyGroups[i]
		if g.Name != name {
			continue
		}
		m, mapped := s.groupMapping(name)
		rows := make([]row, 0, len(g.Proxies))
		for j, p := range g.Proxies {
			if p.IsEmpty() {
				continue // unassigned port inside the range
			}
			rw := row{Index: j, Host: p.Host, Port: p.Port, User: p.User, Type: p.Type, Status: p.Status, LatencyMs: p.LatencyMs, ExternalIP: p.ExternalIP}
			if mapped && m.PortStart+j <= m.PortEnd {
				rw.OutputPort = m.PortStart + j
				rw.OutputAddr = fmt.Sprintf("%s:%d", s.cfg.VpsIp, rw.OutputPort)
			}
			rows = append(rows, rw)
		}
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"name": name, "vps_ip": s.cfg.VpsIp, "proxies": rows,
			"port_start": m.PortStart, "port_end": m.PortEnd,
			"keep_history": g.KeepHistory,
		})
		return
	}
	respondError(w, http.StatusNotFound, "group not found")
}

type groupReq struct {
	Name         string `json:"name"`
	RotationMode string `json:"rotation_mode"`
	RawText      string `json:"raw_text"`
	ProxyType    string `json:"proxy_type"`
	StickyTTLSec int    `json:"sticky_ttl_sec"`
	// PortStart/PortEnd reserve a port range for the group in the same call.
	// PortEnd may be omitted: the range is then sized to the proxy count.
	PortStart int `json:"port_start"`
	PortEnd   int `json:"port_end"`
	// Append adds RawText to the end of the list (existing proxies keep
	// their ports) instead of replacing it. PUT only.
	Append bool `json:"append"`
	// RemovePorts drops the group's port range. PUT only.
	RemovePorts bool `json:"remove_ports"`
	// KeepHistory turns list history on/off for the group ("session" group).
	KeepHistory *bool `json:"keep_history"`
}

func (s *Server) handlePostGroup(w http.ResponseWriter, r *http.Request) {
	var req groupReq
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if !validGroupName(req.Name) {
		respondError(w, http.StatusBadRequest, "name required: letters, digits, - _ . only (max 64)")
		return
	}
	for _, g := range s.cfg.ProxyGroups {
		if g.Name == req.Name {
			respondError(w, http.StatusBadRequest, "group name already exists")
			return
		}
	}
	if req.RotationMode == "" {
		req.RotationMode = "roundrobin"
	}
	if req.ProxyType == "" {
		req.ProxyType = "http"
	}
	entries, errs := parser.ParseProxyList(req.RawText, req.ProxyType)

	prevGroups, prevMappings := s.cfg.ProxyGroups, s.cfg.PortMappings
	if req.PortStart > 0 {
		end := req.PortEnd
		if end <= 0 {
			n := len(entries)
			if n == 0 {
				n = 1
			}
			end = req.PortStart + n - 1
		}
		if err := s.checkPortRange(req.Name, req.PortStart, end); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		if capacity := end - req.PortStart + 1; len(entries) > capacity {
			respondError(w, http.StatusBadRequest, fmt.Sprintf("%d proxies do not fit in %d-%d (%d ports)", len(entries), req.PortStart, end, capacity))
			return
		}
		s.setGroupMapping(req.Name, req.PortStart, end)
	}
	groups := make([]config.ProxyGroup, 0, len(s.cfg.ProxyGroups)+1)
	groups = append(groups, s.cfg.ProxyGroups...)
	groups = append(groups, config.ProxyGroup{
		Name: req.Name, Proxies: entries,
		RotationMode: req.RotationMode, StickyTTLSec: req.StickyTTLSec,
		KeepHistory: req.KeepHistory != nil && *req.KeepHistory,
	})
	s.cfg.ProxyGroups = groups
	if err := s.applyGroupChange(); err != nil {
		s.cfg.ProxyGroups, s.cfg.PortMappings = prevGroups, prevMappings
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "count": len(entries), "skipped": len(errs)})
}

func (s *Server) handlePutGroup(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var req groupReq
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	idx := -1
	for i := range s.cfg.ProxyGroups {
		if s.cfg.ProxyGroups[i].Name == name {
			idx = i
			break
		}
	}
	if idx < 0 {
		respondError(w, http.StatusNotFound, "group not found")
		return
	}

	// Work on a copy so a validation failure leaves the config untouched.
	g := s.cfg.ProxyGroups[idx]
	if req.RotationMode != "" {
		g.RotationMode = req.RotationMode
	}
	if req.StickyTTLSec > 0 {
		g.StickyTTLSec = req.StickyTTLSec
	}
	if req.KeepHistory != nil {
		g.KeepHistory = *req.KeepHistory
	}
	replaced := false
	added, skipped := 0, 0
	if strings.TrimSpace(req.RawText) != "" {
		ptype := req.ProxyType
		if ptype == "" {
			ptype = "http"
		}
		entries, errs := parser.ParseProxyList(req.RawText, ptype)
		skipped = len(errs)
		if req.Append {
			seen := make(map[string]bool, len(g.Proxies))
			merged := make([]config.ProxyEntry, 0, len(g.Proxies)+len(entries))
			for i := range g.Proxies {
				seen[proxyKey(&g.Proxies[i])] = true
				merged = append(merged, g.Proxies[i])
			}
			for i := range entries {
				k := proxyKey(&entries[i])
				if seen[k] {
					skipped++
					continue
				}
				seen[k] = true
				merged = append(merged, entries[i])
				added++
			}
			g.Proxies = merged
		} else {
			g.Proxies = entries
			added = len(entries)
			replaced = true
		}
	}

	prevGroups, prevMappings := s.cfg.ProxyGroups, s.cfg.PortMappings
	switch {
	case req.RemovePorts:
		s.removeGroupMappings(name)
	case req.PortStart > 0:
		end := req.PortEnd
		if end <= 0 {
			n := len(g.Proxies)
			if n == 0 {
				n = 1
			}
			end = req.PortStart + n - 1
		}
		if err := s.checkPortRange(name, req.PortStart, end); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.setGroupMapping(name, req.PortStart, end)
	}
	if m, ok := s.groupMapping(name); ok {
		if capacity := m.PortEnd - m.PortStart + 1; len(g.Proxies) > capacity {
			s.cfg.PortMappings = prevMappings
			respondError(w, http.StatusBadRequest, fmt.Sprintf("%d proxies do not fit in %d-%d (%d ports); widen the port range", len(g.Proxies), m.PortStart, m.PortEnd, capacity))
			return
		}
	}

	// Session groups: archive the outgoing list (with the port each proxy
	// held under the OLD mapping and its recorded public IP) before it is
	// replaced.
	if replaced && g.KeepHistory {
		old := s.cfg.ProxyGroups[idx]
		cur := s.cfg.PortMappings
		s.cfg.PortMappings = prevMappings
		rows := s.snapshotProxies(name, old.Proxies, 0)
		s.cfg.PortMappings = cur
		if err := s.pushHistory(name, "replace", rows); err != nil {
			s.cfg.PortMappings = prevMappings
			respondError(w, http.StatusInternalServerError, "could not archive the current list: "+err.Error())
			return
		}
	}

	groups := make([]config.ProxyGroup, len(s.cfg.ProxyGroups))
	copy(groups, s.cfg.ProxyGroups)
	groups[idx] = g
	s.cfg.ProxyGroups = groups
	if err := s.applyGroupChange(); err != nil {
		s.cfg.ProxyGroups, s.cfg.PortMappings = prevGroups, prevMappings
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"status": "ok", "count": len(g.Proxies), "added": added, "skipped": skipped,
	})
}

// handleDeleteGroup removes a group together with its port range.
func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	found := false
	filtered := make([]config.ProxyGroup, 0, len(s.cfg.ProxyGroups))
	for _, g := range s.cfg.ProxyGroups {
		if g.Name == name {
			found = true
			continue
		}
		filtered = append(filtered, g)
	}
	if !found {
		respondError(w, http.StatusNotFound, "group not found")
		return
	}
	prevGroups, prevMappings := s.cfg.ProxyGroups, s.cfg.PortMappings
	s.cfg.ProxyGroups = filtered
	s.removeGroupMappings(name)
	if err := s.applyGroupChange(); err != nil {
		s.cfg.ProxyGroups, s.cfg.PortMappings = prevGroups, prevMappings
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.removeHistory(name)
	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleGetPortMappings(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{"mappings": s.cfg.PortMappings})
}

func (s *Server) handlePostPortMappings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mappings []config.PortMapping `json:"mappings"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	// Validate: group exists + legal, non-overlapping ranges.
	groupSet := make(map[string]bool)
	for _, g := range s.cfg.ProxyGroups {
		groupSet[g.Name] = true
	}
	sorted := make([]config.PortMapping, len(req.Mappings))
	copy(sorted, req.Mappings)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].PortStart < sorted[j].PortStart })
	for i, m := range sorted {
		if !groupSet[m.GroupName] {
			respondError(w, http.StatusBadRequest, "unknown group: "+m.GroupName)
			return
		}
		if m.PortStart < 1024 || m.PortEnd > 65535 {
			respondError(w, http.StatusBadRequest, "ports must be within 1024-65535")
			return
		}
		if m.PortEnd < m.PortStart {
			respondError(w, http.StatusBadRequest, "port_end < port_start")
			return
		}
		if p := s.cfg.WebPanelPort; p >= m.PortStart && p <= m.PortEnd {
			respondError(w, http.StatusBadRequest, fmt.Sprintf("range %d-%d contains the web panel port %d", m.PortStart, m.PortEnd, p))
			return
		}
		if i > 0 && m.PortStart <= sorted[i-1].PortEnd {
			respondError(w, http.StatusBadRequest, fmt.Sprintf("range %d-%d overlaps (%s & %s)", m.PortStart, m.PortEnd, sorted[i-1].GroupName, m.GroupName))
			return
		}
	}
	prev := s.cfg.PortMappings
	s.cfg.PortMappings = sorted
	if err := s.applyGroupChange(); err != nil {
		s.cfg.PortMappings = prev
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleGetImportSources(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{"sources": s.cfg.ImportSources})
}

func (s *Server) handlePostImportSources(w http.ResponseWriter, r *http.Request) {
	var req config.ImportSource
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	if req.Name == "" || req.URL == "" || req.GroupName == "" {
		respondError(w, http.StatusBadRequest, "name, url, group_name required")
		return
	}
	if req.IntervalSec <= 0 {
		req.IntervalSec = 300
	}
	for i := range s.cfg.ImportSources {
		if s.cfg.ImportSources[i].Name == req.Name {
			s.cfg.ImportSources[i] = req
			_ = config.SaveConfig(s.cfgPath, s.cfg)
			respondJSON(w, http.StatusOK, map[string]string{"status": "updated"})
			return
		}
	}
	s.cfg.ImportSources = append(s.cfg.ImportSources, req)
	if err := config.SaveConfig(s.cfgPath, s.cfg); err != nil {
		respondError(w, http.StatusInternalServerError, "save failed")
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "created"})
}

func (s *Server) handleDeleteImportSource(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	filtered := make([]config.ImportSource, 0, len(s.cfg.ImportSources))
	for _, src := range s.cfg.ImportSources {
		if src.Name != name {
			filtered = append(filtered, src)
		}
	}
	s.cfg.ImportSources = filtered
	_ = config.SaveConfig(s.cfgPath, s.cfg)
	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleImportFetchNow(w http.ResponseWriter, r *http.Request) {
	if s.importer == nil {
		respondError(w, http.StatusServiceUnavailable, "importer unavailable")
		return
	}
	name := r.PathValue("name")
	n, err := s.importer.FetchNow(name)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{"fetched": n})
}

func (s *Server) handleGetRetry(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, s.cfg.RetryCfg)
}

func (s *Server) handlePostRetry(w http.ResponseWriter, r *http.Request) {
	var req config.RetryConfig
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	if req.MaxAttempts <= 0 {
		req.MaxAttempts = 1
	}
	s.cfg.RetryCfg = req
	_ = config.SaveConfig(s.cfgPath, s.cfg)
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
