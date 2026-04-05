package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"proxy-dispatcher/internal/config"
	"proxy-dispatcher/internal/parser"
)

func (s *Server) handleGetGroups(w http.ResponseWriter, r *http.Request) {
	type groupView struct {
		Name         string `json:"name"`
		RotationMode string `json:"rotation_mode"`
		ProxyCount   int    `json:"proxy_count"`
		AliveCount   int    `json:"alive_count"`
		PortRange    string `json:"port_range,omitempty"`
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
	var out []groupView
	for i := range s.cfg.ProxyGroups {
		g := &s.cfg.ProxyGroups[i]
		alive := 0
		for _, p := range g.Proxies {
			if p.Status != "dead" {
				alive++
			}
		}
		out = append(out, groupView{
			Name: g.Name, RotationMode: g.RotationMode,
			ProxyCount: len(g.Proxies), AliveCount: alive,
			PortRange: portRanges[g.Name],
		})
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"groups":        out,
		"port_mappings": s.cfg.PortMappings,
	})
}

func (s *Server) handlePostGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name         string `json:"name"`
		RotationMode string `json:"rotation_mode"`
		RawText      string `json:"raw_text"`
		ProxyType    string `json:"proxy_type"`
		StickyTTLSec int    `json:"sticky_ttl_sec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		respondError(w, http.StatusBadRequest, "name required")
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
	entries, _ := parser.ParseProxyList(req.RawText, req.ProxyType)
	g := config.ProxyGroup{
		Name: req.Name, Proxies: entries,
		RotationMode: req.RotationMode, StickyTTLSec: req.StickyTTLSec,
	}
	s.cfg.ProxyGroups = append(s.cfg.ProxyGroups, g)
	if err := config.SaveConfig(s.cfgPath, s.cfg); err != nil {
		respondError(w, http.StatusInternalServerError, "save failed")
		return
	}
	if s.groupMgr != nil {
		_ = s.groupMgr.Reload(s.cfg.ProxyGroups, s.cfg.PortMappings)
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "count": len(entries)})
}

func (s *Server) handlePutGroup(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var req struct {
		RotationMode string `json:"rotation_mode"`
		RawText      string `json:"raw_text"`
		ProxyType    string `json:"proxy_type"`
		StickyTTLSec int    `json:"sticky_ttl_sec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	for i := range s.cfg.ProxyGroups {
		if s.cfg.ProxyGroups[i].Name == name {
			if req.RotationMode != "" {
				s.cfg.ProxyGroups[i].RotationMode = req.RotationMode
			}
			if req.StickyTTLSec > 0 {
				s.cfg.ProxyGroups[i].StickyTTLSec = req.StickyTTLSec
			}
			if req.RawText != "" {
				ptype := req.ProxyType
				if ptype == "" {
					ptype = "http"
				}
				entries, _ := parser.ParseProxyList(req.RawText, ptype)
				s.cfg.ProxyGroups[i].Proxies = entries
			}
			if err := config.SaveConfig(s.cfgPath, s.cfg); err != nil {
				respondError(w, http.StatusInternalServerError, "save failed")
				return
			}
			if s.groupMgr != nil {
				_ = s.groupMgr.Reload(s.cfg.ProxyGroups, s.cfg.PortMappings)
			}
			respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
			return
		}
	}
	respondError(w, http.StatusNotFound, "group not found")
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	for _, m := range s.cfg.PortMappings {
		if m.GroupName == name {
			respondError(w, http.StatusBadRequest, "group still has port mappings")
			return
		}
	}
	found := false
	filtered := s.cfg.ProxyGroups[:0]
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
	s.cfg.ProxyGroups = filtered
	if err := config.SaveConfig(s.cfgPath, s.cfg); err != nil {
		respondError(w, http.StatusInternalServerError, "save failed")
		return
	}
	if s.groupMgr != nil {
		_ = s.groupMgr.Reload(s.cfg.ProxyGroups, s.cfg.PortMappings)
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleGetPortMappings(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{"mappings": s.cfg.PortMappings})
}

func (s *Server) handlePostPortMappings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mappings []config.PortMapping `json:"mappings"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	// Validate: group exists + no overlapping ranges.
	groupSet := make(map[string]bool)
	for _, g := range s.cfg.ProxyGroups {
		groupSet[g.Name] = true
	}
	seen := make(map[int]string)
	for _, m := range req.Mappings {
		if !groupSet[m.GroupName] {
			respondError(w, http.StatusBadRequest, "unknown group: "+m.GroupName)
			return
		}
		if m.PortEnd < m.PortStart {
			respondError(w, http.StatusBadRequest, "port_end < port_start")
			return
		}
		for p := m.PortStart; p <= m.PortEnd; p++ {
			if prev, ok := seen[p]; ok {
				respondError(w, http.StatusBadRequest, fmt.Sprintf("port %d overlaps (%s & %s)", p, prev, m.GroupName))
				return
			}
			seen[p] = m.GroupName
		}
	}
	s.cfg.PortMappings = req.Mappings
	if err := config.SaveConfig(s.cfgPath, s.cfg); err != nil {
		respondError(w, http.StatusInternalServerError, "save failed")
		return
	}
	if s.groupMgr != nil {
		_ = s.groupMgr.Reload(s.cfg.ProxyGroups, s.cfg.PortMappings)
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok — restart required for new ports"})
}

func (s *Server) handleGetImportSources(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{"sources": s.cfg.ImportSources})
}

func (s *Server) handlePostImportSources(w http.ResponseWriter, r *http.Request) {
	var req config.ImportSource
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
	filtered := s.cfg.ImportSources[:0]
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
