package api

import (
	"fmt"
	"net/http"
	"time"

	"proxy-dispatcher/internal/config"
	"proxy-dispatcher/internal/parser"
)

func (s *Server) handleGetInput(w http.ResponseWriter, r *http.Request) {
	// Build 1:1 mapping table: each input proxy → its output port
	proxies := s.cfg.InputProxies
	type proxyRow struct {
		Host       string `json:"host"`
		Port       int    `json:"port"`
		User       string `json:"user,omitempty"`
		Pass       string `json:"pass,omitempty"`
		Type       string `json:"type"`
		OutputPort int    `json:"output_port"`
		OutputAddr string `json:"output_addr"`
	}
	rows := make([]proxyRow, 0, len(proxies))
	for i, p := range proxies {
		outPort := s.cfg.OutputStartPort + i
		rows = append(rows, proxyRow{
			Host:       p.Host,
			Port:       p.Port,
			User:       p.User,
			Pass:       p.Pass,
			Type:       p.Type,
			OutputPort: outPort,
			OutputAddr: fmt.Sprintf("%s:%d", s.cfg.VpsIp, outPort),
		})
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"input_type":    s.cfg.InputType,
		"proxies":       s.cfg.InputProxies,
		"mapping":       rows,
		"vps_ip":        s.cfg.VpsIp,
		"start_port":    s.cfg.OutputStartPort,
		"count":         len(proxies),
		"rotation_mode": s.cfg.RotationMode,
	})
}

type postInputReq struct {
	InputType    string `json:"input_type"`
	RawText      string `json:"raw_text"`
	VpsIp        string `json:"vps_ip"`
	StartPort    int    `json:"start_port"`
	RotationMode string `json:"rotation_mode"`
}

func (s *Server) handlePostInput(w http.ResponseWriter, r *http.Request) {
	var req postInputReq
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	if req.InputType != "http" && req.InputType != "socks5" {
		respondError(w, http.StatusBadRequest, "input_type must be http or socks5")
		return
	}
	entries, errs := parser.ParseProxyList(req.RawText, req.InputType)
	if len(errs) > 0 {
		respondJSON(w, http.StatusBadRequest, map[string]interface{}{"errors": errs})
		return
	}

	// The Proxy tab manages only the "default" group. Its port range must
	// not collide with the other (per-country) groups.
	startPort := s.cfg.OutputStartPort
	if req.StartPort >= 1024 && req.StartPort <= 65535 {
		startPort = req.StartPort
	}
	if len(entries) > 0 {
		if err := s.checkPortRange("default", startPort, startPort+len(entries)-1); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	// Update VPS IP if provided.
	if req.VpsIp != "" {
		s.cfg.VpsIp = req.VpsIp
	}
	s.cfg.OutputStartPort = startPort

	// 1:1 mapping: output count = input proxy count.
	s.cfg.InputProxies = entries
	s.cfg.InputType = req.InputType
	s.cfg.OutputCount = len(entries)

	// Update rotation mode if provided in request.
	if req.RotationMode != "" {
		s.cfg.RotationMode = req.RotationMode
	}

	// Replace the "default" group + its port mapping, leaving every other
	// group untouched. (This used to overwrite ALL groups and mappings, so
	// saving the Proxy tab wiped any per-country groups.)
	others := make([]config.ProxyGroup, 0, len(s.cfg.ProxyGroups)+1)
	for _, g := range s.cfg.ProxyGroups {
		if g.Name != "default" {
			others = append(others, g)
		}
	}
	s.removeGroupMappings("default")
	if len(entries) > 0 {
		mode := s.cfg.RotationMode
		if mode == "" {
			mode = "roundrobin"
		}
		others = append([]config.ProxyGroup{{
			Name:         "default",
			Proxies:      entries,
			RotationMode: mode,
			StickyTTLSec: 300,
		}}, others...)
		s.setGroupMapping("default", s.cfg.OutputStartPort, s.cfg.OutputStartPort+len(entries)-1)
	}
	s.cfg.ProxyGroups = others

	// Update rotator if available (legacy).
	if s.rotator != nil {
		ptrs := make([]*config.ProxyEntry, len(entries))
		for i := range entries {
			ptrs[i] = &entries[i]
		}
		s.rotator.UpdateProxies(ptrs)
	}

	if err := config.SaveConfig(s.cfgPath, s.cfg); err != nil {
		respondError(w, http.StatusInternalServerError, "save failed")
		return
	}

	// Reload modules (groups, listeners, etc).
	if s.onConfigReload != nil {
		if err := s.onConfigReload(); err != nil {
			s.logger.Warn("config reload after input save", "error", err)
		}
	}
	if s.onConfigSave != nil {
		s.onConfigSave()
	}

	// Build output list for response.
	outputList := make([]string, len(entries))
	for i := range entries {
		outputList[i] = fmt.Sprintf("%s:%d", s.cfg.VpsIp, s.cfg.OutputStartPort+i)
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"count":       len(entries),
		"output_list": outputList,
	})
}

func (s *Server) handleGetOutput(w http.ResponseWriter, r *http.Request) {
	list := make([]string, 0, s.cfg.OutputCount)
	for i := 0; i < s.cfg.OutputCount; i++ {
		list = append(list, fmt.Sprintf("%s:%d", s.cfg.VpsIp, s.cfg.OutputStartPort+i))
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"vps_ip":     s.cfg.VpsIp,
		"start_port": s.cfg.OutputStartPort,
		"count":      s.cfg.OutputCount,
		"list":       list,
	})
}

type postOutputReq struct {
	VpsIp     string `json:"vps_ip"`
	StartPort int    `json:"start_port"`
	Count     int    `json:"count"`
}

func (s *Server) handlePostOutput(w http.ResponseWriter, r *http.Request) {
	var req postOutputReq
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	if req.Count <= 0 || req.Count > 500 {
		respondError(w, http.StatusBadRequest, "count must be 1-500")
		return
	}
	if req.StartPort < 1024 || req.StartPort > 65535 {
		respondError(w, http.StatusBadRequest, "start_port must be 1024-65535")
		return
	}
	if req.StartPort+req.Count-1 > 65535 {
		respondError(w, http.StatusBadRequest, "port range exceeds 65535")
		return
	}
	s.cfg.VpsIp = req.VpsIp
	s.cfg.OutputStartPort = req.StartPort
	s.cfg.OutputCount = req.Count
	if err := config.SaveConfig(s.cfgPath, s.cfg); err != nil {
		respondError(w, http.StatusInternalServerError, "save failed")
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(s.startTime).Seconds()
	ports := []int{}
	if s.listenerMg != nil {
		ports = s.listenerMg.ActivePorts()
	}
	alive := 0
	total := 0
	if s.groupMgr != nil {
		for _, g := range s.groupMgr.AllGroups() {
			total += len(g.Proxies)
			alive += g.Rotator.ActiveCount()
		}
	} else if s.rotator != nil {
		alive = s.rotator.ActiveCount()
		total = len(s.cfg.InputProxies)
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"uptime_s":     int(uptime),
		"proxy_count":  total,
		"alive_count":  alive,
		"active_ports": ports,
	})
}
