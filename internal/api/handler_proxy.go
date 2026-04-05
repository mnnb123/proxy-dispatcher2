package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"proxy-dispatcher/internal/config"
	"proxy-dispatcher/internal/parser"
)

func (s *Server) handleGetInput(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"input_type": s.cfg.InputType,
		"proxies":    s.cfg.InputProxies,
		"count":      len(s.cfg.InputProxies),
	})
}

type postInputReq struct {
	InputType string `json:"input_type"`
	RawText   string `json:"raw_text"`
}

func (s *Server) handlePostInput(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req postInputReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
	s.cfg.InputProxies = entries
	s.cfg.InputType = req.InputType
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
	respondJSON(w, http.StatusOK, map[string]int{"count": len(entries)})
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
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req postOutputReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
