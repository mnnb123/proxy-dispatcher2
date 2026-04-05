package api

import (
	"encoding/json"
	"net/http"

	"proxy-dispatcher/internal/config"
)

func (s *Server) handleGetHealthConfig(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, s.cfg.HealthCheck)
}

func (s *Server) handlePostHealthConfig(w http.ResponseWriter, r *http.Request) {
	var req config.HealthCheckConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	if req.IntervalSec <= 0 {
		req.IntervalSec = 30
	}
	if req.TimeoutSec <= 0 {
		req.TimeoutSec = 5
	}
	if req.MaxConcurrent <= 0 {
		req.MaxConcurrent = 20
	}
	s.cfg.HealthCheck = req
	if err := config.SaveConfig(s.cfgPath, s.cfg); err != nil {
		respondError(w, http.StatusInternalServerError, "save failed")
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleHealthStatus(w http.ResponseWriter, r *http.Request) {
	if s.groupMgr == nil {
		respondError(w, http.StatusServiceUnavailable, "group manager unavailable")
		return
	}
	type proxyView struct {
		Host        string  `json:"host"`
		Port        int     `json:"port"`
		Status      string  `json:"status"`
		Latency     int64   `json:"latency_ms"`
		AvgLatency  int64   `json:"avg_latency"`
		SuccessRate float64 `json:"success_rate"`
		Weight      int     `json:"weight"`
		ActiveConns int32   `json:"active_conns"`
		ExternalIP  string  `json:"external_ip,omitempty"`
	}
	type groupView struct {
		Name    string      `json:"name"`
		Alive   int         `json:"alive"`
		Slow    int         `json:"slow"`
		Dead    int         `json:"dead"`
		Proxies []proxyView `json:"proxies"`
	}
	var out []groupView
	for _, g := range s.groupMgr.AllGroups() {
		gv := groupView{Name: g.Name}
		for _, p := range g.Proxies {
			switch p.Status {
			case "alive":
				gv.Alive++
			case "slow":
				gv.Slow++
			case "dead":
				gv.Dead++
			}
			gv.Proxies = append(gv.Proxies, proxyView{
				Host: p.Host, Port: p.Port, Status: p.Status,
				Latency: p.LatencyMs, AvgLatency: p.AvgLatency,
				SuccessRate: p.SuccessRate, Weight: p.Weight,
				ActiveConns: p.ActiveConns, ExternalIP: p.ExternalIP,
			})
		}
		out = append(out, gv)
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{"groups": out})
}

func (s *Server) handleHealthCheckNow(w http.ResponseWriter, r *http.Request) {
	if s.healthChecker == nil {
		respondError(w, http.StatusServiceUnavailable, "health checker unavailable")
		return
	}
	go s.healthChecker.CheckNow()
	respondJSON(w, http.StatusAccepted, map[string]string{"status": "triggered"})
}
