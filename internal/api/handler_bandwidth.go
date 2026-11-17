package api

import (
	"net/http"

	"proxy-dispatcher/internal/config"
)

func (s *Server) handleGetBandwidthBudget(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, s.cfg.BandwidthBudget)
}

func (s *Server) handlePostBandwidthBudget(w http.ResponseWriter, r *http.Request) {
	var req config.BudgetConfig
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	s.cfg.BandwidthBudget = req
	s.budgetCtrl.Reload(req)
	if err := config.SaveConfig(s.cfgPath, s.cfg); err != nil {
		respondError(w, http.StatusInternalServerError, "save failed")
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleBandwidthStatus(w http.ResponseWriter, r *http.Request) {
	snap := s.tracker.GetSnapshot()
	budget := s.budgetCtrl.GetStatus()
	savingBytes := snap.TotalDirectBytes

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"daily_proxy_bytes":  snap.TotalProxyBytes,
		"daily_direct_bytes": snap.TotalDirectBytes,
		"total_proxy_reqs":   snap.TotalProxyReqs,
		"total_bypass_reqs":  snap.TotalBypassReqs,
		"total_blocked_reqs": snap.TotalBlockedReqs,
		"saving_today_bytes": savingBytes,
		"budget_percent":     budget.Percent,
		"budget_warning":     budget.IsWarning,
		"budget_exceeded":    budget.IsExceeded,
	})
}

func (s *Server) handleBandwidthSnapshot(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, s.tracker.GetSnapshot())
}

func (s *Server) handleBandwidthClear(w http.ResponseWriter, r *http.Request) {
	s.tracker.ResetAll()
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
