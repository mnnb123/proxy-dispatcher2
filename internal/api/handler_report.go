package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"proxy-dispatcher/internal/config"
)

// GET /api/report/recent — recent log entries from ring buffer
func (s *Server) handleReportRecent(w http.ResponseWriter, r *http.Request) {
	if s.reportHub == nil {
		respondError(w, http.StatusServiceUnavailable, "reporting not available")
		return
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	entries := s.reportHub.Ring.GetRecent(limit)
	respondJSON(w, http.StatusOK, entries)
}

// GET /api/report/stats — ring buffer statistics
func (s *Server) handleReportStats(w http.ResponseWriter, r *http.Request) {
	if s.reportHub == nil {
		respondError(w, http.StatusServiceUnavailable, "reporting not available")
		return
	}
	stats := s.reportHub.Ring.Stats()
	respondJSON(w, http.StatusOK, stats)
}

// POST /api/report/clear — clear ring buffer
func (s *Server) handleReportClear(w http.ResponseWriter, r *http.Request) {
	if s.reportHub == nil {
		respondError(w, http.StatusServiceUnavailable, "reporting not available")
		return
	}
	s.reportHub.Ring.Clear()
	respondJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
}

// GET /api/report/chart/minute?domain=&last=60
func (s *Server) handleChartMinute(w http.ResponseWriter, r *http.Request) {
	if s.reportHub == nil {
		respondError(w, http.StatusServiceUnavailable, "reporting not available")
		return
	}
	domain := r.URL.Query().Get("domain")
	lastN := 60
	if v := r.URL.Query().Get("last"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			lastN = n
		}
	}
	points := s.reportHub.Agg.GetMinuteChart(domain, lastN)
	respondJSON(w, http.StatusOK, points)
}

// GET /api/report/chart/hour?domain=&last=24
func (s *Server) handleChartHour(w http.ResponseWriter, r *http.Request) {
	if s.reportHub == nil {
		respondError(w, http.StatusServiceUnavailable, "reporting not available")
		return
	}
	domain := r.URL.Query().Get("domain")
	lastN := 24
	if v := r.URL.Query().Get("last"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			lastN = n
		}
	}
	points := s.reportHub.Agg.GetHourlyChart(domain, lastN)
	respondJSON(w, http.StatusOK, points)
}

// GET /api/report/top-domains?granularity=minute&top=10
func (s *Server) handleTopDomains(w http.ResponseWriter, r *http.Request) {
	if s.reportHub == nil {
		respondError(w, http.StatusServiceUnavailable, "reporting not available")
		return
	}
	gran := r.URL.Query().Get("granularity")
	if gran == "" {
		gran = "minute"
	}
	topN := 10
	if v := r.URL.Query().Get("top"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			topN = n
		}
	}
	ranks := s.reportHub.Agg.GetTopDomains(gran, topN)
	respondJSON(w, http.StatusOK, ranks)
}

// GET /api/report/disk-usage
func (s *Server) handleDiskUsage(w http.ResponseWriter, r *http.Request) {
	if s.reportHub == nil {
		respondError(w, http.StatusServiceUnavailable, "reporting not available")
		return
	}
	info := s.reportHub.Disk.GetDiskUsage()
	respondJSON(w, http.StatusOK, info)
}

// GET /api/report/export-csv?date=2024-01-15
func (s *Server) handleExportCSV(w http.ResponseWriter, r *http.Request) {
	if s.reportHub == nil {
		respondError(w, http.StatusServiceUnavailable, "reporting not available")
		return
	}
	date := r.URL.Query().Get("date")
	if date == "" {
		respondError(w, http.StatusBadRequest, "date parameter required")
		return
	}
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=access-"+date+".csv")
	if err := s.reportHub.Disk.ExportCSV(date, w); err != nil {
		s.logger.Error("export csv error", "error", err)
	}
}

// GET /api/report/alerts?limit=50
func (s *Server) handleGetAlerts(w http.ResponseWriter, r *http.Request) {
	if s.reportHub == nil {
		respondError(w, http.StatusServiceUnavailable, "reporting not available")
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	alerts := s.reportHub.AlertMgr.GetAlerts(limit)
	respondJSON(w, http.StatusOK, alerts)
}

// POST /api/report/alerts/clear
func (s *Server) handleClearAlerts(w http.ResponseWriter, r *http.Request) {
	if s.reportHub == nil {
		respondError(w, http.StatusServiceUnavailable, "reporting not available")
		return
	}
	s.reportHub.AlertMgr.ClearAlerts()
	respondJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
}

// POST /api/report/config — update ring buffer config
func (s *Server) handlePostReportConfig(w http.ResponseWriter, r *http.Request) {
	if s.reportHub == nil {
		respondError(w, http.StatusServiceUnavailable, "reporting not available")
		return
	}
	var req struct {
		RingBufferMaxRows int  `json:"ring_buffer_max_rows"`
		AutoClearSeconds  int  `json:"auto_clear_seconds"`
		AutoClearEnabled  bool `json:"auto_clear_enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid json")
		return
	}
	autoClear := 0
	if req.AutoClearEnabled {
		autoClear = req.AutoClearSeconds
	}
	if req.RingBufferMaxRows > 0 {
		s.reportHub.Ring.UpdateConfig(req.RingBufferMaxRows, autoClear)
	}
	s.cfg.Report.RingBufferMaxRows = req.RingBufferMaxRows
	s.cfg.Report.AutoClearEnabled = req.AutoClearEnabled
	s.cfg.Report.AutoClearSeconds = req.AutoClearSeconds
	config.SaveConfig(s.cfgPath, s.cfg)
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
