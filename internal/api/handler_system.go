package api

import (
	"net/http"

	"proxy-dispatcher/internal/config"
	"proxy-dispatcher/internal/system"
)

func (s *Server) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	info := system.GetSystemInfo(s.version, s.startTime.Unix())
	respondJSON(w, http.StatusOK, info)
}

func (s *Server) handleListBackups(w http.ResponseWriter, r *http.Request) {
	if s.backupMgr == nil {
		respondError(w, http.StatusServiceUnavailable, "backups not enabled")
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{"backups": s.backupMgr.ListBackups()})
}

func (s *Server) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	fn, err := s.backupMgr.CreateBackup()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"filename": fn})
}

type restoreReq struct {
	Filename string `json:"filename"`
}

func (s *Server) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	var req restoreReq
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	if err := s.backupMgr.RestoreBackup(req.Filename); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.adoptConfigFromDisk(); err != nil {
		respondError(w, http.StatusInternalServerError, "restored file but reload failed: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "restored"})
}

func (s *Server) handleDeleteBackup(w http.ResponseWriter, r *http.Request) {
	fn := r.PathValue("filename")
	if err := s.backupMgr.DeleteBackup(fn); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleExportConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="config-export.json"`)
	if err := s.backupMgr.ExportConfig(w); err != nil {
		s.logger.Warn("export failed", "error", err)
	}
}

func (s *Server) handleImportConfig(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		respondError(w, http.StatusBadRequest, "bad multipart")
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		respondError(w, http.StatusBadRequest, "no file")
		return
	}
	defer file.Close()
	if err := s.backupMgr.ImportConfig(file); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.adoptConfigFromDisk(); err != nil {
		respondError(w, http.StatusInternalServerError, "imported file but reload failed: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "imported"})
}

// adoptConfigFromDisk re-reads the config file that RestoreBackup/ImportConfig
// just wrote and makes it the live in-memory config. Without this the
// restored file is never used: every module keeps running on the stale
// *AppConfig, and the next SaveConfig from any handler overwrites the
// restored file with the old contents.
func (s *Server) adoptConfigFromDisk() error {
	fresh, err := config.LoadConfig(s.cfgPath)
	if err != nil {
		return err
	}
	*s.cfg = *fresh
	if s.userMgr != nil {
		s.userMgr.Reload(s.cfg.Users)
	}
	if s.tokenMgr != nil {
		s.tokenMgr.Reload(s.cfg.APITokens)
	}
	if s.onConfigReload != nil {
		return s.onConfigReload()
	}
	return nil
}

// handleResetPorts restarts all listeners and reloads runtime modules —
// one-click recovery when ports stop responding (e.g. upstream proxy died).
func (s *Server) handleResetPorts(w http.ResponseWriter, r *http.Request) {
	if s.onConfigReload == nil {
		respondError(w, http.StatusServiceUnavailable, "reload unavailable")
		return
	}
	if err := s.onConfigReload(); err != nil {
		respondError(w, http.StatusInternalServerError, "reset failed: "+err.Error())
		return
	}
	// Re-check proxy health in the background so alive/dead status refreshes.
	if s.healthChecker != nil {
		go s.healthChecker.CheckNow()
	}
	active := 0
	if s.listenerMg != nil {
		active = len(s.listenerMg.ActivePorts())
	}
	s.logger.Info("ports reset via API", "active_ports", active)
	respondJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "active_ports": active})
}

func (s *Server) handleGetDNS(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, s.cfg.SystemConfig)
}

func (s *Server) handlePostDNS(w http.ResponseWriter, r *http.Request) {
	var req config.SystemConfig
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	s.cfg.SystemConfig = req
	if s.dnsMgr != nil {
		s.dnsMgr.Reload(req)
	}
	_ = config.SaveConfig(s.cfgPath, s.cfg)
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type dnsTestReq struct {
	Domain string `json:"domain"`
}

func (s *Server) handleTestDNS(w http.ResponseWriter, r *http.Request) {
	var req dnsTestReq
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	if s.dnsMgr == nil {
		respondError(w, http.StatusServiceUnavailable, "dns not enabled")
		return
	}
	respondJSON(w, http.StatusOK, s.dnsMgr.TestDNS(req.Domain))
}
