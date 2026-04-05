package api

import (
	"encoding/json"
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	if err := s.backupMgr.RestoreBackup(req.Filename); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.onConfigReload != nil {
		_ = s.onConfigReload()
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
	if s.onConfigReload != nil {
		_ = s.onConfigReload()
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "imported"})
}

func (s *Server) handleGetDNS(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, s.cfg.SystemConfig)
}

func (s *Server) handlePostDNS(w http.ResponseWriter, r *http.Request) {
	var req config.SystemConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	if s.dnsMgr == nil {
		respondError(w, http.StatusServiceUnavailable, "dns not enabled")
		return
	}
	respondJSON(w, http.StatusOK, s.dnsMgr.TestDNS(req.Domain))
}
