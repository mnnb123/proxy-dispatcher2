package api

import (
	"encoding/json"
	"net/http"
	"time"

	"proxy-dispatcher/internal/config"
	"proxy-dispatcher/internal/security"
)

func (s *Server) handleGetWhitelist(w http.ResponseWriter, r *http.Request) {
	entries := s.whitelistMgr.GetEntries()
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"enabled":  s.cfg.Whitelist.Enabled,
		"entries":  entries,
		"auto_ban": s.cfg.Whitelist.AutoBan,
		"count":    len(entries),
	})
}

func (s *Server) handlePostWhitelist(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req config.WhitelistConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	if err := s.whitelistMgr.Reload(req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid whitelist: "+err.Error())
		return
	}
	s.cfg.Whitelist = req
	if err := config.SaveConfig(s.cfgPath, s.cfg); err != nil {
		respondError(w, http.StatusInternalServerError, "save failed")
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type addWhitelistReq struct {
	IP          string `json:"ip"`
	Note        string `json:"note"`
	ExpiresInSec int64 `json:"expires_in_sec"`
}

func (s *Server) handleAddWhitelistIP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req addWhitelistReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	if req.IP == "" {
		respondError(w, http.StatusBadRequest, "ip required")
		return
	}
	entry := config.WhitelistEntry{
		IP:        req.IP,
		Type:      "single",
		Note:      req.Note,
		CreatedAt: time.Now().Unix(),
	}
	if req.ExpiresInSec > 0 {
		entry.ExpiresAt = time.Now().Unix() + req.ExpiresInSec
	}
	if err := s.whitelistMgr.AddEntry(entry); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.cfg.Whitelist.Entries = s.whitelistMgr.GetEntries()
	if err := config.SaveConfig(s.cfgPath, s.cfg); err != nil {
		respondError(w, http.StatusInternalServerError, "save failed")
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type removeWhitelistReq struct {
	IP string `json:"ip"`
}

func (s *Server) handleRemoveWhitelistIP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req removeWhitelistReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	if err := s.whitelistMgr.RemoveEntry(req.IP); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.cfg.Whitelist.Entries = s.whitelistMgr.GetEntries()
	if err := config.SaveConfig(s.cfgPath, s.cfg); err != nil {
		respondError(w, http.StatusInternalServerError, "save failed")
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleMyIP(w http.ResponseWriter, r *http.Request) {
	ip := security.GetClientIP(r)
	respondJSON(w, http.StatusOK, map[string]string{"ip": ip})
}

func (s *Server) handleBannedIPs(w http.ResponseWriter, r *http.Request) {
	ips := s.bruteGuard.GetBannedIPs()
	if ips == nil {
		ips = []string{}
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{"ips": ips})
}
