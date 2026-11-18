package api

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"time"

	"proxy-dispatcher/internal/config"
	"proxy-dispatcher/internal/security"
)

func (s *Server) handleGetWhitelist(w http.ResponseWriter, r *http.Request) {
	entries := s.whitelistMgr.GetEntries()
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"enabled":       s.cfg.Whitelist.Enabled,
		"entries":       entries,
		"auto_ban":      s.cfg.Whitelist.AutoBan,
		"count":         len(entries),
		"account_count": len(s.cfg.Whitelist.Accounts),
	})
}

// handleGetOutputAccounts lists the user/pass accounts accepted on output
// ports. Passwords are included: the operator hands them to clients.
func (s *Server) handleGetOutputAccounts(w http.ResponseWriter, r *http.Request) {
	accounts := append([]config.OutputAccount{}, s.cfg.Whitelist.Accounts...)
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"accounts":          accounts,
		"whitelist_enabled": s.cfg.Whitelist.Enabled,
	})
}

func validCredPart(v string, max int) bool {
	if v == "" || len(v) > max {
		return false
	}
	for _, c := range v {
		if c <= 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// handlePostOutputAccount adds an account, or updates the password/note of
// an existing one. An empty password generates a random one.
func (s *Server) handlePostOutputAccount(w http.ResponseWriter, r *http.Request) {
	var req config.OutputAccount
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	req.User = strings.TrimSpace(req.User)
	if !validCredPart(req.User, 64) || strings.Contains(req.User, ":") {
		respondError(w, http.StatusBadRequest, "user: 1-64 ky tu, khong chua dau cach hoac dau ':'")
		return
	}
	if req.Pass == "" {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			respondError(w, http.StatusInternalServerError, "could not generate password")
			return
		}
		req.Pass = hex.EncodeToString(b)
	}
	if !validCredPart(req.Pass, 128) {
		respondError(w, http.StatusBadRequest, "pass: toi da 128 ky tu, khong chua dau cach")
		return
	}

	prev := s.cfg.Whitelist.Accounts
	next := make([]config.OutputAccount, 0, len(prev)+1)
	updated := false
	for _, a := range prev {
		if a.User == req.User {
			a.Pass, a.Note = req.Pass, req.Note
			updated = true
		}
		next = append(next, a)
	}
	if !updated {
		if len(next) >= 1000 {
			respondError(w, http.StatusBadRequest, "too many accounts (max 1000)")
			return
		}
		req.CreatedAt = time.Now().Unix()
		next = append(next, req)
	}
	s.saveOutputAccounts(w, prev, next, req)
}

func (s *Server) handleDeleteOutputAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		User string `json:"user"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	prev := s.cfg.Whitelist.Accounts
	next := make([]config.OutputAccount, 0, len(prev))
	for _, a := range prev {
		if a.User != req.User {
			next = append(next, a)
		}
	}
	if len(next) == len(prev) {
		respondError(w, http.StatusNotFound, "account not found")
		return
	}
	s.saveOutputAccounts(w, prev, next, config.OutputAccount{User: req.User})
}

func (s *Server) saveOutputAccounts(w http.ResponseWriter, prev, next []config.OutputAccount, acc config.OutputAccount) {
	s.cfg.Whitelist.Accounts = next
	if err := config.SaveConfig(s.cfgPath, s.cfg); err != nil {
		s.cfg.Whitelist.Accounts = prev
		respondError(w, http.StatusInternalServerError, "save failed")
		return
	}
	s.whitelistMgr.SetAccounts(next)
	respondJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "account": acc})
}

func (s *Server) handlePostWhitelist(w http.ResponseWriter, r *http.Request) {
	var req config.WhitelistConfig
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	// Output accounts are managed by their own endpoints; this form does not
	// send them, so keep the stored ones.
	req.Accounts = s.cfg.Whitelist.Accounts
	if err := s.whitelistMgr.Reload(req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid whitelist: "+err.Error())
		return
	}
	s.cfg.Whitelist = req
	if s.bruteGuard != nil {
		// Auto-ban settings were persisted but never applied at runtime.
		s.bruteGuard.Reload(req.AutoBan)
	}
	s.unbanWhitelisted()
	if err := config.SaveConfig(s.cfgPath, s.cfg); err != nil {
		respondError(w, http.StatusInternalServerError, "save failed")
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type addWhitelistReq struct {
	IP           string `json:"ip"`
	Note         string `json:"note"`
	ExpiresInSec int64  `json:"expires_in_sec"`
}

func (s *Server) handleAddWhitelistIP(w http.ResponseWriter, r *http.Request) {
	var req addWhitelistReq
	if err := decodeJSON(r, &req); err != nil {
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
	s.unbanWhitelisted()
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
	var req removeWhitelistReq
	if err := decodeJSON(r, &req); err != nil {
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
	ips := []string{}
	for _, ip := range s.bruteGuard.GetBannedIPs() {
		// Whitelisted IPs must never appear banned — unban on sight.
		if s.whitelistMgr.Matches(ip) {
			s.bruteGuard.Unban(ip)
			continue
		}
		ips = append(ips, ip)
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{"ips": ips})
}

type banIPReq struct {
	IP string `json:"ip"`
}

func (s *Server) handleBanIP(w http.ResponseWriter, r *http.Request) {
	var req banIPReq
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	if net.ParseIP(req.IP) == nil {
		respondError(w, http.StatusBadRequest, "invalid IP")
		return
	}
	if s.whitelistMgr.Matches(req.IP) {
		respondError(w, http.StatusBadRequest, "IP is whitelisted — remove it from the whitelist first")
		return
	}
	s.bruteGuard.Ban(req.IP)
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleClearBanned(w http.ResponseWriter, r *http.Request) {
	n := s.bruteGuard.ClearBanned()
	respondJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "cleared": n})
}

// unbanWhitelisted lifts bans from any IP now covered by the whitelist.
func (s *Server) unbanWhitelisted() {
	for _, ip := range s.bruteGuard.GetBannedIPs() {
		if s.whitelistMgr.Matches(ip) {
			s.bruteGuard.Unban(ip)
		}
	}
}
