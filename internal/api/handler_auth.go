package api

import (
	"encoding/json"
	"net/http"
	"time"

	"proxy-dispatcher/internal/auth"
	"proxy-dispatcher/internal/config"
)

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// handleLogin performs stage-1 login: password → full JWT or totp-required token.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	ip := getClientIP(r)
	ok, remaining := s.limiter.CheckAllowed(ip)
	if !ok {
		respondJSON(w, http.StatusTooManyRequests, map[string]interface{}{
			"error":         "too many failed attempts",
			"retry_after_s": int(remaining.Seconds()),
		})
		return
	}

	var user *config.UserAccount
	if s.userMgr != nil {
		var err error
		user, err = s.userMgr.Authenticate(req.Username, req.Password)
		if err != nil {
			s.limiter.RecordFail(ip)
			respondError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
	} else {
		// Legacy fallback.
		if req.Username != s.cfg.AdminUser || !auth.VerifyPassword(req.Password, s.cfg.AdminPassHash) {
			s.limiter.RecordFail(ip)
			respondError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		user = &config.UserAccount{Username: req.Username, Role: "admin"}
	}
	s.limiter.RecordSuccess(ip)
	s.persistUsers()

	if user.TOTPEnabled {
		tmp, err := auth.GenerateTokenWithExtras(user.Username, s.cfg.JwtSecret, 5*time.Minute, map[string]interface{}{"stage": "totp"})
		if err != nil {
			respondError(w, http.StatusInternalServerError, "token error")
			return
		}
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"totp_required": true,
			"session_token": tmp,
		})
		return
	}
	tok, err := auth.GenerateTokenWithExtras(user.Username, s.cfg.JwtSecret, 24*time.Hour, map[string]interface{}{"stage": "full"})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "token error")
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"token":      tok,
		"expires_in": 86400,
		"role":       user.Role,
	})
}

type loginTOTPReq struct {
	SessionToken string `json:"session_token"`
	Code         string `json:"code"`
	Recovery     string `json:"recovery_code"`
}

// handleLoginTOTP performs stage-2 TOTP or recovery-code login.
func (s *Server) handleLoginTOTP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req loginTOTPReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	claims, err := auth.ValidateTokenClaims(req.SessionToken, s.cfg.JwtSecret)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "invalid session token")
		return
	}
	if stage, _ := claims["stage"].(string); stage != "totp" {
		respondError(w, http.StatusUnauthorized, "wrong stage")
		return
	}
	uname, _ := claims["username"].(string)
	user := s.userMgr.GetUser(uname)
	if user == nil {
		respondError(w, http.StatusUnauthorized, "user not found")
		return
	}
	secret := auth.DecryptTOTPSecret(user.TOTPSecret, s.cfg.JwtSecret)
	ok := false
	if req.Code != "" {
		ok = auth.ValidateTOTP(secret, req.Code)
	} else if req.Recovery != "" {
		var newHashes []string
		ok, newHashes = auth.ValidateRecoveryCode(req.Recovery, user.RecoveryCodes)
		if ok {
			_ = s.userMgr.MutateByID(user.ID, func(u *config.UserAccount) error {
				u.RecoveryCodes = newHashes
				return nil
			})
		}
	}
	if !ok {
		respondError(w, http.StatusUnauthorized, "invalid code")
		return
	}
	s.persistUsers()
	tok, err := auth.GenerateTokenWithExtras(uname, s.cfg.JwtSecret, 24*time.Hour, map[string]interface{}{"stage": "full"})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "token error")
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"token":      tok,
		"expires_in": 86400,
		"role":       user.Role,
	})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	actx := GetAuthContext(r)
	if actx == nil {
		// Legacy path.
		uname, _ := r.Context().Value(ctxKeyUser).(string)
		respondJSON(w, http.StatusOK, map[string]string{"username": uname})
		return
	}
	totpEnabled := false
	if s.userMgr != nil {
		if u := s.userMgr.GetUser(actx.Username); u != nil {
			totpEnabled = u.TOTPEnabled
		}
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"username":     actx.Username,
		"role":         actx.Role,
		"permissions":  actx.Permissions,
		"totp_enabled": totpEnabled,
	})
}

type changePassReq struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req changePassReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	actx := GetAuthContext(r)
	if actx == nil {
		// Legacy Phase 1 fallback.
		if !auth.VerifyPassword(req.OldPassword, s.cfg.AdminPassHash) {
			respondError(w, http.StatusUnauthorized, "wrong old password")
			return
		}
		if len(req.NewPassword) < 8 {
			respondError(w, http.StatusBadRequest, "password too short")
			return
		}
		h, _ := auth.HashPassword(req.NewPassword)
		s.cfg.AdminPassHash = h
		_ = config.SaveConfig(s.cfgPath, s.cfg)
		respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	if _, err := s.userMgr.Authenticate(actx.Username, req.OldPassword); err != nil {
		respondError(w, http.StatusUnauthorized, "wrong old password")
		return
	}
	u := s.userMgr.GetUser(actx.Username)
	if u == nil {
		respondError(w, http.StatusNotFound, "user not found")
		return
	}
	newPass := req.NewPassword
	if err := s.userMgr.UpdateUser(u.ID, auth.UserUpdate{Password: &newPass}); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.persistUsers()
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type totpSetupResp struct {
	Secret       string `json:"secret"`
	QRURL        string `json:"qr_url"`
	SessionToken string `json:"session_token"`
}

func (s *Server) handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	actx := GetAuthContext(r)
	if actx == nil {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	secret, err := auth.GenerateSecret()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "secret error")
		return
	}
	qr := auth.GenerateQRURL(secret, actx.Username, "ProxyDispatcher")
	session, err := auth.GenerateTokenWithExtras(actx.Username, s.cfg.JwtSecret, 10*time.Minute, map[string]interface{}{
		"stage":         "totp_setup",
		"pending_secret": secret,
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "token error")
		return
	}
	respondJSON(w, http.StatusOK, totpSetupResp{Secret: secret, QRURL: qr, SessionToken: session})
}

type totpConfirmReq struct {
	SessionToken string `json:"session_token"`
	Code         string `json:"code"`
}

func (s *Server) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	var req totpConfirmReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	claims, err := auth.ValidateTokenClaims(req.SessionToken, s.cfg.JwtSecret)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "invalid session")
		return
	}
	if stage, _ := claims["stage"].(string); stage != "totp_setup" {
		respondError(w, http.StatusUnauthorized, "wrong stage")
		return
	}
	uname, _ := claims["username"].(string)
	secret, _ := claims["pending_secret"].(string)
	if !auth.ValidateTOTP(secret, req.Code) {
		respondError(w, http.StatusUnauthorized, "invalid code")
		return
	}
	codes, hashes, err := auth.GenerateRecoveryCodes()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "codes error")
		return
	}
	u := s.userMgr.GetUser(uname)
	if u == nil {
		respondError(w, http.StatusNotFound, "user not found")
		return
	}
	enc := auth.EncryptTOTPSecret(secret, s.cfg.JwtSecret)
	if err := s.userMgr.MutateByID(u.ID, func(ua *config.UserAccount) error {
		ua.TOTPEnabled = true
		ua.TOTPSecret = enc
		ua.RecoveryCodes = hashes
		return nil
	}); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.persistUsers()
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"enabled":        true,
		"recovery_codes": codes,
	})
}

type totpDisableReq struct {
	Password string `json:"password"`
}

func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	actx := GetAuthContext(r)
	if actx == nil {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req totpDisableReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	if _, err := s.userMgr.Authenticate(actx.Username, req.Password); err != nil {
		respondError(w, http.StatusUnauthorized, "wrong password")
		return
	}
	u := s.userMgr.GetUser(actx.Username)
	if u == nil {
		respondError(w, http.StatusNotFound, "user not found")
		return
	}
	_ = s.userMgr.MutateByID(u.ID, func(ua *config.UserAccount) error {
		ua.TOTPEnabled = false
		ua.TOTPSecret = ""
		ua.RecoveryCodes = nil
		return nil
	})
	s.persistUsers()
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
