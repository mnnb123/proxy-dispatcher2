package api

import (
	"encoding/json"
	"net/http"
)

type createTokenReq struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
	ExpiresAt   int64    `json:"expires_at"`
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	if s.tokenMgr == nil {
		respondError(w, http.StatusServiceUnavailable, "tokens not enabled")
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{"tokens": s.tokenMgr.ListTokens()})
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var req createTokenReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	actx := GetAuthContext(r)
	createdBy := ""
	if actx != nil {
		createdBy = actx.Username
	}
	raw, t, err := s.tokenMgr.CreateToken(req.Name, req.Permissions, req.ExpiresAt, createdBy)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.persistTokens()
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"token":       raw,
		"id":          t.ID,
		"name":        t.Name,
		"permissions": t.Permissions,
	})
}

func (s *Server) handleDeleteToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.tokenMgr.RevokeToken(id); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.persistTokens()
	respondJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}
