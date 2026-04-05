package api

import (
	"encoding/json"
	"net/http"

	"proxy-dispatcher/internal/auth"
)

type createUserReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if s.userMgr == nil {
		respondError(w, http.StatusServiceUnavailable, "users not enabled")
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{"users": s.userMgr.ListUsers()})
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	u, err := s.userMgr.CreateUser(req.Username, req.Password, req.Role)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.persistUsers()
	respondJSON(w, http.StatusOK, s.userMgr.GetSafeUser(u))
}

type updateUserReq struct {
	Password *string `json:"password,omitempty"`
	Role     *string `json:"role,omitempty"`
	Disabled *bool   `json:"disabled,omitempty"`
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req updateUserReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	if err := s.userMgr.UpdateUser(id, auth.UserUpdate{Password: req.Password, Role: req.Role, Disabled: req.Disabled}); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.persistUsers()
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.userMgr.DeleteUser(id); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.persistUsers()
	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
