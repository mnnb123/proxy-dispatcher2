package api

import (
	"io"
	"net/http"
)

func (s *Server) handleSyncStatus(w http.ResponseWriter, r *http.Request) {
	out := map[string]interface{}{
		"role": s.cfg.SyncConfig.Role,
	}
	if s.syncMaster != nil {
		out["slaves"] = s.syncMaster.GetSlaveStatus()
	}
	if s.syncSlave != nil {
		last, sum := s.syncSlave.GetSyncStatus()
		out["last_receive"] = last
		out["last_checksum"] = sum
	}
	respondJSON(w, http.StatusOK, out)
}

func (s *Server) handleSyncPush(w http.ResponseWriter, r *http.Request) {
	if s.syncMaster == nil {
		respondError(w, http.StatusBadRequest, "not a master node")
		return
	}
	results := s.syncMaster.PushToAll()
	respondJSON(w, http.StatusOK, map[string]interface{}{"results": results})
}

// handleSyncReceive is the slave endpoint. HMAC-authenticated.
func (s *Server) handleSyncReceive(w http.ResponseWriter, r *http.Request) {
	if s.syncSlave == nil {
		respondError(w, http.StatusBadRequest, "not a slave node")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	if err != nil {
		respondError(w, http.StatusBadRequest, "read error")
		return
	}
	sig := r.Header.Get("X-Sync-Signature")
	if err := s.syncSlave.HandleReceive(body, sig); err != nil {
		respondError(w, http.StatusUnauthorized, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
