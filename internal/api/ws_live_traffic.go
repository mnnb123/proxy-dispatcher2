package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/websocket"

	"proxy-dispatcher/internal/auth"
	"proxy-dispatcher/internal/report"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

const maxWSClients = 10

// handleWSLiveTraffic upgrades to WebSocket for live traffic streaming.
// Auth via ?token= query param. Supports pause/resume/filter commands.
func (s *Server) handleWSLiveTraffic(w http.ResponseWriter, r *http.Request) {
	if s.reportHub == nil {
		http.Error(w, "reporting not available", http.StatusServiceUnavailable)
		return
	}

	// Auth check via query token.
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}
	if _, err := s.validateWSToken(token); err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	if s.reportHub.ClientCount() >= maxWSClients {
		http.Error(w, "max clients reached", http.StatusTooManyRequests)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Error("ws upgrade failed", "error", err)
		return
	}

	client := &report.WSClient{
		Send:   make(chan []byte, 256),
		Filter: "",
		Paused: false,
	}
	s.reportHub.RegisterClient(client)

	go s.wsWritePump(conn, client)
	go s.wsReadPump(conn, client)
}

func (s *Server) validateWSToken(token string) (string, error) {
	return auth.ValidateToken(token, s.cfg.JwtSecret)
}

func (s *Server) wsWritePump(conn *websocket.Conn, client *report.WSClient) {
	defer conn.Close()
	for msg := range client.Send {
		if client.Filter != "" {
			if !strings.Contains(string(msg), client.Filter) {
				continue
			}
		}
		if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			break
		}
	}
}

func (s *Server) wsReadPump(conn *websocket.Conn, client *report.WSClient) {
	defer func() {
		s.reportHub.UnregisterClient(client)
		conn.Close()
	}()
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}
		var cmd struct {
			Action string `json:"action"`
			Filter string `json:"filter,omitempty"`
		}
		if json.Unmarshal(msg, &cmd) != nil {
			continue
		}
		switch cmd.Action {
		case "pause":
			client.Paused = true
		case "resume":
			client.Paused = false
		case "filter":
			client.Filter = cmd.Filter
		}
	}
}
