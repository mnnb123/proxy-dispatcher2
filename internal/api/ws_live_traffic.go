package api

import (
	"encoding/json"
	"errors"
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

	client := report.NewWSClient(256)
	s.reportHub.RegisterClient(client)

	go s.wsWritePump(conn, client)
	go s.wsReadPump(conn, client)
}

// validateWSToken accepts only a fully authenticated session: a stage-1
// "totp" token (password only) or a TOTP-setup token must not be able to
// stream the access log.
func (s *Server) validateWSToken(token string) (string, error) {
	claims, err := auth.ValidateTokenClaims(token, s.jwtSecret())
	if err != nil {
		return "", err
	}
	if stage, _ := claims["stage"].(string); stage != "" && stage != "full" {
		return "", errors.New("incomplete login")
	}
	uname, _ := claims["username"].(string)
	if uname == "" {
		return "", errors.New("missing username")
	}
	if s.userMgr != nil {
		u := s.userMgr.GetUser(uname)
		if u == nil || u.Disabled {
			return "", errors.New("user unavailable")
		}
	}
	return uname, nil
}

func (s *Server) wsWritePump(conn *websocket.Conn, client *report.WSClient) {
	defer conn.Close()
	for msg := range client.Send {
		if f := client.GetFilter(); f != "" {
			if !strings.Contains(string(msg), f) {
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
			client.SetPaused(true)
		case "resume":
			client.SetPaused(false)
		case "filter":
			client.SetFilter(cmd.Filter)
		}
	}
}
