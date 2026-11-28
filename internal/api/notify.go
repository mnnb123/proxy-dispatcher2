package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Telegram notices for problems an operator has to act on: socks cannot be
// taken (quota used up, provider error), auto-keep cannot keep its ports,
// the website path is refused (captcha, 2FA, locked account). They are
// separate from the traffic alerts of internal/report, which fire on every
// failed request and would flood a chat.

// tgAPI is the Telegram Bot API host; tests point it at a fake.
var tgAPI = "https://api.telegram.org"

var tgHTTP = &http.Client{Timeout: 10 * time.Second}

// sendTelegram posts one message. Its errors never contain the bot token.
func sendTelegram(ctx context.Context, token, chat, text string) error {
	if token == "" || chat == "" {
		return fmt.Errorf("chua nhap bot token va chat id Telegram")
	}
	if len(text) > 3500 {
		text = text[:3500] + "…"
	}
	body, _ := json.Marshal(map[string]interface{}{"chat_id": chat, "text": text, "disable_web_page_preview": true})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tgAPI+"/bot"+token+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("telegram: bad request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := tgHTTP.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // drop the URL: it carries the bot token
		}
		return fmt.Errorf("telegram: %w", err)
	}
	defer resp.Body.Close()
	var out struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if json.Unmarshal(raw, &out) != nil || !out.OK {
		if out.Description == "" {
			out.Description = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return fmt.Errorf("telegram: %s", out.Description)
	}
	return nil
}

// notifyGate remembers when each kind of problem was last reported.
var notifyGate = struct {
	mu   sync.Mutex
	last map[string]time.Time
}{last: map[string]time.Time{}}

// notifyProblem reports a problem to Telegram in the background, at most
// once per `every` for the same key. It takes the config read lock: call it
// only where the config lock is not held.
func (s *Server) notifyProblem(key string, every time.Duration, text string) {
	s.cfgMu.RLock()
	token, chat := s.cfg.ShopSocks5.TelegramToken, s.cfg.ShopSocks5.TelegramChat
	s.cfgMu.RUnlock()
	if token == "" || chat == "" {
		return
	}
	notifyGate.mu.Lock()
	if t, ok := notifyGate.last[key]; ok && time.Since(t) < every {
		notifyGate.mu.Unlock()
		return
	}
	notifyGate.last[key] = time.Now()
	notifyGate.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := sendTelegram(ctx, token, chat, "⚠️ proxy-dispatcher\n"+text); err != nil && s.logger != nil {
			s.logger.Warn("telegram notice not sent", "error", err)
		}
	}()
}

// POST /api/config/shopsocks5/notify-test — sends a test message with the
// stored bot token and chat id. Runs without the config lock.
func (s *Server) handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.RLock()
	token, chat := s.cfg.ShopSocks5.TelegramToken, s.cfg.ShopSocks5.TelegramChat
	s.cfgMu.RUnlock()
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := sendTelegram(ctx, token, chat, "✅ proxy-dispatcher: thong bao Telegram da hoat dong. Ban se nhan tin o day khi viec lay sock gap loi."); err != nil {
		respondError(w, http.StatusBadGateway, strings.TrimPrefix(err.Error(), "telegram: "))
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{"status": "ok"})
}
