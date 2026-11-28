package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"proxy-dispatcher/internal/config"
)

func TestNotifyProblem(t *testing.T) {
	var mu sync.Mutex
	var got []string
	done := make(chan struct{}, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Chat string `json:"chat_id"`
			Text string `json:"text"`
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &in)
		if r.URL.Path != "/botTOKEN/sendMessage" || in.Chat != "42" {
			io.WriteString(w, `{"ok":false,"description":"Unauthorized"}`)
			return
		}
		mu.Lock()
		got = append(got, in.Text)
		mu.Unlock()
		io.WriteString(w, `{"ok":true}`)
		done <- struct{}{}
	}))
	defer srv.Close()
	old := tgAPI
	tgAPI = srv.URL
	defer func() { tgAPI = old }()

	s := &Server{cfgMu: &sync.RWMutex{}, cfg: &config.AppConfig{ShopSocks5: config.ShopSocks5Config{TelegramToken: "TOKEN", TelegramChat: "42"}}}
	s.notifyProblem("t-key", time.Hour, "het luot")
	s.notifyProblem("t-key", time.Hour, "het luot lan nua") // same problem: not repeated
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("no message arrived")
	}
	select {
	case <-done:
		t.Fatal("the same problem was reported twice within its interval")
	case <-time.After(200 * time.Millisecond):
	}
	mu.Lock()
	if len(got) != 1 || !strings.Contains(got[0], "het luot") {
		t.Fatalf("got %q", got)
	}
	mu.Unlock()

	// A wrong token fails with Telegram's reason and without the token.
	err := sendTelegram(context.Background(), "SECRETBAD", "42", "x")
	if err == nil || !strings.Contains(err.Error(), "Unauthorized") || strings.Contains(err.Error(), "SECRETBAD") {
		t.Fatalf("got %v", err)
	}
	// Not configured: nothing is sent and nothing blocks.
	s2 := &Server{cfgMu: &sync.RWMutex{}, cfg: &config.AppConfig{}}
	s2.notifyProblem("t-other", time.Hour, "x")
}

func TestSendTelegramErrorHidesToken(t *testing.T) {
	old := tgAPI
	tgAPI = "http://127.0.0.1:1" // nothing listens here
	defer func() { tgAPI = old }()
	if err := sendTelegram(context.Background(), "SECRETBAD", "42", "x"); err == nil || strings.Contains(err.Error(), "SECRETBAD") {
		t.Fatalf("got %v", err)
	}
}
