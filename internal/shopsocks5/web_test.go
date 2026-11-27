package shopsocks5

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeSite imitates the website endpoints the client uses.
type fakeSite struct {
	password  string
	captchaOK bool
	need2FA   bool
	blocked   bool

	mu          sync.Mutex
	listQueries []string
}

// queries reads what the list handler recorded (under the lock: the race
// detector does not see an HTTP round trip as synchronisation).
func (f *fakeSite) queries() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.listQueries...)
}

func (f *fakeSite) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/account/login", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var in map[string]interface{}
		if err := json.Unmarshal(raw, &in); err != nil {
			t.Errorf("login body is not JSON: %q", raw)
		}
		if r.Header.Get("X-Requested-With") != "XMLHttpRequest" {
			t.Errorf("login misses X-Requested-With")
		}
		switch {
		case f.blocked:
			io.WriteString(w, `{"status":"fail","is_block":1}`)
		case in["password"] != f.password:
			io.WriteString(w, `{"status":"fail","message":"Wrong password"}`)
		default:
			io.WriteString(w, `{"status":"success","response":{"token":"tok123","user_name":"u"}}`)
		}
	})
	mux.HandleFunc("/authenticator/checkVerify2faFrontend", func(w http.ResponseWriter, r *http.Request) {
		if f.need2FA {
			io.WriteString(w, `{"status":"fail"}`)
			return
		}
		io.WriteString(w, `{"status":"success"}`)
	})
	mux.HandleFunc("/profile/index", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("authorization") != "tok123" {
			io.WriteString(w, `{"status":"fail","message":"Please login"}`)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "response": map[string]interface{}{
			"user_name": "u", "plan_current_name": "DAILY 800", "plan_daily_limit": 800, "count": 12,
			"user_exdate": "03/12/2026, 7:53 AM", "is_verify_captcha": f.captchaOK,
		}})
	})
	mux.HandleFunc("/sock_list", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.listQueries = append(f.listQueries, r.URL.RawQuery)
		f.mu.Unlock()
		io.WriteString(w, `{"status":"success","total":10504,"current":3,"limit":20,"used_today":12,"response":[
			{"sock_id":15866752,"sock_ip":"136.***.***.***","ip_real":"136.34.191.210","sock_hostname":"Google Fiber Inc.",
			 "sock_zip":"64133","sock_city":"Kansas City","sock_states":"Missouri","sock_country":"US","score":0,"level":1,
			 "vpn":0,"sock_back_list":0,"type_sock":"residential","sock_times":"0h:0m:8s","sock_type":null}]}`)
	})
	return mux
}

func newWebTest(t *testing.T, f *fakeSite) *WebClient {
	t.Helper()
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	return NewWeb(srv.URL)
}

func TestWebLoginAndList(t *testing.T) {
	f := &fakeSite{password: "pw", captchaOK: true}
	c := newWebTest(t, f)
	ctx := context.Background()
	if _, err := c.List(ctx, WebFilter{}); !errors.Is(err, ErrWebNotLoggedIn) {
		t.Fatalf("List before login: got %v, want ErrWebNotLoggedIn", err)
	}
	if err := c.Login(ctx, "u@example.com", "pw"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if c.Token() != "tok123" {
		t.Fatalf("token = %q", c.Token())
	}
	page, err := c.List(ctx, WebFilter{Country: "us", SockType: "Residential", Level: "1", Page: 3})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if page.Total != 10504 || page.Page != 3 || page.UsedToday != 12 || len(page.Socks) != 1 {
		t.Fatalf("page = %+v", page)
	}
	s := page.Socks[0]
	if s.ID != 15866752 || s.IPReal != "136.34.191.210" || s.ISP != "Google Fiber Inc." || s.State != "Missouri" ||
		s.SockType != "residential" || s.Level != 1 || s.Score != 0 {
		t.Fatalf("sock = %+v", s)
	}
	q := f.queries()[0]
	for _, want := range []string{"sock_country=US", "type_sock=residential", "level=1", "current=3", "pageSize=20", "all=1", "authorization=tok123"} {
		if !strings.Contains(q, want) {
			t.Errorf("list query %q misses %q", q, want)
		}
	}
}

func TestWebLoginFailures(t *testing.T) {
	ctx := context.Background()

	c := newWebTest(t, &fakeSite{password: "pw"})
	err := c.Login(ctx, "u", "secret-wrong")
	if err == nil || !strings.Contains(err.Error(), "Wrong password") {
		t.Fatalf("wrong password: got %v", err)
	}
	if strings.Contains(err.Error(), "secret-wrong") {
		t.Fatalf("error leaks the password: %v", err)
	}

	c = newWebTest(t, &fakeSite{password: "pw", blocked: true})
	if err := c.Login(ctx, "u", "pw"); !errors.Is(err, ErrWebBlocked) {
		t.Fatalf("blocked: got %v", err)
	}

	c = newWebTest(t, &fakeSite{password: "pw", need2FA: true})
	if err := c.Login(ctx, "u", "pw"); !errors.Is(err, ErrWeb2FA) {
		t.Fatalf("2fa: got %v", err)
	}
	if c.Token() != "" {
		t.Fatalf("token kept after failed 2FA check")
	}
}

func TestWebListStopsAtCaptcha(t *testing.T) {
	f := &fakeSite{password: "pw", captchaOK: false}
	c := newWebTest(t, f)
	ctx := context.Background()
	if err := c.Login(ctx, "u", "pw"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := c.List(ctx, WebFilter{Country: "US"}); !errors.Is(err, ErrWebCaptcha) {
		t.Fatalf("got %v, want ErrWebCaptcha", err)
	}
	if len(f.queries()) != 0 {
		t.Fatalf("list was requested although the captcha is pending")
	}
}

func TestWebErrorsDoNotLeakToken(t *testing.T) {
	c := NewWeb("http://127.0.0.1:1") // nothing listens here
	c.SetToken("supersecrettoken")
	_, err := c.Profile(context.Background())
	if err == nil {
		t.Fatal("expected a connection error")
	}
	if strings.Contains(err.Error(), "supersecrettoken") {
		t.Fatalf("error leaks the session token: %v", err)
	}
}

func TestWebNonJSONReply(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, "<html>Just a moment...</html>")
	}))
	defer srv.Close()
	c := NewWeb(srv.URL)
	err := c.Login(context.Background(), "u", "pw")
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("got %v", err)
	}
}
