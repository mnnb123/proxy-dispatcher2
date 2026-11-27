package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"sync"
	"testing"

	"proxy-dispatcher/internal/config"
	"proxy-dispatcher/internal/shopsocks5"
)

// webSite fakes both the website (login, profile, list) and the API.
type webSite struct {
	mu        sync.Mutex
	rows      []map[string]interface{} // website list
	captchaOK bool
	gone      map[string]bool // IPs the API can no longer give
	logins    int
	byIP      []string // ip_real values the API was asked for
	bulk      int      // socks taken without ip_real
}

func (f *webSite) start(t *testing.T) (config.ShopSocks5Config, *shopsocks5.Client) {
	t.Helper()
	mux := http.NewServeMux()
	ok := func(w http.ResponseWriter, v map[string]interface{}) {
		v["status"] = "success"
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/account/login", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.logins++
		f.mu.Unlock()
		ok(w, map[string]interface{}{"response": map[string]interface{}{"token": "tok"}})
	})
	mux.HandleFunc("/authenticator/checkVerify2faFrontend", func(w http.ResponseWriter, r *http.Request) {
		ok(w, map[string]interface{}{})
	})
	mux.HandleFunc("/profile/index", func(w http.ResponseWriter, r *http.Request) {
		ok(w, map[string]interface{}{"response": map[string]interface{}{"is_verify_captcha": f.captchaOK}})
	})
	mux.HandleFunc("/sock_list", func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("current"))
		var rows []map[string]interface{}
		if page == 1 {
			rows = f.rows
		}
		ok(w, map[string]interface{}{"response": rows, "total": len(f.rows), "current": page, "limit": 20})
	})
	mux.HandleFunc("/socks/all_plan", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		qty, _ := strconv.Atoi(r.FormValue("qty"))
		var socks []map[string]interface{}
		if ip := r.FormValue("ip_real"); ip != "" {
			f.byIP = append(f.byIP, ip)
			if f.gone[ip] {
				io.WriteString(w, `{"success":false,"message":"Socks not found"}`)
				return
			}
			socks = append(socks, map[string]interface{}{"sock_ip": "10.1.0.1:1080", "user_name": "u", "password": "p", "ip_real": ip})
		} else {
			for i := 0; i < qty; i++ {
				f.bulk++
				socks = append(socks, map[string]interface{}{"sock_ip": "10.2.0.1:1080", "user_name": "u", "password": "p", "ip_real": "9.9.9." + strconv.Itoa(f.bulk)})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "response": socks})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	ssWeb.reset()
	ssWeb.mu.Lock()
	ssWeb.recent = nil
	ssWeb.mu.Unlock()
	return config.ShopSocks5Config{UserName: "u", APIToken: "t", BaseURL: srv.URL, WebUser: "w", WebPass: "pw"},
		shopsocks5.New(srv.URL, "u", "t")
}

func webRow(ip, country string) map[string]interface{} {
	return map[string]interface{}{"ip_real": ip, "sock_country": country, "type_sock": "residential", "level": 1}
}

func TestFetchSocksWebFirst(t *testing.T) {
	ctx := context.Background()
	filters := map[string]string{"country": "US", "sock_type": "residential", "level": "1"}

	t.Run("picks from the web list, skips known and unmatched rows for free", func(t *testing.T) {
		f := &webSite{captchaOK: true, gone: map[string]bool{"1.1.1.3": true}, rows: []map[string]interface{}{
			webRow("1.1.1.1", "US"), // already known
			webRow("1.1.1.2", "DE"), // the site ignored the country filter
			webRow("1.1.1.3", "US"), // gone when asked for
			webRow("1.1.1.4", "US"),
			webRow("1.1.1.5", "US"),
			webRow("1.1.1.6", "US"),
		}}
		c, cl := f.start(t)
		s := &Server{cfg: &config.AppConfig{ShopSocks5: c}, cfgMu: &sync.RWMutex{}}
		known := map[string]bool{"1.1.1.1": true}
		got, spent, dups, err := s.fetchSocks(ctx, cl, 2, filters, known)
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"1.1.1.4", "1.1.1.5"}; !reflect.DeepEqual(ipsOf(got), want) {
			t.Fatalf("got %v, want %v", ipsOf(got), want)
		}
		if spent != 2 || dups != 0 || f.bulk != 0 {
			t.Fatalf("spent=%d dups=%d bulk=%d, want 2/0/0", spent, dups, f.bulk)
		}
		if want := []string{"1.1.1.3", "1.1.1.4", "1.1.1.5"}; !reflect.DeepEqual(f.byIP, want) {
			t.Fatalf("api asked for %v, want %v", f.byIP, want)
		}
		if !known["1.1.1.4"] || !known["1.1.1.5"] {
			t.Fatalf("taken IPs were not added to known: %v", known)
		}
		// The session is reused: a second fetch does not log in again and
		// does not ask for IPs it already asked for.
		got, _, _, err = s.fetchSocks(ctx, cl, 1, filters, known)
		if err != nil || len(got) != 1 || got[0].IPReal != "1.1.1.6" || f.logins != 1 {
			t.Fatalf("second fetch: %v err=%v logins=%d", ipsOf(got), err, f.logins)
		}
	})

	t.Run("the API fills what the web list cannot give", func(t *testing.T) {
		f := &webSite{captchaOK: true, rows: []map[string]interface{}{webRow("2.2.2.1", "US")}}
		c, cl := f.start(t)
		s := &Server{cfg: &config.AppConfig{ShopSocks5: c}, cfgMu: &sync.RWMutex{}}
		got, spent, _, err := s.fetchSocks(ctx, cl, 3, filters, map[string]bool{})
		if err != nil || len(got) != 3 || spent != 3 || got[0].IPReal != "2.2.2.1" || f.bulk != 2 {
			t.Fatalf("got %v spent=%d bulk=%d err=%v", ipsOf(got), spent, f.bulk, err)
		}
	})

	t.Run("captcha: falls back to the API and leaves the site alone for a while", func(t *testing.T) {
		f := &webSite{captchaOK: false, rows: []map[string]interface{}{webRow("3.3.3.1", "US")}}
		c, cl := f.start(t)
		s := &Server{cfg: &config.AppConfig{ShopSocks5: c}, cfgMu: &sync.RWMutex{}}
		for i := 0; i < 2; i++ {
			got, _, _, err := s.fetchSocks(ctx, cl, 1, filters, nil)
			if err != nil || len(got) != 1 || len(f.byIP) != 0 {
				t.Fatalf("round %d: got %v byIP=%v err=%v", i, ipsOf(got), f.byIP, err)
			}
		}
		if f.logins != 1 || f.bulk != 2 {
			t.Fatalf("logins=%d bulk=%d, want 1 login (paused after the captcha) and 2 API socks", f.logins, f.bulk)
		}
	})

	t.Run("no website account, or a specific ip_real: plain API only", func(t *testing.T) {
		f := &webSite{captchaOK: true, rows: []map[string]interface{}{webRow("4.4.4.1", "US")}}
		c, cl := f.start(t)
		s := &Server{cfg: &config.AppConfig{ShopSocks5: c}, cfgMu: &sync.RWMutex{}}
		if got, _, _, err := s.fetchSocks(ctx, cl, 1, map[string]string{"ip_real": "7.7.7.7"}, nil); err != nil || got[0].IPReal != "7.7.7.7" {
			t.Fatalf("ip_real: %v %v", ipsOf(got), err)
		}
		c.WebPass = ""
		s = &Server{cfg: &config.AppConfig{ShopSocks5: c}, cfgMu: &sync.RWMutex{}}
		if got, _, _, err := s.fetchSocks(ctx, cl, 1, filters, nil); err != nil || len(got) != 1 || f.bulk != 1 {
			t.Fatalf("no web account: %v bulk=%d %v", ipsOf(got), f.bulk, err)
		}
		if f.logins != 0 {
			t.Fatalf("the website was contacted %d times", f.logins)
		}
	})
}
