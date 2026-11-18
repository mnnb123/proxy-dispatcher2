package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"proxy-dispatcher/internal/shopsocks5"
)

// provider answers each all_plan call with the next IPs from a script.
func provider(t *testing.T, ips []string, calls *int) *shopsocks5.Client {
	t.Helper()
	next := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		qty, _ := strconv.Atoi(r.FormValue("qty"))
		var socks []map[string]interface{}
		for i := 0; i < qty && next < len(ips); i++ {
			socks = append(socks, map[string]interface{}{
				"sock_ip": fmt.Sprintf("10.0.0.%d:1080", next+1), "user_name": "u", "password": "p", "ip_real": ips[next],
			})
			next++
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "response": socks})
	}))
	t.Cleanup(srv.Close)
	return shopsocks5.New(srv.URL, "u", "t")
}

func ipsOf(socks []shopsocks5.Sock) []string {
	out := make([]string, len(socks))
	for i, s := range socks {
		out[i] = s.IPReal
	}
	return out
}

func TestFetchUniqueSocks(t *testing.T) {
	ctx := context.Background()

	t.Run("duplicates are dropped and refilled", func(t *testing.T) {
		calls := 0
		cl := provider(t, []string{"1.1.1.1", "9.9.9.9", "2.2.2.2", "2.2.2.2", "3.3.3.3"}, &calls)
		got, spent, dups, err := fetchUniqueSocks(ctx, cl, 3, nil, map[string]bool{"9.9.9.9": true})
		if err != nil || fmt.Sprint(ipsOf(got)) != "[1.1.1.1 2.2.2.2 3.3.3.3]" || spent != 5 || dups != 2 || calls != 3 {
			t.Fatalf("got %v spent=%d dups=%d calls=%d err=%v", ipsOf(got), spent, dups, calls, err)
		}
	})

	t.Run("gives up after the round limit", func(t *testing.T) {
		calls := 0
		cl := provider(t, []string{"9.9.9.9", "9.9.9.9", "9.9.9.9", "9.9.9.9", "5.5.5.5"}, &calls)
		got, spent, dups, err := fetchUniqueSocks(ctx, cl, 1, nil, map[string]bool{"9.9.9.9": true})
		if err != nil || len(got) != 0 || spent != ssUniqueRounds || dups != ssUniqueRounds || calls != ssUniqueRounds {
			t.Fatalf("got %v spent=%d dups=%d calls=%d err=%v", ipsOf(got), spent, dups, calls, err)
		}
	})

	t.Run("without the option: one call, duplicates kept", func(t *testing.T) {
		calls := 0
		cl := provider(t, []string{"9.9.9.9", "9.9.9.9", "1.1.1.1"}, &calls)
		got, spent, dups, err := fetchUniqueSocks(ctx, cl, 2, nil, nil)
		if err != nil || len(got) != 2 || spent != 2 || dups != 0 || calls != 1 {
			t.Fatalf("got %v spent=%d dups=%d calls=%d err=%v", ipsOf(got), spent, dups, calls, err)
		}
	})

	t.Run("empty stock stops the loop", func(t *testing.T) {
		calls := 0
		cl := provider(t, []string{"1.1.1.1"}, &calls)
		got, spent, _, err := fetchUniqueSocks(ctx, cl, 3, nil, map[string]bool{})
		if err != nil || len(got) != 1 || spent != 1 || calls != 2 {
			t.Fatalf("got %v spent=%d calls=%d err=%v", ipsOf(got), spent, calls, err)
		}
	})
}
