package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"proxy-dispatcher/internal/config"
	"proxy-dispatcher/internal/shopsocks5"
)

// Web-first sock fetching. When the website account is stored, socks are
// chosen from the website's list (exit IP known before paying, so IPs that
// are already known are skipped for free) and each chosen IP is then taken
// through the official API with ip_real. Whatever the website cannot give
// (not configured, captcha, error, not enough rows) is taken the plain API
// way, exactly as before.

const (
	// ssWebMaxPicks caps how many socks one request takes through the
	// website list: each one is a separate API call. The rest of a large
	// request goes through the bulk API.
	ssWebMaxPicks = 60
	// ssWebMaxPages caps list pages read per request.
	ssWebMaxPages = 6
	// ssWebMaxMisses stops the web path after this many chosen IPs in a row
	// could not be taken.
	ssWebMaxMisses = 4
	// ssWebPause is how long the website is left alone after it refused the
	// login or asked for a captcha: retrying at once risks an account lock.
	// It doubles with every refusal in a row, up to ssWebPauseMax.
	ssWebPause    = 15 * time.Minute
	ssWebPauseMax = 6 * time.Hour
	// ssWebRecentTTL is how long an IP that was already asked for is skipped.
	ssWebRecentTTL = 3 * time.Hour
)

// ssWebState is the website session shared by every fetch path.
type ssWebState struct {
	run sync.Mutex // one web-first fetch at a time

	mu          sync.Mutex
	key         string // account the session belongs to
	client      *shopsocks5.WebClient
	pausedUntil time.Time
	fails       int // refusals in a row
	lastErr     string
	lastOK      time.Time
	recent      map[string]time.Time
}

var ssWeb ssWebState

// reset forgets the session and any pause (the account was saved again).
func (w *ssWebState) reset() {
	w.mu.Lock()
	w.key, w.client, w.pausedUntil, w.lastErr, w.fails = "", nil, time.Time{}, "", 0
	w.mu.Unlock()
}

// status describes the web path for the panel.
func (w *ssWebState) status() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	switch {
	case time.Now().Before(w.pausedUntil):
		return fmt.Sprintf("tam dung den %s: %s", w.pausedUntil.Format("15:04"), w.lastErr)
	case w.lastErr != "":
		return "loi lan gan nhat: " + w.lastErr
	case !w.lastOK.IsZero():
		return "hoat dong, doc danh sach lan cuoi luc " + w.lastOK.Format("15:04")
	}
	return "chua dung lan nao"
}

func (w *ssWebState) fail(err error, pause bool) {
	w.mu.Lock()
	w.lastErr = err.Error()
	w.client = nil
	if pause {
		w.fails++
		w.pausedUntil = time.Now().Add(min(ssWebPause<<min(w.fails-1, 10), ssWebPauseMax))
	}
	w.mu.Unlock()
}

// claim reports whether ip was not asked for recently, and marks it.
func (w *ssWebState) claim(ip string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	if w.recent == nil {
		w.recent = make(map[string]time.Time)
	}
	if len(w.recent) > 4096 {
		for k, t := range w.recent {
			if now.Sub(t) > ssWebRecentTTL {
				delete(w.recent, k)
			}
		}
	}
	if t, ok := w.recent[ip]; ok && now.Sub(t) <= ssWebRecentTTL {
		return false
	}
	w.recent[ip] = now
	return true
}

// list reads one page, logging in when there is no session and once more
// when the stored session is no longer accepted.
func (w *ssWebState) list(ctx context.Context, c config.ShopSocks5Config, f shopsocks5.WebFilter) (*shopsocks5.WebPage, error) {
	key := c.BaseURL + "|" + c.WebUser + "|" + c.WebPass + "|" + c.WebTOTP
	w.mu.Lock()
	if w.key != key {
		w.key, w.client, w.pausedUntil, w.lastErr, w.fails = key, nil, time.Time{}, "", 0
	}
	if time.Now().Before(w.pausedUntil) {
		err := fmt.Errorf("web dang tam dung: %s", w.lastErr)
		w.mu.Unlock()
		return nil, err
	}
	cl := w.client
	w.mu.Unlock()

	fresh := false
	for {
		if cl == nil {
			cl = shopsocks5.NewWeb(c.BaseURL)
			cl.TOTPSecret = c.WebTOTP
			if err := cl.Login(ctx, c.WebUser, c.WebPass); err != nil {
				w.fail(err, ctx.Err() == nil)
				return nil, err
			}
			fresh = true
			w.mu.Lock()
			w.client = cl
			w.mu.Unlock()
		}
		page, err := cl.List(ctx, f)
		if err == nil {
			w.mu.Lock()
			w.lastOK, w.lastErr, w.fails = time.Now(), "", 0
			w.mu.Unlock()
			return page, nil
		}
		if ctx.Err() != nil {
			return nil, err
		}
		if fresh || errors.Is(err, shopsocks5.ErrWebCaptcha) {
			w.fail(err, true)
			return nil, err
		}
		cl = nil // the stored session probably expired: log in once more
	}
}

// webRowMatches re-checks a list row against the filter, in case the site
// ignores one of the filter parameters.
func webRowMatches(r shopsocks5.WebSock, f shopsocks5.WebFilter) bool {
	eq := func(want, got string) bool {
		want = strings.TrimSpace(want)
		return want == "" || strings.EqualFold(want, strings.TrimSpace(got))
	}
	return eq(f.Country, r.Country) && eq(f.State, r.State) && eq(f.City, r.City) &&
		eq(f.SockType, r.SockType) && (strings.TrimSpace(f.Level) == "" || strings.TrimSpace(f.Level) == strconv.Itoa(r.Level))
}

// fetchViaWeb takes up to qty socks chosen from the website list. It never
// fails: whatever it could not get is left to the caller's API fallback.
// spent counts every sock the API returned.
func fetchViaWeb(ctx context.Context, cl *shopsocks5.Client, c config.ShopSocks5Config, qty int, filters map[string]string, known map[string]bool, warn func(msg string, err error)) (out []shopsocks5.Sock, spent, dups int) {
	ssWeb.run.Lock()
	defer ssWeb.run.Unlock()

	want := min(qty, ssWebMaxPicks)
	f := shopsocks5.WebFilter{
		Country: filters["country"], State: filters["state"], City: filters["city"],
		SockType: filters["sock_type"], Level: filters["level"],
	}
	misses := 0
	for page := 1; page <= ssWebMaxPages && len(out) < want; page++ {
		f.Page = page
		pg, err := ssWeb.list(ctx, c, f)
		if err != nil {
			warn("shopsocks5 web list unavailable, using the plain API", err)
			return
		}
		for _, row := range pg.Socks {
			if len(out) >= want || ctx.Err() != nil {
				return
			}
			ip := row.IPReal
			if net.ParseIP(ip) == nil || !webRowMatches(row, f) || (known != nil && known[ip]) || !ssWeb.claim(ip) {
				continue
			}
			socks, err := cl.GetSocks(ctx, 1, map[string]string{"ip_real": ip})
			if err != nil || len(socks) == 0 {
				// Someone else took it, or the quota is gone; the fallback
				// reports the real reason if it is the latter.
				if misses++; misses >= ssWebMaxMisses {
					return
				}
				continue
			}
			misses = 0
			spent += len(socks)
			sk := socks[0]
			if sk.IPReal != ip {
				// The API did not honour ip_real: this sock was not chosen
				// and may not match the filter. Stop choosing on the web.
				dups++
				warn("shopsocks5 api returned another IP than the one chosen on the web", nil)
				return
			}
			if known != nil {
				known[ip] = true
			}
			out = append(out, sk)
		}
		if len(pg.Socks) == 0 || page*max(pg.PageSize, 1) >= pg.Total {
			return
		}
	}
	return
}

// fetchSocks is the one way every path takes socks: website list first when
// the website account is stored, the plain API for the rest. It returns
// like fetchUniqueSocks.
func (s *Server) fetchSocks(ctx context.Context, cl *shopsocks5.Client, qty int, filters map[string]string, known map[string]bool) (out []shopsocks5.Sock, spent, dups int, err error) {
	s.cfgMu.RLock()
	c := s.cfg.ShopSocks5
	s.cfgMu.RUnlock()
	if c.WebUser != "" && c.WebPass != "" && filters["ip_real"] == "" {
		out, spent, dups = fetchViaWeb(ctx, cl, c, qty, filters, known, func(msg string, e error) {
			if s.logger != nil {
				s.logger.Warn(msg, "error", e)
			}
			s.notifyProblem("web", 2*time.Hour, fmt.Sprintf("Lay sock qua web khong duoc, dang dung API du phong.\nLy do: %v", e))
		})
		if len(out) >= qty {
			return out, spent, dups, nil
		}
	}
	more, sp, du, e := fetchUniqueSocks(ctx, cl, qty-len(out), filters, known)
	out, spent, dups = append(out, more...), spent+sp, dups+du
	if e != nil && len(out) == 0 {
		return nil, spent, dups, e
	}
	return out, spent, dups, nil
}
