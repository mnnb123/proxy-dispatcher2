package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"proxy-dispatcher/internal/config"
)

// External exclude list: a URL that returns IPs which must never be handed
// out again (e.g. IPs that already produced a lead elsewhere). Socks whose
// exit IP is on the list are dropped like duplicates when fetching from
// ShopSocks5.

const (
	exclTTL      = 30 * time.Second
	exclTimeout  = 15 * time.Second
	exclMaxBytes = 32 << 20
)

var exclCache struct {
	mu  sync.Mutex
	url string
	ips map[string]bool
	at  time.Time
}

// parseIPList extracts IPs from an exclude-list response. Accepted shapes:
// {"ips": ["1.2.3.4", ...]}, a JSON array of strings or of objects with an
// "ip" field, or plain text with one IP per line / comma separated.
func parseIPList(body []byte) map[string]bool {
	out := make(map[string]bool)
	add := func(v string) {
		if ip := net.ParseIP(strings.TrimSpace(v)); ip != nil {
			out[ip.String()] = true
		}
	}
	var addAny func(v interface{})
	addAny = func(v interface{}) {
		switch t := v.(type) {
		case string:
			add(t)
		case []interface{}:
			for _, e := range t {
				addAny(e)
			}
		case map[string]interface{}:
			if ip, ok := t["ip"].(string); ok {
				add(ip)
			}
		}
	}
	body = bytes.TrimSpace(bytes.TrimPrefix(body, []byte("\xef\xbb\xbf")))
	var doc interface{}
	if len(body) > 0 && (body[0] == '{' || body[0] == '[') && json.Unmarshal(body, &doc) == nil {
		if obj, ok := doc.(map[string]interface{}); ok {
			if ips, has := obj["ips"]; has {
				addAny(ips)
			} else {
				for _, v := range obj {
					if arr, isArr := v.([]interface{}); isArr {
						addAny(arr)
					}
				}
			}
		} else {
			addAny(doc)
		}
		return out
	}
	for _, f := range strings.FieldsFunc(string(body), func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ';' || r == ' ' || r == '\t'
	}) {
		add(f)
	}
	return out
}

func validExcludeURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("URL phai bat dau bang http:// hoac https://")
	}
	return nil
}

func downloadIPList(ctx context.Context, raw string) (map[string]bool, error) {
	ctx, cancel := context.WithTimeout(ctx, exclTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, exclMaxBytes))
	if err != nil {
		return nil, err
	}
	return parseIPList(body), nil
}

// excludedIPs returns the exclude list (nil when none is configured). The
// list is cached briefly; if a refresh fails, the last good copy of the
// same URL is used, and only with no copy at all is an error returned so
// the caller can refuse before quota is spent. The map is shared: callers
// must not modify it. Must be called without the config lock held.
func (s *Server) excludedIPs(ctx context.Context) (map[string]bool, error) {
	s.cfgMu.RLock()
	raw := s.cfg.ShopSocks5.ExcludeURL
	s.cfgMu.RUnlock()
	if raw == "" {
		return nil, nil
	}
	exclCache.mu.Lock()
	defer exclCache.mu.Unlock()
	if exclCache.url == raw && exclCache.ips != nil && time.Since(exclCache.at) < exclTTL {
		return exclCache.ips, nil
	}
	ips, err := downloadIPList(ctx, raw)
	if err != nil {
		if exclCache.url == raw && exclCache.ips != nil {
			s.logger.Warn("exclude list: refresh failed, using the previous copy", "error", err)
			return exclCache.ips, nil
		}
		return nil, fmt.Errorf("khong tai duoc danh sach IP loai tru: %v", err)
	}
	exclCache.url, exclCache.ips, exclCache.at = raw, ips, time.Now()
	return ips, nil
}

// ssKnown builds the set of IPs a fetch for group must not return: the
// external exclude list plus, when unique is set, the IPs the group has now
// and, with history, every IP it has had. nil means "no filtering". Must be
// called without the config lock.
func (s *Server) ssKnown(ctx context.Context, group string, unique, history bool) (map[string]bool, error) {
	excl, err := s.excludedIPs(ctx)
	if err != nil {
		return nil, err
	}
	if excl == nil && !unique {
		return nil, nil
	}
	known := make(map[string]bool, len(excl))
	for ip := range excl {
		known[ip] = true
	}
	if unique {
		s.cfgMu.RLock()
		for ip := range s.knownIPs(group, history) {
			known[ip] = true
		}
		s.cfgMu.RUnlock()
	}
	return known, nil
}

// GET /api/config/shopsocks5/exclude — the URL and how many IPs it lists now.
func (s *Server) handleGetExclude(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.RLock()
	raw := s.cfg.ShopSocks5.ExcludeURL
	s.cfgMu.RUnlock()
	out := map[string]interface{}{"url": raw}
	if raw != "" {
		if ips, err := s.excludedIPs(r.Context()); err != nil {
			out["error"] = err.Error()
		} else {
			out["count"] = len(ips)
		}
	}
	respondJSON(w, http.StatusOK, out)
}

// POST /api/config/shopsocks5/exclude  {"url": "https://..."}  ("" turns it off)
// The list must load before the URL is saved.
func (s *Server) handlePostExclude(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL string `json:"url"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	raw := strings.TrimSpace(req.URL)
	count := 0
	if raw != "" {
		if err := validExcludeURL(raw); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		ips, err := downloadIPList(r.Context(), raw)
		if err != nil {
			respondError(w, http.StatusBadGateway, fmt.Sprintf("khong tai duoc danh sach: %v", err))
			return
		}
		if len(ips) == 0 {
			respondError(w, http.StatusBadGateway, "URL khong tra ve IP nao (can JSON co truong \"ips\" hoac moi dong mot IP)")
			return
		}
		count = len(ips)
		exclCache.mu.Lock()
		exclCache.url, exclCache.ips, exclCache.at = raw, ips, time.Now()
		exclCache.mu.Unlock()
	}
	s.cfgMu.Lock()
	prev := s.cfg.ShopSocks5.ExcludeURL
	s.cfg.ShopSocks5.ExcludeURL = raw
	err := config.SaveConfig(s.cfgPath, s.cfg)
	if err != nil {
		s.cfg.ShopSocks5.ExcludeURL = prev
	}
	s.cfgMu.Unlock()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "save failed")
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "url": raw, "count": count})
}
