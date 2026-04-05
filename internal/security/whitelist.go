// Package security provides IP whitelisting and brute-force protection.
package security

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"proxy-dispatcher/internal/config"
)

// WhitelistManager enforces an IP whitelist on incoming connections.
type WhitelistManager struct {
	enabled    bool
	exactIPs   map[string]bool
	cidrNets   []*net.IPNet
	entries    []config.WhitelistEntry
	tempExpiry map[string]int64
	mu         sync.RWMutex
	logger     *slog.Logger
}

// NewWhitelistManager constructs and populates a WhitelistManager.
func NewWhitelistManager(cfg config.WhitelistConfig, logger *slog.Logger) (*WhitelistManager, error) {
	wm := &WhitelistManager{logger: logger}
	if err := wm.load(cfg); err != nil {
		return nil, err
	}
	return wm, nil
}

func (wm *WhitelistManager) load(cfg config.WhitelistConfig) error {
	exact := make(map[string]bool)
	var cidrs []*net.IPNet
	temp := make(map[string]int64)

	for _, e := range cfg.Entries {
		switch e.Type {
		case "cidr":
			_, ipnet, err := net.ParseCIDR(e.IP)
			if err != nil {
				return fmt.Errorf("invalid CIDR %q: %w", e.IP, err)
			}
			cidrs = append(cidrs, ipnet)
		default: // "single" or empty
			exact[e.IP] = true
		}
		if e.ExpiresAt > 0 {
			temp[e.IP] = e.ExpiresAt
		}
	}

	wm.enabled = cfg.Enabled
	wm.exactIPs = exact
	wm.cidrNets = cidrs
	wm.entries = append([]config.WhitelistEntry{}, cfg.Entries...)
	wm.tempExpiry = temp
	return nil
}

// IsAllowed checks whether clientIP passes the whitelist.
func (wm *WhitelistManager) IsAllowed(clientIP string) (bool, string) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	if !wm.enabled {
		return true, "whitelist disabled"
	}

	ip := stripPort(clientIP)
	now := time.Now().Unix()

	if wm.exactIPs[ip] {
		if exp, ok := wm.tempExpiry[ip]; ok && exp > 0 && now > exp {
			return false, "expired"
		}
		return true, "exact match"
	}

	parsed := net.ParseIP(ip)
	if parsed != nil {
		for _, cidr := range wm.cidrNets {
			if cidr.Contains(parsed) {
				return true, "cidr match"
			}
		}
	}

	return false, "not whitelisted"
}

// AddEntry adds an IP entry to the whitelist.
func (wm *WhitelistManager) AddEntry(entry config.WhitelistEntry) error {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	if entry.Type == "cidr" {
		if _, _, err := net.ParseCIDR(entry.IP); err != nil {
			return fmt.Errorf("invalid CIDR: %w", err)
		}
	} else if net.ParseIP(entry.IP) == nil {
		return fmt.Errorf("invalid IP: %s", entry.IP)
	}

	if entry.CreatedAt == 0 {
		entry.CreatedAt = time.Now().Unix()
	}
	if entry.Type == "" {
		entry.Type = "single"
	}

	wm.entries = append(wm.entries, entry)
	if entry.Type == "cidr" {
		_, ipnet, _ := net.ParseCIDR(entry.IP)
		wm.cidrNets = append(wm.cidrNets, ipnet)
	} else {
		wm.exactIPs[entry.IP] = true
	}
	if entry.ExpiresAt > 0 {
		wm.tempExpiry[entry.IP] = entry.ExpiresAt
	}
	return nil
}

// RemoveEntry removes an IP from the whitelist.
func (wm *WhitelistManager) RemoveEntry(ip string) error {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	found := false
	filtered := make([]config.WhitelistEntry, 0, len(wm.entries))
	for _, e := range wm.entries {
		if e.IP == ip {
			found = true
			continue
		}
		filtered = append(filtered, e)
	}
	if !found {
		return fmt.Errorf("entry not found: %s", ip)
	}
	wm.entries = filtered
	delete(wm.exactIPs, ip)
	delete(wm.tempExpiry, ip)

	// Rebuild CIDR list.
	wm.cidrNets = nil
	for _, e := range wm.entries {
		if e.Type == "cidr" {
			_, ipnet, _ := net.ParseCIDR(e.IP)
			wm.cidrNets = append(wm.cidrNets, ipnet)
		}
	}
	return nil
}

// Reload replaces the entire whitelist from config.
func (wm *WhitelistManager) Reload(cfg config.WhitelistConfig) error {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	return wm.load(cfg)
}

// CleanupExpired removes entries whose ExpiresAt has passed.
func (wm *WhitelistManager) CleanupExpired() {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	now := time.Now().Unix()
	filtered := make([]config.WhitelistEntry, 0, len(wm.entries))
	for _, e := range wm.entries {
		if e.ExpiresAt > 0 && now > e.ExpiresAt {
			delete(wm.exactIPs, e.IP)
			delete(wm.tempExpiry, e.IP)
			continue
		}
		filtered = append(filtered, e)
	}
	wm.entries = filtered
}

// GetEntries returns a copy of current whitelist entries.
func (wm *WhitelistManager) GetEntries() []config.WhitelistEntry {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	out := make([]config.WhitelistEntry, len(wm.entries))
	copy(out, wm.entries)
	return out
}

// GetClientIP extracts the real client IP from an HTTP request.
func GetClientIP(r *http.Request) string {
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		if i := strings.Index(xf, ","); i >= 0 {
			return stripPort(strings.TrimSpace(xf[:i]))
		}
		return stripPort(strings.TrimSpace(xf))
	}
	return stripPort(r.RemoteAddr)
}

func stripPort(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
