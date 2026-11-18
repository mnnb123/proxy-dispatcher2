// Package security provides IP whitelisting and brute-force protection.
package security

import (
	"crypto/sha256"
	"crypto/subtle"
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
	accounts   map[string][32]byte // user -> sha256(pass)
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
			if e.ExpiresAt > 0 {
				// Keyed by the canonical network string so the match loops
				// can look expiry up from the *net.IPNet itself.
				temp[ipnet.String()] = e.ExpiresAt
			}
		default: // "single" or empty
			exact[e.IP] = true
		}
		if e.ExpiresAt > 0 {
			temp[e.IP] = e.ExpiresAt
		}
	}

	accounts := make(map[string][32]byte, len(cfg.Accounts))
	for _, a := range cfg.Accounts {
		if a.User == "" || a.Pass == "" {
			continue
		}
		accounts[a.User] = sha256.Sum256([]byte(a.Pass))
	}
	wm.accounts = accounts

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
				if exp, ok := wm.tempExpiry[cidr.String()]; ok && exp > 0 && now > exp {
					continue
				}
				return true, "cidr match"
			}
		}
	}

	return false, "not whitelisted"
}

// HasAccounts reports whether any output user/pass account is configured.
func (wm *WhitelistManager) HasAccounts() bool {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	return len(wm.accounts) > 0
}

// CheckAccount reports whether user/pass matches a configured output account.
func (wm *WhitelistManager) CheckAccount(user, pass string) bool {
	wm.mu.RLock()
	want, ok := wm.accounts[user]
	wm.mu.RUnlock()
	got := sha256.Sum256([]byte(pass))
	// Compare even for unknown users so timing does not reveal which
	// usernames exist.
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1 && ok
}

// SetAccounts replaces the output accounts without touching IP entries.
func (wm *WhitelistManager) SetAccounts(list []config.OutputAccount) {
	accounts := make(map[string][32]byte, len(list))
	for _, a := range list {
		if a.User == "" || a.Pass == "" {
			continue
		}
		accounts[a.User] = sha256.Sum256([]byte(a.Pass))
	}
	wm.mu.Lock()
	wm.accounts = accounts
	wm.mu.Unlock()
}

// Matches reports whether clientIP is covered by a (non-expired) whitelist
// entry, regardless of whether the whitelist is enabled. Used to shield
// whitelisted IPs from auto-ban.
func (wm *WhitelistManager) Matches(clientIP string) bool {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	ip := stripPort(clientIP)
	now := time.Now().Unix()

	if wm.exactIPs[ip] {
		if exp, ok := wm.tempExpiry[ip]; ok && exp > 0 && now > exp {
			return false
		}
		return true
	}

	parsed := net.ParseIP(ip)
	if parsed != nil {
		for _, cidr := range wm.cidrNets {
			if cidr.Contains(parsed) {
				if exp, ok := wm.tempExpiry[cidr.String()]; ok && exp > 0 && now > exp {
					continue
				}
				return true
			}
		}
	}
	return false
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
		if entry.ExpiresAt > 0 {
			wm.tempExpiry[ipnet.String()] = entry.ExpiresAt
		}
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
	wm.rebuildCIDRsLocked()
	return nil
}

// rebuildCIDRsLocked regenerates cidrNets (and their expiry keys) from
// wm.entries. Caller must hold wm.mu.
func (wm *WhitelistManager) rebuildCIDRsLocked() {
	wm.cidrNets = nil
	for _, e := range wm.entries {
		if e.Type != "cidr" {
			continue
		}
		_, ipnet, err := net.ParseCIDR(e.IP)
		if err != nil {
			continue
		}
		wm.cidrNets = append(wm.cidrNets, ipnet)
		if e.ExpiresAt > 0 {
			wm.tempExpiry[ipnet.String()] = e.ExpiresAt
		} else {
			delete(wm.tempExpiry, ipnet.String())
		}
	}
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
	removedCIDR := false
	for _, e := range wm.entries {
		if e.ExpiresAt > 0 && now > e.ExpiresAt {
			delete(wm.exactIPs, e.IP)
			delete(wm.tempExpiry, e.IP)
			if e.Type == "cidr" {
				removedCIDR = true
				if _, ipnet, err := net.ParseCIDR(e.IP); err == nil {
					delete(wm.tempExpiry, ipnet.String())
				}
			}
			continue
		}
		filtered = append(filtered, e)
	}
	wm.entries = filtered
	if removedCIDR {
		// Expired CIDRs were previously only dropped from entries, leaving
		// the live cidrNets slice (and therefore access) unchanged.
		wm.rebuildCIDRsLocked()
	}
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
