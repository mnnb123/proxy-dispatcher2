package security

import (
	"log/slog"
	"sync"
	"time"

	"proxy-dispatcher/internal/config"
)

// AttemptRecord tracks connection attempts for a single IP.
type AttemptRecord struct {
	Count    int
	FirstAt  time.Time
	BannedAt time.Time
}

// BruteGuard tracks unauthorized connection attempts and auto-bans IPs.
type BruteGuard struct {
	enabled     bool
	maxAttempts int
	banDuration time.Duration
	attempts    map[string]*AttemptRecord
	mu          sync.Mutex
	logger      *slog.Logger
}

// defaultBanDuration is used when the configured duration is zero/negative;
// otherwise Ban() and auto-ban would be silent no-ops (remaining <= 0).
const defaultBanDuration = time.Hour

// NewBruteGuard creates a BruteGuard from config.
func NewBruteGuard(cfg config.AutoBanConfig, logger *slog.Logger) *BruteGuard {
	bg := &BruteGuard{
		attempts: make(map[string]*AttemptRecord),
		logger:   logger,
	}
	bg.Reload(cfg)
	return bg
}

// Reload applies new auto-ban settings at runtime. Existing attempt/ban
// records are kept.
func (bg *BruteGuard) Reload(cfg config.AutoBanConfig) {
	bg.mu.Lock()
	defer bg.mu.Unlock()
	bg.enabled = cfg.Enabled
	bg.maxAttempts = cfg.MaxAttempts
	if bg.maxAttempts <= 0 {
		bg.maxAttempts = 5
	}
	bg.banDuration = time.Duration(cfg.BanDurationSec) * time.Second
	if bg.banDuration <= 0 {
		bg.banDuration = defaultBanDuration
	}
}

// RecordAndCheck increments the attempt count for clientIP and returns
// whether the IP is now banned.
func (bg *BruteGuard) RecordAndCheck(clientIP string) (bool, time.Duration) {
	bg.mu.Lock()
	defer bg.mu.Unlock()
	if !bg.enabled {
		return false, 0
	}

	rec, ok := bg.attempts[clientIP]
	if !ok {
		rec = &AttemptRecord{FirstAt: time.Now()}
		bg.attempts[clientIP] = rec
	}

	if !rec.BannedAt.IsZero() {
		remaining := bg.banDuration - time.Since(rec.BannedAt)
		if remaining > 0 {
			return true, remaining
		}
		rec.Count = 0
		rec.BannedAt = time.Time{}
		rec.FirstAt = time.Now()
	}

	rec.Count++
	if rec.Count >= bg.maxAttempts {
		rec.BannedAt = time.Now()
		bg.logger.Warn("IP auto-banned", "ip", clientIP, "attempts", rec.Count)
		return true, bg.banDuration
	}
	return false, 0
}

// Ban manually bans clientIP for the configured ban duration,
// regardless of whether auto-ban is enabled.
func (bg *BruteGuard) Ban(clientIP string) {
	bg.mu.Lock()
	defer bg.mu.Unlock()
	now := time.Now()
	bg.attempts[clientIP] = &AttemptRecord{Count: bg.maxAttempts, FirstAt: now, BannedAt: now}
	bg.logger.Warn("IP manually banned", "ip", clientIP)
}

// IsBanned checks ban status without incrementing the counter.
// Note: not gated on enabled so manual bans work even when auto-ban is off.
func (bg *BruteGuard) IsBanned(clientIP string) (bool, time.Duration) {
	bg.mu.Lock()
	defer bg.mu.Unlock()

	rec, ok := bg.attempts[clientIP]
	if !ok || rec.BannedAt.IsZero() {
		return false, 0
	}
	remaining := bg.banDuration - time.Since(rec.BannedAt)
	if remaining <= 0 {
		delete(bg.attempts, clientIP)
		return false, 0
	}
	return true, remaining
}

// Cleanup removes stale records older than 1 hour.
func (bg *BruteGuard) Cleanup() {
	bg.mu.Lock()
	defer bg.mu.Unlock()

	cutoff := time.Now().Add(-1 * time.Hour)
	for ip, rec := range bg.attempts {
		if !rec.BannedAt.IsZero() {
			if time.Since(rec.BannedAt) > bg.banDuration {
				delete(bg.attempts, ip)
			}
		} else if rec.FirstAt.Before(cutoff) {
			delete(bg.attempts, ip)
		}
	}
}

// Unban removes the ban/attempt record for a single IP.
func (bg *BruteGuard) Unban(clientIP string) {
	bg.mu.Lock()
	defer bg.mu.Unlock()
	delete(bg.attempts, clientIP)
}

// ClearBanned removes all attempt records, unbanning every IP.
func (bg *BruteGuard) ClearBanned() int {
	bg.mu.Lock()
	defer bg.mu.Unlock()

	n := 0
	for ip, rec := range bg.attempts {
		if !rec.BannedAt.IsZero() {
			n++
		}
		delete(bg.attempts, ip)
	}
	bg.logger.Info("banned IPs cleared", "count", n)
	return n
}

// GetBannedIPs returns the list of currently banned IPs.
func (bg *BruteGuard) GetBannedIPs() []string {
	bg.mu.Lock()
	defer bg.mu.Unlock()

	var ips []string
	for ip, rec := range bg.attempts {
		if !rec.BannedAt.IsZero() && time.Since(rec.BannedAt) < bg.banDuration {
			ips = append(ips, ip)
		}
	}
	return ips
}
