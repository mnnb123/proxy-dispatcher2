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

// NewBruteGuard creates a BruteGuard from config.
func NewBruteGuard(cfg config.AutoBanConfig, logger *slog.Logger) *BruteGuard {
	return &BruteGuard{
		enabled:     cfg.Enabled,
		maxAttempts: cfg.MaxAttempts,
		banDuration: time.Duration(cfg.BanDurationSec) * time.Second,
		attempts:    make(map[string]*AttemptRecord),
		logger:      logger,
	}
}

// RecordAndCheck increments the attempt count for clientIP and returns
// whether the IP is now banned.
func (bg *BruteGuard) RecordAndCheck(clientIP string) (bool, time.Duration) {
	if !bg.enabled {
		return false, 0
	}
	bg.mu.Lock()
	defer bg.mu.Unlock()

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

// IsBanned checks ban status without incrementing the counter.
func (bg *BruteGuard) IsBanned(clientIP string) (bool, time.Duration) {
	if !bg.enabled {
		return false, 0
	}
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
