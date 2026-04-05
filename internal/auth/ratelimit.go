package auth

import (
	"sync"
	"time"
)

// AttemptInfo tracks login failures for a given IP.
type AttemptInfo struct {
	FailCount int
	BannedAt  time.Time
}

// LoginLimiter enforces a max-fail/ban-duration rate limit per IP.
type LoginLimiter struct {
	attempts    map[string]*AttemptInfo
	mu          sync.Mutex
	maxFails    int
	banDuration time.Duration
}

// NewLoginLimiter creates a LoginLimiter.
func NewLoginLimiter(maxFails int, banDuration time.Duration) *LoginLimiter {
	return &LoginLimiter{
		attempts:    make(map[string]*AttemptInfo),
		maxFails:    maxFails,
		banDuration: banDuration,
	}
}

// CheckAllowed returns whether ip may attempt login, and remaining ban time.
func (l *LoginLimiter) CheckAllowed(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	info, ok := l.attempts[ip]
	if !ok {
		return true, 0
	}
	if info.FailCount < l.maxFails {
		return true, 0
	}
	elapsed := time.Since(info.BannedAt)
	if elapsed >= l.banDuration {
		delete(l.attempts, ip)
		return true, 0
	}
	return false, l.banDuration - elapsed
}

// RecordFail increments fail counter for ip and may set BannedAt.
func (l *LoginLimiter) RecordFail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	info, ok := l.attempts[ip]
	if !ok {
		info = &AttemptInfo{}
		l.attempts[ip] = info
	}
	info.FailCount++
	if info.FailCount >= l.maxFails {
		info.BannedAt = time.Now()
	}
}

// RecordSuccess clears any failed state for ip.
func (l *LoginLimiter) RecordSuccess(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, ip)
}

// Cleanup removes expired entries; call periodically (e.g. every 10m).
func (l *LoginLimiter) Cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for ip, info := range l.attempts {
		if info.FailCount >= l.maxFails && time.Since(info.BannedAt) >= l.banDuration {
			delete(l.attempts, ip)
		}
	}
}
