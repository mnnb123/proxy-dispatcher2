package engine

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"proxy-dispatcher/internal/config"
)

const maxStickySessions = 50000

// StickySession tracks which proxy a client IP is bound to.
type StickySession struct {
	ProxyHost string
	ExpiresAt time.Time
}

// StickyRotator binds each client IP to a single upstream proxy for TTL.
type StickyRotator struct {
	proxies  []*config.ProxyEntry
	sessions map[string]*StickySession
	ttl      time.Duration
	fallback *RoundRobinRotator
	mu       sync.RWMutex
	logger   *slog.Logger
}

// Next returns the sticky proxy for clientIP, or falls back to round-robin.
func (sr *StickyRotator) Next(clientIP string) (*config.ProxyEntry, error) {
	sr.mu.RLock()
	sess, ok := sr.sessions[clientIP]
	proxies := sr.proxies
	sr.mu.RUnlock()
	if ok && time.Now().Before(sess.ExpiresAt) {
		for _, p := range proxies {
			if p.Status != "dead" && fmt.Sprintf("%s:%d", p.Host, p.Port) == sess.ProxyHost {
				return p, nil
			}
		}
	}
	// Need a fresh pick.
	sr.mu.Lock()
	delete(sr.sessions, clientIP)
	if len(sr.sessions) >= maxStickySessions {
		// evict oldest N (simple drop of random half).
		for k := range sr.sessions {
			delete(sr.sessions, k)
			if len(sr.sessions) <= maxStickySessions/2 {
				break
			}
		}
	}
	sr.mu.Unlock()

	proxy, err := sr.fallback.Next(clientIP)
	if err != nil {
		return nil, err
	}
	sr.mu.Lock()
	sr.sessions[clientIP] = &StickySession{
		ProxyHost: fmt.Sprintf("%s:%d", proxy.Host, proxy.Port),
		ExpiresAt: time.Now().Add(sr.ttl),
	}
	sr.mu.Unlock()
	return proxy, nil
}

// CleanupExpired drops expired sticky sessions.
func (sr *StickyRotator) CleanupExpired() {
	now := time.Now()
	sr.mu.Lock()
	for k, v := range sr.sessions {
		if now.After(v.ExpiresAt) {
			delete(sr.sessions, k)
		}
	}
	sr.mu.Unlock()
}

// UpdateProxies swaps proxy list without clearing sessions.
func (sr *StickyRotator) UpdateProxies(proxies []*config.ProxyEntry) {
	sr.mu.Lock()
	sr.proxies = proxies
	sr.mu.Unlock()
	sr.fallback.UpdateProxies(proxies)
}

// ActiveCount returns alive proxy count.
func (sr *StickyRotator) ActiveCount() int {
	sr.mu.RLock()
	defer sr.mu.RUnlock()
	return len(getAlive(sr.proxies))
}

// SessionCount returns the number of active sticky sessions.
func (sr *StickyRotator) SessionCount() int {
	sr.mu.RLock()
	defer sr.mu.RUnlock()
	return len(sr.sessions)
}

func (sr *StickyRotator) IncrementConn(_ *config.ProxyEntry) {}
func (sr *StickyRotator) DecrementConn(_ *config.ProxyEntry) {}
func (sr *StickyRotator) Mode() string                       { return "sticky" }
