package engine

import (
	"log/slog"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"proxy-dispatcher/internal/config"
)

// LeastConnRotator picks the proxy with the fewest active connections.
type LeastConnRotator struct {
	proxies []*config.ProxyEntry
	rng     *rand.Rand
	mu      sync.RWMutex
	rngMu   sync.Mutex
	logger  *slog.Logger
}

// Next returns the proxy with the lowest ActiveConns, random tie-break.
func (lc *LeastConnRotator) Next(_ string) (*config.ProxyEntry, error) {
	lc.mu.RLock()
	alive := getAlive(lc.proxies)
	lc.mu.RUnlock()
	if len(alive) == 0 {
		return nil, ErrNoProxyAvailable
	}
	var minVal int32 = 1<<31 - 1
	var best []*config.ProxyEntry
	for _, p := range alive {
		c := atomic.LoadInt32(&p.ActiveConns)
		if c < minVal {
			minVal = c
			best = best[:0]
			best = append(best, p)
		} else if c == minVal {
			best = append(best, p)
		}
	}
	if len(best) == 1 {
		return best[0], nil
	}
	if lc.rng == nil {
		lc.rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	lc.rngMu.Lock()
	idx := lc.rng.Intn(len(best))
	lc.rngMu.Unlock()
	return best[idx], nil
}

// UpdateProxies replaces the proxy list.
func (lc *LeastConnRotator) UpdateProxies(proxies []*config.ProxyEntry) {
	lc.mu.Lock()
	lc.proxies = proxies
	lc.mu.Unlock()
}

// ActiveCount returns alive proxy count.
func (lc *LeastConnRotator) ActiveCount() int {
	lc.mu.RLock()
	defer lc.mu.RUnlock()
	return len(getAlive(lc.proxies))
}

// IncrementConn atomically bumps the active-connection counter.
func (lc *LeastConnRotator) IncrementConn(proxy *config.ProxyEntry) {
	atomic.AddInt32(&proxy.ActiveConns, 1)
}

// DecrementConn atomically decrements, clamping at zero.
func (lc *LeastConnRotator) DecrementConn(proxy *config.ProxyEntry) {
	if atomic.AddInt32(&proxy.ActiveConns, -1) < 0 {
		atomic.StoreInt32(&proxy.ActiveConns, 0)
	}
}

func (lc *LeastConnRotator) Mode() string { return "leastconn" }
