package engine

import (
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"proxy-dispatcher/internal/config"
)

// ErrNoProxyAvailable is returned when no alive proxy is available.
var ErrNoProxyAvailable = errors.New("no proxy available")

// Rotator selects one upstream proxy per request, using a rotation strategy.
type Rotator interface {
	Next(clientIP string) (*config.ProxyEntry, error)
	UpdateProxies(proxies []*config.ProxyEntry)
	ActiveCount() int
	IncrementConn(proxy *config.ProxyEntry)
	DecrementConn(proxy *config.ProxyEntry)
	Mode() string
}

// RotatorOpts configures rotator construction.
type RotatorOpts struct {
	StickyTTL time.Duration
	Logger    *slog.Logger
}

// NewRotator is a factory building the rotation strategy by mode name.
func NewRotator(mode string, proxies []*config.ProxyEntry, opts RotatorOpts) (Rotator, error) {
	switch mode {
	case "", "roundrobin":
		return &RoundRobinRotator{proxies: proxies, logger: opts.Logger}, nil
	case "random":
		return &RandomRotator{proxies: proxies, rng: rand.New(rand.NewSource(time.Now().UnixNano())), logger: opts.Logger}, nil
	case "sticky":
		ttl := opts.StickyTTL
		if ttl <= 0 {
			ttl = 300 * time.Second
		}
		fb := &RoundRobinRotator{proxies: proxies, logger: opts.Logger}
		return &StickyRotator{proxies: proxies, sessions: make(map[string]*StickySession), ttl: ttl, fallback: fb, logger: opts.Logger}, nil
	case "leastconn":
		return &LeastConnRotator{proxies: proxies, logger: opts.Logger}, nil
	case "weighted":
		wr := &WeightedRotator{proxies: proxies, rng: rand.New(rand.NewSource(time.Now().UnixNano())), logger: opts.Logger}
		wr.RebuildWeights()
		return wr, nil
	case "fixed":
		return &FixedRotator{proxies: proxies, logger: opts.Logger}, nil
	}
	return nil, fmt.Errorf("unknown rotation mode: %s", mode)
}

// getAlive returns non-dead proxies; if all dead, returns all unknown-status;
// if none, returns empty slice.
func getAlive(proxies []*config.ProxyEntry) []*config.ProxyEntry {
	if len(proxies) == 0 {
		return nil
	}
	out := make([]*config.ProxyEntry, 0, len(proxies))
	for _, p := range proxies {
		if p.Status != "dead" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		// All dead — return all unknown as a last resort.
		for _, p := range proxies {
			if p.Status == "" || p.Status == "unknown" {
				out = append(out, p)
			}
		}
	}
	return out
}

// ── RoundRobinRotator ─────────────────────────────────────────

type RoundRobinRotator struct {
	proxies []*config.ProxyEntry
	index   atomic.Uint64
	mu      sync.RWMutex
	logger  *slog.Logger
}

func (r *RoundRobinRotator) Next(_ string) (*config.ProxyEntry, error) {
	r.mu.RLock()
	alive := getAlive(r.proxies)
	r.mu.RUnlock()
	if len(alive) == 0 {
		return nil, ErrNoProxyAvailable
	}
	idx := r.index.Add(1) % uint64(len(alive))
	return alive[idx], nil
}

func (r *RoundRobinRotator) UpdateProxies(proxies []*config.ProxyEntry) {
	r.mu.Lock()
	r.proxies = proxies
	r.mu.Unlock()
	r.index.Store(0)
}

func (r *RoundRobinRotator) ActiveCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(getAlive(r.proxies))
}

func (r *RoundRobinRotator) IncrementConn(_ *config.ProxyEntry) {}
func (r *RoundRobinRotator) DecrementConn(_ *config.ProxyEntry) {}
func (r *RoundRobinRotator) Mode() string                       { return "roundrobin" }

// ── RandomRotator ─────────────────────────────────────────────

type RandomRotator struct {
	proxies []*config.ProxyEntry
	rng     *rand.Rand
	mu      sync.RWMutex
	logger  *slog.Logger
}

func (r *RandomRotator) Next(_ string) (*config.ProxyEntry, error) {
	r.mu.RLock()
	alive := getAlive(r.proxies)
	r.mu.RUnlock()
	if len(alive) == 0 {
		return nil, ErrNoProxyAvailable
	}
	r.mu.Lock()
	idx := r.rng.Intn(len(alive))
	r.mu.Unlock()
	return alive[idx], nil
}

func (r *RandomRotator) UpdateProxies(proxies []*config.ProxyEntry) {
	r.mu.Lock()
	r.proxies = proxies
	r.mu.Unlock()
}

func (r *RandomRotator) ActiveCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(getAlive(r.proxies))
}

func (r *RandomRotator) IncrementConn(_ *config.ProxyEntry) {}
func (r *RandomRotator) DecrementConn(_ *config.ProxyEntry) {}
func (r *RandomRotator) Mode() string                       { return "random" }
