package engine

import (
	"fmt"
	"log/slog"
	"sync"

	"proxy-dispatcher/internal/config"
)

// FixedRotator assigns each port index to a specific proxy.
// Port 30001 → proxy[0], port 30002 → proxy[1], etc.
// If the assigned proxy is dead, it still returns that proxy (1:1 guarantee).
type FixedRotator struct {
	proxies   []*config.ProxyEntry
	portStart int
	mu        sync.RWMutex
	logger    *slog.Logger
}

// SetPortStart sets the base port for index calculation.
func (f *FixedRotator) SetPortStart(port int) {
	f.mu.Lock()
	f.portStart = port
	f.mu.Unlock()
	if f.logger != nil {
		f.logger.Info("FixedRotator: portStart set", "portStart", port, "proxyCount", len(f.proxies))
	}
}

// NextForPort returns the proxy assigned to the given port.
// proxyIndex = port - portStart. If out of range, wraps around.
func (f *FixedRotator) NextForPort(port int) (*config.ProxyEntry, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if len(f.proxies) == 0 {
		return nil, ErrNoProxyAvailable
	}

	idx := port - f.portStart
	if idx < 0 {
		idx = 0
	}
	idx = idx % len(f.proxies)
	proxy := f.proxies[idx]
	if f.logger != nil {
		f.logger.Debug("FixedRotator: NextForPort", "port", port, "portStart", f.portStart, "idx", idx, "proxy", fmt.Sprintf("%s:%d", proxy.Host, proxy.Port))
	}
	return proxy, nil
}

// Next falls back to index-based selection (for compatibility).
// In fixed mode, callers should prefer NextForPort.
func (f *FixedRotator) Next(_ string) (*config.ProxyEntry, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if len(f.proxies) == 0 {
		return nil, ErrNoProxyAvailable
	}
	return f.proxies[0], nil
}

func (f *FixedRotator) UpdateProxies(proxies []*config.ProxyEntry) {
	f.mu.Lock()
	f.proxies = proxies
	f.mu.Unlock()
}

func (f *FixedRotator) ActiveCount() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.proxies)
}

func (f *FixedRotator) IncrementConn(_ *config.ProxyEntry) {}
func (f *FixedRotator) DecrementConn(_ *config.ProxyEntry) {}
func (f *FixedRotator) Mode() string                       { return "fixed" }

// SingleProxyRotator is a Rotator that always returns the same proxy.
// Used by fixed rotation mode so the retry handler stays compatible.
type SingleProxyRotator struct {
	Proxy *config.ProxyEntry
}

func (s *SingleProxyRotator) Next(_ string) (*config.ProxyEntry, error) { return s.Proxy, nil }
func (s *SingleProxyRotator) UpdateProxies(_ []*config.ProxyEntry)      {}
func (s *SingleProxyRotator) ActiveCount() int                          { return 1 }
func (s *SingleProxyRotator) IncrementConn(_ *config.ProxyEntry)        {}
func (s *SingleProxyRotator) DecrementConn(_ *config.ProxyEntry)        {}
func (s *SingleProxyRotator) Mode() string                              { return "fixed" }
