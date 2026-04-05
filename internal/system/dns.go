package system

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"proxy-dispatcher/internal/config"
)

// DNSTestResult is the outcome of a DNS lookup test.
type DNSTestResult struct {
	Domain    string   `json:"domain"`
	IPs       []string `json:"ips"`
	LatencyMs int64    `json:"latency_ms"`
	Server    string   `json:"server"`
	Error     string   `json:"error,omitempty"`
}

// DNSManager builds a custom resolver using configured DNS servers.
type DNSManager struct {
	servers    []string
	dohEnabled bool
	resolver   *net.Resolver
	logger     *slog.Logger
	mu         sync.RWMutex
}

// NewDNSManager returns a DNSManager whose custom resolver dials the first
// configured server on port 53 (UDP).
func NewDNSManager(cfg config.SystemConfig, logger *slog.Logger) *DNSManager {
	dm := &DNSManager{logger: logger}
	dm.Reload(cfg)
	return dm
}

// Reload rebuilds the resolver from a fresh config.
func (dm *DNSManager) Reload(cfg config.SystemConfig) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.servers = append([]string(nil), cfg.DNSServers...)
	dm.dohEnabled = cfg.DNSOverHTTPS
	servers := dm.servers
	if len(servers) == 0 {
		dm.resolver = net.DefaultResolver
		return
	}
	dm.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", net.JoinHostPort(servers[0], "53"))
		},
	}
}

// GetResolver returns the current *net.Resolver.
func (dm *DNSManager) GetResolver() *net.Resolver {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return dm.resolver
}

// TestDNS resolves the given domain and returns results + latency.
func (dm *DNSManager) TestDNS(domain string) DNSTestResult {
	dm.mu.RLock()
	res := dm.resolver
	server := ""
	if len(dm.servers) > 0 {
		server = dm.servers[0]
	}
	dm.mu.RUnlock()
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := res.LookupHost(ctx, domain)
	out := DNSTestResult{Domain: domain, Server: server, LatencyMs: time.Since(start).Milliseconds()}
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.IPs = ips
	return out
}
