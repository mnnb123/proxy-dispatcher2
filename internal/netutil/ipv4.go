// Package netutil holds small network helpers shared by the engine and the
// health checker.
package netutil

import (
	"context"
	"net"
	"sync"
	"time"
)

const (
	ipv4CacheTTL  = 60 * time.Second
	ipv4CacheSize = 4096
	ipv4Timeout   = 3 * time.Second
)

type ipv4Entry struct {
	ip      string
	expires time.Time
}

var (
	ipv4Mu    sync.Mutex
	ipv4Cache = make(map[string]ipv4Entry)
	// lookupIPv4 is swapped in tests.
	lookupIPv4 = func(ctx context.Context, host string) ([]net.IP, error) {
		return net.DefaultResolver.LookupIP(ctx, "ip4", host)
	}
)

// IPv4Target rewrites "host:port" so that host is an IPv4 literal. An
// upstream SOCKS5 proxy given a domain name resolves it itself and, when
// its exit has IPv6, leaves over IPv6; handing it an IPv4 address forces
// the IPv4 exit. The address is returned unchanged when host already is an
// IP or has no A record (IPv6-only sites keep working).
func IPv4Target(ctx context.Context, addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || net.ParseIP(host) != nil {
		return addr
	}
	if ip := resolveIPv4(ctx, host); ip != "" {
		return net.JoinHostPort(ip, port)
	}
	return addr
}

func resolveIPv4(ctx context.Context, host string) string {
	now := time.Now()
	ipv4Mu.Lock()
	e, ok := ipv4Cache[host]
	ipv4Mu.Unlock()
	if ok && now.Before(e.expires) {
		return e.ip
	}
	ctx, cancel := context.WithTimeout(ctx, ipv4Timeout)
	defer cancel()
	ips, err := lookupIPv4(ctx, host)
	ip := ""
	if err == nil && len(ips) > 0 {
		ip = ips[0].String()
	}
	if ip == "" && ctx.Err() != nil {
		return "" // lookup cut short: do not cache
	}
	ipv4Mu.Lock()
	if len(ipv4Cache) >= ipv4CacheSize {
		for k, v := range ipv4Cache {
			if now.After(v.expires) {
				delete(ipv4Cache, k)
			}
		}
		if len(ipv4Cache) >= ipv4CacheSize {
			ipv4Cache = make(map[string]ipv4Entry)
		}
	}
	ipv4Cache[host] = ipv4Entry{ip: ip, expires: now.Add(ipv4CacheTTL)}
	ipv4Mu.Unlock()
	return ip
}
