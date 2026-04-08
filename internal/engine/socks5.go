package engine

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	socks5 "github.com/armon/go-socks5"

	"proxy-dispatcher/internal/config"
	"proxy-dispatcher/internal/rules"
)

// Socks5Result holds destination info and byte counts from a SOCKS5 session.
type Socks5Result struct {
	DestHost     string
	DestPort     string
	BytesRecv    int64  // bytes received from upstream (download)
	BytesSent    int64  // bytes sent to upstream (upload)
	ProxyUsed    string // set if a retry switched to a different proxy
	RouteType    string // "proxy", "direct", or "blocked"
}

// countingConn wraps a net.Conn to track bytes read and written.
type countingConn struct {
	net.Conn
	read    atomic.Int64
	written atomic.Int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.read.Add(int64(n))
	}
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.written.Add(int64(n))
	}
	return n, err
}

// domainResolver captures the FQDN before the go-socks5 library resolves it.
// It returns a dummy IP so DNS resolution happens on the upstream proxy, not locally.
type domainResolver struct {
	host *string
	once *sync.Once
}

func (d *domainResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	d.once.Do(func() {
		*d.host = name
	})
	// Return dummy IP — the dialer will reconstruct domain:port for upstream.
	return ctx, net.IPv4(0, 0, 0, 1), nil
}

// Socks5Handler handles incoming SOCKS5 client connections by tunneling
// them through an upstream proxy.
type Socks5Handler struct {
	logger     *slog.Logger
	ruleEngine *rules.RuleEngine
}

// NewSocks5Handler creates a new SOCKS5 handler.
func NewSocks5Handler(logger *slog.Logger, ruleEngine *rules.RuleEngine) *Socks5Handler {
	return &Socks5Handler{logger: logger, ruleEngine: ruleEngine}
}

// HandleConnection serves a SOCKS5 session on clientConn, tunneling all
// outbound connections through the provided upstream proxy. If the dial
// fails and a rotator is provided, it retries with up to maxRetries
// different proxies.
// It returns destination info and byte counts captured during the session.
func (h *Socks5Handler) HandleConnection(ctx context.Context, clientConn *BufferedConn, proxy config.ProxyEntry, rotator Rotator, clientIP string) (*Socks5Result, error) {
	const maxRetries = 3
	var result Socks5Result
	var portOnce sync.Once
	var domainOnce sync.Once
	var counter *countingConn

	currentProxy := proxy

	// Resolver captures the FQDN before go-socks5 resolves it to IP.
	resolver := &domainResolver{host: &result.DestHost, once: &domainOnce}

	dialer := func(dialCtx context.Context, network, addr string) (net.Conn, error) {
		// Capture port. addr may be "0.0.0.1:port" (dummy IP from resolver) or "real_ip:port" (client sent IP).
		_, port, _ := net.SplitHostPort(addr)
		portOnce.Do(func() {
			result.DestPort = port
			if result.DestHost == "" {
				// Client sent a raw IP (resolver was not called).
				result.DestHost, _, _ = net.SplitHostPort(addr)
			}
		})

		// Reconstruct target using original domain (if captured by resolver)
		// so upstream proxy handles DNS, not this server.
		targetAddr := addr
		if result.DestHost != "" && port != "" {
			targetAddr = net.JoinHostPort(result.DestHost, port)
		}

		// Check bypass/block rules for this domain.
		if h.ruleEngine != nil && result.DestHost != "" {
			action := h.ruleEngine.Evaluate(result.DestHost, "")
			h.logger.Debug("socks5 rule eval", "domain", result.DestHost, "action", action.Type, "target", targetAddr)
			switch action.Type {
			case "direct", "resource":
				// Bypass: connect directly to target, skip upstream proxy.
				result.RouteType = "direct"
				d := net.Dialer{Timeout: proxyDialTimeout}
				conn, err := d.DialContext(dialCtx, network, targetAddr)
				if err != nil {
					return nil, err
				}
				counter = &countingConn{Conn: conn}
				return counter, nil
			case "block":
				result.RouteType = "blocked"
				return nil, fmt.Errorf("blocked by rule")
			}
		}
		result.RouteType = "proxy"

		// Try current proxy, then retry with different proxies on failure.
		tryProxy := func(p config.ProxyEntry) (net.Conn, error) {
			switch p.Type {
			case "socks5":
				return dialThroughSOCKS5Proxy(dialCtx, p, targetAddr)
			case "http":
				return dialThroughHTTPProxy(dialCtx, p, targetAddr)
			default:
				return nil, fmt.Errorf("unsupported proxy type: %s", p.Type)
			}
		}

		conn, err := tryProxy(currentProxy)
		if err != nil && rotator != nil {
			h.logger.Debug("proxy dial failed, retrying", "proxy", fmt.Sprintf("%s:%d", currentProxy.Host, currentProxy.Port), "error", err)
			for i := 0; i < maxRetries; i++ {
				next, nErr := rotator.Next(clientIP)
				if nErr != nil {
					break
				}
				conn, err = tryProxy(*next)
				if err == nil {
					currentProxy = *next
					result.ProxyUsed = fmt.Sprintf("%s:%d", next.Host, next.Port)
					break
				}
				h.logger.Debug("retry proxy also failed", "proxy", fmt.Sprintf("%s:%d", next.Host, next.Port), "attempt", i+1, "error", err)
			}
		}
		if err != nil {
			return nil, err
		}

		// Wrap with byte counter so we can report traffic size.
		counter = &countingConn{Conn: conn}
		return counter, nil
	}

	conf := &socks5.Config{
		Dial:     dialer,
		Resolver: resolver,
		Logger:   nil,
	}
	server, err := socks5.New(conf)
	if err != nil {
		return &result, fmt.Errorf("create socks5 server: %w", err)
	}

	serveErr := server.ServeConn(clientConn)

	// Collect byte counts after the session ends.
	if counter != nil {
		result.BytesRecv = counter.read.Load()
		result.BytesSent = counter.written.Load()
	}

	if serveErr != nil {
		return &result, fmt.Errorf("serve socks5: %w", serveErr)
	}
	return &result, nil
}

