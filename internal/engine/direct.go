package engine

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"time"

	"proxy-dispatcher/internal/config"
)

// DirectDialer dials targets directly or through a resource proxy.
type DirectDialer struct {
	timeout  time.Duration
	resolver *net.Resolver
	logger   *slog.Logger
}

// NewDirectDialer creates a DirectDialer.
func NewDirectDialer(timeout time.Duration, logger *slog.Logger) *DirectDialer {
	return &DirectDialer{timeout: timeout, logger: logger}
}

// SetResolver injects a custom DNS resolver used by Dial.
func (d *DirectDialer) SetResolver(r *net.Resolver) { d.resolver = r }

// Dial connects directly to addr.
func (d *DirectDialer) Dial(ctx context.Context, addr string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: d.timeout, Resolver: d.resolver}
	return dialer.DialContext(ctx, "tcp", addr)
}

// DialThroughResource tunnels through a resource proxy to reach addr.
func (d *DirectDialer) DialThroughResource(ctx context.Context, addr string, proxy config.ProxyEntry) (net.Conn, error) {
	dialer := net.Dialer{Timeout: d.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(proxy.Host, strconv.Itoa(proxy.Port)))
	if err != nil {
		return nil, fmt.Errorf("dial resource proxy: %w", err)
	}

	switch proxy.Type {
	case "http":
		req := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n"
		if proxy.User != "" {
			req += "Proxy-Authorization: " + ProxyBasicAuth(proxy.User, proxy.Pass) + "\r\n"
		}
		req += "\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			conn.Close()
			return nil, fmt.Errorf("write CONNECT: %w", err)
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("read CONNECT response: %w", err)
		}
		resp := string(buf[:n])
		if len(resp) < 12 || resp[9:12] != "200" {
			conn.Close()
			return nil, fmt.Errorf("resource proxy CONNECT failed: %s", resp)
		}
		return conn, nil
	case "socks5":
		return dialThroughSOCKS5Proxy(ctx, proxy, addr)
	default:
		conn.Close()
		return nil, fmt.Errorf("unsupported resource proxy type: %s", proxy.Type)
	}
}
