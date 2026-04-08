package engine

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	socks5 "github.com/armon/go-socks5"

	"proxy-dispatcher/internal/config"
)

// Socks5Result holds destination info and byte counts from a SOCKS5 session.
type Socks5Result struct {
	DestHost     string
	DestPort     string
	BytesRecv    int64  // bytes received from upstream (download)
	BytesSent    int64  // bytes sent to upstream (upload)
	ProxyUsed    string // set if a retry switched to a different proxy
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
type domainResolver struct {
	host *string
	once *sync.Once
}

func (d *domainResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	d.once.Do(func() {
		*d.host = name
	})
	addr, err := net.ResolveIPAddr("ip", name)
	if err != nil {
		return ctx, nil, err
	}
	return ctx, addr.IP, nil
}

// Socks5Handler handles incoming SOCKS5 client connections by tunneling
// them through an upstream proxy.
type Socks5Handler struct {
	logger *slog.Logger
}

// NewSocks5Handler creates a new SOCKS5 handler.
func NewSocks5Handler(logger *slog.Logger) *Socks5Handler {
	return &Socks5Handler{logger: logger}
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
		// Capture port (and host as fallback if resolver wasn't called, e.g. client sent IP).
		portOnce.Do(func() {
			host, port, err := net.SplitHostPort(addr)
			if err == nil {
				result.DestPort = port
				if result.DestHost == "" {
					result.DestHost = host
				}
			}
		})

		// Try current proxy, then retry with different proxies on failure.
		tryProxy := func(p config.ProxyEntry) (net.Conn, error) {
			switch p.Type {
			case "socks5":
				return dialThroughSOCKS5Proxy(dialCtx, p, addr)
			case "http":
				return dialThroughHTTPProxy(dialCtx, p, addr)
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

// proxyDialTimeout is the max time to wait when connecting to an upstream proxy.
const proxyDialTimeout = 15 * time.Second

// dialThroughHTTPProxy opens a CONNECT tunnel to targetAddr through an
// HTTP proxy.
func dialThroughHTTPProxy(ctx context.Context, proxy config.ProxyEntry, targetAddr string) (net.Conn, error) {
	d := net.Dialer{Timeout: proxyDialTimeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(proxy.Host, strconv.Itoa(proxy.Port)))
	if err != nil {
		return nil, fmt.Errorf("dial http proxy: %w", err)
	}
	// Deadline for the CONNECT handshake.
	conn.SetDeadline(time.Now().Add(proxyDialTimeout))
	defer conn.SetDeadline(time.Time{})

	req := "CONNECT " + targetAddr + " HTTP/1.1\r\nHost: " + targetAddr + "\r\n"
	if proxy.User != "" {
		req += "Proxy-Authorization: " + ProxyBasicAuth(proxy.User, proxy.Pass) + "\r\n"
	}
	req += "\r\n"

	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write connect: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read connect response: %w", err)
	}
	resp := string(buf[:n])
	if len(resp) < 12 || resp[9:12] != "200" {
		conn.Close()
		return nil, fmt.Errorf("http proxy CONNECT failed: %s", resp)
	}
	return conn, nil
}

// dialThroughSOCKS5Proxy performs a SOCKS5 handshake with proxy and
// returns a connection tunneled to targetAddr.
func dialThroughSOCKS5Proxy(ctx context.Context, proxy config.ProxyEntry, targetAddr string) (net.Conn, error) {
	d := net.Dialer{Timeout: proxyDialTimeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(proxy.Host, strconv.Itoa(proxy.Port)))
	if err != nil {
		return nil, fmt.Errorf("dial socks5 proxy: %w", err)
	}
	// Deadline for the SOCKS5 handshake.
	conn.SetDeadline(time.Now().Add(proxyDialTimeout))
	defer conn.SetDeadline(time.Time{})

	// Greeting.
	var greet []byte
	if proxy.User != "" {
		greet = []byte{0x05, 0x02, 0x00, 0x02}
	} else {
		greet = []byte{0x05, 0x01, 0x00}
	}
	if _, err := conn.Write(greet); err != nil {
		conn.Close()
		return nil, err
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}
	if resp[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("bad socks version: %d", resp[0])
	}

	switch resp[1] {
	case 0x00:
		// No auth required.
	case 0x02:
		// Username/password auth.
		authReq := []byte{0x01}
		authReq = append(authReq, byte(len(proxy.User)))
		authReq = append(authReq, []byte(proxy.User)...)
		authReq = append(authReq, byte(len(proxy.Pass)))
		authReq = append(authReq, []byte(proxy.Pass)...)
		if _, err := conn.Write(authReq); err != nil {
			conn.Close()
			return nil, err
		}
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil {
			conn.Close()
			return nil, err
		}
		if authResp[1] != 0x00 {
			conn.Close()
			return nil, fmt.Errorf("socks5 auth failed")
		}
	default:
		conn.Close()
		return nil, fmt.Errorf("unsupported socks5 auth method: %d", resp[1])
	}

	// Connect request.
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("parse target addr: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("parse port: %w", err)
	}

	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			conn.Close()
			return nil, fmt.Errorf("hostname too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	req = append(req, portBytes...)

	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	// Read reply header.
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		conn.Close()
		return nil, err
	}
	if head[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect failed: code=%d", head[1])
	}

	// Skip the bound address in reply.
	switch head[3] {
	case 0x01:
		if _, err := io.ReadFull(conn, make([]byte, 4+2)); err != nil {
			conn.Close()
			return nil, err
		}
	case 0x04:
		if _, err := io.ReadFull(conn, make([]byte, 16+2)); err != nil {
			conn.Close()
			return nil, err
		}
	case 0x03:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(conn, lb); err != nil {
			conn.Close()
			return nil, err
		}
		if _, err := io.ReadFull(conn, make([]byte, int(lb[0])+2)); err != nil {
			conn.Close()
			return nil, err
		}
	default:
		conn.Close()
		return nil, fmt.Errorf("unknown ATYP in reply: %d", head[3])
	}

	return conn, nil
}
