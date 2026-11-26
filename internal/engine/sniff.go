package engine

import (
	"bytes"
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// When a SOCKS5 client sends a raw IP (it resolved DNS itself), the domain is
// recovered from the first bytes it sends: the TLS ClientHello SNI or the
// HTTP Host header. sniffConn delays the upstream dial until those bytes
// arrive, so rules, logs and auto-bypass see the real domain.

const (
	// sniffWait is how long to wait for the client's first bytes before
	// dialing without a domain (protocols where the server speaks first).
	sniffWait = 1500 * time.Millisecond
	// sniffMax caps how much client data is buffered while sniffing.
	sniffMax = 16 << 10
)

// SniffHost extracts the destination host name from the first bytes of a
// client stream. more is true when b may be an incomplete ClientHello or
// HTTP request head and more bytes could reveal the host.
func SniffHost(b []byte) (host string, more bool) {
	if len(b) == 0 {
		return "", true
	}
	if b[0] == 0x16 {
		return sniffTLS(b)
	}
	if m, partial := httpMethodPrefix(b); m {
		return sniffHTTP(b)
	} else if partial {
		return "", true
	}
	return "", false
}

func sniffTLS(b []byte) (string, bool) {
	if len(b) < 5 {
		return "", true
	}
	if b[1] != 0x03 {
		return "", false
	}
	recLen := int(b[3])<<8 | int(b[4])
	if len(b) < 5+recLen {
		return "", true
	}
	return clientHelloSNI(b[5 : 5+recLen]), false
}

// clientHelloSNI returns the server_name of a ClientHello handshake message,
// or "" when absent or malformed.
func clientHelloSNI(h []byte) string {
	if len(h) < 4 || h[0] != 0x01 {
		return ""
	}
	p := h[4:]
	skip := func(n int) bool {
		if len(p) < n {
			return false
		}
		p = p[n:]
		return true
	}
	u8 := func() (int, bool) {
		if len(p) < 1 {
			return 0, false
		}
		v := int(p[0])
		p = p[1:]
		return v, true
	}
	u16 := func() (int, bool) {
		if len(p) < 2 {
			return 0, false
		}
		v := int(p[0])<<8 | int(p[1])
		p = p[2:]
		return v, true
	}
	if !skip(2 + 32) { // version + random
		return ""
	}
	if n, ok := u8(); !ok || !skip(n) { // session id
		return ""
	}
	if n, ok := u16(); !ok || !skip(n) { // cipher suites
		return ""
	}
	if n, ok := u8(); !ok || !skip(n) { // compression methods
		return ""
	}
	extLen, ok := u16()
	if !ok {
		return ""
	}
	if extLen < len(p) {
		p = p[:extLen]
	}
	for len(p) >= 4 {
		typ, _ := u16()
		n, _ := u16()
		if len(p) < n {
			return ""
		}
		body := p[:n]
		p = p[n:]
		if typ != 0x0000 { // server_name
			continue
		}
		// server_name_list: u16 length, then entries {u8 type, u16 len, name}.
		if len(body) < 2 {
			return ""
		}
		body = body[2:]
		for len(body) >= 3 {
			nt := body[0]
			nl := int(body[1])<<8 | int(body[2])
			body = body[3:]
			if len(body) < nl {
				return ""
			}
			if nt == 0 {
				return cleanHost(string(body[:nl]))
			}
			body = body[nl:]
		}
		return ""
	}
	return ""
}

var httpMethods = []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "TRACE "}

// httpMethodPrefix reports whether b starts with an HTTP method (match), or
// is a strict prefix of one (partial).
func httpMethodPrefix(b []byte) (match, partial bool) {
	for _, m := range httpMethods {
		if len(b) >= len(m) {
			if string(b[:len(m)]) == m {
				return true, false
			}
		} else if string(b) == m[:len(b)] {
			partial = true
		}
	}
	return false, partial
}

func sniffHTTP(b []byte) (string, bool) {
	end := bytes.Index(b, []byte("\r\n\r\n"))
	if end < 0 {
		return "", true
	}
	for _, line := range strings.Split(string(b[:end]), "\r\n")[1:] {
		k, v, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "host") {
			continue
		}
		v = strings.TrimSpace(v)
		if h, _, err := net.SplitHostPort(v); err == nil {
			v = h
		}
		return cleanHost(v), false
	}
	return "", false
}

// cleanHost lower-cases a sniffed host name and rejects IPs and anything
// that is not a plausible DNS name.
func cleanHost(s string) string {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if s == "" || len(s) > 253 || net.ParseIP(s) != nil || !strings.Contains(s, ".") {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_') {
			return ""
		}
	}
	return s
}

// sniffConn is a lazily dialed net.Conn. Bytes written to it are buffered
// until SniffHost finds the destination host (or gives up); then dial is
// called with that host and the buffer is flushed. Reads wait for the dial;
// if the client sends nothing within sniffWait the dial happens without a
// host.
type sniffConn struct {
	dial   func(ctx context.Context, host string) (net.Conn, error)
	ctx    context.Context
	cancel context.CancelFunc

	mu    sync.Mutex
	buf   []byte
	ready chan struct{} // closed once conn/err are final
	conn  net.Conn
	err   error
}

func newSniffConn(parent context.Context, dial func(ctx context.Context, host string) (net.Conn, error)) *sniffConn {
	ctx, cancel := context.WithCancel(parent)
	return &sniffConn{dial: dial, ctx: ctx, cancel: cancel, ready: make(chan struct{})}
}

func (s *sniffConn) isReady() bool {
	select {
	case <-s.ready:
		return true
	default:
		return false
	}
}

// finishLocked dials and flushes the buffer. Caller holds s.mu and the
// conn is not ready yet.
func (s *sniffConn) finishLocked(host string) {
	conn, err := s.dial(s.ctx, host)
	if err == nil && len(s.buf) > 0 {
		if _, werr := conn.Write(s.buf); werr != nil {
			conn.Close()
			conn, err = nil, werr
		}
	}
	s.buf = nil
	s.conn, s.err = conn, err
	close(s.ready)
}

func (s *sniffConn) Write(p []byte) (int, error) {
	if !s.isReady() {
		s.mu.Lock()
		if !s.isReady() {
			s.buf = append(s.buf, p...)
			host, more := SniffHost(s.buf)
			if more && len(s.buf) < sniffMax {
				s.mu.Unlock()
				return len(p), nil
			}
			s.finishLocked(host)
			err := s.err
			s.mu.Unlock()
			if err != nil {
				return 0, err
			}
			return len(p), nil
		}
		s.mu.Unlock()
	}
	if s.err != nil {
		return 0, s.err
	}
	return s.conn.Write(p)
}

func (s *sniffConn) Read(p []byte) (int, error) {
	if !s.isReady() {
		t := time.NewTimer(sniffWait)
		select {
		case <-s.ready:
		case <-t.C:
			s.mu.Lock()
			if !s.isReady() {
				host, _ := SniffHost(s.buf)
				s.finishLocked(host)
			}
			s.mu.Unlock()
		}
		t.Stop()
	}
	if s.err != nil {
		return 0, s.err
	}
	return s.conn.Read(p)
}

// CloseWrite is called by go-socks5 when the client stops sending: no more
// bytes can reveal the host, so dial now. Like the plain counting conn used
// before, it does not half-close the upstream.
func (s *sniffConn) CloseWrite() error {
	s.mu.Lock()
	if !s.isReady() {
		host, _ := SniffHost(s.buf)
		s.finishLocked(host)
	}
	s.mu.Unlock()
	return nil
}

func (s *sniffConn) Close() error {
	s.cancel()
	s.mu.Lock()
	if !s.isReady() {
		s.err = net.ErrClosed
		close(s.ready)
	}
	s.mu.Unlock()
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// LocalAddr must be a *net.TCPAddr: go-socks5 puts it in its success reply.
func (s *sniffConn) LocalAddr() net.Addr {
	if s.isReady() && s.conn != nil {
		if a, ok := s.conn.LocalAddr().(*net.TCPAddr); ok {
			return a
		}
	}
	return &net.TCPAddr{IP: net.IPv4zero}
}

func (s *sniffConn) RemoteAddr() net.Addr {
	if s.isReady() && s.conn != nil {
		return s.conn.RemoteAddr()
	}
	return &net.TCPAddr{IP: net.IPv4zero}
}

func (s *sniffConn) SetDeadline(t time.Time) error {
	if s.isReady() && s.conn != nil {
		return s.conn.SetDeadline(t)
	}
	return nil
}

func (s *sniffConn) SetReadDeadline(t time.Time) error {
	if s.isReady() && s.conn != nil {
		return s.conn.SetReadDeadline(t)
	}
	return nil
}

func (s *sniffConn) SetWriteDeadline(t time.Time) error {
	if s.isReady() && s.conn != nil {
		return s.conn.SetWriteDeadline(t)
	}
	return nil
}
