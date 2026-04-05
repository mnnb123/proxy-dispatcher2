package engine

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"
)

// RequestInfo holds the parsed target info from an HTTP request line.
type RequestInfo struct {
	Method        string
	Target        string // host:port
	Host          string
	Port          string
	UrlPath       string
	RawLine       string
	IsHTTPS       bool
	ConsumedBytes []byte
}

// PrefixConn prepends already-consumed bytes before the real connection,
// implementing net.Conn.
type PrefixConn struct {
	prefix io.Reader
	conn   net.Conn
	reader io.Reader
}

// NewPrefixConn creates a PrefixConn that first yields consumed then conn.
func NewPrefixConn(consumed []byte, conn net.Conn) *PrefixConn {
	pr := bytes.NewReader(consumed)
	return &PrefixConn{
		prefix: pr,
		conn:   conn,
		reader: io.MultiReader(pr, conn),
	}
}

func (pc *PrefixConn) Read(p []byte) (int, error)         { return pc.reader.Read(p) }
func (pc *PrefixConn) Write(p []byte) (int, error)        { return pc.conn.Write(p) }
func (pc *PrefixConn) Close() error                       { return pc.conn.Close() }
func (pc *PrefixConn) LocalAddr() net.Addr                { return pc.conn.LocalAddr() }
func (pc *PrefixConn) RemoteAddr() net.Addr               { return pc.conn.RemoteAddr() }
func (pc *PrefixConn) SetDeadline(t time.Time) error      { return pc.conn.SetDeadline(t) }
func (pc *PrefixConn) SetReadDeadline(t time.Time) error  { return pc.conn.SetReadDeadline(t) }
func (pc *PrefixConn) SetWriteDeadline(t time.Time) error { return pc.conn.SetWriteDeadline(t) }

// Ensure PrefixConn implements net.Conn at compile time.
var _ net.Conn = (*PrefixConn)(nil)

// ExtractHTTPTarget reads just enough from buffConn to determine the
// target host and request type. All consumed bytes are recorded so they
// can be replayed via PrefixConn.
func ExtractHTTPTarget(buffConn *BufferedConn) (*RequestInfo, error) {
	reader := bufio.NewReaderSize(buffConn, 4096)
	var consumed bytes.Buffer

	line, err := readLine(reader)
	if err != nil {
		return nil, fmt.Errorf("read request line: %w", err)
	}
	consumed.Write(line)

	parts := strings.SplitN(strings.TrimRight(string(line), "\r\n"), " ", 3)
	if len(parts) < 3 {
		return nil, fmt.Errorf("malformed request line: %q", string(line))
	}
	method := parts[0]
	rawURL := parts[1]

	info := &RequestInfo{
		Method:  method,
		RawLine: strings.TrimRight(string(line), "\r\n"),
	}

	if method == "CONNECT" {
		info.IsHTTPS = true
		h, p := splitHostPort(rawURL, "443")
		info.Host = h
		info.Port = p
		info.Target = net.JoinHostPort(h, p)

		// Consume remaining headers up to \r\n\r\n.
		hdrs, err := readUntilEmptyLine(reader)
		if err != nil {
			return nil, fmt.Errorf("read CONNECT headers: %w", err)
		}
		consumed.Write(hdrs)
		info.ConsumedBytes = consumed.Bytes()
		return info, nil
	}

	// Non-CONNECT: GET/POST/PUT etc.
	// Read all headers to find Host.
	hdrs, err := readUntilEmptyLine(reader)
	if err != nil {
		return nil, fmt.Errorf("read headers: %w", err)
	}
	consumed.Write(hdrs)

	if strings.HasPrefix(rawURL, "http://") || strings.HasPrefix(rawURL, "https://") {
		u, err := url.Parse(rawURL)
		if err != nil {
			return nil, fmt.Errorf("parse url: %w", err)
		}
		defaultPort := "80"
		if u.Scheme == "https" {
			defaultPort = "443"
			info.IsHTTPS = true
		}
		h, p := splitHostPort(u.Host, defaultPort)
		info.Host = h
		info.Port = p
		info.Target = net.JoinHostPort(h, p)
		info.UrlPath = u.RequestURI()
	} else {
		// Relative path — extract Host from headers.
		hostVal := extractHeader(string(hdrs), "Host")
		if hostVal == "" {
			return nil, fmt.Errorf("no Host header in relative request")
		}
		h, p := splitHostPort(hostVal, "80")
		info.Host = h
		info.Port = p
		info.Target = net.JoinHostPort(h, p)
		info.UrlPath = rawURL
	}

	info.ConsumedBytes = consumed.Bytes()
	return info, nil
}

func splitHostPort(hostport, defaultPort string) (string, string) {
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport, defaultPort
	}
	if p == "" {
		p = defaultPort
	}
	return h, p
}

func readLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadBytes('\n')
		line = append(line, chunk...)
		if err != nil || bytes.HasSuffix(line, []byte("\n")) {
			return line, err
		}
	}
}

func readUntilEmptyLine(r *bufio.Reader) ([]byte, error) {
	var buf bytes.Buffer
	for {
		line, err := r.ReadBytes('\n')
		buf.Write(line)
		if err != nil {
			return buf.Bytes(), err
		}
		if len(line) <= 2 && strings.TrimSpace(string(line)) == "" {
			return buf.Bytes(), nil
		}
	}
}

func extractHeader(headers string, name string) string {
	lower := strings.ToLower(name) + ":"
	for _, line := range strings.Split(headers, "\n") {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), lower) {
			return strings.TrimSpace(line[strings.Index(strings.ToLower(line), lower)+len(lower):])
		}
	}
	return ""
}
