package engine

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"proxy-dispatcher/internal/config"
)

// HttpHandler handles incoming HTTP proxy client connections.
type HttpHandler struct {
	logger *slog.Logger
}

// NewHttpHandler creates a new HTTP proxy handler.
func NewHttpHandler(logger *slog.Logger) *HttpHandler {
	return &HttpHandler{logger: logger}
}

var hopByHopHeaders = map[string]bool{
	"Proxy-Authorization": true,
	"Proxy-Connection":    true,
	"Keep-Alive":          true,
	"Upgrade":             true,
	"Te":                  true,
	"Trailer":             true,
}

// HandleConnection reads the first request from clientConn and dispatches
// either a CONNECT tunnel or plain HTTP forward through the upstream proxy.
// It returns the byte counts from the pipe session.
func (h *HttpHandler) HandleConnection(ctx context.Context, clientConn *BufferedConn, proxy config.ProxyEntry) (PipeResult, error) {
	// Use clientConn's own buffered reader: wrapping it in another bufio
	// layer would read ahead and strand bytes in a reader that is discarded.
	reader := clientConn.reader
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return PipeResult{}, fmt.Errorf("read request line: %w", err)
	}
	requestLine = strings.TrimRight(requestLine, "\r\n")
	parts := strings.SplitN(requestLine, " ", 3)
	if len(parts) < 3 {
		return PipeResult{}, fmt.Errorf("malformed request line: %q", requestLine)
	}

	method := parts[0]
	target := parts[1]

	// Read headers into a map.
	tp := textproto.NewReader(reader)
	mimeHeader, err := tp.ReadMIMEHeader()
	if err != nil {
		return PipeResult{}, fmt.Errorf("read headers: %w", err)
	}

	if method == "CONNECT" {
		return h.handleConnect(ctx, clientConn, target, proxy)
	}
	return h.handlePlainHTTP(ctx, clientConn, requestLine, mimeHeader, proxy)
}

func (h *HttpHandler) handleConnect(ctx context.Context, clientConn *BufferedConn, targetHost string, proxy config.ProxyEntry) (PipeResult, error) {
	var proxyConn net.Conn
	var err error

	switch proxy.Type {
	case "http":
		d := net.Dialer{Timeout: 15 * time.Second}
		proxyConn, err = d.DialContext(ctx, "tcp", net.JoinHostPort(proxy.Host, strconv.Itoa(proxy.Port)))
		if err != nil {
			return PipeResult{}, fmt.Errorf("dial http proxy: %w", err)
		}
		req := "CONNECT " + targetHost + " HTTP/1.1\r\nHost: " + targetHost + "\r\n"
		if proxy.User != "" {
			req += "Proxy-Authorization: " + ProxyBasicAuth(proxy.User, proxy.Pass) + "\r\n"
		}
		req += "\r\n"
		if _, err := proxyConn.Write([]byte(req)); err != nil {
			proxyConn.Close()
			return PipeResult{}, fmt.Errorf("write connect: %w", err)
		}
		resp, err := readConnectResponse(proxyConn)
		if err != nil {
			proxyConn.Close()
			return PipeResult{}, fmt.Errorf("read connect response: %w", err)
		}
		if len(resp) < 12 || resp[9:12] != "200" {
			proxyConn.Close()
			return PipeResult{}, fmt.Errorf("upstream CONNECT failed: %s", resp)
		}
	case "socks5":
		proxyConn, err = dialThroughSOCKS5Proxy(ctx, proxy, targetHost)
		if err != nil {
			return PipeResult{}, err
		}
	default:
		return PipeResult{}, fmt.Errorf("unsupported proxy type: %s", proxy.Type)
	}
	defer proxyConn.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		return PipeResult{}, fmt.Errorf("write 200: %w", err)
	}

	// Pipe reads through clientConn's buffered reader, so any bytes the
	// client sent after the CONNECT headers are forwarded naturally.
	pr := Pipe(ctx, clientConn, proxyConn, 60*time.Second)
	return pr, nil
}

func (h *HttpHandler) handlePlainHTTP(ctx context.Context, clientConn *BufferedConn, requestLine string, headers textproto.MIMEHeader, proxy config.ProxyEntry) (PipeResult, error) {
	d := net.Dialer{Timeout: 15 * time.Second}
	proxyConn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(proxy.Host, strconv.Itoa(proxy.Port)))
	if err != nil {
		return PipeResult{}, fmt.Errorf("dial http proxy: %w", err)
	}
	defer proxyConn.Close()

	var sb strings.Builder
	sb.WriteString(requestLine)
	sb.WriteString("\r\n")

	if proxy.User != "" {
		sb.WriteString("Proxy-Authorization: ")
		sb.WriteString(ProxyBasicAuth(proxy.User, proxy.Pass))
		sb.WriteString("\r\n")
	}

	for k, vs := range headers {
		if hopByHopHeaders[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vs {
			sb.WriteString(k)
			sb.WriteString(": ")
			sb.WriteString(v)
			sb.WriteString("\r\n")
		}
	}
	sb.WriteString("\r\n")

	reqBytes := int64(len(sb.String()))
	if _, err := proxyConn.Write([]byte(sb.String())); err != nil {
		return PipeResult{}, fmt.Errorf("write request: %w", err)
	}

	// Pipe the remainder bidirectionally. The previous sequential approach
	// (copy the body, then copy the response) deadlocked on chunked uploads:
	// io.Copy waited for client EOF while the client waited for a response.
	pr := Pipe(ctx, clientConn, proxyConn, 60*time.Second)
	pr.BytesSent += reqBytes
	return pr, nil
}
