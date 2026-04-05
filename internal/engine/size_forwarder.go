package engine

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"proxy-dispatcher/internal/bandwidth"
	"proxy-dispatcher/internal/config"
	"proxy-dispatcher/internal/rules"
)

// SizeForwarderDeps holds all dependencies for SizeForwarder.
type SizeForwarderDeps struct {
	AutoBypassCfg config.AutoBypassConfig
	RuleEngine    *rules.RuleEngine
	Tracker       *bandwidth.Tracker
	DirectDialer  *DirectDialer
	BudgetCtrl    *bandwidth.BudgetController
	ResourceProxy *config.ProxyEntry
	IdleTimeout   time.Duration
	Logger        *slog.Logger
}

// SizeForwardResult embeds PipeResult and indicates if routing changed.
type SizeForwardResult struct {
	PipeResult
	RouteChanged bool
}

// SizeForwarder inspects response size and optionally switches to direct.
type SizeForwarder struct {
	deps SizeForwarderDeps
}

// NewSizeForwarder creates a SizeForwarder.
func NewSizeForwarder(deps SizeForwarderDeps) *SizeForwarder {
	return &SizeForwarder{deps: deps}
}

// Forward sends a request through proxyConn, optionally switching to
// direct if the response exceeds the configured size threshold.
func (sf *SizeForwarder) Forward(ctx context.Context, client net.Conn, proxyConn net.Conn, reqInfo *RequestInfo, consumedReqBytes []byte) (SizeForwardResult, error) {
	domain := reqInfo.Host
	cfg := sf.deps.AutoBypassCfg

	// Budget check.
	budgetResult := sf.deps.BudgetCtrl.CheckBudget(domain)
	if !budgetResult.Allowed {
		proxyConn.Close()
		switch budgetResult.Action {
		case "direct":
			return sf.retryDirect(ctx, client, reqInfo, consumedReqBytes)
		case "drop":
			client.Close()
			return SizeForwardResult{}, fmt.Errorf("budget exceeded, dropped")
		default: // "throttle" or unknown
			pr := Pipe(ctx, client, proxyConn, sf.deps.IdleTimeout)
			sf.deps.Tracker.Record(domain, pr.BytesSent+pr.BytesReceived, "proxy")
			return SizeForwardResult{PipeResult: pr}, nil
		}
	}

	// Force proxy — skip size check.
	if sf.deps.RuleEngine.IsForceProxy(domain) {
		pr := Pipe(ctx, client, proxyConn, sf.deps.IdleTimeout)
		sf.deps.Tracker.Record(domain, pr.BytesSent+pr.BytesReceived, "proxy")
		return SizeForwardResult{PipeResult: pr}, nil
	}

	if !cfg.Enabled {
		pr := Pipe(ctx, client, proxyConn, sf.deps.IdleTimeout)
		sf.deps.Tracker.Record(domain, pr.BytesSent+pr.BytesReceived, "proxy")
		return SizeForwardResult{PipeResult: pr}, nil
	}

	// CONNECT tunnels: predict or stream only.
	if reqInfo.IsHTTPS {
		if cfg.PredictEnabled && cfg.Strategy != "stream" {
			avg := sf.deps.Tracker.GetDomainAvgSize(domain)
			if avg > int64(float64(cfg.SizeThreshold)*0.8) {
				proxyConn.Close()
				return sf.retryDirect(ctx, client, reqInfo, consumedReqBytes)
			}
		}
		pr := Pipe(ctx, client, proxyConn, sf.deps.IdleTimeout)
		sf.deps.Tracker.Record(domain, pr.BytesSent+pr.BytesReceived, "proxy")
		return SizeForwardResult{PipeResult: pr}, nil
	}

	switch cfg.Strategy {
	case "header":
		return sf.headerStrategy(ctx, client, proxyConn, reqInfo, consumedReqBytes, domain)
	case "stream":
		return sf.streamStrategy(ctx, client, proxyConn, domain)
	case "predict":
		return sf.predictStrategy(ctx, client, proxyConn, reqInfo, consumedReqBytes, domain)
	default:
		pr := Pipe(ctx, client, proxyConn, sf.deps.IdleTimeout)
		sf.deps.Tracker.Record(domain, pr.BytesSent+pr.BytesReceived, "proxy")
		return SizeForwardResult{PipeResult: pr}, nil
	}
}

func (sf *SizeForwarder) headerStrategy(ctx context.Context, client, proxyConn net.Conn, reqInfo *RequestInfo, consumed []byte, domain string) (SizeForwardResult, error) {
	cfg := sf.deps.AutoBypassCfg
	reader := bufio.NewReaderSize(proxyConn, 4096)

	// Read response status line + headers without consuming body.
	var headerBuf []byte
	contentLength := int64(-1)
	for {
		line, err := reader.ReadBytes('\n')
		headerBuf = append(headerBuf, line...)
		if err != nil {
			// Failed to read headers — just pipe what we have.
			break
		}
		lineStr := strings.TrimSpace(string(line))
		if lineStr == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(lineStr), "content-length:") {
			val := strings.TrimSpace(lineStr[len("content-length:"):])
			if n, err := strconv.ParseInt(val, 10, 64); err == nil {
				contentLength = n
			}
		}
	}

	if contentLength > cfg.SizeThreshold {
		sf.deps.Logger.Info("header strategy: large response, switching to direct", "domain", domain, "content_length", contentLength)
		proxyConn.Close()
		res, err := sf.retryDirect(ctx, client, reqInfo, consumed)
		res.RouteChanged = true
		return res, err
	}

	// Forward the already-read headers to client, then pipe the rest.
	if _, err := client.Write(headerBuf); err != nil {
		proxyConn.Close()
		return SizeForwardResult{}, err
	}

	// Pipe remaining body: reader (has buffered data) → client, client → proxyConn.
	pr := Pipe(ctx, client, newReaderConn(reader, proxyConn), sf.deps.IdleTimeout)
	total := int64(len(headerBuf)) + pr.BytesSent + pr.BytesReceived
	sf.deps.Tracker.Record(domain, total, "proxy")
	return SizeForwardResult{PipeResult: pr}, nil
}

func (sf *SizeForwarder) streamStrategy(ctx context.Context, client, proxyConn net.Conn, domain string) (SizeForwardResult, error) {
	cfg := sf.deps.AutoBypassCfg
	counter := NewStreamCounter(proxyConn, cfg.SizeThreshold, func(n int64) {
		sf.deps.Logger.Info("stream strategy: threshold exceeded", "domain", domain, "bytes", n)
	})
	wrapped := &countConn{Conn: proxyConn, reader: counter}
	pr := Pipe(ctx, client, wrapped, sf.deps.IdleTimeout)
	sf.deps.Tracker.Record(domain, pr.BytesSent+pr.BytesReceived, "proxy")
	return SizeForwardResult{PipeResult: pr}, nil
}

func (sf *SizeForwarder) predictStrategy(ctx context.Context, client, proxyConn net.Conn, reqInfo *RequestInfo, consumed []byte, domain string) (SizeForwardResult, error) {
	cfg := sf.deps.AutoBypassCfg
	if cfg.PredictEnabled {
		avg := sf.deps.Tracker.GetDomainAvgSize(domain)
		if avg > int64(float64(cfg.SizeThreshold)*0.8) {
			sf.deps.Logger.Info("predict strategy: bypassing", "domain", domain, "avg_size", avg)
			proxyConn.Close()
			res, err := sf.retryDirect(ctx, client, reqInfo, consumed)
			res.RouteChanged = true
			return res, err
		}
	}
	return sf.headerStrategy(ctx, client, proxyConn, reqInfo, consumed, domain)
}

func (sf *SizeForwarder) retryDirect(ctx context.Context, client net.Conn, reqInfo *RequestInfo, consumedReqBytes []byte) (SizeForwardResult, error) {
	remoteConn, err := sf.deps.DirectDialer.Dial(ctx, reqInfo.Target)
	if err != nil {
		return SizeForwardResult{}, fmt.Errorf("direct retry dial: %w", err)
	}
	// Send the original request bytes that the client already sent.
	if len(consumedReqBytes) > 0 {
		if _, err := remoteConn.Write(consumedReqBytes); err != nil {
			remoteConn.Close()
			return SizeForwardResult{}, fmt.Errorf("direct retry write: %w", err)
		}
	}
	pr := Pipe(ctx, client, remoteConn, sf.deps.IdleTimeout)
	sf.deps.Tracker.Record(reqInfo.Host, pr.BytesSent+pr.BytesReceived, "direct")
	return SizeForwardResult{PipeResult: pr, RouteChanged: true}, nil
}

// countConn wraps a net.Conn replacing Read with a StreamCounter.
type countConn struct {
	net.Conn
	reader io.Reader
}

func (c *countConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// readerConn wraps a buffered reader over a net.Conn so the buffered
// bytes are consumed first.
type readerConn struct {
	reader io.Reader
	net.Conn
}

func newReaderConn(r *bufio.Reader, conn net.Conn) *readerConn {
	return &readerConn{reader: r, Conn: conn}
}

func (rc *readerConn) Read(p []byte) (int, error) { return rc.reader.Read(p) }
