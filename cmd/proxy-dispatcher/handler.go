package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"proxy-dispatcher/internal/bandwidth"
	"proxy-dispatcher/internal/config"
	"proxy-dispatcher/internal/engine"
	"proxy-dispatcher/internal/report"
	"proxy-dispatcher/internal/rules"
	"proxy-dispatcher/internal/security"
)

// ConnHandler processes incoming client connections, performing protocol
// detection, rule evaluation, and routing through proxy / direct / block.
type ConnHandler struct {
	cfg           *config.AppConfig
	socks5H       *engine.Socks5Handler
	httpH         *engine.HttpHandler
	groupMgr      *engine.GroupManager
	ruleEngine    *rules.RuleEngine
	directDialer  *engine.DirectDialer
	whitelistMgr  *security.WhitelistManager
	bruteGuard    *security.BruteGuard
	tracker       *bandwidth.Tracker
	sizeForwarder *engine.SizeForwarder
	retryHandler  *engine.RetryHandler
	reportHub     *report.ReportHub
	idleTimeout   time.Duration
	logger        *slog.Logger
}

// Handle is the per-connection entrypoint called by the ListenerManager.
func (h *ConnHandler) Handle(conn net.Conn) {
	startTime := time.Now()
	clientIP := extractHost(conn.RemoteAddr().String())

	if !h.checkWhitelist(conn, clientIP) {
		return
	}

	outputPort := extractPort(conn.LocalAddr())
	group, err := h.groupMgr.GetGroupForPort(outputPort)
	if err != nil {
		h.logger.Warn("no group for port", "port", outputPort, "error", err)
		return
	}

	proto, buffConn, err := engine.DetectProtocol(conn)
	if err != nil || proto == "unknown" {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if proto == "socks5" {
		h.handleSOCKS5(ctx, buffConn, group, clientIP, outputPort, startTime)
		return
	}

	h.handleHTTP(ctx, buffConn, group, clientIP, outputPort, startTime, proto)
}

// checkWhitelist verifies the client IP. Returns false if blocked (conn is closed).
func (h *ConnHandler) checkWhitelist(conn net.Conn, clientIP string) bool {
	allowed, reason := h.whitelistMgr.IsAllowed(clientIP)
	if allowed {
		return true
	}
	h.bruteGuard.RecordAndCheck(clientIP)
	h.logger.Debug("whitelist rejected", "ip", clientIP, "reason", reason)
	h.record(0, clientIP, "", "", "", "", "", "blocked", "", "whitelist: "+reason, 403, 0, 0, 0)
	conn.Close()
	return false
}

// handleSOCKS5 routes a SOCKS5 connection through the upstream proxy
// (or directly if the destination matches a bypass rule).
func (h *ConnHandler) handleSOCKS5(ctx context.Context, buffConn *engine.BufferedConn, group *engine.ManagedGroup, clientIP string, outputPort int, startTime time.Time) {
	proxy, err := group.NextProxy(outputPort, clientIP)
	if err != nil {
		h.logger.Warn("no proxy available", "group", group.Name)
		h.record(outputPort, clientIP, "", "", "", "", "socks5", "proxy", "", "no proxy available", 502, 0, 0, 0)
		return
	}

	proxyAddr := fmt.Sprintf("%s:%d", proxy.Host, proxy.Port)
	sResult, sErr := h.socks5H.HandleConnection(ctx, buffConn, *proxy, group.Rotator, clientIP)
	latency := time.Since(startTime).Milliseconds()

	destHost, destPort, bytesSent, bytesRecv := extractSocksResult(sResult)
	if sResult != nil && sResult.ProxyUsed != "" {
		proxyAddr = sResult.ProxyUsed
	}

	routeType := "proxy"
	if sResult != nil && sResult.RouteType != "" {
		routeType = sResult.RouteType
	}

	// Feed bytes into bandwidth tracker and auto-bypass.
	totalBytes := bytesSent + bytesRecv
	if destHost != "" {
		if totalBytes > 0 {
			h.tracker.Record(destHost, totalBytes, routeType)
		}
		if routeType == "proxy" {
			h.sizeForwarder.CheckAutoBypass(destHost, outputPort, totalBytes)
		}
	}

	inputProxy := proxyAddr
	if routeType == "direct" {
		inputProxy = ""
	}

	if sErr == nil {
		h.record(outputPort, clientIP, destHost, destPort, "CONNECT", "", "socks5", routeType, inputProxy, "", 200, bytesSent, bytesRecv, latency)
		return
	}

	errStr := sErr.Error()
	switch {
	case isNormalClose(errStr):
		h.record(outputPort, clientIP, destHost, destPort, "CONNECT", "", "socks5", routeType, inputProxy, "", 200, bytesSent, bytesRecv, latency)
	case strings.Contains(errStr, "blocked by rule"):
		h.record(outputPort, clientIP, destHost, destPort, "CONNECT", "", "socks5", "blocked", "", "blocked by rule", 403, 0, 0, latency)
	default:
		h.logger.Debug("socks5 session error", "error", sErr)
		h.record(outputPort, clientIP, destHost, destPort, "CONNECT", "", "socks5", routeType, inputProxy, errStr, 502, bytesSent, bytesRecv, latency)
	}
}

// handleHTTP routes an HTTP/HTTPS connection based on rule evaluation.
func (h *ConnHandler) handleHTTP(ctx context.Context, buffConn *engine.BufferedConn, group *engine.ManagedGroup, clientIP string, outputPort int, startTime time.Time, detectedProto string) {
	reqInfo, extractErr := engine.ExtractHTTPTarget(buffConn)
	if extractErr != nil {
		h.handleHTTPFallback(ctx, buffConn, group, clientIP, outputPort, startTime)
		return
	}

	prefixConn := engine.NewPrefixConn(reqInfo.ConsumedBytes, buffConn)
	action := h.ruleEngine.Evaluate(reqInfo.Host, reqInfo.UrlPath)
	proto4 := "http"
	if reqInfo.IsHTTPS {
		proto4 = "https"
	}

	switch action.Type {
	case "block":
		h.routeBlock(prefixConn, reqInfo, outputPort, clientIP, proto4, startTime, action)
	case "direct":
		h.routeDirect(ctx, buffConn, prefixConn, reqInfo, outputPort, clientIP, proto4, startTime)
	case "resource":
		h.routeResource(ctx, buffConn, prefixConn, reqInfo, outputPort, clientIP, proto4, startTime)
	default:
		h.routeProxy(ctx, buffConn, prefixConn, reqInfo, group, outputPort, clientIP, proto4, startTime)
	}
}

// handleHTTPFallback handles connections where HTTP target extraction failed.
func (h *ConnHandler) handleHTTPFallback(ctx context.Context, buffConn *engine.BufferedConn, group *engine.ManagedGroup, clientIP string, outputPort int, startTime time.Time) {
	proxy, err := group.NextProxy(outputPort, clientIP)
	if err != nil {
		h.logger.Warn("no proxy available", "group", group.Name)
		h.record(outputPort, clientIP, "unknown", "", "", "", "http", "proxy", "", "no proxy available", 502, 0, 0, 0)
		return
	}
	pr, err := h.httpH.HandleConnection(ctx, buffConn, *proxy)
	if err != nil {
		h.logger.Debug("http fallback ended", "error", err)
	}
	h.tracker.Record("unknown", pr.BytesSent+pr.BytesReceived, "proxy")
	h.record(outputPort, clientIP, "unknown", "", "", "", "http", "proxy", fmt.Sprintf("%s:%d", proxy.Host, proxy.Port), "", 200, pr.BytesSent, pr.BytesReceived, time.Since(startTime).Milliseconds())
}

func (h *ConnHandler) routeBlock(prefixConn net.Conn, reqInfo *engine.RequestInfo, outputPort int, clientIP, proto4 string, startTime time.Time, action rules.RouteAction) {
	_ = rules.ExecuteBlockAction(prefixConn, action.Block, "http")
	h.tracker.Record(reqInfo.Host, 0, "block")
	h.record(outputPort, clientIP, reqInfo.Host, reqInfo.Port, reqInfo.Method, reqInfo.UrlPath, proto4, "blocked", "", "blocked by rule", 403, 0, 0, time.Since(startTime).Milliseconds())
}

func (h *ConnHandler) routeDirect(ctx context.Context, buffConn *engine.BufferedConn, prefixConn net.Conn, reqInfo *engine.RequestInfo, outputPort int, clientIP, proto4 string, startTime time.Time) {
	remoteConn, err := h.directDialer.Dial(ctx, reqInfo.Target)
	if err != nil {
		h.logger.Debug("direct dial failed", "target", reqInfo.Target, "error", err)
		h.record(outputPort, clientIP, reqInfo.Host, reqInfo.Port, reqInfo.Method, reqInfo.UrlPath, proto4, "direct", "", err.Error(), 502, 0, 0, time.Since(startTime).Milliseconds())
		return
	}
	pr := h.pipeDirectConn(ctx, buffConn, prefixConn, remoteConn, reqInfo)
	h.tracker.Record(reqInfo.Host, pr.BytesSent+pr.BytesReceived, "direct")
	h.record(outputPort, clientIP, reqInfo.Host, reqInfo.Port, reqInfo.Method, reqInfo.UrlPath, proto4, "direct", "", "", 200, pr.BytesSent, pr.BytesReceived, time.Since(startTime).Milliseconds())
}

func (h *ConnHandler) routeResource(ctx context.Context, buffConn *engine.BufferedConn, prefixConn net.Conn, reqInfo *engine.RequestInfo, outputPort int, clientIP, proto4 string, startTime time.Time) {
	resProxy := rules.ResolveBypassTarget("resource", h.cfg.ResourceProxy)
	if resProxy == nil {
		// No resource proxy configured — fallback to direct.
		h.routeDirect(ctx, buffConn, prefixConn, reqInfo, outputPort, clientIP, proto4, startTime)
		return
	}
	remoteConn, err := h.directDialer.DialThroughResource(ctx, reqInfo.Target, *resProxy)
	if err != nil {
		h.logger.Debug("resource dial failed", "target", reqInfo.Target, "error", err)
		h.record(outputPort, clientIP, reqInfo.Host, reqInfo.Port, reqInfo.Method, reqInfo.UrlPath, proto4, "resource", "", err.Error(), 502, 0, 0, time.Since(startTime).Milliseconds())
		return
	}
	pr := engine.Pipe(ctx, prefixConn, remoteConn, h.idleTimeout)
	h.tracker.Record(reqInfo.Host, pr.BytesSent+pr.BytesReceived, "resource")
	h.record(outputPort, clientIP, reqInfo.Host, reqInfo.Port, reqInfo.Method, reqInfo.UrlPath, proto4, "resource", "", "", 200, pr.BytesSent, pr.BytesReceived, time.Since(startTime).Milliseconds())
}

func (h *ConnHandler) routeProxy(ctx context.Context, buffConn *engine.BufferedConn, prefixConn net.Conn, reqInfo *engine.RequestInfo, group *engine.ManagedGroup, outputPort int, clientIP, proto4 string, startTime time.Time) {
	var finalRes engine.SizeForwardResult
	var finalProxyAddr string

	// For fixed rotation, create a single-proxy rotator for retry compatibility.
	rotator := group.Rotator
	if _, ok := group.Rotator.(*engine.FixedRotator); ok {
		proxy, err := group.NextProxy(outputPort, clientIP)
		if err != nil {
			h.record(outputPort, clientIP, reqInfo.Host, reqInfo.Port, reqInfo.Method, reqInfo.UrlPath, proto4, "proxy", "", err.Error(), 502, 0, 0, time.Since(startTime).Milliseconds())
			return
		}
		rotator = &engine.SingleProxyRotator{Proxy: proxy}
	}

	_, retryErr := h.retryHandler.WithRetry(ctx, rotator, clientIP, func(proxy *config.ProxyEntry) error {
		group.Rotator.IncrementConn(proxy)
		defer group.Rotator.DecrementConn(proxy)

		proxyAddr := fmt.Sprintf("%s:%d", proxy.Host, proxy.Port)
		finalProxyAddr = proxyAddr

		proxyConn, dialErr := net.DialTimeout("tcp", proxyAddr, time.Duration(h.cfg.ConnTimeout)*time.Second)
		if dialErr != nil {
			h.logger.Debug("proxy dial failed", "target", proxyAddr, "error", dialErr)
			return dialErr
		}

		if len(reqInfo.ConsumedBytes) > 0 && reqInfo.IsHTTPS {
			return h.proxyHTTPS(ctx, buffConn, proxyConn, reqInfo, proxy, outputPort, &finalRes)
		}

		// Plain HTTP: inject proxy auth then forward.
		if len(reqInfo.ConsumedBytes) > 0 {
			outBytes := reqInfo.ConsumedBytes
			if proxy.User != "" {
				outBytes = engine.InjectProxyAuth(reqInfo.ConsumedBytes, proxy.User, proxy.Pass)
			}
			if _, err := proxyConn.Write(outBytes); err != nil {
				proxyConn.Close()
				return err
			}
		}
		res, sfErr := h.sizeForwarder.Forward(ctx, prefixConn, proxyConn, reqInfo, reqInfo.ConsumedBytes, outputPort)
		if sfErr != nil {
			return sfErr
		}
		finalRes = res
		return nil
	})

	if retryErr != nil {
		h.logger.Debug("proxy retry exhausted", "error", retryErr)
		h.record(outputPort, clientIP, reqInfo.Host, reqInfo.Port, reqInfo.Method, reqInfo.UrlPath, proto4, "proxy", finalProxyAddr, retryErr.Error(), 502, 0, 0, time.Since(startTime).Milliseconds())
		return
	}
	h.record(outputPort, clientIP, reqInfo.Host, reqInfo.Port, reqInfo.Method, reqInfo.UrlPath, proto4, "proxy", finalProxyAddr, "", 200, finalRes.BytesSent, finalRes.BytesReceived, time.Since(startTime).Milliseconds())
}

// proxyHTTPS establishes a CONNECT tunnel through upstream proxy for HTTPS.
func (h *ConnHandler) proxyHTTPS(ctx context.Context, buffConn *engine.BufferedConn, proxyConn net.Conn, reqInfo *engine.RequestInfo, proxy *config.ProxyEntry, outputPort int, result *engine.SizeForwardResult) error {
	connectReq := "CONNECT " + reqInfo.Target + " HTTP/1.1\r\nHost: " + reqInfo.Target + "\r\n"
	if proxy.User != "" {
		connectReq += "Proxy-Authorization: " + engine.ProxyBasicAuth(proxy.User, proxy.Pass) + "\r\n"
	}
	connectReq += "\r\n"

	if _, err := proxyConn.Write([]byte(connectReq)); err != nil {
		proxyConn.Close()
		return fmt.Errorf("write CONNECT: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := proxyConn.Read(buf)
	if err != nil {
		proxyConn.Close()
		return fmt.Errorf("read CONNECT response: %w", err)
	}
	resp := string(buf[:n])
	if len(resp) < 12 || resp[9:12] != "200" {
		proxyConn.Close()
		return fmt.Errorf("upstream CONNECT failed: %s", resp)
	}

	if _, err := buffConn.Conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		proxyConn.Close()
		return fmt.Errorf("write 200: %w", err)
	}

	res, sfErr := h.sizeForwarder.Forward(ctx, buffConn.Conn, proxyConn, reqInfo, nil, outputPort)
	if sfErr != nil {
		return sfErr
	}
	*result = res
	return nil
}

// pipeDirectConn pipes data between client and remote for direct connections.
func (h *ConnHandler) pipeDirectConn(ctx context.Context, buffConn *engine.BufferedConn, prefixConn net.Conn, remoteConn net.Conn, reqInfo *engine.RequestInfo) engine.PipeResult {
	if reqInfo.IsHTTPS {
		if _, err := buffConn.Conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			remoteConn.Close()
			return engine.PipeResult{}
		}
		return engine.Pipe(ctx, buffConn.Conn, remoteConn, h.idleTimeout)
	}
	return engine.Pipe(ctx, prefixConn, remoteConn, h.idleTimeout)
}

// record creates and records a log entry.
func (h *ConnHandler) record(listenPort int, clientIP, domain, portStr, method, urlPath, proto, routeType, inputProxy, errStr string, status int, bytesSent, bytesRecv, latencyMs int64) {
	e := report.NewLogEntry()
	e.ListenPort = listenPort
	e.ClientIP = clientIP
	e.Domain = domain
	if portStr != "" {
		fmt.Sscanf(portStr, "%d", &e.Port)
	}
	e.Method = method
	e.URLPath = urlPath
	e.Protocol = proto
	e.StatusCode = status
	e.RouteType = routeType
	e.InputProxy = inputProxy
	e.BytesSent = bytesSent
	e.BytesRecv = bytesRecv
	e.LatencyMs = latencyMs
	e.Error = errStr
	h.reportHub.Record(e)
}

// --- Helpers ---

func extractHost(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

func extractPort(addr net.Addr) int {
	_, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return 0
	}
	n := 0
	fmt.Sscanf(portStr, "%d", &n)
	return n
}

func extractSocksResult(r *engine.Socks5Result) (destHost, destPort string, bytesSent, bytesRecv int64) {
	if r == nil {
		return
	}
	return r.DestHost, r.DestPort, r.BytesSent, r.BytesRecv
}

func isNormalClose(errStr string) bool {
	return strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "use of closed")
}
