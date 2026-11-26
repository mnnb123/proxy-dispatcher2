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
	// resourceProxy returns the current resource proxy (nil if none). It
	// reads a lock-free snapshot, never the shared *AppConfig.
	resourceProxy func() *config.ProxyEntry
	connTimeout   time.Duration
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

	ipOK, needAuth := h.checkWhitelist(conn, clientIP)
	if !ipOK {
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
		h.handleSOCKS5(ctx, buffConn, group, clientIP, outputPort, startTime, needAuth)
		return
	}

	h.handleHTTP(ctx, buffConn, group, clientIP, outputPort, startTime, proto, needAuth)
}

// badGateway answers a request whose upstream proxy could not be used.
const badGateway = "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n" +
	"Content-Length: 30\r\nConnection: close\r\n\r\nupstream proxy is unavailable\n"

const proxyAuthRequired = "HTTP/1.1 407 Proxy Authentication Required\r\n" +
	"Proxy-Authenticate: Basic realm=\"proxy\"\r\n" +
	"Content-Length: 0\r\nConnection: close\r\n\r\n"

// authFailed records a rejected login. Only wrong credentials count toward
// auto-ban: a client that sent none (a browser's first request before it
// prompts) is just told to authenticate.
func (h *ConnHandler) authFailed(outputPort int, clientIP, proto string, tried bool) {
	reason := "auth: credentials required"
	if tried {
		reason = "auth: wrong user/pass"
		h.bruteGuard.RecordAndCheck(clientIP)
	}
	h.logger.Debug("client auth rejected", "ip", clientIP, "reason", reason)
	h.record(outputPort, clientIP, "", "", "", "", proto, "blocked", "", reason, 407, 0, 0, 0)
}

// checkWhitelist verifies the client IP. ok=false means blocked (conn is
// closed). needAuth=true means the IP is not whitelisted but output accounts
// exist, so the client may still get in with a valid user/pass.
func (h *ConnHandler) checkWhitelist(conn net.Conn, clientIP string) (ok, needAuth bool) {
	// Banned IPs are rejected outright — unless covered by the whitelist.
	if !h.whitelistMgr.Matches(clientIP) {
		if banned, _ := h.bruteGuard.IsBanned(clientIP); banned {
			h.logger.Debug("banned IP rejected", "ip", clientIP)
			h.record(0, clientIP, "", "", "", "", "", "blocked", "", "banned", 403, 0, 0, 0)
			conn.Close()
			return false, false
		}
	}

	allowed, reason := h.whitelistMgr.IsAllowed(clientIP)
	if allowed {
		return true, false
	}
	if h.whitelistMgr.HasAccounts() {
		return true, true
	}
	// Never count/ban an IP that is covered by a whitelist entry
	// (e.g. whitelist matched but rejected for another reason).
	if !h.whitelistMgr.Matches(clientIP) {
		h.bruteGuard.RecordAndCheck(clientIP)
	}
	h.logger.Debug("whitelist rejected", "ip", clientIP, "reason", reason)
	h.record(0, clientIP, "", "", "", "", "", "blocked", "", "whitelist: "+reason, 403, 0, 0, 0)
	conn.Close()
	return false, false
}

// handleSOCKS5 routes a SOCKS5 connection through the upstream proxy
// (or directly if the destination matches a bypass rule).
func (h *ConnHandler) handleSOCKS5(ctx context.Context, buffConn *engine.BufferedConn, group *engine.ManagedGroup, clientIP string, outputPort int, startTime time.Time, needAuth bool) {
	proxy, err := h.groupMgr.GetNextProxy(outputPort, clientIP)
	if err != nil {
		h.logger.Warn("no proxy available", "group", group.Name)
		h.record(outputPort, clientIP, "", "", "", "", "socks5", "proxy", "", "no proxy available", 502, 0, 0, 0)
		return
	}

	proxyAddr := fmt.Sprintf("%s:%d", proxy.Host, proxy.Port)
	var creds func(user, pass string) bool
	if needAuth {
		creds = h.whitelistMgr.CheckAccount
	}
	sResult, sErr := h.socks5H.HandleConnection(ctx, buffConn, *proxy, group.Rotator, clientIP, creds, group.NoBypass)
	latency := time.Since(startTime).Milliseconds()
	if sResult != nil && sResult.AuthDenied {
		h.authFailed(outputPort, clientIP, "socks5", sResult.AuthTried)
		return
	}

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
		if routeType == "proxy" && !group.NoBypass {
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
func (h *ConnHandler) handleHTTP(ctx context.Context, buffConn *engine.BufferedConn, group *engine.ManagedGroup, clientIP string, outputPort int, startTime time.Time, detectedProto string, needAuth bool) {
	reqInfo, extractErr := engine.ExtractHTTPTarget(buffConn)
	if extractErr != nil {
		if needAuth {
			// Cannot read credentials from an unparseable request.
			h.authFailed(outputPort, clientIP, "http", false)
			return
		}
		h.handleHTTPFallback(ctx, buffConn, group, clientIP, outputPort, startTime)
		return
	}
	if needAuth {
		user, pass, sent := engine.ParseProxyBasicAuth(reqInfo.ProxyAuth)
		if !sent || !h.whitelistMgr.CheckAccount(user, pass) {
			_ = buffConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, _ = buffConn.Write([]byte(proxyAuthRequired))
			h.authFailed(outputPort, clientIP, "http", reqInfo.ProxyAuth != "")
			return
		}
	}

	prefixConn := engine.NewPrefixConn(reqInfo.ConsumedBytes, buffConn)
	action := h.ruleEngine.Evaluate(reqInfo.Host, reqInfo.UrlPath)
	if group.NoBypass && (action.Type == "direct" || action.Type == "resource") {
		// Session groups never leave through anything but the port's proxy.
		action.Type = "proxy"
	}
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
	proxy, err := h.groupMgr.GetNextProxy(outputPort, clientIP)
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
	resProxy := h.resourceProxy()
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
	// Use pipeDirectConn so HTTPS gets the CONNECT 200 reply + raw client
	// pipe, and HTTP replays the consumed request line via prefixConn. The
	// resource tunnel from DialThroughResource already reaches the target
	// host directly, so the client's CONNECT line must NOT be replayed into
	// it — doing so corrupts the TLS handshake (ERR_SSL_PROTOCOL_ERROR).
	pr := h.pipeDirectConn(ctx, buffConn, prefixConn, remoteConn, reqInfo)
	h.tracker.Record(reqInfo.Host, pr.BytesSent+pr.BytesReceived, "resource")
	h.record(outputPort, clientIP, reqInfo.Host, reqInfo.Port, reqInfo.Method, reqInfo.UrlPath, proto4, "resource", "", "", 200, pr.BytesSent, pr.BytesReceived, time.Since(startTime).Milliseconds())
}

func (h *ConnHandler) routeProxy(ctx context.Context, buffConn *engine.BufferedConn, prefixConn net.Conn, reqInfo *engine.RequestInfo, group *engine.ManagedGroup, outputPort int, clientIP, proto4 string, startTime time.Time) {
	var finalRes engine.SizeForwardResult
	var finalProxyAddr string
	// started is set once bytes may have reached the client; before that a
	// failure is answered with 502 so the client sees the proxy as dead
	// instead of a connection that just closes.
	started := false

	// Always use direct 1:1 port→proxy lookup. Wrap in SingleProxyRotator for retry compat.
	proxy, err := h.groupMgr.GetNextProxy(outputPort, clientIP)
	if err != nil {
		h.record(outputPort, clientIP, reqInfo.Host, reqInfo.Port, reqInfo.Method, reqInfo.UrlPath, proto4, "proxy", "", err.Error(), 502, 0, 0, time.Since(startTime).Milliseconds())
		return
	}
	rotator := &engine.SingleProxyRotator{Proxy: proxy}

	_, retryErr := h.retryHandler.WithRetry(ctx, rotator, clientIP, func(proxy *config.ProxyEntry) error {
		group.Rotator.IncrementConn(proxy)
		defer group.Rotator.DecrementConn(proxy)

		proxyAddr := fmt.Sprintf("%s:%d", proxy.Host, proxy.Port)
		finalProxyAddr = proxyAddr

		proxyConn, dialErr := net.DialTimeout("tcp", proxyAddr, h.connTimeout)
		if dialErr != nil {
			h.logger.Debug("proxy dial failed", "target", proxyAddr, "error", dialErr)
			return dialErr
		}

		if len(reqInfo.ConsumedBytes) > 0 && reqInfo.IsHTTPS {
			return h.proxyHTTPS(ctx, buffConn, proxyConn, reqInfo, proxy, outputPort, group.NoBypass, &started, &finalRes)
		}

		// Plain HTTP: inject proxy auth then forward. The request head is
		// written here explicitly, so the pipe below must read from buffConn
		// (the bytes after the head), NOT from prefixConn — prefixConn would
		// replay the head a second time and the upstream would see two
		// requests (or a corrupted POST body).
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
		started = true
		res, sfErr := h.forward(ctx, buffConn, proxyConn, reqInfo, reqInfo.ConsumedBytes, outputPort, group.NoBypass)
		if sfErr != nil {
			return sfErr
		}
		finalRes = res
		return nil
	})

	if retryErr != nil {
		h.logger.Debug("proxy retry exhausted", "error", retryErr)
		if !started {
			_ = buffConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, _ = buffConn.Write([]byte(badGateway))
		}
		h.record(outputPort, clientIP, reqInfo.Host, reqInfo.Port, reqInfo.Method, reqInfo.UrlPath, proto4, "proxy", finalProxyAddr, retryErr.Error(), 502, 0, 0, time.Since(startTime).Milliseconds())
		return
	}
	h.record(outputPort, clientIP, reqInfo.Host, reqInfo.Port, reqInfo.Method, reqInfo.UrlPath, proto4, "proxy", finalProxyAddr, "", 200, finalRes.BytesSent, finalRes.BytesReceived, time.Since(startTime).Milliseconds())
}

// proxyHTTPS establishes a CONNECT tunnel through upstream proxy for HTTPS.
func (h *ConnHandler) proxyHTTPS(ctx context.Context, buffConn *engine.BufferedConn, proxyConn net.Conn, reqInfo *engine.RequestInfo, proxy *config.ProxyEntry, outputPort int, noBypass bool, started *bool, result *engine.SizeForwardResult) error {
	connectReq := "CONNECT " + reqInfo.Target + " HTTP/1.1\r\nHost: " + reqInfo.Target + "\r\n"
	if proxy.User != "" {
		connectReq += "Proxy-Authorization: " + engine.ProxyBasicAuth(proxy.User, proxy.Pass) + "\r\n"
	}
	connectReq += "\r\n"

	if _, err := proxyConn.Write([]byte(connectReq)); err != nil {
		proxyConn.Close()
		return fmt.Errorf("write CONNECT: %w", err)
	}

	// Read the upstream CONNECT response exactly up to the terminating
	// \r\n\r\n (see engine.ReadConnectResponse for why a single Read() is
	// unsafe here). A deadline guards against a proxy that never answers.
	_ = proxyConn.SetReadDeadline(time.Now().Add(15 * time.Second))
	resp, err := engine.ReadConnectResponse(proxyConn, 8192)
	_ = proxyConn.SetReadDeadline(time.Time{})
	if err != nil {
		proxyConn.Close()
		return fmt.Errorf("read CONNECT response: %w", err)
	}
	if len(resp) < 12 || resp[9:12] != "200" {
		proxyConn.Close()
		return fmt.Errorf("upstream CONNECT failed: %s", strings.TrimSpace(resp))
	}

	*started = true
	if _, err := buffConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		proxyConn.Close()
		return fmt.Errorf("write 200: %w", err)
	}

	// Pipe via buffConn (not the raw Conn) so any client bytes that were
	// already buffered during protocol detection / header parsing are
	// forwarded instead of silently dropped.
	res, sfErr := h.forward(ctx, buffConn, proxyConn, reqInfo, nil, outputPort, noBypass)
	if sfErr != nil {
		return sfErr
	}
	*result = res
	return nil
}

// forward pipes client and upstream proxy. For a no-bypass group it is a
// plain pipe: the size forwarder is skipped because it can re-route the
// request directly (budget action) and feeds auto-bypass.
func (h *ConnHandler) forward(ctx context.Context, client net.Conn, proxyConn net.Conn, reqInfo *engine.RequestInfo, consumed []byte, outputPort int, noBypass bool) (engine.SizeForwardResult, error) {
	if !noBypass {
		return h.sizeForwarder.Forward(ctx, client, proxyConn, reqInfo, consumed, outputPort)
	}
	pr := engine.Pipe(ctx, client, proxyConn, h.idleTimeout)
	h.tracker.Record(reqInfo.Host, pr.BytesSent+pr.BytesReceived, "proxy")
	return engine.SizeForwardResult{PipeResult: pr}, nil
}

// pipeDirectConn pipes data between client and remote for direct connections.
func (h *ConnHandler) pipeDirectConn(ctx context.Context, buffConn *engine.BufferedConn, prefixConn net.Conn, remoteConn net.Conn, reqInfo *engine.RequestInfo) engine.PipeResult {
	if reqInfo.IsHTTPS {
		if _, err := buffConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			remoteConn.Close()
			return engine.PipeResult{}
		}
		return engine.Pipe(ctx, buffConn, remoteConn, h.idleTimeout)
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
