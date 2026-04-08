package engine

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
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

// BypassEvent records a single auto-bypass decision.
type BypassEvent struct {
	Time      int64  `json:"time"`
	Domain    string `json:"domain"`
	Port      int    `json:"port"`
	Size      int64  `json:"size"`
	Threshold int64  `json:"threshold"`
}

// OnAutoBypassFunc is called when a domain should be added to bypass rules.
type OnAutoBypassFunc func(domain string)

// portDomainAccum tracks accumulated bytes for a domain on a specific port
// within the configured time window.
type portDomainAccum struct {
	bytes     int64
	windowEnd time.Time
}

// SizeForwarder inspects response size and optionally adds domains to bypass.
type SizeForwarder struct {
	deps         SizeForwarderDeps
	onAutoBypass OnAutoBypassFunc
	mu           sync.Mutex
	events       []BypassEvent
	total        int64
	autoAdded    map[string]bool
	// accum tracks bytes per "port|domain" within time window.
	accum map[string]*portDomainAccum
}

// NewSizeForwarder creates a SizeForwarder.
func NewSizeForwarder(deps SizeForwarderDeps) *SizeForwarder {
	return &SizeForwarder{
		deps:      deps,
		autoAdded: make(map[string]bool),
		accum:     make(map[string]*portDomainAccum),
	}
}

// SetOnAutoBypass sets the callback for when a domain exceeds threshold.
func (sf *SizeForwarder) SetOnAutoBypass(fn OnAutoBypassFunc) {
	sf.onAutoBypass = fn
}

// UpdateConfig updates the auto-bypass config at runtime.
func (sf *SizeForwarder) UpdateConfig(cfg config.AutoBypassConfig) {
	sf.mu.Lock()
	sf.deps.AutoBypassCfg = cfg
	sf.mu.Unlock()
}

func (sf *SizeForwarder) recordEvent(domain string, port int, size, threshold int64) {
	sf.mu.Lock()
	defer sf.mu.Unlock()
	sf.total++
	sf.events = append(sf.events, BypassEvent{
		Time:      time.Now().UnixMilli(),
		Domain:    domain,
		Port:      port,
		Size:      size,
		Threshold: threshold,
	})
	if len(sf.events) > 100 {
		sf.events = sf.events[len(sf.events)-100:]
	}
}

// checkAndAutoAdd accumulates bytes for domain+port within time window.
// If accumulated bytes exceed threshold within the window → add to bypass.
func (sf *SizeForwarder) checkAndAutoAdd(domain string, port int, connBytes int64) {
	sf.mu.Lock()
	cfg := sf.deps.AutoBypassCfg
	sf.mu.Unlock()

	if !cfg.Enabled || cfg.SizeThreshold <= 0 {
		return
	}
	// Already in bypass rules?
	action := sf.deps.RuleEngine.Evaluate(domain, "")
	if action.Type == "direct" || action.Type == "resource" {
		return
	}
	// Force proxy domains should not be auto-bypassed.
	if sf.deps.RuleEngine.IsForceProxy(domain) {
		return
	}

	sf.mu.Lock()
	// Already auto-added this session?
	if sf.autoAdded[domain] {
		sf.mu.Unlock()
		return
	}

	key := fmt.Sprintf("%d|%s", port, domain)
	now := time.Now()
	windowDur := time.Duration(cfg.TimeWindowSec) * time.Second
	if windowDur <= 0 {
		windowDur = 2 * time.Minute // default 2 minutes
	}

	acc, ok := sf.accum[key]
	if !ok || now.After(acc.windowEnd) {
		// Start new window.
		sf.accum[key] = &portDomainAccum{
			bytes:     connBytes,
			windowEnd: now.Add(windowDur),
		}
		acc = sf.accum[key]
	} else {
		// Accumulate within window.
		acc.bytes += connBytes
	}

	totalInWindow := acc.bytes
	exceeded := totalInWindow > cfg.SizeThreshold
	if exceeded {
		sf.autoAdded[domain] = true
	}
	sf.mu.Unlock()

	if exceeded {
		sf.deps.Logger.Info("auto-bypass: domain exceeded threshold within time window",
			"domain", domain, "port", port, "bytes", totalInWindow,
			"threshold", cfg.SizeThreshold, "window_sec", cfg.TimeWindowSec)
		sf.recordEvent(domain, port, totalInWindow, cfg.SizeThreshold)
		if sf.onAutoBypass != nil {
			sf.onAutoBypass(domain)
		}
	}
}

// CheckAutoBypass allows external callers (e.g. SOCKS5 path) to feed
// bytes into the auto-bypass accumulator for a given domain+port.
func (sf *SizeForwarder) CheckAutoBypass(domain string, port int, totalBytes int64) {
	sf.checkAndAutoAdd(domain, port, totalBytes)
}

// ClearEvents resets the activity log.
func (sf *SizeForwarder) ClearEvents() {
	sf.mu.Lock()
	defer sf.mu.Unlock()
	sf.events = nil
	sf.total = 0
}

// BypassStats returns recent bypass events and total count.
func (sf *SizeForwarder) BypassStats() ([]BypassEvent, int64) {
	sf.mu.Lock()
	defer sf.mu.Unlock()
	out := make([]BypassEvent, len(sf.events))
	copy(out, sf.events)
	return out, sf.total
}

// Forward sends a request through proxyConn. After the pipe completes,
// accumulates bytes per domain+port within the time window and auto-adds
// the domain to bypass rules if the accumulated total exceeds the threshold.
func (sf *SizeForwarder) Forward(ctx context.Context, client net.Conn, proxyConn net.Conn, reqInfo *RequestInfo, consumedReqBytes []byte, listenPort int) (SizeForwardResult, error) {
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
		default:
			pr := Pipe(ctx, client, proxyConn, sf.deps.IdleTimeout)
			sf.deps.Tracker.Record(domain, pr.BytesSent+pr.BytesReceived, "proxy")
			return SizeForwardResult{PipeResult: pr}, nil
		}
	}

	// Force proxy — skip auto-bypass check.
	if sf.deps.RuleEngine.IsForceProxy(domain) {
		pr := Pipe(ctx, client, proxyConn, sf.deps.IdleTimeout)
		sf.deps.Tracker.Record(domain, pr.BytesSent+pr.BytesReceived, "proxy")
		return SizeForwardResult{PipeResult: pr}, nil
	}

	// Pipe through proxy, then check size after completion.
	pr := Pipe(ctx, client, proxyConn, sf.deps.IdleTimeout)
	connBytes := pr.BytesSent + pr.BytesReceived
	sf.deps.Tracker.Record(domain, connBytes, "proxy")

	// Auto-bypass check: accumulate per port+domain within time window.
	if cfg.Enabled {
		sf.checkAndAutoAdd(domain, listenPort, connBytes)
	}

	return SizeForwardResult{PipeResult: pr}, nil
}

func (sf *SizeForwarder) retryDirect(ctx context.Context, client net.Conn, reqInfo *RequestInfo, consumedReqBytes []byte) (SizeForwardResult, error) {
	remoteConn, err := sf.deps.DirectDialer.Dial(ctx, reqInfo.Target)
	if err != nil {
		return SizeForwardResult{}, fmt.Errorf("direct retry dial: %w", err)
	}
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
