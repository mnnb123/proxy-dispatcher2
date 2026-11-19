// Package health implements active health probing of upstream proxies.
package health

import (
	"log/slog"
	"sync"
	"time"

	"proxy-dispatcher/internal/config"
)

// CheckResult is the outcome of probing a single proxy.
type CheckResult struct {
	Proxy      *config.ProxyEntry
	OldStatus  string
	NewStatus  string
	LatencyMs  int64
	ExternalIP string
	Error      string
	CheckedAt  int64
}

// Group is the health checker's view of a proxy group. Proxies are the
// engine's live *config.ProxyEntry pointers, so status/latency/weight
// written by the checker are visible to the rotators and the API.
type Group struct {
	Name    string
	Proxies []*config.ProxyEntry
}

// GroupProvider returns the current set of groups to probe. It is called
// at the start of every check round so runtime changes (imports, reloads)
// are picked up without an explicit update call.
type GroupProvider func() []Group

// HealthChecker runs periodic health checks against groups of proxies.
type HealthChecker struct {
	cfg            config.HealthCheckConfig
	provider       GroupProvider
	semaphore      chan struct{}
	ticker         *time.Ticker
	OnStatusChange func(*config.ProxyEntry, string, string)
	stopCh         chan struct{}
	logger         *slog.Logger
	mu             sync.RWMutex
}

// NewHealthChecker constructs a HealthChecker from config + a group provider.
func NewHealthChecker(cfg config.HealthCheckConfig, provider GroupProvider, logger *slog.Logger) *HealthChecker {
	mc := cfg.MaxConcurrent
	if mc <= 0 {
		mc = 20
	}
	if provider == nil {
		provider = func() []Group { return nil }
	}
	return &HealthChecker{
		cfg:       cfg,
		provider:  provider,
		semaphore: make(chan struct{}, mc),
		stopCh:    make(chan struct{}),
		logger:    logger,
	}
}

// Start begins the periodic health-check loop and runs one immediately.
func (hc *HealthChecker) Start() {
	if !hc.cfg.Enabled {
		return
	}
	iv := hc.cfg.IntervalSec
	if iv <= 0 {
		iv = 30
	}
	hc.ticker = time.NewTicker(time.Duration(iv) * time.Second)
	go hc.runLoop()
	go hc.runAllChecks()
}

func (hc *HealthChecker) runLoop() {
	for {
		select {
		case <-hc.stopCh:
			return
		case <-hc.ticker.C:
			go hc.runAllChecks()
		}
	}
}

func (hc *HealthChecker) groups() []Group {
	hc.mu.RLock()
	provider := hc.provider
	hc.mu.RUnlock()
	return provider()
}

func (hc *HealthChecker) runAllChecks() {
	groups := hc.groups()

	var wg sync.WaitGroup
	for _, g := range groups {
		for _, p := range g.Proxies {
			if p == nil || p.IsEmpty() {
				continue
			}
			hc.semaphore <- struct{}{}
			wg.Add(1)
			go func(proxy *config.ProxyEntry) {
				defer wg.Done()
				defer func() { <-hc.semaphore }()
				res := hc.checkOne(proxy)
				hc.applyResult(proxy, res)
			}(p)
		}
	}
	wg.Wait()
	hc.recalculateWeights(groups)
}

func (hc *HealthChecker) checkOne(proxy *config.ProxyEntry) CheckResult {
	timeout := time.Duration(hc.cfg.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	var res CheckResult
	if proxy.Type == "socks5" {
		res = probeSOCKS5(proxy, hc.cfg.TestURL, timeout)
	} else {
		res = probeHTTP(proxy, hc.cfg.TestURL, timeout)
	}
	// Classify status.
	if res.Error != "" {
		res.NewStatus = "dead"
	} else if res.LatencyMs > int64(hc.cfg.SlowThresholdMs) {
		res.NewStatus = "slow"
	} else {
		res.NewStatus = "alive"
	}
	res.CheckedAt = time.Now().Unix()
	return res
}

func (hc *HealthChecker) applyResult(proxy *config.ProxyEntry, res CheckResult) {
	old := proxy.Status
	proxy.Status = res.NewStatus
	proxy.LastCheck = res.CheckedAt
	proxy.LatencyMs = res.LatencyMs
	proxy.CheckCount++
	if res.Error != "" {
		proxy.FailCount++
	}
	// Rolling avg: 0.7 old + 0.3 new.
	if proxy.AvgLatency == 0 {
		proxy.AvgLatency = res.LatencyMs
	} else {
		proxy.AvgLatency = int64(float64(proxy.AvgLatency)*0.7 + float64(res.LatencyMs)*0.3)
	}
	if proxy.CheckCount > 0 {
		proxy.SuccessRate = float64(proxy.CheckCount-proxy.FailCount) / float64(proxy.CheckCount)
	}
	if res.ExternalIP != "" {
		proxy.ExternalIP = res.ExternalIP
	}
	if old != res.NewStatus && hc.OnStatusChange != nil {
		hc.OnStatusChange(proxy, old, res.NewStatus)
	}
}

func (hc *HealthChecker) recalculateWeights(groups []Group) {
	for _, g := range groups {
		for _, p := range g.Proxies {
			if p == nil {
				continue
			}
			if p.Status == "dead" {
				p.Weight = 0
				continue
			}
			lp := 50 - int(p.AvgLatency/100)
			if lp < 0 {
				lp = 0
			}
			w := int(p.SuccessRate*50) + lp
			if w < 1 {
				w = 1
			}
			if w > 100 {
				w = 100
			}
			p.Weight = w
		}
	}
}

// Stop halts the periodic checker.
func (hc *HealthChecker) Stop() {
	select {
	case <-hc.stopCh:
	default:
		close(hc.stopCh)
	}
	if hc.ticker != nil {
		hc.ticker.Stop()
	}
}

// CheckNow runs all checks synchronously and returns their results.
func (hc *HealthChecker) CheckNow() []CheckResult {
	groups := hc.groups()
	var results []CheckResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, g := range groups {
		for _, p := range g.Proxies {
			if p == nil {
				continue
			}
			hc.semaphore <- struct{}{}
			wg.Add(1)
			go func(proxy *config.ProxyEntry) {
				defer wg.Done()
				defer func() { <-hc.semaphore }()
				res := hc.checkOne(proxy)
				res.OldStatus = proxy.Status
				hc.applyResult(proxy, res)
				mu.Lock()
				results = append(results, res)
				mu.Unlock()
			}(p)
		}
	}
	wg.Wait()
	hc.recalculateWeights(groups)
	return results
}

// CheckProxies probes exactly the given proxies now (regardless of whether
// periodic checking is enabled) and applies the results to them.
func (hc *HealthChecker) CheckProxies(proxies []*config.ProxyEntry) []CheckResult {
	results := make([]CheckResult, 0, len(proxies))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, p := range proxies {
		if p == nil || p.IsEmpty() {
			continue
		}
		hc.semaphore <- struct{}{}
		wg.Add(1)
		go func(proxy *config.ProxyEntry) {
			defer wg.Done()
			defer func() { <-hc.semaphore }()
			res := hc.checkOne(proxy)
			res.OldStatus = proxy.Status
			hc.applyResult(proxy, res)
			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	return results
}

// CheckProxiesPriority is CheckProxies with its own small worker pool. The
// shared semaphore can be held for minutes by a periodic round over
// thousands of proxies; callers that need an answer now (a freshly placed
// sock, the auto-keep loop) must not queue behind it.
func (hc *HealthChecker) CheckProxiesPriority(proxies []*config.ProxyEntry) []CheckResult {
	results := make([]CheckResult, 0, len(proxies))
	sem := make(chan struct{}, 10)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, p := range proxies {
		if p == nil || p.IsEmpty() {
			continue
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(proxy *config.ProxyEntry) {
			defer wg.Done()
			defer func() { <-sem }()
			res := hc.checkOne(proxy)
			res.OldStatus = proxy.Status
			hc.applyResult(proxy, res)
			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	return results
}

// SetGroupProvider replaces the group provider.
func (hc *HealthChecker) SetGroupProvider(p GroupProvider) {
	if p == nil {
		return
	}
	hc.mu.Lock()
	hc.provider = p
	hc.mu.Unlock()
}
