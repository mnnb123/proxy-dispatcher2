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

// HealthChecker runs periodic health checks against groups of proxies.
type HealthChecker struct {
	cfg            config.HealthCheckConfig
	groups         []*config.ProxyGroup
	semaphore      chan struct{}
	ticker         *time.Ticker
	OnStatusChange func(*config.ProxyEntry, string, string)
	stopCh         chan struct{}
	logger         *slog.Logger
	mu             sync.RWMutex
}

// NewHealthChecker constructs a HealthChecker from config + groups.
func NewHealthChecker(cfg config.HealthCheckConfig, groups []*config.ProxyGroup, logger *slog.Logger) *HealthChecker {
	mc := cfg.MaxConcurrent
	if mc <= 0 {
		mc = 20
	}
	return &HealthChecker{
		cfg:       cfg,
		groups:    groups,
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

func (hc *HealthChecker) runAllChecks() {
	hc.mu.RLock()
	groups := hc.groups
	hc.mu.RUnlock()

	var wg sync.WaitGroup
	for _, g := range groups {
		for i := range g.Proxies {
			p := &g.Proxies[i]
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
	hc.recalculateWeights()
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

func (hc *HealthChecker) recalculateWeights() {
	hc.mu.RLock()
	groups := hc.groups
	hc.mu.RUnlock()
	for _, g := range groups {
		for i := range g.Proxies {
			p := &g.Proxies[i]
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
	hc.mu.RLock()
	groups := hc.groups
	hc.mu.RUnlock()
	var results []CheckResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, g := range groups {
		for i := range g.Proxies {
			p := &g.Proxies[i]
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
	hc.recalculateWeights()
	return results
}

// UpdateGroups swaps the tracked groups atomically.
func (hc *HealthChecker) UpdateGroups(groups []*config.ProxyGroup) {
	hc.mu.Lock()
	hc.groups = groups
	hc.mu.Unlock()
}
