// Package bandwidth tracks per-domain and global traffic statistics.
package bandwidth

import (
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// DomainStat holds traffic statistics for a single domain.
type DomainStat struct {
	Domain          string
	BytesThisHour   atomic.Int64
	BytesThisDay    atomic.Int64
	RequestCount    atomic.Int64
	LastSeen        atomic.Int64
	AvgResponseSize int64
	SampleCount     int64
	ProxyBytes      atomic.Int64
	DirectBytes     atomic.Int64
}

// DomainSummary is a read-only snapshot of a DomainStat.
type DomainSummary struct {
	Domain       string `json:"domain"`
	BytesTotal   int64  `json:"bytes_total"`
	RequestCount int64  `json:"request_count"`
	AvgSize      int64  `json:"avg_size"`
	RouteType    string `json:"route_type"`
}

// TrackerSnapshot is a point-in-time snapshot of all tracker counters.
type TrackerSnapshot struct {
	TotalProxyBytes   int64           `json:"total_proxy_bytes"`
	TotalDirectBytes  int64           `json:"total_direct_bytes"`
	TotalBlockedReqs  int64           `json:"total_blocked_reqs"`
	TotalProxyReqs    int64           `json:"total_proxy_reqs"`
	TotalBypassReqs   int64           `json:"total_bypass_reqs"`
	TopDomainsByBytes []DomainSummary `json:"top_domains_by_bytes"`
}

// Tracker records bandwidth usage globally and per-domain.
type Tracker struct {
	domainStats     map[string]*DomainStat
	mu              sync.RWMutex
	totalProxyBytes atomic.Int64
	totalDirectBytes atomic.Int64
	totalBlockedReqs atomic.Int64
	totalProxyReqs   atomic.Int64
	totalBypassReqs  atomic.Int64
	currentDay      string
	logger          *slog.Logger
}

// NewTracker creates an empty Tracker.
func NewTracker(logger *slog.Logger) *Tracker {
	return &Tracker{
		domainStats: make(map[string]*DomainStat),
		currentDay:  time.Now().Format("2006-01-02"),
		logger:      logger,
	}
}

// Record adds bytes for a request to the appropriate counters.
func (t *Tracker) Record(domain string, bytes int64, routeType string) {
	switch routeType {
	case "proxy":
		t.totalProxyBytes.Add(bytes)
		t.totalProxyReqs.Add(1)
	case "direct", "resource":
		t.totalDirectBytes.Add(bytes)
		t.totalBypassReqs.Add(1)
	case "block":
		t.totalBlockedReqs.Add(1)
		return
	}

	if domain == "" {
		return
	}

	t.mu.RLock()
	ds, ok := t.domainStats[domain]
	t.mu.RUnlock()

	if !ok {
		t.mu.Lock()
		ds, ok = t.domainStats[domain]
		if !ok {
			ds = &DomainStat{Domain: domain}
			t.domainStats[domain] = ds
		}
		t.mu.Unlock()
	}

	ds.BytesThisHour.Add(bytes)
	ds.BytesThisDay.Add(bytes)
	ds.RequestCount.Add(1)
	ds.LastSeen.Store(time.Now().Unix())

	switch routeType {
	case "proxy":
		ds.ProxyBytes.Add(bytes)
	case "direct", "resource":
		ds.DirectBytes.Add(bytes)
	}

	// Rolling average: incremental update.
	ds.SampleCount++
	ds.AvgResponseSize = ds.AvgResponseSize + (bytes-ds.AvgResponseSize)/ds.SampleCount
}

// GetDomainBytesThisHour returns the hourly byte count for a domain.
func (t *Tracker) GetDomainBytesThisHour(domain string) int64 {
	t.mu.RLock()
	ds, ok := t.domainStats[domain]
	t.mu.RUnlock()
	if !ok {
		return 0
	}
	return ds.BytesThisHour.Load()
}

// GetDomainAvgSize returns the rolling average response size for a domain.
func (t *Tracker) GetDomainAvgSize(domain string) int64 {
	t.mu.RLock()
	ds, ok := t.domainStats[domain]
	t.mu.RUnlock()
	if !ok {
		return 0
	}
	return ds.AvgResponseSize
}

// GetTotalProxyBytesToday returns the total proxy bytes for the current day.
func (t *Tracker) GetTotalProxyBytesToday() int64 {
	return t.totalProxyBytes.Load()
}

// GetSnapshot returns a point-in-time snapshot with top 20 domains by bytes.
func (t *Tracker) GetSnapshot() TrackerSnapshot {
	t.mu.RLock()
	summaries := make([]DomainSummary, 0, len(t.domainStats))
	for _, ds := range t.domainStats {
		proxyB := ds.ProxyBytes.Load()
		directB := ds.DirectBytes.Load()
		rt := "proxy"
		if directB > proxyB {
			rt = "direct"
		} else if directB > 0 && proxyB > 0 {
			rt = "mixed"
		}
		summaries = append(summaries, DomainSummary{
			Domain:       ds.Domain,
			BytesTotal:   ds.BytesThisDay.Load(),
			RequestCount: ds.RequestCount.Load(),
			AvgSize:      ds.AvgResponseSize,
			RouteType:    rt,
		})
	}
	t.mu.RUnlock()

	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].BytesTotal > summaries[j].BytesTotal
	})
	if len(summaries) > 20 {
		summaries = summaries[:20]
	}

	return TrackerSnapshot{
		TotalProxyBytes:   t.totalProxyBytes.Load(),
		TotalDirectBytes:  t.totalDirectBytes.Load(),
		TotalBlockedReqs:  t.totalBlockedReqs.Load(),
		TotalProxyReqs:    t.totalProxyReqs.Load(),
		TotalBypassReqs:   t.totalBypassReqs.Load(),
		TopDomainsByBytes: summaries,
	}
}

// ResetHourly resets the hourly byte counters on all domains.
func (t *Tracker) ResetHourly() {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, ds := range t.domainStats {
		ds.BytesThisHour.Store(0)
	}
}

// ResetDaily resets all daily counters and global totals.
func (t *Tracker) ResetDaily() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, ds := range t.domainStats {
		ds.BytesThisDay.Store(0)
		ds.RequestCount.Store(0)
		ds.SampleCount = 0
		ds.AvgResponseSize = 0
		ds.ProxyBytes.Store(0)
		ds.DirectBytes.Store(0)
	}
	t.totalProxyBytes.Store(0)
	t.totalDirectBytes.Store(0)
	t.totalBlockedReqs.Store(0)
	t.totalProxyReqs.Store(0)
	t.totalBypassReqs.Store(0)
	t.currentDay = time.Now().Format("2006-01-02")
}

// ResetAll clears all counters and domain stats immediately.
func (t *Tracker) ResetAll() {
	t.mu.Lock()
	t.domainStats = make(map[string]*DomainStat)
	t.mu.Unlock()
	t.totalProxyBytes.Store(0)
	t.totalDirectBytes.Store(0)
	t.totalBlockedReqs.Store(0)
	t.totalProxyReqs.Store(0)
	t.totalBypassReqs.Store(0)
}

// Cleanup removes domains not seen in 24 hours.
func (t *Tracker) Cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := time.Now().Add(-24 * time.Hour).Unix()
	for domain, ds := range t.domainStats {
		if ds.LastSeen.Load() < cutoff {
			delete(t.domainStats, domain)
		}
	}
}
