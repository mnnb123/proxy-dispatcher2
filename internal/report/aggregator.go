package report

import (
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"
)

// AggBucket holds aggregated stats for a domain+route+time key.
type AggBucket struct {
	Domain       string `json:"domain"`
	RouteType    string `json:"route_type"`
	TimeKey      string `json:"time_key"`
	RequestCount int64  `json:"request_count"`
	TotalBytes   int64  `json:"total_bytes"`
	ErrorCount   int64  `json:"error_count"`
	SumLatencyMs int64  `json:"sum_latency_ms"`
	MinLatencyMs int64  `json:"min_latency_ms"`
	MaxLatencyMs int64  `json:"max_latency_ms"`
}

// ChartPoint is a single data point for time-series charts.
type ChartPoint struct {
	Time       string `json:"time"`
	Bytes      int64  `json:"bytes"`
	Requests   int64  `json:"requests"`
	AvgLatency int64  `json:"avg_latency"`
}

// DomainRank summarises a domain's traffic for ranking.
type DomainRank struct {
	Domain         string           `json:"domain"`
	TotalBytes     int64            `json:"total_bytes"`
	RequestCount   int64            `json:"request_count"`
	ErrorCount     int64            `json:"error_count"`
	AvgLatencyMs   int64            `json:"avg_latency_ms"`
	RouteBreakdown map[string]int64 `json:"route_breakdown"`
}

// Aggregator collects minute/hour/day level traffic statistics.
type Aggregator struct {
	minuteStats map[string]*AggBucket
	minuteMu    sync.RWMutex
	hourStats   map[string]*AggBucket
	hourMu      sync.RWMutex
	dayStats    map[string]*AggBucket
	dayMu       sync.RWMutex
	keepMinutes int
	keepHours   int
	keepDays    int
	logger      *slog.Logger
}

// NewAggregator creates an Aggregator.
func NewAggregator(keepMinutes, keepHours, keepDays int, logger *slog.Logger) *Aggregator {
	return &Aggregator{
		minuteStats: make(map[string]*AggBucket),
		hourStats:   make(map[string]*AggBucket),
		dayStats:    make(map[string]*AggBucket),
		keepMinutes: keepMinutes,
		keepHours:   keepHours,
		keepDays:    keepDays,
		logger:      logger,
	}
}

// Record adds a log entry to minute-level aggregation.
func (a *Aggregator) Record(entry *LogEntry) {
	ts := time.UnixMilli(entry.Timestamp)
	timeKey := ts.Format("2006-01-02T15:04")
	key := fmt.Sprintf("%s|%s|%s", entry.Domain, entry.RouteType, timeKey)

	a.minuteMu.Lock()
	b, ok := a.minuteStats[key]
	if !ok {
		b = &AggBucket{
			Domain: entry.Domain, RouteType: entry.RouteType, TimeKey: timeKey,
			MinLatencyMs: entry.LatencyMs,
		}
		a.minuteStats[key] = b
	}
	b.RequestCount++
	b.TotalBytes += entry.TotalBytes()
	b.SumLatencyMs += entry.LatencyMs
	if entry.Error != "" {
		b.ErrorCount++
	}
	if entry.LatencyMs < b.MinLatencyMs {
		b.MinLatencyMs = entry.LatencyMs
	}
	if entry.LatencyMs > b.MaxLatencyMs {
		b.MaxLatencyMs = entry.LatencyMs
	}
	a.minuteMu.Unlock()
}

// RollupMinuteToHour merges minute buckets into hour buckets.
func (a *Aggregator) RollupMinuteToHour() {
	a.minuteMu.Lock()
	old := a.minuteStats
	a.minuteStats = make(map[string]*AggBucket)
	a.minuteMu.Unlock()

	a.hourMu.Lock()
	for _, b := range old {
		hourKey := b.TimeKey[:13] // "2006-01-02T15"
		key := fmt.Sprintf("%s|%s|%s", b.Domain, b.RouteType, hourKey)
		h, ok := a.hourStats[key]
		if !ok {
			h = &AggBucket{Domain: b.Domain, RouteType: b.RouteType, TimeKey: hourKey, MinLatencyMs: b.MinLatencyMs}
			a.hourStats[key] = h
		}
		mergeBucket(h, b)
	}
	a.hourMu.Unlock()
}

// RollupHourToDay merges hour buckets into day buckets.
func (a *Aggregator) RollupHourToDay() {
	a.hourMu.Lock()
	old := a.hourStats
	a.hourStats = make(map[string]*AggBucket)
	a.hourMu.Unlock()

	a.dayMu.Lock()
	for _, b := range old {
		dayKey := b.TimeKey[:10] // "2006-01-02"
		key := fmt.Sprintf("%s|%s|%s", b.Domain, b.RouteType, dayKey)
		d, ok := a.dayStats[key]
		if !ok {
			d = &AggBucket{Domain: b.Domain, RouteType: b.RouteType, TimeKey: dayKey, MinLatencyMs: b.MinLatencyMs}
			a.dayStats[key] = d
		}
		mergeBucket(d, b)
	}
	a.dayMu.Unlock()
}

func mergeBucket(dst, src *AggBucket) {
	dst.RequestCount += src.RequestCount
	dst.TotalBytes += src.TotalBytes
	dst.ErrorCount += src.ErrorCount
	dst.SumLatencyMs += src.SumLatencyMs
	if src.MinLatencyMs < dst.MinLatencyMs {
		dst.MinLatencyMs = src.MinLatencyMs
	}
	if src.MaxLatencyMs > dst.MaxLatencyMs {
		dst.MaxLatencyMs = src.MaxLatencyMs
	}
}

// CleanupOld removes buckets older than the keep limits.
func (a *Aggregator) CleanupOld() {
	minCutoff := time.Now().Add(-time.Duration(a.keepMinutes) * time.Minute).Format("2006-01-02T15:04")
	a.minuteMu.Lock()
	for k, b := range a.minuteStats {
		if b.TimeKey < minCutoff {
			delete(a.minuteStats, k)
		}
	}
	a.minuteMu.Unlock()

	hourCutoff := time.Now().Add(-time.Duration(a.keepHours) * time.Hour).Format("2006-01-02T15")
	a.hourMu.Lock()
	for k, b := range a.hourStats {
		if b.TimeKey < hourCutoff {
			delete(a.hourStats, k)
		}
	}
	a.hourMu.Unlock()

	dayCutoff := time.Now().AddDate(0, 0, -a.keepDays).Format("2006-01-02")
	a.dayMu.Lock()
	for k, b := range a.dayStats {
		if b.TimeKey < dayCutoff {
			delete(a.dayStats, k)
		}
	}
	a.dayMu.Unlock()
}

// GetMinuteChart returns the last N minute chart points for a domain.
func (a *Aggregator) GetMinuteChart(domain string, lastN int) []ChartPoint {
	a.minuteMu.RLock()
	defer a.minuteMu.RUnlock()
	return buildChart(a.minuteStats, domain, lastN)
}

// GetHourlyChart returns the last N hourly chart points for a domain.
func (a *Aggregator) GetHourlyChart(domain string, lastN int) []ChartPoint {
	a.hourMu.RLock()
	defer a.hourMu.RUnlock()
	return buildChart(a.hourStats, domain, lastN)
}

func buildChart(stats map[string]*AggBucket, domain string, lastN int) []ChartPoint {
	timeMap := make(map[string]*ChartPoint)
	for _, b := range stats {
		if domain != "" && b.Domain != domain {
			continue
		}
		cp, ok := timeMap[b.TimeKey]
		if !ok {
			cp = &ChartPoint{Time: b.TimeKey}
			timeMap[b.TimeKey] = cp
		}
		cp.Bytes += b.TotalBytes
		cp.Requests += b.RequestCount
		cp.AvgLatency += b.SumLatencyMs
	}
	points := make([]ChartPoint, 0, len(timeMap))
	for _, cp := range timeMap {
		if cp.Requests > 0 {
			cp.AvgLatency = cp.AvgLatency / cp.Requests
		}
		points = append(points, *cp)
	}
	sort.Slice(points, func(i, j int) bool { return points[i].Time < points[j].Time })
	if lastN > 0 && len(points) > lastN {
		points = points[len(points)-lastN:]
	}
	return points
}

// GetTopDomains returns the top N domains by bytes for a granularity.
func (a *Aggregator) GetTopDomains(granularity string, topN int) []DomainRank {
	var stats map[string]*AggBucket
	switch granularity {
	case "hour":
		a.hourMu.RLock()
		stats = a.hourStats
		defer a.hourMu.RUnlock()
	case "day":
		a.dayMu.RLock()
		stats = a.dayStats
		defer a.dayMu.RUnlock()
	default:
		a.minuteMu.RLock()
		stats = a.minuteStats
		defer a.minuteMu.RUnlock()
	}

	domainMap := make(map[string]*DomainRank)
	for _, b := range stats {
		dr, ok := domainMap[b.Domain]
		if !ok {
			dr = &DomainRank{Domain: b.Domain, RouteBreakdown: make(map[string]int64)}
			domainMap[b.Domain] = dr
		}
		dr.TotalBytes += b.TotalBytes
		dr.RequestCount += b.RequestCount
		dr.ErrorCount += b.ErrorCount
		dr.AvgLatencyMs += b.SumLatencyMs
		dr.RouteBreakdown[b.RouteType] += b.RequestCount
	}

	ranks := make([]DomainRank, 0, len(domainMap))
	for _, dr := range domainMap {
		if dr.RequestCount > 0 {
			dr.AvgLatencyMs = dr.AvgLatencyMs / dr.RequestCount
		}
		ranks = append(ranks, *dr)
	}
	sort.Slice(ranks, func(i, j int) bool { return ranks[i].TotalBytes > ranks[j].TotalBytes })
	if topN > 0 && len(ranks) > topN {
		ranks = ranks[:topN]
	}
	return ranks
}

// GetRAMUsage returns approximate RAM used by all buckets.
func (a *Aggregator) GetRAMUsage() int64 {
	count := func(m map[string]*AggBucket) int64 { return int64(len(m)) * 200 }
	a.minuteMu.RLock()
	n := count(a.minuteStats)
	a.minuteMu.RUnlock()
	a.hourMu.RLock()
	n += count(a.hourStats)
	a.hourMu.RUnlock()
	a.dayMu.RLock()
	n += count(a.dayStats)
	a.dayMu.RUnlock()
	return n
}
