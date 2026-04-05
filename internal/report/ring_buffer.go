package report

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// RingBufferStats is a point-in-time snapshot of ring buffer state.
type RingBufferStats struct {
	CurrentRows    int       `json:"current_rows"`
	MaxRows        int       `json:"max_rows"`
	RAMBytes       int64     `json:"ram_bytes"`
	TotalAdded     uint64    `json:"total_added"`
	LastClearTime  time.Time `json:"last_clear_time"`
	NextClearInSec int       `json:"next_clear_in_sec"`
	AutoClearSec   int       `json:"auto_clear_sec"`
}

// RingBuffer is a fixed-capacity circular buffer of LogEntry pointers.
type RingBuffer struct {
	entries       []*LogEntry
	head          int
	count         int
	maxRows       int
	totalAdded    atomic.Uint64
	ramBytes      atomic.Int64
	autoClearSec  int
	lastClearTime time.Time
	clearTimer    *time.Timer
	onBeforeClear func([]*LogEntry)
	mu            sync.RWMutex
	logger        *slog.Logger
}

// NewRingBuffer creates a RingBuffer and starts the auto-clear timer.
func NewRingBuffer(maxRows int, autoClearSec int, logger *slog.Logger) *RingBuffer {
	rb := &RingBuffer{
		entries:       make([]*LogEntry, maxRows),
		maxRows:       maxRows,
		autoClearSec:  autoClearSec,
		lastClearTime: time.Now(),
		logger:        logger,
	}
	if autoClearSec > 0 {
		rb.clearTimer = time.AfterFunc(time.Duration(autoClearSec)*time.Second, rb.autoClear)
	}
	return rb
}

func (rb *RingBuffer) autoClear() {
	rb.Clear()
	rb.mu.RLock()
	sec := rb.autoClearSec
	rb.mu.RUnlock()
	if sec > 0 {
		rb.clearTimer.Reset(time.Duration(sec) * time.Second)
	}
}

// Push adds an entry to the ring buffer, overwriting the oldest if full.
func (rb *RingBuffer) Push(entry *LogEntry) {
	rb.mu.Lock()
	old := rb.entries[rb.head]
	if old != nil {
		rb.ramBytes.Add(-int64(old.EstimateSize()))
	}
	rb.entries[rb.head] = entry
	rb.head = (rb.head + 1) % rb.maxRows
	if rb.count < rb.maxRows {
		rb.count++
	}
	rb.mu.Unlock()
	rb.totalAdded.Add(1)
	rb.ramBytes.Add(int64(entry.EstimateSize()))
}

// GetRecent returns up to limit entries ordered newest-first (copy).
func (rb *RingBuffer) GetRecent(limit int) []*LogEntry {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	if limit <= 0 || limit > rb.count {
		limit = rb.count
	}
	result := make([]*LogEntry, 0, limit)
	for i := 0; i < limit; i++ {
		idx := (rb.head - 1 - i + rb.maxRows) % rb.maxRows
		if rb.entries[idx] != nil {
			result = append(result, rb.entries[idx])
		}
	}
	return result
}

// GetAll returns all entries oldest-first (copy).
func (rb *RingBuffer) GetAll() []*LogEntry {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	result := make([]*LogEntry, 0, rb.count)
	start := (rb.head - rb.count + rb.maxRows) % rb.maxRows
	for i := 0; i < rb.count; i++ {
		idx := (start + i) % rb.maxRows
		if rb.entries[idx] != nil {
			result = append(result, rb.entries[idx])
		}
	}
	return result
}

// Clear empties the buffer, calling onBeforeClear if set.
func (rb *RingBuffer) Clear() {
	rb.mu.Lock()
	if rb.onBeforeClear != nil && rb.count > 0 {
		all := make([]*LogEntry, 0, rb.count)
		start := (rb.head - rb.count + rb.maxRows) % rb.maxRows
		for i := 0; i < rb.count; i++ {
			idx := (start + i) % rb.maxRows
			if rb.entries[idx] != nil {
				all = append(all, rb.entries[idx])
			}
		}
		rb.onBeforeClear(all)
	}
	for i := range rb.entries {
		rb.entries[i] = nil
	}
	rb.head = 0
	rb.count = 0
	rb.ramBytes.Store(0)
	rb.lastClearTime = time.Now()
	rb.mu.Unlock()
}

// SetOnBeforeClear sets a callback invoked before clear with current entries.
func (rb *RingBuffer) SetOnBeforeClear(fn func([]*LogEntry)) {
	rb.mu.Lock()
	rb.onBeforeClear = fn
	rb.mu.Unlock()
}

// Stats returns a snapshot of ring buffer statistics.
func (rb *RingBuffer) Stats() RingBufferStats {
	rb.mu.RLock()
	count := rb.count
	maxR := rb.maxRows
	lct := rb.lastClearTime
	acs := rb.autoClearSec
	rb.mu.RUnlock()

	nextClear := 0
	if acs > 0 {
		elapsed := int(time.Since(lct).Seconds())
		nextClear = acs - elapsed
		if nextClear < 0 {
			nextClear = 0
		}
	}
	return RingBufferStats{
		CurrentRows:    count,
		MaxRows:        maxR,
		RAMBytes:       rb.ramBytes.Load(),
		TotalAdded:     rb.totalAdded.Load(),
		LastClearTime:  lct,
		NextClearInSec: nextClear,
		AutoClearSec:   acs,
	}
}

// UpdateConfig resizes the buffer and resets the timer.
func (rb *RingBuffer) UpdateConfig(maxRows int, autoClearSec int) {
	rb.mu.Lock()
	if maxRows != rb.maxRows {
		newEntries := make([]*LogEntry, maxRows)
		copyCount := rb.count
		if copyCount > maxRows {
			copyCount = maxRows
		}
		start := (rb.head - copyCount + rb.maxRows) % rb.maxRows
		for i := 0; i < copyCount; i++ {
			idx := (start + i) % rb.maxRows
			newEntries[i] = rb.entries[idx]
		}
		rb.entries = newEntries
		rb.maxRows = maxRows
		rb.head = copyCount % maxRows
		rb.count = copyCount
	}
	rb.autoClearSec = autoClearSec
	rb.mu.Unlock()

	if rb.clearTimer != nil {
		rb.clearTimer.Stop()
	}
	if autoClearSec > 0 {
		rb.clearTimer = time.AfterFunc(time.Duration(autoClearSec)*time.Second, rb.autoClear)
	}
}
