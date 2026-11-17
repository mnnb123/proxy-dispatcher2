package report

import (
	"log/slog"
	"sync"
	"sync/atomic"

	"proxy-dispatcher/internal/config"
)

// WSClient represents a connected WebSocket client for live traffic.
type WSClient struct {
	Send chan []byte

	mu     sync.Mutex
	filter string
	paused atomic.Bool
}

// NewWSClient creates a WSClient with a send buffer of bufSize messages.
func NewWSClient(bufSize int) *WSClient {
	return &WSClient{Send: make(chan []byte, bufSize)}
}

// SetPaused toggles delivery for this client.
func (c *WSClient) SetPaused(p bool) { c.paused.Store(p) }

// IsPaused reports whether delivery is paused.
func (c *WSClient) IsPaused() bool { return c.paused.Load() }

// SetFilter sets the substring filter applied by the write pump.
func (c *WSClient) SetFilter(f string) {
	c.mu.Lock()
	c.filter = f
	c.mu.Unlock()
}

// GetFilter returns the current substring filter.
func (c *WSClient) GetFilter() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.filter
}

// ReportHub ties together ring buffer, aggregator, disk logger, alert manager,
// and WebSocket broadcast into a single Record() entry point.
type ReportHub struct {
	Ring     *RingBuffer
	Agg      *Aggregator
	Disk     *DiskLogger
	AlertMgr *AlertManager

	wsClients map[*WSClient]bool
	wsMu      sync.RWMutex
	broadcast chan []byte
	closed    atomic.Bool

	logger *slog.Logger
}

// NewReportHub creates all sub-components and starts the broadcast loop.
func NewReportHub(cfg config.ReportConfig, logger *slog.Logger) (*ReportHub, error) {
	autoClear := 0
	if cfg.AutoClearEnabled {
		autoClear = cfg.AutoClearSeconds
	}

	ring := NewRingBuffer(cfg.RingBufferMaxRows, autoClear, logger)
	agg := NewAggregator(cfg.AggregateKeepMinutes, cfg.AggregateKeepHours, cfg.AggregateKeepDays, logger)

	disk, err := NewDiskLogger(cfg, logger)
	if err != nil {
		return nil, err
	}

	alertMgr := NewAlertManager(cfg, logger)

	rh := &ReportHub{
		Ring:      ring,
		Agg:       agg,
		Disk:      disk,
		AlertMgr:  alertMgr,
		wsClients: make(map[*WSClient]bool),
		broadcast: make(chan []byte, 10000),
		logger:    logger,
	}

	if cfg.ExportBeforeClear {
		ring.SetOnBeforeClear(func(entries []*LogEntry) {
			for _, e := range entries {
				disk.Write(e)
			}
		})
	}

	go rh.broadcastLoop()
	return rh, nil
}

// Record processes a log entry through all subsystems.
func (rh *ReportHub) Record(entry *LogEntry) {
	if rh.closed.Load() {
		// Connections still draining after shutdown must not send on the
		// closed broadcast / disk channels.
		return
	}
	rh.Ring.Push(entry)
	rh.Agg.Record(entry)
	rh.Disk.Write(entry)
	rh.AlertMgr.Check(entry)

	data := entry.ToJSON()
	select {
	case rh.broadcast <- data:
	default:
	}
}

// RegisterClient adds a WebSocket client for live traffic.
func (rh *ReportHub) RegisterClient(c *WSClient) {
	rh.wsMu.Lock()
	rh.wsClients[c] = true
	rh.wsMu.Unlock()
}

// UnregisterClient removes a WebSocket client.
func (rh *ReportHub) UnregisterClient(c *WSClient) {
	rh.wsMu.Lock()
	delete(rh.wsClients, c)
	close(c.Send)
	rh.wsMu.Unlock()
}

// ClientCount returns the number of connected WS clients.
func (rh *ReportHub) ClientCount() int {
	rh.wsMu.RLock()
	n := len(rh.wsClients)
	rh.wsMu.RUnlock()
	return n
}

func (rh *ReportHub) broadcastLoop() {
	for msg := range rh.broadcast {
		rh.wsMu.RLock()
		for c := range rh.wsClients {
			if c.IsPaused() {
				continue
			}
			select {
			case c.Send <- msg:
			default:
				// slow client, skip
			}
		}
		rh.wsMu.RUnlock()
	}
}

// Close shuts down all sub-components. Record calls after Close are no-ops.
func (rh *ReportHub) Close() {
	if !rh.closed.CompareAndSwap(false, true) {
		return
	}
	close(rh.broadcast)
	rh.Disk.Close()
}
