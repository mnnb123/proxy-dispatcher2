package report

import (
	"log/slog"
	"sync"

	"proxy-dispatcher/internal/config"
)

// WSClient represents a connected WebSocket client for live traffic.
type WSClient struct {
	Send   chan []byte
	Filter string
	Paused bool
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
			if c.Paused {
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

// Close shuts down all sub-components.
func (rh *ReportHub) Close() {
	close(rh.broadcast)
	rh.Disk.Close()
}
