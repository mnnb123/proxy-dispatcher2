// Package report implements access logging, ring buffer, aggregation,
// disk logging, alerting, and WebSocket broadcast.
package report

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var idCounter atomic.Uint64

// LogEntry represents a single access log record.
type LogEntry struct {
	ID         uint64 `json:"id"`
	Timestamp  int64  `json:"timestamp"`
	ClientIP   string `json:"client_ip"`
	Domain     string `json:"domain"`
	Port       int    `json:"port"`
	ListenPort int    `json:"listen_port"`
	Method     string `json:"method"`
	URLPath    string `json:"url_path"`
	Protocol   string `json:"protocol"`
	StatusCode int    `json:"status_code"`
	RouteType  string `json:"route_type"`
	InputProxy string `json:"input_proxy,omitempty"`
	BytesSent  int64  `json:"bytes_sent"`
	BytesRecv  int64  `json:"bytes_recv"`
	LatencyMs  int64  `json:"latency_ms"`
	Error      string `json:"error,omitempty"`
}

// NewLogEntry creates a LogEntry with auto-incremented ID and current timestamp.
func NewLogEntry() *LogEntry {
	return &LogEntry{
		ID:        idCounter.Add(1),
		Timestamp: time.Now().UnixMilli(),
	}
}

// TotalBytes returns the sum of sent and received bytes.
func (e *LogEntry) TotalBytes() int64 {
	return e.BytesSent + e.BytesRecv
}

// ToDiskLine returns a pipe-delimited representation for disk logging.
func (e *LogEntry) ToDiskLine() string {
	return fmt.Sprintf("%d|%s|%s|%d|%s|%s|%s|%d|%s|%s|%d|%d|%d|%s\n",
		e.Timestamp, e.ClientIP, e.Domain, e.Port, e.Method,
		e.URLPath, e.Protocol, e.StatusCode, e.RouteType,
		e.InputProxy, e.BytesSent, e.BytesRecv, e.LatencyMs, e.Error)
}

// ParseDiskLine parses a pipe-delimited line back into a LogEntry.
func ParseDiskLine(line string) (*LogEntry, error) {
	line = strings.TrimRight(line, "\r\n")
	parts := strings.SplitN(line, "|", 14)
	if len(parts) < 14 {
		return nil, fmt.Errorf("expected 14 fields, got %d", len(parts))
	}
	ts, _ := strconv.ParseInt(parts[0], 10, 64)
	port, _ := strconv.Atoi(parts[3])
	sc, _ := strconv.Atoi(parts[7])
	bs, _ := strconv.ParseInt(parts[10], 10, 64)
	br, _ := strconv.ParseInt(parts[11], 10, 64)
	lat, _ := strconv.ParseInt(parts[12], 10, 64)
	return &LogEntry{
		Timestamp:  ts,
		ClientIP:   parts[1],
		Domain:     parts[2],
		Port:       port,
		Method:     parts[4],
		URLPath:    parts[5],
		Protocol:   parts[6],
		StatusCode: sc,
		RouteType:  parts[8],
		InputProxy: parts[9],
		BytesSent:  bs,
		BytesRecv:  br,
		LatencyMs:  lat,
		Error:      parts[13],
	}, nil
}

// ToJSON marshals the entry to JSON bytes.
func (e *LogEntry) ToJSON() []byte {
	data, _ := json.Marshal(e)
	return data
}

// EstimateSize returns an approximate memory footprint in bytes.
func (e *LogEntry) EstimateSize() int {
	return 150 + len(e.ClientIP) + len(e.Domain) + len(e.Method) +
		len(e.URLPath) + len(e.Protocol) + len(e.RouteType) +
		len(e.InputProxy) + len(e.Error)
}
