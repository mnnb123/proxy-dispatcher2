package report

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"proxy-dispatcher/internal/config"
)

// DiskUsageInfo summarises the on-disk log state.
type DiskUsageInfo struct {
	TotalFiles int    `json:"total_files"`
	TotalBytes int64  `json:"total_bytes"`
	OldestDate string `json:"oldest_date"`
	NewestDate string `json:"newest_date"`
}

// DiskLogger writes LogEntry records to date-rotated log files.
type DiskLogger struct {
	enabled     bool
	basePath    string
	maxDays     int
	maxSizeMB   int
	currentFile *os.File
	currentDate string
	currentSize int64
	writeCh     chan *LogEntry
	done        chan struct{}
	logger      *slog.Logger
}

// NewDiskLogger creates a DiskLogger and starts the write loop.
func NewDiskLogger(cfg config.ReportConfig, logger *slog.Logger) (*DiskLogger, error) {
	dl := &DiskLogger{
		enabled:   cfg.DiskLogEnabled,
		basePath:  cfg.DiskLogPath,
		maxDays:   cfg.DiskLogMaxDays,
		maxSizeMB: cfg.DiskLogMaxSizeMB,
		writeCh:   make(chan *LogEntry, 10000),
		done:      make(chan struct{}),
		logger:    logger,
	}
	if !dl.enabled {
		go dl.writeLoop()
		return dl, nil
	}
	if err := os.MkdirAll(dl.basePath, 0o755); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}
	if err := dl.openFile(); err != nil {
		return nil, err
	}
	go dl.writeLoop()
	return dl, nil
}

func (dl *DiskLogger) openFile() error {
	dl.currentDate = time.Now().Format("2006-01-02")
	name := filepath.Join(dl.basePath, "access-"+dl.currentDate+".log")
	f, err := os.OpenFile(name, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}
	info, _ := f.Stat()
	dl.currentFile = f
	if info != nil {
		dl.currentSize = info.Size()
	}
	return nil
}

// Write queues an entry for async disk write.
func (dl *DiskLogger) Write(entry *LogEntry) {
	select {
	case dl.writeCh <- entry:
	default:
		dl.logger.Warn("disk log buffer full, dropping entry")
	}
}

func (dl *DiskLogger) writeLoop() {
	defer close(dl.done)
	for entry := range dl.writeCh {
		if !dl.enabled || dl.currentFile == nil {
			continue
		}
		dl.checkRotate()
		line := entry.ToDiskLine()
		n, err := dl.currentFile.WriteString(line)
		if err != nil {
			dl.logger.Error("disk write error", "error", err)
			continue
		}
		dl.currentSize += int64(n)
	}
}

func (dl *DiskLogger) checkRotate() {
	today := time.Now().Format("2006-01-02")
	needRotate := today != dl.currentDate
	if dl.maxSizeMB > 0 && dl.currentSize >= int64(dl.maxSizeMB)*1024*1024 {
		needRotate = true
	}
	if !needRotate {
		return
	}
	dl.currentFile.Close()
	dl.openFile()
	go dl.cleanOldFiles()
}

func (dl *DiskLogger) cleanOldFiles() {
	entries, err := os.ReadDir(dl.basePath)
	if err != nil {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -dl.maxDays).Format("2006-01-02")
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "access-") || !strings.HasSuffix(e.Name(), ".log") {
			continue
		}
		date := strings.TrimPrefix(e.Name(), "access-")
		date = strings.TrimSuffix(date, ".log")
		if date < cutoff {
			os.Remove(filepath.Join(dl.basePath, e.Name()))
			dl.logger.Info("removed old log", "file", e.Name())
		}
	}
}

// ExportCSV streams a date's log file as CSV to writer.
func (dl *DiskLogger) ExportCSV(date string, writer io.Writer) error {
	name := filepath.Join(dl.basePath, "access-"+date+".log")
	f, err := os.Open(name)
	if err != nil {
		return fmt.Errorf("open log: %w", err)
	}
	defer f.Close()

	cw := csv.NewWriter(writer)
	cw.Write([]string{"timestamp", "client_ip", "domain", "port", "method", "url_path", "protocol", "status_code", "route_type", "input_proxy", "bytes_sent", "bytes_recv", "latency_ms", "error"})

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		entry, err := ParseDiskLine(scanner.Text())
		if err != nil {
			continue
		}
		cw.Write([]string{
			strconv.FormatInt(entry.Timestamp, 10), entry.ClientIP, entry.Domain,
			strconv.Itoa(entry.Port), entry.Method, entry.URLPath, entry.Protocol,
			strconv.Itoa(entry.StatusCode), entry.RouteType, entry.InputProxy,
			strconv.FormatInt(entry.BytesSent, 10), strconv.FormatInt(entry.BytesRecv, 10),
			strconv.FormatInt(entry.LatencyMs, 10), entry.Error,
		})
	}
	cw.Flush()
	return cw.Error()
}

// Close stops the write loop and closes the file.
func (dl *DiskLogger) Close() {
	close(dl.writeCh)
	<-dl.done
	if dl.currentFile != nil {
		dl.currentFile.Close()
	}
}

// GetDiskUsage returns info about log files on disk.
func (dl *DiskLogger) GetDiskUsage() DiskUsageInfo {
	info := DiskUsageInfo{}
	entries, err := os.ReadDir(dl.basePath)
	if err != nil {
		return info
	}
	var dates []string
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "access-") || !strings.HasSuffix(e.Name(), ".log") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		info.TotalFiles++
		info.TotalBytes += fi.Size()
		date := strings.TrimPrefix(e.Name(), "access-")
		date = strings.TrimSuffix(date, ".log")
		dates = append(dates, date)
	}
	if len(dates) > 0 {
		sort.Strings(dates)
		info.OldestDate = dates[0]
		info.NewestDate = dates[len(dates)-1]
	}
	return info
}
