package system

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SystemInfo is a snapshot of host + process metrics.
type SystemInfo struct {
	Hostname       string     `json:"hostname"`
	OS             string     `json:"os"`
	Arch           string     `json:"arch"`
	GoVersion      string     `json:"go_version"`
	CPUCores       int        `json:"cpu_cores"`
	TotalRAM       int64      `json:"total_ram"`
	FreeRAM        int64      `json:"free_ram"`
	DiskTotal      int64      `json:"disk_total"`
	DiskFree       int64      `json:"disk_free"`
	UptimeSec      int64      `json:"uptime_sec"`
	LoadAvg        [3]float64 `json:"load_avg"`
	Version        string     `json:"version"`
	StartedAt      int64      `json:"started_at"`
	PID            int        `json:"pid"`
	GoroutineCount int        `json:"goroutine_count"`
}

var (
	cacheMu   sync.Mutex
	cacheInfo SystemInfo
	cacheTime time.Time
)

// GetSystemInfo returns host + runtime stats, cached for 10s.
func GetSystemInfo(version string, startedAt int64) SystemInfo {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if time.Since(cacheTime) < 10*time.Second && cacheInfo.Hostname != "" {
		cacheInfo.UptimeSec = time.Now().Unix() - startedAt
		cacheInfo.GoroutineCount = runtime.NumGoroutine()
		return cacheInfo
	}
	host, _ := os.Hostname()
	info := SystemInfo{
		Hostname: host, OS: runtime.GOOS, Arch: runtime.GOARCH,
		GoVersion: runtime.Version(), CPUCores: runtime.NumCPU(),
		Version: version, StartedAt: startedAt, PID: os.Getpid(),
		UptimeSec:      time.Now().Unix() - startedAt,
		GoroutineCount: runtime.NumGoroutine(),
	}
	info.TotalRAM, info.FreeRAM = readMemInfo()
	info.DiskTotal, info.DiskFree = readDiskInfo()
	info.LoadAvg = readLoadAvg()
	cacheInfo = info
	cacheTime = time.Now()
	return info
}

func readMemInfo() (int64, int64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	var total, free int64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		kb, _ := strconv.ParseInt(fields[1], 10, 64)
		switch fields[0] {
		case "MemTotal:":
			total = kb * 1024
		case "MemAvailable:":
			free = kb * 1024
		}
	}
	return total, free
}

func readLoadAvg() [3]float64 {
	var out [3]float64
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return out
	}
	fields := strings.Fields(string(b))
	for i := 0; i < 3 && i < len(fields); i++ {
		out[i], _ = strconv.ParseFloat(fields[i], 64)
	}
	return out
}
