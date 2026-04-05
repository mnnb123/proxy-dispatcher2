// Package syncmgr implements master/slave configuration synchronization.
package syncmgr

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"proxy-dispatcher/internal/config"
)

// SyncPayload is the envelope pushed from master to slaves.
type SyncPayload struct {
	Version   string            `json:"version"`
	Timestamp int64             `json:"timestamp"`
	Checksum  string            `json:"checksum"`
	Config    *config.AppConfig `json:"config"`
}

// SyncResult is a single push outcome.
type SyncResult struct {
	Node       string `json:"node"`
	Success    bool   `json:"success"`
	Error      string `json:"error,omitempty"`
	DurationMs int64  `json:"duration_ms"`
}

// SyncMaster pushes configuration to slaves.
type SyncMaster struct {
	cfg            config.SyncConfig
	configProvider func() *config.AppConfig
	httpClient     *http.Client
	logger         *slog.Logger
	stopCh         chan struct{}
	mu             sync.Mutex
	slaveStatus    map[string]*config.SlaveNode
}

// NewSyncMaster builds a SyncMaster.
func NewSyncMaster(cfg config.SyncConfig, configProvider func() *config.AppConfig, logger *slog.Logger) *SyncMaster {
	sm := &SyncMaster{
		cfg:            cfg,
		configProvider: configProvider,
		httpClient:     &http.Client{Timeout: 30 * time.Second},
		logger:         logger,
		stopCh:         make(chan struct{}),
		slaveStatus:    make(map[string]*config.SlaveNode),
	}
	for i := range cfg.SlaveNodes {
		n := cfg.SlaveNodes[i]
		sm.slaveStatus[n.Name] = &n
	}
	return sm
}

// PushToAll sends the current config to all enabled slaves concurrently.
func (sm *SyncMaster) PushToAll() []SyncResult {
	payload := sm.prepareSyncPayload(sm.configProvider())
	body, _ := json.Marshal(payload)
	sig := sm.sign(body)

	var wg sync.WaitGroup
	var mu sync.Mutex
	results := []SyncResult{}
	done := make(chan struct{})
	for _, n := range sm.cfg.SlaveNodes {
		if !n.Enabled {
			continue
		}
		wg.Add(1)
		go func(node config.SlaveNode) {
			defer wg.Done()
			res := sm.pushToOne(node, body, sig)
			mu.Lock()
			results = append(results, res)
			if st, ok := sm.slaveStatus[node.Name]; ok {
				if res.Success {
					st.LastSync = time.Now().Unix()
					st.LastError = ""
					st.Status = "ok"
				} else {
					st.LastError = res.Error
					st.Status = "error"
				}
			}
			mu.Unlock()
		}(n)
	}
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
	}
	return results
}

func (sm *SyncMaster) sign(body []byte) string {
	mac := hmac.New(sha256.New, []byte(sm.cfg.SharedSecret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func (sm *SyncMaster) pushToOne(slave config.SlaveNode, body []byte, signature string) SyncResult {
	start := time.Now()
	url := slave.URL + "/api/sync/receive"
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return SyncResult{Node: slave.Name, Success: false, Error: err.Error(), DurationMs: time.Since(start).Milliseconds()}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sync-Signature", signature)
	resp, err := sm.httpClient.Do(req)
	if err != nil {
		return SyncResult{Node: slave.Name, Success: false, Error: err.Error(), DurationMs: time.Since(start).Milliseconds()}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return SyncResult{Node: slave.Name, Success: false, Error: fmt.Sprintf("http %d", resp.StatusCode), DurationMs: time.Since(start).Milliseconds()}
	}
	return SyncResult{Node: slave.Name, Success: true, DurationMs: time.Since(start).Milliseconds()}
}

func (sm *SyncMaster) prepareSyncPayload(cfg *config.AppConfig) SyncPayload {
	clone := *cfg
	clone.Users = nil
	clone.APITokens = nil
	clone.SyncConfig = config.SyncConfig{}
	clone.SystemConfig = config.SystemConfig{}
	clone.AdminPassHash = ""
	clone.JwtSecret = ""
	raw, _ := json.Marshal(&clone)
	sum := sha256.Sum256(raw)
	return SyncPayload{
		Version:   "1.0",
		Timestamp: time.Now().Unix(),
		Checksum:  hex.EncodeToString(sum[:]),
		Config:    &clone,
	}
}

// StartAutoSync starts a periodic push ticker if AutoSync is on.
func (sm *SyncMaster) StartAutoSync() {
	if !sm.cfg.AutoSync || sm.cfg.SyncIntervalSec <= 0 {
		return
	}
	t := time.NewTicker(time.Duration(sm.cfg.SyncIntervalSec) * time.Second)
	go func() {
		defer t.Stop()
		for {
			select {
			case <-sm.stopCh:
				return
			case <-t.C:
				sm.PushToAll()
			}
		}
	}()
}

// Stop halts the auto-sync ticker.
func (sm *SyncMaster) Stop() {
	select {
	case <-sm.stopCh:
	default:
		close(sm.stopCh)
	}
}

// GetSlaveStatus returns current slave node statuses.
func (sm *SyncMaster) GetSlaveStatus() []config.SlaveNode {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	out := make([]config.SlaveNode, 0, len(sm.slaveStatus))
	for _, n := range sm.slaveStatus {
		out = append(out, *n)
	}
	return out
}
