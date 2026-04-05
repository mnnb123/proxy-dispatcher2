package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"proxy-dispatcher/internal/config"
)

// AlertEntry represents a single alert event.
type AlertEntry struct {
	ID        uint64 `json:"id"`
	Timestamp int64  `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	Domain    string `json:"domain,omitempty"`
	Value     int64  `json:"value,omitempty"`
}

// AlertManager monitors log entries and fires alerts on anomalies.
type AlertManager struct {
	enabled       bool
	webhookURL    string
	telegramToken string
	telegramChat  string

	alerts    []*AlertEntry
	maxAlerts int
	alertMu   sync.RWMutex
	idCounter uint64

	cooldowns map[string]time.Time
	cooldownMu sync.Mutex

	logger *slog.Logger
}

// NewAlertManager creates an AlertManager from config.
func NewAlertManager(cfg config.ReportConfig, logger *slog.Logger) *AlertManager {
	return &AlertManager{
		enabled:       cfg.AlertEnabled,
		webhookURL:    cfg.AlertWebhookURL,
		telegramToken: cfg.AlertTelegramToken,
		telegramChat:  cfg.AlertTelegramChat,
		alerts:        make([]*AlertEntry, 0, 100),
		maxAlerts:     200,
		cooldowns:     make(map[string]time.Time),
		logger:        logger,
	}
}

// Check evaluates a log entry for alert conditions.
func (am *AlertManager) Check(entry *LogEntry) {
	if !am.enabled {
		return
	}
	if entry.StatusCode >= 500 {
		am.fire("warning", fmt.Sprintf("HTTP %d on %s%s", entry.StatusCode, entry.Domain, entry.URLPath), entry.Domain, int64(entry.StatusCode))
	}
	if entry.Error != "" {
		am.fire("error", fmt.Sprintf("Error on %s: %s", entry.Domain, entry.Error), entry.Domain, 0)
	}
	if entry.LatencyMs > 10000 {
		am.fire("warning", fmt.Sprintf("High latency %dms on %s", entry.LatencyMs, entry.Domain), entry.Domain, entry.LatencyMs)
	}
}

func (am *AlertManager) fire(level, message, domain string, value int64) {
	cooldownKey := fmt.Sprintf("%s:%s", level, domain)

	am.cooldownMu.Lock()
	if t, ok := am.cooldowns[cooldownKey]; ok && time.Since(t) < 60*time.Second {
		am.cooldownMu.Unlock()
		return
	}
	am.cooldowns[cooldownKey] = time.Now()
	am.cooldownMu.Unlock()

	am.idCounter++
	alert := &AlertEntry{
		ID:        am.idCounter,
		Timestamp: time.Now().UnixMilli(),
		Level:     level,
		Message:   message,
		Domain:    domain,
		Value:     value,
	}

	am.alertMu.Lock()
	am.alerts = append(am.alerts, alert)
	if len(am.alerts) > am.maxAlerts {
		am.alerts = am.alerts[len(am.alerts)-am.maxAlerts:]
	}
	am.alertMu.Unlock()

	am.logger.Warn("alert fired", "level", level, "message", message)
	go am.notify(alert)
}

// GetAlerts returns recent alerts, up to limit.
func (am *AlertManager) GetAlerts(limit int) []*AlertEntry {
	am.alertMu.RLock()
	defer am.alertMu.RUnlock()
	total := len(am.alerts)
	if limit <= 0 || limit > total {
		limit = total
	}
	result := make([]*AlertEntry, limit)
	copy(result, am.alerts[total-limit:])
	return result
}

// ClearAlerts removes all stored alerts.
func (am *AlertManager) ClearAlerts() {
	am.alertMu.Lock()
	am.alerts = am.alerts[:0]
	am.alertMu.Unlock()
}

func (am *AlertManager) notify(alert *AlertEntry) {
	if am.webhookURL != "" {
		am.sendWebhook(alert)
	}
	if am.telegramToken != "" && am.telegramChat != "" {
		am.sendTelegram(alert)
	}
}

func (am *AlertManager) sendWebhook(alert *AlertEntry) {
	data, _ := json.Marshal(alert)
	resp, err := http.Post(am.webhookURL, "application/json", bytes.NewReader(data))
	if err != nil {
		am.logger.Error("webhook send failed", "error", err)
		return
	}
	resp.Body.Close()
}

func (am *AlertManager) sendTelegram(alert *AlertEntry) {
	text := fmt.Sprintf("[%s] %s", alert.Level, alert.Message)
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", am.telegramToken)
	payload := map[string]string{
		"chat_id": am.telegramChat,
		"text":    text,
	}
	data, _ := json.Marshal(payload)
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		am.logger.Error("telegram send failed", "error", err)
		return
	}
	resp.Body.Close()
}
