package bandwidth

import (
	"log/slog"
	"sync"
	"sync/atomic"

	"proxy-dispatcher/internal/config"
)

// BudgetResult is the outcome of a budget check.
type BudgetResult struct {
	Allowed      bool   `json:"allowed"`
	Warning      bool   `json:"warning"`
	Reason       string `json:"reason,omitempty"`
	Action       string `json:"action,omitempty"`
	UsagePercent int    `json:"usage_percent"`
}

// BudgetStatus summarises budget consumption for the API.
type BudgetStatus struct {
	DailyUsed  int64 `json:"daily_used"`
	DailyLimit int64 `json:"daily_limit"`
	Percent    int   `json:"percent"`
	IsWarning  bool  `json:"is_warning"`
	IsExceeded bool  `json:"is_exceeded"`
}

// BudgetController enforces daily and per-domain bandwidth budgets.
type BudgetController struct {
	cfg              config.BudgetConfig
	tracker          *Tracker
	logger           *slog.Logger
	mu               sync.RWMutex
	dailyExceeded    atomic.Bool
	warningTriggered atomic.Bool
	domainExceeded   sync.Map
}

// NewBudgetController creates a BudgetController.
func NewBudgetController(cfg config.BudgetConfig, tracker *Tracker, logger *slog.Logger) *BudgetController {
	return &BudgetController{cfg: cfg, tracker: tracker, logger: logger}
}

// CheckBudget evaluates whether a request for domain is within budget.
func (bc *BudgetController) CheckBudget(domain string) BudgetResult {
	bc.mu.RLock()
	cfg := bc.cfg
	bc.mu.RUnlock()

	if !cfg.Enabled {
		return BudgetResult{Allowed: true}
	}

	used := bc.tracker.GetTotalProxyBytesToday()
	pct := 0
	if cfg.DailyLimitBytes > 0 {
		pct = int(used * 100 / cfg.DailyLimitBytes)
	}

	// Daily limit.
	if cfg.DailyLimitBytes > 0 && used >= cfg.DailyLimitBytes {
		if !bc.dailyExceeded.Load() {
			bc.dailyExceeded.Store(true)
			bc.logger.Warn("daily bandwidth budget exceeded", "used", used, "limit", cfg.DailyLimitBytes)
		}
		return BudgetResult{Allowed: false, Reason: "daily_limit", Action: cfg.OverLimitAction, UsagePercent: pct}
	}

	// Domain hourly limit.
	if cfg.DomainHourlyLimit > 0 && domain != "" {
		domainBytes := bc.tracker.GetDomainBytesThisHour(domain)
		if domainBytes >= cfg.DomainHourlyLimit {
			if _, loaded := bc.domainExceeded.LoadOrStore(domain, true); !loaded {
				bc.logger.Warn("domain hourly budget exceeded", "domain", domain, "used", domainBytes)
			}
			return BudgetResult{Allowed: false, Reason: "domain_hourly", Action: cfg.OverLimitAction, UsagePercent: pct}
		}
	}

	// Warning.
	if cfg.WarningPercent > 0 && pct >= cfg.WarningPercent {
		if !bc.warningTriggered.Load() {
			bc.warningTriggered.Store(true)
			bc.logger.Warn("bandwidth budget warning", "percent", pct)
		}
		return BudgetResult{Allowed: true, Warning: true, UsagePercent: pct}
	}

	return BudgetResult{Allowed: true, UsagePercent: pct}
}

// GetStatus returns current budget consumption status.
func (bc *BudgetController) GetStatus() BudgetStatus {
	bc.mu.RLock()
	cfg := bc.cfg
	bc.mu.RUnlock()

	used := bc.tracker.GetTotalProxyBytesToday()
	pct := 0
	if cfg.DailyLimitBytes > 0 {
		pct = int(used * 100 / cfg.DailyLimitBytes)
	}
	return BudgetStatus{
		DailyUsed:  used,
		DailyLimit: cfg.DailyLimitBytes,
		Percent:    pct,
		IsWarning:  cfg.WarningPercent > 0 && pct >= cfg.WarningPercent,
		IsExceeded: cfg.DailyLimitBytes > 0 && used >= cfg.DailyLimitBytes,
	}
}

// Reload replaces the budget config at runtime.
func (bc *BudgetController) Reload(cfg config.BudgetConfig) {
	bc.mu.Lock()
	bc.cfg = cfg
	bc.mu.Unlock()
	bc.dailyExceeded.Store(false)
	bc.warningTriggered.Store(false)
	bc.domainExceeded = sync.Map{}
}
