// Package api implements the HTTP JSON API and web-panel routing.
package api

import (
	"log/slog"
	"net/http"
	"time"

	"proxy-dispatcher/internal/auth"
	"proxy-dispatcher/internal/bandwidth"
	"proxy-dispatcher/internal/config"
	"proxy-dispatcher/internal/engine"
	"proxy-dispatcher/internal/health"
	"proxy-dispatcher/internal/importer"
	"proxy-dispatcher/internal/report"
	"proxy-dispatcher/internal/rules"
	"proxy-dispatcher/internal/security"
	"proxy-dispatcher/internal/syncmgr"
	"proxy-dispatcher/internal/system"
)

// Server is the HTTP API server.
type Server struct {
	cfg           *config.AppConfig
	cfgPath       string
	rotator       engine.Rotator
	limiter       *auth.LoginLimiter
	ruleEngine    *rules.RuleEngine
	whitelistMgr  *security.WhitelistManager
	bruteGuard    *security.BruteGuard
	tracker        *bandwidth.Tracker
	budgetCtrl     *bandwidth.BudgetController
	sizeForwarder  *engine.SizeForwarder
	reportHub      *report.ReportHub
	groupMgr      *engine.GroupManager
	healthChecker *health.HealthChecker
	importer      *importer.URLImporter
	logger        *slog.Logger
	mux           *http.ServeMux
	listenerMg    *engine.ListenerManager
	startTime     time.Time

	// Phase 6.
	userMgr        *auth.UserManager
	tokenMgr       *auth.TokenManager
	syncMaster     *syncmgr.SyncMaster
	syncSlave      *syncmgr.SyncSlave
	backupMgr      *system.BackupManager
	dnsMgr         *system.DNSManager
	version        string
	onConfigReload func() error
	onConfigSave   func()
}

// ServerDeps bundles Phase 6 dependencies for NewServerWithDeps.
type ServerDeps struct {
	Cfg            *config.AppConfig
	CfgPath        string
	Rotator        engine.Rotator
	Limiter        *auth.LoginLimiter
	RuleEngine     *rules.RuleEngine
	WhitelistMgr   *security.WhitelistManager
	BruteGuard     *security.BruteGuard
	Tracker        *bandwidth.Tracker
	BudgetCtrl     *bandwidth.BudgetController
	SizeForwarder  *engine.SizeForwarder
	ListenerMg     *engine.ListenerManager
	ReportHub      *report.ReportHub
	GroupMgr       *engine.GroupManager
	HealthChecker  *health.HealthChecker
	Importer       *importer.URLImporter
	UserMgr        *auth.UserManager
	TokenMgr       *auth.TokenManager
	SyncMaster     *syncmgr.SyncMaster
	SyncSlave      *syncmgr.SyncSlave
	BackupMgr      *system.BackupManager
	DNSMgr         *system.DNSManager
	Version        string
	OnConfigReload func() error
	OnConfigSave   func()
	Logger         *slog.Logger
}

// NewServer constructs a Server and registers its routes.
func NewServer(cfg *config.AppConfig, cfgPath string, rotator engine.Rotator, limiter *auth.LoginLimiter, ruleEng *rules.RuleEngine, whitelistMgr *security.WhitelistManager, bruteGuard *security.BruteGuard, tracker *bandwidth.Tracker, budgetCtrl *bandwidth.BudgetController, lm *engine.ListenerManager, reportHub *report.ReportHub, groupMgr *engine.GroupManager, healthChecker *health.HealthChecker, imp *importer.URLImporter, logger *slog.Logger) *Server {
	return NewServerWithDeps(ServerDeps{
		Cfg: cfg, CfgPath: cfgPath, Rotator: rotator, Limiter: limiter,
		RuleEngine: ruleEng, WhitelistMgr: whitelistMgr, BruteGuard: bruteGuard,
		Tracker: tracker, BudgetCtrl: budgetCtrl, ListenerMg: lm,
		ReportHub: reportHub, GroupMgr: groupMgr, HealthChecker: healthChecker,
		Importer: imp, Logger: logger,
	})
}

// NewServerWithDeps is the Phase 6-aware constructor.
func NewServerWithDeps(d ServerDeps) *Server {
	s := &Server{
		cfg:           d.Cfg,
		cfgPath:       d.CfgPath,
		rotator:       d.Rotator,
		limiter:       d.Limiter,
		ruleEngine:    d.RuleEngine,
		whitelistMgr:  d.WhitelistMgr,
		bruteGuard:    d.BruteGuard,
		tracker:       d.Tracker,
		budgetCtrl:    d.BudgetCtrl,
		sizeForwarder: d.SizeForwarder,
		reportHub:     d.ReportHub,
		groupMgr:      d.GroupMgr,
		healthChecker: d.HealthChecker,
		importer:      d.Importer,
		listenerMg:    d.ListenerMg,
		logger:        d.Logger,
		mux:           http.NewServeMux(),
		startTime:     time.Now(),

		userMgr:        d.UserMgr,
		tokenMgr:       d.TokenMgr,
		syncMaster:     d.SyncMaster,
		syncSlave:      d.SyncSlave,
		backupMgr:      d.BackupMgr,
		dnsMgr:         d.DNSMgr,
		version:        d.Version,
		onConfigReload: d.OnConfigReload,
		onConfigSave:   d.OnConfigSave,
	}

	// Phase 1 routes.
	s.mux.HandleFunc("POST /api/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/login/totp", s.handleLoginTOTP)
	s.mux.HandleFunc("GET /api/me", s.handleMe)
	s.mux.HandleFunc("GET /api/config/input", s.handleGetInput)
	s.mux.HandleFunc("POST /api/config/input", s.handlePostInput)
	s.mux.HandleFunc("GET /api/config/output", s.handleGetOutput)
	s.mux.HandleFunc("POST /api/config/output", s.handlePostOutput)
	s.mux.HandleFunc("GET /api/status", s.handleStatus)
	s.mux.HandleFunc("POST /api/password", s.handleChangePassword)
	s.mux.HandleFunc("POST /api/me/change-password", s.handleChangePassword)
	s.mux.HandleFunc("POST /api/me/totp/setup", s.handleTOTPSetup)
	s.mux.HandleFunc("POST /api/me/totp/confirm", s.handleTOTPConfirm)
	s.mux.HandleFunc("POST /api/me/totp/disable", s.handleTOTPDisable)

	// Phase 2 routes.
	s.mux.HandleFunc("GET /api/config/bypass/domains", s.handleGetBypassDomains)
	s.mux.HandleFunc("POST /api/config/bypass/domains", s.handlePostBypassDomains)
	s.mux.HandleFunc("GET /api/config/bypass/extensions", s.handleGetBypassExtensions)
	s.mux.HandleFunc("POST /api/config/bypass/extensions", s.handlePostBypassExtensions)
	s.mux.HandleFunc("GET /api/config/resource-proxy", s.handleGetResourceProxy)
	s.mux.HandleFunc("POST /api/config/resource-proxy", s.handlePostResourceProxy)
	s.mux.HandleFunc("GET /api/config/block/domains", s.handleGetBlockDomains)
	s.mux.HandleFunc("POST /api/config/block/domains", s.handlePostBlockDomains)

	// Phase 3 routes.
	s.mux.HandleFunc("GET /api/config/whitelist", s.handleGetWhitelist)
	s.mux.HandleFunc("POST /api/config/whitelist", s.handlePostWhitelist)
	s.mux.HandleFunc("POST /api/config/whitelist/add", s.handleAddWhitelistIP)
	s.mux.HandleFunc("DELETE /api/config/whitelist/remove", s.handleRemoveWhitelistIP)
	s.mux.HandleFunc("GET /api/config/whitelist/my-ip", s.handleMyIP)
	s.mux.HandleFunc("GET /api/config/whitelist/banned", s.handleBannedIPs)
	s.mux.HandleFunc("GET /api/config/auto-bypass", s.handleGetAutoBypass)
	s.mux.HandleFunc("POST /api/config/auto-bypass", s.handlePostAutoBypass)
	s.mux.HandleFunc("GET /api/auto-bypass/stats", s.handleAutoBypassStats)
	s.mux.HandleFunc("POST /api/auto-bypass/clear", s.handleAutoBypassClear)
	s.mux.HandleFunc("POST /api/auto-bypass/force-proxy", s.handleAddForceProxy)
	s.mux.HandleFunc("GET /api/config/force-proxy", s.handleGetForceProxy)
	s.mux.HandleFunc("POST /api/config/force-proxy", s.handlePostForceProxy)
	s.mux.HandleFunc("GET /api/config/bandwidth-budget", s.handleGetBandwidthBudget)
	s.mux.HandleFunc("POST /api/config/bandwidth-budget", s.handlePostBandwidthBudget)
	s.mux.HandleFunc("GET /api/bandwidth/status", s.handleBandwidthStatus)
	s.mux.HandleFunc("GET /api/bandwidth/snapshot", s.handleBandwidthSnapshot)
	s.mux.HandleFunc("POST /api/bandwidth/clear", s.handleBandwidthClear)

	// Phase 4 routes.
	s.mux.HandleFunc("GET /api/report/recent", s.handleReportRecent)
	s.mux.HandleFunc("GET /api/report/stats", s.handleReportStats)
	s.mux.HandleFunc("POST /api/report/clear", s.handleReportClear)
	s.mux.HandleFunc("GET /api/report/chart/minute", s.handleChartMinute)
	s.mux.HandleFunc("GET /api/report/chart/hour", s.handleChartHour)
	s.mux.HandleFunc("GET /api/report/top-domains", s.handleTopDomains)
	s.mux.HandleFunc("GET /api/report/disk-usage", s.handleDiskUsage)
	s.mux.HandleFunc("GET /api/report/export-csv", s.handleExportCSV)
	s.mux.HandleFunc("GET /api/report/alerts", s.handleGetAlerts)
	s.mux.HandleFunc("POST /api/report/alerts/clear", s.handleClearAlerts)
	s.mux.HandleFunc("POST /api/report/config", s.handlePostReportConfig)
	s.mux.HandleFunc("/ws/live-traffic", s.handleWSLiveTraffic)

	// Phase 5 routes.
	s.mux.HandleFunc("GET /api/health/config", s.handleGetHealthConfig)
	s.mux.HandleFunc("POST /api/health/config", s.handlePostHealthConfig)
	s.mux.HandleFunc("GET /api/health/status", s.handleHealthStatus)
	s.mux.HandleFunc("POST /api/health/check-now", s.handleHealthCheckNow)
	s.mux.HandleFunc("GET /api/groups", s.handleGetGroups)
	s.mux.HandleFunc("POST /api/groups", s.handlePostGroup)
	s.mux.HandleFunc("PUT /api/groups/{name}", s.handlePutGroup)
	s.mux.HandleFunc("DELETE /api/groups/{name}", s.handleDeleteGroup)
	s.mux.HandleFunc("GET /api/port-mappings", s.handleGetPortMappings)
	s.mux.HandleFunc("POST /api/port-mappings", s.handlePostPortMappings)
	s.mux.HandleFunc("GET /api/import/sources", s.handleGetImportSources)
	s.mux.HandleFunc("POST /api/import/sources", s.handlePostImportSources)
	s.mux.HandleFunc("DELETE /api/import/sources/{name}", s.handleDeleteImportSource)
	s.mux.HandleFunc("POST /api/import/fetch-now/{name}", s.handleImportFetchNow)
	s.mux.HandleFunc("GET /api/config/retry", s.handleGetRetry)
	s.mux.HandleFunc("POST /api/config/retry", s.handlePostRetry)

	// Phase 6 routes.
	s.mux.HandleFunc("GET /api/users", s.handleListUsers)
	s.mux.HandleFunc("POST /api/users", s.handleCreateUser)
	s.mux.HandleFunc("PUT /api/users/{id}", s.handleUpdateUser)
	s.mux.HandleFunc("DELETE /api/users/{id}", s.handleDeleteUser)
	s.mux.HandleFunc("GET /api/tokens", s.handleListTokens)
	s.mux.HandleFunc("POST /api/tokens", s.handleCreateToken)
	s.mux.HandleFunc("DELETE /api/tokens/{id}", s.handleDeleteToken)
	s.mux.HandleFunc("GET /api/sync/status", s.handleSyncStatus)
	s.mux.HandleFunc("POST /api/sync/push", s.handleSyncPush)
	s.mux.HandleFunc("POST /api/sync/receive", s.handleSyncReceive)
	s.mux.HandleFunc("GET /api/system/info", s.handleSystemInfo)
	s.mux.HandleFunc("GET /api/system/backups", s.handleListBackups)
	s.mux.HandleFunc("POST /api/system/backups", s.handleCreateBackup)
	s.mux.HandleFunc("POST /api/system/backups/restore", s.handleRestoreBackup)
	s.mux.HandleFunc("DELETE /api/system/backups/{filename}", s.handleDeleteBackup)
	s.mux.HandleFunc("GET /api/system/export", s.handleExportConfig)
	s.mux.HandleFunc("POST /api/system/import", s.handleImportConfig)
	s.mux.HandleFunc("GET /api/system/dns", s.handleGetDNS)
	s.mux.HandleFunc("POST /api/system/dns", s.handlePostDNS)
	s.mux.HandleFunc("POST /api/system/dns/test", s.handleTestDNS)

	return s
}

// persistUsers saves the user-manager state back into the config file.
func (s *Server) persistUsers() {
	if s.userMgr == nil {
		return
	}
	s.cfg.Users = s.userMgr.Snapshot()
	_ = config.SaveConfig(s.cfgPath, s.cfg)
	if s.onConfigSave != nil {
		s.onConfigSave()
	}
}

// persistTokens saves the token-manager state back into the config file.
func (s *Server) persistTokens() {
	if s.tokenMgr == nil {
		return
	}
	s.cfg.APITokens = s.tokenMgr.Snapshot()
	_ = config.SaveConfig(s.cfgPath, s.cfg)
	if s.onConfigSave != nil {
		s.onConfigSave()
	}
}

// ServeHTTP satisfies http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}
