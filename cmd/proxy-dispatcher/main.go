// Command proxy-dispatcher runs the proxy dispatcher service.
package main

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"proxy-dispatcher/internal/api"
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
	webui "proxy-dispatcher/web"
)

var (
	Version   = "dev"
	BuildDate = "unknown"
	Commit    = "unknown"
)

func main() {
	configPath := flag.String("config", "/etc/proxy-dispatcher/config.json", "path to config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	initCfg := flag.Bool("init-config", false, "write default config and exit")
	vpsIP := flag.String("vps-ip", "", "VPS IP for init-config")
	ringBuffer := flag.Int("ring-buffer", 0, "ring buffer max rows for init-config")
	clearSec := flag.Int("clear-sec", 0, "auto clear seconds for init-config")
	resetAdmin := flag.Bool("reset-admin", false, "reset admin password to 'admin'")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *showVersion {
		fmt.Printf("proxy-dispatcher %s (%s) built %s\n", Version, Commit, BuildDate)
		return
	}
	if *initCfg {
		handleInitConfig(*configPath, *vpsIP, *ringBuffer, *clearSec, logger)
		return
	}
	if *resetAdmin {
		handleResetAdmin(*configPath, logger)
		return
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		logger.Error("load config", "error", err)
		os.Exit(1)
	}

	// --- Initialize all subsystems ---
	limiter := auth.NewLoginLimiter(5, 15*time.Minute)
	httpH := engine.NewHttpHandler(logger)

	groupMgr, err := engine.NewGroupManager(cfg.ProxyGroups, cfg.PortMappings, logger)
	exitOnErr(err, "group manager", logger)
	ruleEngine, err := rules.NewRuleEngine(cfg, logger)
	exitOnErr(err, "rule engine", logger)
	directDialer := engine.NewDirectDialer(time.Duration(cfg.ConnTimeout)*time.Second, logger)
	socks5H := engine.NewSocks5Handler(logger, ruleEngine)
	idleTimeout := time.Duration(cfg.IdleTimeout) * time.Second

	whitelistMgr, err := security.NewWhitelistManager(cfg.Whitelist, logger)
	exitOnErr(err, "whitelist", logger)
	bruteGuard := security.NewBruteGuard(cfg.Whitelist.AutoBan, logger)
	tracker := bandwidth.NewTracker(logger)
	budgetCtrl := bandwidth.NewBudgetController(cfg.BandwidthBudget, tracker, logger)

	reportHub, err := report.NewReportHub(cfg.Report, logger)
	exitOnErr(err, "report hub", logger)

	sizeForwarder := engine.NewSizeForwarder(engine.SizeForwarderDeps{
		AutoBypassCfg: cfg.AutoBypass,
		RuleEngine:    ruleEngine,
		Tracker:       tracker,
		DirectDialer:  directDialer,
		BudgetCtrl:    budgetCtrl,
		ResourceProxy: cfg.ResourceProxy,
		IdleTimeout:   idleTimeout,
		Logger:        logger,
	})

	var cfgMu sync.Mutex
	sizeForwarder.SetOnAutoBypass(func(domain string) {
		cfgMu.Lock()
		defer cfgMu.Unlock()
		cfg.BypassDomains = append(cfg.BypassDomains, config.DomainRule{
			Pattern: domain, Enabled: true, Note: "auto-bypass",
		})
		_ = ruleEngine.Reload(cfg)
		_ = config.SaveConfig(*configPath, cfg)
		logger.Info("auto-bypass: added domain to bypass rules", "domain", domain)
	})

	healthChecker := health.NewHealthChecker(cfg.HealthCheck, groupMgr.AllGroupProxies(), logger)
	healthChecker.OnStatusChange = func(p *config.ProxyEntry, oldS, newS string) {
		logger.Info("proxy status change", "proxy", fmt.Sprintf("%s:%d", p.Host, p.Port), "from", oldS, "to", newS)
		for _, g := range groupMgr.AllGroups() {
			if wr, ok := g.Rotator.(*engine.WeightedRotator); ok {
				wr.RebuildWeights()
			}
		}
	}
	healthChecker.Start()
	defer healthChecker.Stop()

	retryHandler := engine.NewRetryHandler(cfg.RetryCfg, logger)
	urlImporter := importer.NewURLImporter(cfg.ImportSources, groupMgr, logger)
	urlImporter.Start()
	defer urlImporter.Stop()

	// --- Connection handler ---
	connHandler := &ConnHandler{
		cfg: cfg, socks5H: socks5H, httpH: httpH, groupMgr: groupMgr,
		ruleEngine: ruleEngine, directDialer: directDialer,
		whitelistMgr: whitelistMgr, bruteGuard: bruteGuard,
		tracker: tracker, sizeForwarder: sizeForwarder,
		retryHandler: retryHandler, reportHub: reportHub,
		idleTimeout: idleTimeout, logger: logger,
	}

	lm := engine.NewListenerManager(cfg.MaxConnPerPort, connHandler.Handle, logger)
	startListeners(cfg, lm, logger)

	// --- API / web panel ---
	userMgr := auth.NewUserManager(cfg.Users, logger)
	tokenMgr := auth.NewTokenManager(cfg.APITokens, logger)
	backupMgr := system.NewBackupManager(*configPath, logger)
	dnsMgr := system.NewDNSManager(cfg.SystemConfig, logger)
	directDialer.SetResolver(dnsMgr.GetResolver())

	reloadAllModules := buildReloader(cfg, ruleEngine, groupMgr, whitelistMgr, healthChecker, budgetCtrl, dnsMgr, directDialer, lm, logger)

	syncMaster, syncSlave := setupSync(cfg, configPath, reloadAllModules, logger)

	onConfigSave := func() {
		backupMgr.AutoBackup()
		if syncMaster != nil && cfg.SyncConfig.AutoSync {
			go syncMaster.PushToAll()
		}
	}

	apiServer := api.NewServerWithDeps(api.ServerDeps{
		Cfg: cfg, CfgPath: *configPath, Rotator: nil, Limiter: limiter,
		RuleEngine: ruleEngine, WhitelistMgr: whitelistMgr, BruteGuard: bruteGuard,
		Tracker: tracker, BudgetCtrl: budgetCtrl, SizeForwarder: sizeForwarder,
		ListenerMg: lm, ReportHub: reportHub, GroupMgr: groupMgr,
		HealthChecker: healthChecker, Importer: urlImporter,
		UserMgr: userMgr, TokenMgr: tokenMgr,
		SyncMaster: syncMaster, SyncSlave: syncSlave,
		BackupMgr: backupMgr, DNSMgr: dnsMgr, Version: Version,
		OnConfigReload: reloadAllModules, OnConfigSave: onConfigSave,
		Logger: logger,
	})

	httpSrv := startWebPanel(cfg, apiServer, userMgr, tokenMgr, logger)

	// --- Background maintenance ---
	startBackgroundTasks(limiter, whitelistMgr, bruteGuard, tracker, reportHub, groupMgr, tokenMgr, logger)

	// --- Graceful shutdown ---
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	logger.Info("shutting down")

	_ = lm.Stop()
	reportHub.Close()
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutCancel()
	_ = httpSrv.Shutdown(shutCtx)
	logger.Info("bye")
}

// --- CLI subcommands ---

func handleInitConfig(path, vpsIP string, ringBuffer, clearSec int, logger *slog.Logger) {
	cfg := config.DefaultConfig()
	if vpsIP != "" {
		cfg.VpsIp = vpsIP
	}
	if ringBuffer > 0 {
		cfg.Report.RingBufferMaxRows = ringBuffer
	}
	if clearSec > 0 {
		cfg.Report.AutoClearSeconds = clearSec
	}
	if err := config.SaveConfig(path, cfg); err != nil {
		logger.Error("init-config failed", "error", err)
		os.Exit(1)
	}
	fmt.Printf("wrote default config to %s\n", path)
}

func handleResetAdmin(path string, logger *slog.Logger) {
	cfg, err := config.LoadConfig(path)
	if err != nil {
		logger.Error("load config", "error", err)
		os.Exit(1)
	}
	passHash, _ := auth.HashPassword("admin")
	cfg.AdminPassHash = passHash

	found := false
	for i := range cfg.Users {
		if cfg.Users[i].Role == "admin" {
			cfg.Users[i].PassHash = passHash
			cfg.Users[i].TOTPEnabled = false
			cfg.Users[i].TOTPSecret = ""
			cfg.Users[i].RecoveryCodes = nil
			cfg.Users[i].Disabled = false
			found = true
		}
	}
	if !found {
		cfg.Users = append(cfg.Users, config.UserAccount{
			ID: "admin-reset", Username: "admin", PassHash: passHash,
			Role: "admin", CreatedAt: time.Now().Unix(),
		})
	}
	if err := config.SaveConfig(path, cfg); err != nil {
		logger.Error("save config", "error", err)
		os.Exit(1)
	}
	fmt.Println("admin password reset to 'admin' (TOTP disabled)")
}

// --- Setup helpers ---

func exitOnErr(err error, name string, logger *slog.Logger) {
	if err != nil {
		logger.Error(name+" init failed", "error", err)
		os.Exit(1)
	}
}

func startListeners(cfg *config.AppConfig, lm *engine.ListenerManager, logger *slog.Logger) {
	if len(cfg.PortMappings) > 0 {
		for _, m := range cfg.PortMappings {
			count := m.PortEnd - m.PortStart + 1
			if count <= 0 {
				continue
			}
			if err := lm.Start(m.PortStart, count); err != nil {
				logger.Warn("listener start for mapping failed", "group", m.GroupName, "error", err)
			}
		}
		if len(lm.ActivePorts()) == 0 {
			logger.Error("no listeners could be opened from port mappings")
			os.Exit(1)
		}
	} else {
		if err := lm.Start(cfg.OutputStartPort, cfg.OutputCount); err != nil {
			logger.Error("listener start", "error", err)
			os.Exit(1)
		}
	}
}

func buildReloader(cfg *config.AppConfig, ruleEngine *rules.RuleEngine, groupMgr *engine.GroupManager, whitelistMgr *security.WhitelistManager, healthChecker *health.HealthChecker, budgetCtrl *bandwidth.BudgetController, dnsMgr *system.DNSManager, directDialer *engine.DirectDialer, lm *engine.ListenerManager, logger *slog.Logger) func() error {
	return func() error {
		if err := ruleEngine.Reload(cfg); err != nil {
			return err
		}
		if err := groupMgr.Reload(cfg.ProxyGroups, cfg.PortMappings); err != nil {
			return err
		}
		if err := whitelistMgr.Reload(cfg.Whitelist); err != nil {
			return err
		}
		healthChecker.UpdateGroups(groupMgr.AllGroupProxies())
		budgetCtrl.Reload(cfg.BandwidthBudget)
		dnsMgr.Reload(cfg.SystemConfig)
		directDialer.SetResolver(dnsMgr.GetResolver())

		if len(cfg.PortMappings) > 0 {
			for _, m := range cfg.PortMappings {
				count := m.PortEnd - m.PortStart + 1
				if count > 0 {
					if err := lm.Restart(m.PortStart, count); err != nil {
						logger.Warn("listener restart failed", "error", err)
					}
				}
			}
		} else if cfg.OutputCount > 0 {
			if err := lm.Restart(cfg.OutputStartPort, cfg.OutputCount); err != nil {
				logger.Warn("listener restart failed", "error", err)
			}
		}
		return nil
	}
}

func setupSync(cfg *config.AppConfig, configPath *string, reloadAll func() error, logger *slog.Logger) (*syncmgr.SyncMaster, *syncmgr.SyncSlave) {
	switch cfg.SyncConfig.Role {
	case "master":
		sm := syncmgr.NewSyncMaster(cfg.SyncConfig, func() *config.AppConfig { return cfg }, logger)
		if cfg.SyncConfig.AutoSync {
			sm.StartAutoSync()
		}
		return sm, nil
	case "slave":
		onReceive := func(incoming *config.AppConfig) error {
			cfg.ProxyGroups = incoming.ProxyGroups
			cfg.PortMappings = incoming.PortMappings
			cfg.BypassDomains = incoming.BypassDomains
			cfg.BypassExtensions = incoming.BypassExtensions
			cfg.BlockDomains = incoming.BlockDomains
			cfg.ResourceProxy = incoming.ResourceProxy
			cfg.Whitelist = incoming.Whitelist
			cfg.AutoBypass = incoming.AutoBypass
			cfg.ForceProxyDomains = incoming.ForceProxyDomains
			cfg.BandwidthBudget = incoming.BandwidthBudget
			cfg.Report = incoming.Report
			cfg.HealthCheck = incoming.HealthCheck
			cfg.ImportSources = incoming.ImportSources
			cfg.RetryCfg = incoming.RetryCfg
			if err := config.SaveConfig(*configPath, cfg); err != nil {
				return err
			}
			return reloadAll()
		}
		return nil, syncmgr.NewSyncSlave(cfg.SyncConfig, onReceive, logger)
	}
	return nil, nil
}

func startWebPanel(cfg *config.AppConfig, apiServer *api.Server, userMgr *auth.UserManager, tokenMgr *auth.TokenManager, logger *slog.Logger) *http.Server {
	authMW := api.AuthMiddleware(userMgr, tokenMgr, cfg.JwtSecret)
	mux := http.NewServeMux()
	mux.Handle("/api/", authMW(apiServer))
	mux.Handle("/ws/", apiServer)
	mux.Handle("/", staticHandler(webui.Files))

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.WebPanelPort),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	go func() {
		logger.Info("web panel listening", "port", cfg.WebPanelPort)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("http server", "error", err)
		}
	}()
	return srv
}

func staticHandler(webFS fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(webFS))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			r.URL.Path = "/login.html"
		}
		if strings.Contains(r.URL.Path, "..") {
			http.NotFound(w, r)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}
