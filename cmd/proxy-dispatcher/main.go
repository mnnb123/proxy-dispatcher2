// Command proxy-dispatcher runs the proxy dispatcher service.
package main

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
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
		cfg := config.DefaultConfig()
		if *vpsIP != "" {
			cfg.VpsIp = *vpsIP
		}
		if *ringBuffer > 0 {
			cfg.Report.RingBufferMaxRows = *ringBuffer
		}
		if *clearSec > 0 {
			cfg.Report.AutoClearSeconds = *clearSec
		}
		if err := config.SaveConfig(*configPath, cfg); err != nil {
			logger.Error("init-config failed", "error", err)
			os.Exit(1)
		}
		fmt.Printf("wrote default config to %s\n", *configPath)
		return
	}
	if *resetAdmin {
		cfg, err := config.LoadConfig(*configPath)
		if err != nil {
			logger.Error("load config", "error", err)
			os.Exit(1)
		}
		h, _ := auth.HashPassword("admin")
		cfg.AdminPassHash = h
		// Phase 6: also reset any admin user in Users slice and disable TOTP.
		found := false
		for i := range cfg.Users {
			if cfg.Users[i].Role == "admin" {
				cfg.Users[i].PassHash = h
				cfg.Users[i].TOTPEnabled = false
				cfg.Users[i].TOTPSecret = ""
				cfg.Users[i].RecoveryCodes = nil
				cfg.Users[i].Disabled = false
				found = true
			}
		}
		if !found {
			cfg.Users = append(cfg.Users, config.UserAccount{
				ID: "admin-reset", Username: "admin", PassHash: h,
				Role: "admin", CreatedAt: time.Now().Unix(),
			})
		}
		if err := config.SaveConfig(*configPath, cfg); err != nil {
			logger.Error("save config", "error", err)
			os.Exit(1)
		}
		fmt.Println("admin password reset to 'admin' (TOTP disabled)")
		return
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		logger.Error("load config", "error", err)
		os.Exit(1)
	}

	// Core Phase 1.
	limiter := auth.NewLoginLimiter(5, 15*time.Minute)
	httpH := engine.NewHttpHandler(logger)

	// Phase 5: group manager.
	groupMgr, err := engine.NewGroupManager(cfg.ProxyGroups, cfg.PortMappings, logger)
	if err != nil {
		logger.Error("group manager init", "error", err)
		os.Exit(1)
	}

	// Phase 2: rule engine + direct dialer.
	ruleEngine, err := rules.NewRuleEngine(cfg, logger)
	if err != nil {
		logger.Error("rule engine init", "error", err)
		os.Exit(1)
	}
	directDialer := engine.NewDirectDialer(time.Duration(cfg.ConnTimeout)*time.Second, logger)
	socks5H := engine.NewSocks5Handler(logger, ruleEngine)
	idleTimeout := time.Duration(cfg.IdleTimeout) * time.Second

	// Phase 3: whitelist, brute guard, bandwidth, budget, size forwarder.
	whitelistMgr, err := security.NewWhitelistManager(cfg.Whitelist, logger)
	if err != nil {
		logger.Error("whitelist init", "error", err)
		os.Exit(1)
	}
	bruteGuard := security.NewBruteGuard(cfg.Whitelist.AutoBan, logger)
	tracker := bandwidth.NewTracker(logger)
	budgetCtrl := bandwidth.NewBudgetController(cfg.BandwidthBudget, tracker, logger)

	// Phase 4: reporting.
	reportHub, err := report.NewReportHub(cfg.Report, logger)
	if err != nil {
		logger.Error("report hub init", "error", err)
		os.Exit(1)
	}
	recordEntry := func(listenPort int, clientIP, domain, portStr string, method, urlPath, proto, routeType, inputProxy, errStr string, status int, bytesSent, bytesRecv, latencyMs int64) {
		e := report.NewLogEntry()
		e.ListenPort = listenPort
		e.ClientIP = clientIP
		e.Domain = domain
		if portStr != "" {
			fmt.Sscanf(portStr, "%d", &e.Port)
		}
		e.Method = method
		e.URLPath = urlPath
		e.Protocol = proto
		e.StatusCode = status
		e.RouteType = routeType
		e.InputProxy = inputProxy
		e.BytesSent = bytesSent
		e.BytesRecv = bytesRecv
		e.LatencyMs = latencyMs
		e.Error = errStr
		reportHub.Record(e)
	}

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
			Pattern: domain,
			Enabled: true,
			Note:    "auto-bypass",
		})
		_ = ruleEngine.Reload(cfg)
		_ = config.SaveConfig(*configPath, cfg)
		logger.Info("auto-bypass: added domain to bypass rules", "domain", domain)
	})

	// Phase 5: health checker, retry, importer.
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

	extractPort := func(addr net.Addr) int {
		_, portStr, err := net.SplitHostPort(addr.String())
		if err != nil {
			return 0
		}
		p, _ := strconv.Atoi(portStr)
		return p
	}

	handler := func(conn net.Conn) {
		startTime := time.Now()
		clientIP := conn.RemoteAddr().String()
		if h, _, err := net.SplitHostPort(clientIP); err == nil {
			clientIP = h
		}
		// Phase 3: whitelist check first.
		allowed, reason := whitelistMgr.IsAllowed(clientIP)
		if !allowed {
			banned, _ := bruteGuard.RecordAndCheck(clientIP)
			if banned {
				logger.Debug("brute guard banned", "ip", clientIP)
			}
			logger.Debug("whitelist rejected", "ip", clientIP, "reason", reason)
			recordEntry(0, clientIP, "", "", "", "", "", "blocked", "", "whitelist: "+reason, 403, 0, 0, 0)
			conn.Close()
			return
		}

		outputPort := extractPort(conn.LocalAddr())
		group, gErr := groupMgr.GetGroupForPort(outputPort)
		if gErr != nil {
			logger.Warn("no group for port", "port", outputPort, "error", gErr)
			return
		}

		proto, buffConn, err := engine.DetectProtocol(conn)
		if err != nil || proto == "unknown" {
			return
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if proto == "socks5" {
			proxy, err := group.Rotator.Next(clientIP)
			if err != nil {
				logger.Warn("no proxy available", "group", group.Name)
				recordEntry(outputPort, clientIP, "", "", "", "", "socks5", "proxy", "", "no proxy available", 502, 0, 0, 0)
				return
			}
			proxyAddr := fmt.Sprintf("%s:%d", proxy.Host, proxy.Port)
			sResult, sErr := socks5H.HandleConnection(ctx, buffConn, *proxy, group.Rotator, clientIP)
			lat := time.Since(startTime).Milliseconds()
			destHost := ""
			destPort := ""
			var bytesSent, bytesRecv int64
			if sResult != nil {
				destHost = sResult.DestHost
				destPort = sResult.DestPort
				bytesSent = sResult.BytesSent
				bytesRecv = sResult.BytesRecv
				if sResult.ProxyUsed != "" {
					proxyAddr = sResult.ProxyUsed
				}
			}

			// Feed bytes into bandwidth tracker and auto-bypass.
			totalBytes := bytesSent + bytesRecv
			routeType := "proxy"
			if sResult != nil && sResult.RouteType != "" {
				routeType = sResult.RouteType
			}
			if destHost != "" {
				if totalBytes > 0 {
					tracker.Record(destHost, totalBytes, routeType)
				}
				if routeType == "proxy" {
					sizeForwarder.CheckAutoBypass(destHost, outputPort, totalBytes)
				}
			}

			inputProxy := proxyAddr
			if routeType == "direct" {
				inputProxy = ""
			}
			if sErr != nil {
				errStr := sErr.Error()
				// broken pipe / connection reset = normal tunnel close, not an error.
				if strings.Contains(errStr, "broken pipe") || strings.Contains(errStr, "connection reset") || strings.Contains(errStr, "use of closed") {
					recordEntry(outputPort, clientIP, destHost, destPort, "CONNECT", "", "socks5", routeType, inputProxy, "", 200, bytesSent, bytesRecv, lat)
				} else if strings.Contains(errStr, "blocked by rule") {
					recordEntry(outputPort, clientIP, destHost, destPort, "CONNECT", "", "socks5", "blocked", "", "blocked by rule", 403, 0, 0, lat)
				} else {
					logger.Debug("socks5 session error", "error", sErr)
					recordEntry(outputPort, clientIP, destHost, destPort, "CONNECT", "", "socks5", routeType, inputProxy, errStr, 502, bytesSent, bytesRecv, lat)
				}
			} else {
				recordEntry(outputPort, clientIP, destHost, destPort, "CONNECT", "", "socks5", routeType, inputProxy, "", 200, bytesSent, bytesRecv, lat)
			}
			return
		}

		// HTTP path: extract target for rule evaluation.
		reqInfo, extractErr := engine.ExtractHTTPTarget(buffConn)
		if extractErr != nil {
			proxy, err := group.Rotator.Next(clientIP)
			if err != nil {
				logger.Warn("no proxy available", "group", group.Name)
				recordEntry(outputPort, clientIP, "unknown", "", "", "", "http", "proxy", "", "no proxy available", 502, 0, 0, 0)
				return
			}
			pr, err := httpH.HandleConnection(ctx, buffConn, *proxy)
			if err != nil {
				logger.Debug("http fallback ended", "error", err)
			}
			tracker.Record("unknown", pr.BytesSent+pr.BytesReceived, "proxy")
			recordEntry(outputPort, clientIP, "unknown", "", "", "", "http", "proxy", fmt.Sprintf("%s:%d", proxy.Host, proxy.Port), "", 200, pr.BytesSent, pr.BytesReceived, time.Since(startTime).Milliseconds())
			return
		}

		prefixConn := engine.NewPrefixConn(reqInfo.ConsumedBytes, buffConn)
		action := ruleEngine.Evaluate(reqInfo.Host, reqInfo.UrlPath)

		proto4 := "http"
		if reqInfo.IsHTTPS {
			proto4 = "https"
		}

		switch action.Type {
		case "block":
			_ = rules.ExecuteBlockAction(prefixConn, action.Block, "http")
			tracker.Record(reqInfo.Host, 0, "block")
			recordEntry(outputPort, clientIP, reqInfo.Host, reqInfo.Port, reqInfo.Method, reqInfo.UrlPath, proto4, "blocked", "", "blocked by rule", 403, 0, 0, time.Since(startTime).Milliseconds())
			return

		case "direct":
			remoteConn, err := directDialer.Dial(ctx, reqInfo.Target)
			if err != nil {
				logger.Debug("direct dial failed", "target", reqInfo.Target, "error", err)
				recordEntry(outputPort, clientIP, reqInfo.Host, reqInfo.Port, reqInfo.Method, reqInfo.UrlPath, proto4, "direct", "", err.Error(), 502, 0, 0, time.Since(startTime).Milliseconds())
				return
			}
			if reqInfo.IsHTTPS {
				// CONNECT tunnel: send 200 to client, pipe raw bytes (no CONNECT headers to remote).
				if _, werr := buffConn.Conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); werr != nil {
					remoteConn.Close()
					return
				}
				pr := engine.Pipe(ctx, buffConn.Conn, remoteConn, idleTimeout)
				tracker.Record(reqInfo.Host, pr.BytesSent+pr.BytesReceived, "direct")
				recordEntry(outputPort, clientIP, reqInfo.Host, reqInfo.Port, reqInfo.Method, reqInfo.UrlPath, proto4, "direct", "", "", 200, pr.BytesSent, pr.BytesReceived, time.Since(startTime).Milliseconds())
			} else {
				// Plain HTTP: replay consumed request bytes then pipe.
				pr := engine.Pipe(ctx, prefixConn, remoteConn, idleTimeout)
				tracker.Record(reqInfo.Host, pr.BytesSent+pr.BytesReceived, "direct")
				recordEntry(outputPort, clientIP, reqInfo.Host, reqInfo.Port, reqInfo.Method, reqInfo.UrlPath, proto4, "direct", "", "", 200, pr.BytesSent, pr.BytesReceived, time.Since(startTime).Milliseconds())
			}
			return

		case "resource":
			resProxy := rules.ResolveBypassTarget(action.Type, cfg.ResourceProxy)
			if resProxy == nil {
				remoteConn, err := directDialer.Dial(ctx, reqInfo.Target)
				if err != nil {
					logger.Debug("direct dial failed", "target", reqInfo.Target, "error", err)
					recordEntry(outputPort, clientIP, reqInfo.Host, reqInfo.Port, reqInfo.Method, reqInfo.UrlPath, proto4, "direct", "", err.Error(), 502, 0, 0, time.Since(startTime).Milliseconds())
					return
				}
				if reqInfo.IsHTTPS {
					if _, werr := buffConn.Conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); werr != nil {
						remoteConn.Close()
						return
					}
					pr := engine.Pipe(ctx, buffConn.Conn, remoteConn, idleTimeout)
					tracker.Record(reqInfo.Host, pr.BytesSent+pr.BytesReceived, "direct")
					recordEntry(outputPort, clientIP, reqInfo.Host, reqInfo.Port, reqInfo.Method, reqInfo.UrlPath, proto4, "direct", "", "", 200, pr.BytesSent, pr.BytesReceived, time.Since(startTime).Milliseconds())
				} else {
					pr := engine.Pipe(ctx, prefixConn, remoteConn, idleTimeout)
					tracker.Record(reqInfo.Host, pr.BytesSent+pr.BytesReceived, "direct")
					recordEntry(outputPort, clientIP, reqInfo.Host, reqInfo.Port, reqInfo.Method, reqInfo.UrlPath, proto4, "direct", "", "", 200, pr.BytesSent, pr.BytesReceived, time.Since(startTime).Milliseconds())
				}
			} else {
				remoteConn, err := directDialer.DialThroughResource(ctx, reqInfo.Target, *resProxy)
				if err != nil {
					logger.Debug("resource dial failed", "target", reqInfo.Target, "error", err)
					recordEntry(outputPort, clientIP, reqInfo.Host, reqInfo.Port, reqInfo.Method, reqInfo.UrlPath, proto4, "resource", "", err.Error(), 502, 0, 0, time.Since(startTime).Milliseconds())
					return
				}
				pr := engine.Pipe(ctx, prefixConn, remoteConn, idleTimeout)
				tracker.Record(reqInfo.Host, pr.BytesSent+pr.BytesReceived, "resource")
				recordEntry(outputPort, clientIP, reqInfo.Host, reqInfo.Port, reqInfo.Method, reqInfo.UrlPath, proto4, "resource", "", "", 200, pr.BytesSent, pr.BytesReceived, time.Since(startTime).Milliseconds())
			}
			return

		default: // "proxy"
			var finalRes engine.SizeForwardResult
			var finalProxyAddr string
			_, retryErr := retryHandler.WithRetry(ctx, group.Rotator, clientIP, func(proxy *config.ProxyEntry) error {
				group.Rotator.IncrementConn(proxy)
				defer group.Rotator.DecrementConn(proxy)
				proxyAddr := fmt.Sprintf("%s:%d", proxy.Host, proxy.Port)
				finalProxyAddr = proxyAddr
				proxyConn, dialErr := net.DialTimeout("tcp", proxyAddr, time.Duration(cfg.ConnTimeout)*time.Second)
				if dialErr != nil {
					logger.Debug("proxy dial failed", "target", proxyAddr, "error", dialErr)
					return dialErr
				}
				if len(reqInfo.ConsumedBytes) > 0 {
					if reqInfo.IsHTTPS {
						// HTTPS CONNECT: establish tunnel through upstream proxy, then let SizeForwarder decide.
						connectReq := "CONNECT " + reqInfo.Target + " HTTP/1.1\r\nHost: " + reqInfo.Target + "\r\n"
						if proxy.User != "" {
							connectReq += "Proxy-Authorization: " + engine.ProxyBasicAuth(proxy.User, proxy.Pass) + "\r\n"
						}
						connectReq += "\r\n"
						if _, err := proxyConn.Write([]byte(connectReq)); err != nil {
							proxyConn.Close()
							return fmt.Errorf("write CONNECT: %w", err)
						}
						buf := make([]byte, 4096)
						n, rErr := proxyConn.Read(buf)
						if rErr != nil {
							proxyConn.Close()
							return fmt.Errorf("read CONNECT response: %w", rErr)
						}
						resp := string(buf[:n])
						if len(resp) < 12 || resp[9:12] != "200" {
							proxyConn.Close()
							return fmt.Errorf("upstream CONNECT failed: %s", resp)
						}
						// Send 200 to client.
						if _, err := buffConn.Conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
							proxyConn.Close()
							return fmt.Errorf("write 200: %w", err)
						}
						// Now tunnel is established: client <-> proxyConn. Let SizeForwarder handle it.
						res, sfErr := sizeForwarder.Forward(ctx, buffConn.Conn, proxyConn, reqInfo, nil, outputPort)
						if sfErr != nil {
							return sfErr
						}
						finalRes = res
						return nil
					}
					// For plain HTTP: inject Proxy-Authorization into consumed bytes before forwarding.
					outBytes := reqInfo.ConsumedBytes
					if proxy.User != "" {
						outBytes = engine.InjectProxyAuth(reqInfo.ConsumedBytes, proxy.User, proxy.Pass)
					}
					if _, err := proxyConn.Write(outBytes); err != nil {
						proxyConn.Close()
						return err
					}
				}
				res, sfErr := sizeForwarder.Forward(ctx, prefixConn, proxyConn, reqInfo, reqInfo.ConsumedBytes, outputPort)
				if sfErr != nil {
					return sfErr
				}
				finalRes = res
				return nil
			})
			if retryErr != nil {
				logger.Debug("proxy retry exhausted", "error", retryErr)
				recordEntry(outputPort, clientIP, reqInfo.Host, reqInfo.Port, reqInfo.Method, reqInfo.UrlPath, proto4, "proxy", finalProxyAddr, retryErr.Error(), 502, 0, 0, time.Since(startTime).Milliseconds())
				return
			}
			recordEntry(outputPort, clientIP, reqInfo.Host, reqInfo.Port, reqInfo.Method, reqInfo.UrlPath, proto4, "proxy", finalProxyAddr, "", 200, finalRes.BytesSent, finalRes.BytesReceived, time.Since(startTime).Milliseconds())
		}
	}

	lm := engine.NewListenerManager(cfg.MaxConnPerPort, handler, logger)
	// Listen to every port defined in PortMappings. If no mappings exist,
	// fall back to the legacy single-range config.
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

	// Phase 6: auth, sync, backup, DNS, system info.
	userMgr := auth.NewUserManager(cfg.Users, logger)
	tokenMgr := auth.NewTokenManager(cfg.APITokens, logger)
	backupMgr := system.NewBackupManager(*configPath, logger)
	dnsMgr := system.NewDNSManager(cfg.SystemConfig, logger)
	directDialer.SetResolver(dnsMgr.GetResolver())

	reloadAllModules := func() error {
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

		// Restart listeners to match new port mappings.
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

	var syncMaster *syncmgr.SyncMaster
	var syncSlave *syncmgr.SyncSlave
	switch cfg.SyncConfig.Role {
	case "master":
		syncMaster = syncmgr.NewSyncMaster(cfg.SyncConfig, func() *config.AppConfig { return cfg }, logger)
		if cfg.SyncConfig.AutoSync {
			syncMaster.StartAutoSync()
			defer syncMaster.Stop()
		}
	case "slave":
		onReceive := func(incoming *config.AppConfig) error {
			// Preserve local auth/sync state; merge dispatch config only.
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
			return reloadAllModules()
		}
		syncSlave = syncmgr.NewSyncSlave(cfg.SyncConfig, onReceive, logger)
	}

	onConfigSave := func() {
		backupMgr.AutoBackup()
		if syncMaster != nil && cfg.SyncConfig.AutoSync {
			go syncMaster.PushToAll()
		}
	}

	apiServer := api.NewServerWithDeps(api.ServerDeps{
		Cfg: cfg, CfgPath: *configPath, Rotator: nil, Limiter: limiter,
		RuleEngine: ruleEngine, WhitelistMgr: whitelistMgr, BruteGuard: bruteGuard,
		Tracker: tracker, BudgetCtrl: budgetCtrl, SizeForwarder: sizeForwarder, ListenerMg: lm,
		ReportHub: reportHub, GroupMgr: groupMgr, HealthChecker: healthChecker,
		Importer:       urlImporter,
		UserMgr:        userMgr,
		TokenMgr:       tokenMgr,
		SyncMaster:     syncMaster,
		SyncSlave:      syncSlave,
		BackupMgr:      backupMgr,
		DNSMgr:         dnsMgr,
		Version:        Version,
		OnConfigReload: reloadAllModules,
		OnConfigSave:   onConfigSave,
		Logger:         logger,
	})

	authMW := api.AuthMiddleware(userMgr, tokenMgr, cfg.JwtSecret)
	mux := http.NewServeMux()
	mux.Handle("/api/", authMW(apiServer))
	mux.Handle("/ws/", apiServer)
	mux.Handle("/", staticHandler(webui.Files))

	httpSrv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.WebPanelPort),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	go func() {
		logger.Info("web panel listening", "port", cfg.WebPanelPort)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("http server", "error", err)
		}
	}()

	// Background tickers.
	go func() {
		loginCleanup := time.NewTicker(10 * time.Minute)
		minutely := time.NewTicker(1 * time.Minute)
		fiveMin := time.NewTicker(5 * time.Minute)
		hourly := time.NewTicker(1 * time.Hour)
		daily := time.NewTicker(24 * time.Hour)
		defer loginCleanup.Stop()
		defer minutely.Stop()
		defer fiveMin.Stop()
		defer hourly.Stop()
		defer daily.Stop()

		lastDay := time.Now().Format("2006-01-02")
		for {
			select {
			case <-loginCleanup.C:
				limiter.Cleanup()
			case <-minutely.C:
				whitelistMgr.CleanupExpired()
				reportHub.Agg.CleanupOld()
				// Phase 5: sticky session cleanup.
				for _, g := range groupMgr.AllGroups() {
					if sr, ok := g.Rotator.(*engine.StickyRotator); ok {
						sr.CleanupExpired()
					}
				}
				today := time.Now().Format("2006-01-02")
				if today != lastDay {
					tracker.ResetDaily()
					lastDay = today
					logger.Info("daily reset completed")
				}
			case <-fiveMin.C:
				bruteGuard.Cleanup()
			case <-hourly.C:
				tracker.ResetHourly()
				tracker.Cleanup()
				reportHub.Agg.RollupMinuteToHour()
			case <-daily.C:
				reportHub.Agg.RollupHourToDay()
				tokenMgr.Cleanup()
			}
		}
	}()

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
