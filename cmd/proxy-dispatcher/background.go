package main

import (
	"log/slog"
	"time"

	"proxy-dispatcher/internal/auth"
	"proxy-dispatcher/internal/bandwidth"
	"proxy-dispatcher/internal/engine"
	"proxy-dispatcher/internal/report"
	"proxy-dispatcher/internal/security"
)

// startBackgroundTasks launches periodic maintenance goroutines.
func startBackgroundTasks(
	limiter *auth.LoginLimiter,
	whitelistMgr *security.WhitelistManager,
	bruteGuard *security.BruteGuard,
	tracker *bandwidth.Tracker,
	reportHub *report.ReportHub,
	groupMgr *engine.GroupManager,
	tokenMgr *auth.TokenManager,
	logger *slog.Logger,
) {
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
}
