package main

import (
	"log/slog"
	"sync"
	"time"

	"proxy-dispatcher/internal/config"
	"proxy-dispatcher/internal/engine"
)

// deadStreakNeeded is how many health-check rounds in a row must find a
// proxy dead before its port is closed, so one failed probe does not cut
// the customers of a proxy that only hiccupped.
const deadStreakNeeded = 2

type deadStreak struct {
	lastCheck int64
	n         int
}

// deadPortWatcher closes the output ports whose proxy is dead (or that have
// no proxy) and reopens them once the proxy answers again. A checker then
// sees "connection refused" — dead — instead of an open port that cannot
// reach the internet.
type deadPortWatcher struct {
	cfg     *config.AppConfig
	cfgMu   *sync.RWMutex
	groups  *engine.GroupManager
	lm      *engine.ListenerManager
	logger  *slog.Logger
	streaks map[*config.ProxyEntry]*deadStreak
	lastN   int
}

func (w *deadPortWatcher) run(every time.Duration) {
	for range time.Tick(every) {
		w.tick()
	}
}

func (w *deadPortWatcher) tick() {
	w.cfgMu.RLock()
	off := !w.cfg.HealthCheck.Enabled || w.cfg.HealthCheck.KeepDeadPortsOpen
	ports := desiredPorts(w.cfg)
	w.cfgMu.RUnlock()

	down := w.compute(ports, off)
	w.lm.SetDown(down)
	if len(down) != w.lastN {
		w.logger.Info("ports closed because their proxy is dead or missing", "count", len(down))
		w.lastN = len(down)
	}
}

// compute returns the ports to keep closed. Statuses are read from the live
// proxy entries the health checker updates.
func (w *deadPortWatcher) compute(ports []int, off bool) map[int]bool {
	if off {
		w.streaks = nil
		return nil
	}
	if w.streaks == nil {
		w.streaks = make(map[*config.ProxyEntry]*deadStreak)
	}
	seen := make(map[*config.ProxyEntry]bool)
	down := make(map[int]bool)
	for _, port := range ports {
		p, ok := w.groups.GetProxyForPort(port)
		if !ok || p == nil || p.IsEmpty() {
			down[port] = true
			continue
		}
		seen[p] = true
		if p.Status != "dead" {
			delete(w.streaks, p)
			continue
		}
		st := w.streaks[p]
		if st == nil {
			st = &deadStreak{lastCheck: p.LastCheck, n: 1}
			w.streaks[p] = st
		} else if p.LastCheck != st.lastCheck {
			st.lastCheck = p.LastCheck
			st.n++
		}
		if st.n >= deadStreakNeeded {
			down[port] = true
		}
	}
	for p := range w.streaks {
		if !seen[p] {
			delete(w.streaks, p)
		}
	}
	return down
}
