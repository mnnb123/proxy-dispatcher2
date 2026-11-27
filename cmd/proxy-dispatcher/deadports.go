package main

import (
	"log/slog"
	"sync"
	"time"

	"proxy-dispatcher/internal/config"
	"proxy-dispatcher/internal/engine"
)

// deadFor is how long a proxy must stay dead, without a single successful
// check in between, before its port is closed. Shorter streaks made ports
// flap open/closed on every hiccup.
const deadFor = 3 * time.Minute

// deadPortWatcher closes the output ports of ShopSocks5 (session) groups
// whose sock is dead or missing, and reopens them once the sock answers
// again. A checker then sees the port as dead instead of an open port that
// cannot reach the internet. Ports of other groups are never closed: their
// providers are rotating gateways that fail single checks while still
// working.
type deadPortWatcher struct {
	cfg    *config.AppConfig
	cfgMu  *sync.RWMutex
	groups *engine.GroupManager
	lm     *engine.ListenerManager
	logger *slog.Logger
	// since holds when each proxy was first seen dead in its current streak.
	since map[*config.ProxyEntry]time.Time
	lastN int
	now   func() time.Time // for tests; nil means time.Now
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
		w.logger.Info("ports closed because their ShopSocks5 sock is dead or missing", "count", len(down))
		w.lastN = len(down)
	}
}

// compute returns the ports to keep closed. Statuses are read from the live
// proxy entries the health checker updates.
func (w *deadPortWatcher) compute(ports []int, off bool) map[int]bool {
	if off {
		w.since = nil
		return nil
	}
	now := time.Now()
	if w.now != nil {
		now = w.now()
	}
	if w.since == nil {
		w.since = make(map[*config.ProxyEntry]time.Time)
	}
	seen := make(map[*config.ProxyEntry]bool)
	down := make(map[int]bool)
	for _, port := range ports {
		g, err := w.groups.GetGroupForPort(port)
		if err != nil || g == nil || !g.NoBypass {
			continue // only session (ShopSocks5) groups
		}
		p, ok := w.groups.GetProxyForPort(port)
		if !ok || p == nil || p.IsEmpty() {
			down[port] = true
			continue
		}
		seen[p] = true
		if p.Status != "dead" {
			delete(w.since, p)
			continue
		}
		first, ok := w.since[p]
		if !ok {
			w.since[p] = now
			continue
		}
		if now.Sub(first) >= deadFor {
			down[port] = true
		}
	}
	for p := range w.since {
		if !seen[p] {
			delete(w.since, p)
		}
	}
	return down
}
