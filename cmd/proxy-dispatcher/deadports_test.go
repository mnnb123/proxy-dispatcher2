package main

import (
	"io"
	"log/slog"
	"testing"

	"proxy-dispatcher/internal/config"
	"proxy-dispatcher/internal/engine"
)

func TestDeadPortWatcherCompute(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	groups := []config.ProxyGroup{{
		Name:         "g",
		RotationMode: "roundrobin",
		Proxies: []config.ProxyEntry{
			{Host: "10.0.0.1", Port: 1, Type: "http", Status: "alive", LastCheck: 1},
			{Host: "10.0.0.2", Port: 1, Type: "http", Status: "dead", LastCheck: 1},
			{}, // empty slot
		},
	}}
	gm, err := engine.NewGroupManager(groups, []config.PortMapping{{PortStart: 100, PortEnd: 103, GroupName: "g"}}, logger)
	if err != nil {
		t.Fatal(err)
	}
	w := &deadPortWatcher{groups: gm, logger: logger}
	ports := []int{100, 101, 102, 103}

	// First look: the dead proxy needs a second failed round; the empty slot
	// (102) and the port past the list (103) are down at once.
	down := w.compute(ports, false)
	if down[100] || down[101] || !down[102] || !down[103] {
		t.Fatalf("first round down = %v", down)
	}
	// Same round seen again: still not down.
	if down = w.compute(ports, false); down[101] {
		t.Fatal("port went down without a new failed check")
	}
	// A second failed check closes it.
	p, _ := gm.GetProxyForPort(101)
	p.LastCheck = 2
	if down = w.compute(ports, false); !down[101] {
		t.Fatal("port of a proxy dead twice in a row must be down")
	}
	// The proxy answers again: the port reopens.
	p.Status = "alive"
	if down = w.compute(ports, false); down[101] {
		t.Fatal("port must reopen once its proxy is alive")
	}
	// Feature off: nothing is down.
	if down = w.compute(ports, true); len(down) != 0 {
		t.Fatalf("off: down = %v", down)
	}
}
