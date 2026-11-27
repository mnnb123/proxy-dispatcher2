package main

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"proxy-dispatcher/internal/config"
	"proxy-dispatcher/internal/engine"
)

func TestDeadPortWatcherCompute(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	groups := []config.ProxyGroup{
		{
			Name:         "ss",
			RotationMode: "roundrobin",
			KeepHistory:  true, // ShopSocks5 session group
			Proxies: []config.ProxyEntry{
				{Host: "10.0.0.1", Port: 1, Type: "socks5", Status: "alive", LastCheck: 1},
				{Host: "10.0.0.2", Port: 1, Type: "socks5", Status: "dead", LastCheck: 1},
				{}, // empty slot
			},
		},
		{
			Name:         "gw",
			RotationMode: "roundrobin",
			Proxies: []config.ProxyEntry{
				{Host: "gw.example", Port: 1, Type: "http", Status: "dead", LastCheck: 1},
				{},
			},
		},
	}
	gm, err := engine.NewGroupManager(groups, []config.PortMapping{
		{PortStart: 100, PortEnd: 103, GroupName: "ss"},
		{PortStart: 200, PortEnd: 201, GroupName: "gw"},
	}, logger)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(1000, 0)
	w := &deadPortWatcher{groups: gm, logger: logger, now: func() time.Time { return clock }}
	ports := []int{100, 101, 102, 103, 200, 201}

	// First look: the dead sock is not closed yet; the empty slot (102) and
	// the port past the list (103) are down at once. The other group's
	// ports are never touched.
	down := w.compute(ports, false)
	if down[100] || down[101] || !down[102] || !down[103] || down[200] || down[201] {
		t.Fatalf("first look down = %v", down)
	}
	// Dead for less than 3 minutes: still open.
	clock = clock.Add(deadFor - time.Second)
	if down = w.compute(ports, false); down[101] {
		t.Fatal("port closed before the sock was dead for 3 minutes")
	}
	// One good check resets the streak.
	p, _ := gm.GetProxyForPort(101)
	p.Status = "alive"
	w.compute(ports, false)
	p.Status = "dead"
	w.compute(ports, false)
	clock = clock.Add(deadFor - time.Second)
	if down = w.compute(ports, false); down[101] {
		t.Fatal("streak was not reset by a successful check")
	}
	// Dead for 3 minutes in a row: closed. Gateway group stays open.
	clock = clock.Add(2 * time.Second)
	if down = w.compute(ports, false); !down[101] || down[200] {
		t.Fatalf("after 3 dead minutes down = %v", down)
	}
	// The sock answers again: the port reopens.
	p.Status = "alive"
	if down = w.compute(ports, false); down[101] {
		t.Fatal("port must reopen once its sock is alive")
	}
	// Feature off: nothing is down.
	if down = w.compute(ports, true); len(down) != 0 {
		t.Fatalf("off: down = %v", down)
	}
}
