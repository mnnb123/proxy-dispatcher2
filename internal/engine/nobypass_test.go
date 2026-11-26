package engine

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	socks5 "github.com/armon/go-socks5"

	"proxy-dispatcher/internal/config"
	"proxy-dispatcher/internal/rules"
)

// TestSocks5NoBypass: a destination covered by a bypass rule goes direct for
// a normal group, but stays on the upstream proxy for a no-bypass (session)
// group.
func TestSocks5NoBypass(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Destination: says "hi" and closes.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("hi"))
			c.Close()
		}
	}()

	// Upstream SOCKS5 proxy that counts the connections it relays.
	var relayed atomic.Int64
	up, err := socks5.New(&socks5.Config{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		relayed.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}})
	if err != nil {
		t.Fatal(err)
	}
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()
	go func() { _ = up.Serve(upLn) }()
	upstream := config.ProxyEntry{Host: "127.0.0.1", Port: upLn.Addr().(*net.TCPAddr).Port, Type: "socks5"}

	re, err := rules.NewRuleEngine(&config.AppConfig{
		DefaultBypassAction: "direct",
		BypassDomains:       []config.DomainRule{{Pattern: "127.0.0.1", Enabled: true}},
	}, logger)
	if err != nil {
		t.Fatal(err)
	}
	h := NewSocks5Handler(logger, re)

	run := func(noBypass bool) string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		done := make(chan *Socks5Result, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				done <- nil
				return
			}
			defer c.Close()
			_, bc, err := DetectProtocol(c)
			if err != nil {
				done <- nil
				return
			}
			res, _ := h.HandleConnection(context.Background(), bc, upstream, nil, "127.0.0.1", nil, noBypass)
			done <- res
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		front := config.ProxyEntry{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, Type: "socks5"}
		c, err := dialThroughSOCKS5Proxy(ctx, front, target.Addr().String())
		if err != nil {
			t.Fatalf("dial through handler: %v", err)
		}
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.CloseWrite() // nothing to send: lets both relays finish at once
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		got, _ := io.ReadAll(c)
		c.Close()
		if string(got) != "hi" {
			t.Fatalf("noBypass=%v: read %q, want \"hi\"", noBypass, got)
		}
		select {
		case res := <-done:
			if res == nil {
				t.Fatal("handler returned no result")
			}
			return res.RouteType
		case <-time.After(5 * time.Second):
			t.Fatal("handler did not finish")
		}
		return ""
	}

	if rt := run(false); rt != "direct" || relayed.Load() != 0 {
		t.Fatalf("normal group: route=%q relayed=%d, want direct/0", rt, relayed.Load())
	}
	if rt := run(true); rt != "proxy" || relayed.Load() != 1 {
		t.Fatalf("no-bypass group: route=%q relayed=%d, want proxy/1", rt, relayed.Load())
	}
}

// TestSessionGroupIsNoBypass: only groups that keep history (session groups)
// are flagged no-bypass.
func TestSessionGroupIsNoBypass(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	px := []config.ProxyEntry{{Host: "10.0.0.1", Port: 1, Type: "socks5"}}
	gm, err := NewGroupManager([]config.ProxyGroup{
		{Name: "normal", Proxies: px, RotationMode: "roundrobin"},
		{Name: "session", Proxies: px, RotationMode: "roundrobin", KeepHistory: true},
	}, []config.PortMapping{
		{PortStart: 30000, PortEnd: 30000, GroupName: "normal"},
		{PortStart: 40000, PortEnd: 40000, GroupName: "session"},
	}, logger)
	if err != nil {
		t.Fatal(err)
	}
	if g, _ := gm.GetGroupForPort(30000); g == nil || g.NoBypass {
		t.Fatal("normal group must keep bypass")
	}
	if g, _ := gm.GetGroupForPort(40000); g == nil || !g.NoBypass {
		t.Fatal("session group must be no-bypass")
	}
}

// TestHTTPUpstreamRefusalNeverGoesDirect: when an HTTP upstream refuses
// CONNECT (e.g. "407 Zone Disabled"), the dial must fail instead of
// connecting to the target directly with this server's own IP.
func TestHTTPUpstreamRefusalNeverGoesDirect(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	var direct atomic.Int64
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			direct.Add(1)
			c.Close()
		}
	}()

	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	go func() {
		for {
			c, err := up.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 4096)
			_, _ = c.Read(buf)
			_, _ = c.Write([]byte("HTTP/1.1 407 Zone Disabled\r\n\r\n"))
			c.Close()
		}
	}()

	px := config.ProxyEntry{Host: "127.0.0.1", Port: up.Addr().(*net.TCPAddr).Port, Type: "http"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialThroughHTTPProxy(ctx, px, target.Addr().String())
	if err == nil {
		conn.Close()
		t.Fatal("dial succeeded although the upstream refused CONNECT")
	}
	time.Sleep(100 * time.Millisecond)
	if direct.Load() != 0 {
		t.Fatal("the target was reached directly, bypassing the upstream")
	}
}
