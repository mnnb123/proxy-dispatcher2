package engine

import (
	"bytes"
	"context"
	"crypto/tls"
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

// clientHello returns the first TLS record a real Go TLS client sends.
func clientHello(t *testing.T, sni string) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		_ = tls.Client(c1, &tls.Config{ServerName: sni, InsecureSkipVerify: true}).Handshake()
	}()
	_ = c2.SetReadDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c2, hdr); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
	if _, err := io.ReadFull(c2, body); err != nil {
		t.Fatal(err)
	}
	return append(hdr, body...)
}

func TestSniffHostTLS(t *testing.T) {
	ch := clientHello(t, "rr3---sn-abc.googlevideo.com")
	if h, more := SniffHost(ch); h != "rr3---sn-abc.googlevideo.com" || more {
		t.Fatalf("got %q more=%v", h, more)
	}
	// A ClientHello split over several TCP reads asks for more bytes.
	for _, n := range []int{1, 4, 5, len(ch) / 2, len(ch) - 1} {
		if h, more := SniffHost(ch[:n]); h != "" || !more {
			t.Fatalf("prefix %d: got %q more=%v, want more", n, h, more)
		}
	}
	// No SNI (IP server name is not sent) -> no host, no more.
	if h, more := SniffHost(clientHello(t, "1.2.3.4")); h != "" || more {
		t.Fatalf("ip sni: got %q more=%v", h, more)
	}
}

func TestSniffHostHTTP(t *testing.T) {
	req := []byte("GET /x HTTP/1.1\r\nUser-Agent: a\r\nhost: Example.COM:8080\r\n\r\n")
	if h, more := SniffHost(req); h != "example.com" || more {
		t.Fatalf("got %q more=%v", h, more)
	}
	if h, more := SniffHost(req[:20]); h != "" || !more {
		t.Fatalf("partial head: got %q more=%v", h, more)
	}
	if h, more := SniffHost([]byte("GE")); h != "" || !more {
		t.Fatalf("partial method: got %q more=%v", h, more)
	}
	if h, more := SniffHost([]byte("SSH-2.0-OpenSSH\r\n")); h != "" || more {
		t.Fatalf("ssh: got %q more=%v", h, more)
	}
}

// TestSocks5SniffsDomainForIPTarget: a SOCKS5 client that sends a raw IP is
// routed by the domain in its TLS ClientHello; the target still receives the
// ClientHello unchanged, and the result reports the domain.
func TestSocks5SniffsDomainForIPTarget(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Destination: echoes what it receives.
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
			go func() {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(time.Second))
				_, _ = io.Copy(c, c)
			}()
		}
	}()

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
		BypassDomains:       []config.DomainRule{{Pattern: "bypass.example", Enabled: true}},
	}, logger)
	if err != nil {
		t.Fatal(err)
	}
	h := NewSocks5Handler(logger, re)

	run := func(sni string) *Socks5Result {
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
			res, _ := h.HandleConnection(context.Background(), bc, upstream, nil, "127.0.0.1", nil, false)
			done <- res
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		front := config.ProxyEntry{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, Type: "socks5"}
		c, err := dialThroughSOCKS5Proxy(ctx, front, target.Addr().String())
		if err != nil {
			t.Fatalf("dial through handler: %v", err)
		}
		ch := clientHello(t, sni)
		start := time.Now()
		// Send in two pieces, as a ClientHello split over two segments.
		_, _ = c.Write(ch[:7])
		time.Sleep(50 * time.Millisecond)
		_, _ = c.Write(ch[7:])
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		got := make([]byte, len(ch))
		if _, err := io.ReadFull(c, got); err != nil {
			t.Fatalf("echo: %v", err)
		}
		if !bytes.Equal(got, ch) {
			t.Fatal("target did not receive the ClientHello unchanged")
		}
		if time.Since(start) > sniffWait {
			t.Fatal("dial waited for the sniff timeout although the ClientHello was complete")
		}
		c.Close()
		select {
		case res := <-done:
			if res == nil {
				t.Fatal("handler returned no result")
			}
			return res
		case <-time.After(5 * time.Second):
			t.Fatal("handler did not finish")
		}
		return nil
	}

	if res := run("bypass.example"); res.DestHost != "bypass.example" || res.RouteType != "direct" || relayed.Load() != 0 {
		t.Fatalf("bypass domain: host=%q route=%q relayed=%d", res.DestHost, res.RouteType, relayed.Load())
	}
	if res := run("other.example"); res.DestHost != "other.example" || res.RouteType != "proxy" || relayed.Load() != 1 {
		t.Fatalf("other domain: host=%q route=%q relayed=%d", res.DestHost, res.RouteType, relayed.Load())
	} else if res.BytesSent == 0 || res.BytesRecv == 0 {
		t.Fatalf("byte counts not reported: sent=%d recv=%d", res.BytesSent, res.BytesRecv)
	}
}
