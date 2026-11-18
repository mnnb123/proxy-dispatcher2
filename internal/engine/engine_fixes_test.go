package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"proxy-dispatcher/internal/config"
)

// errConn is a net.Conn whose Read fails with a caller-chosen error after
// returning its payload; used to make Pipe see two different error types.
type errConn struct {
	net.Conn
	payload []byte
	err     error
	done    bool
}

func (c *errConn) Read(p []byte) (int, error) {
	if !c.done {
		c.done = true
		n := copy(p, c.payload)
		return n, nil
	}
	return 0, c.err
}

func (c *errConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *errConn) Close() error                     { return nil }
func (c *errConn) SetDeadline(time.Time) error      { return nil }
func (c *errConn) SetReadDeadline(time.Time) error  { return nil }
func (c *errConn) SetWriteDeadline(time.Time) error { return nil }

// TestExtractHTTPTargetKeepsBody: a POST whose body arrives in the same
// segment as the headers must not lose the body to a discarded read-ahead
// buffer. Everything after the header terminator has to still be readable
// from buffConn.
func TestExtractHTTPTargetKeepsBody(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	req := "POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 11\r\n\r\nhello world"
	go func() {
		_, _ = client.Write([]byte(req))
	}()

	proto, buffConn, err := DetectProtocol(server)
	if err != nil || proto != "http" {
		t.Fatalf("detect: proto=%q err=%v", proto, err)
	}
	info, err := ExtractHTTPTarget(buffConn)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if info.Host != "example.com" || info.Port != "80" || info.Method != "POST" {
		t.Fatalf("unexpected info: %+v", info)
	}
	wantHead := req[:strings.Index(req, "\r\n\r\n")+4]
	if string(info.ConsumedBytes) != wantHead {
		t.Fatalf("consumed bytes mismatch:\n got %q\nwant %q", info.ConsumedBytes, wantHead)
	}

	// The body must still be readable from buffConn (not swallowed).
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	body := make([]byte, 11)
	if _, err := io.ReadFull(buffConn, body); err != nil {
		t.Fatalf("body read: %v", err)
	}
	if string(body) != "hello world" {
		t.Fatalf("body = %q, want %q", body, "hello world")
	}
}

// TestExtractHTTPTargetConnect checks CONNECT parsing and that the header
// block is fully consumed.
func TestExtractHTTPTargetConnect(t *testing.T) {
	raw := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Connection: keep-alive\r\n\r\n"
	buffConn := WrapPrefixAsBuffered(NewPrefixConn([]byte(raw), &errConn{err: io.EOF}))
	info, err := ExtractHTTPTarget(buffConn)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if !info.IsHTTPS || info.Target != "example.com:443" {
		t.Fatalf("unexpected info: %+v", info)
	}
	if string(info.ConsumedBytes) != raw {
		t.Fatalf("consumed = %q", info.ConsumedBytes)
	}
}

// TestPipeMixedErrorTypes: both directions failing with different concrete
// error types used to panic in atomic.Value.CompareAndSwap.
func TestPipeMixedErrorTypes(t *testing.T) {
	a := &errConn{payload: []byte("x"), err: &net.OpError{Op: "read", Err: errors.New("boom")}}
	b := &errConn{payload: []byte("y"), err: errors.New("plain error")}

	done := make(chan PipeResult, 1)
	go func() {
		done <- Pipe(context.Background(), a, b, time.Second)
	}()
	select {
	case res := <-done:
		if res.BytesSent != 1 || res.BytesReceived != 1 {
			t.Fatalf("bytes sent/recv = %d/%d, want 1/1", res.BytesSent, res.BytesReceived)
		}
		if res.Error == nil {
			t.Fatalf("expected an error to be reported")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Pipe did not finish")
	}
}

// TestGroupProxiesShareRotatorPointers: health checks must write into the
// same *ProxyEntry objects the rotators read, otherwise status changes are
// invisible to routing.
func TestGroupProxiesShareRotatorPointers(t *testing.T) {
	groups := []config.ProxyGroup{{
		Name:         "g1",
		RotationMode: "roundrobin",
		Proxies: []config.ProxyEntry{
			{Host: "10.0.0.1", Port: 1080, Type: "socks5"},
			{Host: "10.0.0.2", Port: 1080, Type: "socks5"},
		},
	}}
	gm, err := NewGroupManager(groups, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ptrs := gm.GroupProxies()["g1"]
	if len(ptrs) != 2 {
		t.Fatalf("got %d proxies", len(ptrs))
	}
	// Simulate the health checker marking the first proxy dead.
	ptrs[0].Status = "dead"

	var rot Rotator
	for _, mg := range gm.AllGroups() {
		rot = mg.Rotator
	}
	for i := 0; i < 4; i++ {
		p, err := rot.Next("")
		if err != nil {
			t.Fatal(err)
		}
		if p.Host == "10.0.0.1" {
			t.Fatalf("rotator returned the proxy marked dead via GroupProxies pointer")
		}
	}
}

// TestInjectProxyAuthKeepsBody guards the header-injection helper used on
// the plain-HTTP proxy path.
func TestInjectProxyAuthKeepsBody(t *testing.T) {
	raw := []byte("GET http://e.com/ HTTP/1.1\r\nHost: e.com\r\n\r\nBODY")
	out := InjectProxyAuth(raw, "u", "p")
	if !bytes.HasSuffix(out, []byte("\r\n\r\nBODY")) {
		t.Fatalf("body not preserved: %q", out)
	}
	if !bytes.Contains(out, []byte("Proxy-Authorization: Basic dTpw\r\n")) {
		t.Fatalf("auth header missing: %q", out)
	}
}

// TestReconcileKeepsUntouchedPorts: reconciling to a new port set must open
// the new ports, close the removed ones and leave shared ports listening.
// (The old per-mapping Restart closed everything but the last range.)
func TestReconcileKeepsUntouchedPorts(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	lm := NewListenerManager(10, func(c net.Conn) {}, logger)
	defer lm.Stop()

	// Grab three free ports.
	var ports []int
	for i := 0; i < 3; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ports = append(ports, ln.Addr().(*net.TCPAddr).Port)
		ln.Close()
	}
	a, b, c := ports[0], ports[1], ports[2]

	if failed := lm.Reconcile([]int{a, b}); len(failed) != 0 {
		t.Fatalf("failed to open: %v", failed)
	}
	if failed := lm.Reconcile([]int{b, c}); len(failed) != 0 {
		t.Fatalf("failed to open: %v", failed)
	}
	got := lm.ActivePorts()
	want := map[int]bool{b: true, c: true}
	if len(got) != 2 || !want[got[0]] || !want[got[1]] {
		t.Fatalf("active ports = %v, want %d and %d", got, b, c)
	}
	if conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(b)), time.Second); err != nil {
		t.Fatalf("kept port %d not accepting: %v", b, err)
	} else {
		conn.Close()
	}
}

// TestUpdateGroupProxiesRebindsPorts: proxies appended at runtime (URL
// import) must receive the next free ports of the group's range.
func TestUpdateGroupProxiesRebindsPorts(t *testing.T) {
	groups := []config.ProxyGroup{{
		Name: "US", RotationMode: "roundrobin",
		Proxies: []config.ProxyEntry{{Host: "10.0.0.1", Port: 80, Type: "http"}},
	}}
	maps := []config.PortMapping{{PortStart: 30000, PortEnd: 30002, GroupName: "US"}}
	gm, err := NewGroupManager(groups, maps, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := gm.GetProxyForPort(30001); ok {
		t.Fatal("port 30001 should be unbound before the import")
	}
	cur := gm.GroupProxies()["US"]
	cur = append(cur, &config.ProxyEntry{Host: "10.0.0.2", Port: 80, Type: "http"})
	if err := gm.UpdateGroupProxies("US", cur); err != nil {
		t.Fatal(err)
	}
	p, ok := gm.GetProxyForPort(30001)
	if !ok || p.Host != "10.0.0.2" {
		t.Fatalf("port 30001 → %+v (ok=%v), want 10.0.0.2", p, ok)
	}
	if p0, _ := gm.GetProxyForPort(30000); p0 == nil || p0.Host != "10.0.0.1" {
		t.Fatalf("port 30000 binding changed: %+v", p0)
	}
}

func TestExtractStripsProxyAuthorization(t *testing.T) {
	for _, req := range []string{
		"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nproxy-authorization: Basic dTpw\r\n\r\n",
		"POST http://example.com/x HTTP/1.1\r\nProxy-Authorization: Basic dTpw\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nBODY",
	} {
		client, server := net.Pipe()
		go func() { _, _ = client.Write([]byte(req)) }()
		_, bc, err := DetectProtocol(server)
		if err != nil {
			t.Fatal(err)
		}
		info, err := ExtractHTTPTarget(bc)
		if err != nil {
			t.Fatal(err)
		}
		if info.ProxyAuth != "Basic dTpw" {
			t.Fatalf("ProxyAuth = %q", info.ProxyAuth)
		}
		if strings.Contains(strings.ToLower(string(info.ConsumedBytes)), "proxy-authorization") {
			t.Fatalf("header not stripped: %q", info.ConsumedBytes)
		}
		if !strings.HasSuffix(string(info.ConsumedBytes), "\r\n\r\n") || !strings.Contains(string(info.ConsumedBytes), "Host: example.com") {
			t.Fatalf("head damaged: %q", info.ConsumedBytes)
		}
		u, p, ok := ParseProxyBasicAuth(info.ProxyAuth)
		if !ok || u != "u" || p != "p" {
			t.Fatalf("parse = %q %q %v", u, p, ok)
		}
		client.Close()
		server.Close()
	}
	if _, _, ok := ParseProxyBasicAuth("Bearer x"); ok {
		t.Fatal("non-basic accepted")
	}
}
