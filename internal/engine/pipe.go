package engine

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// PipeResult summarizes the outcome of a bidirectional pipe session.
type PipeResult struct {
	BytesSent     int64
	BytesReceived int64
	Duration      time.Duration
	Error         error
}

// idleConn wraps a net.Conn and refreshes its deadline on each I/O
// operation to enforce an idle timeout.
type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c *idleConn) Read(p []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	return c.Conn.Read(p)
}

func (c *idleConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(c.idle))
	return c.Conn.Write(p)
}

// Pipe copies bytes bidirectionally between client and remote until one
// side closes, the idle timeout elapses, or ctx is cancelled.
func Pipe(ctx context.Context, client net.Conn, remote net.Conn, idleTimeout time.Duration) PipeResult {
	start := time.Now()
	var bytesSent, bytesRecv int64
	var firstErr atomic.Value

	ic := &idleConn{Conn: client, idle: idleTimeout}
	ir := &idleConn{Conn: remote, idle: idleTimeout}

	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = client.Close()
			_ = remote.Close()
		})
	}

	ctxDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			closeBoth()
		case <-ctxDone:
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		n, err := io.CopyBuffer(ir, ic, buf)
		atomic.AddInt64(&bytesSent, n)
		if err != nil && err != io.EOF {
			firstErr.CompareAndSwap(nil, err)
		}
		closeBoth()
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		n, err := io.CopyBuffer(ic, ir, buf)
		atomic.AddInt64(&bytesRecv, n)
		if err != nil && err != io.EOF {
			firstErr.CompareAndSwap(nil, err)
		}
		closeBoth()
	}()

	wg.Wait()
	close(ctxDone)

	var retErr error
	if v := firstErr.Load(); v != nil {
		retErr, _ = v.(error)
	}
	return PipeResult{
		BytesSent:     atomic.LoadInt64(&bytesSent),
		BytesReceived: atomic.LoadInt64(&bytesRecv),
		Duration:      time.Since(start),
		Error:         retErr,
	}
}
