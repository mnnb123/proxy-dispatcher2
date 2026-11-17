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

	// firstErr keeps the first non-EOF error from either direction. A plain
	// mutex is used instead of atomic.Value: the two copy goroutines can fail
	// with different concrete error types (*net.OpError vs errors.errorString),
	// and atomic.Value.CompareAndSwap panics on inconsistently typed values.
	var errMu sync.Mutex
	var firstErr error
	setErr := func(err error) {
		if err == nil || err == io.EOF {
			return
		}
		errMu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		errMu.Unlock()
	}

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
		setErr(err)
		closeBoth()
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		n, err := io.CopyBuffer(ic, ir, buf)
		atomic.AddInt64(&bytesRecv, n)
		setErr(err)
		closeBoth()
	}()

	wg.Wait()
	close(ctxDone)

	errMu.Lock()
	retErr := firstErr
	errMu.Unlock()
	return PipeResult{
		BytesSent:     atomic.LoadInt64(&bytesSent),
		BytesReceived: atomic.LoadInt64(&bytesRecv),
		Duration:      time.Since(start),
		Error:         retErr,
	}
}
