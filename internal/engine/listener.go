// Package engine implements the TCP listeners, protocol detection and
// upstream proxy tunneling logic.
package engine

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// ListenerManager manages a set of TCP listeners keyed by port.
type ListenerManager struct {
	active         map[int]net.Listener
	handler        func(net.Conn)
	wg             sync.WaitGroup
	connCount      map[int]*atomic.Int32
	maxConnPerPort int
	logger         *slog.Logger
	mu             sync.RWMutex
	// pending holds wanted ports the last Reconcile could not open (usually
	// the port was momentarily taken as the source port of an outgoing
	// connection). RetryPending opens them later.
	pending map[int]bool
}

// NewListenerManager constructs a ListenerManager.
func NewListenerManager(maxConnPerPort int, handler func(net.Conn), logger *slog.Logger) *ListenerManager {
	return &ListenerManager{
		active:         make(map[int]net.Listener),
		handler:        handler,
		connCount:      make(map[int]*atomic.Int32),
		maxConnPerPort: maxConnPerPort,
		logger:         logger,
	}
}

// openLocked starts listening on port. Caller must hold lm.mu.
func (lm *ListenerManager) openLocked(port int) error {
	if _, ok := lm.active[port]; ok {
		return nil
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return err
	}
	lm.active[port] = ln
	counter, ok := lm.connCount[port]
	if !ok {
		counter = &atomic.Int32{}
		lm.connCount[port] = counter
	}
	go lm.acceptLoop(ln, port, counter)
	return nil
}

// Start begins listening on the given port range, in addition to whatever
// is already open. It returns an error only when no port of the range could
// be opened.
func (lm *ListenerManager) Start(startPort int, count int) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	opened := 0
	for port := startPort; port < startPort+count; port++ {
		if err := lm.openLocked(port); err != nil {
			lm.logger.Warn("cannot listen on port, skipping", "port", port, "error", err)
			continue
		}
		opened++
	}
	if opened == 0 {
		return fmt.Errorf("no listeners could be started in range %d-%d", startPort, startPort+count-1)
	}
	lm.logger.Info("listeners started", "range_start", startPort, "opened", opened, "total", len(lm.active))
	return nil
}

// Reconcile makes the set of listening ports equal to want: ports no longer
// wanted are closed, missing ones are opened, and ports present in both are
// left completely untouched (their in-flight and future connections are not
// disturbed). It returns the ports that could not be opened.
//
// This replaces the old "Restart(range)" pattern, which closed every
// listener and then opened a single range — with several port mappings only
// the last one survived a reload.
func (lm *ListenerManager) Reconcile(want []int) (failed []int) {
	wantSet := make(map[int]bool, len(want))
	for _, p := range want {
		if p > 0 && p <= 65535 {
			wantSet[p] = true
		}
	}

	lm.mu.Lock()
	defer lm.mu.Unlock()

	closed := 0
	for port, ln := range lm.active {
		if !wantSet[port] {
			_ = ln.Close()
			delete(lm.active, port)
			closed++
		}
	}
	opened := 0
	for port := range wantSet {
		if _, ok := lm.active[port]; ok {
			continue
		}
		if err := lm.openLocked(port); err != nil {
			lm.logger.Warn("cannot listen on port, skipping", "port", port, "error", err)
			failed = append(failed, port)
			continue
		}
		opened++
	}
	sort.Ints(failed)
	lm.pending = make(map[int]bool, len(failed))
	for _, p := range failed {
		lm.pending[p] = true
	}
	if opened > 0 || closed > 0 || len(failed) > 0 {
		lm.logger.Info("listeners reconciled", "opened", opened, "closed", closed, "failed", len(failed), "total", len(lm.active))
	}
	return failed
}

// RetryPending tries again to open the ports the last Reconcile could not
// open and returns how many are now listening.
func (lm *ListenerManager) RetryPending() (opened int) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	for port := range lm.pending {
		if err := lm.openLocked(port); err != nil {
			continue
		}
		delete(lm.pending, port)
		opened++
		lm.logger.Info("listener opened on retry", "port", port)
	}
	return opened
}

func (lm *ListenerManager) acceptLoop(listener net.Listener, port int, counter *atomic.Int32) {
	defer func() {
		if r := recover(); r != nil {
			lm.logger.Error("acceptLoop panic", "port", port, "recover", r)
		}
	}()

	var delay time.Duration
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				lm.logger.Debug("listener closed", "port", port)
				return
			}
			// Transient failure (e.g. EMFILE "too many open files"): back off
			// and keep accepting instead of silently abandoning the port.
			if delay == 0 {
				delay = 5 * time.Millisecond
			} else if delay *= 2; delay > time.Second {
				delay = time.Second
			}
			lm.logger.Warn("accept error, retrying", "port", port, "error", err, "backoff", delay)
			time.Sleep(delay)
			continue
		}
		delay = 0

		if counter.Load() >= int32(lm.maxConnPerPort) {
			lm.logger.Warn("max connections reached, rejecting", "port", port)
			conn.Close()
			continue
		}
		// Register the connection under the lock, and only while this
		// listener is still the active one: Stop closes the listeners under
		// the write lock and then waits on wg, so an Add here must not be
		// able to run concurrently with that Wait.
		lm.mu.RLock()
		if lm.active[port] != listener {
			lm.mu.RUnlock()
			conn.Close()
			continue
		}
		counter.Add(1)
		lm.wg.Add(1)
		lm.mu.RUnlock()
		go lm.handleConn(conn, port, counter)
	}
}

func (lm *ListenerManager) handleConn(conn net.Conn, port int, counter *atomic.Int32) {
	defer func() {
		if r := recover(); r != nil {
			lm.logger.Error("handleConn panic", "port", port, "recover", r)
		}
	}()
	defer lm.wg.Done()
	defer counter.Add(-1)
	defer conn.Close()
	lm.handler(conn)
}

// Stop closes all listeners and waits for active connections to finish,
// with a 30-second grace period.
func (lm *ListenerManager) Stop() error {
	lm.mu.Lock()
	for port, ln := range lm.active {
		_ = ln.Close()
		delete(lm.active, port)
	}
	lm.mu.Unlock()

	done := make(chan struct{})
	go func() {
		lm.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		lm.logger.Warn("stop timeout reached, some connections may still be active")
	}
	lm.logger.Info("all listeners stopped")
	return nil
}

// Restart makes [startPort, startPort+count) the only listening range.
// Kept for callers with a single range; prefer Reconcile.
func (lm *ListenerManager) Restart(startPort int, count int) error {
	want := make([]int, 0, count)
	for p := startPort; p < startPort+count; p++ {
		want = append(want, p)
	}
	failed := lm.Reconcile(want)
	if count > 0 && len(failed) == count {
		return fmt.Errorf("no listeners could be started in range %d-%d", startPort, startPort+count-1)
	}
	return nil
}

// ActivePorts returns the sorted list of ports currently being listened on.
func (lm *ListenerManager) ActivePorts() []int {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	out := make([]int, 0, len(lm.active))
	for p := range lm.active {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}
