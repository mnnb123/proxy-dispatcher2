// Package engine implements the TCP listeners, protocol detection and
// upstream proxy tunneling logic.
package engine

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ListenerManager manages a set of TCP listeners on a range of ports.
type ListenerManager struct {
	listeners      []net.Listener
	ports          []int
	handler        func(net.Conn)
	wg             sync.WaitGroup
	connCount      map[int]*atomic.Int32
	maxConnPerPort int
	logger         *slog.Logger
	mu             sync.RWMutex
}

// NewListenerManager constructs a ListenerManager.
func NewListenerManager(maxConnPerPort int, handler func(net.Conn), logger *slog.Logger) *ListenerManager {
	return &ListenerManager{
		handler:        handler,
		connCount:      make(map[int]*atomic.Int32),
		maxConnPerPort: maxConnPerPort,
		logger:         logger,
	}
}

// Start begins listening on the given port range. It returns an error only
// when no ports could be opened.
func (lm *ListenerManager) Start(startPort int, count int) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	for port := startPort; port < startPort+count; port++ {
		addr := fmt.Sprintf("0.0.0.0:%d", port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			lm.logger.Warn("cannot listen on port, skipping", "port", port, "error", err)
			continue
		}
		lm.listeners = append(lm.listeners, ln)
		lm.ports = append(lm.ports, port)
		lm.connCount[port] = &atomic.Int32{}
		go lm.acceptLoop(ln, port)
	}

	if len(lm.listeners) == 0 {
		return fmt.Errorf("no listeners could be started in range %d-%d", startPort, startPort+count-1)
	}
	lm.logger.Info("listeners started", "count", len(lm.listeners))
	return nil
}

func (lm *ListenerManager) acceptLoop(listener net.Listener, port int) {
	defer func() {
		if r := recover(); r != nil {
			lm.logger.Error("acceptLoop panic", "port", port, "recover", r)
		}
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			lm.logger.Info("listener closed", "port", port)
			return
		}

		if lm.connCount[port].Load() >= int32(lm.maxConnPerPort) {
			lm.logger.Warn("max connections reached, rejecting", "port", port)
			conn.Close()
			continue
		}
		lm.connCount[port].Add(1)
		lm.wg.Add(1)
		go lm.handleConn(conn, port)
	}
}

func (lm *ListenerManager) handleConn(conn net.Conn, port int) {
	defer func() {
		if r := recover(); r != nil {
			lm.logger.Error("handleConn panic", "port", port, "recover", r)
		}
	}()
	defer lm.wg.Done()
	defer lm.connCount[port].Add(-1)
	defer conn.Close()
	lm.handler(conn)
}

// Stop closes all listeners and waits for active connections to finish,
// with a 30-second grace period.
func (lm *ListenerManager) Stop() error {
	lm.mu.Lock()
	for _, ln := range lm.listeners {
		_ = ln.Close()
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

// Restart stops all current listeners and starts new ones on the given port range.
func (lm *ListenerManager) Restart(startPort int, count int) error {
	// Close existing listeners.
	lm.mu.Lock()
	for _, ln := range lm.listeners {
		_ = ln.Close()
	}
	lm.listeners = nil
	lm.ports = nil
	lm.connCount = make(map[int]*atomic.Int32)
	lm.mu.Unlock()

	if count <= 0 {
		return nil
	}
	return lm.Start(startPort, count)
}

// ActivePorts returns the list of ports currently being listened on.
func (lm *ListenerManager) ActivePorts() []int {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	out := make([]int, len(lm.ports))
	copy(out, lm.ports)
	return out
}
