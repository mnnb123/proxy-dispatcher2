package rules

import (
	"net"

	"proxy-dispatcher/internal/config"
)

// ExecuteBlockAction sends an appropriate rejection to conn and closes it.
func ExecuteBlockAction(conn net.Conn, block BlockInfo, proto string) error {
	switch block.Action {
	case "403":
		if proto == "http" {
			_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		} else if proto == "socks5" {
			_, _ = conn.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		}
		return conn.Close()
	case "reset":
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
			return tc.Close()
		}
		return conn.Close()
	case "drop":
		return conn.Close()
	default:
		return conn.Close()
	}
}

// ResolveBypassTarget determines the upstream proxy for a bypass action.
// Returns nil for direct connect, resourceProxy for "resource", and nil
// for "proxy" (caller should use rotator).
func ResolveBypassTarget(actionType string, resourceProxy *config.ProxyEntry) *config.ProxyEntry {
	switch actionType {
	case "direct":
		return nil
	case "resource":
		if resourceProxy != nil {
			return resourceProxy
		}
		return nil
	default:
		return nil
	}
}
