package engine

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"proxy-dispatcher/internal/config"
)

// proxyDialTimeout is the max time to wait when connecting to an upstream proxy.
const proxyDialTimeout = 15 * time.Second

// dialThroughHTTPProxy opens a CONNECT tunnel to targetAddr through an
// HTTP proxy. If CONNECT fails (e.g. Squid denying port 80), it falls
// back to a direct TCP connection to the target.
func dialThroughHTTPProxy(ctx context.Context, proxy config.ProxyEntry, targetAddr string) (net.Conn, error) {
	d := net.Dialer{Timeout: proxyDialTimeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(proxy.Host, strconv.Itoa(proxy.Port)))
	if err != nil {
		return nil, fmt.Errorf("dial http proxy: %w", err)
	}
	conn.SetDeadline(time.Now().Add(proxyDialTimeout))
	defer conn.SetDeadline(time.Time{})

	req := "CONNECT " + targetAddr + " HTTP/1.1\r\nHost: " + targetAddr + "\r\n"
	if proxy.User != "" {
		req += "Proxy-Authorization: " + ProxyBasicAuth(proxy.User, proxy.Pass) + "\r\n"
	}
	req += "\r\n"

	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write connect: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read connect response: %w", err)
	}
	resp := string(buf[:n])
	if len(resp) < 12 || resp[9:12] != "200" {
		conn.Close()
		// CONNECT denied (e.g. Squid blocks non-SSL ports). Fall back to direct.
		return d.DialContext(ctx, "tcp", targetAddr)
	}
	return conn, nil
}

// dialThroughSOCKS5Proxy performs a SOCKS5 handshake with proxy and
// returns a connection tunneled to targetAddr.
func dialThroughSOCKS5Proxy(ctx context.Context, proxy config.ProxyEntry, targetAddr string) (net.Conn, error) {
	d := net.Dialer{Timeout: proxyDialTimeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(proxy.Host, strconv.Itoa(proxy.Port)))
	if err != nil {
		return nil, fmt.Errorf("dial socks5 proxy: %w", err)
	}
	conn.SetDeadline(time.Now().Add(proxyDialTimeout))
	defer conn.SetDeadline(time.Time{})

	if err := socks5Greet(conn, proxy); err != nil {
		conn.Close()
		return nil, err
	}

	if err := socks5Connect(conn, targetAddr); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

// socks5Greet performs SOCKS5 greeting and authentication with the upstream.
func socks5Greet(conn net.Conn, proxy config.ProxyEntry) error {
	var greet []byte
	if proxy.User != "" {
		greet = []byte{0x05, 0x02, 0x00, 0x02}
	} else {
		greet = []byte{0x05, 0x01, 0x00}
	}
	if _, err := conn.Write(greet); err != nil {
		return err
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != 0x05 {
		return fmt.Errorf("bad socks version: %d", resp[0])
	}

	switch resp[1] {
	case 0x00:
		return nil
	case 0x02:
		return socks5Auth(conn, proxy.User, proxy.Pass)
	default:
		return fmt.Errorf("unsupported socks5 auth method: %d", resp[1])
	}
}

// socks5Auth performs SOCKS5 username/password authentication.
func socks5Auth(conn net.Conn, user, pass string) error {
	authReq := []byte{0x01}
	authReq = append(authReq, byte(len(user)))
	authReq = append(authReq, []byte(user)...)
	authReq = append(authReq, byte(len(pass)))
	authReq = append(authReq, []byte(pass)...)
	if _, err := conn.Write(authReq); err != nil {
		return err
	}
	authResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResp); err != nil {
		return err
	}
	if authResp[1] != 0x00 {
		return fmt.Errorf("socks5 auth failed")
	}
	return nil
}

// socks5Connect sends a CONNECT request and reads the reply.
func socks5Connect(conn net.Conn, targetAddr string) error {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return fmt.Errorf("parse target addr: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("parse port: %w", err)
	}

	req := []byte{0x05, 0x01, 0x00}
	req = append(req, buildSOCKS5Addr(host, port)...)

	if _, err := conn.Write(req); err != nil {
		return err
	}

	return readSOCKS5Reply(conn)
}

// buildSOCKS5Addr encodes the destination address for a SOCKS5 request.
func buildSOCKS5Addr(host string, port int) []byte {
	var addr []byte
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			addr = append(addr, 0x01)
			addr = append(addr, ip4...)
		} else {
			addr = append(addr, 0x04)
			addr = append(addr, ip.To16()...)
		}
	} else {
		addr = append(addr, 0x03, byte(len(host)))
		addr = append(addr, []byte(host)...)
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	addr = append(addr, portBytes...)
	return addr
}

// readSOCKS5Reply reads and validates the SOCKS5 CONNECT reply.
func readSOCKS5Reply(conn net.Conn) error {
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[1] != 0x00 {
		return fmt.Errorf("socks5 connect failed: code=%d", head[1])
	}

	// Skip the bound address in reply.
	switch head[3] {
	case 0x01:
		_, err := io.ReadFull(conn, make([]byte, 4+2))
		return err
	case 0x04:
		_, err := io.ReadFull(conn, make([]byte, 16+2))
		return err
	case 0x03:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(conn, lb); err != nil {
			return err
		}
		_, err := io.ReadFull(conn, make([]byte, int(lb[0])+2))
		return err
	default:
		return fmt.Errorf("unknown ATYP in reply: %d", head[3])
	}
}
