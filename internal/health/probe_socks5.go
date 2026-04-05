package health

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"proxy-dispatcher/internal/config"
)

func probeSOCKS5(proxy *config.ProxyEntry, testURL string, timeout time.Duration) CheckResult {
	start := time.Now()
	res := CheckResult{Proxy: proxy}
	addr := fmt.Sprintf("%s:%d", proxy.Host, proxy.Port)

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		res.Error = "dial: " + err.Error()
		res.LatencyMs = time.Since(start).Milliseconds()
		return res
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	host := "httpbin.org"
	port := "80"
	path := "/ip"
	if testURL != "" {
		h, p, pa := parseTestURL(testURL)
		if h != "" {
			host = h
			port = p
			path = pa
		}
	}

	// Greeting.
	var greet []byte
	if proxy.User != "" {
		greet = []byte{0x05, 0x02, 0x00, 0x02}
	} else {
		greet = []byte{0x05, 0x01, 0x00}
	}
	if _, err := conn.Write(greet); err != nil {
		res.Error = "write greet: " + err.Error()
		res.LatencyMs = time.Since(start).Milliseconds()
		return res
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		res.Error = "read greet: " + err.Error()
		res.LatencyMs = time.Since(start).Milliseconds()
		return res
	}
	if reply[0] != 0x05 {
		res.Error = "bad socks version"
		res.LatencyMs = time.Since(start).Milliseconds()
		return res
	}
	if reply[1] == 0x02 {
		// Auth.
		authMsg := []byte{0x01, byte(len(proxy.User))}
		authMsg = append(authMsg, []byte(proxy.User)...)
		authMsg = append(authMsg, byte(len(proxy.Pass)))
		authMsg = append(authMsg, []byte(proxy.Pass)...)
		if _, err := conn.Write(authMsg); err != nil {
			res.Error = "write auth: " + err.Error()
			res.LatencyMs = time.Since(start).Milliseconds()
			return res
		}
		aResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, aResp); err != nil {
			res.Error = "read auth: " + err.Error()
			res.LatencyMs = time.Since(start).Milliseconds()
			return res
		}
		if aResp[1] != 0x00 {
			res.Error = "auth failed"
			res.LatencyMs = time.Since(start).Milliseconds()
			return res
		}
	} else if reply[1] != 0x00 {
		res.Error = "no acceptable auth"
		res.LatencyMs = time.Since(start).Milliseconds()
		return res
	}

	// CONNECT command.
	portNum, _ := strconv.Atoi(port)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(portNum>>8), byte(portNum&0xff))
	if _, err := conn.Write(req); err != nil {
		res.Error = "write connect: " + err.Error()
		res.LatencyMs = time.Since(start).Milliseconds()
		return res
	}
	cResp := make([]byte, 4)
	if _, err := io.ReadFull(conn, cResp); err != nil {
		res.Error = "read connect: " + err.Error()
		res.LatencyMs = time.Since(start).Milliseconds()
		return res
	}
	if cResp[1] != 0x00 {
		res.Error = "connect rejected"
		res.LatencyMs = time.Since(start).Milliseconds()
		return res
	}
	// Skip bound addr.
	switch cResp[3] {
	case 0x01:
		io.ReadFull(conn, make([]byte, 4+2))
	case 0x03:
		lenByte := make([]byte, 1)
		io.ReadFull(conn, lenByte)
		io.ReadFull(conn, make([]byte, int(lenByte[0])+2))
	case 0x04:
		io.ReadFull(conn, make([]byte, 16+2))
	}

	// HTTP GET.
	get := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(get)); err != nil {
		res.Error = "write get: " + err.Error()
		res.LatencyMs = time.Since(start).Milliseconds()
		return res
	}
	rdr := bufio.NewReader(conn)
	body, err := io.ReadAll(io.LimitReader(rdr, 16384))
	if err != nil && err != io.EOF {
		res.Error = "read body: " + err.Error()
		res.LatencyMs = time.Since(start).Milliseconds()
		return res
	}
	res.LatencyMs = time.Since(start).Milliseconds()

	raw := string(body)
	if idx := strings.Index(raw, "{"); idx >= 0 {
		var obj map[string]interface{}
		if json.Unmarshal([]byte(raw[idx:]), &obj) == nil {
			if v, ok := obj["origin"].(string); ok {
				res.ExternalIP = strings.TrimSpace(strings.Split(v, ",")[0])
			}
		}
	}
	return res
}
