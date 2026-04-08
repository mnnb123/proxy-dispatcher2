package health

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"proxy-dispatcher/internal/config"
)

func probeHTTP(proxy *config.ProxyEntry, testURL string, timeout time.Duration) CheckResult {
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

	// Use plain HTTP GET through the proxy (most reliable method).
	host := "httpbin.org"
	path := "/ip"
	if testURL != "" {
		h, _, pa := parseTestURL(testURL)
		if h != "" {
			host = h
			path = pa
		}
	}

	// Plain HTTP GET via proxy (no CONNECT needed).
	var b strings.Builder
	b.WriteString("GET http://" + host + path + " HTTP/1.1\r\n")
	b.WriteString("Host: " + host + "\r\n")
	if proxy.User != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(proxy.User + ":" + proxy.Pass))
		b.WriteString("Proxy-Authorization: Basic " + auth + "\r\n")
	}
	b.WriteString("Connection: close\r\n\r\n")
	if _, err := conn.Write([]byte(b.String())); err != nil {
		res.Error = "write: " + err.Error()
		res.LatencyMs = time.Since(start).Milliseconds()
		return res
	}

	rdr := bufio.NewReader(conn)
	statusLine, err := rdr.ReadString('\n')
	if err != nil {
		res.Error = "read status: " + err.Error()
		res.LatencyMs = time.Since(start).Milliseconds()
		return res
	}
	if !strings.Contains(statusLine, "200") {
		res.Error = "http failed: " + strings.TrimSpace(statusLine)
		res.LatencyMs = time.Since(start).Milliseconds()
		return res
	}

	body, err := io.ReadAll(io.LimitReader(rdr, 16384))
	if err != nil && err != io.EOF {
		res.Error = "read body: " + err.Error()
		res.LatencyMs = time.Since(start).Milliseconds()
		return res
	}
	res.LatencyMs = time.Since(start).Milliseconds()

	// Parse body: find JSON with "origin" field.
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

func parseTestURL(u string) (host, port, path string) {
	port = "80"
	path = "/"
	s := strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if i := strings.Index(s, "/"); i >= 0 {
		path = s[i:]
		s = s[:i]
	}
	if i := strings.Index(s, ":"); i >= 0 {
		host = s[:i]
		port = s[i+1:]
	} else {
		host = s
	}
	return
}
