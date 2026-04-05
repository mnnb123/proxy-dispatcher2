// Package parser parses raw proxy list text into ProxyEntry structs.
package parser

import (
	"strconv"
	"strings"

	"proxy-dispatcher/internal/config"
)

// ParseError describes a single line that failed to parse.
type ParseError struct {
	Line    int    `json:"line"`
	RawText string `json:"raw_text"`
	Reason  string `json:"reason"`
}

// ParseProxyList parses multi-line raw text into ProxyEntry slice and
// returns any per-line parse errors encountered.
func ParseProxyList(rawText string, defaultType string) ([]config.ProxyEntry, []ParseError) {
	var entries []config.ProxyEntry
	var errs []ParseError

	lines := strings.Split(rawText, "\n")
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}

		proxyType := defaultType
		rest := line
		switch {
		case strings.HasPrefix(line, "http://"):
			proxyType = "http"
			rest = strings.TrimPrefix(line, "http://")
		case strings.HasPrefix(line, "socks5://"):
			proxyType = "socks5"
			rest = strings.TrimPrefix(line, "socks5://")
		}

		if proxyType != "http" && proxyType != "socks5" {
			errs = append(errs, ParseError{Line: i + 1, RawText: raw, Reason: "type không hợp lệ"})
			continue
		}

		parts := strings.Split(rest, ":")
		var host, user, pass string
		var port int
		var err error

		switch len(parts) {
		case 2:
			host = parts[0]
			port, err = strconv.Atoi(parts[1])
		case 4:
			host = parts[0]
			port, err = strconv.Atoi(parts[1])
			user = parts[2]
			pass = parts[3]
		default:
			errs = append(errs, ParseError{Line: i + 1, RawText: raw, Reason: "format không hợp lệ"})
			continue
		}

		if err != nil {
			errs = append(errs, ParseError{Line: i + 1, RawText: raw, Reason: "port không phải số"})
			continue
		}
		if port < 1 || port > 65535 {
			errs = append(errs, ParseError{Line: i + 1, RawText: raw, Reason: "port ngoài khoảng 1-65535"})
			continue
		}
		if host == "" {
			errs = append(errs, ParseError{Line: i + 1, RawText: raw, Reason: "host rỗng"})
			continue
		}

		entries = append(entries, config.ProxyEntry{
			Host:   host,
			Port:   port,
			User:   user,
			Pass:   pass,
			Type:   proxyType,
			Status: "unknown",
		})
	}
	return entries, errs
}
