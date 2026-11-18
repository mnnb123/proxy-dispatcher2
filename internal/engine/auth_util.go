package engine

import (
	"bytes"
	"encoding/base64"
	"strings"
)

// ParseProxyBasicAuth decodes a "Basic base64(user:pass)" header value.
func ParseProxyBasicAuth(value string) (user, pass string, ok bool) {
	value = strings.TrimSpace(value)
	if len(value) < 6 || !strings.EqualFold(value[:6], "basic ") {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value[6:]))
	if err != nil {
		return "", "", false
	}
	user, pass, ok = strings.Cut(string(raw), ":")
	return user, pass, ok
}

// stripHeader removes every "name:" header line from a raw header block and
// returns the block without them plus the value of the first one found.
func stripHeader(hdrs []byte, name string) ([]byte, string) {
	prefix := strings.ToLower(name) + ":"
	var out bytes.Buffer
	value, found := "", false
	for len(hdrs) > 0 {
		line := hdrs
		if i := bytes.IndexByte(hdrs, '\n'); i >= 0 {
			line = hdrs[:i+1]
		}
		hdrs = hdrs[len(line):]
		if len(line) > len(prefix) && strings.EqualFold(string(line[:len(prefix)]), prefix) {
			if !found {
				value = strings.TrimSpace(string(line[len(prefix):]))
				found = true
			}
			continue
		}
		out.Write(line)
	}
	if !found {
		return out.Bytes(), ""
	}
	return out.Bytes(), value
}

// ProxyBasicAuth returns a "Basic base64(user:pass)" header value.
func ProxyBasicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// InjectProxyAuth inserts a Proxy-Authorization header into raw HTTP request
// bytes just before the final \r\n\r\n separator. If the separator is not
// found the original bytes are returned unchanged.
func InjectProxyAuth(raw []byte, user, pass string) []byte {
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(raw, sep)
	if idx < 0 {
		return raw
	}
	header := []byte("Proxy-Authorization: " + ProxyBasicAuth(user, pass) + "\r\n")
	out := make([]byte, 0, len(raw)+len(header))
	out = append(out, raw[:idx+2]...) // up to and including the \r\n before blank line
	out = append(out, header...)
	out = append(out, raw[idx+2:]...) // the remaining \r\n (blank line + body if any)
	return out
}
