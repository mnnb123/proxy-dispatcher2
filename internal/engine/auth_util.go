package engine

import (
	"bytes"
	"encoding/base64"
)

// proxyBasicAuth returns a "Basic base64(user:pass)" header value.
func proxyBasicAuth(user, pass string) string {
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
	header := []byte("Proxy-Authorization: " + proxyBasicAuth(user, pass) + "\r\n")
	out := make([]byte, 0, len(raw)+len(header))
	out = append(out, raw[:idx+2]...) // up to and including the \r\n before blank line
	out = append(out, header...)
	out = append(out, raw[idx+2:]...)  // the remaining \r\n (blank line + body if any)
	return out
}
