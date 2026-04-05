package engine

import "encoding/base64"

// proxyBasicAuth returns a "Basic base64(user:pass)" header value.
func proxyBasicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}
