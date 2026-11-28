package shopsocks5

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// TOTP returns the 6-digit code an authenticator app shows at time t for a
// base32 secret (RFC 6238: HMAC-SHA1, 30-second steps).
func TOTP(secret string, t time.Time) (string, error) {
	s := strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(strings.TrimSpace(secret)))
	s = strings.TrimRight(s, "=")
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil || len(key) == 0 {
		return "", fmt.Errorf("shopsocks5 web: the 2FA key is not a valid base32 secret")
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(t.Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1000000), nil
}
