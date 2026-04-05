package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// GenerateSecret returns a random 20-byte base32 TOTP secret.
func GenerateSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// GenerateQRURL builds an otpauth URL for authenticator apps.
func GenerateQRURL(secret, username, issuer string) string {
	label := url.PathEscape(issuer + ":" + username)
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", "30")
	return "otpauth://totp/" + label + "?" + v.Encode()
}

func hotp(key []byte, counter uint64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	code %= 1000000
	return fmt.Sprintf("%06d", code)
}

// ValidateTOTP checks 3 time windows (±30s) using constant-time compare.
func ValidateTOTP(secret string, code string) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return false
	}
	step := time.Now().Unix() / 30
	for offset := int64(-1); offset <= 1; offset++ {
		candidate := hotp(key, uint64(step+offset))
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// GenerateRecoveryCodes creates 8 plaintext codes and their bcrypt hashes.
func GenerateRecoveryCodes() ([]string, []string, error) {
	codes := make([]string, 8)
	hashes := make([]string, 8)
	for i := 0; i < 8; i++ {
		b := make([]byte, 4)
		if _, err := rand.Read(b); err != nil {
			return nil, nil, err
		}
		codes[i] = hex.EncodeToString(b)
		h, err := bcrypt.GenerateFromPassword([]byte(codes[i]), 10)
		if err != nil {
			return nil, nil, err
		}
		hashes[i] = string(h)
	}
	return codes, hashes, nil
}

// ValidateRecoveryCode checks input against hashes; if a match is found,
// returns the remaining hashes (with the used one removed).
func ValidateRecoveryCode(input string, hashes []string) (bool, []string) {
	input = strings.TrimSpace(strings.ToLower(input))
	for i, h := range hashes {
		if bcrypt.CompareHashAndPassword([]byte(h), []byte(input)) == nil {
			remaining := make([]string, 0, len(hashes)-1)
			remaining = append(remaining, hashes[:i]...)
			remaining = append(remaining, hashes[i+1:]...)
			return true, remaining
		}
	}
	return false, hashes
}

func xorBytes(data, key []byte) []byte {
	out := make([]byte, len(data))
	if len(key) == 0 {
		copy(out, data)
		return out
	}
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return out
}

// EncryptTOTPSecret XOR-encrypts the secret using the provided key.
func EncryptTOTPSecret(secret string, key string) string {
	return hex.EncodeToString(xorBytes([]byte(secret), []byte(key)))
}

// DecryptTOTPSecret reverses EncryptTOTPSecret.
func DecryptTOTPSecret(encrypted string, key string) string {
	b, err := hex.DecodeString(encrypted)
	if err != nil {
		return ""
	}
	return string(xorBytes(b, []byte(key)))
}
