package syncmgr

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"proxy-dispatcher/internal/config"
)

// ErrInvalidSignature is returned when HMAC verification fails.
var ErrInvalidSignature = errors.New("invalid signature")

// SyncSlave applies config payloads pushed by a master.
type SyncSlave struct {
	cfg           config.SyncConfig
	onReceive     func(*config.AppConfig) error
	lastReceive   int64
	lastChecksum  string
	logger        *slog.Logger
	mu            sync.Mutex
}

// NewSyncSlave constructs a slave receiver.
func NewSyncSlave(cfg config.SyncConfig, onReceive func(*config.AppConfig) error, logger *slog.Logger) *SyncSlave {
	return &SyncSlave{cfg: cfg, onReceive: onReceive, logger: logger}
}

// HandleReceive verifies HMAC then applies the payload.
func (ss *SyncSlave) HandleReceive(body []byte, signature string) error {
	mac := hmac.New(sha256.New, []byte(ss.cfg.SharedSecret))
	mac.Write(body)
	expected := mac.Sum(nil)
	got, err := hex.DecodeString(signature)
	if err != nil {
		return ErrInvalidSignature
	}
	if !hmac.Equal(expected, got) {
		return ErrInvalidSignature
	}
	var payload SyncPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return err
	}
	// Verify checksum.
	raw, _ := json.Marshal(payload.Config)
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != payload.Checksum {
		return errors.New("checksum mismatch")
	}
	ss.mu.Lock()
	if ss.lastChecksum == payload.Checksum {
		ss.mu.Unlock()
		return nil
	}
	ss.mu.Unlock()
	if ss.onReceive != nil {
		if err := ss.onReceive(payload.Config); err != nil {
			return err
		}
	}
	ss.mu.Lock()
	ss.lastReceive = time.Now().Unix()
	ss.lastChecksum = payload.Checksum
	ss.mu.Unlock()
	return nil
}

// GetSyncStatus returns last-receive info.
func (ss *SyncSlave) GetSyncStatus() (int64, string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.lastReceive, ss.lastChecksum
}
