package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"proxy-dispatcher/internal/config"

	"github.com/google/uuid"
)

// SafeAPIToken is a token representation safe to return via API.
type SafeAPIToken struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
	CreatedBy   string   `json:"created_by"`
	CreatedAt   int64    `json:"created_at"`
	ExpiresAt   int64    `json:"expires_at"`
	LastUsed    int64    `json:"last_used"`
	Disabled    bool     `json:"disabled"`
}

// TokenManager manages API tokens indexed by SHA-256 hash.
type TokenManager struct {
	tokens map[string]*config.APIToken
	byID   map[string]*config.APIToken
	mu     sync.RWMutex
	logger *slog.Logger
}

// NewTokenManager constructs a TokenManager from existing tokens.
func NewTokenManager(tokens []config.APIToken, logger *slog.Logger) *TokenManager {
	tm := &TokenManager{
		tokens: make(map[string]*config.APIToken),
		byID:   make(map[string]*config.APIToken),
		logger: logger,
	}
	for i := range tokens {
		t := &tokens[i]
		tm.tokens[t.TokenHash] = t
		tm.byID[t.ID] = t
	}
	return tm
}

func hashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// CreateToken generates a new API token. Returns the raw token (once only).
func (tm *TokenManager) CreateToken(name string, permissions []string, expiresAt int64, createdBy string) (string, *config.APIToken, error) {
	if strings.TrimSpace(name) == "" {
		return "", nil, errors.New("name required")
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	raw := hex.EncodeToString(b)
	th := hashToken(raw)
	token := &config.APIToken{
		ID:          uuid.NewString(),
		Name:        name,
		TokenHash:   th,
		Permissions: permissions,
		CreatedBy:   createdBy,
		CreatedAt:   time.Now().Unix(),
		ExpiresAt:   expiresAt,
	}
	tm.mu.Lock()
	tm.tokens[th] = token
	tm.byID[token.ID] = token
	tm.mu.Unlock()
	return raw, token, nil
}

// ValidateToken looks up a raw token, updating LastUsed on success.
func (tm *TokenManager) ValidateToken(raw string) (*config.APIToken, error) {
	th := hashToken(raw)
	tm.mu.RLock()
	t, ok := tm.tokens[th]
	tm.mu.RUnlock()
	if !ok {
		return nil, errors.New("invalid token")
	}
	if t.Disabled {
		return nil, errors.New("token disabled")
	}
	now := time.Now().Unix()
	if t.ExpiresAt > 0 && now > t.ExpiresAt {
		return nil, errors.New("token expired")
	}
	go func() {
		tm.mu.Lock()
		t.LastUsed = now
		tm.mu.Unlock()
	}()
	return t, nil
}

// HasPermission checks whether a token grants the given permission.
func (tm *TokenManager) HasPermission(token *config.APIToken, perm string) bool {
	for _, p := range token.Permissions {
		if p == perm || p == "*" {
			return true
		}
		if strings.HasSuffix(p, ":*") {
			prefix := strings.TrimSuffix(p, "*")
			if strings.HasPrefix(perm, prefix) {
				return true
			}
		}
	}
	return false
}

// RevokeToken marks a token as disabled.
func (tm *TokenManager) RevokeToken(id string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	t, ok := tm.byID[id]
	if !ok {
		return errors.New("token not found")
	}
	t.Disabled = true
	return nil
}

// DeleteToken removes a token entirely.
func (tm *TokenManager) DeleteToken(id string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	t, ok := tm.byID[id]
	if !ok {
		return errors.New("token not found")
	}
	delete(tm.tokens, t.TokenHash)
	delete(tm.byID, id)
	return nil
}

// ListTokens returns SafeAPIToken copies.
func (tm *TokenManager) ListTokens() []SafeAPIToken {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	out := make([]SafeAPIToken, 0, len(tm.byID))
	for _, t := range tm.byID {
		out = append(out, SafeAPIToken{
			ID: t.ID, Name: t.Name, Permissions: t.Permissions,
			CreatedBy: t.CreatedBy, CreatedAt: t.CreatedAt,
			ExpiresAt: t.ExpiresAt, LastUsed: t.LastUsed, Disabled: t.Disabled,
		})
	}
	return out
}

// Snapshot returns copies for persistence.
func (tm *TokenManager) Snapshot() []config.APIToken {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	out := make([]config.APIToken, 0, len(tm.byID))
	for _, t := range tm.byID {
		out = append(out, *t)
	}
	return out
}

// Reload replaces all tokens.
func (tm *TokenManager) Reload(tokens []config.APIToken) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.tokens = make(map[string]*config.APIToken)
	tm.byID = make(map[string]*config.APIToken)
	for i := range tokens {
		t := &tokens[i]
		tm.tokens[t.TokenHash] = t
		tm.byID[t.ID] = t
	}
}

// Cleanup drops tokens expired over 30 days ago.
func (tm *TokenManager) Cleanup() {
	cutoff := time.Now().Unix() - 30*24*3600
	tm.mu.Lock()
	defer tm.mu.Unlock()
	for id, t := range tm.byID {
		if t.ExpiresAt > 0 && t.ExpiresAt < cutoff {
			delete(tm.tokens, t.TokenHash)
			delete(tm.byID, id)
		}
	}
}
