package auth

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"proxy-dispatcher/internal/config"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// SafeUser is a user representation safe to return via API.
type SafeUser struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	Role        string `json:"role"`
	TOTPEnabled bool   `json:"totp_enabled"`
	CreatedAt   int64  `json:"created_at"`
	LastLogin   int64  `json:"last_login"`
	Disabled    bool   `json:"disabled"`
}

// UserUpdate describes partial user edits.
type UserUpdate struct {
	Password *string
	Role     *string
	Disabled *bool
}

// UserManager owns the set of UserAccounts and exposes safe operations.
type UserManager struct {
	users  map[string]*config.UserAccount
	byID   map[string]*config.UserAccount
	mu     sync.RWMutex
	logger *slog.Logger
}

var validRoles = map[string]bool{"admin": true, "operator": true, "viewer": true}

// NewUserManager constructs a UserManager from the given list.
func NewUserManager(users []config.UserAccount, logger *slog.Logger) *UserManager {
	um := &UserManager{
		users:  make(map[string]*config.UserAccount),
		byID:   make(map[string]*config.UserAccount),
		logger: logger,
	}
	for i := range users {
		u := &users[i]
		um.users[strings.ToLower(u.Username)] = u
		um.byID[u.ID] = u
	}
	return um
}

// Authenticate validates a username/password pair without checking TOTP.
func (um *UserManager) Authenticate(username, password string) (*config.UserAccount, error) {
	um.mu.RLock()
	u, ok := um.users[strings.ToLower(username)]
	um.mu.RUnlock()
	if !ok {
		return nil, errors.New("invalid credentials")
	}
	if u.Disabled {
		return nil, errors.New("user disabled")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PassHash), []byte(password)); err != nil {
		return nil, errors.New("invalid credentials")
	}
	um.mu.Lock()
	u.LastLogin = time.Now().Unix()
	um.mu.Unlock()
	return u, nil
}

// CreateUser registers a new user.
func (um *UserManager) CreateUser(username, password, role string) (*config.UserAccount, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	if l := len(username); l < 3 || l > 32 {
		return nil, errors.New("username must be 3-32 chars")
	}
	if len(password) < 8 {
		return nil, errors.New("password must be at least 8 chars")
	}
	if !validRoles[role] {
		return nil, errors.New("invalid role")
	}
	um.mu.Lock()
	defer um.mu.Unlock()
	if _, exists := um.users[username]; exists {
		return nil, errors.New("username already exists")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return nil, err
	}
	u := &config.UserAccount{
		ID:        uuid.NewString(),
		Username:  username,
		PassHash:  string(hash),
		Role:      role,
		CreatedAt: time.Now().Unix(),
	}
	um.users[username] = u
	um.byID[u.ID] = u
	return u, nil
}

func (um *UserManager) countActiveAdmins() int {
	n := 0
	for _, u := range um.users {
		if u.Role == "admin" && !u.Disabled {
			n++
		}
	}
	return n
}

// UpdateUser applies partial updates.
func (um *UserManager) UpdateUser(id string, updates UserUpdate) error {
	um.mu.Lock()
	defer um.mu.Unlock()
	u, ok := um.byID[id]
	if !ok {
		return errors.New("user not found")
	}
	if updates.Password != nil {
		if len(*updates.Password) < 8 {
			return errors.New("password must be at least 8 chars")
		}
		h, err := bcrypt.GenerateFromPassword([]byte(*updates.Password), 10)
		if err != nil {
			return err
		}
		u.PassHash = string(h)
	}
	if updates.Role != nil {
		if !validRoles[*updates.Role] {
			return errors.New("invalid role")
		}
		if u.Role == "admin" && *updates.Role != "admin" && um.countActiveAdmins() <= 1 {
			return errors.New("cannot demote last admin")
		}
		u.Role = *updates.Role
	}
	if updates.Disabled != nil {
		if *updates.Disabled && u.Role == "admin" && um.countActiveAdmins() <= 1 {
			return errors.New("cannot disable last admin")
		}
		u.Disabled = *updates.Disabled
	}
	return nil
}

// DeleteUser removes a user if it's not the last admin.
func (um *UserManager) DeleteUser(id string) error {
	um.mu.Lock()
	defer um.mu.Unlock()
	u, ok := um.byID[id]
	if !ok {
		return errors.New("user not found")
	}
	if u.Role == "admin" && um.countActiveAdmins() <= 1 {
		return errors.New("cannot delete last admin")
	}
	delete(um.users, strings.ToLower(u.Username))
	delete(um.byID, id)
	return nil
}

// GetUser returns a copy of the user for the given username.
func (um *UserManager) GetUser(username string) *config.UserAccount {
	um.mu.RLock()
	defer um.mu.RUnlock()
	u, ok := um.users[strings.ToLower(username)]
	if !ok {
		return nil
	}
	c := *u
	return &c
}

// GetUserByID returns a copy of the user for the given ID.
func (um *UserManager) GetUserByID(id string) *config.UserAccount {
	um.mu.RLock()
	defer um.mu.RUnlock()
	u, ok := um.byID[id]
	if !ok {
		return nil
	}
	c := *u
	return &c
}

// MutateByID invokes fn with a pointer to the stored account under lock.
// Intended for TOTP/password flows that must persist mutations.
func (um *UserManager) MutateByID(id string, fn func(*config.UserAccount) error) error {
	um.mu.Lock()
	defer um.mu.Unlock()
	u, ok := um.byID[id]
	if !ok {
		return fmt.Errorf("user not found")
	}
	return fn(u)
}

// ListUsers returns SafeUser copies.
func (um *UserManager) ListUsers() []SafeUser {
	um.mu.RLock()
	defer um.mu.RUnlock()
	out := make([]SafeUser, 0, len(um.users))
	for _, u := range um.users {
		out = append(out, um.GetSafeUser(u))
	}
	return out
}

// GetSafeUser converts a UserAccount to SafeUser.
func (um *UserManager) GetSafeUser(u *config.UserAccount) SafeUser {
	return SafeUser{
		ID: u.ID, Username: u.Username, Role: u.Role,
		TOTPEnabled: u.TOTPEnabled, CreatedAt: u.CreatedAt,
		LastLogin: u.LastLogin, Disabled: u.Disabled,
	}
}

// Snapshot returns a copy of all user accounts for persistence.
func (um *UserManager) Snapshot() []config.UserAccount {
	um.mu.RLock()
	defer um.mu.RUnlock()
	out := make([]config.UserAccount, 0, len(um.byID))
	for _, u := range um.byID {
		out = append(out, *u)
	}
	return out
}

// Reload replaces internal state from a new list of users.
func (um *UserManager) Reload(users []config.UserAccount) {
	um.mu.Lock()
	defer um.mu.Unlock()
	um.users = make(map[string]*config.UserAccount)
	um.byID = make(map[string]*config.UserAccount)
	for i := range users {
		u := &users[i]
		um.users[strings.ToLower(u.Username)] = u
		um.byID[u.ID] = u
	}
}
