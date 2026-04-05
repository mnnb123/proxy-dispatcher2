// Package system implements backup, DNS and host-level utilities.
package system

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"proxy-dispatcher/internal/config"
)

const maxImportSize = 10 << 20 // 10 MB

// BackupInfo describes a single backup file on disk.
type BackupInfo struct {
	Filename  string    `json:"filename"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
}

// BackupManager owns the backup directory and last-backup timestamp.
type BackupManager struct {
	configPath string
	backupDir  string
	maxBackups int
	lastBackup time.Time
	logger     *slog.Logger
	mu         sync.Mutex
}

// NewBackupManager constructs the manager, creating backupDir if missing.
func NewBackupManager(configPath string, logger *slog.Logger) *BackupManager {
	dir := filepath.Join(filepath.Dir(configPath), "backups")
	_ = os.MkdirAll(dir, 0o755)
	return &BackupManager{
		configPath: configPath,
		backupDir:  dir,
		maxBackups: 20,
		logger:     logger,
	}
}

func safeFilename(name string) bool {
	if name == "" {
		return false
	}
	if strings.Contains(name, "..") || strings.ContainsAny(name, "/\\") {
		return false
	}
	return true
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// CreateBackup copies the current config file into backupDir.
func (bm *BackupManager) CreateBackup() (string, error) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	ts := time.Now().UTC().Format("20060102-150405")
	fn := fmt.Sprintf("backup-%s.json", ts)
	dst := filepath.Join(bm.backupDir, fn)
	if err := copyFile(bm.configPath, dst); err != nil {
		return "", err
	}
	bm.lastBackup = time.Now()
	bm.cleanupOld()
	return fn, nil
}

func (bm *BackupManager) cleanupOld() {
	entries := bm.listLocked()
	if len(entries) <= bm.maxBackups {
		return
	}
	for _, e := range entries[bm.maxBackups:] {
		_ = os.Remove(filepath.Join(bm.backupDir, e.Filename))
	}
}

// RestoreBackup replaces the live config with a backup file.
func (bm *BackupManager) RestoreBackup(filename string) error {
	if !safeFilename(filename) {
		return fmt.Errorf("invalid filename")
	}
	src := filepath.Join(bm.backupDir, filename)
	// Validate JSON.
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	var tmp config.AppConfig
	if err := json.Unmarshal(raw, &tmp); err != nil {
		return fmt.Errorf("backup is not valid JSON config: %w", err)
	}
	// Safety-net backup before overwriting.
	if _, err := bm.CreateBackup(); err != nil {
		return err
	}
	return copyFile(src, bm.configPath)
}

// ExportConfig writes a sensitive-stripped JSON copy of the config.
func (bm *BackupManager) ExportConfig(w io.Writer) error {
	raw, err := os.ReadFile(bm.configPath)
	if err != nil {
		return err
	}
	var cfg config.AppConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	for i := range cfg.Users {
		cfg.Users[i].PassHash = ""
		cfg.Users[i].TOTPSecret = ""
		cfg.Users[i].RecoveryCodes = nil
	}
	for i := range cfg.APITokens {
		cfg.APITokens[i].TokenHash = ""
	}
	cfg.AdminPassHash = ""
	cfg.JwtSecret = ""
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(&cfg)
}

// ImportConfig merges an incoming config, preserving local auth state.
func (bm *BackupManager) ImportConfig(r io.Reader) error {
	raw, err := io.ReadAll(io.LimitReader(r, maxImportSize))
	if err != nil {
		return err
	}
	var incoming config.AppConfig
	if err := json.Unmarshal(raw, &incoming); err != nil {
		return fmt.Errorf("invalid config JSON: %w", err)
	}
	// Read current to preserve local auth.
	cur, err := os.ReadFile(bm.configPath)
	if err != nil {
		return err
	}
	var current config.AppConfig
	if err := json.Unmarshal(cur, &current); err != nil {
		return err
	}
	incoming.Users = current.Users
	incoming.APITokens = current.APITokens
	incoming.SyncConfig = current.SyncConfig
	incoming.AdminPassHash = current.AdminPassHash
	incoming.JwtSecret = current.JwtSecret
	if _, err := bm.CreateBackup(); err != nil {
		return err
	}
	out, err := json.MarshalIndent(&incoming, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(bm.configPath, out, 0o600)
}

func (bm *BackupManager) listLocked() []BackupInfo {
	entries, err := os.ReadDir(bm.backupDir)
	if err != nil {
		return nil
	}
	out := make([]BackupInfo, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, BackupInfo{
			Filename: e.Name(), Size: info.Size(), CreatedAt: info.ModTime(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// ListBackups returns backups newest-first.
func (bm *BackupManager) ListBackups() []BackupInfo {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	return bm.listLocked()
}

// DeleteBackup removes a backup file.
func (bm *BackupManager) DeleteBackup(filename string) error {
	if !safeFilename(filename) {
		return fmt.Errorf("invalid filename")
	}
	return os.Remove(filepath.Join(bm.backupDir, filename))
}

// AutoBackup creates a backup at most once per hour.
func (bm *BackupManager) AutoBackup() {
	bm.mu.Lock()
	if time.Since(bm.lastBackup) < time.Hour {
		bm.mu.Unlock()
		return
	}
	bm.mu.Unlock()
	_, _ = bm.CreateBackup()
}
