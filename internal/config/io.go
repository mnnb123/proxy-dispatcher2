package config

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// LoadConfig loads config from path, creating a default on missing file
// and falling back to backup on corruption.
func LoadConfig(path string) (*AppConfig, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create config dir: %w", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg := DefaultConfig()
			if saveErr := SaveConfig(path, cfg); saveErr != nil {
				return nil, fmt.Errorf("save default config: %w", saveErr)
			}
			return cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := &AppConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		backupData, bErr := os.ReadFile(path + ".backup")
		if bErr != nil {
			return nil, fmt.Errorf("config corrupt, no backup: %w", err)
		}
		if err := json.Unmarshal(backupData, cfg); err != nil {
			return nil, fmt.Errorf("backup also corrupt: %w", err)
		}
		cfg.MigrateToGroups()
		return cfg, nil
	}
	if cfg.MigrateToGroups() {
		_ = SaveConfig(path, cfg)
	}
	return cfg, nil
}

// SaveConfig writes cfg to path with 0600 permission, creating a backup of
// the previous file first.
func SaveConfig(path string, cfg *AppConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	if _, err := os.Stat(path); err == nil {
		if err := copyFile(path, path+".backup"); err != nil {
			return fmt.Errorf("create backup: %w", err)
		}
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	// Atomic write: write to temp file then rename to prevent corruption.
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		// Rename may fail on some OS (Windows cross-device). Fall back to direct write.
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return fmt.Errorf("write config fallback: %w", err)
		}
	}
	return nil
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
