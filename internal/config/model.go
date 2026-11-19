// Package config defines application configuration types and defaults.
package config

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// ProxyEntry represents a single upstream proxy.
type ProxyEntry struct {
	Host        string  `json:"host"`
	Port        int     `json:"port"`
	User        string  `json:"user,omitempty"`
	Pass        string  `json:"pass,omitempty"`
	Type        string  `json:"type"`
	Status      string  `json:"status"`
	LastCheck   int64   `json:"last_check"`
	LatencyMs   int64   `json:"latency_ms"`
	AvgLatency  int64   `json:"avg_latency"`
	CheckCount  int64   `json:"check_count"`
	FailCount   int64   `json:"fail_count"`
	SuccessRate float64 `json:"success_rate"`
	Weight      int     `json:"weight"`
	ActiveConns int32   `json:"-"`
	ExternalIP  string  `json:"external_ip,omitempty"`
	Country     string  `json:"country,omitempty"`
	// IPv4Only (SOCKS5 upstreams): destination names are resolved to an
	// IPv4 address here, so the upstream cannot leave through IPv6.
	IPv4Only bool `json:"ipv4_only,omitempty"`
}

// IsEmpty reports whether the entry is a placeholder for an output port
// that currently has no proxy. Proxies map to ports by position, so a
// session group keeps a placeholder to leave a port in the middle of its
// range unassigned.
func (p *ProxyEntry) IsEmpty() bool { return p.Host == "" }

// ProxyGroup is a named bundle of proxies with a rotation mode.
type ProxyGroup struct {
	Name         string       `json:"name"`
	Proxies      []ProxyEntry `json:"proxies"`
	RotationMode string       `json:"rotation_mode"`
	StickyTTLSec int          `json:"sticky_ttl_sec"`
	// KeepHistory marks a "session" group: every replaced list is archived
	// (with recorded public IPs) so it can be searched and re-attached.
	KeepHistory bool `json:"keep_history,omitempty"`
	// SessionAPI lets customers change the IP of a port of this session
	// group through the key-authenticated /api/pub/port/... endpoints.
	SessionAPI *SessionAPIConfig `json:"session_api,omitempty"`
	// AutoKeep keeps the first ports of this session group filled with
	// working ShopSocks5 socks (see internal/api/autokeep.go).
	AutoKeep *AutoKeepConfig `json:"auto_keep,omitempty"`
}

// AutoKeepConfig: the first Target ports of the group are probed every
// CheckSec seconds; an empty port, or one whose sock failed DeadChecks
// probes in a row, gets a fresh sock. MaxPerDay caps how many socks this
// may take from the plan per day.
type AutoKeepConfig struct {
	Enabled    bool   `json:"enabled"`
	Target     int    `json:"target"`
	Country    string `json:"country,omitempty"`
	State      string `json:"state,omitempty"`
	City       string `json:"city,omitempty"`
	SockType   string `json:"sock_type,omitempty"`
	Level      string `json:"level,omitempty"`
	Unique     bool   `json:"unique,omitempty"`
	CheckSec   int    `json:"check_sec"`
	DeadChecks int    `json:"dead_checks"`
	MaxPerDay  int    `json:"max_per_day"`
}

// SessionAPIConfig configures the customer API of a session group. The
// filter fields are the defaults used when a new sock is requested.
type SessionAPIConfig struct {
	Enabled        bool   `json:"enabled"`
	Secret         string `json:"secret,omitempty"`
	Country        string `json:"country,omitempty"`
	State          string `json:"state,omitempty"`
	City           string `json:"city,omitempty"`
	SockType       string `json:"sock_type,omitempty"`
	Level          string `json:"level,omitempty"`
	MinIntervalSec int    `json:"min_interval_sec,omitempty"`
	// Unique: a "new IP" request never hands out an IP the group already had.
	Unique bool `json:"unique,omitempty"`
	// Keys are customer keys valid for a set of ports each.
	Keys []SessionAPIKey `json:"keys,omitempty"`
}

// SessionAPIKey is one key shared by several ports of a session group.
// Ports is a list such as "40000-40004,40010".
type SessionAPIKey struct {
	Key   string `json:"key"`
	Ports string `json:"ports"`
	Note  string `json:"note,omitempty"`
}

// PortMapping binds a port range to a group name.
type PortMapping struct {
	PortStart int    `json:"port_start"`
	PortEnd   int    `json:"port_end"`
	GroupName string `json:"group_name"`
}

// HealthCheckConfig controls active health checking.
type HealthCheckConfig struct {
	Enabled         bool   `json:"enabled"`
	IntervalSec     int    `json:"interval_sec"`
	TimeoutSec      int    `json:"timeout_sec"`
	TestURL         string `json:"test_url"`
	SlowThresholdMs int    `json:"slow_threshold_ms"`
	MaxConcurrent   int    `json:"max_concurrent"`
	AutoRemoveDead  bool   `json:"auto_remove_dead"`
}

// RetryConfig controls connection-level retry.
type RetryConfig struct {
	Enabled     bool `json:"enabled"`
	MaxAttempts int  `json:"max_attempts"`
	BackoffMs   int  `json:"backoff_ms"`
}

// ImportSource describes a remote proxy-list source to periodically fetch.
type ImportSource struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	IntervalSec int    `json:"interval_sec"`
	ProxyType   string `json:"proxy_type"`
	GroupName   string `json:"group_name"`
	Enabled     bool   `json:"enabled"`
	AuthHeader  string `json:"auth_header,omitempty"`
	LastFetch   int64  `json:"last_fetch"`
	LastCount   int    `json:"last_count"`
}

// DomainRule describes a single domain matching rule for bypass or block.
type DomainRule struct {
	Pattern string `json:"pattern"`
	Type    string `json:"type"`
	Action  string `json:"action,omitempty"`
	Enabled bool   `json:"enabled"`
	Note    string `json:"note,omitempty"`
}

// ExtensionRule describes a file extension matching rule for bypass.
type ExtensionRule struct {
	Extension string `json:"extension"`
	Group     string `json:"group"`
	Action    string `json:"action,omitempty"`
	Enabled   bool   `json:"enabled"`
}

// WhitelistEntry represents a single whitelisted IP or CIDR.
type WhitelistEntry struct {
	IP        string `json:"ip"`
	Type      string `json:"type"`
	Note      string `json:"note,omitempty"`
	ExpiresAt int64  `json:"expires_at"`
	CreatedAt int64  `json:"created_at"`
}

// AutoBanConfig controls brute-force auto-banning.
type AutoBanConfig struct {
	Enabled        bool `json:"enabled"`
	MaxAttempts    int  `json:"max_attempts"`
	BanDurationSec int  `json:"ban_duration_sec"`
}

// ShopSocks5Config is the shopsocks5.com account used to take socks for
// session groups. BaseURL is only for tests; empty means the real API.
type ShopSocks5Config struct {
	UserName string `json:"user_name,omitempty"`
	APIToken string `json:"api_token,omitempty"`
	BaseURL  string `json:"base_url,omitempty"`
	// ExcludeURL returns IPs that must never be handed out (see
	// internal/api/handler_exclude.go).
	ExcludeURL string `json:"exclude_url,omitempty"`
}

// OutputAccount is a user/password a client may present on an output port
// (HTTP Proxy-Authorization or SOCKS5 username/password) when its IP is not
// whitelisted.
type OutputAccount struct {
	User      string `json:"user"`
	Pass      string `json:"pass"`
	Note      string `json:"note,omitempty"`
	CreatedAt int64  `json:"created_at,omitempty"`
}

// WhitelistConfig holds IP whitelist settings.
type WhitelistConfig struct {
	Enabled bool             `json:"enabled"`
	Entries []WhitelistEntry `json:"entries"`
	AutoBan AutoBanConfig    `json:"auto_ban"`
	// Accounts let clients outside the IP whitelist authenticate with
	// user/pass. Only consulted while the whitelist is enabled.
	Accounts []OutputAccount `json:"accounts,omitempty"`
}

// AutoBypassConfig controls automatic large-content bypass.
type AutoBypassConfig struct {
	Enabled         bool   `json:"enabled"`
	SizeThreshold   int64  `json:"size_threshold"`
	TimeWindowSec   int    `json:"time_window_sec"`
	Action          string `json:"action"`
	ThrottleSpeedBps int64 `json:"throttle_speed_bps"`
	Strategy        string `json:"strategy"`
	PredictEnabled  bool   `json:"predict_enabled"`
}

// BudgetConfig controls bandwidth budget limits.
type BudgetConfig struct {
	Enabled          bool  `json:"enabled"`
	DailyLimitBytes  int64 `json:"daily_limit_bytes"`
	DomainHourlyLimit int64 `json:"domain_hourly_limit"`
	OverLimitAction  string `json:"over_limit_action"`
	WarningPercent   int   `json:"warning_percent"`
}

// ReportConfig controls the reporting/logging subsystem.
type ReportConfig struct {
	RingBufferMaxRows    int    `json:"ring_buffer_max_rows"`
	AutoClearEnabled     bool   `json:"auto_clear_enabled"`
	AutoClearSeconds     int    `json:"auto_clear_seconds"`
	ExportBeforeClear    bool   `json:"export_before_clear"`
	AggregateKeepMinutes int    `json:"aggregate_keep_minutes"`
	AggregateKeepHours   int    `json:"aggregate_keep_hours"`
	AggregateKeepDays    int    `json:"aggregate_keep_days"`
	DiskLogEnabled       bool   `json:"disk_log_enabled"`
	DiskLogPath          string `json:"disk_log_path"`
	DiskLogMaxDays       int    `json:"disk_log_max_days"`
	DiskLogMaxSizeMB     int    `json:"disk_log_max_size_mb"`
	AlertEnabled         bool   `json:"alert_enabled"`
	AlertWebhookURL      string `json:"alert_webhook_url,omitempty"`
	AlertTelegramToken   string `json:"alert_telegram_token,omitempty"`
	AlertTelegramChat    string `json:"alert_telegram_chat,omitempty"`
}

// AppConfig is the root application configuration.
type AppConfig struct {
	VpsIp           string       `json:"vps_ip"`
	AdminUser       string       `json:"admin_user"`
	AdminPassHash   string       `json:"admin_pass_hash"`
	WebPanelPort    int          `json:"web_panel_port"`
	InputProxies    []ProxyEntry `json:"input_proxies"`
	InputType       string       `json:"input_type"`
	OutputStartPort int          `json:"output_start_port"`
	OutputCount     int          `json:"output_count"`
	RotationMode    string       `json:"rotation_mode"`
	JwtSecret       string       `json:"jwt_secret"`
	ConnTimeout     int          `json:"conn_timeout"`
	IdleTimeout     int          `json:"idle_timeout"`
	MaxConnPerPort  int          `json:"max_conn_per_port"`

	BypassDomains       []DomainRule    `json:"bypass_domains"`
	BypassExtensions    []ExtensionRule `json:"bypass_extensions"`
	BlockDomains        []DomainRule    `json:"block_domains"`
	ResourceProxy       *ProxyEntry     `json:"resource_proxy,omitempty"`
	DefaultBypassAction string          `json:"default_bypass_action"`
	DefaultBlockAction  string          `json:"default_block_action"`

	Report           ReportConfig     `json:"report"`

	Whitelist        WhitelistConfig  `json:"whitelist"`
	AutoBypass       AutoBypassConfig `json:"auto_bypass"`
	ForceProxyDomains []DomainRule    `json:"force_proxy_domains"`
	BandwidthBudget  BudgetConfig     `json:"bandwidth_budget"`

	ProxyGroups   []ProxyGroup      `json:"proxy_groups"`
	PortMappings  []PortMapping     `json:"port_mappings"`
	HealthCheck   HealthCheckConfig `json:"health_check"`
	RetryCfg      RetryConfig       `json:"retry_config"`
	ImportSources []ImportSource    `json:"import_sources"`

	// Phase 6.
	Users        []UserAccount `json:"users"`
	APITokens    []APIToken    `json:"api_tokens"`
	SyncConfig   SyncConfig    `json:"sync_config"`
	SystemConfig SystemConfig  `json:"system_config"`

	ShopSocks5 ShopSocks5Config `json:"shopsocks5,omitempty"`
}

// UserAccount is a web-panel user with RBAC + optional TOTP.
type UserAccount struct {
	ID            string   `json:"id"`
	Username      string   `json:"username"`
	PassHash      string   `json:"pass_hash"`
	Role          string   `json:"role"`
	TOTPEnabled   bool     `json:"totp_enabled"`
	TOTPSecret    string   `json:"totp_secret,omitempty"`
	RecoveryCodes []string `json:"recovery_codes,omitempty"`
	CreatedAt     int64    `json:"created_at"`
	LastLogin     int64    `json:"last_login"`
	Disabled      bool     `json:"disabled"`
}

// APIToken is a long-lived token granting API access.
type APIToken struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	TokenHash   string   `json:"token_hash"`
	Permissions []string `json:"permissions"`
	CreatedBy   string   `json:"created_by"`
	CreatedAt   int64    `json:"created_at"`
	ExpiresAt   int64    `json:"expires_at"`
	LastUsed    int64    `json:"last_used"`
	Disabled    bool     `json:"disabled"`
}

// SyncConfig describes master/slave sync relationship.
type SyncConfig struct {
	Role            string      `json:"role"`
	SharedSecret    string      `json:"shared_secret"`
	MasterURL       string      `json:"master_url"`
	SlaveNodes      []SlaveNode `json:"slave_nodes"`
	AutoSync        bool        `json:"auto_sync"`
	SyncIntervalSec int         `json:"sync_interval_sec"`
}

// SlaveNode is a single slave registered with a master.
type SlaveNode struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	Enabled   bool   `json:"enabled"`
	LastSync  int64  `json:"last_sync"`
	LastError string `json:"last_error"`
	Status    string `json:"status"`
}

// SystemConfig carries DNS + system-level settings.
type SystemConfig struct {
	DNSServers   []string `json:"dns_servers"`
	DNSOverHTTPS bool     `json:"dns_over_https"`
	Timezone     string   `json:"timezone"`
}

// DefaultConfig returns a new AppConfig populated with default values.
func DefaultConfig() *AppConfig {
	secretBytes := make([]byte, 32)
	_, _ = rand.Read(secretBytes)
	secret := hex.EncodeToString(secretBytes)

	hash, _ := bcrypt.GenerateFromPassword([]byte("admin"), 10)

	return &AppConfig{
		VpsIp:           "",
		AdminUser:       "admin",
		AdminPassHash:   string(hash),
		WebPanelPort:    8000,
		InputProxies:    []ProxyEntry{},
		InputType:       "http",
		OutputStartPort: 30001,
		OutputCount:     10,
		RotationMode:    "roundrobin",
		JwtSecret:       secret,
		ConnTimeout:     10,
		IdleTimeout:     60,
		MaxConnPerPort:  100,

		Report: AutoDetectReportConfig(GetSystemRAM()),

		BypassDomains:       nil,
		BypassExtensions:    DefaultExtensions(),
		BlockDomains:        nil,
		DefaultBypassAction: "direct",
		DefaultBlockAction:  "403",

		Whitelist: WhitelistConfig{
			Enabled: false,
			AutoBan: AutoBanConfig{Enabled: true, MaxAttempts: 10, BanDurationSec: 3600},
		},
		AutoBypass: AutoBypassConfig{
			Enabled: false, SizeThreshold: 1048576, TimeWindowSec: 120,
			Action: "direct", ThrottleSpeedBps: 102400, Strategy: "header", PredictEnabled: true,
		},
		BandwidthBudget: BudgetConfig{
			Enabled: false, DailyLimitBytes: 5368709120, DomainHourlyLimit: 104857600,
			OverLimitAction: "direct", WarningPercent: 80,
		},

		ProxyGroups:  []ProxyGroup{},
		PortMappings: []PortMapping{},
		HealthCheck: HealthCheckConfig{
			Enabled: true, IntervalSec: 30, TimeoutSec: 5,
			TestURL: "http://httpbin.org/ip", SlowThresholdMs: 3000,
			MaxConcurrent: 20, AutoRemoveDead: false,
		},
		RetryCfg: RetryConfig{
			Enabled: true, MaxAttempts: 3, BackoffMs: 100,
		},
		ImportSources: []ImportSource{},

		Users: []UserAccount{{
			ID:        "default-admin",
			Username:  "admin",
			PassHash:  string(hash),
			Role:      "admin",
			CreatedAt: 0,
		}},
		APITokens: []APIToken{},
		SyncConfig: SyncConfig{
			Role:            "standalone",
			SyncIntervalSec: 300,
		},
		SystemConfig: SystemConfig{
			DNSServers: []string{"8.8.8.8", "1.1.1.1"},
			Timezone:   "UTC",
		},
	}
}

// MigrateToGroups ensures ProxyGroups/PortMappings are populated from legacy
// InputProxies/OutputStartPort+OutputCount when absent.
func (c *AppConfig) MigrateToGroups() bool {
	changed := false
	if len(c.ProxyGroups) == 0 && len(c.InputProxies) > 0 {
		mode := c.RotationMode
		if mode == "" {
			mode = "roundrobin"
		}
		c.ProxyGroups = []ProxyGroup{{
			Name:         "default",
			Proxies:      c.InputProxies,
			RotationMode: mode,
			StickyTTLSec: 300,
		}}
		changed = true
	}
	if len(c.PortMappings) == 0 && c.OutputCount > 0 && c.OutputStartPort > 0 && len(c.ProxyGroups) > 0 {
		c.PortMappings = []PortMapping{{
			PortStart: c.OutputStartPort,
			PortEnd:   c.OutputStartPort + c.OutputCount - 1,
			GroupName: c.ProxyGroups[0].Name,
		}}
		changed = true
	}
	if c.HealthCheck.IntervalSec == 0 {
		c.HealthCheck = HealthCheckConfig{
			Enabled: true, IntervalSec: 30, TimeoutSec: 5,
			TestURL: "http://httpbin.org/ip", SlowThresholdMs: 3000,
			MaxConcurrent: 20, AutoRemoveDead: false,
		}
		changed = true
	}
	if c.RetryCfg.MaxAttempts == 0 {
		c.RetryCfg = RetryConfig{Enabled: true, MaxAttempts: 3, BackoffMs: 100}
		changed = true
	}
	// Phase 6 migration: AdminUser/AdminPassHash → Users.
	if len(c.Users) == 0 && c.AdminUser != "" && c.AdminPassHash != "" {
		c.Users = []UserAccount{{
			ID:        "migrated-admin",
			Username:  strings.ToLower(c.AdminUser),
			PassHash:  c.AdminPassHash,
			Role:      "admin",
			CreatedAt: 0,
		}}
		changed = true
	}
	if c.SyncConfig.Role == "" {
		c.SyncConfig.Role = "standalone"
		changed = true
	}
	if c.SyncConfig.SyncIntervalSec == 0 {
		c.SyncConfig.SyncIntervalSec = 300
		changed = true
	}
	if len(c.SystemConfig.DNSServers) == 0 {
		c.SystemConfig.DNSServers = []string{"8.8.8.8", "1.1.1.1"}
		changed = true
	}
	if c.SystemConfig.Timezone == "" {
		c.SystemConfig.Timezone = "UTC"
		changed = true
	}
	return changed
}

// DefaultExtensions returns the preset extension rules (all disabled).
func DefaultExtensions() []ExtensionRule {
	groups := map[string][]string{
		"media":     {"mp3", "mp4", "avi", "mkv", "mov", "flac", "wav", "webm", "ogg", "m4a"},
		"image":     {"jpg", "jpeg", "png", "gif", "webp", "svg", "ico", "bmp", "tiff"},
		"document":  {"pdf", "doc", "docx", "xlsx", "xls", "ppt", "pptx"},
		"software":  {"exe", "dmg", "apk", "msi", "deb", "rpm"},
		"archive":   {"zip", "rar", "7z", "tar", "gz", "bz2", "xz"},
		"web_asset": {"css", "js", "woff", "woff2", "ttf", "eot", "map"},
	}
	var out []ExtensionRule
	for group, exts := range groups {
		for _, ext := range exts {
			out = append(out, ExtensionRule{Extension: ext, Group: group, Enabled: false})
		}
	}
	return out
}

// GetSystemRAM reads total memory from /proc/meminfo (Linux). Returns 0 on failure.
func GetSystemRAM() int64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, err := strconv.ParseInt(fields[1], 10, 64)
				if err == nil {
					return kb * 1024
				}
			}
		}
	}
	return 0
}

// AutoDetectReportConfig returns a ReportConfig tuned for the given RAM.
func AutoDetectReportConfig(totalRAM int64) ReportConfig {
	maxRows, clearSec := 500, 300
	gb := totalRAM / (1024 * 1024 * 1024)
	switch {
	case gb >= 4:
		maxRows, clearSec = 5000, 600
	case gb >= 2:
		maxRows, clearSec = 2000, 600
	case gb >= 1:
		maxRows, clearSec = 1000, 300
	default:
		maxRows, clearSec = 300, 180
	}
	return ReportConfig{
		RingBufferMaxRows:    maxRows,
		AutoClearEnabled:     true,
		AutoClearSeconds:     clearSec,
		ExportBeforeClear:    false,
		AggregateKeepMinutes: 60,
		AggregateKeepHours:   24,
		AggregateKeepDays:    7,
		DiskLogEnabled:       true,
		DiskLogPath:          "/var/log/proxy-dispatcher/",
		DiskLogMaxDays:       7,
		DiskLogMaxSizeMB:     100,
		AlertEnabled:         true,
	}
}
