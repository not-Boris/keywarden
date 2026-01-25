package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	DefaultConfigPath          = "/etc/keywarden/agent.json"
	DefaultStateDir            = "/var/lib/keywarden-agent"
	DefaultSyncIntervalSeconds = 30
	DefaultLogBatchSize        = 500
	DefaultUsernameTemplate    = "{{username}}_{{user_id}}"
	DefaultShell               = "/bin/bash"
	DefaultAdminGroup          = "sudo"
)

type AccountPolicy struct {
	UsernameTemplate string `json:"username_template"`
	DefaultShell     string `json:"default_shell"`
	AdminGroup       string `json:"admin_group"`
	CreateHome       bool   `json:"create_home"`
	LockOnRevoke     bool   `json:"lock_on_revoke"`
}

type Config struct {
	ServerURL           string        `json:"server_url"`
	ServerID            string        `json:"server_id,omitempty"`
	SyncIntervalSeconds int           `json:"sync_interval_seconds,omitempty"`
	LogBatchSize        int           `json:"log_batch_size,omitempty"`
	StateDir            string        `json:"state_dir,omitempty"`
	AccountPolicy       AccountPolicy `json:"account_policy,omitempty"`
}

func LoadOrInit(path string, serverURL string) (*Config, error) {
	if path == "" {
		path = DefaultConfigPath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("read config: %w", err)
		}
		if serverURL == "" {
			return nil, errors.New("server url required for first boot")
		}
		cfg := &Config{ServerURL: serverURL}
		applyDefaults(cfg)
		if err := validate(cfg, false); err != nil {
			return nil, err
		}
		if err := Save(path, cfg); err != nil {
			return nil, err
		}
		return cfg, nil
	}
	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	applyDefaults(cfg)
	if err := validate(cfg, false); err != nil {
		return nil, err
	}
	return cfg, nil
}

func Save(path string, cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	if err := os.MkdirAll(dir(path), 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

func applyDefaults(cfg *Config) {
	if cfg.SyncIntervalSeconds <= 0 {
		cfg.SyncIntervalSeconds = DefaultSyncIntervalSeconds
	}
	if cfg.LogBatchSize <= 0 {
		cfg.LogBatchSize = DefaultLogBatchSize
	}
	if cfg.StateDir == "" {
		cfg.StateDir = DefaultStateDir
	}
	if cfg.AccountPolicy.UsernameTemplate == "" {
		cfg.AccountPolicy.UsernameTemplate = DefaultUsernameTemplate
	}
	if cfg.AccountPolicy.DefaultShell == "" {
		cfg.AccountPolicy.DefaultShell = DefaultShell
	}
	if cfg.AccountPolicy.AdminGroup == "" {
		cfg.AccountPolicy.AdminGroup = DefaultAdminGroup
	}
}

func validate(cfg *Config, requireServerID bool) error {
	var missing []string
	if cfg.ServerURL == "" {
		missing = append(missing, "server_url")
	}
	if requireServerID && cfg.ServerID == "" {
		missing = append(missing, "server_id")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required config fields: %v", missing)
	}
	if cfg.SyncIntervalSeconds < 5 {
		return errors.New("sync_interval_seconds must be >= 5")
	}
	return nil
}

func (c *Config) ClientCertPath() string {
	return c.StateDir + "/agent.crt"
}

func (c *Config) ClientKeyPath() string {
	return c.StateDir + "/agent.key"
}

func (c *Config) CACertPath() string {
	return c.StateDir + "/ca.crt"
}

func (c *Config) LogCursorPath() string {
	return c.StateDir + "/journal.cursor"
}

func (c *Config) LogSpoolDir() string {
	return c.StateDir + "/spool"
}

func dir(path string) string {
	if idx := strings.LastIndex(path, string(os.PathSeparator)); idx != -1 {
		return path[:idx]
	}
	return "."
}
