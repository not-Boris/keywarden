package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
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

type LogSource struct {
	SourceID       string              `json:"source_id,omitempty"`
	Kind           string              `json:"kind"`
	Name           string              `json:"name,omitempty"`
	ServiceUnit    string              `json:"service_unit,omitempty"`
	FilePath       string              `json:"file_path,omitempty"`
	Parser         string              `json:"parser,omitempty"`
	IncludeMatches map[string][]string `json:"include_matches,omitempty"`
	ExcludeMatches map[string][]string `json:"exclude_matches,omitempty"`
	Category       string              `json:"category,omitempty"`
	EventType      string              `json:"event_type,omitempty"`
	Enabled        *bool               `json:"enabled,omitempty"`
}

type Config struct {
	ServerURL           string        `json:"server_url"`
	ServerID            string        `json:"server_id,omitempty"`
	AgentAPIToken       string        `json:"agent_api_token,omitempty"`
	ServerCAPath        string        `json:"server_ca_path,omitempty"`
	SyncIntervalSeconds int           `json:"sync_interval_seconds,omitempty"`
	LogBatchSize        int           `json:"log_batch_size,omitempty"`
	LogSources          []LogSource   `json:"log_sources,omitempty"`
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
		cfg := &Config{
			ServerURL:     serverURL,
			AgentAPIToken: os.Getenv("KEYWARDEN_AGENT_API_TOKEN"),
			ServerCAPath:  os.Getenv("KEYWARDEN_SERVER_CA_PATH"),
		}
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
	envAgentToken := strings.TrimSpace(os.Getenv("KEYWARDEN_AGENT_API_TOKEN"))
	if cfg.ServerCAPath == "" {
		cfg.ServerCAPath = os.Getenv("KEYWARDEN_SERVER_CA_PATH")
	}
	// Environment should win when set so operators can rotate tokens centrally
	// without editing persisted agent.json on every node.
	if envAgentToken != "" {
		cfg.AgentAPIToken = envAgentToken
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
	cfg.ServerID = strings.TrimSpace(cfg.ServerID)
	cfg.AgentAPIToken = strings.TrimSpace(cfg.AgentAPIToken)
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
	if looksLikePlaceholder(cfg.ServerID) {
		return errors.New("invalid server_id placeholder in config; remove server_id and re-enroll the agent")
	}
	if cfg.ServerID != "" {
		if _, err := strconv.Atoi(cfg.ServerID); err != nil {
			return errors.New("invalid server_id in config; expected numeric server id from enrollment")
		}
	}
	if looksLikePlaceholder(cfg.AgentAPIToken) {
		return errors.New("invalid agent_api_token placeholder in config; remove agent_api_token and re-enroll the agent")
	}
	if cfg.SyncIntervalSeconds < 5 {
		return errors.New("sync_interval_seconds must be >= 5")
	}
	for i, source := range cfg.LogSources {
		kind := strings.ToLower(strings.TrimSpace(source.Kind))
		switch kind {
		case "journal":
			// journal source is valid with optional include/exclude matches.
		case "service":
			if strings.TrimSpace(source.ServiceUnit) == "" && strings.TrimSpace(source.Name) == "" {
				return fmt.Errorf("log_sources[%d]: service source requires service_unit or name", i)
			}
		case "file":
			if strings.TrimSpace(source.FilePath) == "" && strings.TrimSpace(source.Name) == "" {
				return fmt.Errorf("log_sources[%d]: file source requires file_path or name", i)
			}
		default:
			return fmt.Errorf("log_sources[%d]: kind must be 'journal', 'service' or 'file'", i)
		}
		parser := strings.ToLower(strings.TrimSpace(source.Parser))
		if parser == "" {
			continue
		}
		switch parser {
		case "none", "syslog", "nginx_access", "json":
		default:
			return fmt.Errorf("log_sources[%d]: parser must be one of none|syslog|nginx_access|json", i)
		}
	}
	return nil
}

func looksLikePlaceholder(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	return strings.Contains(value, "<") || strings.Contains(value, ">")
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

func (c *Config) LogOffsetsPath() string {
	return c.StateDir + "/log.offsets.json"
}

func (c *Config) LogStatePath() string {
	return c.StateDir + "/log.state.json"
}

func (c *Config) EnabledLogSources() []LogSource {
	if len(c.LogSources) == 0 {
		return nil
	}
	out := make([]LogSource, 0, len(c.LogSources))
	for _, source := range c.LogSources {
		if source.Enabled != nil && !*source.Enabled {
			continue
		}
		out = append(out, source)
	}
	return out
}

func dir(path string) string {
	if idx := strings.LastIndex(path, string(os.PathSeparator)); idx != -1 {
		return path[:idx]
	}
	return "."
}
