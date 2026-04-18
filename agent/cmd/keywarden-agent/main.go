package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"keywarden/agent/internal/client"
	"keywarden/agent/internal/config"
	"keywarden/agent/internal/host"
	"keywarden/agent/internal/logs"
	"keywarden/agent/internal/version"
)

var lastNoEventsNotice time.Time

func main() {
	configPath := flag.String("config", config.DefaultConfigPath, "Path to agent config JSON")
	flag.StringVar(configPath, "c", config.DefaultConfigPath, "Path to agent config JSON (shorthand)")
	serverURL := flag.String("server-url", "", "Keywarden server URL (first boot)")
	enrollToken := flag.String("enroll-token", "", "Enrollment token (first boot)")
	flag.StringVar(enrollToken, "t", "", "Enrollment token (first boot, shorthand)")
	forceEnroll := flag.Bool("force-enroll", false, "Force re-enrollment even if already bootstrapped")
	flag.BoolVar(forceEnroll, "f", false, "Force re-enrollment even if already bootstrapped (shorthand)")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("keywarden-agent %s (commit %s, built %s)\n", version.Version, version.Commit, version.BuildDate)
		return
	}

	cfg, err := config.LoadOrInit(*configPath, pickServerURL(*serverURL))
	if err != nil {
		log.Fatalf("config error: %v", err)
	}
	if err := ensureDirs(cfg); err != nil {
		log.Fatalf("state dir error: %v", err)
	}

	if err := bootstrapIfNeeded(cfg, *configPath, pickEnrollToken(*enrollToken), *forceEnroll); err != nil {
		log.Fatalf("bootstrap error: %v", err)
	}

	apiClient, err := client.New(cfg)
	if err != nil {
		log.Fatalf("client error: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	interval := time.Duration(cfg.SyncIntervalSeconds) * time.Second
	log.Printf("keywarden-agent started: server_id=%s interval=%s", cfg.ServerID, interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	runOnce(ctx, apiClient, cfg)

	for {
		select {
		case <-ctx.Done():
			log.Printf("shutdown requested")
			return
		case <-ticker.C:
			runOnce(ctx, apiClient, cfg)
		}
	}
}

func runOnce(ctx context.Context, apiClient *client.Client, cfg *config.Config) {
	if err := reportHost(ctx, apiClient, cfg); err != nil {
		if client.IsRetriable(err) {
			log.Printf("host update deferred; will retry: %v", err)
		} else {
			log.Printf("host update error: %v", err)
			logAgentUnauthorizedHint(err)
		}
	}
	if err := apiClient.SyncAccounts(ctx, cfg); err != nil {
		log.Printf("sync accounts error: %v", err)
		logAgentUnauthorizedHint(err)
	}
	if err := shipLogs(ctx, apiClient, cfg); err != nil {
		if client.IsRetriable(err) {
			log.Printf("log shipping deferred; will retry: %v", err)
		} else {
			log.Printf("log shipping error: %v", err)
			logAgentUnauthorizedHint(err)
		}
	}
}

func logAgentUnauthorizedHint(err error) {
	var statusErr *client.HTTPStatusError
	if errors.As(err, &statusErr) && statusErr.StatusCode == 401 {
		log.Printf(
			"agent auth failed (401): runtime auth is mTLS-first; verify this agent is using the enrolled client cert/key, server_id matches enrollment, and traffic is routed through nginx /api/v1/agent/ so TLS client-cert headers are forwarded. Bearer agent_api_token is optional compatibility metadata, not the primary auth path.",
		)
	}
}

func ensureDirs(cfg *config.Config) error {
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.LogSpoolDir(), 0o700); err != nil {
		return err
	}
	return nil
}

func shipLogs(ctx context.Context, apiClient *client.Client, cfg *config.Config) error {
	send := func(payload []byte) error {
		return retry(ctx, []time.Duration{250 * time.Millisecond, time.Second, 2 * time.Second}, func() error {
			return apiClient.SendLogBatch(ctx, cfg.ServerID, payload)
		})
	}
	if err := logs.DrainSpool(cfg.LogSpoolDir(), send); err != nil {
		return err
	}

	state, err := logs.ReadState(cfg.LogStatePath())
	if err != nil {
		return err
	}
	localSources := toLogSourcesFromConfig(cfg.EnabledLogSources())
	sourceConfig, err := apiClient.FetchLogConfig(ctx, cfg.ServerID)
	var sources []logs.SourceConfig
	if err != nil {
		if len(localSources) == 0 {
			return err
		}
		log.Printf("log config fetch failed; using local log_sources fallback: %v", err)
		sources = localSources
	} else {
		sources = toLogSources(sourceConfig)
		if len(sources) > 0 && len(localSources) > 0 {
			sources = append(sources, localSources...)
		}
	}
	state, err = reconcileLogState(cfg, state, sources)
	if err != nil {
		return err
	}
	collector := logs.NewCollector()
	events, nextState, err := collector.Collect(ctx, cfg.LogBatchSize, sources, state)
	if err != nil {
		if len(sources) > 0 {
			return err
		}
		fallbackSources := defaultFileFallbackSources()
		log.Printf("default journald collection failed; falling back to file monitors: %v", err)
		events, nextState, err = collector.Collect(ctx, cfg.LogBatchSize, fallbackSources, state)
		if err != nil {
			return err
		}
	}
	if len(events) == 0 && len(sources) == 0 {
		fallbackSources := defaultFileFallbackSources()
		log.Printf("default journald yielded no events; trying file monitors")
		fileEvents, fileState, fileErr := collector.Collect(ctx, cfg.LogBatchSize, fallbackSources, nextState)
		if fileErr != nil {
			return fileErr
		}
		events = fileEvents
		nextState = fileState
	}
	if len(events) == 0 {
		if maybeLogNoEventsNotice(len(sources)) && len(sources) == 0 {
			log.Printf("log shipping file fallback probe: %s", describeFileSourceAvailability(defaultFileFallbackSources()))
		}
		return nil
	}
	payload, err := json.Marshal(events)
	if err != nil {
		return err
	}
	if err := send(payload); err != nil {
		if spoolErr := logs.SaveSpool(cfg.LogSpoolDir(), payload); spoolErr != nil {
			return spoolErr
		}
		return err
	}
	if err := logs.WriteState(cfg.LogStatePath(), nextState); err != nil {
		return err
	}
	return nil
}

func reportHost(ctx context.Context, apiClient *client.Client, cfg *config.Config) error {
	info := host.Detect()
	var pingPtr *int
	if pingMs, err := apiClient.Ping(ctx); err == nil {
		pingPtr = &pingMs
	}
	return retry(ctx, []time.Duration{250 * time.Millisecond, time.Second, 2 * time.Second}, func() error {
		return apiClient.UpdateHost(ctx, cfg.ServerID, client.HeartbeatRequest{
			Host:   info.Hostname,
			IPv4:   info.IPv4,
			IPv6:   info.IPv6,
			PingMs: pingPtr,
		})
	})
}

func pickServerURL(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv("KEYWARDEN_SERVER_URL")
}

func pickEnrollToken(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv("KEYWARDEN_ENROLL_TOKEN")
}

func bootstrapIfNeeded(cfg *config.Config, configPath string, enrollToken string, forceEnroll bool) error {
	previousServerID := strings.TrimSpace(cfg.ServerID)
	if !forceEnroll && cfg.ServerID != "" && fileExists(cfg.ClientCertPath()) && fileExists(cfg.CACertPath()) {
		if strings.TrimSpace(enrollToken) != "" {
			log.Printf("enrollment token provided but bootstrap is already complete; skipping enrollment (use -f/--force-enroll to rotate identity)")
		}
		return nil
	}
	if enrollToken == "" {
		return fmt.Errorf("missing enrollment token; set KEYWARDEN_ENROLL_TOKEN or -t/--enroll-token")
	}
	rotateServerID := ""
	if forceEnroll {
		rotateServerID = previousServerID
		if rotateServerID != "" {
			log.Printf("force re-enrollment requested; rotating certificate in-place for server_id=%s", rotateServerID)
		} else {
			log.Printf("force re-enrollment requested; no existing server_id, enrolling as new server identity")
		}
	}
	keyPath := cfg.ClientKeyPath()
	if !fileExists(keyPath) {
		if err := generateKey(keyPath); err != nil {
			return err
		}
	}
	csrPEM, err := buildCSR(keyPath)
	if err != nil {
		return err
	}
	info := host.Detect()
	hostname := info.Hostname
	resp, err := client.Enroll(context.Background(), cfg.ServerURL, client.EnrollRequest{
		Token:    enrollToken,
		CSRPEM:   csrPEM,
		Host:     hostname,
		IPv4:     info.IPv4,
		IPv6:     info.IPv6,
		ServerID: rotateServerID,
	})
	if err != nil {
		return err
	}
	if rotateServerID != "" && strings.TrimSpace(resp.ServerID) != rotateServerID {
		return fmt.Errorf(
			"re-enrollment returned unexpected server_id=%s (expected %s)",
			strings.TrimSpace(resp.ServerID),
			rotateServerID,
		)
	}
	if err := os.WriteFile(cfg.ClientCertPath(), []byte(resp.ClientCert), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(cfg.CACertPath(), []byte(resp.CACert), 0o600); err != nil {
		return err
	}
	cfg.ServerID = resp.ServerID
	if token := strings.TrimSpace(resp.AgentToken); token != "" {
		cfg.AgentAPIToken = token
	}
	if forceEnroll || (previousServerID != "" && previousServerID != cfg.ServerID) {
		if err := resetLogState(cfg); err != nil {
			return fmt.Errorf("reset log state: %w", err)
		}
	}
	if err := config.Save(configPath, cfg); err != nil {
		return err
	}
	return nil
}

func resetLogState(cfg *config.Config) error {
	if err := os.Remove(cfg.LogCursorPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Remove(cfg.LogOffsetsPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Remove(cfg.LogStatePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Remove(logSourceStatePath(cfg)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.RemoveAll(cfg.LogSpoolDir()); err != nil {
		return err
	}
	return os.MkdirAll(cfg.LogSpoolDir(), 0o700)
}

func defaultFileFallbackSources() []logs.SourceConfig {
	return []logs.SourceConfig{
		{Kind: "file", Name: "/var/log/auth.log", FilePath: "/var/log/auth.log", Category: "auth", EventType: "file.line", Parser: "syslog"},
		{Kind: "file", Name: "/var/log/secure", FilePath: "/var/log/secure", Category: "auth", EventType: "file.line", Parser: "syslog"},
		{Kind: "file", Name: "/var/log/syslog", FilePath: "/var/log/syslog", Category: "system", EventType: "file.line", Parser: "syslog"},
		{Kind: "file", Name: "/var/log/messages", FilePath: "/var/log/messages", Category: "system", EventType: "file.line", Parser: "syslog"},
	}
}

func maybeLogNoEventsNotice(sourceCount int) bool {
	now := time.Now()
	if !lastNoEventsNotice.IsZero() && now.Sub(lastNoEventsNotice) < time.Minute {
		return false
	}
	mode := "default journald (current boot)"
	if sourceCount > 0 {
		mode = "configured sources"
	}
	log.Printf("log shipping: no events collected (%s)", mode)
	lastNoEventsNotice = now
	return true
}

func describeFileSourceAvailability(sources []logs.SourceConfig) string {
	items := make([]string, 0, len(sources))
	for _, source := range sources {
		path := strings.TrimSpace(source.FilePath)
		if path == "" {
			path = strings.TrimSpace(source.Name)
		}
		if path == "" {
			continue
		}
		item := path + ": "
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				items = append(items, item+"missing")
				continue
			}
			items = append(items, item+err.Error())
			continue
		}
		if info.IsDir() {
			items = append(items, item+"is directory")
			continue
		}
		file, openErr := os.Open(path)
		if openErr != nil {
			items = append(items, item+openErr.Error())
			continue
		}
		_ = file.Close()
		items = append(items, fmt.Sprintf("%d bytes readable", info.Size()))
	}
	if len(items) == 0 {
		return "no file sources"
	}
	return strings.Join(items, "; ")
}

func reconcileLogState(
	cfg *config.Config,
	state map[string]logs.SourceState,
	sources []logs.SourceConfig,
) (map[string]logs.SourceState, error) {
	statePath := logSourceStatePath(cfg)
	previous, err := os.ReadFile(statePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return state, err
	}
	previousSig := strings.TrimSpace(string(previous))
	currentSig := logSourceSignature(sources)
	needsReset := false
	if previousSig == "" {
		if len(state) > 0 {
			log.Printf("log state signature missing; resetting per-source state for fresh collection")
			needsReset = true
		}
	} else if previousSig != currentSig {
		log.Printf("log sources changed; resetting per-source state for fresh collection")
		needsReset = true
	}
	if err := os.WriteFile(statePath, []byte(currentSig+"\n"), 0o600); err != nil {
		return state, err
	}
	if needsReset {
		return map[string]logs.SourceState{}, nil
	}
	return state, nil
}

func logSourceStatePath(cfg *config.Config) string {
	return cfg.StateDir + "/log.sources.sha256"
}

func logSourceSignature(sources []logs.SourceConfig) string {
	parts := make([]string, 0, len(sources))
	for _, source := range sources {
		parts = append(parts, strings.Join([]string{
			strings.TrimSpace(source.SourceID),
			strings.ToLower(strings.TrimSpace(source.Kind)),
			strings.TrimSpace(source.Name),
			strings.TrimSpace(source.ServiceUnit),
			strings.TrimSpace(source.FilePath),
			strings.ToLower(strings.TrimSpace(source.Parser)),
			strings.TrimSpace(source.Category),
			strings.TrimSpace(source.EventType),
			encodeMatchMap(source.IncludeMatches),
			encodeMatchMap(source.ExcludeMatches),
		}, "\x1f"))
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1e")))
	return hex.EncodeToString(sum[:])
}

func retry(ctx context.Context, delays []time.Duration, fn func() error) error {
	var lastErr error
	for attempt := 0; attempt <= len(delays); attempt++ {
		if attempt > 0 {
			if !client.IsRetriable(lastErr) {
				return lastErr
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delays[attempt-1]):
			}
		}
		if err := fn(); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return lastErr
}

func generateKey(path string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	keyDER := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER}
	data := pem.EncodeToMemory(block)
	return os.WriteFile(path, data, 0o600)
}

func buildCSR(keyPath string) (string, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return "", fmt.Errorf("invalid private key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	csrTemplate := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "keywarden-agent"}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		return "", err
	}
	csrBlock := &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}
	return string(pem.EncodeToMemory(csrBlock)), nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func toLogSources(in []client.LogSourceConfig) []logs.SourceConfig {
	out := make([]logs.SourceConfig, 0, len(in))
	for _, source := range in {
		out = append(out, logs.SourceConfig{
			SourceID:       source.SourceID,
			Kind:           source.Kind,
			Name:           source.Name,
			ServiceUnit:    source.ServiceUnit,
			FilePath:       source.FilePath,
			Parser:         source.Parser,
			IncludeMatches: source.IncludeMatches,
			ExcludeMatches: source.ExcludeMatches,
			Category:       source.Category,
			EventType:      source.EventType,
		})
	}
	return out
}

func toLogSourcesFromConfig(in []config.LogSource) []logs.SourceConfig {
	out := make([]logs.SourceConfig, 0, len(in))
	for _, source := range in {
		out = append(out, logs.SourceConfig{
			SourceID:       source.SourceID,
			Kind:           source.Kind,
			Name:           source.Name,
			ServiceUnit:    source.ServiceUnit,
			FilePath:       source.FilePath,
			Parser:         source.Parser,
			IncludeMatches: source.IncludeMatches,
			ExcludeMatches: source.ExcludeMatches,
			Category:       source.Category,
			EventType:      source.EventType,
		})
	}
	return out
}

func encodeMatchMap(in map[string][]string) string {
	if len(in) == 0 {
		return ""
	}
	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		values := append([]string{}, in[key]...)
		sort.Strings(values)
		parts = append(parts, key+"="+strings.Join(values, ","))
	}
	return strings.Join(parts, ";")
}
