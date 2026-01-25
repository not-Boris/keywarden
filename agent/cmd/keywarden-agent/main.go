package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"keywarden/agent/internal/client"
	"keywarden/agent/internal/config"
	"keywarden/agent/internal/logs"
	"keywarden/agent/internal/version"
)

func main() {
	configPath := flag.String("config", config.DefaultConfigPath, "Path to agent config JSON")
	serverURL := flag.String("server-url", "", "Keywarden server URL (first boot)")
	enrollToken := flag.String("enroll-token", "", "Enrollment token (first boot)")
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

	if err := bootstrapIfNeeded(cfg, *configPath, pickEnrollToken(*enrollToken)); err != nil {
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
	if err := apiClient.SyncAccounts(ctx, cfg.ServerID); err != nil {
		log.Printf("sync accounts error: %v", err)
	}
	if err := shipLogs(ctx, apiClient, cfg); err != nil {
		log.Printf("log shipping error: %v", err)
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
		return apiClient.SendLogBatch(ctx, cfg.ServerID, payload)
	}
	if err := logs.DrainSpool(cfg.LogSpoolDir(), send); err != nil {
		return err
	}

	cursor, err := logs.ReadCursor(cfg.LogCursorPath())
	if err != nil {
		return err
	}
	collector := logs.NewCollector()
	events, nextCursor, err := collector.Collect(ctx, cursor, cfg.LogBatchSize)
	if err != nil {
		return err
	}
	if len(events) == 0 {
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
	if err := logs.WriteCursor(cfg.LogCursorPath(), nextCursor); err != nil {
		return err
	}
	return nil
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

func bootstrapIfNeeded(cfg *config.Config, configPath string, enrollToken string) error {
	if cfg.ServerID != "" && fileExists(cfg.ClientCertPath()) && fileExists(cfg.CACertPath()) {
		return nil
	}
	if enrollToken == "" {
		return fmt.Errorf("missing enrollment token; set KEYWARDEN_ENROLL_TOKEN or -enroll-token")
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
	hostname, _ := os.Hostname()
	resp, err := client.Enroll(context.Background(), cfg.ServerURL, client.EnrollRequest{
		Token:  enrollToken,
		CSRPEM: csrPEM,
		Host:   hostname,
	})
	if err != nil {
		return err
	}
	if err := os.WriteFile(cfg.ClientCertPath(), []byte(resp.ClientCert), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(cfg.CACertPath(), []byte(resp.CACert), 0o600); err != nil {
		return err
	}
	cfg.ServerID = resp.ServerID
	if err := config.Save(configPath, cfg); err != nil {
		return err
	}
	return nil
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
