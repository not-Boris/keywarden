package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"keywarden/agent/internal/accounts"
	"keywarden/agent/internal/config"
)

const defaultTimeout = 15 * time.Second

type Client struct {
	baseURL string
	http    *http.Client
	tlsCfg  *tls.Config
	scheme  string
	host    string
	addr    string
}

func New(cfg *config.Config) (*Client, error) {
	baseURL := strings.TrimRight(cfg.ServerURL, "/")
	if baseURL == "" {
		return nil, errors.New("server url is required")
	}
	cert, err := tls.LoadX509KeyPair(cfg.ClientCertPath(), cfg.ClientKeyPath())
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}
	caPool, err := x509.SystemCertPool()
	if err != nil || caPool == nil {
		caPool = x509.NewCertPool()
	}
	if cfg.ServerCAPath != "" {
		caData, err := os.ReadFile(cfg.ServerCAPath)
		if err != nil {
			return nil, fmt.Errorf("read server ca cert: %w", err)
		}
		if !caPool.AppendCertsFromPEM(caData) {
			return nil, errors.New("parse server ca cert")
		}
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	httpClient := &http.Client{
		Timeout:   defaultTimeout,
		Transport: transport,
	}

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse server url: %w", err)
	}
	if parsed.Host == "" {
		return nil, errors.New("server url missing host")
	}
	scheme := parsed.Scheme
	if scheme == "" {
		scheme = "https"
	}
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		if scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	addr := net.JoinHostPort(host, port)

	return &Client{
		baseURL: baseURL,
		http:    httpClient,
		tlsCfg:  tlsConfig,
		scheme:  scheme,
		host:    host,
		addr:    addr,
	}, nil
}

type EnrollRequest struct {
	Token   string `json:"token"`
	CSRPEM  string `json:"csr_pem"`
	Host    string `json:"host"`
	IPv4    string `json:"ipv4,omitempty"`
	IPv6    string `json:"ipv6,omitempty"`
	AgentID string `json:"agent_id,omitempty"`
}

type EnrollResponse struct {
	ServerID    string `json:"server_id"`
	ClientCert  string `json:"client_cert_pem"`
	CACert      string `json:"ca_cert_pem"`
	SyncProfile string `json:"sync_profile,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
}

type AccountKey struct {
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
}

type AccountAccess struct {
	UserID         int          `json:"user_id"`
	Username       string       `json:"username"`
	Email          string       `json:"email"`
	SystemUsername string       `json:"system_username"`
	Keys           []AccountKey `json:"keys"`
}

type UserCAResponse struct {
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
}

type AccountSyncEntry struct {
	UserID         int    `json:"user_id"`
	SystemUsername string `json:"system_username"`
	Present        bool   `json:"present"`
}

type SyncReportRequest struct {
	AppliedCount int                `json:"applied_count"`
	RevokedCount int                `json:"revoked_count"`
	Message      string             `json:"message,omitempty"`
	Metadata     map[string]any     `json:"metadata,omitempty"`
	Accounts     []AccountSyncEntry `json:"accounts,omitempty"`
}

func Enroll(ctx context.Context, serverURL string, req EnrollRequest) (*EnrollResponse, error) {
	baseURL := strings.TrimRight(serverURL, "/")
	if baseURL == "" {
		return nil, errors.New("server url is required")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encode enroll request: %w", err)
	}
	httpClient := &http.Client{Timeout: defaultTimeout}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/agent/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build enroll request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("enroll request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("enroll failed: status %s", resp.Status)
	}
	var out EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode enroll response: %w", err)
	}
	if out.ServerID == "" || out.ClientCert == "" || out.CACert == "" {
		return nil, errors.New("enroll response missing required fields")
	}
	return &out, nil
}

func (c *Client) SyncAccounts(ctx context.Context, cfg *config.Config) error {
	if cfg == nil {
		return errors.New("config required for account sync")
	}
	ca, err := c.FetchUserCA(ctx, cfg.ServerID)
	if err != nil {
		return err
	}
	if err := accounts.EnsureCA(ca.PublicKey); err != nil {
		return err
	}
	users, err := c.FetchAccountAccess(ctx, cfg.ServerID)
	if err != nil {
		return err
	}
	accessUsers := make([]accounts.AccessUser, 0, len(users))
	for _, user := range users {
		accessUsers = append(accessUsers, accounts.AccessUser{
			UserID:         user.UserID,
			Username:       user.Username,
			Email:          user.Email,
			SystemUsername: user.SystemUsername,
		})
	}
	result, syncErr := accounts.Sync(cfg.AccountPolicy, cfg.StateDir, accessUsers)
	report := SyncReportRequest{
		AppliedCount: result.Applied,
		RevokedCount: result.Revoked,
		Accounts:     make([]AccountSyncEntry, 0, len(result.Accounts)),
	}
	for _, account := range result.Accounts {
		report.Accounts = append(report.Accounts, AccountSyncEntry{
			UserID:         account.UserID,
			SystemUsername: account.SystemUser,
			Present:        account.Present,
		})
	}
	if syncErr != nil {
		report.Message = syncErr.Error()
	}
	if err := c.SendSyncReport(ctx, cfg.ServerID, report); err != nil {
		if syncErr != nil {
			return fmt.Errorf("sync report failed: %w (sync error: %v)", err, syncErr)
		}
		return err
	}
	return syncErr
}

func (c *Client) FetchAccountAccess(ctx context.Context, serverID string) ([]AccountAccess, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		c.baseURL+"/agent/servers/"+serverID+"/accounts",
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("build account access request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch account access: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, &HTTPStatusError{StatusCode: resp.StatusCode, Status: resp.Status}
	}
	var out []AccountAccess
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode account access: %w", err)
	}
	return out, nil
}

func (c *Client) FetchUserCA(ctx context.Context, serverID string) (*UserCAResponse, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		c.baseURL+"/agent/servers/"+serverID+"/ssh-ca",
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("build user ca request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch user ca: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, &HTTPStatusError{StatusCode: resp.StatusCode, Status: resp.Status}
	}
	var out UserCAResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode user ca: %w", err)
	}
	if strings.TrimSpace(out.PublicKey) == "" {
		return nil, errors.New("user ca missing public key")
	}
	return &out, nil
}

func (c *Client) SendSyncReport(ctx context.Context, serverID string, report SyncReportRequest) error {
	body, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("encode sync report: %w", err)
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.baseURL+"/agent/servers/"+serverID+"/sync-report",
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("build sync report: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("send sync report: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return &HTTPStatusError{StatusCode: resp.StatusCode, Status: resp.Status}
	}
	return nil
}

func (c *Client) SendLogBatch(ctx context.Context, serverID string, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/agent/servers/"+serverID+"/logs", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build log request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("send log batch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return &HTTPStatusError{StatusCode: resp.StatusCode, Status: resp.Status}
	}
	return nil
}

type HeartbeatRequest struct {
	Host   string `json:"host,omitempty"`
	IPv4   string `json:"ipv4,omitempty"`
	IPv6   string `json:"ipv6,omitempty"`
	PingMs *int   `json:"ping_ms,omitempty"`
}

func (c *Client) UpdateHost(ctx context.Context, serverID string, reqBody HeartbeatRequest) error {
	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("encode host update: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/agent/servers/"+serverID+"/heartbeat", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build host update: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("send host update: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return &HTTPStatusError{StatusCode: resp.StatusCode, Status: resp.Status}
	}
	return nil
}

func (c *Client) Ping(ctx context.Context) (int, error) {
	if c.addr == "" {
		return 0, errors.New("server address not configured")
	}
	start := time.Now()
	dialer := &net.Dialer{Timeout: defaultTimeout}
	if c.scheme == "http" {
		conn, err := dialer.DialContext(ctx, "tcp", c.addr)
		if err != nil {
			return 0, err
		}
		_ = conn.Close()
		return int(time.Since(start).Milliseconds()), nil
	}
	cfg := c.tlsCfg.Clone()
	if cfg.ServerName == "" && c.host != "" {
		cfg.ServerName = c.host
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", c.addr, cfg)
	if err != nil {
		return 0, err
	}
	_ = conn.Close()
	return int(time.Since(start).Milliseconds()), nil
}
