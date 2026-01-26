package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"keywarden/agent/internal/config"
)

const defaultTimeout = 15 * time.Second

type Client struct {
	baseURL string
	http    *http.Client
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

	return &Client{baseURL: baseURL, http: httpClient}, nil
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

func (c *Client) SyncAccounts(ctx context.Context, serverID string) error {
	_ = ctx
	_ = serverID
	// TODO: call API to fetch account policy + approved access list.
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
	Host string `json:"host,omitempty"`
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
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
