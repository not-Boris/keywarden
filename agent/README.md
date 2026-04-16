TODO: Move to boris/keywarden-agent. In main repo for now for development.

# keywarden-agent

Minimal Go agent for Keywarden.

## Build

```
go build -o keywarden-agent ./cmd/keywarden-agent
```

## Run

```
./keywarden-agent -config /etc/keywarden/agent.json -server-url https://keywarden.example.com -enroll-token <token>
```

To rotate/re-enroll an existing agent identity, add `-force-enroll` with a fresh token.

You can also pass `KEYWARDEN_SERVER_URL` and `KEYWARDEN_ENROLL_TOKEN` as environment variables.

## systemd service (portable)

The repo includes a reusable unit file and installer:

- Unit: `systemd/keywarden-agent.service`
- Env template: `systemd/keywarden-agent.env.example`
- Installer: `scripts/install-systemd.sh`

### Quick install

From this `agent/` directory:

```bash
go build -o keywarden-agent ./cmd/keywarden-agent
sudo ./scripts/install-systemd.sh
sudoedit /etc/default/keywarden-agent
sudo systemctl enable --now keywarden-agent
```

### Manual install

```bash
sudo install -D -m 0755 ./keywarden-agent /usr/local/bin/keywarden-agent
sudo install -D -m 0644 ./systemd/keywarden-agent.service /etc/systemd/system/keywarden-agent.service
sudo install -D -m 0640 ./systemd/keywarden-agent.env.example /etc/default/keywarden-agent
sudo mkdir -p /etc/keywarden
sudo bash -c 'cat > /etc/keywarden/agent.json <<EOF
{
  "server_url": "https://keywarden.example.com/api/v1"
}
EOF'
sudo chmod 0600 /etc/keywarden/agent.json
sudo systemctl daemon-reload
sudo systemctl enable --now keywarden-agent
```

### First boot behavior

- If `/etc/keywarden/agent.json` does not exist, set `KEYWARDEN_SERVER_URL` in `/etc/default/keywarden-agent`.
- For first enrollment, set `KEYWARDEN_ENROLL_TOKEN` in `/etc/default/keywarden-agent`.
- After successful enrollment, `server_id` and `agent_api_token` are written to `agent.json`.
- You can remove `KEYWARDEN_ENROLL_TOKEN` from `/etc/default/keywarden-agent` after enrollment.

### Service operations

```bash
sudo systemctl status keywarden-agent
sudo journalctl -u keywarden-agent -f
sudo systemctl restart keywarden-agent
```

## Config

On first boot, the agent will create a config file if it does not exist. Only `server_url` is required for bootstrapping.
Do not prefill `server_id` or `agent_api_token` with placeholders; those are written by enrollment.

If the Keywarden server uses a private TLS CA, set `server_ca_path` (or `KEYWARDEN_SERVER_CA_PATH`) to the CA PEM file so the agent can verify the server certificate.
`agent_api_token` is issued by `/agent/enroll` and persisted into `agent.json` automatically.
Use the raw token value (no `Bearer ` prefix). If `KEYWARDEN_AGENT_API_TOKEN` env var is set, it overrides `agent_api_token` in `agent.json`.
When no `log_sources` are configured, the agent defaults to journald collection via `go-systemd/sdjournal` and backfills from the start of the current boot on first sync.
If journald is unavailable, the agent falls back to common system log files (`/var/log/auth.log`, `/var/log/secure`, `/var/log/syslog`, `/var/log/messages`).

`log_sources` can be defined locally for service/file monitors. These are used as:
- fallback if central `/agent/servers/{id}/log-config` cannot be fetched
- additive sources when central config defines one or more explicit sources

If central `log-config` returns an empty list, the agent uses default journald
collection from the current boot and ignores local `log_sources` for that run.

See `config.example.json`.

For package alternatives and external collector options, see `LOGGING_PACKAGES.md`.
