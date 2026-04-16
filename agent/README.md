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
