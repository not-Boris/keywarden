# keywarden-agent

Minimal Go agent scaffold for Keywarden.

## Build

```
go build -o keywarden-agent ./cmd/keywarden-agent
```

## Run

```
./keywarden-agent -config /etc/keywarden/agent.json -server-url https://keywarden.example.com -enroll-token <token>
```

You can also pass `KEYWARDEN_SERVER_URL` and `KEYWARDEN_ENROLL_TOKEN` as environment variables.

## Config

On first boot, the agent will create a config file if it does not exist. Only `server_url` is required for bootstrapping.

See `config.example.json`.
