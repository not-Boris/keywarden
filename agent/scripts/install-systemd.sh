#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Run as root (or via sudo)." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

BIN_SOURCE="${1:-${AGENT_DIR}/keywarden-agent}"
UNIT_SOURCE="${AGENT_DIR}/systemd/keywarden-agent.service"
ENV_SOURCE="${AGENT_DIR}/systemd/keywarden-agent.env.example"

if [[ ! -f "${BIN_SOURCE}" ]]; then
  echo "Agent binary not found: ${BIN_SOURCE}" >&2
  echo "Build it first: go build -o keywarden-agent ./cmd/keywarden-agent" >&2
  exit 1
fi

if [[ ! -f "${UNIT_SOURCE}" ]]; then
  echo "Unit file not found: ${UNIT_SOURCE}" >&2
  exit 1
fi

install -D -m 0755 "${BIN_SOURCE}" /usr/local/bin/keywarden-agent
install -D -m 0644 "${UNIT_SOURCE}" /etc/systemd/system/keywarden-agent.service

if [[ ! -f /etc/default/keywarden-agent ]]; then
  install -D -m 0640 "${ENV_SOURCE}" /etc/default/keywarden-agent
fi

mkdir -p /etc/keywarden
if [[ ! -f /etc/keywarden/agent.json ]]; then
  cat > /etc/keywarden/agent.json <<'EOF'
{
  "server_url": "https://keywarden.example.com/api/v1"
}
EOF
  chmod 0600 /etc/keywarden/agent.json
fi

systemctl daemon-reload

cat <<'EOF'
Installed:
  - /usr/local/bin/keywarden-agent
  - /etc/systemd/system/keywarden-agent.service
  - /etc/default/keywarden-agent (if it did not already exist)
  - /etc/keywarden/agent.json (bootstrap file, if it did not already exist)

Next steps:
  1) Edit /etc/default/keywarden-agent and set KEYWARDEN_SERVER_URL + KEYWARDEN_ENROLL_TOKEN.
  2) (Optional) Edit /etc/keywarden/agent.json with additional settings.
  3) Enable and start:
       systemctl enable --now keywarden-agent
  4) Check status/logs:
       systemctl status keywarden-agent
       journalctl -u keywarden-agent -f
EOF
