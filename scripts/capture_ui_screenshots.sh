#!/usr/bin/env bash
set -eu -o pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ARG="${1:-}"

if [ -n "${RUN_ARG}" ]; then
  if [ -d "${RUN_ARG}" ]; then
    RUN_DIR="${RUN_ARG}"
    RUN_ID="$(basename "${RUN_DIR}")"
  else
    RUN_ID="${RUN_ARG}"
    RUN_DIR="${ROOT_DIR}/evidence/runs/${RUN_ID}"
  fi
else
  RUN_DIR="$(ls -1dt "${ROOT_DIR}"/evidence/runs/* 2>/dev/null | head -n 1)"
  RUN_ID="$(basename "${RUN_DIR}")"
fi

if [ -z "${RUN_DIR:-}" ] || [ ! -d "${RUN_DIR}" ]; then
  echo "Run directory not found." >&2
  exit 1
fi

BASE_URL="${KEYWARDEN_SCREENSHOT_BASE_URL:-}"
ADMIN_USER="${KEYWARDEN_ADMIN_USERNAME:-}"
ADMIN_EMAIL="${KEYWARDEN_ADMIN_EMAIL:-}"
ADMIN_PASS="${KEYWARDEN_ADMIN_PASSWORD:-}"
SERVER_ID="${KEYWARDEN_SCREENSHOT_SERVER_ID:-}"

if [ -f "${ROOT_DIR}/.env" ]; then
  if [ -z "${BASE_URL}" ]; then
    DOMAIN_LINE="$(grep -m1 '^KEYWARDEN_DOMAIN=' "${ROOT_DIR}/.env" || true)"
    DOMAIN_VALUE="${DOMAIN_LINE#KEYWARDEN_DOMAIN=}"
    if [ -n "${DOMAIN_VALUE}" ]; then
      if printf "%s" "${DOMAIN_VALUE}" | grep -qE '^https?://'; then
        BASE_URL="${DOMAIN_VALUE}"
      else
        BASE_URL="https://${DOMAIN_VALUE}"
      fi
    fi
  fi
  if [ -z "${ADMIN_USER}" ]; then
    USER_LINE="$(grep -m1 '^KEYWARDEN_ADMIN_USERNAME=' "${ROOT_DIR}/.env" || true)"
    ADMIN_USER="${USER_LINE#KEYWARDEN_ADMIN_USERNAME=}"
  fi
  if [ -z "${ADMIN_EMAIL}" ]; then
    EMAIL_LINE="$(grep -m1 '^KEYWARDEN_ADMIN_EMAIL=' "${ROOT_DIR}/.env" || true)"
    ADMIN_EMAIL="${EMAIL_LINE#KEYWARDEN_ADMIN_EMAIL=}"
  fi
  if [ -z "${ADMIN_PASS}" ]; then
    PASS_LINE="$(grep -m1 '^KEYWARDEN_ADMIN_PASSWORD=' "${ROOT_DIR}/.env" || true)"
    ADMIN_PASS="${PASS_LINE#KEYWARDEN_ADMIN_PASSWORD=}"
  fi
fi

if [ -z "${BASE_URL}" ]; then
  BASE_URL="https://localhost"
fi
if [ -z "${ADMIN_USER}" ]; then
  ADMIN_USER="admin"
fi
if [ -z "${ADMIN_EMAIL}" ]; then
  ADMIN_EMAIL="admin@example.com"
fi
if [ -z "${ADMIN_PASS}" ]; then
  echo "Missing KEYWARDEN_ADMIN_PASSWORD (env or .env)." >&2
  exit 1
fi
if [ -z "${SERVER_ID}" ] && [ -f "${RUN_DIR}/logs/agent-endpoint-status-counts.txt" ]; then
  SERVER_ID="$(
    sed -n 's#.*servers/\([0-9][0-9]*\)/.*#\1#p' "${RUN_DIR}/logs/agent-endpoint-status-counts.txt" \
      | head -n 1
  )"
fi

CONTAINER_TOOL_DIR="/tmp/keywarden-evidence-tools"
CONTAINER_OUT_DIR="/app/.evidence-screens/${RUN_ID}"
HOST_TMP_OUT_DIR="${ROOT_DIR}/app/.evidence-screens/${RUN_ID}"
HOST_FINAL_OUT_DIR="${RUN_DIR}/screenshots"

docker compose exec -T \
  -e KEYWARDEN_SCREENSHOT_BASE_URL="${BASE_URL}" \
  -e KEYWARDEN_ADMIN_USERNAME="${ADMIN_USER}" \
  -e KEYWARDEN_ADMIN_EMAIL="${ADMIN_EMAIL}" \
  -e KEYWARDEN_ADMIN_PASSWORD="${ADMIN_PASS}" \
  -e KEYWARDEN_SCREENSHOT_SERVER_ID="${SERVER_ID}" \
  keywarden sh -lc "
    set -eu
    mkdir -p '${CONTAINER_TOOL_DIR}' '${CONTAINER_OUT_DIR}'
    if [ ! -f '${CONTAINER_TOOL_DIR}/package.json' ]; then
      cd '${CONTAINER_TOOL_DIR}'
      npm init -y >/dev/null 2>&1
      npm pkg set private=true >/dev/null 2>&1
      npm pkg set type=module >/dev/null 2>&1
    fi
    if [ ! -d '${CONTAINER_TOOL_DIR}/node_modules/playwright' ]; then
      cd '${CONTAINER_TOOL_DIR}'
      npm install --silent playwright@1.53.0
    fi
    ln -sfn '${CONTAINER_TOOL_DIR}/node_modules' /app/scripts/node_modules
    cd '${CONTAINER_TOOL_DIR}'
    if [ ! -f '${CONTAINER_TOOL_DIR}/.deps-ok' ]; then
      if ! npx playwright install-deps chromium >/dev/null 2>&1; then
        apt-get update >/dev/null
        apt-get install -y --no-install-recommends \
          libglib2.0-0 \
          libdbus-1-3 \
          libatk1.0-0 \
          libatk-bridge2.0-0 \
          libatspi2.0-0 \
          libcups2 \
          libxcb1 \
          libxkbcommon0 \
          libx11-6 \
          libxcomposite1 \
          libxdamage1 \
          libxext6 \
          libxfixes3 \
          libxrandr2 \
          libgbm1 \
          libcairo2 \
          libpango-1.0-0 \
          libasound2 >/dev/null
      fi
      touch '${CONTAINER_TOOL_DIR}/.deps-ok'
    fi
    npx playwright install chromium >/dev/null
    cd /app
    python manage.py shell -c \"import os; from django.contrib.auth import get_user_model; U=get_user_model(); username=os.environ['KEYWARDEN_ADMIN_USERNAME']; email=os.environ.get('KEYWARDEN_ADMIN_EMAIL','admin@example.com'); password=os.environ['KEYWARDEN_ADMIN_PASSWORD']; user, created = U.objects.get_or_create(username=username, defaults={'email': email}); user.email = ((user.email or email) if created else user.email); user.is_active=True; user.is_staff=True; user.is_superuser=True; user.set_password(password); user.save(); print('ensured-screenshot-admin', user.username, 'created=' + str(created))\"
    node /app/scripts/capture_ui_screenshots.mjs '${CONTAINER_OUT_DIR}'
  "

rm -rf "${HOST_FINAL_OUT_DIR}"
mkdir -p "${HOST_FINAL_OUT_DIR}"
cp -R "${HOST_TMP_OUT_DIR}/." "${HOST_FINAL_OUT_DIR}/"
ls -1 "${HOST_FINAL_OUT_DIR}" > "${HOST_FINAL_OUT_DIR}/listing.txt"

echo "Screenshots captured for run ${RUN_ID}: ${HOST_FINAL_OUT_DIR}"
