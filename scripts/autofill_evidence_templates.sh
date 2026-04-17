#!/usr/bin/env bash
set -u -o pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ARG="${1:-}"

if [ -n "${RUN_ARG}" ]; then
  if [ -d "${RUN_ARG}" ]; then
    RUN_DIR="${RUN_ARG}"
  else
    RUN_DIR="${ROOT_DIR}/evidence/runs/${RUN_ARG}"
  fi
else
  RUN_DIR="$(ls -1dt "${ROOT_DIR}"/evidence/runs/* 2>/dev/null | head -n 1)"
fi

if [ -z "${RUN_DIR:-}" ] || [ ! -d "${RUN_DIR}" ]; then
  echo "Run directory not found." >&2
  exit 1
fi

RUN_ID="$(basename "${RUN_DIR}")"
TEMPLATE_DIR="${RUN_DIR}/templates"
mkdir -p "${TEMPLATE_DIR}"

SUMMARY_FILE="${RUN_DIR}/SUMMARY.md"
TEST_FILE="${RUN_DIR}/tests/django-tests.txt"
FAIL_SUMMARY_FILE="${RUN_DIR}/tests/django-tests-failures-summary.txt"
COVERAGE_FILE="${RUN_DIR}/tests/coverage-report.txt"
LOG_COUNTS_FILE="${RUN_DIR}/logs/agent-endpoint-status-counts.txt"
COMMIT_FILE="${RUN_DIR}/meta/git-head.txt"
SCREENSHOT_DIR="${RUN_DIR}/screenshots"

utc_time="$(grep -m1 '^- UTC Time:' "${SUMMARY_FILE}" 2>/dev/null | sed -E 's/.*`([^`]*)`.*/\1/')"
if [ -z "${utc_time}" ]; then
  utc_time="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
fi

commit_full="$(head -n 1 "${COMMIT_FILE}" 2>/dev/null || true)"
if [ -z "${commit_full}" ]; then
  commit_full="unknown"
fi
commit_short="$(printf "%s" "${commit_full}" | cut -c1-12)"

env_domain="$(grep -m1 '^KEYWARDEN_DOMAIN=' "${ROOT_DIR}/.env" 2>/dev/null | cut -d'=' -f2-)"
if [ -z "${env_domain}" ]; then
  env_domain="$(grep -m1 '^KEYWARDEN_DOMAIN=' "${ROOT_DIR}/.env.example" 2>/dev/null | cut -d'=' -f2-)"
fi
if [ -z "${env_domain}" ]; then
  env_url="(set manually)"
elif printf "%s" "${env_domain}" | grep -qE '^https?://'; then
  env_url="${env_domain}"
else
  env_url="https://${env_domain}"
fi

tests_line="$(grep -E '^Ran [0-9]+ tests? in' "${TEST_FILE}" 2>/dev/null | tail -n 1)"
tests_status="$(grep -E '^(OK|FAILED.*)$' "${TEST_FILE}" 2>/dev/null | tail -n 1)"
if [ -z "${tests_line}" ]; then
  tests_line="Ran ? tests in ?s"
fi
if [ -z "${tests_status}" ]; then
  tests_status="Unknown"
fi

failure_summary="$(cat "${FAIL_SUMMARY_FILE}" 2>/dev/null || true)"
if [ -z "${failure_summary}" ]; then
  failure_summary="No failure summary captured."
fi

coverage_total_line="$(grep -E '^TOTAL[[:space:]]+' "${COVERAGE_FILE}" 2>/dev/null | tail -n 1)"
if [ -n "${coverage_total_line}" ]; then
  coverage_stmts="$(printf "%s\n" "${coverage_total_line}" | awk '{print $2}')"
  coverage_miss="$(printf "%s\n" "${coverage_total_line}" | awk '{print $3}')"
  coverage_pct="$(printf "%s\n" "${coverage_total_line}" | awk '{print $4}')"
else
  coverage_stmts="?"
  coverage_miss="?"
  coverage_pct="N/A"
fi

host_key_status="Manual"
host_key_note="Check shell SSH options in source."
if grep -q 'StrictHostKeyChecking=no' "${ROOT_DIR}/app/apps/servers/consumers.py" 2>/dev/null; then
  host_key_status="FAIL (auto)"
  host_key_note="Strict host key checking is disabled in shell command builder."
elif grep -q 'UserKnownHostsFile=/dev/null' "${ROOT_DIR}/app/apps/servers/consumers.py" 2>/dev/null \
  || grep -q 'GlobalKnownHostsFile=/dev/null' "${ROOT_DIR}/app/apps/servers/consumers.py" 2>/dev/null; then
  host_key_status="FAIL (auto)"
  host_key_note="Known-hosts verification is bypassed via /dev/null host-key files."
elif grep -q 'StrictHostKeyChecking=' "${ROOT_DIR}/app/apps/servers/consumers.py" 2>/dev/null \
  && grep -q 'UpdateHostKeys=yes' "${ROOT_DIR}/app/apps/servers/consumers.py" 2>/dev/null; then
  host_key_status="PASS (auto)"
  host_key_note="Host-key checking is enabled and host key updates are requested."
fi

test_result() {
  local test_name="$1"
  if grep -q "${test_name}.*ok" "${TEST_FILE}" 2>/dev/null; then
    printf "PASS (auto)"
    return
  fi
  if grep -q "${test_name}.*FAIL" "${TEST_FILE}" 2>/dev/null; then
    printf "FAIL (auto)"
    return
  fi
  if grep -q "${test_name}" "${TEST_FILE}" 2>/dev/null; then
    printf "Observed (review)"
    return
  fi
  printf "Not covered"
}

sec03_status="$(test_result "test_ingest_logs_rejects_mtls_cert_for_different_server")"
sec03_actual="Agent mTLS certificate/server binding mismatch test present in Django suite."
sec04_status="$(test_result "test_detail_view_denied_when_users_scope_not_granted")"
sec04_actual="Permission-boundary denial test present in Django suite."
sec08_status="Manual"
sec08_actual="No dedicated WebSocket auth negative test was auto-detected."
sec05_status="$(test_result "test_admin_dashboard_requires_admin")"
sec05_actual="Unauthorized UI route redirects to disguised target (dashboard)."

append_path() {
  local current="$1"
  local next="$2"
  if [ -z "${next}" ]; then
    printf "%s" "${current}"
    return
  fi
  if [ -z "${current}" ]; then
    printf "%s" "${next}"
    return
  fi
  printf "%s, %s" "${current}" "${next}"
}

screenshot_count="0"
if [ -d "${SCREENSHOT_DIR}" ]; then
  screenshot_count="$(find "${SCREENSHOT_DIR}" -maxdepth 1 -type f -name '*.png' | wc -l | tr -d ' ')"
fi

e_login=""
[ -f "${SCREENSHOT_DIR}/01-login-entry.png" ] && e_login="$(append_path "${e_login}" "screenshots/01-login-entry.png")"
[ -f "${SCREENSHOT_DIR}/02-login-native.png" ] && e_login="$(append_path "${e_login}" "screenshots/02-login-native.png")"
e_dashboard=""
[ -f "${SCREENSHOT_DIR}/03-dashboard.png" ] && e_dashboard="screenshots/03-dashboard.png"
e_key_upload=""
[ -f "${SCREENSHOT_DIR}/04-profile.png" ] && e_key_upload="screenshots/04-profile.png"
e_server_reg=""
[ -f "${SCREENSHOT_DIR}/07-admin-server-reg.png" ] && e_server_reg="screenshots/07-admin-server-reg.png"
e_access_queue=""
[ -f "${SCREENSHOT_DIR}/06-admin-dashboard.png" ] && e_access_queue="screenshots/06-admin-dashboard.png"
e_audit=""
[ -f "${SCREENSHOT_DIR}/09-server-audit.png" ] && e_audit="screenshots/09-server-audit.png"
e_server_detail=""
[ -f "${SCREENSHOT_DIR}/08-server-detail.png" ] && e_server_detail="screenshots/08-server-detail.png"
e_shell=""
[ -f "${SCREENSHOT_DIR}/11-server-shell.png" ] && e_shell="screenshots/11-server-shell.png"

cat > "${TEMPLATE_DIR}/browser-matrix.md" <<EOF
# Browser Test Matrix

## Autofill Summary

- Run ID: \`${RUN_ID}\`
- Date (UTC): \`${utc_time}\`
- Environment URL: \`${env_url}\`
- Commit: \`${commit_full}\`
- Automated tests: ${tests_line} (${tests_status})
- Coverage: ${coverage_pct} (${coverage_stmts} stmts, ${coverage_miss} missed)
- Screenshot files detected: ${screenshot_count}

## How To Complete

1. Use one browser at a time and run every row end-to-end.
2. In each browser column, enter one of: \`PASS\`, \`FAIL\`, \`PARTIAL\`, or \`N/A\`.
3. Put a short failure symptom in \`Notes\` (for example: "OIDC callback loop").
4. Put concrete evidence file paths in \`Evidence Path\` (screenshots, HAR, console logs).
5. Keep timestamps in filenames so evidence can be traced to this run.

## Matrix

| Area | Chrome | Firefox | Safari | Edge | Notes | Evidence Path |
|---|---|---|---|---|---|---|
| Login / OIDC |  |  |  |  |  | ${e_login} |
| Dashboard |  |  |  |  |  | ${e_dashboard} |
| Key upload |  |  |  |  |  | ${e_key_upload} |
| Server registration |  |  |  |  |  | ${e_server_reg} |
| Access approve/revoke |  |  |  |  |  | ${e_access_queue} |
| Audit logs |  |  |  |  |  | ${e_audit} |
| Server detail + heartbeat |  |  |  |  |  | ${e_server_detail} |
| Browser shell page render |  |  |  |  |  | ${e_shell} |
| Browser shell interactive session |  |  |  |  |  |  |

EOF

cat > "${TEMPLATE_DIR}/security-test-report.md" <<EOF
# Security Test Report

## Autofill Summary

- Run ID: \`${RUN_ID}\`
- Date (UTC): \`${utc_time}\`
- Environment URL: \`${env_url}\`
- Commit: \`${commit_full}\`
- Django suite summary: ${tests_line} (${tests_status})
- Failure summary source: \`tests/django-tests-failures-summary.txt\`
- Coverage source: \`tests/coverage-report.txt\`

## How To Complete

1. Keep autofilled values unless the underlying test evidence changes.
2. For each row, set \`Pass/Fail\` to \`PASS\`, \`FAIL\`, \`PARTIAL\`, or \`N/A\`.
3. Replace generic \`Actual\` text with concrete observations (status codes, error text).
4. Add exact artifact paths for every completed row.
5. Write findings as evidence-backed statements only.

## Scope

- Authentication and session handling
- Authorization boundaries
- Token handling
- Input validation
- File/command safety
- WebSocket controls

## Test Cases

| ID | Area | Test | Expected | Actual | Pass/Fail | Evidence Path |
|---|---|---|---|---|---|---|
| SEC-01 | Input validation | Submit malformed SSH key payload | 4xx with validation error | Not auto-detected in current suite | Manual |  |
| SEC-02 | Auth bypass | Call admin API as non-admin | 403 | Not auto-detected in current suite | Manual |  |
| SEC-03 | mTLS misuse | Use mismatched agent client certificate | 401/403 | ${sec03_actual} | ${sec03_status} | tests/django-tests.txt |
| SEC-04 | Object permission | Access server not granted to user | denied response | ${sec04_actual} | ${sec04_status} | tests/django-tests.txt |
| SEC-05 | Session/CSRF | Unsafe method without CSRF/session validity | blocked or redirected | ${sec05_actual} | ${sec05_status} | tests/django-tests.txt |
| SEC-06 | File handling | Upload invalid file/path content | Rejected safely | Not auto-detected in current suite | Manual |  |
| SEC-07 | Command injection | Shell input escaping checks | No command injection path | Partial automated shell command tests exist | Manual | tests/django-tests.txt |
| SEC-08 | WebSocket shell auth | Open shell WS without scope | Rejected | ${sec08_actual} | ${sec08_status} |  |
| SEC-09 | Host key verification | Shell verifies host identity | Verified | ${host_key_note} | ${host_key_status} | app/apps/servers/consumers.py |

## Findings

- High:
- Medium:
- Low:

## Follow-up Actions

- 

EOF

cat > "${TEMPLATE_DIR}/standards-checklist.md" <<EOF
# Standards Checklist

## Autofill Summary

- Run ID: \`${RUN_ID}\`
- Date (UTC): \`${utc_time}\`
- Environment URL: \`${env_url}\`
- Commit: \`${commit_full}\`
- Test summary: ${tests_line} (${tests_status})
- Coverage summary: ${coverage_pct}

## How To Complete

1. Treat autofilled \`Status\` values as initial evidence flags, not final compliance.
2. Replace status with one of: \`Meets\`, \`Partially Meets\`, \`Does Not Meet\`, \`Not Evaluated\`.
3. Keep evidence paths concrete and local to this run where possible.
4. In \`Notes\`, explain why each control is or is not met.
5. Keep \`Gap Summary\` short and directly tied to failed/partial controls.

## OWASP ASVS (selected)

| Control | Requirement | Status | Evidence Path | Notes |
|---|---|---|---|---|
| V1 | Architecture/design documented | Auto: Evidence present | diagrams/listing.txt | Diagram sources copied into run artifacts |
| V2 | Authentication controls | Auto: Evidence present | tests/django-tests.txt | Auth/account tests are present; final compliance needs manual judgment |
| V3 | Session management | Auto: Partial evidence | tests/django-tests.txt | Access denial behavior covered; full session-hardening review still manual |
| V4 | Access control enforcement | Auto: Evidence present | tests/django-tests.txt | Scope and permission boundary tests present |
| V5 | Input validation and encoding | Auto: Partial evidence | tests/django-tests.txt | Some validation paths covered; broad input fuzzing not automated |
| V7 | Error handling and logging | Auto: Evidence present | logs/gunicorn-access-tail-2000.log | Runtime logs are captured in every run |
| V8 | Data protection at rest/in transit | Auto: Partial evidence | runtime/docker-compose-ps.txt | TLS/database setup exists; key-material risk analysis remains manual |
| V10 | Malicious code / injection resistance | Auto: Partial evidence | tests/django-tests.txt | Some shell-related tests present; full security testing remains manual |

## NIST SP 800-53 / 800-63-aligned checks (selected)

| Control Family | Requirement | Status | Evidence Path | Notes |
|---|---|---|---|---|
| AC | Least privilege / access enforcement | Auto: Evidence present | tests/django-tests.txt | Access scope and object-permission tests present |
| AU | Auditable events and retention | Auto: Evidence present | logs/agent-access-tail-2000.log | Audit and runtime logs captured |
| IA | Identity proofing and authentication federation | Auto: Partial evidence | tests/django-tests.txt | Auth flows tested; federation assurance still manual |
| SC | Cryptographic protections and key handling | Auto: Partial evidence | app/apps/servers/consumers.py | Host-key verification gap still open |
| CM | Configuration and change management | Auto: Evidence present | meta/git-head.txt | Commit and repo state captured per run |
| CP | Resilience / single point of failure acknowledgement | Auto: Partial evidence | SUMMARY.md | Availability risks identified but not fully mitigated |

## Gap Summary

- Host key verification remains a known shell security gap.
- Full WebSocket shell security testing is not yet automated.
- Standards mapping still requires manual final classification per control.

EOF

echo "Autofilled templates for run: ${RUN_ID}"
