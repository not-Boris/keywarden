#!/usr/bin/env bash
set -u -o pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ID="${1:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_DIR="${ROOT_DIR}/evidence/runs/${RUN_ID}"
SUMMARY_FILE="${OUT_DIR}/SUMMARY.md"

mkdir -p "${OUT_DIR}"/{meta,runtime,tests,logs,docs}

write_summary() {
  printf "%s\n" "${1-}" >> "${SUMMARY_FILE}"
}

run_capture() {
  local rel_path="$1"
  shift
  local target="${OUT_DIR}/${rel_path}"
  local target_dir
  target_dir="$(dirname "${target}")"
  mkdir -p "${target_dir}"
  if "$@" > "${target}" 2>&1; then
    write_summary "- OK: \`${rel_path}\`"
    return 0
  else
    local rc=$?
    write_summary "- FAIL(${rc}): \`${rel_path}\`"
    return "${rc}"
  fi
}

write_summary "# Evidence Run"
write_summary
write_summary "- Run ID: \`${RUN_ID}\`"
write_summary "- UTC Time: \`$(date -u +"%Y-%m-%dT%H:%M:%SZ")\`"
write_summary "- Host: \`$(hostname)\`"
write_summary "- Root: \`${ROOT_DIR}\`"
write_summary
write_summary "## Capture Status"

run_capture "meta/git-head.txt" git -C "${ROOT_DIR}" rev-parse HEAD
run_capture "meta/git-status.txt" git -C "${ROOT_DIR}" status --short
run_capture "meta/git-log-20.txt" git -C "${ROOT_DIR}" log -n 20 --date=iso --pretty=oneline
run_capture "meta/env-date.txt" date -u

if command -v docker >/dev/null 2>&1; then
  run_capture "runtime/docker-compose-ps.txt" docker compose -f "${ROOT_DIR}/docker-compose.yml" ps
  run_capture "runtime/keywarden-python-version.txt" \
    docker compose -f "${ROOT_DIR}/docker-compose.yml" exec -T keywarden sh -lc "cd /app && python -V"
  run_capture "runtime/keywarden-pip-freeze.txt" \
    docker compose -f "${ROOT_DIR}/docker-compose.yml" exec -T keywarden sh -lc "cd /app && python -m pip freeze"
else
  write_summary "- SKIP: docker not available in PATH"
fi

TEST_TARGETS="apps.accounts.tests.test_auth apps.audit.tests.test_api_audit_middleware apps.servers.tests.test_access_scopes apps.servers.tests.test_audit_pipeline apps.servers.tests.test_consumers apps.servers.tests.test_keys_router"

if command -v docker >/dev/null 2>&1; then
  run_capture "tests/django-tests.txt" \
    docker compose -f "${ROOT_DIR}/docker-compose.yml" exec -T keywarden sh -lc "cd /app && python manage.py test ${TEST_TARGETS} --verbosity 2"
  run_capture "tests/django-tests-failures-summary.txt" \
    sh -lc "grep -E '^(FAIL|ERROR):|^FAILED \\(|^Ran [0-9]+ tests? in' '${OUT_DIR}/tests/django-tests.txt' || true"
  if ! run_capture "tests/coverage-version.txt" \
    docker compose -f "${ROOT_DIR}/docker-compose.yml" exec -T keywarden sh -lc "cd /app && python -m coverage --version"; then
    if run_capture "tests/coverage-install.txt" \
      docker compose -f "${ROOT_DIR}/docker-compose.yml" exec -T keywarden sh -lc "cd /app && python -m pip install coverage"; then
      run_capture "tests/coverage-version.txt" \
        docker compose -f "${ROOT_DIR}/docker-compose.yml" exec -T keywarden sh -lc "cd /app && python -m coverage --version"
    fi
  fi
  if [ -f "${OUT_DIR}/tests/coverage-version.txt" ] && grep -qi "Coverage.py" "${OUT_DIR}/tests/coverage-version.txt"; then
    run_capture "tests/coverage-report.txt" \
      docker compose -f "${ROOT_DIR}/docker-compose.yml" exec -T keywarden sh -lc "cd /app && python -m coverage erase && python -m coverage run manage.py test ${TEST_TARGETS} --verbosity 1; test_rc=\$?; python -m coverage report -m; report_rc=\$?; python -m coverage xml -o /tmp/keywarden-coverage.xml; xml_rc=\$?; exit \$(( test_rc != 0 ? test_rc : ( report_rc != 0 ? report_rc : xml_rc ) ))"
    run_capture "tests/coverage-xml.xml" \
      docker compose -f "${ROOT_DIR}/docker-compose.yml" exec -T keywarden sh -lc "cat /tmp/keywarden-coverage.xml"
  else
    write_summary "- SKIP: coverage module not installed in keywarden container"
  fi
fi

run_capture "docs/rbac-claims.txt" \
  sh -lc "grep -RIn 'operator\\|auditor\\|administrator\\|ROLE_' '${ROOT_DIR}/app/keywarden/api/routers/users.py' '${ROOT_DIR}/app/apps/core/rbac.py' '${ROOT_DIR}/API_DOCS.md'"

if [ -f "${ROOT_DIR}/nginx/logs/agent-access.log" ]; then
  run_capture "logs/agent-access-tail-2000.log" tail -n 2000 "${ROOT_DIR}/nginx/logs/agent-access.log"
  run_capture "logs/agent-endpoint-status-counts.txt" \
    sh -lc "awk -F'\"' '{split(\$3, a, \" \"); if (\$2 != \"\") print \$2 \" \" a[2]}' '${ROOT_DIR}/nginx/logs/agent-access.log' | sort | uniq -c | sort -nr"
fi

if [ -f "${ROOT_DIR}/app/logs/gunicorn-access.log" ]; then
  run_capture "logs/gunicorn-access-tail-2000.log" tail -n 2000 "${ROOT_DIR}/app/logs/gunicorn-access.log"
  run_capture "logs/gunicorn-endpoint-status-counts.txt" \
    sh -lc "awk -F'\"' '{split(\$3, a, \" \"); if (\$2 != \"\") print \$2 \" \" a[2]}' '${ROOT_DIR}/app/logs/gunicorn-access.log' | sort | uniq -c | sort -nr"
fi

if [ -f "${ROOT_DIR}/nginx/logs/error.log" ]; then
  run_capture "logs/nginx-error-tail-1000.log" tail -n 1000 "${ROOT_DIR}/nginx/logs/error.log"
fi

if [ -d "${ROOT_DIR}/evidence/diagrams" ]; then
  mkdir -p "${OUT_DIR}/diagrams"
  run_capture "diagrams/listing.txt" sh -lc "cp '${ROOT_DIR}'/evidence/diagrams/*.mmd '${OUT_DIR}/diagrams/' && ls -1 '${OUT_DIR}/diagrams'"
fi

if [ -d "${ROOT_DIR}/evidence/templates" ]; then
  mkdir -p "${OUT_DIR}/templates"
  run_capture "templates/listing.txt" sh -lc "cp '${ROOT_DIR}'/evidence/templates/*.md '${OUT_DIR}/templates/' && ls -1 '${OUT_DIR}/templates'"
fi

if [ "${KEYWARDEN_EVIDENCE_CAPTURE_SCREENSHOTS:-0}" = "1" ] && [ -x "${ROOT_DIR}/scripts/capture_ui_screenshots.sh" ]; then
  run_capture "screenshots-capture.log" \
    bash "${ROOT_DIR}/scripts/capture_ui_screenshots.sh" "${RUN_ID}"
fi

if [ -x "${ROOT_DIR}/scripts/autofill_evidence_templates.sh" ]; then
  run_capture "templates/autofill.log" \
    bash "${ROOT_DIR}/scripts/autofill_evidence_templates.sh" "${RUN_ID}"
fi

if [ -x "${ROOT_DIR}/scripts/summarize_operational_metrics.sh" ]; then
  run_capture "evaluation/generation.log" \
    bash "${ROOT_DIR}/scripts/summarize_operational_metrics.sh" "${RUN_ID}"
fi

write_summary
write_summary "## Notes"
write_summary "- This run captures operational evidence and test output that can be re-generated."
write_summary "- Screenshot capture can be automated by setting \`KEYWARDEN_EVIDENCE_CAPTURE_SCREENSHOTS=1\`."

printf "Evidence run complete: %s\n" "${OUT_DIR}"
