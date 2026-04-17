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
OUT_DIR="${RUN_DIR}/evaluation"
mkdir -p "${OUT_DIR}"

AGENT_LOG="${RUN_DIR}/logs/agent-access-tail-2000.log"
NGINX_ERROR_LOG="${RUN_DIR}/logs/nginx-error-tail-1000.log"
SUMMARY_MD="${OUT_DIR}/operational-summary.md"
PARSED_CSV="${OUT_DIR}/agent-access-parsed.csv"
HEARTBEAT_EVENTS="${OUT_DIR}/heartbeat-events.csv"
HEARTBEAT_INTERVALS="${OUT_DIR}/heartbeat-intervals.csv"
HEARTBEAT_SUMMARY="${OUT_DIR}/heartbeat-summary.csv"
HEARTBEAT_RECOVERY="${OUT_DIR}/heartbeat-error-recovery.csv"
ENDPOINT_STATUS_COUNTS="${OUT_DIR}/endpoint-status-by-server.csv"

if [ ! -f "${AGENT_LOG}" ]; then
  cat > "${SUMMARY_MD}" <<EOF
# Operational Metrics Summary

- Run ID: \`${RUN_ID}\`
- Status: No \`logs/agent-access-tail-2000.log\` found for this run.

EOF
  echo "Operational metrics summary written: ${SUMMARY_MD}"
  exit 0
fi

awk '
BEGIN {
  OFS = ","
  print "raw_timestamp,server_id,method,path,status,bytes,client_ip"
}
{
  client_ip = $1
  left_bracket = index($0, "[")
  right_bracket = index($0, "]")
  if (left_bracket == 0 || right_bracket <= left_bracket) {
    next
  }
  raw_ts = substr($0, left_bracket + 1, right_bracket - left_bracket - 1)
  quote_count = split($0, quoted, "\"")
  if (quote_count < 3) {
    next
  }
  split(quoted[2], req_parts, " ")
  method = req_parts[1]
  path = req_parts[2]
  if (path == "") {
    next
  }
  split(path, segments, "/")
  server_id = ""
  for (i = 1; i <= length(segments); i++) {
    if (segments[i] == "servers" && (i + 1) <= length(segments)) {
      server_id = segments[i + 1]
      break
    }
  }
  if (server_id == "" || server_id !~ /^[0-9]+$/) {
    next
  }
  split(quoted[3], tail_parts)
  status = tail_parts[1]
  bytes = tail_parts[2]
  print raw_ts, server_id, method, path, status, bytes, client_ip
}
' "${AGENT_LOG}" > "${PARSED_CSV}"

echo "server_id,epoch,raw_timestamp,status" > "${HEARTBEAT_EVENTS}"
rm -f "${OUT_DIR}/heartbeat-events-raw.tmp"
tail -n +2 "${PARSED_CSV}" | while IFS=',' read -r raw_ts server_id method path status bytes client_ip; do
  case "${path}" in
    */heartbeat)
      normalized_ts="$(printf "%s" "${raw_ts}" | sed -E 's#^([0-9]{2})/([A-Za-z]{3})/([0-9]{4}):([0-9]{2}:[0-9]{2}:[0-9]{2}) ([+-][0-9]{4})$#\1 \2 \3 \4 \5#')"
      epoch="$(date -u -d "${normalized_ts}" +%s 2>/dev/null || true)"
      if [ -n "${epoch}" ]; then
        printf "%s,%s,%s,%s\n" "${server_id}" "${epoch}" "${raw_ts}" "${status}" >> "${OUT_DIR}/heartbeat-events-raw.tmp"
      fi
      ;;
  esac
done
if [ -f "${OUT_DIR}/heartbeat-events-raw.tmp" ]; then
  sort -t, -k1,1n -k2,2n "${OUT_DIR}/heartbeat-events-raw.tmp" >> "${HEARTBEAT_EVENTS}"
else
  : > "${OUT_DIR}/heartbeat-events-raw.tmp"
fi

awk -F',' -v intervals_file="${HEARTBEAT_INTERVALS}" -v summary_file="${HEARTBEAT_SUMMARY}" '
BEGIN {
  print "server_id,from_timestamp,to_timestamp,interval_seconds,from_status,to_status" > intervals_file
}
NR == 1 {
  next
}
{
  server_id = $1
  epoch = $2 + 0
  raw_ts = $3
  status = $4 + 0
  event_count[server_id]++
  if (status >= 500) {
    error_count[server_id]++
  }
  if (server_id in prev_epoch) {
    interval = epoch - prev_epoch[server_id]
    if (interval >= 0) {
      print server_id "," prev_ts[server_id] "," raw_ts "," interval "," prev_status[server_id] "," status >> intervals_file
      interval_count[server_id]++
      interval_sum[server_id] += interval
      if (!(server_id in interval_min) || interval < interval_min[server_id]) {
        interval_min[server_id] = interval
      }
      if (!(server_id in interval_max) || interval > interval_max[server_id]) {
        interval_max[server_id] = interval
      }
    }
  }
  prev_epoch[server_id] = epoch
  prev_ts[server_id] = raw_ts
  prev_status[server_id] = status
}
END {
  print "server_id,heartbeat_events,interval_samples,avg_interval_s,min_interval_s,max_interval_s,heartbeat_5xx" > summary_file
  for (server_id in event_count) {
    avg = interval_count[server_id] ? interval_sum[server_id] / interval_count[server_id] : 0
    min_v = interval_count[server_id] ? interval_min[server_id] : 0
    max_v = interval_count[server_id] ? interval_max[server_id] : 0
    err_v = error_count[server_id] + 0
    printf "%s,%d,%d,%.2f,%d,%d,%d\n", server_id, event_count[server_id], interval_count[server_id] + 0, avg, min_v, max_v, err_v >> summary_file
  }
}
' "${HEARTBEAT_EVENTS}"

{
  head -n 1 "${HEARTBEAT_SUMMARY}"
  tail -n +2 "${HEARTBEAT_SUMMARY}" | sort -t, -k1,1n
} > "${OUT_DIR}/heartbeat-summary.tmp"
mv "${OUT_DIR}/heartbeat-summary.tmp" "${HEARTBEAT_SUMMARY}"

awk -F',' '
NR == 1 {
  next
}
{
  key = $2 "," $4 "," $5
  counts[key]++
}
END {
  for (key in counts) {
    split(key, parts, ",")
    printf "%s,%s,%s,%d\n", parts[1], parts[2], parts[3], counts[key]
  }
}
' "${PARSED_CSV}" | sort -t, -k4,4nr -k1,1n > "${OUT_DIR}/endpoint-status-by-server-raw.tmp"

{
  echo "server_id,path,status,count"
  cat "${OUT_DIR}/endpoint-status-by-server-raw.tmp"
} > "${ENDPOINT_STATUS_COUNTS}"

awk -F',' '
BEGIN {
  print "server_id,error_timestamp,error_status,recovery_timestamp,recovery_status,recovery_seconds"
}
NR == 1 {
  next
}
{
  server_id = $1
  epoch = $2 + 0
  raw_ts = $3
  status = $4 + 0
  if (status >= 500 && !(server_id in pending_epoch)) {
    pending_epoch[server_id] = epoch
    pending_ts[server_id] = raw_ts
    pending_status[server_id] = status
  } else if (status >= 200 && status < 300 && (server_id in pending_epoch)) {
    recovery = epoch - pending_epoch[server_id]
    printf "%s,%s,%d,%s,%d,%d\n", server_id, pending_ts[server_id], pending_status[server_id], raw_ts, status, recovery
    delete pending_epoch[server_id]
    delete pending_ts[server_id]
    delete pending_status[server_id]
  }
}
' "${HEARTBEAT_EVENTS}" > "${HEARTBEAT_RECOVERY}"

total_agent_events="$(awk -F',' 'NR>1{count++} END{print count+0}' "${PARSED_CSV}")"
unique_servers="$(awk -F',' 'NR>1{seen[$2]=1} END{count=0; for (s in seen) count++; print count+0}' "${PARSED_CSV}")"
heartbeat_events_total="$(awk -F',' 'NR>1{count++} END{print count+0}' "${HEARTBEAT_EVENTS}")"
heartbeat_errors_total="$(awk -F',' 'NR>1 && $4+0>=500{count++} END{print count+0}' "${HEARTBEAT_EVENTS}")"
nginx_upstream_refused="0"
if [ -f "${NGINX_ERROR_LOG}" ]; then
  nginx_upstream_refused="$(grep -c "connect() failed" "${NGINX_ERROR_LOG}" || true)"
fi

{
  echo "# Operational Metrics Summary"
  echo
  echo "- Run ID: \`${RUN_ID}\`"
  echo "- Parsed agent access events: \`${total_agent_events}\`"
  echo "- Servers observed in agent traffic: \`${unique_servers}\`"
  echo "- Heartbeat events observed: \`${heartbeat_events_total}\`"
  echo "- Heartbeat 5xx responses observed: \`${heartbeat_errors_total}\`"
  echo "- Nginx upstream connection errors (tail window): \`${nginx_upstream_refused}\`"
  echo
  echo "## Heartbeat Interval Summary"
  echo
  echo "| Server ID | Heartbeat Events | Interval Samples | Avg Interval (s) | Min (s) | Max (s) | Heartbeat 5xx |"
  echo "|---|---:|---:|---:|---:|---:|---:|"
  tail -n +2 "${HEARTBEAT_SUMMARY}" | while IFS=',' read -r sid ev samples avg minv maxv errv; do
    printf "| %s | %s | %s | %s | %s | %s | %s |\n" "${sid}" "${ev}" "${samples}" "${avg}" "${minv}" "${maxv}" "${errv}"
  done
  echo
  echo "## Heartbeat Error Recovery Events"
  echo
  if [ "$(awk -F',' 'NR>1{count++} END{print count+0}' "${HEARTBEAT_RECOVERY}")" -eq 0 ]; then
    echo "- No heartbeat error->recovery transitions were found in this log window."
  else
    echo "| Server ID | Error Timestamp | Error Status | Recovery Timestamp | Recovery Status | Recovery Seconds |"
    echo "|---|---|---:|---|---:|---:|"
    tail -n +2 "${HEARTBEAT_RECOVERY}" | while IFS=',' read -r sid ets ests rts rsts sec; do
      printf "| %s | %s | %s | %s | %s | %s |\n" "${sid}" "${ets}" "${ests}" "${rts}" "${rsts}" "${sec}"
    done
  fi
  echo
  echo "## Top Endpoint/Status Counts"
  echo
  echo "| Rank | Server ID | Path | Status | Count |"
  echo "|---:|---:|---|---:|---:|"
  tail -n +2 "${ENDPOINT_STATUS_COUNTS}" | head -n 15 | nl -ba -w1 -s',' | while IFS=',' read -r rank sid path status count; do
    printf "| %s | %s | \`%s\` | %s | %s |\n" "${rank}" "${sid}" "${path}" "${status}" "${count}"
  done
  echo
  echo "## Generated Artifacts"
  echo
  echo "- \`evaluation/agent-access-parsed.csv\`"
  echo "- \`evaluation/heartbeat-events.csv\`"
  echo "- \`evaluation/heartbeat-intervals.csv\`"
  echo "- \`evaluation/heartbeat-summary.csv\`"
  echo "- \`evaluation/heartbeat-error-recovery.csv\`"
  echo "- \`evaluation/endpoint-status-by-server.csv\`"
} > "${SUMMARY_MD}"

rm -f \
  "${OUT_DIR}/heartbeat-events-raw.tmp" \
  "${OUT_DIR}/endpoint-status-by-server-raw.tmp"

echo "Operational metrics summary written: ${SUMMARY_MD}"
