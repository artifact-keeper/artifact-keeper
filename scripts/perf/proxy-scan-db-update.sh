#!/usr/bin/env bash
# =============================================================================
# scripts/perf/proxy-scan-db-update.sh - what a vulnerability-DB update costs
# the proxy scan gate (#6300)
# =============================================================================
# Stands up Postgres, the given backend image and a Maven upstream serving N
# small jars (proxy_scan_db_update_mock.py), all on a private docker network.
# Then:
#
#   1. a Maven Remote with scan_on_proxy and the chosen proxy_scan_action
#      (default fail_closed) pulls every jar once, so each is cached and graded
#      against the image's bundled Grype DB;
#   2. the DB update is simulated from the stored side: an older build of the
#      live Grype binary is recorded as first seen a day earlier
#      (proxy_scan_db_versions; harmless on an image without the table), and
#      every stored verdict is rewritten to that build;
#   3. every jar is pulled again, CONCURRENCY at a time, and the script reports
#      the status codes and latencies of that burst, the upstream GETs it
#      caused, how many of the pulls waited for a scan (the row was graded by
#      the live build before that pull's response came back), and how long it
#      took until every verdict carries the live build.
#
# Usage: scripts/perf/proxy-scan-db-update.sh <backend-image> [N] [CONCURRENCY]
# Env:   ACTION=fail_closed|fail_open|record_only   (default fail_closed)
#        REGRADE_WAIT_SECS=900   how long to wait for the re-grades
#        BACKEND_ENV="K=V ..."   extra backend environment, for example
#                                "SCAN_QUEUE_ENABLED=true" for the durable queue
#        KEEP=1                  leave the stack up
# Needs docker, curl, jq and python3. Prints one JSON summary line last.
# =============================================================================
set -euo pipefail

IMAGE="${1:?usage: $0 <backend-image> [N] [CONCURRENCY]}"
N="${2:-200}"
CONC="${3:-32}"
ACTION="${ACTION:-fail_closed}"
REGRADE_WAIT_SECS="${REGRADE_WAIT_SECS:-900}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TAG="akperf6300-$$"
SUBNET_OCTET=$(( 100 + RANDOM % 100 ))
NET_SUBNET="172.29.${SUBNET_OCTET}.0/24"
MOCK_IP="172.29.${SUBNET_OCTET}.72"
ADMIN_PASS="PerfRunner!2026secure"
WORK="$(mktemp -d)"

cleanup() {
  if [ "${KEEP:-0}" != 1 ]; then
    docker rm -f "${TAG}-backend" "${TAG}-db" "${TAG}-mock" >/dev/null 2>&1 || true
    docker network rm "${TAG}" >/dev/null 2>&1 || true
    docker volume rm "${TAG}-data" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

psql_q() { docker exec "${TAG}-db" psql -U registry -d artifact_registry -tAc "$1" | tr -d '[:space:]'; }
log() { echo "[perf6300] $*" >&2; }

docker network create --subnet "$NET_SUBNET" "$TAG" >/dev/null
docker run -d --name "${TAG}-db" --network "$TAG" \
  -e POSTGRES_USER=registry -e POSTGRES_PASSWORD=registry -e POSTGRES_DB=artifact_registry \
  postgres:16-alpine >/dev/null
docker run -d --name "${TAG}-mock" --network "$TAG" --ip "$MOCK_IP" \
  -e PERF_N="$N" -v "${HERE}/proxy_scan_db_update_mock.py:/app/mock.py:ro" \
  --security-opt label=disable python:3.12-slim python3 /app/mock.py >/dev/null
for _ in $(seq 1 60); do
  docker exec "${TAG}-db" pg_isready -U registry -d artifact_registry >/dev/null 2>&1 && break
  sleep 1
done
docker volume create "${TAG}-data" >/dev/null
EXTRA_ENV=()
for kv in ${BACKEND_ENV:-}; do EXTRA_ENV+=(-e "$kv"); done
docker run -d --name "${TAG}-backend" --network "$TAG" -p 127.0.0.1::8080 \
  -v "${TAG}-data:/data" \
  -e DATABASE_URL=postgresql://registry:registry@${TAG}-db:5432/artifact_registry \
  -e STORAGE_PATH=/data/storage -e BACKUP_PATH=/data/backups -e PLUGINS_DIR=/data/plugins \
  -e JWT_SECRET=perf-nonprod-6300-cobalt-harbor-lantern-7f3a9c2e5b81 \
  -e ADMIN_PASSWORD="$ADMIN_PASS" -e HOST=0.0.0.0 -e PORT=8080 \
  -e RATE_LIMIT_ENABLED=false -e UPSTREAM_ALLOW_PRIVATE_IPS=true \
  -e AK_SSRF_ALLOW_PRIVATE_CIDRS=172.16.0.0/12 -e RUST_LOG=warn "${EXTRA_ENV[@]}" \
  "$IMAGE" >/dev/null
PORT="$(docker port "${TAG}-backend" 8080/tcp | head -1 | sed 's/.*://')"
BASE="http://127.0.0.1:${PORT}"
for _ in $(seq 1 120); do
  curl -sf --max-time 3 "${BASE}/health" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf --max-time 3 "${BASE}/health" >/dev/null || { log "backend did not come up"; docker logs --tail 50 "${TAG}-backend" >&2; exit 1; }

TOKEN="$(curl -sf -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jq -r '.access_token')"
AUTH=(-H "Authorization: Bearer ${TOKEN}")
curl -sf "${AUTH[@]}" -H 'Content-Type: application/json' -X POST "${BASE}/api/v1/repositories" \
  -d "{\"key\":\"perf-mvn\",\"name\":\"perf-mvn\",\"format\":\"maven\",\"repo_type\":\"remote\",\"is_public\":true,\"upstream_url\":\"http://${MOCK_IP}/maven2\"}" >/dev/null
curl -sf "${AUTH[@]}" -H 'Content-Type: application/json' -X PUT "${BASE}/api/v1/repositories/perf-mvn/security" \
  -d "{\"scan_enabled\":true,\"scan_on_proxy\":true,\"proxy_scan_action\":\"${ACTION}\"}" >/dev/null

docker exec "${TAG}-mock" python3 -c \
  "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1/__digests').read().decode())" \
  > "${WORK}/digests.json"
jq -r 'keys[]' "${WORK}/digests.json" > "${WORK}/paths"

# One pull: "<path> <status> <seconds> <epoch when the response was in>".
cat > "${WORK}/pull.sh" <<EOF
#!/usr/bin/env bash
out=\$(curl -s -o /dev/null -w '%{http_code} %{time_total}' --max-time 300 "${BASE}/maven/perf-mvn/\$1") || out="000 0"
echo "\$1 \$out \$(date +%s.%N)"
EOF
chmod +x "${WORK}/pull.sh"
burst() { xargs -P "$CONC" -n 1 "${WORK}/pull.sh" < "${WORK}/paths"; }
mock_hits() {
  docker exec "${TAG}-mock" python3 -c \
    "import urllib.request,json;print(json.load(urllib.request.urlopen('http://127.0.0.1/__hits'))['count'])"
}

log "warm-up: ${N} first pulls (${ACTION}), ${CONC} at a time"
burst > "${WORK}/warm.txt"
# fail_open and record_only grade the first pulls in the background.
for _ in $(seq 1 "$REGRADE_WAIT_SECS"); do
  [ "$(psql_q "SELECT count(*) FROM proxy_scan_results WHERE scan_type='grype'")" -ge "$N" ] && break
  sleep 1
done
LIVE="$(psql_q "SELECT scanner_version FROM proxy_scan_results WHERE scan_type='grype' AND scanner_version LIKE 'grype-%+db-%' LIMIT 1")"
GRADED="$(psql_q "SELECT count(*) FROM proxy_scan_results WHERE scan_type='grype' AND scanner_version='${LIVE}'")"
[ -n "$LIVE" ] && [ "$GRADED" -ge "$N" ] || { log "warm-up graded ${GRADED}/${N} (live '${LIVE}')"; exit 1; }
PREV="${LIVE%%+db-*}+db-2000-01-01"
log "live ${LIVE}; simulating the update from ${PREV}"

psql_q "INSERT INTO proxy_scan_db_versions (scanner_version, first_seen_at) VALUES ('${PREV}', now() - interval '1 day') ON CONFLICT DO NOTHING" >/dev/null 2>&1 || true
psql_q "UPDATE proxy_scan_results SET scanner_version='${PREV}' WHERE scan_type='grype'" >/dev/null
HITS0="$(mock_hits)"
T0="$(date +%s.%N)"
burst > "${WORK}/burst.txt"
T1="$(date +%s.%N)"
HITS1="$(mock_hits)"

# Each pull's own response time against its row: graded by the live build
# before the response means the pull waited for that scan.
docker cp "${WORK}/burst.txt" "${TAG}-db:/tmp/burst.txt"
jq -r 'to_entries[] | "\(.key) \(.value)"' "${WORK}/digests.json" > "${WORK}/map.txt"
docker cp "${WORK}/map.txt" "${TAG}-db:/tmp/map.txt"
INLINE="$(docker exec "${TAG}-db" psql -q -U registry -d artifact_registry -tAc "
  CREATE TEMP TABLE b (path text, status text, secs float8, at float8);
  CREATE TEMP TABLE m (path text, digest text);
  COPY b FROM '/tmp/burst.txt' WITH (FORMAT text, DELIMITER ' ');
  COPY m FROM '/tmp/map.txt' WITH (FORMAT text, DELIMITER ' ');
  SELECT count(*) FROM b JOIN m USING (path)
    JOIN proxy_scan_results r ON r.checksum_sha256 = m.digest AND r.scan_type = 'grype'
   WHERE r.scanner_version = '${LIVE}' AND r.scanned_at <= to_timestamp(b.at);" | tr -d '[:space:]')"
AT_LIVE_AFTER_BURST="$(psql_q "SELECT count(*) FROM proxy_scan_results WHERE scan_type='grype' AND scanner_version='${LIVE}'")"

REGRADED_IN=""
for i in $(seq 1 "$REGRADE_WAIT_SECS"); do
  if [ "$(psql_q "SELECT count(*) FROM proxy_scan_results WHERE scan_type='grype' AND scanner_version='${LIVE}'")" -ge "$N" ]; then
    REGRADED_IN="$(python3 -c "import time;print(round(time.time()-${T1},1))")"
    break
  fi
  [ "$i" = "$REGRADE_WAIT_SECS" ] && REGRADED_IN="timeout"
  sleep 1
done
FINAL="$(psql_q "SELECT count(*) FROM proxy_scan_results WHERE scan_type='grype' AND scanner_version='${LIVE}'")"

python3 - "${WORK}/burst.txt" "$IMAGE" "${BACKEND_ENV:-}" "$N" "$CONC" "$ACTION" "$T0" "$T1" \
  "$((HITS1 - HITS0))" "$INLINE" "$AT_LIVE_AFTER_BURST" "$REGRADED_IN" "$FINAL" <<'PY'
import json, sys
(path, image, backend_env, n, conc, action, t0, t1, hits, inline, at_live, regraded_in, final) = sys.argv[1:]
rows = [l.split() for l in open(path) if l.strip()]
secs = sorted(float(r[2]) for r in rows)
codes = {}
for r in rows:
    codes[r[1]] = codes.get(r[1], 0) + 1
q = lambda p: round(secs[min(len(secs) - 1, int(p * len(secs)))], 3)
print(json.dumps({
    "image": image, "backend_env": backend_env, "artifacts": int(n),
    "concurrency": int(conc), "action": action,
    "burst_wall_secs": round(float(t1) - float(t0), 2),
    "status_counts": codes,
    "latency_secs": {"p50": q(0.50), "p95": q(0.95), "p99": q(0.99), "max": round(secs[-1], 3)},
    "upstream_gets_during_burst": int(hits),
    "pulls_that_waited_for_a_scan": int(inline),
    "verdicts_at_live_build_when_burst_ended": int(at_live),
    "secs_after_burst_until_all_regraded": regraded_in,
    "verdicts_at_live_build_at_end": int(final),
}))
PY
