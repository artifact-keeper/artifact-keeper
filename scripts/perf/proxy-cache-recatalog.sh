#!/usr/bin/env bash
# =============================================================================
# scripts/perf/proxy-cache-recatalog.sh - how long lost proxy-cache catalog
# rows stay lost, and what the re-catalog sweep costs (#6429)
# =============================================================================
# Stands up Postgres (logging every statement), the given backend image and a
# static upstream serving N small files, all on a private docker network. A
# generic Remote points at the upstream and every file is pulled once, so the
# cache holds N entries (body + sidecar) with N catalog rows.
#
# Then LOST catalog rows are deleted, the way a database crash loses the rows
# of fills committed asynchronously (#5635): the files stay, and the delete
# debits the Remote's usage ledger through the same trigger. No file is read
# again. For WINDOW seconds the script watches the catalog and reports:
#   - the bytes missing from the Remote's ledger right after the loss and at
#     the end (cached bytes on disk minus ledger proxy_bytes);
#   - how many lost rows came back, and when the last one did;
#   - each sweep pass the backend logged (keys listed, rows restored, ms);
#   - the statements one pass with nothing to restore runs per 1,000 keys.
#
# Usage: scripts/perf/proxy-cache-recatalog.sh <backend-image> [N] [LOST]
# Env:   FILE_BYTES=4096   size of each upstream file
#        WINDOW=90         seconds to watch after the loss
#        BACKEND_ENV="K=V ..." extra backend environment (the sweep runs every
#                          10 s, on sidecars older than 5 s, unless overridden)
#        KEEP=1            leave the stack up
# Needs docker, curl, jq and python3. Prints one JSON summary line last.
# =============================================================================
set -euo pipefail

IMAGE="${1:?usage: $0 <backend-image> [N] [LOST]}"
N="${2:-2000}"
LOST="${3:-200}"
FILE_BYTES="${FILE_BYTES:-4096}"
WINDOW="${WINDOW:-90}"
TAG="akperf6429-$$"
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
log() { echo "[perf6429] $*" >&2; }
sql() { docker exec "${TAG}-db" psql -U registry -d artifact_registry -tAc "$1" | tr -d '[:space:]'; }

docker network create --subnet "$NET_SUBNET" "$TAG" >/dev/null
docker run -d --name "${TAG}-db" --network "$TAG" \
  -e POSTGRES_USER=registry -e POSTGRES_PASSWORD=registry -e POSTGRES_DB=artifact_registry \
  postgres:16-alpine -c log_min_duration_statement=0 -c log_line_prefix='%m [%p] ' >/dev/null
docker run -d --name "${TAG}-mock" --network "$TAG" --ip "$MOCK_IP" python:3.12-slim \
  sh -c "mkdir -p /srv/f && for i in \$(seq 1 ${N}); do head -c ${FILE_BYTES} /dev/urandom > /srv/f/obj-\$i.bin; done \
         && touch /srv/ready && exec python3 -m http.server 80 -d /srv" >/dev/null
for _ in $(seq 1 60); do
  docker exec "${TAG}-db" pg_isready -U registry -d artifact_registry >/dev/null 2>&1 && break
  sleep 1
done
docker volume create "${TAG}-data" >/dev/null
EXTRA_ENV=(-e PROXY_CACHE_RECATALOG_INTERVAL_SECS=10 -e PROXY_CACHE_RECATALOG_MIN_AGE_SECS=5)
for kv in ${BACKEND_ENV:-}; do EXTRA_ENV+=(-e "$kv"); done
docker run -d --name "${TAG}-backend" --network "$TAG" -p 127.0.0.1::8080 \
  -v "${TAG}-data:/data" \
  -e DATABASE_URL=postgresql://registry:registry@${TAG}-db:5432/artifact_registry \
  -e STORAGE_PATH=/data/storage -e BACKUP_PATH=/data/backups -e PLUGINS_DIR=/data/plugins \
  -e JWT_SECRET=perf-nonprod-6429-amber-quarry-signal-3d8e1f6a9c42 \
  -e ADMIN_PASSWORD="$ADMIN_PASS" -e HOST=0.0.0.0 -e PORT=8080 \
  -e RATE_LIMIT_ENABLED=false -e UPSTREAM_ALLOW_PRIVATE_IPS=true \
  -e AK_SSRF_ALLOW_PRIVATE_CIDRS=172.16.0.0/12 \
  -e RUST_LOG=warn,artifact_keeper_backend::services::proxy_cache_recatalog=debug \
  "${EXTRA_ENV[@]}" "$IMAGE" >/dev/null
PORT="$(docker port "${TAG}-backend" 8080/tcp | head -1 | sed 's/.*://')"
BASE="http://127.0.0.1:${PORT}"
for _ in $(seq 1 120); do
  curl -sf --max-time 3 "${BASE}/health" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf --max-time 3 "${BASE}/health" >/dev/null || { log "backend did not come up"; docker logs --tail 50 "${TAG}-backend" >&2; exit 1; }
for _ in $(seq 1 300); do
  docker exec "${TAG}-mock" test -f /srv/ready && break
  sleep 1
done

TOKEN="$(curl -sf -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jq -r '.access_token')"
curl -sf -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' \
  -X POST "${BASE}/api/v1/repositories" \
  -d "{\"key\":\"perf-rc\",\"name\":\"perf-rc\",\"format\":\"generic\",\"repo_type\":\"remote\",\"is_public\":true,\"upstream_url\":\"http://${MOCK_IP}/f/\"}" >/dev/null
REPO_ID="$(sql "SELECT id FROM repositories WHERE key = 'perf-rc'")"

log "filling ${N} entries"
seq 1 "$N" | sed 's/^/obj-/; s/$/.bin/' | xargs -P 32 -I{} curl -s -o /dev/null --max-time 120 \
  -H "Authorization: Bearer ${TOKEN}" "${BASE}/api/v1/repositories/perf-rc/download/{}"
for _ in $(seq 1 300); do
  rows="$(sql "SELECT count(*) FROM proxy_cache_artifacts WHERE repository_id = '${REPO_ID}' AND size_bytes > 0")"
  [ "$rows" -ge "$N" ] && break
  sleep 1
done
CACHED_BYTES=$(( N * FILE_BYTES ))
# Let every sidecar pass the minimum age and a pass find nothing to do.
sleep 25

LOG_FROM="$(docker logs "${TAG}-db" 2>&1 | wc -l)"
BLOG_FROM="$(docker logs "${TAG}-backend" 2>&1 | wc -l)"
log "losing ${LOST} catalog rows"
sql "DELETE FROM proxy_cache_artifacts WHERE id IN (SELECT id FROM proxy_cache_artifacts WHERE repository_id = '${REPO_ID}' ORDER BY random() LIMIT ${LOST})" >/dev/null
T0="$(date +%s.%N)"
LEDGER0="$(sql "SELECT proxy_bytes FROM repository_usage_ledger WHERE repository_id = '${REPO_ID}'")"
RESTORED_AT=""
end=$(( $(date +%s) + WINDOW ))
while [ "$(date +%s)" -lt "$end" ]; do
  rows="$(sql "SELECT count(*) FROM proxy_cache_artifacts WHERE repository_id = '${REPO_ID}'")"
  if [ "$rows" -ge "$N" ] && [ -z "$RESTORED_AT" ]; then RESTORED_AT="$(date +%s.%N)"; fi
  sleep 0.5
done
LEDGER1="$(sql "SELECT proxy_bytes FROM repository_usage_ledger WHERE repository_id = '${REPO_ID}'")"
LIVE1="$(sql "SELECT COALESCE(SUM(size_bytes),0) FROM proxy_cache_artifacts WHERE repository_id = '${REPO_ID}'")"
UPSTREAM_GETS="$(docker logs "${TAG}-mock" 2>&1 | grep -c '"GET /f/' || true)"
docker logs "${TAG}-db" 2>&1 | tail -n +"$((LOG_FROM + 1))" > "${WORK}/pg.log"
docker logs "${TAG}-backend" 2>&1 | tail -n +"$((BLOG_FROM + 1))" | grep 'Proxy-cache re-catalog pass' > "${WORK}/passes.log" || true

python3 - "$IMAGE" "$N" "$LOST" "$FILE_BYTES" "$WINDOW" "$CACHED_BYTES" "$LEDGER0" "$LEDGER1" "$LIVE1" \
  "$rows" "$T0" "${RESTORED_AT:-}" "$UPSTREAM_GETS" "${WORK}/pg.log" "${WORK}/passes.log" <<'PY'
import json, re, sys
(image, n, lost, fbytes, window, cached, ledger0, ledger1, live1, rows, t0, restored_at,
 upstream_gets, pg_log, passes_log) = sys.argv[1:]
passes = []
for line in open(passes_log, errors="replace"):
    fields = dict(re.findall(r'"?(\w+)"?[=:]\s*"?([\w.]+)"?', line))
    passes.append({k: fields.get(k) for k in ("scanned", "sidecars", "recataloged", "elapsed_ms")})
log = open(pg_log, errors="replace").read()
lookups = log.count("FROM proxy_cache_artifacts WHERE storage_key = ANY")
idle = [p for p in passes if p.get("recataloged") in (None, "0")]
print(json.dumps({
    "image": image, "cached_entries": int(n), "lost_rows": int(lost), "file_bytes": int(fbytes),
    "window_secs": int(window),
    "ledger_missing_bytes_after_loss": int(cached) - int(ledger0 or 0),
    "ledger_missing_bytes_at_end": int(cached) - int(ledger1 or 0),
    "ledger_equals_live_sum_at_end": ledger1 == live1,
    "rows_at_end": int(rows),
    "all_restored_after_secs": round(float(restored_at) - float(t0), 1) if restored_at else None,
    "upstream_gets_total": int(upstream_gets),
    "passes_logged": len(passes),
    "passes": passes[:6],
    "catalog_lookups_logged": lookups,
    "idle_pass_ms": [p["elapsed_ms"] for p in idle][:6],
}))
PY
