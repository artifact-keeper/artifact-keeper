#!/usr/bin/env bash
# =============================================================================
# scripts/perf/proxy-fill-catalog-contention.sh - how long a cold proxy fill's
# catalog upsert takes when many fills land in one Remote at once (#5635)
# =============================================================================
# Stands up Postgres (logging every statement's duration), the given backend
# image and a static upstream serving N small files, all on a private docker
# network. A generic Remote points at the upstream, and every file is pulled
# once, CONCURRENCY at a time: N cold fills into the same repository.
#
# Each fill ends with one `INSERT INTO proxy_cache_artifacts ... ON CONFLICT`
# (proxy_catalog::upsert_fill) that also charges the repository's
# `repository_usage_ledger` row through migration 182's trigger. The script
# reads those statements' durations from the Postgres log, the slow-query log
# view the issue was found with, and reports their p50 / p90 / p99 / max, plus
# the burst's wall time and client latencies.
#
# Usage: scripts/perf/proxy-fill-catalog-contention.sh <backend-image> [N] [CONCURRENCY]
# Env:   FILE_BYTES=4096      size of each upstream file
#        BACKEND_ENV="K=V ..." extra backend environment
#        KEEP=1               leave the stack up
# Needs docker, curl, jq and python3. Prints one JSON summary line last.
# =============================================================================
set -euo pipefail

IMAGE="${1:?usage: $0 <backend-image> [N] [CONCURRENCY]}"
N="${2:-2000}"
CONC="${3:-64}"
FILE_BYTES="${FILE_BYTES:-4096}"
TAG="akperf5635-$$"
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
log() { echo "[perf5635] $*" >&2; }

docker network create --subnet "$NET_SUBNET" "$TAG" >/dev/null
docker run -d --name "${TAG}-db" --network "$TAG" \
  -e POSTGRES_USER=registry -e POSTGRES_PASSWORD=registry -e POSTGRES_DB=artifact_registry \
  postgres:16-alpine -c log_min_duration_statement=0 -c log_line_prefix='%m [%p] ' >/dev/null
# The upstream: N files of FILE_BYTES under /f/, served by a threading server.
docker run -d --name "${TAG}-mock" --network "$TAG" --ip "$MOCK_IP" python:3.12-slim \
  sh -c "mkdir -p /srv/f && for i in \$(seq 1 ${N}); do head -c ${FILE_BYTES} /dev/urandom > /srv/f/obj-\$i.bin; done \
         && touch /srv/ready && exec python3 -m http.server 80 -d /srv" >/dev/null
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
  -e JWT_SECRET=perf-nonprod-5635-cobalt-harbor-lantern-7f3a9c2e5b81 \
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
for _ in $(seq 1 300); do
  docker exec "${TAG}-mock" test -f /srv/ready && break
  sleep 1
done

TOKEN="$(curl -sf -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jq -r '.access_token')"
curl -sf -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' \
  -X POST "${BASE}/api/v1/repositories" \
  -d "{\"key\":\"perf-gen\",\"name\":\"perf-gen\",\"format\":\"generic\",\"repo_type\":\"remote\",\"is_public\":true,\"upstream_url\":\"http://${MOCK_IP}/f/\"}" >/dev/null

seq 1 "$N" | sed 's/^/obj-/; s/$/.bin/' > "${WORK}/paths"
cat > "${WORK}/pull.sh" <<EOF
#!/usr/bin/env bash
curl -s -o /dev/null -w '%{http_code} %{time_total}\n' --max-time 300 \
  -H "Authorization: Bearer ${TOKEN}" "${BASE}/api/v1/repositories/perf-gen/download/\$1" || echo "000 0"
EOF
chmod +x "${WORK}/pull.sh"

# Only the burst's statements count: note where the log stands now.
LOG_FROM="$(docker logs "${TAG}-db" 2>&1 | wc -l)"
log "cold burst: ${N} fills into one Remote, ${CONC} at a time"
T0="$(date +%s.%N)"
xargs -P "$CONC" -n 1 "${WORK}/pull.sh" < "${WORK}/paths" > "${WORK}/burst.txt"
T1="$(date +%s.%N)"
# The catalog row is written after the client has the body: wait for all.
for _ in $(seq 1 300); do
  rows="$(docker exec "${TAG}-db" psql -U registry -d artifact_registry -tAc \
    "SELECT count(*) FROM proxy_cache_artifacts WHERE size_bytes > 0" | tr -d '[:space:]')"
  [ "$rows" -ge "$N" ] && break
  sleep 1
done
T2="$(date +%s.%N)"
docker logs "${TAG}-db" 2>&1 | tail -n +"$((LOG_FROM + 1))" > "${WORK}/pg.log"

python3 - "${WORK}/pg.log" "${WORK}/burst.txt" "$IMAGE" "${BACKEND_ENV:-}" "$N" "$CONC" \
  "$T0" "$T1" "$T2" "$rows" <<'PY'
import json, re, sys
(pg_log, burst, image, backend_env, n, conc, t0, t1, t2, rows) = sys.argv[1:]
# One log entry per "<timestamp> [pid] " line; a statement's text continues
# on the following lines until the next entry.
entries, cur = [], None
start = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+ \S+ \[\d+\] ")
for line in open(pg_log, errors="replace"):
    if start.match(line):
        if cur is not None:
            entries.append(cur)
        cur = line
    elif cur is not None:
        cur += line
if cur is not None:
    entries.append(cur)
dur = re.compile(r"duration: ([0-9.]+) ms\s+execute [^:]*:")
fills = []
for e in entries:
    m = dur.search(e)
    if not m:
        continue
    text = " ".join(e[m.end():].split())
    # proxy_catalog::upsert_fill: the commit's upsert, not the placeholder.
    # (main's statement starts with the INSERT; from #5635 it is preceded
    # by the `sync` CTE.)
    if "INSERT INTO proxy_cache_artifacts" in text[:200] and \
            "RETURNING quarantine_released_at IS NOT NULL" in text:
        fills.append(float(m.group(1)))
fills.sort()
q = lambda xs, p: round(xs[min(len(xs) - 1, int(p * len(xs)))], 2) if xs else None
clients = sorted(float(l.split()[1]) for l in open(burst) if l.strip())
codes = {}
for l in open(burst):
    if l.strip():
        codes[l.split()[0]] = codes.get(l.split()[0], 0) + 1
print(json.dumps({
    "image": image, "backend_env": backend_env, "fills": int(n), "concurrency": int(conc),
    "status_counts": codes,
    "catalog_rows_written": int(rows),
    "fill_upserts_logged": len(fills),
    "fill_upsert_ms": {"p50": q(fills, .5), "p90": q(fills, .9), "p99": q(fills, .99),
                       "max": round(fills[-1], 2) if fills else None,
                       "over_1s": sum(1 for f in fills if f >= 1000)},
    "client_secs": {"p50": q(clients, .5), "p99": q(clients, .99)},
    "burst_wall_secs": round(float(t1) - float(t0), 2),
    "until_all_rows_secs": round(float(t2) - float(t0), 2),
}))
PY
