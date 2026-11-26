#!/usr/bin/env bash
# =============================================================================
# scripts/perf/admin-stats-large-catalog.sh - what GET /api/v1/admin/stats
# costs on a large catalogue (#3094)
# =============================================================================
# Stands up Postgres and the given backend image, then seeds, straight into
# the database: ARTIFACTS rows in `artifacts` over 100 repositories (5 % soft-
# deleted), DOWNLOADS rows in `download_statistics`, PROXY rows in
# `proxy_cache_artifacts` and as many `proxy_download_statistics` rows. The
# seed is written with triggers off, as rows that predate an upgrade are, and
# the usage ledger is then trued up the way migration 182 does it.
#
# Then it reports:
#   * the endpoint's latency over CALLS sequential requests (after a warm-up);
#   * EXPLAIN ANALYZE of the statements the image runs for those four counts:
#     the COUNT(*) queries, or on an image with migration 414 the
#     row_count_deltas read;
#   * the four counts the endpoint returned next to the live COUNT(*) ones.
#
# Usage: scripts/perf/admin-stats-large-catalog.sh <backend-image> [ARTIFACTS] [DOWNLOADS] [PROXY]
# Env:   CALLS=30   KEEP=1 (leave the stack up)
# Needs docker, curl, jq and python3. Prints one JSON summary line last.
# =============================================================================
set -euo pipefail

IMAGE="${1:?usage: $0 <backend-image> [ARTIFACTS] [DOWNLOADS] [PROXY]}"
ARTIFACTS="${2:-1000000}"
DOWNLOADS="${3:-2000000}"
PROXY="${4:-300000}"
CALLS="${CALLS:-30}"
TAG="akperf3094-$$"
ADMIN_PASS="PerfRunner!2026secure"
WORK="$(mktemp -d)"

cleanup() {
  if [ "${KEEP:-0}" != 1 ]; then
    docker rm -f "${TAG}-backend" "${TAG}-db" >/dev/null 2>&1 || true
    docker network rm "${TAG}" >/dev/null 2>&1 || true
    docker volume rm "${TAG}-data" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT
log() { echo "[perf3094] $*" >&2; }
psql_q() { docker exec -i "${TAG}-db" psql -v ON_ERROR_STOP=1 -q -U registry -d artifact_registry -tAX "$@"; }

docker network create "$TAG" >/dev/null
docker run -d --name "${TAG}-db" --network "$TAG" --shm-size=1g \
  -e POSTGRES_USER=registry -e POSTGRES_PASSWORD=registry -e POSTGRES_DB=artifact_registry \
  postgres:16-alpine -c shared_buffers=1GB -c max_wal_size=8GB >/dev/null
for _ in $(seq 1 60); do
  docker exec "${TAG}-db" pg_isready -U registry -d artifact_registry >/dev/null 2>&1 && break
  sleep 1
done
docker volume create "${TAG}-data" >/dev/null
start_backend() {
  docker run -d --name "${TAG}-backend" --network "$TAG" -p 127.0.0.1::8080 \
    -v "${TAG}-data:/data" \
    -e DATABASE_URL=postgresql://registry:registry@${TAG}-db:5432/artifact_registry \
    -e STORAGE_PATH=/data/storage -e BACKUP_PATH=/data/backups -e PLUGINS_DIR=/data/plugins \
    -e JWT_SECRET=perf-nonprod-3094-cobalt-harbor-lantern-7f3a9c2e5b81 \
    -e ADMIN_PASSWORD="$ADMIN_PASS" -e HOST=0.0.0.0 -e PORT=8080 \
    -e RATE_LIMIT_ENABLED=false -e RUST_LOG=warn "$IMAGE" >/dev/null
  PORT="$(docker port "${TAG}-backend" 8080/tcp | head -1 | sed 's/.*://')"
  BASE="http://127.0.0.1:${PORT}"
  for _ in $(seq 1 180); do
    curl -sf --max-time 3 "${BASE}/health" >/dev/null 2>&1 && return 0
    sleep 1
  done
  log "backend did not come up"; docker logs --tail 50 "${TAG}-backend" >&2; exit 1
}
# First start: runs the migrations. Stopped while the seed is written.
start_backend
docker rm -f "${TAG}-backend" >/dev/null

log "seeding ${ARTIFACTS} artifacts, ${DOWNLOADS} downloads, ${PROXY} proxy rows"
psql_q <<SQL
BEGIN;
SET LOCAL session_replication_role = replica;
INSERT INTO repositories (key, name, format, repo_type, storage_path, visibility)
SELECT 'perf-' || g, 'perf-' || g, 'generic', 'local', '/data/storage/perf-' || g, 'private'
  FROM generate_series(1, 100) g;
INSERT INTO artifacts (repository_id, path, name, size_bytes, checksum_sha256, content_type,
                       storage_key, is_deleted, origin)
SELECT r.id, 'p/' || g, 'n' || g, 1000 + g % 5000, md5(g::text) || md5(g::text),
       'application/octet-stream', 'k/' || g, g % 20 = 0,
       jsonb_build_object('kind', 'hosted', 'repository_key', r.key)
  FROM generate_series(1, ${ARTIFACTS}) g
  JOIN (SELECT id, key, row_number() OVER (ORDER BY id) - 1 AS i FROM repositories) r
    ON r.i = g % 100;
INSERT INTO download_statistics (artifact_id)
SELECT id FROM artifacts, generate_series(1, ${DOWNLOADS} / ${ARTIFACTS} + 1) k
 LIMIT ${DOWNLOADS};
INSERT INTO repositories (key, name, format, repo_type, storage_path, visibility, upstream_url)
VALUES ('perf-remote', 'perf-remote', 'generic', 'remote', '/data/storage/perf-remote',
        'private', 'https://example.invalid/');
INSERT INTO proxy_cache_artifacts (repository_id, path, storage_key, metadata_key, size_bytes)
SELECT (SELECT id FROM repositories WHERE key = 'perf-remote'), 'c/' || g, 'pc/' || g,
       'pm/' || g, 4096
  FROM generate_series(1, ${PROXY}) g;
INSERT INTO proxy_download_statistics (proxy_cache_id, repository_id, path)
SELECT id, repository_id, path FROM proxy_cache_artifacts;
-- The usage ledger, trued up as migration 182 does.
INSERT INTO repository_usage_ledger (repository_id, hosted_bytes, proxy_bytes, oci_bytes, updated_at)
SELECT r.id,
       COALESCE((SELECT SUM(a.size_bytes) FROM artifacts a WHERE a.repository_id = r.id
                  AND a.is_deleted = false AND a.storage_key NOT LIKE 'proxy-cache/%'
                  AND a.storage_key NOT LIKE 'oci-manifests/%'), 0),
       COALESCE((SELECT SUM(p.size_bytes) FROM proxy_cache_artifacts p WHERE p.repository_id = r.id), 0),
       0, now()
  FROM repositories r
ON CONFLICT (repository_id) DO UPDATE SET hosted_bytes = EXCLUDED.hosted_bytes,
       proxy_bytes = EXCLUDED.proxy_bytes, oci_bytes = 0, updated_at = now();
COMMIT;
VACUUM ANALYZE;
SQL

start_backend
TOKEN="$(curl -sf -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jq -r '.access_token')"
STATS() { curl -sf --max-time 120 -H "Authorization: Bearer ${TOKEN}" "${BASE}/api/v1/admin/stats"; }

HAS_414="$(psql_q -c "SELECT to_regclass('row_count_seeds') IS NOT NULL")"
if [ "$HAS_414" = t ]; then
  # The image seeds its counts in the background shortly after startup.
  for _ in $(seq 1 600); do
    [ "$(psql_q -c 'SELECT count(*) FROM row_count_seeds')" -ge 4 ] && break
    sleep 1
  done
fi

for _ in 1 2 3; do STATS >/dev/null; done
: > "${WORK}/lat.txt"
for _ in $(seq 1 "$CALLS"); do
  curl -sf -o "${WORK}/stats.json" -w '%{time_total}\n' --max-time 120 \
    -H "Authorization: Bearer ${TOKEN}" "${BASE}/api/v1/admin/stats" >> "${WORK}/lat.txt"
done

explain() { psql_q -c "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) $1" | python3 -c '
import json, sys
p = json.load(sys.stdin)[0]
def rows(n):
    own = n.get("Actual Rows", 0) * n.get("Actual Loops", 1) if "Relation Name" in n else 0
    return own + sum(rows(c) for c in n.get("Plans", []))
print(json.dumps({"ms": p["Execution Time"], "rows_scanned": rows(p["Plan"]),
                  "shared_buffers": p["Plan"].get("Shared Hit Blocks", 0) + p["Plan"].get("Shared Read Blocks", 0)}))'; }
{
  echo '"live_counts": {'
  echo "\"artifacts\": $(explain 'SELECT COUNT(*) FROM artifacts WHERE is_deleted = false'),"
  echo "\"proxy_cache_artifacts\": $(explain 'SELECT COUNT(*) FROM proxy_cache_artifacts'),"
  echo "\"download_statistics\": $(explain 'SELECT COUNT(*) FROM download_statistics'),"
  echo "\"proxy_download_statistics\": $(explain 'SELECT COUNT(*) FROM proxy_download_statistics')"
  echo '}'
  if [ "$HAS_414" = t ]; then
    echo ", \"row_count_deltas_read\": $(explain "SELECT s.table_name, COALESCE((SELECT SUM(d.delta) FROM row_count_deltas d WHERE d.table_name = s.table_name), 0)::BIGINT FROM row_count_seeds s")"
  fi
} > "${WORK}/explain.json"
LIVE="$(psql_q -c "SELECT (SELECT COUNT(*) FROM artifacts WHERE is_deleted = false) || ' ' ||
  (SELECT COUNT(*) FROM proxy_cache_artifacts) || ' ' || (SELECT COUNT(*) FROM download_statistics) || ' ' ||
  (SELECT COUNT(*) FROM proxy_download_statistics)")"

python3 - "${WORK}/lat.txt" "${WORK}/stats.json" "${WORK}/explain.json" "$IMAGE" "$ARTIFACTS" \
  "$DOWNLOADS" "$PROXY" "$LIVE" "$HAS_414" <<'PY'
import json, sys
(lat, stats, explain, image, arts, dls, proxy, live, has414) = sys.argv[1:]
xs = sorted(float(l) * 1000 for l in open(lat) if l.strip())
q = lambda p: round(xs[min(len(xs) - 1, int(p * len(xs)))], 1)
s = json.load(open(stats))
reported = [s["total_artifacts"], s["proxy_artifact_count"],
            s["total_downloads"] - s["proxy_download_count"], s["proxy_download_count"]]
live = [int(v) for v in live.split()]
print(json.dumps({
    "image": image, "artifacts": int(arts), "downloads": int(dls), "proxy_rows": int(proxy),
    "migration_414": has414 == "t",
    "latency_ms": {"p50": q(.5), "p95": q(.95), "max": round(xs[-1], 1), "calls": len(xs)},
    "explain": json.loads("{" + open(explain).read() + "}"),
    "reported_counts": reported, "live_counts": live, "identical": reported == live,
}))
PY
