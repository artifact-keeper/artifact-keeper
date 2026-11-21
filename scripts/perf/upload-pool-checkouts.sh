#!/usr/bin/env bash
# =============================================================================
# scripts/perf/upload-pool-checkouts.sh: before/after measurement for #6318
# =============================================================================
# Stands up a throwaway Postgres (with pg_stat_statements) and one backend
# container per image on a private Docker network, and runs
# upload-pool-checkouts.py against each image in turn:
#   * database statements and transactions per sequential PyPI upload and per
#     generic PUT of a wheel into a PyPI repository (background subtracted);
#   * a burst of CONCURRENCY simultaneous PyPI uploads of BURST_MIB MiB each
#     against a small pool (DATABASE_MAX_CONNECTIONS, default 5), the shape
#     that answered 503 POOL_EXHAUSTED for some of the uploads.
#
# Usage:
#   scripts/perf/upload-pool-checkouts.sh <label>=<image> [<label>=<image> ...]
#
# Env: OUT_DIR (./perf-results), DATABASE_MAX_CONNECTIONS (5), UPLOADS (40),
#      CONCURRENCY (16), BURST_MIB (24), BACKEND_CPUS (4), PORT (18318),
#      NAME_PREFIX (akperf-upload), EXTRA_ENV (space-separated KEY=VALUE).
# Each run writes $OUT_DIR/<label>.json; a summary table is printed at the end.
# Removes its containers and network on exit.
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${OUT_DIR:-./perf-results}"
POOL="${DATABASE_MAX_CONNECTIONS:-5}"
CPUS="${BACKEND_CPUS:-4}"
PORT="${PORT:-18318}"
P="${NAME_PREFIX:-akperf-upload}"
NET="${P}-net"; DB="${P}-db"; BE="${P}-backend"
ADMIN_PASS="PerfUpload!2026secure"
mkdir -p "$OUT_DIR"

cleanup() {
  docker rm -f "$BE" "$DB" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

[ $# -ge 1 ] || { sed -n '2,22p' "$0"; exit 2; }

for spec in "$@"; do
  label="${spec%%=*}"; image="${spec#*=}"
  cleanup
  docker network create "$NET" >/dev/null
  docker run -d --name "$DB" --network "$NET" -e POSTGRES_USER=registry \
    -e POSTGRES_PASSWORD=registry -e POSTGRES_DB=artifact_registry postgres:18-alpine \
    -c shared_preload_libraries=pg_stat_statements -c pg_stat_statements.track=all >/dev/null
  until docker exec "$DB" pg_isready -U registry -d artifact_registry >/dev/null 2>&1; do sleep 1; done
  sleep 2
  docker exec "$DB" psql -U registry -d artifact_registry -qc "CREATE EXTENSION IF NOT EXISTS pg_stat_statements" >/dev/null
  extra=()
  for kv in ${EXTRA_ENV:-}; do extra+=(-e "$kv"); done
  docker run -d --name "$BE" --network "$NET" --cpus "$CPUS" -p "127.0.0.1:${PORT}:8080" \
    -e DATABASE_URL="postgresql://registry:registry@${DB}:5432/artifact_registry" \
    -e JWT_SECRET=perf-upload-nonprod-secret-at-least-32-bytes-long \
    -e ADMIN_PASSWORD="$ADMIN_PASS" -e STORAGE_PATH=/tmp/storage -e BACKUP_PATH=/tmp/backups \
    -e PLUGINS_DIR=/tmp/plugins -e RATE_LIMIT_ENABLED=false -e RUST_LOG=warn \
    -e DATABASE_MAX_CONNECTIONS="$POOL" -e HOST=0.0.0.0 -e PORT=8080 \
    "${extra[@]}" "$image" >/dev/null
  for _ in $(seq 1 120); do
    curl -sf "http://127.0.0.1:${PORT}/readyz" >/dev/null 2>&1 && break
    sleep 1
  done
  python3 "$HERE/upload-pool-checkouts.py" --base-url "http://127.0.0.1:${PORT}" \
    --db-container "$DB" --admin-pass "$ADMIN_PASS" --uploads "${UPLOADS:-40}" \
    --concurrency "${CONCURRENCY:-16}" --burst-mib "${BURST_MIB:-24}" \
    --label "$label" --out "${OUT_DIR}/${label}.json" >/dev/null
  docker logs "$BE" 2>&1 | grep -E "WARN|ERROR" | tail -n 400 >"${OUT_DIR}/${label}.backend.log" || true
  echo ">> ${label}: ${OUT_DIR}/${label}.json" >&2
done

python3 - "$OUT_DIR" "$@" <<'PY'
import json, sys
out = sys.argv[1]
hdr = ("run", "pypi stmts/upload", "pypi xacts/upload", "pypi p50 ms",
       "gput stmts/upload", "gput xacts/upload", "gput p50 ms",
       "burst ok", "burst failed", "burst mix", "burst wall s")
print("| " + " | ".join(hdr) + " |")
print("|" + "---|" * len(hdr))
for spec in sys.argv[2:]:
    label = spec.split("=", 1)[0]
    r = json.load(open(f"{out}/{label}.json"))
    p, g, b = r["pypi_upload"], r["generic_put_wheel"], r["burst"]
    row = (label, p["statements_per_upload"], p["transactions_per_upload"], p["latency_ms"]["p50"],
           g["statements_per_upload"], g["transactions_per_upload"], g["latency_ms"]["p50"],
           b["ok"], b["failed"], json.dumps(b["status_mix"]), b["wall_s"])
    print("| " + " | ".join(str(c) for c in row) + " |")
PY
