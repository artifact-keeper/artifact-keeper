#!/usr/bin/env bash
# =============================================================================
# scripts/perf/db-pool-burst.sh: before/after measurement for #4182
# =============================================================================
# Stands up a throwaway Postgres and one backend container per image on a
# private Docker network, seeds a public generic repository, and runs
# db-pool-burst.py (an installer-fleet burst) against each image in turn. The
# pool is kept small (DATABASE_MAX_CONNECTIONS, default 8) and, optionally,
# every database round trip is slowed with netem (DB_DELAY_MS, default 2, via
# `sudo nsenter ... tc`), so the burst exhausts the pool the way a fleet does
# against a full-size pool and a remote database.
#
# Usage:
#   scripts/perf/db-pool-burst.sh <label>=<image> [<label>=<image> ...]
#   e.g. scripts/perf/db-pool-burst.sh \
#          before=ghcr.io/artifact-keeper/artifact-keeper-backend:sha-5d99629 \
#          after=ak-perf4182/backend:green
#
# Env: OUT_DIR (default ./perf-results), DATABASE_MAX_CONNECTIONS (8),
#      DB_DELAY_MS (2; 0 = no netem), BACKEND_CPUS (4), INSTALLERS (24),
#      PARALLEL (50), FILES (200), RETRIES (5), CLIENT_TIMEOUT (30 s per
#      attempt), PORT (18182), EXTRA_ENV
#      (space-separated KEY=VALUE pairs passed to the backend).
# Each run writes $OUT_DIR/<label>.json; a summary table is printed at the end.
# Removes its containers and network on exit.
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${OUT_DIR:-./perf-results}"
POOL="${DATABASE_MAX_CONNECTIONS:-8}"
DELAY="${DB_DELAY_MS:-2}"
CPUS="${BACKEND_CPUS:-4}"
PORT="${PORT:-18182}"
NET="akperf-burst-net"
DB="akperf-burst-db"
BE="akperf-burst-backend"
ADMIN_PASS="PerfBurst!2026secure"
mkdir -p "$OUT_DIR"

cleanup() {
  docker rm -f "$BE" "$DB" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

[ $# -ge 1 ] || { sed -n '2,25p' "$0"; exit 2; }
ulimit -n 65536 2>/dev/null || true

for spec in "$@"; do
  label="${spec%%=*}"; image="${spec#*=}"
  cleanup
  docker network create "$NET" >/dev/null
  docker run -d --name "$DB" --network "$NET" -e POSTGRES_USER=registry \
    -e POSTGRES_PASSWORD=registry -e POSTGRES_DB=artifact_registry postgres:18-alpine >/dev/null
  until docker exec "$DB" pg_isready -U registry -d artifact_registry >/dev/null 2>&1; do sleep 1; done
  sleep 2
  extra=()
  for kv in ${EXTRA_ENV:-}; do extra+=(-e "$kv"); done
  docker run -d --name "$BE" --network "$NET" --cpus "$CPUS" --ulimit nofile=65536:65536 -p "127.0.0.1:${PORT}:8080" \
    -e DATABASE_URL="postgresql://registry:registry@${DB}:5432/artifact_registry" \
    -e JWT_SECRET=perf-burst-nonprod-secret-at-least-32-bytes-long \
    -e ADMIN_PASSWORD="$ADMIN_PASS" -e STORAGE_PATH=/tmp/storage -e BACKUP_PATH=/tmp/backups \
    -e PLUGINS_DIR=/tmp/plugins -e RATE_LIMIT_ENABLED=false -e RUST_LOG=warn \
    -e DATABASE_MAX_CONNECTIONS="$POOL" -e HOST=0.0.0.0 -e PORT=8080 \
    "${extra[@]}" "$image" >/dev/null
  for _ in $(seq 1 120); do
    curl -sf "http://127.0.0.1:${PORT}/readyz" >/dev/null 2>&1 && break
    sleep 1
  done
  python3 "$HERE/db-pool-burst.py" --base-url "http://127.0.0.1:${PORT}" --seed \
    --admin-user admin --admin-pass "$ADMIN_PASS" --files "${FILES:-200}"
  if [ "$DELAY" != "0" ]; then
    pid="$(docker inspect -f '{{.State.Pid}}' "$DB")"
    sudo nsenter -t "$pid" -n tc qdisc add dev eth0 root netem delay "${DELAY}ms"
  fi
  python3 "$HERE/db-pool-burst.py" --base-url "http://127.0.0.1:${PORT}" \
    --files "${FILES:-200}" --installers "${INSTALLERS:-24}" --parallel "${PARALLEL:-50}" \
    --retries "${RETRIES:-5}" --timeout "${CLIENT_TIMEOUT:-30}" --label "$label" --out "${OUT_DIR}/${label}.json" >/dev/null
  docker logs "$BE" 2>&1 | grep -E "WARN|ERROR" | tail -n 400 >"${OUT_DIR}/${label}.backend.log" || true
  echo ">> ${label}: ${OUT_DIR}/${label}.json" >&2
done

python3 - "$OUT_DIR" "$@" <<'EOF'
import json, sys
out = sys.argv[1]
rows = []
for spec in sys.argv[2:]:
    label = spec.split("=", 1)[0]
    r = json.load(open(f"{out}/{label}.json"))
    a, i, z = r["attempts"], r["installs"], r["readyz"]
    rows.append((label, i["ok"], i["failed"], i["wall_s"], a["total"], a["error_rate"],
                 a["all"]["p50_ms"], a["all"]["p99_ms"], a["ok_2xx"]["p99_ms"],
                 a["shed_503"]["p50_ms"], a["shed_503"]["p99_ms"],
                 json.dumps(a["status_mix"]), json.dumps(z["status_mix"]), z["latency"]["max_ms"]))
hdr = ("run", "inst_ok", "inst_fail", "wall_s", "attempts", "err_rate", "p50_ms", "p99_ms",
       "2xx_p99_ms", "503_p50_ms", "503_p99_ms", "status_mix", "readyz_mix", "readyz_max_ms")
print("| " + " | ".join(hdr) + " |")
print("|" + "---|" * len(hdr))
for row in rows:
    print("| " + " | ".join(str(c) for c in row) + " |")
EOF
