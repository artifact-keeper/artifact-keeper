#!/usr/bin/env bash
# =============================================================================
# scripts/perf/generic-manifest-download-memory.sh - backend memory and storage
# reads of a generic download of a Docker manifest path (#6358)
# =============================================================================
# Brings up Postgres and BACKEND_IMAGE (filesystem storage, no memory cap) on a
# private docker network, pushes a small manifest to a Docker repository, puts
# an OBJECT_MIB object in its place (the stored object and the row's digest,
# as anything written at that path would be), then measures, for a HEAD and
# for a GET of
#   /api/v1/repositories/<docker>/download/v2/big/manifests/1.0
# the backend's peak anonymous memory above its idle level (cgroup
# memory.stat, sampled every 50 ms) and the bytes the backend process read
# (/proc/1/io rchar). The GET body is checked against the object's sha256.
#
# Usage:
#   BACKEND_IMAGE=ghcr.io/artifact-keeper/artifact-keeper-backend:sha-XXXXXXX \
#     scripts/perf/generic-manifest-download-memory.sh [label]
# Env: OBJECT_MIB (default 256), RUNS (default 3), NET_SUFFIX (default 252,
#      picks the 172.30.<n>.0/24 network), NAME_PREFIX (default akperf6358,
#      names the network and containers), KEEP=1 leaves the stack up.
# Output: one line per request on stdout and <label>.tsv in the current
# directory. Needs docker, curl, jq, awk, sha256sum. Runs no cargo build.
# =============================================================================
set -euo pipefail

: "${BACKEND_IMAGE:?set BACKEND_IMAGE}"
LABEL="${1:-run}"
OBJECT_MIB="${OBJECT_MIB:-256}"
RUNS="${RUNS:-3}"
N="${NET_SUFFIX:-252}"
NET="${NAME_PREFIX:-akperf6358}-${N}"
PG="${NET}-pg"
BE="${NET}-be"
PASS='PerfRunner!2026secure'
WORK="$(mktemp -d)"
SAMPLER=""

cleanup() {
  [ -n "$SAMPLER" ] && kill "$SAMPLER" 2>/dev/null || true
  if [ "${KEEP:-0}" != "1" ]; then
    docker rm -f "$BE" "$PG" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

docker network create --subnet "172.30.${N}.0/24" "$NET" >/dev/null
docker run -d --name "$PG" --network "$NET" -e POSTGRES_USER=registry \
  -e POSTGRES_PASSWORD=registry -e POSTGRES_DB=artifact_registry postgres:16-alpine >/dev/null
for _ in $(seq 1 30); do docker exec "$PG" pg_isready -U registry >/dev/null 2>&1 && break; sleep 1; done
docker run -d --name "$BE" --network "$NET" -p 127.0.0.1::8080 \
  -e "DATABASE_URL=postgresql://registry:registry@${PG}:5432/artifact_registry" \
  -e STORAGE_PATH=/data/storage -e BACKUP_PATH=/data/backups -e PLUGINS_DIR=/data/plugins \
  -e JWT_SECRET=perf-nonprod-6358-manifest-download-0123456789 -e ADMIN_PASSWORD="$PASS" \
  -e HOST=0.0.0.0 -e PORT=8080 -e STORAGE_BACKEND=filesystem -e RATE_LIMIT_ENABLED=false \
  -e RUST_LOG=warn "$BACKEND_IMAGE" >/dev/null
PORT="$(docker port "$BE" 8080/tcp | head -n1 | sed 's/.*://')"
BASE="http://127.0.0.1:${PORT}"
for _ in $(seq 1 90); do curl -sf "$BASE/health" >/dev/null 2>&1 && break; sleep 1; done
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${PASS}\"}" | jq -r '.access_token // .token // empty')"
[ -n "$TOK" ] || { echo "login failed" >&2; exit 1; }
AH="Authorization: Bearer $TOK"
IMAGE_ID="$(docker inspect -f '{{.Image}}' "$BE" | cut -c8-19)"
psql_q() { docker exec "$PG" psql -U registry -d artifact_registry -tAc "$1" | tr -d '[:space:]'; }

curl -sf -o /dev/null -X POST "$BASE/api/v1/repositories" -H "$AH" -H 'Content-Type: application/json' \
  -d '{"key":"perf-docker","name":"perf-docker","format":"docker","repo_type":"local","is_public":false}'
CFG="$(printf '1%.0s' $(seq 1 64))"
MAN='{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:'"$CFG"'","size":2},"layers":[]}'
c="$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "$AH" \
  -H 'Content-Type: application/vnd.oci.image.manifest.v1+json' --data-binary "$MAN" \
  "$BASE/v2/perf-docker/big/manifests/1.0")"
[ "$c" = "201" ] || { echo "manifest push answered $c" >&2; exit 1; }
KEY="$(psql_q "SELECT a.storage_key FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = 'perf-docker' AND a.path = 'v2/big/manifests/1.0'")"
ROOT="$(psql_q "SELECT storage_path FROM repositories WHERE key = 'perf-docker'")"
head -c $((OBJECT_MIB * 1048576)) /dev/urandom > "$WORK/obj.bin"
SHA="$(sha256sum "$WORK/obj.bin" | awk '{print $1}')"
docker cp "$WORK/obj.bin" "${BE}:${ROOT}/${KEY}"
psql_q "UPDATE artifacts SET checksum_sha256 = '${SHA}' WHERE path = 'v2/big/manifests/1.0'" >/dev/null
URL="$BASE/api/v1/repositories/perf-docker/download/v2/big/manifests/1.0"

# The backend's anonymous memory: cgroup v2 memory.stat `anon`, or cgroup v1
# `total_rss`.
anon() {
  local stat
  stat="$(docker exec "$BE" cat /sys/fs/cgroup/memory.stat 2>/dev/null || true)"
  if [ -n "$stat" ]; then
    awk '/^anon /{print $2}' <<<"$stat"
  else
    docker exec "$BE" cat /sys/fs/cgroup/memory/memory.stat 2>/dev/null | awk '/^total_rss /{print $2}'
  fi
}
rchar() { docker exec "$BE" cat /proc/1/io | awk '/^rchar:/{print $2}'; }
mib() { awk -v b="$1" 'BEGIN{printf "%.1f", b/1048576}'; }

# measure <method>: one request; prints "<status> <peak anon delta MiB> <read MiB> <secs> <ok>"
measure() {
  local base r0 r1 t0 t1 code ok=yes
  sleep 2
  base="$(anon)"
  echo "$base" > "$WORK/peak"
  ( m="$base"; while :; do a="$(anon)"; [ -n "$a" ] && [ "$a" -gt "$m" ] && { m="$a"; echo "$m" > "$WORK/peak"; }; sleep 0.05; done ) &
  SAMPLER=$!
  r0="$(rchar)"; t0="$(date +%s.%N)"
  if [ "$1" = HEAD ]; then
    code="$(curl -s -I -o "$WORK/h" -w '%{http_code}' -H "$AH" "$URL")"
    grep -qi "^content-length: $((OBJECT_MIB * 1048576))" "$WORK/h" || ok=no
  else
    code="$(curl -s -o "$WORK/get.bin" -w '%{http_code}' -H "$AH" "$URL")"
    [ "$(sha256sum "$WORK/get.bin" | awk '{print $1}')" = "$SHA" ] || ok=no
    rm -f "$WORK/get.bin"
  fi
  t1="$(date +%s.%N)"; r1="$(rchar)"
  sleep 0.3
  kill "$SAMPLER" 2>/dev/null; wait "$SAMPLER" 2>/dev/null || true; SAMPLER=""
  echo "$code $(mib $(( $(cat "$WORK/peak") - base ))) $(mib $((r1 - r0))) $(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f", b-a}') $ok"
}

printf 'label\timage\tobject_mib\tmethod\trun\tstatus\tpeak_anon_delta_mib\tbackend_read_mib\tsecs\tlength_or_bytes_ok\n' > "${LABEL}.tsv"
for method in HEAD GET; do
  for run in $(seq 1 "$RUNS"); do
    read -r code peak read secs ok <<<"$(measure "$method")"
    printf '%s %s run %s: %s, peak anon +%s MiB, backend read %s MiB, %ss, ok=%s\n' \
      "$LABEL" "$method" "$run" "$code" "$peak" "$read" "$secs" "$ok"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$LABEL" "$IMAGE_ID" "$OBJECT_MIB" "$method" \
      "$run" "$code" "$peak" "$read" "$secs" "$ok" >> "${LABEL}.tsv"
  done
done
