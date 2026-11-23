#!/usr/bin/env bash
# =============================================================================
# scripts/perf/serve-verify-large-objects.sh - backend CPU and time to last
# byte of warm multi-GiB pulls with serve-time SHA-256 verification on and off
# (#6468)
# =============================================================================
# Brings up Postgres and BACKEND_IMAGE (filesystem storage on a docker volume)
# on a private docker network, and stores one object per size in SIZES_MIB:
#   * generic: a hosted generic artifact, served by
#     GET /api/v1/repositories/<repo>/download/<path>
#   * oci:     an OCI blob pushed through /v2 (monolithic upload), served by
#     GET /v2/<repo>/<image>/blobs/sha256:<digest>
# Then, for DOWNLOAD_VERIFY_CHECKSUMS=true and =false (the backend container
# is recreated on the same database and volume), and for each concurrency in
# CONCURRENCY, it runs N simultaneous GETs of the same object RUNS times and
# reports the backend's CPU time over the batch (host cgroup v2 cpu.stat), CPU
# seconds per GiB served, aggregate throughput, and p50/max time to last byte.
# Every body is checked for its full length. The pulls are over loopback, so
# the network is not the limit; compare the numbers with your link rate.
#
# Usage:
#   BACKEND_IMAGE=ghcr.io/artifact-keeper/artifact-keeper-backend:sha-XXXXXXX \
#     scripts/perf/serve-verify-large-objects.sh [label]
# Env: SIZES_MIB (default "1024 4096"), CONCURRENCY (default "1 8"),
#      ROUTES (default "generic oci"), RUNS (default 3), NET_SUFFIX
#      (default 246, picks 172.30.<n>.0/24), NAME_PREFIX (default
#      akperf6468), SKIP_CLIENT_VERIFIED (passed to the backend as
#      DOWNLOAD_VERIFY_SKIP_CLIENT_VERIFIED, e.g. "oci"; default empty),
#      KEEP=1 leaves the stack up.
# Output: one line per batch on stdout and <label>.tsv in the current
# directory. Needs docker, curl, jq, awk, sha256sum. Runs no cargo build.
# =============================================================================
set -euo pipefail

: "${BACKEND_IMAGE:?set BACKEND_IMAGE}"
LABEL="${1:-run}"
SIZES_MIB="${SIZES_MIB:-1024 4096}"
CONCURRENCY="${CONCURRENCY:-1 8}"
ROUTES="${ROUTES:-generic oci}"
RUNS="${RUNS:-3}"
N="${NET_SUFFIX:-246}"
NET="${NAME_PREFIX:-akperf6468}-${N}"
PG="${NET}-pg"
BE="${NET}-be"
VOL="${NET}-data"
PASS='PerfRunner!2026secure'
WORK="$(mktemp -d)"

cleanup() {
  if [ "${KEEP:-0}" != "1" ]; then
    docker rm -f "$BE" "$PG" >/dev/null 2>&1 || true
    docker volume rm "$VOL" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

docker network create --subnet "172.30.${N}.0/24" "$NET" >/dev/null
docker volume create "$VOL" >/dev/null
docker run -d --name "$PG" --network "$NET" -e POSTGRES_USER=registry \
  -e POSTGRES_PASSWORD=registry -e POSTGRES_DB=artifact_registry postgres:16-alpine >/dev/null
for _ in $(seq 1 30); do docker exec "$PG" pg_isready -U registry >/dev/null 2>&1 && break; sleep 1; done

# start_backend <true|false>: (re)create the backend with verification on/off.
start_backend() {
  docker rm -f "$BE" >/dev/null 2>&1 || true
  docker run -d --name "$BE" --network "$NET" -p 127.0.0.1::8080 -v "$VOL:/data" \
    -e "DATABASE_URL=postgresql://registry:registry@${PG}:5432/artifact_registry" \
    -e STORAGE_PATH=/data/storage -e BACKUP_PATH=/data/backups -e PLUGINS_DIR=/data/plugins \
    -e JWT_SECRET=perf-nonprod-6468-serve-verify-0123456789abcdef -e ADMIN_PASSWORD="$PASS" \
    -e HOST=0.0.0.0 -e PORT=8080 -e STORAGE_BACKEND=filesystem -e RATE_LIMIT_ENABLED=false \
    -e "DOWNLOAD_VERIFY_CHECKSUMS=$1" -e "DOWNLOAD_VERIFY_SKIP_CLIENT_VERIFIED=${SKIP_CLIENT_VERIFIED:-}" \
    -e RUST_LOG=warn "$BACKEND_IMAGE" >/dev/null
  PORT="$(docker port "$BE" 8080/tcp | head -n1 | sed 's/.*://')"
  BASE="http://127.0.0.1:${PORT}"
  for _ in $(seq 1 120); do curl -sf "$BASE/health" >/dev/null 2>&1 && break; sleep 1; done
  TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"admin\",\"password\":\"${PASS}\"}" | jq -r '.access_token // .token // empty')"
  [ -n "$TOK" ] || { echo "login failed" >&2; exit 1; }
  AH="Authorization: Bearer $TOK"
}

# Backend CPU time in microseconds, read on the host from the container's
# cgroup (the image has no shell): cgroup v2 cpu.stat, systemd or cgroupfs
# driver.
cpu_us() {
  local id f
  id="$(docker inspect -f '{{.Id}}' "$BE")"
  for f in "/sys/fs/cgroup/system.slice/docker-${id}.scope/cpu.stat" "/sys/fs/cgroup/docker/${id}/cpu.stat"; do
    [ -r "$f" ] && { awk '/^usage_usec /{print $2}' "$f"; return; }
  done
  echo "cannot find the backend's cgroup cpu.stat" >&2; exit 1
}

start_backend true
IMAGE_ID="$(docker inspect -f '{{.Image}}' "$BE" | cut -c8-19)"
for r in perf-generic perf-oci; do
  fmt=generic; [ "$r" = perf-oci ] && fmt=docker
  curl -sf -o /dev/null -X POST "$BASE/api/v1/repositories" -H "$AH" -H 'Content-Type: application/json' \
    -d "{\"key\":\"$r\",\"name\":\"$r\",\"format\":\"$fmt\",\"repo_type\":\"local\",\"is_public\":false}"
done

declare -A URL SHA
for s in $SIZES_MIB; do
  f="$WORK/obj-$s.bin"
  head -c $((s * 1048576)) /dev/urandom > "$f"
  SHA[$s]="$(sha256sum "$f" | awk '{print $1}')"
  if [[ " $ROUTES " == *" generic "* ]]; then
    c="$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "$AH" -T "$f" \
      "$BASE/api/v1/repositories/perf-generic/artifacts/big/${s}/obj-${s}.bin")"
    case "$c" in 200|201) ;; *) echo "generic upload of ${s} MiB answered $c" >&2; exit 1 ;; esac
    URL[generic-$s]="/api/v1/repositories/perf-generic/download/big/${s}/obj-${s}.bin"
  fi
  if [[ " $ROUTES " == *" oci "* ]]; then
    loc="$(curl -s -D - -o /dev/null -X POST -H "$AH" "$BASE/v2/perf-oci/big/blobs/uploads/" \
      | awk 'tolower($1)=="location:"{print $2}' | tr -d '\r')"
    case "$loc" in http*) ;; *) loc="$BASE$loc" ;; esac
    sep='?'; [[ "$loc" == *\?* ]] && sep='&'
    c="$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "$AH" -H 'Content-Type: application/octet-stream' \
      -T "$f" "${loc}${sep}digest=sha256:${SHA[$s]}")"
    [ "$c" = "201" ] || { echo "OCI blob push of ${s} MiB answered $c" >&2; exit 1; }
    URL[oci-$s]="/v2/perf-oci/big/blobs/sha256:${SHA[$s]}"
  fi
  rm -f "$f"
done

# batch <url> <bytes> <n>: n simultaneous GETs; prints
# "<cpu_s> <wall_s> <p50_ttlb_s> <max_ttlb_s> <ok>"
batch() {
  local url="$1" bytes="$2" n="$3" c0 c1 t0 t1 ok=yes i
  rm -f "$WORK"/r.*
  c0="$(cpu_us)"; t0="$(date +%s.%N)"
  for i in $(seq 1 "$n"); do
    curl -s -o /dev/null -H "$AH" -w '%{http_code} %{size_download} %{time_total}\n' "$url" > "$WORK/r.$i" &
  done
  wait
  t1="$(date +%s.%N)"; c1="$(cpu_us)"
  for i in $(seq 1 "$n"); do
    read -r code size _ < "$WORK/r.$i"
    { [ "$code" = 200 ] && [ "$size" = "$bytes" ]; } || ok=no
  done
  local times
  times="$(awk '{print $3}' "$WORK"/r.* | sort -n)"
  echo "$(awk -v a="$c0" -v b="$c1" 'BEGIN{printf "%.2f", (b-a)/1e6}') \
$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f", b-a}') \
$(awk -v n="$n" 'NR==int((n+1)/2){printf "%.2f", $1}' <<<"$times") \
$(tail -n1 <<<"$times" | awk '{printf "%.2f", $1}') $ok"
}

printf 'label\timage\troute\tsize_mib\tverify\tconcurrency\trun\tbackend_cpu_s\tcpu_s_per_gib\twall_s\tagg_mb_s\tp50_ttlb_s\tmax_ttlb_s\tok\n' > "${LABEL}.tsv"
for verify in true false; do
  start_backend "$verify"
  for route in $ROUTES; do
    for s in $SIZES_MIB; do
      url="${URL[$route-$s]}"; [[ "$url" == /* ]] && url="$BASE$url"
      bytes=$((s * 1048576))
      batch "$url" "$bytes" 1 >/dev/null   # warm the page cache
      for n in $CONCURRENCY; do
        for run in $(seq 1 "$RUNS"); do
          read -r cpu wall p50 max ok <<<"$(batch "$url" "$bytes" "$n")"
          gib="$(awk -v b="$bytes" -v n="$n" 'BEGIN{printf "%.3f", b*n/1073741824}')"
          per="$(awk -v c="$cpu" -v g="$gib" 'BEGIN{printf "%.2f", c/g}')"
          mbs="$(awk -v b="$bytes" -v n="$n" -v w="$wall" 'BEGIN{printf "%.0f", b*n/1e6/w}')"
          printf '%s %-7s %5s MiB verify=%-5s x%s run %s: cpu %ss (%s s/GiB), wall %ss, %s MB/s, ttlb p50 %ss max %ss, ok=%s\n' \
            "$LABEL" "$route" "$s" "$verify" "$n" "$run" "$cpu" "$per" "$wall" "$mbs" "$p50" "$max" "$ok"
          printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$LABEL" "$IMAGE_ID" "$route" "$s" \
            "$verify" "$n" "$run" "$cpu" "$per" "$wall" "$mbs" "$p50" "$max" "$ok" >> "${LABEL}.tsv"
        done
      done
    done
  done
done
