#!/usr/bin/env bash
# =============================================================================
# scripts/perf/upstream-circuit-breaker.sh - requests and latency through a
# Virtual with one dead member, and a Remote serving stale behind a dead
# upstream (#5013)
# =============================================================================
# Brings up Postgres, a mock upstream and BACKEND_IMAGE on a private docker
# network, then measures three upstream failure modes:
#
#   refused     the member's upstream is a closed port (connection refused)
#   blackhole   the member's upstream drops every SYN (a listener whose accept
#               queue is full, so the kernel discards new SYNs; the client
#               waits out PROXY_UPSTREAM_CONNECT_TIMEOUT_SECS, 10 s)
#   stale       a generic Remote whose cached entry has expired, its upstream
#               switched to the black hole (the stale-if-error path of #5013's
#               comments)
#
# For refused and blackhole: a Helm Virtual over [dead member, healthy member]
# answers GET index.yaml REQS times one after another, then BURST times at
# once. For stale: the Remote answers its expired file REQS times. Reported per
# phase: HTTP statuses, wall time, p50 / p95 / max latency, and the upstream
# contact the dead member cost, read from the mock's own kernel counters (its
# network namespace carries only this traffic):
#   refused    TCP resets the mock sent (one per refused connect)
#   blackhole  SYNs its full accept queue dropped (a connect that waits out
#              the 10 s connect timeout is retried ~4 times by the kernel)
#
# Usage:
#   BACKEND_IMAGE=ghcr.io/artifact-keeper/artifact-keeper-backend:sha-XXXXXXX \
#     scripts/perf/upstream-circuit-breaker.sh [label]
# Env: REQS (default 30), BURST (default 20), NET_SUFFIX (default 251, picks
#      the 172.30.<n>.0/24 network), KEEP=1 leaves the stack up.
# Output: a table on stdout and <label>.tsv in the current directory.
# Needs docker, curl, jq, awk. Runs no cargo build.
# =============================================================================
set -euo pipefail

: "${BACKEND_IMAGE:?set BACKEND_IMAGE}"
LABEL="${1:-run}"
REQS="${REQS:-30}"
BURST="${BURST:-20}"
N="${NET_SUFFIX:-251}"
NET="akperf5013-${N}"
SUBNET="172.30.${N}.0/24"
MOCK_IP="172.30.${N}.10"
PG="akperf5013-${N}-pg"
MOCK="akperf5013-${N}-mock"
BE="akperf5013-${N}-be"
PASS='PerfRunner!2026secure'
WORK="$(mktemp -d)"

cleanup() {
  if [ "${KEEP:-0}" != "1" ]; then
    docker rm -f "$BE" "$MOCK" "$PG" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# --- mock upstream -----------------------------------------------------------
# :80 serves any path (a Helm index for */index.yaml, fixed bytes otherwise)
# :81 black hole: listen(0), never accept, accept queue pre-filled
# :9  nothing listens: connection refused
cat > "$WORK/mock.py" <<'PY'
import socket, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

INDEX = b"""apiVersion: v1
entries:
  perfchart:
  - apiVersion: v2
    name: perfchart
    version: 1.0.0
    created: "2020-01-01T00:00:00Z"
    digest: 0000000000000000000000000000000000000000000000000000000000000000
    urls:
    - charts/perfchart-1.0.0.tgz
generated: "2020-01-01T00:00:00Z"
"""
BLOB = b"x" * 4096

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def _send(self, head):
        body = INDEX if self.path.endswith("/index.yaml") else BLOB
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("ETag", '"perf-v1"')
        self.end_headers()
        if not head:
            self.wfile.write(body)
    def do_GET(self):
        self._send(False)
    def do_HEAD(self):
        self._send(True)

hole = socket.socket()
hole.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
hole.bind(("0.0.0.0", 81))
hole.listen(0)
fillers = []
for _ in range(4):
    s = socket.socket()
    s.setblocking(False)
    try:
        s.connect(("127.0.0.1", 81))
    except BlockingIOError:
        pass
    fillers.append(s)
ThreadingHTTPServer(("0.0.0.0", 80), H).serve_forever()
PY

docker network create --subnet "$SUBNET" "$NET" >/dev/null
docker run -d --name "$PG" --network "$NET" -e POSTGRES_USER=registry \
  -e POSTGRES_PASSWORD=registry -e POSTGRES_DB=artifact_registry postgres:16-alpine >/dev/null
docker run -d --name "$MOCK" --network "$NET" --ip "$MOCK_IP" \
  -v "$WORK/mock.py:/mock.py:ro" python:3.12-slim python3 /mock.py >/dev/null
for _ in $(seq 1 30); do docker exec "$PG" pg_isready -U registry >/dev/null 2>&1 && break; sleep 1; done
docker run -d --name "$BE" --network "$NET" -p 127.0.0.1::8080 \
  -e "DATABASE_URL=postgresql://registry:registry@${PG}:5432/artifact_registry" \
  -e STORAGE_PATH=/data/storage -e BACKUP_PATH=/data/backups -e PLUGINS_DIR=/data/plugins \
  -e JWT_SECRET=perf-nonprod-5013-circuit-breaker-0123456789 -e ADMIN_PASSWORD="$PASS" \
  -e HOST=0.0.0.0 -e PORT=8080 -e STORAGE_BACKEND=filesystem -e RATE_LIMIT_ENABLED=false \
  -e UPSTREAM_ALLOW_PRIVATE_IPS=true -e AK_SSRF_ALLOW_PRIVATE_CIDRS="${MOCK_IP}/32" \
  -e RUST_LOG=info "$BACKEND_IMAGE" >/dev/null
PORT="$(docker port "$BE" 8080/tcp | head -n1 | sed 's/.*://')"
BASE="http://127.0.0.1:${PORT}"
for _ in $(seq 1 90); do curl -sf "$BASE/health" >/dev/null 2>&1 && break; sleep 1; done
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${PASS}\"}" | jq -r '.access_token // .token // empty')"
[ -n "$TOK" ] || { echo "login failed" >&2; exit 1; }
IMAGE_ID="$(docker inspect -f '{{.Image}}' "$BE" | cut -c8-19)"

api() { curl -s -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' "$@"; }
mk() { # <key> <format> <type> [upstream]
  api -X POST "$BASE/api/v1/repositories" -d "$(jq -n --arg k "$1" --arg f "$2" --arg t "$3" --arg u "${4:-}" \
    '{key:$k,name:$k,format:$f,repo_type:$t,is_public:false} + (if $u == "" then {} else {upstream_url:$u} end)')" >/dev/null
}
member() { api -X POST "$BASE/api/v1/repositories/$1/members" -d "{\"member_key\":\"$2\",\"priority\":$3}" >/dev/null; }

# One request: "<status> <seconds>".
one() { curl -s -o /dev/null --max-time 120 -w '%{http_code} %{time_total}\n' -H "Authorization: Bearer $TOK" "$BASE$1"; }

# summarize <phase> <file of "status secs" lines> <wall secs> <attempts>
summarize() {
  sort -k2 -n "$2" | awk -v phase="$1" -v wall="$3" -v att="$4" -v label="$LABEL" '
    { st[$1]++; t[NR]=$2 }
    END {
      p50=t[int((NR+1)*0.50)]; p95=t[int((NR*0.95)+0.999)]; if (p95=="") p95=t[NR];
      s=""; for (k in st) s=s k "x" st[k] " ";
      printf "%s\t%s\t%d\t%s\t%.2f\t%.3f\t%.3f\t%.3f\t%s\n", label, phase, NR, s, wall, p50, p95, t[NR], att
    }' | tee -a "$OUT"
}

# The mock's TCP resets sent and SYNs dropped by its full accept queue.
mock_counters() {
  docker exec "$MOCK" python3 -c '
def row(path, prefix):
    lines = [l.split() for l in open(path) if l.startswith(prefix)]
    return dict(zip(lines[0][1:], map(int, lines[1][1:])))
t = row("/proc/net/snmp", "Tcp:")
x = row("/proc/net/netstat", "TcpExt:")
print(t["OutRsts"], x["ListenDrops"])'
}
# <before "rsts drops"> -> the contact the phase cost the dead member
count_attempts() { # <port> <before>
  local now; now="$(mock_counters)"
  if [ "$1" = "81" ]; then
    echo "$(( $(echo "$now" | cut -d' ' -f2) - $(echo "$2" | cut -d' ' -f2) )) syn-drops"
  else
    echo "$(( $(echo "$now" | cut -d' ' -f1) - $(echo "$2" | cut -d' ' -f1) )) resets"
  fi
}

run_seq() { # <phase> <path> <dead port>
  local f="$WORK/$1.seq" t0 t1 before
  : > "$f"; before="$(mock_counters)"; t0="$(date +%s.%N)"
  for _ in $(seq 1 "$REQS"); do one "$2" >> "$f"; done
  t1="$(date +%s.%N)"; sleep 1
  summarize "$1/seq" "$f" "$(awk -v a="$t0" -v b="$t1" 'BEGIN{print b-a}')" "$(count_attempts "$3" "$before")"
}
run_burst() { # <phase> <path> <dead port>
  local f="$WORK/$1.burst" t0 t1 before pids=""
  : > "$f"; before="$(mock_counters)"; t0="$(date +%s.%N)"
  for i in $(seq 1 "$BURST"); do one "$2" > "$f.$i" & pids="$pids $!"; done
  # shellcheck disable=SC2086
  wait $pids; t1="$(date +%s.%N)"; cat "$f".* > "$f"; sleep 1
  summarize "$1/burst" "$f" "$(awk -v a="$t0" -v b="$t1" 'BEGIN{print b-a}')" "$(count_attempts "$3" "$before")"
}

OUT="$PWD/${LABEL}.tsv"
printf 'label\tphase\tn\tstatuses\twall_s\tp50_s\tp95_s\tmax_s\tdead_upstream_contact\n' | tee "$OUT"
echo "# image ${BACKEND_IMAGE} (${IMAGE_ID})" >&2

mk perf-ok helm remote "http://${MOCK_IP}:80/ok"
for mode in refused blackhole; do
  port=9; [ "$mode" = "blackhole" ] && port=81
  mk "perf-${mode}" helm remote "http://${MOCK_IP}:${port}/dead"
  mk "perf-v-${mode}" helm virtual
  member "perf-v-${mode}" "perf-${mode}" 1
  member "perf-v-${mode}" perf-ok 2
  run_seq "virtual-${mode}" "/helm/perf-v-${mode}/index.yaml" "$port"
  run_burst "virtual-${mode}" "/helm/perf-v-${mode}/index.yaml" "$port"
done

# Stale: prime through the healthy port, expire, then black-hole the upstream.
mk perf-stale generic remote "http://${MOCK_IP}:80/files/"
one "/api/v1/repositories/perf-stale/download/a/f.bin" >/dev/null
api -X PUT "$BASE/api/v1/repositories/perf-stale/cache-ttl" -d '{"cache_ttl_seconds":1}' >/dev/null
api -X PATCH "$BASE/api/v1/repositories/perf-stale" -d "{\"upstream_url\":\"http://${MOCK_IP}:81/files/\"}" >/dev/null
sleep 3
run_seq "remote-stale-blackhole" "/api/v1/repositories/perf-stale/download/a/f.bin" 81

echo "# wrote ${OUT}" >&2
