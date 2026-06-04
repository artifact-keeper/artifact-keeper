#!/usr/bin/env bash
# Multi-replica single-flight race driver (#1624).
#
# Reproduces #1606: per-process singleflight races across replicas serving
# partial/truncated artifacts. Acceptance gate for #1609.
#
# Mirrors the scripts/stress/ pattern: fire a concurrent storm, capture every
# response, validate, print a PASS/FAIL summary, exit non-zero on failure.
#
# Preconditions: the concurrency-e2e stack is up with >=3 backend replicas:
#   docker compose -f docker-compose.concurrency-e2e.yml up -d --scale backend=3
#
# What it does:
#   1. Authenticates against the LB.
#   2. Creates a maven REMOTE (proxy) repo pointed at the mock upstream.
#   3. Resets the mock upstream fetch counter.
#   4. Fires N concurrent GETs (default 200) for the SINGLE uncached artifact
#      through the LB (round-robined across replicas).
#   5. Asserts:
#        A1 upstream fetch counter == 1 (modulo FETCH_TOLERANCE)
#        A2 every response is HTTP 200 with sha256 == the published digest
#        A3 exactly one cached blob in the object store
#
# Environment (with defaults):
#   LB_URL              http://localhost:18080   load balancer in front of replicas
#   MOCK_UPSTREAM_URL   http://localhost:19999   mock upstream control plane (host side)
#   MOCK_UPSTREAM_INTERNAL  http://mock-upstream:9999  what the backend uses to reach upstream
#   ADMIN_USER          admin
#   ADMIN_PASS          TestRunner!2026secure
#   CONCURRENCY         200                      number of concurrent GETs
#   REPO_KEY            maven-race-proxy
#   ARTIFACT_PATH       race/big-artifact.bin    path under the proxy repo
#   RESULTS_DIR         /tmp/concurrency-results
#   FETCH_TOLERANCE     0                        allow counter up to 1+tolerance
#   MINIO_ALIAS_CMD     (auto)                   how to count blobs in MinIO
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/concurrency/assert_lib.sh
. "$SCRIPT_DIR/assert_lib.sh"

LB_URL="${LB_URL:-http://localhost:18080}"
MOCK_UPSTREAM_URL="${MOCK_UPSTREAM_URL:-http://localhost:19999}"
MOCK_UPSTREAM_INTERNAL="${MOCK_UPSTREAM_INTERNAL:-http://mock-upstream:9999}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-TestRunner!2026secure}"
CONCURRENCY="${CONCURRENCY:-200}"
REPO_KEY="${REPO_KEY:-maven-race-proxy}"
ARTIFACT_PATH="${ARTIFACT_PATH:-race/big-artifact.bin}"
RESULTS_DIR="${RESULTS_DIR:-/tmp/concurrency-results}"
API_URL="$LB_URL/api/v1"
MINIO_NETWORK="${MINIO_NETWORK:-concurrency-e2e-network}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

# Run an `mc` command line inside the compose network and stream its stdout to
# the host. The minio/mc image's ENTRYPOINT is `mc` and it ships NO shell utils
# (no grep/awk), so we (a) override the entrypoint to /bin/sh and (b) do all
# text processing on the HOST side. `$1` is the mc command (without the leading
# `mc`), e.g. mc_in_network "ls -r local/artifact-keeper/".
mc_in_network() {
    docker run --rm --network "$MINIO_NETWORK" --entrypoint /bin/sh minio/mc:latest -c \
        "mc alias set local http://minio:9000 minioadmin minioadmin >/dev/null 2>&1 && mc $1" 2>/dev/null
}

echo "=============================================="
echo "Multi-Replica Single-Flight Race (#1624)"
echo "=============================================="
echo "LB URL:            $LB_URL"
echo "Mock upstream:     $MOCK_UPSTREAM_URL (internal: $MOCK_UPSTREAM_INTERNAL)"
echo "Concurrency:       $CONCURRENCY"
echo "Proxy repo:        $REPO_KEY (maven, remote)"
echo "Artifact path:     $ARTIFACT_PATH"
echo "Results dir:       $RESULTS_DIR"
echo ""

mkdir -p "$RESULTS_DIR"
rm -f "$RESULTS_DIR"/*.bin "$RESULTS_DIR"/results.csv "$RESULTS_DIR"/summary.json 2>/dev/null || true

# ---------------------------------------------------------------------------
# Step 0: published digest from the mock upstream
# ---------------------------------------------------------------------------
echo "==> Fetching published digest from mock upstream..."
DIGEST_JSON=$(curl -sf "$MOCK_UPSTREAM_URL/__digest__" 2>/dev/null) || {
    echo "ERROR: mock upstream not reachable at $MOCK_UPSTREAM_URL/__digest__"
    echo "Is the stack up? docker compose -f docker-compose.concurrency-e2e.yml up -d --scale backend=3"
    exit 2
}
EXPECTED_SHA=$(echo "$DIGEST_JSON" | sed -n 's/.*"sha256":"\([0-9a-f]*\)".*/\1/p')
EXPECTED_SIZE=$(echo "$DIGEST_JSON" | sed -n 's/.*"size":\([0-9]*\).*/\1/p')
if [ -z "$EXPECTED_SHA" ]; then
    echo "ERROR: could not parse digest from: $DIGEST_JSON"
    exit 2
fi
echo "  Published sha256: $EXPECTED_SHA"
echo "  Published size:   $EXPECTED_SIZE bytes"
echo ""

# ---------------------------------------------------------------------------
# Step 1: authenticate against the LB
# ---------------------------------------------------------------------------
echo "==> Authenticating against the load balancer..."
LOGIN_RESP=$(curl -sf -X POST "$API_URL/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" 2>&1) || {
    echo "ERROR: failed to authenticate at $API_URL/auth/login. Are the backends healthy?"
    exit 2
}
TOKEN=$(echo "$LOGIN_RESP" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
if [ -z "$TOKEN" ]; then
    echo "ERROR: no access_token in login response: $LOGIN_RESP"
    exit 2
fi
AUTH="Authorization: Bearer $TOKEN"
echo "  Authenticated."
echo ""

# ---------------------------------------------------------------------------
# Step 2: create the maven remote proxy repo pointed at the mock upstream
# ---------------------------------------------------------------------------
# Cold-cache guarantee: a WARM cache hides the race entirely (every request
# becomes a cache hit, upstream is never touched, and the harness can neither
# pass nor fail meaningfully). Wipe the shared object store before each storm
# unless explicitly disabled. Runs `mc` inside the compose network so it works
# regardless of host port remapping.
if [ "${WIPE_CACHE:-1}" = "1" ] && docker ps >/dev/null 2>&1; then
    echo "==> Wiping shared object store for a cold cache (set WIPE_CACHE=0 to skip)..."
    # Remove every cached object, then confirm the bucket is empty. We delete the
    # whole proxy-cache prefix recursively. `rm -r --force` on the prefix is the
    # reliable form against this MinIO (whole-bucket `rb` is flaky here).
    mc_in_network "rm -r --force local/artifact-keeper/proxy-cache" >/dev/null 2>&1 || true
    REMAINING=$(mc_in_network "ls -r local/artifact-keeper/" | grep -c '__content__' || true)
    REMAINING="${REMAINING:-0}"
    if [ "$REMAINING" = "0" ]; then
        echo "  object store wiped (0 cached blobs)"
    else
        echo "  WARNING: $REMAINING cached blob(s) survived the wipe; the race may be masked by a warm cache"
    fi
fi

echo "==> Creating maven remote proxy repo '$REPO_KEY' -> $MOCK_UPSTREAM_INTERNAL ..."
curl -s -o /dev/null -X DELETE "$API_URL/repositories/$REPO_KEY" -H "$AUTH" 2>/dev/null || true
CREATE_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/repositories" \
    -H "$AUTH" -H 'Content-Type: application/json' \
    -d "{\"key\":\"$REPO_KEY\",\"name\":\"Maven Race Proxy\",\"format\":\"maven\",\"repo_type\":\"remote\",\"is_public\":true,\"upstream_url\":\"$MOCK_UPSTREAM_INTERNAL\"}")
if [ "$CREATE_CODE" != "200" ] && [ "$CREATE_CODE" != "201" ]; then
    echo "ERROR: repo create returned HTTP $CREATE_CODE"
    exit 2
fi
echo "  Repo created (HTTP $CREATE_CODE)."
echo ""

# ---------------------------------------------------------------------------
# Step 3: reset the upstream fetch counter so the count reflects THIS storm
# ---------------------------------------------------------------------------
echo "==> Resetting mock upstream fetch counter..."
curl -s -o /dev/null -X POST "$MOCK_UPSTREAM_URL/__reset__" || true
PRE_COUNT=$(curl -sf "$MOCK_UPSTREAM_URL/__count__" | sed -n 's/.*"fetches":\([0-9]*\).*/\1/p')
echo "  Counter reset to: ${PRE_COUNT:-?}"
echo ""

# Proxy GET URL through the LB. Maven proxy route: GET /maven/<repo>/*path,
# which maps to upstream <upstream_url>/<path> => mock /race/big-artifact.bin.
PROXY_GET_URL="$LB_URL/maven/$REPO_KEY/$ARTIFACT_PATH"

# ---------------------------------------------------------------------------
# Step 4: fire N concurrent GETs for the single uncached artifact
# ---------------------------------------------------------------------------
echo "==> Firing $CONCURRENCY concurrent GETs at: $PROXY_GET_URL"
echo "idx,status,sha256,bytes" > "$RESULTS_DIR/results.csv"

fetch_one() {
    local idx="$1"
    local out="$RESULTS_DIR/resp-$idx.bin"
    local status sha bytes
    # `--http1.1` + no connection reuse keeps `%{http_code}` to a single value
    # (otherwise curl can emit the code once per reused/retried connection and
    # the field becomes e.g. "200200"). Take the LAST 3 digits defensively.
    status=$(curl -s -o "$out" -w "%{http_code}" --http1.1 -H 'Connection: close' \
        --max-time 300 "$PROXY_GET_URL" 2>/dev/null || echo "000")
    status="${status: -3}"
    sha=$(sha256_of_file "$out")
    bytes=$(wc -c < "$out" 2>/dev/null | tr -d ' ')
    echo "$idx,$status,$sha,$bytes" >> "$RESULTS_DIR/results.csv"
    # Keep only the first few bodies for forensic inspection; delete the rest to
    # avoid filling the disk with N * 256 MB.
    if [ "$idx" -gt 5 ]; then rm -f "$out"; fi
}

START_TIME=$(date +%s)
PIDS=()
for i in $(seq 1 "$CONCURRENCY"); do
    fetch_one "$i" &
    PIDS+=("$!")
done
# Wait for ALL of them so the storm is genuinely concurrent (no batching).
for pid in "${PIDS[@]}"; do wait "$pid"; done
END_TIME=$(date +%s)
echo "  Storm complete in $((END_TIME - START_TIME))s."
echo ""

# ---------------------------------------------------------------------------
# Step 5: gather post-storm facts
# ---------------------------------------------------------------------------
# Settle window: a leader replica whose client disconnected may still be
# draining the upstream body after the client-side curl returned. The counter
# is incremented at fetch START, so this mainly lets any just-started fetches
# register. Without it the counter can be read a beat too early and under-count.
SETTLE_SECS="${SETTLE_SECS:-3}"
sleep "$SETTLE_SECS"

echo "==> Reading mock upstream fetch counter..."
POST_COUNT=$(curl -sf "$MOCK_UPSTREAM_URL/__count__" | sed -n 's/.*"fetches":\([0-9]*\).*/\1/p')
POST_COUNT="${POST_COUNT:-0}"
echo "  Upstream fetch counter: $POST_COUNT"
echo ""

echo "==> Counting cached blobs in object store..."
# A3: count cached blob objects under proxy-cache/<repo>/ in MinIO. Each cached
# artifact has one `__content__` object; we count those. The listing is produced
# inside the compose network (works regardless of host port remapping) and
# counted on the HOST (the mc image has no grep). Falls back to "unknown" if
# docker is unavailable.
BLOB_COUNT="unknown"
if docker ps >/dev/null 2>&1; then
    BLOB_COUNT=$(mc_in_network "ls -r local/artifact-keeper/proxy-cache/$REPO_KEY/" \
        | grep -c '__content__$' || true)
    BLOB_COUNT="${BLOB_COUNT:-0}"
fi
echo "  Cached blob count: $BLOB_COUNT"
echo ""

# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------
echo "=============================================="
echo "Assertions"
echo "=============================================="
FAILED=0

echo "--- A1: exactly one upstream fetch ---"
A1=$(assert_fetch_counter_one "$POST_COUNT"); A1_RC=$?
if [ "$A1_RC" -eq 0 ]; then echo -e "  ${GREEN}$A1${NC}"; else echo -e "  ${RED}$A1${NC}"; FAILED=$((FAILED+1)); fi

echo "--- A2: every response 200 + correct sha256 ---"
A2=$(assert_all_responses_ok "$RESULTS_DIR/results.csv" "$EXPECTED_SHA"); A2_RC=$?
if [ "$A2_RC" -eq 0 ]; then echo -e "  ${GREEN}$A2${NC}"; else echo -e "  ${RED}$A2${NC}"; FAILED=$((FAILED+1)); fi

echo "--- A3: exactly one cached blob ---"
if [ "$BLOB_COUNT" = "unknown" ]; then
    echo -e "  ${YELLOW}SKIP could not count blobs (no mc / docker on host)${NC}"
else
    A3=$(assert_single_cached_blob "$BLOB_COUNT"); A3_RC=$?
    if [ "$A3_RC" -eq 0 ]; then echo -e "  ${GREEN}$A3${NC}"; else echo -e "  ${RED}$A3${NC}"; FAILED=$((FAILED+1)); fi
fi
echo ""

# Per-status breakdown for the summary.
OK_COUNT=$(awk -F',' 'NR>1 && $2=="200"{c++} END{print c+0}' "$RESULTS_DIR/results.csv")
BAD_COUNT=$(awk -F',' 'NR>1 && $2!="200"{c++} END{print c+0}' "$RESULTS_DIR/results.csv")
DIGEST_OK=$(awk -F',' -v e="$EXPECTED_SHA" 'NR>1 && $3==e{c++} END{print c+0}' "$RESULTS_DIR/results.csv")
DIGEST_BAD=$(awk -F',' -v e="$EXPECTED_SHA" 'NR>1 && $3!=e{c++} END{print c+0}' "$RESULTS_DIR/results.csv")

cat > "$RESULTS_DIR/summary.json" <<EOF
{
  "test": "multireplica_singleflight_race",
  "issue": 1624,
  "reproduces": 1606,
  "gate_for": 1609,
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "config": {
    "concurrency": $CONCURRENCY,
    "repo_key": "$REPO_KEY",
    "artifact_path": "$ARTIFACT_PATH",
    "expected_sha256": "$EXPECTED_SHA",
    "expected_size": ${EXPECTED_SIZE:-0},
    "fetch_tolerance": ${FETCH_TOLERANCE:-0}
  },
  "results": {
    "upstream_fetch_count": $POST_COUNT,
    "cached_blob_count": "$BLOB_COUNT",
    "responses_200": $OK_COUNT,
    "responses_non_200": $BAD_COUNT,
    "digest_match": $DIGEST_OK,
    "digest_mismatch": $DIGEST_BAD,
    "failed_assertions": $FAILED
  }
}
EOF

echo "=============================================="
echo "Summary"
echo "=============================================="
echo "  Concurrency:            $CONCURRENCY"
echo "  Upstream fetch count:   $POST_COUNT  (expected 1)"
echo "  Cached blob count:      $BLOB_COUNT  (expected 1)"
echo "  Responses 200:          $OK_COUNT / $CONCURRENCY"
echo "  Responses non-200:      $BAD_COUNT"
echo "  Digest match:           $DIGEST_OK"
echo "  Digest mismatch:        $DIGEST_BAD"
echo "  Summary written to:     $RESULTS_DIR/summary.json"
echo ""

if [ "$FAILED" -gt 0 ]; then
    echo -e "${RED}=============================================="
    echo "RACE HARNESS FAILED ($FAILED assertion(s))"
    echo "==============================================${NC}"
    echo ""
    echo "On current 'main' this is the EXPECTED outcome: it reproduces #1606"
    echo "(per-process single-flight does not coordinate across replicas)."
    echo "This harness flips green once #1609 lands."
    exit 1
fi

echo -e "${GREEN}=============================================="
echo "RACE HARNESS PASSED"
echo "==============================================${NC}"
echo ""
echo "Cross-process single-flight is holding: one upstream fetch, one cached"
echo "blob, every client received the full untruncated artifact."
