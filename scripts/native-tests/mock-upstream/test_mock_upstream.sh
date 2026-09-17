#!/usr/bin/env bash
# Standalone HTTP-contract tests for mock_upstream.py (#3950).
#
# Runs WITHOUT Docker or the artifact-keeper stack: boots the mock on a loopback
# port and drives it with curl, so the mock's own semantics are trustworthy
# independent of a full cache-correctness run.
#
# The contract under test is the one the backend actually depends on: its
# TTL-expiry revalidation is a CONDITIONAL HEAD
# (`UpstreamClient::check_etag_changed`, backend/src/services/proxy_service.rs),
# so a HEAD must answer 304 to a matching `If-None-Match` and count as a
# revalidation. A HEAD that always answered an unconditional 200 with no ETag
# left `revalidations` at 0 and made every revalidation look like a change.
#
# Usage: ./scripts/native-tests/mock-upstream/test_mock_upstream.sh
# Requires: bash, python3, curl, jq.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAR="/maven2/com/example/widget/1.0.0/widget-1.0.0.jar"
MD="/maven2/com/example/widget/maven-metadata.xml"

PASS=0; FAIL=0
ok()  { echo "  ok   - $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL - $1"; FAIL=$((FAIL+1)); }
expect_eq() { # desc expected actual
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}

# An ephemeral port, so concurrent CI jobs on one runner cannot collide.
PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
BASE="http://127.0.0.1:$PORT"

python3 "$SCRIPT_DIR/mock_upstream.py" --port "$PORT" >/dev/null 2>&1 &
MOCK_PID=$!
cleanup() { kill "$MOCK_PID" 2>/dev/null; wait "$MOCK_PID" 2>/dev/null; }
trap cleanup EXIT

READY=0
for _ in $(seq 1 50); do
    if curl -sf "$BASE/__mock__/health" >/dev/null 2>&1; then READY=1; break; fi
    sleep 0.1
done
if [ "$READY" != "1" ]; then
    echo "FAIL: mock upstream did not come up on $BASE"
    exit 1
fi

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
counters() { # path -> "count revalidations"
    curl -s "$BASE/__mock__/count?path=$1" | jq -r '"\(.count) \(.revalidations)"'
}

echo "== HEAD answers conditionally and counts as a revalidation =="
curl -s -X POST "$BASE/__mock__/reset" >/dev/null
ETAG=$(curl -sI "$BASE$MD" | tr -d '\r' | sed -n 's/^[Ee][Tt][Aa][Gg]: //p')
if [ -n "$ETAG" ]; then
    ok "HEAD sends an ETag ($ETAG)"
else
    bad "HEAD sent no ETag — check_etag_changed reads a 200 without one as CHANGED"
fi

curl -s -X POST "$BASE/__mock__/reset" >/dev/null
RC=$(code -I -H "If-None-Match: $ETAG" "$BASE$MD")
expect_eq "HEAD + matching If-None-Match -> 304" "304" "$RC"
expect_eq "  ... and bumps revalidations, not count" "0 1" "$(counters "$MD")"

curl -s -X POST "$BASE/__mock__/reset" >/dev/null
RC=$(code -I -H 'If-None-Match: "not-the-current-etag"' "$BASE$MD")
expect_eq "HEAD + stale If-None-Match -> 200" "200" "$RC"
expect_eq "  ... and bumps neither counter (no body served)" "0 0" "$(counters "$MD")"

curl -s -X POST "$BASE/__mock__/reset" >/dev/null
RC=$(code -I "$BASE$MD")
expect_eq "unconditional HEAD -> 200" "200" "$RC"
expect_eq "  ... still does not bump count" "0 0" "$(counters "$MD")"

echo "== HEAD and GET agree on headers, existence and mutation =="
GET_LEN=$(curl -s "$BASE$JAR" | wc -c | tr -d ' ')
HEAD_LEN=$(curl -sI "$BASE$JAR" | tr -d '\r' | sed -n 's/^[Cc]ontent-[Ll]ength: //p')
expect_eq "HEAD Content-Length matches the GET body length" "$GET_LEN" "$HEAD_LEN"
expect_eq "HEAD of a missing path -> 404" "404" "$(code -I "$BASE/maven2/com/example/nope/1.0.0/nope-1.0.0.jar")"
expect_eq "HEAD of the control plane -> 405" "405" "$(code -I "$BASE/__mock__/health")"

curl -s -X POST "$BASE/__mock__/reset" >/dev/null
curl -s -X POST "$BASE/__mock__/mutate?path=$MD" >/dev/null
RC=$(code -I -H "If-None-Match: $ETAG" "$BASE$MD")
expect_eq "HEAD + If-None-Match of a MUTATED resource -> 200 (upstream changed)" "200" "$RC"
expect_eq "  ... and records no revalidation" "0 0" "$(counters "$MD")"

echo "== GET keeps its existing behaviour =="
curl -s -X POST "$BASE/__mock__/reset" >/dev/null
expect_eq "GET -> 200" "200" "$(code "$BASE$JAR")"
expect_eq "  ... bumps count" "1 0" "$(counters "$JAR")"
JAR_ETAG=$(curl -sI "$BASE$JAR" | tr -d '\r' | sed -n 's/^[Ee][Tt][Aa][Gg]: //p')
curl -s -X POST "$BASE/__mock__/reset" >/dev/null
expect_eq "GET + matching If-None-Match -> 304" "304" "$(code -H "If-None-Match: $JAR_ETAG" "$BASE$JAR")"
expect_eq "  ... bumps revalidations, not count" "0 1" "$(counters "$JAR")"
expect_eq "GET of a missing path -> 404" "404" "$(code "$BASE/maven2/com/example/nope/1.0.0/nope-1.0.0.jar")"

echo ""
echo "mock_upstream tests: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
