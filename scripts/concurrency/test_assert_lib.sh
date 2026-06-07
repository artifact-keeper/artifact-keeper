#!/usr/bin/env bash
# Unit tests for assert_lib.sh and a standalone smoke test of mock_upstream.py.
#
# Runs WITHOUT Docker or the full stack. Validates the digest/counter/blob-count
# assertion logic against local stubs so the harness's pass/fail decisions are
# trustworthy independent of a real multi-container run.
#
# Usage: ./scripts/concurrency/test_assert_lib.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/concurrency/assert_lib.sh
. "$SCRIPT_DIR/assert_lib.sh"

PASS=0; FAIL=0
ok()   { echo "  ok   - $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL - $1"; FAIL=$((FAIL+1)); }

check_rc() { # desc expected_rc actual_rc
    if [ "$2" = "$3" ]; then ok "$1 (rc=$3)"; else bad "$1 (expected rc=$2, got $3)"; fi
}

expect_eq() { # desc expected actual
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}

echo "== assert_fetch_counter_one =="
assert_fetch_counter_one 1 >/dev/null 2>&1; rc=$?; check_rc "count==1 passes" 0 "$rc"
assert_fetch_counter_one 8 >/dev/null 2>&1; rc=$?; check_rc "count==8 fails (the #1606 multi-fetch)" 1 "$rc"
assert_fetch_counter_one 0 >/dev/null 2>&1; rc=$?; check_rc "count==0 fails (never fetched)" 1 "$rc"
FETCH_TOLERANCE=2 assert_fetch_counter_one 3 >/dev/null 2>&1; rc=$?; check_rc "count==3 passes with tolerance=2" 0 "$rc"
FETCH_TOLERANCE=2 assert_fetch_counter_one 4 >/dev/null 2>&1; rc=$?; check_rc "count==4 fails with tolerance=2" 1 "$rc"

echo "== assert_single_cached_blob =="
assert_single_cached_blob 1 >/dev/null 2>&1; rc=$?; check_rc "blob count 1 passes" 0 "$rc"
assert_single_cached_blob 3 >/dev/null 2>&1; rc=$?; check_rc "blob count 3 fails" 1 "$rc"
assert_single_cached_blob 0 >/dev/null 2>&1; rc=$?; check_rc "blob count 0 fails" 1 "$rc"

echo "== sha256_of_file =="
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
printf 'hello' > "$TMP/h.txt"
EXPECT="2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
GOT=$(sha256_of_file "$TMP/h.txt")
if [ "$GOT" = "$EXPECT" ]; then ok "sha256('hello') correct"; else bad "sha256('hello') got $GOT"; fi

echo "== assert_all_responses_ok =="
GOOD_SHA="$EXPECT"
# All-good CSV: every response 200 with the right digest.
cat > "$TMP/good.csv" <<EOF
idx,status,sha256,bytes
1,200,$GOOD_SHA,5
2,200,$GOOD_SHA,5
3,200,$GOOD_SHA,5
EOF
assert_all_responses_ok "$TMP/good.csv" "$GOOD_SHA" >/dev/null 2>&1; rc=$?; check_rc "all-200 correct-digest passes" 0 "$rc"

# Truncated/torn body: one response has a different (truncated) digest -> the #1606 failure.
cat > "$TMP/torn.csv" <<EOF
idx,status,sha256,bytes
1,200,$GOOD_SHA,5
2,200,deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef,3
3,200,$GOOD_SHA,5
EOF
assert_all_responses_ok "$TMP/torn.csv" "$GOOD_SHA" >/dev/null 2>&1; rc=$?; check_rc "truncated body fails (#1606)" 1 "$rc"

# Non-200 response (e.g. a 502 leak under stampede).
cat > "$TMP/err.csv" <<EOF
idx,status,sha256,bytes
1,200,$GOOD_SHA,5
2,502,,0
3,200,$GOOD_SHA,5
EOF
assert_all_responses_ok "$TMP/err.csv" "$GOOD_SHA" >/dev/null 2>&1; rc=$?; check_rc "non-200 response fails" 1 "$rc"

# Empty CSV (no responses).
echo "idx,status,sha256,bytes" > "$TMP/empty.csv"
assert_all_responses_ok "$TMP/empty.csv" "$GOOD_SHA" >/dev/null; rc=$?; check_rc "no responses fails" 1 "$rc"

echo "== mock_upstream.py standalone (counter + digest stability) =="
if command -v python3 >/dev/null 2>&1; then
    # Tiny artifact + zero latency so the test is fast.
    PORT=$(( (RANDOM % 2000) + 21000 ))
    ARTIFACT_SIZE_BYTES=4096 LATENCY_MS=0 PORT=$PORT SEED=1624 \
        python3 "$SCRIPT_DIR/mock_upstream.py" >/dev/null 2>&1 &
    MOCK_PID=$!
    # Wait for it to come up.
    up=0
    for _ in $(seq 1 50); do
        if curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then up=1; break; fi
        sleep 0.1
    done
    if [ "$up" != "1" ]; then
        bad "mock upstream did not start on port $PORT"
    else
        # Counter starts at 0.
        c0=$(curl -sf "http://127.0.0.1:$PORT/__count__" | sed -n 's/.*"fetches":\([0-9]*\).*/\1/p')
        expect_eq "counter starts at 0" "0" "$c0"

        # Two fetches -> counter == 2; both bodies have the SAME (stable) digest
        # equal to the published digest.
        PUB=$(curl -sf "http://127.0.0.1:$PORT/__digest__" | sed -n 's/.*"sha256":"\([0-9a-f]*\)".*/\1/p')
        curl -sf "http://127.0.0.1:$PORT/race/big-artifact.bin" -o "$TMP/a1.bin"
        curl -sf "http://127.0.0.1:$PORT/race/big-artifact.bin" -o "$TMP/a2.bin"
        c2=$(curl -sf "http://127.0.0.1:$PORT/__count__" | sed -n 's/.*"fetches":\([0-9]*\).*/\1/p')
        expect_eq "counter == 2 after two fetches" "2" "$c2"

        s1=$(sha256_of_file "$TMP/a1.bin"); s2=$(sha256_of_file "$TMP/a2.bin")
        expect_eq "fetch 1 digest matches published" "$PUB" "$s1"
        expect_eq "two fetches byte-identical (deterministic content)" "$s1" "$s2"

        sz=$(wc -c < "$TMP/a1.bin" | tr -d ' ')
        expect_eq "artifact size honoured (4096 bytes)" "4096" "$sz"

        # Reset returns counter to 0.
        curl -sf -X POST "http://127.0.0.1:$PORT/__reset__" >/dev/null
        cr=$(curl -sf "http://127.0.0.1:$PORT/__count__" | sed -n 's/.*"fetches":\([0-9]*\).*/\1/p')
        expect_eq "counter resets to 0" "0" "$cr"
    fi
    kill "$MOCK_PID" >/dev/null 2>&1 || true
    wait "$MOCK_PID" 2>/dev/null || true
else
    echo "  SKIP - python3 not available for mock_upstream standalone test"
fi

echo ""
echo "=============================================="
echo "assert_lib unit tests: PASS=$PASS FAIL=$FAIL"
echo "=============================================="
[ "$FAIL" -eq 0 ] || exit 1
