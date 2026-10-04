#!/bin/sh
# Orchestrator for P2P mesh replication E2E tests.
# Runs each test script in sequence, tracks pass/fail, and prints a summary.
set -e

echo "=========================================="
echo "  P2P Mesh Replication E2E Tests"
echo "=========================================="
echo ""

# Install dependencies
echo "==> Installing dependencies..."
apk add --no-cache curl jq >/dev/null 2>&1
echo "    curl and jq installed"
echo ""

# ---------------------------------------------------------------------------
# Peer credentials (#1936)
# ---------------------------------------------------------------------------
# A peer's `api_key` is the bearer credential the OTHER instance presents when
# it probes this peer (GET /api/v1/peers) and when its sync worker PUTs an
# artifact here, so it has to be a real API token minted on this peer. The
# scripts used to register placeholder strings ("peer-b-key"): every liveness
# probe got 401, the peer never went `online`, and every sync task stayed
# `pending` forever while the tests passed on "a task was queued".
mint_peer_token() {
    _url="$1"
    _jwt=$(curl -sf -X POST "$_url/api/v1/auth/login" \
        -H 'Content-Type: application/json' \
        -d "$(jq -cn --arg p "$ADMIN_PASS" '{username: "admin", password: $p}')" \
        | jq -r '.access_token // empty')
    [ -n "$_jwt" ] || { echo "FATAL: admin login to $_url failed" >&2; return 1; }
    curl -sf -X POST "$_url/api/v1/auth/tokens" \
        -H "Authorization: Bearer $_jwt" \
        -H 'Content-Type: application/json' \
        -d '{"name": "mesh-e2e-peer-link", "scopes": ["admin"], "expires_in_days": 1}' \
        | jq -r '.token // empty'
}

: "${ADMIN_PASS:?ADMIN_PASS is not set (the mesh-test service reads it from .env.test)}"
echo "==> Minting peer-link API tokens..."
PEER_A_API_KEY=$(mint_peer_token "http://backend-peer-a:8080")
PEER_B_API_KEY=$(mint_peer_token "http://backend-peer-b:8080")
if [ -z "$PEER_A_API_KEY" ] || [ -z "$PEER_B_API_KEY" ]; then
    echo "FATAL: could not mint a peer-link API token on both peers"
    exit 1
fi
export PEER_A_API_KEY PEER_B_API_KEY
echo "    peer-a and peer-b tokens minted"
echo ""

PASS_COUNT=0
FAIL_COUNT=0
RESULTS=""

run_test() {
    TEST_NAME="$1"
    TEST_SCRIPT="$2"

    echo "=========================================="
    echo "  Running: $TEST_NAME"
    echo "=========================================="
    echo ""

    if sh "$TEST_SCRIPT"; then
        PASS_COUNT=$((PASS_COUNT + 1))
        RESULTS="${RESULTS}\n  PASS  ${TEST_NAME}"
        echo ""
        echo "  >> $TEST_NAME: PASSED"
        echo ""
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        RESULTS="${RESULTS}\n  FAIL  ${TEST_NAME}"
        echo ""
        echo "  >> $TEST_NAME: FAILED"
        echo ""
    fi
}

run_test "Peer Registration"  /scripts/test-peer-registration.sh
run_test "Sync Policy"        /scripts/test-sync-policy.sh
run_test "Artifact Sync"      /scripts/test-artifact-sync.sh
run_test "Retroactive Sync"   /scripts/test-retroactive-sync.sh
run_test "Heartbeat"          /scripts/test-heartbeat.sh

TOTAL=$((PASS_COUNT + FAIL_COUNT))

echo ""
echo "=========================================="
echo "  Mesh E2E Test Summary"
echo "=========================================="
printf "%b\n" "$RESULTS"
echo ""
echo "  Total: $TOTAL  Passed: $PASS_COUNT  Failed: $FAIL_COUNT"
echo "=========================================="
echo ""

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo "MESH E2E TESTS FAILED"
    exit 1
fi

echo "ALL MESH E2E TESTS PASSED"
exit 0
