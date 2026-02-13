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
