#!/bin/bash
# Run all native client tests
# Usage: ./run-all.sh [profile]
# Profiles: smoke (default), all, pypi, npm, cargo, maven, go, rpm, deb, helm, conda, docker
set -euo pipefail

PROFILE="${1:-smoke}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=============================================="
echo "Native Client Tests - Profile: $PROFILE"
echo "=============================================="

# Define test sets
SMOKE_TESTS=(pypi npm cargo)
ALL_TESTS=(pypi npm cargo maven go rpm deb helm conda docker)

# Select tests based on profile
case "$PROFILE" in
    smoke)
        TESTS=("${SMOKE_TESTS[@]}")
        ;;
    all)
        TESTS=("${ALL_TESTS[@]}")
        ;;
    pypi|npm|cargo|maven|go|rpm|deb|helm|conda|docker)
        TESTS=("$PROFILE")
        ;;
    *)
        echo "ERROR: Unknown profile: $PROFILE"
        echo "Available profiles: smoke, all, pypi, npm, cargo, maven, go, rpm, deb, helm, conda, docker"
        exit 1
        ;;
esac

echo "Running tests: ${TESTS[*]}"
echo ""

# Track results
PASSED=()
FAILED=()

for test in "${TESTS[@]}"; do
    echo ""
    echo ">>> Running $test test..."
    echo "=============================================="

    TEST_SCRIPT="$SCRIPT_DIR/test-$test.sh"

    if [ ! -f "$TEST_SCRIPT" ]; then
        echo "WARNING: Test script not found: $TEST_SCRIPT"
        FAILED+=("$test (script not found)")
        continue
    fi

    if bash "$TEST_SCRIPT" 2>&1; then
        PASSED+=("$test")
        echo ">>> $test: PASSED"
    else
        FAILED+=("$test")
        echo ">>> $test: FAILED"
    fi
done

echo ""
echo "=============================================="
echo "Test Results Summary"
echo "=============================================="
echo ""

echo "Passed (${#PASSED[@]}):"
for t in "${PASSED[@]}"; do
    echo "  ✅ $t"
done

if [ ${#FAILED[@]} -gt 0 ]; then
    echo ""
    echo "Failed (${#FAILED[@]}):"
    for t in "${FAILED[@]}"; do
        echo "  ❌ $t"
    done
    echo ""
    echo "=============================================="
    echo "SOME TESTS FAILED"
    echo "=============================================="
    exit 1
fi

echo ""
echo "=============================================="
echo "ALL TESTS PASSED"
echo "=============================================="
