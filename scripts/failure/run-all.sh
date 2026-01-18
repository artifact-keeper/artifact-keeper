#!/bin/bash
# Run all failure injection tests
# Usage: ./run-all.sh [test]
# Tests: all (default), server-crash, db-disconnect, storage-failure
set -euo pipefail

TEST="${1:-all}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${RESULTS_DIR:-/tmp/failure-results}"

echo "=============================================="
echo "Failure Injection Tests - Test: $TEST"
echo "=============================================="
echo ""

mkdir -p "$RESULTS_DIR"

# Define test sets
ALL_TESTS=(server-crash db-disconnect storage-failure)

# Select tests based on argument
case "$TEST" in
    all)
        TESTS=("${ALL_TESTS[@]}")
        ;;
    server-crash|db-disconnect|storage-failure)
        TESTS=("$TEST")
        ;;
    *)
        echo "ERROR: Unknown test: $TEST"
        echo "Available tests: all, server-crash, db-disconnect, storage-failure"
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

    # Export results directory for the test
    export RESULTS_DIR

    if bash "$TEST_SCRIPT" 2>&1; then
        PASSED+=("$test")
        echo ">>> $test: PASSED"
    else
        FAILED+=("$test")
        echo ">>> $test: FAILED"
    fi

    # Add delay between tests to allow cleanup
    sleep 5
done

echo ""
echo "=============================================="
echo "Failure Test Results Summary"
echo "=============================================="
echo ""

echo "Passed (${#PASSED[@]}):"
for t in "${PASSED[@]}"; do
    echo "  ✅ $t"
done

# Generate combined report
cat > "$RESULTS_DIR/failure-summary.json" << EOF
{
  "test_suite": "failure_injection",
  "timestamp": "$(date -Iseconds)",
  "tests_run": ${#TESTS[@]},
  "passed": ${#PASSED[@]},
  "failed": ${#FAILED[@]},
  "results": {
    "passed": [$(printf '"%s",' "${PASSED[@]}" | sed 's/,$//')]
    $([ ${#FAILED[@]} -gt 0 ] && echo ", \"failed\": [$(printf '"%s",' "${FAILED[@]}" | sed 's/,$//')" || echo ", \"failed\": [")
    ]
  }
}
EOF

if [ ${#FAILED[@]} -gt 0 ]; then
    echo ""
    echo "Failed (${#FAILED[@]}):"
    for t in "${FAILED[@]}"; do
        echo "  ❌ $t"
    done
    echo ""
    echo "=============================================="
    echo "SOME FAILURE TESTS FAILED"
    echo "=============================================="
    echo "Results saved to: $RESULTS_DIR/failure-summary.json"
    exit 1
fi

echo ""
echo "=============================================="
echo "ALL FAILURE TESTS PASSED"
echo "=============================================="
echo "Results saved to: $RESULTS_DIR/failure-summary.json"
