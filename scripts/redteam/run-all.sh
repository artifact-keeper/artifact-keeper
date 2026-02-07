#!/bin/bash
# Red Team Security Test Runner
# Usage: ./run-all.sh [--test <name>] [--severity <level>]
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

# Parse arguments
RUN_TEST=""
MIN_SEVERITY=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --test) RUN_TEST="$2"; shift 2 ;;
        --severity) MIN_SEVERITY="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo "=============================================="
echo "  Red Team Security Tests"
echo "  Target: $REGISTRY_URL"
echo "  Time:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "=============================================="
echo ""

# Wait for backend
info "Waiting for backend..."
wait_for_backend || exit 1
pass "Backend is ready"

# Initialize report
init_report

# Discover tests
ALL_TESTS=()
for f in "$SCRIPT_DIR"/tests/[0-9]*.sh; do
    [ -f "$f" ] && ALL_TESTS+=("$f")
done

if [ -n "$RUN_TEST" ]; then
    # Run single test
    MATCH=""
    for f in "${ALL_TESTS[@]}"; do
        basename=$(basename "$f" .sh)
        if [[ "$basename" == *"$RUN_TEST"* ]]; then
            MATCH="$f"
            break
        fi
    done
    if [ -z "$MATCH" ]; then
        echo "ERROR: No test matching '$RUN_TEST'"
        echo "Available tests:"
        for f in "${ALL_TESTS[@]}"; do echo "  $(basename "$f" .sh)"; done
        exit 1
    fi
    ALL_TESTS=("$MATCH")
fi

# Run tests
TOTAL=${#ALL_TESTS[@]}
CURRENT=0
TEST_PASSED=0
TEST_FAILED=0

for test_script in "${ALL_TESTS[@]}"; do
    CURRENT=$((CURRENT + 1))
    test_name=$(basename "$test_script" .sh)

    echo ""
    echo "[$CURRENT/$TOTAL] Running: $test_name"
    echo "----------------------------------------------"

    if bash "$test_script" 2>&1; then
        TEST_PASSED=$((TEST_PASSED + 1))
    else
        TEST_FAILED=$((TEST_FAILED + 1))
        warn "Test $test_name exited with non-zero status"
    fi
done

# Finalize report
finalize_report

# Summary
echo ""
echo "=============================================="
echo "  Results Summary"
echo "=============================================="
echo -e "  Tests run:  $TOTAL"
echo -e "  ${GREEN}Passed:${NC}     $_PASS_COUNT checks"
echo -e "  ${RED}Failed:${NC}     $_FAIL_COUNT checks"
echo -e "  ${YELLOW}Warnings:${NC}   $_WARN_COUNT checks"
echo ""

if [ $_FAIL_COUNT -gt 0 ]; then
    echo -e "  ${RED}Security issues found. Review $REPORT_FILE${NC}"
else
    echo -e "  ${GREEN}No critical issues detected.${NC}"
fi

echo ""
echo "Report: $REPORT_FILE"

# Exit non-zero if any findings were detected (regression gate)
if [ $_FAIL_COUNT -gt 0 ]; then
    exit 1
fi
exit 0
