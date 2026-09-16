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

# Initialize the report and reset the on-disk counters BEFORE the first
# pass/fail/warn/info call, otherwise that call's increment is wiped (#3491).
init_report

# Wait for backend
info "Waiting for backend..."
wait_for_backend || exit 1
pass "Backend is ready"

# Log in ONCE, up front, and cache the token for every script that needs it.
# Tests 04 and 10 spend the login rate-limit window on purpose; without this
# priming step the scripts that run after them found the window exhausted and
# skipped themselves with "Could not authenticate" (#3491).
if auth_token > /dev/null; then
    pass "Obtained a shared admin token for the authenticated checks"
else
    warn "Could not obtain an admin token; authenticated checks will skip"
fi

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

# Finalize report. A report that does not parse is itself a suite failure:
# the JSON is what a CI gate reads, so "green run, unreadable report" must not
# be a reachable outcome (#3491).
REPORT_OK=0
finalize_report || REPORT_OK=1

# Summary. The counts come from the shared on-disk counters, not from shell
# variables: each test above ran in its own `bash` process.
CHECKS_PASSED=$(counter pass)
CHECKS_FAILED=$(counter fail)
CHECKS_WARNED=$(counter warn)

echo ""
echo "=============================================="
echo "  Results Summary"
echo "=============================================="
echo -e "  Scripts run:   $TOTAL (${TEST_PASSED} exited 0, ${TEST_FAILED} non-zero)"
echo -e "  ${GREEN}Passed:${NC}     $CHECKS_PASSED checks"
echo -e "  ${RED}Failed:${NC}     $CHECKS_FAILED checks"
echo -e "  ${YELLOW}Warnings:${NC}   $CHECKS_WARNED checks"
echo -e "  Findings:   $(counter findings)"
echo ""

if [ "$CHECKS_FAILED" -gt 0 ]; then
    echo -e "  ${RED}Security issues found. Review $REPORT_FILE${NC}"
else
    echo -e "  ${GREEN}No critical issues detected.${NC}"
fi

echo ""
echo "Report: $REPORT_FILE"

# Exit non-zero if any findings were detected (regression gate)
if [ "$CHECKS_FAILED" -gt 0 ] || [ "$REPORT_OK" -ne 0 ]; then
    exit 1
fi
exit 0
