#!/usr/bin/env bash
# WASM Plugin E2E Test Suite Runner
#
# Runs all WASM plugin E2E tests:
# 1. Git installation tests
# 2. Lifecycle tests (enable/disable/uninstall)
# 3. Hot-reload tests
#
# Requires: backend running on port 8080
#
# Usage:
#   ./test-wasm-plugins.sh              # Run all tests
#   ./test-wasm-plugins.sh git          # Run only git installation tests
#   ./test-wasm-plugins.sh lifecycle    # Run only lifecycle tests
#   ./test-wasm-plugins.sh reload       # Run only hot-reload tests

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API_URL="${API_URL:-http://localhost:8080}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

pass() { echo -e "${GREEN}✓ $1${NC}"; }
fail() { echo -e "${RED}✗ $1${NC}"; }
info() { echo -e "${YELLOW}→ $1${NC}"; }
header() { echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"; echo -e "${CYAN}║ $1${NC}"; echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"; }

TESTS_PASSED=0
TESTS_FAILED=0

run_test() {
    local name="$1"
    local script="$2"

    header "$name"

    if [ ! -x "$script" ]; then
        chmod +x "$script"
    fi

    if API_URL="$API_URL" "$script"; then
        pass "TEST PASSED: $name"
        ((TESTS_PASSED++))
    else
        fail "TEST FAILED: $name"
        ((TESTS_FAILED++))
    fi
}

# Check connectivity first
info "Checking API connectivity..."
if ! curl -sf "${API_URL}/health" > /dev/null 2>&1; then
    echo -e "${RED}Error: Cannot connect to API server at ${API_URL}${NC}"
    echo "Make sure the backend is running:"
    echo "  cargo run --bin artifact-keeper-backend"
    exit 1
fi
pass "API server is running"

# Determine which tests to run
TEST_FILTER="${1:-all}"

case "$TEST_FILTER" in
    git)
        run_test "WASM Plugin Git Installation" "${SCRIPT_DIR}/test-wasm-plugin-git.sh"
        ;;
    lifecycle)
        run_test "WASM Plugin Lifecycle" "${SCRIPT_DIR}/test-wasm-plugin-lifecycle.sh"
        ;;
    reload)
        run_test "WASM Plugin Hot-Reload" "${SCRIPT_DIR}/test-wasm-plugin-reload.sh"
        ;;
    all)
        run_test "WASM Plugin Git Installation" "${SCRIPT_DIR}/test-wasm-plugin-git.sh"
        run_test "WASM Plugin Lifecycle" "${SCRIPT_DIR}/test-wasm-plugin-lifecycle.sh"
        run_test "WASM Plugin Hot-Reload" "${SCRIPT_DIR}/test-wasm-plugin-reload.sh"
        ;;
    *)
        echo "Usage: $0 [git|lifecycle|reload|all]"
        exit 1
        ;;
esac

# Summary
echo ""
header "WASM Plugin Test Suite Summary"
echo ""
echo -e "  ${GREEN}Passed: ${TESTS_PASSED}${NC}"
echo -e "  ${RED}Failed: ${TESTS_FAILED}${NC}"
echo ""

if [ "$TESTS_FAILED" -gt 0 ]; then
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
else
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
fi
