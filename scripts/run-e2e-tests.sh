#!/usr/bin/env bash
#
# Automated E2E Test Runner
# Runs Playwright E2E tests in Docker containers
#
# Usage:
#   ./scripts/run-e2e-tests.sh                  # Run smoke tests (default)
#   ./scripts/run-e2e-tests.sh --profile all    # Run all tests including native clients
#   ./scripts/run-e2e-tests.sh --profile pypi   # Run only PyPI native client tests
#   ./scripts/run-e2e-tests.sh --build          # Force rebuild containers
#   ./scripts/run-e2e-tests.sh --clean          # Clean up after tests
#   ./scripts/run-e2e-tests.sh --stress         # Include stress tests
#   ./scripts/run-e2e-tests.sh --failure        # Include failure injection tests
#
# Profiles:
#   smoke  - Quick tests: Playwright E2E + PyPI, NPM, Cargo native clients (default)
#   all    - All tests: Playwright E2E + all native clients
#   pypi, npm, cargo, maven, go, rpm, deb, helm, conda, docker - Individual native client tests
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Default options
BUILD_FLAG=""
CLEAN_AFTER=false
PROFILE="smoke"
RUN_STRESS=false
RUN_FAILURE=false
TEST_TAG=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --build)
            BUILD_FLAG="--build"
            shift
            ;;
        --clean)
            CLEAN_AFTER=true
            shift
            ;;
        --profile)
            PROFILE="$2"
            shift 2
            ;;
        --stress)
            RUN_STRESS=true
            shift
            ;;
        --failure)
            RUN_FAILURE=true
            shift
            ;;
        --tag)
            TEST_TAG="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --profile PROFILE  Test profile to run (smoke, all, pypi, npm, cargo, maven, go, rpm, deb, helm, conda, docker)"
            echo "  --build            Force rebuild all containers"
            echo "  --clean            Clean up containers and volumes after tests"
            echo "  --stress           Run stress tests after E2E tests"
            echo "  --failure          Run failure injection tests after E2E tests"
            echo "  --tag TAG          Filter Playwright tests by tag (@smoke, @full)"
            echo "  --help             Show this help message"
            echo ""
            echo "Profiles:"
            echo "  smoke              Quick smoke tests: Playwright E2E + PyPI, NPM, Cargo (default)"
            echo "  all                All tests: Playwright E2E + all native clients"
            echo "  pypi|npm|cargo...  Individual native client tests"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

cd "$PROJECT_ROOT"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Artifact Keeper E2E Test Runner${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${BLUE}Profile: ${NC}$PROFILE"
echo -e "${BLUE}Stress tests: ${NC}$RUN_STRESS"
echo -e "${BLUE}Failure tests: ${NC}$RUN_FAILURE"
[ -n "$TEST_TAG" ] && echo -e "${BLUE}Test tag filter: ${NC}$TEST_TAG"
echo ""

# Function to clean up
cleanup() {
    echo -e "\n${YELLOW}Cleaning up containers...${NC}"
    docker compose -f docker-compose.test.yml down -v --remove-orphans 2>/dev/null || true
}

# Trap for cleanup on error or exit
if [ "$CLEAN_AFTER" = true ]; then
    trap cleanup EXIT
fi

# Check Docker is running
if ! docker info >/dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running${NC}"
    exit 1
fi

# Create results directories with write permissions for container
echo -e "${BLUE}Creating test results directories...${NC}"
mkdir -p test-results playwright-report
chmod 777 test-results playwright-report

# Stop any existing containers
echo -e "${YELLOW}Stopping any existing test containers...${NC}"
docker compose -f docker-compose.test.yml down -v --remove-orphans 2>/dev/null || true

# Set up environment variables for test configuration
export TEST_TAG="${TEST_TAG}"

# Build and start containers with profile
echo -e "${BLUE}Running Playwright E2E tests...${NC}"
docker compose -f docker-compose.test.yml up $BUILD_FLAG --abort-on-container-exit --exit-code-from playwright
PLAYWRIGHT_EXIT=$?

# Run native client tests if profile is smoke or all
NATIVE_EXIT=0
if [ "$PROFILE" = "smoke" ] || [ "$PROFILE" = "all" ] || [[ "$PROFILE" =~ ^(pypi|npm|cargo|maven|go|rpm|deb|helm|conda|docker)$ ]]; then
    echo ""
    echo -e "${BLUE}Running native client tests (profile: $PROFILE)...${NC}"
    docker compose -f docker-compose.test.yml --profile "$PROFILE" up \
        --abort-on-container-exit 2>/dev/null || true
    NATIVE_EXIT=$?
fi

# Run stress tests if requested
STRESS_EXIT=0
if [ "$RUN_STRESS" = true ]; then
    echo ""
    echo -e "${BLUE}Running stress tests...${NC}"
    if [ -f "$SCRIPT_DIR/stress/run-concurrent-uploads.sh" ]; then
        # Start infrastructure for stress tests
        docker compose -f docker-compose.test.yml up -d postgres backend
        sleep 15
        "$SCRIPT_DIR/stress/run-concurrent-uploads.sh" || STRESS_EXIT=$?
        if [ -f "$SCRIPT_DIR/stress/validate-results.sh" ]; then
            "$SCRIPT_DIR/stress/validate-results.sh" || STRESS_EXIT=$?
        fi
    else
        echo -e "${YELLOW}Stress test scripts not found, skipping${NC}"
    fi
fi

# Run failure tests if requested
FAILURE_EXIT=0
if [ "$RUN_FAILURE" = true ]; then
    echo ""
    echo -e "${BLUE}Running failure injection tests...${NC}"
    if [ -f "$SCRIPT_DIR/failure/run-all.sh" ]; then
        "$SCRIPT_DIR/failure/run-all.sh" || FAILURE_EXIT=$?
    else
        echo -e "${YELLOW}Failure test scripts not found, skipping${NC}"
    fi
fi

# Calculate overall exit code
EXIT_CODE=0
[ $PLAYWRIGHT_EXIT -ne 0 ] && EXIT_CODE=1
[ $NATIVE_EXIT -ne 0 ] && EXIT_CODE=1
[ $STRESS_EXIT -ne 0 ] && EXIT_CODE=1
[ $FAILURE_EXIT -ne 0 ] && EXIT_CODE=1

# Report results
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  E2E Test Results Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Playwright results
if [ $PLAYWRIGHT_EXIT -eq 0 ]; then
    echo -e "${GREEN}  ✅ Playwright E2E: PASSED${NC}"
else
    echo -e "${RED}  ❌ Playwright E2E: FAILED${NC}"
fi

# Native client results
if [ "$PROFILE" != "none" ]; then
    if [ $NATIVE_EXIT -eq 0 ]; then
        echo -e "${GREEN}  ✅ Native Clients ($PROFILE): PASSED${NC}"
    else
        echo -e "${RED}  ❌ Native Clients ($PROFILE): FAILED${NC}"
    fi
fi

# Stress test results
if [ "$RUN_STRESS" = true ]; then
    if [ $STRESS_EXIT -eq 0 ]; then
        echo -e "${GREEN}  ✅ Stress Tests: PASSED${NC}"
    else
        echo -e "${RED}  ❌ Stress Tests: FAILED${NC}"
    fi
fi

# Failure test results
if [ "$RUN_FAILURE" = true ]; then
    if [ $FAILURE_EXIT -eq 0 ]; then
        echo -e "${GREEN}  ✅ Failure Tests: PASSED${NC}"
    else
        echo -e "${RED}  ❌ Failure Tests: FAILED${NC}"
    fi
fi

echo ""
echo -e "${BLUE}========================================${NC}"
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}  ALL TESTS PASSED${NC}"
else
    echo -e "${RED}  SOME TESTS FAILED${NC}"
fi
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Test results available at:"
echo "  - HTML Report: ./playwright-report/index.html"
echo "  - Test Results: ./test-results/"
echo ""

# Clean up if not keeping containers
if [ "$CLEAN_AFTER" = true ]; then
    cleanup
fi

exit $EXIT_CODE
