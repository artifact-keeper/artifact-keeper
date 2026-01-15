#!/usr/bin/env bash
#
# Automated E2E Test Runner
# Runs Playwright E2E tests in Docker containers
#
# Usage:
#   ./scripts/run-e2e-tests.sh           # Run all tests
#   ./scripts/run-e2e-tests.sh --headed  # Run with headed browser (local only)
#   ./scripts/run-e2e-tests.sh --build   # Force rebuild containers
#   ./scripts/run-e2e-tests.sh --clean   # Clean up after tests
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
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --build    Force rebuild all containers"
            echo "  --clean    Clean up containers and volumes after tests"
            echo "  --help     Show this help message"
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

# Create results directories
echo -e "${BLUE}Creating test results directories...${NC}"
mkdir -p test-results playwright-report

# Stop any existing containers
echo -e "${YELLOW}Stopping any existing test containers...${NC}"
docker compose -f docker-compose.test.yml down -v --remove-orphans 2>/dev/null || true

# Build and start containers
echo -e "${BLUE}Building and starting containers...${NC}"
docker compose -f docker-compose.test.yml up $BUILD_FLAG --abort-on-container-exit --exit-code-from playwright

# Capture exit code
EXIT_CODE=$?

# Report results
echo ""
echo -e "${BLUE}========================================${NC}"
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}  E2E Tests PASSED${NC}"
else
    echo -e "${RED}  E2E Tests FAILED${NC}"
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
