#!/bin/bash
# Test OWASP Dependency-Track integration
# Requires: docker compose up -d (with dependency-track-apiserver running)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
DT_URL="${DEPENDENCY_TRACK_URL:-http://localhost:8092}"
DT_API_KEY="${DEPENDENCY_TRACK_API_KEY:-}"
BACKEND_URL="${BACKEND_URL:-http://localhost:8080}"

echo "=== Dependency-Track Integration Tests ==="
echo "DT URL: $DT_URL"
echo "Backend URL: $BACKEND_URL"
echo ""

# Helper functions
pass() { echo -e "${GREEN}✓ $1${NC}"; }
fail() { echo -e "${RED}✗ $1${NC}"; exit 1; }
warn() { echo -e "${YELLOW}⚠ $1${NC}"; }
info() { echo -e "  $1"; }

# Test 1: Check if Dependency-Track is running
echo "1. Checking Dependency-Track API server..."
DT_VERSION=$(curl -sf "$DT_URL/api/version" 2>/dev/null || echo "")
if [ -n "$DT_VERSION" ]; then
    pass "Dependency-Track API is running"
    info "Version: $(echo "$DT_VERSION" | jq -r '.version // "unknown"' 2>/dev/null || echo "$DT_VERSION")"
else
    fail "Dependency-Track API not reachable at $DT_URL"
fi

# Test 2: Check API key (if provided)
if [ -n "$DT_API_KEY" ]; then
    echo ""
    echo "2. Testing API key authentication..."
    PROJECTS=$(curl -sf -H "X-Api-Key: $DT_API_KEY" "$DT_URL/api/v1/project" 2>/dev/null || echo "")
    if [ -n "$PROJECTS" ]; then
        pass "API key authentication successful"
        PROJECT_COUNT=$(echo "$PROJECTS" | jq 'length' 2>/dev/null || echo "0")
        info "Existing projects: $PROJECT_COUNT"
    else
        fail "API key authentication failed"
    fi
else
    echo ""
    echo "2. Skipping API key test (DEPENDENCY_TRACK_API_KEY not set)"
    warn "Set DEPENDENCY_TRACK_API_KEY to test authenticated endpoints"
fi

# Test 3: Create a test project
if [ -n "$DT_API_KEY" ]; then
    echo ""
    echo "3. Creating test project..."
    TEST_PROJECT_NAME="artifact-keeper-test-$(date +%s)"

    CREATE_RESP=$(curl -sf -X PUT \
        -H "X-Api-Key: $DT_API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"$TEST_PROJECT_NAME\", \"version\": \"1.0.0\"}" \
        "$DT_URL/api/v1/project" 2>/dev/null || echo "")

    if [ -n "$CREATE_RESP" ]; then
        PROJECT_UUID=$(echo "$CREATE_RESP" | jq -r '.uuid' 2>/dev/null || echo "")
        if [ -n "$PROJECT_UUID" ] && [ "$PROJECT_UUID" != "null" ]; then
            pass "Created test project: $TEST_PROJECT_NAME"
            info "UUID: $PROJECT_UUID"
        else
            fail "Failed to create project (no UUID in response)"
        fi
    else
        fail "Failed to create test project"
    fi

    # Test 4: Upload a minimal SBOM
    echo ""
    echo "4. Uploading test SBOM..."

    # Create a minimal CycloneDX SBOM
    SBOM_JSON=$(cat <<SBOM
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:$(uuidgen 2>/dev/null || echo "test-uuid-123")",
  "version": 1,
  "metadata": {
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "tools": [{"name": "artifact-keeper-test", "version": "1.0.0"}]
  },
  "components": [
    {
      "type": "library",
      "name": "lodash",
      "version": "4.17.21",
      "purl": "pkg:npm/lodash@4.17.21",
      "licenses": [{"license": {"id": "MIT"}}]
    },
    {
      "type": "library",
      "name": "axios",
      "version": "1.6.0",
      "purl": "pkg:npm/axios@1.6.0",
      "licenses": [{"license": {"id": "MIT"}}]
    }
  ]
}
SBOM
)

    # Base64 encode the SBOM
    SBOM_B64=$(echo "$SBOM_JSON" | base64 | tr -d '\n')

    UPLOAD_RESP=$(curl -sf -X PUT \
        -H "X-Api-Key: $DT_API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"project\": \"$PROJECT_UUID\", \"bom\": \"$SBOM_B64\"}" \
        "$DT_URL/api/v1/bom" 2>/dev/null || echo "")

    if [ -n "$UPLOAD_RESP" ]; then
        BOM_TOKEN=$(echo "$UPLOAD_RESP" | jq -r '.token' 2>/dev/null || echo "")
        if [ -n "$BOM_TOKEN" ] && [ "$BOM_TOKEN" != "null" ]; then
            pass "Uploaded SBOM successfully"
            info "Processing token: $BOM_TOKEN"
        else
            pass "Uploaded SBOM (no token returned - sync mode)"
        fi
    else
        fail "Failed to upload SBOM"
    fi

    # Test 5: Wait for BOM processing and check components
    echo ""
    echo "5. Checking BOM processing..."
    sleep 3  # Give DT time to process

    COMPONENTS=$(curl -sf -H "X-Api-Key: $DT_API_KEY" \
        "$DT_URL/api/v1/component/project/$PROJECT_UUID" 2>/dev/null || echo "")

    if [ -n "$COMPONENTS" ]; then
        COMP_COUNT=$(echo "$COMPONENTS" | jq 'length' 2>/dev/null || echo "0")
        pass "BOM processed successfully"
        info "Components found: $COMP_COUNT"
    else
        warn "Components not yet available (may still be processing)"
    fi

    # Test 6: Check for findings/vulnerabilities
    echo ""
    echo "6. Checking vulnerability findings..."

    FINDINGS=$(curl -sf -H "X-Api-Key: $DT_API_KEY" \
        "$DT_URL/api/v1/finding/project/$PROJECT_UUID" 2>/dev/null || echo "")

    if [ -n "$FINDINGS" ]; then
        FINDING_COUNT=$(echo "$FINDINGS" | jq 'length' 2>/dev/null || echo "0")
        pass "Findings check successful"
        info "Vulnerabilities found: $FINDING_COUNT"
    else
        warn "No findings returned (may still be analyzing)"
    fi

    # Cleanup: Delete test project
    echo ""
    echo "7. Cleaning up test project..."

    DELETE_RESP=$(curl -sf -X DELETE \
        -H "X-Api-Key: $DT_API_KEY" \
        "$DT_URL/api/v1/project/$PROJECT_UUID" 2>/dev/null && echo "ok" || echo "")

    if [ "$DELETE_RESP" = "ok" ]; then
        pass "Deleted test project"
    else
        warn "Could not delete test project (may require manual cleanup)"
    fi
fi

# Test backend integration (if running)
echo ""
echo "=== Backend Integration Tests ==="

echo "8. Checking backend health..."
BACKEND_HEALTH=$(curl -sf "$BACKEND_URL/health" 2>/dev/null || echo "")
if [ -n "$BACKEND_HEALTH" ]; then
    pass "Backend is running"
else
    warn "Backend not reachable at $BACKEND_URL (skipping backend tests)"
    echo ""
    echo "=== Summary ==="
    echo "Dependency-Track tests completed."
    echo "Start backend to run full integration tests."
    exit 0
fi

echo ""
echo "=== All Tests Passed ==="
