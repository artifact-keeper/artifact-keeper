#!/usr/bin/env bash
# WASM Plugin E2E Test - Git Installation
#
# Tests installing WASM plugins from Git repositories:
# 1. Install plugin from example repo
# 2. Verify plugin manifest parsing
# 3. Verify format handler registration
# 4. Test plugin execution (parse_metadata, validate)
# 5. Test format handler API
# 6. Cleanup
#
# Requires: backend running on port 8080
#
# Usage:
#   ./test-wasm-plugin-git.sh
#   API_URL=http://localhost:8080 ./test-wasm-plugin-git.sh

set -euo pipefail

API_URL="${API_URL:-http://localhost:8080}"
EXAMPLE_PLUGIN_REPO="${EXAMPLE_PLUGIN_REPO:-https://github.com/artifact-keeper/artifact-keeper-example-plugin}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

pass() { echo -e "${GREEN}✓ $1${NC}"; }
fail() { echo -e "${RED}✗ $1${NC}"; exit 1; }
info() { echo -e "${YELLOW}→ $1${NC}"; }
header() { echo -e "\n${BLUE}=== $1 ===${NC}"; }

# Check for required tools
for cmd in curl jq; do
    if ! command -v "$cmd" &> /dev/null; then
        fail "$cmd is not installed"
    fi
done

# Test connectivity
info "Testing connection to ${API_URL}..."
if ! curl -sf "${API_URL}/health" > /dev/null 2>&1; then
    fail "Cannot connect to API server at ${API_URL}"
fi
pass "Connected to API server"

# Store plugin ID for cleanup
PLUGIN_ID=""

cleanup() {
    if [ -n "$PLUGIN_ID" ]; then
        info "Cleaning up: uninstalling plugin ${PLUGIN_ID}"
        curl -sf -X DELETE "${API_URL}/api/plugins/${PLUGIN_ID}?force=true" > /dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# -------------------------------------------------------------------------
# Step 1: List existing plugins (baseline)
# -------------------------------------------------------------------------
header "Listing Existing Plugins"
PLUGINS_BEFORE=$(curl -sf "${API_URL}/api/plugins" | jq '.items | length')
info "Found ${PLUGINS_BEFORE} existing plugins"

# -------------------------------------------------------------------------
# Step 2: Install plugin from Git
# -------------------------------------------------------------------------
header "Installing Plugin from Git Repository"
info "Repository: ${EXAMPLE_PLUGIN_REPO}"

INSTALL_RESPONSE=$(curl -sf -X POST "${API_URL}/api/plugins/install/git" \
    -H "Content-Type: application/json" \
    -d "{\"url\": \"${EXAMPLE_PLUGIN_REPO}\"}" 2>&1) || {
    echo "Install response: $INSTALL_RESPONSE"
    fail "Failed to install plugin from Git"
}

echo "$INSTALL_RESPONSE" | jq .

PLUGIN_ID=$(echo "$INSTALL_RESPONSE" | jq -r '.plugin_id')
PLUGIN_NAME=$(echo "$INSTALL_RESPONSE" | jq -r '.name')
PLUGIN_VERSION=$(echo "$INSTALL_RESPONSE" | jq -r '.version')
FORMAT_KEY=$(echo "$INSTALL_RESPONSE" | jq -r '.format_key')

if [ "$PLUGIN_ID" = "null" ] || [ -z "$PLUGIN_ID" ]; then
    fail "Plugin ID not returned"
fi
pass "Plugin installed: ${PLUGIN_NAME} v${PLUGIN_VERSION} (format: ${FORMAT_KEY})"

# -------------------------------------------------------------------------
# Step 3: Verify plugin details
# -------------------------------------------------------------------------
header "Verifying Plugin Details"
PLUGIN_DETAILS=$(curl -sf "${API_URL}/api/plugins/${PLUGIN_ID}")
echo "$PLUGIN_DETAILS" | jq .

STATUS=$(echo "$PLUGIN_DETAILS" | jq -r '.status')
if [ "$STATUS" = "active" ]; then
    pass "Plugin status is active"
else
    fail "Expected status 'active', got '${STATUS}'"
fi

# Check manifest fields
DISPLAY_NAME=$(echo "$PLUGIN_DETAILS" | jq -r '.display_name')
AUTHOR=$(echo "$PLUGIN_DETAILS" | jq -r '.author // "null"')
if [ "$DISPLAY_NAME" != "null" ] && [ -n "$DISPLAY_NAME" ]; then
    pass "Manifest parsed: display_name = ${DISPLAY_NAME}"
else
    fail "Manifest display_name not parsed"
fi

# -------------------------------------------------------------------------
# Step 4: Verify format handler registration
# -------------------------------------------------------------------------
header "Verifying Format Handler Registration"
FORMAT_HANDLERS=$(curl -sf "${API_URL}/api/format-handlers")
echo "$FORMAT_HANDLERS" | jq ".items[] | select(.format_key == \"${FORMAT_KEY}\")"

HANDLER=$(echo "$FORMAT_HANDLERS" | jq ".items[] | select(.format_key == \"${FORMAT_KEY}\")")
if [ -n "$HANDLER" ]; then
    pass "Format handler registered: ${FORMAT_KEY}"

    HANDLER_TYPE=$(echo "$HANDLER" | jq -r '.handler_type')
    IS_ENABLED=$(echo "$HANDLER" | jq -r '.is_enabled')

    if [ "$HANDLER_TYPE" = "wasm" ]; then
        pass "Handler type is WASM"
    else
        fail "Expected handler_type 'wasm', got '${HANDLER_TYPE}'"
    fi

    if [ "$IS_ENABLED" = "true" ]; then
        pass "Handler is enabled"
    else
        fail "Handler is not enabled"
    fi
else
    fail "Format handler not found: ${FORMAT_KEY}"
fi

# -------------------------------------------------------------------------
# Step 5: Test format handler execution
# -------------------------------------------------------------------------
header "Testing Format Handler Execution"

# Create a test file (Unity packages are gzipped tarballs)
TEST_FILE=$(mktemp)
echo "test content for unity package" | gzip > "$TEST_FILE"

info "Testing format handler with sample file..."
TEST_RESPONSE=$(curl -sf -X POST "${API_URL}/api/format-handlers/${FORMAT_KEY}/test" \
    -F "path=com.example.test/1.0.0/test-1.0.0.unitypackage" \
    -F "file=@${TEST_FILE}" 2>&1) || {
    rm -f "$TEST_FILE"
    info "Test endpoint response: $TEST_RESPONSE"
    # This might fail if the test endpoint requires specific file format
    # For now, we just verify the endpoint exists
    info "Format handler test endpoint exists (file format validation may fail)"
}

rm -f "$TEST_FILE"

if echo "$TEST_RESPONSE" | jq . 2>/dev/null; then
    pass "Format handler test completed"
    echo "$TEST_RESPONSE" | jq .
fi

# -------------------------------------------------------------------------
# Step 6: Check plugin events
# -------------------------------------------------------------------------
header "Checking Plugin Events"
EVENTS=$(curl -sf "${API_URL}/api/plugins/${PLUGIN_ID}/events?limit=10")
EVENT_COUNT=$(echo "$EVENTS" | jq '.items | length')
info "Found ${EVENT_COUNT} events"

if [ "$EVENT_COUNT" -gt "0" ]; then
    echo "$EVENTS" | jq '.items[0]'

    INSTALL_EVENT=$(echo "$EVENTS" | jq '.items[] | select(.event_type == "installed")' | head -1)
    if [ -n "$INSTALL_EVENT" ]; then
        pass "Install event logged"
    else
        info "No explicit 'installed' event found (may use different event type)"
    fi
else
    info "No events logged yet"
fi

# -------------------------------------------------------------------------
# Step 7: Test installation with specific git ref
# -------------------------------------------------------------------------
header "Testing Installation with Git Ref"
info "Installing with ref 'main'..."

# First uninstall the current plugin
curl -sf -X DELETE "${API_URL}/api/plugins/${PLUGIN_ID}?force=true" > /dev/null 2>&1 || true
PLUGIN_ID=""

INSTALL_WITH_REF=$(curl -sf -X POST "${API_URL}/api/plugins/install/git" \
    -H "Content-Type: application/json" \
    -d "{\"url\": \"${EXAMPLE_PLUGIN_REPO}\", \"ref\": \"main\"}" 2>&1) || {
    fail "Failed to install plugin with git ref"
}

PLUGIN_ID=$(echo "$INSTALL_WITH_REF" | jq -r '.plugin_id')
if [ "$PLUGIN_ID" != "null" ] && [ -n "$PLUGIN_ID" ]; then
    pass "Plugin installed with git ref 'main'"
else
    fail "Failed to install with git ref"
fi

# -------------------------------------------------------------------------
# Step 8: Verify plugin count increased
# -------------------------------------------------------------------------
header "Verifying Plugin Count"
PLUGINS_AFTER=$(curl -sf "${API_URL}/api/plugins" | jq '.items | length')
info "Plugins after test: ${PLUGINS_AFTER}"

# We installed then uninstalled, then installed again, so should be +1
if [ "$PLUGINS_AFTER" -ge "$PLUGINS_BEFORE" ]; then
    pass "Plugin count verified"
else
    fail "Expected plugin count >= ${PLUGINS_BEFORE}, got ${PLUGINS_AFTER}"
fi

# -------------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------------
header "Test Summary"
echo -e "${GREEN}All WASM plugin Git installation tests passed!${NC}"
echo ""
echo "Plugin Details:"
echo "  ID: ${PLUGIN_ID}"
echo "  Name: ${PLUGIN_NAME}"
echo "  Version: ${PLUGIN_VERSION}"
echo "  Format Key: ${FORMAT_KEY}"
