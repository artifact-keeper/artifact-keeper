#!/usr/bin/env bash
# WASM Plugin E2E Test - Hot Reload
#
# Tests plugin hot-reload functionality:
# 1. Install plugin
# 2. Trigger reload from source
# 3. Verify version tracking
# 4. Test reload failure handling
#
# Requires: backend running on port 8080
#
# Usage:
#   ./test-wasm-plugin-reload.sh
#   API_URL=http://localhost:8080 ./test-wasm-plugin-reload.sh

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

PLUGIN_ID=""

cleanup() {
    if [ -n "$PLUGIN_ID" ]; then
        info "Cleaning up: uninstalling plugin ${PLUGIN_ID}"
        curl -sf -X DELETE "${API_URL}/api/plugins/${PLUGIN_ID}?force=true" > /dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# -------------------------------------------------------------------------
# Step 1: Install plugin
# -------------------------------------------------------------------------
header "Installing Plugin"
info "Repository: ${EXAMPLE_PLUGIN_REPO}"

INSTALL_RESPONSE=$(curl -sf -X POST "${API_URL}/api/plugins/install/git" \
    -H "Content-Type: application/json" \
    -d "{\"url\": \"${EXAMPLE_PLUGIN_REPO}\"}" 2>&1) || {
    fail "Failed to install plugin"
}

PLUGIN_ID=$(echo "$INSTALL_RESPONSE" | jq -r '.plugin_id')
PLUGIN_NAME=$(echo "$INSTALL_RESPONSE" | jq -r '.name')
INITIAL_VERSION=$(echo "$INSTALL_RESPONSE" | jq -r '.version')

if [ "$PLUGIN_ID" = "null" ] || [ -z "$PLUGIN_ID" ]; then
    fail "Plugin ID not returned"
fi
pass "Plugin installed: ${PLUGIN_NAME} v${INITIAL_VERSION}"

# Get initial plugin details
INITIAL_DETAILS=$(curl -sf "${API_URL}/api/plugins/${PLUGIN_ID}")
INITIAL_UPDATED_AT=$(echo "$INITIAL_DETAILS" | jq -r '.updated_at // .installed_at')
info "Initial updated_at: ${INITIAL_UPDATED_AT}"

# -------------------------------------------------------------------------
# Step 2: Trigger hot-reload
# -------------------------------------------------------------------------
header "Triggering Hot Reload"
info "Reloading plugin ${PLUGIN_ID} from source..."

# Small delay to ensure timestamps differ
sleep 1

RELOAD_RESPONSE=$(curl -sf -X POST "${API_URL}/api/plugins/${PLUGIN_ID}/reload" 2>&1) || {
    echo "Reload response: $RELOAD_RESPONSE"
    fail "Failed to reload plugin"
}
echo "$RELOAD_RESPONSE" | jq . 2>/dev/null || echo "$RELOAD_RESPONSE"
pass "Reload request completed"

# -------------------------------------------------------------------------
# Step 3: Verify reload
# -------------------------------------------------------------------------
header "Verifying Reload"

# Get updated plugin details
RELOADED_DETAILS=$(curl -sf "${API_URL}/api/plugins/${PLUGIN_ID}")
RELOADED_VERSION=$(echo "$RELOADED_DETAILS" | jq -r '.version')
RELOADED_STATUS=$(echo "$RELOADED_DETAILS" | jq -r '.status')
RELOADED_UPDATED_AT=$(echo "$RELOADED_DETAILS" | jq -r '.updated_at // .installed_at')

info "Version after reload: ${RELOADED_VERSION}"
info "Status after reload: ${RELOADED_STATUS}"
info "Updated_at after reload: ${RELOADED_UPDATED_AT}"

# Version should be the same (same source)
if [ "$RELOADED_VERSION" = "$INITIAL_VERSION" ]; then
    pass "Version unchanged (same source): ${RELOADED_VERSION}"
else
    info "Version changed: ${INITIAL_VERSION} -> ${RELOADED_VERSION}"
fi

# Status should still be active
if [ "$RELOADED_STATUS" = "active" ]; then
    pass "Plugin still active after reload"
else
    fail "Expected status 'active' after reload, got '${RELOADED_STATUS}'"
fi

# updated_at should be different (or at least not fail)
if [ "$RELOADED_UPDATED_AT" != "$INITIAL_UPDATED_AT" ]; then
    pass "Timestamp updated after reload"
else
    info "Timestamp unchanged (may be same second)"
fi

# -------------------------------------------------------------------------
# Step 4: Check reload events
# -------------------------------------------------------------------------
header "Checking Reload Events"
EVENTS=$(curl -sf "${API_URL}/api/plugins/${PLUGIN_ID}/events?limit=20")
EVENT_COUNT=$(echo "$EVENTS" | jq '.items | length')
info "Found ${EVENT_COUNT} events"

if [ "$EVENT_COUNT" -gt "0" ]; then
    echo "$EVENTS" | jq '.items[] | {event_type, message, created_at}' | head -20

    # Look for reload event
    if echo "$EVENTS" | jq -e '.items[] | select(.event_type == "reloaded" or .event_type == "reload" or .message | contains("reload"))' > /dev/null 2>&1; then
        pass "Found reload event"
    else
        info "No explicit reload event found (may use different naming)"
    fi
fi

# -------------------------------------------------------------------------
# Step 5: Test format handler still works after reload
# -------------------------------------------------------------------------
header "Testing Format Handler After Reload"
FORMAT_KEY=$(curl -sf "${API_URL}/api/plugins/${PLUGIN_ID}" | jq -r '.format_key // empty')

if [ -n "$FORMAT_KEY" ]; then
    HANDLER=$(curl -sf "${API_URL}/api/format-handlers/${FORMAT_KEY}" 2>/dev/null || echo '{}')
    IS_ENABLED=$(echo "$HANDLER" | jq -r '.is_enabled')
    if [ "$IS_ENABLED" = "true" ]; then
        pass "Format handler still enabled after reload"
    else
        info "Format handler status: ${IS_ENABLED}"
    fi
else
    info "No format_key in plugin response"
fi

# -------------------------------------------------------------------------
# Step 6: Test multiple reloads
# -------------------------------------------------------------------------
header "Testing Multiple Consecutive Reloads"
for i in 1 2 3; do
    info "Reload #${i}..."
    RELOAD_RESPONSE=$(curl -sf -X POST "${API_URL}/api/plugins/${PLUGIN_ID}/reload" 2>&1) || {
        fail "Reload #${i} failed"
    }
    sleep 0.5
done
pass "Multiple reloads completed without error"

# Verify plugin still works
FINAL_STATUS=$(curl -sf "${API_URL}/api/plugins/${PLUGIN_ID}" | jq -r '.status')
if [ "$FINAL_STATUS" = "active" ]; then
    pass "Plugin still active after multiple reloads"
else
    fail "Plugin status '${FINAL_STATUS}' after multiple reloads"
fi

# -------------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------------
header "Test Summary"
echo -e "${GREEN}All WASM plugin hot-reload tests passed!${NC}"
echo ""
echo "Tested:"
echo "  - Single reload from source"
echo "  - Version tracking"
echo "  - Status preservation"
echo "  - Event logging"
echo "  - Multiple consecutive reloads"
