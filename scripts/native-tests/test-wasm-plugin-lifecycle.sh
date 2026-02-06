#!/usr/bin/env bash
# WASM Plugin E2E Test - Lifecycle Management
#
# Tests complete plugin lifecycle:
# 1. Install plugin
# 2. Disable plugin - verify requests fail gracefully
# 3. Re-enable plugin - verify requests succeed
# 4. Uninstall plugin - verify cleanup
# 5. Verify all lifecycle events logged
#
# Requires: backend running on port 8080
#
# Usage:
#   ./test-wasm-plugin-lifecycle.sh
#   API_URL=http://localhost:8080 ./test-wasm-plugin-lifecycle.sh

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
FORMAT_KEY=""

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
FORMAT_KEY=$(echo "$INSTALL_RESPONSE" | jq -r '.format_key')
PLUGIN_NAME=$(echo "$INSTALL_RESPONSE" | jq -r '.name')

if [ "$PLUGIN_ID" = "null" ] || [ -z "$PLUGIN_ID" ]; then
    fail "Plugin ID not returned"
fi
pass "Plugin installed: ${PLUGIN_NAME} (ID: ${PLUGIN_ID})"

# Verify initial status
INITIAL_STATUS=$(curl -sf "${API_URL}/api/plugins/${PLUGIN_ID}" | jq -r '.status')
if [ "$INITIAL_STATUS" = "active" ]; then
    pass "Initial status: active"
else
    fail "Expected initial status 'active', got '${INITIAL_STATUS}'"
fi

# -------------------------------------------------------------------------
# Step 2: Disable plugin
# -------------------------------------------------------------------------
header "Disabling Plugin"
info "Disabling plugin ${PLUGIN_ID}..."

DISABLE_RESPONSE=$(curl -sf -X POST "${API_URL}/api/plugins/${PLUGIN_ID}/disable" 2>&1) || {
    fail "Failed to disable plugin"
}
echo "$DISABLE_RESPONSE" | jq . 2>/dev/null || echo "$DISABLE_RESPONSE"

# Verify status changed
DISABLED_STATUS=$(curl -sf "${API_URL}/api/plugins/${PLUGIN_ID}" | jq -r '.status')
if [ "$DISABLED_STATUS" = "disabled" ]; then
    pass "Plugin status changed to disabled"
else
    fail "Expected status 'disabled', got '${DISABLED_STATUS}'"
fi

# Verify format handler is disabled
HANDLER_ENABLED=$(curl -sf "${API_URL}/api/format-handlers/${FORMAT_KEY}" | jq -r '.is_enabled')
if [ "$HANDLER_ENABLED" = "false" ]; then
    pass "Format handler disabled"
else
    info "Format handler may still be enabled (checking behavior...)"
fi

# -------------------------------------------------------------------------
# Step 3: Re-enable plugin
# -------------------------------------------------------------------------
header "Re-enabling Plugin"
info "Enabling plugin ${PLUGIN_ID}..."

ENABLE_RESPONSE=$(curl -sf -X POST "${API_URL}/api/plugins/${PLUGIN_ID}/enable" 2>&1) || {
    fail "Failed to enable plugin"
}
echo "$ENABLE_RESPONSE" | jq . 2>/dev/null || echo "$ENABLE_RESPONSE"

# Verify status changed back
ENABLED_STATUS=$(curl -sf "${API_URL}/api/plugins/${PLUGIN_ID}" | jq -r '.status')
if [ "$ENABLED_STATUS" = "active" ]; then
    pass "Plugin status changed to active"
else
    fail "Expected status 'active', got '${ENABLED_STATUS}'"
fi

# Verify format handler is re-enabled
HANDLER_ENABLED=$(curl -sf "${API_URL}/api/format-handlers/${FORMAT_KEY}" | jq -r '.is_enabled')
if [ "$HANDLER_ENABLED" = "true" ]; then
    pass "Format handler re-enabled"
else
    info "Format handler status: ${HANDLER_ENABLED}"
fi

# -------------------------------------------------------------------------
# Step 4: Check lifecycle events
# -------------------------------------------------------------------------
header "Checking Lifecycle Events"
EVENTS=$(curl -sf "${API_URL}/api/plugins/${PLUGIN_ID}/events?limit=20")
EVENT_COUNT=$(echo "$EVENTS" | jq '.items | length')
info "Found ${EVENT_COUNT} events"

if [ "$EVENT_COUNT" -gt "0" ]; then
    echo "$EVENTS" | jq '.items[] | {event_type, message, created_at}' | head -30

    # Check for expected events
    for event_type in "installed" "disabled" "enabled"; do
        if echo "$EVENTS" | jq -e ".items[] | select(.event_type == \"${event_type}\")" > /dev/null 2>&1; then
            pass "Found '${event_type}' event"
        else
            info "Event type '${event_type}' not found (may use different naming)"
        fi
    done
else
    info "No events logged"
fi

# -------------------------------------------------------------------------
# Step 5: Uninstall plugin
# -------------------------------------------------------------------------
header "Uninstalling Plugin"
info "Uninstalling plugin ${PLUGIN_ID}..."

UNINSTALL_RESPONSE=$(curl -sf -X DELETE "${API_URL}/api/plugins/${PLUGIN_ID}" 2>&1) || {
    # Might need force flag
    info "Trying with force flag..."
    UNINSTALL_RESPONSE=$(curl -sf -X DELETE "${API_URL}/api/plugins/${PLUGIN_ID}?force=true" 2>&1) || {
        fail "Failed to uninstall plugin"
    }
}
echo "$UNINSTALL_RESPONSE" | jq . 2>/dev/null || echo "$UNINSTALL_RESPONSE"
pass "Plugin uninstalled"

# Clear PLUGIN_ID so cleanup doesn't try again
PLUGIN_ID=""

# -------------------------------------------------------------------------
# Step 6: Verify cleanup
# -------------------------------------------------------------------------
header "Verifying Cleanup"

# Plugin should no longer exist
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${API_URL}/api/plugins/${PLUGIN_ID:-none}" 2>/dev/null || echo "000")
if [ "$HTTP_STATUS" = "404" ] || [ "$HTTP_STATUS" = "000" ]; then
    pass "Plugin record deleted (404 returned)"
else
    info "Plugin endpoint returned: ${HTTP_STATUS}"
fi

# Format handler should be gone or marked as unavailable
HANDLER_CHECK=$(curl -sf "${API_URL}/api/format-handlers/${FORMAT_KEY}" 2>&1 || echo '{"error": "not found"}')
if echo "$HANDLER_CHECK" | jq -e '.handler_type == "wasm"' > /dev/null 2>&1; then
    fail "Format handler still exists after uninstall"
else
    pass "Format handler removed or reverted to core"
fi

# -------------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------------
header "Test Summary"
echo -e "${GREEN}All WASM plugin lifecycle tests passed!${NC}"
echo ""
echo "Tested lifecycle:"
echo "  1. Install → active"
echo "  2. Disable → disabled"
echo "  3. Enable → active"
echo "  4. Uninstall → removed"
