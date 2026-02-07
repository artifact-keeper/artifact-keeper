#!/bin/bash
# Red Team Test 11: WASM Plugin Security
# Validates that WASM plugin installation endpoints enforce proper
# security controls, including URL validation and access control.

source "$(dirname "$0")/../lib.sh"

set -uo pipefail

header "WASM Plugin Security Testing"

# -----------------------------------------------------------------------
# Test 1: Check if plugin endpoints exist
# -----------------------------------------------------------------------
header "Plugin endpoint discovery"

for endpoint in "/api/v1/plugins" "/api/v1/plugins/install/git" "/api/v1/plugins/install/zip"; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -u "${ADMIN_USER}:${ADMIN_PASS}" \
        "${REGISTRY_URL}${endpoint}" 2>/dev/null) || true

    if [ "$STATUS" = "404" ]; then
        info "Endpoint ${endpoint} not found (404) - not implemented"
    elif [ "$STATUS" = "405" ]; then
        info "Endpoint ${endpoint} exists but returned 405 (method not allowed)"
    elif [ "$STATUS" = "401" ] || [ "$STATUS" = "403" ]; then
        pass "Endpoint ${endpoint} requires authentication (${STATUS})"
    else
        info "Endpoint ${endpoint} returned status ${STATUS}"
    fi
done

# -----------------------------------------------------------------------
# Test 2: Git install with malicious URL (file:// scheme)
# -----------------------------------------------------------------------
header "Git install - malicious URL validation"

info "Attempting plugin install from file:///etc/passwd"

RESPONSE=$(curl -s -w "\n%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -d '{"url": "file:///etc/passwd"}' \
    "${REGISTRY_URL}/api/v1/plugins/install/git" 2>/dev/null) || true

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "404" ]; then
    info "Git install endpoint not found (404) - skipping URL validation test"
elif [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
    fail "Git install accepted file:// URL without validation"
    add_finding "HIGH" "wasm/git-install-arbitrary-url" \
        "Plugin git install endpoint accepted a file:///etc/passwd URL. This could allow server-side file access or SSRF attacks." \
        "POST /api/v1/plugins/install/git with {\"url\": \"file:///etc/passwd\"} returned ${HTTP_CODE}: ${BODY}"
elif [ "$HTTP_CODE" = "400" ] || [ "$HTTP_CODE" = "422" ]; then
    pass "Git install rejected file:// URL (${HTTP_CODE})"
elif [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
    pass "Git install endpoint properly requires authorization (${HTTP_CODE})"
else
    warn "Git install returned unexpected status ${HTTP_CODE} for file:// URL"
    info "Response body: ${BODY}"
fi

# Test with other potentially dangerous URL schemes
for scheme in "ftp://attacker.example.com/plugin.git" "gopher://attacker.example.com/" "dict://attacker.example.com/"; do
    RESPONSE=$(curl -s -w "\n%{http_code}" \
        -X POST -H "Content-Type: application/json" \
        -u "${ADMIN_USER}:${ADMIN_PASS}" \
        -d "{\"url\": \"${scheme}\"}" \
        "${REGISTRY_URL}/api/v1/plugins/install/git" 2>/dev/null) || true

    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    BODY=$(echo "$RESPONSE" | sed '$d')

    if [ "$HTTP_CODE" = "404" ]; then
        break  # Endpoint doesn't exist, no point testing more schemes
    elif [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
        fail "Git install accepted dangerous URL scheme: ${scheme}"
        add_finding "HIGH" "wasm/git-install-dangerous-scheme" \
            "Plugin git install accepted a dangerous URL scheme (${scheme}). This may allow SSRF attacks." \
            "POST /api/v1/plugins/install/git with {\"url\": \"${scheme}\"} returned ${HTTP_CODE}: ${BODY}"
    elif [ "$HTTP_CODE" = "400" ] || [ "$HTTP_CODE" = "422" ]; then
        pass "Git install rejected dangerous URL scheme: ${scheme} (${HTTP_CODE})"
    fi
done

# -----------------------------------------------------------------------
# Test 3: Unauthenticated access to plugin endpoints
# -----------------------------------------------------------------------
header "Plugin endpoint authentication"

for endpoint in "/api/v1/plugins" "/api/v1/plugins/install/git" "/api/v1/plugins/install/zip"; do
    STATUS=$(api_call_status GET "$endpoint") || true

    if [ "$STATUS" = "401" ] || [ "$STATUS" = "403" ]; then
        pass "Endpoint ${endpoint} blocks unauthenticated access (${STATUS})"
    elif [ "$STATUS" = "404" ]; then
        info "Endpoint ${endpoint} not found (404)"
    else
        fail "Endpoint ${endpoint} accessible without authentication (${STATUS})"
        add_finding "HIGH" "wasm/unauth-plugin-access" \
            "Plugin endpoint ${endpoint} is accessible without authentication (HTTP ${STATUS})" \
            "GET ${endpoint} without credentials returned ${STATUS}"
    fi
done

# -----------------------------------------------------------------------
# Test 4: List installed plugins
# -----------------------------------------------------------------------
header "Installed plugin enumeration"

RESPONSE=$(curl -s -w "\n%{http_code}" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${REGISTRY_URL}/api/v1/plugins" 2>/dev/null) || true

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "200" ]; then
    PLUGIN_COUNT=$(echo "$BODY" | jq 'if type == "array" then length else 0 end' 2>/dev/null || echo "unknown")
    info "Plugin listing returned ${PLUGIN_COUNT} plugins"

    if [ "$PLUGIN_COUNT" != "0" ] && [ "$PLUGIN_COUNT" != "unknown" ]; then
        info "Installed plugins:"
        echo "$BODY" | jq -r '.[] | "  - \(.name // .id // "unknown")"' 2>/dev/null || info "  (could not parse plugin list)"
    fi
elif [ "$HTTP_CODE" = "404" ]; then
    info "Plugin listing endpoint not found (404)"
else
    info "Plugin listing returned status ${HTTP_CODE}"
fi

exit 0
