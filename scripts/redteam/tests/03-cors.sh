#!/bin/bash
# Red Team Test 03: CORS Misconfiguration
# Tests whether the server allows cross-origin requests from untrusted origins.

source "$(dirname "$0")/../lib.sh"

set -uo pipefail

header "CORS Misconfiguration Testing"

EVIL_ORIGIN="https://evil.com"

# --- Test 1: Simple request with malicious Origin header ---
info "Testing simple request with Origin: ${EVIL_ORIGIN}"

RESPONSE_HEADERS=$(curl -sI -X GET \
    -H "Origin: ${EVIL_ORIGIN}" \
    "${REGISTRY_URL}/health" 2>&1) || true

ACAO=$(echo "$RESPONSE_HEADERS" | grep -i "^Access-Control-Allow-Origin:" | head -1 | sed 's/^[^:]*: *//' | tr -d '\r') || true

if [ -z "$ACAO" ]; then
    pass "No Access-Control-Allow-Origin header returned for evil origin (simple GET)"
elif [ "$ACAO" = "*" ]; then
    fail "CORS allows any origin (wildcard): Access-Control-Allow-Origin: *"
    add_finding "CRITICAL" "cors/wildcard-origin" \
        "Server returns Access-Control-Allow-Origin: * which allows any website to make cross-origin requests. This could allow malicious sites to interact with the API on behalf of authenticated users." \
        "Request: GET /health with Origin: ${EVIL_ORIGIN}. Response header: Access-Control-Allow-Origin: *"
elif [ "$ACAO" = "$EVIL_ORIGIN" ]; then
    fail "CORS reflects arbitrary origin: ${EVIL_ORIGIN}"
    add_finding "CRITICAL" "cors/origin-reflection" \
        "Server reflects the attacker-controlled Origin header in Access-Control-Allow-Origin. This allows any website to make authenticated cross-origin requests to the API." \
        "Request: GET /health with Origin: ${EVIL_ORIGIN}. Response header: Access-Control-Allow-Origin: ${EVIL_ORIGIN}"
else
    pass "Access-Control-Allow-Origin is set to a specific allowed origin: ${ACAO}"
fi

# --- Test 2: Preflight OPTIONS request with malicious Origin ---
info "Testing preflight OPTIONS request with Origin: ${EVIL_ORIGIN}"

PREFLIGHT_HEADERS=$(curl -sI -X OPTIONS \
    -H "Origin: ${EVIL_ORIGIN}" \
    -H "Access-Control-Request-Method: POST" \
    -H "Access-Control-Request-Headers: Content-Type, Authorization" \
    "${REGISTRY_URL}/api/v1/repositories" 2>&1) || true

PREFLIGHT_ACAO=$(echo "$PREFLIGHT_HEADERS" | grep -i "^Access-Control-Allow-Origin:" | head -1 | sed 's/^[^:]*: *//' | tr -d '\r') || true
PREFLIGHT_METHODS=$(echo "$PREFLIGHT_HEADERS" | grep -i "^Access-Control-Allow-Methods:" | head -1 | sed 's/^[^:]*: *//' | tr -d '\r') || true
PREFLIGHT_HEADERS_ALLOWED=$(echo "$PREFLIGHT_HEADERS" | grep -i "^Access-Control-Allow-Headers:" | head -1 | sed 's/^[^:]*: *//' | tr -d '\r') || true
PREFLIGHT_CREDENTIALS=$(echo "$PREFLIGHT_HEADERS" | grep -i "^Access-Control-Allow-Credentials:" | head -1 | sed 's/^[^:]*: *//' | tr -d '\r') || true

if [ -z "$PREFLIGHT_ACAO" ]; then
    pass "No Access-Control-Allow-Origin in preflight response for evil origin"
elif [ "$PREFLIGHT_ACAO" = "*" ]; then
    fail "Preflight allows any origin (wildcard): Access-Control-Allow-Origin: *"
    add_finding "CRITICAL" "cors/preflight-wildcard" \
        "Preflight (OPTIONS) response returns Access-Control-Allow-Origin: * allowing any site to make cross-origin API requests." \
        "OPTIONS /api/v1/repositories with Origin: ${EVIL_ORIGIN}. ACAO: *, Methods: ${PREFLIGHT_METHODS:-none}, Headers: ${PREFLIGHT_HEADERS_ALLOWED:-none}"
elif [ "$PREFLIGHT_ACAO" = "$EVIL_ORIGIN" ]; then
    fail "Preflight reflects arbitrary origin: ${EVIL_ORIGIN}"
    add_finding "CRITICAL" "cors/preflight-reflection" \
        "Preflight (OPTIONS) response reflects the attacker-controlled Origin in Access-Control-Allow-Origin, enabling cross-origin attacks." \
        "OPTIONS /api/v1/repositories with Origin: ${EVIL_ORIGIN}. ACAO: ${PREFLIGHT_ACAO}, Methods: ${PREFLIGHT_METHODS:-none}, Headers: ${PREFLIGHT_HEADERS_ALLOWED:-none}"
else
    pass "Preflight Access-Control-Allow-Origin is restricted: ${PREFLIGHT_ACAO}"
fi

# --- Test 3: Check if credentials are allowed with wildcard ---
if [ "$PREFLIGHT_CREDENTIALS" = "true" ] && { [ "$PREFLIGHT_ACAO" = "*" ] || [ "$PREFLIGHT_ACAO" = "$EVIL_ORIGIN" ]; }; then
    fail "CORS allows credentials with permissive origin"
    add_finding "CRITICAL" "cors/credentials-with-wildcard" \
        "Server sets Access-Control-Allow-Credentials: true alongside a permissive Access-Control-Allow-Origin. This allows malicious sites to make authenticated requests and read responses, potentially stealing user data." \
        "ACAO: ${PREFLIGHT_ACAO}, Access-Control-Allow-Credentials: true"
elif [ "$PREFLIGHT_CREDENTIALS" = "true" ]; then
    warn "Access-Control-Allow-Credentials is true (acceptable if origin is properly restricted)"
else
    pass "Credentials are not allowed for cross-origin requests (or not set)"
fi

# --- Test 4: Test with null origin (sometimes bypasses allowlists) ---
info "Testing with Origin: null (common bypass technique)"

NULL_RESPONSE=$(curl -sI -X GET \
    -H "Origin: null" \
    "${REGISTRY_URL}/health" 2>&1) || true

NULL_ACAO=$(echo "$NULL_RESPONSE" | grep -i "^Access-Control-Allow-Origin:" | head -1 | sed 's/^[^:]*: *//' | tr -d '\r') || true

if [ "$NULL_ACAO" = "null" ]; then
    fail "CORS allows null origin"
    add_finding "HIGH" "cors/null-origin" \
        "Server allows Origin: null in Access-Control-Allow-Origin. The null origin can be triggered from sandboxed iframes and data: URLs, potentially enabling cross-origin attacks." \
        "Request: GET /health with Origin: null. Response: Access-Control-Allow-Origin: null"
elif [ -z "$NULL_ACAO" ]; then
    pass "No Access-Control-Allow-Origin returned for null origin"
else
    pass "Origin null is not reflected (ACAO: ${NULL_ACAO})"
fi

exit 0
