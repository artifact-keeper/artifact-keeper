#!/bin/bash
# Red Team Test 15: Metrics Endpoint Authentication (Regression)
# Verifies that the Prometheus metrics endpoint requires authentication.
# This is a regression test — metrics were previously accessible at /metrics
# without auth, exposing 11+ MB of operational data.

source "$(dirname "$0")/../lib.sh"

set -uo pipefail

header "Metrics Endpoint Authentication Testing"

# -----------------------------------------------------------------------
# Test 1: /metrics without auth (old path — should be gone)
# -----------------------------------------------------------------------
info "Testing GET /metrics without authentication (old public path)"

RESPONSE=$(curl -s -w "\n%{http_code}" \
    "${REGISTRY_URL}/metrics" 2>/dev/null) || true

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "200" ]; then
    BODY_SIZE=${#BODY}
    fail "Metrics endpoint /metrics is accessible without authentication (${BODY_SIZE} bytes)"
    add_finding "MEDIUM" "metrics/unauthenticated-public" \
        "Prometheus metrics endpoint /metrics is accessible without authentication, exposing ${BODY_SIZE} bytes of operational data including request paths, status codes, and internal metrics." \
        "GET /metrics returned 200 with ${BODY_SIZE} bytes. First 200 chars: $(echo "$BODY" | head -c 200)"
elif [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
    pass "Metrics endpoint /metrics requires authentication (${HTTP_CODE})"
elif [ "$HTTP_CODE" = "404" ]; then
    pass "Metrics endpoint /metrics not found at root (404) — likely moved behind auth"
else
    info "Metrics endpoint /metrics returned unexpected status ${HTTP_CODE}"
fi

# -----------------------------------------------------------------------
# Test 2: /api/v1/admin/metrics without auth (new path — should require auth)
# -----------------------------------------------------------------------
info "Testing GET /api/v1/admin/metrics without authentication"

RESPONSE=$(curl -s -w "\n%{http_code}" \
    "${REGISTRY_URL}/api/v1/admin/metrics" 2>/dev/null) || true

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
    pass "Admin metrics endpoint requires authentication (${HTTP_CODE})"
elif [ "$HTTP_CODE" = "200" ]; then
    BODY_SIZE=${#BODY}
    fail "Admin metrics endpoint accessible without auth (${BODY_SIZE} bytes)"
    add_finding "MEDIUM" "metrics/admin-unauthenticated" \
        "Admin metrics endpoint /api/v1/admin/metrics is accessible without authentication." \
        "GET /api/v1/admin/metrics returned 200 with ${BODY_SIZE} bytes"
elif [ "$HTTP_CODE" = "404" ]; then
    info "Admin metrics endpoint not found (404)"
else
    info "Admin metrics endpoint returned ${HTTP_CODE}"
fi

# -----------------------------------------------------------------------
# Test 3: /api/v1/admin/metrics WITH auth (should work)
# -----------------------------------------------------------------------
header "Authenticated Metrics Access"

info "Authenticating..."

LOGIN_RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" \
    -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" \
    "${REGISTRY_URL}/api/v1/auth/login" 2>/dev/null) || true

TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.access_token // empty' 2>/dev/null) || true

if [ -z "$TOKEN" ]; then
    warn "Could not authenticate — skipping authenticated metrics test"
    exit 0
fi

info "Testing GET /api/v1/admin/metrics with valid token"

RESPONSE=$(curl -s -w "\n%{http_code}" \
    -H "Authorization: Bearer ${TOKEN}" \
    "${REGISTRY_URL}/api/v1/admin/metrics" 2>/dev/null) || true

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "200" ]; then
    pass "Admin metrics accessible with authentication (${#BODY} bytes)"
elif [ "$HTTP_CODE" = "403" ]; then
    info "Admin metrics requires admin role (${HTTP_CODE}) — acceptable"
elif [ "$HTTP_CODE" = "404" ]; then
    info "Admin metrics endpoint not found at /api/v1/admin/metrics (404)"
else
    info "Authenticated admin metrics returned ${HTTP_CODE}"
fi

exit 0
