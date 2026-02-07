#!/bin/bash
# Red Team Test 10: Rate Limiting
# Verifies that rate limiting is in place for authentication and
# general API endpoints to prevent brute-force attacks.

source "$(dirname "$0")/../lib.sh"

set -uo pipefail

header "Rate Limiting Tests"

REQUEST_COUNT=50

# -----------------------------------------------------------------------
# Test 1: Rapid failed login attempts
# -----------------------------------------------------------------------
header "Brute-force login test (${REQUEST_COUNT} rapid requests)"

info "Sending ${REQUEST_COUNT} failed login attempts to POST /api/v1/auth/login"

RATE_LIMITED=false
RATE_LIMIT_HEADER_FOUND=false
BLOCKED_COUNT=0

for i in $(seq 1 $REQUEST_COUNT); do
    RESPONSE=$(curl -s -w "\n%{http_code}" -D - \
        -X POST -H "Content-Type: application/json" \
        -d '{"username":"attacker","password":"wrong-password-'"$i"'"}' \
        "${REGISTRY_URL}/api/v1/auth/login" 2>/dev/null) || true

    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    RESP_HEADERS=$(echo "$RESPONSE" | sed '$d')

    # Check for rate limit headers
    if echo "$RESP_HEADERS" | grep -qi "X-RateLimit-Limit"; then
        RATE_LIMIT_HEADER_FOUND=true
    fi

    # 429 Too Many Requests means rate limiting is active
    if [ "$HTTP_CODE" = "429" ]; then
        RATE_LIMITED=true
        BLOCKED_COUNT=$((BLOCKED_COUNT + 1))
    fi
done

if [ "$RATE_LIMITED" = true ]; then
    pass "Rate limiting is active on login endpoint (blocked after some attempts, ${BLOCKED_COUNT} requests returned 429)"
elif [ "$RATE_LIMIT_HEADER_FOUND" = true ]; then
    warn "Rate limit headers present but no requests were blocked after ${REQUEST_COUNT} attempts"
    add_finding "MEDIUM" "rate-limit/login-not-enforced" \
        "Rate limit headers are present on /api/v1/auth/login but ${REQUEST_COUNT} rapid failed login attempts were not blocked" \
        "Sent ${REQUEST_COUNT} POST requests with wrong credentials. X-RateLimit-Limit header found but no 429 responses received."
else
    fail "No rate limiting detected on login endpoint after ${REQUEST_COUNT} failed attempts"
    add_finding "HIGH" "rate-limit/login-missing" \
        "No rate limiting on /api/v1/auth/login. An attacker can perform unlimited brute-force login attempts without being throttled." \
        "Sent ${REQUEST_COUNT} POST /api/v1/auth/login requests with invalid credentials. No X-RateLimit-Limit header found and no 429 responses received."
fi

# -----------------------------------------------------------------------
# Test 2: Rapid authenticated API requests
# -----------------------------------------------------------------------
header "API rate limit test (${REQUEST_COUNT} rapid requests)"

info "Sending ${REQUEST_COUNT} rapid GET requests to /api/v1/repositories"

RATE_LIMITED=false
RATE_LIMIT_HEADER_FOUND=false
BLOCKED_COUNT=0

for i in $(seq 1 $REQUEST_COUNT); do
    RESPONSE=$(curl -s -w "\n%{http_code}" -D - \
        -X GET -u "${ADMIN_USER}:${ADMIN_PASS}" \
        "${REGISTRY_URL}/api/v1/repositories" 2>/dev/null) || true

    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    RESP_HEADERS=$(echo "$RESPONSE" | sed '$d')

    if echo "$RESP_HEADERS" | grep -qi "X-RateLimit-Limit"; then
        RATE_LIMIT_HEADER_FOUND=true
    fi

    if [ "$HTTP_CODE" = "429" ]; then
        RATE_LIMITED=true
        BLOCKED_COUNT=$((BLOCKED_COUNT + 1))
    fi
done

if [ "$RATE_LIMITED" = true ]; then
    pass "Rate limiting is active on API endpoints (${BLOCKED_COUNT} requests returned 429)"
elif [ "$RATE_LIMIT_HEADER_FOUND" = true ]; then
    info "Rate limit headers present on /api/v1/repositories but no requests were blocked"
    pass "Rate limit headers are present (X-RateLimit-Limit) on API endpoints"
else
    warn "No rate limit headers found on /api/v1/repositories"
    add_finding "MEDIUM" "rate-limit/api-missing" \
        "No rate limiting detected on /api/v1/repositories. Consider adding rate limits to protect against abuse and DoS." \
        "Sent ${REQUEST_COUNT} GET /api/v1/repositories requests. No X-RateLimit-Limit header and no 429 responses."
fi

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
header "Rate Limit Summary"

if [ "$RATE_LIMIT_HEADER_FOUND" = true ]; then
    info "Rate limit headers detected: Yes"
else
    info "Rate limit headers detected: No"
fi

exit 0
