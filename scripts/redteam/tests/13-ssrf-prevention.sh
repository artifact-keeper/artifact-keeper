#!/bin/bash
# Red Team Test 13: SSRF Prevention (Regression)
# Verifies that webhook URL validation blocks internal/private network targets.
# This is a regression test for the SSRF vulnerability found during dynamic scanning.

source "$(dirname "$0")/../lib.sh"

set -uo pipefail

header "SSRF Prevention Testing"

# We need an auth token to create webhooks
info "Authenticating to test webhook creation..."

LOGIN_RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" \
    -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" \
    "${REGISTRY_URL}/api/v1/auth/login" 2>/dev/null) || true

TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.access_token // empty' 2>/dev/null) || true

if [ -z "$TOKEN" ]; then
    warn "Could not authenticate — skipping SSRF tests (login may have changed)"
    info "Login response: $(echo "$LOGIN_RESPONSE" | head -c 200)"
    exit 0
fi

pass "Authenticated successfully"

# Helper: attempt to create a webhook with a blocked URL
test_ssrf_url() {
    local description="$1"
    local url="$2"

    info "Testing SSRF block: ${description} (${url})"

    RESPONSE=$(curl -s -w "\n%{http_code}" \
        -X POST -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${TOKEN}" \
        -d "{\"name\":\"ssrf-test\",\"url\":\"${url}\",\"events\":[\"artifact.pushed\"]}" \
        "${REGISTRY_URL}/api/v1/webhooks" 2>/dev/null) || true

    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    BODY=$(echo "$RESPONSE" | sed '$d')

    if [ "$HTTP_CODE" = "400" ] || [ "$HTTP_CODE" = "422" ]; then
        pass "Blocked: ${description} (${HTTP_CODE})"
        return 0
    elif [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        fail "SSRF: ${description} was ACCEPTED (${HTTP_CODE})"
        # Try to clean up the created webhook
        WEBHOOK_ID=$(echo "$BODY" | jq -r '.id // empty' 2>/dev/null) || true
        if [ -n "$WEBHOOK_ID" ]; then
            curl -s -X DELETE -H "Authorization: Bearer ${TOKEN}" \
                "${REGISTRY_URL}/api/v1/webhooks/${WEBHOOK_ID}" >/dev/null 2>&1 || true
        fi
        add_finding "CRITICAL" "ssrf/webhook-${description// /-}" \
            "Webhook creation accepted an internal/private URL: ${url}. An attacker could use this to probe internal services, access cloud metadata, or exfiltrate data via server-side requests." \
            "POST /api/v1/webhooks with url=${url} returned ${HTTP_CODE}. Body: $(echo "$BODY" | head -c 500)"
        return 1
    else
        info "Unexpected status ${HTTP_CODE} for ${description}: $(echo "$BODY" | head -c 200)"
        return 0
    fi
}

# --- Test AWS/Cloud metadata endpoints ---
header "Cloud Metadata SSRF"

test_ssrf_url "AWS metadata (IP)" "http://169.254.169.254/latest/meta-data/"
test_ssrf_url "AWS metadata (hostname)" "http://metadata.google.internal/computeMetadata/v1/"
test_ssrf_url "Azure metadata" "http://metadata.azure.com/metadata/instance"

# --- Test private/internal IP ranges ---
header "Private Network SSRF"

test_ssrf_url "Loopback (127.0.0.1)" "http://127.0.0.1:8080/admin"
test_ssrf_url "Loopback (localhost)" "http://localhost:5432/"
test_ssrf_url "Private 10.x" "http://10.0.0.1/"
test_ssrf_url "Private 172.16.x" "http://172.16.0.1/"
test_ssrf_url "Private 192.168.x" "http://192.168.1.1/"

# --- Test internal Docker service names ---
header "Internal Service SSRF"

test_ssrf_url "Docker backend" "http://backend:8080/"
test_ssrf_url "Docker postgres" "http://postgres:5432/"
test_ssrf_url "Docker redis" "http://redis:6379/"

# --- Test that legitimate external URLs still work ---
header "Legitimate URL Validation"

info "Testing that external URLs are accepted..."

RESPONSE=$(curl -s -w "\n%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN}" \
    -d '{"name":"ssrf-legit-test","url":"https://example.com/webhook","events":["artifact.pushed"]}' \
    "${REGISTRY_URL}/api/v1/webhooks" 2>/dev/null) || true

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    pass "Legitimate external URL accepted (${HTTP_CODE})"
    # Clean up
    WEBHOOK_ID=$(echo "$BODY" | jq -r '.id // empty' 2>/dev/null) || true
    if [ -n "$WEBHOOK_ID" ]; then
        curl -s -X DELETE -H "Authorization: Bearer ${TOKEN}" \
            "${REGISTRY_URL}/api/v1/webhooks/${WEBHOOK_ID}" >/dev/null 2>&1 || true
    fi
elif [ "$HTTP_CODE" = "400" ] || [ "$HTTP_CODE" = "422" ]; then
    warn "Legitimate URL rejected (may be overly restrictive): $(echo "$BODY" | head -c 200)"
else
    info "External URL returned ${HTTP_CODE}: $(echo "$BODY" | head -c 200)"
fi

exit 0
