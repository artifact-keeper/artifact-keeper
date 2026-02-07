#!/bin/bash
# Red Team Test 14: API Key / Secret Exposure (Regression)
# Verifies that sensitive fields like API keys, tokens, and passwords
# are not exposed in API responses.
# This is a regression test for the peer API key leak found during dynamic scanning.

source "$(dirname "$0")/../lib.sh"

set -uo pipefail

header "API Key / Secret Exposure Testing"

# Authenticate first
info "Authenticating..."

LOGIN_RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" \
    -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" \
    "${REGISTRY_URL}/api/v1/auth/login" 2>/dev/null) || true

TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.access_token // empty' 2>/dev/null) || true

if [ -z "$TOKEN" ]; then
    warn "Could not authenticate — skipping API key exposure tests"
    exit 0
fi

pass "Authenticated successfully"

# -----------------------------------------------------------------------
# Test 1: Peer instances API key exposure
# -----------------------------------------------------------------------
header "Peer Instance API Key Exposure"

info "Fetching peer instances from GET /api/v1/peers"

RESPONSE=$(curl -s -w "\n%{http_code}" \
    -H "Authorization: Bearer ${TOKEN}" \
    "${REGISTRY_URL}/api/v1/peers" 2>/dev/null) || true

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "200" ]; then
    # Check if api_key field appears in the response
    if echo "$BODY" | jq -e '.. | .api_key? // empty' 2>/dev/null | grep -q .; then
        fail "Peer API response exposes api_key field"
        API_KEY_VALUE=$(echo "$BODY" | jq -r '.. | .api_key? // empty' 2>/dev/null | head -1)
        add_finding "CRITICAL" "exposure/peer-api-key" \
            "GET /api/v1/peers returns api_key in plaintext. An attacker with read access to the peers API can steal inter-node authentication credentials and impersonate peer instances." \
            "api_key value found in response: ${API_KEY_VALUE:0:20}..."
    else
        pass "Peer API response does not expose api_key field"
    fi

    # Also check for other sensitive-looking fields
    SENSITIVE_FIELDS=$(echo "$BODY" | jq -r '.. | keys_unsorted? // empty | .[]' 2>/dev/null \
        | grep -iE "^(password|secret|private_key|token|credential|api_secret)$" | sort -u) || true

    if [ -n "$SENSITIVE_FIELDS" ]; then
        warn "Peer API response contains sensitive-looking fields: ${SENSITIVE_FIELDS}"
        add_finding "HIGH" "exposure/peer-sensitive-fields" \
            "GET /api/v1/peers response contains fields that may expose secrets: ${SENSITIVE_FIELDS}" \
            "Fields found: ${SENSITIVE_FIELDS}"
    fi
elif [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
    info "Peers endpoint requires authentication (${HTTP_CODE}) — this is expected"
elif [ "$HTTP_CODE" = "404" ]; then
    info "Peers endpoint not found (404) — skipping"
else
    info "Peers endpoint returned ${HTTP_CODE}"
fi

# -----------------------------------------------------------------------
# Test 2: User list password/hash exposure
# -----------------------------------------------------------------------
header "User Data Exposure"

info "Fetching users from GET /api/v1/users"

RESPONSE=$(curl -s -w "\n%{http_code}" \
    -H "Authorization: Bearer ${TOKEN}" \
    "${REGISTRY_URL}/api/v1/users" 2>/dev/null) || true

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "200" ]; then
    # Check for password hashes or sensitive auth fields
    HAS_PASSWORD=$(echo "$BODY" | jq -e '.. | .password_hash? // .password? // empty' 2>/dev/null | head -1) || true

    if [ -n "$HAS_PASSWORD" ]; then
        fail "User API response exposes password/hash field"
        add_finding "CRITICAL" "exposure/user-password-hash" \
            "GET /api/v1/users returns password_hash or password field. An attacker can use this to crack passwords offline." \
            "Field found in response (value redacted)"
    else
        pass "User API response does not expose password hashes"
    fi

    # Check for TOTP secrets
    HAS_TOTP=$(echo "$BODY" | jq -e '.. | .totp_secret? // empty' 2>/dev/null | head -1) || true

    if [ -n "$HAS_TOTP" ]; then
        fail "User API response exposes TOTP secrets"
        add_finding "CRITICAL" "exposure/user-totp-secret" \
            "GET /api/v1/users returns totp_secret field. An attacker can use this to bypass 2FA." \
            "totp_secret field found in response"
    else
        pass "User API response does not expose TOTP secrets"
    fi
elif [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
    info "Users endpoint requires elevated privileges (${HTTP_CODE})"
else
    info "Users endpoint returned ${HTTP_CODE}"
fi

# -----------------------------------------------------------------------
# Test 3: Scan all API endpoints for common secret patterns
# -----------------------------------------------------------------------
header "Broad Secret Pattern Scan"

SECRET_PATTERN='(password|secret|private.key|api.key|token|credential|aws.access|aws.secret)'

ENDPOINTS=(
    "/api/v1/repositories"
    "/api/v1/admin/config"
    "/api/v1/admin/settings"
)

for endpoint in "${ENDPOINTS[@]}"; do
    RESPONSE=$(curl -s -w "\n%{http_code}" \
        -H "Authorization: Bearer ${TOKEN}" \
        "${REGISTRY_URL}${endpoint}" 2>/dev/null) || true

    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    BODY=$(echo "$RESPONSE" | sed '$d')

    if [ "$HTTP_CODE" = "200" ] && [ ${#BODY} -gt 2 ]; then
        MATCHES=$(echo "$BODY" | grep -oiE "\"${SECRET_PATTERN}\"[[:space:]]*:" | head -5) || true
        if [ -n "$MATCHES" ]; then
            warn "Endpoint ${endpoint} may expose secrets: ${MATCHES}"
            add_finding "MEDIUM" "exposure/endpoint-secrets" \
                "Endpoint ${endpoint} response contains fields matching secret patterns: ${MATCHES}" \
                "Endpoint: ${endpoint}, Fields: ${MATCHES}"
        fi
    fi
done

pass "Broad secret pattern scan complete"

exit 0
