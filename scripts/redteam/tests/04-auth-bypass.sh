#!/bin/bash
# Red Team Test 04: Authentication Bypass
# Tests whether protected endpoints can be accessed without valid credentials.

source "$(dirname "$0")/../lib.sh"

set -uo pipefail

header "Authentication Bypass Testing"

# Helper: test that an endpoint requires authentication
# Usage: test_requires_auth METHOD PATH DESCRIPTION
test_requires_auth() {
    local method="$1"
    local path="$2"
    local description="$3"
    local data="${4:-}"

    local status
    if [ -n "$data" ]; then
        status=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" \
            -H "Content-Type: application/json" \
            -d "$data" \
            "${REGISTRY_URL}${path}" 2>&1) || true
    else
        status=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" \
            "${REGISTRY_URL}${path}" 2>&1) || true
    fi

    if [ "$status" = "401" ] || [ "$status" = "403" ]; then
        pass "${description} - correctly returned ${status}"
    elif [ "$status" = "000" ]; then
        warn "${description} - connection failed (status 000)"
    else
        fail "${description} - returned ${status} instead of 401/403"
        add_finding "HIGH" "auth-bypass/${method}-$(echo "$path" | tr '/' '-')" \
            "Authentication bypass: ${method} ${path} returned HTTP ${status} without credentials. Expected 401 or 403. ${description}." \
            "Request: ${method} ${path} (no auth). Response status: ${status}"
    fi
}

# ============================================================
# Section 1: Protected endpoints (must require authentication)
# ============================================================
info "Testing protected endpoints without authentication..."

# Create repository (should require auth)
test_requires_auth POST "/api/v1/repositories" \
    "Create repository without auth" \
    '{"name":"redteam-test-repo","type":"generic"}'

# List users (should require auth)
test_requires_auth GET "/api/v1/users" \
    "List users without auth"

# Delete repository (should require auth)
test_requires_auth DELETE "/api/v1/repositories/test-pypi" \
    "Delete repository without auth"

# ============================================================
# Section 2: Optional-auth endpoints (check for data leakage)
# ============================================================
header "Optional-Auth Endpoint Data Leakage"
info "Testing optional-auth endpoints for sensitive data exposure..."

# List repositories without auth
REPOS_RESPONSE=$(api_call_noauth GET "/api/v1/repositories") || true
REPOS_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X GET "${REGISTRY_URL}/api/v1/repositories" 2>&1) || true

if [ "$REPOS_STATUS" = "401" ] || [ "$REPOS_STATUS" = "403" ]; then
    pass "Repository listing requires authentication (status ${REPOS_STATUS})"
elif [ "$REPOS_STATUS" = "200" ]; then
    info "Repository listing is accessible without auth (status 200) - checking for sensitive data..."

    # Check if internal/sensitive fields are exposed
    HAS_CREDENTIALS=$(echo "$REPOS_RESPONSE" | jq -r '.. | .credentials? // .password? // .secret? // .token? // empty' 2>/dev/null | head -1) || true
    HAS_INTERNAL_PATHS=$(echo "$REPOS_RESPONSE" | jq -r '.. | .storage_path? // .internal_url? // empty' 2>/dev/null | head -1) || true

    if [ -n "$HAS_CREDENTIALS" ]; then
        fail "Repository listing exposes credential fields to unauthenticated users"
        add_finding "HIGH" "auth-bypass/repo-credential-leak" \
            "The GET /api/v1/repositories endpoint returns credential or secret fields to unauthenticated users. This may expose sensitive configuration." \
            "Credential-like fields found in unauthenticated response: ${HAS_CREDENTIALS}"
    else
        pass "No credential fields found in unauthenticated repository listing"
    fi

    if [ -n "$HAS_INTERNAL_PATHS" ]; then
        warn "Repository listing exposes internal paths to unauthenticated users"
        add_finding "MEDIUM" "auth-bypass/repo-path-leak" \
            "The GET /api/v1/repositories endpoint returns internal storage paths to unauthenticated users. This information could aid further attacks." \
            "Internal path fields found: ${HAS_INTERNAL_PATHS}"
    else
        pass "No internal path fields found in unauthenticated repository listing"
    fi
else
    warn "Repository listing returned unexpected status: ${REPOS_STATUS}"
fi

# ============================================================
# Section 3: Artifact upload without auth
# ============================================================
header "Unauthenticated Artifact Upload"
info "Testing artifact upload to format-specific endpoints without auth..."

# PyPI upload attempt
PYPI_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -F "content=@/dev/null;filename=redteam-pkg-0.1.0.tar.gz" \
    -F "name=redteam-pkg" \
    -F "version=0.1.0" \
    "${REGISTRY_URL}/api/v1/pypi/test-pypi/" 2>&1) || true

if [ "$PYPI_STATUS" = "401" ] || [ "$PYPI_STATUS" = "403" ]; then
    pass "PyPI upload requires authentication (status ${PYPI_STATUS})"
elif [ "$PYPI_STATUS" = "000" ]; then
    warn "PyPI upload endpoint - connection failed"
else
    fail "PyPI upload accepted without auth (status ${PYPI_STATUS})"
    add_finding "HIGH" "auth-bypass/pypi-upload-noauth" \
        "PyPI artifact upload (POST /api/v1/pypi/test-pypi/) returned HTTP ${PYPI_STATUS} without authentication. Expected 401 or 403. Unauthenticated users may be able to publish malicious packages." \
        "POST /api/v1/pypi/test-pypi/ with dummy package. Status: ${PYPI_STATUS}"
fi

# NPM upload attempt
NPM_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    -H "Content-Type: application/json" \
    -d '{"name":"@redteam/test-pkg","versions":{"0.1.0":{"name":"@redteam/test-pkg","version":"0.1.0"}}}' \
    "${REGISTRY_URL}/api/v1/npm/test-npm/@redteam/test-pkg" 2>&1) || true

if [ "$NPM_STATUS" = "401" ] || [ "$NPM_STATUS" = "403" ]; then
    pass "NPM upload requires authentication (status ${NPM_STATUS})"
elif [ "$NPM_STATUS" = "000" ]; then
    warn "NPM upload endpoint - connection failed"
else
    fail "NPM upload accepted without auth (status ${NPM_STATUS})"
    add_finding "HIGH" "auth-bypass/npm-upload-noauth" \
        "NPM artifact upload (PUT /api/v1/npm/test-npm/@redteam/test-pkg) returned HTTP ${NPM_STATUS} without authentication. Expected 401 or 403. Unauthenticated users may be able to publish malicious packages." \
        "PUT /api/v1/npm/test-npm/@redteam/test-pkg with dummy payload. Status: ${NPM_STATUS}"
fi

# Generic PUT upload attempt
GENERIC_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    -H "Content-Type: application/octet-stream" \
    -d "redteam-test-data" \
    "${REGISTRY_URL}/api/v1/generic/test-generic/redteam-test/1.0.0/payload.bin" 2>&1) || true

if [ "$GENERIC_STATUS" = "401" ] || [ "$GENERIC_STATUS" = "403" ]; then
    pass "Generic upload requires authentication (status ${GENERIC_STATUS})"
elif [ "$GENERIC_STATUS" = "000" ]; then
    warn "Generic upload endpoint - connection failed"
else
    fail "Generic upload accepted without auth (status ${GENERIC_STATUS})"
    add_finding "HIGH" "auth-bypass/generic-upload-noauth" \
        "Generic artifact upload (PUT /api/v1/generic/test-generic/redteam-test/1.0.0/payload.bin) returned HTTP ${GENERIC_STATUS} without authentication. Expected 401 or 403. Unauthenticated users may be able to upload arbitrary files." \
        "PUT /api/v1/generic/.../payload.bin with test data. Status: ${GENERIC_STATUS}"
fi

exit 0
