#!/bin/bash
# Red Team Test 05: Default Credentials
# Tests whether default/well-known credentials are still active in production.
# Checks admin login, peer API key, Meilisearch, and PostgreSQL.

source "$(dirname "$0")/../lib.sh"

set -uo pipefail

header "Default Credentials Testing"

# --- Test 1: Admin login with default credentials ---
# Credentials sourced from env vars ADMIN_USER / ADMIN_PASS (see lib.sh)
info "Attempting admin login with default credentials (${ADMIN_USER}:***)"

LOGIN_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" \
    "${REGISTRY_URL}/api/v1/auth/login" 2>&1) || true

LOGIN_BODY=$(echo "$LOGIN_RESPONSE" | head -n -1)
LOGIN_STATUS=$(echo "$LOGIN_RESPONSE" | tail -n 1)

if [ "$LOGIN_STATUS" = "200" ]; then
    fail "Default admin credentials accepted (${ADMIN_USER}:***) - HTTP 200"
    add_finding "CRITICAL" "default-creds/admin-login" \
        "Default admin credentials are active. An attacker can gain full administrative access to the registry. Change the admin password immediately." \
        "POST /api/v1/auth/login with default credentials returned HTTP 200. Response body (truncated): $(echo "$LOGIN_BODY" | head -c 500)"
elif [ "$LOGIN_STATUS" = "401" ] || [ "$LOGIN_STATUS" = "403" ]; then
    pass "Default admin credentials rejected (HTTP ${LOGIN_STATUS})"
else
    warn "Unexpected response for admin login: HTTP ${LOGIN_STATUS}"
    info "Response: $(echo "$LOGIN_BODY" | head -c 300)"
fi

# --- Test 2: Try other common default credential pairs ---
info "Trying additional common credential pairs..."

CRED_PAIRS="admin:admin admin:password admin:changeme root:root root:admin"

for pair in $CRED_PAIRS; do
    username="${pair%%:*}"
    password="${pair#*:}"

    RESP=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${username}\",\"password\":\"${password}\"}" \
        "${REGISTRY_URL}/api/v1/auth/login" 2>&1) || true

    if [ "$RESP" = "200" ]; then
        fail "Default credentials accepted: ${username}:${password}"
        add_finding "CRITICAL" "default-creds/common-pair-${username}" \
            "Common default credentials (${username}:${password}) are active. Change the password immediately." \
            "POST /api/v1/auth/login with username=${username} returned HTTP 200"
    else
        pass "Credentials rejected: ${username}:${password} (HTTP ${RESP})"
    fi
done

# --- Test 3: Peer API key with default value ---
info "Testing default peer API key (change-me-in-production)"

PEER_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    -H "X-API-Key: change-me-in-production" \
    -d '{"name":"redteam-probe","endpoint_url":"http://attacker.example.com:8080"}' \
    "${REGISTRY_URL}/api/v1/peers/announce" 2>&1) || true

PEER_BODY=$(echo "$PEER_RESPONSE" | head -n -1)
PEER_STATUS=$(echo "$PEER_RESPONSE" | tail -n 1)

if [ "$PEER_STATUS" = "200" ] || [ "$PEER_STATUS" = "201" ]; then
    fail "Default peer API key accepted (change-me-in-production) - HTTP ${PEER_STATUS}"
    add_finding "CRITICAL" "default-creds/peer-api-key" \
        "Default peer API key (change-me-in-production) is active. An attacker could register a malicious peer node and intercept or inject artifacts into the mesh network." \
        "POST /api/v1/peers/announce with X-API-Key: change-me-in-production returned HTTP ${PEER_STATUS}. Body: $(echo "$PEER_BODY" | head -c 500)"
elif [ "$PEER_STATUS" = "401" ] || [ "$PEER_STATUS" = "403" ]; then
    pass "Default peer API key rejected (HTTP ${PEER_STATUS})"
elif [ "$PEER_STATUS" = "404" ]; then
    info "Peer announce endpoint not found (HTTP 404) - peer mesh may not be enabled"
else
    warn "Unexpected peer announce response: HTTP ${PEER_STATUS}"
    info "Response: $(echo "$PEER_BODY" | head -c 300)"
fi

# --- Test 4: Meilisearch with default dev API key ---
MEILI_URL="${MEILI_URL:-http://meilisearch:7700}"
info "Testing Meilisearch at ${MEILI_URL} with default dev key (artifact-keeper-dev-key)"

MEILI_RESPONSE=$(curl -s -w "\n%{http_code}" --connect-timeout 5 \
    -H "Authorization: Bearer artifact-keeper-dev-key" \
    "${MEILI_URL}/indexes" 2>&1) || true

MEILI_BODY=$(echo "$MEILI_RESPONSE" | head -n -1)
MEILI_STATUS=$(echo "$MEILI_RESPONSE" | tail -n 1)

if [ "$MEILI_STATUS" = "000" ] || [ -z "$MEILI_STATUS" ]; then
    info "Meilisearch not reachable at ${MEILI_URL} (connection refused or timed out)"
elif [ "$MEILI_STATUS" = "200" ]; then
    fail "Meilisearch accessible with default dev API key"
    add_finding "MEDIUM" "default-creds/meilisearch-dev-key" \
        "Meilisearch is accessible with the default development API key (artifact-keeper-dev-key). An attacker could read or modify search indexes, potentially extracting metadata about all artifacts and repositories." \
        "GET ${MEILI_URL}/indexes with Bearer artifact-keeper-dev-key returned HTTP 200. Indexes: $(echo "$MEILI_BODY" | head -c 500)"
elif [ "$MEILI_STATUS" = "401" ] || [ "$MEILI_STATUS" = "403" ]; then
    pass "Meilisearch rejected default dev key (HTTP ${MEILI_STATUS})"
else
    warn "Unexpected Meilisearch response: HTTP ${MEILI_STATUS}"
fi

# Also check if Meilisearch is accessible without any key
MEILI_NOKEY=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 \
    "${MEILI_URL}/health" 2>&1) || true

if [ "$MEILI_NOKEY" = "200" ]; then
    warn "Meilisearch health endpoint is publicly accessible (no auth required)"
    info "This is expected for /health but verify other endpoints require auth"
fi

# --- Test 5: PostgreSQL direct access with default credentials ---
DB_HOST="${DB_HOST:-postgres}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-registry}"
DB_PASS="${DB_PASS:-registry}"
DB_NAME="${DB_NAME:-artifact_registry}"

info "Testing PostgreSQL direct access at ${DB_HOST}:${DB_PORT} with default credentials"

if command -v psql &>/dev/null; then
    PG_RESULT=$(PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" \
        -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1;" 2>&1 && echo "CONNECTED") || true

    if echo "$PG_RESULT" | grep -q "CONNECTED"; then
        fail "PostgreSQL accessible with default credentials (${DB_USER}:${DB_PASS})"
        add_finding "HIGH" "default-creds/postgres-direct" \
            "PostgreSQL database is directly accessible from the test container with default credentials (${DB_USER}:${DB_PASS}). In production, the database should not be reachable from untrusted networks and must use strong credentials." \
            "Connected to ${DB_HOST}:${DB_PORT} as ${DB_USER} to database ${DB_NAME} successfully."

        # Try to enumerate sensitive data
        TABLE_COUNT=$(PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" \
            -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';" 2>&1) || true
        TABLE_COUNT=$(echo "$TABLE_COUNT" | tr -d '[:space:]')

        if [ -n "$TABLE_COUNT" ] && [ "$TABLE_COUNT" -gt 0 ] 2>/dev/null; then
            warn "Database contains ${TABLE_COUNT} public tables (data exposure risk)"
        fi
    else
        pass "PostgreSQL not reachable or credentials rejected"
    fi
else
    # Fallback: try with pg_isready or raw TCP check
    if command -v pg_isready &>/dev/null; then
        PG_READY=$(pg_isready -h "$DB_HOST" -p "$DB_PORT" 2>&1) || true
        if echo "$PG_READY" | grep -q "accepting connections"; then
            warn "PostgreSQL is accepting connections at ${DB_HOST}:${DB_PORT} (psql not available to test auth)"
            add_finding "MEDIUM" "default-creds/postgres-reachable" \
                "PostgreSQL at ${DB_HOST}:${DB_PORT} is accepting connections from the test container. Could not fully test auth (psql not installed). Ensure database is not exposed to untrusted networks." \
                "$PG_READY"
        else
            pass "PostgreSQL not reachable at ${DB_HOST}:${DB_PORT}"
        fi
    else
        info "Neither psql nor pg_isready available; skipping PostgreSQL direct access test"
    fi
fi

exit 0
