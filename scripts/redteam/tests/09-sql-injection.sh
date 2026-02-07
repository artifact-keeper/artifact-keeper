#!/bin/bash
# Red Team Test 09: SQL Injection
# Tests query parameters for SQL injection vulnerabilities using
# a set of common payloads and optional sqlmap validation.

source "$(dirname "$0")/../lib.sh"

set -uo pipefail

header "SQL Injection Testing"

# Locate the payloads file relative to this script
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PAYLOADS_FILE="${SCRIPT_DIR}/../payloads/sqli-basic.txt"

if [ ! -f "$PAYLOADS_FILE" ]; then
    fail "Payload file not found: ${PAYLOADS_FILE}"
    exit 0
fi

PAYLOAD_COUNT=$(wc -l < "$PAYLOADS_FILE" | tr -d ' ')
info "Loaded ${PAYLOAD_COUNT} SQL injection payloads from sqli-basic.txt"

# SQL error patterns that indicate a successful injection or unhandled error
SQL_ERROR_PATTERNS="(SQL syntax|mysql_fetch|ORA-[0-9]|pg_query|sqlite3\.|SQLSTATE|Unclosed quotation|syntax error at or near|unterminated|Microsoft OLE DB|ODBC SQL Server|PostgreSQL.*ERROR|column .* does not exist)"

# -----------------------------------------------------------------------
# Test 1: Injection in /api/v1/search?q=
# -----------------------------------------------------------------------
header "Testing /api/v1/search?q= with SQLi payloads"

SQLI_FOUND=false

while IFS= read -r payload || [ -n "$payload" ]; do
    [ -z "$payload" ] && continue

    # URL-encode the payload for safe transport
    ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''${payload}'''))" 2>/dev/null || echo "$payload")

    RESPONSE=$(curl -s -w "\n%{http_code}" \
        -u "${ADMIN_USER}:${ADMIN_PASS}" \
        "${REGISTRY_URL}/api/v1/search?q=${ENCODED}") || true

    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    BODY=$(echo "$RESPONSE" | sed '$d')

    # Check for SQL error messages in the response body
    if echo "$BODY" | grep -qiE "$SQL_ERROR_PATTERNS"; then
        fail "SQL error leaked in /api/v1/search response for payload: ${payload}"
        SQLI_FOUND=true
        add_finding "HIGH" "sqli/search-error-leak" \
            "SQL error message found in /api/v1/search response when injecting: ${payload}" \
            "$BODY"
    fi

    # A 500 status with a SQL-related payload is suspicious
    if [ "$HTTP_CODE" = "500" ]; then
        warn "Server returned 500 for /api/v1/search with payload: ${payload}"
    fi
done < "$PAYLOADS_FILE"

if [ "$SQLI_FOUND" = false ]; then
    pass "No SQL error leakage detected in /api/v1/search"
fi

# -----------------------------------------------------------------------
# Test 2: Injection in /api/v1/repositories?search=
# -----------------------------------------------------------------------
header "Testing /api/v1/repositories?search= with SQLi payloads"

SQLI_FOUND=false

while IFS= read -r payload || [ -n "$payload" ]; do
    [ -z "$payload" ] && continue

    ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''${payload}'''))" 2>/dev/null || echo "$payload")

    RESPONSE=$(curl -s -w "\n%{http_code}" \
        -u "${ADMIN_USER}:${ADMIN_PASS}" \
        "${REGISTRY_URL}/api/v1/repositories?search=${ENCODED}") || true

    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    BODY=$(echo "$RESPONSE" | sed '$d')

    if echo "$BODY" | grep -qiE "$SQL_ERROR_PATTERNS"; then
        fail "SQL error leaked in /api/v1/repositories response for payload: ${payload}"
        SQLI_FOUND=true
        add_finding "HIGH" "sqli/repositories-error-leak" \
            "SQL error message found in /api/v1/repositories response when injecting: ${payload}" \
            "$BODY"
    fi

    if [ "$HTTP_CODE" = "500" ]; then
        warn "Server returned 500 for /api/v1/repositories with payload: ${payload}"
    fi
done < "$PAYLOADS_FILE"

if [ "$SQLI_FOUND" = false ]; then
    pass "No SQL error leakage detected in /api/v1/repositories"
fi

# -----------------------------------------------------------------------
# Test 3: sqlmap automated scan (quick, non-destructive)
# -----------------------------------------------------------------------
header "Running sqlmap quick scan"

if command -v sqlmap &>/dev/null; then
    info "sqlmap found, running batch scan against /api/v1/search?q=test"

    SQLMAP_OUTPUT=$(sqlmap -u "${REGISTRY_URL}/api/v1/search?q=test" \
        --batch --level=1 --risk=1 --time-sec=5 \
        --auth-type=Basic --auth-cred="${ADMIN_USER}:${ADMIN_PASS}" 2>&1) || true

    # Check if sqlmap found any injectable parameters
    if echo "$SQLMAP_OUTPUT" | grep -qi "is vulnerable\|injectable\|Parameter.*is.*dynamic"; then
        fail "sqlmap detected potential SQL injection vulnerability"
        add_finding "HIGH" "sqli/sqlmap-injectable" \
            "sqlmap detected injectable parameter in /api/v1/search" \
            "$SQLMAP_OUTPUT"
    else
        pass "sqlmap did not detect injectable parameters"
    fi

    # Report any errors or warnings from sqlmap
    if echo "$SQLMAP_OUTPUT" | grep -qi "connection timed out\|connection refused"; then
        warn "sqlmap had connectivity issues - results may be incomplete"
    fi
else
    info "sqlmap not installed - skipping automated scan"
fi

exit 0
