#!/bin/bash
# Red Team Test 12: Information Disclosure
# Checks for unintended information leakage through metrics endpoints,
# error responses, HTTP headers, and health check endpoints.

source "$(dirname "$0")/../lib.sh"

set -uo pipefail

header "Information Disclosure Testing"

# -----------------------------------------------------------------------
# Test 1: Prometheus metrics exposure
# -----------------------------------------------------------------------
header "Prometheus metrics endpoint"

RESPONSE=$(curl -s -w "\n%{http_code}" \
    "${REGISTRY_URL}/metrics" 2>/dev/null) || true

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "200" ]; then
    warn "Metrics endpoint /metrics is accessible without authentication"
    add_finding "MEDIUM" "info-disclosure/metrics-unauthenticated" \
        "Prometheus metrics endpoint /metrics is exposed without authentication. This may reveal internal application details, performance data, and operational information." \
        "GET /metrics returned 200 with $(echo "$BODY" | wc -l | tr -d ' ') lines of metrics data"

    # Check for sensitive information in metrics labels
    SENSITIVE_PATTERNS="password|secret|token|api_key|database_url|connection_string|dsn|credential"
    if echo "$BODY" | grep -qiE "$SENSITIVE_PATTERNS"; then
        fail "Metrics contain potentially sensitive labels or values"
        SENSITIVE_LINES=$(echo "$BODY" | grep -iE "$SENSITIVE_PATTERNS" | head -5)
        add_finding "HIGH" "info-disclosure/metrics-sensitive-data" \
            "Prometheus metrics contain labels or values matching sensitive patterns (password, secret, token, etc.)" \
            "$SENSITIVE_LINES"
    else
        pass "No obviously sensitive labels found in metrics data"
    fi

    # Check for database connection info
    if echo "$BODY" | grep -qiE "db_host|db_port|db_name|pg_|postgres"; then
        warn "Metrics may expose database connection details"
        add_finding "MEDIUM" "info-disclosure/metrics-db-info" \
            "Prometheus metrics contain database-related labels that may reveal infrastructure details" \
            "$(echo "$BODY" | grep -iE 'db_host|db_port|db_name|pg_|postgres' | head -5)"
    fi
elif [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
    pass "Metrics endpoint requires authentication (${HTTP_CODE})"
elif [ "$HTTP_CODE" = "404" ]; then
    pass "Metrics endpoint not found (404) - not exposed"
else
    info "Metrics endpoint returned status ${HTTP_CODE}"
fi

# -----------------------------------------------------------------------
# Test 2: Error response detail level (nonexistent path)
# -----------------------------------------------------------------------
header "Error response information leakage"

RESPONSE=$(curl -s -w "\n%{http_code}" \
    "${REGISTRY_URL}/nonexistent-path-$(date +%s)" 2>/dev/null) || true

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

info "GET /nonexistent-path returned ${HTTP_CODE}"

# Check for stack traces in error responses
STACK_TRACE_PATTERNS="(at .*\.(rs|go|py|java|js):[0-9]|Traceback|panic:|goroutine [0-9]|thread '.*' panicked|stack backtrace|RUST_BACKTRACE|Exception in thread)"
if echo "$BODY" | grep -qiE "$STACK_TRACE_PATTERNS"; then
    fail "Error response contains stack trace or internal path information"
    add_finding "MEDIUM" "info-disclosure/stack-trace-in-error" \
        "Error response for a nonexistent path includes stack trace or internal path information, revealing implementation details." \
        "$BODY"
else
    pass "Error response does not contain stack traces"
fi

# Check for internal file paths
if echo "$BODY" | grep -qiE "(\/home\/|\/usr\/|\/app\/|\/src\/|\/var\/|\.rs:|\.go:)"; then
    warn "Error response may contain internal file paths"
    add_finding "LOW" "info-disclosure/internal-paths" \
        "Error response may contain internal file system paths" \
        "$BODY"
else
    pass "Error response does not reveal internal file paths"
fi

# -----------------------------------------------------------------------
# Test 3: Malformed JSON login error detail
# -----------------------------------------------------------------------
header "Malformed request error detail"

RESPONSE=$(curl -s -w "\n%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d '{invalid json here' \
    "${REGISTRY_URL}/api/v1/auth/login" 2>/dev/null) || true

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

info "POST /api/v1/auth/login with malformed JSON returned ${HTTP_CODE}"

# Check if error message is overly detailed
if echo "$BODY" | grep -qiE "(serde|deserialize|parse error at line|column [0-9]|expected .*at position|JsonPayloadError|JsonRejection)"; then
    warn "Malformed JSON error reveals parser implementation details"
    add_finding "LOW" "info-disclosure/json-parser-detail" \
        "Error response for malformed JSON reveals internal parser details (e.g., serde, parse position). Consider returning a generic 'Invalid JSON' message." \
        "$BODY"
else
    pass "Malformed JSON error does not reveal excessive implementation details"
fi

# -----------------------------------------------------------------------
# Test 4: Server header version disclosure
# -----------------------------------------------------------------------
header "Server header analysis"

HEADERS=$(curl -sI "${REGISTRY_URL}/health" 2>/dev/null) || true

if echo "$HEADERS" | grep -qi "^Server:"; then
    SERVER_VALUE=$(echo "$HEADERS" | grep -i "^Server:" | head -1 | sed 's/^[^:]*: *//' | tr -d '\r')
    # Check if server header includes version numbers
    if echo "$SERVER_VALUE" | grep -qE "[0-9]+\.[0-9]+"; then
        warn "Server header discloses version: ${SERVER_VALUE}"
        add_finding "LOW" "info-disclosure/server-version" \
            "Server header reveals version information: ${SERVER_VALUE}. Version disclosure helps attackers identify known vulnerabilities for specific software versions." \
            "Server: ${SERVER_VALUE}"
    else
        info "Server header present but no version disclosed: ${SERVER_VALUE}"
    fi
else
    pass "No Server header found - no version disclosure"
fi

# -----------------------------------------------------------------------
# Test 5: Health and readiness endpoint information
# -----------------------------------------------------------------------
header "Health endpoint information leakage"

for endpoint in "/health" "/ready" "/healthz" "/readyz"; do
    RESPONSE=$(curl -s -w "\n%{http_code}" \
        "${REGISTRY_URL}${endpoint}" 2>/dev/null) || true

    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    BODY=$(echo "$RESPONSE" | sed '$d')

    if [ "$HTTP_CODE" = "200" ]; then
        info "Endpoint ${endpoint} is accessible (200)"

        # Check if health response contains excessive information
        # Simple "ok" or {"status":"healthy"} is fine; detailed info is not
        BODY_LENGTH=${#BODY}

        if [ "$BODY_LENGTH" -gt 500 ]; then
            warn "Endpoint ${endpoint} returns extensive data (${BODY_LENGTH} bytes)"
            add_finding "LOW" "info-disclosure/verbose-health" \
                "Health endpoint ${endpoint} returns extensive information (${BODY_LENGTH} bytes). Consider limiting health endpoint responses to minimal status indicators." \
                "$(echo "$BODY" | head -c 500)..."
        fi

        # Check for database connection details, hostnames, versions
        if echo "$BODY" | grep -qiE "(host|version|database|postgres|uptime|build|commit|sha|port)"; then
            DETAIL_LINES=$(echo "$BODY" | grep -oiE '"[^"]*":\s*"[^"]*"' | grep -iE "(host|version|database|postgres|uptime|build|commit|sha|port)" | head -5)
            if [ -n "$DETAIL_LINES" ]; then
                warn "Endpoint ${endpoint} reveals infrastructure details"
                add_finding "LOW" "info-disclosure/health-infra-details" \
                    "Health endpoint ${endpoint} reveals infrastructure information such as database hosts, versions, or build details." \
                    "$DETAIL_LINES"
            fi
        fi
    elif [ "$HTTP_CODE" = "404" ]; then
        info "Endpoint ${endpoint} not found (404)"
    else
        info "Endpoint ${endpoint} returned ${HTTP_CODE}"
    fi
done

exit 0
