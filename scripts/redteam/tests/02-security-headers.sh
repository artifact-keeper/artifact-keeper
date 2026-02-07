#!/bin/bash
# Red Team Test 02: Missing Security Headers
# Checks HTTP response headers for required security headers.

source "$(dirname "$0")/../lib.sh"

set -uo pipefail

header "Security Headers Analysis"

info "Fetching response headers from /health"

HEADERS=$(api_call_headers GET /health) || true

if [ -z "$HEADERS" ]; then
    fail "Could not retrieve response headers from /health"
    add_finding "HIGH" "headers/unreachable" \
        "Unable to retrieve HTTP headers from ${REGISTRY_URL}/health" \
        "curl returned empty response"
    exit 0
fi

info "Response headers received:"
echo "$HEADERS" | while IFS= read -r line; do
    info "  $line"
done

# Helper: check if a header is present in the response
check_header() {
    local header_name="$1"
    local severity="$2"
    local description="$3"

    # Case-insensitive grep for the header name
    if echo "$HEADERS" | grep -qi "^${header_name}:"; then
        local header_value
        header_value=$(echo "$HEADERS" | grep -i "^${header_name}:" | head -1 | sed 's/^[^:]*: *//' | tr -d '\r')
        pass "${header_name} is present (value: ${header_value})"
    else
        fail "${header_name} header is missing"
        add_finding "$severity" "headers/missing-${header_name}" \
            "$description" \
            "Header '${header_name}' was not found in the response from GET /health. Response headers: $(echo "$HEADERS" | tr '\r\n' ' ')"
    fi
}

# Check X-Frame-Options
check_header "X-Frame-Options" "MEDIUM" \
    "Missing X-Frame-Options header. The application may be vulnerable to clickjacking attacks. Recommended value: DENY or SAMEORIGIN."

# Check X-Content-Type-Options
check_header "X-Content-Type-Options" "LOW" \
    "Missing X-Content-Type-Options header. Browsers may perform MIME-type sniffing, potentially leading to XSS. Recommended value: nosniff."

# Check Content-Security-Policy
check_header "Content-Security-Policy" "MEDIUM" \
    "Missing Content-Security-Policy header. The application does not define a CSP, increasing the risk of XSS and data injection attacks."

# Check Strict-Transport-Security
check_header "Strict-Transport-Security" "MEDIUM" \
    "Missing Strict-Transport-Security (HSTS) header. Without HSTS, the application may be vulnerable to protocol downgrade attacks and cookie hijacking. Recommended: max-age=31536000; includeSubDomains."

# Bonus: check for information disclosure headers
info "Checking for information disclosure in headers..."

if echo "$HEADERS" | grep -qi "^Server:"; then
    SERVER_VALUE=$(echo "$HEADERS" | grep -i "^Server:" | head -1 | sed 's/^[^:]*: *//' | tr -d '\r')
    warn "Server header reveals technology: ${SERVER_VALUE}"
    add_finding "LOW" "headers/server-disclosure" \
        "Server header discloses backend technology: ${SERVER_VALUE}. Consider removing or generalizing this header to reduce information leakage." \
        "Server: ${SERVER_VALUE}"
else
    pass "Server header is not present (no technology disclosure)"
fi

if echo "$HEADERS" | grep -qi "^X-Powered-By:"; then
    POWERED_VALUE=$(echo "$HEADERS" | grep -i "^X-Powered-By:" | head -1 | sed 's/^[^:]*: *//' | tr -d '\r')
    warn "X-Powered-By header reveals technology: ${POWERED_VALUE}"
    add_finding "LOW" "headers/x-powered-by-disclosure" \
        "X-Powered-By header discloses backend technology: ${POWERED_VALUE}. This header should be removed." \
        "X-Powered-By: ${POWERED_VALUE}"
else
    pass "X-Powered-By header is not present (no technology disclosure)"
fi

exit 0
