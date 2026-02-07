#!/bin/bash
# Red Team Test 08: Path Traversal
# Tests whether path traversal payloads can escape the repository root
# and access arbitrary files on the server filesystem.

source "$(dirname "$0")/../lib.sh"

set -uo pipefail

header "Path Traversal Testing"

PAYLOADS_FILE="$(dirname "$0")/../payloads/traversal-paths.txt"

if [ ! -f "$PAYLOADS_FILE" ]; then
    warn "Payloads file not found at ${PAYLOADS_FILE}; skipping path traversal tests"
    exit 0
fi

PAYLOAD_COUNT=$(wc -l < "$PAYLOADS_FILE" | tr -d '[:space:]')
info "Loaded ${PAYLOAD_COUNT} traversal payloads from ${PAYLOADS_FILE}"

# Track findings
TRAVERSAL_FOUND=false
TESTED_COUNT=0
SUSPICIOUS_COUNT=0

# Endpoints to test (format: "METHOD|URL_TEMPLATE")
# {payload} will be replaced with each traversal string
ENDPOINTS=(
    "GET|/pypi/test-pypi/simple/{payload}"
    "GET|/npm/test-npm/{payload}"
    "GET|/api/v1/repositories/test-pypi/download/{payload}"
)

# Helper: test a single URL for path traversal
test_traversal() {
    local method="$1"
    local url="$2"
    local payload_desc="$3"

    local response
    response=$(curl -s -w "\n%{http_code}" -X "$method" "${REGISTRY_URL}${url}" 2>&1) || true

    local body
    body=$(echo "$response" | head -n -1)
    local status
    status=$(echo "$response" | tail -n 1)

    TESTED_COUNT=$((TESTED_COUNT + 1))

    # A 200 with non-JSON content or known file signatures is suspicious
    if [ "$status" = "200" ]; then
        # Check for known file content patterns (Linux passwd, shadow, etc.)
        if echo "$body" | grep -qE "root:.*:0:0:|daemon:.*:/usr/sbin|nobody:.*:/nonexistent"; then
            TRAVERSAL_FOUND=true
            SUSPICIOUS_COUNT=$((SUSPICIOUS_COUNT + 1))
            fail "PATH TRAVERSAL: ${url} returned /etc/passwd content"
            add_finding "CRITICAL" "path-traversal/file-read" \
                "Path traversal successful: ${method} ${url} returned contents of /etc/passwd. An attacker can read arbitrary files from the server filesystem." \
                "Payload: ${payload_desc}. URL: ${url}. Response (truncated): $(echo "$body" | head -c 500)"
            return
        fi

        # Check for Cargo.toml / Rust source code
        if echo "$body" | grep -qE "\[package\]|\[dependencies\]|fn main|use std::"; then
            TRAVERSAL_FOUND=true
            SUSPICIOUS_COUNT=$((SUSPICIOUS_COUNT + 1))
            fail "PATH TRAVERSAL: ${url} returned application source code"
            add_finding "CRITICAL" "path-traversal/source-read" \
                "Path traversal successful: ${method} ${url} returned application source code. An attacker can read the application codebase." \
                "Payload: ${payload_desc}. URL: ${url}. Response (truncated): $(echo "$body" | head -c 500)"
            return
        fi

        # Check for environment variables (proc/self/environ)
        if echo "$body" | grep -qE "PATH=|HOME=|DATABASE_URL=|JWT_SECRET="; then
            TRAVERSAL_FOUND=true
            SUSPICIOUS_COUNT=$((SUSPICIOUS_COUNT + 1))
            fail "PATH TRAVERSAL: ${url} returned environment variables"
            add_finding "CRITICAL" "path-traversal/env-leak" \
                "Path traversal successful: ${method} ${url} returned process environment variables containing secrets." \
                "Payload: ${payload_desc}. URL: ${url}. Response (truncated): $(echo "$body" | head -c 500)"
            return
        fi

        # Check if response is NOT JSON (unexpected 200 with non-JSON could be file content)
        local content_type
        content_type=$(curl -sI -X "$method" "${REGISTRY_URL}${url}" 2>&1 \
            | grep -i "^Content-Type:" | head -1 | sed 's/^[^:]*: *//' | tr -d '\r') || true

        if [ -n "$body" ] && ! echo "$body" | jq . >/dev/null 2>&1; then
            # Non-JSON 200 response — could be file content
            if [ ${#body} -gt 20 ]; then
                SUSPICIOUS_COUNT=$((SUSPICIOUS_COUNT + 1))
                warn "Suspicious 200 response for ${url} (non-JSON, ${#body} bytes, Content-Type: ${content_type:-unknown})"
                add_finding "MEDIUM" "path-traversal/suspicious-200" \
                    "${method} ${url} returned HTTP 200 with non-JSON content (${#body} bytes). This may indicate partial path traversal or unintended file serving." \
                    "Payload: ${payload_desc}. Content-Type: ${content_type:-unknown}. Body (truncated): $(echo "$body" | head -c 300)"
            fi
        fi
    fi
    # 400, 404, 500 are all acceptable (request rejected or resource not found)
}

# --- Test raw payloads from file ---
info "Testing raw path traversal payloads..."

while IFS= read -r payload || [ -n "$payload" ]; do
    # Skip empty lines and comments
    [ -z "$payload" ] && continue
    [[ "$payload" == \#* ]] && continue

    for endpoint_def in "${ENDPOINTS[@]}"; do
        method="${endpoint_def%%|*}"
        url_template="${endpoint_def#*|}"
        url="${url_template//\{payload\}/$payload}"
        test_traversal "$method" "$url" "$payload"
    done
done < "$PAYLOADS_FILE"

# --- Test URL-encoded variants ---
info "Testing URL-encoded path traversal variants..."

URL_ENCODED_PAYLOADS=(
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd"
    "..%2f..%2f..%2fetc%2fpasswd"
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fproc%2fself%2fenviron"
    "..%252f..%252f..%252fetc%252fpasswd"
    "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
    "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd"
)

for payload in "${URL_ENCODED_PAYLOADS[@]}"; do
    for endpoint_def in "${ENDPOINTS[@]}"; do
        method="${endpoint_def%%|*}"
        url_template="${endpoint_def#*|}"
        url="${url_template//\{payload\}/$payload}"
        # Use --path-as-is to prevent curl from normalizing the URL
        response=$(curl -s --path-as-is -w "\n%{http_code}" -X "$method" "${REGISTRY_URL}${url}" 2>&1) || true

        body=$(echo "$response" | head -n -1)
        status=$(echo "$response" | tail -n 1)
        TESTED_COUNT=$((TESTED_COUNT + 1))

        if [ "$status" = "200" ]; then
            if echo "$body" | grep -qE "root:.*:0:0:|daemon:.*:/usr/sbin|PATH=|HOME=|\[package\]"; then
                TRAVERSAL_FOUND=true
                SUSPICIOUS_COUNT=$((SUSPICIOUS_COUNT + 1))
                fail "PATH TRAVERSAL (URL-encoded): ${url} returned sensitive file content"
                add_finding "CRITICAL" "path-traversal/url-encoded" \
                    "URL-encoded path traversal successful: ${method} ${url} returned sensitive file content." \
                    "Payload: ${payload}. Response (truncated): $(echo "$body" | head -c 500)"
            fi
        fi
    done
done

# --- Test with double-URL-encoding (server may decode twice) ---
info "Testing double-URL-encoded traversal (bypass attempts)..."

DOUBLE_ENCODED=(
    "..%25252f..%25252f..%25252fetc%25252fpasswd"
    "%252e%252e%252f%252e%252e%252fetc%252fpasswd"
)

for payload in "${DOUBLE_ENCODED[@]}"; do
    for endpoint_def in "${ENDPOINTS[@]}"; do
        method="${endpoint_def%%|*}"
        url_template="${endpoint_def#*|}"
        url="${url_template//\{payload\}/$payload}"

        response=$(curl -s --path-as-is -w "\n%{http_code}" -X "$method" "${REGISTRY_URL}${url}" 2>&1) || true
        body=$(echo "$response" | head -n -1)
        status=$(echo "$response" | tail -n 1)
        TESTED_COUNT=$((TESTED_COUNT + 1))

        if [ "$status" = "200" ]; then
            if echo "$body" | grep -qE "root:.*:0:0:|PATH=|HOME=|\[package\]"; then
                TRAVERSAL_FOUND=true
                SUSPICIOUS_COUNT=$((SUSPICIOUS_COUNT + 1))
                fail "PATH TRAVERSAL (double-encoded): ${url} returned sensitive content"
                add_finding "CRITICAL" "path-traversal/double-encoded" \
                    "Double-URL-encoded path traversal successful: ${method} ${url}. Server appears to decode URL components multiple times." \
                    "Payload: ${payload}. Response (truncated): $(echo "$body" | head -c 500)"
            fi
        fi
    done
done

# --- Summary ---
info "Tested ${TESTED_COUNT} URL combinations"

if [ "$TRAVERSAL_FOUND" = true ]; then
    fail "Path traversal vulnerabilities detected (${SUSPICIOUS_COUNT} suspicious responses)"
elif [ "$SUSPICIOUS_COUNT" -gt 0 ]; then
    warn "${SUSPICIOUS_COUNT} suspicious responses found (non-critical, review recommended)"
else
    pass "All path traversal payloads returned 400/404 — no traversal detected"
fi

exit 0
