#!/bin/bash
# Red Team Test 07: OCI V2 Unlimited Body / Resource Exhaustion
# Tests whether the OCI blob upload endpoint enforces body size limits.
# Does NOT perform an actual DoS — only confirms whether large payloads are accepted.

source "$(dirname "$0")/../lib.sh"

set -uo pipefail

header "OCI V2 Upload Body Limit Testing"

# --- Step 1: Authenticate ---
info "Authenticating to obtain OCI token"

TOKEN_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" \
    "${REGISTRY_URL}/api/v1/auth/login" 2>&1) || true

TOKEN_BODY=$(echo "$TOKEN_RESPONSE" | head -n -1)
TOKEN_STATUS=$(echo "$TOKEN_RESPONSE" | tail -n 1)

AUTH_TOKEN=""
if [ "$TOKEN_STATUS" = "200" ]; then
    AUTH_TOKEN=$(echo "$TOKEN_BODY" | jq -r '.token // .access_token // empty' 2>/dev/null) || true
fi

# Fallback to basic auth if token login does not yield a bearer token
if [ -z "$AUTH_TOKEN" ]; then
    info "No bearer token obtained; will use HTTP Basic auth for OCI requests"
    AUTH_HEADER="Authorization: Basic $(echo -n "${ADMIN_USER}:${ADMIN_PASS}" | base64)"
else
    info "Bearer token obtained"
    AUTH_HEADER="Authorization: Bearer ${AUTH_TOKEN}"
fi

# --- Step 2: Check OCI V2 endpoint availability ---
OCI_REPO="redteam-oci-test"
info "Checking OCI V2 base endpoint at /v2/"

V2_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "$AUTH_HEADER" \
    "${REGISTRY_URL}/v2/" 2>&1) || true

if [ "$V2_STATUS" = "000" ]; then
    warn "OCI V2 endpoint not reachable; skipping OCI tests"
    exit 0
elif [ "$V2_STATUS" = "404" ]; then
    info "OCI V2 endpoint returned 404 - OCI support may not be enabled"
    exit 0
elif [ "$V2_STATUS" = "401" ]; then
    info "OCI V2 endpoint requires authentication (HTTP 401)"
    # Try the OCI token endpoint for proper auth
    OCI_TOKEN_RESP=$(curl -s -u "${ADMIN_USER}:${ADMIN_PASS}" \
        "${REGISTRY_URL}/v2/token?scope=repository:${OCI_REPO}:push,pull&service=artifact-keeper" 2>&1) || true
    OCI_TOKEN=$(echo "$OCI_TOKEN_RESP" | jq -r '.token // empty' 2>/dev/null) || true
    if [ -n "$OCI_TOKEN" ]; then
        AUTH_HEADER="Authorization: Bearer ${OCI_TOKEN}"
        info "Obtained OCI-scoped token"
    fi
fi

info "OCI V2 base returned HTTP ${V2_STATUS}"

# --- Step 3: Ensure test OCI repository exists ---
info "Creating OCI repository '${OCI_REPO}' (may already exist)"

curl -s -o /dev/null -X POST \
    -H "Content-Type: application/json" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -d "{\"name\":\"${OCI_REPO}\",\"repo_type\":\"oci\"}" \
    "${REGISTRY_URL}/api/v1/repositories" 2>&1 || true

# --- Step 4: Inspect OCI endpoint headers ---
info "Checking response headers on OCI V2 catalog"

OCI_HEADERS=$(curl -sI -H "$AUTH_HEADER" "${REGISTRY_URL}/v2/_catalog" 2>&1) || true

info "OCI V2 /_catalog headers:"
echo "$OCI_HEADERS" | while IFS= read -r line; do
    line_clean=$(echo "$line" | tr -d '\r')
    [ -n "$line_clean" ] && info "  ${line_clean}"
done

# Check for Docker-Distribution-API-Version header
if echo "$OCI_HEADERS" | grep -qi "Docker-Distribution-API-Version"; then
    info "Docker-Distribution-API-Version header present"
else
    info "Docker-Distribution-API-Version header not present"
fi

# --- Step 5: Start blob upload session ---
info "Starting blob upload session: POST /v2/${OCI_REPO}/blobs/uploads/"

UPLOAD_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    -H "$AUTH_HEADER" \
    -H "Content-Type: application/octet-stream" \
    "${REGISTRY_URL}/v2/${OCI_REPO}/blobs/uploads/" 2>&1) || true

UPLOAD_BODY=$(echo "$UPLOAD_RESPONSE" | head -n -1)
UPLOAD_STATUS=$(echo "$UPLOAD_RESPONSE" | tail -n 1)

if [ "$UPLOAD_STATUS" = "202" ]; then
    info "Blob upload session started (HTTP 202)"
elif [ "$UPLOAD_STATUS" = "401" ] || [ "$UPLOAD_STATUS" = "403" ]; then
    warn "Blob upload requires auth we do not have (HTTP ${UPLOAD_STATUS}); skipping upload size test"
    exit 0
elif [ "$UPLOAD_STATUS" = "404" ]; then
    info "Blob upload endpoint returned 404 - OCI upload not available for this repo"
    exit 0
else
    warn "Unexpected status from blob upload start: HTTP ${UPLOAD_STATUS}"
    info "Response: $(echo "$UPLOAD_BODY" | head -c 300)"
fi

# Extract the upload location URL from the response headers
UPLOAD_LOCATION=$(curl -sI -X POST \
    -H "$AUTH_HEADER" \
    -H "Content-Type: application/octet-stream" \
    "${REGISTRY_URL}/v2/${OCI_REPO}/blobs/uploads/" 2>&1 \
    | grep -i "^Location:" | head -1 | sed 's/^[^:]*: *//' | tr -d '\r') || true

if [ -z "$UPLOAD_LOCATION" ]; then
    warn "No Location header in upload response; cannot proceed with PATCH upload"
    exit 0
fi

info "Upload session Location: ${UPLOAD_LOCATION}"

# Ensure the location is a full URL
if [[ "$UPLOAD_LOCATION" != http* ]]; then
    UPLOAD_LOCATION="${REGISTRY_URL}${UPLOAD_LOCATION}"
fi

# --- Step 6: Attempt to upload a 10MB payload ---
PAYLOAD_SIZE=$((10 * 1024 * 1024))  # 10 MB
info "Generating ${PAYLOAD_SIZE} byte (10MB) payload for upload test"

# Generate payload from /dev/urandom (or /dev/zero for speed)
PAYLOAD_FILE=$(mktemp /tmp/oci-dos-payload.XXXXXX)
dd if=/dev/zero bs=1024 count=10240 of="$PAYLOAD_FILE" 2>/dev/null

PATCH_RESPONSE=$(curl -s -w "\n%{http_code}" -X PATCH \
    -H "$AUTH_HEADER" \
    -H "Content-Type: application/octet-stream" \
    -H "Content-Length: ${PAYLOAD_SIZE}" \
    --data-binary "@${PAYLOAD_FILE}" \
    "${UPLOAD_LOCATION}" 2>&1) || true

PATCH_BODY=$(echo "$PATCH_RESPONSE" | head -n -1)
PATCH_STATUS=$(echo "$PATCH_RESPONSE" | tail -n 1)

# Clean up temp file
rm -f "$PAYLOAD_FILE"

info "PATCH upload returned HTTP ${PATCH_STATUS}"

if [ "$PATCH_STATUS" = "202" ]; then
    fail "10MB blob upload accepted without size restriction (HTTP 202)"
    add_finding "CRITICAL" "oci-dos/unlimited-body" \
        "OCI V2 blob upload endpoint accepts a 10MB payload without enforcing any body size limit. The DefaultBodyLimit is disabled on OCI routes, allowing arbitrarily large uploads. An attacker could exhaust disk space or memory by uploading extremely large blobs." \
        "PATCH ${UPLOAD_LOCATION} with 10MB payload returned HTTP 202. Response: $(echo "$PATCH_BODY" | head -c 500)"
elif [ "$PATCH_STATUS" = "413" ]; then
    pass "10MB upload correctly rejected with HTTP 413 (Payload Too Large)"
elif [ "$PATCH_STATUS" = "401" ] || [ "$PATCH_STATUS" = "403" ]; then
    warn "Upload PATCH returned auth error (HTTP ${PATCH_STATUS}); cannot determine body limit"
else
    warn "Unexpected response for 10MB upload: HTTP ${PATCH_STATUS}"
    info "Response: $(echo "$PATCH_BODY" | head -c 300)"
fi

# --- Step 7: Check if there is a Content-Length enforcement on POST ---
info "Testing upload initiation with large Content-Length header (no body)"

CL_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H "$AUTH_HEADER" \
    -H "Content-Type: application/octet-stream" \
    -H "Content-Length: 10737418240" \
    "${REGISTRY_URL}/v2/${OCI_REPO}/blobs/uploads/" 2>&1) || true

if [ "$CL_RESPONSE" = "413" ]; then
    pass "Server rejects oversized Content-Length on upload start (HTTP 413)"
elif [ "$CL_RESPONSE" = "202" ] || [ "$CL_RESPONSE" = "200" ]; then
    warn "Server accepted upload start with 10GB Content-Length header"
    add_finding "MEDIUM" "oci-dos/no-content-length-check" \
        "OCI V2 upload endpoint does not validate Content-Length header on session initiation. A 10GB Content-Length was accepted. While the actual body was not sent, this suggests no pre-validation of upload sizes." \
        "POST /v2/${OCI_REPO}/blobs/uploads/ with Content-Length: 10737418240 returned HTTP ${CL_RESPONSE}"
else
    info "Content-Length enforcement test returned HTTP ${CL_RESPONSE}"
fi

exit 0
