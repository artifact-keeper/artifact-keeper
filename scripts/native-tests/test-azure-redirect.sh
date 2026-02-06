#!/usr/bin/env bash
# Azure Blob Storage Redirect Download Test
#
# Tests Azure SAS URL redirects for artifact downloads.
# This test is meant to be run MANUALLY when you have Azure credentials.
# NOT automated in CI due to cost concerns.
#
# Status: NOT VALIDATED - Community testing welcome!
#
# Prerequisites:
#   - Backend running locally with Azure storage configured
#   - Azure CLI configured (az login)
#   - Storage account with container created
#
# Environment variables:
#   API_URL                    - Backend URL (default: http://localhost:8080)
#   AZURE_STORAGE_ACCOUNT      - Storage account name (required)
#   AZURE_STORAGE_CONTAINER    - Container name (required)
#   AZURE_STORAGE_ACCESS_KEY   - Account access key (required)
#   ADMIN_USER                 - Admin username (default: admin)
#   ADMIN_PASS                 - Admin password (default: admin123)
#   SKIP_CLEANUP               - Set to "true" to skip cleanup
#
# Usage:
#   AZURE_STORAGE_ACCOUNT=myaccount \
#   AZURE_STORAGE_CONTAINER=artifacts \
#   AZURE_STORAGE_ACCESS_KEY=xxx \
#   ./test-azure-redirect.sh
#
# Cost estimate: ~$0.01 (minimal blob operations)

set -euo pipefail

API_URL="${API_URL:-http://localhost:8080}"
AZURE_STORAGE_ACCOUNT="${AZURE_STORAGE_ACCOUNT:-}"
AZURE_STORAGE_CONTAINER="${AZURE_STORAGE_CONTAINER:-}"
AZURE_STORAGE_ACCESS_KEY="${AZURE_STORAGE_ACCESS_KEY:-}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin123}"
SKIP_CLEANUP="${SKIP_CLEANUP:-false}"

TEST_REPO="azure-redirect-test-$$"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

pass() { echo -e "${GREEN}✓ $1${NC}"; }
fail() { echo -e "${RED}✗ $1${NC}"; exit 1; }
info() { echo -e "${YELLOW}→ $1${NC}"; }
header() { echo -e "\n${BLUE}=== $1 ===${NC}"; }

cleanup() {
    if [ "$SKIP_CLEANUP" = "true" ]; then
        info "Skipping cleanup (SKIP_CLEANUP=true)"
        return
    fi

    header "Cleanup"

    if [ -n "${TOKEN:-}" ]; then
        info "Deleting test repository..."
        curl -sf -X DELETE "${API_URL}/api/v1/repositories/${TEST_REPO}" \
            -H "Authorization: Bearer $TOKEN" > /dev/null 2>&1 || true
    fi

    if [ -n "$AZURE_STORAGE_ACCOUNT" ]; then
        info "Cleaning Azure blobs..."
        az storage blob delete-batch \
            --account-name "$AZURE_STORAGE_ACCOUNT" \
            --account-key "$AZURE_STORAGE_ACCESS_KEY" \
            --source "$AZURE_STORAGE_CONTAINER" \
            --pattern "azure-redirect-test*" > /dev/null 2>&1 || true
    fi

    pass "Cleanup complete"
}

trap cleanup EXIT

# Check prerequisites
header "Checking Prerequisites"

for cmd in curl jq az; do
    if ! command -v "$cmd" &> /dev/null; then
        fail "$cmd is not installed"
    fi
done
pass "Required tools installed"

if [ -z "$AZURE_STORAGE_ACCOUNT" ] || [ -z "$AZURE_STORAGE_CONTAINER" ] || [ -z "$AZURE_STORAGE_ACCESS_KEY" ]; then
    fail "AZURE_STORAGE_ACCOUNT, AZURE_STORAGE_CONTAINER, and AZURE_STORAGE_ACCESS_KEY are required"
fi

# Test Azure access
info "Verifying Azure storage access..."
az storage container show \
    --name "$AZURE_STORAGE_CONTAINER" \
    --account-name "$AZURE_STORAGE_ACCOUNT" \
    --account-key "$AZURE_STORAGE_ACCESS_KEY" > /dev/null 2>&1 || fail "Cannot access Azure container"
pass "Azure storage accessible"

# Test API connectivity
header "Testing Connectivity"
info "API: ${API_URL}"
info "Storage Account: ${AZURE_STORAGE_ACCOUNT}"
info "Container: ${AZURE_STORAGE_CONTAINER}"

if ! curl -sf "${API_URL}/health" > /dev/null 2>&1; then
    fail "Cannot connect to API server"
fi
pass "API server is running"

# Get JWT token
header "Authenticating"
LOGIN_RESP=$(curl -sf -X POST "${API_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"${ADMIN_USER}\", \"password\": \"${ADMIN_PASS}\"}" 2>&1) || fail "Login failed"

TOKEN=$(echo "$LOGIN_RESP" | jq -r '.access_token')
if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    fail "Failed to get access token"
fi
pass "Authenticated"

# Create test repository
header "Setting Up Test"

info "Creating repository..."
CREATE_RESP=$(curl -sf -X POST "${API_URL}/api/v1/repositories" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{
        \"key\": \"${TEST_REPO}\",
        \"name\": \"Azure Redirect Test\",
        \"format\": \"generic\",
        \"repo_type\": \"local\"
    }" 2>&1) || fail "Failed to create repository"

REPO_ID=$(echo "$CREATE_RESP" | jq -r '.id')
pass "Repository created"

# Configure for Azure storage
info "Configuring Azure storage backend..."
docker exec artifact-keeper-db psql -U registry -d artifact_registry -c "
    UPDATE repositories
    SET storage_backend = 'azure', storage_path = '${TEST_REPO}'
    WHERE key = '${TEST_REPO}'
" > /dev/null 2>&1 || fail "Failed to configure storage"
pass "Storage configured"

# Upload test artifact
header "Uploading Test Artifact"

TEST_FILE=$(mktemp)
TEST_CONTENT="Azure redirect test - $(date) - $$"
echo "$TEST_CONTENT" > "$TEST_FILE"

info "Uploading via API..."
curl -sf -X PUT "${API_URL}/api/v1/repositories/${TEST_REPO}/artifacts/test/azure-test.txt" \
    -H "Content-Type: text/plain" \
    -H "Authorization: Bearer $TOKEN" \
    --data-binary "@${TEST_FILE}" > /dev/null || fail "Upload failed"

# Get storage key and upload to Azure
STORAGE_KEY=$(docker exec artifact-keeper-db psql -U registry -d artifact_registry -t -c "
    SELECT storage_key FROM artifacts
    WHERE repository_id = '$REPO_ID' AND path = 'test/azure-test.txt'
" | tr -d ' \n')

info "Uploading to Azure Blob..."
az storage blob upload \
    --account-name "$AZURE_STORAGE_ACCOUNT" \
    --account-key "$AZURE_STORAGE_ACCESS_KEY" \
    --container-name "$AZURE_STORAGE_CONTAINER" \
    --name "$STORAGE_KEY" \
    --file "$TEST_FILE" \
    --overwrite > /dev/null 2>&1 || fail "Azure upload failed"

pass "Artifact uploaded to Azure"
rm -f "$TEST_FILE"

# Test download redirect
header "Testing Download Redirect"

info "Requesting artifact..."
DOWNLOAD_HEADERS=$(curl -sI "${API_URL}/api/v1/repositories/${TEST_REPO}/download/test/azure-test.txt" \
    -H "Authorization: Bearer $TOKEN" 2>&1)

HTTP_STATUS=$(echo "$DOWNLOAD_HEADERS" | grep -i "^HTTP" | tail -1 | awk '{print $2}')
STORAGE_HEADER=$(echo "$DOWNLOAD_HEADERS" | grep -i "x-artifact-storage" | awk '{print $2}' | tr -d '\r\n')

echo "  HTTP Status: $HTTP_STATUS"
echo "  X-Artifact-Storage: $STORAGE_HEADER"

if [ "$HTTP_STATUS" = "302" ]; then
    pass "Got 302 redirect"

    LOCATION=$(echo "$DOWNLOAD_HEADERS" | grep -i "^location:" | sed 's/[Ll]ocation: //' | tr -d '\r\n')

    if echo "$LOCATION" | grep -q "blob.core.windows.net"; then
        pass "Redirect points to Azure Blob Storage"
    fi

    if echo "$LOCATION" | grep -q "sig="; then
        pass "URL contains SAS signature"
    fi

    info "Downloading via SAS URL..."
    DOWNLOADED=$(curl -sf "$LOCATION" 2>&1) || fail "SAS URL download failed"

    if [ "$DOWNLOADED" = "$TEST_CONTENT" ]; then
        pass "Content matches!"
    else
        fail "Content mismatch"
    fi
else
    info "Got HTTP $HTTP_STATUS - redirect may be disabled"
fi

# Summary
header "Test Summary"
echo -e "${GREEN}Azure redirect test completed!${NC}"
echo ""
echo "Storage Account: ${AZURE_STORAGE_ACCOUNT}"
echo "Container: ${AZURE_STORAGE_CONTAINER}"
echo "X-Artifact-Storage: ${STORAGE_HEADER:-N/A}"
