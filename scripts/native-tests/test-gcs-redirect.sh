#!/usr/bin/env bash
# Google Cloud Storage Redirect Download Test
#
# Tests GCS signed URL redirects for artifact downloads.
# This test is meant to be run MANUALLY when you have GCP credentials.
# NOT automated in CI due to cost concerns.
#
# Status: NOT VALIDATED - Community testing welcome!
#
# Prerequisites:
#   - Backend running locally with GCS storage configured
#   - gcloud CLI configured (gcloud auth login)
#   - Service account with storage.objects.* permissions
#   - Private key file for signing URLs
#
# Environment variables:
#   API_URL                       - Backend URL (default: http://localhost:8080)
#   GCS_BUCKET                    - GCS bucket name (required)
#   GCS_PROJECT_ID                - GCP project ID (required)
#   GCS_SERVICE_ACCOUNT_EMAIL     - Service account email (required)
#   GCS_PRIVATE_KEY_PATH          - Path to private key PEM file (required)
#   ADMIN_USER                    - Admin username (default: admin)
#   ADMIN_PASS                    - Admin password (default: admin123)
#   SKIP_CLEANUP                  - Set to "true" to skip cleanup
#
# Usage:
#   GCS_BUCKET=my-bucket \
#   GCS_PROJECT_ID=my-project \
#   GCS_SERVICE_ACCOUNT_EMAIL=sa@project.iam.gserviceaccount.com \
#   GCS_PRIVATE_KEY_PATH=/path/to/key.pem \
#   ./test-gcs-redirect.sh
#
# Cost estimate: ~$0.01 (minimal object operations)

set -euo pipefail

API_URL="${API_URL:-http://localhost:8080}"
GCS_BUCKET="${GCS_BUCKET:-}"
GCS_PROJECT_ID="${GCS_PROJECT_ID:-}"
GCS_SERVICE_ACCOUNT_EMAIL="${GCS_SERVICE_ACCOUNT_EMAIL:-}"
GCS_PRIVATE_KEY_PATH="${GCS_PRIVATE_KEY_PATH:-}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin123}"
SKIP_CLEANUP="${SKIP_CLEANUP:-false}"

TEST_REPO="gcs-redirect-test-$$"

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

    if [ -n "$GCS_BUCKET" ]; then
        info "Cleaning GCS objects..."
        gsutil -q rm "gs://${GCS_BUCKET}/gcs-redirect-test*" 2>/dev/null || true
    fi

    pass "Cleanup complete"
}

trap cleanup EXIT

# Check prerequisites
header "Checking Prerequisites"

for cmd in curl jq gsutil; do
    if ! command -v "$cmd" &> /dev/null; then
        fail "$cmd is not installed"
    fi
done
pass "Required tools installed"

if [ -z "$GCS_BUCKET" ] || [ -z "$GCS_PROJECT_ID" ] || [ -z "$GCS_SERVICE_ACCOUNT_EMAIL" ]; then
    fail "GCS_BUCKET, GCS_PROJECT_ID, and GCS_SERVICE_ACCOUNT_EMAIL are required"
fi

if [ -z "$GCS_PRIVATE_KEY_PATH" ] || [ ! -f "$GCS_PRIVATE_KEY_PATH" ]; then
    fail "GCS_PRIVATE_KEY_PATH must point to a valid private key file"
fi

# Test GCS access
info "Verifying GCS bucket access..."
gsutil ls "gs://${GCS_BUCKET}" > /dev/null 2>&1 || fail "Cannot access GCS bucket"
pass "GCS bucket accessible"

# Test API connectivity
header "Testing Connectivity"
info "API: ${API_URL}"
info "GCS Bucket: ${GCS_BUCKET}"
info "Project: ${GCS_PROJECT_ID}"

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
        \"name\": \"GCS Redirect Test\",
        \"format\": \"generic\",
        \"repo_type\": \"local\"
    }" 2>&1) || fail "Failed to create repository"

REPO_ID=$(echo "$CREATE_RESP" | jq -r '.id')
pass "Repository created"

# Configure for GCS storage
info "Configuring GCS storage backend..."
docker exec artifact-keeper-db psql -U registry -d artifact_registry -c "
    UPDATE repositories
    SET storage_backend = 'gcs', storage_path = '${TEST_REPO}'
    WHERE key = '${TEST_REPO}'
" > /dev/null 2>&1 || fail "Failed to configure storage"
pass "Storage configured"

# Upload test artifact
header "Uploading Test Artifact"

TEST_FILE=$(mktemp)
TEST_CONTENT="GCS redirect test - $(date) - $$"
echo "$TEST_CONTENT" > "$TEST_FILE"

info "Uploading via API..."
curl -sf -X PUT "${API_URL}/api/v1/repositories/${TEST_REPO}/artifacts/test/gcs-test.txt" \
    -H "Content-Type: text/plain" \
    -H "Authorization: Bearer $TOKEN" \
    --data-binary "@${TEST_FILE}" > /dev/null || fail "Upload failed"

# Get storage key and upload to GCS
STORAGE_KEY=$(docker exec artifact-keeper-db psql -U registry -d artifact_registry -t -c "
    SELECT storage_key FROM artifacts
    WHERE repository_id = '$REPO_ID' AND path = 'test/gcs-test.txt'
" | tr -d ' \n')

info "Uploading to GCS..."
gsutil -q cp "$TEST_FILE" "gs://${GCS_BUCKET}/${STORAGE_KEY}" || fail "GCS upload failed"

pass "Artifact uploaded to GCS"
rm -f "$TEST_FILE"

# Test download redirect
header "Testing Download Redirect"

info "Requesting artifact..."
DOWNLOAD_HEADERS=$(curl -sI "${API_URL}/api/v1/repositories/${TEST_REPO}/download/test/gcs-test.txt" \
    -H "Authorization: Bearer $TOKEN" 2>&1)

HTTP_STATUS=$(echo "$DOWNLOAD_HEADERS" | grep -i "^HTTP" | tail -1 | awk '{print $2}')
STORAGE_HEADER=$(echo "$DOWNLOAD_HEADERS" | grep -i "x-artifact-storage" | awk '{print $2}' | tr -d '\r\n')

echo "  HTTP Status: $HTTP_STATUS"
echo "  X-Artifact-Storage: $STORAGE_HEADER"

if [ "$HTTP_STATUS" = "302" ]; then
    pass "Got 302 redirect"

    LOCATION=$(echo "$DOWNLOAD_HEADERS" | grep -i "^location:" | sed 's/[Ll]ocation: //' | tr -d '\r\n')

    if echo "$LOCATION" | grep -q "storage.googleapis.com"; then
        pass "Redirect points to Google Cloud Storage"
    fi

    if echo "$LOCATION" | grep -q "X-Goog-Signature"; then
        pass "URL contains V4 signature"
    fi

    info "Downloading via signed URL..."
    DOWNLOADED=$(curl -sf "$LOCATION" 2>&1) || fail "Signed URL download failed"

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
echo -e "${GREEN}GCS redirect test completed!${NC}"
echo ""
echo "Bucket: ${GCS_BUCKET}"
echo "Project: ${GCS_PROJECT_ID}"
echo "X-Artifact-Storage: ${STORAGE_HEADER:-N/A}"
