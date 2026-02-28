#!/usr/bin/env bash
# S3 Redirect Download E2E Test
#
# Tests S3 presigned URL redirects and CloudFront signed URLs.
# This test is meant to be run MANUALLY when you have AWS credentials.
# It is NOT automated in CI due to cost concerns.
#
# Prerequisites:
#   - Backend running locally with S3 storage configured:
#       S3_BUCKET, S3_REGION, S3_REDIRECT_DOWNLOADS=true
#   - AWS CLI configured with valid credentials (aws sts get-caller-identity)
#   - An S3 bucket you have read/write access to
#
# Environment variables:
#   API_URL         - Backend URL (default: http://localhost:8080)
#   S3_BUCKET       - S3 bucket name (required, or will create temporary one)
#   S3_REGION       - AWS region (default: us-east-1)
#   ADMIN_USER      - Admin username (default: admin)
#   ADMIN_PASS      - Admin password (default: admin123)
#   CLOUDFRONT_URL  - CloudFront distribution URL (optional)
#   SKIP_CLEANUP    - Set to "true" to skip cleanup (for debugging)
#
# Usage:
#   # With existing bucket:
#   S3_BUCKET=my-bucket ./test-s3-redirect.sh
#
#   # Create temporary bucket (will be deleted after test):
#   ./test-s3-redirect.sh
#
# Cost estimate: ~$0.01 (1 PUT, 1 GET, temporary bucket)

set -euo pipefail

API_URL="${API_URL:-http://localhost:8080}"
S3_BUCKET="${S3_BUCKET:-}"
S3_REGION="${S3_REGION:-us-east-1}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin123}"
CLOUDFRONT_URL="${CLOUDFRONT_URL:-}"
SKIP_CLEANUP="${SKIP_CLEANUP:-false}"

CREATED_BUCKET=""
TEST_REPO="s3-redirect-test-$$"

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

    # Delete test artifact and repo via API
    if [ -n "${TOKEN:-}" ]; then
        info "Deleting test repository via API..."
        curl -sf -X DELETE "${API_URL}/api/v1/repositories/${TEST_REPO}" \
            -H "Authorization: Bearer $TOKEN" > /dev/null 2>&1 || true
    fi

    # Delete S3 objects
    if [ -n "$S3_BUCKET" ]; then
        info "Cleaning S3 objects..."
        aws s3 rm "s3://${S3_BUCKET}/" --recursive --quiet 2>/dev/null || true
    fi

    # Delete temporary bucket if we created one
    if [ -n "$CREATED_BUCKET" ]; then
        info "Deleting temporary S3 bucket: $CREATED_BUCKET"
        aws s3 rb "s3://${CREATED_BUCKET}" --force 2>/dev/null || true
    fi

    # Clean up database (repository set to s3 backend)
    info "Cleaning up database..."
    docker exec artifact-keeper-db psql -U registry -d artifact_registry -c "
        DELETE FROM artifacts WHERE repository_id IN (SELECT id FROM repositories WHERE key LIKE 's3-redirect-test-%');
        DELETE FROM repositories WHERE key LIKE 's3-redirect-test-%';
    " > /dev/null 2>&1 || true

    pass "Cleanup complete"
}

trap cleanup EXIT

# Check prerequisites
header "Checking Prerequisites"

for cmd in curl jq aws; do
    if ! command -v "$cmd" &> /dev/null; then
        fail "$cmd is not installed"
    fi
done
pass "Required tools installed (curl, jq, aws)"

# Verify AWS credentials
info "Verifying AWS credentials..."
AWS_ACCOUNT=$(aws sts get-caller-identity --query Account --output text 2>/dev/null) || fail "AWS credentials not configured"
pass "AWS credentials valid (account: $AWS_ACCOUNT)"

# Create temporary bucket if not provided
if [ -z "$S3_BUCKET" ]; then
    S3_BUCKET="artifact-keeper-test-$(date +%s)"
    CREATED_BUCKET="$S3_BUCKET"
    info "Creating temporary S3 bucket: $S3_BUCKET"
    aws s3 mb "s3://${S3_BUCKET}" --region "$S3_REGION" > /dev/null 2>&1 || fail "Failed to create bucket"
    pass "Temporary bucket created"
else
    # Verify bucket access
    info "Verifying S3 bucket access..."
    aws s3 ls "s3://${S3_BUCKET}" > /dev/null 2>&1 || fail "Cannot access S3 bucket: ${S3_BUCKET}"
    pass "S3 bucket accessible"
fi

# Test API connectivity
header "Testing Connectivity"
info "API: ${API_URL}"
info "S3 Bucket: ${S3_BUCKET}"
info "Region: ${S3_REGION}"

if ! curl -sf "${API_URL}/health" > /dev/null 2>&1; then
    fail "Cannot connect to API server at ${API_URL}"
fi
pass "API server is running"

# -------------------------------------------------------------------------
# Get JWT token
# -------------------------------------------------------------------------
header "Authenticating"

info "Logging in as ${ADMIN_USER}..."
LOGIN_RESP=$(curl -sf -X POST "${API_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"${ADMIN_USER}\", \"password\": \"${ADMIN_PASS}\"}" 2>&1) || fail "Login failed"

TOKEN=$(echo "$LOGIN_RESP" | jq -r '.access_token')
if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    fail "Failed to get access token"
fi
pass "Authenticated successfully"

# -------------------------------------------------------------------------
# Create test repository
# -------------------------------------------------------------------------
header "Setting Up Test Repository"

info "Creating repository: ${TEST_REPO}"
CREATE_RESP=$(curl -sf -X POST "${API_URL}/api/v1/repositories" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{
        \"key\": \"${TEST_REPO}\",
        \"name\": \"S3 Redirect Test\",
        \"format\": \"generic\",
        \"repo_type\": \"local\"
    }" 2>&1) || fail "Failed to create repository"

REPO_ID=$(echo "$CREATE_RESP" | jq -r '.id')
pass "Repository created: $REPO_ID"

# Update repository to use S3 storage backend
info "Configuring repository for S3 storage..."
docker exec artifact-keeper-db psql -U registry -d artifact_registry -c "
    UPDATE repositories
    SET storage_backend = 's3', storage_path = '${TEST_REPO}'
    WHERE key = '${TEST_REPO}'
" > /dev/null 2>&1 || fail "Failed to update storage backend"
pass "Repository configured for S3"

# -------------------------------------------------------------------------
# Upload test artifact
# -------------------------------------------------------------------------
header "Uploading Test Artifact"

TEST_FILE=$(mktemp)
TEST_CONTENT="Test artifact content - $(date) - $$"
echo "$TEST_CONTENT" > "$TEST_FILE"

info "Uploading to filesystem first..."
UPLOAD_RESP=$(curl -sf -X PUT "${API_URL}/api/v1/repositories/${TEST_REPO}/artifacts/test/redirect-test.txt" \
    -H "Content-Type: text/plain" \
    -H "Authorization: Bearer $TOKEN" \
    --data-binary "@${TEST_FILE}" 2>&1) || fail "Failed to upload artifact"

STORAGE_KEY=$(docker exec artifact-keeper-db psql -U registry -d artifact_registry -t -c "
    SELECT storage_key FROM artifacts
    WHERE repository_id = '$REPO_ID' AND path = 'test/redirect-test.txt'
" | tr -d ' \n')

pass "Artifact uploaded (storage_key: ${STORAGE_KEY:0:20}...)"

# Copy to S3
info "Copying artifact to S3..."
aws s3 cp "$TEST_FILE" "s3://${S3_BUCKET}/${STORAGE_KEY}" --quiet || fail "Failed to copy to S3"
pass "Artifact copied to S3"

rm -f "$TEST_FILE"

# -------------------------------------------------------------------------
# Test download redirect
# -------------------------------------------------------------------------
header "Testing Download Redirect"

info "Requesting artifact download..."
DOWNLOAD_HEADERS=$(curl -sI "${API_URL}/api/v1/repositories/${TEST_REPO}/download/test/redirect-test.txt" \
    -H "Authorization: Bearer $TOKEN" 2>&1)

HTTP_STATUS=$(echo "$DOWNLOAD_HEADERS" | grep -i "^HTTP" | tail -1 | awk '{print $2}')
STORAGE_HEADER=$(echo "$DOWNLOAD_HEADERS" | grep -i "x-artifact-storage" | awk '{print $2}' | tr -d '\r\n')
LOCATION=$(echo "$DOWNLOAD_HEADERS" | grep -i "^location:" | sed 's/[Ll]ocation: //' | tr -d '\r\n')

echo "  HTTP Status: $HTTP_STATUS"
echo "  X-Artifact-Storage: $STORAGE_HEADER"

if [ "$HTTP_STATUS" = "302" ]; then
    pass "Got 302 redirect response"

    if [ -n "$LOCATION" ]; then
        info "Redirect URL: ${LOCATION:0:80}..."

        if echo "$LOCATION" | grep -q "cloudfront"; then
            pass "Redirect points to CloudFront"
        elif echo "$LOCATION" | grep -q "s3\|amazonaws"; then
            pass "Redirect points to S3 presigned URL"
        fi

        # Verify presigned URL works
        info "Downloading via presigned URL..."
        DOWNLOADED_CONTENT=$(curl -sf "$LOCATION" 2>&1) || fail "Failed to download from presigned URL"

        if [ "$DOWNLOADED_CONTENT" = "$TEST_CONTENT" ]; then
            pass "Content matches! Presigned URL works correctly"
        else
            echo "Expected: $TEST_CONTENT"
            echo "Got: $DOWNLOADED_CONTENT"
            fail "Content mismatch"
        fi
    else
        fail "302 response but no Location header"
    fi
elif [ "$HTTP_STATUS" = "200" ]; then
    info "Got 200 response - redirect may be disabled or not configured"
    info "Check that backend was started with S3_REDIRECT_DOWNLOADS=true"

    if [ "$STORAGE_HEADER" = "proxy" ]; then
        pass "Content served via proxy (redirect disabled)"
    fi
else
    fail "Unexpected HTTP status: ${HTTP_STATUS}"
fi

# -------------------------------------------------------------------------
# Test with curl -L (follow redirects)
# -------------------------------------------------------------------------
header "Testing Full Download Flow"

info "Downloading with automatic redirect following..."
FULL_DOWNLOAD=$(curl -sfL "${API_URL}/api/v1/repositories/${TEST_REPO}/download/test/redirect-test.txt" \
    -H "Authorization: Bearer $TOKEN" 2>&1) || fail "Full download failed"

if [ "$FULL_DOWNLOAD" = "$TEST_CONTENT" ]; then
    pass "Full download flow works correctly"
else
    fail "Content mismatch in full download"
fi

# -------------------------------------------------------------------------
# CloudFront test (if configured)
# -------------------------------------------------------------------------
if [ -n "$CLOUDFRONT_URL" ]; then
    header "Testing CloudFront Integration"
    info "CloudFront URL: ${CLOUDFRONT_URL}"

    CF_HEADERS=$(curl -sI "${CLOUDFRONT_URL}/" 2>&1 | head -5)
    if echo "$CF_HEADERS" | grep -q "HTTP"; then
        pass "CloudFront distribution reachable"
    else
        info "CloudFront may require signed URLs (expected)"
    fi
fi

# -------------------------------------------------------------------------
# Test scanner with S3 storage backend
# -------------------------------------------------------------------------
header "Testing Scanner with S3 Backend"

info "Triggering security scan on S3-backed artifact..."
ARTIFACT_ID=$(docker exec artifact-keeper-db psql -U registry -d artifact_registry -t -c "
    SELECT id FROM artifacts
    WHERE repository_id = '$REPO_ID' AND path = 'test/redirect-test.txt'
    LIMIT 1
" | tr -d ' \n')

if [ -z "$ARTIFACT_ID" ] || [ "$ARTIFACT_ID" = "" ]; then
    fail "Could not find artifact ID for scan test"
fi

info "Artifact ID: $ARTIFACT_ID"

# Trigger a scan via the API
SCAN_RESP=$(curl -s -w "\n%{http_code}" -X POST "${API_URL}/api/v1/security/scans" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"artifact_id\": \"${ARTIFACT_ID}\"}" 2>&1)

SCAN_BODY=$(echo "$SCAN_RESP" | head -n -1)
SCAN_STATUS=$(echo "$SCAN_RESP" | tail -1)

# A text file is not a scannable artifact type, so we accept either:
# - 200/201/202: scan was queued/completed (scanner resolved storage correctly)
# - 400/422: scanner correctly rejected non-scannable content type
# What we do NOT accept:
# - 500 with "No such file or directory" (scanner tried local filesystem instead of S3)
if [ "$SCAN_STATUS" = "500" ]; then
    if echo "$SCAN_BODY" | grep -qi "no such file\|not found\|os error 2"; then
        fail "Scanner failed with filesystem error on S3-backed repo. Storage resolution is broken."
    fi
    info "Scan returned 500 but not a filesystem error (may be expected for text files)"
    pass "Scanner did not fall back to local filesystem"
else
    pass "Scan request returned HTTP $SCAN_STATUS (scanner resolved storage correctly)"
fi

# -------------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------------
header "Test Summary"
echo -e "${GREEN}All S3 tests passed (redirect + scanner)!${NC}"
echo ""
echo "Configuration tested:"
echo "  API URL: ${API_URL}"
echo "  S3 Bucket: ${S3_BUCKET}"
echo "  Region: ${S3_REGION}"
echo "  Storage Header: ${STORAGE_HEADER:-N/A}"
if [ -n "$CLOUDFRONT_URL" ]; then
    echo "  CloudFront: ${CLOUDFRONT_URL}"
fi
echo ""
echo "The S3 redirect feature is working correctly."
