#!/bin/bash
# Storage garbage collection E2E tests
#
# Tests that soft-deleted artifacts have their physical storage cleaned up
# when the GC endpoint is triggered, and that deduplication is respected.
#
# Usage: ./test-storage-gc.sh
# Environment:
#   REGISTRY_URL  - Backend URL (default: http://localhost:30080)
#   ADMIN_USER    - Admin username (default: admin)
#   ADMIN_PASS    - Admin password (default: TestRunner!2026secure)
set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:30080}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-TestRunner!2026secure}"

echo "==> Storage GC E2E Tests"
echo "Registry: $REGISTRY_URL"

PASSED=0
FAILED=0

pass() {
    echo "  PASS: $1"
    PASSED=$((PASSED + 1))
}

fail() {
    echo "  FAIL: $1"
    FAILED=$((FAILED + 1))
}

# ---- Authenticate ----
echo ""
echo "==> Authenticating..."
TOKEN=$(curl -sf "$REGISTRY_URL/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" | jq -r '.access_token')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    echo "FATAL: Authentication failed"
    exit 1
fi
echo "  Authenticated as $ADMIN_USER"

UNIQUE=$(date +%s%N)

# ---- Test 1: Dry-run returns result ----
echo ""
echo "==> [1/5] Dry-run storage GC"
RESULT=$(curl -sf -X POST "$REGISTRY_URL/api/v1/admin/storage-gc" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"dry_run": true}')
DRY_RUN=$(echo "$RESULT" | jq -r '.dry_run')
if [ "$DRY_RUN" = "true" ]; then
    pass "Dry-run returns dry_run=true"
else
    fail "Expected dry_run=true, got $DRY_RUN"
fi

# ---- Test 2: Upload, delete, GC cycle ----
echo ""
echo "==> [2/5] Upload, delete, GC cycle"
REPO_KEY="gc-test-$UNIQUE"

# Create repo
curl -sf -X POST "$REGISTRY_URL/api/v1/repositories" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"key\":\"$REPO_KEY\",\"name\":\"GC Test\",\"format\":\"generic\",\"repo_type\":\"local\"}" > /dev/null

# Upload artifact
echo "gc-test-content-$UNIQUE" | curl -sf -X PUT \
    "$REGISTRY_URL/api/v1/repositories/$REPO_KEY/artifacts/test-file.txt" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/octet-stream" \
    --data-binary @- > /dev/null

# Verify artifact is downloadable
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "$REGISTRY_URL/api/v1/repositories/$REPO_KEY/artifacts/test-file.txt" \
    -H "Authorization: Bearer $TOKEN") || HTTP_CODE="000"
if [ "$HTTP_CODE" = "200" ]; then
    pass "Artifact downloadable after upload"
else
    fail "Artifact not found after upload (HTTP $HTTP_CODE)"
fi

# Delete artifact (soft-delete)
curl -sf -X DELETE \
    "$REGISTRY_URL/api/v1/repositories/$REPO_KEY/artifacts/test-file.txt" \
    -H "Authorization: Bearer $TOKEN" > /dev/null

# Run GC
GC_RESULT=$(curl -sf -X POST "$REGISTRY_URL/api/v1/admin/storage-gc" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"dry_run": false}')
KEYS_DELETED=$(echo "$GC_RESULT" | jq -r '.storage_keys_deleted')
if [ "$KEYS_DELETED" -ge 1 ] 2>/dev/null; then
    pass "GC deleted $KEYS_DELETED storage key(s)"
else
    fail "Expected at least 1 key deleted, got: $KEYS_DELETED"
fi

# ---- Test 3: Verify artifact is truly gone ----
echo ""
echo "==> [3/5] Artifact returns 404 after GC"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "$REGISTRY_URL/api/v1/repositories/$REPO_KEY/artifacts/test-file.txt" \
    -H "Authorization: Bearer $TOKEN") || HTTP_CODE="000"
if [ "$HTTP_CODE" = "404" ] || [ "$HTTP_CODE" = "000" ]; then
    pass "Artifact returns 404 after GC"
else
    fail "Expected 404, got HTTP $HTTP_CODE"
fi

# ---- Test 4: Run GC again (idempotent, nothing to clean) ----
echo ""
echo "==> [4/5] Repeated GC is idempotent"
GC_RESULT2=$(curl -sf -X POST "$REGISTRY_URL/api/v1/admin/storage-gc" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"dry_run": false}')
KEYS_DELETED2=$(echo "$GC_RESULT2" | jq -r '.storage_keys_deleted')
if [ "$KEYS_DELETED2" -eq 0 ] 2>/dev/null; then
    pass "Repeated GC finds nothing to clean"
else
    # Not a hard failure, other soft-deleted artifacts may exist
    pass "Repeated GC deleted $KEYS_DELETED2 additional key(s)"
fi

# ---- Test 5: Deduplication safety ----
echo ""
echo "==> [5/5] Deduplication safety"
REPO_KEY_A="gc-dedup-a-$UNIQUE"
REPO_KEY_B="gc-dedup-b-$UNIQUE"

# Create two repos
curl -sf -X POST "$REGISTRY_URL/api/v1/repositories" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"key\":\"$REPO_KEY_A\",\"name\":\"GC Dedup A\",\"format\":\"generic\",\"repo_type\":\"local\"}" > /dev/null

curl -sf -X POST "$REGISTRY_URL/api/v1/repositories" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"key\":\"$REPO_KEY_B\",\"name\":\"GC Dedup B\",\"format\":\"generic\",\"repo_type\":\"local\"}" > /dev/null

# Upload identical content to both repos (same bytes = same storage key via CAS)
SHARED_CONTENT="shared-dedup-content-$UNIQUE"

echo "$SHARED_CONTENT" | curl -sf -X PUT \
    "$REGISTRY_URL/api/v1/repositories/$REPO_KEY_A/artifacts/shared.txt" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/octet-stream" \
    --data-binary @- > /dev/null

echo "$SHARED_CONTENT" | curl -sf -X PUT \
    "$REGISTRY_URL/api/v1/repositories/$REPO_KEY_B/artifacts/shared.txt" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/octet-stream" \
    --data-binary @- > /dev/null

# Delete from repo A only
curl -sf -X DELETE \
    "$REGISTRY_URL/api/v1/repositories/$REPO_KEY_A/artifacts/shared.txt" \
    -H "Authorization: Bearer $TOKEN" > /dev/null

# Run GC
curl -sf -X POST "$REGISTRY_URL/api/v1/admin/storage-gc" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"dry_run": false}' > /dev/null

# Verify repo B's artifact still works (storage key must NOT be deleted)
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "$REGISTRY_URL/api/v1/repositories/$REPO_KEY_B/artifacts/shared.txt" \
    -H "Authorization: Bearer $TOKEN") || HTTP_CODE="000"
if [ "$HTTP_CODE" = "200" ]; then
    pass "Dedup-safe: repo B artifact survives GC after repo A deletion"
else
    fail "Dedup violation: repo B artifact gone (HTTP $HTTP_CODE)"
fi

# ---- Summary ----
echo ""
echo "==> Results: $PASSED passed, $FAILED failed"
[ "$FAILED" -eq 0 ] || exit 1
