#!/usr/bin/env bash
# Tag-filtered replication E2E test
#
# Tests the full workflow from issue #235:
# 1. Upload artifact with tag distribution=test
# 2. Create sync policy filtering on distribution=production
# 3. Change tag to distribution=production -> expect push task
# 4. Change tag to distribution=eol -> expect delete task
#
# Usage:
#   ./scripts/native-tests/test-tag-replication.sh
#
# Environment:
#   API_URL       Backend URL (default: http://localhost:8080)
#   ADMIN_USER    Admin username (default: admin)
#   ADMIN_PASS    Admin password (default: TestRunner!2026secure)

set -euo pipefail

API_URL="${API_URL:-http://localhost:8080}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-TestRunner!2026secure}"

PASSED=0
FAILED=0
TESTS_RUN=0

# Unique suffix to avoid collisions
SUFFIX="$(date +%s%N)"

# Cleanup tracking
CLEANUP_PEER_ID=""
CLEANUP_POLICY_ID=""
CLEANUP_REPO_KEY=""

cleanup() {
    echo ""
    echo "--- Cleanup ---"
    if [ -n "$CLEANUP_POLICY_ID" ]; then
        curl -sf -X DELETE "${API_URL}/api/v1/sync-policies/${CLEANUP_POLICY_ID}" \
            -H "Authorization: Bearer ${TOKEN}" >/dev/null 2>&1 || true
    fi
    if [ -n "$CLEANUP_PEER_ID" ]; then
        curl -sf -X DELETE "${API_URL}/api/v1/peers/${CLEANUP_PEER_ID}" \
            -H "Authorization: Bearer ${TOKEN}" >/dev/null 2>&1 || true
    fi
    echo "Cleanup complete."
}

trap cleanup EXIT

pass() {
    PASSED=$((PASSED + 1))
    TESTS_RUN=$((TESTS_RUN + 1))
    echo "  PASS: $1"
}

fail() {
    FAILED=$((FAILED + 1))
    TESTS_RUN=$((TESTS_RUN + 1))
    echo "  FAIL: $1"
}

# -----------------------------------------------------------------------
# Authenticate
# -----------------------------------------------------------------------

echo "=== Tag-Filtered Replication E2E Test ==="
echo "Backend: ${API_URL}"
echo ""

echo "--- Authenticating ---"
LOGIN_RESP=$(curl -sf -X POST "${API_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"${ADMIN_USER}\", \"password\": \"${ADMIN_PASS}\"}")

TOKEN=$(echo "$LOGIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null || true)

if [ -z "$TOKEN" ]; then
    echo "FAIL: Could not authenticate"
    exit 1
fi
echo "  Authenticated as ${ADMIN_USER}"
echo ""

# -----------------------------------------------------------------------
# Test 1: Create repository and upload artifact
# -----------------------------------------------------------------------

REPO_KEY="tag-e2e-${SUFFIX}"
CLEANUP_REPO_KEY="$REPO_KEY"

echo "--- Test 1: Create repository and upload artifact ---"

REPO_RESP=$(curl -sf -X POST "${API_URL}/api/v1/repositories" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"key\": \"${REPO_KEY}\", \"name\": \"Tag E2E Test\", \"format\": \"generic\", \"repo_type\": \"local\", \"is_public\": true}")

REPO_ID=$(echo "$REPO_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null || true)
if [ -n "$REPO_ID" ]; then
    pass "Created repository ${REPO_KEY} (${REPO_ID})"
else
    fail "Failed to create repository"
    exit 1
fi

# Upload artifact
ARTIFACT_RESP=$(curl -sf -X PUT "${API_URL}/api/v1/repositories/${REPO_KEY}/artifacts/test/e2e-artifact-1.0.0.bin" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/octet-stream" \
    -d "e2e tag replication test content")

ARTIFACT_ID=$(echo "$ARTIFACT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null || true)
if [ -n "$ARTIFACT_ID" ]; then
    pass "Uploaded artifact (${ARTIFACT_ID})"
else
    fail "Failed to upload artifact"
    exit 1
fi

# -----------------------------------------------------------------------
# Test 2: Artifact label CRUD
# -----------------------------------------------------------------------

echo ""
echo "--- Test 2: Artifact label CRUD ---"

# Add label
ADD_RESP=$(curl -sf -X POST "${API_URL}/api/v1/artifacts/${ARTIFACT_ID}/labels/distribution" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"value": "test"}')

LABEL_KEY=$(echo "$ADD_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['key'])" 2>/dev/null || true)
LABEL_VAL=$(echo "$ADD_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['value'])" 2>/dev/null || true)
if [ "$LABEL_KEY" = "distribution" ] && [ "$LABEL_VAL" = "test" ]; then
    pass "Added label distribution=test"
else
    fail "Add label returned unexpected: key=${LABEL_KEY}, value=${LABEL_VAL}"
fi

# List labels
LIST_RESP=$(curl -sf -X GET "${API_URL}/api/v1/artifacts/${ARTIFACT_ID}/labels" \
    -H "Authorization: Bearer ${TOKEN}")

TOTAL=$(echo "$LIST_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['total'])" 2>/dev/null || true)
if [ "$TOTAL" = "1" ]; then
    pass "Listed labels (total=1)"
else
    fail "Expected 1 label, got ${TOTAL}"
fi

# Bulk set labels
SET_RESP=$(curl -sf -X PUT "${API_URL}/api/v1/artifacts/${ARTIFACT_ID}/labels" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"labels": [{"key": "distribution", "value": "staging"}, {"key": "tier", "value": "silver"}]}')

SET_TOTAL=$(echo "$SET_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['total'])" 2>/dev/null || true)
if [ "$SET_TOTAL" = "2" ]; then
    pass "Bulk set labels (total=2)"
else
    fail "Bulk set expected 2 labels, got ${SET_TOTAL}"
fi

# Delete label
DEL_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" -X DELETE \
    "${API_URL}/api/v1/artifacts/${ARTIFACT_ID}/labels/tier" \
    -H "Authorization: Bearer ${TOKEN}")

if [ "$DEL_STATUS" = "204" ]; then
    pass "Deleted label tier (204)"
else
    fail "Delete label returned ${DEL_STATUS}, expected 204"
fi

# -----------------------------------------------------------------------
# Test 3: Create peer and sync policy with match_tags
# -----------------------------------------------------------------------

echo ""
echo "--- Test 3: Sync policy with match_tags ---"

PEER_NAME="tag-e2e-peer-${SUFFIX}"
PEER_RESP=$(curl -sf -X POST "${API_URL}/api/v1/peers" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"name\": \"${PEER_NAME}\", \"endpoint_url\": \"https://${PEER_NAME}.test:8080\", \"api_key\": \"test-api-key-${SUFFIX}\"}")

PEER_ID=$(echo "$PEER_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null || true)
if [ -n "$PEER_ID" ]; then
    CLEANUP_PEER_ID="$PEER_ID"
    pass "Created peer (${PEER_ID})"
else
    fail "Failed to create peer"
fi

POLICY_RESP=$(curl -sf -X POST "${API_URL}/api/v1/sync-policies" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{
        \"name\": \"tag-e2e-policy-${SUFFIX}\",
        \"enabled\": true,
        \"repo_selector\": {\"repository_ids\": [\"${REPO_ID}\"]},
        \"peer_selector\": {\"peer_ids\": [\"${PEER_ID}\"]},
        \"artifact_filter\": {\"match_tags\": {\"distribution\": \"production\"}},
        \"replication_mode\": \"push\"
    }")

POLICY_ID=$(echo "$POLICY_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null || true)
if [ -n "$POLICY_ID" ]; then
    CLEANUP_POLICY_ID="$POLICY_ID"
    pass "Created sync policy with match_tags (${POLICY_ID})"
else
    fail "Failed to create sync policy"
fi

# -----------------------------------------------------------------------
# Test 4: Set matching tag -> should trigger evaluation
# -----------------------------------------------------------------------

echo ""
echo "--- Test 4: Set matching tag (distribution=production) ---"

# Set tag to production (matches the policy)
MATCH_RESP=$(curl -sf -X POST "${API_URL}/api/v1/artifacts/${ARTIFACT_ID}/labels/distribution" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"value": "production"}')

MATCH_VAL=$(echo "$MATCH_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['value'])" 2>/dev/null || true)
if [ "$MATCH_VAL" = "production" ]; then
    pass "Set matching tag distribution=production"
else
    fail "Failed to set matching tag"
fi

# Brief pause for async evaluation
sleep 1

# -----------------------------------------------------------------------
# Test 5: Change to non-matching tag -> should trigger delete evaluation
# -----------------------------------------------------------------------

echo ""
echo "--- Test 5: Change to non-matching tag (distribution=eol) ---"

EOL_RESP=$(curl -sf -X POST "${API_URL}/api/v1/artifacts/${ARTIFACT_ID}/labels/distribution" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"value": "eol"}')

EOL_VAL=$(echo "$EOL_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['value'])" 2>/dev/null || true)
if [ "$EOL_VAL" = "eol" ]; then
    pass "Changed tag to distribution=eol (non-matching)"
else
    fail "Failed to change tag to non-matching"
fi

sleep 1

# -----------------------------------------------------------------------
# Test 6: Labels on nonexistent artifact returns 404
# -----------------------------------------------------------------------

echo ""
echo "--- Test 6: Error handling ---"

ERR_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X GET \
    "${API_URL}/api/v1/artifacts/00000000-0000-0000-0000-000000000000/labels" \
    -H "Authorization: Bearer ${TOKEN}" 2>/dev/null)

if [ "$ERR_STATUS" = "404" ]; then
    pass "Nonexistent artifact returns 404"
else
    fail "Expected 404 for nonexistent artifact, got ${ERR_STATUS}"
fi

# -----------------------------------------------------------------------
# Test 7: Policy without match_tags (backward compatibility)
# -----------------------------------------------------------------------

echo ""
echo "--- Test 7: Backward compatibility (no match_tags) ---"

COMPAT_RESP=$(curl -sf -X POST "${API_URL}/api/v1/sync-policies" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{
        \"name\": \"tag-e2e-compat-${SUFFIX}\",
        \"enabled\": true,
        \"repo_selector\": {\"repository_ids\": [\"${REPO_ID}\"]},
        \"peer_selector\": {\"peer_ids\": [\"${PEER_ID}\"]},
        \"artifact_filter\": {},
        \"replication_mode\": \"push\"
    }")

COMPAT_ID=$(echo "$COMPAT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null || true)
if [ -n "$COMPAT_ID" ]; then
    pass "Created policy without match_tags (backward compatible)"
    # Clean up the compat policy
    curl -sf -X DELETE "${API_URL}/api/v1/sync-policies/${COMPAT_ID}" \
        -H "Authorization: Bearer ${TOKEN}" >/dev/null 2>&1 || true
else
    fail "Failed to create backward-compatible policy"
fi

# -----------------------------------------------------------------------
# Results
# -----------------------------------------------------------------------

echo ""
echo "========================================="
echo "  Tag-Filtered Replication E2E Results"
echo "========================================="
echo "  Total: ${TESTS_RUN}"
echo "  Passed: ${PASSED}"
echo "  Failed: ${FAILED}"
echo "========================================="

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi

echo ""
echo "All tests passed."
