#!/bin/bash
# Test script: Soft-deleted artifact re-upload (issue #321)
#
# Verifies that after an artifact is soft-deleted, re-uploading the same
# path succeeds instead of hitting UNIQUE(repository_id, path) constraint.
#
# Prerequisites: backend running at localhost:8080 with admin/admin credentials
set -euo pipefail

BACKEND_URL="${BACKEND_URL:-http://localhost:8080}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin}"

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0

pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    TOTAL=$((TOTAL + 1))
    echo "  PASS: $1"
}

fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    TOTAL=$((TOTAL + 1))
    echo "  FAIL: $1"
}

echo "============================================="
echo "  Soft-Delete Re-Upload Tests (Issue #321)"
echo "============================================="
echo "Backend: $BACKEND_URL"
echo ""

# ── Setup: Authenticate ─────────────────────────────────────────────

echo "--- Setup: Authenticating as $ADMIN_USER ---"
LOGIN_RESP=$(curl -sf -X POST "$BACKEND_URL/api/v1/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}")

TOKEN=$(echo "$LOGIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
if [ -z "$TOKEN" ]; then
    echo "FATAL: Failed to authenticate"
    exit 1
fi
echo "  Got JWT token"

# ── Setup: Create a test Maven repo ─────────────────────────────────

UNIQUE=$(date +%s)
REPO_KEY="test-reupload-$UNIQUE"

echo ""
echo "--- Setup: Creating test repository ---"
REPO_RESP=$(curl -sf -X POST "$BACKEND_URL/api/v1/repositories" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{
        \"key\": \"$REPO_KEY\",
        \"name\": \"Test Reupload $UNIQUE\",
        \"format\": \"maven\",
        \"repo_type\": \"local\",
        \"is_public\": true
    }")
echo "  Created repo: $REPO_KEY"

# ── Setup: Create a test JAR ────────────────────────────────────────

WORK_DIR=$(mktemp -d)
trap "rm -rf $WORK_DIR" EXIT

mkdir -p "$WORK_DIR/META-INF"
echo "Manifest-Version: 1.0" > "$WORK_DIR/META-INF/MANIFEST.MF"
echo "Created-By: test" >> "$WORK_DIR/META-INF/MANIFEST.MF"
(cd "$WORK_DIR" && zip -q test.jar META-INF/MANIFEST.MF)
JAR_PATH="$WORK_DIR/test.jar"

# ── Test 1: Maven upload, soft-delete, re-upload ────────────────────

echo ""
echo "--- Test 1: Maven artifact soft-delete then re-upload ---"

ARTIFACT_PATH="com/test/mylib/1.0/mylib-1.0.jar"

# Step 1a: Upload the artifact
UPLOAD1=$(curl -s -o /dev/null -w "%{http_code}" \
    -X PUT \
    -u "$ADMIN_USER:$ADMIN_PASS" \
    -H "Content-Type: application/java-archive" \
    --data-binary @"$JAR_PATH" \
    "$BACKEND_URL/maven/$REPO_KEY/$ARTIFACT_PATH")

if [ "$UPLOAD1" = "201" ] || [ "$UPLOAD1" = "200" ]; then
    pass "1a. Initial upload succeeds (HTTP $UPLOAD1)"
else
    fail "1a. Initial upload returned HTTP $UPLOAD1 (expected 200/201)"
fi

# Step 1b: Delete the artifact (soft-delete via API)
DEL_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X DELETE \
    -H "Authorization: Bearer $TOKEN" \
    "$BACKEND_URL/api/v1/repositories/$REPO_KEY/artifacts/$ARTIFACT_PATH")

if [ "$DEL_STATUS" = "200" ]; then
    pass "1b. Soft-delete succeeds (HTTP $DEL_STATUS)"
else
    fail "1b. Soft-delete returned HTTP $DEL_STATUS (expected 200)"
fi

# Step 1c: Re-upload the same artifact (this is the bug from #321)
UPLOAD2=$(curl -s -o /dev/null -w "%{http_code}" \
    -X PUT \
    -u "$ADMIN_USER:$ADMIN_PASS" \
    -H "Content-Type: application/java-archive" \
    --data-binary @"$JAR_PATH" \
    "$BACKEND_URL/maven/$REPO_KEY/$ARTIFACT_PATH")

if [ "$UPLOAD2" = "201" ] || [ "$UPLOAD2" = "200" ]; then
    pass "1c. Re-upload after soft-delete succeeds (HTTP $UPLOAD2)"
else
    fail "1c. Re-upload after soft-delete returned HTTP $UPLOAD2 (expected 200/201) -- THIS IS THE #321 BUG"
fi

# Step 1d: Verify the artifact is downloadable
DL_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    "$BACKEND_URL/maven/$REPO_KEY/$ARTIFACT_PATH")

if [ "$DL_STATUS" = "200" ]; then
    pass "1d. Re-uploaded artifact is downloadable (HTTP $DL_STATUS)"
else
    fail "1d. Re-uploaded artifact download returned HTTP $DL_STATUS (expected 200)"
fi

# ── Test 2: Double delete and re-upload ─────────────────────────────

echo ""
echo "--- Test 2: Double soft-delete then re-upload ---"

ARTIFACT_PATH2="com/test/mylib/2.0/mylib-2.0.jar"

# Upload
curl -s -o /dev/null -X PUT \
    -u "$ADMIN_USER:$ADMIN_PASS" \
    -H "Content-Type: application/java-archive" \
    --data-binary @"$JAR_PATH" \
    "$BACKEND_URL/maven/$REPO_KEY/$ARTIFACT_PATH2"

# Delete
curl -s -o /dev/null -X DELETE \
    -H "Authorization: Bearer $TOKEN" \
    "$BACKEND_URL/api/v1/repositories/$REPO_KEY/artifacts/$ARTIFACT_PATH2"

# Re-upload
curl -s -o /dev/null -X PUT \
    -u "$ADMIN_USER:$ADMIN_PASS" \
    -H "Content-Type: application/java-archive" \
    --data-binary @"$JAR_PATH" \
    "$BACKEND_URL/maven/$REPO_KEY/$ARTIFACT_PATH2"

# Delete again
DEL2=$(curl -s -o /dev/null -w "%{http_code}" \
    -X DELETE \
    -H "Authorization: Bearer $TOKEN" \
    "$BACKEND_URL/api/v1/repositories/$REPO_KEY/artifacts/$ARTIFACT_PATH2")

if [ "$DEL2" = "200" ]; then
    pass "2a. Second soft-delete succeeds (HTTP $DEL2)"
else
    fail "2a. Second soft-delete returned HTTP $DEL2 (expected 200)"
fi

# Re-upload a second time (two soft-deleted rows at the same path)
UPLOAD3=$(curl -s -o /dev/null -w "%{http_code}" \
    -X PUT \
    -u "$ADMIN_USER:$ADMIN_PASS" \
    -H "Content-Type: application/java-archive" \
    --data-binary @"$JAR_PATH" \
    "$BACKEND_URL/maven/$REPO_KEY/$ARTIFACT_PATH2")

if [ "$UPLOAD3" = "201" ] || [ "$UPLOAD3" = "200" ]; then
    pass "2b. Re-upload after two soft-deletes succeeds (HTTP $UPLOAD3)"
else
    fail "2b. Re-upload after two soft-deletes returned HTTP $UPLOAD3 (expected 200/201)"
fi

# ── Test 3: SNAPSHOT re-upload (mutable by design) ──────────────────

echo ""
echo "--- Test 3: Maven SNAPSHOT re-upload ---"

SNAPSHOT_PATH="com/test/mylib/1.0-SNAPSHOT/mylib-1.0-SNAPSHOT.jar"

# Upload SNAPSHOT
SNAP1=$(curl -s -o /dev/null -w "%{http_code}" \
    -X PUT \
    -u "$ADMIN_USER:$ADMIN_PASS" \
    -H "Content-Type: application/java-archive" \
    --data-binary @"$JAR_PATH" \
    "$BACKEND_URL/maven/$REPO_KEY/$SNAPSHOT_PATH")

if [ "$SNAP1" = "201" ] || [ "$SNAP1" = "200" ]; then
    pass "3a. SNAPSHOT initial upload succeeds (HTTP $SNAP1)"
else
    fail "3a. SNAPSHOT initial upload returned HTTP $SNAP1 (expected 200/201)"
fi

# Re-upload SNAPSHOT (should overwrite, not conflict)
SNAP2=$(curl -s -o /dev/null -w "%{http_code}" \
    -X PUT \
    -u "$ADMIN_USER:$ADMIN_PASS" \
    -H "Content-Type: application/java-archive" \
    --data-binary @"$JAR_PATH" \
    "$BACKEND_URL/maven/$REPO_KEY/$SNAPSHOT_PATH")

if [ "$SNAP2" = "201" ] || [ "$SNAP2" = "200" ]; then
    pass "3b. SNAPSHOT re-upload succeeds (HTTP $SNAP2)"
else
    fail "3b. SNAPSHOT re-upload returned HTTP $SNAP2 (expected 200/201)"
fi

# Soft-delete SNAPSHOT then re-upload
curl -s -o /dev/null -X DELETE \
    -H "Authorization: Bearer $TOKEN" \
    "$BACKEND_URL/api/v1/repositories/$REPO_KEY/artifacts/$SNAPSHOT_PATH"

SNAP3=$(curl -s -o /dev/null -w "%{http_code}" \
    -X PUT \
    -u "$ADMIN_USER:$ADMIN_PASS" \
    -H "Content-Type: application/java-archive" \
    --data-binary @"$JAR_PATH" \
    "$BACKEND_URL/maven/$REPO_KEY/$SNAPSHOT_PATH")

if [ "$SNAP3" = "201" ] || [ "$SNAP3" = "200" ]; then
    pass "3c. SNAPSHOT re-upload after soft-delete succeeds (HTTP $SNAP3)"
else
    fail "3c. SNAPSHOT re-upload after soft-delete returned HTTP $SNAP3 (expected 200/201)"
fi

# ── Test 4: Non-SNAPSHOT re-upload should still CONFLICT ────────────

echo ""
echo "--- Test 4: Non-SNAPSHOT duplicate still returns CONFLICT ---"

RELEASE_PATH="com/test/mylib/3.0/mylib-3.0.jar"

curl -s -o /dev/null -X PUT \
    -u "$ADMIN_USER:$ADMIN_PASS" \
    -H "Content-Type: application/java-archive" \
    --data-binary @"$JAR_PATH" \
    "$BACKEND_URL/maven/$REPO_KEY/$RELEASE_PATH"

DUP=$(curl -s -o /dev/null -w "%{http_code}" \
    -X PUT \
    -u "$ADMIN_USER:$ADMIN_PASS" \
    -H "Content-Type: application/java-archive" \
    --data-binary @"$JAR_PATH" \
    "$BACKEND_URL/maven/$REPO_KEY/$RELEASE_PATH")

if [ "$DUP" = "409" ]; then
    pass "4a. Non-SNAPSHOT duplicate correctly returns CONFLICT (HTTP $DUP)"
else
    fail "4a. Non-SNAPSHOT duplicate returned HTTP $DUP (expected 409)"
fi

# ── Cleanup ─────────────────────────────────────────────────────────

echo ""
echo "--- Cleanup: Deleting test repo ---"
curl -sf -X DELETE "$BACKEND_URL/api/v1/repositories/$REPO_KEY" \
    -H "Authorization: Bearer $TOKEN" > /dev/null 2>&1 && echo "  Deleted $REPO_KEY" || echo "  Warning: failed to delete $REPO_KEY"

# ── Summary ─────────────────────────────────────────────────────────

echo ""
echo "============================================="
echo "  Results: $PASS_COUNT passed, $FAIL_COUNT failed (of $TOTAL)"
echo "============================================="

if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
echo "All soft-delete re-upload tests PASSED"
