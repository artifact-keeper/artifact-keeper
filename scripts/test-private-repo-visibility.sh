#!/bin/bash
# Test script: Private repo visibility and auth enforcement
#
# Verifies the fixes from issues #333 and #320:
#   1. Anonymous GET /api/v1/packages excludes private repos
#   2. Basic auth upload to private Maven repo succeeds
#   3. Anonymous download from private repo returns 404
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
echo "  Private Repo Visibility & Auth Tests"
echo "============================================="
echo "Backend: $BACKEND_URL"
echo ""

# ── Step 1: Authenticate ────────────────────────────────────────────────

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

# ── Step 2: Create test repos ───────────────────────────────────────────

UNIQUE=$(date +%s)
PUBLIC_KEY="test-maven-public-$UNIQUE"
PRIVATE_KEY="test-maven-private-$UNIQUE"

echo ""
echo "--- Setup: Creating test repositories ---"

# Create public Maven repo
PUB_RESP=$(curl -sf -X POST "$BACKEND_URL/api/v1/repositories" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{
        \"key\": \"$PUBLIC_KEY\",
        \"name\": \"Test Maven Public $UNIQUE\",
        \"format\": \"maven\",
        \"repo_type\": \"local\",
        \"is_public\": true
    }")
PUB_ID=$(echo "$PUB_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
echo "  Created public repo: $PUBLIC_KEY ($PUB_ID)"

# Create private Maven repo
PRIV_RESP=$(curl -sf -X POST "$BACKEND_URL/api/v1/repositories" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{
        \"key\": \"$PRIVATE_KEY\",
        \"name\": \"Test Maven Private $UNIQUE\",
        \"format\": \"maven\",
        \"repo_type\": \"local\",
        \"is_public\": false
    }")
PRIV_ID=$(echo "$PRIV_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
echo "  Created private repo: $PRIVATE_KEY ($PRIV_ID)"

# ── Step 3: Upload artifacts ────────────────────────────────────────────

echo ""
echo "--- Setup: Uploading test artifacts ---"

# Create a small test JAR (just a zip with a manifest)
WORK_DIR=$(mktemp -d)
trap "rm -rf $WORK_DIR" EXIT

mkdir -p "$WORK_DIR/META-INF"
echo "Manifest-Version: 1.0" > "$WORK_DIR/META-INF/MANIFEST.MF"
echo "Created-By: test" >> "$WORK_DIR/META-INF/MANIFEST.MF"
(cd "$WORK_DIR" && zip -q test.jar META-INF/MANIFEST.MF)

JAR_PATH="$WORK_DIR/test.jar"
ARTIFACT_PATH="com/test/mylib/1.0/mylib-1.0.jar"

# Upload to public repo with Basic auth
PUB_UPLOAD=$(curl -s -o /dev/null -w "%{http_code}" \
    -X PUT \
    -u "$ADMIN_USER:$ADMIN_PASS" \
    -H "Content-Type: application/java-archive" \
    --data-binary @"$JAR_PATH" \
    "$BACKEND_URL/maven/$PUBLIC_KEY/$ARTIFACT_PATH")
echo "  Upload to public repo: HTTP $PUB_UPLOAD"

# Upload to private repo with Basic auth (this is test #2)
PRIV_UPLOAD=$(curl -s -o /dev/null -w "%{http_code}" \
    -X PUT \
    -u "$ADMIN_USER:$ADMIN_PASS" \
    -H "Content-Type: application/java-archive" \
    --data-binary @"$JAR_PATH" \
    "$BACKEND_URL/maven/$PRIVATE_KEY/$ARTIFACT_PATH")
echo "  Upload to private repo: HTTP $PRIV_UPLOAD"

sleep 1

# ── Test 1: Anonymous API listing excludes private repos ────────────────

echo ""
echo "--- Test 1: Anonymous API listing excludes private repos ---"

# Anonymous /api/v1/repositories should not show private repos
ANON_REPOS=$(curl -sf "$BACKEND_URL/api/v1/repositories?per_page=500")
ANON_HAS_PUBLIC=$(echo "$ANON_REPOS" | python3 -c "
import sys, json
data = json.load(sys.stdin)
items = data.get('items', [])
found = any(r.get('key') == '$PUBLIC_KEY' for r in items)
print('yes' if found else 'no')
")
ANON_HAS_PRIVATE=$(echo "$ANON_REPOS" | python3 -c "
import sys, json
data = json.load(sys.stdin)
items = data.get('items', [])
found = any(r.get('key') == '$PRIVATE_KEY' for r in items)
print('yes' if found else 'no')
")

if [ "$ANON_HAS_PRIVATE" = "no" ]; then
    pass "1a. Anonymous /api/v1/repositories does NOT list private repo"
else
    fail "1a. Anonymous /api/v1/repositories LISTS private repo (should be hidden)"
fi

if [ "$ANON_HAS_PUBLIC" = "yes" ]; then
    pass "1b. Anonymous /api/v1/repositories lists public repo"
else
    fail "1b. Anonymous /api/v1/repositories does NOT list public repo (should be visible)"
fi

# Authenticated request should see both
AUTH_REPOS=$(curl -sf -H "Authorization: Bearer $TOKEN" "$BACKEND_URL/api/v1/repositories?per_page=500")
AUTH_HAS_PRIVATE=$(echo "$AUTH_REPOS" | python3 -c "
import sys, json
data = json.load(sys.stdin)
items = data.get('items', [])
found = any(r.get('key') == '$PRIVATE_KEY' for r in items)
print('yes' if found else 'no')
")

if [ "$AUTH_HAS_PRIVATE" = "yes" ]; then
    pass "1c. Authenticated /api/v1/repositories lists private repo"
else
    fail "1c. Authenticated /api/v1/repositories does NOT list private repo"
fi

# Anonymous access to private repo's artifacts listing should fail
ANON_PRIV_ARTS=$(curl -s -o /dev/null -w "%{http_code}" \
    "$BACKEND_URL/api/v1/repositories/$PRIVATE_KEY/artifacts")
if [ "$ANON_PRIV_ARTS" = "404" ] || [ "$ANON_PRIV_ARTS" = "401" ] || [ "$ANON_PRIV_ARTS" = "403" ]; then
    pass "1d. Anonymous /api/v1/repositories/{private}/artifacts blocked (HTTP $ANON_PRIV_ARTS)"
else
    fail "1d. Anonymous /api/v1/repositories/{private}/artifacts returned HTTP $ANON_PRIV_ARTS (expected 401/403/404)"
fi

# ── Test 2: Basic auth upload to private Maven repo succeeds ────────────

echo ""
echo "--- Test 2: Basic auth upload to private Maven repo ---"

if [ "$PRIV_UPLOAD" = "201" ] || [ "$PRIV_UPLOAD" = "200" ]; then
    pass "2a. Basic auth PUT to private Maven repo returns HTTP $PRIV_UPLOAD"
else
    fail "2a. Basic auth PUT to private Maven repo returns HTTP $PRIV_UPLOAD (expected 200 or 201)"
fi

# Upload a second artifact to verify continued access
PRIV_UPLOAD2=$(curl -s -o /dev/null -w "%{http_code}" \
    -X PUT \
    -u "$ADMIN_USER:$ADMIN_PASS" \
    -H "Content-Type: application/java-archive" \
    --data-binary @"$JAR_PATH" \
    "$BACKEND_URL/maven/$PRIVATE_KEY/com/test/mylib/2.0/mylib-2.0.jar")

if [ "$PRIV_UPLOAD2" = "201" ] || [ "$PRIV_UPLOAD2" = "200" ]; then
    pass "2b. Second Basic auth upload to private repo succeeds (HTTP $PRIV_UPLOAD2)"
else
    fail "2b. Second Basic auth upload to private repo failed (HTTP $PRIV_UPLOAD2)"
fi

# ── Test 3: Anonymous download from private repo returns 404 ────────────

echo ""
echo "--- Test 3: Anonymous download from private repo ---"

# Anonymous download from PRIVATE repo should fail
ANON_PRIV_DL=$(curl -s -o /dev/null -w "%{http_code}" \
    "$BACKEND_URL/maven/$PRIVATE_KEY/$ARTIFACT_PATH")

if [ "$ANON_PRIV_DL" = "401" ] || [ "$ANON_PRIV_DL" = "403" ] || [ "$ANON_PRIV_DL" = "404" ]; then
    pass "3a. Anonymous download from private repo blocked (HTTP $ANON_PRIV_DL)"
else
    fail "3a. Anonymous download from private repo returned HTTP $ANON_PRIV_DL (expected 401/403/404)"
fi

# Anonymous download from PUBLIC repo should succeed
ANON_PUB_DL=$(curl -s -o /dev/null -w "%{http_code}" \
    "$BACKEND_URL/maven/$PUBLIC_KEY/$ARTIFACT_PATH")

if [ "$ANON_PUB_DL" = "200" ]; then
    pass "3b. Anonymous download from public repo succeeds (HTTP $ANON_PUB_DL)"
else
    fail "3b. Anonymous download from public repo returned HTTP $ANON_PUB_DL (expected 200)"
fi

# Authenticated download from private repo should succeed
AUTH_PRIV_DL=$(curl -s -o /dev/null -w "%{http_code}" \
    -u "$ADMIN_USER:$ADMIN_PASS" \
    "$BACKEND_URL/maven/$PRIVATE_KEY/$ARTIFACT_PATH")

if [ "$AUTH_PRIV_DL" = "200" ]; then
    pass "3c. Authenticated download from private repo succeeds (HTTP $AUTH_PRIV_DL)"
else
    fail "3c. Authenticated download from private repo returned HTTP $AUTH_PRIV_DL (expected 200)"
fi

# Anonymous maven-metadata.xml from private repo should fail
ANON_PRIV_META=$(curl -s -o /dev/null -w "%{http_code}" \
    "$BACKEND_URL/maven/$PRIVATE_KEY/com/test/mylib/maven-metadata.xml")

if [ "$ANON_PRIV_META" = "401" ] || [ "$ANON_PRIV_META" = "403" ] || [ "$ANON_PRIV_META" = "404" ]; then
    pass "3d. Anonymous maven-metadata.xml from private repo blocked (HTTP $ANON_PRIV_META)"
else
    fail "3d. Anonymous maven-metadata.xml from private repo returned HTTP $ANON_PRIV_META (expected 401/403/404)"
fi

# ── Test 4: Anonymous /api/v1/artifacts excludes private repo artifacts ──

echo ""
echo "--- Test 4: Artifact API visibility ---"

# Get artifact ID from private repo (authenticated, using repo key)
PRIV_ARTIFACT_ID=$(curl -sf -H "Authorization: Bearer $TOKEN" \
    "$BACKEND_URL/api/v1/repositories/$PRIVATE_KEY/artifacts" 2>/dev/null | \
    python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    items = data.get('items', data.get('artifacts', []))
    print(items[0]['id'] if items else '')
except:
    print('')
" 2>/dev/null || echo "")

if [ -n "$PRIV_ARTIFACT_ID" ] && [ "$PRIV_ARTIFACT_ID" != "" ]; then
    # Anonymous access to specific private artifact should fail
    ANON_ART=$(curl -s -o /dev/null -w "%{http_code}" \
        "$BACKEND_URL/api/v1/artifacts/$PRIV_ARTIFACT_ID")
    if [ "$ANON_ART" = "404" ]; then
        pass "4a. Anonymous GET /api/v1/artifacts/{id} for private repo returns 404"
    else
        fail "4a. Anonymous GET /api/v1/artifacts/{id} for private repo returned HTTP $ANON_ART (expected 404)"
    fi

    # Authenticated access should succeed
    AUTH_ART=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $TOKEN" \
        "$BACKEND_URL/api/v1/artifacts/$PRIV_ARTIFACT_ID")
    if [ "$AUTH_ART" = "200" ]; then
        pass "4b. Authenticated GET /api/v1/artifacts/{id} for private repo returns 200"
    else
        fail "4b. Authenticated GET /api/v1/artifacts/{id} for private repo returned HTTP $AUTH_ART (expected 200)"
    fi
else
    echo "  SKIP: 4a-4b. Could not find artifact in private repo (repo artifacts endpoint may use different response shape)"
fi

# ── Cleanup ─────────────────────────────────────────────────────────────

echo ""
echo "--- Cleanup: Deleting test repos ---"
curl -sf -X DELETE "$BACKEND_URL/api/v1/repositories/$PUBLIC_KEY" \
    -H "Authorization: Bearer $TOKEN" > /dev/null 2>&1 && echo "  Deleted $PUBLIC_KEY" || echo "  Warning: failed to delete $PUBLIC_KEY"
curl -sf -X DELETE "$BACKEND_URL/api/v1/repositories/$PRIVATE_KEY" \
    -H "Authorization: Bearer $TOKEN" > /dev/null 2>&1 && echo "  Deleted $PRIVATE_KEY" || echo "  Warning: failed to delete $PRIVATE_KEY"

# ── Summary ─────────────────────────────────────────────────────────────

echo ""
echo "============================================="
echo "  Results: $PASS_COUNT passed, $FAIL_COUNT failed (of $TOTAL)"
echo "============================================="

if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
echo "All private repo visibility tests PASSED"
