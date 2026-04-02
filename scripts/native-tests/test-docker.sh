#!/bin/bash
# Docker Registry V2 (OCI Distribution Spec) E2E test
# Tests docker login, push, pull, and verification
set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-localhost:30080}"
REGISTRY_USER="${REGISTRY_USER:-admin}"
REGISTRY_PASS="${REGISTRY_PASS:-TestRunner!2026secure}"
REPO_KEY="${REPO_KEY:-test-docker}"
TEST_VERSION="1.0.$(date +%s)"
FAILURES=0
REGISTRY_SCHEME="${REGISTRY_SCHEME:-http}"
REGISTRY_BASE_URL="${REGISTRY_SCHEME}://$REGISTRY_URL"
HTTP_CODE_FORMAT="%{http_code}"

pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAILURES=$((FAILURES + 1)); }

echo "==> Docker Registry V2 E2E Test"
echo "Registry: $REGISTRY_URL"
echo "Version: $TEST_VERSION"
echo ""

# --------------------------------------------------------------------------
# 1. Test V2 version check (unauthenticated should return 401)
# --------------------------------------------------------------------------
echo "--- Test: V2 version check (unauthenticated) ---"
HTTP_CODE=$(curl -s -o /dev/null -w "$HTTP_CODE_FORMAT" "$REGISTRY_BASE_URL/v2/")
if [ "$HTTP_CODE" = "401" ]; then
    pass "GET /v2/ returns 401 without auth"
else
    fail "GET /v2/ returned $HTTP_CODE, expected 401"
fi

# Check WWW-Authenticate header
WWW_AUTH=$(curl -s -D - -o /dev/null "$REGISTRY_BASE_URL/v2/" | grep -i "www-authenticate" || true)
if echo "$WWW_AUTH" | grep -q "Bearer"; then
    pass "WWW-Authenticate header contains Bearer challenge"
else
    fail "WWW-Authenticate header missing or invalid: $WWW_AUTH"
fi

# --------------------------------------------------------------------------
# 2. Test token endpoint
# --------------------------------------------------------------------------
echo ""
echo "--- Test: Token endpoint ---"
TOKEN_RESP=$(curl -s -u "$REGISTRY_USER:$REGISTRY_PASS" "$REGISTRY_BASE_URL/v2/token")
TOKEN=$(echo "$TOKEN_RESP" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("token",""))' 2>/dev/null || echo "")
if [ -n "$TOKEN" ] && [ "$TOKEN" != "None" ]; then
    pass "Token endpoint returns JWT"
else
    fail "Token endpoint did not return a token: $TOKEN_RESP"
fi

# Test invalid credentials
BAD_CODE=$(curl -s -o /dev/null -w "$HTTP_CODE_FORMAT" -u "baduser:badpass" "$REGISTRY_BASE_URL/v2/token")
if [ "$BAD_CODE" = "401" ]; then
    pass "Token endpoint rejects invalid credentials"
else
    fail "Token endpoint returned $BAD_CODE for invalid credentials, expected 401"
fi

# --------------------------------------------------------------------------
# 3. Test authenticated V2 check
# --------------------------------------------------------------------------
echo ""
echo "--- Test: V2 version check (authenticated) ---"
AUTH_CODE=$(curl -s -o /dev/null -w "$HTTP_CODE_FORMAT" -H "Authorization: Bearer $TOKEN" "$REGISTRY_BASE_URL/v2/")
if [ "$AUTH_CODE" = "200" ]; then
    pass "GET /v2/ returns 200 with valid token"
else
    fail "GET /v2/ returned $AUTH_CODE with valid token, expected 200"
fi

# --------------------------------------------------------------------------
# 4. Test docker login
# --------------------------------------------------------------------------
echo ""
echo "--- Test: docker login ---"
docker logout "$REGISTRY_URL" 2>/dev/null || true
if echo "$REGISTRY_PASS" | docker login "$REGISTRY_URL" -u "$REGISTRY_USER" --password-stdin 2>/dev/null; then
    pass "docker login succeeded"
else
    fail "docker login failed"
fi

# --------------------------------------------------------------------------
# 5. Build and push a test image
# --------------------------------------------------------------------------
echo ""
echo "--- Test: docker push ---"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"; docker rmi "$IMAGE_NAME" 2>/dev/null || true' EXIT

cat > "$WORK_DIR/Dockerfile" << EOF
FROM alpine:3.19
LABEL version="$TEST_VERSION"
LABEL description="Docker V2 E2E test image"
RUN echo "Hello from E2E test! Version: $TEST_VERSION" > /hello.txt
CMD ["cat", "/hello.txt"]
EOF

IMAGE_NAME="$REGISTRY_URL/$REPO_KEY/e2e-test:$TEST_VERSION"
echo "  Building image: $IMAGE_NAME"
docker build -t "$IMAGE_NAME" "$WORK_DIR" -q >/dev/null 2>&1

echo "  Pushing image..."
if docker push "$IMAGE_NAME" 2>&1; then
    pass "docker push succeeded"
else
    fail "docker push failed"
fi

# --------------------------------------------------------------------------
# 6. Verify manifest exists via API
# --------------------------------------------------------------------------
echo ""
echo "--- Test: Verify manifest via API ---"
TOKEN=$(curl -s -u "$REGISTRY_USER:$REGISTRY_PASS" "$REGISTRY_BASE_URL/v2/token" | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])' 2>/dev/null)
MANIFEST_CODE=$(curl -s -o /dev/null -w "$HTTP_CODE_FORMAT" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
    "$REGISTRY_BASE_URL/v2/$REPO_KEY/e2e-test/manifests/$TEST_VERSION")
if [ "$MANIFEST_CODE" = "200" ]; then
    pass "Manifest GET returns 200"
else
    fail "Manifest GET returned $MANIFEST_CODE, expected 200"
fi

# HEAD request
MANIFEST_HEAD=$(curl -s -o /dev/null -w "$HTTP_CODE_FORMAT" --head \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
    "$REGISTRY_BASE_URL/v2/$REPO_KEY/e2e-test/manifests/$TEST_VERSION")
if [ "$MANIFEST_HEAD" = "200" ]; then
    pass "Manifest HEAD returns 200"
else
    fail "Manifest HEAD returned $MANIFEST_HEAD, expected 200"
fi

# --------------------------------------------------------------------------
# 7. Test docker pull (remove local first)
# --------------------------------------------------------------------------
echo ""
echo "--- Test: docker pull ---"
docker rmi "$IMAGE_NAME" 2>/dev/null || true

if docker pull "$IMAGE_NAME" 2>&1; then
    pass "docker pull succeeded"
else
    fail "docker pull failed"
fi

# --------------------------------------------------------------------------
# 8. Verify pulled image works
# --------------------------------------------------------------------------
echo ""
echo "--- Test: Verify pulled image ---"
OUTPUT=$(docker run --rm "$IMAGE_NAME" 2>&1)
if echo "$OUTPUT" | grep -q "$TEST_VERSION"; then
    pass "Pulled image runs correctly with expected output"
else
    fail "Pulled image output did not contain version: $OUTPUT"
fi

# --------------------------------------------------------------------------
# 9. Test pushing an existing real-world image
# --------------------------------------------------------------------------
echo ""
echo "--- Test: Push real-world image (alpine) ---"
ALPINE_IMAGE="$REGISTRY_URL/$REPO_KEY/alpine:3.19"
docker tag alpine:3.19 "$ALPINE_IMAGE" 2>/dev/null || docker pull alpine:3.19 && docker tag alpine:3.19 "$ALPINE_IMAGE"
if docker push "$ALPINE_IMAGE" 2>&1; then
    pass "Real-world image push succeeded"
else
    fail "Real-world image push failed"
fi
docker rmi "$ALPINE_IMAGE" 2>/dev/null || true

# --------------------------------------------------------------------------
# 10. Test non-existent manifest returns 404
# --------------------------------------------------------------------------
echo ""
echo "--- Test: Non-existent manifest returns 404 ---"
NOT_FOUND=$(curl -s -o /dev/null -w "$HTTP_CODE_FORMAT" \
    -H "Authorization: Bearer $TOKEN" \
    "$REGISTRY_BASE_URL/v2/$REPO_KEY/nonexistent/manifests/notreal")
if [ "$NOT_FOUND" = "404" ]; then
    pass "Non-existent manifest returns 404"
else
    fail "Non-existent manifest returned $NOT_FOUND, expected 404"
fi

# --------------------------------------------------------------------------
# 11. Test tags/list endpoint
# --------------------------------------------------------------------------
echo ""
echo "--- Test: Tags list ---"
# Refresh token
TOKEN=$(curl -s -u "$REGISTRY_USER:$REGISTRY_PASS" "$REGISTRY_BASE_URL/v2/token" | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])' 2>/dev/null)

TAGS_FULL=$(curl -s -w "\n%{http_code}" -H "Authorization: Bearer $TOKEN" \
    "$REGISTRY_BASE_URL/v2/$REPO_KEY/e2e-test/tags/list")
TAGS_CODE=$(echo "$TAGS_FULL" | tail -1)
TAGS_RESP=$(echo "$TAGS_FULL" | sed '$d')
if [[ "$TAGS_CODE" = "200" ]]; then
    pass "Tags list returns 200"
else
    fail "Tags list returned $TAGS_CODE, expected 200"
fi

# Verify response contains the pushed tag
if echo "$TAGS_RESP" | python3 -c "import sys,json; tags=json.load(sys.stdin)['tags']; assert '$TEST_VERSION' in tags" 2>/dev/null; then
    pass "Tags list contains pushed tag $TEST_VERSION"
else
    fail "Tags list does not contain expected tag: $TAGS_RESP"
fi

# Verify response has correct name field
if echo "$TAGS_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['name']=='e2e-test'" 2>/dev/null; then
    pass "Tags list has correct name field"
else
    fail "Tags list name field incorrect: $TAGS_RESP"
fi

# Test pagination with n=1
TAGS_PAGE=$(curl -s -D /tmp/tags_headers -H "Authorization: Bearer $TOKEN" \
    "$REGISTRY_BASE_URL/v2/$REPO_KEY/e2e-test/tags/list?n=1")
if ! PAGE_TAGS=$(echo "$TAGS_PAGE" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['tags']))" 2>/dev/null); then
    echo "error" >&2
    PAGE_TAGS="error"
fi
if [[ "$PAGE_TAGS" = "1" ]]; then
    pass "Tags list pagination returns exactly 1 tag with n=1"
else
    fail "Tags list pagination returned $PAGE_TAGS tags, expected 1"
fi

# Test n=0 returns empty
TAGS_ZERO=$(curl -s -H "Authorization: Bearer $TOKEN" \
    "$REGISTRY_BASE_URL/v2/$REPO_KEY/e2e-test/tags/list?n=0")
if ! ZERO_COUNT=$(echo "$TAGS_ZERO" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['tags']))" 2>/dev/null); then
    echo "error" >&2
    ZERO_COUNT="error"
fi
if [[ "$ZERO_COUNT" = "0" ]]; then
    pass "Tags list with n=0 returns empty list"
else
    fail "Tags list with n=0 returned $ZERO_COUNT tags, expected 0"
fi

# Test non-existent image returns 404
TAGS_404=$(curl -s -o /dev/null -w "$HTTP_CODE_FORMAT" -H "Authorization: Bearer $TOKEN" \
    "$REGISTRY_BASE_URL/v2/$REPO_KEY/nonexistent/tags/list")
if [[ "$TAGS_404" = "404" ]]; then
    pass "Tags list for non-existent image returns 404"
else
    fail "Tags list for non-existent image returned $TAGS_404, expected 404"
fi

# Test unauthenticated access returns 401
TAGS_NOAUTH=$(curl -s -o /dev/null -w "$HTTP_CODE_FORMAT" \
    "$REGISTRY_BASE_URL/v2/$REPO_KEY/e2e-test/tags/list")
if [[ "$TAGS_NOAUTH" = "401" ]]; then
    pass "Tags list without auth returns 401"
else
    fail "Tags list without auth returned $TAGS_NOAUTH, expected 401"
fi

# --------------------------------------------------------------------------
# 12. Test catalog endpoint
# --------------------------------------------------------------------------
echo ""
echo "--- Test: Catalog ---"
CATALOG_FULL=$(curl -s -w "\n%{http_code}" -H "Authorization: Bearer $TOKEN" \
    "$REGISTRY_BASE_URL/v2/_catalog")
CATALOG_CODE=$(echo "$CATALOG_FULL" | tail -1)
CATALOG_RESP=$(echo "$CATALOG_FULL" | sed '$d')
if [[ "$CATALOG_CODE" = "200" ]]; then
    pass "Catalog returns 200"
else
    fail "Catalog returned $CATALOG_CODE, expected 200"
fi

# Verify response contains the pushed image
if echo "$CATALOG_RESP" | python3 -c "import sys,json; repos=json.load(sys.stdin)['repositories']; assert any('e2e-test' in r for r in repos)" 2>/dev/null; then
    pass "Catalog contains e2e-test image"
else
    fail "Catalog does not contain e2e-test: $CATALOG_RESP"
fi

# Test catalog pagination with n=1
CATALOG_PAGE_CODE=$(curl -s -o /dev/null -w "$HTTP_CODE_FORMAT" -H "Authorization: Bearer $TOKEN" \
    "$REGISTRY_BASE_URL/v2/_catalog?n=1")
if [[ "$CATALOG_PAGE_CODE" = "200" ]]; then
    pass "Catalog pagination returns 200"
else
    fail "Catalog pagination returned $CATALOG_PAGE_CODE, expected 200"
fi

# Test catalog unauthenticated returns 401
CATALOG_NOAUTH=$(curl -s -o /dev/null -w "$HTTP_CODE_FORMAT" \
    "$REGISTRY_BASE_URL/v2/_catalog")
if [[ "$CATALOG_NOAUTH" = "401" ]]; then
    pass "Catalog without auth returns 401"
else
    fail "Catalog without auth returned $CATALOG_NOAUTH, expected 401"
fi

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
echo ""
echo "================================="
if [ "$FAILURES" -eq 0 ]; then
    echo "ALL DOCKER V2 TESTS PASSED"
    exit 0
else
    echo "$FAILURES TEST(S) FAILED"
    exit 1
fi
