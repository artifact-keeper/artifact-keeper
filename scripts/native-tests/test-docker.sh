#!/bin/bash
# Docker Registry V2 (OCI Distribution Spec) E2E test
# Tests docker login, push, pull, and verification
set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-localhost:30080}"
REGISTRY_USER="${REGISTRY_USER:-admin}"
REGISTRY_PASS="${REGISTRY_PASS:-admin123}"
REPO_KEY="${REPO_KEY:-test-docker}"
TEST_VERSION="1.0.$(date +%s)"
FAILURES=0

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
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://$REGISTRY_URL/v2/")
if [ "$HTTP_CODE" = "401" ]; then
    pass "GET /v2/ returns 401 without auth"
else
    fail "GET /v2/ returned $HTTP_CODE, expected 401"
fi

# Check WWW-Authenticate header
WWW_AUTH=$(curl -s -D - -o /dev/null "http://$REGISTRY_URL/v2/" | grep -i "www-authenticate" || true)
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
TOKEN_RESP=$(curl -s -u "$REGISTRY_USER:$REGISTRY_PASS" "http://$REGISTRY_URL/v2/token")
TOKEN=$(echo "$TOKEN_RESP" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("token",""))' 2>/dev/null || echo "")
if [ -n "$TOKEN" ] && [ "$TOKEN" != "None" ]; then
    pass "Token endpoint returns JWT"
else
    fail "Token endpoint did not return a token: $TOKEN_RESP"
fi

# Test invalid credentials
BAD_CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "baduser:badpass" "http://$REGISTRY_URL/v2/token")
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
AUTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "http://$REGISTRY_URL/v2/")
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
TOKEN=$(curl -s -u "$REGISTRY_USER:$REGISTRY_PASS" "http://$REGISTRY_URL/v2/token" | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])' 2>/dev/null)
MANIFEST_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
    "http://$REGISTRY_URL/v2/$REPO_KEY/e2e-test/manifests/$TEST_VERSION")
if [ "$MANIFEST_CODE" = "200" ]; then
    pass "Manifest GET returns 200"
else
    fail "Manifest GET returned $MANIFEST_CODE, expected 200"
fi

# HEAD request
MANIFEST_HEAD=$(curl -s -o /dev/null -w "%{http_code}" -X HEAD \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
    "http://$REGISTRY_URL/v2/$REPO_KEY/e2e-test/manifests/$TEST_VERSION")
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
NOT_FOUND=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN" \
    "http://$REGISTRY_URL/v2/$REPO_KEY/nonexistent/manifests/notreal")
if [ "$NOT_FOUND" = "404" ]; then
    pass "Non-existent manifest returns 404"
else
    fail "Non-existent manifest returned $NOT_FOUND, expected 404"
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
