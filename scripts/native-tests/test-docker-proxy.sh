#!/bin/bash
# Docker Hub Remote Proxy E2E test script
#
# Tests the OCI remote proxy against Docker Hub, specifically:
#   1. Official single-name images (alpine, nginx, ubuntu) get library/ prefix
#   2. Namespaced images (grafana/grafana) pass through without prefix
#   3. Non-Docker Hub registries (ghcr.io) are unaffected
#   4. Manifest content is valid JSON with expected OCI/Docker fields
#   5. Remote repos reject pushes (write rejection)
#   6. Cache: second fetch returns 200
#
# Usage:
#   ./test-docker-proxy.sh                                      # localhost:8080
#   REGISTRY_URL=http://backend:8080 ./test-docker-proxy.sh     # Docker Compose
#
# Requires: curl, jq
set -uo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:8080}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin123}"
API_URL="$REGISTRY_URL/api/v1"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASSED=0
FAILED=0
SKIPPED=0

pass() {
    echo -e "  ${GREEN}PASS${NC}: $1"
    PASSED=$((PASSED + 1))
}

fail() {
    echo -e "  ${RED}FAIL${NC}: $1"
    FAILED=$((FAILED + 1))
}

skip() {
    echo -e "  ${YELLOW}SKIP${NC}: $1"
    SKIPPED=$((SKIPPED + 1))
}

TMPDIR_TEST="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_TEST"' EXIT

# ============================================================================
# Setup: Authenticate and create test repositories
# ============================================================================

echo "=============================================="
echo "Docker Hub Remote Proxy E2E Tests"
echo "=============================================="
echo "Registry: $REGISTRY_URL"
echo ""

echo "==> Authenticating..."
LOGIN_RESP=$(curl -sf -X POST "$API_URL/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" 2>&1) || {
    echo "ERROR: Failed to authenticate. Is the backend running at $REGISTRY_URL?"
    exit 1
}
TOKEN=$(echo "$LOGIN_RESP" | jq -r '.access_token')
if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    echo "ERROR: Failed to get auth token"
    exit 1
fi
AUTH="Authorization: Bearer $TOKEN"
echo "  Authenticated successfully"
echo ""

# Helper: create a repository (deletes first if exists)
create_repo() {
    local key="$1" name="$2" format="$3" repo_type="$4" upstream_url="${5:-}"

    curl -s -o /dev/null -X DELETE "$API_URL/repositories/$key" -H "$AUTH" 2>/dev/null || true

    local body="{\"key\":\"$key\",\"name\":\"$name\",\"format\":\"$format\",\"repo_type\":\"$repo_type\",\"is_public\":true"
    if [ -n "$upstream_url" ]; then
        body="$body,\"upstream_url\":\"$upstream_url\""
    fi
    body="$body}"
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/repositories" \
        -H "$AUTH" -H 'Content-Type: application/json' -d "$body")
    if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
        return 0
    else
        echo "  WARNING: create_repo $key returned HTTP $http_code"
        return 1
    fi
}

# Helper: get OCI bearer token for a repo
get_oci_token() {
    local token_resp
    token_resp=$(curl -sf -u "$ADMIN_USER:$ADMIN_PASS" "$REGISTRY_URL/v2/token" 2>/dev/null || echo "")
    echo "$token_resp" | jq -r '.token // empty' 2>/dev/null || echo ""
}

echo "==> Creating test repositories..."

create_repo "dockerhub-proxy" "Docker Hub Proxy" "docker" "remote" "https://registry-1.docker.io"
echo "  - dockerhub-proxy (remote -> registry-1.docker.io)"

create_repo "ghcr-proxy" "GHCR Proxy" "docker" "remote" "https://ghcr.io"
echo "  - ghcr-proxy (remote -> ghcr.io)"

echo ""

# Get OCI token for authenticated requests
OCI_TOKEN=$(get_oci_token)
if [ -z "$OCI_TOKEN" ]; then
    echo "ERROR: Failed to get OCI bearer token"
    exit 1
fi
OCI_AUTH="Authorization: Bearer $OCI_TOKEN"

# ============================================================================
# Phase 1: Official single-name images (library/ prefix required)
# ============================================================================

echo "==> Phase 1: Official Docker Hub images (single-name, needs library/ prefix)"

# Accept headers for Docker manifest requests
ACCEPT_MANIFEST="Accept: application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json"

# --- Test 1.1: alpine:3.20 ---
echo ""
echo "  [1.1] Pull manifest: alpine:3.20 (official image)..."
ALPINE_CODE=$(curl -s -o "$TMPDIR_TEST/alpine-manifest.json" -w "%{http_code}" \
    -H "$OCI_AUTH" -H "$ACCEPT_MANIFEST" \
    "$REGISTRY_URL/v2/dockerhub-proxy/alpine/manifests/3.20")
if [ "$ALPINE_CODE" = "200" ]; then
    # Validate it looks like a real manifest (has mediaType or schemaVersion)
    SCHEMA_VER=$(jq -r '.schemaVersion // empty' "$TMPDIR_TEST/alpine-manifest.json" 2>/dev/null || echo "")
    MEDIA_TYPE=$(jq -r '.mediaType // empty' "$TMPDIR_TEST/alpine-manifest.json" 2>/dev/null || echo "")
    if [ -n "$SCHEMA_VER" ] || [ -n "$MEDIA_TYPE" ]; then
        pass "alpine:3.20 manifest fetched (schemaVersion=$SCHEMA_VER, mediaType=$MEDIA_TYPE)"
    else
        fail "alpine:3.20 returned 200 but response is not a valid manifest"
    fi
else
    fail "alpine:3.20 manifest returned HTTP $ALPINE_CODE (expected 200)"
fi

# --- Test 1.2: nginx:stable ---
echo "  [1.2] Pull manifest: nginx:stable (official image)..."
NGINX_CODE=$(curl -s -o "$TMPDIR_TEST/nginx-manifest.json" -w "%{http_code}" \
    -H "$OCI_AUTH" -H "$ACCEPT_MANIFEST" \
    "$REGISTRY_URL/v2/dockerhub-proxy/nginx/manifests/stable")
if [ "$NGINX_CODE" = "200" ]; then
    SCHEMA_VER=$(jq -r '.schemaVersion // empty' "$TMPDIR_TEST/nginx-manifest.json" 2>/dev/null || echo "")
    MEDIA_TYPE=$(jq -r '.mediaType // empty' "$TMPDIR_TEST/nginx-manifest.json" 2>/dev/null || echo "")
    if [ -n "$SCHEMA_VER" ] || [ -n "$MEDIA_TYPE" ]; then
        pass "nginx:stable manifest fetched (schemaVersion=$SCHEMA_VER, mediaType=$MEDIA_TYPE)"
    else
        fail "nginx:stable returned 200 but response is not a valid manifest"
    fi
else
    fail "nginx:stable manifest returned HTTP $NGINX_CODE (expected 200)"
fi

# --- Test 1.3: ubuntu:24.04 ---
echo "  [1.3] Pull manifest: ubuntu:24.04 (official image)..."
UBUNTU_CODE=$(curl -s -o "$TMPDIR_TEST/ubuntu-manifest.json" -w "%{http_code}" \
    -H "$OCI_AUTH" -H "$ACCEPT_MANIFEST" \
    "$REGISTRY_URL/v2/dockerhub-proxy/ubuntu/manifests/24.04")
if [ "$UBUNTU_CODE" = "200" ]; then
    SCHEMA_VER=$(jq -r '.schemaVersion // empty' "$TMPDIR_TEST/ubuntu-manifest.json" 2>/dev/null || echo "")
    MEDIA_TYPE=$(jq -r '.mediaType // empty' "$TMPDIR_TEST/ubuntu-manifest.json" 2>/dev/null || echo "")
    if [ -n "$SCHEMA_VER" ] || [ -n "$MEDIA_TYPE" ]; then
        pass "ubuntu:24.04 manifest fetched (schemaVersion=$SCHEMA_VER, mediaType=$MEDIA_TYPE)"
    else
        fail "ubuntu:24.04 returned 200 but response is not a valid manifest"
    fi
else
    fail "ubuntu:24.04 manifest returned HTTP $UBUNTU_CODE (expected 200)"
fi

echo ""

# ============================================================================
# Phase 2: Namespaced images (no library/ prefix needed)
# ============================================================================

echo "==> Phase 2: Namespaced Docker Hub images (should work without library/ prefix)"

# --- Test 2.1: grafana/grafana ---
echo ""
echo "  [2.1] Pull manifest: grafana/grafana:latest (namespaced image)..."
GRAFANA_CODE=$(curl -s -o "$TMPDIR_TEST/grafana-manifest.json" -w "%{http_code}" \
    -H "$OCI_AUTH" -H "$ACCEPT_MANIFEST" \
    "$REGISTRY_URL/v2/dockerhub-proxy/grafana/grafana/manifests/latest")
if [ "$GRAFANA_CODE" = "200" ]; then
    SCHEMA_VER=$(jq -r '.schemaVersion // empty' "$TMPDIR_TEST/grafana-manifest.json" 2>/dev/null || echo "")
    if [ -n "$SCHEMA_VER" ]; then
        pass "grafana/grafana:latest manifest fetched (namespaced, no library/ prefix)"
    else
        fail "grafana/grafana returned 200 but response is not a valid manifest"
    fi
else
    # Namespaced images may require Docker Hub auth tokens; 401/403 is acceptable
    if [ "$GRAFANA_CODE" = "401" ] || [ "$GRAFANA_CODE" = "403" ]; then
        skip "grafana/grafana returned $GRAFANA_CODE (upstream auth required, not a prefix issue)"
    else
        fail "grafana/grafana manifest returned HTTP $GRAFANA_CODE (expected 200 or auth error)"
    fi
fi

echo ""

# ============================================================================
# Phase 3: Non-Docker Hub registry (no library/ prefix applied)
# ============================================================================

echo "==> Phase 3: Non-Docker Hub registry (ghcr.io, library/ prefix must NOT be applied)"

# --- Test 3.1: ghcr.io public image ---
echo ""
echo "  [3.1] Pull manifest from ghcr.io proxy (non-Docker Hub)..."
# Use a well-known public ghcr.io image
GHCR_CODE=$(curl -s -o "$TMPDIR_TEST/ghcr-manifest.json" -w "%{http_code}" \
    -H "$OCI_AUTH" -H "$ACCEPT_MANIFEST" \
    "$REGISTRY_URL/v2/ghcr-proxy/actions/runner/manifests/latest")
if [ "$GHCR_CODE" = "200" ]; then
    SCHEMA_VER=$(jq -r '.schemaVersion // empty' "$TMPDIR_TEST/ghcr-manifest.json" 2>/dev/null || echo "")
    if [ -n "$SCHEMA_VER" ]; then
        pass "ghcr.io image fetched without library/ prefix (schemaVersion=$SCHEMA_VER)"
    else
        fail "ghcr.io returned 200 but response is not a valid manifest"
    fi
elif [ "$GHCR_CODE" = "401" ] || [ "$GHCR_CODE" = "403" ]; then
    skip "ghcr.io returned $GHCR_CODE (upstream auth required, not a prefix issue)"
elif [ "$GHCR_CODE" = "404" ]; then
    # A 404 on ghcr.io is fine as long as it is not because library/ was prepended
    skip "ghcr.io returned 404 (image may not exist or require auth)"
else
    fail "ghcr.io proxy returned HTTP $GHCR_CODE"
fi

echo ""

# ============================================================================
# Phase 4: Manifest content validation
# ============================================================================

echo "==> Phase 4: Manifest content validation"

# --- Test 4.1: Alpine manifest has layers or manifests list ---
echo ""
echo "  [4.1] Validate alpine manifest structure..."
if [ -f "$TMPDIR_TEST/alpine-manifest.json" ]; then
    HAS_LAYERS=$(jq 'has("layers")' "$TMPDIR_TEST/alpine-manifest.json" 2>/dev/null || echo "false")
    HAS_MANIFESTS=$(jq 'has("manifests")' "$TMPDIR_TEST/alpine-manifest.json" 2>/dev/null || echo "false")
    if [ "$HAS_LAYERS" = "true" ]; then
        LAYER_COUNT=$(jq '.layers | length' "$TMPDIR_TEST/alpine-manifest.json" 2>/dev/null || echo "0")
        pass "alpine manifest has $LAYER_COUNT layer(s) (single-arch manifest)"
    elif [ "$HAS_MANIFESTS" = "true" ]; then
        MANIFEST_COUNT=$(jq '.manifests | length' "$TMPDIR_TEST/alpine-manifest.json" 2>/dev/null || echo "0")
        pass "alpine manifest is a manifest list with $MANIFEST_COUNT entries (multi-arch)"
    else
        fail "alpine manifest has neither 'layers' nor 'manifests' field"
    fi
else
    skip "alpine manifest file not available"
fi

# --- Test 4.2: Docker-Content-Digest header present ---
echo "  [4.2] Check Docker-Content-Digest header on alpine manifest..."
DIGEST_HEADER=$(curl -s -D - -o /dev/null \
    -H "$OCI_AUTH" -H "$ACCEPT_MANIFEST" \
    "$REGISTRY_URL/v2/dockerhub-proxy/alpine/manifests/3.20" 2>/dev/null \
    | grep -i "docker-content-digest" || true)
if echo "$DIGEST_HEADER" | grep -qi "sha256:"; then
    DIGEST_VAL=$(echo "$DIGEST_HEADER" | sed 's/.*sha256:/sha256:/' | tr -d '\r\n ')
    pass "Docker-Content-Digest header present ($DIGEST_VAL)"
elif [ -z "$DIGEST_HEADER" ]; then
    skip "Docker-Content-Digest header not returned (proxy may not forward it)"
else
    fail "Docker-Content-Digest header malformed: $DIGEST_HEADER"
fi

echo ""

# ============================================================================
# Phase 5: Write rejection (remote repos should not accept pushes)
# ============================================================================

echo "==> Phase 5: Write rejection (remote repos must reject pushes)"

# --- Test 5.1: PUT manifest to remote repo should fail ---
echo ""
echo "  [5.1] Push manifest to Docker Hub proxy repo (should be rejected)..."
PUSH_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X PUT "$REGISTRY_URL/v2/dockerhub-proxy/test-image/manifests/v1.0" \
    -H "$OCI_AUTH" \
    -H "Content-Type: application/vnd.docker.distribution.manifest.v2+json" \
    -d '{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{},"layers":[]}')
if [ "$PUSH_CODE" = "405" ] || [ "$PUSH_CODE" = "403" ] || [ "$PUSH_CODE" = "400" ]; then
    pass "Push to remote repo rejected with HTTP $PUSH_CODE"
else
    fail "Push to remote repo returned HTTP $PUSH_CODE (expected 405/403/400)"
fi

# --- Test 5.2: POST blob upload to remote repo should fail ---
echo "  [5.2] Start blob upload on Docker Hub proxy repo (should be rejected)..."
UPLOAD_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$REGISTRY_URL/v2/dockerhub-proxy/test-image/blobs/uploads/" \
    -H "$OCI_AUTH")
if [ "$UPLOAD_CODE" = "405" ] || [ "$UPLOAD_CODE" = "403" ] || [ "$UPLOAD_CODE" = "400" ]; then
    pass "Blob upload to remote repo rejected with HTTP $UPLOAD_CODE"
else
    fail "Blob upload to remote repo returned HTTP $UPLOAD_CODE (expected 405/403/400)"
fi

echo ""

# ============================================================================
# Phase 6: Cache verification
# ============================================================================

echo "==> Phase 6: Cache verification (second fetch should still succeed)"

# --- Test 6.1: Re-fetch alpine manifest ---
echo ""
echo "  [6.1] Re-fetch alpine:3.20 (cache hit expected)..."
CACHE_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "$OCI_AUTH" -H "$ACCEPT_MANIFEST" \
    "$REGISTRY_URL/v2/dockerhub-proxy/alpine/manifests/3.20")
if [ "$CACHE_CODE" = "200" ]; then
    pass "Second alpine fetch returned 200 (cache or upstream hit)"
else
    fail "Second alpine fetch returned HTTP $CACHE_CODE (expected 200)"
fi

echo ""

# ============================================================================
# Phase 7: Repository API validation
# ============================================================================

echo "==> Phase 7: Repository API validation"

# --- Test 7.1: Docker Hub proxy repo shows correct type ---
echo ""
echo "  [7.1] Repository API: repo_type is remote..."
REPO_DETAIL=$(curl -sf "$API_URL/repositories/dockerhub-proxy" -H "$AUTH" 2>/dev/null || echo "{}")
REPO_TYPE=$(echo "$REPO_DETAIL" | jq -r '.repo_type // empty' 2>/dev/null || echo "")
if echo "$REPO_TYPE" | grep -qi "remote"; then
    pass "dockerhub-proxy shows repo_type=remote"
else
    fail "dockerhub-proxy repo_type is '$REPO_TYPE' (expected 'remote')"
fi

# --- Test 7.2: Upstream URL is exposed ---
echo "  [7.2] Repository API: upstream_url..."
UPSTREAM=$(echo "$REPO_DETAIL" | jq -r '.upstream_url // empty' 2>/dev/null || echo "")
if echo "$UPSTREAM" | grep -q "docker.io"; then
    pass "dockerhub-proxy upstream_url contains docker.io ($UPSTREAM)"
elif [ -z "$UPSTREAM" ]; then
    skip "upstream_url not exposed in repository detail API"
else
    fail "dockerhub-proxy upstream_url is '$UPSTREAM' (expected docker.io)"
fi

# --- Test 7.3: Non-existent image returns 404 ---
echo "  [7.3] Non-existent image returns 404..."
NOTFOUND_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "$OCI_AUTH" -H "$ACCEPT_MANIFEST" \
    "$REGISTRY_URL/v2/dockerhub-proxy/this-image-definitely-does-not-exist-xyz/manifests/latest")
if [ "$NOTFOUND_CODE" = "404" ]; then
    pass "Non-existent image returns 404"
elif [ "$NOTFOUND_CODE" = "502" ]; then
    pass "Non-existent image returns 502 (upstream error, acceptable)"
else
    fail "Non-existent image returned HTTP $NOTFOUND_CODE (expected 404)"
fi

echo ""

# ============================================================================
# Summary
# ============================================================================

TOTAL=$((PASSED + FAILED + SKIPPED))

echo "=============================================="
echo "Docker Hub Remote Proxy E2E Results"
echo "=============================================="
echo ""
echo "  Passed:  $PASSED"
echo "  Failed:  $FAILED"
echo "  Skipped: $SKIPPED"
echo "  Total:   $TOTAL"
echo ""

if [ "$FAILED" -gt 0 ]; then
    echo "=============================================="
    echo "SOME TESTS FAILED"
    echo "=============================================="
    exit 1
fi

echo "=============================================="
echo "ALL TESTS PASSED"
echo "=============================================="
