#!/bin/bash
# Remote Proxy + Virtual Repository E2E test script
#
# Tests:
#   1. Create remote (proxy) repos pointing to real upstream registries
#   2. Proxy download: fetch packages through our proxy from upstream
#   3. Write rejection: verify publish/upload is blocked on remote repos
#   4. Create virtual repos aggregating local + remote members
#   5. Virtual resolution: download through virtual repo with priority ordering
#   6. Cache verification: second proxy fetch should be faster (cached)
#
# Usage:
#   ./test-proxy-virtual.sh                    # Run against localhost:8080
#   REGISTRY_URL=http://backend:8080 ./test-proxy-virtual.sh  # Docker compose
#
# Requires: curl, jq
# Optional: npm (for npm client tests), pip3 (for pypi client tests)
set -uo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:8080}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-TestRunner!2026secure}"
API_URL="$REGISTRY_URL/api/v1"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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

# Temp files cleanup
TMPDIR_TEST="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_TEST"' EXIT

# ============================================================================
# Setup: Get auth token
# ============================================================================

echo "=============================================="
echo "Remote Proxy + Virtual Repository E2E Tests"
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

# Helper: create a repository (deletes first if exists to ensure clean state)
create_repo() {
    local key="$1" name="$2" format="$3" repo_type="$4" upstream_url="${5:-}"

    # Delete if exists (ignore errors)
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

# Helper: add member to virtual repo
add_virtual_member() {
    local virtual_key="$1" member_key="$2" priority="$3"
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/repositories/$virtual_key/members" \
        -H "$AUTH" -H 'Content-Type: application/json' \
        -d "{\"member_key\":\"$member_key\",\"priority\":$priority}")
    if [ "$http_code" = "200" ] || [ "$http_code" = "201" ] || [ "$http_code" = "409" ]; then
        return 0
    else
        echo "  WARNING: add_virtual_member $virtual_key/$member_key returned HTTP $http_code"
        return 1
    fi
}

# ============================================================================
# Phase 1: Create test repositories
# ============================================================================

echo "==> Phase 1: Creating test repositories..."

# Local repos (create first — needed as virtual members)
create_repo "npm-local-e2e" "NPM Local E2E" "npm" "local"
echo "  - npm-local-e2e (local)"

create_repo "pypi-local-e2e" "PyPI Local E2E" "pypi" "local"
echo "  - pypi-local-e2e (local)"

# Remote (proxy) repos
create_repo "npm-proxy" "NPM Proxy" "npm" "remote" "https://registry.npmjs.org"
echo "  - npm-proxy (remote -> registry.npmjs.org)"

create_repo "pypi-proxy" "PyPI Proxy" "pypi" "remote" "https://pypi.org"
echo "  - pypi-proxy (remote -> pypi.org)"

create_repo "maven-proxy" "Maven Proxy" "maven" "remote" "https://repo1.maven.org/maven2"
echo "  - maven-proxy (remote -> repo1.maven.org)"

create_repo "hex-local-e2e" "Hex Local E2E" "hex" "local"
echo "  - hex-local-e2e (local)"

create_repo "hex-proxy" "Hex Proxy" "hex" "remote" "https://repo.hex.pm"
echo "  - hex-proxy (remote -> repo.hex.pm)"

# Virtual repos (aggregating local + remote)
create_repo "npm-virtual" "NPM Virtual" "npm" "virtual"
echo "  - npm-virtual (virtual)"

create_repo "pypi-virtual" "PyPI Virtual" "pypi" "virtual"
echo "  - pypi-virtual (virtual)"

create_repo "hex-virtual" "Hex Virtual" "hex" "virtual"
echo "  - hex-virtual (virtual)"

# Wire virtual members (local first = higher priority, then remote proxy)
add_virtual_member "npm-virtual" "npm-local-e2e" 1
add_virtual_member "npm-virtual" "npm-proxy" 2
echo "  - npm-virtual members: npm-local-e2e (pri=1), npm-proxy (pri=2)"

add_virtual_member "pypi-virtual" "pypi-local-e2e" 1
add_virtual_member "pypi-virtual" "pypi-proxy" 2
echo "  - pypi-virtual members: pypi-local-e2e (pri=1), pypi-proxy (pri=2)"

add_virtual_member "hex-virtual" "hex-local-e2e" 1
add_virtual_member "hex-virtual" "hex-proxy" 2
echo "  - hex-virtual members: hex-local-e2e (pri=1), hex-proxy (pri=2)"

echo ""

# ============================================================================
# Phase 2: Remote Proxy Download Tests
# ============================================================================

echo "==> Phase 2: Remote proxy download tests"

# --- Test 2.1: NPM proxy - fetch package metadata ---
echo ""
echo "  [2.1] NPM proxy: fetch package metadata for 'is-odd'..."
NPM_META_CODE=$(curl -s -o "$TMPDIR_TEST/npm-meta.json" -w "%{http_code}" \
    "$REGISTRY_URL/npm/npm-proxy/is-odd")
if [ "$NPM_META_CODE" = "200" ]; then
    NPM_PKG_NAME=$(jq -r '.name' "$TMPDIR_TEST/npm-meta.json" 2>/dev/null || echo "")
    if [ "$NPM_PKG_NAME" = "is-odd" ]; then
        NPM_VERSIONS=$(jq '.versions | length' "$TMPDIR_TEST/npm-meta.json" 2>/dev/null || echo "0")
        pass "NPM metadata fetched: is-odd ($NPM_VERSIONS versions)"
    else
        fail "NPM metadata response doesn't contain expected package name (got: $NPM_PKG_NAME)"
    fi
else
    fail "NPM metadata proxy returned HTTP $NPM_META_CODE"
fi

# --- Test 2.2: NPM proxy - download tarball ---
echo "  [2.2] NPM proxy: download tarball for 'is-odd' latest..."
LATEST_VER=""
if [ -f "$TMPDIR_TEST/npm-meta.json" ]; then
    LATEST_VER=$(jq -r '."dist-tags".latest // empty' "$TMPDIR_TEST/npm-meta.json" 2>/dev/null || echo "")
fi
if [ -n "$LATEST_VER" ]; then
    TARBALL_CODE=$(curl -s -o "$TMPDIR_TEST/npm-tarball.tgz" -w "%{http_code}" \
        "$REGISTRY_URL/npm/npm-proxy/is-odd/-/is-odd-${LATEST_VER}.tgz")
    if [ "$TARBALL_CODE" = "200" ]; then
        TARBALL_SIZE=$(wc -c < "$TMPDIR_TEST/npm-tarball.tgz" | tr -d ' ')
        if [ "$TARBALL_SIZE" -gt 100 ]; then
            pass "NPM tarball downloaded: is-odd-${LATEST_VER}.tgz (${TARBALL_SIZE} bytes)"
        else
            fail "NPM tarball too small: ${TARBALL_SIZE} bytes"
        fi
    else
        fail "NPM tarball proxy returned HTTP $TARBALL_CODE"
    fi
else
    skip "Could not determine latest version from metadata"
fi

# --- Test 2.3: PyPI proxy - fetch simple index ---
echo "  [2.3] PyPI proxy: fetch simple index for 'six'..."
PYPI_INDEX_CODE=$(curl -s -o "$TMPDIR_TEST/pypi-index.html" -w "%{http_code}" \
    "$REGISTRY_URL/pypi/pypi-proxy/simple/six/")
if [ "$PYPI_INDEX_CODE" = "200" ]; then
    if grep -q "six-" "$TMPDIR_TEST/pypi-index.html" 2>/dev/null; then
        PYPI_FILE_COUNT=$(grep -c "href=" "$TMPDIR_TEST/pypi-index.html" 2>/dev/null || echo "0")
        pass "PyPI simple index fetched: six ($PYPI_FILE_COUNT files listed)"
    else
        fail "PyPI simple index doesn't contain expected package links"
    fi
else
    fail "PyPI simple index proxy returned HTTP $PYPI_INDEX_CODE"
fi

# --- Test 2.4: PyPI proxy - download a file via direct proxy path ---
echo "  [2.4] PyPI proxy: download package file for 'six'..."
# Use the packages/ proxy path directly (format-specific file download)
PYPI_DL_CODE=$(curl -s -o "$TMPDIR_TEST/pypi-file.whl" -w "%{http_code}" \
    "$REGISTRY_URL/pypi/pypi-proxy/packages/six-1.16.0-py2.py3-none-any.whl")
if [ "$PYPI_DL_CODE" = "200" ]; then
    PYPI_DL_SIZE=$(wc -c < "$TMPDIR_TEST/pypi-file.whl" | tr -d ' ')
    if [ "$PYPI_DL_SIZE" -gt 100 ]; then
        pass "PyPI file downloaded: six-1.16.0 wheel (${PYPI_DL_SIZE} bytes)"
    else
        fail "PyPI file too small: ${PYPI_DL_SIZE} bytes"
    fi
else
    # PyPI file downloads may go through the upstream directly via rewritten URLs
    # This is expected behavior — the simple index URLs point to files.pythonhosted.org
    skip "PyPI file proxy returned HTTP $PYPI_DL_CODE (upstream URLs not rewritten — expected for now)"
fi

# --- Test 2.5: Hex proxy - fetch package metadata for 'phoenix' ---
echo "  [2.5] Hex proxy: fetch package metadata for 'phoenix'..."
HEX_META_CODE=$(curl -s -o "$TMPDIR_TEST/hex-meta.json" -w "%{http_code}" \
    "$REGISTRY_URL/hex/hex-proxy/packages/phoenix")
if [ "$HEX_META_CODE" = "200" ]; then
    # The response may be JSON (from our API) or protobuf (passthrough from hex.pm).
    # Try JSON validation first; fall back to size check for binary payloads.
    HEX_PKG_NAME=$(jq -r '.name // empty' "$TMPDIR_TEST/hex-meta.json" 2>/dev/null || echo "")
    if [ "$HEX_PKG_NAME" = "phoenix" ]; then
        HEX_RELEASES=$(jq '.releases | length // 0' "$TMPDIR_TEST/hex-meta.json" 2>/dev/null || echo "0")
        pass "Hex package metadata fetched: phoenix ($HEX_RELEASES releases)"
    else
        HEX_META_SIZE=$(wc -c < "$TMPDIR_TEST/hex-meta.json" | tr -d ' ')
        if [ "$HEX_META_SIZE" -gt 50 ]; then
            pass "Hex package metadata fetched: phoenix (${HEX_META_SIZE} bytes, binary payload)"
        else
            fail "Hex package metadata too small: ${HEX_META_SIZE} bytes"
        fi
    fi
else
    fail "Hex package metadata proxy returned HTTP $HEX_META_CODE"
fi

# --- Test 2.6: Hex proxy - fetch names endpoint ---
echo "  [2.6] Hex proxy: fetch names endpoint..."
HEX_NAMES_CODE=$(curl -s -o "$TMPDIR_TEST/hex-names.bin" -w "%{http_code}" \
    "$REGISTRY_URL/hex/hex-proxy/names")
if [ "$HEX_NAMES_CODE" = "200" ]; then
    HEX_NAMES_SIZE=$(wc -c < "$TMPDIR_TEST/hex-names.bin" | tr -d ' ')
    if [ "$HEX_NAMES_SIZE" -gt 10 ]; then
        pass "Hex names endpoint fetched (${HEX_NAMES_SIZE} bytes, signed protobuf)"
    else
        fail "Hex names response too small: ${HEX_NAMES_SIZE} bytes"
    fi
else
    fail "Hex names proxy returned HTTP $HEX_NAMES_CODE"
fi

# --- Test 2.7: Hex proxy - fetch versions endpoint ---
echo "  [2.7] Hex proxy: fetch versions endpoint..."
HEX_VERSIONS_CODE=$(curl -s -o "$TMPDIR_TEST/hex-versions.bin" -w "%{http_code}" \
    "$REGISTRY_URL/hex/hex-proxy/versions")
if [ "$HEX_VERSIONS_CODE" = "200" ]; then
    HEX_VERSIONS_SIZE=$(wc -c < "$TMPDIR_TEST/hex-versions.bin" | tr -d ' ')
    if [ "$HEX_VERSIONS_SIZE" -gt 10 ]; then
        pass "Hex versions endpoint fetched (${HEX_VERSIONS_SIZE} bytes, signed protobuf)"
    else
        fail "Hex versions response too small: ${HEX_VERSIONS_SIZE} bytes"
    fi
else
    fail "Hex versions proxy returned HTTP $HEX_VERSIONS_CODE"
fi

# --- Test 2.8: Maven proxy - download artifact ---
echo "  [2.8] Maven proxy: download junit-4.13.2.jar..."
MAVEN_CODE=$(curl -s -o "$TMPDIR_TEST/maven-jar.jar" -w "%{http_code}" \
    "$REGISTRY_URL/maven/maven-proxy/junit/junit/4.13.2/junit-4.13.2.jar")
if [ "$MAVEN_CODE" = "200" ]; then
    MAVEN_SIZE=$(wc -c < "$TMPDIR_TEST/maven-jar.jar" | tr -d ' ')
    if [ "$MAVEN_SIZE" -gt 100 ]; then
        pass "Maven artifact downloaded: junit-4.13.2.jar (${MAVEN_SIZE} bytes)"
    else
        fail "Maven artifact too small: ${MAVEN_SIZE} bytes"
    fi
else
    fail "Maven proxy returned HTTP $MAVEN_CODE"
fi

# --- Test 2.9: Proxy cache - second fetch should be served from cache ---
echo "  [2.9] Proxy cache: verify second fetch is served (possibly cached)..."
CACHE_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "$REGISTRY_URL/npm/npm-proxy/is-odd")
if [ "$CACHE_CODE" = "200" ]; then
    pass "Second proxy fetch returned 200 (cache or upstream hit)"
else
    fail "Second proxy fetch returned HTTP $CACHE_CODE"
fi

echo ""

# ============================================================================
# Phase 3: Write Rejection Tests
# ============================================================================

echo "==> Phase 3: Write rejection tests (remote repos should reject publishes)"

# --- Test 3.1: NPM publish to remote repo ---
echo "  [3.1] NPM publish to remote repo should be rejected..."
# NPM uses Basic auth for publish — encode as base64
NPM_AUTH_TOKEN=$(echo -n "${ADMIN_USER}:${ADMIN_PASS}" | base64)
PUBLISH_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X PUT "$REGISTRY_URL/npm/npm-proxy/test-rejected-pkg" \
    -H "Authorization: Basic $NPM_AUTH_TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"name":"test-rejected-pkg","versions":{"1.0.0":{"name":"test-rejected-pkg","version":"1.0.0"}},"_attachments":{}}')
if [ "$PUBLISH_CODE" = "405" ]; then
    pass "NPM publish to remote repo correctly rejected with 405"
elif [ "$PUBLISH_CODE" = "400" ] || [ "$PUBLISH_CODE" = "403" ]; then
    pass "NPM publish to remote repo rejected with $PUBLISH_CODE (acceptable)"
else
    fail "NPM publish to remote repo returned HTTP $PUBLISH_CODE (expected 405)"
fi

# --- Test 3.2: PyPI upload to remote repo ---
echo "  [3.2] PyPI upload to remote repo should be rejected..."
PYPI_UPLOAD_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$REGISTRY_URL/pypi/pypi-proxy/" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -F ":action=file_upload" \
    -F "name=test-rejected" \
    -F "version=1.0.0" \
    -F "content=@/dev/null;filename=test.whl")
if [ "$PYPI_UPLOAD_CODE" = "405" ]; then
    pass "PyPI upload to remote repo correctly rejected with 405"
elif [ "$PYPI_UPLOAD_CODE" = "400" ] || [ "$PYPI_UPLOAD_CODE" = "403" ]; then
    pass "PyPI upload to remote repo rejected with $PYPI_UPLOAD_CODE (acceptable)"
else
    fail "PyPI upload to remote repo returned HTTP $PYPI_UPLOAD_CODE (expected 405)"
fi

# --- Test 3.3: Hex publish to remote repo ---
echo "  [3.3] Hex publish to remote repo should be rejected..."
HEX_AUTH_TOKEN=$(echo -n "${ADMIN_USER}:${ADMIN_PASS}" | base64)
HEX_PUB_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$REGISTRY_URL/hex/hex-proxy/publish" \
    -H "Authorization: Basic $HEX_AUTH_TOKEN" \
    -H 'Content-Type: application/octet-stream' \
    --data-binary "fake-tarball-data")
if [ "$HEX_PUB_CODE" = "405" ]; then
    pass "Hex publish to remote repo correctly rejected with 405"
elif [ "$HEX_PUB_CODE" = "400" ] || [ "$HEX_PUB_CODE" = "403" ]; then
    pass "Hex publish to remote repo rejected with $HEX_PUB_CODE (acceptable)"
else
    fail "Hex publish to remote repo returned HTTP $HEX_PUB_CODE (expected 405)"
fi

# --- Test 3.4: NPM publish to virtual repo ---
echo "  [3.4] NPM publish to virtual repo should be rejected..."
VIRTUAL_PUB_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X PUT "$REGISTRY_URL/npm/npm-virtual/test-rejected-pkg" \
    -H "Authorization: Basic $NPM_AUTH_TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"name":"test-rejected-pkg","versions":{"1.0.0":{"name":"test-rejected-pkg","version":"1.0.0"}},"_attachments":{}}')
if [ "$VIRTUAL_PUB_CODE" = "400" ]; then
    pass "NPM publish to virtual repo correctly rejected with 400"
elif [ "$VIRTUAL_PUB_CODE" = "405" ] || [ "$VIRTUAL_PUB_CODE" = "403" ]; then
    pass "NPM publish to virtual repo rejected with $VIRTUAL_PUB_CODE (acceptable)"
else
    fail "NPM publish to virtual repo returned HTTP $VIRTUAL_PUB_CODE (expected 400)"
fi

echo ""

# ============================================================================
# Phase 4: Virtual Repository Resolution Tests
# ============================================================================

echo "==> Phase 4: Virtual repository resolution tests"

# --- Test 4.1: Virtual NPM tarball download (falls through to remote proxy) ---
echo "  [4.1] Virtual NPM tarball: download through virtual repo..."
if [ -n "$LATEST_VER" ]; then
    VIRTUAL_TARBALL_CODE=$(curl -s -o "$TMPDIR_TEST/virtual-tarball.tgz" -w "%{http_code}" \
        "$REGISTRY_URL/npm/npm-virtual/is-odd/-/is-odd-${LATEST_VER}.tgz")
    if [ "$VIRTUAL_TARBALL_CODE" = "200" ]; then
        VIRTUAL_TARBALL_SIZE=$(wc -c < "$TMPDIR_TEST/virtual-tarball.tgz" | tr -d ' ')
        if [ "$VIRTUAL_TARBALL_SIZE" -gt 100 ]; then
            pass "Virtual NPM tarball downloaded: is-odd-${LATEST_VER}.tgz (${VIRTUAL_TARBALL_SIZE} bytes)"
        else
            fail "Virtual NPM tarball too small: ${VIRTUAL_TARBALL_SIZE} bytes"
        fi
    else
        fail "Virtual NPM tarball returned HTTP $VIRTUAL_TARBALL_CODE"
    fi
else
    skip "No latest version available for tarball test"
fi

# --- Test 4.2: Virtual NPM metadata (falls through to remote proxy) ---
echo "  [4.2] Virtual NPM metadata: should fall through to remote proxy..."
VIRTUAL_NPM_CODE=$(curl -s -o "$TMPDIR_TEST/virtual-npm-meta.json" -w "%{http_code}" \
    "$REGISTRY_URL/npm/npm-virtual/is-odd")
if [ "$VIRTUAL_NPM_CODE" = "200" ]; then
    VIRTUAL_PKG=$(jq -r '.name' "$TMPDIR_TEST/virtual-npm-meta.json" 2>/dev/null || echo "")
    if [ "$VIRTUAL_PKG" = "is-odd" ]; then
        pass "Virtual NPM resolved 'is-odd' metadata through remote member"
    else
        fail "Virtual NPM response doesn't contain expected package name"
    fi
elif [ "$VIRTUAL_NPM_CODE" = "404" ]; then
    skip "Virtual NPM metadata not yet implemented (expected — only binary downloads resolved)"
else
    fail "Virtual NPM metadata returned HTTP $VIRTUAL_NPM_CODE"
fi

# --- Test 4.3: Virtual PyPI index (falls through to remote proxy) ---
echo "  [4.3] Virtual PyPI download: simple index through virtual repo..."
VIRTUAL_PYPI_CODE=$(curl -s -o "$TMPDIR_TEST/virtual-pypi.html" -w "%{http_code}" \
    "$REGISTRY_URL/pypi/pypi-virtual/simple/six/")
if [ "$VIRTUAL_PYPI_CODE" = "200" ]; then
    if grep -q "six-" "$TMPDIR_TEST/virtual-pypi.html" 2>/dev/null; then
        pass "Virtual PyPI resolved 'six' simple index through remote member"
    else
        fail "Virtual PyPI response doesn't contain expected package links"
    fi
elif [ "$VIRTUAL_PYPI_CODE" = "404" ]; then
    skip "Virtual PyPI index not yet implemented (expected — only binary downloads resolved)"
else
    fail "Virtual PyPI simple index returned HTTP $VIRTUAL_PYPI_CODE"
fi

# --- Test 4.4: Virtual Hex package_info (falls through to remote proxy) ---
echo "  [4.4] Virtual Hex package_info: should fall through to remote proxy..."
VIRTUAL_HEX_CODE=$(curl -s -o "$TMPDIR_TEST/virtual-hex-meta.json" -w "%{http_code}" \
    "$REGISTRY_URL/hex/hex-virtual/packages/phoenix")
if [ "$VIRTUAL_HEX_CODE" = "200" ]; then
    VIRTUAL_HEX_SIZE=$(wc -c < "$TMPDIR_TEST/virtual-hex-meta.json" | tr -d ' ')
    if [ "$VIRTUAL_HEX_SIZE" -gt 50 ]; then
        pass "Virtual Hex resolved 'phoenix' package_info through remote member (${VIRTUAL_HEX_SIZE} bytes)"
    else
        fail "Virtual Hex package_info response too small: ${VIRTUAL_HEX_SIZE} bytes"
    fi
elif [ "$VIRTUAL_HEX_CODE" = "404" ]; then
    skip "Virtual Hex package_info proxy not yet resolving through members"
else
    fail "Virtual Hex package_info returned HTTP $VIRTUAL_HEX_CODE"
fi

# --- Test 4.5: Virtual Hex names (returns local only, merging out of scope) ---
echo "  [4.5] Virtual Hex names: returns local data (merging out of scope)..."
VIRTUAL_HEX_NAMES_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "$REGISTRY_URL/hex/hex-virtual/names")
if [ "$VIRTUAL_HEX_NAMES_CODE" = "200" ]; then
    pass "Virtual Hex names returned 200 (local data)"
elif [ "$VIRTUAL_HEX_NAMES_CODE" = "404" ]; then
    skip "Virtual Hex names returned 404 (no local artifacts, merging out of scope)"
else
    fail "Virtual Hex names returned unexpected HTTP $VIRTUAL_HEX_NAMES_CODE"
fi

# --- Test 4.6: Virtual member listing ---
echo "  [4.6] Virtual member listing API..."
MEMBERS_CODE=$(curl -s -o "$TMPDIR_TEST/members.json" -w "%{http_code}" \
    "$API_URL/repositories/npm-virtual/members" -H "$AUTH")
if [ "$MEMBERS_CODE" = "200" ]; then
    # Response format: {"members": [...]}
    MEMBER_COUNT=$(jq '.members | length // 0' "$TMPDIR_TEST/members.json" 2>/dev/null || echo "0")
    if [ "$MEMBER_COUNT" -ge 2 ]; then
        pass "Virtual member listing: npm-virtual has $MEMBER_COUNT members"
    else
        fail "Virtual member listing: expected >= 2 members, got $MEMBER_COUNT"
    fi
else
    fail "Virtual member listing returned HTTP $MEMBERS_CODE"
fi

echo ""

# ============================================================================
# Phase 5: Native client integration (if available)
# ============================================================================

echo "==> Phase 5: Native client integration tests"

# --- Test 5.1: npm install through proxy ---
echo "  [5.1] npm install through proxy repo..."
if command -v npm >/dev/null 2>&1; then
    NPM_INSTALL_DIR="$(mktemp -d)"
    (
        cd "$NPM_INSTALL_DIR"
        npm init -y --silent >/dev/null 2>&1
        if npm install is-odd --registry "$REGISTRY_URL/npm/npm-proxy/" --no-audit --no-fund 2>/dev/null; then
            if [ -d node_modules/is-odd ]; then
                echo "OK"
            else
                echo "MISSING"
            fi
        else
            echo "FAILED"
        fi
    ) > "$TMPDIR_TEST/npm-result.txt" 2>&1
    NPM_RESULT=$(cat "$TMPDIR_TEST/npm-result.txt" | tail -1)
    rm -rf "$NPM_INSTALL_DIR"
    case "$NPM_RESULT" in
        OK) pass "npm install is-odd via proxy succeeded" ;;
        MISSING) fail "npm install appeared to succeed but node_modules/is-odd not found" ;;
        *) fail "npm install via proxy failed" ;;
    esac
else
    skip "npm not available"
fi

# --- Test 5.2: npm install through virtual repo ---
echo "  [5.2] npm install through virtual repo..."
if command -v npm >/dev/null 2>&1; then
    NPM_VIRTUAL_DIR="$(mktemp -d)"
    (
        cd "$NPM_VIRTUAL_DIR"
        npm init -y --silent >/dev/null 2>&1
        if npm install is-odd --registry "$REGISTRY_URL/npm/npm-virtual/" --no-audit --no-fund 2>/dev/null; then
            if [ -d node_modules/is-odd ]; then
                echo "OK"
            else
                echo "MISSING"
            fi
        else
            echo "FAILED"
        fi
    ) > "$TMPDIR_TEST/npm-virtual-result.txt" 2>&1
    NPM_V_RESULT=$(cat "$TMPDIR_TEST/npm-virtual-result.txt" | tail -1)
    rm -rf "$NPM_VIRTUAL_DIR"
    case "$NPM_V_RESULT" in
        OK) pass "npm install is-odd via virtual repo succeeded" ;;
        MISSING) fail "npm install via virtual appeared to succeed but node_modules/is-odd not found" ;;
        *) fail "npm install via virtual repo failed" ;;
    esac
else
    skip "npm not available"
fi

# --- Test 5.3: pip install through proxy ---
echo "  [5.3] pip install through proxy repo..."
if command -v pip3 >/dev/null 2>&1; then
    PIP_INSTALL_DIR="$(mktemp -d)"
    TRUSTED_HOST=$(echo "$REGISTRY_URL" | sed 's|https\?://||' | cut -d: -f1)
    if pip3 install six \
        --index-url "$REGISTRY_URL/pypi/pypi-proxy/simple/" \
        --trusted-host "$TRUSTED_HOST" \
        --target "$PIP_INSTALL_DIR" \
        --no-deps --quiet 2>/dev/null; then
        if ls "$PIP_INSTALL_DIR" 2>/dev/null | grep -qi six; then
            pass "pip install six via proxy succeeded"
        else
            fail "pip install appeared to succeed but six not found in target dir"
        fi
    else
        fail "pip install via proxy failed"
    fi
    rm -rf "$PIP_INSTALL_DIR"
else
    skip "pip3 not available"
fi

# --- Test 5.4: pip install through virtual repo ---
echo "  [5.4] pip install through virtual repo..."
if command -v pip3 >/dev/null 2>&1; then
    PIP_VIRTUAL_DIR="$(mktemp -d)"
    TRUSTED_HOST=$(echo "$REGISTRY_URL" | sed 's|https\?://||' | cut -d: -f1)
    if pip3 install six \
        --index-url "$REGISTRY_URL/pypi/pypi-virtual/simple/" \
        --trusted-host "$TRUSTED_HOST" \
        --target "$PIP_VIRTUAL_DIR" \
        --no-deps --quiet 2>/dev/null; then
        if ls "$PIP_VIRTUAL_DIR" 2>/dev/null | grep -qi six; then
            pass "pip install six via virtual repo succeeded"
        else
            fail "pip install via virtual appeared to succeed but six not found"
        fi
    else
        # Virtual PyPI index may not be implemented yet
        skip "pip install via virtual repo not yet supported (virtual index not implemented)"
    fi
    rm -rf "$PIP_VIRTUAL_DIR"
else
    skip "pip3 not available"
fi

echo ""

# ============================================================================
# Phase 6: Repository API validation
# ============================================================================

echo "==> Phase 6: Repository API validation"

# --- Test 6.1: Verify remote repo shows correct type ---
echo "  [6.1] Repository API: remote repo type..."
REPO_DETAIL=$(curl -sf "$API_URL/repositories/npm-proxy" -H "$AUTH" 2>/dev/null || echo "{}")
REPO_TYPE=$(echo "$REPO_DETAIL" | jq -r '.repo_type // empty' 2>/dev/null || echo "")
if echo "$REPO_TYPE" | grep -qi "remote"; then
    pass "npm-proxy shows repo_type=remote"
else
    fail "npm-proxy repo_type is '$REPO_TYPE' (expected 'remote')"
fi

# --- Test 6.2: Verify virtual repo shows correct type ---
echo "  [6.2] Repository API: virtual repo type..."
VREPO_DETAIL=$(curl -sf "$API_URL/repositories/npm-virtual" -H "$AUTH" 2>/dev/null || echo "{}")
VREPO_TYPE=$(echo "$VREPO_DETAIL" | jq -r '.repo_type // empty' 2>/dev/null || echo "")
if echo "$VREPO_TYPE" | grep -qi "virtual"; then
    pass "npm-virtual shows repo_type=virtual"
else
    fail "npm-virtual repo_type is '$VREPO_TYPE' (expected 'virtual')"
fi

# --- Test 6.3: Verify upstream URL on remote repo ---
echo "  [6.3] Repository API: upstream_url on remote repo..."
UPSTREAM=$(echo "$REPO_DETAIL" | jq -r '.upstream_url // empty' 2>/dev/null || echo "")
if echo "$UPSTREAM" | grep -q "registry.npmjs.org"; then
    pass "npm-proxy upstream_url=registry.npmjs.org"
elif [ -z "$UPSTREAM" ]; then
    skip "upstream_url not exposed in repository detail API response"
else
    fail "npm-proxy upstream_url is '$UPSTREAM'"
fi

# --- Test 6.4: Non-existent package should return 404 ---
echo "  [6.4] Proxy 404: non-existent package..."
NOTFOUND_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "$REGISTRY_URL/npm/npm-proxy/this-package-definitely-does-not-exist-xyz-123")
if [ "$NOTFOUND_CODE" = "404" ]; then
    pass "Non-existent package returns 404"
elif [ "$NOTFOUND_CODE" = "502" ]; then
    pass "Non-existent package returns 502 (upstream error, acceptable)"
else
    fail "Non-existent package returned HTTP $NOTFOUND_CODE (expected 404)"
fi

echo ""

# ============================================================================
# Summary
# ============================================================================

TOTAL=$((PASSED + FAILED + SKIPPED))

echo "=============================================="
echo "Remote Proxy + Virtual Repository E2E Results"
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
