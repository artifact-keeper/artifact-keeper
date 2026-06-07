#!/usr/bin/env bash
# Virtual-resolution regression E2E tests (issue #1625, gate for #1611)
#
# Reproduces three OPEN wrong-result bugs in virtual repository resolution by
# asserting the CORRECT behavior. These tests are RED on `main` BY DESIGN — a
# failure here proves the bug still exists. When #1611 lands they flip green and
# become its regression gate.
#
#   #1600 — PyPI virtual unions a remote-only package into the simple index but
#           binds the DOWNLOAD to the local member -> 404 (index/download
#           inconsistency + dependency-confusion). We assert: a package present
#           ONLY on the remote member is listed in the virtual's simple index
#           AND its wheel downloads 200 through the virtual.
#   #1595 — Maven virtual does not proxy GROUP-level plugin-prefix
#           maven-metadata.xml from remote members -> 404 (breaks
#           `mvn <prefix>:<goal>`). We assert: the group-level metadata is
#           served 200 through the virtual and contains the <plugins> list.
#   #1562 — Maven virtual 404s a remote-only artifact (e.g. a parent POM) that
#           the remote member serves 200 directly. We assert: the remote-only
#           parent POM resolves 200 through the virtual.
#
# Mirrors scripts/native-tests/test-proxy-virtual.sh (auth flow, create_repo,
# add_virtual_member, PASS/FAIL helpers).
#
# Usage:
#   MOCK_UPSTREAM_URL=http://mock-upstream:9101 ./test-virtual-resolution.sh
#   REGISTRY_URL=http://localhost:8080 MOCK_UPSTREAM_URL=http://localhost:9101 \
#     ./test-virtual-resolution.sh
#
# Requires: curl, jq. Optional: pip3 (PEP-503 end-to-end download).
set -uo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:8080}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-TestRunner!2026secure}"
# The mock upstream serves deterministic Maven/PyPI shaped paths under /maven2
# and /simple. For #1562/#1595 we prefer the mock; live Maven Central is used as
# an optional fallback only if MOCK_UPSTREAM_URL is unset.
MOCK_UPSTREAM_URL="${MOCK_UPSTREAM_URL:-http://localhost:9101}"
API_URL="$REGISTRY_URL/api/v1"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASSED=0; FAILED=0; SKIPPED=0
pass() { echo -e "  ${GREEN}PASS${NC}: $1"; PASSED=$((PASSED + 1)); }
fail() { echo -e "  ${RED}FAIL${NC}: $1"; FAILED=$((FAILED + 1)); }
skip() { echo -e "  ${YELLOW}SKIP${NC}: $1"; SKIPPED=$((SKIPPED + 1)); }

TMPDIR_TEST="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_TEST"' EXIT

echo "=============================================="
echo "Virtual-Resolution Regression E2E (#1600/#1595/#1562)"
echo "=============================================="
echo "Registry:      $REGISTRY_URL"
echo "Mock upstream: $MOCK_UPSTREAM_URL"
echo "NOTE: These tests are RED on 'main' by design (they reproduce open bugs)."
echo ""

# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
echo "==> Authenticating..."
LOGIN_RESP=$(curl -sf -X POST "$API_URL/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" 2>&1) || {
    echo "ERROR: Failed to authenticate. Is the backend running at $REGISTRY_URL?"
    exit 1
}
TOKEN=$(echo "$LOGIN_RESP" | jq -r '.access_token')
if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    echo "ERROR: Failed to get auth token"; exit 1
fi
AUTH="Authorization: Bearer $TOKEN"
echo "  Authenticated successfully"
echo ""

# create_repo: same contract as test-proxy-virtual.sh (delete-then-create).
create_repo() {
    local key="$1" name="$2" format="$3" repo_type="$4" upstream_url="${5:-}" member_repos="${6:-}"
    curl -s -o /dev/null -X DELETE "$API_URL/repositories/$key" -H "$AUTH" 2>/dev/null || true
    local body="{\"key\":\"$key\",\"name\":\"$name\",\"format\":\"$format\",\"repo_type\":\"$repo_type\",\"is_public\":true"
    [ -n "$upstream_url" ] && body="$body,\"upstream_url\":\"$upstream_url\""
    [ -n "$member_repos" ] && body="$body,\"member_repos\":$member_repos"
    body="$body}"
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/repositories" \
        -H "$AUTH" -H 'Content-Type: application/json' -d "$body")
    if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
        return 0
    fi
    echo "  ERROR: create_repo $key returned HTTP $http_code (body: $body)"
    echo "  Aborting: subsequent tests depend on this repo existing."
    exit 1
}

# ---------------------------------------------------------------------------
# Phase 0: wait for the mock upstream control plane
# ---------------------------------------------------------------------------
echo "==> Phase 0: Waiting for mock upstream..."
MOCK_READY=0
for _ in $(seq 1 30); do
    if curl -sf "$MOCK_UPSTREAM_URL/__mock__/health" >/dev/null 2>&1; then
        MOCK_READY=1; break
    fi
    sleep 1
done
if [ "$MOCK_READY" != "1" ]; then
    echo "ERROR: mock upstream not reachable at $MOCK_UPSTREAM_URL"; exit 1
fi
curl -s -X POST "$MOCK_UPSTREAM_URL/__mock__/reset" >/dev/null
echo "  Mock upstream ready"
echo ""

# ---------------------------------------------------------------------------
# Phase 1: create repositories
#   maven-vr-remote  -> mock /maven2   (priority 2)
#   maven-vr-local   -> empty local    (priority 1)
#   maven-vr-virtual -> [local, remote]
#   pypi-vr-remote   -> mock /        (PyPI simple at /simple)
#   pypi-vr-local    -> empty local
#   pypi-vr-virtual  -> [local, remote]
# ---------------------------------------------------------------------------
echo "==> Phase 1: Creating repositories (local + remote->mock + virtual)..."
create_repo "maven-vr-local"  "Maven VR Local"  "maven" "local"
create_repo "maven-vr-remote" "Maven VR Remote" "maven" "remote" "$MOCK_UPSTREAM_URL/maven2"
create_repo "maven-vr-virtual" "Maven VR Virtual" "maven" "virtual" "" \
    '[{"repo_key":"maven-vr-local","priority":1},{"repo_key":"maven-vr-remote","priority":2}]'
echo "  - maven-vr-virtual members: maven-vr-local (1), maven-vr-remote (2)"

create_repo "pypi-vr-local"  "PyPI VR Local"  "pypi" "local"
create_repo "pypi-vr-remote" "PyPI VR Remote" "pypi" "remote" "$MOCK_UPSTREAM_URL"
create_repo "pypi-vr-virtual" "PyPI VR Virtual" "pypi" "virtual" "" \
    '[{"repo_key":"pypi-vr-local","priority":1},{"repo_key":"pypi-vr-remote","priority":2}]'
echo "  - pypi-vr-virtual members: pypi-vr-local (1), pypi-vr-remote (2)"
echo ""

# ---------------------------------------------------------------------------
# Phase 2: #1600 — PyPI virtual index/download consistency for a remote-only pkg
# ---------------------------------------------------------------------------
echo "==> Phase 2: #1600 PyPI virtual remote-only download consistency"

# 2a: sanity — the remote member serves the simple index + wheel directly (200).
echo "  [2a] Control: remote member serves lonelydep simple index + wheel directly..."
RM_INDEX=$(curl -s -o "$TMPDIR_TEST/rm-index.html" -w "%{http_code}" \
    "$REGISTRY_URL/pypi/pypi-vr-remote/simple/lonelydep/")
RM_WHEEL=$(curl -s -o /dev/null -w "%{http_code}" \
    "$REGISTRY_URL/pypi/pypi-vr-remote/packages/ld/lonelydep/lonelydep-2.3.0-py3-none-any.whl")
if [ "$RM_INDEX" = "200" ] && [ "$RM_WHEEL" = "200" ]; then
    pass "remote member: lonelydep index=$RM_INDEX wheel=$RM_WHEEL"
else
    skip "remote member did not serve lonelydep (index=$RM_INDEX wheel=$RM_WHEEL) — check proxy URL rewriting"
fi

# 2b: the VIRTUAL simple index must LIST the remote-only wheel.
echo "  [2b] Virtual simple index lists the remote-only lonelydep wheel..."
V_INDEX=$(curl -s -o "$TMPDIR_TEST/v-index.html" -w "%{http_code}" \
    "$REGISTRY_URL/pypi/pypi-vr-virtual/simple/lonelydep/")
if [ "$V_INDEX" = "200" ] && grep -q "lonelydep-2.3.0" "$TMPDIR_TEST/v-index.html" 2>/dev/null; then
    pass "virtual simple index lists lonelydep-2.3.0 wheel"
else
    fail "virtual simple index did not list lonelydep-2.3.0 (HTTP $V_INDEX) — #1600"
fi

# 2c: THE BUG — the wheel listed by the index must DOWNLOAD 200 via the virtual.
echo "  [2c] Virtual DOWNLOAD of the listed wheel must be 200 (not 404)..."
V_WHEEL=$(curl -s -o "$TMPDIR_TEST/v-wheel.whl" -w "%{http_code}" \
    "$REGISTRY_URL/pypi/pypi-vr-virtual/packages/ld/lonelydep/lonelydep-2.3.0-py3-none-any.whl")
if [ "$V_WHEEL" = "200" ]; then
    WHEEL_SZ=$(wc -c < "$TMPDIR_TEST/v-wheel.whl" | tr -d ' ')
    pass "virtual download of lonelydep-2.3.0 wheel returned 200 (${WHEEL_SZ} bytes)"
else
    fail "virtual download of index-listed wheel returned $V_WHEEL (expected 200) — #1600 index/download inconsistency"
fi

# 2d (optional): real pip download through the virtual.
echo "  [2d] pip download lonelydep through the virtual (PEP-503 end-to-end)..."
if command -v pip3 >/dev/null 2>&1; then
    PIP_DIR="$(mktemp -d)"
    TRUSTED_HOST=$(echo "$REGISTRY_URL" | sed 's|https\?://||' | cut -d: -f1)
    if pip3 download lonelydep \
        --index-url "$REGISTRY_URL/pypi/pypi-vr-virtual/simple/" \
        --trusted-host "$TRUSTED_HOST" \
        --no-deps --dest "$PIP_DIR" --quiet 2>"$TMPDIR_TEST/pip-err.txt"; then
        if find "$PIP_DIR" -maxdepth 1 -iname '*lonelydep*' 2>/dev/null | grep -q .; then
            pass "pip download lonelydep via virtual succeeded"
        else
            fail "pip reported success but no lonelydep artifact downloaded"
        fi
    else
        fail "pip download lonelydep via virtual failed (#1600 — index lists it, download 404s)"
    fi
    rm -rf "$PIP_DIR"
else
    skip "pip3 not available (curl-level assertions in 2b/2c still cover #1600)"
fi
echo ""

# ---------------------------------------------------------------------------
# Phase 3: #1595 — Maven virtual group-level plugin-prefix metadata
# ---------------------------------------------------------------------------
echo "==> Phase 3: #1595 Maven virtual group-level plugin-prefix metadata"

# 3a: control — remote member serves the group-level metadata directly (200).
echo "  [3a] Control: remote member serves group-level plugin metadata directly..."
RM_PREFIX=$(curl -s -o "$TMPDIR_TEST/rm-prefix.xml" -w "%{http_code}" \
    "$REGISTRY_URL/maven/maven-vr-remote/org/example/plugins/maven-metadata.xml")
if [ "$RM_PREFIX" = "200" ] && grep -q "<plugins>" "$TMPDIR_TEST/rm-prefix.xml" 2>/dev/null; then
    pass "remote member serves group-level plugin metadata (200, has <plugins>)"
else
    skip "remote member group-level metadata not served (HTTP $RM_PREFIX)"
fi

# 3b: THE BUG — the virtual must proxy the group-level metadata (200, not 404).
echo "  [3b] Virtual group-level plugin metadata must be 200 (not 404)..."
V_PREFIX=$(curl -s -o "$TMPDIR_TEST/v-prefix.xml" -w "%{http_code}" \
    "$REGISTRY_URL/maven/maven-vr-virtual/org/example/plugins/maven-metadata.xml")
if [ "$V_PREFIX" = "200" ] && grep -q "<plugins>" "$TMPDIR_TEST/v-prefix.xml" 2>/dev/null; then
    pass "virtual group-level plugin metadata returned 200 with <plugins> list"
else
    fail "virtual group-level plugin metadata returned $V_PREFIX (expected 200 w/ <plugins>) — #1595"
fi

# 3c: prove it carries the prefix Maven needs to resolve `example:<goal>`.
echo "  [3c] Virtual group-level metadata exposes the plugin <prefix>..."
if [ "$V_PREFIX" = "200" ] && grep -q "<prefix>example</prefix>" "$TMPDIR_TEST/v-prefix.xml" 2>/dev/null; then
    pass "virtual group metadata exposes prefix 'example' (enables mvn example:<goal>)"
else
    fail "virtual group metadata missing <prefix>example</prefix> — mvn <prefix>:<goal> would fail — #1595"
fi
echo ""

# ---------------------------------------------------------------------------
# Phase 4: #1562 — Maven virtual remote-only artifact (parent POM)
# ---------------------------------------------------------------------------
echo "==> Phase 4: #1562 Maven virtual remote-only artifact (parent POM)"

# 4a: control — remote member serves the parent POM directly (200).
echo "  [4a] Control: remote member serves remote-only parent POM directly..."
RM_POM=$(curl -s -o /dev/null -w "%{http_code}" \
    "$REGISTRY_URL/maven/maven-vr-remote/com/example/parent/1.0.0/parent-1.0.0.pom")
if [ "$RM_POM" = "200" ]; then
    pass "remote member serves com.example:parent:1.0.0 POM (200)"
else
    skip "remote member did not serve parent POM (HTTP $RM_POM)"
fi

# 4b: THE BUG — a remote-only artifact that was NEVER fetched via the remote
#     member directly must still resolve 200 on its FIRST request through the
#     virtual. This is the exact #1562 condition: an uncached remote-only
#     artifact (parent POM) requested through the virtual. We use a dedicated
#     `vonly-parent` path that no control fetch ever primes, so a warm cache
#     cannot mask the bug.
echo "  [4b] Virtual must serve an UNCACHED remote-only parent POM 200 on first request (not 404)..."
V_POM=$(curl -s -o "$TMPDIR_TEST/v-pom.xml" -w "%{http_code}" \
    "$REGISTRY_URL/maven/maven-vr-virtual/com/example/vonly-parent/1.0.0/vonly-parent-1.0.0.pom")
if [ "$V_POM" = "200" ] && grep -q "<artifactId>vonly-parent</artifactId>" "$TMPDIR_TEST/v-pom.xml" 2>/dev/null; then
    pass "virtual served UNCACHED remote-only parent POM (200) — first-request proxy fall-through works"
else
    fail "virtual returned $V_POM for uncached remote-only parent POM (remote serves it 200) — #1562"
fi
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
TOTAL=$((PASSED + FAILED + SKIPPED))
echo "=============================================="
echo "Virtual-Resolution Regression Results"
echo "=============================================="
echo "  Passed:  $PASSED"
echo "  Failed:  $FAILED"
echo "  Skipped: $SKIPPED"
echo "  Total:   $TOTAL"
echo ""
if [ "$FAILED" -gt 0 ]; then
    echo "RESULT: FAILURES PRESENT."
    echo "On 'main' this is EXPECTED — failures reproduce #1600/#1595/#1562."
    echo "After #1611 lands, this suite must be fully green."
    exit 1
fi
echo "RESULT: ALL PASSED (virtual resolution is correct — #1611 has landed)."
