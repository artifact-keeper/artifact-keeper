#!/usr/bin/env bash
# Cache-correctness E2E tests against a controllable mock upstream (#1625, gate for #1611)
#
# Invariant ④ (issue #1611): cache freshness is a per-path-pattern property.
#   * IMMUTABLE paths (versioned jar, digest-addressed blob) cache forever — after
#     the first fetch they are NEVER re-fetched upstream within the TTL window.
#   * MUTABLE paths (maven-metadata.xml, PyPI simple index, npm packument) get a
#     short TTL and are REVALIDATED via conditional request (If-None-Match /
#     If-Modified-Since); a 304 keeps serving cache cheaply, and a CHANGED upstream
#     (new ETag/body) is reflected promptly.
#   * NEGATIVE cache: a 404 then an upstream publish becomes visible within the
#     short negative TTL.
#
# Assertions are black-box: they read the mock upstream's request COUNTER
# (/__mock__/count) rather than inspecting artifact-keeper internals.
#
# RED on `main` by design: today the cache layer does not classify
# immutable-vs-mutable, so the counter/TTL assertions are expected to FAIL until
# #1611 lands. A failure here proves the mis-caching.
#
# Usage:
#   MOCK_UPSTREAM_URL=http://mock-upstream:9101 ./test-proxy-cache-correctness.sh
#   REGISTRY_URL=http://localhost:8080 MOCK_UPSTREAM_URL=http://localhost:9101 \
#     CACHE_TTL_SECONDS=30 ./test-proxy-cache-correctness.sh
#
# Requires: curl, jq.
set -uo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:8080}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-TestRunner!2026secure}"
MOCK_UPSTREAM_URL="${MOCK_UPSTREAM_URL:-http://localhost:9101}"
API_URL="$REGISTRY_URL/api/v1"
# How long to wait for a mutable path's TTL to expire before asserting
# revalidation. Override to match the backend's configured metadata TTL.
CACHE_TTL_SECONDS="${CACHE_TTL_SECONDS:-30}"
# Short negative-cache TTL window (seconds) to wait after publishing a 404 path.
NEG_TTL_SECONDS="${NEG_TTL_SECONDS:-15}"
# Number of repeat pulls within the immutable TTL window.
IMMUTABLE_PULLS="${IMMUTABLE_PULLS:-5}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASSED=0; FAILED=0; SKIPPED=0
pass() { echo -e "  ${GREEN}PASS${NC}: $1"; PASSED=$((PASSED + 1)); }
fail() { echo -e "  ${RED}FAIL${NC}: $1"; FAILED=$((FAILED + 1)); }
skip() { echo -e "  ${YELLOW}SKIP${NC}: $1"; SKIPPED=$((SKIPPED + 1)); }

echo "=============================================="
echo "Cache-Correctness E2E (immutable vs mutable, #1611)"
echo "=============================================="
echo "Registry:      $REGISTRY_URL"
echo "Mock upstream: $MOCK_UPSTREAM_URL"
echo "Metadata TTL wait: ${CACHE_TTL_SECONDS}s, negative TTL wait: ${NEG_TTL_SECONDS}s"
echo "NOTE: RED on 'main' by design — reproduces immutable-vs-mutable mis-caching."
echo ""

# ---- mock control-plane helpers -------------------------------------------
mock_reset() { curl -s -X POST "$MOCK_UPSTREAM_URL/__mock__/reset" >/dev/null; }
mock_count() {
    # $1 = upstream path. Echoes the request counter (data-plane 200s).
    curl -sf "$MOCK_UPSTREAM_URL/__mock__/count?path=$1" 2>/dev/null | jq -r '.count // 0'
}
mock_revalidations() {
    curl -sf "$MOCK_UPSTREAM_URL/__mock__/count?path=$1" 2>/dev/null | jq -r '.revalidations // 0'
}
mock_mutate()    { curl -s -X POST "$MOCK_UPSTREAM_URL/__mock__/mutate?path=$1" >/dev/null; }
mock_publish()   { curl -s -X POST "$MOCK_UPSTREAM_URL/__mock__/publish?path=$1" --data-binary "${2:-published}" >/dev/null; }
mock_unpublish() { curl -s -X POST "$MOCK_UPSTREAM_URL/__mock__/unpublish?path=$1" >/dev/null; }

# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
echo "==> Authenticating..."
LOGIN_RESP=$(curl -sf -X POST "$API_URL/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" 2>&1) || {
    echo "ERROR: Failed to authenticate. Is the backend running at $REGISTRY_URL?"; exit 1; }
TOKEN=$(echo "$LOGIN_RESP" | jq -r '.access_token')
[ -n "$TOKEN" ] && [ "$TOKEN" != "null" ] || { echo "ERROR: no auth token"; exit 1; }
AUTH="Authorization: Bearer $TOKEN"
echo "  Authenticated successfully"
echo ""

create_repo() {
    local key="$1" name="$2" format="$3" repo_type="$4" upstream_url="${5:-}"
    curl -s -o /dev/null -X DELETE "$API_URL/repositories/$key" -H "$AUTH" 2>/dev/null || true
    local body="{\"key\":\"$key\",\"name\":\"$name\",\"format\":\"$format\",\"repo_type\":\"$repo_type\",\"is_public\":true"
    [ -n "$upstream_url" ] && body="$body,\"upstream_url\":\"$upstream_url\""
    body="$body}"
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/repositories" \
        -H "$AUTH" -H 'Content-Type: application/json' -d "$body")
    if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then return 0; fi
    echo "  ERROR: create_repo $key returned HTTP $http_code"; exit 1
}

# ---------------------------------------------------------------------------
# Phase 0: mock upstream readiness + repos
# ---------------------------------------------------------------------------
echo "==> Phase 0: Waiting for mock upstream + creating remote repos..."
MOCK_READY=0
for _ in $(seq 1 30); do
    curl -sf "$MOCK_UPSTREAM_URL/__mock__/health" >/dev/null 2>&1 && { MOCK_READY=1; break; }
    sleep 1
done
[ "$MOCK_READY" = "1" ] || { echo "ERROR: mock upstream unreachable at $MOCK_UPSTREAM_URL"; exit 1; }
mock_reset

create_repo "cache-maven-remote" "Cache Maven Remote" "maven" "remote" "$MOCK_UPSTREAM_URL/maven2"
create_repo "cache-pypi-remote"  "Cache PyPI Remote"  "pypi"  "remote" "$MOCK_UPSTREAM_URL"
echo "  - cache-maven-remote -> $MOCK_UPSTREAM_URL/maven2"
echo "  - cache-pypi-remote  -> $MOCK_UPSTREAM_URL"
echo ""

# Upstream paths (as the mock sees them, after the repo's upstream prefix).
IMMUTABLE_JAR_UP="/maven2/com/example/widget/1.0.0/widget-1.0.0.jar"
MUTABLE_MD_UP="/maven2/com/example/widget/maven-metadata.xml"
SIMPLE_UP="/simple/lonelydep/"
LATE_JAR_UP="/maven2/com/example/late/1.0.0/late-1.0.0.jar"

# Proxy URLs (what a client hits on artifact-keeper).
IMMUTABLE_JAR="$REGISTRY_URL/maven/cache-maven-remote/com/example/widget/1.0.0/widget-1.0.0.jar"
MUTABLE_MD="$REGISTRY_URL/maven/cache-maven-remote/com/example/widget/maven-metadata.xml"
SIMPLE_IDX="$REGISTRY_URL/pypi/cache-pypi-remote/simple/lonelydep/"
LATE_JAR="$REGISTRY_URL/maven/cache-maven-remote/com/example/late/1.0.0/late-1.0.0.jar"

# ---------------------------------------------------------------------------
# Phase 1: IMMUTABLE — versioned jar fetched exactly once across many pulls
# ---------------------------------------------------------------------------
echo "==> Phase 1: Immutable path cached forever (counter stays 1)"
mock_reset
echo "  Pulling $IMMUTABLE_PULLS times within the TTL window..."
ALL_200=1
for i in $(seq 1 "$IMMUTABLE_PULLS"); do
    code=$(curl -s -o /dev/null -w "%{http_code}" "$IMMUTABLE_JAR")
    [ "$code" = "200" ] || { ALL_200=0; echo "    pull $i -> HTTP $code"; }
done
IMM_COUNT=$(mock_count "$IMMUTABLE_JAR_UP")
if [ "$ALL_200" = "1" ]; then
    pass "all $IMMUTABLE_PULLS immutable pulls returned 200"
else
    fail "not all immutable pulls returned 200"
fi
if [ "$IMM_COUNT" = "1" ]; then
    pass "immutable jar fetched upstream exactly once (counter=1) across $IMMUTABLE_PULLS pulls"
else
    fail "immutable jar hit upstream $IMM_COUNT times (expected 1) — immutable mis-cache — #1611"
fi
echo ""

# ---------------------------------------------------------------------------
# Phase 2: MUTABLE — revalidate after TTL; 304 keeps cache; change is reflected
# ---------------------------------------------------------------------------
echo "==> Phase 2: Mutable path revalidates via conditional request"
mock_reset

echo "  [2a] First fetch populates cache..."
MD1=$(curl -s -o /dev/null -w "%{http_code}" "$MUTABLE_MD")
MD_COUNT_1=$(mock_count "$MUTABLE_MD_UP")
if [ "$MD1" = "200" ] && [ "$MD_COUNT_1" = "1" ]; then
    pass "first metadata fetch: 200, upstream counter=1"
else
    fail "first metadata fetch HTTP=$MD1 upstream-count=$MD_COUNT_1 (expected 200 / 1)"
fi

echo "  [2b] Second fetch within TTL is served from cache (no new upstream 200)..."
curl -s -o /dev/null "$MUTABLE_MD"
MD_COUNT_2=$(mock_count "$MUTABLE_MD_UP")
if [ "$MD_COUNT_2" = "1" ]; then
    pass "within-TTL metadata re-fetch served from cache (upstream counter still 1)"
else
    fail "within-TTL metadata re-fetch hit upstream ($MD_COUNT_2) — TTL not honored — #1611"
fi

echo "  [2c] Waiting ${CACHE_TTL_SECONDS}s for TTL expiry, then revalidate (expect 304, body unchanged)..."
sleep "$CACHE_TTL_SECONDS"
BODY_BEFORE=$(curl -s "$MUTABLE_MD")
REVAL=$(mock_revalidations "$MUTABLE_MD_UP")
if [ "$REVAL" -ge 1 ] 2>/dev/null; then
    pass "post-TTL fetch issued a conditional revalidation (mock answered 304 x$REVAL)"
else
    fail "post-TTL fetch did NOT revalidate conditionally (revalidations=$REVAL) — #1611"
fi
if echo "$BODY_BEFORE" | grep -q "<artifactId>widget</artifactId>"; then
    pass "post-revalidation body still served correctly"
else
    skip "could not confirm metadata body shape (revalidation counter is the primary assertion)"
fi

echo "  [2d] Mutate upstream (new ETag/body), then a fetch must reflect the change promptly..."
mock_mutate "$MUTABLE_MD_UP"
sleep "$CACHE_TTL_SECONDS"
BODY_AFTER=$(curl -s "$MUTABLE_MD")
if echo "$BODY_AFTER" | grep -q "1.1.0"; then
    pass "changed upstream metadata reflected after TTL (now lists 1.1.0)"
else
    fail "changed upstream metadata NOT reflected (still stale) — mutable serving stale — #1611"
fi
echo ""

# ---------------------------------------------------------------------------
# Phase 3: MUTABLE — PyPI simple index revalidation (second format)
# ---------------------------------------------------------------------------
echo "==> Phase 3: PyPI simple index is mutable (reflects upstream change)"
mock_reset
S1=$(curl -s -o /dev/null -w "%{http_code}" "$SIMPLE_IDX")
if [ "$S1" = "200" ]; then
    pass "simple index first fetch 200"
else
    skip "simple index first fetch HTTP $S1 (proxy may rewrite PyPI URLs differently)"
fi
mock_mutate "$SIMPLE_UP"   # flips 2.3.0 -> 2.4.0 in the index body
sleep "$CACHE_TTL_SECONDS"
SIDX_AFTER=$(curl -s "$SIMPLE_IDX")
if echo "$SIDX_AFTER" | grep -q "2.4.0"; then
    pass "changed PyPI simple index reflected after TTL (now lists 2.4.0)"
else
    fail "changed PyPI simple index NOT reflected after TTL (stale index) — #1611"
fi
echo ""

# ---------------------------------------------------------------------------
# Phase 4: NEGATIVE cache — 404 then publish becomes visible within negative TTL
# ---------------------------------------------------------------------------
echo "==> Phase 4: Negative cache (404 then publish becomes visible)"
mock_reset
mock_unpublish "$LATE_JAR_UP"   # ensure it starts as 404 upstream

echo "  [4a] First fetch of a missing path returns 404 (populates negative cache)..."
N1=$(curl -s -o /dev/null -w "%{http_code}" "$LATE_JAR")
if [ "$N1" = "404" ]; then
    pass "missing artifact returns 404"
else
    fail "missing artifact returned $N1 (expected 404)"
fi

echo "  [4b] Publish upstream, then within negative TTL the artifact becomes visible..."
mock_publish "$LATE_JAR_UP" "late-jar-now-published"
# Negative cache should be SHORT; poll up to NEG_TTL_SECONDS for it to appear.
VISIBLE=0
for _ in $(seq 1 "$NEG_TTL_SECONDS"); do
    NC2=$(curl -s -o /dev/null -w "%{http_code}" "$LATE_JAR")
    if [ "$NC2" = "200" ]; then VISIBLE=1; break; fi
    sleep 1
done
if [ "$VISIBLE" = "1" ]; then
    pass "published artifact became visible within negative-TTL window (200)"
else
    fail "published artifact still 404 after ${NEG_TTL_SECONDS}s — negative cache too sticky — #1611"
fi
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
TOTAL=$((PASSED + FAILED + SKIPPED))
echo "=============================================="
echo "Cache-Correctness Results"
echo "=============================================="
echo "  Passed:  $PASSED"
echo "  Failed:  $FAILED"
echo "  Skipped: $SKIPPED"
echo "  Total:   $TOTAL"
echo ""
if [ "$FAILED" -gt 0 ]; then
    echo "RESULT: FAILURES PRESENT."
    echo "On 'main' this is EXPECTED — failures reproduce immutable-vs-mutable mis-caching."
    echo "After #1611 lands, this suite must be fully green."
    exit 1
fi
echo "RESULT: ALL PASSED (cache classification is correct — #1611 has landed)."
