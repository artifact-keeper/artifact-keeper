#!/bin/bash
# Curation E2E test script
#
# Tests the package curation workflow end-to-end:
#   1. Create remote + staging repos for RPM and DEB
#   2. Enable curation via SQL (scheduler syncs upstream metadata)
#   3. Verify packages appear in the curation catalog
#   4. Test rules (block, allow, version constraints, arch filters)
#   5. Test manual approve/block, bulk operations, stats
#   6. Test rule CRUD (update, delete, re-evaluate)
#   7. Repeat core flow for DEB format
#
# Requires: curl, jq, psql (postgresql-client), bash
# Environment: REGISTRY_URL, ADMIN_USER, ADMIN_PASS, MOCK_UPSTREAM_URL, PG* vars
set -uo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:8080}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-TestRunner!2026secure}"
MOCK_UPSTREAM_URL="${MOCK_UPSTREAM_URL:-http://localhost:9999}"
API_URL="$REGISTRY_URL/api/v1"
CURATION_URL="$API_URL/curation"

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

echo "=============================================="
echo "Curation E2E Tests"
echo "=============================================="
echo "Registry: $REGISTRY_URL"
echo "Mock upstream: $MOCK_UPSTREAM_URL"
echo ""

# ============================================================================
# Auth
# ============================================================================

echo "==> Authenticating..."
LOGIN_RESP=$(curl -sf -X POST "$API_URL/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" 2>&1) || {
    echo "ERROR: Failed to authenticate at $REGISTRY_URL"
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

# ============================================================================
# Phase 1: Create remote + staging repos for RPM
# ============================================================================

echo "==> Phase 1: Creating RPM remote + staging repos..."

# Create remote repo pointing at mock-upstream RPM
curl -s -o /dev/null -X DELETE "$API_URL/repositories/curation-rpm-remote" -H "$AUTH" 2>/dev/null || true
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/repositories" \
    -H "$AUTH" -H 'Content-Type: application/json' \
    -d "{\"key\":\"curation-rpm-remote\",\"name\":\"Curation RPM Remote\",\"format\":\"rpm\",\"repo_type\":\"remote\",\"upstream_url\":\"$MOCK_UPSTREAM_URL/rpm/\",\"is_public\":true}")
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
    pass "Create RPM remote repo"
else
    fail "Create RPM remote repo (HTTP $HTTP_CODE)"
fi

# Get the remote repo ID
REMOTE_RPM_ID=$(curl -sf "$API_URL/repositories/curation-rpm-remote" -H "$AUTH" | jq -r '.id')
echo "  Remote RPM repo ID: $REMOTE_RPM_ID"

# Create staging repo
curl -s -o /dev/null -X DELETE "$API_URL/repositories/curation-rpm-staging" -H "$AUTH" 2>/dev/null || true
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/repositories" \
    -H "$AUTH" -H 'Content-Type: application/json' \
    -d "{\"key\":\"curation-rpm-staging\",\"name\":\"Curation RPM Staging\",\"format\":\"rpm\",\"repo_type\":\"staging\",\"is_public\":true}")
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
    pass "Create RPM staging repo"
else
    fail "Create RPM staging repo (HTTP $HTTP_CODE)"
fi

# Get the staging repo ID
STAGING_RPM_ID=$(curl -sf "$API_URL/repositories/curation-rpm-staging" -H "$AUTH" | jq -r '.id')
echo "  Staging RPM repo ID: $STAGING_RPM_ID"

# ============================================================================
# Phase 2: Enable curation via SQL and wait for sync
# ============================================================================

echo ""
echo "==> Phase 2: Enable curation and wait for package sync..."

# Enable curation on the staging repo via direct SQL
psql -c "UPDATE repositories SET
    curation_enabled = true,
    curation_source_repo_id = '$REMOTE_RPM_ID',
    curation_default_action = 'review',
    curation_sync_interval_secs = 30
  WHERE id = '$STAGING_RPM_ID';"

pass "Enable curation on RPM staging repo"

# Poll the packages endpoint until 6 packages appear (max 90 seconds)
echo "  Waiting for curation sync (up to 90s)..."
SYNC_OK=false
for i in $(seq 1 30); do
    PKG_COUNT=$(curl -sf "$CURATION_URL/packages?staging_repo_id=$STAGING_RPM_ID&limit=50" \
        -H "$AUTH" | jq 'length')
    if [ "$PKG_COUNT" = "6" ]; then
        SYNC_OK=true
        break
    fi
    sleep 3
done

if [ "$SYNC_OK" = "true" ]; then
    pass "Curation sync found 6 RPM packages"
else
    fail "Curation sync timed out (got $PKG_COUNT packages, expected 6)"
    echo "  Cannot continue without synced packages. Exiting."
    exit 1
fi

# ============================================================================
# Phase 3: Verify initial state (default action = review)
# ============================================================================

echo ""
echo "==> Phase 3: Verify initial package state..."

# With default_action=review and no rules, all packages should be in "review" status
REVIEW_COUNT=$(curl -sf "$CURATION_URL/packages?staging_repo_id=$STAGING_RPM_ID&status=review" \
    -H "$AUTH" | jq 'length')
if [ "$REVIEW_COUNT" = "6" ]; then
    pass "All 6 packages in 'review' status (default action)"
else
    fail "Expected 6 packages in 'review', got $REVIEW_COUNT"
fi

# Verify stats endpoint
STATS=$(curl -sf "$CURATION_URL/stats?staging_repo_id=$STAGING_RPM_ID" -H "$AUTH")
STATS_REVIEW=$(echo "$STATS" | jq -r '.counts[] | select(.status == "review") | .count')
if [ "$STATS_REVIEW" = "6" ]; then
    pass "Stats endpoint shows 6 review packages"
else
    fail "Stats endpoint: expected 6 review, got $STATS_REVIEW"
fi

# ============================================================================
# Phase 4: Create block rule and re-evaluate
# ============================================================================

echo ""
echo "==> Phase 4: Block rule (telnet* pattern)..."

# Create a block rule for telnet* pattern
BLOCK_RULE=$(curl -sf -X POST "$CURATION_URL/rules" \
    -H "$AUTH" -H 'Content-Type: application/json' \
    -d "{\"staging_repo_id\":\"$STAGING_RPM_ID\",\"package_pattern\":\"telnet*\",\"action\":\"block\",\"priority\":10,\"reason\":\"Telnet is insecure\"}")
BLOCK_RULE_ID=$(echo "$BLOCK_RULE" | jq -r '.id')
if [ -n "$BLOCK_RULE_ID" ] && [ "$BLOCK_RULE_ID" != "null" ]; then
    pass "Create block rule for telnet* (ID: $BLOCK_RULE_ID)"
else
    fail "Create block rule for telnet*"
fi

# Re-evaluate all packages with default_action=review
EVAL_COUNT=$(curl -sf -X POST "$CURATION_URL/packages/re-evaluate" \
    -H "$AUTH" -H 'Content-Type: application/json' \
    -d "{\"staging_repo_id\":\"$STAGING_RPM_ID\",\"default_action\":\"review\"}")
pass "Re-evaluated packages (count: $EVAL_COUNT)"

# Verify telnet-server is blocked
TELNET_STATUS=$(curl -sf "$CURATION_URL/packages?staging_repo_id=$STAGING_RPM_ID&status=blocked" \
    -H "$AUTH" | jq -r '.[].package_name')
if echo "$TELNET_STATUS" | grep -q "telnet-server"; then
    pass "telnet-server is blocked"
else
    fail "telnet-server should be blocked, got: $TELNET_STATUS"
fi

# ============================================================================
# Phase 5: Allow rule (nginx exact match)
# ============================================================================

echo ""
echo "==> Phase 5: Allow rule (nginx exact match)..."

ALLOW_RULE=$(curl -sf -X POST "$CURATION_URL/rules" \
    -H "$AUTH" -H 'Content-Type: application/json' \
    -d "{\"staging_repo_id\":\"$STAGING_RPM_ID\",\"package_pattern\":\"nginx\",\"action\":\"allow\",\"priority\":10,\"reason\":\"Approved web server\"}")
ALLOW_RULE_ID=$(echo "$ALLOW_RULE" | jq -r '.id')
if [ -n "$ALLOW_RULE_ID" ] && [ "$ALLOW_RULE_ID" != "null" ]; then
    pass "Create allow rule for nginx"
else
    fail "Create allow rule for nginx"
fi

# Re-evaluate
curl -sf -X POST "$CURATION_URL/packages/re-evaluate" \
    -H "$AUTH" -H 'Content-Type: application/json' \
    -d "{\"staging_repo_id\":\"$STAGING_RPM_ID\",\"default_action\":\"review\"}" > /dev/null

# Verify nginx is approved
NGINX_PKG=$(curl -sf "$CURATION_URL/packages?staging_repo_id=$STAGING_RPM_ID&status=approved" \
    -H "$AUTH" | jq -r '.[].package_name')
if echo "$NGINX_PKG" | grep -q "nginx"; then
    pass "nginx is approved"
else
    fail "nginx should be approved"
fi

# ============================================================================
# Phase 6: Version constraint rule
# ============================================================================

echo ""
echo "==> Phase 6: Version constraint (block curl < 8.0)..."

VERSION_RULE=$(curl -sf -X POST "$CURATION_URL/rules" \
    -H "$AUTH" -H 'Content-Type: application/json' \
    -d "{\"staging_repo_id\":\"$STAGING_RPM_ID\",\"package_pattern\":\"curl\",\"version_constraint\":\"< 8.0\",\"action\":\"block\",\"priority\":5,\"reason\":\"Old curl has CVEs\"}")
VERSION_RULE_ID=$(echo "$VERSION_RULE" | jq -r '.id')
if [ -n "$VERSION_RULE_ID" ] && [ "$VERSION_RULE_ID" != "null" ]; then
    pass "Create version constraint rule (block curl < 8.0)"
else
    fail "Create version constraint rule"
fi

# Re-evaluate
curl -sf -X POST "$CURATION_URL/packages/re-evaluate" \
    -H "$AUTH" -H 'Content-Type: application/json' \
    -d "{\"staging_repo_id\":\"$STAGING_RPM_ID\",\"default_action\":\"review\"}" > /dev/null

# curl 8.5.0 should NOT be blocked (8.5.0 is not < 8.0)
CURL_STATUS=$(curl -sf "$CURATION_URL/packages?staging_repo_id=$STAGING_RPM_ID" \
    -H "$AUTH" | jq -r '.[] | select(.package_name == "curl") | .status')
if [ "$CURL_STATUS" = "review" ]; then
    pass "curl 8.5.0 is NOT blocked by '< 8.0' constraint (still review)"
else
    fail "curl 8.5.0 should be 'review' (version 8.5.0 >= 8.0), got: $CURL_STATUS"
fi

# ============================================================================
# Phase 7: Architecture filter rule
# ============================================================================

echo ""
echo "==> Phase 7: Architecture filter (block x86_64 only)..."

# Create rule that blocks wget but only for x86_64
ARCH_RULE=$(curl -sf -X POST "$CURATION_URL/rules" \
    -H "$AUTH" -H 'Content-Type: application/json' \
    -d "{\"staging_repo_id\":\"$STAGING_RPM_ID\",\"package_pattern\":\"wget\",\"architecture\":\"x86_64\",\"action\":\"block\",\"priority\":10,\"reason\":\"Block wget on x86_64\"}")
ARCH_RULE_ID=$(echo "$ARCH_RULE" | jq -r '.id')
if [ -n "$ARCH_RULE_ID" ] && [ "$ARCH_RULE_ID" != "null" ]; then
    pass "Create arch-specific block rule for wget (x86_64 only)"
else
    fail "Create arch-specific rule"
fi

# Re-evaluate
curl -sf -X POST "$CURATION_URL/packages/re-evaluate" \
    -H "$AUTH" -H 'Content-Type: application/json' \
    -d "{\"staging_repo_id\":\"$STAGING_RPM_ID\",\"default_action\":\"review\"}" > /dev/null

# wget (x86_64) should be blocked
WGET_STATUS=$(curl -sf "$CURATION_URL/packages?staging_repo_id=$STAGING_RPM_ID" \
    -H "$AUTH" | jq -r '.[] | select(.package_name == "wget") | .status')
if [ "$WGET_STATUS" = "blocked" ]; then
    pass "wget (x86_64) is blocked by arch-specific rule"
else
    fail "wget (x86_64) should be blocked, got: $WGET_STATUS"
fi

# nano (aarch64) should NOT be affected by x86_64-only rule
NANO_STATUS=$(curl -sf "$CURATION_URL/packages?staging_repo_id=$STAGING_RPM_ID" \
    -H "$AUTH" | jq -r '.[] | select(.package_name == "nano") | .status')
if [ "$NANO_STATUS" = "review" ]; then
    pass "nano (aarch64) is NOT blocked by x86_64-only rule"
else
    fail "nano (aarch64) should still be 'review', got: $NANO_STATUS"
fi

# ============================================================================
# Phase 8: Manual approve/block via single-package endpoints
# ============================================================================

echo ""
echo "==> Phase 8: Manual approve/block..."

# Get the curl package ID
CURL_PKG_ID=$(curl -sf "$CURATION_URL/packages?staging_repo_id=$STAGING_RPM_ID" \
    -H "$AUTH" | jq -r '.[] | select(.package_name == "curl") | .id')

# Manual approve
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$CURATION_URL/packages/$CURL_PKG_ID/approve" \
    -H "$AUTH")
if [ "$HTTP_CODE" = "200" ]; then
    pass "Manual approve curl"
else
    fail "Manual approve curl (HTTP $HTTP_CODE)"
fi

# Verify curl is now approved
CURL_STATUS=$(curl -sf "$CURATION_URL/packages/$CURL_PKG_ID" -H "$AUTH" | jq -r '.status')
if [ "$CURL_STATUS" = "approved" ]; then
    pass "curl status is 'approved' after manual approve"
else
    fail "curl should be 'approved', got: $CURL_STATUS"
fi

# Manual block
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$CURATION_URL/packages/$CURL_PKG_ID/block" \
    -H "$AUTH")
if [ "$HTTP_CODE" = "200" ]; then
    pass "Manual block curl"
else
    fail "Manual block curl (HTTP $HTTP_CODE)"
fi

CURL_STATUS=$(curl -sf "$CURATION_URL/packages/$CURL_PKG_ID" -H "$AUTH" | jq -r '.status')
if [ "$CURL_STATUS" = "blocked" ]; then
    pass "curl status is 'blocked' after manual block"
else
    fail "curl should be 'blocked', got: $CURL_STATUS"
fi

# ============================================================================
# Phase 9: Bulk approve
# ============================================================================

echo ""
echo "==> Phase 9: Bulk approve..."

# Get IDs of vim and nano (both should be in review)
VIM_PKG_ID=$(curl -sf "$CURATION_URL/packages?staging_repo_id=$STAGING_RPM_ID" \
    -H "$AUTH" | jq -r '.[] | select(.package_name == "vim") | .id')
NANO_PKG_ID=$(curl -sf "$CURATION_URL/packages?staging_repo_id=$STAGING_RPM_ID" \
    -H "$AUTH" | jq -r '.[] | select(.package_name == "nano") | .id')

BULK_RESULT=$(curl -sf -X POST "$CURATION_URL/packages/bulk-approve" \
    -H "$AUTH" -H 'Content-Type: application/json' \
    -d "{\"ids\":[\"$VIM_PKG_ID\",\"$NANO_PKG_ID\"],\"reason\":\"Bulk approved for testing\"}")
if [ "$BULK_RESULT" = "2" ]; then
    pass "Bulk approved 2 packages (vim, nano)"
else
    fail "Bulk approve returned $BULK_RESULT, expected 2"
fi

# ============================================================================
# Phase 10: Stats endpoint verification
# ============================================================================

echo ""
echo "==> Phase 10: Stats verification..."

# After all operations:
# - nginx: approved (allow rule)
# - curl: blocked (manually blocked)
# - telnet-server: blocked (block rule)
# - wget: blocked (arch rule)
# - vim: approved (bulk approved)
# - nano: approved (bulk approved)
STATS=$(curl -sf "$CURATION_URL/stats?staging_repo_id=$STAGING_RPM_ID" -H "$AUTH")
APPROVED_COUNT=$(echo "$STATS" | jq -r '.counts[] | select(.status == "approved") | .count // 0')
BLOCKED_COUNT=$(echo "$STATS" | jq -r '.counts[] | select(.status == "blocked") | .count // 0')
if [ "$APPROVED_COUNT" = "3" ] && [ "$BLOCKED_COUNT" = "3" ]; then
    pass "Stats: 3 approved, 3 blocked"
else
    fail "Stats: expected 3 approved + 3 blocked, got approved=$APPROVED_COUNT blocked=$BLOCKED_COUNT"
fi

# ============================================================================
# Phase 11: Rule CRUD (update, delete, re-evaluate)
# ============================================================================

echo ""
echo "==> Phase 11: Rule CRUD..."

# List rules
RULE_COUNT=$(curl -sf "$CURATION_URL/rules?staging_repo_id=$STAGING_RPM_ID" -H "$AUTH" | jq 'length')
if [ "$RULE_COUNT" -ge "4" ]; then
    pass "List rules: $RULE_COUNT rules found"
else
    fail "List rules: expected >= 4, got $RULE_COUNT"
fi

# Update the block rule priority (telnet rule)
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "$CURATION_URL/rules/$BLOCK_RULE_ID" \
    -H "$AUTH" -H 'Content-Type: application/json' \
    -d "{\"package_pattern\":\"telnet*\",\"action\":\"block\",\"priority\":99,\"reason\":\"Updated priority\",\"enabled\":true}")
if [ "$HTTP_CODE" = "200" ]; then
    pass "Update rule priority"
else
    fail "Update rule priority (HTTP $HTTP_CODE)"
fi

# Delete the arch rule
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$CURATION_URL/rules/$ARCH_RULE_ID" \
    -H "$AUTH")
if [ "$HTTP_CODE" = "204" ]; then
    pass "Delete arch rule"
else
    fail "Delete arch rule (HTTP $HTTP_CODE)"
fi

# Re-evaluate after deleting arch rule: wget should go back to review
curl -sf -X POST "$CURATION_URL/packages/re-evaluate" \
    -H "$AUTH" -H 'Content-Type: application/json' \
    -d "{\"staging_repo_id\":\"$STAGING_RPM_ID\",\"default_action\":\"review\"}" > /dev/null

WGET_STATUS=$(curl -sf "$CURATION_URL/packages?staging_repo_id=$STAGING_RPM_ID" \
    -H "$AUTH" | jq -r '.[] | select(.package_name == "wget") | .status')
if [ "$WGET_STATUS" = "review" ]; then
    pass "wget returns to 'review' after arch rule deleted"
else
    fail "wget should be 'review' after arch rule deleted, got: $WGET_STATUS"
fi

# ============================================================================
# Phase 12: Global rules (no staging_repo_id)
# ============================================================================

echo ""
echo "==> Phase 12: Global rules..."

# Create a global block rule (no staging_repo_id)
GLOBAL_RULE=$(curl -sf -X POST "$CURATION_URL/rules" \
    -H "$AUTH" -H 'Content-Type: application/json' \
    -d "{\"package_pattern\":\"nano\",\"action\":\"block\",\"priority\":1,\"reason\":\"Global: nano blocked everywhere\"}")
GLOBAL_RULE_ID=$(echo "$GLOBAL_RULE" | jq -r '.id')
if [ -n "$GLOBAL_RULE_ID" ] && [ "$GLOBAL_RULE_ID" != "null" ]; then
    pass "Create global block rule for nano"
else
    fail "Create global block rule"
fi

# Re-evaluate: nano should now be blocked (global rule takes effect, priority 1 < 10)
curl -sf -X POST "$CURATION_URL/packages/re-evaluate" \
    -H "$AUTH" -H 'Content-Type: application/json' \
    -d "{\"staging_repo_id\":\"$STAGING_RPM_ID\",\"default_action\":\"review\"}" > /dev/null

NANO_STATUS=$(curl -sf "$CURATION_URL/packages?staging_repo_id=$STAGING_RPM_ID" \
    -H "$AUTH" | jq -r '.[] | select(.package_name == "nano") | .status')
if [ "$NANO_STATUS" = "blocked" ]; then
    pass "nano blocked by global rule"
else
    fail "nano should be blocked by global rule, got: $NANO_STATUS"
fi

# ============================================================================
# Phase 13: DEB format (repeat core flow)
# ============================================================================

echo ""
echo "==> Phase 13: DEB format tests..."

# Create DEB remote repo
curl -s -o /dev/null -X DELETE "$API_URL/repositories/curation-deb-remote" -H "$AUTH" 2>/dev/null || true
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/repositories" \
    -H "$AUTH" -H 'Content-Type: application/json' \
    -d "{\"key\":\"curation-deb-remote\",\"name\":\"Curation DEB Remote\",\"format\":\"debian\",\"repo_type\":\"remote\",\"upstream_url\":\"$MOCK_UPSTREAM_URL/deb/\",\"is_public\":true}")
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
    pass "Create DEB remote repo"
else
    fail "Create DEB remote repo (HTTP $HTTP_CODE)"
fi

REMOTE_DEB_ID=$(curl -sf "$API_URL/repositories/curation-deb-remote" -H "$AUTH" | jq -r '.id')

# Create DEB staging repo
curl -s -o /dev/null -X DELETE "$API_URL/repositories/curation-deb-staging" -H "$AUTH" 2>/dev/null || true
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/repositories" \
    -H "$AUTH" -H 'Content-Type: application/json' \
    -d "{\"key\":\"curation-deb-staging\",\"name\":\"Curation DEB Staging\",\"format\":\"debian\",\"repo_type\":\"staging\",\"is_public\":true}")
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
    pass "Create DEB staging repo"
else
    fail "Create DEB staging repo (HTTP $HTTP_CODE)"
fi

STAGING_DEB_ID=$(curl -sf "$API_URL/repositories/curation-deb-staging" -H "$AUTH" | jq -r '.id')

# Enable curation via SQL
psql -c "UPDATE repositories SET
    curation_enabled = true,
    curation_source_repo_id = '$REMOTE_DEB_ID',
    curation_default_action = 'allow',
    curation_sync_interval_secs = 30
  WHERE id = '$STAGING_DEB_ID';"

pass "Enable curation on DEB staging repo"

# Wait for DEB sync
echo "  Waiting for DEB curation sync (up to 90s)..."
SYNC_OK=false
for i in $(seq 1 30); do
    PKG_COUNT=$(curl -sf "$CURATION_URL/packages?staging_repo_id=$STAGING_DEB_ID&limit=50" \
        -H "$AUTH" | jq 'length')
    if [ "$PKG_COUNT" = "6" ]; then
        SYNC_OK=true
        break
    fi
    sleep 3
done

if [ "$SYNC_OK" = "true" ]; then
    pass "DEB curation sync found 6 packages"
else
    fail "DEB curation sync timed out (got $PKG_COUNT packages)"
fi

# With default_action=allow, all packages should be approved (except nano blocked by global rule)
APPROVED_COUNT=$(curl -sf "$CURATION_URL/packages?staging_repo_id=$STAGING_DEB_ID&status=approved" \
    -H "$AUTH" | jq 'length')
if [ "$APPROVED_COUNT" -ge "5" ]; then
    pass "DEB packages auto-approved with default_action=allow ($APPROVED_COUNT approved)"
else
    fail "Expected >= 5 DEB packages approved, got $APPROVED_COUNT"
fi

# Check if nano was blocked by global rule (should be blocked, priority 1)
NANO_DEB_STATUS=$(curl -sf "$CURATION_URL/packages?staging_repo_id=$STAGING_DEB_ID" \
    -H "$AUTH" | jq -r '.[] | select(.package_name == "nano") | .status')
if [ "$NANO_DEB_STATUS" = "blocked" ]; then
    pass "DEB nano blocked by global rule (cross-repo)"
else
    fail "DEB nano should be blocked by global rule, got: $NANO_DEB_STATUS"
fi

# Create DEB-specific block rule for telnet
DEB_RULE=$(curl -sf -X POST "$CURATION_URL/rules" \
    -H "$AUTH" -H 'Content-Type: application/json' \
    -d "{\"staging_repo_id\":\"$STAGING_DEB_ID\",\"package_pattern\":\"telnet\",\"action\":\"block\",\"priority\":10,\"reason\":\"Block telnet in DEB\"}")
DEB_RULE_ID=$(echo "$DEB_RULE" | jq -r '.id')
if [ -n "$DEB_RULE_ID" ] && [ "$DEB_RULE_ID" != "null" ]; then
    pass "Create DEB-specific block rule for telnet"
else
    fail "Create DEB-specific block rule"
fi

# Re-evaluate DEB packages
curl -sf -X POST "$CURATION_URL/packages/re-evaluate" \
    -H "$AUTH" -H 'Content-Type: application/json' \
    -d "{\"staging_repo_id\":\"$STAGING_DEB_ID\",\"default_action\":\"allow\"}" > /dev/null

# Verify telnet is blocked in DEB
TELNET_DEB_STATUS=$(curl -sf "$CURATION_URL/packages?staging_repo_id=$STAGING_DEB_ID" \
    -H "$AUTH" | jq -r '.[] | select(.package_name == "telnet") | .status')
if [ "$TELNET_DEB_STATUS" = "blocked" ]; then
    pass "DEB telnet blocked by DEB-specific rule"
else
    fail "DEB telnet should be blocked, got: $TELNET_DEB_STATUS"
fi

# ============================================================================
# Cleanup: delete global rule so it doesn't affect other tests
# ============================================================================

curl -s -o /dev/null -X DELETE "$CURATION_URL/rules/$GLOBAL_RULE_ID" -H "$AUTH" 2>/dev/null || true

# ============================================================================
# Summary
# ============================================================================

echo ""
echo "=============================================="
echo "Curation E2E Test Results"
echo "=============================================="
echo -e "  ${GREEN}PASSED${NC}: $PASSED"
echo -e "  ${RED}FAILED${NC}: $FAILED"
echo -e "  ${YELLOW}SKIPPED${NC}: $SKIPPED"
echo "=============================================="

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0
