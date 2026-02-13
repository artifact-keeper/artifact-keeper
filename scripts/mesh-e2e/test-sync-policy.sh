#!/bin/sh
# Test: Sync policy creation and auto-subscription via evaluation
# Creates a sync policy on peer-a that targets all peers for generic-format
# repositories, evaluates it, and verifies that peer-b gets subscribed.
set -e

PEER_A_URL="http://backend-peer-a:8080"
PEER_B_URL="http://backend-peer-b:8080"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { echo "==> $1"; }
pass() { echo "  [PASS] $1"; }
fail() { echo "  [FAIL] $1"; exit 1; }

# ---------------------------------------------------------------------------
# 1. Login to peer-a
# ---------------------------------------------------------------------------
log "Logging in to peer-a..."
PEER_A_TOKEN=$(curl -sf -X POST "$PEER_A_URL/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}' | jq -r '.access_token')

[ -n "$PEER_A_TOKEN" ] && [ "$PEER_A_TOKEN" != "null" ] \
  && pass "peer-a login succeeded" \
  || fail "peer-a login failed"

# ---------------------------------------------------------------------------
# 2. Create a test repository on peer-a
# ---------------------------------------------------------------------------
log "Creating repository 'mesh-policy-test' on peer-a..."
curl -sf -X POST "$PEER_A_URL/api/v1/repositories" \
  -H "Authorization: Bearer $PEER_A_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "key": "mesh-policy-test",
    "name": "Mesh Policy Test",
    "format": "generic",
    "repo_type": "local",
    "is_public": true
  }' >/dev/null 2>&1 || true
pass "repository 'mesh-policy-test' ensured on peer-a"

# ---------------------------------------------------------------------------
# 3. Ensure peer-b is registered on peer-a
# ---------------------------------------------------------------------------
log "Ensuring peer-b is registered on peer-a..."
curl -sf -X POST "$PEER_A_URL/api/v1/peers" \
  -H "Authorization: Bearer $PEER_A_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "peer-b",
    "endpoint_url": "http://backend-peer-b:8080",
    "region": "us-west-2",
    "api_key": "peer-b-key"
  }' >/dev/null 2>&1 || true
pass "peer-b registration ensured"

# Get peer-b ID from peer list on peer-a
PEERS_ON_A=$(curl -sf -X GET "$PEER_A_URL/api/v1/peers" \
  -H "Authorization: Bearer $PEER_A_TOKEN")

PEER_B_ID=$(echo "$PEERS_ON_A" | jq -r '
  if type == "array" then
    [.[] | select(.name == "peer-b" or .endpoint_url == "http://backend-peer-b:8080")][0] | .id // .peer_id // empty
  elif .peers then
    [.peers[] | select(.name == "peer-b" or .endpoint_url == "http://backend-peer-b:8080")][0] | .id // .peer_id // empty
  else empty end')

[ -n "$PEER_B_ID" ] \
  && pass "peer-b ID on peer-a: $PEER_B_ID" \
  || fail "could not find peer-b in peer-a peer list"

# ---------------------------------------------------------------------------
# 4. Create sync policy
# ---------------------------------------------------------------------------
log "Creating sync policy 'e2e-test-policy'..."
POLICY_RESP=$(curl -sf -X POST "$PEER_A_URL/api/v1/sync-policies" \
  -H "Authorization: Bearer $PEER_A_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "e2e-test-policy",
    "enabled": true,
    "repo_selector": {"match_formats": ["generic"]},
    "peer_selector": {"all": true},
    "replication_mode": "push",
    "priority": 0
  }')

POLICY_ID=$(echo "$POLICY_RESP" | jq -r '.id // .policy_id // empty')
[ -n "$POLICY_ID" ] \
  && pass "sync policy created (id=$POLICY_ID)" \
  || fail "failed to create sync policy: $POLICY_RESP"

# ---------------------------------------------------------------------------
# 5. Evaluate sync policies
# ---------------------------------------------------------------------------
log "Evaluating sync policies..."
EVAL_RESP=$(curl -sf -X POST "$PEER_A_URL/api/v1/sync-policies/evaluate" \
  -H "Authorization: Bearer $PEER_A_TOKEN" \
  -H 'Content-Type: application/json')

pass "sync policy evaluation triggered"

# Give the backend a moment to process subscriptions
sleep 2

# ---------------------------------------------------------------------------
# 6. Verify peer-b has subscriptions
# ---------------------------------------------------------------------------
log "Checking subscriptions for peer-b..."
SUBS_RESP=$(curl -sf -X GET "$PEER_A_URL/api/v1/peers/$PEER_B_ID/repositories" \
  -H "Authorization: Bearer $PEER_A_TOKEN" 2>/dev/null || echo "[]")

# Check if the generic repo is subscribed
SUB_COUNT=$(echo "$SUBS_RESP" | jq -r '
  if type == "array" then
    [.[] | select(.repository_key == "mesh-policy-test" or .key == "mesh-policy-test" or .repo_key == "mesh-policy-test")] | length
  elif .repositories then
    [.repositories[] | select(.repository_key == "mesh-policy-test" or .key == "mesh-policy-test" or .repo_key == "mesh-policy-test")] | length
  elif .subscriptions then
    [.subscriptions[] | select(.repository_key == "mesh-policy-test" or .key == "mesh-policy-test" or .repo_key == "mesh-policy-test")] | length
  else 0 end')

[ "$SUB_COUNT" -gt 0 ] 2>/dev/null \
  && pass "peer-b is subscribed to 'mesh-policy-test' via sync policy" \
  || fail "peer-b subscription not found for 'mesh-policy-test' after policy evaluation (subs=$SUBS_RESP)"

echo ""
echo "Sync policy test completed successfully."
