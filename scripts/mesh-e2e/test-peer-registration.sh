#!/bin/sh
# Test: Bidirectional peer registration
# Registers peer-b on peer-a, then announces peer-a to peer-b, and verifies
# that each peer can see the other in its peer list.
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
# 2. Get peer-a identity
# ---------------------------------------------------------------------------
log "Getting peer-a identity..."
PEER_A_IDENTITY=$(curl -sf -X GET "$PEER_A_URL/api/v1/peers/identity" \
  -H "Authorization: Bearer $PEER_A_TOKEN")

PEER_A_INSTANCE_ID=$(echo "$PEER_A_IDENTITY" | jq -r '.peer_instance_id // .id // empty')
PEER_A_NAME=$(echo "$PEER_A_IDENTITY" | jq -r '.name // empty')

[ -n "$PEER_A_INSTANCE_ID" ] \
  && pass "peer-a identity: id=$PEER_A_INSTANCE_ID name=$PEER_A_NAME" \
  || fail "could not retrieve peer-a identity"

# ---------------------------------------------------------------------------
# 3. Register peer-b on peer-a
# ---------------------------------------------------------------------------
log "Registering peer-b on peer-a..."
REGISTER_RESP=$(curl -sf -X POST "$PEER_A_URL/api/v1/peers" \
  -H "Authorization: Bearer $PEER_A_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "peer-b",
    "endpoint_url": "http://backend-peer-b:8080",
    "region": "us-west-2",
    "api_key": "peer-b-key"
  }')

PEER_B_ID_ON_A=$(echo "$REGISTER_RESP" | jq -r '.id // .peer_id // empty')
[ -n "$PEER_B_ID_ON_A" ] \
  && pass "peer-b registered on peer-a (id=$PEER_B_ID_ON_A)" \
  || fail "failed to register peer-b on peer-a: $REGISTER_RESP"

# ---------------------------------------------------------------------------
# 4. Login to peer-b
# ---------------------------------------------------------------------------
log "Logging in to peer-b..."
PEER_B_TOKEN=$(curl -sf -X POST "$PEER_B_URL/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}' | jq -r '.access_token')

[ -n "$PEER_B_TOKEN" ] && [ "$PEER_B_TOKEN" != "null" ] \
  && pass "peer-b login succeeded" \
  || fail "peer-b login failed"

# ---------------------------------------------------------------------------
# 5. Announce peer-a to peer-b
# ---------------------------------------------------------------------------
log "Announcing peer-a to peer-b..."
ANNOUNCE_RESP=$(curl -sf -X POST "$PEER_B_URL/api/v1/peers/announce" \
  -H "Authorization: Bearer $PEER_B_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{
    \"peer_instance_id\": \"$PEER_A_INSTANCE_ID\",
    \"name\": \"peer-a\",
    \"endpoint_url\": \"http://backend-peer-a:8080\",
    \"api_key\": \"peer-a-key\"
  }")

PEER_A_ID_ON_B=$(echo "$ANNOUNCE_RESP" | jq -r '.id // .peer_id // empty')
[ -n "$PEER_A_ID_ON_B" ] \
  && pass "peer-a announced on peer-b (id=$PEER_A_ID_ON_B)" \
  || fail "failed to announce peer-a on peer-b: $ANNOUNCE_RESP"

# ---------------------------------------------------------------------------
# 6. Verify peer-a is listed on peer-b
# ---------------------------------------------------------------------------
log "Verifying peer-a visible on peer-b..."
PEERS_ON_B=$(curl -sf -X GET "$PEER_B_URL/api/v1/peers" \
  -H "Authorization: Bearer $PEER_B_TOKEN")

PEER_A_FOUND=$(echo "$PEERS_ON_B" | jq -r '
  if type == "array" then
    [.[] | select(.name == "peer-a" or .endpoint_url == "http://backend-peer-a:8080")] | length
  elif .peers then
    [.peers[] | select(.name == "peer-a" or .endpoint_url == "http://backend-peer-a:8080")] | length
  else 0 end')

[ "$PEER_A_FOUND" -gt 0 ] 2>/dev/null \
  && pass "peer-a is listed on peer-b" \
  || fail "peer-a NOT found in peer-b peer list"

# ---------------------------------------------------------------------------
# 7. Verify peer-b is listed on peer-a
# ---------------------------------------------------------------------------
log "Verifying peer-b visible on peer-a..."
PEERS_ON_A=$(curl -sf -X GET "$PEER_A_URL/api/v1/peers" \
  -H "Authorization: Bearer $PEER_A_TOKEN")

PEER_B_FOUND=$(echo "$PEERS_ON_A" | jq -r '
  if type == "array" then
    [.[] | select(.name == "peer-b" or .endpoint_url == "http://backend-peer-b:8080")] | length
  elif .peers then
    [.peers[] | select(.name == "peer-b" or .endpoint_url == "http://backend-peer-b:8080")] | length
  else 0 end')

[ "$PEER_B_FOUND" -gt 0 ] 2>/dev/null \
  && pass "peer-b is listed on peer-a" \
  || fail "peer-b NOT found in peer-a peer list"

echo ""
echo "Peer registration test completed successfully."
