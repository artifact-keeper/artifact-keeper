#!/bin/sh
# Test: End-to-end artifact synchronization between peers
# Uploads an artifact to peer-a, subscribes peer-b, waits for the sync worker,
# and verifies the artifact is available on peer-b.
set -e

PEER_A_URL="http://backend-peer-a:8080"
PEER_B_URL="http://backend-peer-b:8080"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { echo "==> $1"; }
pass() { echo "  [PASS] $1"; }
fail() { echo "  [FAIL] $1"; exit 1; }

# Throwaway e2e admin credential: compose injects ADMIN_PASS into the
# mesh-test container from the repository-root .env.test (#3490).
: "${ADMIN_PASS:?ADMIN_PASS is not set (the mesh-test service reads it from .env.test)}"
LOGIN_BODY=$(jq -cn --arg p "$ADMIN_PASS" '{username: "admin", password: $p}')
: "${PEER_B_API_KEY:?PEER_B_API_KEY is not set (run-all-mesh-tests.sh mints it)}"

# Poll GET <url> with <token> until it returns 200 or MESH_SYNC_TIMEOUT_SECS
# (default 120) elapses. Prints the last HTTP status. The sync worker ticks
# every 10s, but a fresh peer and the retry backoff can delay the first
# transfer, so a single fixed sleep both under- and over-waits (#1936).
wait_for_http_200() {
  _url="$1"; _token="$2"; _deadline=$(( $(date +%s) + ${MESH_SYNC_TIMEOUT_SECS:-120} ))
  while :; do
    _code=$(curl -s -o /dev/null -w "%{http_code}" "$_url" -H "Authorization: Bearer $_token")
    if [ "$_code" = "200" ] || [ "$(date +%s)" -ge "$_deadline" ]; then
      echo "$_code"; return 0
    fi
    sleep 5
  done
}

# ---------------------------------------------------------------------------
# 1. Login to both peers
# ---------------------------------------------------------------------------
log "Logging in to peer-a..."
PEER_A_TOKEN=$(curl -sf -X POST "$PEER_A_URL/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "$LOGIN_BODY" | jq -r '.access_token')

[ -n "$PEER_A_TOKEN" ] && [ "$PEER_A_TOKEN" != "null" ] \
  && pass "peer-a login succeeded" \
  || fail "peer-a login failed"

log "Logging in to peer-b..."
PEER_B_TOKEN=$(curl -sf -X POST "$PEER_B_URL/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "$LOGIN_BODY" | jq -r '.access_token')

[ -n "$PEER_B_TOKEN" ] && [ "$PEER_B_TOKEN" != "null" ] \
  && pass "peer-b login succeeded" \
  || fail "peer-b login failed"

# ---------------------------------------------------------------------------
# 2. Create repository on peer-a
# ---------------------------------------------------------------------------
log "Creating repository 'mesh-sync-test' on peer-a..."
curl -sf -X POST "$PEER_A_URL/api/v1/repositories" \
  -H "Authorization: Bearer $PEER_A_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "key": "mesh-sync-test",
    "name": "Mesh Sync Test",
    "format": "generic",
    "repo_type": "local",
    "is_public": true
  }' >/dev/null 2>&1 || true
pass "repository 'mesh-sync-test' ensured on peer-a"

# ---------------------------------------------------------------------------
# 3. Create same repository on peer-b (so it can receive artifacts)
# ---------------------------------------------------------------------------
log "Creating repository 'mesh-sync-test' on peer-b..."
curl -sf -X POST "$PEER_B_URL/api/v1/repositories" \
  -H "Authorization: Bearer $PEER_B_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "key": "mesh-sync-test",
    "name": "Mesh Sync Test",
    "format": "generic",
    "repo_type": "local",
    "is_public": true
  }' >/dev/null 2>&1 || true
pass "repository 'mesh-sync-test' ensured on peer-b"

# ---------------------------------------------------------------------------
# 4. Register peer-b on peer-a (if not already done)
# ---------------------------------------------------------------------------
log "Ensuring peer-b is registered on peer-a..."
curl -s -X POST "$PEER_A_URL/api/v1/peers" \
  -H "Authorization: Bearer $PEER_A_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "peer-b",
    "endpoint_url": "http://backend-peer-b:8080",
    "region": "us-west-2",
    "api_key": "'"$PEER_B_API_KEY"'"
  }' >/dev/null 2>&1 || true
pass "peer-b registration ensured"

# Get peer-b ID from peer list on peer-a
PEERS_ON_A=$(curl -sf -X GET "$PEER_A_URL/api/v1/peers" \
  -H "Authorization: Bearer $PEER_A_TOKEN")

PEER_B_ID=$(echo "$PEERS_ON_A" | jq -r '
  if .items then
    [.items[] | select(.name == "peer-b" or .endpoint_url == "http://backend-peer-b:8080")][0] | .id // empty
  elif type == "array" then
    [.[] | select(.name == "peer-b" or .endpoint_url == "http://backend-peer-b:8080")][0] | .id // empty
  else empty end')

[ -n "$PEER_B_ID" ] \
  && pass "peer-b ID on peer-a: $PEER_B_ID" \
  || fail "could not find peer-b in peer-a peer list"

# ---------------------------------------------------------------------------
# 5. Look up the repository ID for mesh-sync-test
# ---------------------------------------------------------------------------
log "Looking up repository ID for 'mesh-sync-test'..."
REPO_ID=$(curl -sf -X GET "$PEER_A_URL/api/v1/repositories" \
  -H "Authorization: Bearer $PEER_A_TOKEN" | jq -r '
  if .items then
    [.items[] | select(.key == "mesh-sync-test")][0] | .id // empty
  elif type == "array" then
    [.[] | select(.key == "mesh-sync-test")][0] | .id // empty
  else empty end')

[ -n "$REPO_ID" ] \
  && pass "repository ID: $REPO_ID" \
  || fail "could not find repository 'mesh-sync-test'"

# ---------------------------------------------------------------------------
# 6. Subscribe peer-b to the repo
# ---------------------------------------------------------------------------
log "Subscribing peer-b to 'mesh-sync-test'..."
SUB_RESP=$(curl -s -X POST "$PEER_A_URL/api/v1/peers/$PEER_B_ID/repositories" \
  -H "Authorization: Bearer $PEER_A_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"repository_id\": \"$REPO_ID\", \"replication_mode\": \"push\", \"sync_enabled\": true}" 2>/dev/null || echo "{}")

pass "peer-b subscribed to 'mesh-sync-test'"

# ---------------------------------------------------------------------------
# 7. Upload artifact to peer-a
# ---------------------------------------------------------------------------
log "Uploading artifact to peer-a..."
ARTIFACT_CONTENT="mesh-replication-e2e-test-content-$(date +%s)"
UPLOAD_RESP=$(printf '%s' "$ARTIFACT_CONTENT" | curl -sf -X PUT \
  "$PEER_A_URL/api/v1/repositories/mesh-sync-test/artifacts/test/sync-file.bin" \
  -H "Authorization: Bearer $PEER_A_TOKEN" \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @-)

pass "artifact uploaded to peer-a"

# ---------------------------------------------------------------------------
# 8. Wait briefly and check sync tasks
# ---------------------------------------------------------------------------
log "Waiting 2 seconds before checking sync tasks..."
sleep 2

TASKS_RESP=$(curl -sf -X GET "$PEER_A_URL/api/v1/peers/$PEER_B_ID/sync/tasks" \
  -H "Authorization: Bearer $PEER_A_TOKEN" 2>/dev/null || echo "[]")

TASK_COUNT=$(echo "$TASKS_RESP" | jq -r '
  if type == "array" then length
  elif .items then (.items | length)
  else 0 end')

[ "$TASK_COUNT" -gt 0 ] 2>/dev/null \
  && pass "sync tasks found: $TASK_COUNT task(s)" \
  || echo "  [INFO] no sync tasks found yet (may appear after worker run)"

# ---------------------------------------------------------------------------
# 9. Verify the artifact arrives on peer-b
# ---------------------------------------------------------------------------
log "Waiting up to ${MESH_SYNC_TIMEOUT_SECS:-120}s for the artifact to arrive on peer-b..."
DOWNLOAD_STATUS=$(wait_for_http_200 \
  "$PEER_B_URL/api/v1/repositories/mesh-sync-test/artifacts/test/sync-file.bin" "$PEER_B_TOKEN")

# Report the task states either way: they are what tells a worker that never
# claimed the task apart from one whose transfer failed.
TASKS_AFTER=$(curl -sf -X GET "$PEER_A_URL/api/v1/peers/$PEER_B_ID/sync/tasks" \
  -H "Authorization: Bearer $PEER_A_TOKEN" 2>/dev/null || echo "[]")
echo "  [INFO] sync task states on peer-a: $(echo "$TASKS_AFTER" | jq -c '
  if type == "array" then [.[] | .status]
  elif .items then [.items[] | .status]
  else . end')"

# Queued tasks are not replication: until #1936 this step passed on
# "tasks were created" alone, so it could never catch a sync worker that
# queues and then never delivers.
[ "$DOWNLOAD_STATUS" = "200" ] \
  && pass "artifact successfully synced to peer-b (HTTP 200)" \
  || fail "artifact not on peer-b after ${MESH_SYNC_TIMEOUT_SECS:-120}s (HTTP $DOWNLOAD_STATUS, $TASK_COUNT task(s) queued)"

echo ""
echo "Artifact sync test completed successfully."
