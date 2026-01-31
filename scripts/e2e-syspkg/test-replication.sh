#!/usr/bin/env bash
# Replication E2E test -- edge nodes, sync tasks, chunked transfer, peer mesh
#
# Usage:
#   ./scripts/e2e-syspkg/test-replication.sh
#
# Prerequisites:
#   docker compose up -d   (backend + postgres must be running on port 30080)
set -euo pipefail

BACKEND_URL="${BACKEND_URL:-http://localhost:30080}"
TS="$(date +%s)"
PASS_COUNT=0
FAIL_COUNT=0
CLEANUP_IDS=()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log()  { echo "==> $*"; }
pass() { echo "  PASS: $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "  FAIL: $*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }
fatal() { echo "FATAL: $*" >&2; cleanup; exit 1; }

# Authenticated curl wrapper (returns body; sets HTTP_CODE)
acurl() {
    local method="$1"; shift
    local url="$1"; shift
    local tmpfile
    tmpfile=$(mktemp)
    HTTP_CODE=$(curl -s -o "$tmpfile" -w "%{http_code}" \
        -X "$method" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        "$@" \
        "$url")
    BODY=$(cat "$tmpfile")
    rm -f "$tmpfile"
}

cleanup() {
    log "Cleaning up test resources..."
    for nid in "${CLEANUP_IDS[@]}"; do
        curl -s -o /dev/null -X DELETE \
            -H "Authorization: Bearer $TOKEN" \
            "$BACKEND_URL/api/v1/edge-nodes/$nid" 2>/dev/null || true
    done
    log "Cleanup complete"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 0. Preflight
# ---------------------------------------------------------------------------

log "Replication E2E Test (ts=$TS)"
log "Backend: $BACKEND_URL"

if ! curl -sf "$BACKEND_URL/health" > /dev/null 2>&1; then
    fatal "Backend not reachable at $BACKEND_URL"
fi
log "Backend is healthy"

# ---------------------------------------------------------------------------
# 1. Login
# ---------------------------------------------------------------------------

log "Step 1: Login"
LOGIN_RESP=$(curl -s -X POST "$BACKEND_URL/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin123"}')
TOKEN=$(echo "$LOGIN_RESP" | jq -r '.access_token // .token // empty')
[ -n "$TOKEN" ] || fatal "Failed to get auth token"
pass "Authenticated"

# ---------------------------------------------------------------------------
# 2. Create test repository
# ---------------------------------------------------------------------------

log "Step 2: Create test repository"
REPO_KEY="repl-e2e-$TS"
acurl POST "$BACKEND_URL/api/v1/repositories" \
    -d "{\"key\":\"$REPO_KEY\",\"name\":\"Repl E2E $TS\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":true}"

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
    REPO_ID=$(echo "$BODY" | jq -r '.id')
    pass "Created repository $REPO_KEY (id=$REPO_ID)"
else
    fatal "Failed to create repository (HTTP $HTTP_CODE): $BODY"
fi

# ---------------------------------------------------------------------------
# 3. Register 2 edge nodes
# ---------------------------------------------------------------------------

log "Step 3: Register edge nodes"

register_node() {
    local name="$1" endpoint="$2" region="$3"
    acurl POST "$BACKEND_URL/api/v1/edge-nodes" \
        -d "{\"name\":\"$name\",\"endpoint_url\":\"$endpoint\",\"region\":\"$region\",\"cache_size_bytes\":10737418240}"
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
        echo "$BODY" | jq -r '.id'
    else
        echo ""
    fi
}

NODE1_ID=$(register_node "repl-e2e-edge1-$TS" "https://edge1-$TS.test:8080" "us-east-1")
[ -n "$NODE1_ID" ] || fatal "Failed to register edge node 1"
CLEANUP_IDS+=("$NODE1_ID")
pass "Registered edge node 1 ($NODE1_ID)"

NODE2_ID=$(register_node "repl-e2e-edge2-$TS" "https://edge2-$TS.test:8080" "us-east-1")
[ -n "$NODE2_ID" ] || fatal "Failed to register edge node 2"
CLEANUP_IDS+=("$NODE2_ID")
pass "Registered edge node 2 ($NODE2_ID)"

# ---------------------------------------------------------------------------
# 4. Assign repo to both nodes with different priorities
# ---------------------------------------------------------------------------

log "Step 4: Assign repository to edge nodes"

acurl POST "$BACKEND_URL/api/v1/edge-nodes/$NODE1_ID/repositories" \
    -d "{\"repository_id\":\"$REPO_ID\",\"sync_enabled\":true,\"priority_override\":\"immediate\"}"
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "204" ]; then
    pass "Assigned repo to edge 1 (priority=immediate)"
else
    fail "Assign repo to edge 1 failed (HTTP $HTTP_CODE): $BODY"
fi

acurl POST "$BACKEND_URL/api/v1/edge-nodes/$NODE2_ID/repositories" \
    -d "{\"repository_id\":\"$REPO_ID\",\"sync_enabled\":true,\"priority_override\":\"scheduled\"}"
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "204" ]; then
    pass "Assigned repo to edge 2 (priority=scheduled)"
else
    fail "Assign repo to edge 2 failed (HTTP $HTTP_CODE): $BODY"
fi

# ---------------------------------------------------------------------------
# 5. Upload an artifact
# ---------------------------------------------------------------------------

log "Step 5: Upload test artifact"
ARTIFACT_PATH="test/repl-artifact-$TS.bin"
ARTIFACT_CONTENT="replication e2e test content $TS"

acurl PUT "$BACKEND_URL/api/v1/repositories/$REPO_KEY/artifacts/$ARTIFACT_PATH" \
    -H "Content-Type: application/octet-stream" \
    -d "$ARTIFACT_CONTENT"

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
    ARTIFACT_ID=$(echo "$BODY" | jq -r '.id')
    pass "Uploaded artifact ($ARTIFACT_ID)"
else
    fatal "Upload artifact failed (HTTP $HTTP_CODE): $BODY"
fi

# ---------------------------------------------------------------------------
# 6. Verify sync tasks
# ---------------------------------------------------------------------------

log "Step 6: Check sync tasks"

acurl GET "$BACKEND_URL/api/v1/edge-nodes/$NODE1_ID/sync/tasks"
if [ "$HTTP_CODE" = "200" ]; then
    TASK_COUNT=$(echo "$BODY" | jq 'length')
    pass "Got sync tasks for edge 1 (count=$TASK_COUNT)"
else
    fail "Get sync tasks for edge 1 failed (HTTP $HTTP_CODE)"
fi

acurl GET "$BACKEND_URL/api/v1/edge-nodes/$NODE2_ID/sync/tasks"
if [ "$HTTP_CODE" = "200" ]; then
    TASK_COUNT=$(echo "$BODY" | jq 'length')
    pass "Got sync tasks for edge 2 (count=$TASK_COUNT)"
else
    fail "Get sync tasks for edge 2 failed (HTTP $HTTP_CODE)"
fi

# ---------------------------------------------------------------------------
# 7. Init chunked transfer for edge 1
# ---------------------------------------------------------------------------

log "Step 7: Init chunked transfer"

acurl POST "$BACKEND_URL/api/v1/edge-nodes/$NODE1_ID/transfer/init" \
    -d "{\"artifact_id\":\"$ARTIFACT_ID\"}"

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
    SESSION_ID=$(echo "$BODY" | jq -r '.id')
    TOTAL_CHUNKS=$(echo "$BODY" | jq -r '.total_chunks')
    SESSION_STATUS=$(echo "$BODY" | jq -r '.status')
    pass "Init transfer session ($SESSION_ID, chunks=$TOTAL_CHUNKS, status=$SESSION_STATUS)"
else
    fail "Init transfer failed (HTTP $HTTP_CODE): $BODY"
    SESSION_ID=""
fi

# ---------------------------------------------------------------------------
# 8. Get chunk manifest
# ---------------------------------------------------------------------------

if [ -n "${SESSION_ID:-}" ]; then
    log "Step 8: Get chunk manifest"

    acurl GET "$BACKEND_URL/api/v1/edge-nodes/$NODE1_ID/transfer/$SESSION_ID/chunks"

    if [ "$HTTP_CODE" = "200" ]; then
        MANIFEST_CHUNK_COUNT=$(echo "$BODY" | jq '.chunks | length')
        pass "Got chunk manifest (chunks=$MANIFEST_CHUNK_COUNT)"

        # -------------------------------------------------------------------
        # 9. Complete chunks and session
        # -------------------------------------------------------------------

        log "Step 9: Complete chunks and session"
        ALL_CHUNKS_OK=true

        for i in $(seq 0 $((MANIFEST_CHUNK_COUNT - 1))); do
            CHUNK_CHECKSUM=$(echo "$BODY" | jq -r ".chunks[$i].checksum")

            acurl POST "$BACKEND_URL/api/v1/edge-nodes/$NODE1_ID/transfer/$SESSION_ID/chunk/$i/complete" \
                -d "{\"checksum\":\"$CHUNK_CHECKSUM\"}"

            if [ "$HTTP_CODE" != "200" ] && [ "$HTTP_CODE" != "204" ]; then
                fail "Complete chunk $i failed (HTTP $HTTP_CODE)"
                ALL_CHUNKS_OK=false
            fi
        done

        if [ "$ALL_CHUNKS_OK" = true ]; then
            pass "All $MANIFEST_CHUNK_COUNT chunks completed"
        fi

        # Complete session
        acurl POST "$BACKEND_URL/api/v1/edge-nodes/$NODE1_ID/transfer/$SESSION_ID/complete"
        if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
            pass "Transfer session completed"
        else
            fail "Complete session failed (HTTP $HTTP_CODE): $BODY"
        fi

        # Verify session status
        acurl GET "$BACKEND_URL/api/v1/edge-nodes/$NODE1_ID/transfer/$SESSION_ID"
        if [ "$HTTP_CODE" = "200" ]; then
            FINAL_STATUS=$(echo "$BODY" | jq -r '.status')
            if [ "$FINAL_STATUS" = "completed" ]; then
                pass "Session status verified: completed"
            else
                fail "Session status is '$FINAL_STATUS', expected 'completed'"
            fi
        else
            fail "Get final session status failed (HTTP $HTTP_CODE)"
        fi
    else
        fail "Get chunk manifest failed (HTTP $HTTP_CODE)"
    fi
else
    log "Step 8-9: Skipped (no session)"
fi

# ---------------------------------------------------------------------------
# 10. Peer probe from edge 1 to edge 2
# ---------------------------------------------------------------------------

log "Step 10: Submit peer probe"

acurl POST "$BACKEND_URL/api/v1/edge-nodes/$NODE1_ID/peers/probe" \
    -d "{\"target_node_id\":\"$NODE2_ID\",\"latency_ms\":15,\"bandwidth_estimate_bps\":1000000000}"

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
    PROBE_LATENCY=$(echo "$BODY" | jq -r '.latency_ms')
    pass "Peer probe recorded (latency=${PROBE_LATENCY}ms)"
else
    fail "Peer probe failed (HTTP $HTTP_CODE): $BODY"
fi

# ---------------------------------------------------------------------------
# 11. Verify peer discovery
# ---------------------------------------------------------------------------

log "Step 11: Peer discovery"

acurl GET "$BACKEND_URL/api/v1/edge-nodes/$NODE1_ID/peers/discover"

if [ "$HTTP_CODE" = "200" ]; then
    PEER_COUNT=$(echo "$BODY" | jq 'length')
    FOUND_NODE2=$(echo "$BODY" | jq -r ".[] | select(.node_id == \"$NODE2_ID\") | .node_id")
    if [ "$FOUND_NODE2" = "$NODE2_ID" ]; then
        pass "Peer discovery found edge 2 (total peers=$PEER_COUNT)"
    else
        fail "Peer discovery did not find edge 2 among $PEER_COUNT peers"
    fi
else
    fail "Peer discovery failed (HTTP $HTTP_CODE)"
fi

# ---------------------------------------------------------------------------
# 12. Scored peers
# ---------------------------------------------------------------------------

log "Step 12: Scored peers"

# First update chunk availability so scored-peers has data
acurl PUT "$BACKEND_URL/api/v1/edge-nodes/$NODE2_ID/chunks/$ARTIFACT_ID" \
    -d '{"chunk_bitmap":[255],"total_chunks":8}'

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
    pass "Updated chunk availability for edge 2"
else
    fail "Update chunk availability failed (HTTP $HTTP_CODE): $BODY"
fi

acurl GET "$BACKEND_URL/api/v1/edge-nodes/$NODE1_ID/chunks/$ARTIFACT_ID/scored-peers"

if [ "$HTTP_CODE" = "200" ]; then
    SCORED_COUNT=$(echo "$BODY" | jq 'length')
    pass "Got scored peers (count=$SCORED_COUNT)"
else
    fail "Get scored peers failed (HTTP $HTTP_CODE): $BODY"
fi

# ---------------------------------------------------------------------------
# 13. Network profile
# ---------------------------------------------------------------------------

log "Step 13: Set network profile on edge 1"

acurl PUT "$BACKEND_URL/api/v1/edge-nodes/$NODE1_ID/network-profile" \
    -d '{"max_bandwidth_bps":100000000,"sync_window_start":"02:00:00","sync_window_end":"06:00:00"}'

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
    pass "Network profile set"
else
    fail "Set network profile failed (HTTP $HTTP_CODE): $BODY"
fi

# ---------------------------------------------------------------------------
# 14. Heartbeat
# ---------------------------------------------------------------------------

log "Step 14: Edge node heartbeat"

acurl POST "$BACKEND_URL/api/v1/edge-nodes/$NODE1_ID/heartbeat" \
    -d '{"cache_used_bytes":2147483648}'

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
    pass "Heartbeat sent"
else
    fail "Heartbeat failed (HTTP $HTTP_CODE): $BODY"
fi

# Verify heartbeat updated the node
acurl GET "$BACKEND_URL/api/v1/edge-nodes/$NODE1_ID"
if [ "$HTTP_CODE" = "200" ]; then
    USED=$(echo "$BODY" | jq -r '.cache_used_bytes')
    if [ "$USED" = "2147483648" ]; then
        pass "Heartbeat cache_used_bytes persisted"
    else
        fail "cache_used_bytes=$USED, expected 2147483648"
    fi
else
    fail "Get edge node after heartbeat failed (HTTP $HTTP_CODE)"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "=============================================="
echo "Replication E2E Results"
echo "=============================================="
echo "Passed: $PASS_COUNT"
echo "Failed: $FAIL_COUNT"
echo ""

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo "=== Replication E2E test FAILED ==="
    exit 1
fi

echo "=== Replication E2E test PASSED ==="
