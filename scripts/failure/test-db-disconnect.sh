#!/bin/bash
# Failure test: Database disconnect handling
# Tests that the backend handles database disconnects gracefully
set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:8080}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.test.yml}"
RESULTS_DIR="${RESULTS_DIR:-/tmp/failure-results}"

echo "=============================================="
echo "Failure Test: Database Disconnect"
echo "=============================================="
echo "Registry: $REGISTRY_URL"
echo "Compose file: $COMPOSE_FILE"
echo ""

mkdir -p "$RESULTS_DIR"

# Create test package
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "==> Creating test package..."
echo "db disconnect test data" > "$WORK_DIR/test-data.txt"
tar -czf "$WORK_DIR/db-test-pkg.tar.gz" -C "$WORK_DIR" test-data.txt

# Verify server is running
echo ""
echo "==> Verifying server is healthy..."
HEALTH=$(curl -s "$REGISTRY_URL/api/v1/health" 2>/dev/null || echo "{}")
echo "Health: $HEALTH"

if ! echo "$HEALTH" | grep -q "ok\|healthy\|UP"; then
    echo "WARNING: Server health check may have issues"
fi

# Test 1: Upload with database connected (baseline)
echo ""
echo "==> Test 1: Baseline upload (DB connected)..."
BASELINE_STATUS=$(curl -s -w "%{http_code}" -o "$RESULTS_DIR/baseline.log" \
    -X PUT \
    -u admin:admin123 \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@$WORK_DIR/db-test-pkg.tar.gz" \
    "$REGISTRY_URL/api/v1/repositories/db-test/artifacts/baseline-pkg.tar.gz" \
    2>&1 || echo "000")
echo "Baseline upload status: $BASELINE_STATUS"

# Stop the database
echo ""
echo "==> Stopping database..."
docker compose -f "$COMPOSE_FILE" stop postgres 2>/dev/null || \
    docker stop artifact-keeper-postgres 2>/dev/null || \
    echo "Could not stop postgres (may not be running in docker)"

# Wait for connections to fail
sleep 3

# Test 2: Attempt upload with database disconnected
echo ""
echo "==> Test 2: Upload with DB disconnected..."
DISCONNECT_STATUS=$(curl -s -w "%{http_code}" -o "$RESULTS_DIR/disconnect.log" \
    --max-time 30 \
    -X PUT \
    -u admin:admin123 \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@$WORK_DIR/db-test-pkg.tar.gz" \
    "$REGISTRY_URL/api/v1/repositories/db-test/artifacts/disconnect-pkg.tar.gz" \
    2>&1 || echo "000")
echo "Disconnected upload status: $DISCONNECT_STATUS"
echo "Response: $(cat "$RESULTS_DIR/disconnect.log" 2>/dev/null)"

# Verify server returns appropriate error (not 200)
if [ "$DISCONNECT_STATUS" -ge 200 ] && [ "$DISCONNECT_STATUS" -lt 300 ]; then
    echo "WARNING: Upload succeeded during DB disconnect - unexpected"
    DISCONNECT_HANDLED="unexpected_success"
elif [ "$DISCONNECT_STATUS" -ge 500 ] && [ "$DISCONNECT_STATUS" -lt 600 ]; then
    echo "Server returned 5xx error (expected)"
    DISCONNECT_HANDLED="server_error"
else
    echo "Server returned non-5xx error"
    DISCONNECT_HANDLED="other_error"
fi

# Test 3: Check health endpoint during disconnect
echo ""
echo "==> Test 3: Health check during DB disconnect..."
HEALTH_DISCONNECT=$(curl -s --max-time 10 "$REGISTRY_URL/api/v1/health" 2>/dev/null || echo "{\"status\": \"unavailable\"}")
echo "Health during disconnect: $HEALTH_DISCONNECT"

# Restart the database
echo ""
echo "==> Restarting database..."
docker compose -f "$COMPOSE_FILE" start postgres 2>/dev/null || \
    docker start artifact-keeper-postgres 2>/dev/null || \
    echo "Could not restart postgres"

# Wait for database to be ready
echo "==> Waiting for database to be ready..."
MAX_WAIT=60
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
    if docker compose -f "$COMPOSE_FILE" exec -T postgres pg_isready 2>/dev/null || \
       docker exec artifact-keeper-postgres pg_isready 2>/dev/null; then
        echo "Database is ready after ${WAITED}s"
        break
    fi
    sleep 2
    WAITED=$((WAITED + 2))
done

if [ $WAITED -ge $MAX_WAIT ]; then
    echo "ERROR: Database did not recover"
fi

# Wait a bit more for backend to reconnect
sleep 5

# Test 4: Upload after reconnect
echo ""
echo "==> Test 4: Upload after DB reconnect..."
RECONNECT_STATUS=$(curl -s -w "%{http_code}" -o "$RESULTS_DIR/reconnect.log" \
    -X PUT \
    -u admin:admin123 \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@$WORK_DIR/db-test-pkg.tar.gz" \
    "$REGISTRY_URL/api/v1/repositories/db-test/artifacts/reconnect-pkg.tar.gz" \
    2>&1 || echo "000")
echo "Reconnect upload status: $RECONNECT_STATUS"

# Test 5: Verify health after reconnect
echo ""
echo "==> Test 5: Health check after reconnect..."
HEALTH_RECONNECT=$(curl -s "$REGISTRY_URL/api/v1/health" 2>/dev/null || echo "{}")
echo "Health after reconnect: $HEALTH_RECONNECT"

# Generate report
cat > "$RESULTS_DIR/db-disconnect-test.json" << EOF
{
  "test": "database_disconnect",
  "timestamp": "$(date -Iseconds)",
  "results": {
    "baseline_upload": {
      "status": $BASELINE_STATUS,
      "success": $([ "$BASELINE_STATUS" -ge 200 ] && [ "$BASELINE_STATUS" -lt 300 ] && echo "true" || echo "false")
    },
    "during_disconnect": {
      "status": $DISCONNECT_STATUS,
      "handling": "$DISCONNECT_HANDLED"
    },
    "after_reconnect": {
      "status": $RECONNECT_STATUS,
      "success": $([ "$RECONNECT_STATUS" -ge 200 ] && [ "$RECONNECT_STATUS" -lt 300 ] && echo "true" || echo "false")
    },
    "health_during_disconnect": $(echo "$HEALTH_DISCONNECT" | jq '.' 2>/dev/null || echo '{}'),
    "health_after_reconnect": $(echo "$HEALTH_RECONNECT" | jq '.' 2>/dev/null || echo '{}')
  }
}
EOF

echo ""
echo "=============================================="
echo "Database Disconnect Test Results"
echo "=============================================="
cat "$RESULTS_DIR/db-disconnect-test.json"
echo ""

# Pass if:
# 1. Baseline succeeded
# 2. Disconnect was handled (not 2xx)
# 3. Reconnect succeeded
PASS=true
if [ "$BASELINE_STATUS" -lt 200 ] || [ "$BASELINE_STATUS" -ge 300 ]; then
    echo "FAIL: Baseline upload failed"
    PASS=false
fi
if [ "$DISCONNECT_STATUS" -ge 200 ] && [ "$DISCONNECT_STATUS" -lt 300 ]; then
    echo "FAIL: Upload succeeded during disconnect (should fail)"
    PASS=false
fi
if [ "$RECONNECT_STATUS" -lt 200 ] || [ "$RECONNECT_STATUS" -ge 300 ]; then
    echo "FAIL: Upload failed after reconnect"
    PASS=false
fi

if [ "$PASS" = true ]; then
    echo "✅ Database disconnect test PASSED"
    exit 0
else
    echo "❌ Database disconnect test FAILED"
    exit 1
fi
