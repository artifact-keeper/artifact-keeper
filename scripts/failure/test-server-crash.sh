#!/bin/bash
# Failure test: Server crash recovery
# Tests that uploads in progress are handled gracefully when server crashes
set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:8080}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.test.yml}"
RESULTS_DIR="${RESULTS_DIR:-/tmp/failure-results}"

echo "=============================================="
echo "Failure Test: Server Crash Recovery"
echo "=============================================="
echo "Registry: $REGISTRY_URL"
echo "Compose file: $COMPOSE_FILE"
echo ""

mkdir -p "$RESULTS_DIR"

# Create test package
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "==> Creating test package..."
dd if=/dev/urandom of="$WORK_DIR/large-file.bin" bs=1M count=50 2>/dev/null
tar -czf "$WORK_DIR/crash-test-pkg.tar.gz" -C "$WORK_DIR" large-file.bin
CHECKSUM=$(sha256sum "$WORK_DIR/crash-test-pkg.tar.gz" | cut -d' ' -f1)
echo "Package checksum: $CHECKSUM"

# Verify server is running
echo ""
echo "==> Verifying server is running..."
if ! curl -s "$REGISTRY_URL/api/v1/health" > /dev/null 2>&1; then
    echo "ERROR: Server is not running at $REGISTRY_URL"
    exit 1
fi
echo "Server is running"

# Start upload in background
echo ""
echo "==> Starting large upload in background..."
curl -s -X PUT \
    -u admin:admin123 \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@$WORK_DIR/crash-test-pkg.tar.gz" \
    "$REGISTRY_URL/api/v1/repositories/crash-test/artifacts/crash-test-pkg.tar.gz" \
    -o "$RESULTS_DIR/upload-response.log" 2>&1 &
UPLOAD_PID=$!

# Wait a moment for upload to start
sleep 2

# Kill the backend container (simulate crash)
echo "==> Simulating server crash..."
docker compose -f "$COMPOSE_FILE" kill backend 2>/dev/null || \
    docker kill artifact-keeper-backend 2>/dev/null || \
    echo "Could not kill backend (may not be running in docker)"

# Wait for upload to fail
wait $UPLOAD_PID || true
echo "Upload process exited"

# Check upload result
UPLOAD_RESULT=$(cat "$RESULTS_DIR/upload-response.log" 2>/dev/null || echo "no response")
echo "Upload response: $UPLOAD_RESULT"

# Restart the backend
echo ""
echo "==> Restarting server..."
docker compose -f "$COMPOSE_FILE" up -d backend 2>/dev/null || \
    docker start artifact-keeper-backend 2>/dev/null || \
    echo "Could not restart backend - may need manual intervention"

# Wait for server to be healthy
echo "==> Waiting for server to be healthy..."
MAX_WAIT=60
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
    if curl -s "$REGISTRY_URL/api/v1/health" > /dev/null 2>&1; then
        echo "Server is healthy after ${WAITED}s"
        break
    fi
    sleep 2
    WAITED=$((WAITED + 2))
done

if [ $WAITED -ge $MAX_WAIT ]; then
    echo "ERROR: Server did not recover within ${MAX_WAIT}s"
    echo '{"test": "server_crash", "status": "failed", "reason": "server_did_not_recover"}' > "$RESULTS_DIR/crash-test.json"
    exit 1
fi

# Verify no orphaned data
echo ""
echo "==> Checking for orphaned data..."

# Check if partial upload exists (should be cleaned up)
ARTIFACT_CHECK=$(curl -s -u admin:admin123 \
    "$REGISTRY_URL/api/v1/repositories/crash-test/artifacts/crash-test-pkg.tar.gz" \
    2>/dev/null || echo "{}")

if echo "$ARTIFACT_CHECK" | grep -q "not found\|404"; then
    echo "Good: Partial upload was not persisted (expected)"
    ORPHAN_STATUS="clean"
else
    echo "Warning: Artifact may have been partially persisted"
    ORPHAN_STATUS="possible_orphan"
fi

# Try upload again
echo ""
echo "==> Retrying upload after recovery..."
RETRY_STATUS=$(curl -s -w "%{http_code}" -o "$RESULTS_DIR/retry-response.log" \
    -X PUT \
    -u admin:admin123 \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@$WORK_DIR/crash-test-pkg.tar.gz" \
    "$REGISTRY_URL/api/v1/repositories/crash-test/artifacts/crash-test-pkg.tar.gz" \
    2>&1 || echo "000")

echo "Retry HTTP status: $RETRY_STATUS"

# Generate report
cat > "$RESULTS_DIR/crash-test.json" << EOF
{
  "test": "server_crash",
  "timestamp": "$(date -Iseconds)",
  "results": {
    "original_upload": "interrupted",
    "server_recovery_time_sec": $WAITED,
    "orphan_status": "$ORPHAN_STATUS",
    "retry_status": "$RETRY_STATUS",
    "retry_success": $([ "$RETRY_STATUS" -ge 200 ] && [ "$RETRY_STATUS" -lt 300 ] && echo "true" || echo "false")
  }
}
EOF

echo ""
echo "=============================================="
echo "Server Crash Test Results"
echo "=============================================="
cat "$RESULTS_DIR/crash-test.json"
echo ""

# Pass if server recovered and retry succeeded
if [ "$RETRY_STATUS" -ge 200 ] && [ "$RETRY_STATUS" -lt 300 ]; then
    echo "✅ Server crash recovery test PASSED"
    exit 0
else
    echo "❌ Server crash recovery test FAILED"
    exit 1
fi
