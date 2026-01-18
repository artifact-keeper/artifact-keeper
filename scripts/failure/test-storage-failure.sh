#!/bin/bash
# Failure test: Storage failure handling
# Tests that the backend handles storage failures gracefully
set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:8080}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.test.yml}"
STORAGE_PATH="${STORAGE_PATH:-/var/lib/artifact-keeper/storage}"
RESULTS_DIR="${RESULTS_DIR:-/tmp/failure-results}"

echo "=============================================="
echo "Failure Test: Storage Failure"
echo "=============================================="
echo "Registry: $REGISTRY_URL"
echo "Storage path: $STORAGE_PATH"
echo ""

mkdir -p "$RESULTS_DIR"

# Create test packages
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "==> Creating test packages..."
echo "storage failure test data" > "$WORK_DIR/test-data.txt"
tar -czf "$WORK_DIR/storage-test-pkg.tar.gz" -C "$WORK_DIR" test-data.txt

# Create a larger package for quota test
dd if=/dev/urandom of="$WORK_DIR/large-data.bin" bs=1M count=100 2>/dev/null
tar -czf "$WORK_DIR/large-pkg.tar.gz" -C "$WORK_DIR" large-data.bin

# Test 1: Baseline upload
echo ""
echo "==> Test 1: Baseline upload..."
BASELINE_STATUS=$(curl -s -w "%{http_code}" -o "$RESULTS_DIR/storage-baseline.log" \
    -X PUT \
    -u admin:admin123 \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@$WORK_DIR/storage-test-pkg.tar.gz" \
    "$REGISTRY_URL/api/v1/repositories/storage-test/artifacts/baseline-pkg.tar.gz" \
    2>&1 || echo "000")
echo "Baseline upload status: $BASELINE_STATUS"

# Test 2: Simulate disk full (if we have access to the storage container)
echo ""
echo "==> Test 2: Simulating disk full condition..."

# Try to fill the storage volume (create a large file)
FILL_FILE="/tmp/fill-storage-$$"
DISK_FULL_SIMULATED=false

# Method 1: Try via docker exec
if docker compose -f "$COMPOSE_FILE" exec -T backend \
    dd if=/dev/zero of=/storage/fill-file bs=1M count=10000 2>/dev/null; then
    echo "Created fill file in backend container"
    DISK_FULL_SIMULATED=true
elif docker exec artifact-keeper-backend \
    dd if=/dev/zero of=/storage/fill-file bs=1M count=10000 2>/dev/null; then
    echo "Created fill file in backend container"
    DISK_FULL_SIMULATED=true
fi

# Method 2: Make storage read-only
if [ "$DISK_FULL_SIMULATED" = false ]; then
    echo "Attempting to make storage read-only..."
    docker compose -f "$COMPOSE_FILE" exec -T backend \
        chmod 444 /storage 2>/dev/null && DISK_FULL_SIMULATED=true || true
fi

if [ "$DISK_FULL_SIMULATED" = true ]; then
    sleep 2

    # Test upload during "disk full"
    DISKFULL_STATUS=$(curl -s -w "%{http_code}" -o "$RESULTS_DIR/diskfull.log" \
        --max-time 60 \
        -X PUT \
        -u admin:admin123 \
        -H "Content-Type: application/octet-stream" \
        --data-binary "@$WORK_DIR/large-pkg.tar.gz" \
        "$REGISTRY_URL/api/v1/repositories/storage-test/artifacts/large-pkg.tar.gz" \
        2>&1 || echo "000")
    echo "Disk full upload status: $DISKFULL_STATUS"
    echo "Response: $(head -c 500 "$RESULTS_DIR/diskfull.log" 2>/dev/null)"

    # Cleanup: Remove fill file or restore permissions
    docker compose -f "$COMPOSE_FILE" exec -T backend rm -f /storage/fill-file 2>/dev/null || true
    docker compose -f "$COMPOSE_FILE" exec -T backend chmod 755 /storage 2>/dev/null || true
    docker exec artifact-keeper-backend rm -f /storage/fill-file 2>/dev/null || true
    docker exec artifact-keeper-backend chmod 755 /storage 2>/dev/null || true
else
    echo "Could not simulate disk full - skipping test"
    DISKFULL_STATUS="skipped"
fi

# Test 3: Corrupted file handling
echo ""
echo "==> Test 3: Upload corrupted/incomplete data..."

# Create a truncated file (simulate network interruption)
head -c 1000 "$WORK_DIR/storage-test-pkg.tar.gz" > "$WORK_DIR/truncated.tar.gz"

TRUNCATED_STATUS=$(curl -s -w "%{http_code}" -o "$RESULTS_DIR/truncated.log" \
    -X PUT \
    -u admin:admin123 \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@$WORK_DIR/truncated.tar.gz" \
    "$REGISTRY_URL/api/v1/repositories/storage-test/artifacts/truncated-pkg.tar.gz" \
    2>&1 || echo "000")
echo "Truncated upload status: $TRUNCATED_STATUS"

# Test 4: Empty file upload
echo ""
echo "==> Test 4: Upload empty file..."
touch "$WORK_DIR/empty.tar.gz"

EMPTY_STATUS=$(curl -s -w "%{http_code}" -o "$RESULTS_DIR/empty.log" \
    -X PUT \
    -u admin:admin123 \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@$WORK_DIR/empty.tar.gz" \
    "$REGISTRY_URL/api/v1/repositories/storage-test/artifacts/empty-pkg.tar.gz" \
    2>&1 || echo "000")
echo "Empty file upload status: $EMPTY_STATUS"

# Test 5: Recovery - upload should work again
echo ""
echo "==> Test 5: Recovery upload..."
sleep 2

RECOVERY_STATUS=$(curl -s -w "%{http_code}" -o "$RESULTS_DIR/storage-recovery.log" \
    -X PUT \
    -u admin:admin123 \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@$WORK_DIR/storage-test-pkg.tar.gz" \
    "$REGISTRY_URL/api/v1/repositories/storage-test/artifacts/recovery-pkg.tar.gz" \
    2>&1 || echo "000")
echo "Recovery upload status: $RECOVERY_STATUS"

# Generate report
cat > "$RESULTS_DIR/storage-failure-test.json" << EOF
{
  "test": "storage_failure",
  "timestamp": "$(date -Iseconds)",
  "results": {
    "baseline": {
      "status": $BASELINE_STATUS,
      "success": $([ "$BASELINE_STATUS" -ge 200 ] && [ "$BASELINE_STATUS" -lt 300 ] && echo "true" || echo "false")
    },
    "disk_full": {
      "simulated": $DISK_FULL_SIMULATED,
      "status": "$([ "$DISKFULL_STATUS" = "skipped" ] && echo "skipped" || echo "$DISKFULL_STATUS")"
    },
    "truncated_file": {
      "status": $TRUNCATED_STATUS,
      "handled_gracefully": $([ "$TRUNCATED_STATUS" -ge 400 ] && echo "true" || echo "false")
    },
    "empty_file": {
      "status": $EMPTY_STATUS
    },
    "recovery": {
      "status": $RECOVERY_STATUS,
      "success": $([ "$RECOVERY_STATUS" -ge 200 ] && [ "$RECOVERY_STATUS" -lt 300 ] && echo "true" || echo "false")
    }
  }
}
EOF

echo ""
echo "=============================================="
echo "Storage Failure Test Results"
echo "=============================================="
cat "$RESULTS_DIR/storage-failure-test.json"
echo ""

# Pass if:
# 1. Baseline succeeded
# 2. Recovery succeeded
PASS=true
if [ "$BASELINE_STATUS" -lt 200 ] || [ "$BASELINE_STATUS" -ge 300 ]; then
    echo "FAIL: Baseline upload failed"
    PASS=false
fi
if [ "$RECOVERY_STATUS" -lt 200 ] || [ "$RECOVERY_STATUS" -ge 300 ]; then
    echo "FAIL: Recovery upload failed"
    PASS=false
fi

if [ "$PASS" = true ]; then
    echo "✅ Storage failure test PASSED"
    exit 0
else
    echo "❌ Storage failure test FAILED"
    exit 1
fi
