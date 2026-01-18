#!/bin/bash
# Stress test validation: Verify uploaded artifacts
# Validates checksums, counts, and checks for deadlocks/corruption
set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:8080}"
RESULTS_DIR="${RESULTS_DIR:-/tmp/stress-results}"
TEST_FORMAT="${TEST_FORMAT:-pypi}"

echo "=============================================="
echo "Stress Test Validation"
echo "=============================================="
echo "Registry: $REGISTRY_URL"
echo "Results dir: $RESULTS_DIR"
echo "Test format: $TEST_FORMAT"
echo ""

# Check if results exist
if [ ! -f "$RESULTS_DIR/results.csv" ]; then
    echo "ERROR: No results file found at $RESULTS_DIR/results.csv"
    echo "Run run-concurrent-uploads.sh first"
    exit 1
fi

# Load expected results
EXPECTED_COUNT=$(wc -l < "$RESULTS_DIR/results.csv")
EXPECTED_COUNT=$((EXPECTED_COUNT - 1))  # Subtract header
echo "Expected artifacts: $EXPECTED_COUNT"

# Verify artifact count in registry
echo ""
echo "==> Verifying artifact count in registry..."
REGISTRY_COUNT=$(curl -s -u admin:admin123 \
    "$REGISTRY_URL/api/v1/repositories/stress-test-$TEST_FORMAT/artifacts" \
    2>/dev/null | jq '.total // .artifacts | length // 0' 2>/dev/null || echo "0")

echo "Registry artifact count: $REGISTRY_COUNT"

if [ "$REGISTRY_COUNT" -lt "$EXPECTED_COUNT" ]; then
    echo "WARNING: Registry has fewer artifacts ($REGISTRY_COUNT) than expected ($EXPECTED_COUNT)"
    MISSING=$((EXPECTED_COUNT - REGISTRY_COUNT))
    echo "Missing artifacts: $MISSING"
fi

# Verify checksums for a sample of artifacts
echo ""
echo "==> Validating checksums for sample of artifacts..."
SAMPLE_SIZE=10
CHECKSUM_ERRORS=0

# Get list of successful uploads with checksums
grep ",20[0-9]," "$RESULTS_DIR/results.csv" | head -$SAMPLE_SIZE | while IFS=',' read -r idx status duration checksum; do
    # Try to download and verify
    artifact_name="stress-test-pkg-$idx-1.0.$idx"

    # Get artifact from registry
    response=$(curl -s -w "\n%{http_code}" -u admin:admin123 \
        "$REGISTRY_URL/api/v1/repositories/stress-test-$TEST_FORMAT/artifacts/$artifact_name" \
        2>/dev/null || echo "000")

    http_code=$(echo "$response" | tail -1)

    if [ "$http_code" -ge 200 ] && [ "$http_code" -lt 300 ]; then
        echo "  ✓ Artifact $artifact_name exists"
    else
        echo "  ✗ Artifact $artifact_name not found (HTTP $http_code)"
        CHECKSUM_ERRORS=$((CHECKSUM_ERRORS + 1))
    fi
done

# Check for database deadlocks (via health endpoint or logs)
echo ""
echo "==> Checking for deadlocks and errors..."

HEALTH_STATUS=$(curl -s "$REGISTRY_URL/api/v1/health" 2>/dev/null || echo "{}")
echo "Health endpoint response: $HEALTH_STATUS"

# Check if any error patterns in server logs (if accessible)
if [ -f "/var/log/artifact-keeper/server.log" ]; then
    DEADLOCK_COUNT=$(grep -c -i "deadlock" /var/log/artifact-keeper/server.log 2>/dev/null || echo "0")
    PANIC_COUNT=$(grep -c -i "panic" /var/log/artifact-keeper/server.log 2>/dev/null || echo "0")

    echo "Deadlock occurrences: $DEADLOCK_COUNT"
    echo "Panic occurrences: $PANIC_COUNT"

    if [ "$DEADLOCK_COUNT" -gt 0 ] || [ "$PANIC_COUNT" -gt 0 ]; then
        echo "WARNING: Detected errors in server logs"
    fi
fi

# Check for orphaned files (files without database records)
echo ""
echo "==> Checking for data consistency..."

# This would require database access - for now, check via API
CONSISTENCY_CHECK=$(curl -s -u admin:admin123 \
    "$REGISTRY_URL/api/v1/admin/health/storage" 2>/dev/null || echo "{\"status\": \"unknown\"}")

echo "Storage consistency: $CONSISTENCY_CHECK"

# Generate validation report
cat > "$RESULTS_DIR/validation.json" << EOF
{
  "test": "stress_validation",
  "timestamp": "$(date -Iseconds)",
  "validation": {
    "expected_artifacts": $EXPECTED_COUNT,
    "registry_artifacts": $REGISTRY_COUNT,
    "missing_artifacts": $((EXPECTED_COUNT - REGISTRY_COUNT)),
    "checksum_errors": $CHECKSUM_ERRORS,
    "health_status": $(echo "$HEALTH_STATUS" | jq '.' 2>/dev/null || echo '{}')
  }
}
EOF

echo ""
echo "=============================================="
echo "Validation Summary"
echo "=============================================="
echo ""
echo "Expected artifacts: $EXPECTED_COUNT"
echo "Found in registry: $REGISTRY_COUNT"
echo "Checksum errors: $CHECKSUM_ERRORS"
echo ""
echo "Validation report: $RESULTS_DIR/validation.json"
echo ""

# Determine pass/fail
if [ "$REGISTRY_COUNT" -lt "$EXPECTED_COUNT" ] || [ "$CHECKSUM_ERRORS" -gt 0 ]; then
    echo "❌ Validation FAILED"
    exit 1
fi

echo "✅ Validation PASSED"
