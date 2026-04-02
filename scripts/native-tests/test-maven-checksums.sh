#!/usr/bin/env bash
set -euo pipefail

BACKEND="${BACKEND_URL:-http://localhost:8080}"
REPO="maven-checksum-test-$$"
USER="${ADMIN_USER:-admin}"
PASS="${ADMIN_PASS:-TestRunner!2026secure}"

echo "=== Maven Checksum Completeness Test ==="

# Create test repo
curl -sf -u "$USER:$PASS" -X POST "$BACKEND/api/v1/repositories" \
  -H "Content-Type: application/json" \
  -d "{\"key\":\"$REPO\",\"name\":\"Checksum Test\",\"format\":\"maven\",\"repoType\":\"local\"}" >/dev/null

# Upload a test artifact
echo "test-content" | curl -sf -u "$USER:$PASS" -X PUT \
  "$BACKEND/maven/$REPO/com/example/test/1.0/test-1.0.jar" \
  --data-binary @- >/dev/null

PASS_COUNT=0
FAIL_COUNT=0

for ext in sha1 md5 sha256 sha512; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    "$BACKEND/maven/$REPO/com/example/test/1.0/test-1.0.jar.$ext")
  if [ "$STATUS" = "200" ]; then
    echo "PASS: .${ext} checksum returned 200"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo "FAIL: .${ext} checksum returned $STATUS (expected 200)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
done

# Cleanup
curl -sf -u "$USER:$PASS" -X DELETE "$BACKEND/api/v1/repositories/$REPO" >/dev/null 2>&1 || true

echo ""
echo "Results: $PASS_COUNT passed, $FAIL_COUNT failed"
[ "$FAIL_COUNT" -eq 0 ] || exit 1
