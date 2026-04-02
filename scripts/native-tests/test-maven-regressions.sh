#!/usr/bin/env bash
set -euo pipefail

BACKEND="${BACKEND_URL:-http://localhost:8080}"
REPO="maven-regression-$$"
USER="${ADMIN_USER:-admin}"
PASS="${ADMIN_PASS:-TestRunner!2026secure}"

echo "=== Maven Regression Tests ==="

curl -sf -u "$USER:$PASS" -X POST "$BACKEND/api/v1/repositories" \
  -H "Content-Type: application/json" \
  -d "{\"key\":\"$REPO\",\"name\":\"Regression\",\"format\":\"maven\",\"repoType\":\"local\"}" >/dev/null

PASS_COUNT=0
FAIL_COUNT=0

pass() { echo "PASS: $1"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "FAIL: $1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }

# --- #297/#321: SNAPSHOT re-upload should succeed ---
echo "test-v1" | curl -sf -u "$USER:$PASS" -X PUT \
  "$BACKEND/maven/$REPO/com/test/snap/1.0-SNAPSHOT/snap-1.0-SNAPSHOT.jar" \
  --data-binary @- >/dev/null
echo "test-v2" | curl -sf -u "$USER:$PASS" -X PUT \
  "$BACKEND/maven/$REPO/com/test/snap/1.0-SNAPSHOT/snap-1.0-SNAPSHOT.jar" \
  --data-binary @- >/dev/null && pass "#297 SNAPSHOT re-upload" || fail "#297 SNAPSHOT re-upload"

# --- Release re-upload should fail (409) ---
echo "test" | curl -sf -u "$USER:$PASS" -X PUT \
  "$BACKEND/maven/$REPO/com/test/rel/1.0/rel-1.0.jar" \
  --data-binary @- >/dev/null
STATUS=$(echo "test2" | curl -s -o /dev/null -w "%{http_code}" -u "$USER:$PASS" -X PUT \
  "$BACKEND/maven/$REPO/com/test/rel/1.0/rel-1.0.jar" --data-binary @-)
[ "$STATUS" = "409" ] && pass "Release re-upload rejected (409)" || fail "Release re-upload: got $STATUS"

# --- #414: Checksum for SNAPSHOT should return hash, not XML ---
CHECKSUM=$(curl -sf "$BACKEND/maven/$REPO/com/test/snap/1.0-SNAPSHOT/snap-1.0-SNAPSHOT.jar.sha1" || echo "FETCH_FAILED")
if echo "$CHECKSUM" | grep -qv "<?xml"; then
  pass "#414 SNAPSHOT checksum is hash not XML"
else
  fail "#414 SNAPSHOT checksum returned XML"
fi

# --- #415: POM + JAR should group under same artifact ---
echo "<project></project>" | curl -sf -u "$USER:$PASS" -X PUT \
  "$BACKEND/maven/$REPO/com/test/grouped/1.0/grouped-1.0.pom" --data-binary @- >/dev/null
echo "jar-content" | curl -sf -u "$USER:$PASS" -X PUT \
  "$BACKEND/maven/$REPO/com/test/grouped/1.0/grouped-1.0.jar" --data-binary @- >/dev/null
JAR_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BACKEND/maven/$REPO/com/test/grouped/1.0/grouped-1.0.jar")
POM_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BACKEND/maven/$REPO/com/test/grouped/1.0/grouped-1.0.pom")
[ "$JAR_STATUS" = "200" ] && [ "$POM_STATUS" = "200" ] && pass "#415 POM+JAR both accessible" || fail "#415 POM=$POM_STATUS JAR=$JAR_STATUS"

# --- Content-Type check (C5) ---
CT=$(curl -sf -o /dev/null -w "%{content_type}" "$BACKEND/maven/$REPO/com/test/grouped/1.0/grouped-1.0.pom")
echo "$CT" | grep -q "text/xml" && pass "C5 POM content-type is text/xml" || fail "C5 POM content-type: $CT"

# Cleanup
curl -sf -u "$USER:$PASS" -X DELETE "$BACKEND/api/v1/repositories/$REPO" >/dev/null 2>&1 || true

echo ""
echo "Results: $PASS_COUNT passed, $FAIL_COUNT failed"
[ "$FAIL_COUNT" -eq 0 ] || exit 1
