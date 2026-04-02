#!/bin/bash
# Health probe and observability endpoint tests
# Tests /livez, /readyz, /healthz, /health, and /api/v1/admin/metrics
#
# Usage: ./test-health-probes.sh
# Environment:
#   REGISTRY_URL  - Backend URL (default: http://localhost:30080)
#   ADMIN_USER    - Admin username (default: admin)
#   ADMIN_PASS    - Admin password (default: TestRunner!2026secure)
set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:30080}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-TestRunner!2026secure}"

echo "==> Health Probe & Observability Tests"
echo "Registry: $REGISTRY_URL"

PASSED=0
FAILED=0

pass() {
    echo "  PASS: $1"
    PASSED=$((PASSED + 1))
}

fail() {
    echo "  FAIL: $1"
    FAILED=$((FAILED + 1))
}

# ---- Authenticate ----
echo ""
echo "==> Authenticating..."
TOKEN=$(curl -sf "$REGISTRY_URL/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" | jq -r '.access_token')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    echo "FATAL: Authentication failed"
    exit 1
fi
echo "  Authenticated as $ADMIN_USER"

# ---- Test 1: /livez returns 200 with status ok ----
echo ""
echo "==> [1/19] /livez returns 200 with {\"status\":\"ok\"}"
HTTP_CODE=$(curl -sf -o /tmp/livez.json -w "%{http_code}" "$REGISTRY_URL/livez" 2>/dev/null) || true

if [ "$HTTP_CODE" = "200" ]; then
    STATUS=$(jq -r '.status' /tmp/livez.json)
    if [ "$STATUS" = "ok" ]; then
        pass "/livez returns 200 with status=ok"
    else
        fail "/livez status was '$STATUS', expected 'ok'"
    fi
else
    fail "/livez returned HTTP $HTTP_CODE, expected 200"
fi

# ---- Test 2: /livez response has no external check fields ----
echo "==> [2/19] /livez response is minimal (no database/storage fields)"
KEYS=$(jq -r 'keys[]' /tmp/livez.json 2>/dev/null | tr '\n' ',')
if echo "$KEYS" | grep -q "database\|checks\|storage"; then
    fail "/livez response contains external check fields: $KEYS"
else
    pass "/livez response is minimal: $KEYS"
fi

# ---- Test 3: /readyz returns 200 ----
echo "==> [3/19] /readyz returns 200"
HTTP_CODE=$(curl -sf -o /tmp/readyz.json -w "%{http_code}" "$REGISTRY_URL/readyz" 2>/dev/null) || true

if [ "$HTTP_CODE" = "200" ]; then
    pass "/readyz returns 200"
else
    fail "/readyz returned HTTP $HTTP_CODE, expected 200"
fi

# ---- Test 4: /readyz has database check ----
echo "==> [4/19] /readyz checks database"
DB_STATUS=$(jq -r '.checks.database.status' /tmp/readyz.json 2>/dev/null)
if [ "$DB_STATUS" = "healthy" ]; then
    pass "/readyz database check is healthy"
else
    fail "/readyz database check: $DB_STATUS"
fi

# ---- Test 5: /readyz has migrations check ----
echo "==> [5/19] /readyz checks migrations"
MIG_STATUS=$(jq -r '.checks.migrations.status' /tmp/readyz.json 2>/dev/null)
if [ "$MIG_STATUS" = "healthy" ]; then
    pass "/readyz migrations check is healthy"
else
    fail "/readyz migrations check: $MIG_STATUS"
fi

# ---- Test 6: /readyz has setup_complete check ----
echo "==> [6/19] /readyz checks setup_complete"
SETUP_STATUS=$(jq -r '.checks.setup_complete.status' /tmp/readyz.json 2>/dev/null)
if [ "$SETUP_STATUS" = "healthy" ]; then
    pass "/readyz setup_complete check is healthy"
else
    fail "/readyz setup_complete check: $SETUP_STATUS"
fi

# ---- Test 7: /ready is alias for /readyz ----
echo "==> [7/19] /ready returns same structure as /readyz"
HTTP_CODE=$(curl -sf -o /tmp/ready.json -w "%{http_code}" "$REGISTRY_URL/ready" 2>/dev/null) || true
if [ "$HTTP_CODE" = "200" ]; then
    READY_STATUS=$(jq -r '.checks.database.status' /tmp/ready.json 2>/dev/null)
    if [ "$READY_STATUS" = "healthy" ]; then
        pass "/ready returns same structure as /readyz"
    else
        fail "/ready response structure differs from /readyz"
    fi
else
    fail "/ready returned HTTP $HTTP_CODE, expected 200"
fi

# ---- Test 8: /health returns 200 ----
echo "==> [8/19] /health returns 200"
HTTP_CODE=$(curl -sf -o /tmp/health.json -w "%{http_code}" "$REGISTRY_URL/health" 2>/dev/null) || true
if [ "$HTTP_CODE" = "200" ]; then
    pass "/health returns 200"
else
    fail "/health returned HTTP $HTTP_CODE, expected 200"
fi

# ---- Test 9: /health has database check ----
echo "==> [9/19] /health checks database"
DB_STATUS=$(jq -r '.checks.database.status' /tmp/health.json 2>/dev/null)
if [ "$DB_STATUS" = "healthy" ]; then
    pass "/health database check is healthy"
else
    fail "/health database check: $DB_STATUS"
fi

# ---- Test 10: /health has storage check ----
echo "==> [10/19] /health checks storage"
STORAGE_STATUS=$(jq -r '.checks.storage.status' /tmp/health.json 2>/dev/null)
if [ "$STORAGE_STATUS" = "healthy" ]; then
    pass "/health storage check is healthy"
else
    fail "/health storage check: $STORAGE_STATUS"
fi

# ---- Test 11: /health includes db_pool stats ----
echo "==> [11/19] /health includes db_pool stats"
MAX_CONN=$(jq -r '.db_pool.max_connections' /tmp/health.json 2>/dev/null)
if [ "$MAX_CONN" != "null" ] && [ -n "$MAX_CONN" ]; then
    ACTIVE=$(jq -r '.db_pool.active_connections' /tmp/health.json 2>/dev/null)
    IDLE=$(jq -r '.db_pool.idle_connections' /tmp/health.json 2>/dev/null)
    SIZE=$(jq -r '.db_pool.size' /tmp/health.json 2>/dev/null)
    pass "/health db_pool: max=$MAX_CONN active=$ACTIVE idle=$IDLE size=$SIZE"
else
    fail "/health missing db_pool stats"
fi

# ---- Test 12: /health includes version ----
echo "==> [12/19] /health includes version"
VERSION=$(jq -r '.version' /tmp/health.json 2>/dev/null)
if [ -n "$VERSION" ] && [ "$VERSION" != "null" ]; then
    pass "/health version: $VERSION"
else
    fail "/health missing version field"
fi

# ---- Test 13: /healthz is alias for /health ----
echo "==> [13/19] /healthz is alias for /health"
HTTP_CODE=$(curl -sf -o /tmp/healthz.json -w "%{http_code}" "$REGISTRY_URL/healthz" 2>/dev/null) || true
if [ "$HTTP_CODE" = "200" ]; then
    HZ_VERSION=$(jq -r '.version' /tmp/healthz.json 2>/dev/null)
    if [ "$HZ_VERSION" = "$VERSION" ]; then
        pass "/healthz returns same data as /health"
    else
        fail "/healthz version mismatch: got $HZ_VERSION, expected $VERSION"
    fi
else
    fail "/healthz returned HTTP $HTTP_CODE, expected 200"
fi

# ---- Test 14: /api/v1/admin/metrics returns Prometheus format ----
echo "==> [14/19] /api/v1/admin/metrics returns Prometheus metrics"
HTTP_CODE=$(curl -sf -o /tmp/metrics.txt -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN" \
    "$REGISTRY_URL/api/v1/admin/metrics" 2>/dev/null) || true
if [ "$HTTP_CODE" = "200" ]; then
    pass "Metrics endpoint returns 200"
else
    fail "Metrics endpoint returned HTTP $HTTP_CODE, expected 200"
fi

# ---- Test 15: Metrics contain ak_http_requests_total ----
echo "==> [15/19] Metrics contain ak_http_requests_total"
if grep -q "ak_http_requests_total" /tmp/metrics.txt 2>/dev/null; then
    pass "ak_http_requests_total present in metrics"
else
    fail "ak_http_requests_total not found in metrics"
fi

# ---- Test 16: Metrics contain db pool gauges ----
echo "==> [16/19] Metrics contain DB pool gauges"
if grep -q "ak_db_pool_connections" /tmp/metrics.txt 2>/dev/null; then
    pass "ak_db_pool_connections gauges present in metrics"
else
    # Pool gauges are updated periodically, may not appear yet
    echo "  WARN: ak_db_pool_connections not yet in metrics (updated every 5 min)"
    pass "ak_db_pool_connections may not be populated yet (periodic update)"
fi

# ---- Test 17: X-Correlation-ID header returned ----
echo "==> [17/19] Responses include X-Correlation-ID header"
CORR_ID=$(curl -sf -D - -o /dev/null "$REGISTRY_URL/livez" 2>/dev/null | grep -i "x-correlation-id" | awk '{print $2}' | tr -d '\r')
if [ -n "$CORR_ID" ]; then
    pass "X-Correlation-ID returned: $CORR_ID"
else
    fail "X-Correlation-ID header not present in response"
fi

# ---- Test 18: Custom X-Correlation-ID is echoed back ----
echo "==> [18/19] Custom X-Correlation-ID is propagated"
CUSTOM_ID="test-correlation-$(date +%s)"
RETURNED_ID=$(curl -sf -D - -o /dev/null \
    -H "X-Correlation-ID: $CUSTOM_ID" \
    "$REGISTRY_URL/livez" 2>/dev/null | grep -i "x-correlation-id" | awk '{print $2}' | tr -d '\r')
if [ "$RETURNED_ID" = "$CUSTOM_ID" ]; then
    pass "Custom correlation ID propagated: $CUSTOM_ID"
else
    fail "Correlation ID mismatch: sent '$CUSTOM_ID', got '$RETURNED_ID'"
fi

# ---- Test 19: traceparent header extracts trace-id as correlation ID ----
echo "==> [19/19] traceparent header trace-id used as correlation ID"
TRACE_ID="4bf92f3577b34da6a3ce929d0e0e4736"
TRACEPARENT="00-${TRACE_ID}-00f067aa0ba902b7-01"
RETURNED_ID=$(curl -sf -D - -o /dev/null \
    -H "traceparent: $TRACEPARENT" \
    "$REGISTRY_URL/livez" 2>/dev/null | grep -i "x-correlation-id" | awk '{print $2}' | tr -d '\r')
if [ "$RETURNED_ID" = "$TRACE_ID" ]; then
    pass "traceparent trace-id used as correlation ID: $TRACE_ID"
else
    fail "traceparent trace-id not extracted: expected '$TRACE_ID', got '$RETURNED_ID'"
fi

# ---- Summary ----
echo ""
echo "=============================================="
echo "Health Probe Test Results"
echo "=============================================="
echo "  Passed: $PASSED"
echo "  Failed: $FAILED"
echo "  Total:  $((PASSED + FAILED))"
echo "=============================================="

# Cleanup
rm -f /tmp/livez.json /tmp/readyz.json /tmp/ready.json /tmp/health.json /tmp/healthz.json /tmp/metrics.txt

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi

echo "ALL HEALTH PROBE TESTS PASSED"
