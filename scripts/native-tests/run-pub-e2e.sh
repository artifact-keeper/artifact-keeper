#!/bin/bash
# Full E2E test script for Dart Pub upload
# Starts infrastructure, runs backend, executes test, captures results, cleans up
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REGISTRY_URL="${REGISTRY_URL:-http://localhost:8080}"
PUB_REPO_KEY="${PUB_REPO_KEY:-test-dart-pub}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-TestRunner!2026secure}"
BACKEND_PID=""
COMPOSE_PROJECT="artifact-keeper-dart-test"

cleanup() {
  echo ""
  echo "==> Cleaning up..."
  if [ -n "$BACKEND_PID" ] && kill -0 "$BACKEND_PID" 2>/dev/null; then
    kill "$BACKEND_PID" 2>/dev/null || true
    wait "$BACKEND_PID" 2>/dev/null || true
    echo "  Backend stopped (PID $BACKEND_PID)"
  fi
  docker compose -p "$COMPOSE_PROJECT" -f "$REPO_ROOT/docker-compose.local-dev.yml" down -v 2>/dev/null || true
  echo "  Postgres stopped"
}
trap cleanup EXIT

echo "=============================================="
echo "Dart Pub Upload — Full E2E Test"
echo "=============================================="
echo ""

# ---- Step 1: Start PostgreSQL ----
echo "==> [1/3] Starting PostgreSQL..."
docker compose -p "$COMPOSE_PROJECT" -f "$REPO_ROOT/docker-compose.local-dev.yml" up -d postgres 2>&1 | tail -3

echo "  Waiting for Postgres to be healthy..."
for i in $(seq 1 30); do
  if docker compose -p "$COMPOSE_PROJECT" -f "$REPO_ROOT/docker-compose.local-dev.yml" exec -T postgres pg_isready -U registry -d artifact_registry >/dev/null 2>&1; then
    echo "  Postgres is ready"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "  ❌ Postgres failed to start"
    exit 1
  fi
  sleep 1
done

# ---- Step 2: Start backend ----
echo ""
echo "==> [2/3] Starting backend (migrations run automatically on startup)..."
cd "$REPO_ROOT"

# Source project env file, then override for this test
set -a
source .env.local-dev
set +a
export ADMIN_PASSWORD="TestRunner!2026secure"
export HOST="0.0.0.0"
export SQLX_OFFLINE="true"
export AK_WEBHOOK_SECRET_KEY="$(openssl rand -base64 32)"

cargo run --bin artifact-keeper &
BACKEND_PID=$!
echo "  Backend PID: $BACKEND_PID"

echo "  Waiting for backend to be healthy (first build can take several minutes)..."
for i in $(seq 1 600); do
  if curl -sf "$REGISTRY_URL/health" >/dev/null 2>&1; then
    echo "  Backend is ready at $REGISTRY_URL"
    break
  fi
  if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
    echo "  ❌ Backend process died. Check cargo output above."
    exit 1
  fi
  if [ "$i" -eq 600 ]; then
    echo "  ❌ Backend failed to start within 10 minutes"
    exit 1
  fi
  sleep 1
done

# ---- Step 3: Run test ----
echo ""
echo "==> [3/3] Running Dart Pub E2E test..."
echo "=============================================="
REGISTRY_URL="$REGISTRY_URL" \
PUB_REPO_KEY="$PUB_REPO_KEY" \
ADMIN_USER="$ADMIN_USER" \
ADMIN_PASS="$ADMIN_PASS" \
  bash "$SCRIPT_DIR/test-pub.sh"
TEST_EXIT=$?

echo ""
echo "=============================================="
if [ "$TEST_EXIT" -eq 0 ]; then
  echo "✅ FULL E2E TEST PASSED"
else
  echo "❌ FULL E2E TEST FAILED (exit code: $TEST_EXIT)"
fi
echo "=============================================="

exit $TEST_EXIT
