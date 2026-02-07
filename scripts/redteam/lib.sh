#!/bin/bash
# Shared utilities for red team tests

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Environment
REGISTRY_URL="${REGISTRY_URL:-http://backend:8080}"
GRPC_URL="${GRPC_URL:-backend:9090}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin123}"
RESULTS_DIR="${RESULTS_DIR:-/results}"
REPORT_FILE="${RESULTS_DIR}/redteam-report.json"

# Counters
_PASS_COUNT=0
_FAIL_COUNT=0
_WARN_COUNT=0
_INFO_COUNT=0
_FIRST_FINDING=true

pass() { _PASS_COUNT=$((_PASS_COUNT + 1)); echo -e "  ${GREEN}[PASS]${NC} $1"; }
fail() { _FAIL_COUNT=$((_FAIL_COUNT + 1)); echo -e "  ${RED}[FAIL]${NC} $1"; }
warn() { _WARN_COUNT=$((_WARN_COUNT + 1)); echo -e "  ${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "  ${BLUE}[INFO]${NC} $1"; }
header() { echo -e "\n${CYAN}=== $1 ===${NC}"; }

# HTTP helpers
api_call() {
    local method="$1" path="$2" data="${3:-}"
    if [ -n "$data" ]; then
        curl -s -X "$method" -H "Content-Type: application/json" \
            -u "${ADMIN_USER}:${ADMIN_PASS}" \
            -d "$data" "${REGISTRY_URL}${path}"
    else
        curl -s -X "$method" -u "${ADMIN_USER}:${ADMIN_PASS}" "${REGISTRY_URL}${path}"
    fi
}

api_call_noauth() {
    local method="$1" path="$2" data="${3:-}"
    if [ -n "$data" ]; then
        curl -s -X "$method" -H "Content-Type: application/json" \
            -d "$data" "${REGISTRY_URL}${path}"
    else
        curl -s -X "$method" "${REGISTRY_URL}${path}"
    fi
}

api_call_status() {
    local method="$1" path="$2"
    curl -s -o /dev/null -w "%{http_code}" -X "$method" "${REGISTRY_URL}${path}"
}

api_call_headers() {
    local method="$1" path="$2"
    curl -sI -X "$method" "${REGISTRY_URL}${path}"
}

# JSON report functions
init_report() {
    mkdir -p "$RESULTS_DIR"
    cat > "$REPORT_FILE" <<EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "target": "$REGISTRY_URL",
  "findings": [
EOF
    _FIRST_FINDING=true
}

add_finding() {
    local severity="$1" test_name="$2" description="$3" evidence="${4:-}"
    # Auto-initialize report if running a single test outside run-all.sh
    if [ ! -f "$REPORT_FILE" ]; then
        init_report
    fi
    if [ "$_FIRST_FINDING" = true ]; then
        _FIRST_FINDING=false
    else
        echo "," >> "$REPORT_FILE"
    fi
    cat >> "$REPORT_FILE" <<EOF
    {
      "severity": "$severity",
      "test": "$test_name",
      "description": "$description",
      "evidence": $(echo "$evidence" | jq -Rs . 2>/dev/null || echo "\"$evidence\"")
    }
EOF
}

finalize_report() {
    cat >> "$REPORT_FILE" <<EOF

  ],
  "summary": {
    "pass": $_PASS_COUNT,
    "fail": $_FAIL_COUNT,
    "warn": $_WARN_COUNT,
    "info": $_INFO_COUNT
  }
}
EOF
    info "Report written to $REPORT_FILE"
}

# Wait for backend to be ready
wait_for_backend() {
    local max_wait=60
    local waited=0
    while [ $waited -lt $max_wait ]; do
        if curl -sf "${REGISTRY_URL}/health" > /dev/null 2>&1; then
            return 0
        fi
        sleep 2
        waited=$((waited + 2))
    done
    echo "ERROR: Backend not ready after ${max_wait}s"
    return 1
}
