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
# Throwaway e2e admin credential: the value is defined once, in the
# repository-root .env.test (#3490). Located relative to THIS file rather than
# to $0, because every test script sources it from tests/ one level deeper.
# Absent inside the redteam container, which mounts only scripts/redteam — and
# there compose has already injected the same variables from the same file.
_ak_test_env="$(dirname "${BASH_SOURCE[0]}")/../lib/test-env.sh"
# shellcheck source=/dev/null
[ -r "$_ak_test_env" ] && . "$_ak_test_env"
ADMIN_PASS="${ADMIN_PASS:-${AK_TEST_ADMIN_PASSWORD:-}}"
# Directory holding the .proto files, mounted into the redteam container by
# docker-compose.test.yml. grpcurl needs them to invoke a method when server
# reflection is disabled (which it is, and should be — see tests/06).
PROTO_DIR="${PROTO_DIR:-/protos}"
RESULTS_DIR="${RESULTS_DIR:-/results}"
REPORT_FILE="${RESULTS_DIR}/redteam-report.json"

# ---------------------------------------------------------------------------
# Cross-script state (#3491)
#
# run-all.sh INVOKES each test script (`bash tests/NN-*.sh`), it does not
# source it, so every script gets its own shell and its own copy of any
# variable this file defines. Shell counters therefore reset per script: the
# final summary printed "Passed: 1 checks" after dozens of PASS lines, and the
# "is this the first finding?" flag reset too, so the report was written
# without the commas between findings contributed by different scripts and
# `jq` could not parse it.
#
# Keep both on disk instead. The suite is strictly sequential, so a
# read-modify-write per counter is sufficient and needs no locking.
# ---------------------------------------------------------------------------
STATE_DIR="${RESULTS_DIR}/.state"

_state_file() { printf '%s/%s' "$STATE_DIR" "$1"; }

# counter <name> -- current value, 0 when unset or corrupt.
counter() {
    local n
    n=$(cat "$(_state_file "$1")" 2>/dev/null) || n=0
    case "$n" in
        '' | *[!0-9]*) n=0 ;;
    esac
    printf '%s' "$n"
}

_bump() {
    local name="$1" n
    mkdir -p "$STATE_DIR" 2>/dev/null || true
    n=$(counter "$name")
    echo $((n + 1)) > "$(_state_file "$name")"
}

pass() { _bump pass; echo -e "  ${GREEN}[PASS]${NC} $1"; }
fail() { _bump fail; echo -e "  ${RED}[FAIL]${NC} $1"; }
warn() { _bump warn; echo -e "  ${YELLOW}[WARN]${NC} $1"; }
info() { _bump info; echo -e "  ${BLUE}[INFO]${NC} $1"; }
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

# ---------------------------------------------------------------------------
# Shared admin bearer token (#3491)
#
# The login rate limiter (RATE_LIMIT_LOGIN_PER_WINDOW, 10 per 900s) is a
# control we WANT enabled while the suite runs, and tests 04 and 10
# deliberately spend attempts against it. Every later script used to log in
# for itself, found the window exhausted, and printed "Could not authenticate
# — skipping": tests 14 and 15 reported success while asserting nothing.
#
# Log in at most once per run and share the token through RESULTS_DIR. A
# cached token is re-validated before use, so an expiry mid-run costs one
# extra login rather than silently failing every authenticated probe.
# ---------------------------------------------------------------------------
_TOKEN_CACHE_NAME="auth-token"

_login_for_token() {
    local response token
    response=$(curl -s -X POST -H "Content-Type: application/json" \
        -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" \
        "${REGISTRY_URL}/api/v1/auth/login" 2>/dev/null) || true
    token=$(echo "$response" | jq -r '.access_token // .token // empty' 2>/dev/null) || true
    [ -n "$token" ] || return 1
    mkdir -p "$STATE_DIR" 2>/dev/null || true
    (umask 077; printf '%s' "$token" > "$(_state_file "$_TOKEN_CACHE_NAME")")
    printf '%s' "$token"
}

_token_is_live() {
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $1" \
        "${REGISTRY_URL}/api/v1/repositories" 2>/dev/null) || return 1
    [ "$code" != "401" ]
}

# auth_token -- echo a usable admin bearer token, or return 1.
auth_token() {
    local cached
    cached=$(cat "$(_state_file "$_TOKEN_CACHE_NAME")" 2>/dev/null) || cached=""
    if [ -n "$cached" ] && _token_is_live "$cached"; then
        printf '%s' "$cached"
        return 0
    fi
    _login_for_token
}

# JSON report functions
init_report() {
    mkdir -p "$RESULTS_DIR" "$STATE_DIR"
    rm -f "$STATE_DIR"/pass "$STATE_DIR"/fail "$STATE_DIR"/warn \
        "$STATE_DIR"/info "$STATE_DIR"/findings "$STATE_DIR"/"$_TOKEN_CACHE_NAME"
    cat > "$REPORT_FILE" <<EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "target": "$REGISTRY_URL",
  "findings": [
EOF
}

add_finding() {
    local severity="$1" test_name="$2" description="$3" evidence="${4:-}"
    # Auto-initialize report if running a single test outside run-all.sh
    if [ ! -f "$REPORT_FILE" ]; then
        init_report
    fi
    # The separator depends on whether ANY script has written a finding yet,
    # which is why the count lives on disk and not in a shell variable.
    if [ "$(counter findings)" -gt 0 ]; then
        echo "," >> "$REPORT_FILE"
    fi
    _bump findings
    cat >> "$REPORT_FILE" <<EOF
    {
      "severity": $(printf '%s' "$severity" | jq -Rs .),
      "test": $(printf '%s' "$test_name" | jq -Rs .),
      "description": $(printf '%s' "$description" | jq -Rs .),
      "evidence": $(printf '%s' "$evidence" | jq -Rs .)
    }
EOF
}

# finalize_report -- close the JSON document and prove it parses. Returns
# non-zero if it does not, so a report nothing can read is a loud failure
# rather than a file discovered to be garbage weeks later (#3491).
finalize_report() {
    cat >> "$REPORT_FILE" <<EOF

  ],
  "summary": {
    "pass": $(counter pass),
    "fail": $(counter fail),
    "warn": $(counter warn),
    "info": $(counter info),
    "findings": $(counter findings)
  }
}
EOF
    if ! jq empty "$REPORT_FILE" 2>/dev/null; then
        echo -e "  ${RED}[FAIL]${NC} $REPORT_FILE is not valid JSON"
        return 1
    fi
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
