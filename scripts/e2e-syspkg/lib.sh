#!/bin/bash
# Shared helper functions for system package E2E tests.
# Source this file from each test script: source /scripts/lib.sh

BACKEND_URL="${BACKEND_URL:-http://artifact-keeper-backend:8080}"
AUTH_USER="${AUTH_USER:-admin}"
AUTH_PASS="${AUTH_PASS:-admin123}"
TOKEN=""

log() { echo "==> $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

# Authenticate and export TOKEN
api_login() {
    log "Logging in as $AUTH_USER..."
    local resp
    resp=$(curl -sf -X POST "$BACKEND_URL/api/v1/auth/login" \
        -H 'Content-Type: application/json' \
        -d "{\"username\":\"$AUTH_USER\",\"password\":\"$AUTH_PASS\"}")
    TOKEN=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null) \
        || TOKEN=$(echo "$resp" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
    [ -n "$TOKEN" ] || fail "Failed to get auth token"
    export TOKEN
    log "Authenticated successfully"
}

# Create a repository: api_create_repo <key> <format>
api_create_repo() {
    local key="$1" format="$2"
    log "Creating repository: $key (format=$format)..."
    local resp
    resp=$(curl -s -w "\n%{http_code}" -X POST "$BACKEND_URL/api/v1/repositories" \
        -H "Authorization: Bearer $TOKEN" \
        -H 'Content-Type: application/json' \
        -d "{\"key\":\"$key\",\"name\":\"E2E $key\",\"format\":\"$format\",\"repo_type\":\"local\",\"is_public\":true}")
    local http_code
    http_code=$(echo "$resp" | tail -1)
    local body
    body=$(echo "$resp" | sed '$d')

    if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
        REPO_ID=$(echo "$body" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null) \
            || REPO_ID=$(echo "$body" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
        export REPO_ID
        log "Repository created: $REPO_ID"
    elif echo "$body" | grep -qi "already exists\|duplicate\|unique"; then
        # Repo already exists, fetch its ID
        log "Repository $key already exists, fetching ID..."
        REPO_ID=$(curl -sf "$BACKEND_URL/api/v1/repositories" \
            -H "Authorization: Bearer $TOKEN" | \
            python3 -c "
import sys, json
data = json.load(sys.stdin)
repos = data if isinstance(data, list) else data.get('items', data.get('repositories', []))
for r in repos:
    if r['key'] == '$key':
        print(r['id']); break" 2>/dev/null)
        [ -n "$REPO_ID" ] || fail "Could not find existing repo $key"
        export REPO_ID
        log "Found existing repository: $REPO_ID"
    else
        fail "Failed to create repository (HTTP $http_code): $body"
    fi
}

# Create a signing key for a repo: api_create_signing_key [key_type]
# Uses $REPO_ID, exports $SIGNING_KEY_ID. key_type defaults to rsa for
# existing system-package tests; Debian passes gpg so apt receives real
# OpenPGP Release metadata signatures.
api_create_signing_key() {
    local key_type="${1:-rsa}"
    log "Creating $key_type RSA-4096 signing key for repo $REPO_ID..."
    local resp
    resp=$(curl -sf -X POST "$BACKEND_URL/api/v1/signing/keys" \
        -H "Authorization: Bearer $TOKEN" \
        -H 'Content-Type: application/json' \
        -d "{\"name\":\"e2e-signing-key\",\"key_type\":\"$key_type\",\"algorithm\":\"rsa4096\",\"repository_id\":\"$REPO_ID\"}")
    SIGNING_KEY_ID=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null) \
        || SIGNING_KEY_ID=$(echo "$resp" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
    [ -n "$SIGNING_KEY_ID" ] || fail "Failed to create signing key"
    export SIGNING_KEY_ID
    log "Signing key created: $SIGNING_KEY_ID"
}

# Configure signing on the repo: api_configure_signing
# Uses $REPO_ID, $SIGNING_KEY_ID
api_configure_signing() {
    log "Configuring signing for repo $REPO_ID..."
    curl -sf -X POST "$BACKEND_URL/api/v1/signing/repositories/$REPO_ID/config" \
        -H "Authorization: Bearer $TOKEN" \
        -H 'Content-Type: application/json' \
        -d "{\"signing_key_id\":\"$SIGNING_KEY_ID\",\"sign_metadata\":true}" > /dev/null \
        || fail "Failed to configure signing"
    log "Signing configured"
}

# Full setup: login + create repo + create key + configure signing
# Usage: setup_signed_repo <repo_key> <format> [key_type]
setup_signed_repo() {
    api_login
    api_create_repo "$1" "$2"
    api_create_signing_key "${3:-rsa}"
    api_configure_signing
}

# Setup without signing
# Usage: setup_repo <repo_key> <format>
setup_repo() {
    api_login
    api_create_repo "$1" "$2"
}
