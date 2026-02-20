#!/usr/bin/env bash
set -euo pipefail

# OIDC Bootstrap E2E Test
# Verifies:
#   1. OIDC env vars are bootstrapped into oidc_configs table
#   2. OIDC login flow works with Keycloak using OIDC_GROUPS_CLAIM=roles
#   3. SKIP_ADMIN_PROVISIONING=true works with env-based OIDC bootstrap

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

COMPOSE_FILE="docker-compose.oidc-bootstrap-test.yml"
BACKEND_URL="http://localhost:8080"
KEYCLOAK_URL="http://localhost:8180"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $*"; }

TESTS_PASSED=0
TESTS_FAILED=0

run_test() {
    local name="$1"
    local cmd="$2"
    echo -n "  $name ... "
    if output=$(eval "$cmd" 2>&1); then
        log_pass "OK"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_fail "FAILED"
        echo "    $output" | head -5
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

cleanup() {
    log_info "Tearing down test environment..."
    docker compose -f "$COMPOSE_FILE" down -v --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

# ============================================================================
# 1. Start environment
# ============================================================================
log_info "Starting OIDC bootstrap test environment..."
docker compose -f "$COMPOSE_FILE" up -d

log_info "Waiting for Keycloak..."
for i in $(seq 1 60); do
    if curl -sf "${KEYCLOAK_URL}/health/ready" &>/dev/null; then
        log_pass "Keycloak ready"
        break
    fi
    if [[ $i -eq 60 ]]; then
        log_fail "Keycloak failed to start"
        docker compose -f "$COMPOSE_FILE" logs keycloak | tail -20
        exit 1
    fi
    sleep 3
done

log_info "Waiting for backend..."
for i in $(seq 1 40); do
    if curl -sf "${BACKEND_URL}/health" &>/dev/null; then
        log_pass "Backend ready"
        break
    fi
    if [[ $i -eq 40 ]]; then
        log_fail "Backend failed to start"
        docker compose -f "$COMPOSE_FILE" logs backend | tail -30
        exit 1
    fi
    sleep 2
done

# ============================================================================
# 2. Test: SKIP_ADMIN_PROVISIONING works
# ============================================================================
echo ""
log_info "========== Test: SKIP_ADMIN_PROVISIONING =========="

run_test "Admin login is rejected (no admin user provisioned)" '
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BACKEND_URL}/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\": \"admin\", \"password\": \"anything\"}")
    [[ "$http_code" == "401" ]]
'

run_test "Backend logs show SKIP_ADMIN_PROVISIONING message" '
    docker compose -f "$COMPOSE_FILE" logs backend 2>&1 | sed "s/\x1b\[[0-9;]*m//g" | grep -q "SKIP_ADMIN_PROVISIONING"
'

# ============================================================================
# 3. Test: OIDC config bootstrapped from env vars
# ============================================================================
echo ""
log_info "========== Test: OIDC Env Var Bootstrap =========="

run_test "Backend logs show OIDC bootstrap message" '
    docker compose -f "$COMPOSE_FILE" logs backend 2>&1 | sed "s/\x1b\[[0-9;]*m//g" | grep -q "Bootstrapped OIDC provider"
'

run_test "oidc_configs table has exactly 1 row" '
    count=$(docker compose -f "$COMPOSE_FILE" exec -T postgres \
        psql -U registry -d artifact_registry -t -c "SELECT count(*) FROM oidc_configs;" | tr -d " ")
    [[ "$count" == "1" ]]
'

run_test "Bootstrapped config has correct issuer_url" '
    issuer=$(docker compose -f "$COMPOSE_FILE" exec -T postgres \
        psql -U registry -d artifact_registry -t -c "SELECT issuer_url FROM oidc_configs LIMIT 1;" | tr -d " ")
    [[ "$issuer" == "http://keycloak:8080/realms/artifact-keeper" ]]
'

run_test "Bootstrapped config has groups_claim=roles in attribute_mapping" '
    mapping=$(docker compose -f "$COMPOSE_FILE" exec -T postgres \
        psql -U registry -d artifact_registry -t -c "SELECT attribute_mapping FROM oidc_configs LIMIT 1;")
    echo "$mapping" | grep -q '"groups_claim"' && echo "$mapping" | grep -q '"roles"'
'

run_test "Bootstrapped config has redirect_uri in attribute_mapping" '
    mapping=$(docker compose -f "$COMPOSE_FILE" exec -T postgres \
        psql -U registry -d artifact_registry -t -c "SELECT attribute_mapping FROM oidc_configs LIMIT 1;")
    echo "$mapping" | grep -q '"redirect_uri"'
'

run_test "Bootstrapped config has encrypted client_secret (not plaintext)" '
    secret=$(docker compose -f "$COMPOSE_FILE" exec -T postgres \
        psql -U registry -d artifact_registry -t -c "SELECT client_secret_encrypted FROM oidc_configs LIMIT 1;" | tr -d " ")
    [[ "$secret" != "artifact-keeper-secret" ]] && [[ -n "$secret" ]]
'

# ============================================================================
# 4. Setup Keycloak realm and test OIDC login flow
# ============================================================================
echo ""
log_info "========== Test: OIDC Login Flow with Keycloak =========="

# Use kcadm.sh inside the container to avoid HTTPS requirement on admin API.
# All admin commands run on localhost inside the container, bypassing SSL checks.
KCADM="docker compose -f $COMPOSE_FILE exec -T keycloak /opt/keycloak/bin/kcadm.sh"

log_info "Authenticating to Keycloak admin CLI..."
KC_CONFIGURED=false
for attempt in $(seq 1 10); do
    if $KCADM config credentials --server http://localhost:8080 --realm master \
        --user admin --password admin 2>/dev/null; then
        KC_CONFIGURED=true
        break
    fi
    sleep 5
done

if [[ "$KC_CONFIGURED" != "true" ]]; then
    log_fail "Could not authenticate to Keycloak admin CLI, skipping OIDC login flow tests"
    TESTS_FAILED=$((TESTS_FAILED + 4))
else

# Create realm
$KCADM create realms -s realm=artifact-keeper -s enabled=true 2>/dev/null || true

# Disable SSL requirement on the new realm (allows HTTP token exchange from host)
$KCADM update realms/artifact-keeper -s sslRequired=none 2>/dev/null || true

# Get the bootstrapped OIDC config ID from the database
OIDC_ID=$(docker compose -f "$COMPOSE_FILE" exec -T postgres \
    psql -U registry -d artifact_registry -t -c "SELECT id FROM oidc_configs LIMIT 1;" | tr -d " ")
log_info "Bootstrapped OIDC config ID: ${OIDC_ID}"

# Create OIDC client in Keycloak with matching redirect URI
$KCADM create clients -r artifact-keeper \
    -s clientId=artifact-keeper \
    -s enabled=true \
    -s clientAuthenticatorType=client-secret \
    -s secret=artifact-keeper-secret \
    -s 'redirectUris=["http://localhost:8080/api/v1/auth/sso/oidc/*/callback"]' \
    -s publicClient=false \
    -s protocol=openid-connect \
    -s standardFlowEnabled=true \
    -s directAccessGrantsEnabled=true 2>/dev/null || true

# Get the client's internal ID for adding protocol mappers
CLIENT_INTERNAL_ID=$($KCADM get clients -r artifact-keeper -q clientId=artifact-keeper \
    --fields id 2>/dev/null | jq -r '.[0].id' || echo "")

if [[ -n "$CLIENT_INTERNAL_ID" ]] && [[ "$CLIENT_INTERNAL_ID" != "null" ]]; then
    # Add a mapper to put realm roles into a "roles" claim in the id_token
    # (Keycloak default is "groups", but our test uses OIDC_GROUPS_CLAIM=roles)
    $KCADM create "clients/${CLIENT_INTERNAL_ID}/protocol-mappers/models" -r artifact-keeper \
        -s name=roles-claim \
        -s protocol=openid-connect \
        -s protocolMapper=oidc-usermodel-realm-role-mapper \
        -s 'config."multivalued"=true' \
        -s 'config."claim.name"=roles' \
        -s 'config."jsonType.label"=String' \
        -s 'config."id.token.claim"=true' \
        -s 'config."access.token.claim"=true' \
        -s 'config."userinfo.token.claim"=true' 2>/dev/null || true
fi

# Create test user
$KCADM create users -r artifact-keeper \
    -s username=oidcuser \
    -s email=oidcuser@test.local \
    -s firstName=OIDC \
    -s lastName=User \
    -s enabled=true \
    -s emailVerified=true 2>/dev/null || true

# Set user password
$KCADM set-password -r artifact-keeper --username oidcuser --new-password oidcpassword 2>/dev/null || true

run_test "OIDC login endpoint returns redirect to Keycloak" '
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        "${BACKEND_URL}/api/v1/auth/sso/oidc/${OIDC_ID}/login")
    [[ "$http_code" =~ ^(307|302)$ ]]
'

run_test "OIDC redirect URL contains Keycloak authorization endpoint" '
    location=$(curl -sI "${BACKEND_URL}/api/v1/auth/sso/oidc/${OIDC_ID}/login" | grep -i "^location:" || echo "")
    echo "$location" | grep -qi "keycloak\|realms/artifact-keeper"
'

run_test "Keycloak direct token exchange works" '
    kc_token=$(curl -sf -X POST "${KEYCLOAK_URL}/realms/artifact-keeper/protocol/openid-connect/token" \
        --data-urlencode "grant_type=password" \
        --data-urlencode "client_id=artifact-keeper" \
        --data-urlencode "client_secret=artifact-keeper-secret" \
        --data-urlencode "username=oidcuser" \
        --data-urlencode "password=oidcpassword" | jq -r ".access_token")
    [[ -n "$kc_token" ]] && [[ "$kc_token" != "null" ]]
'

run_test "Keycloak id_token contains 'roles' claim (not 'groups')" '
    token_response=$(curl -sf -X POST "${KEYCLOAK_URL}/realms/artifact-keeper/protocol/openid-connect/token" \
        --data-urlencode "grant_type=password" \
        --data-urlencode "client_id=artifact-keeper" \
        --data-urlencode "client_secret=artifact-keeper-secret" \
        --data-urlencode "username=oidcuser" \
        --data-urlencode "password=oidcpassword" \
        --data-urlencode "scope=openid email profile")
    id_token=$(echo "$token_response" | jq -r ".id_token")
    # Decode JWT payload (base64url middle segment, add padding for macOS base64)
    b64=$(echo "$id_token" | cut -d. -f2 | tr -- "-_" "+/")
    pad=$((4 - ${#b64} % 4))
    [[ $pad -lt 4 ]] && b64="${b64}$(printf "=%.0s" $(seq 1 $pad))"
    payload=$(echo "$b64" | base64 -d 2>/dev/null || echo "{}")
    echo "$payload" | jq -e ".roles" > /dev/null
'

fi  # end KC_CONFIGURED check

# ============================================================================
# 5. Test: Idempotent bootstrap (restart should not create duplicate)
# ============================================================================
echo ""
log_info "========== Test: Idempotent Bootstrap =========="

run_test "Restart backend does not create duplicate OIDC config" '
    docker compose -f "$COMPOSE_FILE" restart backend
    sleep 10
    for i in $(seq 1 20); do
        curl -sf "${BACKEND_URL}/health" &>/dev/null && break
        sleep 2
    done
    count=$(docker compose -f "$COMPOSE_FILE" exec -T postgres \
        psql -U registry -d artifact_registry -t -c "SELECT count(*) FROM oidc_configs;" | tr -d " ")
    [[ "$count" == "1" ]]
'

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "=============================================="
echo "           OIDC BOOTSTRAP TEST SUMMARY"
echo "=============================================="
echo -e "  ${GREEN}Passed:${NC} $TESTS_PASSED"
echo -e "  ${RED}Failed:${NC} $TESTS_FAILED"
echo "=============================================="

if [[ $TESTS_FAILED -gt 0 ]]; then
    log_fail "Some tests failed!"
    echo ""
    log_info "Backend logs:"
    docker compose -f "$COMPOSE_FILE" logs backend 2>&1 | tail -30
    exit 1
else
    log_pass "All tests passed!"
    exit 0
fi
