#!/usr/bin/env bash
set -euo pipefail

# SSO E2E Test Runner
# Tests LDAP, OIDC, and SAML authentication flows against real identity providers

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[PASS]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[FAIL]${NC} $*"; }

TESTS_PASSED=0
TESTS_FAILED=0

# Parse arguments
CLEAN=false
SKIP_SETUP=false
TEST_LDAP=true
TEST_OIDC=true
TEST_SAML=true

while [[ $# -gt 0 ]]; do
    case $1 in
        --clean) CLEAN=true; shift ;;
        --skip-setup) SKIP_SETUP=true; shift ;;
        --ldap-only) TEST_OIDC=false; TEST_SAML=false; shift ;;
        --oidc-only) TEST_LDAP=false; TEST_SAML=false; shift ;;
        --saml-only) TEST_LDAP=false; TEST_OIDC=false; shift ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --clean       Tear down environment after tests"
            echo "  --skip-setup  Skip environment setup (assumes already running)"
            echo "  --ldap-only   Only run LDAP tests"
            echo "  --oidc-only   Only run OIDC tests"
            echo "  --saml-only   Only run SAML tests"
            echo "  -h, --help    Show this help"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

cleanup() {
    if [[ "$CLEAN" == "true" ]]; then
        log_info "Cleaning up test environment..."
        docker compose down -v --remove-orphans 2>/dev/null || true
        rm -f sso-config-ids.env
    fi
}
trap cleanup EXIT

# ============================================================================
# Environment Setup
# ============================================================================

if [[ "$SKIP_SETUP" == "false" ]]; then
    log_info "Starting SSO test environment..."
    docker compose up -d

    log_info "Waiting for services to be healthy..."

    # Wait for OpenLDAP
    log_info "Waiting for OpenLDAP..."
    for i in {1..30}; do
        if docker compose exec -T openldap ldapsearch -x -H ldap://localhost -b "dc=test,dc=local" -D "cn=admin,dc=test,dc=local" -w adminpassword &>/dev/null; then
            break
        fi
        sleep 2
    done
    log_success "OpenLDAP is ready"

    # Wait for Keycloak (no timeout command on macOS, use loop)
    log_info "Waiting for Keycloak (this may take a minute)..."
    for i in {1..40}; do
        if curl -sf http://localhost:8180/health/ready &>/dev/null; then
            break
        fi
        sleep 3
    done
    if ! curl -sf http://localhost:8180/health/ready &>/dev/null; then
        log_error "Keycloak failed to start"
        exit 1
    fi
    log_success "Keycloak is ready"

    # Wait for backend
    log_info "Waiting for Artifact Keeper backend..."
    for i in {1..30}; do
        if curl -sf http://localhost:8080/health &>/dev/null; then
            break
        fi
        sleep 2
    done
    if ! curl -sf http://localhost:8080/health &>/dev/null; then
        log_error "Backend failed to start"
        docker compose logs backend | tail -50
        exit 1
    fi
    log_success "Backend is ready"

    # Setup test data in IdPs
    log_info "Setting up LDAP test users..."
    ./setup-ldap.sh

    log_info "Setting up Keycloak realm and clients..."
    ./setup-keycloak.sh

    # Setup SSO configs in backend
    log_info "Configuring SSO providers in backend..."
    ./setup-backend-sso.sh
fi

# Load SSO config IDs
if [[ ! -f sso-config-ids.env ]]; then
    log_error "sso-config-ids.env not found. Run without --skip-setup first."
    exit 1
fi
source sso-config-ids.env

log_info "Loaded SSO Config IDs:"
log_info "  LDAP: ${LDAP_CONFIG_ID}"
log_info "  OIDC: ${OIDC_CONFIG_ID}"
log_info "  SAML: ${SAML_CONFIG_ID}"

# ============================================================================
# Test Functions
# ============================================================================

run_test() {
    local name="$1"
    local cmd="$2"

    echo -n "  Testing: $name... "
    if output=$(eval "$cmd" 2>&1); then
        log_success "OK"
        ((TESTS_PASSED++))
        return 0
    else
        log_error "FAILED"
        echo "    Output: $output" | head -5
        ((TESTS_FAILED++))
        return 1
    fi
}

# ============================================================================
# LDAP Tests
# ============================================================================

if [[ "$TEST_LDAP" == "true" ]]; then
    echo ""
    log_info "========== LDAP Authentication Tests =========="

    # Test LDAP login with valid credentials
    run_test "LDAP user login (valid)" '
        response=$(curl -sf -X POST "http://localhost:8080/api/v1/auth/sso/ldap/${LDAP_CONFIG_ID}/login" \
            -H "Content-Type: application/json" \
            -d "{\"username\": \"testuser\", \"password\": \"testpassword\"}")
        echo "$response" | jq -e ".access_token" > /dev/null
    ' || true

    # Test LDAP login with wrong password
    run_test "LDAP rejects bad password" '
        ! curl -sf -X POST "http://localhost:8080/api/v1/auth/sso/ldap/${LDAP_CONFIG_ID}/login" \
            -H "Content-Type: application/json" \
            -d "{\"username\": \"testuser\", \"password\": \"wrongpassword\"}"
    ' || true

    # Test LDAP admin user login
    run_test "LDAP admin user login" '
        response=$(curl -sf -X POST "http://localhost:8080/api/v1/auth/sso/ldap/${LDAP_CONFIG_ID}/login" \
            -H "Content-Type: application/json" \
            -d "{\"username\": \"adminuser\", \"password\": \"adminpassword\"}")
        echo "$response" | jq -e ".access_token" > /dev/null
    ' || true

    # Test that LDAP user can access /auth/me
    run_test "LDAP user can access /auth/me" '
        token=$(curl -sf -X POST "http://localhost:8080/api/v1/auth/sso/ldap/${LDAP_CONFIG_ID}/login" \
            -H "Content-Type: application/json" \
            -d "{\"username\": \"testuser\", \"password\": \"testpassword\"}" | jq -r ".access_token")
        user=$(curl -sf "http://localhost:8080/api/v1/auth/me" -H "Authorization: Bearer $token")
        echo "$user" | jq -e ".username" > /dev/null
    ' || true

    # Test LDAP config test endpoint
    run_test "LDAP test connection endpoint" '
        # Login as admin first
        admin_token=$(curl -sf -X POST "http://localhost:8080/api/v1/auth/login" \
            -H "Content-Type: application/json" \
            -d "{\"username\": \"admin\", \"password\": \"admin123\"}" | jq -r ".access_token")
        response=$(curl -sf -X POST "http://localhost:8080/api/v1/admin/sso/ldap/${LDAP_CONFIG_ID}/test" \
            -H "Authorization: Bearer $admin_token" \
            -H "Content-Type: application/json")
        echo "$response" | jq -e ".success" > /dev/null
    ' || true
fi

# ============================================================================
# OIDC Tests
# ============================================================================

if [[ "$TEST_OIDC" == "true" ]]; then
    echo ""
    log_info "========== OIDC Authentication Tests =========="

    # Test OIDC login redirect (accepts any 2xx or 3xx as valid redirect response)
    run_test "OIDC login returns redirect URL" '
        http_code=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/api/v1/auth/sso/oidc/${OIDC_CONFIG_ID}/login")
        [[ "$http_code" =~ ^(200|301|302|303|307|308)$ ]]
    ' || true

    # Test that OIDC redirect contains Keycloak URL
    run_test "OIDC redirects to Keycloak" '
        response=$(curl -sI "http://localhost:8080/api/v1/auth/sso/oidc/${OIDC_CONFIG_ID}/login" | grep -i "location" || echo "")
        echo "$response" | grep -q "keycloak\|8180\|realms/artifact-keeper"
    ' || true

    # Test Keycloak direct token (proves Keycloak is configured correctly)
    run_test "Keycloak OIDC token exchange works" '
        kc_token=$(curl -sf -X POST "http://localhost:8180/realms/artifact-keeper/protocol/openid-connect/token" \
            --data-urlencode "grant_type=password" \
            --data-urlencode "client_id=artifact-keeper" \
            --data-urlencode "client_secret=artifact-keeper-secret" \
            --data-urlencode "username=oidcuser" \
            --data-urlencode "password=oidcpassword" | jq -r ".access_token")
        [[ -n "$kc_token" ]] && [[ "$kc_token" != "null" ]]
    ' || true

    # Test listing OIDC providers
    run_test "Can list OIDC providers" '
        admin_token=$(curl -sf -X POST "http://localhost:8080/api/v1/auth/login" \
            -H "Content-Type: application/json" \
            -d "{\"username\": \"admin\", \"password\": \"admin123\"}" | jq -r ".access_token")
        response=$(curl -sf "http://localhost:8080/api/v1/admin/sso/oidc" \
            -H "Authorization: Bearer $admin_token")
        echo "$response" | jq -e "length >= 1" > /dev/null
    ' || true
fi

# ============================================================================
# SAML Tests
# ============================================================================

if [[ "$TEST_SAML" == "true" ]]; then
    echo ""
    log_info "========== SAML Authentication Tests =========="

    # Test SAML login redirect (accepts any 2xx or 3xx as valid redirect response)
    run_test "SAML login returns redirect" '
        http_code=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/api/v1/auth/sso/saml/${SAML_CONFIG_ID}/login")
        [[ "$http_code" =~ ^(200|301|302|303|307|308)$ ]]
    ' || true

    # Test SAML redirects to IdP
    run_test "SAML redirects to Keycloak IdP" '
        response=$(curl -sI "http://localhost:8080/api/v1/auth/sso/saml/${SAML_CONFIG_ID}/login" | grep -i "location" || echo "")
        echo "$response" | grep -qi "keycloak\|8180\|saml"
    ' || true

    # Test listing SAML providers
    run_test "Can list SAML providers" '
        admin_token=$(curl -sf -X POST "http://localhost:8080/api/v1/auth/login" \
            -H "Content-Type: application/json" \
            -d "{\"username\": \"admin\", \"password\": \"admin123\"}" | jq -r ".access_token")
        response=$(curl -sf "http://localhost:8080/api/v1/admin/sso/saml" \
            -H "Authorization: Bearer $admin_token")
        echo "$response" | jq -e "length >= 1" > /dev/null
    ' || true

    # Test Keycloak SAML metadata is accessible
    run_test "Keycloak SAML metadata available" '
        curl -sf "http://localhost:8180/realms/artifact-keeper/protocol/saml/descriptor" | grep -q "EntityDescriptor"
    ' || true
fi

# ============================================================================
# Provider List Tests
# ============================================================================

echo ""
log_info "========== Provider List Tests =========="

run_test "Can list all enabled SSO providers" '
    admin_token=$(curl -sf -X POST "http://localhost:8080/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\": \"admin\", \"password\": \"admin123\"}" | jq -r ".access_token")
    response=$(curl -sf "http://localhost:8080/api/v1/admin/sso/providers" \
        -H "Authorization: Bearer $admin_token")
    echo "$response" | jq -e "length >= 1" > /dev/null
' || true

# ============================================================================
# Summary
# ============================================================================

echo ""
echo "=============================================="
echo "                TEST SUMMARY"
echo "=============================================="
echo -e "  ${GREEN}Passed:${NC} $TESTS_PASSED"
echo -e "  ${RED}Failed:${NC} $TESTS_FAILED"
echo "=============================================="

if [[ $TESTS_FAILED -gt 0 ]]; then
    log_error "Some tests failed!"
    exit 1
else
    log_success "All tests passed!"
    exit 0
fi
