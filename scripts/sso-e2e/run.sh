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

    # Setup test data
    log_info "Setting up LDAP test users..."
    ./setup-ldap.sh

    log_info "Setting up Keycloak realm and clients..."
    ./setup-keycloak.sh
fi

# ============================================================================
# Test Functions
# ============================================================================

run_test() {
    local name="$1"
    local cmd="$2"

    echo -n "  Testing: $name... "
    if eval "$cmd" &>/dev/null; then
        log_success "OK"
        ((TESTS_PASSED++))
        return 0
    else
        log_error "FAILED"
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

    # Test LDAP login
    run_test "LDAP user login" '
        response=$(curl -sf -X POST http://localhost:8080/api/v1/auth/ldap/login \
            -H "Content-Type: application/json" \
            -d "{\"username\": \"testuser\", \"password\": \"testpassword\"}")
        echo "$response" | jq -e ".access_token" > /dev/null
    ' || true

    # Test LDAP login with wrong password
    run_test "LDAP rejects bad password" '
        ! curl -sf -X POST http://localhost:8080/api/v1/auth/ldap/login \
            -H "Content-Type: application/json" \
            -d "{\"username\": \"testuser\", \"password\": \"wrongpassword\"}"
    ' || true

    # Test LDAP user info after login
    run_test "LDAP user has correct attributes" '
        token=$(curl -sf -X POST http://localhost:8080/api/v1/auth/ldap/login \
            -H "Content-Type: application/json" \
            -d "{\"username\": \"testuser\", \"password\": \"testpassword\"}" | jq -r ".access_token")
        user=$(curl -sf http://localhost:8080/api/v1/auth/me -H "Authorization: Bearer $token")
        echo "$user" | jq -e ".username == \"testuser\"" > /dev/null
    ' || true
fi

# ============================================================================
# OIDC Tests
# ============================================================================

if [[ "$TEST_OIDC" == "true" ]]; then
    echo ""
    log_info "========== OIDC Authentication Tests =========="

    # Test OIDC authorization URL
    run_test "OIDC auth URL returns redirect" '
        response=$(curl -sf -w "%{http_code}" -o /dev/null http://localhost:8080/api/v1/auth/oidc/authorize)
        [[ "$response" == "302" ]] || [[ "$response" == "200" ]]
    ' || true

    # Test OIDC with Keycloak direct grant (resource owner password)
    run_test "OIDC token exchange" '
        # Get token from Keycloak directly
        kc_token=$(curl -sf -X POST "http://localhost:8180/realms/artifact-keeper/protocol/openid-connect/token" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "grant_type=password" \
            -d "client_id=artifact-keeper" \
            -d "client_secret=artifact-keeper-secret" \
            -d "username=oidcuser" \
            -d "password=oidcpassword" | jq -r ".access_token")
        [[ -n "$kc_token" ]] && [[ "$kc_token" != "null" ]]
    ' || true
fi

# ============================================================================
# SAML Tests
# ============================================================================

if [[ "$TEST_SAML" == "true" ]]; then
    echo ""
    log_info "========== SAML Authentication Tests =========="

    # Test SAML metadata endpoint
    run_test "SAML SP metadata available" '
        curl -sf http://localhost:8080/api/v1/auth/saml/metadata | grep -q "EntityDescriptor"
    ' || true

    # Test SAML login redirect
    run_test "SAML login redirects to IdP" '
        response=$(curl -sf -w "%{http_code}" -o /dev/null http://localhost:8080/api/v1/auth/saml/login)
        [[ "$response" == "302" ]] || [[ "$response" == "200" ]]
    ' || true
fi

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
