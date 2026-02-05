#!/usr/bin/env bash
set -euo pipefail

# Setup Keycloak realm, clients, and users for OIDC/SAML testing

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

KEYCLOAK_URL="http://localhost:8180"
ADMIN_USER="admin"
ADMIN_PASSWORD="admin"
REALM="artifact-keeper"

echo "Configuring Keycloak for SSO testing..."

# Get admin token
echo "Getting admin access token..."
ADMIN_TOKEN=$(curl -s "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
    --data-urlencode "username=${ADMIN_USER}" \
    --data-urlencode "password=${ADMIN_PASSWORD}" \
    --data-urlencode "grant_type=password" \
    --data-urlencode "client_id=admin-cli" | jq -r '.access_token')

if [[ -z "$ADMIN_TOKEN" ]] || [[ "$ADMIN_TOKEN" == "null" ]]; then
    echo "Failed to get admin token"
    exit 1
fi

AUTH_HEADER="Authorization: Bearer ${ADMIN_TOKEN}"

# Check if realm exists
REALM_EXISTS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "$AUTH_HEADER" \
    "${KEYCLOAK_URL}/admin/realms/${REALM}")

if [[ "$REALM_EXISTS" == "200" ]]; then
    echo "Realm '${REALM}' already exists, skipping creation..."
else
    echo "Creating realm '${REALM}'..."
    curl -sf -X POST "${KEYCLOAK_URL}/admin/realms" \
        -H "$AUTH_HEADER" \
        -H "Content-Type: application/json" \
        -d "{
            \"realm\": \"${REALM}\",
            \"enabled\": true,
            \"registrationAllowed\": false,
            \"loginWithEmailAllowed\": true,
            \"duplicateEmailsAllowed\": false,
            \"resetPasswordAllowed\": true,
            \"editUsernameAllowed\": false,
            \"bruteForceProtected\": true
        }"
fi

# Create OIDC client
echo "Creating OIDC client..."
curl -sf -X POST "${KEYCLOAK_URL}/admin/realms/${REALM}/clients" \
    -H "$AUTH_HEADER" \
    -H "Content-Type: application/json" \
    -d '{
        "clientId": "artifact-keeper",
        "name": "Artifact Keeper",
        "enabled": true,
        "clientAuthenticatorType": "client-secret",
        "secret": "artifact-keeper-secret",
        "redirectUris": [
            "http://localhost:8080/api/v1/auth/oidc/callback",
            "http://localhost:3000/api/v1/auth/oidc/callback"
        ],
        "webOrigins": ["http://localhost:8080", "http://localhost:3000"],
        "publicClient": false,
        "protocol": "openid-connect",
        "standardFlowEnabled": true,
        "directAccessGrantsEnabled": true,
        "serviceAccountsEnabled": false,
        "attributes": {
            "pkce.code.challenge.method": "S256"
        }
    }' 2>/dev/null || echo "  (client may already exist)"

# Create SAML client
echo "Creating SAML client..."
curl -sf -X POST "${KEYCLOAK_URL}/admin/realms/${REALM}/clients" \
    -H "$AUTH_HEADER" \
    -H "Content-Type: application/json" \
    -d '{
        "clientId": "artifact-keeper-saml",
        "name": "Artifact Keeper SAML",
        "enabled": true,
        "protocol": "saml",
        "frontchannelLogout": true,
        "attributes": {
            "saml.assertion.signature": "true",
            "saml.force.post.binding": "true",
            "saml.multivalued.roles": "false",
            "saml.encrypt": "false",
            "saml.server.signature": "true",
            "saml.server.signature.keyinfo.ext": "false",
            "saml.signature.algorithm": "RSA_SHA256",
            "saml.client.signature": "false",
            "saml_force_name_id_format": "false",
            "saml_name_id_format": "username",
            "saml_signature_canonicalization_method": "http://www.w3.org/2001/10/xml-exc-c14n#"
        },
        "redirectUris": [
            "http://localhost:8080/api/v1/auth/saml/acs"
        ],
        "adminUrl": "http://localhost:8080/api/v1/auth/saml"
    }' 2>/dev/null || echo "  (client may already exist)"

# Create test users
echo "Creating test users..."

# OIDC test user
curl -sf -X POST "${KEYCLOAK_URL}/admin/realms/${REALM}/users" \
    -H "$AUTH_HEADER" \
    -H "Content-Type: application/json" \
    -d '{
        "username": "oidcuser",
        "email": "oidcuser@test.local",
        "firstName": "OIDC",
        "lastName": "User",
        "enabled": true,
        "emailVerified": true,
        "credentials": [{
            "type": "password",
            "value": "oidcpassword",
            "temporary": false
        }]
    }' 2>/dev/null || echo "  (user may already exist)"

# SAML test user
curl -sf -X POST "${KEYCLOAK_URL}/admin/realms/${REALM}/users" \
    -H "$AUTH_HEADER" \
    -H "Content-Type: application/json" \
    -d '{
        "username": "samluser",
        "email": "samluser@test.local",
        "firstName": "SAML",
        "lastName": "User",
        "enabled": true,
        "emailVerified": true,
        "credentials": [{
            "type": "password",
            "value": "samlpassword",
            "temporary": false
        }]
    }' 2>/dev/null || echo "  (user may already exist)"

echo ""
echo "Keycloak setup complete!"
echo ""
echo "OIDC Configuration:"
echo "  Issuer: ${KEYCLOAK_URL}/realms/${REALM}"
echo "  Client ID: artifact-keeper"
echo "  Client Secret: artifact-keeper-secret"
echo ""
echo "SAML Configuration:"
echo "  IdP Metadata: ${KEYCLOAK_URL}/realms/${REALM}/protocol/saml/descriptor"
echo "  Client ID: artifact-keeper-saml"
echo ""
echo "Test users:"
echo "  - oidcuser / oidcpassword"
echo "  - samluser / samlpassword"
