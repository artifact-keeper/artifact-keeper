#!/usr/bin/env bash
set -euo pipefail

# Setup SSO providers in Artifact Keeper backend
# This creates LDAP, OIDC, and SAML configs pointing to test IdPs

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BACKEND_URL="http://localhost:8080"
ADMIN_USER="admin"
ADMIN_PASSWORD="admin123"

echo "Configuring SSO providers in Artifact Keeper backend..."

# Get admin token
echo "Logging in as admin..."
LOGIN_RESPONSE=$(curl -s -X POST "${BACKEND_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"${ADMIN_USER}\", \"password\": \"${ADMIN_PASSWORD}\"}")

ADMIN_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.access_token')

if [[ -z "$ADMIN_TOKEN" ]] || [[ "$ADMIN_TOKEN" == "null" ]]; then
    echo "Failed to login as admin"
    echo "Response: $LOGIN_RESPONSE"
    exit 1
fi
echo "Admin login successful"

AUTH_HEADER="Authorization: Bearer ${ADMIN_TOKEN}"

# ---------------------------------------------------------------------------
# Create LDAP config
# ---------------------------------------------------------------------------
echo ""
echo "Creating LDAP configuration..."

LDAP_CONFIG=$(cat <<EOF
{
    "name": "Test OpenLDAP",
    "server_url": "ldap://openldap:389",
    "bind_dn": "cn=admin,dc=test,dc=local",
    "bind_password": "adminpassword",
    "user_base_dn": "ou=people,dc=test,dc=local",
    "user_filter": "(uid={username})",
    "group_base_dn": "ou=groups,dc=test,dc=local",
    "group_filter": "(memberUid={username})",
    "email_attribute": "mail",
    "display_name_attribute": "cn",
    "username_attribute": "uid",
    "groups_attribute": "cn",
    "admin_group_dn": "cn=admins,ou=groups,dc=test,dc=local",
    "use_starttls": false,
    "is_enabled": true,
    "priority": 1
}
EOF
)

LDAP_RESPONSE=$(curl -s -X POST "${BACKEND_URL}/api/v1/admin/sso/ldap" \
    -H "$AUTH_HEADER" \
    -H "Content-Type: application/json" \
    -d "$LDAP_CONFIG")

LDAP_ID=$(echo "$LDAP_RESPONSE" | jq -r '.id')

if [[ -z "$LDAP_ID" ]] || [[ "$LDAP_ID" == "null" ]]; then
    echo "Failed to create LDAP config"
    echo "Response: $LDAP_RESPONSE"
else
    echo "LDAP config created: $LDAP_ID"
fi

# ---------------------------------------------------------------------------
# Create OIDC config
# ---------------------------------------------------------------------------
echo ""
echo "Creating OIDC configuration..."

OIDC_CONFIG=$(cat <<EOF
{
    "name": "Test Keycloak OIDC",
    "issuer_url": "http://keycloak:8080/realms/artifact-keeper",
    "client_id": "artifact-keeper",
    "client_secret": "artifact-keeper-secret",
    "scopes": ["openid", "email", "profile"],
    "attribute_mapping": {
        "email": "email",
        "name": "name",
        "username": "preferred_username"
    },
    "is_enabled": true,
    "auto_create_users": true
}
EOF
)

OIDC_RESPONSE=$(curl -s -X POST "${BACKEND_URL}/api/v1/admin/sso/oidc" \
    -H "$AUTH_HEADER" \
    -H "Content-Type: application/json" \
    -d "$OIDC_CONFIG")

OIDC_ID=$(echo "$OIDC_RESPONSE" | jq -r '.id')

if [[ -z "$OIDC_ID" ]] || [[ "$OIDC_ID" == "null" ]]; then
    echo "Failed to create OIDC config"
    echo "Response: $OIDC_RESPONSE"
else
    echo "OIDC config created: $OIDC_ID"
fi

# ---------------------------------------------------------------------------
# Create SAML config
# ---------------------------------------------------------------------------
echo ""
echo "Creating SAML configuration..."

# Get Keycloak SAML certificate
echo "Fetching Keycloak SAML metadata..."
SAML_METADATA=$(curl -s "http://localhost:8180/realms/artifact-keeper/protocol/saml/descriptor")

# Extract certificate from metadata (between <ds:X509Certificate> tags)
SAML_CERT=$(echo "$SAML_METADATA" | grep -oP '(?<=<ds:X509Certificate>)[^<]+' | head -1 || echo "")

if [[ -z "$SAML_CERT" ]]; then
    echo "Warning: Could not extract SAML certificate from metadata"
    # Use a placeholder - the test might fail but we'll see the error
    SAML_CERT="MIICmzCCAYMCBgGN..."
fi

SAML_CONFIG=$(cat <<EOF
{
    "name": "Test Keycloak SAML",
    "entity_id": "http://keycloak:8080/realms/artifact-keeper",
    "sso_url": "http://keycloak:8080/realms/artifact-keeper/protocol/saml",
    "slo_url": "http://keycloak:8080/realms/artifact-keeper/protocol/saml",
    "certificate": "${SAML_CERT}",
    "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
    "attribute_mapping": {
        "email": "email",
        "name": "name",
        "username": "username"
    },
    "sp_entity_id": "artifact-keeper-sp",
    "sign_requests": false,
    "require_signed_assertions": false,
    "is_enabled": true
}
EOF
)

SAML_RESPONSE=$(curl -s -X POST "${BACKEND_URL}/api/v1/admin/sso/saml" \
    -H "$AUTH_HEADER" \
    -H "Content-Type: application/json" \
    -d "$SAML_CONFIG")

SAML_ID=$(echo "$SAML_RESPONSE" | jq -r '.id')

if [[ -z "$SAML_ID" ]] || [[ "$SAML_ID" == "null" ]]; then
    echo "Failed to create SAML config"
    echo "Response: $SAML_RESPONSE"
else
    echo "SAML config created: $SAML_ID"
fi

# ---------------------------------------------------------------------------
# Write config IDs to file for test script
# ---------------------------------------------------------------------------
echo ""
echo "Writing config IDs to sso-config-ids.env..."

cat > "${SCRIPT_DIR}/sso-config-ids.env" <<EOF
# SSO Config IDs (generated by setup-backend-sso.sh)
LDAP_CONFIG_ID=${LDAP_ID}
OIDC_CONFIG_ID=${OIDC_ID}
SAML_CONFIG_ID=${SAML_ID}
EOF

echo ""
echo "=========================================="
echo "SSO Backend Setup Complete!"
echo "=========================================="
echo ""
echo "Config IDs:"
echo "  LDAP: ${LDAP_ID}"
echo "  OIDC: ${OIDC_ID}"
echo "  SAML: ${SAML_ID}"
echo ""
echo "Test endpoints:"
echo "  LDAP Login:  POST ${BACKEND_URL}/api/v1/auth/sso/ldap/${LDAP_ID}/login"
echo "  OIDC Login:  GET  ${BACKEND_URL}/api/v1/auth/sso/oidc/${OIDC_ID}/login"
echo "  SAML Login:  GET  ${BACKEND_URL}/api/v1/auth/sso/saml/${SAML_ID}/login"
