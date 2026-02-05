# SSO E2E Tests

End-to-end tests for LDAP, OIDC, and SAML authentication flows against real identity providers.

## Prerequisites

- Docker and Docker Compose
- `curl` and `jq`

## Quick Start

```bash
# Run all SSO tests
./run.sh

# Run with cleanup after
./run.sh --clean

# Run specific auth type only
./run.sh --ldap-only
./run.sh --oidc-only
./run.sh --saml-only
```

## Test Environment

The test environment spins up:

| Service | Port | Description |
|---------|------|-------------|
| OpenLDAP | 3389 | LDAP authentication |
| Keycloak | 8180 | OIDC and SAML IdP |
| PostgreSQL | 5433 | Backend database |
| Backend | 8080 | Artifact Keeper API |

## Test Users

### LDAP Users
- `testuser` / `testpassword` (member of: developers)
- `adminuser` / `adminpassword` (member of: admins)

### Keycloak Users (OIDC/SAML)
- `oidcuser` / `oidcpassword`
- `samluser` / `samlpassword`

## Manual Testing

```bash
# Start environment without running tests
docker compose up -d
./setup-ldap.sh
./setup-keycloak.sh

# Test LDAP login manually
curl -X POST http://localhost:8080/api/v1/auth/ldap/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "testpassword"}'

# Get Keycloak token directly
curl -X POST "http://localhost:8180/realms/artifact-keeper/protocol/openid-connect/token" \
  -d "grant_type=password" \
  -d "client_id=artifact-keeper" \
  -d "client_secret=artifact-keeper-secret" \
  -d "username=oidcuser" \
  -d "password=oidcpassword"

# Cleanup
docker compose down -v
```

## Keycloak Admin Console

Access Keycloak admin at http://localhost:8180 with `admin` / `admin`.

## Troubleshooting

### LDAP connection issues
```bash
# Test LDAP directly
docker compose exec openldap ldapsearch -x -H ldap://localhost \
  -b "dc=test,dc=local" -D "cn=admin,dc=test,dc=local" -w adminpassword
```

### Keycloak not ready
Keycloak can take 30-60 seconds to start. Check health:
```bash
curl http://localhost:8180/health/ready
```
