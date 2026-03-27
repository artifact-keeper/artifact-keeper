#!/bin/sh
# Bootstrap script for E2E tests: creates admin token and test repositories
#
# Works in both Docker containers (docker-compose.test.yml) and on self-hosted
# CI runners (ARC pods). Uses REGISTRY_URL env var with Docker-default fallback.
#
# Environment:
#   REGISTRY_URL  - Backend URL (default: http://backend:8080)
#   ADMIN_USER    - Admin username (default: admin)
#   ADMIN_PASS    - Admin password (default: admin123)
set -e

REGISTRY_URL="${REGISTRY_URL:-http://backend:8080}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin123}"

# Install deps only if missing (Alpine in Docker vs Ubuntu on ARC runners)
if ! command -v curl >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
  apk add --no-cache curl jq >/dev/null 2>&1 || sudo apt-get install -y -qq curl jq >/dev/null 2>&1 || true
fi

echo "==> Logging in as $ADMIN_USER at $REGISTRY_URL..."
TOKEN=$(curl -sf -X POST "$REGISTRY_URL/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" | jq -r '.access_token')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
  echo "ERROR: Authentication failed"
  exit 1
fi

echo "==> Creating test repositories..."
for format in \
  "test-pypi:Test PyPI:pypi" \
  "test-npm:Test NPM:npm" \
  "test-cargo:Test Cargo:cargo" \
  "test-maven:Test Maven:maven" \
  "test-go:Test Go:go" \
  "test-rpm:Test RPM:rpm" \
  "test-deb:Test Debian:debian" \
  "test-helm:Test Helm:helm" \
  "test-conda:Test Conda:conda" \
  "test-docker:Test Docker:docker" \
  "test-protobuf:Test Protobuf:protobuf" \
  "test-hex:Test Hex:hex"
do
  KEY=$(echo "$format" | cut -d: -f1)
  NAME=$(echo "$format" | cut -d: -f2)
  FMT=$(echo "$format" | cut -d: -f3)
  curl -sf -X POST "$REGISTRY_URL/api/v1/repositories" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"key\":\"$KEY\",\"name\":\"$NAME\",\"format\":\"$FMT\",\"repo_type\":\"local\",\"is_public\":true}" \
    >/dev/null 2>&1 || true
  echo "  - $KEY ($FMT)"
done

echo "==> Creating remote (proxy) repositories..."
for remote in \
  "npm-proxy:NPM Proxy:npm:https://registry.npmjs.org" \
  "pypi-proxy:PyPI Proxy:pypi:https://pypi.org" \
  "maven-proxy:Maven Proxy:maven:https://repo1.maven.org/maven2" \
  "hex-proxy:Hex Proxy:hex:https://repo.hex.pm" \
  "dockerhub-proxy:Docker Hub Proxy:docker:https://registry-1.docker.io" \
  "ghcr-proxy:GHCR Proxy:docker:https://ghcr.io"
do
  KEY=$(echo "$remote" | cut -d: -f1)
  NAME=$(echo "$remote" | cut -d: -f2)
  FMT=$(echo "$remote" | cut -d: -f3)
  URL=$(echo "$remote" | cut -d: -f4-) # handles : in URLs
  curl -sf -X POST "$REGISTRY_URL/api/v1/repositories" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"key\":\"$KEY\",\"name\":\"$NAME\",\"format\":\"$FMT\",\"repo_type\":\"remote\",\"upstream_url\":\"$URL\",\"is_public\":true}" \
    >/dev/null 2>&1 || true
  echo "  - $KEY ($FMT remote -> $URL)"
done

echo "==> Creating local repos for virtual members..."
for local in \
  "npm-local-e2e:NPM Local E2E:npm" \
  "pypi-local-e2e:PyPI Local E2E:pypi" \
  "hex-local-e2e:Hex Local E2E:hex"
do
  KEY=$(echo "$local" | cut -d: -f1)
  NAME=$(echo "$local" | cut -d: -f2)
  FMT=$(echo "$local" | cut -d: -f3)
  curl -sf -X POST "$REGISTRY_URL/api/v1/repositories" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"key\":\"$KEY\",\"name\":\"$NAME\",\"format\":\"$FMT\",\"repo_type\":\"local\",\"is_public\":true}" \
    >/dev/null 2>&1 || true
  echo "  - $KEY ($FMT local)"
done

echo "==> Creating virtual repositories..."
for virtual in \
  "npm-virtual:NPM Virtual:npm" \
  "pypi-virtual:PyPI Virtual:pypi" \
  "hex-virtual:Hex Virtual:hex"
do
  KEY=$(echo "$virtual" | cut -d: -f1)
  NAME=$(echo "$virtual" | cut -d: -f2)
  FMT=$(echo "$virtual" | cut -d: -f3)
  curl -sf -X POST "$REGISTRY_URL/api/v1/repositories" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"key\":\"$KEY\",\"name\":\"$NAME\",\"format\":\"$FMT\",\"repo_type\":\"virtual\",\"is_public\":true}" \
    >/dev/null 2>&1 || true
  echo "  - $KEY ($FMT virtual)"
done

echo "==> Wiring virtual repository members..."
for member in \
  "npm-virtual:npm-local-e2e:1" \
  "npm-virtual:npm-proxy:2" \
  "pypi-virtual:pypi-local-e2e:1" \
  "pypi-virtual:pypi-proxy:2" \
  "hex-virtual:hex-local-e2e:1" \
  "hex-virtual:hex-proxy:2"
do
  VKEY=$(echo "$member" | cut -d: -f1)
  MKEY=$(echo "$member" | cut -d: -f2)
  PRI=$(echo "$member" | cut -d: -f3)
  curl -sf -X POST "$REGISTRY_URL/api/v1/repositories/$VKEY/members" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"member_key\":\"$MKEY\",\"priority\":$PRI}" \
    >/dev/null 2>&1 || true
  echo "  - $VKEY <- $MKEY (priority=$PRI)"
done

echo "==> Setup complete"

# In Docker container mode, signal healthcheck and keep alive
if [ -f /.dockerenv ] || [ -n "$DOCKER_CONTAINER" ]; then
  touch /tmp/.setup-done
  tail -f /dev/null
fi
