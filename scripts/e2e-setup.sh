#!/bin/sh
# Bootstrap script for E2E tests: creates admin token and test repositories
set -e

apk add --no-cache curl jq >/dev/null 2>&1

echo "==> Logging in as admin..."
TOKEN=$(curl -sf -X POST http://backend:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}' | jq -r '.access_token')

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
  "test-docker:Test Docker:docker"
do
  KEY=$(echo "$format" | cut -d: -f1)
  NAME=$(echo "$format" | cut -d: -f2)
  FMT=$(echo "$format" | cut -d: -f3)
  curl -sf -X POST http://backend:8080/api/v1/repositories \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"key\":\"$KEY\",\"name\":\"$NAME\",\"format\":\"$FMT\",\"repo_type\":\"local\",\"is_public\":true}" \
    >/dev/null 2>&1 || true
  echo "  - $KEY ($FMT)"
done

echo "==> Setup complete"
touch /tmp/.setup-done
tail -f /dev/null
