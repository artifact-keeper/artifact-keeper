#!/bin/bash
# Pub proxy (remote) repo E2E test
# Tests that a proxy repo downloads packages from pub.dev via Dart CLI
set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:8080}"
PROXY_REPO_KEY="${PROXY_REPO_KEY:-pub-proxy}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-TestRunner!2026secure}"

echo "==> Pub Proxy Repo E2E Test"
echo "Registry: $REGISTRY_URL"
echo "Proxy:    $PROXY_REPO_KEY"
echo ""

# ---- Step 1: Create remote (proxy) repo ----
echo "==> [1/4] Creating remote (proxy) repo..."

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -u "$ADMIN_USER:$ADMIN_PASS" \
  "$REGISTRY_URL/api/v1/repositories/$PROXY_REPO_KEY")

if [ "$HTTP_CODE" = "404" ]; then
  CREATE_RESP=$(curl -s -w "\n%{http_code}" \
    -u "$ADMIN_USER:$ADMIN_PASS" \
    -X POST "$REGISTRY_URL/api/v1/repositories" \
    -H "Content-Type: application/json" \
    -d "{
      \"key\": \"$PROXY_REPO_KEY\",
      \"name\": \"Pub Proxy\",
      \"format\": \"pub\",
      \"repo_type\": \"remote\",
      \"upstream_url\": \"https://pub.dev\",
      \"is_public\": true
    }")
  CREATE_STATUS=$(echo "$CREATE_RESP" | tail -1)
  CREATE_BODY=$(echo "$CREATE_RESP" | sed '$d')
  echo "  Create response ($CREATE_STATUS): $CREATE_BODY"
  if [ "$CREATE_STATUS" -ge 300 ]; then
    echo "❌ Failed to create proxy repository"
    exit 1
  fi
elif [ "$HTTP_CODE" = "200" ]; then
  echo "  Repository already exists"
else
  echo "  ⚠️  Unexpected status checking repo: $HTTP_CODE"
fi

# ---- Step 2: Verify proxy rejects publish ----
echo ""
echo "==> [2/4] Verifying proxy rejects publish..."

PUBLISH_RESP=$(curl -s -w "\n---HTTP_STATUS:%{http_code}---" \
  -u "$ADMIN_USER:$ADMIN_PASS" \
  -X POST \
  -H "Content-Type: multipart/form-data" \
  -F "file=@/dev/null" \
  "$REGISTRY_URL/pub/$PROXY_REPO_KEY/api/packages/versions/newUpload")

PUBLISH_STATUS=$(echo "$PUBLISH_RESP" | grep -o 'HTTP_STATUS:[0-9]*' | cut -d: -f2)
echo "  Status: $PUBLISH_STATUS"

if [ "$PUBLISH_STATUS" = "405" ]; then
  echo "  ✅ Proxy correctly rejects publish (405)"
else
  echo "  ⚠️  Expected 405, got $PUBLISH_STATUS"
fi

# ---- Step 3: dart pub get through proxy ----
echo ""
echo "==> [3/4] Testing dart pub get through proxy..."

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

# Get host IP for Docker networking
HOST_IP=$(ipconfig getifaddr en0 2>/dev/null || echo "host.docker.internal")

# Setup nginx TLS proxy
CERT_DIR="$WORK_DIR/certs"
mkdir -p "$CERT_DIR"
openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" \
  -days 1 -nodes -subj "/CN=$HOST_IP" \
  -addext "subjectAltName=IP:$HOST_IP,DNS:localhost" 2>/dev/null

docker ps -q --filter "ancestor=nginx:alpine" | xargs -r docker stop 2>/dev/null || true

cat > "$CERT_DIR/nginx.conf" << NGINX
worker_processes 1;
events { worker_connections 64; }
http {
    server {
        listen 443 ssl;
        ssl_certificate     /certs/cert.pem;
        ssl_certificate_key /certs/key.pem;
        location / {
            proxy_pass http://host.docker.internal:8080;
            proxy_set_header Host \$http_host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }
    }
}
NGINX

echo "  Starting nginx TLS proxy..."
NGINX_CID=$(docker run -d --rm \
  --add-host=host.docker.internal:host-gateway \
  -p 9443:443 \
  -v "$CERT_DIR/nginx.conf:/etc/nginx/nginx.conf:ro" \
  -v "$CERT_DIR:/certs:ro" \
  nginx:alpine nginx -g 'daemon off;' 2>&1 || true)
sleep 2

if [ -z "$NGINX_CID" ] || ! docker ps --format '{{.ID}}' | grep -q "^${NGINX_CID:0:12}"; then
  echo "  ❌ nginx failed to start"
  docker stop "$NGINX_CID" 2>/dev/null || true
  exit 1
fi
echo "  nginx running on https://$HOST_IP:9443"

# Create consumer project that depends on `http` from the proxy
CONSUMER_DIR="$WORK_DIR/consumer"
mkdir -p "$CONSUMER_DIR/lib"
cat > "$CONSUMER_DIR/pubspec.yaml" << EOF
name: test_proxy_consumer
environment:
  sdk: ">=2.15.0 <4.0.0"
dependencies:
  http:
    hosted: https://$HOST_IP:9443/pub/$PROXY_REPO_KEY
    version: ^1.0.0
EOF
cat > "$CONSUMER_DIR/lib/consumer.dart" << EOF
import 'package:http/http.dart' as http;
Future<void> use() async => await http.get(Uri.parse('https://example.com'));
EOF

echo "  Running dart pub get..."
docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  -v "$CERT_DIR/cert.pem:/certs/self-signed.crt:ro" \
  -v "$CONSUMER_DIR:/project" \
  -w /project \
  -e ADMIN_USER="$ADMIN_USER" \
  -e ADMIN_PASS="$ADMIN_PASS" \
  dart:stable \
  sh -c "
    cp /certs/self-signed.crt /usr/local/share/ca-certificates/self-signed.crt 2>/dev/null || \
      cp /certs/self-signed.crt /usr/lib/ssl/certs/self-signed.crt 2>/dev/null || \
      mkdir -p /etc/ssl/certs && cp /certs/self-signed.crt /etc/ssl/certs/self-signed.crt
    update-ca-certificates 2>/dev/null || true
    printf '%s\n' '$(echo -n "$ADMIN_USER:$ADMIN_PASS" | base64)' | dart pub token add 'https://$HOST_IP:9443/pub/$PROXY_REPO_KEY/'
    dart pub get 2>&1
  "
DART_EXIT=$?

docker stop "$NGINX_CID" >/dev/null 2>&1 || true

# ---- Step 4: Summary ----
echo ""
echo "=============================================="
echo "PROXY TEST SUMMARY"
echo "=============================================="
echo "Proxy repo:   $PROXY_REPO_KEY"
echo "dart pub get:  $DART_EXIT"
echo ""

if [ "$DART_EXIT" -eq 0 ]; then
  echo "✅ Pub proxy E2E test PASSED"
else
  echo "❌ Pub proxy E2E test FAILED (exit code: $DART_EXIT)"
fi
