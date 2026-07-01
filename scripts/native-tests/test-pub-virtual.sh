#!/bin/bash
# Pub virtual repo E2E test
# Tests that a virtual repo aggregates a local repo via Dart CLI
set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:8080}"
LOCAL_REPO_KEY="${LOCAL_REPO_KEY:-pub-local}"
VIRTUAL_REPO_KEY="${VIRTUAL_REPO_KEY:-pub-virtual}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-TestRunner!2026secure}"
PKG_NAME="test_e2e_dart_pkg"
PKG_VERSION="1.0.$(date +%s)"

echo "==> Pub Virtual Repo E2E Test"
echo "Registry: $REGISTRY_URL"
echo "Local:    $LOCAL_REPO_KEY"
echo "Virtual:  $VIRTUAL_REPO_KEY"
echo "Package:  $PKG_NAME@$PKG_VERSION"
echo ""

# ---- Step 1: Create local repo ----
echo "==> [1/5] Creating local repo..."

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -u "$ADMIN_USER:$ADMIN_PASS" \
  "$REGISTRY_URL/api/v1/repositories/$LOCAL_REPO_KEY")

if [ "$HTTP_CODE" = "404" ]; then
  CREATE_RESP=$(curl -s -w "\n%{http_code}" \
    -u "$ADMIN_USER:$ADMIN_PASS" \
    -X POST "$REGISTRY_URL/api/v1/repositories" \
    -H "Content-Type: application/json" \
    -d "{
      \"key\": \"$LOCAL_REPO_KEY\",
      \"name\": \"Pub Local\",
      \"format\": \"pub\",
      \"repo_type\": \"local\"
    }")
  CREATE_STATUS=$(echo "$CREATE_RESP" | tail -1)
  echo "  Create response ($CREATE_STATUS)"
  if [ "$CREATE_STATUS" -ge 300 ]; then
    echo "❌ Failed to create local repository"
    exit 1
  fi
elif [ "$HTTP_CODE" = "200" ]; then
  echo "  Repository already exists"
else
  echo "  ⚠️  Unexpected status: $HTTP_CODE"
fi

# ---- Step 2: Create virtual repo ----
echo ""
echo "==> [2/5] Creating virtual repo..."

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -u "$ADMIN_USER:$ADMIN_PASS" \
  "$REGISTRY_URL/api/v1/repositories/$VIRTUAL_REPO_KEY")

if [ "$HTTP_CODE" = "404" ]; then
  CREATE_RESP=$(curl -s -w "\n%{http_code}" \
    -u "$ADMIN_USER:$ADMIN_PASS" \
    -X POST "$REGISTRY_URL/api/v1/repositories" \
    -H "Content-Type: application/json" \
    -d "{
      \"key\": \"$VIRTUAL_REPO_KEY\",
      \"name\": \"Pub Virtual\",
      \"format\": \"pub\",
      \"repo_type\": \"virtual\",
      \"is_public\": true,
      \"member_repos\": [
        {\"repo_key\": \"$LOCAL_REPO_KEY\", \"priority\": 1}
      ]
    }")
  CREATE_STATUS=$(echo "$CREATE_RESP" | tail -1)
  echo "  Create response ($CREATE_STATUS)"
  if [ "$CREATE_STATUS" -ge 300 ]; then
    echo "❌ Failed to create virtual repository"
    exit 1
  fi
elif [ "$HTTP_CODE" = "200" ]; then
  echo "  Repository already exists"
else
  echo "  ⚠️  Unexpected status: $HTTP_CODE"
fi

# ---- Step 3: Publish test package to local repo ----
echo ""
echo "==> [3/5] Publishing test package to local repo..."

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

PKG_DIR="$WORK_DIR/$PKG_NAME"
mkdir -p "$PKG_DIR/lib"

cat > "$PKG_DIR/pubspec.yaml" << EOF
name: $PKG_NAME
version: $PKG_VERSION
description: Test package for virtual repo E2E
environment:
  sdk: ">=2.12.0 <4.0.0"
EOF

cat > "$PKG_DIR/lib/$PKG_NAME.dart" << EOF
String hello() => 'Hello from $PKG_NAME!';
EOF

ARCHIVE="$WORK_DIR/${PKG_NAME}-${PKG_VERSION}.tar.gz"
(cd "$PKG_DIR" && tar czf "$ARCHIVE" pubspec.yaml lib/)

# Get upload URL
STEP1_RESP=$(curl -s -w "\n---HTTP_STATUS:%{http_code}---" \
  -u "$ADMIN_USER:$ADMIN_PASS" \
  -H "Accept: application/vnd.pub.v2+json" \
  -X GET \
  "$REGISTRY_URL/pub/$LOCAL_REPO_KEY/api/packages/versions/new")

STEP1_STATUS=$(echo "$STEP1_RESP" | grep -o 'HTTP_STATUS:[0-9]*' | cut -d: -f2)
STEP1_BODY=$(echo "$STEP1_RESP" | sed '/^---HTTP_STATUS:/d')

if [ "$STEP1_STATUS" != "200" ]; then
  echo "❌ Step 1 failed: $STEP1_STATUS"
  echo "   $STEP1_BODY"
  exit 1
fi

UPLOAD_URL=$(echo "$STEP1_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin)['url'])" 2>/dev/null)
echo "  Upload URL: $UPLOAD_URL"

# Upload
STEP2_RESP=$(curl -s -w "\n---HTTP_STATUS:%{http_code}---" \
  -D - \
  -u "$ADMIN_USER:$ADMIN_PASS" \
  -X POST \
  -H "Content-Type: multipart/form-data" \
  -F "file=@$ARCHIVE" \
  "$UPLOAD_URL" 2>&1)

STEP2_STATUS=$(echo "$STEP2_RESP" | grep -o 'HTTP_STATUS:[0-9]*' | cut -d: -f2)
STEP2_LOCATION=$(echo "$STEP2_RESP" | grep -i "^location:" | tr -d '\r' | sed 's/^location: *//i')

if [ "$STEP2_STATUS" != "204" ] && [ "$STEP2_STATUS" != "200" ]; then
  echo "❌ Upload failed: $STEP2_STATUS"
  exit 1
fi
echo "  Upload: $STEP2_STATUS"

# Finalize
if [ -n "$STEP2_LOCATION" ]; then
  if ! echo "$STEP2_LOCATION" | grep -q "^http"; then
    STEP2_LOCATION="$REGISTRY_URL$STEP2_LOCATION"
  fi
  FINALIZE_RESP=$(curl -s -w "\n---HTTP_STATUS:%{http_code}---" \
    -u "$ADMIN_USER:$ADMIN_PASS" \
    -H "Accept: application/vnd.pub.v2+json" \
    "$STEP2_LOCATION")
  FINALIZE_STATUS=$(echo "$FINALIZE_RESP" | grep -o 'HTTP_STATUS:[0-9]*' | cut -d: -f2)
  echo "  Finalize: $FINALIZE_STATUS"
fi

# ---- Step 4: dart pub get through virtual repo ----
echo ""
echo "==> [4/5] Testing dart pub get through virtual repo..."

HOST_IP=$(ipconfig getifaddr en0 2>/dev/null || echo "host.docker.internal")

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

# Create consumer project
CONSUMER_DIR="$WORK_DIR/consumer"
mkdir -p "$CONSUMER_DIR/lib"
cat > "$CONSUMER_DIR/pubspec.yaml" << EOF
name: test_virtual_consumer
environment:
  sdk: ">=2.15.0 <4.0.0"
dependencies:
  $PKG_NAME:
    hosted: https://$HOST_IP:9443/pub/$VIRTUAL_REPO_KEY
    version: $PKG_VERSION
EOF
cat > "$CONSUMER_DIR/lib/consumer.dart" << EOF
import 'package:$PKG_NAME/$PKG_NAME.dart';
String use() => hello();
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
    printf '%s\n' '$(echo -n "$ADMIN_USER:$ADMIN_PASS" | base64)' | dart pub token add 'https://$HOST_IP:9443/pub/$VIRTUAL_REPO_KEY/'
    dart pub get 2>&1
  "
DART_EXIT=$?

docker stop "$NGINX_CID" >/dev/null 2>&1 || true

# ---- Step 5: Verify virtual rejects publish ----
echo ""
echo "==> [5/5] Verifying virtual rejects publish..."

PUBLISH_RESP=$(curl -s -w "\n---HTTP_STATUS:%{http_code}---" \
  -u "$ADMIN_USER:$ADMIN_PASS" \
  -X POST \
  -H "Content-Type: multipart/form-data" \
  -F "file=@/dev/null" \
  "$REGISTRY_URL/pub/$VIRTUAL_REPO_KEY/api/packages/versions/newUpload")

PUBLISH_STATUS=$(echo "$PUBLISH_RESP" | grep -o 'HTTP_STATUS:[0-9]*' | cut -d: -f2)
echo "  Status: $PUBLISH_STATUS"

if [ "$PUBLISH_STATUS" = "405" ]; then
  echo "  ✅ Virtual correctly rejects publish (405)"
else
  echo "  ⚠️  Expected 405, got $PUBLISH_STATUS"
fi

# ---- Summary ----
echo ""
echo "=============================================="
echo "VIRTUAL TEST SUMMARY"
echo "=============================================="
echo "Local repo:     $LOCAL_REPO_KEY"
echo "Virtual repo:   $VIRTUAL_REPO_KEY"
echo "dart pub get:    $DART_EXIT"
echo ""

if [ "$DART_EXIT" -eq 0 ]; then
  echo "✅ Pub virtual E2E test PASSED"
else
  echo "❌ Pub virtual E2E test FAILED (exit code: $DART_EXIT)"
fi
