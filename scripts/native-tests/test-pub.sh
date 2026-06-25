#!/bin/bash
# Dart Pub native client test script
# Tests the pub.dev Repository Spec v2 upload protocol
# This is a DIAGNOSTIC test: it logs full responses to confirm the problem.
set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:30080}"
PUB_REPO_KEY="${PUB_REPO_KEY:-test-dart-pub}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-TestRunner!2026secure}"
PKG_NAME="test_e2e_dart_pkg"
PKG_VERSION="1.0.$(date +%s)"

echo "==> Dart Pub Native Client Test (pub.dev v2 protocol)"
echo "Registry: $REGISTRY_URL"
echo "Repo:     $PUB_REPO_KEY"
echo "Package:  $PKG_NAME@$PKG_VERSION"
echo ""

# ---- Step 0: Create hosted Pub repository ----
echo "==> [0/5] Creating hosted Pub repository..."

# Check if repo already exists
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -u "$ADMIN_USER:$ADMIN_PASS" \
  "$REGISTRY_URL/api/v1/repositories/$PUB_REPO_KEY")

if [ "$HTTP_CODE" = "404" ]; then
  CREATE_RESP=$(curl -s -w "\n%{http_code}" \
    -u "$ADMIN_USER:$ADMIN_PASS" \
    -X POST "$REGISTRY_URL/api/v1/repositories" \
    -H "Content-Type: application/json" \
    -d "{
      \"key\": \"$PUB_REPO_KEY\",
      \"name\": \"Test Dart Pub Repo\",
      \"format\": \"pub\",
      \"repo_type\": \"local\"
    }")
  CREATE_STATUS=$(echo "$CREATE_RESP" | tail -1)
  CREATE_BODY=$(echo "$CREATE_RESP" | sed '$d')
  echo "  Create response ($CREATE_STATUS): $CREATE_BODY"
  if [ "$CREATE_STATUS" -ge 300 ]; then
    echo "❌ Failed to create repository"
    exit 1
  fi
elif [ "$HTTP_CODE" = "200" ]; then
  echo "  Repository already exists"
else
  echo "  ⚠️  Unexpected status checking repo: $HTTP_CODE"
fi

# Generate test package
echo "==> [1/5] Building test package..."
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

PKG_DIR="$WORK_DIR/$PKG_NAME"
mkdir -p "$PKG_DIR/lib"

cat > "$PKG_DIR/pubspec.yaml" << EOF
name: $PKG_NAME
version: $PKG_VERSION
description: Test package for artifact-keeper Dart Pub E2E
environment:
  sdk: ">=2.12.0 <4.0.0"
EOF

cat > "$PKG_DIR/lib/$PKG_NAME.dart" << EOF
/// Test package for artifact-keeper E2E testing.
String hello() => 'Hello from $PKG_NAME!';
EOF

# Build tar.gz (pubspec.yaml MUST be at the root of the archive)
ARCHIVE="$WORK_DIR/${PKG_NAME}-${PKG_VERSION}.tar.gz"
(cd "$PKG_DIR" && tar czf "$ARCHIVE" pubspec.yaml lib/)
echo "  Archive: $ARCHIVE"
echo "  Contents:"
tar tzf "$ARCHIVE" | head -10

# ---- Step 1: Get upload URL ----
echo ""
echo "==> [2/5] Step 1: GET upload URL..."
STEP1_RESP=$(curl -s -w "\n---HTTP_STATUS:%{http_code}---" \
  -u "$ADMIN_USER:$ADMIN_PASS" \
  -H "Accept: application/vnd.pub.v2+json" \
  -X GET \
  "$REGISTRY_URL/pub/$PUB_REPO_KEY/api/packages/versions/new")

STEP1_STATUS=$(echo "$STEP1_RESP" | grep -o 'HTTP_STATUS:[0-9]*' | cut -d: -f2)
STEP1_BODY=$(echo "$STEP1_RESP" | sed '/^---HTTP_STATUS:/d')

echo "  Status: $STEP1_STATUS"
echo "  Body:   $STEP1_BODY"

if [ "$STEP1_STATUS" != "200" ]; then
  echo "❌ Step 1 failed: expected 200, got $STEP1_STATUS"
  echo "   Response body: $STEP1_BODY"
  exit 1
fi

# Extract upload URL from response
UPLOAD_URL=$(echo "$STEP1_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin)['url'])" 2>/dev/null || true)
if [ -z "$UPLOAD_URL" ]; then
  echo "❌ Could not extract upload URL from response"
  exit 1
fi
echo "  Upload URL: $UPLOAD_URL"

# ---- Step 2: Upload package (multipart) ----
echo ""
echo "==> [3/5] Step 2: POST multipart upload..."
FULL_UPLOAD_URL="$UPLOAD_URL"
echo "  Full URL: $FULL_UPLOAD_URL"

STEP2_RESP=$(curl -s -w "\n---HTTP_STATUS:%{http_code}---\n---HEADERS---" \
  -D - \
  -u "$ADMIN_USER:$ADMIN_PASS" \
  -X POST \
  -H "Content-Type: multipart/form-data" \
  -F "file=@$ARCHIVE" \
  "$FULL_UPLOAD_URL" 2>&1)

STEP2_STATUS=$(echo "$STEP2_RESP" | grep -o 'HTTP_STATUS:[0-9]*' | cut -d: -f2)
STEP2_HEADERS=$(echo "$STEP2_RESP" | sed -n '/---HEADERS---/q;p' | head -30)
STEP2_BODY=$(echo "$STEP2_RESP" | sed '/^---HTTP_STATUS:/d; /^---HEADERS---/d')

echo "  Status:  $STEP2_STATUS"
echo "  Headers: $STEP2_HEADERS"
echo "  Body:    $STEP2_BODY"

# Extract Location header
STEP2_LOCATION=$(echo "$STEP2_HEADERS" | grep -i "^location:" | tr -d '\r' | sed 's/^location: *//i')
if [ -n "$STEP2_LOCATION" ]; then
  echo "  Location: $STEP2_LOCATION"
else
  echo "  ⚠️  No Location header in response"
fi

# Diagnostic: what did we expect?
echo ""
echo "  --- DIAGNOSTIC ---"
case "$STEP2_STATUS" in
  204)
    echo "  ✅ Status 204 No Content — correct per pub.dev protocol"
    ;;
  200)
    echo "  ⚠️  Status 200 — some implementations return 200, check if Location header present"
    ;;
  302)
    echo "  ⚠️  Status 302 Found — client has followRedirects=false, may not follow this"
    echo "      The client reads Location header manually, not via redirect"
    ;;
  405)
    echo "  ❌ Status 405 Method Not Allowed — the route may not accept POST"
    echo "      Or middleware is rejecting the request"
    ;;
  *)
    echo "  ❓ Status $STEP2_STATUS — unexpected, need investigation"
    ;;
esac

if [ -z "$STEP2_LOCATION" ] && [ "$STEP2_STATUS" != "200" ]; then
  echo ""
  echo "❌ No Location header and non-200 status — cannot proceed to Step 3"
  echo "   This confirms the upload protocol is broken."
  exit 1
fi

# ---- Step 3: Finalize ----
echo ""
echo "==> [4/5] Step 3: GET finalize..."

# Determine finalize URL
if [ -n "$STEP2_LOCATION" ]; then
  # Location might be relative or absolute
  if echo "$STEP2_LOCATION" | grep -q "^http"; then
    FINALIZE_URL="$STEP2_LOCATION"
  else
    FINALIZE_URL="$REGISTRY_URL$STEP2_LOCATION"
  fi
else
  # Fallback: try the standard finish URL
  FINALIZE_URL="$REGISTRY_URL/pub/$PUB_REPO_KEY/api/packages/versions/newUploadFinish"
  echo "  ⚠️  No Location header, using default: $FINALIZE_URL"
fi

echo "  Finalize URL: $FINALIZE_URL"

STEP3_RESP=$(curl -s -w "\n---HTTP_STATUS:%{http_code}---" \
  -u "$ADMIN_USER:$ADMIN_PASS" \
  -H "Accept: application/vnd.pub.v2+json" \
  "$FINALIZE_URL")

STEP3_STATUS=$(echo "$STEP3_RESP" | grep -o 'HTTP_STATUS:[0-9]*' | cut -d: -f2)
STEP3_BODY=$(echo "$STEP3_RESP" | sed '/^---HTTP_STATUS:/d')

echo "  Status: $STEP3_STATUS"
echo "  Body:   $STEP3_BODY"

if [ "$STEP3_STATUS" = "200" ]; then
  echo "  ✅ Step 3 succeeded"
else
  echo "  ❌ Step 3 failed: expected 200, got $STEP3_STATUS"
fi

# ---- Step 4: Verify package is queryable ----
echo ""
echo "==> [5/5] Verifying package info..."
QUERY_RESP=$(curl -s -w "\n---HTTP_STATUS:%{http_code}---" \
  -u "$ADMIN_USER:$ADMIN_PASS" \
  -H "Accept: application/vnd.pub.v2+json" \
  "$REGISTRY_URL/pub/$PUB_REPO_KEY/api/packages/$PKG_NAME")

QUERY_STATUS=$(echo "$QUERY_RESP" | grep -o 'HTTP_STATUS:[0-9]*' | cut -d: -f2)
QUERY_BODY=$(echo "$QUERY_RESP" | sed '/^---HTTP_STATUS:/d')

echo "  Status: $QUERY_STATUS"
echo "  Body:   $QUERY_BODY"

if [ "$QUERY_STATUS" = "200" ]; then
  echo "  ✅ Package is queryable"
else
  echo "  ❌ Package query failed: $QUERY_STATUS"
fi

# ---- Step 5: Download archive ----
echo ""
echo "==> [6/7] Downloading archive via curl..."

# Get archive URL and expected SHA256 from package info
ARCHIVE_URL=$(echo "$QUERY_BODY" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(d['latest']['archive_url'])
" 2>/dev/null || true)
EXPECTED_SHA256=$(echo "$QUERY_BODY" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(d['latest'].get('archive_sha256',''))
" 2>/dev/null || true)
echo "  Archive URL: $ARCHIVE_URL"
echo "  Expected SHA256: $EXPECTED_SHA256"
DOWNLOAD_FILE="$WORK_DIR/downloaded-$PKG_NAME-$PKG_VERSION.tar.gz"

DOWNLOAD_RESP=$(curl -s -w "\n---HTTP_STATUS:%{http_code}---" \
  -u "$ADMIN_USER:$ADMIN_PASS" \
  -o "$DOWNLOAD_FILE" \
  "$ARCHIVE_URL")

DOWNLOAD_STATUS=$(echo "$DOWNLOAD_RESP" | grep -o 'HTTP_STATUS:[0-9]*' | cut -d: -f2)

echo "  URL:    $ARCHIVE_URL"
echo "  Status: $DOWNLOAD_STATUS"

if [ "$DOWNLOAD_STATUS" = "200" ]; then
  DOWNLOAD_SIZE=$(stat -f%z "$DOWNLOAD_FILE" 2>/dev/null || stat -c%s "$DOWNLOAD_FILE" 2>/dev/null || echo "?")
  echo "  Size:   $DOWNLOAD_SIZE bytes"

  # Verify SHA256
  ACTUAL_SHA256=$(shasum -a 256 "$DOWNLOAD_FILE" 2>/dev/null | cut -d' ' -f1 || sha256sum "$DOWNLOAD_FILE" 2>/dev/null | cut -d' ' -f1)
  echo "  Actual SHA256:   $ACTUAL_SHA256"
  if [ -n "$EXPECTED_SHA256" ] && [ "$EXPECTED_SHA256" = "$ACTUAL_SHA256" ]; then
    echo "  ✅ SHA256 matches"
  elif [ -n "$EXPECTED_SHA256" ]; then
    echo "  ❌ SHA256 mismatch: expected $EXPECTED_SHA256, got $ACTUAL_SHA256"
  else
    echo "  ⚠️  No SHA256 in package info to compare"
  fi

  # Verify it's a valid tar.gz
  if tar tzf "$DOWNLOAD_FILE" >/dev/null 2>&1; then
    echo "  ✅ Archive is valid tar.gz"
    echo "  Contents:"
    tar tzf "$DOWNLOAD_FILE" | head -10
  else
    echo "  ❌ Downloaded file is not a valid tar.gz"
  fi
else
  echo "  ❌ Download failed: $DOWNLOAD_STATUS"
fi

# ---- Summary ----
echo ""
echo "=============================================="
echo "DIAGNOSTIC SUMMARY"
echo "=============================================="
echo "Step 1 (get URL):     $STEP1_STATUS"
echo "Step 2 (upload):      $STEP2_STATUS"
echo "Step 3 (finalize):    $STEP3_STATUS"
echo "Step 4 (query):       $QUERY_STATUS"
echo "Step 5 (download):    $DOWNLOAD_STATUS"
echo ""

ALL_OK=true
[ "$STEP1_STATUS" = "200" ] || ALL_OK=false
[ "$STEP3_STATUS" = "200" ] || ALL_OK=false
[ "$QUERY_STATUS" = "200" ] || ALL_OK=false
[ "$DOWNLOAD_STATUS" = "200" ] || ALL_OK=false

if $ALL_OK && [ "$STEP2_STATUS" = "204" -o "$STEP2_STATUS" = "200" ]; then
  echo "✅ curl protocol test PASSED"
else
  echo "❌ curl protocol test FAILED — review the diagnostic output above"
fi

# ---- Test with actual dart CLI ----
echo ""
echo "=============================================="
echo "Dart CLI Test (dart pub publish)"
echo "=============================================="

if ! command -v docker >/dev/null 2>&1; then
  echo "⚠️  docker not found, skipping dart CLI test"
  exit 0
fi

# Use a different version for the dart CLI test
DART_PKG_VERSION="2.0.$(date +%s)"

# Get host IP for Docker networking (macOS Docker Desktop)
HOST_IP=$(ipconfig getifaddr en0 2>/dev/null || echo "host.docker.internal")

echo "==> Setting up dart project..."
DART_DIR="$WORK_DIR/dart_project"
mkdir -p "$DART_DIR/lib"

cat > "$DART_DIR/pubspec.yaml" << EOF
name: $PKG_NAME
version: $DART_PKG_VERSION
description: Test package for artifact-keeper Dart Pub E2E
publish_to: "https://$HOST_IP:9443/pub/$PUB_REPO_KEY"
environment:
  sdk: ">=2.12.0 <4.0.0"
EOF

cat > "$DART_DIR/lib/$PKG_NAME.dart" << EOF
/// Test package for artifact-keeper E2E testing.
String hello() => 'Hello from $PKG_NAME!';
EOF

# Dart pub requires these files
touch "$DART_DIR/LICENSE"
cat > "$DART_DIR/README.md" << EOF
# $PKG_NAME
Test package for artifact-keeper E2E.
EOF
cat > "$DART_DIR/CHANGELOG.md" << EOF
## $DART_PKG_VERSION
- Initial version.
EOF

echo "==> Running dart pub publish via Docker..."
# Dart requires HTTPS for auth. Start nginx with self-signed cert as TLS proxy.
CERT_DIR="$WORK_DIR/certs"
mkdir -p "$CERT_DIR"
openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" \
  -days 1 -nodes -subj "/CN=$HOST_IP" \
  -addext "subjectAltName=IP:$HOST_IP,DNS:localhost" 2>/dev/null

# Kill any stale nginx containers from previous runs
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

# Verify nginx is running
if [ -z "$NGINX_CID" ] || ! docker ps --format '{{.ID}}' | grep -q "^${NGINX_CID:0:12}"; then
  echo "  ❌ nginx failed to start. Logs:"
  docker logs "$NGINX_CID" 2>&1 | tail -10 || true
  docker stop "$NGINX_CID" 2>/dev/null || true
  echo "  Falling back to curl-only test (dart requires HTTPS for auth)"
  DART_EXIT=1
else
  echo "  nginx running on https://$HOST_IP:9443 (container: ${NGINX_CID:0:12})"

  docker run --rm \
    --add-host=host.docker.internal:host-gateway \
    -v "$CERT_DIR/cert.pem:/certs/self-signed.crt:ro" \
    -v "$DART_DIR:/project" \
    -w /project \
    dart:stable \
    sh -c "
      cp /certs/self-signed.crt /usr/local/share/ca-certificates/self-signed.crt 2>/dev/null || \
        cp /certs/self-signed.crt /usr/lib/ssl/certs/self-signed.crt 2>/dev/null || \
        mkdir -p /etc/ssl/certs && cp /certs/self-signed.crt /etc/ssl/certs/self-signed.crt
      update-ca-certificates 2>/dev/null || true
      printf '%s\n' '$(echo -n "$ADMIN_USER:$ADMIN_PASS" | base64)' | dart pub token add 'https://$HOST_IP:9443/pub/$PUB_REPO_KEY/'
      dart pub publish --force --skip-validation 2>&1
    "
  DART_EXIT=$?
fi

if [ "$DART_EXIT" -eq 0 ]; then
  echo "✅ dart pub publish succeeded"
else
  echo "❌ dart pub publish failed (exit code: $DART_EXIT)"
fi

# ---- Verify and download via dart pub get ----
echo ""
echo "==> Verifying and downloading via dart pub get..."

if [ -n "${NGINX_CID:-}" ]; then
  # Create a consumer project that depends on the published package
  CONSUMER_DIR="$WORK_DIR/consumer"
  mkdir -p "$CONSUMER_DIR/lib"
  cat > "$CONSUMER_DIR/pubspec.yaml" << EOF
name: test_consumer
environment:
    sdk: ">=2.15.0 <4.0.0"
dependencies:
  $PKG_NAME:
    hosted: https://$HOST_IP:9443/pub/$PUB_REPO_KEY
    version: $DART_PKG_VERSION
EOF
  cat > "$CONSUMER_DIR/lib/consumer.dart" << EOF
import 'package:$PKG_NAME/$PKG_NAME.dart';
String use() => hello();
EOF

  docker run --rm \
    --add-host=host.docker.internal:host-gateway \
    -v "$CERT_DIR/cert.pem:/certs/self-signed.crt:ro" \
    -v "$CONSUMER_DIR:/project" \
    -w /project \
    -e ADMIN_USER="$ADMIN_USER" \
    -e ADMIN_PASS="$ADMIN_PASS" \
    -e DART_HOST="$HOST_IP" \
    dart:stable \
    sh -c "
      cp /certs/self-signed.crt /usr/local/share/ca-certificates/self-signed.crt 2>/dev/null || \
        cp /certs/self-signed.crt /usr/lib/ssl/certs/self-signed.crt 2>/dev/null || \
        mkdir -p /etc/ssl/certs && cp /certs/self-signed.crt /etc/ssl/certs/self-signed.crt
      update-ca-certificates 2>/dev/null || true
      printf '%s\n' '$(echo -n "$ADMIN_USER:$ADMIN_PASS" | base64)' | dart pub token add 'https://$HOST_IP:9443/pub/$PUB_REPO_KEY/'
      echo '==> Running dart pub get...'
      dart pub get 2>&1
      echo ''
      echo '==> Resolved packages:'
      cat .dart_tool/package_config.json 2>/dev/null | grep -A2 \"$PKG_NAME\" || true
    "
  DART_DL_EXIT=$?
  if [ "$DART_DL_EXIT" -eq 0 ]; then
    echo "✅ dart pub get PASSED"
  else
    echo "❌ dart pub get FAILED (exit code: $DART_DL_EXIT)"
  fi

  docker stop "$NGINX_CID" >/dev/null 2>&1 || true
else
  echo "  ⚠️  nginx not running, skipping Dart download test"
fi
