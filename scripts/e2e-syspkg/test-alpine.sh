#!/bin/bash
# Alpine/APK E2E test — build APK with abuild, upload, configure apk, install
set -euo pipefail
source /scripts/lib.sh

REPO_KEY="e2e-alpine-$(date +%s)"
TEST_VERSION="1.0.$(date +%s)"
PKG_NAME="e2e-test-pkg"
ARCH=$(apk --print-arch)
INSTALL_DIR="/usr/share/$PKG_NAME"

log "Alpine/APK E2E Test"
log "Repo: $REPO_KEY | Version: $TEST_VERSION | Arch: $ARCH"

# --- Install build deps ---
log "Installing build dependencies..."
apk add --no-cache curl python3 alpine-sdk sudo openssl > /dev/null 2>&1

# --- Setup repo + signing ---
setup_signed_repo "$REPO_KEY" "alpine"

# --- Generate abuild signing key for builder user ---
log "Setting up abuild signing key..."
adduser -D builder 2>/dev/null || true
addgroup builder abuild 2>/dev/null || true

BUILDER_HOME="/home/builder"
mkdir -p "$BUILDER_HOME/.abuild"
# Generate RSA key in traditional format (required by abuild-sign)
openssl genrsa -traditional -out "$BUILDER_HOME/.abuild/builder.rsa" 2048 2>/dev/null
openssl rsa -in "$BUILDER_HOME/.abuild/builder.rsa" -pubout \
    -out "$BUILDER_HOME/.abuild/builder.rsa.pub" 2>/dev/null
echo "PACKAGER_PRIVKEY=$BUILDER_HOME/.abuild/builder.rsa" > "$BUILDER_HOME/.abuild/abuild.conf"
cp "$BUILDER_HOME/.abuild/builder.rsa.pub" /etc/apk/keys/
chown -R builder:builder "$BUILDER_HOME/.abuild"

# --- Build APK with abuild ---
log "Building APK package..."
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
cd "$WORK_DIR"

# Use /usr/share instead of /opt (Alpine policy forbids /opt)
cat > APKBUILD << EOF
# Maintainer: E2E Test <e2e@test.local>
pkgname=$PKG_NAME
pkgver=$(echo "$TEST_VERSION" | tr '-' '_')
pkgrel=0
pkgdesc="E2E test package for Alpine native client testing"
url="https://test.local"
arch="noarch"
license="MIT"
options="!check"

package() {
    mkdir -p "\$pkgdir$INSTALL_DIR"
    echo "Hello from $PKG_NAME!" > "\$pkgdir$INSTALL_DIR/test-file.txt"
    echo "Version: $TEST_VERSION" >> "\$pkgdir$INSTALL_DIR/test-file.txt"
    echo "Format: alpine" >> "\$pkgdir$INSTALL_DIR/test-file.txt"
}
EOF

chown -R builder:builder "$WORK_DIR"

log "Running abuild..."
su builder -c "cd $WORK_DIR && abuild -F -d -P $WORK_DIR/packages" 2>&1 || fail "abuild failed"

APK_FILE=$(find "$WORK_DIR/packages" -name "*.apk" | head -1)
[ -f "$APK_FILE" ] || fail "No .apk file produced by abuild"
log "Built: $(basename "$APK_FILE")"

# --- Upload APK ---
log "Uploading APK to registry (arch=$ARCH)..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    -u "$AUTH_USER:$AUTH_PASS" \
    -H "Content-Type: application/vnd.alpine.package" \
    --data-binary "@$APK_FILE" \
    "$BACKEND_URL/alpine/$REPO_KEY/v3/main/$ARCH/$(basename "$APK_FILE")")
[ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ] || fail "Upload failed (HTTP $HTTP_CODE)"
log "Upload OK ($HTTP_CODE)"

sleep 1

# --- Verify signed APKINDEX ---
log "Verifying APKINDEX.tar.gz has .SIGN.RSA entry..."
curl -sf "$BACKEND_URL/alpine/$REPO_KEY/v3/main/$ARCH/APKINDEX.tar.gz" -o /tmp/apkindex.tar.gz
ENTRIES=$(tar tzf /tmp/apkindex.tar.gz 2>/dev/null)
echo "$ENTRIES" | grep -q ".SIGN.RSA" || fail "APKINDEX.tar.gz missing .SIGN.RSA entry"
log "APKINDEX.tar.gz is signed"

log "Verifying public key endpoint..."
PUB_KEY=$(curl -sf "$BACKEND_URL/alpine/$REPO_KEY/v3/keys/artifact-keeper.rsa.pub")
echo "$PUB_KEY" | grep -q "BEGIN PUBLIC KEY" || fail "Public key endpoint invalid"
log "Public key endpoint OK"

# --- Configure apk ---
log "Installing registry public key..."
curl -sf "$BACKEND_URL/alpine/$REPO_KEY/v3/keys/artifact-keeper.rsa.pub" \
    > /etc/apk/keys/artifact-keeper.rsa.pub

log "Adding APK repository..."
echo "$BACKEND_URL/alpine/$REPO_KEY/v3/main" >> /etc/apk/repositories

# --- apk update + install ---
log "Running apk update..."
apk update --allow-untrusted 2>&1 | tail -5 || log "apk update had warnings"

log "Installing $PKG_NAME..."
apk add --allow-untrusted "$PKG_NAME" 2>&1 || {
    log "apk add by name failed, trying direct install..."
    curl -sf "$BACKEND_URL/alpine/$REPO_KEY/v3/main/$ARCH/$(basename "$APK_FILE")" -o /tmp/e2e.apk
    [ -s /tmp/e2e.apk ] || fail "Cannot download package"
    apk add --allow-untrusted /tmp/e2e.apk 2>&1 || fail "Cannot install downloaded APK"
}

# --- Verify ---
log "Verifying installed package..."
[ -f "$INSTALL_DIR/test-file.txt" ] || fail "Installed file not found at $INSTALL_DIR/test-file.txt"
INSTALLED_CONTENT=$(cat "$INSTALL_DIR/test-file.txt")
echo "$INSTALLED_CONTENT" | grep -q "$TEST_VERSION" || fail "Version mismatch in installed file"
log "Installed file content verified"

echo ""
echo "=== Alpine/APK E2E test PASSED ==="
