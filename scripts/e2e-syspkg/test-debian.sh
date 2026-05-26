#!/bin/bash
# Debian/APT E2E test — build .deb, upload, configure apt with GPG, install
set -euo pipefail
source /scripts/lib.sh

REPO_KEY="e2e-debian-$(date +%s)"
TEST_VERSION="1.0.$(date +%s)"
PKG_NAME="e2e-test-pkg"

log "Debian/APT E2E Test"
log "Repo: $REPO_KEY | Version: $TEST_VERSION"

# --- Install build deps ---
log "Installing build dependencies..."
apt-get update -qq > /dev/null
apt-get install -y -qq build-essential devscripts dpkg-dev curl gnupg python3 > /dev/null 2>&1

# --- Setup repo + signing ---
setup_signed_repo "$REPO_KEY" "debian" "gpg"

# --- Build .deb package ---
log "Building Debian package..."
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

PKG_DIR="$WORK_DIR/$PKG_NAME-$TEST_VERSION"
mkdir -p "$PKG_DIR/debian" "$PKG_DIR/src"

cat > "$PKG_DIR/debian/control" << EOF
Source: $PKG_NAME
Section: misc
Priority: optional
Maintainer: E2E Test <e2e@test.local>
Build-Depends: debhelper-compat (= 13)

Package: $PKG_NAME
Architecture: all
Depends: \${misc:Depends}
Description: E2E test package for Debian native client testing
 Verifies that the artifact registry serves valid signed APT metadata.
EOF

cat > "$PKG_DIR/debian/changelog" << EOF
$PKG_NAME ($TEST_VERSION-1) unstable; urgency=low

  * E2E test release

 -- E2E Test <e2e@test.local>  $(date -R)
EOF

cat > "$PKG_DIR/debian/rules" << 'RULES'
#!/usr/bin/make -f
%:
	dh $@
override_dh_auto_install:
	mkdir -p debian/e2e-test-pkg/opt/e2e-test-pkg
	cp src/test-file.txt debian/e2e-test-pkg/opt/e2e-test-pkg/
RULES
chmod +x "$PKG_DIR/debian/rules"

cat > "$PKG_DIR/src/test-file.txt" << EOF
Hello from $PKG_NAME!
Version: $TEST_VERSION
Format: debian
EOF

cd "$PKG_DIR"
dpkg-buildpackage -us -uc -b 2>&1 || fail "dpkg-buildpackage failed"
DEB_FILE=$(find "$WORK_DIR" -name "*.deb" | head -1)
[ -f "$DEB_FILE" ] || fail "dpkg-buildpackage produced no .deb"
log "Built: $(basename "$DEB_FILE")"

# --- Upload .deb ---
log "Uploading .deb to registry..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    -u "$AUTH_USER:$AUTH_PASS" \
    -H "Content-Type: application/vnd.debian.binary-package" \
    --data-binary "@$DEB_FILE" \
    "$BACKEND_URL/debian/$REPO_KEY/pool/main/e/${PKG_NAME}/$(basename "$DEB_FILE")")
[ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ] || fail "Upload failed (HTTP $HTTP_CODE)"
log "Upload OK ($HTTP_CODE)"

sleep 1

# --- Verify signed metadata ---
log "Verifying InRelease (GPG clearsigned)..."
INRELEASE=$(curl -sf "$BACKEND_URL/debian/$REPO_KEY/dists/stable/InRelease")
echo "$INRELEASE" | grep -q "BEGIN PGP SIGNED MESSAGE" || fail "InRelease missing GPG signature"
log "InRelease is GPG-signed"

log "Verifying Release.gpg (detached signature)..."
RELEASE_GPG=$(curl -sf "$BACKEND_URL/debian/$REPO_KEY/dists/stable/Release.gpg")
echo "$RELEASE_GPG" | grep -q "BEGIN PGP SIGNATURE" || fail "Release.gpg missing"
log "Release.gpg present"

# --- Configure apt ---
log "Downloading public key..."
curl -sf "$BACKEND_URL/debian/$REPO_KEY/dists/stable/gpg-key.asc" > /tmp/repo-key.asc
[ -s /tmp/repo-key.asc ] || fail "Empty public key"

grep -q "BEGIN PGP PUBLIC KEY BLOCK" /tmp/repo-key.asc || fail "Public key is not OpenPGP armored"
install -d -m 0755 /etc/apt/keyrings
gpg --dearmor -o /etc/apt/keyrings/e2e-registry.gpg /tmp/repo-key.asc

log "Adding apt source (signed-by mode)..."
echo "deb [signed-by=/etc/apt/keyrings/e2e-registry.gpg] $BACKEND_URL/debian/$REPO_KEY stable main" \
    > /etc/apt/sources.list.d/e2e-registry.list

# --- apt-get update + install ---
log "Running apt-get update..."
apt-get update 2>&1 | tail -10

log "Installing $PKG_NAME..."
apt-get install -y -qq "$PKG_NAME" 2>&1 || {
    log "apt install failed, checking if package is listed..."
    apt-cache show "$PKG_NAME" 2>&1 || true
    fail "Could not install $PKG_NAME"
}

# --- Verify ---
log "Verifying installed package..."
INSTALLED_CONTENT=$(cat "/opt/$PKG_NAME/test-file.txt" 2>/dev/null) || fail "Installed file not found"
echo "$INSTALLED_CONTENT" | grep -q "$TEST_VERSION" || fail "Version mismatch in installed file"
log "Installed file content verified"

echo ""
echo "=== Debian/APT E2E test PASSED ==="
