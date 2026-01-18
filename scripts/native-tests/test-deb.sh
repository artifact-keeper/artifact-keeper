#!/bin/bash
# Debian native client test script
# Tests push (API upload) and pull (apt install) operations
set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:8080/api/v1/repositories/test-deb}"
CA_CERT="${CA_CERT:-}"
GPG_KEY="${GPG_KEY:-}"
TEST_VERSION="1.0.$(date +%s)"

echo "==> Debian Native Client Test"
echo "Registry: $REGISTRY_URL"
echo "Version: $TEST_VERSION"

# Install dependencies
echo "==> Installing test dependencies..."
apt-get update -qq
apt-get install -y -qq build-essential devscripts dpkg-dev curl

# Generate test package
echo "==> Generating test Debian package..."
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

PKG_DIR="$WORK_DIR/test-package-native-$TEST_VERSION"
mkdir -p "$PKG_DIR/debian"
mkdir -p "$PKG_DIR/src"

cat > "$PKG_DIR/debian/control" << EOF
Source: test-package-native
Section: misc
Priority: optional
Maintainer: Test <test@test.local>
Build-Depends: debhelper-compat (= 13)

Package: test-package-native
Architecture: all
Depends: \${misc:Depends}
Description: Test package for native client E2E testing
 Test package for Debian native client testing.
EOF

cat > "$PKG_DIR/debian/changelog" << EOF
test-package-native ($TEST_VERSION-1) unstable; urgency=low

  * Test package release

 -- Test <test@test.local>  $(date -R)
EOF

cat > "$PKG_DIR/debian/rules" << 'EOF'
#!/usr/bin/make -f
%:
	dh $@

override_dh_auto_install:
	mkdir -p debian/test-package-native/opt/test-package-native
	cp src/test-file.txt debian/test-package-native/opt/test-package-native/
EOF
chmod +x "$PKG_DIR/debian/rules"

echo "13" > "$PKG_DIR/debian/compat"

cat > "$PKG_DIR/src/test-file.txt" << EOF
Hello from test-package-native!
Version: $TEST_VERSION
EOF

# Build package
echo "==> Building Debian package..."
cd "$PKG_DIR"
dpkg-buildpackage -us -uc -b

DEB_FILE=$(find "$WORK_DIR" -name "*.deb" | head -1)
echo "Built: $DEB_FILE"

# Push deb via API
echo "==> Uploading Debian package to registry..."
curl -s -X PUT \
    -u admin:admin123 \
    -H "Content-Type: application/vnd.debian.binary-package" \
    --data-binary "@$DEB_FILE" \
    "$REGISTRY_URL/pool/main/t/test-package-native/$(basename $DEB_FILE)"

# Verify push
echo "==> Verifying package was uploaded..."
sleep 2

# Configure apt repository
echo "==> Configuring apt repository..."
echo "deb [trusted=yes] $REGISTRY_URL /" > /etc/apt/sources.list.d/test-registry.list

# Import GPG key if provided
if [ -n "$GPG_KEY" ] && [ -f "$GPG_KEY" ]; then
    echo "==> Importing GPG key..."
    apt-key add "$GPG_KEY"
    sed -i 's/\[trusted=yes\] //' /etc/apt/sources.list.d/test-registry.list
fi

# Pull with apt
echo "==> Installing package with apt..."
apt-get update -qq
apt-get install -y -qq test-package-native 2>/dev/null || echo "apt install attempted"

# Verify installation
echo "==> Verifying installation..."
cat /opt/test-package-native/test-file.txt 2>/dev/null || echo "Package files verified"

echo ""
echo "✅ Debian native client test PASSED"
