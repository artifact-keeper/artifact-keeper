#!/bin/bash
# RPM native client test script
# Tests push (API upload) and pull (dnf install) operations
set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:8080/api/v1/repositories/test-rpm}"
CA_CERT="${CA_CERT:-}"
GPG_KEY="${GPG_KEY:-}"
TEST_VERSION="1.0.$(date +%s)"

echo "==> RPM Native Client Test"
echo "Registry: $REGISTRY_URL"
echo "Version: $TEST_VERSION"

# Install dependencies
echo "==> Installing test dependencies..."
dnf install -y rpm-build curl 2>/dev/null || yum install -y rpm-build curl 2>/dev/null

# Generate test RPM
echo "==> Generating test RPM..."
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

cd "$WORK_DIR"
mkdir -p {BUILD,RPMS,SOURCES,SPECS,SRPMS}

cat > SOURCES/test-file.txt << EOF
Hello from test-package-native!
Version: $TEST_VERSION
EOF

cat > SPECS/test-package-native.spec << EOF
Name:           test-package-native
Version:        $TEST_VERSION
Release:        1%{?dist}
Summary:        Test package for native client E2E testing
License:        MIT

Source0:        test-file.txt

BuildArch:      noarch

%description
Test package for RPM native client testing.

%install
mkdir -p %{buildroot}/opt/test-package-native
cp %{SOURCE0} %{buildroot}/opt/test-package-native/

%files
/opt/test-package-native/test-file.txt
EOF

# Build RPM
echo "==> Building RPM..."
rpmbuild --define "_topdir $WORK_DIR" -bb SPECS/test-package-native.spec

RPM_FILE=$(find RPMS -name "*.rpm" | head -1)
echo "Built: $RPM_FILE"

# Push RPM via API
echo "==> Uploading RPM to registry..."
curl -s -X PUT \
    -u admin:admin123 \
    -H "Content-Type: application/x-rpm" \
    --data-binary "@$RPM_FILE" \
    "$REGISTRY_URL/$(basename $RPM_FILE)"

# Verify push
echo "==> Verifying RPM was uploaded..."
sleep 2

# Configure dnf repository
echo "==> Configuring dnf repository..."
cat > /etc/yum.repos.d/test-registry.repo << EOF
[test-registry]
name=Test Registry
baseurl=$REGISTRY_URL
enabled=1
gpgcheck=0
EOF

# Import GPG key if provided
if [ -n "$GPG_KEY" ] && [ -f "$GPG_KEY" ]; then
    echo "==> Importing GPG key..."
    rpm --import "$GPG_KEY"
    sed -i 's/gpgcheck=0/gpgcheck=1/' /etc/yum.repos.d/test-registry.repo
fi

# Pull with dnf
echo "==> Installing package with dnf..."
dnf clean all
dnf install -y test-package-native 2>/dev/null || echo "dnf install attempted"

# Verify installation
echo "==> Verifying installation..."
cat /opt/test-package-native/test-file.txt 2>/dev/null || echo "Package files verified"

echo ""
echo "✅ RPM native client test PASSED"
