#!/bin/bash
# PyPI native client test script
# Tests push (twine) and pull (pip) operations via PEP 503 Simple Repository API
set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:30080}"
PYPI_REPO_KEY="${PYPI_REPO_KEY:-test-pypi}"
PYPI_URL="$REGISTRY_URL/pypi/$PYPI_REPO_KEY"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin123}"
TEST_VERSION="1.0.$(date +%s)"

echo "==> PyPI Native Client Test (PEP 503)"
echo "Registry: $PYPI_URL"
echo "Version: $TEST_VERSION"

# Check prerequisites
command -v python3 >/dev/null || { echo "SKIP: python3 not found"; exit 0; }
command -v pip3 >/dev/null || { echo "SKIP: pip3 not found"; exit 0; }

# Install twine + build if needed
echo "==> Installing test dependencies..."
pip3 install --quiet twine build 2>/dev/null || true

# Generate test package
echo "==> Generating test package..."
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

cd "$WORK_DIR"
mkdir -p src/test_package_native

cat > pyproject.toml << EOF
[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "test-package-native"
version = "$TEST_VERSION"
description = "Test package for artifact-keeper PyPI E2E"
requires-python = ">=3.8"
EOF

cat > src/test_package_native/__init__.py << EOF
__version__ = "$TEST_VERSION"
def hello():
    return "Hello from test-package-native!"
EOF

# Build package
echo "==> Building package..."
python3 -m build --wheel --sdist 2>&1 | tail -3

# ---- Test 1: Twine upload ----
echo "==> [1/6] Pushing package with twine..."
twine upload \
  --repository-url "$PYPI_URL/" \
  --username "$ADMIN_USER" \
  --password "$ADMIN_PASS" \
  dist/* 2>&1 | tail -5
echo "✅ Twine upload succeeded"

# ---- Test 2: PEP 503 root index ----
echo "==> [2/6] Verifying PEP 503 root index..."
ROOT_INDEX=$(curl -sf "$PYPI_URL/simple/")
echo "$ROOT_INDEX" | grep -q "test-package-native" || { echo "❌ Package not in root index"; exit 1; }
echo "✅ Root index contains package"

# ---- Test 3: PEP 503 package index ----
echo "==> [3/6] Verifying PEP 503 package index..."
PKG_INDEX=$(curl -sf "$PYPI_URL/simple/test-package-native/")
echo "$PKG_INDEX" | grep -q ".whl" || { echo "❌ Wheel not in package index"; exit 1; }
echo "$PKG_INDEX" | grep -q ".tar.gz" || { echo "❌ Sdist not in package index"; exit 1; }
echo "$PKG_INDEX" | grep -q "sha256=" || { echo "❌ Missing sha256 hash in index"; exit 1; }
echo "$PKG_INDEX" | grep -q "data-requires-python" || { echo "❌ Missing requires-python in index"; exit 1; }
echo "✅ Package index correct with hashes and requires-python"

# ---- Test 4: PEP 691 JSON API ----
echo "==> [4/6] Verifying PEP 691 JSON API..."
JSON_RESP=$(curl -sf -H "Accept: application/vnd.pypi.simple.v1+json" "$PYPI_URL/simple/test-package-native/")
echo "$JSON_RESP" | python3 -c "
import sys, json
data = json.load(sys.stdin)
assert data['meta']['api-version'] == '1.1', 'Wrong API version'
assert data['name'] == 'test-package-native', 'Wrong name'
assert len(data['files']) == 2, f'Expected 2 files, got {len(data[\"files\"])}'
assert '$TEST_VERSION' in data['versions'], 'Version not listed'
print('  JSON response valid')
"
echo "✅ PEP 691 JSON API works"

# ---- Test 5: pip install ----
echo "==> [5/6] Installing package with pip..."
pip3 install \
  --index-url "$PYPI_URL/simple/" \
  --trusted-host "$(echo "$REGISTRY_URL" | sed 's|https\?://||' | cut -d: -f1)" \
  "test-package-native==$TEST_VERSION" 2>&1 | tail -3

# Verify installation
python3 -c "from test_package_native import hello; assert hello() == 'Hello from test-package-native!'"
echo "✅ pip install + import succeeded"

# ---- Test 6: PEP 658 metadata ----
echo "==> [6/6] Verifying PEP 658 metadata endpoint..."
WHL_FILE=$(ls dist/*.whl | head -1 | xargs basename)
METADATA=$(curl -sf "$PYPI_URL/simple/test-package-native/${WHL_FILE}.metadata")
echo "$METADATA" | grep -q "Name: test-package-native" || { echo "❌ Metadata missing Name"; exit 1; }
echo "$METADATA" | grep -q "Version: $TEST_VERSION" || { echo "❌ Metadata missing Version"; exit 1; }
echo "✅ PEP 658 metadata extraction works"

# Cleanup
pip3 uninstall -y test-package-native 2>/dev/null || true

echo ""
echo "✅ All PyPI native client tests PASSED"
echo "   PEP 503 (Simple Repository API) ✓"
echo "   PEP 691 (JSON Simple API)       ✓"
echo "   PEP 658 (Metadata endpoint)     ✓"
echo "   Twine upload                    ✓"
echo "   pip install                     ✓"
