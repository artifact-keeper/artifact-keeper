#!/bin/bash
# PyPI native client test script
# Tests push (twine) and pull (pip) operations
set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:8080/api/v1/repositories/test-pypi}"
CA_CERT="${CA_CERT:-}"
TEST_VERSION="1.0.$(date +%s)"

echo "==> PyPI Native Client Test"
echo "Registry: $REGISTRY_URL"
echo "Version: $TEST_VERSION"

# Install dependencies
echo "==> Installing test dependencies..."
pip install --quiet twine build

# Generate test package
echo "==> Generating test package..."
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

cd "$WORK_DIR"
mkdir -p src/test_package

cat > pyproject.toml << EOF
[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "test-package-native"
version = "$TEST_VERSION"
description = "Test package for native client E2E testing"
EOF

cat > src/test_package/__init__.py << EOF
__version__ = "$TEST_VERSION"
def hello():
    return "Hello from test-package-native!"
EOF

# Build package
echo "==> Building package..."
python -m build --wheel --sdist

# Push with twine
echo "==> Pushing package with twine..."
TWINE_ARGS="--repository-url $REGISTRY_URL --username admin --password admin123"
if [ -n "$CA_CERT" ] && [ -f "$CA_CERT" ]; then
    TWINE_ARGS="$TWINE_ARGS --cert $CA_CERT"
fi

twine upload $TWINE_ARGS dist/*

# Verify push
echo "==> Verifying package was uploaded..."
sleep 2

# Pull with pip
echo "==> Installing package with pip..."
PIP_ARGS="--index-url $REGISTRY_URL/simple --trusted-host $(echo $REGISTRY_URL | sed 's|https\?://||' | cut -d/ -f1)"
if [ -n "$CA_CERT" ] && [ -f "$CA_CERT" ]; then
    PIP_ARGS="$PIP_ARGS --cert $CA_CERT"
fi

pip install $PIP_ARGS "test-package-native==$TEST_VERSION"

# Verify installation
echo "==> Verifying installed package..."
python -c "from test_package import hello; print(hello())"

echo ""
echo "✅ PyPI native client test PASSED"
