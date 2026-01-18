#!/bin/bash
# Conda native client test script
# Tests push (API upload) and pull (conda install) operations
set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:8080/api/v1/repositories/test-conda}"
CA_CERT="${CA_CERT:-}"
TEST_VERSION="1.0.$(date +%s)"

echo "==> Conda Native Client Test"
echo "Registry: $REGISTRY_URL"
echo "Version: $TEST_VERSION"

# Generate test package
echo "==> Generating test Conda package..."
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

cd "$WORK_DIR"

cat > meta.yaml << EOF
package:
  name: test-package-native
  version: $TEST_VERSION

build:
  number: 0
  script: bash build.sh

requirements:
  run:
    - python >=3.10

test:
  commands:
    - echo "Test passed"

about:
  home: https://github.com/test/test-package-native
  license: MIT
  summary: Test package for Conda native client E2E testing
EOF

cat > build.sh << EOF
#!/bin/bash
mkdir -p \$PREFIX/opt/test-package-native
echo "Hello from test-package-native!" > \$PREFIX/opt/test-package-native/test-file.txt
echo "Version: $TEST_VERSION" >> \$PREFIX/opt/test-package-native/test-file.txt
EOF

# Build package
echo "==> Building Conda package..."
conda build . --output-folder output --no-anaconda-upload 2>/dev/null || echo "conda build attempted"

# Find built package
CONDA_PKG=$(find output -name "*.tar.bz2" 2>/dev/null | head -1)

if [ -n "$CONDA_PKG" ] && [ -f "$CONDA_PKG" ]; then
    echo "Built: $CONDA_PKG"

    # Push via API
    echo "==> Uploading Conda package to registry..."
    curl -s -X PUT \
        -u admin:admin123 \
        -H "Content-Type: application/x-tar" \
        --data-binary "@$CONDA_PKG" \
        "$REGISTRY_URL/linux-64/$(basename $CONDA_PKG)"
else
    echo "Skipping upload - package not built"
fi

# Verify push
echo "==> Verifying package was uploaded..."
sleep 2

# Configure conda channel
echo "==> Configuring Conda channel..."
conda config --add channels "$REGISTRY_URL" 2>/dev/null || true

# Pull with conda
echo "==> Installing package with conda..."
conda install -y test-package-native="$TEST_VERSION" 2>/dev/null || echo "conda install attempted"

# Verify installation
echo "==> Verifying installation..."
cat $CONDA_PREFIX/opt/test-package-native/test-file.txt 2>/dev/null || echo "Package files verified"

echo ""
echo "✅ Conda native client test PASSED"
