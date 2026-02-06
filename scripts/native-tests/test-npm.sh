#!/bin/bash
# NPM native client test script
# Tests push (npm publish) and pull (npm install) operations
set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:30080}"
REPO_KEY="${REPO_KEY:-test-npm}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin123}"
CA_CERT="${CA_CERT:-}"
TEST_VERSION="1.0.$(date +%s)"

NPM_REGISTRY="${REGISTRY_URL}/npm/${REPO_KEY}/"

echo "==> NPM Native Client Test"
echo "Registry: $NPM_REGISTRY"
echo "Version: $TEST_VERSION"

# Ensure the NPM repository exists
echo "==> Ensuring $REPO_KEY repository exists..."
TOKEN=$(curl -sf -X POST "$REGISTRY_URL/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>process.stdout.write(JSON.parse(d).access_token))" 2>/dev/null || true)

if [ -n "$TOKEN" ]; then
  curl -sf -X POST "$REGISTRY_URL/api/v1/repositories" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"key\":\"$REPO_KEY\",\"name\":\"Test NPM\",\"format\":\"npm\",\"repo_type\":\"local\",\"is_public\":true}" 2>/dev/null || true
fi

# Generate test package
echo "==> Generating test package..."
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

cd "$WORK_DIR"

cat > package.json << EOF
{
  "name": "@test/native-package",
  "version": "$TEST_VERSION",
  "description": "Test package for native client E2E testing",
  "main": "index.js",
  "author": "Test Author",
  "license": "MIT"
}
EOF

cat > index.js << EOF
module.exports = {
  hello: function() {
    return "Hello from @test/native-package!";
  },
  version: "$TEST_VERSION"
};
EOF

# Configure npm registry
echo "==> Configuring npm registry..."
npm config set registry "$NPM_REGISTRY"
npm config set //${NPM_REGISTRY#http*://}:_authToken "$(echo -n 'admin:admin123' | base64)"

if [ -n "$CA_CERT" ] && [ -f "$CA_CERT" ]; then
    npm config set cafile "$CA_CERT"
fi

# Push with npm publish
echo "==> Publishing package with npm..."
npm publish --access public || npm publish

# Verify push
echo "==> Verifying package was published..."
sleep 2

# Pull with npm install
echo "==> Installing package with npm..."
mkdir -p "$WORK_DIR/test-install"
cd "$WORK_DIR/test-install"
npm init -y
npm install "@test/native-package@$TEST_VERSION"

# Verify installation
echo "==> Verifying installed package..."
node -e "const pkg = require('@test/native-package'); console.log(pkg.hello());"

echo ""
echo "==> NPM native client test PASSED"
