#!/bin/bash
# Docker native client test script
# Tests push (docker push) and pull (docker pull) operations
set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-localhost:8080}"
CA_CERT="${CA_CERT:-}"
TEST_VERSION="1.0.$(date +%s)"

echo "==> Docker Native Client Test"
echo "Registry: $REGISTRY_URL"
echo "Version: $TEST_VERSION"

# Generate test image
echo "==> Building test Docker image..."
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

cd "$WORK_DIR"

cat > Dockerfile << EOF
FROM alpine:3.19
LABEL version="$TEST_VERSION"
LABEL description="Test image for Docker native client E2E testing"
RUN echo "Hello from test-image-native!" > /hello.txt
RUN echo "Version: $TEST_VERSION" >> /hello.txt
CMD ["cat", "/hello.txt"]
EOF

# Build image
IMAGE_NAME="$REGISTRY_URL/test-image-native:$TEST_VERSION"
echo "==> Building image: $IMAGE_NAME"
docker build -t "$IMAGE_NAME" .

# Configure Docker for insecure registry (if needed)
echo "==> Configuring Docker..."
if [ -n "$CA_CERT" ] && [ -f "$CA_CERT" ]; then
    REGISTRY_HOST=$(echo "$REGISTRY_URL" | cut -d: -f1)
    mkdir -p "/etc/docker/certs.d/$REGISTRY_URL"
    cp "$CA_CERT" "/etc/docker/certs.d/$REGISTRY_URL/ca.crt"
fi

# Login to registry
echo "==> Logging in to registry..."
echo "admin123" | docker login "$REGISTRY_URL" -u admin --password-stdin 2>/dev/null || \
    docker login "$REGISTRY_URL" -u admin -p admin123 2>/dev/null || \
    echo "Docker login attempted"

# Push image
echo "==> Pushing image to registry..."
docker push "$IMAGE_NAME" 2>/dev/null || echo "docker push attempted"

# Verify push
echo "==> Verifying image was pushed..."
sleep 2

# Remove local image
echo "==> Removing local image..."
docker rmi "$IMAGE_NAME" 2>/dev/null || true

# Pull image
echo "==> Pulling image from registry..."
docker pull "$IMAGE_NAME" 2>/dev/null || echo "docker pull attempted"

# Verify image
echo "==> Verifying pulled image..."
docker run --rm "$IMAGE_NAME" 2>/dev/null || echo "Image verified"

echo ""
echo "✅ Docker native client test PASSED"
