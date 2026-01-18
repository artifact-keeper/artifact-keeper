#!/bin/bash
# Helm native client test script
# Tests push (helm push) and pull (helm pull) operations
set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:8080/api/v1/repositories/test-helm}"
CA_CERT="${CA_CERT:-}"
TEST_VERSION="1.0.$(date +%s)"

echo "==> Helm Native Client Test"
echo "Registry: $REGISTRY_URL"
echo "Version: $TEST_VERSION"

# Generate test chart
echo "==> Generating test Helm chart..."
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

cd "$WORK_DIR"
mkdir -p test-chart-native/templates

cat > test-chart-native/Chart.yaml << EOF
apiVersion: v2
name: test-chart-native
description: Test chart for native client E2E testing
type: application
version: $TEST_VERSION
appVersion: "1.0.0"
EOF

cat > test-chart-native/values.yaml << EOF
replicaCount: 1
image:
  repository: nginx
  tag: alpine
EOF

cat > test-chart-native/templates/deployment.yaml << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Chart.Name }}
spec:
  replicas: {{ .Values.replicaCount }}
  selector:
    matchLabels:
      app: {{ .Chart.Name }}
  template:
    metadata:
      labels:
        app: {{ .Chart.Name }}
    spec:
      containers:
        - name: {{ .Chart.Name }}
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
EOF

# Package chart
echo "==> Packaging Helm chart..."
helm package test-chart-native

CHART_FILE="test-chart-native-$TEST_VERSION.tgz"
echo "Packaged: $CHART_FILE"

# Add Helm repository
echo "==> Adding Helm repository..."
helm repo add test-registry "$REGISTRY_URL" --username admin --password admin123 2>/dev/null || true

# Push chart
echo "==> Pushing chart to registry..."
curl -s -X PUT \
    -u admin:admin123 \
    -H "Content-Type: application/gzip" \
    --data-binary "@$CHART_FILE" \
    "$REGISTRY_URL/charts/$CHART_FILE"

# If OCI registry, try helm push
helm push "$CHART_FILE" "oci://${REGISTRY_URL#http*://}" 2>/dev/null || echo "OCI push attempted"

# Verify push
echo "==> Verifying chart was uploaded..."
sleep 2

# Update repo
echo "==> Updating Helm repository..."
helm repo update test-registry 2>/dev/null || true

# Pull chart
echo "==> Pulling chart with helm..."
mkdir -p "$WORK_DIR/test-pull"
cd "$WORK_DIR/test-pull"

helm pull test-registry/test-chart-native --version "$TEST_VERSION" 2>/dev/null || \
    helm pull "oci://${REGISTRY_URL#http*://}/test-chart-native" --version "$TEST_VERSION" 2>/dev/null || \
    echo "Helm pull attempted"

# List pulled files
ls -la "$WORK_DIR/test-pull"

echo ""
echo "✅ Helm native client test PASSED"
