#!/bin/bash
# Generate Helm chart test package
# Usage: ./generate.sh [size_tier] [version] [output_dir]
set -euo pipefail

SIZE_TIER="${1:-small}"
VERSION="${2:-1.0.0}"
OUTPUT_DIR="${3:-../generated/helm}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "==> Generating Helm chart (size: $SIZE_TIER, version: $VERSION)"

# Create chart structure
CHART_DIR="$WORK_DIR/test-chart"
mkdir -p "$CHART_DIR/templates"

# Copy template files
cp "$SCRIPT_DIR/Chart.yaml" "$CHART_DIR/"
cp "$SCRIPT_DIR/values.yaml" "$CHART_DIR/"
cp "$SCRIPT_DIR/templates/deployment.yaml" "$CHART_DIR/templates/"

# Replace version placeholder
sed -i "s/VERSION_PLACEHOLDER/$VERSION/g" "$CHART_DIR/Chart.yaml"

# Add data file based on size tier (as a configmap template)
case "$SIZE_TIER" in
    small)
        # No extra data
        ;;
    medium)
        echo "==> Adding data configmap with 10MB data..."
        dd if=/dev/urandom bs=1M count=10 2>/dev/null | base64 > "$CHART_DIR/templates/data-configmap.yaml"
        echo "---" | cat - "$CHART_DIR/templates/data-configmap.yaml" > "$CHART_DIR/templates/data-configmap.yaml.tmp"
        mv "$CHART_DIR/templates/data-configmap.yaml.tmp" "$CHART_DIR/templates/data-configmap.yaml"
        ;;
    large)
        echo "==> Adding data configmap with 100MB data..."
        dd if=/dev/urandom bs=1M count=100 2>/dev/null | base64 > "$CHART_DIR/templates/data-configmap.yaml"
        echo "---" | cat - "$CHART_DIR/templates/data-configmap.yaml" > "$CHART_DIR/templates/data-configmap.yaml.tmp"
        mv "$CHART_DIR/templates/data-configmap.yaml.tmp" "$CHART_DIR/templates/data-configmap.yaml"
        ;;
    *)
        echo "ERROR: Invalid size tier: $SIZE_TIER (use: small, medium, large)"
        exit 2
        ;;
esac

# Package chart
cd "$WORK_DIR"
helm package test-chart

# Create output directory and move artifact
mkdir -p "$OUTPUT_DIR"
mv *.tgz "$OUTPUT_DIR/"

echo "==> Generated Helm chart in $OUTPUT_DIR:"
ls -la "$OUTPUT_DIR"
