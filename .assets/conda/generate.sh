#!/bin/bash
# Generate Conda test package
# Usage: ./generate.sh [size_tier] [version] [output_dir]
set -euo pipefail

SIZE_TIER="${1:-small}"
VERSION="${2:-1.0.0}"
OUTPUT_DIR="${3:-../generated/conda}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "==> Generating Conda package (size: $SIZE_TIER, version: $VERSION)"

# Copy template files
cp "$SCRIPT_DIR/meta.yaml" "$WORK_DIR/"
cp "$SCRIPT_DIR/build.sh" "$WORK_DIR/"

# Replace version placeholder
sed -i "s/VERSION_PLACEHOLDER/$VERSION/g" "$WORK_DIR/meta.yaml"

# Add data file based on size tier
case "$SIZE_TIER" in
    small)
        # No extra data
        ;;
    medium)
        echo "==> Adding 10MB data file..."
        dd if=/dev/urandom of="$WORK_DIR/data.bin" bs=1M count=10 2>/dev/null
        ;;
    large)
        echo "==> Adding 100MB data file..."
        dd if=/dev/urandom of="$WORK_DIR/data.bin" bs=1M count=100 2>/dev/null
        ;;
    *)
        echo "ERROR: Invalid size tier: $SIZE_TIER (use: small, medium, large)"
        exit 2
        ;;
esac

# Build package
cd "$WORK_DIR"
conda build . --output-folder output --no-anaconda-upload

# Create output directory and move artifact
mkdir -p "$OUTPUT_DIR"
find output -name "*.tar.bz2" -exec cp {} "$OUTPUT_DIR/" \;

echo "==> Generated Conda package in $OUTPUT_DIR:"
ls -la "$OUTPUT_DIR"
