#!/bin/bash
# Generate Docker test image
# Usage: ./generate.sh [size_tier] [version] [output_dir]
set -euo pipefail

SIZE_TIER="${1:-small}"
VERSION="${2:-1.0.0}"
OUTPUT_DIR="${3:-../generated/docker}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "==> Generating Docker image (size: $SIZE_TIER, version: $VERSION)"

# Copy template files
cp "$SCRIPT_DIR/Dockerfile" "$WORK_DIR/"
cp "$SCRIPT_DIR/entrypoint.sh" "$WORK_DIR/"

# Replace version placeholder
sed -i "s/VERSION_PLACEHOLDER/$VERSION/g" "$WORK_DIR/Dockerfile"
sed -i "s/VERSION_PLACEHOLDER/$VERSION/g" "$WORK_DIR/entrypoint.sh"

# Add data file based on size tier
case "$SIZE_TIER" in
    small)
        # No extra data
        ;;
    medium)
        echo "==> Adding 10MB data file..."
        dd if=/dev/urandom of="$WORK_DIR/data.bin" bs=1M count=10 2>/dev/null
        echo "COPY data.bin /data.bin" >> "$WORK_DIR/Dockerfile"
        ;;
    large)
        echo "==> Adding 100MB data file..."
        dd if=/dev/urandom of="$WORK_DIR/data.bin" bs=1M count=100 2>/dev/null
        echo "COPY data.bin /data.bin" >> "$WORK_DIR/Dockerfile"
        ;;
    *)
        echo "ERROR: Invalid size tier: $SIZE_TIER (use: small, medium, large)"
        exit 2
        ;;
esac

# Build and save image
cd "$WORK_DIR"
IMAGE_NAME="test-image:$VERSION"
docker build -t "$IMAGE_NAME" .

# Create output directory and save image as tar
mkdir -p "$OUTPUT_DIR"
docker save "$IMAGE_NAME" -o "$OUTPUT_DIR/test-image-$VERSION.tar"

echo "==> Generated Docker image in $OUTPUT_DIR:"
ls -la "$OUTPUT_DIR"
echo ""
echo "Image also available as: $IMAGE_NAME"
