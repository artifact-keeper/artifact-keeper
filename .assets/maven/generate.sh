#!/bin/bash
# Generate Maven test package
# Usage: ./generate.sh [size_tier] [version] [output_dir]
set -euo pipefail

SIZE_TIER="${1:-small}"
VERSION="${2:-1.0.0}"
OUTPUT_DIR="${3:-../generated/maven}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "==> Generating Maven package (size: $SIZE_TIER, version: $VERSION)"

# Copy template files
mkdir -p "$WORK_DIR/src/main/java/com/test"
mkdir -p "$WORK_DIR/src/main/resources"
cp "$SCRIPT_DIR/pom.xml" "$WORK_DIR/"
cp "$SCRIPT_DIR/src/main/java/com/test/TestClass.java" "$WORK_DIR/src/main/java/com/test/"

# Replace version placeholder
sed -i "s/VERSION_PLACEHOLDER/$VERSION/g" "$WORK_DIR/pom.xml"

# Add data file based on size tier
case "$SIZE_TIER" in
    small)
        # No extra data
        ;;
    medium)
        echo "==> Adding 10MB data file..."
        dd if=/dev/urandom of="$WORK_DIR/src/main/resources/data.bin" bs=1M count=10 2>/dev/null
        ;;
    large)
        echo "==> Adding 100MB data file..."
        dd if=/dev/urandom of="$WORK_DIR/src/main/resources/data.bin" bs=1M count=100 2>/dev/null
        ;;
    *)
        echo "ERROR: Invalid size tier: $SIZE_TIER (use: small, medium, large)"
        exit 2
        ;;
esac

# Build package
cd "$WORK_DIR"
mvn package -q -DskipTests

# Create output directory and move artifact
mkdir -p "$OUTPUT_DIR"
cp target/*.jar "$OUTPUT_DIR/"

echo "==> Generated Maven package in $OUTPUT_DIR:"
ls -la "$OUTPUT_DIR"
