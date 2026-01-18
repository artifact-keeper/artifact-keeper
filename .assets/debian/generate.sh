#!/bin/bash
# Generate Debian test package
# Usage: ./generate.sh [size_tier] [version] [output_dir]
set -euo pipefail

SIZE_TIER="${1:-small}"
VERSION="${2:-1.0.0}"
OUTPUT_DIR="${3:-../generated/debian}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "==> Generating Debian package (size: $SIZE_TIER, version: $VERSION)"

# Create package structure
PKG_DIR="$WORK_DIR/test-package-$VERSION"
mkdir -p "$PKG_DIR/debian"
mkdir -p "$PKG_DIR/src"

# Copy template files
cp "$SCRIPT_DIR/debian/control" "$PKG_DIR/debian/"
cp "$SCRIPT_DIR/debian/changelog" "$PKG_DIR/debian/"
cp "$SCRIPT_DIR/debian/rules" "$PKG_DIR/debian/"
cp "$SCRIPT_DIR/debian/compat" "$PKG_DIR/debian/"
cp "$SCRIPT_DIR/src/test-file.txt" "$PKG_DIR/src/"

# Make rules executable
chmod +x "$PKG_DIR/debian/rules"

# Replace version placeholder
sed -i "s/VERSION_PLACEHOLDER/$VERSION/g" "$PKG_DIR/debian/changelog"

# Add data file based on size tier
case "$SIZE_TIER" in
    small)
        # No extra data
        ;;
    medium)
        echo "==> Adding 10MB data file..."
        dd if=/dev/urandom of="$PKG_DIR/src/data.bin" bs=1M count=10 2>/dev/null
        # Update rules to include data file
        sed -i '/test-file.txt/a \	cp src/data.bin debian/test-package/opt/test-package/' "$PKG_DIR/debian/rules"
        ;;
    large)
        echo "==> Adding 100MB data file..."
        dd if=/dev/urandom of="$PKG_DIR/src/data.bin" bs=1M count=100 2>/dev/null
        # Update rules to include data file
        sed -i '/test-file.txt/a \	cp src/data.bin debian/test-package/opt/test-package/' "$PKG_DIR/debian/rules"
        ;;
    *)
        echo "ERROR: Invalid size tier: $SIZE_TIER (use: small, medium, large)"
        exit 2
        ;;
esac

# Build package
cd "$PKG_DIR"
dpkg-buildpackage -us -uc -b

# Create output directory and move artifact
mkdir -p "$OUTPUT_DIR"
cp "$WORK_DIR"/*.deb "$OUTPUT_DIR/"

echo "==> Generated Debian package in $OUTPUT_DIR:"
ls -la "$OUTPUT_DIR"
