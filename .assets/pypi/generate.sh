#!/bin/bash
# Generate PyPI test package
# Usage: ./generate.sh [size_tier] [version] [output_dir]
set -euo pipefail

SIZE_TIER="${1:-small}"
VERSION="${2:-1.0.0}"
OUTPUT_DIR="${3:-../generated/pypi}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "==> Generating PyPI package (size: $SIZE_TIER, version: $VERSION)"

# Copy template files
cp -r "$SCRIPT_DIR"/* "$WORK_DIR/"
rm -f "$WORK_DIR/generate.sh"

# Replace version placeholder
sed -i "s/VERSION_PLACEHOLDER/$VERSION/g" "$WORK_DIR/pyproject.toml"
sed -i "s/VERSION_PLACEHOLDER/$VERSION/g" "$WORK_DIR/src/test_package/__init__.py"

# Add data file based on size tier
case "$SIZE_TIER" in
    small)
        # No extra data
        ;;
    medium)
        echo "==> Adding 10MB data file..."
        dd if=/dev/urandom of="$WORK_DIR/src/test_package/data.bin" bs=1M count=10 2>/dev/null
        ;;
    large)
        echo "==> Adding 100MB data file..."
        dd if=/dev/urandom of="$WORK_DIR/src/test_package/data.bin" bs=1M count=100 2>/dev/null
        ;;
    *)
        echo "ERROR: Invalid size tier: $SIZE_TIER (use: small, medium, large)"
        exit 2
        ;;
esac

# Build package
cd "$WORK_DIR"
python -m pip install --quiet build
python -m build --wheel --sdist

# Create output directory and move artifacts
mkdir -p "$OUTPUT_DIR"
cp dist/*.whl dist/*.tar.gz "$OUTPUT_DIR/"

echo "==> Generated PyPI package in $OUTPUT_DIR:"
ls -la "$OUTPUT_DIR"
