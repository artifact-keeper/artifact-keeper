#!/bin/bash
# Generate all test packages for E2E native client testing
# Usage: ./generate-all.sh [size_tier] [version]
set -euo pipefail

SIZE_TIER="${1:-small}"
VERSION="${2:-1.0.0}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ASSETS_DIR="$REPO_ROOT/.assets"
OUTPUT_DIR="$ASSETS_DIR/generated"

echo "=============================================="
echo "Generating all test packages"
echo "=============================================="
echo "Size tier: $SIZE_TIER"
echo "Version: $VERSION"
echo "Output: $OUTPUT_DIR"
echo "=============================================="

# Ensure output directory exists and is clean
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# List of all package formats
FORMATS=(pypi npm cargo maven go rpm debian helm conda docker)

# Track results
SUCCESSFUL=()
FAILED=()

for format in "${FORMATS[@]}"; do
    echo ""
    echo ">>> Generating $format package..."

    GENERATE_SCRIPT="$ASSETS_DIR/$format/generate.sh"

    if [ ! -f "$GENERATE_SCRIPT" ]; then
        echo "WARNING: $GENERATE_SCRIPT not found, skipping"
        FAILED+=("$format (script not found)")
        continue
    fi

    if bash "$GENERATE_SCRIPT" "$SIZE_TIER" "$VERSION" "$OUTPUT_DIR/$format" 2>&1; then
        SUCCESSFUL+=("$format")
        echo ">>> $format: SUCCESS"
    else
        FAILED+=("$format")
        echo ">>> $format: FAILED"
    fi
done

echo ""
echo "=============================================="
echo "Generation Summary"
echo "=============================================="
echo ""
echo "Successful (${#SUCCESSFUL[@]}):"
for fmt in "${SUCCESSFUL[@]}"; do
    echo "  ✓ $fmt"
done

if [ ${#FAILED[@]} -gt 0 ]; then
    echo ""
    echo "Failed (${#FAILED[@]}):"
    for fmt in "${FAILED[@]}"; do
        echo "  ✗ $fmt"
    done
    echo ""
    echo "WARNING: Some packages failed to generate"
    exit 1
fi

echo ""
echo "All packages generated successfully!"
echo ""
echo "Output directory contents:"
ls -la "$OUTPUT_DIR"
