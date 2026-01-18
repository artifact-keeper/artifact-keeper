#!/bin/bash
# Generate RPM test package
# Usage: ./generate.sh [size_tier] [version] [output_dir]
set -euo pipefail

SIZE_TIER="${1:-small}"
VERSION="${2:-1.0.0}"
OUTPUT_DIR="${3:-../generated/rpm}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "==> Generating RPM package (size: $SIZE_TIER, version: $VERSION)"

# Setup rpmbuild directory structure
mkdir -p "$WORK_DIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Copy spec file and replace version
cp "$SCRIPT_DIR/test-package.spec" "$WORK_DIR/SPECS/"
sed -i "s/VERSION_PLACEHOLDER/$VERSION/g" "$WORK_DIR/SPECS/test-package.spec"

# Copy source files
cp "$SCRIPT_DIR/SOURCES/test-file.txt" "$WORK_DIR/SOURCES/"

# Add data file based on size tier
case "$SIZE_TIER" in
    small)
        # No extra data
        ;;
    medium)
        echo "==> Adding 10MB data file..."
        dd if=/dev/urandom of="$WORK_DIR/SOURCES/data.bin" bs=1M count=10 2>/dev/null
        # Update spec to include data file
        sed -i '/^Source0:/a Source1:        data.bin' "$WORK_DIR/SPECS/test-package.spec"
        sed -i '/cp %{SOURCE0}/a cp %{SOURCE1} %{buildroot}/opt/test-package/' "$WORK_DIR/SPECS/test-package.spec"
        sed -i '/test-file.txt$/a /opt/test-package/data.bin' "$WORK_DIR/SPECS/test-package.spec"
        ;;
    large)
        echo "==> Adding 100MB data file..."
        dd if=/dev/urandom of="$WORK_DIR/SOURCES/data.bin" bs=1M count=100 2>/dev/null
        # Update spec to include data file
        sed -i '/^Source0:/a Source1:        data.bin' "$WORK_DIR/SPECS/test-package.spec"
        sed -i '/cp %{SOURCE0}/a cp %{SOURCE1} %{buildroot}/opt/test-package/' "$WORK_DIR/SPECS/test-package.spec"
        sed -i '/test-file.txt$/a /opt/test-package/data.bin' "$WORK_DIR/SPECS/test-package.spec"
        ;;
    *)
        echo "ERROR: Invalid size tier: $SIZE_TIER (use: small, medium, large)"
        exit 2
        ;;
esac

# Build RPM
rpmbuild --define "_topdir $WORK_DIR" -bb "$WORK_DIR/SPECS/test-package.spec"

# Create output directory and move artifact
mkdir -p "$OUTPUT_DIR"
find "$WORK_DIR/RPMS" -name "*.rpm" -exec cp {} "$OUTPUT_DIR/" \;

echo "==> Generated RPM package in $OUTPUT_DIR:"
ls -la "$OUTPUT_DIR"
