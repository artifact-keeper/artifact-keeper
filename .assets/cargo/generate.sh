#!/bin/bash
# Generate Cargo test crate
# Usage: ./generate.sh [size_tier] [version] [output_dir]
set -euo pipefail

SIZE_TIER="${1:-small}"
VERSION="${2:-1.0.0}"
OUTPUT_DIR="${3:-../generated/cargo}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "==> Generating Cargo crate (size: $SIZE_TIER, version: $VERSION)"

# Copy template files
mkdir -p "$WORK_DIR/src"
cp "$SCRIPT_DIR/Cargo.toml" "$WORK_DIR/"
cp "$SCRIPT_DIR/src/lib.rs" "$WORK_DIR/src/"

# Create README
cat > "$WORK_DIR/README.md" << EOF
# test-crate

A test crate for E2E native client testing of the Artifact Keeper registry.

## Usage

\`\`\`rust
use test_crate::hello;
println!("{}", hello());
\`\`\`
EOF

# Replace version placeholder
sed -i "s/VERSION_PLACEHOLDER/$VERSION/g" "$WORK_DIR/Cargo.toml"

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

# Package the crate
cd "$WORK_DIR"
cargo package --allow-dirty --no-verify

# Create output directory and move artifact
mkdir -p "$OUTPUT_DIR"
cp target/package/*.crate "$OUTPUT_DIR/"

echo "==> Generated Cargo crate in $OUTPUT_DIR:"
ls -la "$OUTPUT_DIR"
