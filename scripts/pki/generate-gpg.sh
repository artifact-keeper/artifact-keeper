#!/bin/bash
# Generate GPG keys for RPM/Debian package signing in E2E testing
# Usage: ./generate-gpg.sh [output_dir]
set -euo pipefail

OUTPUT_DIR="${1:-.pki}"
KEY_NAME="Artifact Keeper Test"
KEY_EMAIL="test@artifact-keeper.local"
KEY_COMMENT="E2E Testing Key"

mkdir -p "$OUTPUT_DIR"

# Create a temporary GNUPGHOME to avoid polluting user's keyring
export GNUPGHOME="$(mktemp -d)"
trap 'rm -rf "$GNUPGHOME"' EXIT

echo "==> Generating GPG key pair..."

# Generate key using batch mode (non-interactive)
cat > "$GNUPGHOME/keygen.conf" << EOF
%echo Generating test GPG key
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: $KEY_NAME
Name-Comment: $KEY_COMMENT
Name-Email: $KEY_EMAIL
Expire-Date: 1y
%no-protection
%commit
%echo Done
EOF

gpg --batch --generate-key "$GNUPGHOME/keygen.conf"

echo "==> Exporting public key..."
gpg --armor --export "$KEY_EMAIL" > "$OUTPUT_DIR/gpg-signing.pub"

echo "==> Exporting private key..."
gpg --armor --export-secret-keys "$KEY_EMAIL" > "$OUTPUT_DIR/gpg-signing.key"

echo "==> Getting key ID..."
KEY_ID=$(gpg --list-keys --keyid-format SHORT "$KEY_EMAIL" | grep pub | awk '{print $2}' | cut -d'/' -f2)
echo "$KEY_ID" > "$OUTPUT_DIR/gpg-key-id.txt"

echo "==> Setting permissions..."
chmod 600 "$OUTPUT_DIR/gpg-signing.key"
chmod 644 "$OUTPUT_DIR/gpg-signing.pub" "$OUTPUT_DIR/gpg-key-id.txt"

echo ""
echo "GPG files generated in $OUTPUT_DIR:"
ls -la "$OUTPUT_DIR"/gpg-*
echo ""
echo "Public Key: $OUTPUT_DIR/gpg-signing.pub"
echo "Private Key: $OUTPUT_DIR/gpg-signing.key (keep private!)"
echo "Key ID: $KEY_ID"
