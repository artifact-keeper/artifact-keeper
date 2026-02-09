#!/bin/bash
# Generate self-signed CA and server certificates for E2E testing
# Usage: ./generate-certs.sh [output_dir]
set -euo pipefail

OUTPUT_DIR="${1:-.pki}"
DAYS_VALID=365
CA_CN="Test CA"
SERVER_CN="localhost"

mkdir -p "$OUTPUT_DIR"

echo "==> Generating CA private key..."
openssl genrsa -out "$OUTPUT_DIR/ca.key" 4096

echo "==> Generating CA certificate..."
openssl req -x509 -new -nodes \
  -key "$OUTPUT_DIR/ca.key" \
  -sha256 \
  -days "$DAYS_VALID" \
  -out "$OUTPUT_DIR/ca.crt" \
  -subj "/CN=$CA_CN/O=Artifact Keeper Test/C=US"

echo "==> Generating server private key..."
openssl genrsa -out "$OUTPUT_DIR/server.key" 2048

echo "==> Generating server certificate signing request..."
openssl req -new \
  -key "$OUTPUT_DIR/server.key" \
  -out "$OUTPUT_DIR/server.csr" \
  -subj "/CN=$SERVER_CN/O=Artifact Keeper Test/C=US"

echo "==> Creating certificate extensions file..."
cat > "$OUTPUT_DIR/server.ext" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = backend
DNS.3 = registry
DNS.4 = postgres
DNS.5 = *.test.local
IP.1 = 127.0.0.1
EOF

echo "==> Signing server certificate with CA..."
openssl x509 -req \
  -in "$OUTPUT_DIR/server.csr" \
  -CA "$OUTPUT_DIR/ca.crt" \
  -CAkey "$OUTPUT_DIR/ca.key" \
  -CAcreateserial \
  -out "$OUTPUT_DIR/server.crt" \
  -days "$DAYS_VALID" \
  -sha256 \
  -extfile "$OUTPUT_DIR/server.ext"

echo "==> Cleaning up temporary files..."
rm -f "$OUTPUT_DIR/server.csr" "$OUTPUT_DIR/server.ext" "$OUTPUT_DIR/ca.srl"

echo "==> Setting permissions..."
chmod 600 "$OUTPUT_DIR/ca.key" "$OUTPUT_DIR/server.key"
chmod 644 "$OUTPUT_DIR/ca.crt" "$OUTPUT_DIR/server.crt"

echo ""
echo "PKI files generated in $OUTPUT_DIR:"
ls -la "$OUTPUT_DIR"
echo ""
echo "CA Certificate: $OUTPUT_DIR/ca.crt"
echo "Server Certificate: $OUTPUT_DIR/server.crt"
echo "Server Key: $OUTPUT_DIR/server.key (keep private!)"
