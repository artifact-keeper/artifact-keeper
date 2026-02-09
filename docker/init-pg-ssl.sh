#!/bin/bash
# Enable SSL in PostgreSQL using mounted certificates.
# This script runs during container first-boot (as the postgres user)
# via /docker-entrypoint-initdb.d/.
set -euo pipefail

CERT_SRC="/var/lib/postgresql/certs"

if [ ! -f "$CERT_SRC/server.crt" ]; then
  echo "init-pg-ssl: no certificates found at $CERT_SRC, skipping SSL setup"
  exit 0
fi

echo "init-pg-ssl: configuring PostgreSQL SSL..."
cp "$CERT_SRC/server.crt" "$PGDATA/server.crt"
cp "$CERT_SRC/server.key" "$PGDATA/server.key"
cp "$CERT_SRC/ca.crt"     "$PGDATA/ca.crt"
chmod 600 "$PGDATA/server.key"

cat >> "$PGDATA/postgresql.conf" <<EOF
# --- SSL (added by init-pg-ssl.sh) ---
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'
ssl_ca_file = 'ca.crt'
EOF

echo "init-pg-ssl: SSL enabled"
