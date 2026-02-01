#!/usr/bin/env bash
set -euo pipefail

echo "==> [07] Installing first-boot service"

# The first-boot script runs once on initial launch to generate secrets,
# initialize the database, and optionally configure SSL.

cat > /opt/artifact-keeper/first-boot.sh <<'FIRSTBOOT'
#!/usr/bin/env bash
set -euo pipefail

MARKER="/opt/artifact-keeper/.first-boot-complete"
CREDS_FILE="/opt/artifact-keeper/.credentials"

if [ -f "$MARKER" ]; then
    echo "First boot already completed, skipping."
    exit 0
fi

echo "==> Artifact Keeper first-boot configuration"

# -------------------------------------------------------------------------
# 1. Generate secrets
# -------------------------------------------------------------------------
DB_PASSWORD=$(openssl rand -hex 24)
JWT_SECRET=$(openssl rand -hex 32)
MEILI_KEY=$(openssl rand -hex 24)
ADMIN_PASSWORD=$(openssl rand -base64 16 | tr -d '=/+' | head -c 16)

# -------------------------------------------------------------------------
# 2. Configure PostgreSQL
# -------------------------------------------------------------------------
echo "==> Setting up PostgreSQL database"
sudo -u postgres psql <<SQL
CREATE USER artifact_keeper WITH PASSWORD '${DB_PASSWORD}';
CREATE DATABASE artifact_keeper OWNER artifact_keeper;
GRANT ALL PRIVILEGES ON DATABASE artifact_keeper TO artifact_keeper;
SQL

# -------------------------------------------------------------------------
# 3. Update Meilisearch config
# -------------------------------------------------------------------------
echo "MEILI_MASTER_KEY=${MEILI_KEY}" > /etc/artifact-keeper/meilisearch.env
chmod 600 /etc/artifact-keeper/meilisearch.env
systemctl restart meilisearch

# -------------------------------------------------------------------------
# 4. Update Artifact Keeper config
# -------------------------------------------------------------------------
cat > /etc/artifact-keeper/artifact-keeper.env <<ENV
RUST_LOG=info
HOST=127.0.0.1
PORT=8080
DATABASE_URL=postgresql://artifact_keeper:${DB_PASSWORD}@127.0.0.1:5432/artifact_keeper
JWT_SECRET=${JWT_SECRET}
STORAGE_BACKEND=filesystem
STORAGE_PATH=/var/lib/artifact-keeper/storage
BACKUP_PATH=/var/lib/artifact-keeper/backups
PLUGIN_DIR=/var/lib/artifact-keeper/plugins
SCAN_WORKSPACE=/var/lib/artifact-keeper/scan-workspace
MEILISEARCH_URL=http://127.0.0.1:7700
MEILISEARCH_API_KEY=${MEILI_KEY}
TRIVY_SERVER_URL=http://127.0.0.1:8090
ADMIN_BOOTSTRAP_PASSWORD=${ADMIN_PASSWORD}
ENV
chmod 600 /etc/artifact-keeper/artifact-keeper.env
chown artifact-keeper:artifact-keeper /etc/artifact-keeper/artifact-keeper.env

# -------------------------------------------------------------------------
# 5. Read user-data for optional domain configuration
# -------------------------------------------------------------------------
DOMAIN=""
ADMIN_EMAIL=""
if TOKEN=$(curl -s --max-time 2 -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null); then
    USERDATA=$(curl -s --max-time 2 -H "X-aws-ec2-metadata-token: ${TOKEN}" \
        "http://169.254.169.254/latest/user-data" 2>/dev/null || true)
    if [ -n "$USERDATA" ]; then
        DOMAIN=$(echo "$USERDATA" | grep -oP '^DOMAIN=\K.*' || true)
        ADMIN_EMAIL=$(echo "$USERDATA" | grep -oP '^ADMIN_EMAIL=\K.*' || true)
    fi
fi

# -------------------------------------------------------------------------
# 6. Configure SSL if domain is provided
# -------------------------------------------------------------------------
if [ -n "$DOMAIN" ] && [ -n "$ADMIN_EMAIL" ]; then
    echo "==> Configuring SSL for ${DOMAIN}"
    # Update nginx server_name
    sed -i "s/server_name _;/server_name ${DOMAIN};/" /etc/nginx/sites-available/artifact-keeper
    systemctl reload nginx

    # Request Let's Encrypt certificate
    certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "$ADMIN_EMAIL" --redirect || \
        echo "WARNING: Certbot failed — continuing without SSL"
fi

# -------------------------------------------------------------------------
# 7. Enable firewall and start services
# -------------------------------------------------------------------------
echo "==> Starting services"
ufw --force enable
systemctl restart artifact-keeper
systemctl restart nginx

# -------------------------------------------------------------------------
# 8. Write credentials file and marker
# -------------------------------------------------------------------------
cat > "$CREDS_FILE" <<CREDS
=====================================
  Artifact Keeper Credentials
=====================================
Admin Username: admin
Admin Password: ${ADMIN_PASSWORD}

Database User:  artifact_keeper
Database Pass:  ${DB_PASSWORD}

Meilisearch Key: ${MEILI_KEY}
JWT Secret:      ${JWT_SECRET}
=====================================

Access your instance at:
  http://$(curl -s --max-time 2 -H "X-aws-ec2-metadata-token: ${TOKEN}" \
    "http://169.254.169.254/latest/meta-data/public-ipv4" 2>/dev/null || echo "YOUR_IP")

CREDS
chmod 600 "$CREDS_FILE"

touch "$MARKER"
echo "==> First boot complete! Credentials saved to ${CREDS_FILE}"
FIRSTBOOT

chmod +x /opt/artifact-keeper/first-boot.sh

# Systemd one-shot service
cat > /etc/systemd/system/artifact-keeper-first-boot.service <<'EOF'
[Unit]
Description=Artifact Keeper first-boot configuration
After=network-online.target postgresql.service
Wants=network-online.target
Before=artifact-keeper.service

[Service]
Type=oneshot
ExecStart=/opt/artifact-keeper/first-boot.sh
RemainAfterExit=yes
StandardOutput=journal+console

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable artifact-keeper-first-boot

echo "==> [07] First-boot service installed"
