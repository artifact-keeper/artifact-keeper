#!/usr/bin/env bash
set -euo pipefail

MARKER="/opt/artifact-keeper/.first-boot-complete"
CREDS_FILE="/opt/artifact-keeper/.credentials"
AK_DIR="/opt/artifact-keeper"

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

# -------------------------------------------------------------------------
# 2. Write .env for Docker Compose
# -------------------------------------------------------------------------
cat > "${AK_DIR}/.env" <<EOF
ARTIFACT_KEEPER_VERSION=$(grep ARTIFACT_KEEPER_VERSION "${AK_DIR}/.env" | cut -d= -f2)
DB_PASSWORD=${DB_PASSWORD}
JWT_SECRET=${JWT_SECRET}
MEILI_MASTER_KEY=${MEILI_KEY}
EOF
chmod 600 "${AK_DIR}/.env"

# -------------------------------------------------------------------------
# 3. Read user-data for optional domain configuration
# -------------------------------------------------------------------------
DOMAIN=""
ADMIN_EMAIL=""
TOKEN=""
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
# 4. Configure Nginx
# -------------------------------------------------------------------------
rm -f /etc/nginx/sites-enabled/default
cp "${AK_DIR}/nginx-host.conf" /etc/nginx/sites-available/artifact-keeper
ln -sf /etc/nginx/sites-available/artifact-keeper /etc/nginx/sites-enabled/artifact-keeper

if [ -n "$DOMAIN" ]; then
    sed -i "s/server_name _;/server_name ${DOMAIN};/" /etc/nginx/sites-available/artifact-keeper
fi

nginx -t && systemctl restart nginx

# -------------------------------------------------------------------------
# 5. Configure SSL if domain provided
# -------------------------------------------------------------------------
if [ -n "$DOMAIN" ] && [ -n "$ADMIN_EMAIL" ]; then
    echo "==> Configuring SSL for ${DOMAIN}"
    certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "$ADMIN_EMAIL" --redirect || \
        echo "WARNING: Certbot failed — continuing without SSL"
fi

# -------------------------------------------------------------------------
# 6. Enable firewall
# -------------------------------------------------------------------------
ufw --force enable

# -------------------------------------------------------------------------
# 7. Get public IP for credentials file
# -------------------------------------------------------------------------
PUBLIC_IP=""
if [ -n "$TOKEN" ]; then
    PUBLIC_IP=$(curl -s --max-time 2 -H "X-aws-ec2-metadata-token: ${TOKEN}" \
        "http://169.254.169.254/latest/meta-data/public-ipv4" 2>/dev/null || echo "YOUR_IP")
fi

# -------------------------------------------------------------------------
# 8. Write credentials file
# -------------------------------------------------------------------------
cat > "$CREDS_FILE" <<CREDS
=====================================
  Artifact Keeper Credentials
=====================================

Access URL: ${DOMAIN:+https://${DOMAIN}}${DOMAIN:-http://${PUBLIC_IP:-YOUR_IP}}

Database Password:  ${DB_PASSWORD}
Meilisearch Key:    ${MEILI_KEY}
JWT Secret:         ${JWT_SECRET}

Docker Compose Dir: ${AK_DIR}

Manage services:
  cd ${AK_DIR}
  docker compose ps
  docker compose logs -f backend
  docker compose restart

=====================================
CREDS
chmod 600 "$CREDS_FILE"

touch "$MARKER"
echo "==> First boot complete! Credentials saved to ${CREDS_FILE}"
