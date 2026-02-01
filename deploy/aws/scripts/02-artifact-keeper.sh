#!/usr/bin/env bash
set -euo pipefail

echo "==> [02] Setting up Artifact Keeper (Docker Compose)"

AK_DIR="/opt/artifact-keeper"
mkdir -p "${AK_DIR}"

# Copy compose file and first-boot script from packer upload
cp /tmp/ak-scripts/docker-compose.yml "${AK_DIR}/docker-compose.yml"
cp /tmp/ak-scripts/first-boot.sh "${AK_DIR}/first-boot.sh"
cp /tmp/ak-scripts/nginx-host.conf "${AK_DIR}/nginx-host.conf"
chmod +x "${AK_DIR}/first-boot.sh"

# Create data directories
mkdir -p /data/{postgres,meilisearch,storage,trivy-cache}

# Pull images now so first boot is fast
export ARTIFACT_KEEPER_VERSION="${ARTIFACT_KEEPER_VERSION}"
cd "${AK_DIR}"

# Write the .env with the version tag
cat > "${AK_DIR}/.env" <<EOF
ARTIFACT_KEEPER_VERSION=${ARTIFACT_KEEPER_VERSION}
# Populated by first-boot:
DB_PASSWORD=changeme
JWT_SECRET=changeme
MEILI_MASTER_KEY=changeme
EOF
chmod 600 "${AK_DIR}/.env"

docker compose pull

# Systemd service for docker compose
cat > /etc/systemd/system/artifact-keeper.service <<'EOF'
[Unit]
Description=Artifact Keeper (Docker Compose)
After=docker.service artifact-keeper-first-boot.service
Requires=docker.service
PartOf=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/artifact-keeper
ExecStart=/usr/bin/docker compose up -d --wait
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
EOF

# First-boot one-shot service
cat > /etc/systemd/system/artifact-keeper-first-boot.service <<'EOF'
[Unit]
Description=Artifact Keeper first-boot configuration
After=docker.service network-online.target
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
systemctl enable artifact-keeper

echo "==> [02] Artifact Keeper configured"
