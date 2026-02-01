#!/usr/bin/env bash
set -euo pipefail

echo "==> [05] Installing Artifact Keeper ${ARTIFACT_KEEPER_VERSION}"

# Download pre-built binary from GitHub Releases
curl -fsSL "https://github.com/artifact-keeper/artifact-keeper/releases/download/v${ARTIFACT_KEEPER_VERSION}/artifact-keeper-linux-amd64" \
  -o /usr/local/bin/artifact-keeper
chmod +x /usr/local/bin/artifact-keeper

# Download and extract frontend
curl -fsSL "https://github.com/artifact-keeper/artifact-keeper/releases/download/v${ARTIFACT_KEEPER_VERSION}/artifact-keeper-frontend-dist.tar.gz" \
  -o /tmp/frontend.tar.gz
mkdir -p /opt/artifact-keeper/frontend
tar -xzf /tmp/frontend.tar.gz -C /opt/artifact-keeper/frontend --strip-components=1
chown -R artifact-keeper:artifact-keeper /opt/artifact-keeper/frontend
rm /tmp/frontend.tar.gz

# Environment file (will be populated by first-boot)
cat > /etc/artifact-keeper/artifact-keeper.env <<'EOF'
RUST_LOG=info
HOST=127.0.0.1
PORT=8080
STORAGE_BACKEND=filesystem
STORAGE_PATH=/var/lib/artifact-keeper/storage
BACKUP_PATH=/var/lib/artifact-keeper/backups
PLUGIN_DIR=/var/lib/artifact-keeper/plugins
SCAN_WORKSPACE=/var/lib/artifact-keeper/scan-workspace
TRIVY_SERVER_URL=http://127.0.0.1:8090
# Set by first-boot:
# DATABASE_URL=
# JWT_SECRET=
# MEILISEARCH_URL=
# MEILISEARCH_API_KEY=
EOF
chmod 600 /etc/artifact-keeper/artifact-keeper.env
chown artifact-keeper:artifact-keeper /etc/artifact-keeper/artifact-keeper.env

# Systemd service
cat > /etc/systemd/system/artifact-keeper.service <<'EOF'
[Unit]
Description=Artifact Keeper registry server
After=network.target postgresql.service meilisearch.service trivy-server.service
Requires=postgresql.service meilisearch.service

[Service]
Type=simple
User=artifact-keeper
Group=artifact-keeper
ExecStart=/usr/local/bin/artifact-keeper
EnvironmentFile=/etc/artifact-keeper/artifact-keeper.env
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable artifact-keeper

# Log rotation
cat > /etc/logrotate.d/artifact-keeper <<'EOF'
/var/log/artifact-keeper/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    copytruncate
}
EOF

mkdir -p /var/log/artifact-keeper
chown artifact-keeper:artifact-keeper /var/log/artifact-keeper

echo "==> [05] Artifact Keeper ${ARTIFACT_KEEPER_VERSION} installed"
