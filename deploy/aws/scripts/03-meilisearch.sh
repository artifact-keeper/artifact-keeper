#!/usr/bin/env bash
set -euo pipefail

echo "==> [03] Installing Meilisearch ${MEILISEARCH_VERSION}"

curl -fsSL "https://github.com/meilisearch/meilisearch/releases/download/v${MEILISEARCH_VERSION}/meilisearch-linux-amd64" \
  -o /usr/local/bin/meilisearch
chmod +x /usr/local/bin/meilisearch

# Data directory
mkdir -p /var/lib/meilisearch
chown artifact-keeper:artifact-keeper /var/lib/meilisearch

# Systemd service (master key will be set by first-boot)
cat > /etc/systemd/system/meilisearch.service <<'EOF'
[Unit]
Description=Meilisearch search engine
After=network.target

[Service]
Type=simple
User=artifact-keeper
Group=artifact-keeper
ExecStart=/usr/local/bin/meilisearch \
  --db-path /var/lib/meilisearch/data.ms \
  --http-addr 127.0.0.1:7700 \
  --env production
EnvironmentFile=/etc/artifact-keeper/meilisearch.env
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

mkdir -p /etc/artifact-keeper
echo "MEILI_MASTER_KEY=changeme" > /etc/artifact-keeper/meilisearch.env
chmod 600 /etc/artifact-keeper/meilisearch.env

systemctl daemon-reload
systemctl enable meilisearch

echo "==> [03] Meilisearch ${MEILISEARCH_VERSION} installed"
