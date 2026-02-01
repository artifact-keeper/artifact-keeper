#!/usr/bin/env bash
set -euo pipefail

echo "==> [01] System packages and base configuration"

apt-get update
apt-get upgrade -y
apt-get install -y \
  ca-certificates \
  curl \
  gnupg \
  jq \
  lsb-release \
  nginx \
  certbot \
  python3-certbot-nginx \
  unzip \
  wget \
  ufw \
  fail2ban \
  logrotate \
  htop \
  awscli

# Create artifact-keeper system user
useradd --system --shell /bin/false --home-dir /opt/artifact-keeper --create-home artifact-keeper

# Create data directories
mkdir -p /var/lib/artifact-keeper/{storage,backups,plugins,scan-workspace}
chown -R artifact-keeper:artifact-keeper /var/lib/artifact-keeper

# Configure UFW firewall (don't enable yet — first-boot will do that)
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow http
ufw allow https

# Configure fail2ban
systemctl enable fail2ban

echo "==> [01] System setup complete"
