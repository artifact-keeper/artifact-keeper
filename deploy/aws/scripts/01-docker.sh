#!/usr/bin/env bash
set -euo pipefail

echo "==> [01] Installing Docker and system packages"

# Base packages
apt-get update
apt-get install -y \
  ca-certificates \
  curl \
  gnupg \
  jq \
  certbot \
  python3-certbot-nginx \
  nginx \
  ufw \
  fail2ban

# Docker official GPG key and repo
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  > /etc/apt/sources.list.d/docker.list

apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Enable Docker
systemctl enable docker

# Allow ubuntu user to use docker
usermod -aG docker ubuntu

# Configure UFW (don't enable yet — first-boot will)
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow http
ufw allow https

systemctl enable fail2ban

echo "==> [01] Docker installed"
