#!/usr/bin/env bash
# Reset the demo instance to a clean state.
# Intended to run as a daily cron job on the demo EC2 host.
#
# Crontab example:
#   0 4 * * * /opt/artifact-keeper/deploy/demo/reset-demo.sh >> /var/log/demo-reset.log 2>&1

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Starting demo reset..."

# Bring everything down and remove volumes
docker compose -f docker-compose.demo.yml down -v

# Pull latest images
docker compose -f docker-compose.demo.yml pull

# Start fresh
docker compose -f docker-compose.demo.yml up -d

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Demo reset complete."
