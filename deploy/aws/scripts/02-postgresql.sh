#!/usr/bin/env bash
set -euo pipefail

echo "==> [02] Installing PostgreSQL ${POSTGRESQL_VERSION}"

# Add PostgreSQL APT repository
curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor -o /usr/share/keyrings/postgresql.gpg
echo "deb [signed-by=/usr/share/keyrings/postgresql.gpg] http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
  > /etc/apt/sources.list.d/pgdg.list

apt-get update
apt-get install -y "postgresql-${POSTGRESQL_VERSION}"

# PostgreSQL will be configured by first-boot (DB user, password, database)
# For now just make sure it's enabled
systemctl enable postgresql

echo "==> [02] PostgreSQL ${POSTGRESQL_VERSION} installed"
