#!/usr/bin/env bash
# Start the local development stack.
#
# Usage:
#   ./scripts/dev.sh          # Start postgres + run migrations
#   ./scripts/dev.sh stop     # Stop postgres
#   ./scripts/dev.sh reset    # Wipe DB volume and restart fresh

set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE_FILE="docker-compose.local-dev.yml"
ENV_FILE=".env.local-dev"

case "${1:-start}" in
  start)
    echo "==> Starting local-dev Postgres..."
    docker compose -f "$COMPOSE_FILE" up -d

    echo "==> Waiting for Postgres to be ready..."
    until docker exec artifact-keeper-dev-db pg_isready -U registry -d artifact_registry -q 2>/dev/null; do
      sleep 1
    done

    echo "==> Running migrations..."
    set -a; source "$ENV_FILE"; set +a
    cargo sqlx migrate run --source backend/migrations

    echo ""
    echo "Postgres is running on localhost:30432"
    echo ""
    echo "Start the backend:"
    echo "  source .env.local-dev && cargo run -p artifact-keeper-backend"
    echo ""
    ;;

  stop)
    echo "==> Stopping local-dev stack..."
    docker compose -f "$COMPOSE_FILE" down
    ;;

  reset)
    echo "==> Resetting local-dev stack (wiping DB)..."
    docker compose -f "$COMPOSE_FILE" down -v
    exec "$0" start
    ;;

  *)
    echo "Usage: $0 {start|stop|reset}"
    exit 1
    ;;
esac
