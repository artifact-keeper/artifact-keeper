#!/bin/sh
# Entrypoint script for backend container
# Ensures data directories have correct permissions

# Create directories if they don't exist
mkdir -p /data/storage /data/backups 2>/dev/null || true

# Run the application
exec artifact-keeper "$@"
