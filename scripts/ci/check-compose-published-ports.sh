#!/usr/bin/env bash
#
# Regression gate for #4480: the default stock compose stack publishes only
# the reverse proxy on all host interfaces.
#
# A `ports:` entry without an address binds 0.0.0.0 (and ::), and on Docker
# it also bypasses host firewalld/ufw rules. docker-compose.yml published
# Postgres (fixed registry/registry login), OpenSearch (security plugin
# disabled), Trivy and OpenSCAP that way, so a default `docker compose up -d`
# on a host with a routable address exposed the metadata database and the
# search index to the network. The backend reaches all four on the compose
# network and needs none of those ports.
#
# Invariant: in every service that starts by default (no `profiles:`), other
# than `caddy`, each published port is bound to a loopback address
# (127.0.0.1, ::1 or localhost). Opt-in profiles (Dependency-Track) are out of
# scope.
#
# Usage: check-compose-published-ports.sh [compose-file]

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE="${1:-$ROOT/docker-compose.yml}"

python3 - "$COMPOSE" <<'PY'
import sys

import yaml

PUBLIC_SERVICES = {"caddy"}
LOOPBACK = {"127.0.0.1", "::1", "[::1]", "localhost"}

path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    compose = yaml.safe_load(f)


def host_ip(port):
    """Host address of one `ports:` entry, or None when it binds all interfaces."""
    if isinstance(port, dict):
        return port.get("host_ip") or None
    spec = str(port).split("/", 1)[0]
    if spec.startswith("["):  # [::1]:8080:80
        return spec[: spec.index("]") + 1]
    parts = spec.split(":")
    return parts[0] if len(parts) == 3 else None


errors = []
services = compose.get("services") or {}
if "postgres" not in services:
    errors.append(f"{path}: no postgres service; the gate would check nothing")
for name, service in services.items():
    service = service or {}
    if name in PUBLIC_SERVICES or service.get("profiles"):
        continue
    for port in service.get("ports") or []:
        ip = host_ip(port)
        if ip not in LOOPBACK:
            errors.append(
                f"{path}: service {name!r} publishes {port!r} on "
                f"{ip or 'all interfaces'}; drop the port or bind it to 127.0.0.1"
            )

if errors:
    for e in errors:
        print(f"FAIL: {e}", file=sys.stderr)
    sys.exit(1)
print("OK: only the reverse proxy is published beyond loopback by default")
PY
