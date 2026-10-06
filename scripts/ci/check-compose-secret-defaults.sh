#!/usr/bin/env bash
#
# Regression gate for #4478: the stock compose stack must not ship a secret
# default that the backend rejects at startup.
#
# The backend refuses every known JWT_SECRET placeholder (KNOWN_PLACEHOLDERS /
# WEAK_SUBSTRINGS in backend/src/config.rs) and refuses an AK_WEBHOOK_SECRET_KEY
# that is set but does not decode to 32 bytes. docker-compose.yml defaulted
# both to such values, and .env.example carried a rejected JWT_SECRET, so a
# fresh `docker compose up -d` (or `cp .env.example .env`) gave a backend that
# restarted forever.
#
# Invariants:
#   docker-compose.yml, backend service:
#     - JWT_SECRET has no non-empty default (`${JWT_SECRET:-}` or `${JWT_SECRET}`)
#     - AK_WEBHOOK_SECRET_KEY has no value at all, so compose passes it through
#       only when the operator defines it (an empty string is "set but
#       invalid" and stops the backend, an unset key only warns)
#   .env.example:
#     - JWT_SECRET is present and empty
#     - AK_WEBHOOK_SECRET_KEY is not set to anything uncommented
#   scripts/install.sh:
#     - writes AK_WEBHOOK_SECRET_KEY into the generated .env (#4313)
#
# Usage: check-compose-secret-defaults.sh [compose-file] [env-example] [install.sh]

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE="${1:-$ROOT/docker-compose.yml}"
ENV_EXAMPLE="${2:-$ROOT/.env.example}"
INSTALLER="${3:-$ROOT/scripts/install.sh}"

python3 - "$COMPOSE" "$ENV_EXAMPLE" "$INSTALLER" <<'PY'
import re
import sys

import yaml

compose_path, env_path, installer_path = sys.argv[1:4]
errors = []

with open(compose_path, encoding="utf-8") as f:
    compose = yaml.safe_load(f)
env = (compose.get("services", {}).get("backend", {}) or {}).get("environment", {}) or {}
if isinstance(env, list):
    env = dict(item.split("=", 1) if "=" in item else (item, None) for item in env)

jwt = env.get("JWT_SECRET")
if jwt is not None and not re.fullmatch(r"\$\{JWT_SECRET(:?-)?\}", str(jwt)):
    errors.append(
        f"{compose_path}: backend JWT_SECRET is {jwt!r}; it must have no default "
        "(use ${JWT_SECRET:-}) so an unset secret fails once with the backend's "
        "own error instead of a placeholder the backend rejects"
    )

if "AK_WEBHOOK_SECRET_KEY" in env and env["AK_WEBHOOK_SECRET_KEY"] is not None:
    errors.append(
        f"{compose_path}: backend AK_WEBHOOK_SECRET_KEY is "
        f"{env['AK_WEBHOOK_SECRET_KEY']!r}; declare it with no value so it is "
        "passed through only when set (a placeholder or empty string stops the backend)"
    )

jwt_lines = []
with open(env_path, encoding="utf-8") as f:
    for n, line in enumerate(f, 1):
        m = re.match(r"^\s*(JWT_SECRET|AK_WEBHOOK_SECRET_KEY)\s*=(.*)$", line)
        if not m:
            continue
        name, value = m.group(1), m.group(2).strip()
        if name == "JWT_SECRET":
            jwt_lines.append(n)
            if value:
                errors.append(
                    f"{env_path}:{n}: JWT_SECRET={value!r}; leave it empty with the "
                    "generating command in a comment"
                )
        else:
            errors.append(
                f"{env_path}:{n}: AK_WEBHOOK_SECRET_KEY is set uncommented; an empty "
                "or placeholder value stops the backend, keep it commented out"
            )
if not jwt_lines:
    errors.append(f"{env_path}: no JWT_SECRET= line; it must document the required secret")

with open(installer_path, encoding="utf-8") as f:
    installer = f.read()
if not re.search(r"^AK_WEBHOOK_SECRET_KEY=\$\{AK_WEBHOOK_SECRET_KEY\}$", installer, re.M):
    errors.append(
        f"{installer_path}: the generated .env does not set AK_WEBHOOK_SECRET_KEY (#4313)"
    )

if errors:
    for e in errors:
        print(f"FAIL: {e}", file=sys.stderr)
    sys.exit(1)
print("OK: compose, .env.example and the installer ship no secret the backend rejects")
PY
