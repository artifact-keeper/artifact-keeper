#!/usr/bin/env bash
#
# Regression gate for #4481: every first-party image in the stock compose
# stack follows a documented version pin.
#
# docker-compose.yml told operators to pin a release with
# ARTIFACT_KEEPER_VERSION, but only the backend honoured it: openscap (released
# with the same tag as the backend) and web were hardcoded to `:latest`, so a
# "pinned" stack still pulled whatever `latest` was for two of its images.
#
# Invariants for docker-compose.yml:
#   - artifact-keeper-backend and artifact-keeper-openscap images are tagged
#     ${ARTIFACT_KEEPER_VERSION:-latest} (released together, same tag)
#   - the artifact-keeper-web image is tagged
#     ${ARTIFACT_KEEPER_WEB_VERSION:-latest} (web releases are decoupled, #2708)
#   - no other ghcr.io/artifact-keeper image is left on a literal tag
# and .env.example documents both variables.
#
# Usage: check-compose-version-pins.sh [compose-file] [env-example]

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE="${1:-$ROOT/docker-compose.yml}"
ENV_EXAMPLE="${2:-$ROOT/.env.example}"

python3 - "$COMPOSE" "$ENV_EXAMPLE" <<'PY'
import re
import sys

import yaml

compose_path, env_path = sys.argv[1:3]
EXPECTED_TAG = {
    "artifact-keeper-backend": "${ARTIFACT_KEEPER_VERSION:-latest}",
    "artifact-keeper-openscap": "${ARTIFACT_KEEPER_VERSION:-latest}",
    "artifact-keeper-web": "${ARTIFACT_KEEPER_WEB_VERSION:-latest}",
}

with open(compose_path, encoding="utf-8") as f:
    compose = yaml.safe_load(f)

errors = []
seen = set()
for name, service in (compose.get("services") or {}).items():
    image = str((service or {}).get("image") or "")
    m = re.fullmatch(r"(?:docker\.io/)?(?:ghcr\.io/artifact-keeper/|artifactkeeper/)"
                     r"(artifact-keeper-[a-z-]+|backend|web|openscap):(.+)", image)
    if not m:
        continue
    repo, tag = m.group(1), m.group(2)
    if not repo.startswith("artifact-keeper-"):
        repo = f"artifact-keeper-{repo}"
    expected = EXPECTED_TAG.get(repo)
    if expected is None:
        if not tag.startswith("${"):
            errors.append(
                f"{compose_path}: service {name!r} pins {image!r} to a literal tag; "
                "it ignores every documented version variable"
            )
        continue
    seen.add(repo)
    if tag != expected:
        errors.append(
            f"{compose_path}: service {name!r} uses {image!r}; tag must be {expected}"
        )

for repo in EXPECTED_TAG:
    if repo not in seen:
        errors.append(f"{compose_path}: no service runs the {repo} image")

with open(env_path, encoding="utf-8") as f:
    env_example = f.read()
for var in ("ARTIFACT_KEEPER_VERSION", "ARTIFACT_KEEPER_WEB_VERSION"):
    if not re.search(rf"^{var}=", env_example, re.M):
        errors.append(f"{env_path}: {var} is not documented")

if errors:
    for e in errors:
        print(f"FAIL: {e}", file=sys.stderr)
    sys.exit(1)
print("OK: backend/openscap follow ARTIFACT_KEEPER_VERSION, web follows ARTIFACT_KEEPER_WEB_VERSION")
PY
