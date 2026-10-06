#!/usr/bin/env bash
#
# Regression gate for #4479: every image in the stock docker-compose.yml must
# be fully qualified with its registry host.
#
# A short name such as `postgres:18-alpine` is resolved by the container
# engine, not by the compose file. Under podman with the Fedora default
# `short-name-mode = "enforcing"` it matched a locally cached
# `ghcr.io/artifact-keeper/ci-mirror/postgres:18-alpine` before any registry
# was consulted, and on hosts with several `unqualified-search-registries` it
# needs an alias or a TTY prompt that compose does not have. Naming the
# registry (`docker.io/library/postgres:18-alpine`) makes every host pull the
# same image.
#
# An image reference is fully qualified when its first path component is a
# registry host: it contains a `.` or a `:`, or is `localhost`.
#
# Usage: check-compose-image-names.sh [compose-file ...]

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [ "$#" -eq 0 ]; then
  set -- "$ROOT/docker-compose.yml"
fi

python3 - "$@" <<'PY'
import sys

import yaml

errors = []
checked = 0
for path in sys.argv[1:]:
    with open(path, encoding="utf-8") as f:
        compose = yaml.safe_load(f)
    for name, service in (compose.get("services") or {}).items():
        image = (service or {}).get("image")
        if not image:
            continue
        checked += 1
        first, sep, _ = str(image).partition("/")
        qualified = bool(sep) and ("." in first or ":" in first or first == "localhost")
        if not qualified:
            errors.append(
                f"{path}: service {name!r} uses short image name {image!r}; "
                "name the registry (e.g. docker.io/library/<image>:<tag>)"
            )

if errors:
    for e in errors:
        print(f"FAIL: {e}", file=sys.stderr)
    sys.exit(1)
if checked == 0:
    print("FAIL: no service images found; the gate would check nothing", file=sys.stderr)
    sys.exit(1)
print(f"OK: {checked} compose image reference(s) are fully qualified")
PY
