#!/usr/bin/env bash
#
# Regression gate for #4482 (and #1772): every native package-format prefix
# the backend mounts must be routed to the backend by the stock Caddyfile.
#
# docker/Caddyfile sends each format prefix straight to backend:8080 and lets
# everything else fall through to the web UI. A prefix missing from that list
# reaches the Next.js container instead, which answers with its HTML 404 for
# any prefix its own proxy list lacks. That is how `/pacman` and `/bazel`
# never worked behind the stock stack, `/general` (#1772) only worked with
# unreleased web code, and `/lxc` only worked through the web middleware.
#
# The list of prefixes is derived from the source, not hardcoded: every
# `.nest(<prefix>, ...)` in the `format_routes` router of
# backend/src/api/routes.rs, with `handlers::<name>::MOUNT_PREFIX` constants
# resolved from the handler module. A mount is covered when the Caddyfile's
# `(backend_routes)` snippet has `reverse_proxy /<first-segment>/* backend:8080`
# (or `/<first-segment>*`), so `/api/cargo` is covered by `/api/*` and
# `/conda/t` by `/conda/*`.
#
# Usage: check-caddy-format-routes.sh [routes.rs] [Caddyfile]

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ROUTES="${1:-$ROOT/backend/src/api/routes.rs}"
CADDYFILE="${2:-$ROOT/docker/Caddyfile}"

python3 - "$ROUTES" "$CADDYFILE" <<'PY'
import os
import re
import sys

routes_path, caddy_path = sys.argv[1:3]
errors = []

with open(routes_path, encoding="utf-8") as f:
    routes = f.read()
m = re.search(r"let format_routes = Router::new\(\)(.*?)\n\s*\.layer\(", routes, re.S)
if not m:
    sys.exit(f"FAIL: {routes_path}: cannot find the `format_routes` router")
block = m.group(1)

handlers_dir = os.path.join(os.path.dirname(routes_path), "handlers")
mounts = []
for arg in re.findall(r"\.nest\(\s*([^,]+?)\s*,", block):
    if arg.startswith('"'):
        mounts.append(arg.strip('"'))
        continue
    const = re.fullmatch(r"handlers::(\w+)::(\w+)", arg)
    if not const:
        errors.append(f"{routes_path}: cannot resolve mount prefix {arg!r}")
        continue
    module, name = const.groups()
    path = os.path.join(handlers_dir, f"{module}.rs")
    if not os.path.exists(path):
        path = os.path.join(handlers_dir, module, "mod.rs")
    with open(path, encoding="utf-8") as f:
        value = re.search(rf'pub const {name}: &str = "([^"]+)";', f.read())
    if not value:
        errors.append(f"{path}: cannot resolve {name}")
        continue
    mounts.append(value.group(1))

if len(mounts) < 10:
    errors.append(f"{routes_path}: found only {len(mounts)} format mounts; the parser is broken")

with open(caddy_path, encoding="utf-8") as f:
    caddy = f.read()
snippet = re.search(r"^\(backend_routes\)\s*\{(.*?)^\}", caddy, re.S | re.M)
if not snippet:
    sys.exit(f"FAIL: {caddy_path}: no (backend_routes) snippet")
routed = set()
for line in snippet.group(1).splitlines():
    r = re.match(r"\s*reverse_proxy\s+/([^/\s*]+)(?:/\*|\*)\s+backend:8080\s*$", line)
    if r:
        routed.add(r.group(1))

for mount in mounts:
    segment = mount.strip("/").split("/", 1)[0]
    if segment not in routed:
        errors.append(
            f"{caddy_path}: backend mounts {mount} but (backend_routes) has no "
            f"`reverse_proxy /{segment}/* backend:8080`; requests fall through to the web UI"
        )

if errors:
    for e in errors:
        print(f"FAIL: {e}", file=sys.stderr)
    sys.exit(1)
print(f"OK: all {len(mounts)} backend format mounts are routed by the Caddyfile")
PY
