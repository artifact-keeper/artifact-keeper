#!/usr/bin/env bash
#
# CI gate for issue #1316: forbid the legacy raw-string admin scope check.
#
# Authorization decisions on API-token scopes must go through the single
# canonical helper `token_service::scopes_grant_access`, which centralizes the
# `*` / `admin` wildcard policy. Re-inlining a brittle `scopes.iter().any(|s|
# s == "admin")` (or `... == "admin"` adjacent to a `*` wildcard) at an
# allow/deny site bypasses that helper and is exactly the regression this gate
# prevents.
#
# What it flags (in backend/src, OUTSIDE `#[cfg(test)]` modules):
#   * any iterator `.any(...)` closure that compares an element to "admin"
#     (the form removed from `AuthExtension::has_scope` and
#     `oci_scopes_grant`), and
#   * a `== "admin"` that sits on the same line as a `== "*"` wildcard
#     (the legacy scope-wildcard idiom).
#
# What it deliberately does NOT flag:
#   * the canonical helper `token_service::scopes_grant_access` itself, which
#     uses `.contains(&"admin".to_string())` (not an `.any()` closure and not
#     paired with a literal `== "*"`),
#   * the SSO break-glass login bypass `payload.username == "admin"` (a
#     username comparison, not a scope authz decision),
#   * the Artifactory-import config parser arm `"admin" => ...`,
#   * anything inside a `#[cfg(test)]` module (test fixtures/assertions).
#
# Exits non-zero (failing the build) on any match.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC_DIR="${1:-$ROOT/backend/src}"

# A single Python pass keeps the cfg(test) tracking and the two pattern checks
# in one place. grep/awk alone cannot reliably skip test modules.
python3 - "$SRC_DIR" <<'PY'
import os
import re
import sys

src_dir = sys.argv[1]

# Legacy authz scope-check idioms (the ones removed for #1316):
#   1. an `.any(...)` closure that compares an element to "admin"
#   2. a `== "admin"` paired with a `== "*"` wildcard on the same line
any_admin = re.compile(r'\.any\([^)]*==\s*"admin"')
wildcard_admin = re.compile(r'(==\s*"\*".*==\s*"admin"|==\s*"admin".*==\s*"\*")')

violations = []

for dirpath, _dirs, files in os.walk(src_dir):
    for name in files:
        if not name.endswith(".rs"):
            continue
        path = os.path.join(dirpath, name)
        in_test = False
        test_depth = 0  # brace depth at which the test module opened
        depth = 0
        pending_cfg_test = False
        with open(path, encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh, start=1):
                line = raw.rstrip("\n")
                stripped = line.strip()

                # Track `#[cfg(test)]` followed by a `mod ... {` block so we can
                # skip the entire test module (fixtures and assertions are
                # allowed to mention the "admin" string).
                if not in_test:
                    if stripped.startswith("#[cfg(test)]"):
                        pending_cfg_test = True
                    elif pending_cfg_test and "mod " in stripped:
                        if "{" in line:
                            in_test = True
                            test_depth = depth
                            depth += line.count("{") - line.count("}")
                            pending_cfg_test = False
                            continue
                        # `mod foo` on its own line; opening brace next line.
                        # Mark so the next `{` opens the test module.
                    elif stripped and not stripped.startswith("//"):
                        # Any other significant line cancels a dangling cfg(test)
                        # attribute (e.g. it was on a function, not a module).
                        if pending_cfg_test and "mod " not in stripped:
                            pending_cfg_test = False

                if in_test:
                    depth += line.count("{") - line.count("}")
                    if depth <= test_depth:
                        in_test = False
                    continue

                depth += line.count("{") - line.count("}")

                # Ignore line comments — a `// ... == "admin"` note is fine.
                code = line.split("//", 1)[0]
                if any_admin.search(code) or wildcard_admin.search(code):
                    violations.append((path, lineno, stripped))

if violations:
    sys.stderr.write(
        "ERROR: legacy raw-string admin scope check detected (issue #1316).\n"
        "Authorization must use token_service::scopes_grant_access instead of\n"
        "an inline `== \"admin\"` / `.any(|s| s == \"admin\")` scope match.\n\n"
    )
    for path, lineno, text in violations:
        sys.stderr.write(f"  {path}:{lineno}: {text}\n")
    sys.exit(1)

print("OK: no legacy raw-string admin scope checks found in", src_dir)
PY
