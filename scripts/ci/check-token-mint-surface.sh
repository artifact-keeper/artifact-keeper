#!/usr/bin/env bash
#
# CI gate for issue #1315 (epic #1617 -> #1615 auth consolidation):
# pin the exact set of token-minting endpoints in the API tree.
#
# WHY THIS PIN IS LOAD-BEARING
# ----------------------------
# Every token-minting HTTP handler ultimately calls the single mint
# primitive `AuthService::generate_api_token`. Each such handler must, BEFORE
# minting, refuse to grant admin-class scopes to a non-admin caller -- either
# by routing the requested scopes through
# `token_service::enforce_admin_only_scopes` (self-or-admin endpoints), or by
# gating the whole handler behind `require_admin` (admin-only endpoints).
#
# PRs #1261 and #1306 patched the scope-content policy on each existing
# endpoint individually. The structural risk (issue #1315) is that a 6th
# token-minting endpoint added later silently re-opens the
# privilege-escalation hole because the author forgot the reject rule.
#
# This gate enumerates every PRODUCTION call site of `generate_api_token` in
# `backend/src/api/handlers` (excluding `#[cfg(test)]` modules) and asserts the
# set is EXACTLY the reviewed list below. Adding a new token-minting endpoint
# fails this gate until the author updates `EXPECTED` here -- forcing a
# deliberate, reviewed change. The gate additionally verifies that each owning
# handler file references a reject rule (`enforce_admin_only_scopes` or
# `require_admin`), so a new mint site cannot land without an authz guard.
#
# Mirrors the style of `scripts/ci/check-no-legacy-admin-scope.sh` (#1316) and
# the "Lint migration slots are unique" CI step.
#
# Exits non-zero (failing the build) on any drift.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HANDLERS_DIR="${1:-$ROOT/backend/src/api/handlers}"

python3 - "$HANDLERS_DIR" <<'PY'
import os
import sys

handlers_dir = sys.argv[1]

# ---------------------------------------------------------------------------
# THE PINNED SET. Each entry is a production token-minting handler:
#   relative file (under handlers/)  ->  reject rule it MUST enforce.
#
# "scopes"  => the handler funnels requested scopes through
#              token_service::enforce_admin_only_scopes (self-or-admin
#              endpoints: a non-admin may mint a token, but never one bearing
#              an admin-class scope).
# "admin"   => the whole handler is gated by require_admin (admin-only
#              endpoint: only an admin can reach the mint at all).
#
# To add a new token-minting endpoint you MUST add it here in the same PR
# that adds the route -- that is the deliberate, reviewed change #1315 wants.
# ---------------------------------------------------------------------------
EXPECTED = {
    "auth.rs": "scopes",              # POST /api/v1/auth/tokens
    "profile.rs": "scopes",           # POST /api/v1/profile/access-tokens
    "users.rs": "scopes",             # POST /api/v1/users/:id/tokens (self-or-admin)
    "repo_tokens.rs": "scopes",       # POST /api/v1/repositories/:key/tokens
    "service_accounts.rs": "admin",   # POST /api/v1/service-accounts/:id/tokens
}

REJECT_MARKERS = {
    "scopes": "enforce_admin_only_scopes",
    "admin": "require_admin",
}


def production_lines(path):
    """Yield (lineno, code) for source lines OUTSIDE any #[cfg(test)] module."""
    in_test = False
    test_depth = 0
    depth = 0
    pending_cfg_test = False
    with open(path, encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.rstrip("\n")
            stripped = line.strip()
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
                elif stripped and not stripped.startswith("//"):
                    if pending_cfg_test and "mod " not in stripped:
                        pending_cfg_test = False
            if in_test:
                depth += line.count("{") - line.count("}")
                if depth <= test_depth:
                    in_test = False
                continue
            depth += line.count("{") - line.count("}")
            code = line.split("//", 1)[0]
            yield lineno, code


# Discover every production mint site.
found = {}        # filename -> [linenos]
file_text = {}    # filename -> full source (for reject-marker check)
for name in os.listdir(handlers_dir):
    if not name.endswith(".rs"):
        continue
    path = os.path.join(handlers_dir, name)
    with open(path, encoding="utf-8") as fh:
        file_text[name] = fh.read()
    for lineno, code in production_lines(path):
        if "generate_api_token" in code:
            found.setdefault(name, []).append(lineno)

errors = []

found_set = set(found)
expected_set = set(EXPECTED)

unreviewed = sorted(found_set - expected_set)
for name in unreviewed:
    sites = ", ".join(str(n) for n in found[name])
    errors.append(
        f"NEW token-minting endpoint detected in handlers/{name} (line(s) {sites}) "
        f"that is NOT in the pinned set. If this is a legitimate new endpoint, add "
        f"it to EXPECTED in scripts/ci/check-token-mint-surface.sh AND ensure it "
        f"enforces a reject rule (enforce_admin_only_scopes or require_admin). "
        f"This is the deliberate review #1315 requires."
    )

missing = sorted(expected_set - found_set)
for name in missing:
    errors.append(
        f"Pinned token-minting endpoint handlers/{name} no longer calls "
        f"generate_api_token. If the endpoint was removed, delete it from EXPECTED "
        f"in scripts/ci/check-token-mint-surface.sh."
    )

# Verify each pinned handler still carries its required reject rule.
for name in sorted(expected_set & found_set):
    kind = EXPECTED[name]
    marker = REJECT_MARKERS[kind]
    if marker not in file_text[name]:
        errors.append(
            f"Token-minting endpoint handlers/{name} is pinned to use '{marker}' "
            f"({kind} reject rule) but that marker is absent -- the "
            f"privilege-escalation guard appears to have been removed/weakened."
        )

if errors:
    sys.stderr.write(
        "ERROR: token-minting endpoint surface drift detected (issue #1315).\n\n"
    )
    for e in errors:
        sys.stderr.write(f"  - {e}\n\n")
    sys.exit(1)

print(
    f"OK: token-minting endpoint surface matches the pinned set "
    f"({len(expected_set)} endpoints), each with its reject rule intact."
)
PY
