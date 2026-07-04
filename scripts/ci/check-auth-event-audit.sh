#!/usr/bin/env bash
#
# CI gate for issue #1617 Phase 1: auth-event audit completeness.
#
# WHY THIS PIN IS LOAD-BEARING
# ----------------------------
# Compliance regimes (SOC 2 CC7, EU CRA) require a complete audit trail for
# authentication events and credential (API-token) lifecycle. Local-password
# login has always audited Login / LoginFailed / Logout, but the enterprise
# auth paths (OIDC / SAML / LDAP) and the API-token mint/revoke endpoints
# historically emitted NOTHING -- so federated logins and token lifecycle left
# no trail. Phase 1 closed that gap by emitting audit events on those paths.
#
# The structural risk this gate prevents: a future edit removes the audit
# call next to a token mint/revoke, or a new federated-login handler lands
# without an audit call, silently re-opening the coverage hole.
#
# This gate asserts, over PRODUCTION source (excluding `#[cfg(test)]` modules):
#   1. Every handler file that mints tokens (`generate_api_token`) also
#      references the shared mint/revoke audit helper `api_token_audit_entry`.
#   2. The SSO handler (`sso.rs`) references the shared federated-login audit
#      helper `audit_federated_login`, and each production `authenticate_federated`
#      call site is accompanied by at least one federated-login audit call.
#
# Mirrors the style of `scripts/ci/check-token-mint-surface.sh` (#1315).
# Exits non-zero (failing the build) on any drift.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HANDLERS_DIR="${1:-$ROOT/backend/src/api/handlers}"

python3 - "$HANDLERS_DIR" <<'PY'
import os
import sys

handlers_dir = sys.argv[1]


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


def production_text(path):
    return "\n".join(code for _, code in production_lines(path))


errors = []

# --- 1. Token mint/revoke audit coverage -------------------------------------
for name in sorted(os.listdir(handlers_dir)):
    if not name.endswith(".rs"):
        continue
    path = os.path.join(handlers_dir, name)
    prod = production_text(path)
    if "generate_api_token" in prod and "api_token_audit_entry" not in prod:
        errors.append(
            f"handlers/{name} mints API tokens (generate_api_token) but does not "
            f"call the shared audit helper `api_token_audit_entry`. Every mint and "
            f"revoke endpoint MUST emit an ApiTokenCreated / ApiTokenRevoked audit "
            f"event (#1617 Phase 1). Add a fire-and-forget audit call."
        )

# --- 2. Federated (SSO) login audit coverage ---------------------------------
sso_path = os.path.join(handlers_dir, "sso.rs")
if os.path.exists(sso_path):
    sso_prod = production_text(sso_path)
    fed_sites = sso_prod.count("authenticate_federated")
    audit_calls = sso_prod.count("audit_federated_login")
    if fed_sites and "audit_federated_login" not in sso_prod:
        errors.append(
            "handlers/sso.rs runs federated logins (authenticate_federated) but "
            "never calls `audit_federated_login`. OIDC/SAML/LDAP logins MUST emit "
            "Login / LoginFailed audit events (#1617 Phase 1)."
        )
    elif fed_sites and audit_calls < fed_sites:
        errors.append(
            f"handlers/sso.rs has {fed_sites} federated-login call site(s) "
            f"(authenticate_federated) but only {audit_calls} `audit_federated_login` "
            f"call(s). Each federated-login path MUST record both its success (Login) "
            f"and failure (LoginFailed) outcome (#1617 Phase 1)."
        )

if errors:
    sys.stderr.write("ERROR: auth-event audit coverage gap detected (issue #1617).\n\n")
    for e in errors:
        sys.stderr.write(f"  - {e}\n\n")
    sys.exit(1)

print("OK: auth-event audit coverage intact (SSO logins + token mint/revoke).")
PY
