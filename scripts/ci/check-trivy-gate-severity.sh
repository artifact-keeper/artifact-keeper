#!/usr/bin/env bash
#
# CI gate for issue #3122: a Trivy step that BLOCKS a publish must actually
# apply the severity filter it declares.
#
# WHY THIS GATE IS LOAD-BEARING
# -----------------------------
# `aquasecurity/trivy-action` silently discards the `severity:` input when the
# report format is SARIF. From the action's own `entrypoint.sh` (pinned SHA
# ed142fd0673e97e23eac54620cfb913e5ce36c25, v0.36.0), lines 75-83:
#
#     # Handle SARIF
#     if [ "${TRIVY_FORMAT:-}" = "sarif" ]; then
#       if [ "${INPUT_LIMIT_SEVERITIES_FOR_SARIF:-false,,}" != "true" ]; then
#         echo "Building SARIF report with all severities"
#         unset TRIVY_SEVERITY          # <-- severity input thrown away
#       else
#         echo "Building SARIF report"
#       fi
#     fi
#
# Combined with `exit-code: '1'`, that turns a step documented as
# "CRITICAL,HIGH only" into one that fails the build on a fixable CVE of ANY
# severity — including LOW. That is exactly what happened in #3122: every
# `main` push was blocked for days by CVE-2026-54787, a LOW
# (`security-severity: 3.1`, SARIF level `note`), while the workflow comments
# and the job step summary both claimed CRITICAL/HIGH-only.
#
# The failure mode is silent and it is *over*-blocking, which is the dangerous
# direction for a security gate: the cheapest way to unblock a publish becomes
# another `.trivyignore` entry, so the ignore file fills up with findings
# nobody consciously accepted, and the gate trains people to route around it.
# A gate that cries wolf is how a real CRITICAL eventually gets waved through.
#
# THE INVARIANT
# -------------
# For every `aquasecurity/trivy-action` step in `.github/workflows/` that gates
# (a non-zero `exit-code`):
#
#   1. it MUST declare a `severity:` — an unbounded blocking scan is never
#      intentional; and
#   2. that `severity:` MUST actually reach Trivy, i.e. EITHER the format is
#      not `sarif`, OR `limit-severities-for-sarif` is exactly `true`.
#
# Requirement (2) is what regressed in #3122. Note that the string must be
# lowercase `true`: the action's `${INPUT_...:-false,,}` is a broken attempt at
# bash's `,,` lowercasing (the `,,` is part of the *default value*, not a case
# modifier), so `True`/`TRUE` compare unequal to `true` and silently fall into
# the discard branch.
#
# Non-gating steps (`exit-code: '0'`, e.g. the SARIF visibility passes and
# scheduled-container-scan.yml) are intentionally exempt: for those, scanning
# at all severities is the desired behaviour and nothing is blocked by it.
#
# Exits non-zero (failing the build) on any drift.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKFLOW_DIR="${1:-$ROOT/.github/workflows}"

python3 - "$WORKFLOW_DIR" <<'PY'
import os
import sys

import yaml

workflow_dir = sys.argv[1]

ACTION = "aquasecurity/trivy-action"

violations = []
gating_steps = 0
exempt_steps = 0


def norm(value):
    """YAML may give us a bool, an int, or a string depending on quoting."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value).strip()


def walk(workflow_path):
    global gating_steps, exempt_steps

    with open(workflow_path, encoding="utf-8") as handle:
        doc = yaml.safe_load(handle)

    if not isinstance(doc, dict):
        return

    for job_name, job in (doc.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps") or []:
            if not isinstance(step, dict):
                continue
            uses = norm(step.get("uses", ""))
            if not uses.startswith(ACTION):
                continue

            with_block = step.get("with") or {}
            step_name = norm(step.get("name", "<unnamed>"))
            where = f"{os.path.basename(workflow_path)} :: {job_name} :: {step_name}"

            exit_code = norm(with_block.get("exit-code", "0"))
            if exit_code == "0":
                exempt_steps += 1
                continue

            gating_steps += 1

            severity = norm(with_block.get("severity", ""))
            fmt = norm(with_block.get("format", "table")).lower()
            limit = norm(with_block.get("limit-severities-for-sarif", "false"))

            if not severity:
                violations.append(
                    f"{where}\n"
                    f"    gates with exit-code '{exit_code}' but declares no `severity:`.\n"
                    f"    An unbounded blocking scan fails on any finding at any severity."
                )
                continue

            if fmt == "sarif" and limit != "true":
                violations.append(
                    f"{where}\n"
                    f"    declares `severity: {severity}` and gates with exit-code "
                    f"'{exit_code}',\n"
                    f"    but `format: sarif` makes trivy-action `unset TRIVY_SEVERITY` "
                    f"(entrypoint.sh:75-83),\n"
                    f"    so the filter never reaches Trivy and the step fails on ANY "
                    f"severity (issue #3122).\n"
                    f"    Fix: split the visibility pass (format sarif, exit-code '0') "
                    f"from the gating pass\n"
                    f"    (format table, exit-code '1'), or set "
                    f"`limit-severities-for-sarif: true` (lowercase)."
                )


for entry in sorted(os.listdir(workflow_dir)):
    if entry.endswith((".yml", ".yaml")):
        walk(os.path.join(workflow_dir, entry))

if violations:
    print("ERROR: Trivy gating step(s) do not apply their declared severity filter:\n")
    for violation in violations:
        print(f"  - {violation}\n")
    print(
        "See issue #3122. A gate that fires on severities it declares it ignores\n"
        "trains people to bypass it, which is how a real CRITICAL gets waved through."
    )
    sys.exit(1)

if gating_steps == 0:
    print(
        "ERROR: found no gating aquasecurity/trivy-action step "
        f"(non-zero exit-code) under {workflow_dir}.\n"
        "The container CVE gate is the control this check exists to protect; if it\n"
        "was intentionally removed or renamed, update this script deliberately."
    )
    sys.exit(1)

print(
    f"OK: {gating_steps} gating Trivy step(s) apply their declared severity filter "
    f"({exempt_steps} non-gating visibility step(s) exempt)."
)
PY
