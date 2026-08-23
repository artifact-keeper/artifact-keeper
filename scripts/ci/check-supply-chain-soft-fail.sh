#!/usr/bin/env bash
#
# CI gate for issue #3496: a supply-chain step that is supposed to be a
# GUARANTEE must not be allowed to fail silently.
#
# WHY THIS GATE IS LOAD-BEARING
# -----------------------------
# `.github/workflows/docker-publish.yml` carried six STEP-level
# `continue-on-error: true` on `Generate artifact attestation` (all four
# published images) and `Attach VEX attestations` (backend and
# backend-alpine).
#
# A STEP-level `continue-on-error` is the worst of the available options for
# a control:
#
#   * the step turns yellow inside the job, but the JOB result stays
#     `success`, so `needs.<job>.result`, branch protection, required checks
#     and every downstream gate see green;
#   * nothing is written to the job summary and no annotation is raised, so
#     the only trace is a skimmable icon in a log nobody opens;
#   * the publish steps ran BEFORE it, so the image is already on ghcr.io and
#     Docker Hub by the time the failure is swallowed.
#
# The net effect is that build provenance was never proven to attach to any
# published image: an OIDC token outage, a registry rejection or an
# `actions/attest-build-provenance` outage was indistinguishable from success.
# That is the same failure the project already paid for in #2824, where the
# cosign step failed and 1.6.1 shipped unsigned — caught only because a human
# went looking — and the same shape as the step-level `continue-on-error` that
# made `resilience-tests` unfalsifiable across two releases.
#
# THE INVARIANTS
# --------------
#   1. SUPPLY-CHAIN CONTROLS ARE NEVER SOFT (all workflows). No step in
#      `.github/workflows/` that generates an attestation
#      (`actions/attest-*`) or signs/attests with cosign (`cosign sign`,
#      `cosign attest`) may set `continue-on-error` to anything but `false`.
#      These produce the artifacts consumers verify; a missing one must be
#      loud. Hard-failing costs a job re-run — the merge jobs are idempotent
#      by construction (imagetools re-points the SAME digest) — and buys a
#      signal that a soft step cannot give.
#
#   2. THE PUBLISH WORKFLOW HAS NO SOFT STEPS AT ALL. `docker-publish.yml`
#      may carry no `continue-on-error` on any step or job. A step there is
#      either something the publish depends on (then it must fail the job) or
#      genuinely best-effort (then say so in the script with an explicit
#      `::warning::` and a `$GITHUB_STEP_SUMMARY` line, the way "Attach VEX
#      attestations" now does, so the failure is visible to a human).
#      An invisible YAML key is not a place to record a policy decision.
#
#   3. NON-VACUITY. If no attestation step and no cosign signing step is
#      found at all, this script FAILS. The control it protects is the
#      existence of those steps; a guard that passes because its subject
#      disappeared is exactly the defect #3496 is about.
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

# The workflow whose steps must all be hard-fail (invariant 2).
PUBLISH_WORKFLOW = "docker-publish.yml"

# `uses:` prefixes that produce a supply-chain attestation (invariant 1).
ATTEST_USES_PREFIXES = ("actions/attest-build-provenance@", "actions/attest-sbom@", "actions/attest@")

# `run:` substrings that sign or attest with cosign (invariant 1).
COSIGN_RUN_MARKERS = ("cosign sign", "cosign attest")

violations = []
control_steps = 0


def is_soft(step_or_job):
    """True when continue-on-error is set to anything other than a literal false.

    YAML gives a bool for `true`/`false`; an expression such as
    `${{ github.event_name == 'schedule' }}` arrives as a string and is
    treated as soft, because it can evaluate to true.
    """
    if "continue-on-error" not in step_or_job:
        return False
    value = step_or_job["continue-on-error"]
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() != "false"


def classify(step):
    """Return a control label for a supply-chain step, else None."""
    uses = str(step.get("uses") or "")
    for prefix in ATTEST_USES_PREFIXES:
        if uses.startswith(prefix):
            return f"attestation step (`uses: {uses.split('@')[0]}`)"
    run = str(step.get("run") or "")
    for marker in COSIGN_RUN_MARKERS:
        if marker in run:
            return f"cosign step (`{marker}`)"
    return None


def walk(path):
    global control_steps

    basename = os.path.basename(path)
    with open(path, encoding="utf-8") as handle:
        doc = yaml.safe_load(handle)
    if not isinstance(doc, dict):
        return

    for job_name, job in (doc.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue

        if basename == PUBLISH_WORKFLOW and is_soft(job):
            violations.append(
                f"{basename} :: {job_name} (job-level)\n"
                f"    sets `continue-on-error`. The publish workflow may not soft-fail\n"
                f"    anything (#3496): a swallowed failure there means an image is on\n"
                f"    the registry with a control that did not run."
            )

        for step in job.get("steps") or []:
            if not isinstance(step, dict):
                continue
            step_name = str(step.get("name") or step.get("uses") or "<unnamed>")
            where = f"{basename} :: {job_name} :: {step_name}"

            label = classify(step)
            if label is not None:
                control_steps += 1
                if is_soft(step):
                    violations.append(
                        f"{where}\n"
                        f"    is a supply-chain control — {label} — and sets\n"
                        f"    `continue-on-error`. A STEP-level continue-on-error leaves the\n"
                        f"    JOB result `success`, so a failed signature or attestation is\n"
                        f"    invisible to `needs:`, to required checks and to the run summary,\n"
                        f"    while the image publishes anyway (#3496, and #2824 before it).\n"
                        f"    Remove it. The merge jobs are idempotent, so the recovery from a\n"
                        f"    transient failure is `Re-run failed jobs`."
                    )
                    continue

            if basename == PUBLISH_WORKFLOW and is_soft(step):
                violations.append(
                    f"{where}\n"
                    f"    sets `continue-on-error` in the publish workflow (#3496). Either the\n"
                    f"    publish depends on this step (then let it fail the job), or it is\n"
                    f"    best-effort — in which case handle the failure in the script and\n"
                    f"    raise an explicit `::warning::` plus a $GITHUB_STEP_SUMMARY line, the\n"
                    f"    way `Attach VEX attestations` does, so a human can see it."
                )


if not os.path.isdir(workflow_dir):
    print(f"ERROR: workflow directory not found: {workflow_dir}")
    sys.exit(1)

for entry in sorted(os.listdir(workflow_dir)):
    if entry.endswith((".yml", ".yaml")):
        walk(os.path.join(workflow_dir, entry))

if violations:
    print("ERROR: supply-chain step(s) can fail without failing the build:\n")
    for violation in violations:
        print(f"  - {violation}\n")
    print(
        "See issue #3496. A control that cannot report its own failure is not a\n"
        "control; it is a comment."
    )
    sys.exit(1)

if control_steps == 0:
    print(
        "ERROR: found no attestation or cosign signing step under "
        f"{workflow_dir}.\n"
        "Image signing and build provenance are the controls this check exists to\n"
        "protect. If they were intentionally removed or renamed, update this script\n"
        "deliberately rather than letting it pass vacuously."
    )
    sys.exit(1)

print(
    f"OK: {control_steps} supply-chain step(s) hard-fail their job; "
    f"no soft-failed steps in {PUBLISH_WORKFLOW}."
)
PY
