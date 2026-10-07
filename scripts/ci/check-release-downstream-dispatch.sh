#!/usr/bin/env bash
#
# CI gate: every workflow that must run after a release is DISPATCHED by
# release.yml, and can be dispatched by hand (#3789, #3896, #3897).
#
# WHY THIS GATE IS LOAD-BEARING
# -----------------------------
# release.yml creates the GitHub Release with GITHUB_TOKEN, and an event caused
# by GITHUB_TOKEN never starts another workflow. So a downstream workflow that
# listens for `release: published` simply does not run for a workflow-created
# release -- and nothing goes red. That is how sync-openapi-spec.yml (#3789),
# release-announce.yml (#3897) and ami-build.yml (#3896) all silently stopped
# running when the certified flow (#3777) landed, while every release looked
# green. The fix is a dispatch from release.yml, followed to a verdict; this
# gate makes removing any part of it a red build instead of another silent gap.
#
# THE INVARIANTS (per downstream workflow D in DOWNSTREAM below)
# --------------------------------------------------------------
#   1. DISPATCHABLE. D has an `on.workflow_dispatch` trigger with the input
#      release.yml passes, declared `required: true`.
#   2. HAND RELEASES STILL COVERED. D keeps `on.release.types: [published]`,
#      which is the only path for a Release a human publishes.
#   3. DISPATCHED. Some job in release.yml runs `gh workflow run D` with
#      `--ref "${GITHUB_REF_NAME}"` and the input, AFTER the Release exists
#      (`needs:` includes `release`), with `actions: write`.
#   4. FOLLOWED. That same job runs scripts/ci/follow-dispatched-run.sh with
#      FOLLOW_WORKFLOW: D, so a dispatch that never runs or runs red turns the
#      release run red.
#   5. PRERELEASE POLICY. The job's `if:` excludes prereleases
#      (`!contains(github.ref_name, '-')`) exactly when D is stable-only.
#   6. NO INPUT INJECTION. No `run:` script in D interpolates `${{ inputs.* }}`
#      or `${{ github.event.release.* }}` directly; they reach the shell
#      through `env:` and are validated there.
#   7. NOT SKIPPED ON DISPATCH. No job in D is gated on
#      `github.event_name == 'release'`, which would make the dispatch a no-op.
#
# Usage: check-release-downstream-dispatch.sh [workflow-dir]
# Exits non-zero (failing the build) on any drift. Pure YAML, no network.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKFLOW_DIR="${1:-$ROOT/.github/workflows}"

python3 - "$WORKFLOW_DIR" <<'PY'
import os
import re
import sys

import yaml

workflow_dir = sys.argv[1]
RELEASE_WORKFLOW = "release.yml"
FOLLOWER = "scripts/ci/follow-dispatched-run.sh"

# workflow file -> (input release.yml passes, stable releases only?)
DOWNSTREAM = {
    "sync-openapi-spec.yml": (None, False),
    "release-announce.yml": ("tag", False),
    "ami-build.yml": ("version", True),
}

STABLE_ONLY = re.compile(r"!\s*contains\(\s*github\.ref_name\s*,\s*'-'\s*\)")
# Caller-controlled values: dispatch inputs and the release payload (a
# release name or body is free text written by whoever published it).
INPUT_IN_RUN = re.compile(r"\$\{\{\s*(github\.event\.)?(inputs\.|github\.event\.release\.)")
RELEASE_ONLY_IF = re.compile(r"github\.event_name\s*==\s*'release'")

errors = []


def load(name):
    path = os.path.join(workflow_dir, name)
    if not os.path.isfile(path):
        errors.append(f"{name} not found under {workflow_dir}.")
        return None
    with open(path, encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def triggers(wf):
    # PyYAML (YAML 1.1) reads a bare `on:` key as boolean True.
    on = wf.get("on", wf.get(True))
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return {k: None for k in on}
    return on or {}


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


release = load(RELEASE_WORKFLOW)
release_jobs = (release or {}).get("jobs") or {}

for wf_name, (input_name, stable_only) in DOWNSTREAM.items():
    wf = load(wf_name)
    if wf is None:
        continue
    on = triggers(wf)

    # 1. dispatchable
    if "workflow_dispatch" not in on:
        errors.append(
            f"{wf_name} has no `workflow_dispatch` trigger. release.yml cannot start it\n"
            f"  (its `release: published` never fires for a GITHUB_TOKEN release), and a\n"
            f"  maintainer cannot run it by hand."
        )
    elif input_name:
        inputs = ((on.get("workflow_dispatch") or {}).get("inputs") or {})
        spec = inputs.get(input_name)
        if not isinstance(spec, dict) or spec.get("required") is not True:
            errors.append(
                f"{wf_name} :: workflow_dispatch must declare input `{input_name}` with\n"
                f"  `required: true`; release.yml passes `-f {input_name}=...`."
            )

    # 2. hand releases
    rel = on.get("release") if isinstance(on, dict) else None
    if "release" not in on or "published" not in as_list((rel or {}).get("types")):
        errors.append(
            f"{wf_name} lost `on.release.types: [published]`; a Release published by\n"
            f"  hand (whose event does fire) would no longer start it."
        )

    # 6. / 7. inside D
    for job_name, job in (wf.get("jobs") or {}).items():
        job = job or {}
        cond = str(job.get("if", ""))
        if RELEASE_ONLY_IF.search(cond):
            errors.append(
                f"{wf_name} :: {job_name} is gated on `github.event_name == 'release'`, so\n"
                f"  the dispatch from release.yml would skip it."
            )
        for step in job.get("steps") or []:
            run = str((step or {}).get("run", ""))
            if INPUT_IN_RUN.search(run):
                errors.append(
                    f"{wf_name} :: {job_name} :: {step.get('name', '<unnamed>')} interpolates\n"
                    f"  `${{{{ inputs.* }}}}` or `${{{{ github.event.release.* }}}}` into a run script;\n"
                    f"  pass it through `env:` and validate it."
                )

    # 3. / 4. / 5. in release.yml
    # A COMMAND line, not a mention: the follow step's `::error::` text quotes
    # the same `gh workflow run ...` as a hand-recovery hint, and must not
    # count as the dispatch.
    dispatch_re = re.compile(
        r"^\s*gh\s+workflow\s+run\s+" + re.escape(wf_name) + r"\b", re.MULTILINE
    )
    dispatchers = []
    for job_name, job in release_jobs.items():
        job = job or {}
        runs = [str((s or {}).get("run", "")) for s in job.get("steps") or []]
        if any(dispatch_re.search(r) for r in runs):
            dispatchers.append((job_name, job, runs))
    if release is not None and not dispatchers:
        errors.append(
            f"{RELEASE_WORKFLOW} has no job running `gh workflow run {wf_name}`. Releases\n"
            f"  created by the workflow will never run it."
        )
    for job_name, job, runs in dispatchers:
        where = f"{RELEASE_WORKFLOW} :: {job_name}"
        script = "\n".join(r for r in runs if dispatch_re.search(r))
        # Join backslash continuations so flags on the next line count.
        flat = re.sub(r"\\\n\s*", " ", script)
        call = next((l for l in flat.splitlines() if dispatch_re.match(l)), "")
        if not re.search(r"--ref\s+\"?\$\{?GITHUB_REF_NAME\}?\"?", call):
            errors.append(f"{where} must dispatch {wf_name} with --ref \"${{GITHUB_REF_NAME}}\" (the tag).")
        if input_name and not re.search(r"-f\s+" + re.escape(input_name) + r"=", call):
            errors.append(f"{where} must pass `-f {input_name}=...` to {wf_name}.")
        if "release" not in as_list(job.get("needs")):
            errors.append(
                f"{where} dispatches {wf_name} but does not `needs: release`; it could run\n"
                f"  before the GitHub Release exists."
            )
        perms = job.get("permissions") or {}
        if not isinstance(perms, dict) or perms.get("actions") != "write":
            errors.append(f"{where} needs `permissions: actions: write` to dispatch and follow {wf_name}.")
        followed = False
        for step in job.get("steps") or []:
            step = step or {}
            env = step.get("env") or {}
            if env.get("FOLLOW_WORKFLOW") == wf_name and FOLLOWER in str(step.get("run", "")):
                followed = True
        if not followed:
            errors.append(
                f"{where} dispatches {wf_name} but never follows it with {FOLLOWER}\n"
                f"  (FOLLOW_WORKFLOW: {wf_name}); a dead or red run would go unnoticed."
            )
        cond = str(job.get("if", ""))
        excludes_pre = bool(STABLE_ONLY.search(cond))
        if stable_only and not excludes_pre:
            errors.append(
                f"{where} must skip prereleases (`!contains(github.ref_name, '-')` in its `if:`);\n"
                f"  {wf_name} is stable-only by policy (RELEASING.md)."
            )
        if not stable_only and excludes_pre:
            errors.append(
                f"{where} skips prereleases, but {wf_name} is meant to run for them too\n"
                f"  (RELEASING.md)."
            )

if errors:
    print("Release downstream-dispatch drift:\n", file=sys.stderr)
    for e in errors:
        print(f"  - {e}\n", file=sys.stderr)
    sys.exit(1)
print(f"OK: {', '.join(DOWNSTREAM)} are dispatched and followed by {RELEASE_WORKFLOW}, and dispatchable by hand.")
PY
