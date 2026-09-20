#!/usr/bin/env bash
#
# Structural self-test for .github/workflows/release-branch-gate.yml (#4070).
#
# WHY THIS EXISTS
# ---------------
# `Verify commits trace back to main` is a REQUIRED status context on ruleset
# 20038606, so the ruleset's promise is only worth what the job behind it
# actually evaluates. Until #4070 the job's first step looked for the
# `release-process: approved` label and, when it found one, skipped every
# remaining step through `if: steps.skip.outputs.skip != 'true'`. A job whose
# steps all skip still concludes SUCCESS, so the required context was satisfied
# without the ancestry check ever running — by anyone who could open a PR
# against `release/*` and label their own PR.
#
# test-check-release-branch-commits.sh pins the verdict the SCRIPT reaches. It
# cannot see the half that failed here: the workflow deciding not to call it.
# So this asserts the wiring instead, and the assertions are all about one
# thing — no label, and nothing derived from a label, may condition the gate.
#
#   1. NON-VACUITY. Exactly one step invokes
#      check-release-branch-commits.sh, and it carries no `if:`. A guard that
#      passes because its subject disappeared is not a guard.
#   2. THE JOB IS UNCONDITIONAL. Neither the job nor any of its steps carries
#      an `if:` that mentions a label, `steps.skip`, or the labels payload.
#   3. NO SKIP PLUMBING. No step declares `id: skip` or writes `skip=` to
#      $GITHUB_OUTPUT, and nothing in the file announces a bypass.
#   4. THE LABEL IS ANNOUNCED, NOT HONOURED. The label is still read, so that
#      applying it produces a `::warning` saying it does nothing — never a
#      `::notice` that reads like a successful bypass.
#
# Usage: bash scripts/ci/test-release-branch-gate.sh [workflow.yml]
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKFLOW="${1:-$ROOT/.github/workflows/release-branch-gate.yml}"

if [ ! -f "$WORKFLOW" ]; then
  echo "cannot find release-branch-gate.yml at ${WORKFLOW}" >&2
  exit 2
fi

echo "release-branch-gate wiring (#4070)"

python3 - "$WORKFLOW" <<'PY'
import sys

import yaml

path = sys.argv[1]
raw = open(path, encoding="utf-8").read()
doc = yaml.safe_load(raw)

fails = []


def pass_(msg):
    print(f"  \033[32mPASS\033[0m  {msg}")


def fail(msg):
    print(f"  \033[31mFAIL\033[0m  {msg}")
    fails.append(msg)


jobs = (doc or {}).get("jobs") or {}
job = jobs.get("verify-main-ancestor")
if not isinstance(job, dict):
    fail("the workflow has no `verify-main-ancestor` job; the required context "
         "`Verify commits trace back to main` is produced by it")
    print()
    print("1 case(s) failed")
    sys.exit(1)

steps = [s for s in (job.get("steps") or []) if isinstance(s, dict)]


def where(step):
    return str(step.get("name") or step.get("uses") or "<unnamed>")


# The label payload, in the spellings a workflow can reach it by. A conditional
# naming any of them is a bypass however it is spelled.
LABEL_MARKERS = ("label", "steps.skip", "skip.outputs")


# ── 1. non-vacuity ─────────────────────────────────────────────────────────
gate_steps = [s for s in steps if "check-release-branch-commits.sh" in str(s.get("run") or "")]
if len(gate_steps) == 1:
    pass_("exactly one step runs check-release-branch-commits.sh")
elif not gate_steps:
    fail("no step runs scripts/ci/check-release-branch-commits.sh — the job "
         "would conclude success without verifying anything")
else:
    fail(f"{len(gate_steps)} steps run check-release-branch-commits.sh; expected exactly one")

for step in gate_steps:
    if "if" in step:
        fail(f"the gate step ({where(step)}) carries `if: {step['if']}` — the "
             "check must run on every PR against release/*, unconditionally")
    else:
        pass_("the gate step carries no `if:`")

# ── 2. the job is unconditional ────────────────────────────────────────────
if "if" in job:
    fail(f"the `verify-main-ancestor` job carries `if: {job['if']}`; a skipped "
         "job still satisfies a required status context")
else:
    pass_("the job carries no `if:`")

conditioned = []
for step in steps:
    cond = str(step.get("if") or "")
    if cond and any(marker in cond.lower() for marker in LABEL_MARKERS):
        conditioned.append(f"{where(step)} -> if: {cond}")
if conditioned:
    for c in conditioned:
        fail(f"a step is conditioned on a label or a skip output: {c}")
else:
    pass_("no step is conditioned on a label or a skip output")

# ── 3. no skip plumbing ────────────────────────────────────────────────────
for step in steps:
    if str(step.get("id") or "") == "skip":
        fail(f"step {where(step)} declares `id: skip`; #4070 removed the skip step")
        break
else:
    pass_("no step declares `id: skip`")

for step in steps:
    run = str(step.get("run") or "")
    if "skip=" in run and "GITHUB_OUTPUT" in run:
        fail(f"step {where(step)} writes a `skip=` output; nothing here may "
             "publish a bypass decision for a later step to read")
        break
else:
    pass_("no step writes a `skip=` output")

if "gate bypassed" in raw.lower() or "bypasses" in raw.lower():
    fail("the workflow still announces a bypass; the label bypass was removed "
         "in #4070 and no text should claim otherwise")
else:
    pass_("the workflow announces no bypass")

# ── 4. the label is announced, not honoured ────────────────────────────────
label_steps = [s for s in steps if "release-process: approved" in str(s.get("run") or "")]
if not label_steps:
    fail("no step mentions `release-process: approved`; applying the label "
         "should still raise a warning saying it does not bypass the gate")
else:
    for step in label_steps:
        run = str(step.get("run") or "")
        if "::warning" not in run:
            fail(f"step {where(step)} reads the label but raises no `::warning`")
        elif "::notice" in run:
            fail(f"step {where(step)} raises a `::notice` about the label; a "
                 "notice reads like a successful bypass, which is what #4070 removed")
        else:
            pass_("the label raises a `::warning`, not a `::notice`")

print()
if fails:
    print(f"{len(fails)} case(s) failed")
    sys.exit(1)
print("all cases passed")
PY
