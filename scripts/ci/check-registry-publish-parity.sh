#!/usr/bin/env bash
#
# Registry signing parity gate for `docker-publish.yml` (issue #3562).
#
# THE INVARIANT
# -------------
#   EVERY REGISTRY A PUBLISH JOB MIRRORS AN IMAGE TO IS ALSO A REGISTRY IT
#   SIGNS THAT IMAGE ON, AND VERIFIES THE PUBLISHED TAGS ON.
#
# This is the same statement #3559 makes about a single registry -- the bytes a
# user pulls by tag are the bytes that were signed -- carried across the fact
# that this project ships the identical bytes through TWO distribution
# channels. A consumer pulling `docker.io/artifactkeeper/backend:1.8.1` and a
# consumer pulling `ghcr.io/artifact-keeper/artifact-keeper-backend:1.8.1` get
# byte-identical images; only one of them could verify what they got.
#
# WHY A STATIC GATE, WHEN THE RUNTIME GATE ALREADY EXISTS
# -------------------------------------------------------
# `check-published-image-signature.sh` is the real assertion: it re-resolves
# published tags and demands a cosign signature over what they name. But it can
# only assert about the refs it is HANDED. The defect #3562 records is exactly
# that shape -- a correct, hard-failing, well-tested signing step and a
# correct, hard-failing, well-tested verification step, both pointed at one of
# the two registries the workflow publishes to. Nothing was broken; something
# was simply absent, and absence is invisible to a runtime check.
#
# So this gate reads the workflow rather than the registry, and asks the one
# question the runtime gate structurally cannot: does the list of registries
# this job PUSHES to equal the list it SIGNS and VERIFIES? Deleting the Docker
# Hub half of either step turns this red on the PR that does it, without
# waiting for a publish.
#
# WHAT IS AND IS NOT IN SCOPE
#   * A job is IN SCOPE when it signs with cosign AND mirrors an image to
#     Docker Hub. Those are the jobs that publish new bytes.
#   * `apply-floating-tags` is deliberately out of scope: it writes no new
#     bytes, only re-points tags at a digest the merge jobs already published
#     and signed on both registries. `imagetools create` uploads no layers and
#     produces no new manifest, so the signature keeps covering it -- which is
#     also why the Docker Hub signature must be made over the DIGEST.
#   * A job disabled with a literal `if: false` is skipped, because it
#     publishes nothing. `merge-backend-alpine` is in that state today (Alpine
#     builds suspended). Re-enabling it changes that `if:`, and this gate fires
#     on the same PR -- which is the point: the exemption expires by itself.
#
# NON-VACUITY. If fewer than MIN_SIGNING_JOBS in-scope jobs are found, this
# FAILS. Without it the gate would be trivially satisfiable by deleting a
# signing step: no signing step, no in-scope job, no complaint. That is the
# same defect the gate exists to catch, so the count is checked (#3496
# invariant 3, applied here).
#
# EXIT CODES
#   0  parity holds.
#   1  BLOCK. A job publishes to a registry it does not sign or does not
#      verify, or the gate found too few subjects to be meaningful.
#   2  INFRA / CONFIG. The question could not be asked: workflow file missing,
#      unparsable, or python3/PyYAML unavailable.
#
# Usage: check-registry-publish-parity.sh [path/to/docker-publish.yml]

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKFLOW="${1:-$ROOT/.github/workflows/docker-publish.yml}"

if [ ! -f "$WORKFLOW" ]; then
  echo "::error title=Registry parity gate cannot run::workflow file not found: ${WORKFLOW}. Not finding the subject is an infrastructure failure, never a pass."
  exit 2
fi

python3 - "$WORKFLOW" <<'PY'
import os
import re
import sys

try:
    import yaml
except Exception as exc:  # pragma: no cover - environment problem, not drift
    print(f"::error title=Registry parity gate cannot run::PyYAML unavailable: {exc}")
    sys.exit(2)

path = sys.argv[1]

# How many jobs must be in scope for this gate to mean anything. Today:
# merge-backend, merge-openscap, merge-scanner-adapter. Adding a fourth
# published image raises the count and is fine; losing one is the regression
# this number exists to catch.
MIN_SIGNING_JOBS = 3

# Text that identifies a reference to each registry, in a `run:` body or in a
# step's `env:`. Deliberately broad -- the tag sets reach the steps through
# several indirections (`/tmp/hub-tags.json`, `steps.meta-dockerhub.outputs`,
# `${DOCKERHUB_*}`) and a narrow literal match would be defeated by any of
# them.
GHCR_MARKERS = (r"ghcr\.io", r"env\.REGISTRY", r"\$\{REGISTRY\}", r"ghcr-tags")
HUB_MARKERS = (r"docker\.io/", r"hub-tags", r"meta-dockerhub", r"DOCKERHUB_")

MIRROR_MARKER = "imagetools create"
COSIGN_SIGN = "cosign sign"
VERIFY_SCRIPT = "check-published-image-signature.sh"

INFRA = 2
BLOCK = 1


def step_text(step):
    """Everything in a step that can carry a registry reference."""
    parts = [str(step.get("run") or ""), str(step.get("name") or "")]
    env = step.get("env")
    if isinstance(env, dict):
        for key, value in env.items():
            parts.append(f"{key}: {value}")
    return "\n".join(parts)


def has(text, markers):
    return any(re.search(marker, text) for marker in markers)


def disabled(job):
    """True only for a literal `if: false`, never for an expression."""
    condition = job.get("if")
    if isinstance(condition, bool):
        return condition is False
    return str(condition).strip().lower() == "false"


try:
    with open(path, encoding="utf-8") as handle:
        doc = yaml.safe_load(handle)
except Exception as exc:
    print(f"::error title=Registry parity gate cannot run::{path} did not parse: {exc}")
    sys.exit(INFRA)

if not isinstance(doc, dict) or not isinstance(doc.get("jobs"), dict):
    print(f"::error title=Registry parity gate cannot run::{path} has no jobs mapping.")
    sys.exit(INFRA)

basename = os.path.basename(path)
violations = []
in_scope = []
skipped_disabled = []

for job_name, job in doc["jobs"].items():
    if not isinstance(job, dict):
        continue
    steps = [s for s in (job.get("steps") or []) if isinstance(s, dict)]
    texts = [(s, step_text(s)) for s in steps]

    signs = [t for _, t in texts if COSIGN_SIGN in t]
    mirrors_hub = [
        t for _, t in texts if MIRROR_MARKER in t and has(t, HUB_MARKERS)
    ]

    if not signs or not mirrors_hub:
        continue

    if disabled(job):
        skipped_disabled.append(job_name)
        continue

    in_scope.append(job_name)

    # (a) Signing parity. The job pushes the image to Docker Hub, so a cosign
    #     signature must be made on the docker.io reference too -- a signature
    #     is scoped to the repository it was pushed to, so the ghcr one says
    #     nothing to anyone pulling from Docker Hub.
    if not any(has(t, HUB_MARKERS) for t in signs):
        violations.append(
            f"{basename} :: {job_name}\n"
            f"    mirrors an image to Docker Hub but its `cosign sign` step(s) reference\n"
            f"    only ghcr. A cosign signature lives in the repository it was pushed to,\n"
            f"    so signing the ghcr ref leaves every docker.io tag unverifiable even\n"
            f"    though the bytes are identical (#3562). Sign the docker.io digest too."
        )
    if not any(has(t, GHCR_MARKERS) for t in signs):
        violations.append(
            f"{basename} :: {job_name}\n"
            f"    signs a Docker Hub reference but no ghcr one. Parity runs both ways:\n"
            f"    every registry this job publishes to must be signed."
        )

    # (b) Verification parity. A gate pointed at one of two registries leaves
    #     exactly the hole #3562 records, and leaves it invisible.
    verifies = [t for _, t in texts if VERIFY_SCRIPT in t]
    if not verifies:
        violations.append(
            f"{basename} :: {job_name}\n"
            f"    signs and publishes but never runs {VERIFY_SCRIPT}. `cosign sign` prints\n"
            f"    nothing on the happy path, so a green signing step is not evidence that a\n"
            f"    signature reached the published tag (#3559)."
        )
    else:
        if not any(has(t, HUB_MARKERS) for t in verifies):
            violations.append(
                f"{basename} :: {job_name}\n"
                f"    verifies published tags on ghcr only. The Docker Hub tags this job\n"
                f"    wrote are exactly the ones that shipped unsigned for the whole life of\n"
                f"    the project (#3562); a gate that checks one of two registries would\n"
                f"    have stayed green through all of it. Pass the Docker Hub tag set too."
            )
        if not any(has(t, GHCR_MARKERS) for t in verifies):
            violations.append(
                f"{basename} :: {job_name}\n"
                f"    verifies published tags on Docker Hub only, not on ghcr."
            )

if skipped_disabled:
    print(
        "Skipped (disabled with a literal `if: false`, so it publishes nothing): "
        + ", ".join(sorted(skipped_disabled))
    )
    print(
        "  Re-enabling one of those jobs changes that `if:` and brings it into scope on"
    )
    print("  the same pull request. The exemption expires by itself.")

if violations:
    print("ERROR: a publish job does not sign and verify every registry it publishes to:\n")
    for violation in violations:
        print(f"  - {violation}\n")
    print(
        "See issue #3562. The bytes a user pulls by tag must be the bytes that were\n"
        "signed -- on whichever registry they pulled from."
    )
    sys.exit(BLOCK)

if len(in_scope) < MIN_SIGNING_JOBS:
    print(
        f"ERROR: found only {len(in_scope)} job(s) in {basename} that sign an image and\n"
        f"mirror it to Docker Hub; expected at least {MIN_SIGNING_JOBS}\n"
        f"(merge-backend, merge-openscap, merge-scanner-adapter).\n\n"
        "This gate's scope is defined by the presence of a cosign signing step, so\n"
        "deleting one would otherwise silently remove a job from its own guard --\n"
        "the same defect the gate exists to catch. If an image was intentionally\n"
        "retired, lower MIN_SIGNING_JOBS deliberately in this script."
    )
    sys.exit(BLOCK)

print(
    f"OK: {len(in_scope)} publish job(s) in {basename} sign and verify every registry "
    f"they publish to: " + ", ".join(sorted(in_scope)) + "."
)
PY
