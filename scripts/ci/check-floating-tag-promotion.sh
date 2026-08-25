#!/usr/bin/env bash
#
# CI gate: a floating container tag may only be written after the release gate.
#
# WHY THIS GATE IS LOAD-BEARING
# -----------------------------
# `:latest` and the `X.Y` series alias are what an operator gets when they
# express no opinion, so they are the tags that must never name uncertified
# bytes. Two properties of the publish pipeline used to break that, and both
# are invisible on any run where everything succeeds:
#
#   1. TIMING. `docker-publish.yml` runs on the tag push, which is necessarily
#      BEFORE the release gate -- it is what builds the bytes the gate tests.
#      A `type=raw,value=latest` line in a merge job therefore moves `:latest`
#      before any verdict exists. On v1.8.1 the publish finished 78 minutes
#      before the release was published; that was the NORMAL path, not a
#      failure path.
#   2. FAN-IN. `merge-backend`, `merge-openscap` and `merge-scanner-adapter`
#      are parallel siblings. A floating tag written inside one of them moves
#      as soon as THAT image passes, whatever happened to the other two, which
#      is how a partial publish becomes a public `:latest`.
#
# So the invariant is structural, not behavioural: exactly one job writes
# floating tags, it fans in from all three merge jobs, and it has no `if:`
# that could let it run when a sibling did not succeed.
#
# THE INVARIANTS
# --------------
#   1. ONE WRITER. In `docker-publish.yml`, no job other than the designated
#      floating-tag job may contain a floating-tag producer -- a
#      `type=raw,value=latest` or `type=semver,pattern={{major}}...` line in a
#      `docker/metadata-action` tag set, or a `type=raw` line fed from an
#      adapter `minor`/`major` step output. A job that is disabled outright
#      (`if: false`) is exempt and reported, because it publishes nothing.
#
#   2. THE WRITER FANS IN FROM EVERY MERGE JOB, UNCONDITIONALLY. It must
#      `needs:` every `merge-*` job that is not disabled, and it must carry no
#      job-level `if:`. The default `success()` on those `needs` IS the
#      control; an `if: !cancelled()` or `always()` would restore the
#      partial-publish hole exactly.
#
#   3. THE RELEASE PATH PROMOTES AFTER THE GATE. `release.yml` must contain a
#      job that dispatches the promote path with floating advance enabled, and
#      that job must `needs:` both the release gate and the release
#      publication -- otherwise "post-gate" is only a comment.
#
#   4. NON-VACUITY. If the writer job, the floating producers, or the
#      post-gate promotion cannot be found at all, this script FAILS rather
#      than passing because its subject disappeared.
#
# Exits non-zero (failing the build) on any drift.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKFLOW_DIR="${1:-$ROOT/.github/workflows}"

python3 - "$WORKFLOW_DIR" <<'PY'
import os
import re
import sys

import yaml

workflow_dir = sys.argv[1]

PUBLISH_WORKFLOW = "docker-publish.yml"
RELEASE_WORKFLOW = "release.yml"
WRITER_JOB = "apply-floating-tags"

# A "floating-tag producer" is one of the concrete mechanisms this pipeline has
# ever used to emit `:latest` / `:X.Y` / `:X`, and it is looked for ONLY inside
# a `docker/metadata-action` tag set. Matching the mechanism in the place it
# lives keeps the check precise in both directions: a comment or a log line
# mentioning "latest" is not a producer, and a re-added metadata tag line is
# one no matter what the surrounding comment claims.
METADATA_ACTION = "docker/metadata-action@"
PRODUCERS = (
    (re.compile(r"type=raw,\s*value=latest"), "type=raw,value=latest"),
    (re.compile(r"type=semver,\s*pattern=\{\{major\}\}"), "type=semver,pattern={{major}}..."),
    (re.compile(r"type=raw,\s*value=\$\{\{\s*steps\.[A-Za-z0-9_-]+\.outputs\.(minor|major)\s*\}\}"),
     "type=raw fed from an adapter minor/major output"),
)

errors = []


def load(name):
    path = os.path.join(workflow_dir, name)
    if not os.path.isfile(path):
        errors.append(f"{name} not found under {workflow_dir}.")
        return None
    with open(path, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def disabled(job):
    """A job gated `if: false` publishes nothing and is exempt."""
    return str(job.get("if", "")).strip().lower() in ("false", "${{ false }}")


def job_text(job):
    return yaml.safe_dump(job, default_flow_style=False)


def runs_text(job):
    """The job's own shell, without its YAML scaffolding.

    Deliberately not `job_text`: `runs-on: ubuntu-latest` contains the string
    "latest", so a non-vacuity check over the whole serialised job would pass
    for a writer that never writes `:latest` at all.
    """
    parts = []
    for step in job.get("steps") or []:
        if isinstance(step, dict):
            parts.append(str(step.get("name") or ""))
            parts.append(str(step.get("run") or ""))
    return "\n".join(parts)


def metadata_tag_sets(job):
    """Every `tags:` string handed to docker/metadata-action in this job."""
    for step in job.get("steps") or []:
        if not isinstance(step, dict):
            continue
        if not str(step.get("uses") or "").startswith(METADATA_ACTION):
            continue
        tags = (step.get("with") or {}).get("tags")
        if tags:
            yield str(step.get("name") or step.get("id") or "<unnamed>"), str(tags)


publish = load(PUBLISH_WORKFLOW)
release = load(RELEASE_WORKFLOW)

producers_seen = 0
disabled_with_producers = []

if publish is not None:
    jobs = publish.get("jobs") or {}

    # ── invariant 1: one writer ────────────────────────────────────────────
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        for step_name, tags in metadata_tag_sets(job):
            hits = [label for pattern, label in PRODUCERS if pattern.search(tags)]
            if not hits:
                continue
            producers_seen += len(hits)
            if job_name == WRITER_JOB:
                continue
            if disabled(job):
                disabled_with_producers.append(f"{job_name} :: {step_name} ({', '.join(hits)})")
                continue
            errors.append(
                f"{PUBLISH_WORKFLOW} :: {job_name} :: {step_name} emits a floating tag\n"
                f"    ({', '.join(hits)}). Only `{WRITER_JOB}` may write a floating tag. A\n"
                f"    merge job runs before the release gate and cannot see whether its\n"
                f"    sibling images published, so a floating tag written there can name\n"
                f"    uncertified bytes (v1.8.1: 78 minutes) or a partial publish (v1.7.2)."
            )

    # ── invariant 2: the writer fans in from every live merge job ──────────
    writer = jobs.get(WRITER_JOB)
    if not isinstance(writer, dict):
        errors.append(
            f"{PUBLISH_WORKFLOW} has no `{WRITER_JOB}` job. Floating tags have no owner,\n"
            f"    so nothing enforces that they are written after every merge job."
        )
    else:
        needs = writer.get("needs") or []
        if isinstance(needs, str):
            needs = [needs]
        live_merges = sorted(
            name for name, job in jobs.items()
            if name.startswith("merge-") and isinstance(job, dict) and not disabled(job)
        )
        missing = [m for m in live_merges if m not in needs]
        if missing:
            errors.append(
                f"{PUBLISH_WORKFLOW} :: {WRITER_JOB} does not `needs:` {', '.join(missing)}.\n"
                f"    It must fan in from EVERY live merge job, or a floating tag can move\n"
                f"    while one of the images failed to publish."
            )
        if "if" in writer:
            errors.append(
                f"{PUBLISH_WORKFLOW} :: {WRITER_JOB} carries a job-level `if:`\n"
                f"    ({writer['if']!r}). The default `success()` on its `needs:` IS the\n"
                f"    control here; an `if:` with `always()` or `!cancelled()` would let it\n"
                f"    run after a failed or skipped merge job, which is exactly the\n"
                f"    partial-publish hole it exists to close."
            )

# ── invariant 3: the release path promotes after the gate ──────────────────
if release is not None:
    jobs = release.get("jobs") or {}
    promoters = [
        (name, job) for name, job in jobs.items()
        if isinstance(job, dict) and "promote_floating" in job_text(job)
    ]
    if not promoters:
        errors.append(
            f"{RELEASE_WORKFLOW} has no job dispatching the floating promotion\n"
            f"    (`promote_floating`). Without it the floating tags are never applied\n"
            f"    at all, since the merge jobs no longer write them."
        )
    for name, job in promoters:
        needs = job.get("needs") or []
        if isinstance(needs, str):
            needs = [needs]
        for required in ("release-gate", "release"):
            if required not in needs:
                errors.append(
                    f"{RELEASE_WORKFLOW} :: {name} dispatches the floating promotion but\n"
                    f"    does not `needs: {required}`. \"After the gate\" has to be an edge in\n"
                    f"    the job graph; a comment saying so is not enforcement."
                )

# ── invariant 4: non-vacuity ───────────────────────────────────────────────
# There are legitimately ZERO live metadata producers now, so the anchor is the
# writer itself: it has to actually re-point tags, and one of them has to be
# `latest`. A gate whose subject quietly disappeared must go red, not green.
if publish is not None:
    writer = (publish.get("jobs") or {}).get(WRITER_JOB)
    if isinstance(writer, dict):
        text = runs_text(writer)
        if "imagetools create" not in text:
            errors.append(
                f"{PUBLISH_WORKFLOW} :: {WRITER_JOB} never runs `imagetools create`, so it\n"
                f"    writes no tag at all. Re-pointing an existing manifest-list digest is\n"
                f"    what makes the promotion build-free and digest-preserving; if that\n"
                f"    moved elsewhere, this gate is pointing at the wrong job."
            )
        if "latest" not in text:
            errors.append(
                f"{PUBLISH_WORKFLOW} :: {WRITER_JOB} does not mention `latest`. The floating\n"
                f"    tag this whole ordering exists for is not being written here."
            )

if errors:
    print("ERROR: floating tags are not confined to the post-gate promotion:\n")
    for error in errors:
        print(f"  - {error}\n")
    print(
        "A floating tag written before the release gate names bytes nothing has\n"
        "certified. See issues #2698 and #3540."
    )
    sys.exit(1)

for entry in disabled_with_producers:
    print(f"note: {entry} still declares floating tags but is disabled (`if: false`); exempt.")
print(
    f"OK: {producers_seen} floating-tag producer(s), all confined to "
    f"`{WRITER_JOB}` or to disabled jobs; the release path promotes after the gate."
)
PY
