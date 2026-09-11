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
# floating tags, it fans in from all three merge jobs, and its scheduling
# condition cannot let it run when a sibling did not succeed -- nor leave it
# skipped on the one path that exists to run it.
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
#   2. THE WRITER RUNS EXACTLY WHEN EVERY MERGE JOB SUCCEEDED. It must
#      `needs:` every `merge-*` job that is not disabled, and its job-level
#      `if:` is evaluated here the way GitHub schedules it, against two kinds
#      of run: with any merge job failed, cancelled or skipped it must NOT run
#      (`always()` / `!cancelled()` alone is the v1.7.2 partial-publish hole);
#      on a PROMOTE dispatch -- preflight and every merge succeeded, every
#      build job skipped by design -- it MUST run. The second half is #3652:
#      the first version had no `if:` at all, and the implicit `success()`
#      GitHub applies then is evaluated over the TRANSITIVE needs chain, so
#      the skipped build grandparents vetoed the job on every promote and the
#      post-gate promotion (#3540) never executed. The shape that satisfies
#      both is the barrier stated over DIRECT results:
#      `!cancelled() && needs.<merge>.result == 'success'` for each merge.
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


PREFLIGHT_JOB = "publish-preflight"

# ── a model of how GitHub schedules a job from its `if:` ──────────────────
# Only the subset a scheduling barrier needs: the status functions, `&&`,
# `||`, `!`, parentheses, quoted strings and `needs.<job>.result`. Anything
# else (other contexts, functions with arguments) is refused rather than
# guessed, so the gate cannot pass on an expression it did not understand.
STATUS_FUNCTIONS = ("success", "failure", "cancelled", "always")
TOKEN = re.compile(r"\s+|\$\{\{|\}\}|\(|\)|==|!=|&&|\|\||!|'[^']*'|[A-Za-z_][A-Za-z0-9_.\-]*")


class Unsupported(Exception):
    pass


def tokenize(expression):
    tokens, pos = [], 0
    while pos < len(expression):
        match = TOKEN.match(expression, pos)
        if not match:
            raise Unsupported(f"unrecognised text at {expression[pos:pos + 20]!r}")
        pos = match.end()
        token = match.group(0)
        if token.strip() and token not in ("${{", "}}"):
            tokens.append(token)
    return tokens


def evaluate(expression, results, direct_needs, ancestors):
    """Whether a job with this `if:` runs, given every other job's result.

    `ancestors` is the TRANSITIVE `needs` closure: that is what the status
    functions look at, and it is why a plain `success()` -- implicit whenever
    the expression uses no status function, and whenever there is no `if:`
    at all -- is vetoed by a skipped grandparent (#3652). `needs.<job>.result`
    is only defined for DIRECT needs, exactly as on GitHub.
    """
    functions = {
        "success": lambda: all(results[a] == "success" for a in ancestors),
        "failure": lambda: any(results[a] == "failure" for a in ancestors),
        "cancelled": lambda: any(results[a] == "cancelled" for a in ancestors),
        "always": lambda: True,
    }
    tokens = tokenize(expression)
    if not any(t in functions for t in tokens):
        tokens = ["success", "(", ")"] + (["&&", "("] + tokens + [")"] if tokens else [])
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def take(expected=None):
        nonlocal pos
        token = peek()
        if token is None or (expected is not None and token != expected):
            raise Unsupported(f"expected {expected or 'an operand'}, found {token!r}")
        pos += 1
        return token

    def parse_or():
        value = parse_and()
        while peek() == "||":
            take()
            value = parse_and() or value
        return value

    def parse_and():
        value = parse_equality()
        while peek() == "&&":
            take()
            value = parse_equality() and value
        return value

    def parse_equality():
        value = parse_unary()
        while peek() in ("==", "!="):
            operator = take()
            other = parse_unary()
            value = (value == other) if operator == "==" else (value != other)
        return value

    def parse_unary():
        if peek() == "!":
            take()
            return not parse_unary()
        return parse_primary()

    def parse_primary():
        token = take()
        if token == "(":
            value = parse_or()
            take(")")
            return value
        if token in functions:
            take("(")
            take(")")
            return functions[token]()
        if token.startswith("'"):
            return token[1:-1]
        result_ref = re.fullmatch(r"needs\.([A-Za-z0-9_\-]+)\.result", token)
        if result_ref and result_ref.group(1) in direct_needs:
            return results[result_ref.group(1)]
        raise Unsupported(f"cannot evaluate {token!r}")

    value = parse_or()
    if peek() is not None:
        raise Unsupported(f"unexpected {peek()!r}")
    return bool(value)


def transitive_needs(jobs, name):
    seen, stack = set(), list(needs_of(jobs.get(name)))
    while stack:
        dep = stack.pop()
        if dep in seen or dep not in jobs:
            continue
        seen.add(dep)
        stack.extend(needs_of(jobs[dep]))
    return sorted(seen)


def needs_of(job):
    needs = (job or {}).get("needs") or []
    return [needs] if isinstance(needs, str) else list(needs)


def check_writer_schedule(jobs, writer, direct_needs, live_merges):
    """Invariant 2: evaluate the writer's `if:` on the runs that matter."""
    condition = writer.get("if")
    expression = "" if condition is None else str(condition)
    shown = "<none>" if condition is None else " ".join(expression.split())
    ancestors = transitive_needs(jobs, WRITER_JOB)
    # Everything upstream of the merges other than preflight is a build/scan
    # job, and a PROMOTE dispatch skips all of them by design -- the
    # promotion is build-free (#3540). That is the run this job exists for.
    builders = [a for a in ancestors if a != PREFLIGHT_JOB and a not in live_merges]

    def run(mode, **overrides):
        results = {name: "success" for name in jobs}
        if mode == "promote":
            results.update({b: "skipped" for b in builders})
        results.update(overrides)
        return results

    scenarios = [("a normal push where every job succeeded", run("push"), True)]
    if builders:
        scenarios.append((
            "a PROMOTE dispatch (preflight and every merge job succeeded, "
            f"{', '.join(builders)} skipped by design)", run("promote"), True))
    for merge in live_merges:
        for outcome in ("failure", "cancelled", "skipped"):
            for mode in ("push", "promote"):
                scenarios.append((
                    f"a {mode} where {merge} ended {outcome}",
                    run(mode, **{merge: outcome}), False))

    for label, results, expected in scenarios:
        try:
            runs = evaluate(expression, results, direct_needs, ancestors)
        except Unsupported as exc:
            errors.append(
                f"{PUBLISH_WORKFLOW} :: {WRITER_JOB} has a job-level `if:` this gate cannot\n"
                f"    evaluate ({shown!r}: {exc}). It is a scheduling barrier over the\n"
                f"    merge jobs' `needs.<job>.result` and nothing else; anything the\n"
                f"    gate cannot evaluate offline is refused rather than trusted."
            )
            return
        if runs and not expected:
            errors.append(
                f"{PUBLISH_WORKFLOW} :: {WRITER_JOB} would RUN on {label}\n"
                f"    (job-level `if:` {shown!r}). Every live merge job's result must be\n"
                f"    exactly 'success' before a floating tag moves; `always()` or a bare\n"
                f"    `!cancelled()` lets it run after a failed or skipped merge, which is\n"
                f"    exactly the partial-publish hole it exists to close (v1.7.2)."
            )
            return
        if expected and not runs:
            errors.append(
                f"{PUBLISH_WORKFLOW} :: {WRITER_JOB} would be SKIPPED on {label}\n"
                f"    (job-level `if:` {shown!r}). An `if:` without a status function --\n"
                f"    or no `if:` at all -- gets an implicit `success()` that GitHub\n"
                f"    evaluates over the TRANSITIVE needs chain, so the build jobs a\n"
                f"    promote dispatch skips by design veto the one job that moves the\n"
                f"    floating tags after the gate (#3652). State the barrier over DIRECT\n"
                f"    results: `!cancelled() && needs.<merge>.result == 'success'` for\n"
                f"    every merge job."
            )
            return


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
        else:
            check_writer_schedule(jobs, writer, needs, live_merges)

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
