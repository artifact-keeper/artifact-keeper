#!/usr/bin/env bash
#
# Self-test for scripts/ci/check-release-branch-commits.sh (#1090, #3422).
#
# The gate is only exercised on PRs against `release/*`, which is a handful of
# runs per release — far too rare for a regression to surface on its own. So
# the interesting cases are built here as real (tiny) git repos rather than
# waited for:
#
#   - the two exemptions #3422 adds must PASS (release prep, narrowed
#     backport) — these were bypassed with `release-process: approved` four
#     times during the 1.7.6 cut because the gate could not express them;
#   - the gate must reach its verdict from the commits alone: since #4070 no
#     label skips it, so a non-ancestor, non-exempt commit must still FAIL
#     with every label-shaped variable in the environment;
#   - so must the three path C gained when it was unified with release
#     preflight check 5 (#3829): a changelog-only commit, a dependency bump
#     and a CI/workflow-only commit. A `docs(changelog):` commit used to
#     satisfy the preflight and be refused here, with a message about
#     cherry-picks that never mentioned path C;
#   - and, more importantly, every one of them must stay NARROW: a
#     `chore(release):` or `docs(changelog):` subject over a commit that also
#     touches source, a version-file-only commit under some other subject, or
#     a cherry-pick trailer naming a sha main does not have, must all still
#     FAIL. An exemption that is not tested from the failing side is a hole,
#     not an exemption.
#
# Usage: bash scripts/ci/test-check-release-branch-commits.sh
set -uo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/check-release-branch-commits.sh"
[ -f "$SCRIPT" ] || {
  echo "cannot find check-release-branch-commits.sh next to this test" >&2
  exit 2
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0

pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() {
  printf '  \033[31mFAIL\033[0m  %s\n' "$*"
  fails=$((fails + 1))
}

# ── fixture repo ────────────────────────────────────────────────────────────
#
# main:            m1 -> m2(feature) -> m3(feature2)
# release/1.9.x:   m1 -> (branch commits, one per case)
#
# Every case commits onto a fresh branch off `base` so the cases cannot
# interfere with each other.
REPO="$WORK/repo"
mkdir -p "$REPO"
cd "$REPO" || exit 2
git init -q -b main .
git config user.email t@example.com
git config user.name t
git config commit.gpgsign false

mkdir -p backend/src/api docker/scanner-adapter .github/release-notes
printf 'v1\n' > backend/src/lib.rs
printf 'version = "1.9.0"\n' > Cargo.toml
printf 'lock\n' > Cargo.lock
printf 'version = "1.9.0"\n' > backend/src/api/openapi.rs
printf '## [Unreleased]\n' > CHANGELOG.md
printf '1.2.3\n' > docker/scanner-adapter/VERSION
git add -A && git commit -qm "m1: base"
BASE="$(git rev-parse HEAD)"

printf 'feature\n' > backend/src/feature.rs
git add -A && git commit -qm "feat: a feature that lands on main first"
MAIN_FEATURE="$(git rev-parse HEAD)"

printf 'feature2\n' > backend/src/feature2.rs
git add -A && git commit -qm "feat: a second feature on main"
MAIN_FEATURE2="$(git rev-parse HEAD)"
git branch -q main-ref HEAD # stands in for origin/main

run_case() { # <label> <expected-exit> <expected-substring> <head-ref> [base-ref]
  local label="$1" want="$2" needle="$3" head="$4" base="${5:-$BASE}"
  local out got
  out="$(cd "$REPO" && MAIN_REF=main-ref MAIN_SCAN_DEPTH=50 bash "$SCRIPT" "$base" "$head" 2>&1)"
  got=$?
  if [ "$got" != "$want" ]; then
    fail "$label: expected exit $want, got $got"
    printf '%s\n' "$out" | sed 's/^/        /' >&2
  elif [ -n "$needle" ] && ! printf '%s\n' "$out" | grep -qF "$needle"; then
    fail "$label: exit $got correct but output lacks '$needle'"
    printf '%s\n' "$out" | sed 's/^/        /' >&2
  else
    pass "$label (exit $got)"
  fi
}

echo "check-release-branch-commits (#1090, #3422)"

# ── Path A: already on main ────────────────────────────────────────────────
run_case "commit already on main -> pass" 0 "on main" "$MAIN_FEATURE2" "$BASE"

# ── Path B: clean cherry-pick (patch-id match) ─────────────────────────────
# MAIN_FEATURE2 rather than MAIN_FEATURE: picking a commit straight onto its
# own parent reproduces it byte for byte, which would exercise path A again.
git checkout -q -B case-cherry "$BASE"
git cherry-pick "$MAIN_FEATURE2" > /dev/null 2>&1
run_case "clean cherry-pick -> pass (patch-id)" 0 "cherry-pick of" case-cherry

# ── Path C: release prep ───────────────────────────────────────────────────
git checkout -q -B case-prep "$BASE"
mkdir -p .github/release-notes
printf 'version = "1.9.1"\n' > Cargo.toml
printf 'lock2\n' > Cargo.lock
printf 'version = "1.9.1"\n' > backend/src/api/openapi.rs
printf '## [Unreleased]\n\n## [1.9.1] - 2026-01-01\n' > CHANGELOG.md
printf '1.2.4\n' > docker/scanner-adapter/VERSION
printf 'notes\n' > .github/release-notes/1.9.1.md
git add -A && git commit -qm "chore(release): prepare 1.9.1"
run_case "release prep, allowlisted paths only -> pass" 0 "release prep" case-prep

# A rename inside .github/release-notes/ is the shape the real 1.7.6 prep had
# (1.7.5.md -> 1.7.6.md). Both ends of the rename must be checked, which is
# why the script uses `git diff-tree -r` WITHOUT rename detection.
git checkout -q -B case-prep-rename "$BASE"
mkdir -p .github/release-notes
printf 'notes\n' > .github/release-notes/1.9.1.md
git add -A && git commit -qm "docs: seed notes"
git mv .github/release-notes/1.9.1.md .github/release-notes/1.9.2.md
printf 'version = "1.9.2"\n' > Cargo.toml
git add -A && git commit -qm "chore(release): prepare 1.9.2"
run_case "release prep with a release-notes rename -> pass" 0 "release prep" \
  case-prep-rename "case-prep-rename~1"

# ── Path C stays narrow ────────────────────────────────────────────────────
git checkout -q -B case-prep-plus-source "$BASE"
printf 'version = "1.9.3"\n' > Cargo.toml
printf 'sneaky\n' > backend/src/sneaky.rs
git add -A && git commit -qm "chore(release): prepare 1.9.3"
run_case "chore(release) that also touches source -> FAIL" 1 \
  "outside the release prep path set" case-prep-plus-source

# `chore: rewrite the version` and not `chore: bump ...`: a `bump` subject over
# manifests alone IS exempt (the dependency-bump rule, below), and the point of
# this case is the OTHER half — that a subject outside the exemption set does
# not become one by touching only version files.
git checkout -q -B case-version-only-wrong-subject "$BASE"
printf 'version = "1.9.4"\n' > Cargo.toml
git add -A && git commit -qm "chore: rewrite the version"
run_case "version-file-only under a non-exempt subject -> FAIL" 1 "path C" \
  case-version-only-wrong-subject

# ── Path C: the three shapes unified with preflight check 5 (#3829) ────────
# A CHANGELOG-only commit. It satisfied the preflight and was refused here,
# which is the round trip #3829 was filed for.
git checkout -q -B case-changelog "$BASE"
printf '## [Unreleased]\n\n- **a late entry** (#1).\n' > CHANGELOG.md
git add -A && git commit -qm "docs(changelog): record the late fix"
run_case "changelog-only commit -> pass" 0 "changelog-only commit" case-changelog

# The same two shapes since CHANGELOG fragments (changes/unreleased/): a late
# entry is a new fragment, and a release prep assembles the fragments into
# CHANGELOG.md and deletes them. Both must stay exempt, or every cut after
# the switch is refused here.
git checkout -q -B case-changelog-fragment "$BASE"
mkdir -p changes/unreleased
printf -- '---\nsection: Fixed\nissues: [#1]\n---\n- **a late entry** (#1).\n' > changes/unreleased/1-a-late-entry.md
git add -A && git commit -qm "docs(changelog): record the late fix"
run_case "changelog-only commit adding a fragment -> pass" 0 "changelog-only commit" case-changelog-fragment
git checkout -q -B case-prep-assembles case-changelog-fragment
git rm -q changes/unreleased/1-a-late-entry.md
printf 'version = "1.9.1"\n' > Cargo.toml
printf '## [Unreleased]\n\n## [1.9.1] - 2026-01-01\n\n### Fixed\n\n- **a late entry** (#1).\n' > CHANGELOG.md
git add -A && git commit -qm "chore(release): prepare 1.9.1"
run_case "release prep that assembles and deletes fragments -> pass" 0 "release prep" \
  case-prep-assembles case-changelog-fragment

# ...and it stays narrow in the path dimension.
git checkout -q -B case-changelog-plus-source "$BASE"
printf '## [Unreleased]\n' > CHANGELOG.md
printf 'sneaky\n' > backend/src/sneaky.rs
git add -A && git commit -qm "docs(changelog): record the late fix"
run_case "docs(changelog) that also touches source -> FAIL" 1 \
  "outside the changelog-only commit path set" case-changelog-plus-source

# A dependency bump: manifests and lockfiles only.
git checkout -q -B case-bump "$BASE"
printf 'lock-bumped\n' > Cargo.lock
git add -A && git commit -qm "chore(deps): bump serde from 1.0.1 to 1.0.2"
run_case "dependency bump over lockfiles -> pass" 0 "dependency bump" case-bump

# A `bump` subject is not a licence: the branch gate would otherwise accept any
# content on a maintenance branch under a chosen title, which is the exact hole
# path C was written narrow to avoid.
git checkout -q -B case-bump-plus-source "$BASE"
printf 'lock-bumped\n' > Cargo.lock
printf 'sneaky\n' > backend/src/sneaky.rs
git add -A && git commit -qm "chore(deps): bump serde from 1.0.1 to 1.0.2"
run_case "dependency bump that also touches source -> FAIL" 1 \
  "outside the dependency bump path set" case-bump-plus-source

# A bump on a maintenance line is user-visible and writes its own CHANGELOG
# entry in the same commit (#4070). That is the shape PR #3893's rustls /
# wasmtime bump had, and the label was what carried it through; the changelog
# set is part of the bump path set so it does not need one.
git checkout -q -B case-bump-with-changelog "$BASE"
printf 'lock-bumped\n' > Cargo.lock
printf '## [Unreleased]\n\n- **bump rustls** (#1).\n' > CHANGELOG.md
git add -A && git commit -qm "chore(deps): bump rustls from 0.23.44 to 0.23.45"
run_case "dependency bump that writes its own CHANGELOG entry -> pass" 0 \
  "dependency bump" case-bump-with-changelog

# ...and the widened set stays narrow in the direction that matters.
git checkout -q -B case-bump-changelog-plus-source "$BASE"
printf 'lock-bumped\n' > Cargo.lock
printf '## [Unreleased]\n\n- **bump rustls** (#1).\n' > CHANGELOG.md
printf 'sneaky\n' > backend/src/sneaky.rs
git add -A && git commit -qm "chore(deps): bump rustls from 0.23.44 to 0.23.45"
run_case "bump + CHANGELOG that also touches source -> FAIL" 1 \
  "outside the dependency bump path set" case-bump-changelog-plus-source

# A CI/workflow-only commit, whatever its subject: `git cherry-pick -x` of a
# tooling forward-port keeps the subject of the commit it came from, and
# nothing in that path set ships to a user.
git checkout -q -B case-ci-only "$BASE"
mkdir -p .github/workflows scripts/ci
printf 'name: ci\n' > .github/workflows/tooling.yml
printf 'echo hi\n' > scripts/ci/tooling.sh
git add -A && git commit -qm "feat(ci): forward-port the release tooling"
run_case "CI/workflow-only commit -> pass" 0 "CI/workflow-only commit" case-ci-only

# A CI subject over a commit that also edits source is not CI-only.
git checkout -q -B case-ci-plus-source "$BASE"
mkdir -p .github/workflows
printf 'name: ci\n' > .github/workflows/tooling.yml
printf 'sneaky\n' > backend/src/sneaky.rs
git add -A && git commit -qm "feat(ci): forward-port the release tooling"
run_case "CI subject that also touches source -> FAIL" 1 "path C" case-ci-plus-source

# ── Path D: narrowed backport ──────────────────────────────────────────────
# Same intent as MAIN_FEATURE but a different patch (a hunk resolved away),
# carrying the -x trailer. patch-id cannot match by construction.
git checkout -q -B case-narrowed "$BASE"
printf 'feature-but-narrowed\n' > backend/src/feature.rs
git add -A
git commit -qm "feat: a feature that lands on main first

(cherry picked from commit ${MAIN_FEATURE})"
run_case "narrowed backport, trailer on main -> pass" 0 "narrowed backport of" case-narrowed

# ── Path D stays narrow ────────────────────────────────────────────────────
git checkout -q -B case-bogus-trailer "$BASE"
printf 'invented\n' > backend/src/invented.rs
git add -A
git commit -qm "feat: invented locally

(cherry picked from commit 0123456789abcdef0123456789abcdef01234567)"
run_case "trailer naming a sha main does not have -> FAIL" 1 "not on main-ref" \
  case-bogus-trailer

# ── The original failure this gate exists for (#1068) ──────────────────────
git checkout -q -B case-branch-only "$BASE"
printf 'authored here\n' > backend/src/branch_only.rs
git add -A && git commit -qm "fix: authored directly against the release branch"
run_case "branch-only commit -> FAIL" 1 "✗" case-branch-only
# The failure message must name path C, not just "not a cherry-pick" (#3829):
# it is the applicable rule for every release-hygiene commit, and the old text
# listed three remedies without mentioning it once.
out="$(cd "$REPO" && MAIN_REF=main-ref MAIN_SCAN_DEPTH=50 bash "$SCRIPT" "$BASE" case-branch-only 2>&1)"
if printf '%s\n' "$out" | grep -qF "C. it is an exempt release-hygiene commit"; then
  pass "the failure message names path C"
else
  fail "the failure message does not name path C"
  printf '%s\n' "$out" | sed 's/^/        /' >&2
fi

# ── No label can satisfy the gate (#4070) ──────────────────────────────────
#
# `release-process: approved` used to skip the whole job in the workflow, and a
# skipped job still concluded success, so the required `Verify commits trace
# back to main` context was satisfiable by anyone who could open a PR against
# `release/*` and label it. The verdict now comes from the commits alone: this
# script reads no label, and the workflow runs it unconditionally (pinned
# separately by test-release-branch-gate.sh). Re-run the #1068 shape with every
# label-shaped variable set to the approving value — it must still FAIL.
out="$(
  cd "$REPO" \
    && MAIN_REF=main-ref MAIN_SCAN_DEPTH=50 \
      RELEASE_PROCESS_APPROVED=true \
      SKIP=true \
      LABELS='["release-process: approved"]' \
      LABELS_JSON='[{"name":"release-process: approved"}]' \
      GITHUB_EVENT_PATH=/dev/null \
      bash "$SCRIPT" "$BASE" case-branch-only 2>&1
)"
got=$?
if [ "$got" = "1" ]; then
  pass "a 'release-process: approved' environment cannot satisfy the gate (exit 1)"
else
  fail "label env: expected the branch-only commit to still fail (exit 1), got $got"
  printf '%s\n' "$out" | sed 's/^/        /' >&2
fi
# ...and the remedy must not send the reader back to the label.
if printf '%s\n' "$out" | grep -qF "There is no label that waives this."; then
  pass "the remedy says the label waives nothing"
else
  fail "the remedy still offers the label as an escape hatch"
  printf '%s\n' "$out" | sed 's/^/        /' >&2
fi

# ── Degenerate inputs ──────────────────────────────────────────────────────
run_case "empty range -> pass with a notice" 0 "nothing to verify" "$BASE" "$BASE"

out="$(cd "$REPO" && MAIN_REF=no-such-ref bash "$SCRIPT" "$BASE" "$MAIN_FEATURE" 2>&1)"
got=$?
if [ "$got" = "2" ] && printf '%s\n' "$out" | grep -qF "INFRA"; then
  pass "unresolvable MAIN_REF -> INFRA (exit 2)"
else
  fail "unresolvable MAIN_REF: expected exit 2 with INFRA, got $got"
fi

out="$(cd "$REPO" && MAIN_REF=main-ref bash "$SCRIPT" 2>&1)"
got=$?
if [ "$got" = "2" ] && printf '%s\n' "$out" | grep -qF "usage"; then
  pass "missing arguments -> INFRA (exit 2)"
else
  fail "missing arguments: expected exit 2 with usage, got $got"
fi

echo
if [ "$fails" -gt 0 ]; then
  echo "$fails case(s) failed"
  exit 1
fi
echo "all cases passed"
