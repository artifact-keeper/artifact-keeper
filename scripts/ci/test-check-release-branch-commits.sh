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
#   - and, more importantly, they must stay NARROW: a `chore(release):`
#     subject that also touches source, or a version-file-only commit under
#     some other subject, or a cherry-pick trailer naming a sha main does not
#     have, must all still FAIL. An exemption that is not tested from the
#     failing side is a hole, not an exemption.
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
run_case "chore(release) that also touches source -> FAIL" 1 "✗" case-prep-plus-source

git checkout -q -B case-version-only-wrong-subject "$BASE"
printf 'version = "1.9.4"\n' > Cargo.toml
git add -A && git commit -qm "chore: bump the version"
run_case "version-file-only under a non-release subject -> FAIL" 1 "✗" \
  case-version-only-wrong-subject

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
