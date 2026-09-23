#!/usr/bin/env bash
#
# Self-test for scripts/ci/check-changelog-placement.sh (#3797).
#
# The gate fires on a shape that only exists for a few days around each
# release cut — a branch whose bullet was written before the cut and merged
# after it — so waiting for a live example means waiting for the next time
# somebody gets burned. The four that prompted the issue (#3570, #3619, #3627,
# #3628) all merged CLEAN; there was nothing to see.
#
# So every leg is built here as a real (tiny) git repo, and the failing
# direction matters as much as the passing one:
#
#   - a bullet under `[Unreleased]` must PASS, and a release prep — which
#     renames the heading over bullets it does not touch — must PASS too,
#     because a gate that fires on every release PR gets turned off;
#   - a bullet under a released heading must FAIL and must NAME both the
#     bullet and the heading it landed under;
#   - a heading left with nothing under it must FAIL, while the prose
#     `### Upgrade note — …` subsections released versions carry must not;
#   - a bullet with no `#NNNN` must WARN and must NOT fail;
#   - and an unmeasurable branch (no base ref, no merge base) must report
#     INFRA, never a pass — a shallow clone is exactly how this gate would
#     otherwise go quietly green forever.
#
# Cases 11-17 cover CHANGELOG fragments (changes/unreleased/, one file per
# PR): a valid fragment with CHANGELOG.md untouched passes; an invalid or
# misplaced one fails; a release prep that ASSEMBLES the fragments into a new
# `## [X.Y.Z]` section -- built here by the real assembler -- passes, while a
# bullet stranded under an existing released heading still fails even inside
# such a prep; and a legacy bullet under `[Unreleased]` passes with a notice
# (the transition window).
#
# Usage: bash scripts/ci/test-check-changelog-placement.sh
set -uo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/check-changelog-placement.sh"
[ -f "$SCRIPT" ] || {
  echo "cannot find check-changelog-placement.sh next to this test" >&2
  exit 2
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
n=0
r=""

pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() {
  printf '  \033[31mFAIL\033[0m  %s\n' "$*"
  fails=$((fails + 1))
}

# The state of CHANGELOG.md on `main` before the branch is cut: an open
# [Unreleased] with one bullet, above one shipped release.
base_changelog() {
  cat << 'EOF'
# Changelog

## [Unreleased]

### Fixed

- **a fix that is already pending** (#1000)

### Changed

- **a change that is already pending** (#1001)

## [1.9.0] - 2026-09-01

### Fixed

- **something that actually shipped in 1.9.0** (#900)

### Upgrade note — this heading is prose, not a list

The release notes carry paragraphs like this one under a `### ` heading, and
they are not empty sections.
EOF
}

# Sets $r to a fresh repo whose `main` holds base_changelog, with a `pr`
# branch checked out off it. Not a function that prints the path: the case
# counter has to survive, and a subshell would swallow it.
make_repo() {
  n=$((n + 1))
  r="$WORK/repo.$n"
  mkdir -p "$r"
  git -C "$r" init -q -b main . > /dev/null
  git -C "$r" config user.email t@example.com
  git -C "$r" config user.name t
  git -C "$r" config commit.gpgsign false
  base_changelog > "$r/CHANGELOG.md"
  printf 'v1\n' > "$r/src.txt"
  git -C "$r" add -A
  git -C "$r" commit -qm "base" > /dev/null
  git -C "$r" checkout -q -b pr
}

commit_pr() { git -C "$r" add -A && git -C "$r" commit -qm "pr change" > /dev/null; }

run_case() { # <label> <expected-exit> <expected-substring> [base-ref]
  local label="$1" want="$2" needle="$3" base="${4:-main}" out got
  out="$(cd "$r" && GITHUB_EVENT_NAME=pull_request bash "$SCRIPT" "$base" 2>&1)"
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

echo "check-changelog-placement (#3797)"

# 1. The normal shape: a bullet added under [Unreleased].
make_repo
python3 - "$r/CHANGELOG.md" << 'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace("- **a fix that is already pending** (#1000)\n",
              "- **a fix that is already pending** (#1000)\n\n- **the bullet this PR adds** (#3797)\n")
open(p, 'w').write(s)
PY
commit_pr
run_case "bullet added under [Unreleased] -> pass" 0 "all under '## [Unreleased]'"

# 2. THE REGRESSION (#3570): the cut renamed the heading this branch anchored
#    to, the merge was clean, and the bullet now documents a shipped release.
make_repo
python3 - "$r/CHANGELOG.md" << 'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace("- **something that actually shipped in 1.9.0** (#900)\n",
              "- **something that actually shipped in 1.9.0** (#900)\n\n- **the bullet this PR adds** (#3797)\n")
open(p, 'w').write(s)
PY
commit_pr
run_case "bullet added under a released section -> fail" 1 "the bullet this PR adds"

# 2b. The message has to name the heading, not just the bullet — "somewhere
#     in CHANGELOG.md" sends the reader scrolling.
out="$(cd "$r" && GITHUB_EVENT_NAME=pull_request bash "$SCRIPT" main 2>&1)"
if printf '%s\n' "$out" | grep -qF "## [1.9.0] - 2026-09-01" \
  && printf '%s\n' "$out" | grep -qF "### Fixed"; then
  pass "failure names the '## [' heading and the '### ' subheading"
else
  fail "failure should name both headings"
  printf '%s\n' "$out" | sed 's/^/        /' >&2
fi

# 3. Removing the last bullet under a heading strands the heading (#3795).
make_repo
python3 - "$r/CHANGELOG.md" << 'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace("- **a change that is already pending** (#1001)\n", "")
open(p, 'w').write(s)
PY
commit_pr
run_case "bullet removed, heading left behind -> fail" 1 "has no content before the next heading"

# 4. A bullet whose first reference is not a `#NNNN` WARNS. It must not fail:
#    some entries genuinely have no issue, and failing them would push people
#    to invent references, which is worse than the problem.
make_repo
python3 - "$r/CHANGELOG.md" << 'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace("- **a fix that is already pending** (#1000)\n",
              "- **a fix that is already pending** (#1000)\n\n- **an advisory-only entry** (GHSA-ww52-pmcg-f53c).\n")
open(p, 'w').write(s)
PY
commit_pr
run_case "added bullet with no #NNNN -> warn, still pass" 0 "has no #NNNN reference"

# 5. A release prep renames `## [Unreleased]` to `## [X.Y.Z] - <date>` over
#    bullets it does not touch and opens a fresh one. Those bullets are
#    CONTEXT in the diff, not additions, so the gate must stay silent — this
#    is the one PR per release that would otherwise always be red.
make_repo
python3 - "$r/CHANGELOG.md" << 'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace("## [Unreleased]\n", "## [Unreleased]\n\n## [1.9.1] - 2026-09-16\n", 1)
open(p, 'w').write(s)
PY
commit_pr
run_case "release prep renames the heading over untouched bullets -> pass" 0 "CHANGELOG placement: clean"

# 6. A branch that does not touch CHANGELOG.md at all is not this gate's
#    business, and must not be failed for pre-existing state.
make_repo
printf 'v2\n' > "$r/src.txt"
commit_pr
run_case "branch does not touch CHANGELOG.md -> pass" 0 "unchanged on this branch"

# 7. Non-pull-request events are a no-op with a message that says why, rather
#    than a silent exit 0 that looks like a verdict.
make_repo
commit_pr 2> /dev/null || true
out="$(cd "$r" && GITHUB_EVENT_NAME=push bash "$SCRIPT" main 2>&1)"
got=$?
if [ "$got" = "0" ] && printf '%s\n' "$out" | grep -qF "no-op on 'push' events"; then
  pass "push event -> no-op with a clear message (exit 0)"
else
  fail "push event: expected exit 0 with a no-op message, got $got"
  printf '%s\n' "$out" | sed 's/^/        /' >&2
fi

# 8. A base ref that does not resolve is INFRA (exit 2), never a pass.
make_repo
run_case "unresolvable base ref -> INFRA" 2 "does not resolve" "origin/no-such-branch"

# 9. No common ancestor — the shallow-clone shape — is INFRA too, and the
#    message has to name fetch-depth, which is the actual fix.
make_repo
git -C "$r" checkout -q --orphan orphan
base_changelog > "$r/CHANGELOG.md"
git -C "$r" add -A && git -C "$r" commit -qm "orphan" > /dev/null
run_case "no merge base with the base ref -> INFRA" 2 "fetch-depth: 0"

# 10. A directory that is not a git repository is INFRA as well.
mkdir -p "$WORK/not-a-repo"
out="$(cd "$WORK/not-a-repo" && GITHUB_EVENT_NAME=pull_request bash "$SCRIPT" main 2>&1)"
got=$?
if [ "$got" = "2" ] && printf '%s\n' "$out" | grep -qF "INFRA"; then
  pass "non-repository -> INFRA (exit 2)"
else
  fail "non-repository: expected exit 2 with INFRA, got $got"
fi

FRAGMENT_TOOL="$(dirname "$SCRIPT")/changelog-fragments.py"
frag() { # <repo-relative path> <section> <issue> <lead>
  mkdir -p "$r/$(dirname "$1")"
  printf -- '---\nsection: %s\nissues: [#%s]\n---\n- **%s** (#%s). Why and what.\n' \
    "$2" "$3" "$4" "$3" > "$r/$1"
}

# 11. THE NEW NORMAL: a fragment, CHANGELOG.md untouched.
make_repo
frag changes/unreleased/4200-a-new-fix.md Fixed 4200 "a new fix"
commit_pr
run_case "valid fragment, CHANGELOG.md untouched -> pass" 0 "1 CHANGELOG fragment(s) added or edited on this branch, all valid"

# 12. An invalid fragment fails the PR that adds it, naming the file.
make_repo
frag changes/unreleased/4200-a-new-fix.md Bugfix 4200 "a new fix"
commit_pr
run_case "invalid fragment -> fail" 1 "changes/unreleased/4200-a-new-fix.md"

# 13. A fragment outside changes/unreleased/ is never assembled.
make_repo
frag changes/4200-a-new-fix.md Fixed 4200 "a new fix"
commit_pr
run_case "fragment outside changes/unreleased/ -> fail" 1 "is not directly in changes/unreleased/"

# 14. THE RELEASE PREP. main carries two fragments and a legacy bullet; the
#     prep runs the real assembler, which deletes the fragments and ADDS
#     bullets under a new `## [1.9.1]` heading. That heading is added by this
#     branch, so the bullets under it are the cut, not a stranded entry.
make_repo
git -C "$r" checkout -q main
frag changes/unreleased/4200-a-new-fix.md Fixed 4200 "a new fix"
frag changes/unreleased/4201-a-new-feature.md Added 4201 "a new feature"
git -C "$r" add -A && git -C "$r" commit -qm "fragments on main" > /dev/null
git -C "$r" checkout -q -B pr main
if python3 "$FRAGMENT_TOOL" assemble 1.9.1 --date 2026-09-23 \
    --changelog "$r/CHANGELOG.md" --dir "$r/changes/unreleased" 2> /dev/null; then
  commit_pr
  run_case "release prep assembling fragments into a new section -> pass" 0 "under a version heading this branch adds"
else
  fail "the assembler refused the release-prep fixture"
fi

# 15. ...but the exemption is for the heading the branch adds, not for any
#     branch that adds a heading: a bullet slipped under the RELEASED 1.9.0 in
#     the same prep is still the #3570 shape.
python3 - "$r/CHANGELOG.md" << 'PY2'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace("- **something that actually shipped in 1.9.0** (#900)\n",
              "- **something that actually shipped in 1.9.0** (#900)\n\n- **stranded in the prep** (#4202)\n")
open(p, 'w').write(s)
PY2
commit_pr
run_case "bullet under a released heading inside a prep -> still fail" 1 "stranded in the prep"

# 16. THE TRANSITION WINDOW: a legacy bullet under [Unreleased] passes, with a
#     notice pointing at the fragment path.
make_repo
python3 - "$r/CHANGELOG.md" << 'PY2'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace("- **a fix that is already pending** (#1000)\n",
              "- **a fix that is already pending** (#1000)\n\n- **a legacy-style bullet** (#4203)\n")
open(p, 'w').write(s)
PY2
commit_pr
run_case "legacy bullet under [Unreleased] -> pass with a notice" 0 "CHANGELOG entry could be a fragment"

# 17. A bullet directly under a released `## [` heading, with no `### `
#     between them, is misplaced too. The row used to be tab-separated, `read`
#     collapsed the empty subheading field, and the bullet was skipped.
make_repo
python3 - "$r/CHANGELOG.md" << 'PY2'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace("## [1.9.0] - 2026-09-01\n", "## [1.9.0] - 2026-09-01\n\n- **no subheading** (#4204)\n")
open(p, 'w').write(s)
PY2
commit_pr
run_case "bullet directly under a released heading -> fail" 1 "no subheading"

echo
if [ "$fails" -gt 0 ]; then
  echo "$fails case(s) failed"
  exit 1
fi
echo "all cases passed"
