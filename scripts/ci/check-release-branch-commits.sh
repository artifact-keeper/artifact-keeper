#!/usr/bin/env bash
#
# Release branch gate (#1090 / #1068, extended by #3422).
#
# Verifies that every commit a PR adds to a `release/*` maintenance branch
# traces back to `main`. Four ways a commit can qualify:
#
#   A. it is literally an ancestor of main (a merge-forward of main);
#   B. a commit with the same `git patch-id` exists on main (a clean
#      cherry-pick or rebase);
#   C. it is an EXEMPT release-hygiene commit — a release prep
#      (`chore(release): ...`), a changelog-only commit
#      (`docs(changelog): ...`), a dependency bump, or a commit whose changed
#      paths are all CI/workflow paths. The version being prepared exists only
#      on the maintenance branch, so there is nothing on main to trace to and
#      there should not be. Before #3422 this had to be waved through with
#      `release-process: approved` on every single cut; the 1.7.6 cut burned
#      that label four times in one release, which is what made the bypass
#      routine enough to stop being noticed (#4070);
#   D. it is a NARROWED BACKPORT — a commit carrying a
#      `(cherry picked from commit <sha>)` trailer whose sha is on main, but
#      whose patch-id differs because hunks that could not apply were
#      resolved away (a guard test depending on scaffolding the branch does
#      not have, a CHANGELOG hunk targeting `[Unreleased]` when the branch
#      needs `[1.7.6]`). The narrowing is real and worth seeing, so it is
#      logged as "narrowed backport of <sha>" rather than passed silently.
#
# Anything else still fails, and there is no way to wave it through: a commit
# authored directly against the maintenance branch that never went through main
# is exactly what this gate exists to stop (PR #1068 bundled +1489 lines that
# way and forced a revert mid-RC cycle). The `release-process: approved` label
# used to skip the whole job in the workflow, which made the required status
# context satisfiable by whoever opened the PR (#4070); it is now a review
# marker with no effect on any gate. A shape that genuinely belongs on a
# release line belongs in the exemption set, where it is reviewed.
#
# C is deliberately narrow in BOTH dimensions — subject AND path set. A
# `chore(release):` commit that also touches backend source is not a release
# prep, and a version-file-only commit with some other subject is not either.
# Widening one without the other would turn the exemption into a hole a real
# drift could walk through.
#
# C's rules are NOT defined here: they live in
# scripts/ci/release-commit-exemptions.sh, because release preflight check 5
# asks the same "does this commit owe a CHANGELOG entry / a trip through
# main?" question and the two answers used to disagree (#3829) — a
# `docs(changelog):` commit satisfied the preflight and was refused here, with
# a message about cherry-picks that never named path C at all.
#
# Usage:  check-release-branch-commits.sh <base-sha> <head-sha>
#
# Env:
#   MAIN_REF          ref to trace against (default origin/main); the
#                     self-test points this at fixture branches.
#   MAIN_SCAN_DEPTH   how many main commits to index patch-ids from
#                     (default 1500, ~3 months of main at typical velocity).
#
# Exit codes: 0 all commits trace back, 1 one or more do not, 2 infra
# (MAIN_REF missing / unreadable range).
set -euo pipefail

# Path C's rules, shared with release preflight check 5 (#3829). It ships with
# this script; on a maintenance branch that cherry-picked one without the
# other, say so rather than dying on "No such file or directory".
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -r "${_here}/release-commit-exemptions.sh" ]]; then
  echo "INFRA: ${_here}/release-commit-exemptions.sh is missing. It carries path C's exemption rules and is cherry-picked alongside this script (artifact-keeper#3829)." >&2
  exit 2
fi
# shellcheck source=scripts/ci/release-commit-exemptions.sh
. "${_here}/release-commit-exemptions.sh"

MAIN_REF="${MAIN_REF:-origin/main}"
MAIN_SCAN_DEPTH="${MAIN_SCAN_DEPTH:-1500}"

BASE_SHA="${1:-}"
HEAD_SHA="${2:-}"
if [[ -z "$BASE_SHA" || -z "$HEAD_SHA" ]]; then
  echo "INFRA: usage: $(basename "$0") <base-sha> <head-sha>" >&2
  exit 2
fi

if ! git rev-parse --verify --quiet "${MAIN_REF}^{commit}" > /dev/null; then
  echo "INFRA: MAIN_REF '${MAIN_REF}' does not resolve to a commit" >&2
  exit 2
fi

# Enumerated into a variable first, not straight into `mapfile` from a process
# substitution: mapfile reports success even when the producer failed, which
# would turn an unreadable range into "no commits to verify" — a silent pass.
if ! rev_list="$(git rev-list --no-merges "${BASE_SHA}..${HEAD_SHA}")"; then
  echo "INFRA: cannot enumerate ${BASE_SHA}..${HEAD_SHA}" >&2
  exit 2
fi
mapfile -t pr_commits <<< "$rev_list"
# A single empty line from an empty rev-list becomes one empty element.
if [[ ${#pr_commits[@]} -eq 1 && -z "${pr_commits[0]}" ]]; then
  pr_commits=()
fi

if [[ ${#pr_commits[@]} -eq 0 ]]; then
  echo "::notice::PR contains no non-merge commits; nothing to verify."
  exit 0
fi

# ── Path C helper ───────────────────────────────────────────────────────────
#
# The predicate itself is release_commit_exemption() from
# release-commit-exemptions.sh: `chore(release):` / `docs(changelog):` /
# a dependency bump, each confined to its own path set, plus any commit whose
# changed paths are all CI/workflow paths. It also exports
# $RELEASE_EXEMPTION_RULE and $RELEASE_EXEMPTION_DETAIL so a refusal can name
# the rule the commit actually failed rather than talking about cherry-picks.

# ── Path D helpers ──────────────────────────────────────────────────────────

# Echoes the sha of the last `(cherry picked from commit <sha>)` trailer in
# the commit message, if any. Last rather than first: a chain of backports
# accumulates trailers and the most recent one names the commit this one was
# actually taken from.
cherry_pick_source() {
  git log -1 --format='%B' "$1" \
    | sed -n 's/^[[:space:]]*(cherry picked from commit \([0-9a-f]\{7,40\}\))[[:space:]]*$/\1/p' \
    | tail -n1
}

# ── Index main ──────────────────────────────────────────────────────────────

echo "Indexing patch-ids from ${MAIN_REF} (last ${MAIN_SCAN_DEPTH} commits)..."
declare -A main_patch_ids
while read -r main_sha; do
  pid=$(git show "$main_sha" 2> /dev/null | git patch-id --stable 2> /dev/null | awk '{print $1}' || true)
  if [[ -n "$pid" ]]; then
    main_patch_ids["$pid"]="$main_sha"
  fi
done < <(git rev-list --no-merges -n "$MAIN_SCAN_DEPTH" "$MAIN_REF")

echo "Indexed ${#main_patch_ids[@]} patch-ids from ${MAIN_REF}."
echo

# ── Verify ──────────────────────────────────────────────────────────────────

fail=0
fail_lines=()
for sha in "${pr_commits[@]}"; do
  subject=$(git log -1 --format='%s' "$sha" 2> /dev/null || echo '<no subject>')
  short=$(git rev-parse --short "$sha")

  # Path A: already on main (e.g. a merge of main into the release branch).
  if git merge-base --is-ancestor "$sha" "$MAIN_REF"; then
    echo "  ✓ ${short} on main: ${subject}"
    continue
  fi

  # Path B: same patch content exists on main (clean cherry-pick / rebase).
  pid=$(git show "$sha" 2> /dev/null | git patch-id --stable 2> /dev/null | awk '{print $1}' || true)
  if [[ -n "$pid" && -n "${main_patch_ids[$pid]:-}" ]]; then
    main_short=$(git rev-parse --short "${main_patch_ids[$pid]}")
    echo "  ✓ ${short} cherry-pick of ${main_short} on main: ${subject}"
    continue
  fi

  # Path C: an exempt release-hygiene commit (shared with preflight check 5).
  # The verdict comes back in globals, never through a command substitution:
  # a subshell would drop the detail the failure line needs.
  rc=0
  release_commit_exemption "$sha" "$subject" || rc=$?
  if [[ "$rc" -eq 2 ]]; then
    echo "INFRA: ${RELEASE_EXEMPTION_DETAIL}" >&2
    exit 2
  fi
  if [[ "$rc" -eq 0 ]]; then
    echo "  ✓ ${short} path C, ${RELEASE_EXEMPTION_LABEL}: ${subject}"
    continue
  fi
  # Remembered for the failure line: a commit whose SUBJECT claimed an
  # exemption it did not earn is the case the old message hid.
  c_detail="$RELEASE_EXEMPTION_DETAIL"
  c_rule="$RELEASE_EXEMPTION_RULE"

  # Path D: narrowed backport — trailer names a commit that IS on main.
  picked="$(cherry_pick_source "$sha")"
  if [[ -n "$picked" ]] && git rev-parse --verify --quiet "${picked}^{commit}" > /dev/null \
    && git merge-base --is-ancestor "$picked" "$MAIN_REF"; then
    picked_short=$(git rev-parse --short "$picked")
    echo "  ✓ ${short} narrowed backport of ${picked_short} on main" \
      "(patch differs; hunks were resolved away): ${subject}"
    continue
  fi
  if [[ -n "$picked" ]]; then
    # A trailer that names something main does not have is worse than no
    # trailer: it asserts a provenance that is not there. Say which sha.
    fail_lines+=("  ✗ ${short}: ${subject} [path D: cherry-pick trailer names ${picked}, which is not on ${MAIN_REF}]")
    fail=$((fail + 1))
    continue
  fi

  # None of the four: authored directly against the release branch. Name the
  # rule it came closest to (#3829): "not a cherry-pick" is true of a
  # `docs(changelog):` commit too, and says nothing about why it was refused.
  fail=$((fail + 1))
  if [[ -n "$c_rule" ]]; then
    fail_lines+=("  ✗ ${short}: ${subject} [path C: ${c_detail}]")
  else
    fail_lines+=("  ✗ ${short}: ${subject} [not on ${MAIN_REF} (A), no patch-id match (B), path C: ${c_detail}, no cherry-pick trailer (D)]")
  fi
done

if [[ $fail -gt 0 ]]; then
  echo
  echo "::error title=Release branch gate failed::${fail} commit(s) on this PR match none of the four accepted paths; each ✗ line below names the one it came closest to."
  printf '%s\n' "${fail_lines[@]}"
  echo
  echo "Every commit on a PR against a maintenance branch must match one of:"
  echo "  A. it is already on ${MAIN_REF};"
  echo "  B. it has the same patch-id as a commit on ${MAIN_REF} (a clean"
  echo "     cherry-pick or rebase);"
  echo "  C. it is an exempt release-hygiene commit — one of:"
  release_exemption_rules_text | sed 's/^/   /'
  echo "     Path C is the SAME exemption set release preflight check 5 uses"
  echo "     (scripts/ci/release-commit-exemptions.sh, artifact-keeper#3829),"
  echo "     so a commit that satisfies one gate satisfies the other;"
  echo "  D. it is a narrowed backport: a \`(cherry picked from commit <sha>)\`"
  echo "     trailer naming a commit that is on main. \`git cherry-pick -x\`"
  echo "     writes that trailer for you; keep it when you resolve hunks away."
  echo
  echo "The expected workflow for anything else is:"
  echo "  1. Land the change on main first."
  echo "  2. Soak through main's CI (the CI workflow gates main)."
  echo "  3. Cherry-pick (\`git cherry-pick -x <sha>\`) the main commit(s) here."
  echo
  echo "There is no label that waives this. \`release-process: approved\` used"
  echo "to skip the job outright and still report success, so the required"
  echo "check meant nothing on a PR whose author could label it"
  echo "(artifact-keeper#4070); it is now a review marker only. If a shape"
  echo "genuinely cannot go through main first and recurs, add it to"
  echo "scripts/ci/release-commit-exemptions.sh with a test, where it is"
  echo "reviewed code -- do not reach for the label."
  echo
  echo "Reference: artifact-keeper#1090 / artifact-keeper#1068 / artifact-keeper#3422 / artifact-keeper#3829 / artifact-keeper#4070"
  exit 1
fi

echo
echo "::notice::All ${#pr_commits[@]} PR commit(s) trace back to ${MAIN_REF}. Gate passed."
