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
#   C. it is a RELEASE-PREP commit — subject `chore(release): ...` touching
#      only the version/changelog/release-notes file set. The version being
#      prepared exists only on the maintenance branch, so there is nothing on
#      main to trace to and there should not be. Before #3422 this had to be
#      waved through with `release-process: approved` on every single cut;
#      the 1.7.6 cut burned that label four times in one release;
#   D. it is a NARROWED BACKPORT — a commit carrying a
#      `(cherry picked from commit <sha>)` trailer whose sha is on main, but
#      whose patch-id differs because hunks that could not apply were
#      resolved away (a guard test depending on scaffolding the branch does
#      not have, a CHANGELOG hunk targeting `[Unreleased]` when the branch
#      needs `[1.7.6]`). The narrowing is real and worth seeing, so it is
#      logged as "narrowed backport of <sha>" rather than passed silently.
#
# Anything else still fails: a commit authored directly against the
# maintenance branch that never went through main is exactly what this gate
# exists to stop (PR #1068 bundled +1489 lines that way and forced a revert
# mid-RC cycle). The `release-process: approved` label remains the escape
# hatch for the genuine remainder, and is handled by the workflow, not here.
#
# C is deliberately narrow in BOTH dimensions — subject prefix AND path set.
# A `chore(release):` commit that also touches backend source is not a
# release prep, and a version-file-only commit with some other subject is not
# either. Widening one without the other would turn the exemption into a hole
# a real drift could walk through.
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

# ── Path C helpers ──────────────────────────────────────────────────────────

# Every path a release-prep commit is allowed to touch. Bash `case` globs, so
# `*` also spans `/`; that is fine here — each pattern is anchored on a
# concrete filename or directory that only carries version metadata.
release_prep_path() {
  case "$1" in
    Cargo.toml | Cargo.lock) return 0 ;;
    openapi.rs | */openapi.rs) return 0 ;; # **/openapi.rs
    CHANGELOG.md) return 0 ;;
    .github/release-notes/*) return 0 ;;
    docker/*/VERSION) return 0 ;;
    *) return 1 ;;
  esac
}

# True when <sha> is a release-prep commit: `chore(release): ` subject AND
# every changed path in the allowlist. An empty file list is NOT a release
# prep — a commit that changes nothing has nothing to exempt.
is_release_prep() {
  local sha="$1" subject files f
  subject="$(git log -1 --format='%s' "$sha")"
  [[ "$subject" =~ ^chore\(release\):\  ]] || return 1

  # -r (recurse into trees) and no -M: a rename is reported as its two paths
  # rather than one, so both ends are checked against the allowlist. The
  # 1.7.6 prep renames .github/release-notes/1.7.5.md -> 1.7.6.md.
  mapfile -t files < <(git diff-tree --no-commit-id --name-only -r "$sha")
  [[ ${#files[@]} -gt 0 ]] || return 1

  for f in "${files[@]}"; do
    [[ -n "$f" ]] || continue
    release_prep_path "$f" || return 1
  done
  return 0
}

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

  # Path C: release-prep for a version that exists only on this branch.
  if is_release_prep "$sha"; then
    echo "  ✓ ${short} release prep (version/changelog paths only): ${subject}"
    continue
  fi

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
    fail_lines+=("  ✗ ${short}: ${subject} [cherry-pick trailer names ${picked}, which is not on ${MAIN_REF}]")
    fail=$((fail + 1))
    continue
  fi

  # None of the four: authored directly against the release branch.
  fail=$((fail + 1))
  fail_lines+=("  ✗ ${short}: ${subject}")
done

if [[ $fail -gt 0 ]]; then
  echo
  echo "::error title=Release branch gate failed::${fail} commit(s) on this PR are not on main, are not cherry-picks of main commits, and are neither a release prep nor a narrowed backport."
  printf '%s\n' "${fail_lines[@]}"
  echo
  echo "This is a maintenance line. The expected workflow is:"
  echo "  1. Land the change on main first."
  echo "  2. Soak through main's CI (the CI workflow gates main)."
  echo "  3. Cherry-pick (\`git cherry-pick -x <sha>\`) the main commit(s) here."
  echo
  echo "Two shapes are accepted without a patch-id match:"
  echo "  - a release prep: subject \`chore(release): ...\` touching only"
  echo "    Cargo.toml, Cargo.lock, **/openapi.rs, CHANGELOG.md,"
  echo "    .github/release-notes/** and docker/*/VERSION;"
  echo "  - a narrowed backport: a \`(cherry picked from commit <sha>)\`"
  echo "    trailer naming a commit that is on main. \`git cherry-pick -x\`"
  echo "    writes that trailer for you; keep it when you resolve hunks away."
  echo
  echo "If this PR genuinely cannot go through main first (e.g., a fix that"
  echo "ONLY applies to the maintenance branch), apply the label"
  echo "  release-process: approved"
  echo "and re-run this check. Document the rationale in the PR body."
  echo
  echo "Reference: artifact-keeper#1090 / artifact-keeper#1068 / artifact-keeper#3422"
  exit 1
fi

echo
echo "::notice::All ${#pr_commits[@]} PR commit(s) trace back to ${MAIN_REF}. Gate passed."
