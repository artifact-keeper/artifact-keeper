#!/usr/bin/env bash
# =============================================================================
# coverage-merge-base.sh — the commit the coverage gates diff against
# =============================================================================
#
# WHY
# The new-code gate counts the lines a pull request ADDS, so it needs the
# exact commit the measured tree grew from. It used to find it with
# `git merge-base` over a 200-commit shallow fetch and fell back to the base
# branch TIP when the walk found nothing (#1646's documented trade-off). A
# branch further behind than the window then diffed against a tip it never
# saw, and every line other PRs had landed since read as "new" -- untested
# by this PR, so the gate failed on code the PR did not write. main moves
# ~17 commits a day; open PRs 240-270 commits behind already existed.
#
# WHAT IT DOES
# Asks GitHub for the merge base server-side, where history is complete:
#
#   GET repos/<repo>/compare/<base-ref>...<measured-sha>  -> .merge_base_commit.sha
#
# <measured-sha> must be the commit that was BUILT and MEASURED (github.sha).
# On pull_request that is the PR's merge commit, whose merge base with the
# base branch is its first parent: the base as it was when the merge was
# made. Diffing the merge commit against it yields exactly the PR's lines, in
# the merge commit's line numbers -- the numbers lcov.info uses -- however
# far behind the branch is. (The PR head's merge base would be the branch
# point instead, and the diff from there to the merge commit would include
# everything main landed since: the very phantom delta this avoids.)
#
# Then fetches that one commit at depth 1 so `git diff <sha>` has its tree.
#
# If the API fails and the measured commit is a merge, its first parent is
# read from the commit object (present even in a depth-1 clone) -- the same
# answer, derived locally. Anything else is an error: the caller reports the
# gate as not measured rather than silently diffing against a guess.
#
# INPUT (environment)
#   GITHUB_REPOSITORY  owner/repo
#   BASE_REF           the PR's base branch name (github.base_ref)
#   MEASURED_SHA       the checked-out commit (github.sha)
#   GH_TOKEN           for gh
# OUTPUT
#   stdout: the 40-hex merge base; exit 0. Diagnostics on stderr; exit 1.
#
# Tested by scripts/ci/test-coverage-merge-base.sh (stubbed gh).
# =============================================================================
set -euo pipefail

: "${GITHUB_REPOSITORY:?}" "${BASE_REF:?}" "${MEASURED_SHA:?}"

is_sha() { [[ "$1" =~ ^[0-9a-f]{40}$ ]]; }

mb=""
if api=$(gh api "repos/${GITHUB_REPOSITORY}/compare/${BASE_REF}...${MEASURED_SHA}" \
           --jq '.merge_base_commit.sha' 2>/dev/null) && is_sha "$api"; then
  mb="$api"
  echo "merge base from the compare API: $mb" >&2
else
  echo "::warning::compare API gave no merge base for ${BASE_REF}...${MEASURED_SHA}; trying the measured commit's first parent" >&2
  mapfile -t parents < <(git cat-file -p "$MEASURED_SHA" 2>/dev/null | sed -n 's/^parent //p')
  if [ "${#parents[@]}" -ge 2 ] && is_sha "${parents[0]}"; then
    mb="${parents[0]}"
    echo "merge base from the merge commit's first parent: $mb" >&2
  fi
fi

if [ -z "$mb" ]; then
  echo "::error title=No merge base::Could not determine what ${MEASURED_SHA} is diffed against (compare API failed and it is not a merge commit). The coverage gates cannot measure new code; re-run the job." >&2
  exit 1
fi

if ! git cat-file -e "${mb}^{tree}" 2>/dev/null; then
  git fetch --no-tags --depth=1 origin "$mb" >&2 \
    || { echo "::error title=No merge base::git fetch of merge base $mb failed" >&2; exit 1; }
fi
git cat-file -e "${mb}^{tree}" 2>/dev/null \
  || { echo "::error title=No merge base::merge base $mb is not available after fetching it" >&2; exit 1; }

echo "$mb"
