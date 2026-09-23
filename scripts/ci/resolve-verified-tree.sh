#!/usr/bin/env bash
# =============================================================================
# resolve-verified-tree.sh — has a merged pull request already proved this
#                            exact tree green?
# =============================================================================
#
# WHY
# A push to main re-runs the Rust jobs on the commit a
# pull request just produced. When the PR was up to date with main, its squash
# (or merge) commit has byte-for-byte the tree the PR's own CI already built
# and tested, so the push run re-proves a verdict that exists. Most of those
# push runs are also cancelled by the next merge before they finish.
#
# WHAT IT CHECKS
# The pushed commit S (first parent P, tree T) is "verified" only when ALL hold
# for some merged pull request associated with S:
#   1. S does not change a rust-cache key input (Cargo.toml / Cargo.lock at any
#      depth, rust-toolchain[.toml], .cargo/). Pushes are the only runs that
#      save the rust-cache; skipping the push that moves the key would leave
#      every later PR restoring a stale cache.
#   2. the PR was merged into the branch that was pushed;
#   3. the PR head H has tree T;
#   4. H contains P (compare P...H is "ahead" or "identical"). A pull_request
#      run tests the merge of H into the base as it was at run time; that base
#      is an ancestor of P, so when H contains P the tested tree IS tree(H) = T.
#      Without this a PR that was not up to date could match T by accident
#      while its CI tested a different merge result;
#   5. on H, the latest GitHub Actions check runs named CI Complete, Check Rust
#      and Backend Unit Tests all concluded `success`. A `skipped` Rust job
#      (a CI-only PR) proves nothing about Rust, so it does not count.
# The Tier 2 integration suites are steps of Backend Unit Tests (#4208), so a
# green unit check on H covers them; there is no separate integration verdict.
#
# FAILS OPEN: any API error, a malformed answer, or no qualifying PR prints
# verified=false and the caller runs the jobs. The script always exits 0 on a
# well-formed invocation; exit 2 is a usage error.
#
# OUTPUT (stdout, one key=value per line; diagnostics go to stderr):
#   verified=true|false
#   reason=<one line>
#
# Usage: resolve-verified-tree.sh <pushed-sha> <pushed-branch>
# Env:   GITHUB_REPOSITORY (owner/repo), GH_TOKEN for gh.
#        CHECK_COMPLETE, CHECK_RUST, CHECK_UNIT override the
#        check-run names (defaults: the ci.yml job names).
# =============================================================================
set -uo pipefail

SHA="${1:-}"
BRANCH="${2:-}"
REPO="${GITHUB_REPOSITORY:-}"
if [ -z "$SHA" ] || [ -z "$BRANCH" ] || [ -z "$REPO" ]; then
  echo "usage: resolve-verified-tree.sh <pushed-sha> <pushed-branch> (GITHUB_REPOSITORY must be set)" >&2
  exit 2
fi

CHECK_COMPLETE="${CHECK_COMPLETE:-✅ CI Complete}"
CHECK_RUST="${CHECK_RUST:-🦀 Check Rust}"
CHECK_UNIT="${CHECK_UNIT:-🧪 Backend Unit Tests}"
# The GitHub Actions app. A check run with a CI job's name posted by any other
# app (a third-party integration, a personal token) is not a CI verdict.
ACTIONS_APP_ID=15368

verdict() {
  echo "verified=$1"
  echo "reason=$2"
  echo "tree check: verified=$1 -- $2" >&2
  exit 0
}

is_sha() { [[ "$1" =~ ^[0-9a-f]{40}$ ]]; }

is_sha "$SHA" || verdict false "pushed sha '$SHA' is not a 40-hex commit id"

commit=$(gh api "repos/${REPO}/git/commits/${SHA}" --jq '"\(.tree.sha) \(.parents[0].sha // "")"') \
  || verdict false "could not read commit ${SHA}"
read -r TREE PARENT <<< "$commit"
is_sha "${TREE:-}" || verdict false "commit ${SHA} has no readable tree"
is_sha "${PARENT:-}" || verdict false "commit ${SHA} has no parent to compare against"

# 1. rust-cache key inputs. --paginate walks the commit's file list pages.
files=$(gh api --paginate "repos/${REPO}/commits/${SHA}" --jq '.files[].filename') \
  || verdict false "could not list the files commit ${SHA} changes"
[ -n "$files" ] || verdict false "commit ${SHA} lists no changed files"
while IFS= read -r f; do
  case "$f" in
    Cargo.toml|Cargo.lock|*/Cargo.toml|*/Cargo.lock|rust-toolchain|rust-toolchain.toml|.cargo/*)
      verdict false "commit changes ${f}, a rust-cache key input; the push run must save a fresh cache"
      ;;
  esac
done <<< "$files"

# Latest conclusion of one named check run on a commit, or "none".
check_conclusion() {
  local sha="$1" name="$2" out
  out=$(gh api -X GET "repos/${REPO}/commits/${sha}/check-runs" \
          -f check_name="$name" -f filter=latest -F app_id="$ACTIONS_APP_ID" \
          --jq '[.check_runs[] | .conclusion // "pending"] | if length == 0 then "none" else (if all(. == "success") then "success" else "failure" end) end') \
    || { echo "error"; return; }
  case "$out" in
    success|failure|none) echo "$out" ;;
    *) echo "error" ;;
  esac
}

prs=$(gh api "repos/${REPO}/commits/${SHA}/pulls" \
        --jq '.[] | select(.merged_at != null) | "\(.number) \(.head.sha) \(.base.ref)"') \
  || verdict false "could not list the pull requests associated with ${SHA}"
[ -n "$prs" ] || verdict false "no merged pull request is associated with ${SHA}"

why="no associated merged pull request qualified"
while read -r number head base; do
  [ -n "${number:-}" ] || continue
  if [ "$base" != "$BRANCH" ]; then
    why="PR #${number} was merged into ${base}, not ${BRANCH}"
    continue
  fi
  if ! is_sha "${head:-}"; then
    why="PR #${number} has no readable head sha"
    continue
  fi
  # 3. identical tree
  head_tree=$(gh api "repos/${REPO}/git/commits/${head}" --jq '.tree.sha') || {
    why="could not read PR #${number} head ${head}"
    continue
  }
  if [ "$head_tree" != "$TREE" ]; then
    why="PR #${number} head ${head} has tree ${head_tree}, the push has ${TREE}"
    continue
  fi
  # 4. the head contains the pushed commit's parent
  status=$(gh api "repos/${REPO}/compare/${PARENT}...${head}" --jq '.status') || {
    why="could not compare ${PARENT}...${head}"
    continue
  }
  case "$status" in
    ahead|identical) ;;
    *)
      why="PR #${number} head ${head} does not contain ${PARENT} (compare: ${status}); its CI tested a different merge"
      continue
      ;;
  esac
  # 5. green verdicts on the head
  ok=true
  for name in "$CHECK_COMPLETE" "$CHECK_RUST" "$CHECK_UNIT"; do
    c=$(check_conclusion "$head" "$name")
    if [ "$c" != "success" ]; then
      why="PR #${number} head ${head}: '${name}' is ${c}, not success"
      ok=false
      break
    fi
  done
  [ "$ok" = true ] || continue
  verdict true "tree ${TREE} proven by PR #${number} at ${head}"
done <<< "$prs"

verdict false "$why"
