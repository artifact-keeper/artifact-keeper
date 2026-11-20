#!/usr/bin/env bash
# Keep the release commit a branch tip until its GitHub Release exists (#6338).
#
# WHY
#   GITHUB_TOKEN is refused (`403 Resource not accessible by integration`) on
#   POST /releases when the release's commit is not the tip of any branch
#   (softprops/action-gh-release#411). Every release before 1.12.3 happened to
#   point at a branch tip. 1.12.3 did not: PRs merged to main between the
#   certification and the publish, so its certified commit was only an
#   ancestor of main, and Create Release failed on four attempts. The release
#   was published only after a maintainer created `publish/v1.12.3` at the
#   commit by hand and re-ran the failed job.
#
#   This script does that step for the pipeline. release-promote.yml pins the
#   branch before it creates the tag; release.yml makes sure the pin is there
#   before Create Release and removes it once the Release exists.
#
# USAGE
#   pin-release-branch.sh pin   <tag> <sha>
#   pin-release-branch.sh unpin <tag> <sha>
#
#   The branch is `publish/<tag>`. Needs GH_TOKEN with `contents: write` and
#   GITHUB_REPOSITORY. A ref created by GITHUB_TOKEN fires no push or create
#   event, so the branch starts no workflow.
#
#   pin    exit 0: `publish/<tag>` exists at <sha> (created now, or already).
#          exit 1: it exists at another commit (left alone: someone else's
#                  branch, or a stale pin to inspect), or the API refused.
#   unpin  exit 0 always once the arguments are valid: removes the branch when
#          it names <sha>; leaves one at another commit alone, with a warning.
#          A failed delete is a warning too: the Release already exists, and a
#          leftover branch costs nothing but tidiness.
#   exit 2: usage.
set -euo pipefail

mode="${1:-}"; tag="${2:-}"; sha="${3:-}"
if [[ "$mode" != pin && "$mode" != unpin ]] || [[ -z "$tag" ]] || ! [[ "$sha" =~ ^[0-9a-f]{40}$ ]]; then
  echo "usage: $0 pin|unpin <tag> <40-hex sha>" >&2
  exit 2
fi
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"

branch="publish/${tag}"
api="repos/${GITHUB_REPOSITORY}/git"
err="$(mktemp)"
trap 'rm -f "$err"' EXIT

# Prints the commit the branch names; prints nothing when it does not exist.
# Exit 1 when the lookup itself failed (anything but a 404).
current() {
  local out
  if out="$(gh api "${api}/ref/heads/${branch}" --jq '.object.sha' 2>"$err")"; then
    printf '%s\n' "$out"
    return 0
  fi
  grep -qE 'HTTP 404|Not Found' "$err" && return 0
  return 1
}

if ! at="$(current)"; then
  echo "::warning title=Could not read ${branch}::$(tr '\n' ' ' <"$err")"
  [[ "$mode" == unpin ]] && exit 0
  exit 1
fi

case "$mode" in
  pin)
    if [[ "$at" == "$sha" ]]; then
      echo "${branch} already names ${sha}."
      exit 0
    fi
    if [[ -n "$at" ]]; then
      echo "::error title=${branch} names another commit::${branch} is at ${at}, not ${sha}. It was left alone. Inspect it, delete it if it is a stale pin, and re-run."
      exit 1
    fi
    if ! gh api -X POST "${api}/refs" -f "ref=refs/heads/${branch}" -f "sha=${sha}" --silent 2>"$err"; then
      echo "::error title=Could not create ${branch}::$(tr '\n' ' ' <"$err")"
      exit 1
    fi
    echo "Created ${branch} at ${sha}."
    ;;
  unpin)
    if [[ -z "$at" ]]; then
      echo "${branch} does not exist; nothing to remove."
    elif [[ "$at" != "$sha" ]]; then
      echo "::warning title=${branch} names another commit::${branch} is at ${at}, not ${sha}; left alone."
    elif gh api -X DELETE "${api}/refs/heads/${branch}" --silent 2>"$err"; then
      echo "Removed ${branch}."
    else
      echo "::warning title=Could not remove ${branch}::$(tr '\n' ' ' <"$err") Delete it by hand: gh api -X DELETE repos/${GITHUB_REPOSITORY}/git/refs/heads/${branch}"
    fi
    ;;
esac
