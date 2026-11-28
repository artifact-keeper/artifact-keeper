#!/usr/bin/env bash
#
# Advisory PR check for #6476: warn when a `ci:` PR changes a path that
# release-commit-exemptions.sh does not treat as CI-only and adds no fragment.
#
# #6363 found six `ci(...)` PRs in the 1.12.2 range that touched shipped paths
# (a script or test under backend/) and reached the cut without a citation.
# Release preflight check 5 then needed a hand-written CHANGELOG entry. The
# subject says CI-only, but the exemption rule is path-based, so the mismatch
# is only visible by reading both the title and the diff.
#
# This is a warning, not a failure (#6476 option 3): warning first, and make
# it blocking later only if the warning proves quiet. The path set is sourced
# from release-commit-exemptions.sh, the same set check 5 uses, so a change
# to what counts as a CI-only path cannot drift between the two checks.
#
# Usage:  warn-ci-changelog-fragment.sh [<base-ref>]   (default origin/<GITHUB_BASE_REF>)
#
# Env:
#   GITHUB_EVENT_NAME  non-PR events are a no-op; unset means a local PR-like run.
#   PR_TITLE           the PR title to classify; a conventional `ci:`/`ci(scope):`
#                      or `ci!:`/`ci(scope)!:` type is checked.
#   EXEMPTIONS_FILE    override the shared exemption set; for the self-test.
#
# Exit status is always 0: every inability to measure warns rather than fails.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXEMPTIONS_FILE="${EXEMPTIONS_FILE:-$HERE/release-commit-exemptions.sh}"
EVENT="${GITHUB_EVENT_NAME:-pull_request}"
TITLE="${PR_TITLE:-}"

no_op() {
  echo "ci changelog fragment check: $*"
  exit 0
}

warn() {
  echo "::warning title=ci PR without a CHANGELOG fragment::$*"
}

if [[ "$EVENT" != "pull_request" && "$EVENT" != "pull_request_target" ]]; then
  no_op "no-op on '${EVENT}' events; only a pull request has a title and a base diff."
fi

CI_TITLE_RE='^ci(\([^)]*\))?(!)?:[[:space:]]'
if [[ ! "$TITLE" =~ $CI_TITLE_RE ]]; then
  no_op "title type is not 'ci'."
fi

if ! git rev-parse --git-dir > /dev/null 2>&1; then
  warn "not a git repository at $PWD; could not compare the PR against its base (#6476)."
  exit 0
fi

BASE_REF="${1:-origin/${GITHUB_BASE_REF:-main}}"
if ! git rev-parse --verify --quiet "${BASE_REF}^{commit}" > /dev/null; then
  warn "base ref '${BASE_REF}' does not resolve; fetch it with 'git fetch --no-tags origin \"\$GITHUB_BASE_REF:refs/remotes/origin/\$GITHUB_BASE_REF\"' before this check (#6476)."
  exit 0
fi

MERGE_BASE="$(git merge-base HEAD "$BASE_REF" 2> /dev/null || true)"
if [[ -z "$MERGE_BASE" ]]; then
  warn "no merge base between HEAD and '${BASE_REF}'; this check needs a full checkout (#6476)."
  exit 0
fi

if ! diff="$(git diff --name-status --no-renames "$MERGE_BASE" HEAD 2> /dev/null)"; then
  warn "could not read the PR diff against ${MERGE_BASE} (#6476)."
  exit 0
fi

paths=()
fragment_added=false
while IFS=$'\t' read -r status path; do
  [[ -n "$path" ]] || continue
  paths+=("$path")
  if [[ "$status" == "A" && "$path" =~ ^changes/unreleased/[0-9]+-[a-z0-9-]+\.md$ ]]; then
    fragment_added=true
  fi
done <<< "$diff"

if [[ ${#paths[@]} -eq 0 ]]; then
  no_op "no changed paths to classify."
fi
if [[ "$fragment_added" == true ]]; then
  no_op "a CHANGELOG fragment was added."
fi

if [[ ! -r "$EXEMPTIONS_FILE" ]]; then
  warn "cannot read ${EXEMPTIONS_FILE}; could not decide which paths are CI-only (#6476)."
  exit 0
fi
# shellcheck source=scripts/ci/release-commit-exemptions.sh
. "$EXEMPTIONS_FILE"
if ! declare -F _release_first_path_outside > /dev/null; then
  warn "${EXEMPTIONS_FILE} does not define the shared path-set predicate; could not decide which paths are CI-only (#6476)."
  exit 0
fi

if ! outside="$(_release_first_path_outside ci "${paths[@]}")"; then
  no_op "every changed path is in the shared CI path set."
fi

warn "title '${TITLE}' changes ${outside}, outside the shared CI path set, and adds no fragment under changes/unreleased/. Release preflight check 5 will need a hand-written citation at the cut. Add a fragment for the shipped change, or keep the diff within $(release_exemption_path_set ci). This is advisory for now (#6476)."
