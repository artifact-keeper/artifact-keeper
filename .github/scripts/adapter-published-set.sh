#!/usr/bin/env bash
#
# Resolve the scanner-adapter's PUBLISHED SET: the adapter version each
# published backend release ships (#3770).
#
#   usage: adapter-published-set.sh
#   env:   GITHUB_REPOSITORY (owner/repo), GH_TOKEN
#   stdin: one published release tag per line (`v1.8.2`), as produced by
#          `gh api .../releases --jq` filtered to non-draft, non-prerelease.
#   stdout: one adapter version per line, in input order (duplicates kept;
#           floating-tag-plan.sh de-duplicates). Progress goes to stderr.
#
# The adapter is versioned on its own line (docker/scanner-adapter/VERSION),
# so "has a published release" is defined through the backend releases that
# ship it. This is the shared input for the two places that apply that rule:
# the promote's `apply-floating-tags` plan (docker-publish.yml) and the
# release-side assert that checks what the promote did (release.yml). One
# resolver keeps the two from ever disagreeing.
#
# A `Not Found (HTTP 404)` means the file is absent at a live tag -- the
# release predates the VERSION file -- and is ignored. Any other error,
# including a missing tag (`No commit found for the ref`), FAILS CLOSED: the
# release whose adapter version could not be read might be the one that makes
# a promotion a backwards move.
#
# Exit codes: 0 resolved (the set may be empty); 1 a lookup failed.

set -euo pipefail

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"

err="$(mktemp)"
trap 'rm -f "$err"' EXIT

while IFS= read -r rel; do
  rel="${rel//[$'\t\r\n ']/}"
  [[ -n "$rel" ]] || continue
  if av=$(gh api -H 'Accept: application/vnd.github.raw+json' \
            "repos/${GITHUB_REPOSITORY}/contents/docker/scanner-adapter/VERSION?ref=${rel}" \
            </dev/null 2>"$err"); then
    av="${av//[$'\t\r\n ']/}"
    echo "    ${rel} -> scanner-adapter ${av}" >&2
    echo "${av}"
  elif grep -q 'Not Found (HTTP 404)' "$err"; then
    echo "    ${rel} -> predates docker/scanner-adapter/VERSION; ignored" >&2
  else
    echo "::error title=Adapter release lookup failed::could not read docker/scanner-adapter/VERSION at ${rel}: $(cat "$err")" >&2
    exit 1
  fi
done
