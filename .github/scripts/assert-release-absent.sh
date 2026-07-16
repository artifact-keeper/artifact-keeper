#!/usr/bin/env bash
#
# Refuse to proceed unless a tag demonstrably has no GitHub Release yet.
#
#   usage: assert-release-absent.sh <tag>
#   env:   GH_TOKEN, GITHUB_REPOSITORY
#
# Exit 0 only when the repository is readable AND the tag returns a clean 404.
# An existing release is a refusal; so is any answer we cannot interpret.
#
# Scope, stated honestly: `GET /releases/tags/{tag}` resolves PUBLISHED
# releases. Draft releases are not addressable by tag and are not visible to a
# `contents: read` token at all, so this check cannot see them. The equivalent
# check repeated inside the release job -- which inherits `contents: write` --
# is what catches a draft. Stale drafts may well exist from the old
# draft-on-failure behaviour, in which case a run can burn the full gate and
# build cycle before the late check refuses it. Delete leftover drafts before
# re-cutting a version.

set -uo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <tag>" >&2
  exit 2
fi

TAG="$1"

if [[ -z "${GITHUB_REPOSITORY:-}" ]]; then
  echo "::error title=Release lookup failed::GITHUB_REPOSITORY is not set; cannot check whether ${TAG} is already released."
  exit 1
fi

# Prove the token can read this repository first. Otherwise a bad token, a
# renamed repository, or a permissions change all answer 404 -- and would be
# read as "the version is free".
if ! gh api "repos/${GITHUB_REPOSITORY}" --silent >/dev/null 2>&1; then
  echo "::error title=Release lookup failed::Cannot read repos/${GITHUB_REPOSITORY}. Without repository access a 404 on a release proves nothing, so this fails closed."
  exit 1
fi

set +e
LOOKUP=$(gh api -i "repos/${GITHUB_REPOSITORY}/releases/tags/${TAG}" 2>/dev/null)
LOOKUP_RC=$?
set -e

if [[ "$LOOKUP_RC" -eq 0 ]]; then
  echo "::error title=Release already exists::${TAG} already has a published GitHub Release. Refusing to modify its metadata or assets; create a new version."
  exit 1
fi

# Read the status line itself rather than grepping for prose. `gh` writes
# `gh: Not Found (HTTP 404)` to stderr, but the response status line that `-i`
# puts on stdout looks like `HTTP/2.0 404 Not Found`.
STATUS_LINE=$(head -n 1 <<<"$LOOKUP" | tr -d '\r')
if [[ ! "$STATUS_LINE" =~ ^HTTP/[0-9.]+[[:space:]]+404([[:space:]]|$) ]]; then
  echo "::error title=Release lookup failed::Unable to prove ${TAG} is unused; failing closed."
  printf '%s\n' "$LOOKUP"
  exit 1
fi

echo "${TAG} has no published GitHub Release. OK."
