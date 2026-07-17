#!/usr/bin/env bash
#
# Validate the image tag requested by a manual `workflow_dispatch` build and
# print the normalized value the workflow should actually publish.
#
#   usage: validate-dispatch-tag.sh <requested-tag>
#   stdout: the normalized tag (only on success)
#   exit:   0 accepted, 1 rejected
#
# Manual builds exist for candidate and dev labels. They must not become a
# second, unguarded way to publish the tags that the release path owns and that
# the chart and the release gate depend on.
#
# Two rules matter here, and the order matters:
#
#  1. Validate the NORMALIZED value, not the raw input. The tag eventually
#     reaches docker/metadata-action, which trims each field before using it,
#     so a check that reads the raw string is checking a different value than
#     the one that gets published. Normalizing first -- and then publishing the
#     normalized value rather than the original input -- keeps the checked
#     value and the published value identical.
#
#  2. Allowlist the character set before anything else. metadata-action parses
#     each tag line as comma-separated `key=value` attributes, so any input
#     that is passed through verbatim can carry structure rather than just a
#     value. Restricting the tag to the characters a Docker tag may legally
#     contain removes that whole class of input, and it is a rule with an
#     obvious right answer rather than a list of things to remember to block.
#
# What is refused (case-insensitively, after normalization):
#   - the floating stable labels: latest, stable, edge
#   - the labels the release gate itself validates: dev, and branch names
#   - bare or v-prefixed version numbers of any arity: 1, 1.5, 1.5.8, 1.5.8.1
#   - reserved prefixes: release-*, latest-*, stable-*, edge-*, dev-*, sha-*
#
# What is accepted: genuine candidate labels -- rc-1.5.9, 1.1-dev, pr-123,
# candidate-abc123.

set -uo pipefail

reject() {
  echo "::error title=Manual tag refused::$1" >&2
  exit 1
}

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <requested-tag>" >&2
  exit 2
fi

RAW="$1"

# Normalize exactly the way docker/metadata-action will: strip surrounding
# whitespace. ${VAR##/%%} with an extglob-free pattern keeps this portable.
TAG="${RAW#"${RAW%%[![:space:]]*}"}"
TAG="${TAG%"${TAG##*[![:space:]]}"}"

if [[ -z "$TAG" ]]; then
  reject "an empty tag is not a candidate label."
fi

# Docker's own tag grammar: [A-Za-z0-9_][A-Za-z0-9._-]{0,127}. Anything else --
# whitespace, commas, '=', ':', '/', unicode -- is not a tag.
if [[ ! "$TAG" =~ ^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$ ]]; then
  reject "'${RAW}' is not a valid image tag. Use only letters, digits, '.', '_' and '-' (max 128 characters, starting with a letter, digit or underscore)."
fi

LOWER="${TAG,,}"

# The floating labels and the labels release gating keys off. `dev` is the
# sharpest of these: the release workflow validates `backend_tag: dev`, so a
# manual build that publishes `dev` re-points the very images the gate is
# about to bless.
case "$LOWER" in
  latest|stable|edge|dev|main|master)
    reject "'${TAG}' is a release-managed label. Stable and gate-significant tags come from the guarded release path; use an explicit candidate or dev label such as rc-1.5.9 or 1.1-dev."
    ;;
esac

# Reserved namespaces. Note this deliberately does not catch `1.1-dev`, which
# is a real dev label this repository publishes from release/1.1.x.
if [[ "$LOWER" =~ ^(latest|stable|edge|dev|release|sha)[._-] ]]; then
  reject "'${TAG}' uses a reserved tag namespace. Use an explicit candidate or dev label such as rc-1.5.9 or 1.1-dev."
fi

# Bare or v-prefixed version numbers of any arity. This covers the chart's
# floating pins (1, 1.5) and full versions (1.5.8), including four-part
# variants (1.5.8.1) that read as a release but sort outside semver.
if [[ "$LOWER" =~ ^v?[0-9]+([._][0-9]+)*$ ]]; then
  reject "'${TAG}' is a version number. Version tags are published only by the release path; use an explicit candidate or dev label such as rc-1.5.9."
fi

printf '%s\n' "$TAG"
