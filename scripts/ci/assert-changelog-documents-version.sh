#!/usr/bin/env bash
#
# Refuse a stable release whose CHANGELOG does not document it.
#
#   usage: assert-changelog-documents-version.sh <version|tag> [changelog]
#   exit:  0 documented (or a prerelease, which is exempt), 1 refused, 2 usage
#
# Release policy: every final release vX.Y.Z carries a non-empty `## [X.Y.Z]`
# section in CHANGELOG.md (RELEASING.md step 3). Since entries moved to one
# fragment per PR under changes/unreleased/, that section is written by
# `scripts/release/assemble-changelog.sh X.Y.Z` in the release prep, which
# renders the fragments (and any bullets still under `## [Unreleased]`) into
# it. This check is unchanged by that: it reads the section the assembler
# wrote. It deliberately does NOT look at changes/unreleased/ -- the
# candidate overlays only CHANGELOG.md and .github/release-notes/ from the
# certified commit (RELEASING.md "What runs from the certified commit"), so
# the fragment directory it would see there is main's, not the commit's.
# Fragments left over after the prep are release-preflight check 5's to
# report. This used to live inline in release.yml's verify-images-published
# job, where it ran only on a stable tag push. The candidate flow (#3771,
# #3773) has to ask the same question of a COMMIT before any tag exists, so
# the check lives here once and both callers run it. Prerelease versions
# (contain `-`) are exempt, as before: an -rc is a candidate, not a
# documented release. The same rule is enforced by the version-set-integrity
# job in the artifact-keeper-test release gate when it is dispatched with a
# stable release tag.

set -uo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 <version|tag> [changelog]" >&2
  exit 2
fi

VERSION="${1#v}"
CHANGELOG="${2:-CHANGELOG.md}"

if [[ ! "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "${VERSION} is not a final release version (X.Y.Z); CHANGELOG check skipped."
  exit 0
fi
if [[ ! -f "$CHANGELOG" ]]; then
  echo "::error title=CHANGELOG missing::${CHANGELOG} does not exist on this ref."
  exit 1
fi

ver_esc="${VERSION//./\\.}"
if ! grep -qE "^## \[${ver_esc}\]" "$CHANGELOG"; then
  echo "::error title=CHANGELOG entry missing::${CHANGELOG} has no entry for ${VERSION} -- run 'scripts/release/assemble-changelog.sh ${VERSION}' in the release prep to render changes/unreleased/ into a '## [${VERSION}] - <date>' section before the cut. A release with no entry is refused (RELEASING.md step 3)."
  exit 1
fi
content_lines=$(awk -v ver="${VERSION}" '
  BEGIN { esc = ver; gsub(/\./, "\\.", esc); pat = "^## \\[" esc "\\]" }
  $0 ~ pat { insec = 1; next }
  insec && /^## /  { exit }
  insec && NF > 0  { n++ }
  END { print n + 0 }
' "$CHANGELOG")
if [[ "${content_lines}" -eq 0 ]]; then
  echo "::error title=CHANGELOG entry empty::${CHANGELOG} has a '## [${VERSION}]' heading but no content under it -- the fragments were not assembled into it (scripts/release/assemble-changelog.sh --append ${VERSION}), or there were none; fill in the release notes before the cut."
  exit 1
fi
echo "${CHANGELOG} documents ${VERSION} (${content_lines} content lines). OK."
