#!/usr/bin/env bash
#
# Refuse a stable release whose CHANGELOG does not document it.
#
#   usage: assert-changelog-documents-version.sh <version|tag> [changelog]
#   exit:  0 documented (or a prerelease, which is exempt), 1 refused, 2 usage
#
# Release policy: every final release vX.Y.Z carries a non-empty `## [X.Y.Z]`
# section in CHANGELOG.md (promote [Unreleased] before the cut; RELEASING.md
# step 3). This used to live inline in release.yml's verify-images-published
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
  echo "::error title=CHANGELOG entry missing::${CHANGELOG} has no entry for ${VERSION} -- promote [Unreleased] to a '## [${VERSION}] - <date>' section before the cut. A release with no entry is refused (RELEASING.md step 3)."
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
  echo "::error title=CHANGELOG entry empty::${CHANGELOG} has a '## [${VERSION}]' heading but no content under it -- fill in the release notes before the cut."
  exit 1
fi
echo "${CHANGELOG} documents ${VERSION} (${content_lines} content lines). OK."
