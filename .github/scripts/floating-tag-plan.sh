#!/usr/bin/env bash
#
# Decide which FLOATING container tags may be advanced to a given release
# version.
#
#   usage: floating-tag-plan.sh <target-version>
#   stdin: one published release tag per line (`v1.8.1` or `1.8.1`); anything
#          that is not a stable `X.Y.Z` is ignored, so the caller can pipe
#          `gh api .../releases --jq '.[].tag_name'` through a draft/prerelease
#          filter and not worry about SDK/component tags in the same list.
#   stdout: the floating tag names that may point at <target-version>, one per
#           line, in a stable order (`X.Y` before `latest`).
#
# WHY THIS EXISTS
# ---------------
# `:latest` and `:X.Y` used to be written by the merge jobs at tag-push time,
# which is BEFORE the release gate has certified anything. On v1.8.1 the
# publish finished at 14:59:49 and the release published at 16:17:54, so
# `:latest` named gate-uncertified bytes for 78 minutes on the ordinary,
# everything-went-right path. When the cut goes wrong it is worse: v1.7.2
# published `backend:1.7.2` and `:latest`, stayed publicly pullable for hours
# with the gate never run, and the version was then retired.
#
# Floating tags are now applied by a separate post-gate promotion, and this
# script is the rule that promotion obeys:
#
#   A FLOATING TAG MAY ONLY POINT AT A VERSION THAT HAS A PUBLISHED,
#   NON-DRAFT, NON-PRERELEASE GITHUB RELEASE.
#
# That single invariant does three jobs at once:
#
#   * it makes the gate load-bearing -- the release object is only created
#     after the gate, so "has a published release" is a proxy for "certified";
#   * it makes moving a floating tag BACKWARDS impossible without an explicit,
#     visible act (un-publishing the newer release), because `latest` is only
#     allowed for the highest published version and `X.Y` only for the highest
#     within that series;
#   * it gives a rollback that needs no new machinery: delete (or mark
#     prerelease) the bad release, re-run the promote dispatch for the previous
#     version, and this script now permits exactly the tags that should move
#     back.
#
# A backport is handled by the series rule rather than by a special case:
# promoting 1.7.9 while 1.8.2 is the newest release advances `:1.7` and leaves
# `:latest` alone, which is what a maintenance patch should do.
#
# Exit codes:
#   0  a plan was produced (it may legitimately be EMPTY -- e.g. a superseded
#      patch that is newest in neither its series nor overall)
#   2  usage error
#   3  the target is not a stable X.Y.Z (prereleases never take floating tags)
#   4  the target has no published stable release, so no floating tag may move

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <target-version>" >&2
  exit 2
fi

TARGET="${1#v}"

if [[ ! "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "::error title=Not a stable version::'${1}' is not an X.Y.Z release; floating tags are never advanced to a prerelease or candidate." >&2
  exit 3
fi

# Read the published set. Normalise (`vX.Y.Z` -> `X.Y.Z`), keep only stable
# semver, and de-duplicate; a repository can carry the same version as both a
# release tag and some other tag shape.
published=()
while IFS= read -r line; do
  line="${line//[$'\t\r\n ']/}"
  [[ -n "$line" ]] || continue
  line="${line#v}"
  [[ "$line" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
  published+=("$line")
done

if [[ "${#published[@]}" -eq 0 ]]; then
  echo "::error title=No published releases::stdin listed no stable X.Y.Z releases, so there is nothing a floating tag is allowed to point at." >&2
  exit 4
fi

mapfile -t published < <(printf '%s\n' "${published[@]}" | sort -u)

# The target itself must be published. This is the check that would have
# refused the v1.7.2 shape: images existed, the git tag was later deleted, and
# no release object was ever created -- so no floating tag may name it.
target_published=false
for v in "${published[@]}"; do
  if [[ "$v" == "$TARGET" ]]; then
    target_published=true
    break
  fi
done
if [[ "$target_published" != true ]]; then
  echo "::error title=No published release for ${TARGET}::A floating tag may only point at a version with a published, non-draft, non-prerelease GitHub Release. ${TARGET} has none, so no floating tag will be moved." >&2
  exit 4
fi

# Numeric, field-wise semver ordering. `sort -V` is close but is locale- and
# implementation-sensitive; an explicit numeric key sort on the three fields is
# not, and stable semver has exactly three fields here by construction.
newest_of() { # reads versions on stdin, prints the highest
  sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1
}

series="${TARGET%.*}"                      # 1.8.2 -> 1.8
newest_overall="$(printf '%s\n' "${published[@]}" | newest_of)"
newest_in_series="$(printf '%s\n' "${published[@]}" | grep -E "^${series//./\\.}\." | newest_of)"

plan=()
if [[ "$TARGET" == "$newest_in_series" ]]; then
  plan+=("$series")
  echo "  ${series}  -> allowed (${TARGET} is the newest published ${series}.x release)" >&2
else
  echo "  ${series}  -> refused (newest published ${series}.x release is ${newest_in_series})" >&2
fi

if [[ "$TARGET" == "$newest_overall" ]]; then
  plan+=("latest")
  echo "  latest -> allowed (${TARGET} is the newest published release)" >&2
else
  echo "  latest -> refused (newest published release is ${newest_overall})" >&2
fi

if [[ "${#plan[@]}" -gt 0 ]]; then
  printf '%s\n' "${plan[@]}"
fi
