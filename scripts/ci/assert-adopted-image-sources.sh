#!/usr/bin/env bash
#
# Refuse to adopt published images unless they were built from sources
# byte-identical to the commit being released (issue #3640).
#
# WHY THIS EXISTS
#   resolve-candidate-digest can now accept a `promote_version` dispatch as
#   the docker-publish run that vouches for a release (the re-tag recovery,
#   #2698). A promote rebuilds nothing -- it re-points tags at bytes that
#   already exist -- so on a re-tagged version the published image was built
#   from a DIFFERENT commit than the tag. Backend builds are non-reproducible
#   by construction (GIT_SHA is a build-arg, provenance mode=max embeds the
#   revision), so "same digest" can never be re-proven by rebuilding; the only
#   sound question is whether the published revision and the tag differ in any
#   input the image is built FROM. This script asks exactly that question and
#   hard-refuses on any difference: an under-specified or skipped comparison
#   here is how a release gate would silently certify stale bytes.
#
#   The comparison is the same idiom release-preflight.sh check 4 uses for the
#   scanner-adapter (`git diff <published-rev> <tag-sha> -- <image inputs>`).
#
# THE INPUT SET
#   Exactly what docker/Dockerfile.backend consumes from the build context --
#   its only context COPYs are `Cargo.toml Cargo.lock ./`, `backend ./backend`
#   and `.sqlx ./.sqlx` -- plus the Dockerfile itself (base images, build
#   steps, tool pins) and .dockerignore (it shapes what `COPY backend` sees).
#   If the Dockerfile grows a new context COPY, this list MUST grow with it.
#
# WHAT IS KNOWINGLY NOT ASSERTED
#   "The image was built from the tagged commit." On a verified adoption the
#   published revision differs from the tag by non-image files (changelog,
#   CI scripts); the image's own revision annotation and embedded GIT_SHA
#   keep naming the commit that built it. No gate anywhere asserted the
#   image-built-from-tag property before this script existed either -- it was
#   lost silently; now the skew is measured, bounded to non-image paths, and
#   printed loudly.
#
# Env:
#   ADOPT_TAG_SHA        (required) 40-hex commit being released
#   ADOPT_PUBLISHED_REV  (required) what registry-tag-revision.sh reported for
#                        the published :VERSION index: a 40-hex sha, `none`,
#                        or `indeterminate`
#   ADOPT_PATHS          override the input path set (self-test only)
#   ADOPT_LABEL          image label for messages (default backend:VERSION)
#   GITHUB_STEP_SUMMARY  appended to when set
#
# Exit:
#   0  identical revision, or a verified adoption (diff over the input set
#      is empty)
#   1  REFUSED -- sources differ inside the input set, or the published image
#      carries no provenance to verify against
#   2  INFRA   -- could not measure (unreadable annotation, unfetchable
#      commit). NOT a verdict about the bytes.
#
set -uo pipefail

SHA="${ADOPT_TAG_SHA:-}"
REV="${ADOPT_PUBLISHED_REV:-}"
LABEL="${ADOPT_LABEL:-the published backend image}"
DEFAULT_PATHS="Cargo.toml Cargo.lock backend .sqlx docker/Dockerfile.backend .dockerignore"
read -r -a PATHS <<< "${ADOPT_PATHS:-$DEFAULT_PATHS}"

summary() {
  [ -n "${GITHUB_STEP_SUMMARY:-}" ] && printf '%s\n' "$1" >> "$GITHUB_STEP_SUMMARY"
  printf '%s\n' "$1"
}

if [[ ! "$SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "INFRA: ADOPT_TAG_SHA must be a full 40-char sha (got '${SHA}')" >&2
  exit 2
fi

case "$REV" in
  "$SHA")
    summary "Image provenance: ${LABEL} was built from the tagged commit ${SHA} -- no adoption needed."
    exit 0
    ;;
  none)
    # A measured answer: the index exists and carries no revision annotation.
    # Without provenance there is nothing to verify an adoption against.
    echo "REFUSED: ${LABEL} is published but carries no org.opencontainers.image.revision annotation; an unverifiable image cannot be adopted." >&2
    exit 1
    ;;
  indeterminate | "")
    echo "INFRA: the source revision of ${LABEL} could not be read (got '${REV:-<empty>}'); indeterminate, retry." >&2
    exit 2
    ;;
esac

if [[ ! "$REV" =~ ^[0-9a-f]{40}$ ]]; then
  echo "INFRA: ADOPT_PUBLISHED_REV is not a sha/none/indeterminate (got '${REV}')" >&2
  exit 2
fi

# A shallow checkout may not have the published commit; fetch just it.
for c in "$REV" "$SHA"; do
  if ! git cat-file -e "${c}^{commit}" 2>/dev/null; then
    git fetch --no-tags --depth=1 origin "$c" >/dev/null 2>&1 || true
  fi
  if ! git cat-file -e "${c}^{commit}" 2>/dev/null; then
    echo "INFRA: commit ${c} is not fetchable, so the source comparison cannot be made." >&2
    exit 2
  fi
done

if git diff --quiet "$REV" "$SHA" -- "${PATHS[@]}"; then
  summary "Image provenance: VERIFIED ADOPTION -- ${LABEL} was published from ${REV}, the tag is ${SHA}, and the two are byte-identical across every image input (${PATHS[*]}). The commits differ only outside the image."
  exit 0
fi

echo "REFUSED: ${LABEL} was published from ${REV}, but the tag ${SHA} changes image inputs:" >&2
git diff --name-only "$REV" "$SHA" -- "${PATHS[@]}" | sed 's/^/  /' >&2
echo "-> these published bytes are STALE for this tag. Bump the version (do not re-tag) or revert the input change." >&2
summary "Image provenance: REFUSED adoption of ${LABEL} (published from ${REV}; tag ${SHA} changes image inputs)."
exit 1
