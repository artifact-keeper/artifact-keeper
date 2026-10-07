#!/usr/bin/env bash
#
# Which scanner-adapter digest the release ships, and therefore which one the
# candidate certifies (issue #4076).
#
# The adapter is versioned by docker/scanner-adapter/VERSION, and
# assert-adapter-exact-version.sh decides what `:VERSION` will name:
#   new    the promote creates `:VERSION` from this commit's sha-<sha> image,
#          so that rebuild is what ships.
#   stays  `:VERSION` keeps the digest it was published with from the owning
#          commit. This commit's rebuild of the same sources ships nowhere, so
#          certifying it would name an adapter the release does not contain
#          (1.10.0 shipped 1.2.11 = sha-7f55ff2 while the certification named
#          sha-75e8cd5). The published digest is certified instead, after
#          checking that it is what the owner's sha tag names (provenance) and
#          that Docker Hub's `:VERSION` is absent or the same bytes.
#
# THE TAGGED COMMIT MUST BE ABLE TO VERIFY A "stays" CERTIFICATION. release.yml
# runs on the tag and executes the TAGGED commit's copy of
# scripts/ci/assert-candidate-certified.sh. A copy older than #4076 anchors
# every image at sha-<sha>, finds no certification on the adapter rebuild and
# refuses -- after the promote has already created the immutable tag and
# `:X.Y.Z`, i.e. a burned version. So "stays" is refused here, before
# anything is named, unless the certified commit's verifier understands
# `scanner_adapter_decision`. On a maintenance line that means: backport #4076
# to release/X.Y.x first. ("new" certifies the sha-<sha> rebuild, which every
# verifier accepts.)
#
# Exit codes: 0 ok, 1 refused (anything that does not prove the digest).
#
# Env:
#   DECISION         (required) new|stays, from assert-adapter-exact-version.sh
#   OWNER_REV        40-hex owning commit (required for stays)
#   ADAPTER_VERSION  (required) the adapter VERSION at the certified commit
#   REBUILD_DIGEST   (required for new) this commit's sha-<sha> adapter digest
#   SHORT            (required) the certified commit's 7-char sha
#   CERT_SHA         (required for stays) the certified commit's full sha; its
#                    tree must be in the current git repository
#   CERTIFIED_BRANCH the line the commit belongs to, for the error message
#   ADAPTER_IMAGE    default ghcr.io/artifact-keeper/artifact-keeper-scanner-adapter
#   ADAPTER_HUB_IMAGE  default artifactkeeper/scanner-adapter
#   PIN_DIGEST_CMD, PIN_CONSISTENT_CMD  probe overrides for the self-test
#                    (default .github/scripts/registry-tag-digest.sh and
#                    .github/scripts/assert-version-digest-consistent.sh)
#
# Output (stdout, and $GITHUB_OUTPUT when set): adapter_digest, adapter_tag,
# adapter_image_ref, adapter_decision, adapter_owner_rev.
set -uo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
DIGEST_CMD="${PIN_DIGEST_CMD:-${ROOT}/.github/scripts/registry-tag-digest.sh}"
CONSISTENT_CMD="${PIN_CONSISTENT_CMD:-${ROOT}/.github/scripts/assert-version-digest-consistent.sh}"
IMAGE="${ADAPTER_IMAGE:-ghcr.io/artifact-keeper/artifact-keeper-scanner-adapter}"
HUB_IMAGE="${ADAPTER_HUB_IMAGE:-artifactkeeper/scanner-adapter}"
DECISION="${DECISION:-}"
OWNER_REV="${OWNER_REV:-}"
VERSION="${ADAPTER_VERSION:-}"
REBUILD="${REBUILD_DIGEST:-}"
SHORT="${SHORT:-}"
CERT_SHA="${CERT_SHA:-}"
LINE="${CERTIFIED_BRANCH:-its release line}"
VERIFIER=scripts/ci/assert-candidate-certified.sh
name="${IMAGE#ghcr.io/}"

refuse() { echo "::error title=${1}::${2}"; echo "REFUSED: ${2}"; exit 1; }

[[ -n "$VERSION" ]] || refuse "Scanner adapter version unknown" "ADAPTER_VERSION is empty."
[[ "$SHORT" =~ ^[0-9a-f]{7}$ ]] || refuse "Certified commit unknown" "SHORT must be a 7-character sha (got '${SHORT}')."

case "$DECISION" in
  new)
    [[ "$REBUILD" =~ ^sha256: ]] || refuse "Candidate adapter digest unknown" "REBUILD_DIGEST is '${REBUILD:-<none>}', not a sha256 digest."
    digest="$REBUILD"; tag="sha-${SHORT}"
    echo "  scanner-adapter ${VERSION} is new: the release ships this commit's ${tag} (${digest})."
    ;;
  stays)
    [[ "$OWNER_REV" =~ ^[0-9a-f]{40}$ ]] \
      || refuse "Scanner adapter owner unknown" "the exact-version decision said 'stays' but named no owning revision (got '${OWNER_REV}')."
    [[ "$CERT_SHA" =~ ^[0-9a-f]{40}$ ]] \
      || refuse "Certified commit unknown" "CERT_SHA must be the full 40-character sha of the certified commit (got '${CERT_SHA}')."
    verifier="$(git show "${CERT_SHA}:${VERIFIER}" 2>/dev/null || true)"
    grep -q 'scanner_adapter_decision' <<<"$verifier" \
      || refuse "Tagged commit cannot verify this certification" "scanner-adapter ${VERSION} stays, so the certification names the published :${VERSION} digest, but ${VERIFIER} at ${CERT_SHA:0:7} predates #4076 and would refuse it in release.yml AFTER the tag exists (a burned version). Backport #4076 to ${LINE} first (the verifier, its self-test and release-candidate.yml), then certify the backport commit."
    digest="$("$DIGEST_CMD" ghcr.io "$name" "$VERSION" 2>/dev/null || true)"
    [[ "$digest" =~ ^sha256: ]] \
      || refuse "Published scanner adapter unreadable" "ghcr.io/${name}:${VERSION} is '${digest:-unreadable}', though the decision found it published."
    owner_digest="$("$DIGEST_CMD" ghcr.io "$name" "sha-${OWNER_REV:0:7}" 2>/dev/null || true)"
    [[ "$owner_digest" == "$digest" ]] \
      || refuse "Published scanner adapter provenance mismatch" "ghcr.io/${name}:${VERSION} is ${digest}, but sha-${OWNER_REV:0:7} (the commit it records as its source) is '${owner_digest:-unreadable}'. Refusing to certify bytes whose build cannot be traced."
    "$CONSISTENT_CMD" "$VERSION" "$digest" "ghcr.io|${name}" "docker.io|${HUB_IMAGE}" \
      || refuse "Scanner adapter registries disagree" "docker.io/${HUB_IMAGE}:${VERSION} does not name ${digest} (see above)."
    tag="$VERSION"
    echo "  scanner-adapter ${VERSION} stays: the release ships :${tag} (${digest}, built from ${OWNER_REV:0:7}), not this commit's rebuild ${REBUILD:-<none>}."
    ;;
  *)
    refuse "Scanner adapter decision unreadable" "assert-adapter-exact-version.sh passed but wrote decision='${DECISION}'."
    ;;
esac

emit() {
  echo "$1=$2"
  [[ -n "${GITHUB_OUTPUT:-}" ]] && echo "$1=$2" >> "$GITHUB_OUTPUT"
  return 0
}
emit adapter_digest "$digest"
emit adapter_tag "$tag"
emit adapter_image_ref "${IMAGE}:${tag}@${digest}"
emit adapter_decision "$DECISION"
emit adapter_owner_rev "$OWNER_REV"
exit 0
