#!/usr/bin/env bash
#
# Digest-aware republish guard for the exact (chart-pinned) version tag.
#
#   usage: assert-version-digest-consistent.sh <version-tag> <incoming-digest> \
#            <registry>'|'<repository> [more targets...]
#   env:   GHCR_TOKEN, DOCKERHUB_USERNAME, DOCKERHUB_TOKEN  (for the state probe)
#          the caller must also be `docker login`-ed to each registry so
#          `docker buildx imagetools inspect` can read a present tag's digest.
#
# <incoming-digest> is the sha256 manifest-list digest this run points the
# version tag at -- the manifest already assembled on (or resolved from) ghcr
# THIS run. It is compared against whatever each registry currently serves for
# <version-tag>.
#
# Why this replaces the blunt "tag exists -> refuse" guard
# --------------------------------------------------------
# The old guard (assert-stable-tag-free.sh) refused whenever the version tag was
# PRESENT on either registry. That is correct for a fresh cut but wedges a
# partial publish permanently: at the v1.6.2 cut the ghcr manifest published,
# then the Docker Hub copy died on a transient network error, so the job went
# red with `:1.6.2` already on ghcr. Every re-run then died at the guard --
# because `:1.6.2` IS published -- and there was no way to finish the mirror.
#
# The safety property the guard actually protects is narrower than "the tag
# exists": it is "a released image is never silently REPLACED WITH DIFFERENT
# CONTENT". So this guard compares digests instead of mere existence:
#
#   absent        -> OK. First publish, or this registry never received the tag
#                    (partial-publish recovery -- e.g. ghcr has it, Docker Hub
#                    does not). There is nothing to overwrite.
#   present, SAME -> OK. The tag already resolves to <incoming-digest>.
#                    Re-applying it is a byte-for-byte no-op. THIS is what makes
#                    a plain re-run (or the promote path) idempotent and lets a
#                    partial publish be completed.
#   present, DIFF -> REFUSE. The tag is published and resolves to OTHER content.
#                    Re-pointing it would silently replace a released image with
#                    different bits (a moved/re-cut git tag the preflight cannot
#                    detect, or a tamper). This is the supply-chain protection,
#                    preserved verbatim -- a DIFFERENT digest is still refused.
#   indeterminate -> REFUSE (fail closed). Exactly as assert-stable-tag-free:
#                    if the tag's state cannot be PROVEN we never publish over
#                    it. An auth failure / outage must not read as "absent".
#
# State detection is delegated to registry-tag-state.sh, which reads an HTTP
# status (never an error-text blob) and only ever reports `absent` for a
# definitive MANIFEST_UNKNOWN 404 from a repository it has proven it can read.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROBE="${SCRIPT_DIR}/registry-tag-state.sh"

# The pure comparison. Kept as a named function with no I/O so it can be
# exercised directly by --self-test: `decide <state> <existing> <incoming>`
# returns 0 to ALLOW (publish/no-op) and 1 to REFUSE.
decide() {
  local state="$1" existing="$2" incoming="$3"
  case "$state" in
    absent)
      return 0 ;;                                  # nothing published -> allow
    present)
      [[ -n "$existing" && "$existing" == "$incoming" ]] && return 0
      return 1 ;;                                  # missing/other digest -> refuse
    *)
      return 1 ;;                                  # indeterminate -> fail closed
  esac
}

self_test() {
  local fails=0 d1='sha256:aaaa' d2='sha256:bbbb'
  check() { # <desc> <expected 0|1> <state> <existing> <incoming>
    local desc="$1" want="$2"; shift 2
    decide "$@"; local got=$?
    if [[ "$got" -eq "$want" ]]; then
      echo "  ok   ${desc} (verdict=${got})"
    else
      echo "  FAIL ${desc}: wanted ${want} got ${got}"; fails=1
    fi
  }
  # absent -> allow (fresh publish / partial-publish recovery)
  check "absent allows publish"                 0 absent ''   "$d1"
  # present + same digest -> allow (idempotent re-apply / promote)
  check "present same-digest allows re-apply"   0 present "$d1" "$d1"
  # present + different digest -> REFUSE (the threat: overwrite w/ other bits)
  check "present different-digest refuses"      1 present "$d2" "$d1"
  # present but digest unreadable -> REFUSE (cannot prove SAME)
  check "present unreadable-digest refuses"     1 present ''   "$d1"
  # indeterminate -> REFUSE (fail closed)
  check "indeterminate refuses (fail closed)"   1 indeterminate '' "$d1"
  return "$fails"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
  exit $?
fi

if [[ $# -lt 3 ]]; then
  echo "usage: $0 <version-tag> <incoming-digest> <registry>|<repository> [more...]" >&2
  exit 2
fi

TAG="$1"
INCOMING="$2"
shift 2

# Normalize: accept the digest with or without the sha256: prefix.
[[ "$INCOMING" == sha256:* ]] || INCOMING="sha256:${INCOMING}"

blocked=0

for target in "$@"; do
  registry="${target%%|*}"
  repository="${target#*|}"
  ref="${registry}/${repository}:${TAG}"

  state=$("$PROBE" "$registry" "$repository" "$TAG") || true

  existing=""
  if [[ "$state" == "present" ]]; then
    # Read the manifest-list digest the registry currently serves for this tag.
    existing=$(docker buildx imagetools inspect --format '{{json .Manifest}}' "$ref" 2>/dev/null \
      | jq -r '.digest // empty' 2>/dev/null) || existing=""
    if [[ -z "$existing" ]]; then
      # Present per the HTTP probe but its digest could not be read back: treat
      # as unprovable rather than assume a match. Fails closed via decide().
      echo "registry-tag-state: ${ref} reported present but its digest was unreadable" >&2
    fi
  fi

  if decide "$state" "$existing" "$INCOMING"; then
    case "$state" in
      absent)  echo "  ok   ${ref} is not published yet — nothing to overwrite" ;;
      present) echo "  ok   ${ref} already resolves to ${INCOMING} — idempotent re-apply" ;;
    esac
  else
    case "$state" in
      present)
        echo "::error title=Published version would be overwritten::${ref} is published at ${existing:-<unreadable>}, but this run resolves ${INCOMING}. Exact version tags are the identity a chart pins; they are never re-pointed to different content. Cut a new version instead."
        ;;
      *)
        echo "::error title=Registry lookup inconclusive::Unable to prove the state of ${ref} (probe said '${state}'). Refusing to publish rather than risk replacing a published tag."
        ;;
    esac
    blocked=1
  fi
done

exit "$blocked"
