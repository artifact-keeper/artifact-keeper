#!/usr/bin/env bash
#
# Refuse to publish an exact release tag that a registry already serves.
#
#   usage: assert-stable-tag-free.sh <tag> <registry>'|'<repository> [more...]
#
# Exit 0 only when EVERY named registry definitively reports the tag as free.
# A tag that already exists is a refusal, and so is any answer the probe cannot
# stand behind (see registry-tag-state.sh) -- publishing over a tag because a
# registry was briefly unreachable is the failure this guard exists to prevent.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROBE="${SCRIPT_DIR}/registry-tag-state.sh"

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <tag> <registry>|<repository> [more...]" >&2
  exit 2
fi

TAG="$1"
shift

blocked=0

for target in "$@"; do
  registry="${target%%|*}"
  repository="${target#*|}"

  state=$("$PROBE" "$registry" "$repository" "$TAG") || true

  case "$state" in
    absent)
      echo "  ok   ${registry}/${repository}:${TAG} is not published yet"
      ;;
    present)
      echo "::error title=Published tag would be overwritten::${registry}/${repository}:${TAG} already exists. Exact version tags are the identity a chart pins; they are never republished. Cut a new version instead."
      blocked=1
      ;;
    *)
      echo "::error title=Registry lookup inconclusive::Unable to prove whether ${registry}/${repository}:${TAG} exists. Refusing to publish rather than risk replacing a published tag."
      blocked=1
      ;;
  esac
done

exit "$blocked"
