#!/usr/bin/env bash
#
# Report whether a tag exists in a container registry, without ever guessing.
#
#   usage: registry-tag-state.sh <ghcr.io|docker.io> <repository> <tag>
#   stdout: exactly one of `present`, `absent`, `indeterminate`
#   exit:   0 for present/absent, 1 for indeterminate
#
# Why this exists
# ---------------
# The obvious implementation -- run `docker buildx imagetools inspect` and
# decide the tag is absent when the error text mentions "manifest unknown" --
# fails open. Registries deliberately answer an unauthorized read with the
# same "manifest unknown" that they use for a genuinely missing tag (it stops
# anonymous callers from enumerating private repositories), and unrelated
# problems produce text that matches too: a missing `docker` binary, a buildx
# flag error, a DNS failure, an HTML error page from an intercepting proxy, or
# an expired credential. Every one of those would be read as "the tag is free
# to publish".
#
# So this script reads an HTTP status from the registry API instead of
# pattern-matching an error blob, and it only ever reports `absent` for a
# definitive `404` carrying a `MANIFEST_UNKNOWN` error code from a repository
# we have demonstrably been able to read. Anything else -- 401, 403, 5xx,
# a network failure, an unparseable body -- is `indeterminate`, and callers
# are expected to treat that as a hard stop rather than as absence.
#
# Environment:
#   GHCR_TOKEN                        token used to mint a ghcr.io pull token
#   DOCKERHUB_USERNAME/DOCKERHUB_TOKEN  optional Docker Hub credentials; without
#                                     them an anonymous pull token is used,
#                                     which can only see public repositories
#                                     (a private repository then reports
#                                     `indeterminate`, not `absent`)

set -uo pipefail

PRESENT='present'
ABSENT='absent'
INDETERMINATE='indeterminate'

MANIFEST_ACCEPT=(
  -H 'Accept: application/vnd.oci.image.index.v1+json'
  -H 'Accept: application/vnd.oci.image.manifest.v1+json'
  -H 'Accept: application/vnd.docker.distribution.manifest.list.v2+json'
  -H 'Accept: application/vnd.docker.distribution.manifest.v2+json'
)

log() { echo "registry-tag-state: $*" >&2; }

registry_host() {
  case "$1" in
    ghcr.io) echo 'ghcr.io' ;;
    docker.io) echo 'registry-1.docker.io' ;;
    *) return 1 ;;
  esac
}

# Mint a pull-scoped bearer token. Prints the token, or nothing on failure.
fetch_token() {
  local registry="$1" name="$2" response=''

  case "$registry" in
    ghcr.io)
      response=$(curl -sS --proto '=https' --max-time 30 \
        -H "Authorization: Bearer ${GHCR_TOKEN:-}" \
        "https://ghcr.io/token?service=ghcr.io&scope=repository:${name}:pull" 2>/dev/null) || return 1
      ;;
    docker.io)
      local auth=()
      if [[ -n "${DOCKERHUB_USERNAME:-}" && -n "${DOCKERHUB_TOKEN:-}" ]]; then
        auth=(-u "${DOCKERHUB_USERNAME}:${DOCKERHUB_TOKEN}")
      fi
      response=$(curl -sS --proto '=https' --max-time 30 "${auth[@]}" \
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${name}:pull" 2>/dev/null) || return 1
      ;;
    *)
      return 1
      ;;
  esac

  jq -r '.token // empty' <<<"$response" 2>/dev/null
}

main() {
  if [[ $# -ne 3 ]]; then
    log "usage: $0 <ghcr.io|docker.io> <repository> <tag>"
    echo "$INDETERMINATE"
    return 1
  fi

  local registry="$1" name="$2" tag="$3"
  local host token body code rc

  if ! host=$(registry_host "$registry"); then
    log "unknown registry '${registry}'"
    echo "$INDETERMINATE"
    return 1
  fi

  token=$(fetch_token "$registry" "$name")
  if [[ -z "$token" ]]; then
    log "could not obtain a pull token for ${registry}/${name}"
    echo "$INDETERMINATE"
    return 1
  fi

  body=$(mktemp)
  # shellcheck disable=SC2064
  trap "rm -f '$body'" RETURN

  # Establish that we can actually read this repository before believing any
  # 404 it gives us. Without this, an authorization failure and a free tag are
  # the same answer.
  code=$(curl -sS --proto '=https' --max-time 30 -o "$body" -w '%{http_code}' \
    -H "Authorization: Bearer ${token}" \
    "https://${host}/v2/${name}/tags/list?n=1" 2>/dev/null)
  rc=$?
  if [[ $rc -ne 0 ]]; then
    log "${registry}/${name}: tag listing failed to complete (curl exit ${rc})"
    echo "$INDETERMINATE"
    return 1
  fi
  if [[ "$code" != '200' ]]; then
    log "${registry}/${name}: tag listing returned HTTP ${code}; cannot prove read access, so a 404 on a manifest would be meaningless"
    echo "$INDETERMINATE"
    return 1
  fi

  code=$(curl -sSL --proto '=https' --max-time 30 -o "$body" -w '%{http_code}' \
    -H "Authorization: Bearer ${token}" \
    "${MANIFEST_ACCEPT[@]}" \
    "https://${host}/v2/${name}/manifests/${tag}" 2>/dev/null)
  rc=$?
  if [[ $rc -ne 0 ]]; then
    log "${registry}/${name}:${tag}: manifest request failed to complete (curl exit ${rc})"
    echo "$INDETERMINATE"
    return 1
  fi

  case "$code" in
    200)
      log "${registry}/${name}:${tag}: HTTP 200, tag is published"
      echo "$PRESENT"
      return 0
      ;;
    404)
      if jq -e '(.errors // []) | any(.code == "MANIFEST_UNKNOWN")' "$body" >/dev/null 2>&1; then
        log "${registry}/${name}:${tag}: HTTP 404 MANIFEST_UNKNOWN from a readable repository, tag is free"
        echo "$ABSENT"
        return 0
      fi
      log "${registry}/${name}:${tag}: HTTP 404 without a MANIFEST_UNKNOWN error code; not treating as absence"
      echo "$INDETERMINATE"
      return 1
      ;;
    *)
      log "${registry}/${name}:${tag}: HTTP ${code}; not treating as absence"
      echo "$INDETERMINATE"
      return 1
      ;;
  esac
}

main "$@"
