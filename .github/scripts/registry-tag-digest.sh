#!/usr/bin/env bash
#
# Report the manifest-list digest a container registry serves for a tag,
# without ever guessing (issue #3771).
#
#   usage: registry-tag-digest.sh <ghcr.io|docker.io> <repository> <tag>
#   stdout: exactly one of `sha256:<64 hex>`, `absent`, `indeterminate`
#   exit:   0 for a digest, 1 for absent/indeterminate
#
# Why this exists
# ---------------
# release.yml resolves the digest the gate tests with an inline HEAD request
# and reads `Docker-Content-Digest`; release-preflight.sh and the publish
# guards read tag PRESENCE through registry-tag-state.sh. The candidate and
# promote flows need both answers for the `sha-<sha>` images Docker Publish
# built on main -- "what digest does this tag name right now" -- from a plain
# ubuntu runner and from a laptop, so this is the digest counterpart of
# registry-tag-state.sh: same token exchange, same read-access proof before a
# 404 is believed, same three-way answer. `absent` is only ever reported for a
# definitive MANIFEST_UNKNOWN 404 from a repository we have demonstrably been
# able to read; anything else is `indeterminate`, and callers treat that as a
# hard stop rather than as absence.
#
# The digest is the registry's `Docker-Content-Digest` header for the tag's
# manifest (the manifest-list digest for a multi-arch tag -- the identity
# `docker pull` resolves and cosign signs). When a registry omits the header,
# the body's sha256 is the same value by definition and is used instead.
#
# Environment:
#   GHCR_TOKEN                          token used to mint a ghcr.io pull token
#   DOCKERHUB_USERNAME/DOCKERHUB_TOKEN  optional Docker Hub credentials; without
#                                       them an anonymous pull token is used,
#                                       which can only see public repositories

set -uo pipefail

ABSENT='absent'
INDETERMINATE='indeterminate'

MANIFEST_ACCEPT=(
  -H 'Accept: application/vnd.oci.image.index.v1+json'
  -H 'Accept: application/vnd.docker.distribution.manifest.list.v2+json'
  -H 'Accept: application/vnd.docker.distribution.manifest.v2+json'
)

log() { echo "registry-tag-digest: $*" >&2; }

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
  local host token body headers code rc digest

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

  body=$(mktemp); headers=$(mktemp)
  # shellcheck disable=SC2064
  trap "rm -f '$body' '$headers'" RETURN

  # Prove read access before believing any 404 (registry-tag-state.sh has the
  # full rationale: an unauthorized read and a free tag answer alike).
  code=$(curl -sS --proto '=https' --max-time 30 -o "$body" -w '%{http_code}' \
    -H "Authorization: Bearer ${token}" \
    "https://${host}/v2/${name}/tags/list?n=1" 2>/dev/null)
  rc=$?
  if [[ $rc -ne 0 || "$code" != '200' ]]; then
    log "${registry}/${name}: tag listing returned HTTP ${code} (curl exit ${rc}); cannot prove read access"
    echo "$INDETERMINATE"
    return 1
  fi

  # No -L: a redirect would move the Bearer token to another host, and the
  # manifest endpoint answers directly on every registry this supports.
  code=$(curl -sS --proto '=https' --max-time 30 -o "$body" -D "$headers" -w '%{http_code}' \
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
      digest=$(tr -d '\r' < "$headers" \
        | awk 'tolower($1) == "docker-content-digest:" { d = $2 } END { print d }')
      if [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
        digest="sha256:$(sha256sum "$body" | awk '{ print $1 }')"
        log "${registry}/${name}:${tag}: no Docker-Content-Digest header; digest computed from the manifest body"
      fi
      log "${registry}/${name}:${tag}: HTTP 200, ${digest}"
      echo "$digest"
      return 0
      ;;
    404)
      if jq -e '(.errors // []) | any(.code == "MANIFEST_UNKNOWN")' "$body" >/dev/null 2>&1; then
        log "${registry}/${name}:${tag}: HTTP 404 MANIFEST_UNKNOWN from a readable repository, tag is absent"
        echo "$ABSENT"
        return 1
      fi
      log "${registry}/${name}:${tag}: HTTP 404 without a MANIFEST_UNKNOWN error code; not treating as absence"
      echo "$INDETERMINATE"
      return 1
      ;;
    *)
      log "${registry}/${name}:${tag}: HTTP ${code}; not a digest"
      echo "$INDETERMINATE"
      return 1
      ;;
  esac
}

main "$@"
