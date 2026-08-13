#!/usr/bin/env bash
#
# Report the source revision a published image tag was built from.
#
#   usage: registry-tag-revision.sh <ghcr.io|docker.io> <repository> <tag>
#   stdout: a 40-hex commit sha, or `none`, or `indeterminate`
#   exit:   0 for a sha, 1 for none/indeterminate
#
# Why this exists
# ---------------
# docker-publish.yml stamps every multi-arch index it creates with
# `--annotation "index:org.opencontainers.image.revision=${GITHUB_SHA}"`, and
# the scanner-adapter publish job reads that annotation back to decide whether
# a rebuild of an already-published exact version tag would change the image.
# It reads it with `docker buildx imagetools inspect`, which needs a docker
# daemon and a registry login.
#
# release-preflight.sh has to answer the same question BEFORE a tag exists, and
# it runs on a maintainer's laptop and on a plain ubuntu runner. Requiring
# docker + buildx + a registry login there would mean the check silently does
# not run in exactly the situations it is meant to protect. So this reads the
# annotation straight off the registry API with curl, the way its sibling
# registry-tag-state.sh reads presence.
#
# The three outcomes are kept distinct on purpose, because callers must treat
# them differently:
#
#   <sha>          the tag is published and names the commit it was built from.
#   none           the manifest was read successfully and carries no valid
#                  revision annotation. This is a real, measured answer -- the
#                  publish job hard-fails on it ("Adapter provenance missing"),
#                  so a caller should treat it as a problem, not as a retry.
#   indeterminate  we could not read the manifest at all (auth, network, 5xx,
#                  an unparseable body). NOT a statement about the image.
#
# Collapsing `none` into `indeterminate` would turn a genuine provenance defect
# into an infrastructure retry; collapsing it the other way would turn a dead
# credential into a fabricated verdict about someone's published image. Same
# discipline as registry-tag-state.sh, which refuses to read an unauthorized
# 404 as absence.
#
# Environment:
#   GHCR_TOKEN                          token used to mint a ghcr.io pull token
#   DOCKERHUB_USERNAME/DOCKERHUB_TOKEN  optional Docker Hub credentials; without
#                                       them an anonymous pull token is used,
#                                       which can only see public repositories

set -uo pipefail

NONE='none'
INDETERMINATE='indeterminate'

MANIFEST_ACCEPT=(
  -H 'Accept: application/vnd.oci.image.index.v1+json'
  -H 'Accept: application/vnd.oci.image.manifest.v1+json'
  -H 'Accept: application/vnd.docker.distribution.manifest.list.v2+json'
  -H 'Accept: application/vnd.docker.distribution.manifest.v2+json'
)

log() { echo "registry-tag-revision: $*" >&2; }

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
  local host token body code rc rev

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
  if [[ "$code" != '200' ]]; then
    log "${registry}/${name}:${tag}: HTTP ${code}; cannot read the revision annotation"
    echo "$INDETERMINATE"
    return 1
  fi

  # docker-publish stamps the annotation on the INDEX (`index:` prefix on the
  # imagetools --annotation flag), which is the object this request returns for
  # a multi-arch tag.
  if ! rev=$(jq -r '.annotations["org.opencontainers.image.revision"] // empty' "$body" 2>/dev/null); then
    log "${registry}/${name}:${tag}: manifest body did not parse as JSON"
    echo "$INDETERMINATE"
    return 1
  fi

  if [[ "$rev" =~ ^[0-9a-f]{40}$ ]]; then
    log "${registry}/${name}:${tag}: built from ${rev}"
    echo "$rev"
    return 0
  fi

  # Read fine, but there is no usable provenance. A measured answer.
  log "${registry}/${name}:${tag}: no valid org.opencontainers.image.revision annotation"
  echo "$NONE"
  return 1
}

main "$@"
