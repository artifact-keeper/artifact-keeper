#!/usr/bin/env bash
#
# Watch the digest-pinned external base images, off the release path (#3755).
#
# WHY THIS EXISTS
# ---------------
# docker/Dockerfile.scanner-adapter pins its trivy stage by DIGEST, not by tag,
# and the comment above that `FROM` says why: `artifact-keeper/trivy` rebuilds
# weekly to pick up RPM errata, so its tags are moving targets by design. That
# same comment ends with "the digest below will need moving again".
#
# Nothing in this repository noticed when it did. The sibling publishes a new
# `0.74.0-rN` tag whenever a CVE forces a dependency override; the digest here
# ages silently; and the first signal is the Docker Publish security gate going
# red on the scanner-adapter arm -- at release time, on the critical path of a
# cut. That is how CVE-2026-84304 (grpc-go, HIGH, fixed) blocked this week's
# cut until artifact-keeper/trivy#12 was merged, tagged `v0.74.0-r2`, and the
# digest repointed by #3753. The whole loop was manual and none of it started
# until a release was already blocked.
#
# So this asks, on a schedule, the two questions the publish gate only asks at
# the worst possible moment:
#
#   FRESHNESS      does the pinned digest still name the newest published tag
#                  of that repository?
#   VULNERABILITY  does the pinned digest still scan clean under the SAME
#                  configuration the publish gate applies?
#
# WHY THE TWO ANSWERS ARE WEIGHTED DIFFERENTLY
# --------------------------------------------
# A vulnerable pin is a fact about the image we are shipping: it will block the
# next publish, so it FAILS here (exit 1) while there is still time to open the
# override PR upstream. A merely stale pin is not: the sibling rebuilds weekly
# for errata that often change nothing we ship, and chasing every rebuild would
# mean a scanner-adapter VERSION bump a week for no security gain. Worth
# remembering that freshness is not even a proxy for safety here -- v0.73.0-r1
# scanned clean when it was published on 2026-08-07 and went red on 2026-08-13
# (#3307) without a byte changing, and 0.73.0-r2 then went red the same way. So
# "newer tag exists, pin still clean" is a WARNING and moving the pin is
# optional.
#
# THE SCAN CONFIGURATION IS NOT A CHOICE
# --------------------------------------
# The gate this check is trying to pre-empt is `Trivy gate - Scanner Adapter`
# in .github/workflows/docker-publish.yml:
#
#     severity: 'CRITICAL,HIGH'   ignore-unfixed: true   trivyignores: '.trivyignore'
#
# and scripts/ci/check-trivy-gate-severity.sh is the CI gate that keeps that
# severity filter actually reaching Trivy (#3122). Scanning here with anything
# looser would cry wolf; scanning with anything tighter would miss exactly the
# finding we exist to catch. The flags below mirror those three inputs.
#
# We ask Trivy for JSON with `--exit-code 0` and count the results ourselves
# rather than letting `--exit-code 1` speak: Trivy uses exit 1 both for "found
# something" and for "I failed", and collapsing those two would turn a broken
# DB download into a fabricated verdict about someone's published image. Same
# discipline as .github/scripts/registry-tag-state.sh, which refuses to read an
# unauthorized 404 as absence. `--severity` is honoured for every CLI format;
# it is only the trivy-ACTION wrapper that discards it for SARIF (#3122).
#
# EXIT CODES
#   0  OK      -- every pin is clean (possibly with a staleness WARNING)
#   1  FAIL    -- at least one pin has a CRITICAL/HIGH fixed finding
#   2  INFRA   -- an answer could not be obtained (no network, no token, no
#                 trivy, an image whose upstream this script cannot map). NEVER
#                 a pass: an unmeasured pin is not a clean pin. Exit 1 outranks
#                 exit 2, as in scripts/ci/release-preflight.sh -- a finding we
#                 did measure is not weakened by a later one we could not.
#
# USAGE
#   check-pinned-base-images.sh [<repo-root>]
#
# ENVIRONMENT
#   GHCR_TOKEN / GITHUB_TOKEN   token used to mint a ghcr.io pull token and to
#                               call the GitHub tags API
#
#   The three probes are indirected through these so the unit test can run
#   without a network (scripts/ci/test-check-pinned-base-images.sh). Each stub
#   is invoked with the same arguments as the real probe, must print the same
#   thing on stdout, and must exit non-zero only to mean "could not measure":
#
#   PINNED_BASE_TAGS_CMD    <owner/repo>                 -> tag names, one per line
#   PINNED_BASE_DIGEST_CMD  <registry> <name> <tag>       -> sha256:<64hex>
#   PINNED_BASE_SCAN_CMD    <image-ref> <ignorefile>      -> findings, one per line,
#                                                           TSV: severity, id, pkg,
#                                                           installed, fixed

set -uo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

RED=''; YELLOW=''; GREEN=''; RST=''
if [ -t 1 ]; then
  RED=$'\033[31m'; YELLOW=$'\033[33m'; GREEN=$'\033[32m'; RST=$'\033[0m'
fi

problems=0
warnings=0
infra=0
checked=0

log() { echo "check-pinned-base-images: $*" >&2; }

note_infra() { # <message>
  echo "${YELLOW}INFRA${RST}: $1"
  infra=$((infra + 1))
}

# ---------------------------------------------------------------------------
# Where a pinned image's tags come from.
#
# Table-driven on purpose. The trivy stage is the only digest-pinned external
# base image today, and a check written around that single fact would have to
# be rewritten the first time a second one appears. Adding a row is the whole
# cost of a new pin.
#
# An image with no row is INFRA, not a pass: we cannot answer "is this the
# newest tag" for an upstream we do not know how to enumerate, and saying
# nothing would be indistinguishable from saying it is fine.
# ---------------------------------------------------------------------------
source_repo_for_image() { # <image> -> <owner/repo> on stdout
  case "$1" in
    ghcr.io/artifact-keeper/*)
      # Our own rebuild-of-upstream repos: ghcr.io/artifact-keeper/<name> is
      # published by the GitHub repo artifact-keeper/<name>.
      echo "artifact-keeper/${1##*/}"
      ;;
    *) return 1 ;;
  esac
}

# The publish job renders the git tag without its leading `v`
# (docker/metadata-action `type=semver,pattern={{version}}`), so `v0.74.0-r2`
# in git is `0.74.0-r2` in the registry.
registry_tag_for_source_tag() { echo "${1#v}"; }

# ---------------------------------------------------------------------------
# Probes. One function each; the real implementation runs only when no stub is
# configured.
# ---------------------------------------------------------------------------

probe_source_tags() { # <owner/repo>
  if [ -n "${PINNED_BASE_TAGS_CMD:-}" ]; then
    "$PINNED_BASE_TAGS_CMD" "$1"
    return $?
  fi
  command -v gh >/dev/null 2>&1 || { log "gh is not on PATH"; return 1; }
  gh api --paginate "repos/$1/tags" --jq '.[].name' 2>/dev/null
}

probe_tag_digest() { # <registry> <name> <tag>
  if [ -n "${PINNED_BASE_DIGEST_CMD:-}" ]; then
    "$PINNED_BASE_DIGEST_CMD" "$1" "$2" "$3"
    return $?
  fi

  local registry="$1" name="$2" tag="$3" host token digest
  case "$registry" in
    ghcr.io) host='ghcr.io' ;;
    *) log "unknown registry '${registry}'"; return 1 ;;
  esac

  token=$(curl -sS --proto '=https' --max-time 30 \
    -H "Authorization: Bearer ${GHCR_TOKEN:-${GITHUB_TOKEN:-}}" \
    "https://${host}/token?service=${host}&scope=repository:${name}:pull" 2>/dev/null \
    | jq -r '.token // empty' 2>/dev/null)
  if [ -z "$token" ]; then
    log "could not obtain a pull token for ${registry}/${name}"
    return 1
  fi

  # The manifest-list digest is what a `FROM ...@sha256:` pin names, and the
  # registry hands it back in the Docker-Content-Digest header of a HEAD --
  # which also avoids re-hashing the body ourselves and getting it wrong.
  digest=$(curl -sSI --proto '=https' --max-time 30 \
    -H "Authorization: Bearer ${token}" \
    -H 'Accept: application/vnd.oci.image.index.v1+json' \
    -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
    -H 'Accept: application/vnd.docker.distribution.manifest.list.v2+json' \
    -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
    "https://${host}/v2/${name}/manifests/${tag}" 2>/dev/null \
    | tr -d '\r' | awk 'tolower($1) == "docker-content-digest:" { print $2 }')

  if [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    log "${registry}/${name}:${tag}: no usable Docker-Content-Digest (got '${digest:-<nothing>}')"
    return 1
  fi
  echo "$digest"
}

probe_scan() { # <image-ref> <ignorefile>
  if [ -n "${PINNED_BASE_SCAN_CMD:-}" ]; then
    "$PINNED_BASE_SCAN_CMD" "$1" "$2"
    return $?
  fi
  command -v trivy >/dev/null 2>&1 || { log "trivy is not on PATH"; return 1; }

  local report
  report=$(trivy image \
    --severity CRITICAL,HIGH \
    --ignore-unfixed \
    --ignorefile "$2" \
    --format json \
    --exit-code 0 \
    --quiet \
    "$1" 2>/dev/null) || { log "trivy failed to scan $1"; return 1; }

  jq -er '
    [ (.Results // [])[] | (.Vulnerabilities // [])[]
      | [ .Severity, .VulnerabilityID, .PkgName, .InstalledVersion, (.FixedVersion // "") ]
      | @tsv ] | .[]
  ' <<<"$report" 2>/dev/null
  # jq -e exits 4 on an empty result set, which here means "scanned clean".
  local rc=$?
  if [ $rc -ne 0 ] && [ $rc -ne 4 ]; then
    log "could not parse the Trivy report for $1"
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# Discovery: every `FROM <ref>@sha256:<64hex>` in this repository's Dockerfiles.
# ---------------------------------------------------------------------------
if [ ! -d "$ROOT/docker" ]; then
  echo "${YELLOW}INFRA${RST}: no docker/ directory under ${ROOT}" >&2
  exit 2
fi

pins=$(grep -REhn --include='Dockerfile*' \
  '^[[:space:]]*FROM[[:space:]]+[^[:space:]]+@sha256:[0-9a-f]{64}' "$ROOT/docker" 2>/dev/null \
  | sed -E 's/^[0-9]+:[[:space:]]*FROM[[:space:]]+([^[:space:]]+)@(sha256:[0-9a-f]{64}).*/\1 \2/' \
  | sort -u)

if [ -z "$pins" ]; then
  # Not a pass. Either every pin was un-pinned (a real regression in the
  # supply-chain posture this check protects) or the discovery pattern rotted.
  echo "${YELLOW}INFRA${RST}: found no digest-pinned FROM in ${ROOT}/docker."
  echo "  Either the pins were replaced by floating tags -- which is the drift"
  echo "  docker/Dockerfile.scanner-adapter's comment exists to prevent -- or this"
  echo "  script's discovery pattern no longer matches. Both need a human."
  exit 2
fi

echo "Digest-pinned external base images under ${ROOT}/docker:"
echo

while read -r image pinned_digest; do
  [ -n "$image" ] || continue
  checked=$((checked + 1))
  ref="${image}@${pinned_digest}"
  echo "  ${image}"
  echo "    pinned digest : ${pinned_digest}"

  registry="${image%%/*}"
  name="${image#*/}"
  newest_source_tag=''
  newest_registry_tag=''
  newest_digest=''

  if ! source_repo="$(source_repo_for_image "$image")"; then
    note_infra "no upstream mapping for ${image}; cannot answer freshness.
    Add a case to source_repo_for_image() naming the GitHub repository that
    publishes this image."
    echo
    continue
  fi

  # --- freshness -----------------------------------------------------------
  newest_source_tag=$(probe_source_tags "$source_repo" \
    | grep -E '^v' | sort -V | tail -n1)
  if [ -z "$newest_source_tag" ]; then
    note_infra "could not read the tags of ${source_repo}; freshness unknown for ${image}."
    fresh='unknown'
  else
    newest_registry_tag="$(registry_tag_for_source_tag "$newest_source_tag")"
    if ! newest_digest=$(probe_tag_digest "$registry" "$name" "$newest_registry_tag"); then
      note_infra "could not resolve ${image}:${newest_registry_tag} to a digest; freshness unknown."
      fresh='unknown'
    elif [ "$newest_digest" = "$pinned_digest" ]; then
      fresh='yes'
      echo "    newest tag    : ${newest_source_tag} (registry ${newest_registry_tag}) — pinned"
    else
      fresh='no'
      echo "    newest tag    : ${newest_source_tag} (registry ${newest_registry_tag})"
      echo "                    ${newest_digest}"
    fi
  fi

  # --- vulnerability -------------------------------------------------------
  if ! findings=$(probe_scan "$ref" "$ROOT/.trivyignore"); then
    note_infra "could not scan ${ref}; its vulnerability state is unmeasured, which is not the same as clean."
    echo
    continue
  fi

  if [ -n "$findings" ]; then
    count=$(printf '%s\n' "$findings" | grep -c .)
    echo "    ${RED}VULNERABLE${RST}  : ${count} CRITICAL/HIGH fixed finding(s)"
    printf '%s\n' "$findings" | while IFS=$'\t' read -r sev id pkg installed fixed; do
      echo "      - ${sev} ${id} in ${pkg} ${installed} (fixed in ${fixed:-unknown})"
    done
    echo
    echo "    This pin will block the next Docker Publish: the scanner-adapter arm"
    echo "    gates on exactly these flags (--severity CRITICAL,HIGH --ignore-unfixed"
    echo "    --ignorefile .trivyignore). Remedy, in order:"
    echo "      1. open the dependency override PR in ${source_repo};"
    echo "      2. tag it (the next -rN, e.g. after ${newest_source_tag:-the current tag});"
    echo "      3. repoint the digest in docker/Dockerfile.scanner-adapter and bump"
    echo "         docker/scanner-adapter/VERSION here."
    if [ "$fresh" = 'no' ]; then
      echo "    Check step 1 first: ${source_repo} already publishes a newer tag"
      echo "    (${newest_source_tag}, ${newest_digest}). If that one scans clean the"
      echo "    override already exists and only step 3 is needed."
    fi
    echo "    Suppressing in .trivyignore is only correct when NO fixed dependency"
    echo "    exists to build against; every finding above has one."
    problems=$((problems + 1))
  elif [ "$fresh" = 'no' ]; then
    echo "    ${YELLOW}WARNING${RST}     : a newer tag exists, but the pinned digest scans clean."
    echo "    Moving the pin is optional. The sibling rebuilds weekly for errata, and"
    echo "    a clean scan today does not stay clean (v0.73.0-r1 went red six days"
    echo "    after publication without a byte changing, #3307), so freshness is not"
    echo "    a proxy for safety and this does not fail the check."
    warnings=$((warnings + 1))
  elif [ "$fresh" = 'yes' ]; then
    echo "    ${GREEN}OK${RST}          : newest published tag, and it scans clean."
  else
    echo "    scan            : clean (freshness unknown, see the INFRA line above)"
  fi
  echo
done <<< "$pins"

echo "Checked ${checked} digest-pinned base image(s): ${problems} vulnerable, ${warnings} stale-but-clean, ${infra} unmeasurable."

# Exit 1 outranks exit 2, the same way release-preflight.sh ranks them: a
# finding we did measure is not softened into a retry by a later one we could
# not.
if [ "$problems" -gt 0 ]; then
  echo "${RED}FAIL${RST}: ${problems} pinned base image(s) carry a CRITICAL/HIGH fixed finding."
  exit 1
fi
if [ "$infra" -gt 0 ]; then
  echo "${YELLOW}INFRA${RST}: ${infra} pinned base image(s) could not be measured; treat as unknown, not as clean."
  exit 2
fi
echo "${GREEN}OK${RST}: every digest-pinned base image scans clean under the publish gate's configuration."
exit 0
