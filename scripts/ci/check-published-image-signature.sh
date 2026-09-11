#!/usr/bin/env bash
#
# Tag-anchored cosign signature gate for published container images (#3559).
#
# THE INVARIANT
# -------------
#   THE BYTES A USER PULLS BY TAG ARE THE BYTES THAT WERE SIGNED.
#
# Everything below exists to make that statement falsifiable in CI. The gate
# starts from the published TAG, resolves it to a digest the way a `docker
# pull` would, and then demands a cosign signature over THAT digest. It never
# takes a digest from the job that did the signing: a control anchored to an
# intermediate value can only ever prove that the intermediate value was
# signed, which is precisely the failure mode being guarded against.
#
# WHY A SIGNING STEP IS NOT A GATE
# --------------------------------
# `docker-publish.yml` runs `cosign sign --yes ...@<digest>` as a hard-failing
# step, and it has done since #2824 (1.6.1 shipped unsigned because that step
# failed and nobody noticed) and #3496 (no supply-chain step in this workflow
# may soft-fail). Both changes make a FAILING signer loud. Neither of them
# proves the signature reached the thing that ships:
#
#   * `cosign sign` prints "Generating ephemeral keys... / Signing artifact..."
#     and nothing else on the happy path -- no "pushed to" line, no digest.
#     A reader of a green log cannot tell a pushed signature from a no-op.
#   * The signature is attached to whatever digest the workflow computed. If a
#     later step, a promotion, or a re-`imagetools create` moved the tag, the
#     step is still green and the shipped image is still unverifiable.
#   * ghcr.io does NOT implement the OCI referrers API
#     (`/v2/<name>/referrers/<digest>` answers 404 MANIFEST_UNKNOWN), and
#     cosign v3 no longer writes the legacy `sha256-<digest>.sig` tag by
#     default -- it writes an OCI 1.1 referrer under the fallback tag
#     `sha256-<digest>`. Hand-rolled registry probes therefore report "no
#     signature" for images that are perfectly well signed. Ask cosign, not
#     the tag namespace.
#
# So the only honest question is the one this script asks, in this order:
# resolve the tag -> verify a signature over the resolved digest -> confirm
# the signature cosign accepted is actually a `cosign sign` signature.
#
# THAT LAST STEP MATTERS. Under cosign v3 a bare `cosign verify` also accepts
# the `actions/attest-build-provenance` DSSE bundle, whose predicate type is
# `https://slsa.dev/provenance/v1`. An image with provenance and NO cosign
# signature passes a naive `cosign verify`. This gate requires at least one
# accepted signature whose payload type is `https://sigstore.dev/cosign/sign/v1`
# and whose subject digest equals the digest the tag resolved to.
#
# IDENTITY IS PART OF THE ASSERTION
# ---------------------------------
# `cosign verify` with an identity pattern that matches everything verifies
# nothing: any Sigstore user on earth can sign any public image, and an
# unpinned verify accepts their signature as readily as ours. The identity
# regexp and the OIDC issuer are therefore mandatory, and a regexp that
# matches any identity is refused as a configuration error (exit 2) rather
# than being allowed to pass vacuously.
#
# EXIT CODES -- INFRASTRUCTURE IS NOT TAMPERING
# ---------------------------------------------
#   0  every ref verified.
#   1  BLOCK. A published tag is unsigned, is signed by an identity we do not
#      accept, is signed only by an attestation rather than by cosign, or the
#      signature covers a different digest than the tag resolves to. This is a
#      supply-chain finding about the image.
#   2  INFRA / CONFIG. The question could not be asked: registry 5xx, DNS,
#      Rekor/Fulcio outage, missing cosign binary, no refs, vacuous identity
#      pattern. Both exits fail the build -- nothing here is soft (#3496) --
#      but a Sigstore outage must not read in the log as a tampered image, and
#      an operator triaging a red publish needs to know which one they have.
#
# Usage:
#   check-published-image-signature.sh <registry>/<image>:<tag> [more refs...]
#
# Environment:
#   PUBLISHED_SIG_IDENTITY_REGEXP  cosign --certificate-identity-regexp.
#                                  Defaults to this repo's docker-publish
#                                  workflow on a branch or tag ref.
#   PUBLISHED_SIG_OIDC_ISSUER      cosign --certificate-oidc-issuer.
#                                  Defaults to GitHub Actions' OIDC issuer.
#   PUBLISHED_SIG_ATTEMPTS         attempts per infra-class failure (default 3).
#   PUBLISHED_SIG_BASIC_AUTH       optional "user:password" used ONLY to obtain
#                                  a read token when resolving a tag on a
#                                  private registry. Never logged, and never
#                                  sent to a registry other than
#                                  PUBLISHED_SIG_BASIC_AUTH_HOST.
#   PUBLISHED_SIG_BASIC_AUTH_HOST  the ONE registry host the credential above
#                                  belongs to (default ghcr.io). Refs on any
#                                  other host resolve anonymously.
#   COSIGN                         cosign binary (default: cosign).
#
set -uo pipefail

COSIGN_BIN="${COSIGN:-cosign}"
ATTEMPTS="${PUBLISHED_SIG_ATTEMPTS:-3}"
OIDC_ISSUER="${PUBLISHED_SIG_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"
IDENTITY_REGEXP="${PUBLISHED_SIG_IDENTITY_REGEXP:-^https://github\.com/artifact-keeper/artifact-keeper/\.github/workflows/docker-publish\.yml@refs/(heads|tags)/.+$}"
# The single registry host PUBLISHED_SIG_BASIC_AUTH is valid for. A registry
# credential is scoped to the registry that issued it; the token endpoint it
# gets presented to is chosen by a WWW-Authenticate header the REGISTRY sends,
# so an unscoped credential is a credential the far end can redirect to itself.
# ghcr's realm is on ghcr.io, but Docker Hub's is auth.docker.io -- a different
# origin entirely -- so without this scope, adding one docker.io ref to an
# invocation carrying ghcr credentials would hand a GITHUB_TOKEN to Docker's
# auth server. Refs on any other host resolve anonymously, which is all a
# public mirror needs.
BASIC_AUTH_HOST="${PUBLISHED_SIG_BASIC_AUTH_HOST:-ghcr.io}"

# The payload type cosign itself stamps on a `cosign sign` signature. An
# attestation bundle carries its predicate type here instead, which is how the
# two are told apart.
COSIGN_SIGN_TYPE='https://sigstore.dev/cosign/sign/v1'

RED=1
INFRA=2

err()   { printf '%s\n' "$*" >&2; }
note()  { printf '%s\n' "$*"; }

# GitHub Actions annotations when running in CI; plain text otherwise.
annotate() { # annotate <error|warning> <title> <message>
  if [ -n "${GITHUB_ACTIONS-}" ]; then
    printf '::%s title=%s::%s\n' "$1" "$2" "$3"
  else
    printf '%s: %s: %s\n' "$1" "$2" "$3"
  fi
}

# ---------------------------------------------------------------------------
# Configuration guards. A gate that cannot fail is not a gate (#3496 invariant
# 3, applied to this script's own inputs).
# ---------------------------------------------------------------------------
if [ "$#" -eq 0 ]; then
  annotate error "Signature gate has no subject" \
    "check-published-image-signature.sh was called with no image references. A verification step with nothing to verify passes vacuously; refusing."
  exit "$INFRA"
fi

case "$IDENTITY_REGEXP" in
  ''|'.*'|'.+'|'^.*$'|'^.+$'|'.*$'|'^.*')
    annotate error "Signature gate identity is vacuous" \
      "PUBLISHED_SIG_IDENTITY_REGEXP='${IDENTITY_REGEXP}' matches any signer. Anyone can sign any public image with Sigstore, so an unpinned verify proves nothing. Pin it to the workflow that is allowed to sign."
    exit "$INFRA"
    ;;
esac

if [ -z "$OIDC_ISSUER" ]; then
  annotate error "Signature gate issuer is empty" \
    "PUBLISHED_SIG_OIDC_ISSUER is empty. Without an issuer the identity regexp can be satisfied by a certificate from any OIDC provider."
  exit "$INFRA"
fi

for tool in curl jq; do
  command -v "$tool" >/dev/null 2>&1 || {
    annotate error "Signature gate cannot run" "required tool '${tool}' is not on PATH."
    exit "$INFRA"
  }
done

if ! command -v "$COSIGN_BIN" >/dev/null 2>&1 && [ ! -x "$COSIGN_BIN" ]; then
  annotate error "Signature gate cannot run" \
    "cosign ('${COSIGN_BIN}') is not available. Not finding the verifier is an infrastructure failure, never a pass."
  exit "$INFRA"
fi

# ---------------------------------------------------------------------------
# Resolve <registry>/<image>:<tag> to the digest a `docker pull` of that tag
# would fetch, using the registry API directly.
#
# Doing this over HTTP rather than through a client gives the one thing this
# gate needs and a client hides: the status code. A 404 means the tag is not
# there (a publish problem -- BLOCK); a 5xx or a transport error means we could
# not ask (INFRA). Auth follows the standard WWW-Authenticate token dance, so
# the same code path works for ghcr.io, docker.io and anything else conformant.
#
# Prints "<http-status> <digest>"; digest empty when unresolved.
# ---------------------------------------------------------------------------
resolve_digest() {
  local ref="$1"
  local host path name tag realm service scope token hdrs status digest

  host="${ref%%/*}"
  path="${ref#*/}"
  name="${path%:*}"
  tag="${path##*:}"

  local accept='Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'
  local url="https://${host}/v2/${name}/manifests/${tag}"

  # Docker Hub's registry lives on registry-1.docker.io; docker.io is the
  # canonical name in a pull reference but not an endpoint.
  if [ "$host" = "docker.io" ] || [ "$host" = "index.docker.io" ]; then
    url="https://registry-1.docker.io/v2/${name}/manifests/${tag}"
  fi

  hdrs="$(curl -sSI --max-time 30 -H "$accept" "$url" 2>/dev/null)" || { echo "000 "; return; }
  status="$(printf '%s' "$hdrs" | tr -d '\r' | awk 'toupper($1) ~ /^HTTP/ {print $2}' | tail -1)"

  if [ "$status" = "401" ]; then
    # Parse realm/service/scope out of the challenge and fetch a read token.
    local chal
    chal="$(printf '%s' "$hdrs" | tr -d '\r' | grep -i '^www-authenticate:' | head -1)"
    realm="$(printf '%s' "$chal" | sed -n 's/.*realm="\([^"]*\)".*/\1/p')"
    service="$(printf '%s' "$chal" | sed -n 's/.*service="\([^"]*\)".*/\1/p')"
    scope="$(printf '%s' "$chal" | sed -n 's/.*scope="\([^"]*\)".*/\1/p')"
    [ -n "$scope" ] || scope="repository:${name}:pull"
    if [ -n "$realm" ]; then
      local token_url="${realm}?scope=${scope}"
      [ -n "$service" ] && token_url="${token_url}&service=${service}"
      if [ -n "${PUBLISHED_SIG_BASIC_AUTH-}" ] && [ "$host" = "$BASIC_AUTH_HOST" ]; then
        token="$(curl -sSL --max-time 30 -u "${PUBLISHED_SIG_BASIC_AUTH}" "$token_url" 2>/dev/null | jq -r '.token // .access_token // empty')"
      else
        token="$(curl -sSL --max-time 30 "$token_url" 2>/dev/null | jq -r '.token // .access_token // empty')"
      fi
    fi
    if [ -n "${token-}" ]; then
      hdrs="$(curl -sSI --max-time 30 -H "Authorization: Bearer ${token}" -H "$accept" "$url" 2>/dev/null)" || { echo "000 "; return; }
      status="$(printf '%s' "$hdrs" | tr -d '\r' | awk 'toupper($1) ~ /^HTTP/ {print $2}' | tail -1)"
    fi
  fi

  digest="$(printf '%s' "$hdrs" | tr -d '\r' | grep -i '^docker-content-digest:' | tail -1 | awk '{print $2}')"
  echo "${status:-000} ${digest}"
}

# ---------------------------------------------------------------------------
# Classify a cosign failure. cosign exits 1 for "this image is not signed" AND
# for "I could not reach Rekor", so the distinction has to come from what it
# said. Only the phrases below -- cosign's own verification-failure wording --
# are treated as a finding about the image. Everything else is infrastructure,
# which keeps a Fulcio/Rekor/registry outage from being reported as tampering.
# ---------------------------------------------------------------------------
is_verification_failure() {
  case "$1" in
    *"no signatures found"*|\
    *"no matching signatures"*|\
    *"none of the expected identities matched"*|\
    *"no matching attestations"*|\
    *"certificate identity"*|\
    *"invalid signature when validating"*|\
    *"MANIFEST_UNKNOWN"*) return 0 ;;
  esac
  return 1
}

# ---------------------------------------------------------------------------
# Verify one ref. Echoes findings; returns 0 / RED / INFRA.
# ---------------------------------------------------------------------------
verify_ref() {
  local ref="$1"

  case "$ref" in
    *@*)
      annotate error "Signature gate input is a digest reference" \
        "'${ref}' pins a digest. This gate must start from a tag: verifying a digest somebody handed you proves only that that digest was signed, which is the defect it exists to catch."
      return "$INFRA"
      ;;
  esac
  case "$ref" in
    */*:*) : ;;
    *)
      annotate error "Signature gate input is not a tag reference" \
        "'${ref}' is not <registry>/<image>:<tag>. This gate must start from a tag, because the tag is what a user pulls."
      return "$INFRA"
      ;;
  esac
  case "${ref##*/}" in
    *:*) : ;;
    *)
      annotate error "Signature gate input has no tag" \
        "'${ref}' names no tag. Verifying a digest you were handed proves only that that digest was signed."
      return "$INFRA"
      ;;
  esac

  local image="${ref%:*}"
  local status digest attempt=1 out rc

  # --- resolve the tag ----------------------------------------------------
  while :; do
    read -r status digest <<<"$(resolve_digest "$ref")"
    case "$status" in
      200) break ;;
      404)
        annotate error "Published tag is missing" \
          "${ref} does not resolve on the registry. The publish did not produce the tag it promised."
        return "$RED"
        ;;
    esac
    if [ "$attempt" -ge "$ATTEMPTS" ]; then
      annotate error "Cannot resolve published tag (infrastructure)" \
        "${ref} did not resolve after ${ATTEMPTS} attempt(s); last HTTP status '${status}'. This is a registry/network failure, NOT a statement about the image."
      return "$INFRA"
    fi
    err "  resolve attempt ${attempt}/${ATTEMPTS} for ${ref} returned '${status}'; retrying"
    attempt=$((attempt + 1))
    sleep $((attempt * 3))
  done

  if [ -z "$digest" ]; then
    annotate error "Cannot resolve published tag (infrastructure)" \
      "${ref} answered HTTP 200 with no Docker-Content-Digest header."
    return "$INFRA"
  fi

  note "  ${ref}"
  note "    tag resolves to ${digest}"

  # --- verify a signature over THAT digest --------------------------------
  attempt=1
  while :; do
    out="$("$COSIGN_BIN" verify \
            --certificate-identity-regexp "$IDENTITY_REGEXP" \
            --certificate-oidc-issuer "$OIDC_ISSUER" \
            "${image}@${digest}" 2>&1)"
    rc=$?
    [ "$rc" -eq 0 ] && break
    if is_verification_failure "$out"; then
      annotate error "Published image is not verifiably signed" \
        "${ref} resolves to ${digest}, and cosign found no acceptable signature for it. Identity must match ${IDENTITY_REGEXP} issued by ${OIDC_ISSUER}."
      err "$out"
      return "$RED"
    fi
    if [ "$attempt" -ge "$ATTEMPTS" ]; then
      annotate error "Signature verification failed (infrastructure)" \
        "cosign could not complete verification of ${ref} after ${ATTEMPTS} attempt(s). This is a Sigstore/registry failure, NOT a finding about the image."
      err "$out"
      return "$INFRA"
    fi
    err "  cosign attempt ${attempt}/${ATTEMPTS} for ${ref} hit a transient error; retrying"
    attempt=$((attempt + 1))
    sleep $((attempt * 3))
  done

  # cosign prints a human preamble on stderr and the accepted payloads as JSON
  # on stdout; both are captured together above, so take the JSON array.
  local json
  json="$(printf '%s\n' "$out" | sed -n '/^\[/,$p')"
  if [ -z "$json" ] || ! printf '%s' "$json" | jq -e . >/dev/null 2>&1; then
    annotate error "Signature verification produced no parsable result (infrastructure)" \
      "cosign exited 0 for ${ref} but emitted no JSON payload array to inspect."
    err "$out"
    return "$INFRA"
  fi

  # A `cosign sign` signature, over the digest the TAG resolves to. Both halves
  # are load-bearing: without the type test an attestation-only image passes,
  # and without the digest test a signature over some other manifest passes.
  local matched
  matched="$(printf '%s' "$json" | jq --arg t "$COSIGN_SIGN_TYPE" --arg d "$digest" \
    '[.[] | select(.critical.type == $t and .critical.image."docker-manifest-digest" == $d)] | length')"

  if [ "${matched:-0}" -lt 1 ]; then
    local types
    types="$(printf '%s' "$json" | jq -r '[.[].critical.type] | join(", ")')"
    annotate error "Published image has no cosign signature" \
      "${ref} resolves to ${digest}. cosign accepted material of type(s) [${types}], but none is a '${COSIGN_SIGN_TYPE}' signature over that digest. Build provenance is not a signature: under cosign v3 an attestation bundle alone satisfies a bare 'cosign verify'."
    err "$json"
    return "$RED"
  fi

  note "    signed: ${matched} cosign signature(s) over ${digest}"
  return 0
}

# ---------------------------------------------------------------------------
note "Verifying that every published tag resolves to signed bytes."
note "  identity: ${IDENTITY_REGEXP}"
note "  issuer:   ${OIDC_ISSUER}"

blocked=()
infra=()
ok=0

for ref in "$@"; do
  verify_ref "$ref"
  case $? in
    0) ok=$((ok + 1)) ;;
    "$RED") blocked+=("$ref") ;;
    *) infra+=("$ref") ;;
  esac
done

if [ "${#blocked[@]}" -gt 0 ]; then
  err ""
  err "BLOCKED: ${#blocked[@]} published tag(s) do not resolve to signed bytes:"
  for r in "${blocked[@]}"; do err "  - ${r}"; done
  err ""
  err "The invariant this gate exists for -- the bytes a user pulls by tag are"
  err "the bytes that were signed -- does not hold for those tags. Do not treat"
  err "this as flaky; every step in the merge jobs is idempotent, so if the"
  err "signer merely failed, re-running the job fixes it and this turns green."
  exit "$RED"
fi

if [ "${#infra[@]}" -gt 0 ]; then
  err ""
  err "INFRASTRUCTURE FAILURE: could not verify ${#infra[@]} published tag(s):"
  for r in "${infra[@]}"; do err "  - ${r}"; done
  err ""
  err "This is NOT a statement that the images are unsigned or tampered with --"
  err "the question could not be asked. Re-run this job once the registry and"
  err "Sigstore (Fulcio/Rekor) are reachable."
  exit "$INFRA"
fi

note ""
note "OK: ${ok} published tag(s) resolve to bytes signed by ${IDENTITY_REGEXP}."
