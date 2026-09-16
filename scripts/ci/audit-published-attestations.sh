#!/usr/bin/env bash
#
# Audit: does every published image digest actually carry the two things the
# publish pipeline claims to attach to it? (issue #3519)
#
#   1. a build-provenance predicate  (actions/attest-build-provenance)
#   2. a cosign signature            (cosign sign --yes, keyless, GitHub OIDC)
#
# WHY THIS EXISTS
# ---------------
# Both attachments were, for most of this project's life, unverified after the
# fact:
#
#   * The four `Generate artifact attestation` steps in docker-publish.yml
#     carried `continue-on-error: true` from the day they were added, so a
#     failed provenance push was indistinguishable from success (#3496, fixed
#     in #3518 -- they hard-fail now). Every digest published before that
#     landed was published through a control that could not report its own
#     failure, so no published image's provenance has ever been PROVEN
#     present.
#   * `cosign sign` has hard-failed since #2824 (the step failed once and
#     1.6.1 shipped unsigned, caught only because a human went looking) and
#     each merge job re-checks its own tags since #3559 -- but nothing has
#     ever gone back over what is already on the registry.
#
# So this is the retrospective half of #3519: a one-off (re-runnable) audit
# that reads the registry and the attestations API and says, per digest,
# whether both are there. The forward-looking half is the hard gate in
# docker-publish.yml's `verify-published` job, which runs this same script on
# every `refs/tags/v*` publish.
#
# IT ASKS WITH THE SAME COMMANDS THE GATE USES
# --------------------------------------------
# An audit that asks a different question than the gate is worth very little:
# it can report healthy digests the gate would refuse, or vice versa. So:
#
#   * the tag -> digest resolution is `.github/scripts/registry-tag-digest.sh`,
#     the probe the candidate and promote flows already trust (it never
#     guesses -- `absent` only for a definitive MANIFEST_UNKNOWN from a
#     repository it has demonstrably been able to read, `indeterminate`
#     otherwise);
#   * provenance is `gh attestation verify oci://<image>@<digest> --owner ...`,
#     the same command `scripts/ci/assert-candidate-certified.sh` uses for the
#     candidate certification;
#   * the signature question is delegated WHOLE to
#     `scripts/ci/check-published-image-signature.sh` (#3559) rather than
#     re-implemented. That script already knows the two things a hand-rolled
#     cosign call gets wrong: under cosign v3 a bare `cosign verify` is
#     satisfied by an `attest-build-provenance` DSSE bundle alone (so an
#     image with provenance and NO signature passes), and a signature over a
#     digest somebody handed you is not a signature over the digest the tag
#     resolves to. Duplicating that logic here would mean two subtly
#     different answers to one question.
#
# WHAT "THE FOUR IMAGES" ARE
# --------------------------
# The four images docker-publish.yml attests: backend, openscap,
# scanner-adapter and backend-alpine. The alpine variant's build and merge
# jobs are gated `if: false` (suspended; UBI is the default backend image), so
# it publishes nothing today -- and its ghcr package may not exist at all,
# which the digest probe reports as `indeterminate` rather than `absent`
# because it proves read access before believing a 404. It is therefore in the
# default set marked `suspended`: neither answer fails the audit, and a
# `::warning`-free skip line says so. A tag that DOES resolve for it gets the
# full check, so re-enabling the alpine jobs needs no edit here -- but drop
# the `=suspended` marker at the same time, so a silent alpine publish
# failure is a finding again rather than a skip.
#
# DOCKER HUB. Each image is also mirrored to docker.io, and those mirrors are
# signed and verified per-publish (#3562). They are deliberately NOT in the
# default set here: `imagetools create` copies a manifest list without
# rewriting it, so a Hub tag resolves to the SAME digest as its ghcr
# counterpart and the provenance verdict transfers unchanged. The cosign
# signature does NOT transfer -- it lives in the repository it was pushed to
# -- so to audit the Hub side as well, pass the mirrors in AK_AUDIT_IMAGES.
#
# THE SCANNER-ADAPTER IS INDEPENDENTLY VERSIONED
# ----------------------------------------------
# It never publishes a tag at the AK release version (see
# merge-scanner-adapter, and `verify-published`, which reads
# docker/scanner-adapter/VERSION for exactly this reason). So a bare `1.9.0`
# argument must not be asked of it. Resolution order for its tag:
#
#   1. AK_AUDIT_ADAPTER_TAG when set (empty string = skip the adapter);
#   2. the argument itself when it is a floating name (latest/dev/main/...);
#   3. `git show v<arg>:docker/scanner-adapter/VERSION` -- the adapter version
#      that release shipped, read from the tag being audited;
#   4. failing that, the argument itself, with a printed note saying so.
#
# EXIT CODES -- "COULD NOT ASK" IS NOT "IS MISSING"
# -------------------------------------------------
#   0  every digest audited carries both a provenance predicate and a cosign
#      signature.
#   1  at least one digest is MISSING one of them, or a non-suspended image
#      has no manifest at the requested tag. This is a finding about the
#      images. Remedy: re-run the merge job for that release from the tag --
#      every step in it is idempotent (#3496) -- then re-run this audit.
#   2  the question could not be asked for at least one digest (registry or
#      attestations-API failure, missing tool, bad arguments). NEVER a pass.
#
# Usage:
#   scripts/ci/audit-published-attestations.sh <tag|latest> [<tag|latest> ...]
#
#   $ scripts/ci/audit-published-attestations.sh latest 1.9.0 1.8.2
#
# Environment:
#   AK_AUDIT_OWNER            `gh attestation verify --owner` (default artifact-keeper).
#                             An explicitly EMPTY value is refused rather than
#                             defaulted: a verify with no trust root proves nothing.
#   AK_AUDIT_PREDICATE_TYPE   predicate the provenance must carry
#                             (default https://slsa.dev/provenance/v1)
#   AK_AUDIT_SIGNER_WORKFLOW  optional `gh attestation verify --signer-workflow`
#                             value, e.g.
#                             artifact-keeper/artifact-keeper/.github/workflows/docker-publish.yml
#                             Unset by default -- see the note in the report on
#                             #3519 about tightening `--owner`.
#   AK_AUDIT_IDENTITY_REGEXP  cosign --certificate-identity-regexp; passed
#                             through to check-published-image-signature.sh.
#                             Defaults to docker-publish.yml on a branch or
#                             tag ref -- the identity the signing step mints.
#   AK_AUDIT_OIDC_ISSUER      cosign --certificate-oidc-issuer
#                             (default https://token.actions.githubusercontent.com)
#   AK_AUDIT_IMAGES           override the image set: space-separated
#                             `<key>=<registry>/<repository>[=suspended]`
#   AK_AUDIT_ADAPTER_TAG      the scanner-adapter's own tag (see above);
#                             set to the empty string to skip the adapter
#   AK_AUDIT_DIGEST_CMD       tag->digest probe
#                             (default .github/scripts/registry-tag-digest.sh)
#   AK_AUDIT_SIG_CMD          signature gate
#                             (default scripts/ci/check-published-image-signature.sh)
#   GH_TOKEN / GHCR_TOKEN     for `gh` and for the registry probe
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

OWNER="${AK_AUDIT_OWNER-artifact-keeper}"
PREDICATE_TYPE="${AK_AUDIT_PREDICATE_TYPE:-https://slsa.dev/provenance/v1}"
SIGNER_WORKFLOW="${AK_AUDIT_SIGNER_WORKFLOW:-}"
IDENTITY_REGEXP="${AK_AUDIT_IDENTITY_REGEXP:-^https://github\.com/artifact-keeper/artifact-keeper/\.github/workflows/docker-publish\.yml@refs/(heads|tags)/.+$}"
OIDC_ISSUER="${AK_AUDIT_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"
DIGEST_CMD="${AK_AUDIT_DIGEST_CMD:-${ROOT}/.github/scripts/registry-tag-digest.sh}"
SIG_CMD="${AK_AUDIT_SIG_CMD:-${ROOT}/scripts/ci/check-published-image-signature.sh}"

# `<key>=<registry>/<repository>` and an optional `=suspended` marker. See the
# header: alpine is in the set but publishes nothing today.
IMAGES="${AK_AUDIT_IMAGES:-\
backend=ghcr.io/artifact-keeper/artifact-keeper-backend \
openscap=ghcr.io/artifact-keeper/artifact-keeper-openscap \
scanner-adapter=ghcr.io/artifact-keeper/artifact-keeper-scanner-adapter \
backend-alpine=ghcr.io/artifact-keeper/artifact-keeper-backend-alpine=suspended}"

RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; RST=$'\033[0m'
[[ -t 1 ]] || { RED=""; GRN=""; YEL=""; RST=""; }

BLOCK_RC=1
INFRA_RC=2

usage() {
  cat <<USAGE
usage: $(basename "$0") <tag|latest> [<tag|latest> ...]

Audits, for every image docker-publish.yml attests, whether the digest each
tag resolves to carries a build-provenance predicate AND a cosign signature.

  exit 0  every digest carries both
  exit 1  at least one is missing
  exit 2  the question could not be asked (infrastructure / bad arguments)
USAGE
}

# Findings accumulate; the script audits everything it was asked about and
# reports once. A gate that stops at the first bad digest hides the rest, and
# the whole point of a one-off audit is the complete picture.
missing=()
infra=()
ok=0
skipped=()

annotate() { # annotate <error|warning> <title> <message>
  if [[ -n "${GITHUB_ACTIONS-}" ]]; then
    printf '::%s title=%s::%s\n' "$1" "$2" "$3"
  else
    printf '%s: %s: %s\n' "$1" "$2" "$3"
  fi
}

# Errors that mean "could not reach", as opposed to "looked and it is not
# there". Same vocabulary as assert-candidate-certified.sh and
# verify-release-assets.sh.
looks_like_infra() {
  grep -qiE 'timeout|timed out|connection refused|dial tcp|i/o timeout|temporarily unavailable|EOF|5[0-9][0-9] |rate limit|no such host|TLS handshake|network is unreachable' <<<"$1"
}

# The gh-specific half of the same distinction, and the reason it is spelled
# out rather than folded into the list above: `gh attestation` did not exist
# before gh 2.49, and an older gh answers `gh attestation verify ...` with
# `unknown command "attestation"` on a NONZERO exit. Treated as a verdict,
# that reports every digest on the runner as having no provenance -- a
# supply-chain finding, on a red release job, caused by a tool version. The
# same goes for an unauthenticated or under-scoped token: "I was not allowed
# to look" is not "there is nothing there".
gh_looks_like_infra() {
  looks_like_infra "$1" && return 0
  grep -qiE 'unknown command|unknown flag|unknown shorthand|gh auth login|not logged in|bad credentials|must be authenticated|HTTP 40[13]|requires authentication' <<<"$1"
}

# ---------------------------------------------------------------------------
# Arguments. A verification tool with nothing to verify passes vacuously, so
# an empty argument list is a configuration failure, not a clean audit.
# ---------------------------------------------------------------------------
case "${1-}" in
  -h|--help) usage; exit 0 ;;
esac

if [[ $# -eq 0 ]]; then
  usage >&2
  annotate error "Attestation audit has no subject" \
    "audit-published-attestations.sh was called with no tags. An audit with nothing to audit reports success while proving nothing; refusing."
  exit "$INFRA_RC"
fi

for arg in "$@"; do
  case "$arg" in
    -*)
      usage >&2
      annotate error "Attestation audit got an unknown option" "'${arg}' is not an option this script takes; arguments are tags."
      exit "$INFRA_RC"
      ;;
    sha256:*|*@*)
      annotate error "Attestation audit input is a digest" \
        "'${arg}' names a digest. This audit starts from TAGS and resolves them itself: auditing a digest somebody handed you proves only that that digest is attested, which is the gap #3519 is about."
      exit "$INFRA_RC"
      ;;
    '')
      annotate error "Attestation audit got an empty tag" "One of the arguments is the empty string."
      exit "$INFRA_RC"
      ;;
    */*|*:*|*' '*)
      annotate error "Attestation audit input is not a tag" \
        "'${arg}' is not a bare tag (e.g. 1.9.0, latest). Pass tags, not image references -- the image set is fixed (see AK_AUDIT_IMAGES)."
      exit "$INFRA_RC"
      ;;
  esac
done

for tool in gh jq git; do
  command -v "$tool" >/dev/null 2>&1 || {
    annotate error "Attestation audit cannot run" "required tool '${tool}' is not on PATH."
    exit "$INFRA_RC"
  }
done

# `gh attestation` arrived in gh 2.49. An older gh is a missing verifier, and
# a missing verifier is an infrastructure failure -- never a pass, and never a
# report that the images are unattested. Asked once, up front, so the answer
# is one clear line instead of one misleading verdict per digest.
if ! gh attestation verify --help >/dev/null 2>&1; then
  annotate error "Attestation audit cannot run" \
    "this gh ($(gh --version 2>/dev/null | head -1)) has no 'attestation verify' command; it was added in gh 2.49. Not finding the verifier is an infrastructure failure, never a pass."
  exit "$INFRA_RC"
fi
[[ -x "$DIGEST_CMD" ]] || { annotate error "Attestation audit cannot run" "digest probe ${DIGEST_CMD} is not executable."; exit "$INFRA_RC"; }
[[ -x "$SIG_CMD"    ]] || { annotate error "Attestation audit cannot run" "signature gate ${SIG_CMD} is not executable."; exit "$INFRA_RC"; }

# The same vacuity guard check-published-image-signature.sh applies to its own
# identity pattern: a regexp that matches every signer verifies nothing.
case "$IDENTITY_REGEXP" in
  ''|'.*'|'.+'|'^.*$'|'^.+$'|'.*$'|'^.*')
    annotate error "Attestation audit identity is vacuous" \
      "AK_AUDIT_IDENTITY_REGEXP='${IDENTITY_REGEXP}' matches any signer. Anyone can sign any public image with Sigstore."
    exit "$INFRA_RC"
    ;;
esac
[[ -n "$OWNER" ]] || { annotate error "Attestation audit owner is empty" "AK_AUDIT_OWNER is empty; gh attestation verify would have no trust root to check against."; exit "$INFRA_RC"; }

# ---------------------------------------------------------------------------
# The scanner-adapter's own tag for a given release tag. See the header.
# ---------------------------------------------------------------------------
adapter_tag_for() {
  local tag="$1" from_git
  if [[ -n "${AK_AUDIT_ADAPTER_TAG+set}" ]]; then
    printf '%s' "$AK_AUDIT_ADAPTER_TAG"
    return 0
  fi
  case "$tag" in
    *[0-9].[0-9]*)
      from_git="$(git -C "$ROOT" show "v${tag#v}:docker/scanner-adapter/VERSION" 2>/dev/null | tr -d '[:space:]')"
      if [[ -n "$from_git" ]]; then
        printf '%s' "$from_git"
      else
        echo "    note: no v${tag#v}:docker/scanner-adapter/VERSION in this checkout; asking the adapter for '${tag}' as given." >&2
        printf '%s' "$tag"
      fi
      ;;
    *) printf '%s' "$tag" ;;   # latest / dev / main / a series-dev alias
  esac
}

# ---------------------------------------------------------------------------
# Does this digest carry a build-provenance predicate?
# Echoes `yes`, `no` or `infra`; the explanation goes to stderr.
# ---------------------------------------------------------------------------
provenance_state() {
  local image="$1" digest="$2"
  local subject="oci://${image}@${digest}"
  local args=(attestation verify "$subject" --owner "$OWNER" --predicate-type "$PREDICATE_TYPE" --format json)
  [[ -n "$SIGNER_WORKFLOW" ]] && args+=(--signer-workflow "$SIGNER_WORKFLOW")

  local out rc=0
  out="$(gh "${args[@]}" 2>&1)" || rc=$?
  if [[ "$rc" -ne 0 ]]; then
    printf '%s\n' "$out" | sed 's/^/      /' >&2
    if gh_looks_like_infra "$out"; then echo infra; else echo no; fi
    return 0
  fi

  # Found by SHAPE, not by position in gh's JSON envelope, so a change to that
  # envelope does not silently turn every predicate into "missing" (the same
  # reason assert-candidate-certified.sh reads it this way).
  local statements
  statements="$(jq -c --arg t "$PREDICATE_TYPE" \
    '[.. | objects | select(has("predicateType")) | select(.predicateType == $t)]' <<<"$out" 2>/dev/null || true)"
  if [[ -z "$statements" || "$(jq 'length' <<<"$statements" 2>/dev/null || echo 0)" -lt 1 ]]; then
    # gh exited 0 but its output carries no statement we can read the
    # predicate type out of. That is a tooling change, not a verdict.
    echo infra
    return 0
  fi
  echo yes
}

# ---------------------------------------------------------------------------
# Does the digest this tag resolves to carry a cosign signature?
# Delegated whole to the #3559 gate; its exit codes are already 0/BLOCK/INFRA.
# ---------------------------------------------------------------------------
signature_state() {
  local ref="$1" rc=0
  PUBLISHED_SIG_IDENTITY_REGEXP="$IDENTITY_REGEXP" \
  PUBLISHED_SIG_OIDC_ISSUER="$OIDC_ISSUER" \
    "$SIG_CMD" "$ref" 1>&2 || rc=$?
  case "$rc" in
    0) echo yes ;;
    1) echo no ;;
    *) echo infra ;;
  esac
}

echo "== published-attestation audit (#3519) =="
echo "owner:     ${OWNER}"
echo "predicate: ${PREDICATE_TYPE}"
echo "identity:  ${IDENTITY_REGEXP}"
echo "issuer:    ${OIDC_ISSUER}"
[[ -n "$SIGNER_WORKFLOW" ]] && echo "signer:    ${SIGNER_WORKFLOW}"
echo "tags:      $*"
echo

for tag in "$@"; do
  echo "--- ${tag} ---"
  for entry in $IMAGES; do
    key="${entry%%=*}"
    rest="${entry#*=}"
    ref="${rest%%=*}"
    marker="${rest#*=}"
    [[ "$marker" == "$ref" ]] && marker=""

    image_tag="$tag"
    if [[ "$key" == "scanner-adapter" ]]; then
      image_tag="$(adapter_tag_for "$tag")"
      if [[ -z "$image_tag" ]]; then
        echo "  ${key}: skipped (AK_AUDIT_ADAPTER_TAG is empty -- the adapter publishes no tag for this release)"
        skipped+=("${ref} @ ${tag}")
        continue
      fi
    fi

    registry="${ref%%/*}"
    repository="${ref#*/}"
    answer="$("$DIGEST_CMD" "$registry" "$repository" "$image_tag" 2>/dev/null)" || true

    # A `suspended` image publishes nothing today, so NEITHER answer below is
    # a finding about it: `absent` is the expected state, and `indeterminate`
    # is what the probe reports for a repository that does not exist at all
    # (it proves read access before believing a 404, and an absent package
    # cannot be read). Failing on either would redden every release cut over
    # an image this workflow deliberately does not build.
    if [[ "$marker" == "suspended" && ( "$answer" == absent || "$answer" == indeterminate ) ]]; then
      echo "  ${key}: ${ref}:${image_tag} ${answer} -- image suspended in docker-publish.yml (if: false), skipping"
      echo "      (drop the '=suspended' marker from AK_AUDIT_IMAGES when those jobs are re-enabled)"
      skipped+=("${ref}:${image_tag}")
      continue
    fi

    case "$answer" in
      sha256:*) : ;;
      absent)
        annotate error "Published tag is missing" \
          "${ref}:${image_tag} does not resolve. Nothing to audit, and nothing for a user to pull."
        missing+=("${ref}:${image_tag} (no manifest)")
        continue
        ;;
      *)
        annotate error "Attestation audit could not resolve a tag" \
          "the registry probe answered '${answer:-<nothing>}' for ${ref}:${image_tag}. This is a registry/network failure, NOT a statement about the image."
        infra+=("${ref}:${image_tag} (unresolved)")
        continue
        ;;
    esac

    digest="$answer"
    prov="$(provenance_state "$ref" "$digest")"
    sig="$(signature_state "${ref}:${image_tag}")"

    colour="$GRN"
    [[ "$prov" == yes && "$sig" == yes ]] || colour="$RED"
    [[ "$prov" == infra || "$sig" == infra ]] && colour="$YEL"
    printf '  %s%-16s%s %s@%s\n' "$colour" "$key" "$RST" "$ref" "$digest"
    printf '      provenance=%s  signature=%s\n' "$prov" "$sig"

    if [[ "$prov" == infra || "$sig" == infra ]]; then
      infra+=("${ref}@${digest} (provenance=${prov} signature=${sig})")
    elif [[ "$prov" != yes || "$sig" != yes ]]; then
      missing+=("${ref}@${digest} [${image_tag}] (provenance=${prov} signature=${sig})")
    else
      ok=$((ok + 1))
    fi
  done
  echo
done

echo "== result =="
echo "  complete (provenance + signature): ${ok}"
echo "  missing:                           ${#missing[@]}"
echo "  could not measure:                 ${#infra[@]}"
echo "  skipped:                           ${#skipped[@]}"
for s in "${skipped[@]-}"; do [[ -n "$s" ]] && echo "    - skipped ${s}"; done

if [[ "${#missing[@]}" -gt 0 ]]; then
  echo ""
  echo "${RED}MISSING${RST}: ${#missing[@]} published digest(s) do not carry both attachments:"
  for m in "${missing[@]}"; do echo "  - ${m}"; done
  echo ""
  echo "Re-attest from the tag: every step in the merge jobs is idempotent"
  echo "(imagetools re-points the SAME digest; cosign sign and"
  echo "attest-build-provenance are both safe to repeat), so re-running the"
  echo "merge job for that release fixes it and this audit turns green."
  annotate error "Published digests are missing provenance or a signature" \
    "${#missing[@]} digest(s) audited by audit-published-attestations.sh carry no build provenance and/or no cosign signature."
  exit "$BLOCK_RC"
fi

if [[ "${#infra[@]}" -gt 0 ]]; then
  echo ""
  echo "${YEL}INFRASTRUCTURE${RST}: could not audit ${#infra[@]} digest(s):"
  for i in "${infra[@]}"; do echo "  - ${i}"; done
  echo ""
  echo "This is NOT a statement that those digests are unattested -- the"
  echo "question could not be asked. Re-run once the registry and the GitHub"
  echo "attestations API are reachable."
  exit "$INFRA_RC"
fi

echo ""
echo "${GRN}OK${RST}: every audited digest carries a ${PREDICATE_TYPE} predicate and a cosign signature."
