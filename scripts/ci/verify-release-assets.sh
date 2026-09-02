#!/usr/bin/env bash
#
# Release gate: refuse to PUBLISH a GitHub Release whose assets have not been
# proven signed, attested and self-consistent (issue #3558).
#
# WHY THIS EXISTS
# ---------------
# The container images have been covered for a long time -- cosign keyless
# signatures, an SBOM attestation, `provenance: mode=max`,
# `actions/attest-build-provenance`, all hard-failing since #3496. The release
# BINARIES had none of it. Each one shipped with a `<name>.sha256` file next to
# it, and that file is served from the same place, by the same authority, as the
# artifact it describes: whoever can replace `artifact-keeper-linux-amd64.tar.gz`
# on a release can replace `artifact-keeper-linux-amd64.tar.gz.sha256` in the
# same action. It is a corruption check that is routinely read as an
# authenticity check.
#
# So `checksums.txt` is now signed with cosign keyless, and the assets carry a
# build-provenance attestation. This script is the part that makes those worth
# anything: it VERIFIES them, in the release job, BEFORE `Create Release`.
#
# WHY *BEFORE* PUBLISHING, SPECIFICALLY
#   `.github/scripts/assert-release-absent.sh` refuses to run against a tag that
#   already has a release, and `softprops/action-gh-release` is configured with
#   `overwrite_files: false`. Those two together mean a PARTIAL publish is not
#   recoverable by re-running: the second attempt is refused. A release that
#   published first and discovered a bad signature second would have burned an
#   immutable tag (`refs/tags/v*` is covered by ruleset 19144026). Failing here
#   costs a re-run of a job that has produced nothing yet.
#
# WHAT IT REFUSES, AND WHY EACH CLAUSE IS LOAD-BEARING
#   1. AN UNPINNED IDENTITY. `cosign verify-blob` requires SOME identity
#      constraint, but `--certificate-identity-regexp '.*'` satisfies the flag
#      and verifies nothing: any Fulcio certificate from any GitHub workflow in
#      the world matches. Sigstore is a public CA. So this script inspects the
#      regexp it was given and refuses a permissive one BEFORE it verifies
#      anything. This is the check most likely to be quietly weakened later,
#      when someone hits an identity mismatch at 2am and "just makes it match".
#   2. ASSET PRESENCE, per expected target. A signature over a checksums file
#      that lists four binaries is a perfectly valid signature over an
#      incomplete release.
#   3. CHECKSUM COVERAGE. `sha256sum -c` on a file that lists nothing passes.
#      Every shipped asset must appear in `checksums.txt`, so the signature
#      covers the whole asset set rather than an arbitrary subset of it.
#   4. CHECKSUMS vs ACTUAL BYTES. The signature covers `checksums.txt`; only
#      `sha256sum -c` connects `checksums.txt` to the artifacts. Verifying the
#      signature without that is verifying a manifest of nothing in particular.
#   5. BUILD PROVENANCE, on the archives, pinned to THIS workflow. `cosign` and
#      `actions/attest-build-provenance` fail independently (different
#      services, different failure modes), and consumers reach for one or the
#      other, so both are proven here rather than one standing in for both.
#
# INFRA (exit 2) vs BLOCKED (exit 1)
#   Sigstore, Rekor, Fulcio and the GitHub attestations API are network
#   services. An outage there and a tampered artifact must not read alike: one
#   says "retry", the other says "something replaced your bytes". `cosign` and
#   `gh` both exit 1 for either, so failures are classified by their stderr
#   against a list of transport-shaped markers, and ANYTHING UNRECOGNISED IS
#   TREATED AS A BLOCK. The heuristic can only ever be wrong in the direction of
#   calling an outage tampering, which costs a re-run.
#
#   Both exit codes fail the step and stop the release. The distinction is for
#   the human reading the log, and it is the same distinction
#   release-preflight.sh and assert-preflight-evidence.sh already draw.
#
# Env:
#   ASSETS_DIR              (required) directory holding the release assets
#   EXPECT_NAMES            (required) whitespace-separated artifact base names,
#                           e.g. "artifact-keeper-linux-amd64 ...". Empty is
#                           refused: a gate with nothing to check is not a pass.
#   EXPECT_IDENTITY_REGEXP  (required) pinned Fulcio SAN regexp
#   EXPECT_OIDC_ISSUER      default https://token.actions.githubusercontent.com
#   ATTEST_REPO             (required) owner/name for `gh attestation verify`
#   ATTEST_SIGNER_WORKFLOW  (required) [host/]<owner>/<repo>/<path to workflow>
#                           passed to `gh attestation verify --signer-workflow`,
#                           so provenance is pinned to the workflow that is
#                           allowed to attest a release -- not merely to the
#                           repository, which several other workflows here also
#                           attest from. Empty is refused.
#   CHECKSUMS_FILE          default $ASSETS_DIR/checksums.txt
#   BUNDLE_FILE             default $CHECKSUMS_FILE.cosign.bundle
#   GITHUB_STEP_SUMMARY     appended to when set
#
# Exit codes:
#   0  every asset present, checksums match the bytes, signature verifies
#      against the pinned identity, provenance verifies
#   1  BLOCKED -- do not publish
#   2  INFRA   -- could not measure. NOT a pass; retry.
#
set -uo pipefail

RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; RST=$'\033[0m'
[[ -t 1 ]] || { RED=""; GRN=""; YEL=""; RST=""; }

ASSETS_DIR="${ASSETS_DIR:-}"
EXPECT_NAMES="${EXPECT_NAMES:-}"
EXPECT_IDENTITY_REGEXP="${EXPECT_IDENTITY_REGEXP:-}"
EXPECT_OIDC_ISSUER="${EXPECT_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"
ATTEST_REPO="${ATTEST_REPO:-}"
ATTEST_SIGNER_WORKFLOW="${ATTEST_SIGNER_WORKFLOW:-}"

declare -a detail=()
say()  { detail+=("$1"); printf '  %s\n' "$1"; }
head2() { printf '\n%s\n' "$1"; }

summarise() {
  local status="$1" line="$2"
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
      echo "### Release asset verification: ${status}"
      echo
      echo "| | |"
      echo "|---|---|"
      echo "| assets | \`${ASSETS_DIR}\` |"
      echo "| expected targets | ${EXPECT_NAMES:-<none>} |"
      echo "| pinned identity | \`${EXPECT_IDENTITY_REGEXP:-<none>}\` |"
      echo "| provenance signer | \`${ATTEST_SIGNER_WORKFLOW:-<none>}\` |"
      echo "| oidc issuer | \`${EXPECT_OIDC_ISSUER}\` |"
      echo "| verdict | ${line} |"
      echo
      # `"${arr[@]}"` on an EMPTY array is an unbound-variable error under
      # `set -u` in bash before 4.4 -- and /bin/bash on the macOS runners this
      # repository builds on is 3.2. `${arr[@]+...}` is the portable guard.
      # `detail` is empty on exactly the early-failure paths that matter, so
      # without this the summary write would itself fail there.
      for d in ${detail[@]+"${detail[@]}"}; do echo "- ${d}"; done
    } >> "$GITHUB_STEP_SUMMARY"
  fi
}

block() {
  local line="$1"
  echo
  printf '%sBLOCKED%s: %s\n' "$RED" "$RST" "$line"
  echo "::error title=Release assets failed verification::${line} The GitHub Release was NOT created. See the job log."
  summarise "BLOCKED" "$line"
  exit 1
}

infra() {
  local line="$1"
  echo
  printf '%sINFRA%s: %s\n' "$YEL" "$RST" "$line"
  echo "::error title=Release asset verification could not be measured::${line} This is not a pass and not evidence of tampering -- retry the job."
  summarise "INFRA" "$line"
  exit 2
}

# Transport-shaped failures. Everything not matching is a BLOCK, deliberately:
# the safe direction for an unrecognised error is "assume the bytes are wrong".
NETWORK_MARKERS='connection refused|connection reset|no such host|i/o timeout|context deadline exceeded|TLS handshake|EOF$|dial tcp|502 Bad Gateway|503 Service Unavailable|504 Gateway|too many requests|rate limit|temporary failure in name resolution|server misbehaving|network is unreachable'

looks_like_infra() {
  printf '%s' "$1" | grep -Eqi "$NETWORK_MARKERS"
}

echo "== release asset verification gate (#3558) =="
echo "assets dir: ${ASSETS_DIR}"
echo "identity:   ${EXPECT_IDENTITY_REGEXP}"
echo "issuer:     ${EXPECT_OIDC_ISSUER}"
echo "repo:       ${ATTEST_REPO}"

# ---------------------------------------------------------------------------
# 0. the gate's own preconditions -- non-vacuity
# ---------------------------------------------------------------------------
head2 "0. gate preconditions"

[[ -n "$ASSETS_DIR" ]] || infra "ASSETS_DIR is not set."
[[ -d "$ASSETS_DIR" ]] || infra "ASSETS_DIR does not exist: ${ASSETS_DIR}"
[[ -n "$ATTEST_REPO" ]] || infra "ATTEST_REPO is not set."

# `gh attestation verify --repo X` accepts an attestation produced by ANY
# workflow in X that holds `attestations: write`. This repository has several,
# so "the provenance came from artifact-keeper/artifact-keeper" is a weaker
# statement than it reads as. Pin the workflow, the same way the cosign
# certificate identity is pinned below, and refuse to run unpinned.
if [[ -z "$ATTEST_SIGNER_WORKFLOW" ]]; then
  block "ATTEST_SIGNER_WORKFLOW is empty. Provenance would then be accepted from any workflow in ${ATTEST_REPO} that can write attestations, which is a different claim from the one this gate is supposed to make."
fi
case "$ATTEST_SIGNER_WORKFLOW" in
  */.github/workflows/*) ;;
  *) block "ATTEST_SIGNER_WORKFLOW ('${ATTEST_SIGNER_WORKFLOW}') does not name a workflow file. gh expects [host/]<owner>/<repo>/<path>/<to>/<workflow>." ;;
esac
say "provenance signer pinned to ${ATTEST_SIGNER_WORKFLOW}"

# Deliberate word splitting: EXPECT_NAMES is whitespace-separated and may be a
# YAML block scalar, so newlines have to split too (`read -a <<<` would take
# only the first line and silently check one target).
# shellcheck disable=SC2206
declare -a EXPECTED=( $EXPECT_NAMES )
if [[ "${#EXPECTED[@]}" -eq 0 ]]; then
  block "EXPECT_NAMES is empty, so this gate would check nothing and pass. A guard that passes because its subject disappeared is not a guard (the #3496 lesson). Name the artifacts the release is expected to carry."
fi
say "expecting ${#EXPECTED[@]} artifact(s): ${EXPECTED[*]}"

if [[ -z "$EXPECT_IDENTITY_REGEXP" ]]; then
  block "EXPECT_IDENTITY_REGEXP is empty. Keyless verification without a pinned certificate identity accepts any certificate Fulcio ever issued, to anyone."
fi

# A permissive regexp is the failure this check exists for. Sigstore's Fulcio is
# a PUBLIC CA: `.*` means "signed by somebody, somewhere". The pattern must at
# minimum be anchored and name this repository's workflow path.
_squashed="${EXPECT_IDENTITY_REGEXP//[[:space:]]/}"
case "$_squashed" in
  '.*'|'^.*'|'.*$'|'^.*$'|'.+'|'^.+$'|'')
    block "EXPECT_IDENTITY_REGEXP is '${EXPECT_IDENTITY_REGEXP}', which matches every certificate Fulcio has ever issued. A verify that accepts any identity verifies nothing." ;;
esac
if [[ "$_squashed" != ^* ]]; then
  block "EXPECT_IDENTITY_REGEXP ('${EXPECT_IDENTITY_REGEXP}') is not anchored at the start. An unanchored pattern matches a certificate whose identity merely CONTAINS the expected prefix, which any attacker-controlled repository path can arrange."
fi
if ! printf '%s' "$EXPECT_IDENTITY_REGEXP" | grep -qF '.github/workflows/'; then
  block "EXPECT_IDENTITY_REGEXP ('${EXPECT_IDENTITY_REGEXP}') does not pin a workflow path. Pin the repository AND the workflow file that is allowed to sign a release, not merely the owner: any workflow in any repository the owner controls would otherwise satisfy it."
fi
say "identity constraint is anchored and names a workflow path"

command -v sha256sum >/dev/null 2>&1 || infra "sha256sum is not on PATH."
command -v cosign    >/dev/null 2>&1 || infra "cosign is not on PATH -- the signature cannot be verified. Install it before this step."
command -v gh        >/dev/null 2>&1 || infra "gh is not on PATH -- build provenance cannot be verified."

CHECKSUMS_FILE="${CHECKSUMS_FILE:-$ASSETS_DIR/checksums.txt}"
BUNDLE_FILE="${BUNDLE_FILE:-${CHECKSUMS_FILE}.cosign.bundle}"

# ---------------------------------------------------------------------------
# 1. every expected asset is present
# ---------------------------------------------------------------------------
head2 "1. asset presence"

declare -a ARCHIVES=()
missing=()
for name in "${EXPECTED[@]}"; do
  archive=""
  if   [[ -f "$ASSETS_DIR/${name}.tar.gz" ]]; then archive="${name}.tar.gz"
  elif [[ -f "$ASSETS_DIR/${name}.exe"    ]]; then archive="${name}.exe"
  else
    missing+=("${name}.tar.gz or ${name}.exe")
    continue
  fi
  ARCHIVES+=("$archive")
  [[ -f "$ASSETS_DIR/${archive}.sha256" ]] || missing+=("${archive}.sha256")
  # The per-target CycloneDX SBOM. Its absence is a BLOCK and not a warning:
  # an SBOM that ships only when the generator happened to work is one nobody
  # can rely on, and a consumer cannot tell "this release has no SBOM" from
  # "this release's SBOM went missing".
  [[ -f "$ASSETS_DIR/${name}.cdx.json" ]] || missing+=("${name}.cdx.json (CycloneDX SBOM)")
done

if [[ "${#missing[@]}" -gt 0 ]]; then
  for m in "${missing[@]}"; do say "MISSING: ${m}"; done
  block "${#missing[@]} expected release asset(s) are absent from ${ASSETS_DIR}. Publishing now would ship an incomplete release whose signature is nonetheless valid over what remains."
fi
say "all ${#EXPECTED[@]} target(s) present with archive, .sha256 and .cdx.json"

# ---------------------------------------------------------------------------
# 2. checksums.txt covers every asset, and matches the actual bytes
# ---------------------------------------------------------------------------
head2 "2. checksums.txt vs the bytes on disk"

[[ -f "$CHECKSUMS_FILE" ]] || block "${CHECKSUMS_FILE} does not exist. There is nothing for the signature to cover."
[[ -s "$CHECKSUMS_FILE" ]] || block "${CHECKSUMS_FILE} is empty. \`sha256sum -c\` on an empty manifest succeeds and proves nothing."

checksums_base="$(basename "$CHECKSUMS_FILE")"
bundle_base="$(basename "$BUNDLE_FILE")"

# Everything shipped must be named in the manifest. Otherwise an asset can be
# replaced freely: the signature is still valid, `sha256sum -c` still passes,
# and the substituted file was simply never described.
uncovered=()
while IFS= read -r f; do
  base="$(basename "$f")"
  [[ "$base" == "$checksums_base" || "$base" == "$bundle_base" ]] && continue
  # `sha256sum` writes "<hex>  <name>" (two spaces, or " *" in binary mode).
  if ! grep -Eq "^[0-9a-fA-F]{64} [ *]?${base//./\\.}$" "$CHECKSUMS_FILE"; then
    uncovered+=("$base")
  fi
done < <(find "$ASSETS_DIR" -maxdepth 1 -type f | sort)

if [[ "${#uncovered[@]}" -gt 0 ]]; then
  for u in "${uncovered[@]}"; do say "NOT IN ${checksums_base}: ${u}"; done
  block "${#uncovered[@]} shipped asset(s) are not named in ${checksums_base}. The signature covers the manifest, so an asset the manifest never mentions is an asset nothing signed."
fi
n_listed="$(grep -Ec '^[0-9a-fA-F]{64} [ *]?' "$CHECKSUMS_FILE" || true)"
say "${checksums_base} lists ${n_listed} file(s) and covers every asset in the directory"

cs_out=""
if ! cs_out="$( cd "$ASSETS_DIR" && sha256sum -c "$checksums_base" 2>&1 )"; then
  printf '%s\n' "$cs_out" | sed 's/^/      /'
  block "sha256sum -c failed: the bytes on disk do not match ${checksums_base}. Either the manifest is stale or an artifact changed after it was written -- in both cases the signature about to be published would attest to a digest the release does not contain."
fi
say "sha256sum -c: every listed digest matches the bytes on disk"

# ---------------------------------------------------------------------------
# 3. the signature exists
# ---------------------------------------------------------------------------
head2 "3. signature material"

if [[ ! -f "$BUNDLE_FILE" ]]; then
  block "No signature: ${BUNDLE_FILE} does not exist. The cosign signing step did not produce a bundle, so the release would publish unsigned -- which is #2824 exactly, where a failed cosign step let 1.6.1 ship unsigned and a human found it later."
fi
[[ -s "$BUNDLE_FILE" ]] || block "${BUNDLE_FILE} exists but is empty."
say "bundle present: ${bundle_base} ($(wc -c < "$BUNDLE_FILE" | tr -d ' ') bytes)"

# ---------------------------------------------------------------------------
# 4. cosign verify-blob, against the PINNED identity
# ---------------------------------------------------------------------------
head2 "4. cosign verify-blob (pinned identity)"

# cosign v3 removed `--signature`/`--certificate` from verify-blob: a Sigstore
# bundle is the supported way to carry keyless verification material, which is
# why the release ships one `.cosign.bundle` rather than a `.sig` + `.pem` pair.
cosign_out=""
cosign_rc=0
cosign_out="$(cosign verify-blob \
    --bundle "$BUNDLE_FILE" \
    --certificate-identity-regexp "$EXPECT_IDENTITY_REGEXP" \
    --certificate-oidc-issuer "$EXPECT_OIDC_ISSUER" \
    "$CHECKSUMS_FILE" 2>&1)" || cosign_rc=$?

if [[ "$cosign_rc" -ne 0 ]]; then
  printf '%s\n' "$cosign_out" | sed 's/^/      /'
  if looks_like_infra "$cosign_out"; then
    infra "cosign verify-blob could not reach Sigstore (Fulcio/Rekor/TUF). The signature was neither proven good nor proven bad."
  fi
  block "cosign verify-blob REFUSED ${checksums_base}. Either the signature does not cover these bytes, or the certificate identity is not '${EXPECT_IDENTITY_REGEXP}' at issuer ${EXPECT_OIDC_ISSUER}. Do not publish."
fi
printf '%s\n' "$cosign_out" | sed 's/^/      /'
say "cosign verify-blob: OK against ${EXPECT_IDENTITY_REGEXP}"

# ---------------------------------------------------------------------------
# 5. gh attestation verify, on every shipped archive
# ---------------------------------------------------------------------------
head2 "5. build provenance"

for archive in "${ARCHIVES[@]}"; do
  gh_out=""
  gh_rc=0
  gh_out="$(gh attestation verify "$ASSETS_DIR/$archive" \
      --repo "$ATTEST_REPO" \
      --signer-workflow "$ATTEST_SIGNER_WORKFLOW" 2>&1)" || gh_rc=$?
  if [[ "$gh_rc" -ne 0 ]]; then
    printf '%s\n' "$gh_out" | sed 's/^/      /'
    if looks_like_infra "$gh_out"; then
      infra "gh attestation verify could not reach the GitHub attestations API while checking ${archive}."
    fi
    block "gh attestation verify REFUSED ${archive} for ${ATTEST_REPO} signed by ${ATTEST_SIGNER_WORKFLOW}. Either no build provenance covers this artifact, or it was produced by a different workflow -- so \`gh attestation verify <file> --repo ${ATTEST_REPO}\`, the command SECURITY.md tells users to run, would fail for them too."
  fi
  say "provenance OK: ${archive}"
done

# ---------------------------------------------------------------------------
# verdict
# ---------------------------------------------------------------------------
line="${#EXPECTED[@]} target(s): assets complete, ${checksums_base} matches the bytes, signature verifies against the pinned identity, provenance verifies."
echo
printf '%sVERIFIED%s: %s\n' "$GRN" "$RST" "$line"
summarise "PASS" "$line"
exit 0
