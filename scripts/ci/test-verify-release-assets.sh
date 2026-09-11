#!/usr/bin/env bash
#
# Self-test for scripts/ci/verify-release-assets.sh (issue #3558).
#
# WHY THIS EXISTS
#   The gate under test is the only thing standing between "we signed
#   something" and "the thing we shipped is the thing we signed". It runs
#   exactly once per release, on a code path that cannot be rehearsed without
#   cutting a tag -- so if it is wrong, it is wrong in production, once, on the
#   day it matters. Everything it refuses is exercised here instead.
#
#   The dangerous direction is fail-OPEN, so most cases below assert a nonzero
#   exit. Three deserve naming:
#
#     * WRONG IDENTITY (case 6). A signature that verifies is not the same as a
#       signature from the right signer. Fulcio is a PUBLIC CA: anyone can get a
#       certificate for their own workflow and sign anything with it. This case
#       supplies a bundle whose certificate identity belongs to a different
#       repository and asserts the gate refuses it.
#     * A PERMISSIVE PIN (case 7). `--certificate-identity-regexp '.*'` makes
#       cosign exit 0 for that same attacker certificate. It satisfies every
#       flag cosign requires and verifies nothing. The gate refuses to run with
#       one, which is the arm most likely to be "fixed" away by someone
#       debugging an identity mismatch under time pressure.
#     * A COVERAGE HOLE (case 4). `sha256sum -c` passes over a manifest that
#       omits a file. An asset nobody listed is an asset nobody signed.
#
# HOW
#   The gate reaches the outside world only through `cosign` and `gh`, so both
#   are stubbed first on PATH. The `cosign` stub is NOT a rubber stamp: it
#   parses the flags it is given, refuses a keyless verification with no
#   identity constraint, compares the blob digest against the bundle, and
#   applies the identity regexp itself. That is what makes case 6 and case 7
#   meaningful -- a gate that dropped `--certificate-identity-regexp`, or passed
#   a permissive one straight through to cosign, would go GREEN against a
#   rubber-stamp stub and goes RED against this one.
#
#   No network, no repository state, ~2s.
#
# Usage: bash scripts/ci/test-verify-release-assets.sh
set -uo pipefail

GATE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/verify-release-assets.sh"
[ -f "$GATE" ] || { echo "cannot find verify-release-assets.sh next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0

pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

REPO=artifact-keeper/artifact-keeper
GOOD_IDENTITY="https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/v9.9.9"
GOOD_ISSUER="https://token.actions.githubusercontent.com"
GOOD_SIGNER="${REPO}/.github/workflows/release.yml"
# The pin release.yml actually uses, with the tag regex-escaped.
GOOD_REGEXP='^https://github\.com/artifact-keeper/artifact-keeper/\.github/workflows/release\.yml@refs/tags/v9\.9\.9$'
NAMES="artifact-keeper-linux-amd64 artifact-keeper-darwin-arm64 artifact-keeper-windows-amd64"

# --- stubs -----------------------------------------------------------------
STUB="$WORK/bin"; mkdir -p "$STUB"

# A cosign stub that actually enforces what cosign enforces. The fake bundle is
# a three-line key=value file: identity, issuer, and the sha256 of the blob it
# was made for.
cat > "$STUB/cosign" <<'STUBCOSIGN'
#!/usr/bin/env bash
[ "${1:-}" = "verify-blob" ] || { echo "stub cosign: unexpected subcommand '${1:-}'" >&2; exit 64; }
shift
bundle=""; idre=""; issuer=""; blob=""
while [ $# -gt 0 ]; do
  case "$1" in
    --bundle)                      bundle="$2"; shift 2 ;;
    --certificate-identity-regexp) idre="$2";   shift 2 ;;
    --certificate-oidc-issuer)     issuer="$2"; shift 2 ;;
    --*)                           shift 2 ;;
    *)                             blob="$1";   shift ;;
  esac
done
if [ "${FAKE_COSIGN_NETFAIL:-0}" = "1" ]; then
  echo "Error: updating TUF metadata: dial tcp 140.82.121.4:443: connect: connection refused" >&2
  exit 1
fi
# cosign itself refuses a keyless verification with no identity constraint.
[ -n "$idre" ]   || { echo "Error: --certificate-identity or --certificate-identity-regexp must be set for keyless flows" >&2; exit 1; }
[ -n "$issuer" ] || { echo "Error: --certificate-oidc-issuer must be set for keyless flows" >&2; exit 1; }
[ -f "$bundle" ] || { echo "Error: reading ${bundle}: no such file or directory" >&2; exit 1; }
b_id="$(sed -n 's/^identity=//p' "$bundle")"
b_is="$(sed -n 's/^issuer=//p' "$bundle")"
b_sha="$(sed -n 's/^sha256=//p' "$bundle")"
actual="$(sha256sum "$blob" | awk '{print $1}')"
[ "$actual" = "$b_sha" ] || { echo "Error: verifying blob: signature does not cover these bytes" >&2; exit 1; }
printf '%s' "$b_id" | grep -Eq "$idre" || { echo "Error: none of the expected identities matched what was in the certificate: got '${b_id}'" >&2; exit 1; }
[ "$b_is" = "$issuer" ] || { echo "Error: expected oidc issuer '${issuer}', got '${b_is}'" >&2; exit 1; }
echo "Verified OK"
STUBCOSIGN
chmod +x "$STUB/cosign"

# A `gh attestation verify` stub that enforces what gh enforces, including the
# `--signer-workflow` pin. FAKE_GH_SIGNER is the workflow the (pretend)
# attestation was actually produced by, so dropping the pin from the gate makes
# case 9b go green here and RED in reality -- which is the wrong direction, so
# the stub refuses a mismatch itself.
cat > "$STUB/gh" <<'STUBGH'
#!/usr/bin/env bash
[ "${1:-}" = "attestation" ] && [ "${2:-}" = "verify" ] || { echo "stub gh: unexpected '${1:-} ${2:-}'" >&2; exit 64; }
shift 2
signer=""; repo=""
while [ $# -gt 0 ]; do
  case "$1" in
    --signer-workflow) signer="$2"; shift 2 ;;
    --repo|-R)         repo="$2";   shift 2 ;;
    --*)               shift 2 ;;
    *)                 shift ;;
  esac
done
if [ "${FAKE_GH_NETFAIL:-0}" = "1" ]; then
  echo 'failed to fetch attestations: Post "https://api.github.com/graphql": dial tcp: i/o timeout' >&2
  exit 1
fi
if [ "${FAKE_GH_FAIL:-0}" = "1" ]; then
  echo "✗ no attestations found for subject" >&2
  exit 1
fi
[ -n "$repo" ] || { echo "stub gh: --repo was not passed" >&2; exit 1; }
actual_signer="${FAKE_GH_SIGNER:-artifact-keeper/artifact-keeper/.github/workflows/release.yml}"
if [ -n "$signer" ] && [ "$signer" != "$actual_signer" ]; then
  echo "✗ verification failed: the attestation was signed by ${actual_signer}, not ${signer}" >&2
  exit 1
fi
echo "Loaded 1 attestation from GitHub API"
echo "✓ Verification succeeded!"
STUBGH
chmod +x "$STUB/gh"

# --- fixture ---------------------------------------------------------------
# Builds a well-formed release-assets directory: three targets (two tarballs,
# one .exe), each with its legacy .sha256 and its CycloneDX SBOM, a
# checksums.txt covering everything, and a bundle over checksums.txt.
make_release() {
  local dir="$1"
  rm -rf "$dir"; mkdir -p "$dir"
  local n
  for n in $NAMES; do
    local archive="${n}.tar.gz"
    case "$n" in *windows*) archive="${n}.exe" ;; esac
    printf 'pretend %s bytes\n' "$n" > "$dir/$archive"
    ( cd "$dir" && sha256sum "$archive" > "${archive}.sha256" )
    cat > "$dir/${n}.cdx.json" <<CDX
{"bomFormat":"CycloneDX","specVersion":"1.5",
 "metadata":{"component":{"type":"application","name":"artifact-keeper-backend","version":"9.9.9"}},
 "components":[$(for i in $(seq 1 60); do printf '{"type":"library","name":"c%s","version":"1.0.0"}' "$i"; [ "$i" -lt 60 ] && printf ','; done)]}
CDX
  done
  regen_checksums "$dir"
  sign_checksums "$dir" "$GOOD_IDENTITY" "$GOOD_ISSUER"
}

regen_checksums() {
  local dir="$1"
  ( cd "$dir" && find . -maxdepth 1 -type f ! -name checksums.txt ! -name 'checksums.txt.cosign.bundle' -printf '%P\n' \
      | sort | xargs sha256sum > checksums.txt )
}

sign_checksums() {
  local dir="$1" identity="$2" issuer="$3"
  {
    echo "identity=${identity}"
    echo "issuer=${issuer}"
    echo "sha256=$(sha256sum "$dir/checksums.txt" | awk '{print $1}')"
  } > "$dir/checksums.txt.cosign.bundle"
}

# <label> <expected-exit> <expected-substring>
expect() {
  local label="$1" want="$2" needle="$3" got=0
  ( PATH="$STUB:$PATH" \
      ASSETS_DIR="$DIR" \
      EXPECT_NAMES="${CASE_NAMES-$NAMES}" \
      EXPECT_IDENTITY_REGEXP="${CASE_REGEXP-$GOOD_REGEXP}" \
      EXPECT_OIDC_ISSUER="${CASE_ISSUER-$GOOD_ISSUER}" \
      ATTEST_REPO="$REPO" \
      ATTEST_SIGNER_WORKFLOW="${CASE_SIGNER-$GOOD_SIGNER}" \
      FAKE_COSIGN_NETFAIL="${FAKE_COSIGN_NETFAIL:-0}" \
      FAKE_GH_FAIL="${FAKE_GH_FAIL:-0}" \
      FAKE_GH_NETFAIL="${FAKE_GH_NETFAIL:-0}" \
      FAKE_GH_SIGNER="${FAKE_GH_SIGNER:-$GOOD_SIGNER}" \
      bash "$GATE" >"$WORK/out.txt" 2>&1 ) || got=$?
  if [ "$got" != "$want" ]; then
    fail "$label: expected exit $want, got $got"
    sed 's/^/        /' "$WORK/out.txt" >&2
  elif ! grep -qF -- "$needle" "$WORK/out.txt"; then
    fail "$label: exit $got correct but output lacks '$needle'"
    sed 's/^/        /' "$WORK/out.txt" >&2
  else
    pass "$label (exit $got)"
  fi
}

DIR="$WORK/release-assets"
reset_case() {
  make_release "$DIR"
  CASE_NAMES="$NAMES"; CASE_REGEXP="$GOOD_REGEXP"; CASE_ISSUER="$GOOD_ISSUER"
  CASE_SIGNER="$GOOD_SIGNER"; FAKE_GH_SIGNER="$GOOD_SIGNER"
  FAKE_COSIGN_NETFAIL=0; FAKE_GH_FAIL=0; FAKE_GH_NETFAIL=0
}

echo "release asset verification gate: every leg"

# 1. HAPPY PATH. Stated first so a later red is unambiguously about the change
#    under test and not about a broken fixture.
reset_case
expect "complete, signed, attested release -> PASS" 0 \
  "VERIFIED"

# 2. checksums.txt does not describe the bytes. The manifest is signed; if it
#    does not match what shipped, the signature attests to a digest the release
#    does not contain.
reset_case
printf 'tampered after the manifest was written\n' > "$DIR/artifact-keeper-linux-amd64.tar.gz"
sign_checksums "$DIR" "$GOOD_IDENTITY" "$GOOD_ISSUER"
expect "checksums.txt does not match the assets -> BLOCKED" 1 \
  "sha256sum -c failed"

# 3. The signed blob itself was modified after signing: cosign must refuse,
#    because the bundle no longer covers these bytes.
#    The manifest stays internally consistent -- the new line is a CORRECT
#    digest of a real file, so `sha256sum -c` passes and the coverage check
#    passes -- and only the signature notices that checksums.txt is no longer
#    the file that was signed.
reset_case
printf 'an extra asset added after signing\n' > "$DIR/smuggled.bin"
( cd "$DIR" && sha256sum smuggled.bin >> checksums.txt )
expect "checksums.txt edited after signing -> BLOCKED" 1 \
  "cosign verify-blob REFUSED"

# 4. COVERAGE HOLE. `sha256sum -c` passes happily over a manifest that simply
#    does not mention a file, so an unlisted asset is an unsigned asset.
reset_case
grep -v 'artifact-keeper-darwin-arm64.tar.gz$' "$DIR/checksums.txt" > "$DIR/checksums.tmp"
mv "$DIR/checksums.tmp" "$DIR/checksums.txt"
sign_checksums "$DIR" "$GOOD_IDENTITY" "$GOOD_ISSUER"
expect "an asset missing from checksums.txt -> BLOCKED" 1 \
  "are not named in checksums.txt"

# 5. NO SIGNATURE AT ALL. This is #2824's shape: the signing step failed, the
#    release published anyway, and a human noticed later.
reset_case
rm -f "$DIR/checksums.txt.cosign.bundle"
expect "missing signature bundle -> BLOCKED" 1 \
  "No signature"

# 6. ★ WRONG IDENTITY. The bundle verifies -- it is a real signature over these
#    exact bytes -- but the certificate belongs to somebody else's workflow.
reset_case
sign_checksums "$DIR" \
  "https://github.com/attacker/evil/.github/workflows/release.yml@refs/tags/v9.9.9" \
  "$GOOD_ISSUER"
expect "valid signature, WRONG certificate identity -> BLOCKED" 1 \
  "cosign verify-blob REFUSED"

# 6b. ...and the same certificate from the right repository but the WRONG
#     workflow. `docker-publish.yml` also signs, with a certificate from this
#     same repository; only release.yml may sign a release manifest.
reset_case
sign_checksums "$DIR" \
  "https://github.com/${REPO}/.github/workflows/docker-publish.yml@refs/tags/v9.9.9" \
  "$GOOD_ISSUER"
expect "signature from another workflow in this repo -> BLOCKED" 1 \
  "cosign verify-blob REFUSED"

# 6c. Right workflow, wrong OIDC issuer.
reset_case
sign_checksums "$DIR" "$GOOD_IDENTITY" "https://accounts.google.com"
expect "signature from another OIDC issuer -> BLOCKED" 1 \
  "cosign verify-blob REFUSED"

# 7. ★ A PERMISSIVE PIN. `.*` satisfies cosign's "you must constrain the
#    identity" requirement and constrains nothing. The gate must refuse the
#    CONFIGURATION, before it verifies anything -- proven by pointing it at a
#    release signed by an attacker certificate, which `.*` would accept.
reset_case
sign_checksums "$DIR" \
  "https://github.com/attacker/evil/.github/workflows/release.yml@refs/tags/v9.9.9" \
  "$GOOD_ISSUER"
CASE_REGEXP='.*'
expect "identity pinned to '.*' -> BLOCKED before verifying" 1 \
  "matches every certificate Fulcio has ever issued"

# 7b. An unanchored pattern matches an identity that merely CONTAINS the
#     expected text, which an attacker-controlled repository name can arrange.
reset_case
CASE_REGEXP='https://github\.com/artifact-keeper/artifact-keeper/\.github/workflows/release\.yml'
expect "identity pattern not anchored -> BLOCKED" 1 \
  "not anchored at the start"

# 7c. Pinning only the owner leaves every workflow in every repository the
#     owner controls able to sign a release.
reset_case
CASE_REGEXP='^https://github\.com/artifact-keeper/.*'
expect "identity pins the owner but no workflow path -> BLOCKED" 1 \
  "does not pin a workflow path"

# 7d. No pin at all.
reset_case
CASE_REGEXP=''
expect "no identity pin -> BLOCKED" 1 \
  "accepts any certificate Fulcio ever issued"

# 8. MISSING SBOM ASSET. An SBOM that ships only when its generator happened to
#    work is one no consumer can build a process on.
reset_case
rm -f "$DIR/artifact-keeper-darwin-arm64.cdx.json"
regen_checksums "$DIR"; sign_checksums "$DIR" "$GOOD_IDENTITY" "$GOOD_ISSUER"
expect "missing .cdx.json SBOM asset -> BLOCKED" 1 \
  "CycloneDX SBOM"

# 8b. A whole target absent. The signature over the remaining four would be
#     perfectly valid.
reset_case
rm -f "$DIR"/artifact-keeper-windows-amd64.*
regen_checksums "$DIR"; sign_checksums "$DIR" "$GOOD_IDENTITY" "$GOOD_ISSUER"
expect "a whole target missing from the release -> BLOCKED" 1 \
  "expected release asset(s) are absent"

# 8c. The legacy per-file .sha256 is still a published asset and is still
#     required, so its disappearance is a change to the release contract.
reset_case
rm -f "$DIR/artifact-keeper-linux-amd64.tar.gz.sha256"
regen_checksums "$DIR"; sign_checksums "$DIR" "$GOOD_IDENTITY" "$GOOD_ISSUER"
expect "missing legacy .sha256 -> BLOCKED" 1 \
  "artifact-keeper-linux-amd64.tar.gz.sha256"

# 9. NO PROVENANCE. cosign and the attestations API fail independently, and
#    consumers reach for one or the other.
reset_case
FAKE_GH_FAIL=1
expect "gh attestation verify refuses an asset -> BLOCKED" 1 \
  "gh attestation verify REFUSED"

# 9b. ★ PROVENANCE FROM THE WRONG WORKFLOW. `--repo` alone accepts an
#     attestation from any workflow in this repository that can write one, and
#     docker-publish.yml writes four per publish. The release assets must carry
#     provenance from release.yml specifically.
reset_case
FAKE_GH_SIGNER="${REPO}/.github/workflows/docker-publish.yml"
expect "provenance signed by another workflow in this repo -> BLOCKED" 1 \
  "gh attestation verify REFUSED"

# 9c. ...and the gate must refuse to run with the signer pin left empty, for
#     the same reason it refuses a permissive certificate identity.
reset_case
CASE_SIGNER=""
expect "no provenance signer pin -> BLOCKED" 1 \
  "ATTEST_SIGNER_WORKFLOW is empty"

reset_case
CASE_SIGNER="artifact-keeper/artifact-keeper"
expect "signer pin names a repo but no workflow file -> BLOCKED" 1 \
  "does not name a workflow file"

# 10. INFRA, not tampering. A Sigstore outage and a substituted artifact must
#     not read alike -- both stop the release, but only one means "retry".
reset_case
FAKE_COSIGN_NETFAIL=1
expect "Sigstore unreachable -> INFRA (exit 2), not BLOCKED" 2 \
  "could not reach Sigstore"

reset_case
FAKE_GH_NETFAIL=1
expect "attestations API unreachable -> INFRA (exit 2)" 2 \
  "could not reach the GitHub attestations API"

# 11. NON-VACUITY. A gate whose subject list is empty checks nothing and would
#     otherwise pass -- the #3496 defect one layer out.
reset_case
CASE_NAMES=""
expect "no expected targets named -> BLOCKED, not vacuously green" 1 \
  "would check nothing and pass"

# 12. The tools themselves missing is INFRA: nothing was measured.
#     PATH is narrowed to an empty directory plus a coreutils shim providing
#     ONLY what the gate needs before it reaches cosign, so this cannot pass by
#     accident on a host that happens to have cosign installed somewhere else.
reset_case
mkdir -p "$WORK/emptybin" "$WORK/shim"
for t in bash sha256sum find grep sed sort basename wc tr head cat awk; do
  real="$(command -v "$t" || true)"
  [ -n "$real" ] && ln -sf "$real" "$WORK/shim/$t"
done
got=0
( PATH="$WORK/emptybin:$WORK/shim" ASSETS_DIR="$DIR" EXPECT_NAMES="$NAMES" \
    EXPECT_IDENTITY_REGEXP="$GOOD_REGEXP" ATTEST_REPO="$REPO" \
    ATTEST_SIGNER_WORKFLOW="$GOOD_SIGNER" \
    bash "$GATE" >"$WORK/out.txt" 2>&1 ) || got=$?
if [ "$got" = "2" ] && grep -qF "cosign is not on PATH" "$WORK/out.txt"; then
  pass "cosign not installed -> INFRA (exit 2) (exit $got)"
else
  fail "cosign not installed: expected exit 2 mentioning cosign, got $got"
  sed 's/^/        /' "$WORK/out.txt" >&2
fi

# ---------------------------------------------------------------------------
# identity pattern CONSTRUCTION
#
# The gate above verifies against whatever pattern it is handed. Building that
# pattern is the other half, and it is the half that was already wrong.
# release.yml escaped the tag with
#
#     sed 's/[.^$*+?()[\]{}|\\]/\\&/g'
#
# which reads as "escape every regex metacharacter" and is a no-op: `\` is not
# special inside a POSIX bracket expression, so the `]` after it CLOSES the
# class and the rest becomes literal text that must follow the matched
# character. `v1.8.2` came through unescaped and every `.` in the "pinned"
# identity was a wildcard. Nothing asserted on the pattern's TEXT, so nothing
# noticed. These cases do.
# ---------------------------------------------------------------------------
BUILDER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/release-identity-regexp.sh"

echo
echo "identity pattern construction"

expect_pattern() {  # <label> <repo> <workflow> <ref> <expected>
  local label="$1" got
  got="$(bash "$BUILDER" "$2" "$3" "$4")" || { fail "$label: builder exited nonzero"; return; }
  if [ "$got" = "$5" ]; then
    pass "$label"
  else
    fail "$label"
    printf '        want: %s\n        got:  %s\n' "$5" "$got" >&2
  fi
}

expect_pattern "a version tag has its dots escaped" \
  artifact-keeper/artifact-keeper release.yml refs/tags/v1.8.2 \
  '^https://github\.com/artifact-keeper/artifact-keeper/\.github/workflows/release\.yml@refs/tags/v1\.8\.2$'

expect_pattern "a prerelease tag too" \
  artifact-keeper/artifact-keeper release.yml refs/tags/v1.9.0-rc.1 \
  '^https://github\.com/artifact-keeper/artifact-keeper/\.github/workflows/release\.yml@refs/tags/v1\.9\.0-rc\.1$'

# The property that actually matters, stated as behaviour rather than as text:
# the built pattern must accept this workflow's identity and refuse the
# near-misses an unescaped `.` lets through.
match_check() {  # <label> <pattern> <candidate> <should-match: y|n>
  local label="$1" pat="$2" cand="$3" want="$4" got
  if printf '%s' "$cand" | grep -Eq "$pat"; then got=y; else got=n; fi
  if [ "$got" = "$want" ]; then
    pass "$label"
  else
    fail "$label: pattern [$pat] vs [$cand] -> $got, wanted $want"
  fi
}

PAT="$(bash "$BUILDER" artifact-keeper/artifact-keeper release.yml refs/tags/v1.8.2)"
SAN='https://github.com/artifact-keeper/artifact-keeper/.github/workflows/release.yml@refs/tags/v1.8.2'
match_check "accepts this workflow's own identity" "$PAT" "$SAN" y
match_check "refuses another repository" "$PAT" \
  'https://github.com/attacker/evil/.github/workflows/release.yml@refs/tags/v1.8.2' n
match_check "refuses another workflow in this repository" "$PAT" \
  'https://github.com/artifact-keeper/artifact-keeper/.github/workflows/docker-publish.yml@refs/tags/v1.8.2' n
match_check "refuses another tag" "$PAT" \
  'https://github.com/artifact-keeper/artifact-keeper/.github/workflows/release.yml@refs/tags/v1.8.3' n
match_check "refuses a longer identity that CONTAINS this one" "$PAT" "${SAN}.evil" n
# The regression itself. Under the old no-op escaper all three of these
# MATCHED, because an unescaped `.` matches any character.
match_check "refuses 'releaseXyml' (a dot must not be a wildcard)" "$PAT" \
  'https://github.com/artifact-keeper/artifact-keeper/.github/workflows/releaseXyml@refs/tags/v1.8.2' n
match_check "refuses 'v1X8X2' (a dot must not be a wildcard)" "$PAT" \
  'https://github.com/artifact-keeper/artifact-keeper/.github/workflows/release.yml@refs/tags/v1X8X2' n
match_check "refuses 'githubXcom' (a dot must not be a wildcard)" "$PAT" \
  'https://githubXcom/artifact-keeper/artifact-keeper/.github/workflows/release.yml@refs/tags/v1.8.2' n

# The builder is also refused a vacuous call, so a caller that lost its ref
# cannot end up publishing with a half-built pin.
for bad in "'' release.yml refs/tags/v1.8.2" "artifact-keeper/artifact-keeper '' refs/tags/v1.8.2" "artifact-keeper/artifact-keeper release.yml ''"; do
  rc=0
  eval "bash \"\$BUILDER\" $bad" >/dev/null 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then pass "builder refuses an empty argument ($bad)"; else fail "builder accepted an empty argument ($bad)"; fi
done

# Finally, the two halves have to agree: the pattern the builder produces must
# be one the GATE accepts, and must verify a real signature carrying it.
reset_case
sign_checksums "$DIR" \
  "https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/v9.9.9" "$GOOD_ISSUER"
CASE_REGEXP="$(bash "$BUILDER" "$REPO" release.yml refs/tags/v9.9.9)"
expect "the built pattern is accepted by the gate and verifies -> PASS" 0 \
  "VERIFIED"


echo
if [ "$fails" -eq 0 ]; then
  printf '\033[32mall release-asset gate cases behaved as required\033[0m\n'
  exit 0
fi
printf '\033[31m%s case(s) failed\033[0m\n' "$fails"
exit 1
