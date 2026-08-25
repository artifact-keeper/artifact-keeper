#!/usr/bin/env bash
#
# Self-test for scripts/ci/check-published-image-signature.sh (issue #3559).
#
# WHY THIS EXISTS
#   The gate under test says "the bytes a user pulls by tag are the bytes that
#   were signed". On a healthy repository it is green no matter what it does,
#   so the only way to know it works is to make it fail on purpose, once per
#   way an image can be unsigned. Two of those ways are the ones a plausible
#   implementation gets wrong, and both are pinned here:
#
#     * case 4 -- an image carrying `actions/attest-build-provenance` output
#       and NO cosign signature. Under cosign v3 a bare `cosign verify`
#       ACCEPTS that DSSE bundle and exits 0. A gate that only checks cosign's
#       exit code passes this image. It must not.
#     * case 5 -- a valid cosign signature over a DIFFERENT digest than the
#       one the tag resolves to. This is the exact shape #3559 was filed
#       about; a gate anchored to a digest handed to it by the signing job
#       cannot see it.
#
#   The other dangerous direction is calling an outage a tamper, so the
#   infrastructure cases assert exit 2 specifically, not merely "nonzero".
#
# HOW
#   The gate reaches the outside world through exactly two commands, `curl`
#   (resolve the tag) and `cosign` (verify the digest). Both are stubbed first
#   on PATH and replay canned answers, as is `sleep` so the retry case does
#   not spend real time. No network, no registry, no Sigstore; ~1s.
#
# Usage: bash scripts/ci/test-check-published-image-signature.sh
set -uo pipefail

GATE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/check-published-image-signature.sh"
[ -f "$GATE" ] || { echo "cannot find check-published-image-signature.sh next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0

pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

REF=ghcr.io/artifact-keeper/artifact-keeper-backend:1.9.9
DIGEST=sha256:44e433bc856b5e8dceb63b803e5ff1d96b0584fbfe3ea676d5d52592555ca333
OTHER=sha256:0f73b18c0c4a9b431474dd9ab93aa7a05eaeb9392bd0b82873133a2f2654fda5
IDENTITY='^https://github\.com/artifact-keeper/artifact-keeper/\.github/workflows/docker-publish\.yml@refs/(heads|tags)/.+$'

# --- stubs -----------------------------------------------------------------
STUB="$WORK/bin"; mkdir -p "$STUB"

# curl: only the `-sSI` manifest HEAD matters. FAKE_STATUS may be a
# space-separated list, consumed one entry per call, so a retry can be tested.
cat > "$STUB/curl" <<'STUBCURL'
#!/usr/bin/env bash
statuses=(${FAKE_STATUS:-200})
n=0
[ -f "$FAKE_STATE/curl.n" ] && n=$(cat "$FAKE_STATE/curl.n")
idx=$n
[ "$idx" -ge "${#statuses[@]}" ] && idx=$(( ${#statuses[@]} - 1 ))
echo $((n + 1)) > "$FAKE_STATE/curl.n"
status="${statuses[$idx]}"
[ "$status" = "000" ] && exit 6
echo "HTTP/2 ${status} "
if [ "$status" = "200" ] && [ "${FAKE_NO_DIGEST_HEADER:-0}" != "1" ]; then
  echo "docker-content-digest: ${FAKE_DIGEST}"
fi
echo ""
STUBCURL
chmod +x "$STUB/curl"

# cosign: replays a canned exit code and combined stdout+stderr.
cat > "$STUB/cosign" <<'STUBCOSIGN'
#!/usr/bin/env bash
echo cosign-was-called >> "$FAKE_STATE/cosign.calls"
[ "$1" = "verify" ] || { echo "unexpected cosign subcommand: $1" >&2; exit 99; }
printf '%s\n' "${FAKE_COSIGN_OUT-}"
exit "${FAKE_COSIGN_RC:-0}"
STUBCOSIGN
chmod +x "$STUB/cosign"

printf '#!/usr/bin/env bash\nexit 0\n' > "$STUB/sleep"; chmod +x "$STUB/sleep"

# cosign's real output shape: a human preamble, then the payload array.
signed_json() { # signed_json <type> <digest>
  cat <<JSON

Verification for ${REF} --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
[{"critical":{"identity":{"docker-reference":"x"},"image":{"docker-manifest-digest":"$2"},"type":"$1"},"optional":{}}]
JSON
}

# <label> <expected-exit> <expected-substring>
# The scenario comes from the FAKE_* / CASE_* variables the caller set.
expect() {
  local label="$1" want="$2" needle="$3" got=0
  rm -f "$WORK/curl.n" "$WORK/cosign.calls"

  # Deliberate word split: a case may pass no refs at all (" ") or several,
  # and they must reach the gate as separate arguments.
  # shellcheck disable=SC2206
  local -a refs=( ${CASE_REFS-$REF} )

  (
    export PATH="$STUB:$PATH"
    export FAKE_STATE="$WORK"
    export FAKE_STATUS="${FAKE_STATUS:-200}"
    export FAKE_DIGEST="${FAKE_DIGEST:-$DIGEST}"
    export FAKE_NO_DIGEST_HEADER="${FAKE_NO_DIGEST_HEADER:-0}"
    export FAKE_COSIGN_RC="${FAKE_COSIGN_RC:-0}"
    export FAKE_COSIGN_OUT="${FAKE_COSIGN_OUT-}"
    export PUBLISHED_SIG_ATTEMPTS="${CASE_ATTEMPTS:-1}"
    export PUBLISHED_SIG_IDENTITY_REGEXP="${CASE_IDENTITY:-$IDENTITY}"
    export COSIGN="${CASE_COSIGN:-cosign}"
    bash "$GATE" "${refs[@]}" >"$WORK/out.txt" 2>&1
  ) || got=$?

  if [ "$got" != "$want" ]; then
    fail "$label: expected exit $want, got $got"
    sed 's/^/        /' "$WORK/out.txt" | head -20
    return
  fi
  if [ -n "$needle" ] && ! grep -qF -- "$needle" "$WORK/out.txt"; then
    fail "$label: exit $got correct but output lacks '$needle'"
    sed 's/^/        /' "$WORK/out.txt" | head -20
    return
  fi
  pass "$label"
}

reset() {
  unset FAKE_STATUS FAKE_DIGEST FAKE_NO_DIGEST_HEADER FAKE_COSIGN_RC FAKE_COSIGN_OUT
  unset CASE_ATTEMPTS CASE_IDENTITY CASE_COSIGN CASE_REFS
}

echo "check-published-image-signature.sh"

# 1. The happy path. A cosign signature over the digest the tag resolves to.
reset
FAKE_COSIGN_OUT="$(signed_json 'https://sigstore.dev/cosign/sign/v1' "$DIGEST")"
expect "signed tag passes" 0 "signed: 1 cosign signature(s) over ${DIGEST}"

# 2. #2824's shape: the image is simply not signed.
reset
FAKE_COSIGN_RC=1
FAKE_COSIGN_OUT="Error: no signatures found
error during command execution: no signatures found"
expect "unsigned published tag BLOCKS" 1 "not verifiably signed"

# 3. Signed, but by somebody we do not accept. An unpinned verify would pass.
reset
FAKE_COSIGN_RC=1
FAKE_COSIGN_OUT="Error: none of the expected identities matched what was in the certificate"
expect "wrong signer identity BLOCKS" 1 "not verifiably signed"

# 4. THE SUBTLE ONE. Build provenance and no cosign signature: cosign v3
#    accepts the attestation bundle and exits 0. Checking only the exit code
#    passes an unsigned image.
reset
FAKE_COSIGN_OUT="$(signed_json 'https://slsa.dev/provenance/v1' "$DIGEST")"
expect "attestation-only image BLOCKS (provenance is not a signature)" 1 "has no cosign signature"

# 5. THE #3559 SHAPE. A real cosign signature, over a digest that is not the
#    one this tag resolves to. A gate anchored to the signer's digest cannot
#    see this; a gate anchored to the tag must.
reset
FAKE_COSIGN_OUT="$(signed_json 'https://sigstore.dev/cosign/sign/v1' "$OTHER")"
expect "signature over a different digest BLOCKS" 1 "has no cosign signature"

# 6. The publish did not produce the tag it promised. That is about the
#    image, not about the network: 404 is unambiguous.
reset
FAKE_STATUS=404
expect "missing published tag BLOCKS" 1 "Published tag is missing"

# 7..9. INFRASTRUCTURE. Each must be exit 2 -- never 1, or a Sigstore outage
#       reads in the log as a tampered image, and never 0.
reset
FAKE_STATUS=503
expect "registry 5xx is INFRA, not a finding" 2 "infrastructure"

reset
FAKE_STATUS=000
expect "registry transport failure is INFRA" 2 "infrastructure"

reset
FAKE_COSIGN_RC=1
FAKE_COSIGN_OUT="error during command execution: error fetching from rekor: dial tcp: i/o timeout"
expect "Rekor outage is INFRA, not a finding" 2 "infrastructure"

# 10. A 200 with no digest header tells us nothing; it must not pass.
reset
FAKE_NO_DIGEST_HEADER=1
expect "200 with no content-digest is INFRA" 2 "no Docker-Content-Digest"

# 11. cosign exits 0 but says nothing parsable. Never a pass.
reset
FAKE_COSIGN_OUT="Verification for x -- ok"
expect "unparsable cosign output is INFRA" 2 "no parsable result"

# 12. No verifier, no verdict.
reset
CASE_COSIGN=/nonexistent/cosign
expect "missing cosign binary is INFRA, not a pass" 2 "is not available"

# 13..15. NON-VACUITY. A gate with no subject, or one that accepts any signer,
#         passes for reasons that have nothing to do with the images.
reset
CASE_REFS=" "
expect "no refs refuses rather than passing vacuously" 2 "no image references"

reset
CASE_IDENTITY='.*'
expect "identity regexp matching everything is refused" 2 "matches any signer"

reset
CASE_REFS="ghcr.io/artifact-keeper/artifact-keeper-backend@${DIGEST}"
expect "a digest reference is refused (the tag is what users pull)" 2 "pins a digest"

# 16. Retry: a transient resolve failure followed by success must not block.
reset
FAKE_STATUS="503 200"
CASE_ATTEMPTS=3
FAKE_COSIGN_OUT="$(signed_json 'https://sigstore.dev/cosign/sign/v1' "$DIGEST")"
expect "transient resolve failure is retried, then passes" 0 "signed: 1 cosign signature"

# 17. One bad ref among several must fail the whole gate.
reset
CASE_REFS="$REF"
FAKE_COSIGN_RC=1
FAKE_COSIGN_OUT="Error: no signatures found"
expect "a single unsigned tag fails the run" 1 "BLOCKED: 1 published tag(s)"

# 18. Fixture replay. This is the VERBATIM payload array cosign 3.0.6 printed
#     for the published ghcr.io/...-backend:1.8.1 on 2026-08-25, including the
#     provenance entry that sits alongside the signature. It pins the JSON
#     shape the type/digest assertion reads, so an upstream change to that
#     shape is a red test rather than a gate that quietly stops asserting.
reset
FAKE_COSIGN_OUT='
Verification for ghcr.io/artifact-keeper/artifact-keeper-backend:1.8.1 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The code-signing certificate was verified using trusted certificate authority certificates
[{"critical":{"identity":{"docker-reference":"ghcr.io/artifact-keeper/artifact-keeper-backend:1.8.1"},"image":{"docker-manifest-digest":"sha256:44e433bc856b5e8dceb63b803e5ff1d96b0584fbfe3ea676d5d52592555ca333"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}},{"critical":{"identity":{"docker-reference":"ghcr.io/artifact-keeper/artifact-keeper-backend:1.8.1"},"image":{"docker-manifest-digest":"sha256:44e433bc856b5e8dceb63b803e5ff1d96b0584fbfe3ea676d5d52592555ca333"},"type":"https://slsa.dev/provenance/v1"},"optional":{}}]'
expect "real 1.8.1 cosign output passes" 0 "signed: 1 cosign signature"

# 19. The same real output with the signature entry removed -- i.e. exactly
#     what a 1.6.1-shaped image (provenance, no cosign signature) looks like.
reset
FAKE_COSIGN_OUT='
Verification for ghcr.io/artifact-keeper/artifact-keeper-backend:1.8.1 --
[{"critical":{"identity":{"docker-reference":"ghcr.io/artifact-keeper/artifact-keeper-backend:1.8.1"},"image":{"docker-manifest-digest":"sha256:44e433bc856b5e8dceb63b803e5ff1d96b0584fbfe3ea676d5d52592555ca333"},"type":"https://slsa.dev/provenance/v1"},"optional":{}}]'
expect "real output minus the signature BLOCKS" 1 "has no cosign signature"

echo ""
if [ "$fails" -gt 0 ]; then
  echo "FAILED: $fails case(s)"
  exit 1
fi
echo "OK: every case behaved (including all ${0##*/} BLOCK and INFRA legs)."
