#!/usr/bin/env bash
#
# Self-test for scripts/ci/audit-published-attestations.sh (issue #3519).
#
# WHY THIS EXISTS
#   The audit is also the RELEASE GATE: `verify-published` runs it on every
#   `refs/tags/v*` publish, so its fail-open directions cost a release each.
#   And it cannot be exercised for real anywhere but on a tag cut, against a
#   registry and the GitHub attestations API -- which is exactly the shape
#   #3496 is about ("a control that cannot be shown to fail"). So the decision
#   logic is pinned here instead, offline.
#
#   The dangerous directions, one case each:
#     * a digest with a cosign signature but NO provenance predicate must
#       BLOCK. This is #3519's whole subject: the attestation steps were
#       soft-failing, so this is the shape a real published digest is most
#       likely to have.
#     * a digest with provenance but no signature must BLOCK (#2824's shape).
#     * "could not ask" must exit 2, never 0 and never 1 -- a Sigstore or
#       registry outage is not a finding about an image, and is not a pass.
#     * an empty argument list must exit 2. An audit with nothing to audit
#       reports success while proving nothing.
#     * the scanner-adapter must be asked for ITS OWN version, never the AK
#       release version, which it never publishes (see merge-scanner-adapter).
#
# HOW
#   The audit reaches the outside world through exactly three commands, and
#   all three are replaceable by environment variable or by PATH:
#     AK_AUDIT_DIGEST_CMD   the tag -> digest probe
#     AK_AUDIT_SIG_CMD      the #3559 cosign gate
#     gh                    `gh attestation verify` (stubbed first on PATH)
#   No network, no registry, no Sigstore; ~1s.
#
# Usage: bash scripts/ci/test-audit-published-attestations.sh
set -uo pipefail

AUDIT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/audit-published-attestations.sh"
[ -f "$AUDIT" ] || { echo "cannot find audit-published-attestations.sh next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0

pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

DIGEST=sha256:44e433bc856b5e8dceb63b803e5ff1d96b0584fbfe3ea676d5d52592555ca333

# One image by default, so a case's output is small enough to read. The
# multi-image and suspended-image behaviours get their own cases.
ONE_IMAGE='backend=ghcr.io/artifact-keeper/artifact-keeper-backend'

# --- stubs -----------------------------------------------------------------
STUB="$WORK/bin"; mkdir -p "$STUB"

# The tag -> digest probe. Answers from FAKE_DIGEST_ANSWER and records every
# (registry, repository, tag) triple it was asked about, which is how the
# scanner-adapter cases assert on the TAG the audit chose.
cat > "$STUB/digest-probe" <<'STUBDIGEST'
#!/usr/bin/env bash
echo "$1 $2 $3" >> "$FAKE_STATE/digest.calls"
answer="${FAKE_DIGEST_ANSWER:-sha256:44e433bc856b5e8dceb63b803e5ff1d96b0584fbfe3ea676d5d52592555ca333}"
# Per-image override: FAKE_DIGEST_ANSWER_<key-with-dashes-as-underscores>
suffix="${2##*-}"
var="FAKE_DIGEST_ANSWER_${suffix//-/_}"
[ -n "${!var-}" ] && answer="${!var}"
echo "$answer"
case "$answer" in sha256:*) exit 0 ;; *) exit 1 ;; esac
STUBDIGEST
chmod +x "$STUB/digest-probe"

# The #3559 signature gate. Replays an exit code: 0 signed, 1 unsigned
# (BLOCK), 2 infrastructure.
cat > "$STUB/sig-gate" <<'STUBSIG'
#!/usr/bin/env bash
echo "$*" >> "$FAKE_STATE/sig.calls"
echo "  stub signature gate for $*"
exit "${FAKE_SIG_RC:-0}"
STUBSIG
chmod +x "$STUB/sig-gate"

# `gh attestation verify`. Replays gh's two shapes: a JSON array of bundles
# carrying in-toto statements, or a nonzero exit with an error message.
cat > "$STUB/gh" <<'STUBGH'
#!/usr/bin/env bash
# `gh --version` and the `attestation verify --help` capability probe answer
# first and are not recorded: they are how the audit decides whether this gh
# can verify at all, not part of the verdict.
if [ "${FAKE_GH_NO_ATTESTATION:-0}" = "1" ]; then
  echo 'unknown command "attestation" for "gh"' >&2
  exit 1
fi
[ "$1" = "--version" ] && { echo "gh version 2.99.0 (stub)"; exit 0; }
case " $* " in *" --help "*) exit 0 ;; esac
printf '%s\n' "$*" >> "$FAKE_STATE/gh.calls"
[ "$1" = "attestation" ] && [ "$2" = "verify" ] || { echo "unexpected gh invocation: $*" >&2; exit 99; }
if [ -n "${FAKE_GH_ERR-}" ]; then
  printf '%s\n' "$FAKE_GH_ERR" >&2
  exit "${FAKE_GH_RC:-1}"
fi
cat <<JSON
[{"attestation":{"bundle":{"dsseEnvelope":{}}},"verificationResult":{"statement":{"_type":"https://in-toto.io/Statement/v1","predicateType":"${FAKE_GH_PREDICATE:-https://slsa.dev/provenance/v1}","predicate":{"buildDefinition":{}}}}}]
JSON
STUBGH
chmod +x "$STUB/gh"

# <label> <expected-exit> <expected-substring>
# The scenario comes from the FAKE_* / CASE_* variables the caller set.
expect() {
  local label="$1" want="$2" needle="$3" got=0
  rm -f "$WORK/gh.calls" "$WORK/sig.calls" "$WORK/digest.calls"

  # Deliberate word split: a case may pass no tags at all (" ") or several,
  # and they must reach the audit as separate arguments.
  # shellcheck disable=SC2206
  local -a tags=( ${CASE_TAGS-1.9.0} )

  (
    export PATH="$STUB:$PATH"
    export FAKE_STATE="$WORK"
    export FAKE_DIGEST_ANSWER="${FAKE_DIGEST_ANSWER:-$DIGEST}"
    export FAKE_SIG_RC="${FAKE_SIG_RC:-0}"
    export FAKE_GH_RC="${FAKE_GH_RC:-1}"
    export FAKE_GH_ERR="${FAKE_GH_ERR-}"
    export FAKE_GH_PREDICATE="${FAKE_GH_PREDICATE:-https://slsa.dev/provenance/v1}"
    export FAKE_GH_NO_ATTESTATION="${FAKE_GH_NO_ATTESTATION:-0}"
    export AK_AUDIT_DIGEST_CMD="$STUB/digest-probe"
    export AK_AUDIT_SIG_CMD="$STUB/sig-gate"
    export AK_AUDIT_IMAGES="${CASE_IMAGES:-$ONE_IMAGE}"
    [ -n "${FAKE_DIGEST_ANSWER_adapter+set}" ] && export FAKE_DIGEST_ANSWER_adapter
    [ -n "${CASE_ADAPTER_TAG+set}" ] && export AK_AUDIT_ADAPTER_TAG="$CASE_ADAPTER_TAG"
    [ -n "${CASE_IDENTITY+set}" ] && export AK_AUDIT_IDENTITY_REGEXP="$CASE_IDENTITY"
    [ -n "${CASE_OWNER+set}" ] && export AK_AUDIT_OWNER="$CASE_OWNER"
    [ -n "${CASE_SIGNER_WORKFLOW+set}" ] && export AK_AUDIT_SIGNER_WORKFLOW="$CASE_SIGNER_WORKFLOW"
    bash "$AUDIT" "${tags[@]}" >"$WORK/out.txt" 2>&1
  ) || got=$?

  if [ "$got" != "$want" ]; then
    fail "$label: expected exit $want, got $got"
    sed 's/^/        /' "$WORK/out.txt" | head -25
    return
  fi
  if [ -n "$needle" ] && ! grep -qF -- "$needle" "$WORK/out.txt"; then
    fail "$label: exit $got correct but output lacks '$needle'"
    sed 's/^/        /' "$WORK/out.txt" | head -25
    return
  fi
  pass "$label"
}

reset() {
  unset FAKE_DIGEST_ANSWER FAKE_SIG_RC FAKE_GH_RC FAKE_GH_ERR FAKE_GH_PREDICATE FAKE_GH_NO_ATTESTATION
  unset FAKE_DIGEST_ANSWER_adapter FAKE_DIGEST_ANSWER_backend FAKE_DIGEST_ANSWER_alpine
  unset CASE_TAGS CASE_IMAGES CASE_ADAPTER_TAG CASE_IDENTITY CASE_OWNER CASE_SIGNER_WORKFLOW
}

echo "audit-published-attestations.sh"

# ---------------------------------------------------------------------------
# Argument parsing. Every leg here exits 2 (could not ask), never 1: none of
# them is a statement about an image.
# ---------------------------------------------------------------------------
reset
CASE_TAGS=" "
expect "no tags at all is refused, not a vacuous pass" 2 "An audit with nothing to audit"

reset
CASE_TAGS="--owner"
expect "an unknown option is refused" 2 "is not an option this script takes"

reset
CASE_TAGS="sha256:deadbeef"
expect "a digest argument is refused (the audit starts from tags)" 2 "names a digest"

reset
CASE_TAGS="ghcr.io/artifact-keeper/artifact-keeper-backend:1.9.0"
expect "an image reference is refused" 2 "is not a bare tag"

reset
CASE_TAGS="1.9.0@sha256:deadbeef"
expect "a tag with a digest suffix is refused" 2 "names a digest"

reset
CASE_IDENTITY='.*'
expect "a vacuous identity pattern is a configuration error" 2 "matches any signer"

reset
CASE_OWNER=''
expect "an empty --owner is a configuration error" 2 "AK_AUDIT_OWNER is empty"

# ---------------------------------------------------------------------------
# The pass/fail decision, one case per way a digest can be incomplete.
# ---------------------------------------------------------------------------
reset
expect "provenance + signature -> pass" 0 "provenance=yes  signature=yes"

reset
FAKE_GH_RC=1
FAKE_GH_ERR="Error: no attestations found for subject"
expect "signed but NO provenance BLOCKS (#3519's shape)" 1 "provenance=no  signature=yes"

reset
FAKE_SIG_RC=1
expect "provenance but NO signature BLOCKS (#2824's shape)" 1 "provenance=yes  signature=no"

reset
FAKE_GH_RC=1
FAKE_GH_ERR="Error: no attestations found for subject"
FAKE_SIG_RC=1
expect "neither attached BLOCKS" 1 "provenance=no  signature=no"

# gh exits 0 but its JSON carries a predicate type that is not the one we
# asked for. `--predicate-type` should have filtered it, so this is a tooling
# change, not a verdict: INFRA, never a pass.
reset
FAKE_GH_PREDICATE="https://github.com/artifact-keeper/artifact-keeper/attestations/release-candidate/v1"
expect "a predicate of the wrong type is not counted as provenance" 2 "could not measure"

# ---------------------------------------------------------------------------
# Infrastructure is not tampering. Each of these must exit 2.
# ---------------------------------------------------------------------------
reset
FAKE_GH_RC=1
FAKE_GH_ERR="error connecting to api.github.com: dial tcp: i/o timeout"
expect "attestations API outage is INFRA, not a missing predicate" 2 "could not measure"

# `gh attestation` arrived in gh 2.49. An older gh exits NONZERO with
# `unknown command`, which read as a verdict reports every digest on the
# runner as unattested -- a supply-chain finding caused by a tool version, on
# a red release job. It must be one clear infrastructure line instead.
reset
FAKE_GH_NO_ATTESTATION=1
expect "a gh with no 'attestation' command is INFRA, not a verdict" 2 "no 'attestation verify' command"

# Same distinction for a token that was not allowed to look. "I could not
# ask" is not "there is nothing there".
reset
FAKE_GH_RC=1
FAKE_GH_ERR="HTTP 401: Bad credentials (https://api.github.com/orgs/artifact-keeper/attestations/sha256:...)"
expect "an unauthenticated attestations read is INFRA" 2 "could not measure"

reset
FAKE_SIG_RC=2
expect "a Sigstore/registry outage in the signature gate is INFRA" 2 "could not measure"

reset
FAKE_DIGEST_ANSWER="indeterminate"
expect "an unreadable registry is INFRA, never absence" 2 "NOT a statement about the image"

# A tag that is definitively absent IS about the image: nothing for a user to
# pull, and nothing to audit.
reset
FAKE_DIGEST_ANSWER="absent"
expect "a missing manifest on a live image BLOCKS" 1 "does not resolve"

# ...unless the image is one docker-publish.yml has suspended (`if: false`),
# where absence is the expected state and must not redden an audit.
reset
CASE_IMAGES='backend-alpine=ghcr.io/artifact-keeper/artifact-keeper-backend-alpine=suspended'
FAKE_DIGEST_ANSWER="absent"
expect "a suspended image with no manifest is skipped, not failed" 0 "image suspended in docker-publish.yml"

# The alpine package may not EXIST on ghcr at all, which the probe reports as
# `indeterminate` (it proves read access before believing a 404). That must
# also skip -- otherwise every release cut goes red on an image this workflow
# deliberately does not build.
reset
CASE_IMAGES='backend-alpine=ghcr.io/artifact-keeper/artifact-keeper-backend-alpine=suspended'
FAKE_DIGEST_ANSWER="indeterminate"
expect "a suspended image whose package does not exist is skipped" 0 "image suspended in docker-publish.yml"

# But a suspended image that DOES publish gets the full check, so re-enabling
# the alpine jobs needs no edit here.
reset
CASE_IMAGES='backend-alpine=ghcr.io/artifact-keeper/artifact-keeper-backend-alpine=suspended'
FAKE_SIG_RC=1
expect "a suspended image that resolves is still audited" 1 "provenance=yes  signature=no"

# ---------------------------------------------------------------------------
# The scanner-adapter is independently versioned: asking it for the AK release
# version would report every release as missing.
# ---------------------------------------------------------------------------
ADAPTER='scanner-adapter=ghcr.io/artifact-keeper/artifact-keeper-scanner-adapter'

reset
CASE_IMAGES="$ADAPTER"
CASE_ADAPTER_TAG="0.4.7"
expect "the adapter is audited at its own version" 0 "provenance=yes  signature=yes"
if grep -q ' artifact-keeper/artifact-keeper-scanner-adapter 0.4.7$' "$WORK/digest.calls"; then
  pass "the adapter was asked for 0.4.7, not the AK release version"
else
  fail "the adapter was asked for the wrong tag: $(tr '\n' ';' < "$WORK/digest.calls")"
fi

# An empty AK_AUDIT_ADAPTER_TAG means "this release publishes no adapter tag"
# -- the prerelease case `verify-published` already special-cases. It must
# skip, not fail, and must not touch the registry for that image.
reset
CASE_IMAGES="$ADAPTER"
CASE_ADAPTER_TAG=""
expect "an empty adapter tag skips the adapter instead of failing it" 0 "the adapter publishes no tag for this release"
if [ -f "$WORK/digest.calls" ]; then
  fail "the adapter was probed anyway: $(tr '\n' ';' < "$WORK/digest.calls")"
else
  pass "a skipped adapter is not probed at all"
fi

# ---------------------------------------------------------------------------
# Reporting: the audit answers about everything it was asked, and one bad
# digest does not hide the rest.
# ---------------------------------------------------------------------------
reset
CASE_TAGS="1.9.0 latest"
expect "several tags are audited in one run" 0 "complete (provenance + signature): 2"

reset
CASE_IMAGES="$ONE_IMAGE $ADAPTER"
CASE_ADAPTER_TAG="0.4.7"
FAKE_DIGEST_ANSWER_adapter="absent"
expect "one missing image does not stop the others being audited" 1 "complete (provenance + signature): 1"

# The pin the gate stands on: the owner and predicate type actually reach gh.
reset
expect "the audit runs at all" 0 "provenance=yes"
if grep -q -- '--owner artifact-keeper' "$WORK/gh.calls" \
   && grep -q -- '--predicate-type https://slsa.dev/provenance/v1' "$WORK/gh.calls"; then
  pass "gh attestation verify is pinned to the owner and the build-provenance predicate"
else
  fail "gh was not pinned: $(cat "$WORK/gh.calls")"
fi

# `--signer-workflow` is off by default (it would have to match every
# attestation ever pushed, including ones from before #3518). When it is set
# it must reach gh, so the pin can be turned on without a code change.
reset
CASE_SIGNER_WORKFLOW="artifact-keeper/artifact-keeper/.github/workflows/docker-publish.yml"
expect "the optional signer-workflow pin does not break the audit" 0 "provenance=yes"
if grep -q -- '--signer-workflow artifact-keeper/artifact-keeper/.github/workflows/docker-publish.yml' "$WORK/gh.calls"; then
  pass "AK_AUDIT_SIGNER_WORKFLOW reaches gh when set"
else
  fail "AK_AUDIT_SIGNER_WORKFLOW did not reach gh: $(cat "$WORK/gh.calls")"
fi

echo ""
if [ "$fails" -gt 0 ]; then
  echo "FAILED: $fails case(s)"
  exit 1
fi
echo "OK: every case behaved (including all ${0##*/} BLOCK and INFRA legs)."
