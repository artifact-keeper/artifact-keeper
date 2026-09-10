#!/usr/bin/env bash
#
# Self-test for scripts/ci/assert-candidate-certified.sh (issues #3771, #3772).
#
# WHY THIS EXISTS
#   This gate is what stands between "a commit's images passed the gate" and
#   every permanent name -- `:X.Y.Z`, the git tag, the GitHub Release. Its
#   failure direction is fail-OPEN, so most cases here assert a refusal:
#   no attestation, an attestation from the wrong workflow or from the right
#   workflow on the wrong ref, one that names another commit, one whose
#   digests no longer match the registry, an image set stitched together from
#   two candidate runs. A digest carrying two certifications (the same commit
#   certified twice) must resolve to the same run on every image, whatever
#   order gh returns them in. A maintenance release is certified FROM MAIN,
#   so the accepted identity never widens -- a case below pins that a
#   certification signed on `release/1.9.x` is still refused -- and the cases
#   around it cover the second control instead: the DERIVED release line the
#   commit belongs to, the predicate's `certified_ref` cross-check against it,
#   and the gate inheriting the resolver's refusal rather than shrugging it
#   off. The
#   registry, the attestations API and the ref resolver are stubbed (a digest
#   probe script, a `gh` on PATH and a resolver script), so this runs offline
#   in ~1s. The resolver's own decisions are tested in
#   scripts/ci/test-resolve-certified-ref.sh.
#
# Usage: bash scripts/ci/test-assert-candidate-certified.sh
set -uo pipefail

GATE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assert-candidate-certified.sh"
[ -f "$GATE" ] || { echo "cannot find assert-candidate-certified.sh next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

SHA_A=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
SHA_B=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
D_BACKEND=sha256:1111111111111111111111111111111111111111111111111111111111111111
D_OPENSCAP=sha256:2222222222222222222222222222222222222222222222222222222222222222
D_ADAPTER=sha256:3333333333333333333333333333333333333333333333333333333333333333
D_OTHER=sha256:9999999999999999999999999999999999999999999999999999999999999999
PTYPE=https://github.com/artifact-keeper/artifact-keeper/attestations/release-candidate/v1

STUB="$WORK/bin"; mkdir -p "$STUB"

# Digest probe stub: answers per image name from FAKE_DIGEST_<key>.
cat > "$STUB/probe" <<'STUBPROBE'
#!/usr/bin/env bash
case "$2" in
  *-backend)         v="${FAKE_DIGEST_backend-}" ;;
  *-openscap)        v="${FAKE_DIGEST_openscap-}" ;;
  *-scanner-adapter) v="${FAKE_DIGEST_adapter-}" ;;
  *) v="" ;;
esac
[ -n "$v" ] || v=indeterminate
echo "$v"
case "$v" in sha256:*) exit 0 ;; *) exit 1 ;; esac
STUBPROBE
chmod +x "$STUB/probe"

# gh stub: `gh attestation verify oci://<img>@<digest> ...`. Enforces the
# cert-identity (exact, case-sensitive: the SAN), source-ref and
# predicate-type pins the way gh does (a pin that is not passed at all is
# refused, so the gate cannot quietly drop one; `--signer-workflow`, whose
# SAN regex carries no ref, is refused outright so it cannot creep back), and
# answers with a JSON envelope of the real shape carrying the predicate from
# FAKE_PREDICATE (or a per-image override FAKE_PREDICATE_<key>). When
# FAKE_PREDICATES_<key> is set to a JSON array, one statement per element is
# returned, in that order -- a digest carrying several certifications.
cat > "$STUB/gh" <<'STUBGH'
#!/usr/bin/env bash
[ "${1:-}" = "attestation" ] && [ "${2:-}" = "verify" ] || { echo "stub gh: unexpected '${1:-} ${2:-}'" >&2; exit 64; }
shift 2
subject=""; identity=""; ptype=""; sref=""
while [ $# -gt 0 ]; do
  case "$1" in
    --signer-workflow) echo "✗ stub: --signer-workflow pins no ref; use --cert-identity" >&2; exit 64 ;;
    --cert-identity)   identity="$2"; shift 2 ;;
    --source-ref)      sref="$2";   shift 2 ;;
    --predicate-type)  ptype="$2";  shift 2 ;;
    --repo|--format)   shift 2 ;;
    oci://*)           subject="$1"; shift ;;
    *)                 shift ;;
  esac
done
[ "${FAKE_GH_NETFAIL:-0}" = "1" ] && { echo 'failed to fetch attestations: dial tcp: i/o timeout' >&2; exit 1; }
[ "${FAKE_GH_NONE:-0}" = "1" ] && { echo '✗ no attestations found for subject' >&2; exit 1; }
actual_signer="${FAKE_GH_SIGNER:-artifact-keeper/artifact-keeper/.github/workflows/release-candidate.yml}"
actual_ref="${FAKE_GH_SOURCE_REF:-refs/heads/main}"
actual_identity="https://github.com/${actual_signer}@${actual_ref}"
[ -n "$identity" ] || { echo "✗ stub: --cert-identity not pinned" >&2; exit 1; }
[ "$identity" = "$actual_identity" ] || { echo "✗ signed by ${actual_identity}, not ${identity}" >&2; exit 1; }
[ -n "$sref" ] || { echo "✗ stub: --source-ref not pinned" >&2; exit 1; }
# gh compares the ref extension case-insensitively (strings.EqualFold); the
# stub does the same, so only the exact SAN pin above can catch `Main`.
[ "$(printf '%s' "$sref" | tr '[:upper:]' '[:lower:]')" = "$(printf '%s' "$actual_ref" | tr '[:upper:]' '[:lower:]')" ] \
  || { echo "✗ signed on ${actual_ref}, not ${sref}" >&2; exit 1; }
[ -n "$ptype" ] || { echo "✗ stub: --predicate-type not pinned" >&2; exit 1; }
case "$subject" in
  *-backend@*)         p="${FAKE_PREDICATE_backend:-$FAKE_PREDICATE}"; list="${FAKE_PREDICATES_backend:-}" ;;
  *-openscap@*)        p="${FAKE_PREDICATE_openscap:-$FAKE_PREDICATE}"; list="${FAKE_PREDICATES_openscap:-}" ;;
  *-scanner-adapter@*) p="${FAKE_PREDICATE_adapter:-$FAKE_PREDICATE}"; list="${FAKE_PREDICATES_adapter:-}" ;;
  *) p="$FAKE_PREDICATE"; list="" ;;
esac
[ -n "$list" ] || list="[$p]"
jq -c --arg t "$ptype" '[.[] | {attestation:{bundle:{}},verificationResult:{statement:{"_type":"https://in-toto.io/Statement/v1",predicateType:$t,subject:[{digest:{sha256:"x"}}],predicate:.}}}]' <<<"$list"
STUBGH
chmod +x "$STUB/gh"

# Ref-resolver stub: the gate must take the ref from here and nowhere else.
# FAKE_RESOLVE_RC lets a case assert that the gate inherits a refusal (1) or a
# measurement failure (2) instead of falling back to a default ref.
cat > "$STUB/resolve" <<'STUBRESOLVE'
#!/usr/bin/env bash
[ "${FAKE_RESOLVE_RC:-0}" = "0" ] || { echo "stub resolver refusing" >&2; exit "${FAKE_RESOLVE_RC}"; }
ref="${FAKE_RESOLVED_REF:-refs/heads/main}"
echo "certified_ref=${ref}"
echo "certified_branch=${ref#refs/heads/}"
STUBRESOLVE
chmod +x "$STUB/resolve"

good_predicate() { # <sha> <run> [certified_ref]  (empty 3rd arg = field absent)
  local ref="${3-refs/heads/main}" extra=""
  [ -n "$ref" ] && extra="$(printf '"certified_ref":"%s",' "$ref")"
  printf '{"commit_sha":"%s","version":"1.9.0",%s"candidate_run_id":"%s","gate_run_id":"777","digests":{"backend":"%s","openscap":"%s","scanner_adapter":"%s"}}' \
    "$1" "$extra" "$2" "$D_BACKEND" "$D_OPENSCAP" "$D_ADAPTER"
}

# <label> <expected-exit> <expected-substring>; scenario from exported env.
expect() {
  local label="$1" want="$2" needle="$3" got=0 out
  out="$( PATH="$STUB:$PATH" \
      CERT_REPO=artifact-keeper/artifact-keeper \
      CERT_SHA="${SHA:-$SHA_A}" \
      CERT_DIGEST_CMD="$STUB/probe" \
      CERT_RESOLVE_CMD="$STUB/resolve" \
      CERT_PREDICATE_TYPE="$PTYPE" \
      GITHUB_OUTPUT="$WORK/out" \
      bash "$GATE" 2>&1 )" || got=$?
  if [ "$got" = "$want" ] && printf '%s' "$out" | grep -qF -- "$needle"; then
    pass "$label"
  else
    fail "$label (wanted exit ${want} containing '${needle}', got exit ${got})"
    printf '%s\n' "$out" | sed 's/^/        /' | tail -n 6
  fi
}

# Baseline scenario: everything consistent.
export FAKE_DIGEST_backend="$D_BACKEND" FAKE_DIGEST_openscap="$D_OPENSCAP" FAKE_DIGEST_adapter="$D_ADAPTER"
export FAKE_PREDICATE; FAKE_PREDICATE="$(good_predicate "$SHA_A" 4242)"
unset FAKE_GH_NETFAIL FAKE_GH_NONE FAKE_GH_SIGNER FAKE_GH_SOURCE_REF FAKE_PREDICATE_backend FAKE_PREDICATE_openscap FAKE_PREDICATE_adapter \
      FAKE_PREDICATES_backend FAKE_PREDICATES_openscap FAKE_PREDICATES_adapter SHA CERT_EXPECT_VERSION \
      FAKE_RESOLVE_RC FAKE_RESOLVED_REF CERT_SOURCE_REF

echo "assert-candidate-certified.sh self-test"

# 1. the pass
: > "$WORK/out"
expect "consistent certification -> CERTIFIED (exit 0)" 0 "CERTIFIED"
if grep -qx "backend_digest=${D_BACKEND}" "$WORK/out" && grep -qx "gate_run_id=777" "$WORK/out" && grep -qx "certified=true" "$WORK/out"; then
  pass "outputs carry the digests and run ids"
else
  fail "outputs missing (got: $(tr '\n' ' ' < "$WORK/out"))"
fi

# 2. version pin
CERT_EXPECT_VERSION=1.9.0 expect "expected version matches -> exit 0" 0 "CERTIFIED"
CERT_EXPECT_VERSION=1.9.1 expect "expected version differs -> BLOCKED" 1 "is for version '1.9.0', but this release is 1.9.1"

# 3. no attestation at all -- the hand-pushed-tag shape
FAKE_GH_NONE=1 expect "no attestation on the digest -> BLOCKED" 1 "carries no release-candidate certification"

# 4. an attestation from a different workflow in the same repo is not a certification
FAKE_GH_SIGNER=artifact-keeper/artifact-keeper/.github/workflows/docker-publish.yml \
  expect "attestation from another workflow -> BLOCKED" 1 "carries no release-candidate certification"

# 4b. the right workflow on the wrong ref: a topic-branch copy of
#     release-candidate.yml (gate removed) attesting main's images
FAKE_GH_SOURCE_REF=refs/heads/wip \
  expect "attestation from the candidate workflow on another ref -> BLOCKED" 1 "carries no release-candidate certification"
# ...including a ref that differs from main only in case: git refs are
# case-sensitive, gh's --source-ref comparison is not, the SAN pin is.
FAKE_GH_SOURCE_REF=refs/heads/Main \
  expect "attestation from the candidate workflow on 'Main' -> BLOCKED" 1 "carries no release-candidate certification"

# 5. certified, but for another commit
FAKE_PREDICATE="$(good_predicate "$SHA_B" 4242)" \
  expect "predicate names another commit -> BLOCKED" 1 "names commit '${SHA_B}', not ${SHA_A}"

# 6. registry moved on since certification
# (a real gh finds no attestation on the new digest at all -- case 3's leg;
# the stub answers for any digest, which exercises the predicate comparison)
FAKE_DIGEST_backend="$D_OTHER" \
  expect "sha tag now serves a different digest -> BLOCKED" 1 "the registry now serves ${D_OTHER}"
# ...and the subtler form: the attestation exists on the new digest (another
# candidate certified it) but its predicate lists the old one for this key.
FAKE_DIGEST_openscap="$D_OTHER" FAKE_PREDICATE_openscap="$(good_predicate "$SHA_A" 4242)" \
  expect "predicate digest differs from the registry -> BLOCKED" 1 "the registry now serves ${D_OTHER}"

# 7. image set stitched from two candidate runs
FAKE_PREDICATE_adapter="$(good_predicate "$SHA_A" 5150)" \
  expect "adapter certified by a different run -> BLOCKED" 1 "certified by ONE run or not at all"

# 7b. two certifications per digest (the same commit certified twice): the
#     highest run common to every image wins, whatever order gh returns them
#     in, so a re-certified commit stays promotable
: > "$WORK/out"
FAKE_PREDICATES_backend="[$(good_predicate "$SHA_A" 4242),$(good_predicate "$SHA_A" 5150)]" \
FAKE_PREDICATES_openscap="[$(good_predicate "$SHA_A" 5150),$(good_predicate "$SHA_A" 4242)]" \
FAKE_PREDICATES_adapter="[$(good_predicate "$SHA_A" 4242),$(good_predicate "$SHA_A" 5150)]" \
  expect "two certifications per digest, both runs on every image -> CERTIFIED by the newest" 0 "candidate run 5150"
if grep -qx "candidate_run_id=5150" "$WORK/out"; then
  pass "outputs name the selected run"
else
  fail "outputs name $(grep candidate_run_id "$WORK/out" || echo nothing)"
fi
# ...the common run is chosen even when it is not the newest everywhere
FAKE_PREDICATES_backend="[$(good_predicate "$SHA_A" 4242),$(good_predicate "$SHA_A" 5150)]" \
FAKE_PREDICATES_openscap="[$(good_predicate "$SHA_A" 4242)]" \
FAKE_PREDICATES_adapter="[$(good_predicate "$SHA_A" 5150),$(good_predicate "$SHA_A" 4242)]" \
  expect "second certification incomplete (one image only) -> CERTIFIED by the run all images share" 0 "candidate run 4242"
# ...a statement for ANOTHER commit on the same bytes is ignored, not fatal
FAKE_PREDICATES_backend="[$(good_predicate "$SHA_B" 9999),$(good_predicate "$SHA_A" 4242)]" \
  expect "another commit's certification listed first -> CERTIFIED by this commit's" 0 "candidate run 4242"
# ...and two runs that never both covered every image are still a refusal
FAKE_PREDICATES_backend="[$(good_predicate "$SHA_A" 4242)]" \
FAKE_PREDICATES_openscap="[$(good_predicate "$SHA_A" 5150)]" \
  expect "no run common to all images -> BLOCKED" 1 "certified by ONE run or not at all"

# 8. the sha images do not exist (docs-only tip, or deleted)
FAKE_DIGEST_backend=absent \
  expect "sha tag absent -> BLOCKED, names #3629" 1 "does not exist"

# 9. measurement failures are INFRA, never a pass
FAKE_DIGEST_backend=indeterminate \
  expect "registry unreadable -> INFRA (exit 2)" 2 "could not read"
FAKE_GH_NETFAIL=1 \
  expect "attestations API unreachable -> INFRA (exit 2)" 2 "could not reach"

# 10. a predicate with no provenance of its own
FAKE_PREDICATE='{"commit_sha":"'"$SHA_A"'","version":"1.9.0","digests":{"backend":"'"$D_BACKEND"'","openscap":"'"$D_OPENSCAP"'","scanner_adapter":"'"$D_ADAPTER"'"}}' \
  expect "predicate without a candidate run id -> BLOCKED" 1 "names no candidate run id"

# 11. bad input
SHA=abc expect "malformed CERT_SHA -> INFRA (exit 2)" 2 "40-character"

# ── the DERIVED release line (maintenance-branch candidates) ───────────────
# A patch release is certified FROM MAIN, so the accepted identity is
# unchanged: `...release-candidate.yml@refs/heads/main`, whatever line the
# commit is on. What the line decides is which commits main may certify, and
# the predicate's certified_ref is checked against it.
export FAKE_RESOLVED_REF=refs/heads/release/1.9.x
FAKE_PREDICATE="$(good_predicate "$SHA_A" 4242 refs/heads/release/1.9.x)"
expect "a release/1.9.x commit certified from main -> accepted" 0 "release-candidate.yml@refs/heads/main"

# THE POINT of certifying from main: a copy of release-candidate.yml on a
# release branch signs with an identity nothing accepts, so the "create a
# release/* ref and put an edited workflow on it" attack has no identity to
# reach for -- it is refused by the same unwidened pin that refuses any other
# branch, not by a widened one that has to be argued about.
export FAKE_GH_SOURCE_REF=refs/heads/release/1.9.x
expect "a certification signed on release/1.9.x is refused, pin unwidened" 1 "carries no release-candidate certification"
unset FAKE_GH_SOURCE_REF

# The predicate records the line the signer resolved; the repository is asked
# the same question again at promote time. A disagreement is never promoted.
FAKE_PREDICATE="$(good_predicate "$SHA_A" 4242 refs/heads/main)"
expect "predicate certified_ref disagreeing with the derived line is refused" 1 "disagree about which line"

FAKE_PREDICATE="$(good_predicate "$SHA_A" 4242 "")"
expect "a maintenance-line certification with no certified_ref is refused" 1 "must record the line"

# Certifications minted before certified_ref existed stay promotable, but only
# for main, where the line could not have been anything else.
export FAKE_RESOLVED_REF=refs/heads/main
expect "a legacy main certification with no certified_ref still passes" 0 "predates certified_ref"

# The gate inherits the resolver's verdict -- which is where the content pin
# on release-candidate.yml is enforced -- and never shrugs it off.
FAKE_PREDICATE="$(good_predicate "$SHA_A" 4242)"
export FAKE_RESOLVE_RC=1
expect "a refused resolver blocks the gate (exit 1)" 1 "no line that may be released"
export FAKE_RESOLVE_RC=2
expect "an unmeasurable resolver is INFRA (exit 2), never a pass" 2 "could not resolve which line"
unset FAKE_RESOLVE_RC FAKE_RESOLVED_REF

echo
if [ "$fails" -eq 0 ]; then echo "all assert-candidate-certified.sh cases passed"; exit 0; fi
echo "${fails} assert-candidate-certified.sh case(s) FAILED"; exit 1
