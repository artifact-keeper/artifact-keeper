#!/usr/bin/env bash
#
# Self-test for scripts/ci/assert-preflight-evidence.sh (issue #3538).
#
# WHY THIS EXISTS
#   The gate under test says "no release without a green preflight for this
#   exact commit". A gate nobody has watched fail is not a gate -- that is the
#   finding this whole change came from, twice over (#3429 / v1.7.5: preflight
#   check 4 existed and was never run; v1.7.7: the preflight ran, said the
#   verdict did not exist yet, and the tag went out 18 minutes later). So each
#   leg is exercised here, including every leg that must BLOCK.
#
#   The dangerous direction is fail-OPEN, so most cases below assert a nonzero
#   exit. Two of them are the ones that would be tempting to write as passes:
#     * an in-flight preflight run (case 2/3) -- the exact v1.7.7 shape;
#     * a green run whose evidence names a DIFFERENT commit (case 7) -- the
#       v1.7.5/6/7 shape, where `ref: main` was hardcoded and the transcript
#       was about another branch.
#   Revert either branch of the script to a pass and those cases go red.
#
# HOW
#   The gate reaches GitHub only through `gh`, so a stub `gh` first on PATH
#   replays canned Actions API answers. No network, no repo state, ~1s. The
#   annotated tag message is injected through GATE_TAG_MESSAGE for the same
#   reason.
#
# Usage: bash scripts/ci/test-assert-preflight-evidence.sh
set -uo pipefail

GATE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assert-preflight-evidence.sh"
[ -f "$GATE" ] || { echo "cannot find assert-preflight-evidence.sh next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0

pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

SHA_A=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
SHA_B=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

# --- gh stub ---------------------------------------------------------------
# Replays three endpoints:
#   .../actions/workflows/<wf>/runs?head_sha=...   -> $FAKE_RUNS (TSV rows;
#        id \t status \t conclusion \t created_at \t event), or a failure when
#        FAKE_RUNS_FAIL=1.
#   .../actions/runs/<id>/artifacts               -> $FAKE_ARTIFACTS (one name
#        per line), or a failure when FAKE_ARTIFACTS_FAIL=1.
#   git/ref/tags, git/tags                        -> not used; the tests inject
#        the tag message directly so the override cases stay offline.
STUB="$WORK/bin"; mkdir -p "$STUB"
cat > "$STUB/gh" <<'STUBGH'
#!/usr/bin/env bash
case "$1" in
  api)
    case "$2" in
      *actions/workflows/*/runs*)
        [ "${FAKE_RUNS_FAIL-0}" = "1" ] && exit 1
        [ -n "${FAKE_RUNS-}" ] && printf '%s\n' "$FAKE_RUNS"
        exit 0
        ;;
      *actions/runs/*/artifacts*)
        [ "${FAKE_ARTIFACTS_FAIL-0}" = "1" ] && exit 1
        [ -n "${FAKE_ARTIFACTS-}" ] && printf '%s\n' "$FAKE_ARTIFACTS"
        exit 0
        ;;
    esac
    ;;
esac
exit 0
STUBGH
chmod +x "$STUB/gh"

# <label> <expected-exit> <expected-substring>
# Reads the scenario from FAKE_* / GATE_* already exported by the caller.
expect() {
  local label="$1" want="$2" needle="$3" got=0
  ( PATH="$STUB:$PATH" \
      GATE_REPO=artifact-keeper/artifact-keeper \
      GATE_SHA="${CASE_SHA:-$SHA_A}" \
      GATE_TAG="${CASE_TAG:-v9.9.9}" \
      GATE_TAG_MESSAGE="${CASE_TAG_MESSAGE-}" \
      FAKE_RUNS="${FAKE_RUNS-}" \
      FAKE_RUNS_FAIL="${FAKE_RUNS_FAIL-0}" \
      FAKE_ARTIFACTS="${FAKE_ARTIFACTS-}" \
      FAKE_ARTIFACTS_FAIL="${FAKE_ARTIFACTS_FAIL-0}" \
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

reset_case() {
  FAKE_RUNS=""; FAKE_RUNS_FAIL=0
  FAKE_ARTIFACTS=""; FAKE_ARTIFACTS_FAIL=0
  CASE_SHA="$SHA_A"; CASE_TAG=v9.9.9; CASE_TAG_MESSAGE=""
}

echo "preflight evidence gate: the five legs"

# 1. NO preflight at all. The v1.7.5 shape: the check existed, nobody ran it.
reset_case
expect "no preflight run for the commit -> BLOCKED" 1 \
  "No Release Preflight has ever run against this commit."

# 2. A preflight is running right now. The v1.7.7 shape: a verdict that does
#    not exist yet must not read as a non-blocking one.
reset_case
FAKE_RUNS=$'777\tin_progress\t\t2026-08-20T21:22:33Z\tworkflow_dispatch'
expect "preflight in_progress -> BLOCKED, names the run" 1 \
  "waiting on run 777"

# 3. ...and a green run does not license ignoring a NEWER in-flight one.
reset_case
FAKE_RUNS=$'100\tcompleted\tsuccess\t2026-08-20T10:00:00Z\tworkflow_dispatch\n777\tqueued\t\t2026-08-20T21:22:33Z\tworkflow_dispatch'
FAKE_ARTIFACTS="release-preflight-${SHA_A}"
expect "green run + newer queued run -> BLOCKED" 1 \
  "still 'queued'"

# 4. A red preflight blocks. This is a measurement, not a formality.
reset_case
FAKE_RUNS=$'321\tcompleted\tfailure\t2026-08-20T13:57:24Z\tschedule'
expect "preflight failed -> BLOCKED" 1 \
  "concluded 'failure'"

# 5. A green preflight carrying evidence for THIS commit proceeds.
reset_case
FAKE_RUNS=$'555\tcompleted\tsuccess\t2026-08-21T13:56:49Z\tschedule'
FAKE_ARTIFACTS="release-preflight-${SHA_A}"
expect "green preflight with matching evidence -> PASS" 0 \
  "Green Release Preflight run 555 audited"

echo
echo "run selection: the newest completed measurement decides"

# A green that a later run superseded is not evidence. Checks 1/3/4 measure
# state outside the tree, so the same commit can go red after being green;
# accepting "some green exists" is the revoked "the red is cosmetic" reasoning.
reset_case
FAKE_RUNS=$'100\tcompleted\tsuccess\t2026-08-20T10:00:00Z\tworkflow_dispatch\n200\tcompleted\tfailure\t2026-08-20T20:00:00Z\tschedule'
FAKE_ARTIFACTS="release-preflight-${SHA_A}"
expect "older green superseded by a newer red -> BLOCKED" 1 \
  "run 200"

# The converse, which really happened for 2358355b on 2026-08-17: a red run at
# 21:55 and a green re-run at 22:29 for the same commit. The green wins.
reset_case
FAKE_RUNS=$'100\tcompleted\tfailure\t2026-08-17T21:55:52Z\tworkflow_dispatch\n200\tcompleted\tsuccess\t2026-08-17T22:29:05Z\tworkflow_dispatch'
FAKE_ARTIFACTS="release-preflight-${SHA_A}"
expect "red run then a green re-run -> PASS on the newer" 0 \
  "run 200 audited"

# Ordering is computed from created_at, not taken from the API's response
# order, so a stale-ordered listing cannot flip the verdict.
reset_case
FAKE_RUNS=$'200\tcompleted\tsuccess\t2026-08-17T22:29:05Z\tworkflow_dispatch\n100\tcompleted\tfailure\t2026-08-17T21:55:52Z\tworkflow_dispatch'
FAKE_ARTIFACTS="release-preflight-${SHA_A}"
expect "API order reversed -> still decided by created_at" 0 \
  "run 200 audited"

echo
echo "evidence must name the tree that was audited"

# head_sha is the sha of the ref the run was DISPATCHED on. A green run with
# no evidence artifact predates this gate, or audited something else.
reset_case
FAKE_RUNS=$'555\tcompleted\tsuccess\t2026-08-21T13:56:49Z\tschedule'
FAKE_ARTIFACTS=""
expect "green run with no evidence artifact -> BLOCKED" 1 \
  "carries no evidence that it audited"

# The v1.7.5/6/7 shape: `ref: main` was hardcoded, so a run dispatched from a
# release branch produced a READY transcript about main. head_sha would match;
# the audited tree would not.
reset_case
FAKE_RUNS=$'555\tcompleted\tsuccess\t2026-08-21T13:56:49Z\tschedule'
FAKE_ARTIFACTS="release-preflight-${SHA_B}"
expect "evidence names a DIFFERENT commit -> BLOCKED" 1 \
  "carries no evidence that it audited"

echo
echo "indeterminate is not a pass"

reset_case
FAKE_RUNS_FAIL=1
expect "runs query fails -> INFRA (exit 2)" 2 \
  "Could not query"

reset_case
FAKE_RUNS=$'555\tcompleted\tsuccess\t2026-08-21T13:56:49Z\tschedule'
FAKE_ARTIFACTS_FAIL=1
expect "artifact listing fails -> INFRA (exit 2)" 2 \
  "Could not list artifacts"

reset_case
CASE_SHA="not-a-sha"
expect "a non-sha commit input -> INFRA (exit 2)" 2 \
  "must be a full 40-character commit sha"

echo
echo "break glass: loud, reasoned, and scoped to one tag"

# The documented hotfix path. It bypasses the readiness verdict and nothing
# else, and it says so in the log.
reset_case
CASE_TAG_MESSAGE=$'Release 9.9.9\n\nPreflight-Override: cut off-branch at 635496d0; preflight was run locally against that exact tree, transcript on #3538'
expect "valid override on a blocked verdict -> PASS" 0 \
  "[OVERRIDDEN]"

reset_case
CASE_TAG_MESSAGE=$'Release 9.9.9\n\nPreflight-Override: cut off-branch at 635496d0; preflight was run locally against that exact tree, transcript on #3538'
expect "an honoured override is annotated as a workflow warning" 0 \
  "::warning title=Release preflight gate overridden::"

reset_case
CASE_TAG_MESSAGE=$'Release 9.9.9\n\nPreflight-Override: cut off-branch at 635496d0; preflight was run locally against that exact tree, transcript on #3538'
expect "an honoured override still prints the verdict it overrode" 0 \
  "No Release Preflight has ever run against this commit."

# `git tag -a -m` hard-wraps what a human types, so a wrapped reason must be
# folded rather than truncated at the first newline -- a half-sentence in the
# audit trail is not a stated reason.
reset_case
CASE_TAG_MESSAGE=$'Release 9.9.9\n\nPreflight-Override: no branch exists to dispatch Release Preflight on\nfor this off-branch commit; run locally against that exact tree, transcript\non #3538\n\nSigned-off-by: someone'
expect "a wrapped override reason is folded, not truncated" 0 \
  "on #3538"

# ...and folding stops at the next trailer, so an unrelated one is not swallowed.
reset_case
CASE_TAG_MESSAGE=$'Release 9.9.9\n\nPreflight-Override: this is a long enough reason to be accepted here\nSigned-off-by: someone'
expect "folding stops at the next trailer" 0 \
  "reason: this is a long enough reason to be accepted here"

# A reason that only reaches the minimum length by folding a continuation line
# is still a reason; a bare key with a wrapped-away nothing is not.
reset_case
CASE_TAG_MESSAGE=$'Release 9.9.9\n\nPreflight-Override:\n\nthis prose is after a blank line and is not part of the trailer'
expect "a blank line ends the trailer -> reason is empty -> BLOCKED" 1 \
  "reason is too short"

# A bypass with no stated reason is the thing being removed, so it must not be
# the easy path.
reset_case
CASE_TAG_MESSAGE=$'Release 9.9.9\n\nPreflight-Override:'
expect "override with an empty reason -> BLOCKED" 1 \
  "reason is too short"

reset_case
CASE_TAG_MESSAGE=$'Release 9.9.9\n\nPreflight-Override: yolo'
expect "override with a token reason -> BLOCKED" 1 \
  "reason is too short"

# "I could not measure" is not a risk anyone can knowingly accept.
reset_case
FAKE_RUNS_FAIL=1
CASE_TAG_MESSAGE=$'Release 9.9.9\n\nPreflight-Override: the registry probe is down for maintenance, accepting the risk'
expect "override cannot convert INFRA into a pass" 2 \
  "cannot override an INFRA result"

# An ordinary tag message is not an override, however it is worded.
reset_case
CASE_TAG_MESSAGE=$'Release 9.9.9\n\nSkipping the preflight override discussion entirely.'
expect "prose mentioning override is not a trailer -> BLOCKED" 1 \
  "No Release Preflight has ever run"

# And an override that was not needed says so instead of pretending it did
# something.
reset_case
FAKE_RUNS=$'555\tcompleted\tsuccess\t2026-08-21T13:56:49Z\tschedule'
FAKE_ARTIFACTS="release-preflight-${SHA_A}"
CASE_TAG_MESSAGE=$'Release 9.9.9\n\nPreflight-Override: belt and braces, this should not be needed at all'
expect "override present but unnecessary -> PASS, and says so" 0 \
  "was not needed"

echo
if [ "$fails" -ne 0 ]; then
  printf '\033[31m%d case(s) failed\033[0m\n' "$fails"
  exit 1
fi
echo "all preflight-evidence gate cases passed"
