#!/usr/bin/env bash
#
# Self-test for scripts/ci/decide-branch-floating-tags.sh (#6080).
#
# The guard may withhold a branch floating tag (`:dev`, `:X.Y-dev`, `:main`)
# ONLY when this run's commit is provably older than the one the tag already
# names. Every other answer -- absent tag, unreadable registry, API failure,
# diverged history, a ref with no probe -- must be "move", which is what the
# workflow did before the guard. Both directions are exercised: a guard that
# never withholds lets an older run move `:dev` backwards; one that withholds
# on doubt freezes `:dev` on an infra blip.
#
# HOW: a stub `gh` answers the compare API, a stub registry-tag-revision.sh
# answers the probe. No network, ~1s.
#
# Usage: bash scripts/ci/test-decide-branch-floating-tags.sh
# shellcheck disable=SC2015  # pass/fail both return 0: `A && pass || fail` is if-then-else here
set -uo pipefail

GUARD="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/decide-branch-floating-tags.sh"
[ -f "$GUARD" ] || { echo "cannot find decide-branch-floating-tags.sh next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

SHA_NEW=1111111111111111111111111111111111111111
SHA_OLD=2222222222222222222222222222222222222222

STUB="$WORK/bin"; mkdir -p "$STUB"
# gh api repos/<r>/compare/<base>...<head> --jq .status  -> $FAKE_COMPARE
cat > "$STUB/gh" <<'STUBGH'
#!/usr/bin/env bash
[ "$1" = api ] || exit 0
case "$2" in
  */compare/*)
    echo "$2" >> "${FAKE_LOG:-/dev/null}"
    [ "${FAKE_COMPARE_FAIL-0}" = 1 ] && exit 1
    echo "${FAKE_COMPARE-}" ;;
esac
exit 0
STUBGH
chmod +x "$STUB/gh"
# registry-tag-revision.sh <registry> <repo> <tag> -> $FAKE_REV (exit 1 unless a sha)
cat > "$WORK/rev.sh" <<'STUBREV'
#!/usr/bin/env bash
echo "$3" >> "${FAKE_PROBE_LOG:-/dev/null}"
echo "${FAKE_REV-none}"
[[ "${FAKE_REV-}" =~ ^[0-9a-f]{40}$ ]]
STUBREV

# <label> <want-move> <want-substring>
expect() {
  local label="$1" want="$2" needle="$3" got=0
  : > "$WORK/gho"
  ( PATH="$STUB:$PATH" GITHUB_OUTPUT="$WORK/gho" \
      FLOATING_SHA="${CASE_SHA:-$SHA_NEW}" FLOATING_REF="${CASE_REF:-refs/heads/main}" \
      FLOATING_REPO=artifact-keeper/artifact-keeper FLOATING_REVISION_CMD="$WORK/rev.sh" \
      FAKE_REV="${FAKE_REV-none}" FAKE_COMPARE="${FAKE_COMPARE-}" FAKE_COMPARE_FAIL="${FAKE_COMPARE_FAIL-0}" \
      FAKE_LOG="$WORK/compare.log" FAKE_PROBE_LOG="$WORK/probe.log" \
      bash "$GUARD" artifact-keeper/artifact-keeper-backend >"$WORK/out.txt" 2>&1 ) || got=$?
  if [ "$got" != 0 ]; then
    fail "$label: expected exit 0, got $got"; sed 's/^/        /' "$WORK/out.txt" >&2
  elif ! grep -qx "move=${want}" "$WORK/gho"; then
    fail "$label: GITHUB_OUTPUT is '$(cat "$WORK/gho")', want move=${want}"; sed 's/^/        /' "$WORK/out.txt" >&2
  elif ! grep -qF -- "$needle" "$WORK/out.txt"; then
    fail "$label: output lacks '$needle'"; sed 's/^/        /' "$WORK/out.txt" >&2
  else
    pass "$label (move=${want})"
  fi
}
reset() {
  FAKE_REV=none; FAKE_COMPARE=""; FAKE_COMPARE_FAIL=0
  CASE_SHA="$SHA_NEW"; CASE_REF=refs/heads/main
  : > "$WORK/compare.log"; : > "$WORK/probe.log"
}

echo "branch floating-tag guard: the legs"

reset; FAKE_REV="$SHA_OLD"; FAKE_COMPARE=ahead
expect "this commit is newer than :dev -> move" true "reason=ahead probe=dev"
grep -qF "compare/${SHA_OLD}...${SHA_NEW}" "$WORK/compare.log" \
  && pass "compare is asked <current>...<this commit>" \
  || fail "compare was not asked ${SHA_OLD}...${SHA_NEW} (got: $(cat "$WORK/compare.log"))"

# THE POINT: an older commit's run finishing last must not move :dev back.
reset; CASE_SHA="$SHA_OLD"; FAKE_REV="$SHA_NEW"; FAKE_COMPARE=behind
expect "this commit is older than :dev -> keep" false "reason=behind"

reset; FAKE_REV="$SHA_NEW"
expect "re-run of the commit :dev already names -> move" true "reason=same-commit"

reset; FAKE_REV="$SHA_OLD"; FAKE_COMPARE=identical
expect "identical trees -> move" true "reason=identical"

reset; FAKE_REV="$SHA_OLD"; FAKE_COMPARE=diverged
expect "diverged history -> move (last writer wins)" true "reason=diverged"

reset; FAKE_REV=none
expect ":dev absent or unannotated -> move" true "reason=probe-none"

reset; FAKE_REV=indeterminate
expect "registry unreadable -> move, never a freeze" true "reason=probe-indeterminate"

reset; FAKE_REV="$SHA_OLD"; FAKE_COMPARE_FAIL=1
expect "compare API down -> move" true "reason=compare-unknown"

reset; CASE_REF=refs/heads/release/1.11.x; FAKE_REV="$SHA_NEW"; CASE_SHA="$SHA_OLD"; FAKE_COMPARE=behind
expect "maintenance line probes its :X.Y-dev and keeps when older" false "probe=1.11-dev"
grep -qx "1.11-dev" "$WORK/probe.log" && pass "release/1.11.x reads :1.11-dev" || fail "probe was '$(cat "$WORK/probe.log")'"

reset; CASE_REF=refs/heads/feature/x
expect "a branch with no probe tag -> move" true "reason=no-probe"
[ -s "$WORK/probe.log" ] && fail "no-probe branch still read the registry" || pass "no-probe branch reads nothing"

reset; CASE_SHA=deadbeef
expect "no full sha -> move" true "reason=no-sha"

echo
if [ "$fails" -gt 0 ]; then echo "${fails} case(s) FAILED"; exit 1; fi
echo "all cases passed"
