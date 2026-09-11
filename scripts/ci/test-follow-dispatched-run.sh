#!/usr/bin/env bash
#
# Self-test for scripts/ci/follow-dispatched-run.sh (issues #3771, #3772).
#
# The follower decides which run a dispatch produced and whether it passed.
# Both directions are dangerous: following a run on another ref, or an older
# dispatch on the same ref, would let a stale green vouch for a new dispatch;
# and a non-success conclusion must never read as a pass. Stubs `gh` with a
# canned run list and per-run status; no network, ~1s.
#
# Usage: bash scripts/ci/test-follow-dispatched-run.sh
set -uo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/follow-dispatched-run.sh"
[ -f "$SCRIPT" ] || { echo "cannot find follow-dispatched-run.sh next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

STUB="$WORK/bin"; mkdir -p "$STUB"
# FAKE_RUNS: TSV rows `id \t head_branch \t head_sha \t created_at`.
# FAKE_STATUS_<id>: "<status> <conclusion>" for the run poll.
cat > "$STUB/gh" <<'STUBGH'
#!/usr/bin/env bash
[ "$1" = "api" ] || exit 64
case "$2" in
  *actions/workflows/*/runs*)
    [ "${FAKE_LIST_FAIL:-0}" = "1" ] && exit 1
    [ -n "${FAKE_RUNS-}" ] && printf '%s\n' "$FAKE_RUNS"
    exit 0 ;;
  *actions/runs/*)
    id="${2##*/runs/}"
    var="FAKE_STATUS_${id}"
    printf '%s\n' "${!var:-completed success}"
    exit 0 ;;
esac
exit 64
STUBGH
chmod +x "$STUB/gh"

SHA_A=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
SHA_B=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
T0=2026-09-08T10:00:00Z
T1=2026-09-08T10:05:00Z
T2=2026-09-08T10:06:00Z

# <label> <expected-exit> <expected-stdout>
expect() {
  local label="$1" want_rc="$2" want_out="$3" got_out got_rc=0
  got_out="$(PATH="$STUB:$PATH" FOLLOW_REPO=o/r FOLLOW_WORKFLOW=docker-publish.yml \
    FOLLOW_POLL_SECONDS=0 FOLLOW_APPEAR_SECONDS="${APPEAR:-1}" \
    bash "$SCRIPT" 2>/dev/null)" || got_rc=$?
  if [ "$got_rc" = "$want_rc" ] && [ "$got_out" = "$want_out" ]; then
    pass "$label"
  else
    fail "$label (wanted rc=${want_rc} '${want_out}', got rc=${got_rc} '${got_out}')"
  fi
}

echo "follow-dispatched-run.sh self-test"

# 1. the plain case
FAKE_RUNS="$(printf '101\tmain\t%s\t%s' "$SHA_A" "$T1")" \
FOLLOW_REF=main FOLLOW_SINCE="$T0" \
  expect "one matching run, success -> exit 0" 0 "run_id=101 conclusion=success"

# 2. a run on another ref is not ours
FAKE_RUNS="$(printf '101\tv1.9.0\t%s\t%s' "$SHA_A" "$T1")" \
FOLLOW_REF=main FOLLOW_SINCE="$T0" \
  expect "run on a different ref -> never appears (exit 21)" 21 "run_id= state=none"

# 3. an older dispatch on the same ref is not ours
FAKE_RUNS="$(printf '100\tmain\t%s\t2026-09-08T09:00:00Z' "$SHA_A")" \
FOLLOW_REF=main FOLLOW_SINCE="$T0" \
  expect "run created before SINCE -> exit 21" 21 "run_id= state=none"

# 4. newest match wins
FAKE_RUNS="$(printf '101\tmain\t%s\t%s\n102\tmain\t%s\t%s' "$SHA_A" "$T1" "$SHA_A" "$T2")" \
FOLLOW_REF=main FOLLOW_SINCE="$T0" FAKE_STATUS_101="completed failure" \
  expect "two matches -> the newest is followed" 0 "run_id=102 conclusion=success"

# 5. a failed conclusion is a failure, stated
FAKE_RUNS="$(printf '101\tmain\t%s\t%s' "$SHA_A" "$T1")" \
FOLLOW_REF=main FOLLOW_SINCE="$T0" FAKE_STATUS_101="completed failure" \
  expect "run concluded failure -> exit 1" 1 "run_id=101 conclusion=failure"

# 6. head_sha filter
FAKE_RUNS="$(printf '101\tmain\t%s\t%s' "$SHA_B" "$T1")" \
FOLLOW_REF=main FOLLOW_SINCE="$T0" FOLLOW_SHA="$SHA_A" \
  expect "head_sha mismatch -> exit 21" 21 "run_id= state=none"

# 7. API down for the whole appear window -> INFRA, not "never started"
FAKE_LIST_FAIL=1 FOLLOW_REF=main FOLLOW_SINCE="$T0" \
  expect "listing API failing -> exit 30" 30 "run_id= state=infra"

# 8. find-only mode
FAKE_RUNS="$(printf '101\tmain\t%s\t%s' "$SHA_A" "$T1")" \
FOLLOW_REF=main FOLLOW_SINCE="$T0" FOLLOW_WAIT=false \
  expect "FOLLOW_WAIT=false -> found, exit 0" 0 "run_id=101 status=found"

# 9. missing configuration is INFRA
FOLLOW_REF="" FOLLOW_SINCE="$T0" \
  expect "no FOLLOW_REF -> exit 30" 30 "run_id= state=infra"

echo
if [ "$fails" -eq 0 ]; then echo "all follow-dispatched-run.sh cases passed"; exit 0; fi
echo "${fails} follow-dispatched-run.sh case(s) FAILED"; exit 1
