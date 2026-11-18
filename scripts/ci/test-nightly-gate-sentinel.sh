#!/usr/bin/env bash
#
# Self-test for scripts/ci/nightly-gate-sentinel.sh (#6073).
#
# The sentinel is what makes a release candidate outrank the nightly gate on
# the shared pool. Both directions matter: missing a candidate leaves it
# queued behind an advisory run for hours, and cancelling on an API error or
# on a COMPLETED candidate throws away a night for nothing. Stubs `gh`;
# offline, ~1s.
#
# Usage: bash scripts/ci/test-nightly-gate-sentinel.sh
set -uo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/nightly-gate-sentinel.sh"
[ -f "$SCRIPT" ] || { echo "cannot find nightly-gate-sentinel.sh next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

STUB="$WORK/bin"; mkdir -p "$STUB"
# FAKE_RC_RUNS: lines "<id> <status> <url>" for non-completed candidate runs
#               (the stub applies no filter: the script's --jq is not run).
# FAKE_LIST_FAIL=1: listing candidate runs fails.
# FAKE_JOBS: job names of the nightly run, one per line.
# Every call is logged to $WORK/calls.
cat > "$STUB/gh" <<'STUBGH'
#!/usr/bin/env bash
echo "$*" >> "$FAKE_LOG"
[ "$1" = "api" ] || exit 64
shift
if [ "$1" = "-X" ]; then
  [ "$2" = "POST" ] && [[ "$3" == */cancel ]] && exit 0
  exit 64
fi
[ "$1" = "--paginate" ] && shift
case "$1" in
  *actions/workflows/*/runs*)
    [ "${FAKE_LIST_FAIL:-0}" = "1" ] && exit 1
    [ -n "${FAKE_RC_RUNS-}" ] && printf '%s\n' "$FAKE_RC_RUNS"
    exit 0 ;;
  *actions/runs/*/jobs*)
    [ -n "${FAKE_JOBS-}" ] && printf '%s\n' "$FAKE_JOBS"
    exit 0 ;;
esac
exit 64
STUBGH
chmod +x "$STUB/gh"

run() { # <mode> -> sets OUT, RC; env passes through
  : > "$WORK/calls"
  RC=0
  OUT="$(PATH="$STUB:$PATH" FAKE_LOG="$WORK/calls" SENTINEL_REPO=o/r SENTINEL_POLL_SECONDS=0 \
    GITHUB_OUTPUT='' GITHUB_STEP_SUMMARY='' bash "$SCRIPT" "$1" 2>/dev/null)" || RC=$?
}
check() { # <label> <want-rc> <want-substring-in-stdout>
  if [ "$RC" = "$2" ] && [[ "$OUT" == *"$3"* ]]; then pass "$1"; else fail "$1 (rc=$RC out='$OUT')"; fi
}
cancelled() { grep -q -- '-X POST repos/o/r/actions/runs/77/cancel' "$WORK/calls"; }

echo "--once"
FAKE_RC_RUNS='' run --once
check "no candidate in flight: clear" 0 "outranked=false"
FAKE_RC_RUNS='900 queued https://x/runs/900' run --once
check "queued candidate outranks" 3 "outranked_by=https://x/runs/900"
FAKE_RC_RUNS='901 in_progress https://x/runs/901' run --once
check "running candidate outranks" 3 "outranked=true"
FAKE_LIST_FAIL=1 run --once
check "API error is INFRA, not a skip" 30 "outranked=false"
SENTINEL_WATCH="a.yml b.yml" FAKE_RC_RUNS='' run --once
if [ "$(grep -c 'actions/workflows/' "$WORK/calls")" = 2 ]; then pass "every watched workflow is read"; else fail "watched workflows: $(cat "$WORK/calls")"; fi

echo "--watch"
FAKE_RC_RUNS='902 queued https://x/runs/902' SENTINEL_RUN_ID=77 SENTINEL_DONE_JOB=Report run --watch
check "candidate appears: pre-empted" 0 "result=preempted"
if cancelled; then pass "pre-emption cancels the nightly run"; else fail "no cancel call: $(cat "$WORK/calls")"; fi

FAKE_RC_RUNS='' FAKE_JOBS=$'Gate [main] / deploy\nReport' SENTINEL_DONE_EVERY=1 SENTINEL_RUN_ID=77 SENTINEL_DONE_JOB=Report run --watch
check "report job exists: done" 0 "result=done"
if ! cancelled; then pass "done does not cancel"; else fail "cancelled on done"; fi

FAKE_RC_RUNS='' FAKE_JOBS=$'Gate [main] / deploy\nReport nightly' SENTINEL_DONE_EVERY=1 SENTINEL_BUDGET_SECONDS=0 SENTINEL_RUN_ID=77 SENTINEL_DONE_JOB=Report run --watch
check "a job merely starting with the done name is not done; budget hands over" 0 "result=handoff"

FAKE_LIST_FAIL=1 SENTINEL_BUDGET_SECONDS=0 SENTINEL_RUN_ID=77 SENTINEL_DONE_JOB=Report run --watch
check "API error never cancels" 0 "result=handoff"
if ! cancelled; then pass "no cancel on API error"; else fail "cancelled on API error"; fi

SENTINEL_RUN_ID=abc SENTINEL_DONE_JOB=Report run --watch
check "bad run id is a usage error" 2 ""
run --bogus
check "unknown mode is a usage error" 2 ""

echo
if [ "$fails" -ne 0 ]; then echo "$fails check(s) failed"; exit 1; fi
echo "all nightly-gate-sentinel checks passed"
