#!/usr/bin/env bash
#
# Self-test for scripts/ci/nightly-gate-once.sh (#6155).
#
# The nightly has several scheduled triggers; this script is what keeps them
# to one gate a night. Both directions matter: a backstop that runs anyway
# costs the self-hosted pool a second full gate, and one that skips when no
# gate was reported (the first trigger dropped, skipped for a candidate, or
# pre-empted) loses the night. Stubs `gh`; offline, ~1s. Needs GNU date
# (Linux, or run it in an ubuntu container on macOS).
#
# Usage: bash scripts/ci/test-nightly-gate-once.sh
set -uo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/nightly-gate-once.sh"
[ -f "$SCRIPT" ] || { echo "cannot find nightly-gate-once.sh next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

STUB="$WORK/bin"; mkdir -p "$STUB"
# FAKE_RUNS: lines "<id> <created_at>" (the stub applies no filter).
# FAKE_LIST_FAIL=1: listing runs fails. FAKE_JOBS_FAIL=<id>: that run's jobs fail.
# $WORK/jobs-<id>: lines "<conclusion>\t<name>" for run <id>.
# $WORK/arts-<id>: artifact names of run <id>. FAKE_ARTS_FAIL=<id>: they fail.
# Every call is logged to $WORK/calls.
cat > "$STUB/gh" <<'STUBGH'
#!/usr/bin/env bash
echo "$*" >> "$FAKE_LOG"
[ "$1" = "api" ] || exit 64
shift
[ "$1" = "--paginate" ] && shift
case "$1" in
  *actions/workflows/*/runs*)
    [ "${FAKE_LIST_FAIL:-0}" = "1" ] && exit 1
    [ -n "${FAKE_RUNS-}" ] && printf '%s\n' "$FAKE_RUNS"
    exit 0 ;;
  *actions/runs/*/artifacts*)
    id="${1#*actions/runs/}"; id="${id%%/*}"
    [ "${FAKE_ARTS_FAIL:-}" = "$id" ] && exit 1
    [ -f "$FAKE_DIR/arts-$id" ] && cat "$FAKE_DIR/arts-$id"
    exit 0 ;;
  *actions/runs/*/jobs*)
    id="${1#*actions/runs/}"; id="${id%%/*}"
    [ "${FAKE_JOBS_FAIL:-}" = "$id" ] && exit 1
    [ -f "$FAKE_DIR/jobs-$id" ] && cat "$FAKE_DIR/jobs-$id"
    exit 0 ;;
esac
exit 64
STUBGH
chmod +x "$STUB/gh"

jobs_for() { # <id> <conclusion> <name>...
  local id="$1" c="$2"; shift 2
  : > "$WORK/jobs-$id"
  for n in "$@"; do printf '%s\t%s\n' "$c" "$n" >> "$WORK/jobs-$id"; done
}

# 2026-11-21T07:52:00Z
NOW_TS=1795247520
run() { # sets OUT, ERR, RC; env passes through
  : > "$WORK/calls"
  RC=0
  OUT="$(PATH="$STUB:$PATH" FAKE_LOG="$WORK/calls" FAKE_DIR="$WORK" ONCE_REPO=o/r ONCE_RUN_ID=500 \
    ONCE_NOW="${ONCE_NOW:-$NOW_TS}" GITHUB_OUTPUT='' GITHUB_STEP_SUMMARY='' bash "$SCRIPT" 2>"$WORK/err")" || RC=$?
  ERR="$(cat "$WORK/err")"
}
check() { # <label> <want-rc> <want-substring-in-stdout>
  if [ "$RC" = "$2" ] && [[ "$OUT" == *"$3"* ]]; then pass "$1"; else fail "$1 (rc=$RC out='$OUT' err='$ERR')"; fi
}

echo "one gate a night"
FAKE_RUNS='' run
check "first trigger of the night: run" 0 "already=false"

jobs_for 401 success 'Resolve the lines and their images' 'Report nightly gate results' 'Nightly finished'
FAKE_RUNS=$'500 2026-11-21T07:52:00Z\n401 2026-11-21T03:40:00Z' run
check "an earlier trigger reported a green gate: skip" 3 "already_by=https://github.com/o/r/actions/runs/401"

jobs_for 402 failure 'Report nightly gate results'
printf 'nightly-gate-verdict\n' > "$WORK/arts-402"
FAKE_RUNS='402 2026-11-21T03:40:00Z' run
check "an earlier report failed after writing its verdict: skip" 3 "already=true"

jobs_for 408 failure 'Report nightly gate results'
printf 'some-other-artifact\n' > "$WORK/arts-408"
FAKE_RUNS='408 2026-11-21T03:40:00Z' run
check "an earlier report failed without writing a verdict: run" 0 "already=false"

jobs_for 409 failure 'Report nightly gate results'
FAKE_ARTS_FAIL=409 FAKE_RUNS='409 2026-11-21T03:40:00Z' run
check "reading a failed report's artifacts fails: run (INFRA)" 30 "already=false"

jobs_for 403 skipped 'Resolve the lines and their images' 'Report nightly gate results' 'Nightly finished'
FAKE_RUNS='403 2026-11-21T03:40:00Z' run
check "an earlier trigger skipped (candidate in flight): run" 0 "already=false"

jobs_for 404 cancelled 'Report nightly gate results'
FAKE_RUNS='404 2026-11-21T03:40:00Z' run
check "an earlier trigger was pre-empted: run" 0 "already=false"

jobs_for 405 success 'Resolve the lines and their images'
FAKE_RUNS='405 2026-11-21T03:40:00Z' run
check "an earlier run without a report job: run" 0 "already=false"

jobs_for 500 success 'Report nightly gate results'
FAKE_RUNS='500 2026-11-21T07:52:00Z' run
check "this run itself never counts" 0 "already=false"

jobs_for 406 success 'Report nightly s3 lane'
FAKE_RUNS='406 2026-11-21T03:40:00Z' run
check "a lane report is not the gate's report" 0 "already=false"

FAKE_RUNS='' run
if grep -q 'event=schedule&created=%3E%3D2026-11-20T19:52:00Z' "$WORK/calls"; then
  pass "looks back ONCE_WINDOW_HOURS (12) at scheduled runs only"
else
  fail "list query: $(cat "$WORK/calls")"
fi

echo "API errors run the gate"
FAKE_LIST_FAIL=1 run
check "listing runs fails: run (INFRA)" 30 "already=false"
FAKE_JOBS_FAIL=407 FAKE_RUNS='407 2026-11-21T03:40:00Z' run
check "reading a run's jobs fails: run (INFRA)" 30 "already=false"

echo "schedule lag"
ONCE_CRON='17 23 * * *' FAKE_RUNS='' run
check "23:17 trigger started 07:52 next day" 0 "late_minutes=515"
if [[ "$ERR" == *"Scheduled for 23:17 UTC, started 07:52 UTC: 8h35m late."* ]]; then pass "lag is logged"; else fail "lag log: $ERR"; fi
ONCE_CRON='17 7 * * *' FAKE_RUNS='' run
check "07:17 trigger started 07:52 same day" 0 "late_minutes=35"
ONCE_CRON='0 8 * * 1' FAKE_RUNS='' run
if [[ "$OUT" != *late_minutes* && "$RC" = 0 ]]; then pass "a non-daily cron reports no lag"; else fail "non-daily cron: rc=$RC out=$OUT"; fi

echo "usage"
RC=0; OUT="$(ONCE_RUN_ID='' bash "$SCRIPT" 2>/dev/null)" || RC=$?
check "no run id is a usage error" 2 ""

echo
if [ "$fails" -eq 0 ]; then echo "all nightly-gate-once tests passed"; else echo "${fails} nightly-gate-once test(s) FAILED"; exit 1; fi
