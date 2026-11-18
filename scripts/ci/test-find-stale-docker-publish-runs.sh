#!/usr/bin/env bash
#
# Self-test for scripts/ci/find-stale-docker-publish-runs.sh (#6080).
#
# The finder cancels runs, so its dangerous direction is cancelling a run
# that is MOVING: one whose jobs have a runner, one that is merely young, one
# that is `in_progress` waiting for the self-hosted pool, or one for another
# commit when scoped to a sha. Those legs must leave the run alone. The
# other direction -- a run queued with no runner past the threshold -- must
# be reported, cancelled when asked, and fall back to force-cancel.
#
# HOW: a stub `gh` replays the runs and jobs lists and records every POST.
# No network, ~1s.
#
# Usage: bash scripts/ci/test-find-stale-docker-publish-runs.sh
# shellcheck disable=SC2015  # pass/fail both return 0: `A && pass || fail` is if-then-else here
set -uo pipefail

FINDER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/find-stale-docker-publish-runs.sh"
[ -f "$FINDER" ] || { echo "cannot find find-stale-docker-publish-runs.sh next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

SHA_A=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
SHA_B=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
NOW=$(date -u -d '2026-11-16T12:00:00Z' +%s)

STUB="$WORK/bin"; mkdir -p "$STUB"
# FAKE_RUNS: TSV  id sha branch event status attempt started_at
# FAKE_JOBS_<id>: number of started jobs for run <id> (default 0)
# FAKE_CANCEL_FAIL=1: plain cancel answers 409; FAKE_FORCE_FAIL=1: force too
cat > "$STUB/gh" <<'STUBGH'
#!/usr/bin/env bash
[ "$1" = api ] || exit 0
shift
if [ "$1" = -X ]; then
  echo "$2 $3" >> "$FAKE_POSTS"
  case "$3" in
    */force-cancel) [ "${FAKE_FORCE_FAIL-0}" = 1 ] && exit 1; exit 0 ;;
    */cancel)       [ "${FAKE_CANCEL_FAIL-0}" = 1 ] && exit 1; exit 0 ;;
  esac
  exit 0
fi
case "$1" in
  *actions/workflows/*/runs*)
    [ "${FAKE_RUNS_FAIL-0}" = 1 ] && exit 1
    echo "$1" >> "$FAKE_QUERIES"
    [ -n "${FAKE_RUNS-}" ] && printf '%s\n' "$FAKE_RUNS"
    exit 0 ;;
  *actions/runs/*/jobs*)
    id="${1#*actions/runs/}"; id="${id%%/*}"
    v="FAKE_JOBS_${id}"; echo "${!v:-0}"
    exit 0 ;;
esac
exit 0
STUBGH
chmod +x "$STUB/gh"

# <label> <want-exit> <want-substring> [extra env...]
expect() {
  local label="$1" want="$2" needle="$3" got=0; shift 3
  : > "$WORK/posts"; : > "$WORK/queries"
  ( export PATH="$STUB:$PATH" STALE_REPO=artifact-keeper/artifact-keeper STALE_NOW="$NOW" \
      FAKE_POSTS="$WORK/posts" FAKE_QUERIES="$WORK/queries" FAKE_RUNS="${FAKE_RUNS-}"
    for kv in "$@"; do export "${kv?}"; done
    bash "$FINDER" >"$WORK/out.txt" 2>"$WORK/err.txt" ) || got=$?
  if [ "$got" != "$want" ]; then
    fail "$label: expected exit $want, got $got"; sed 's/^/        /' "$WORK/out.txt" "$WORK/err.txt" >&2
  elif [ -n "$needle" ] && ! grep -qF -- "$needle" "$WORK/out.txt"; then
    fail "$label: stdout lacks '$needle'"; sed 's/^/        /' "$WORK/out.txt" "$WORK/err.txt" >&2
  else
    pass "$label (exit $got)"
  fi
}
no_posts() { [ -s "$WORK/posts" ] && fail "$1: POSTed $(tr '\n' ' ' <"$WORK/posts")" || pass "$1: nothing cancelled"; }

echo "stale Docker Publish run finder: the legs"

FAKE_RUNS=$'501\t'"$SHA_A"$'\tmain\tpush\tqueued\t1\t2026-11-16T11:00:00Z'
expect "queued 60m, no job started -> reported" 1 "stale run_id=501 sha=${SHA_A} branch=main event=push attempt=1 age_min=60 action=reported"
no_posts "report mode"

expect "same, cancel mode -> cancelled" 1 "action=cancelled" STALE_ACTION=cancel
grep -qx "POST repos/artifact-keeper/artifact-keeper/actions/runs/501/cancel" "$WORK/posts" \
  && pass "cancel POSTed for run 501" || fail "posts were: $(cat "$WORK/posts")"

expect "cancel refused (409) -> force-cancel" 1 "action=cancelled" STALE_ACTION=cancel FAKE_CANCEL_FAIL=1
grep -q "/501/force-cancel" "$WORK/posts" && pass "force-cancel POSTed" || fail "posts were: $(cat "$WORK/posts")"

expect "both refused -> cancel-failed, still exit 1" 1 "action=cancel-failed" STALE_ACTION=cancel FAKE_CANCEL_FAIL=1 FAKE_FORCE_FAIL=1

# A run whose summary says queued but a job has a runner is moving.
expect "a job already has a runner -> not stale" 0 "" STALE_ACTION=cancel FAKE_JOBS_501=1
no_posts "job with a runner"

FAKE_RUNS=$'502\t'"$SHA_A"$'\tmain\tpush\tqueued\t1\t2026-11-16T11:45:00Z'
expect "queued 15m -> under the threshold" 0 "" STALE_ACTION=cancel
no_posts "young run"

# Waiting for the amd64 pool is in_progress, never touched.
FAKE_RUNS=$'503\t'"$SHA_A"$'\tmain\tpush\tin_progress\t1\t2026-11-16T08:00:00Z'
expect "in_progress for hours -> not stale" 0 "" STALE_ACTION=cancel
no_posts "in_progress run"

# A re-run resets run_started_at: measured from the attempt, not creation.
FAKE_RUNS=$'504\t'"$SHA_A"$'\tmain\tpush\tqueued\t2\t2026-11-16T11:50:00Z'
expect "re-run attempt started 10m ago -> not stale" 0 "" STALE_ACTION=cancel

# Scoped to a sha: another commit's stale run is not ours to cancel.
FAKE_RUNS=$'505\t'"$SHA_B"$'\tmain\tpush\tqueued\t1\t2026-11-16T10:00:00Z'
expect "scoped to sha A, stale run is sha B -> left alone" 0 "" STALE_ACTION=cancel STALE_SHA="$SHA_A"
no_posts "other sha"
grep -q "head_sha=${SHA_A}" "$WORK/queries" && pass "scoped query filters head_sha server-side" || fail "queries: $(cat "$WORK/queries")"

FAKE_RUNS=$'506\t'"$SHA_A"$'\trelease/1.11.x\tpush\tqueued\t1\t2026-11-16T10:00:00Z\n507\t'"$SHA_B"$'\tmain\tworkflow_dispatch\tqueued\t1\t2026-11-16T11:59:00Z'
expect "two queued, one stale -> only the stale one" 1 "stale run_id=506" STALE_ACTION=cancel
grep -q "/507/" "$WORK/posts" && fail "young run 507 was cancelled" || pass "young run 507 untouched"

FAKE_RUNS=""
expect "API down -> infra" 30 "" FAKE_RUNS_FAIL=1
expect "nothing queued -> exit 0" 0 ""
expect "bad threshold -> infra" 30 "" STALE_MINUTES=zero

echo
if [ "$fails" -gt 0 ]; then echo "${fails} case(s) FAILED"; exit 1; fi
echo "all cases passed"
