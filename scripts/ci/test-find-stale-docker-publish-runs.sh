#!/usr/bin/env bash
#
# Self-test for scripts/ci/find-stale-docker-publish-runs.sh (#6080, #6289).
#
# The finder cancels runs, so its dangerous direction is cancelling a run
# that is MOVING or NEEDED: one whose jobs have a runner, one that is merely
# young, one with a job mid-build, a tag / dispatch / schedule / release/**
# run, a re-run (how a Release Candidate rebuilds its own commit), a run no
# newer commit supersedes, one a Release Candidate may be waiting for, or one
# for another commit when scoped to a sha. Those legs must leave the run
# alone. The other direction must act: a run queued with no runner past the
# threshold is reported, cancelled when asked, and falls back to
# force-cancel; a started main push run whose last job has waited for a
# runner past the threshold while a newer push waits behind it (the
# 44495887855 shape, #6289) is cancelled, and every other stuck run is
# reported so the watchdog goes red.
#
# HOW: a stub `gh` serves JSON fixtures shaped like the REST API's, applies
# the server-side filters (status, branch, event, head_sha) and then the
# finder's own --jq filter through jq, so the filters themselves are tested.
# It records every POST. No network, ~2s.
#
# Usage: bash scripts/ci/test-find-stale-docker-publish-runs.sh
# shellcheck disable=SC2015  # pass/fail both return 0: `A && pass || fail` is if-then-else here
set -uo pipefail

FINDER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/find-stale-docker-publish-runs.sh"
[ -f "$FINDER" ] || { echo "cannot find find-stale-docker-publish-runs.sh next to this test" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

SHA_A=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
SHA_B=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
SHA_C=cccccccccccccccccccccccccccccccccccccccc
NOW=$(date -u -d '2026-11-16T12:00:00Z' +%s)
FX="$WORK/fx"

STUB="$WORK/bin"; mkdir -p "$STUB"
# Fixtures (TSV, turned into API-shaped JSON by the stub):
#   $FX/runs-<workflow file>.tsv  id sha branch event status attempt run_started_at created_at
#   $FX/jobs-<run id>.tsv         status runner(- = none) created_at name
# FAKE_RUNS_FAIL=1: every runs list fails; FAKE_SUPERSEDED_FAIL=1: the
# branch-scoped runs list fails; FAKE_JOBS_FAIL_<id>=1: that run's jobs fail;
# FAKE_CANCEL_FAIL=1: plain cancel answers 409; FAKE_FORCE_FAIL=1: force too.
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
path="$1"; shift
filter="."
while [ $# -gt 0 ]; do [ "$1" = --jq ] && { filter="$2"; shift; }; shift; done
echo "$path" >> "$FAKE_QUERIES"
param() { local q="${path#*\?}"; tr '&' '\n' <<<"$q" | sed -n "s/^$1=//p" | head -1; }
case "$path" in
  *actions/workflows/*/runs*)
    [ "${FAKE_RUNS_FAIL-0}" = 1 ] && exit 1
    [ -n "$(param branch)" ] && [ "${FAKE_SUPERSEDED_FAIL-0}" = 1 ] && exit 1
    wf="${path#*actions/workflows/}"; wf="${wf%%/*}"
    f="$FAKE_FX/runs-${wf}.tsv"; [ -f "$f" ] || : > "$f"
    jq -R -s --arg st "$(param status)" --arg br "$(param branch)" \
      --arg ev "$(param event)" --arg sha "$(param head_sha)" '
      split("\n") | map(select(length > 0) | split("\t")
        | {id: (.[0]|tonumber), head_sha: .[1], head_branch: .[2], event: .[3],
           status: .[4], run_attempt: (.[5]|tonumber), run_started_at: .[6],
           created_at: .[7]})
      | map(select(($st == "" or .status == $st) and ($br == "" or .head_branch == $br)
                   and ($ev == "" or .event == $ev) and ($sha == "" or .head_sha == $sha)))
      | sort_by(.created_at) | reverse | {workflow_runs: .}' "$f" | jq -r "$filter"
    ;;
  *actions/runs/*/jobs*)
    id="${path#*actions/runs/}"; id="${id%%/*}"
    v="FAKE_JOBS_FAIL_${id}"; [ "${!v-0}" = 1 ] && exit 1
    f="$FAKE_FX/jobs-${id}.tsv"; [ -f "$f" ] || : > "$f"
    jq -R -s '
      split("\n") | map(select(length > 0) | split("\t")
        | {status: .[0], runner_name: (if .[1] == "-" then null else .[1] end),
           created_at: .[2], name: .[3]})
      | {total_count: length, jobs: .}' "$f" | jq -r "$filter"
    ;;
esac
exit 0
STUBGH
chmod +x "$STUB/gh"

reset_fx() { rm -rf "$FX"; mkdir -p "$FX"; }
# run <id> <sha> <branch> <event> <status> <attempt> <started> [created] [workflow]
run() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" "${8:-$7}" \
    >> "$FX/runs-${9:-docker-publish.yml}.tsv"
}
# job <run id> <status> <runner|-> <created> <name>
job() { printf '%s\t%s\t%s\t%s\n' "$2" "$3" "$4" "$5" >> "$FX/jobs-$1.tsv"; }
# a started run like 44495887855: everything done but the amd64 backend leg
done_but_amd64() {  # <run id> <amd64 status> <amd64 runner|-> <amd64 created>
  job "$1" completed "GitHub Actions 1" 2026-11-16T07:00:00Z "Publish identity preflight"
  job "$1" completed "GitHub Actions 2" 2026-11-16T07:00:10Z "Backend (linux/arm64)"
  job "$1" completed akvm-1 2026-11-16T07:00:10Z "OpenSCAP (linux/amd64)"
  job "$1" "$2" "$3" "$4" "Backend (linux/amd64)"
}

# <label> <want-exit> <want-substring> [extra env...]
expect() {
  local label="$1" want="$2" needle="$3" got=0; shift 3
  : > "$WORK/posts"; : > "$WORK/queries"
  ( export PATH="$STUB:$PATH" STALE_REPO=artifact-keeper/artifact-keeper STALE_NOW="$NOW" \
      FAKE_POSTS="$WORK/posts" FAKE_QUERIES="$WORK/queries" FAKE_FX="$FX"
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
posted() { grep -qx "POST repos/artifact-keeper/artifact-keeper/actions/runs/$2/cancel" "$WORK/posts" \
  && pass "$1: cancel POSTed for run $2" || fail "$1: posts were: $(tr '\n' ' ' <"$WORK/posts")"; }

echo "stale Docker Publish run finder (#6080): queued, nothing started"

reset_fx
run 501 "$SHA_A" main push queued 1 2026-11-16T11:00:00Z
job 501 queued - 2026-11-16T11:00:00Z "Publish identity preflight"
expect "queued 60m, no job started -> reported" 1 "stale run_id=501 sha=${SHA_A} branch=main event=push attempt=1 age_min=60 action=reported"
no_posts "report mode"

expect "same, cancel mode -> cancelled" 1 "action=cancelled" STALE_ACTION=cancel
posted "stale run" 501

expect "cancel refused (409) -> force-cancel" 1 "action=cancelled" STALE_ACTION=cancel FAKE_CANCEL_FAIL=1
grep -q "/501/force-cancel" "$WORK/posts" && pass "force-cancel POSTed" || fail "posts were: $(cat "$WORK/posts")"

expect "both refused -> cancel-failed, still exit 1" 1 "action=cancel-failed" STALE_ACTION=cancel FAKE_CANCEL_FAIL=1 FAKE_FORCE_FAIL=1

# A run whose summary says queued but a job has a runner is moving.
reset_fx
run 501 "$SHA_A" main push queued 1 2026-11-16T11:00:00Z
job 501 queued "GitHub Actions 9" 2026-11-16T11:00:00Z "Publish identity preflight"
expect "a job already has a runner -> not stale" 0 "" STALE_ACTION=cancel
no_posts "job with a runner"

reset_fx
run 502 "$SHA_A" main push queued 1 2026-11-16T11:45:00Z
expect "queued 15m -> under the threshold" 0 "" STALE_ACTION=cancel
no_posts "young run"

# A re-run resets run_started_at: measured from the attempt, not creation.
reset_fx
run 504 "$SHA_A" main push queued 2 2026-11-16T11:50:00Z 2026-11-16T06:00:00Z
expect "re-run attempt started 10m ago -> not stale" 0 "" STALE_ACTION=cancel

# Scoped to a sha: another commit's stale run is not ours to cancel.
reset_fx
run 505 "$SHA_B" main push queued 1 2026-11-16T10:00:00Z
expect "scoped to sha A, stale run is sha B -> left alone" 0 "" STALE_ACTION=cancel STALE_SHA="$SHA_A"
no_posts "other sha"
grep -q "head_sha=${SHA_A}" "$WORK/queries" && pass "scoped query filters head_sha server-side" || fail "queries: $(cat "$WORK/queries")"

reset_fx
run 506 "$SHA_A" release/1.11.x push queued 1 2026-11-16T10:00:00Z
run 507 "$SHA_B" main workflow_dispatch queued 1 2026-11-16T11:59:00Z
expect "two queued, one stale -> only the stale one" 1 "stale run_id=506" STALE_ACTION=cancel
grep -q "/507/" "$WORK/posts" && fail "young run 507 was cancelled" || pass "young run 507 untouched"

echo
echo "stuck Docker Publish run finder (#6289): started, a job waits for a runner"

# The 44495887855 shape: main push, in_progress since 07:00, every job done
# but the amd64 leg, queued with no runner for 5h; a newer push is pending.
stuck_fixture() {  # [amd64 status] [amd64 runner]
  reset_fx
  run 601 "$SHA_A" main push in_progress 1 2026-11-16T07:00:00Z
  done_but_amd64 601 "${1:-queued}" "${2:--}" 2026-11-16T07:00:10Z
  run 602 "$SHA_B" main push pending 1 2026-11-16T09:00:00Z
}
stuck_fixture
expect "amd64 leg queued 5h, newer push pending -> cancelled" 1 \
  "stuck run_id=601 sha=${SHA_A} branch=main event=push attempt=1 age_min=300 queued_min=299 action=cancelled hold=- job=\"Backend (linux/amd64)\"" \
  STALE_ACTION=cancel
posted "superseded stuck run" 601
grep -q "/602/" "$WORK/posts" && fail "the pending newer run 602 was touched" || pass "pending newer run 602 untouched"

expect "same, report mode -> reported, nothing cancelled" 1 "action=reported hold=report-mode" STALE_ACTION=report
no_posts "report mode (stuck)"

expect "cancel refused -> force-cancel" 1 "action=cancelled" STALE_ACTION=cancel FAKE_CANCEL_FAIL=1
grep -q "/601/force-cancel" "$WORK/posts" && pass "force-cancel POSTed for 601" || fail "posts were: $(cat "$WORK/posts")"

expect "threshold is the knob: STUCK_JOB_MINUTES=400 -> under it (run ceiling raised too)" 0 "" \
  STALE_ACTION=cancel STUCK_JOB_MINUTES=400 STUCK_RUN_MINUTES=600
no_posts "under raised threshold"

# Nothing newer waiting: cancelling would build nothing in its place.
reset_fx
run 601 "$SHA_A" main push in_progress 1 2026-11-16T07:00:00Z
done_but_amd64 601 queued - 2026-11-16T07:00:10Z
run 600 "$SHA_C" main push completed 1 2026-11-16T06:00:00Z
expect "no newer push waiting -> reported (not-superseded)" 1 "action=reported hold=not-superseded" STALE_ACTION=cancel
no_posts "not superseded"

# The newer run is not a main push (a dispatch on main): not the coalesced group.
reset_fx
run 601 "$SHA_A" main push in_progress 1 2026-11-16T07:00:00Z
done_but_amd64 601 queued - 2026-11-16T07:00:10Z
run 603 "$SHA_B" main workflow_dispatch queued 1 2026-11-16T11:50:00Z  # young: not #6080-stale itself
expect "only a newer DISPATCH waiting -> not superseded" 1 "hold=not-superseded" STALE_ACTION=cancel
no_posts "dispatch is not a superseding push"

# The amd64 leg has a runner now: mid-build, it finishes (#2099).
stuck_fixture in_progress ak-beefy-runners-1
expect "amd64 leg building, run 5h old -> reported (job-running), never cancelled" 1 \
  "action=reported hold=job-running" STALE_ACTION=cancel
no_posts "mid-build run"

# A job with a runner assigned that still reads queued is moving.
stuck_fixture queued ak-beefy-runners-1
expect "amd64 leg queued WITH a runner -> job-running" 1 "hold=job-running" STALE_ACTION=cancel
no_posts "runner assigned"

# A young started run whose amd64 leg queued 20m: nothing to do.
reset_fx
run 610 "$SHA_A" main push in_progress 1 2026-11-16T11:00:00Z
done_but_amd64 610 queued - 2026-11-16T11:40:00Z
run 611 "$SHA_B" main push pending 1 2026-11-16T11:30:00Z
expect "amd64 leg queued 20m (run 60m old) -> not stuck" 0 "" STALE_ACTION=cancel
no_posts "short wait"

# A run that is moving but very old: reported against the ceiling, kept.
reset_fx
run 620 "$SHA_A" main push in_progress 1 2026-11-16T07:00:00Z
done_but_amd64 620 in_progress ak-beefy-runners-1 2026-11-16T07:00:10Z
run 621 "$SHA_B" main push pending 1 2026-11-16T09:00:00Z
expect "in_progress 5h, building -> reported against the ceiling" 1 "stuck run_id=620" STALE_ACTION=cancel
grep -q "queued_min=- action=reported hold=job-running" "$WORK/out.txt" && pass "ceiling hit reported as job-running" || fail "out: $(cat "$WORK/out.txt")"
no_posts "old but building"
expect "in_progress 3h, building -> not stuck" 0 "" STALE_ACTION=cancel STUCK_RUN_MINUTES=400

# Runs that are never cancelled, however stuck.
for spec in "tag:v1.12.3:push" "dispatch:main:workflow_dispatch" "schedule:main:schedule" "release-line:release/1.12.x:push"; do
  IFS=: read -r what ref ev <<<"$spec"
  reset_fx
  run 630 "$SHA_A" "$ref" "$ev" in_progress 1 2026-11-16T07:00:00Z
  done_but_amd64 630 queued - 2026-11-16T07:00:10Z
  run 631 "$SHA_B" "$ref" "$ev" pending 1 2026-11-16T09:00:00Z
  expect "stuck ${what} run -> reported (not-a-main-push)" 1 "hold=not-a-main-push" STALE_ACTION=cancel
  no_posts "${what} run"
done

# A re-run: how a Release Candidate rebuilds its own (replaced) commit.
reset_fx
run 640 "$SHA_A" main push in_progress 2 2026-11-16T07:00:00Z 2026-11-16T05:00:00Z
done_but_amd64 640 queued - 2026-11-16T07:00:10Z
run 641 "$SHA_B" main push pending 1 2026-11-16T09:00:00Z
expect "stuck re-run attempt -> reported (re-run)" 1 "attempt=2 age_min=300 queued_min=299 action=reported hold=re-run" STALE_ACTION=cancel
no_posts "re-run"

# A Release Candidate in flight may be waiting for this very commit.
stuck_fixture
run 9001 "$SHA_C" main workflow_dispatch in_progress 1 2026-11-16T11:00:00Z "" release-candidate.yml
expect "release candidate in flight -> reported (candidate-active)" 1 "hold=candidate-active" STALE_ACTION=cancel
no_posts "candidate active"
stuck_fixture
run 9001 "$SHA_C" main workflow_dispatch completed 1 2026-11-16T05:00:00Z "" release-candidate.yml
expect "only a finished candidate -> cancelled" 1 "action=cancelled" STALE_ACTION=cancel

# A candidate that is only QUEUED (not yet running) holds every cancel too:
# it will wait for some commit's images once it starts.
reset_fx
run 660 "$SHA_A" main push in_progress 1 2026-11-16T07:00:00Z
done_but_amd64 660 queued - 2026-11-16T07:00:10Z
run 661 "$SHA_B" main push in_progress 1 2026-11-16T07:05:00Z
done_but_amd64 661 queued - 2026-11-16T07:05:10Z
run 662 "$SHA_C" main push pending 1 2026-11-16T09:00:00Z
run 9002 "$SHA_C" main workflow_dispatch queued 1 2026-11-16T11:58:00Z "" release-candidate.yml
expect "queued release candidate -> every stuck run held" 1 "stuck run_id=661" STALE_ACTION=cancel
[ "$(grep -c 'action=reported hold=candidate-active' "$WORK/out.txt")" = 2 ] \
  && pass "both stuck runs report hold=candidate-active" || fail "out: $(cat "$WORK/out.txt")"
no_posts "queued candidate"

# Anything it cannot prove holds the cancel.
stuck_fixture
expect "superseded check fails -> reported (superseded-unknown)" 1 "hold=superseded-unknown" STALE_ACTION=cancel FAKE_SUPERSEDED_FAIL=1
no_posts "superseded unknown"
expect "jobs read fails -> skipped, exit 0" 0 "" STALE_ACTION=cancel FAKE_JOBS_FAIL_601=1
no_posts "jobs unknown"

# The run summary may still say queued after a job ran (run 44544311118):
# that is the started path, not #6080's.
reset_fx
run 650 "$SHA_A" main push queued 1 2026-11-16T07:00:00Z
done_but_amd64 650 queued - 2026-11-16T07:00:10Z
run 651 "$SHA_B" main push pending 1 2026-11-16T09:00:00Z
expect "status queued but jobs ran, amd64 waits 5h -> stuck, cancelled" 1 "stuck run_id=650" STALE_ACTION=cancel
posted "queued-summary stuck run" 650
grep -q "^stale " "$WORK/out.txt" && fail "reported as #6080 stale too" || pass "not double-reported as stale"

echo
echo "infrastructure"
reset_fx
expect "API down -> infra" 30 "" FAKE_RUNS_FAIL=1
expect "nothing queued or running -> exit 0" 0 ""
grep -q "status=in_progress" "$WORK/queries" && pass "in_progress runs are listed too (#6289)" || fail "queries: $(cat "$WORK/queries")"
expect "bad threshold -> infra" 30 "" STALE_MINUTES=zero
expect "bad job threshold -> infra" 30 "" STUCK_JOB_MINUTES=0
expect "bad run ceiling -> infra" 30 "" STUCK_RUN_MINUTES=x

echo
echo "the watchdog workflow wires it (#6289)"
WF_DIR="$(cd "$(dirname "$FINDER")/../../.github/workflows" 2>/dev/null && pwd)"
if [ -n "$WF_DIR" ] && [ -f "$WF_DIR/docker-publish-watchdog.yml" ]; then
  wd="$WF_DIR/docker-publish-watchdog.yml"
  publish_name="$(sed -n 's/^name: *//p' "$WF_DIR/docker-publish.yml" | head -1)"
  # The schedule alone fired hours apart; a Docker Publish event must run it.
  awk '/^  workflow_run:/{f=1;next} f&&/^  [a-z_]+:/{f=0} f' "$wd" | grep -qF "workflows: [${publish_name}]" \
    && pass "runs on workflow_run of '${publish_name}'" || fail "docker-publish-watchdog.yml has no workflow_run on '${publish_name}'"
  awk '/^  workflow_run:/{f=1;next} f&&/^  [a-z_]+:/{f=0} f' "$wd" | grep -q "types: \[requested, completed\]" \
    && pass "on requested and completed" || fail "workflow_run types are not [requested, completed]"
  # Its own cancel ends a Docker Publish run, which starts another watchdog:
  # cancelling the sweep in progress would hide that cancel's report.
  awk '/^concurrency:/{f=1;next} f&&/^[^ #]/{f=0} f' "$wd" | grep -qx "  cancel-in-progress: false" \
    && pass "concurrency does not cancel a sweep in progress" || fail "docker-publish-watchdog.yml concurrency must be cancel-in-progress: false"
  for v in STUCK_JOB_MINUTES STUCK_RUN_MINUTES STALE_ACTION; do
    grep -q "^ *${v}: " "$wd" && pass "passes ${v} to the finder" || fail "docker-publish-watchdog.yml does not set ${v}"
  done
else
  echo "  (workflow files not next to this script; skipped)"
fi

echo
if [ "$fails" -gt 0 ]; then echo "${fails} case(s) FAILED"; exit 1; fi
echo "all cases passed"
