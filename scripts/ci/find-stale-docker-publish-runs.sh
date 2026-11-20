#!/usr/bin/env bash
#
# Find (and optionally cancel) Docker Publish runs that are stuck: QUEUED with
# no runner at all (#6080), or STARTED but with a job that has waited for a
# runner far too long (#6289).
#
# WHY THIS EXISTS
#   A run that never gets a runner stays `queued` indefinitely (main@ea9425b6
#   sat 75 minutes). While it does, it holds its concurrency group's running
#   slot, so the next run in that group stays `pending` with zero jobs, and a
#   Release Candidate waiting on either of them waits out its timeout. Nobody
#   is told; somebody has to notice and cancel it by hand.
#
#   The same thing happens to a run that HAS started (#6289). Run 44495887855
#   (main@361dcf82) was `in_progress` from 09:22 to 15:10 on 2026-11-19 with
#   every job done except `Backend (linux/amd64)`, which waited ~6 h in the
#   one-slot ak-beefy-runners queue. Since main pushes coalesce (#6264), that
#   run held main's group the whole time: three newer pushes were replaced as
#   pending and `:main` / `sha-` images did not move for ~7 h. Its run status
#   was `in_progress`, so the #6080 rule never looked at it.
#
# WHAT COUNTS AS STALE (#6080; deliberately narrow, any branch or event)
#   * the run's status is `queued`: not ONE of its jobs has started. The first
#     job, publish-preflight, runs on a GitHub-hosted runner and normally
#     starts within a minute, so this is not "the amd64 pool is busy";
#   * this attempt started more than STALE_MINUTES ago (`run_started_at`,
#     which a re-run resets);
#   * the jobs API agrees: no job has a runner assigned or has left `queued`.
#   `pending` runs (waiting for their concurrency group) are not stale: the
#   run holding the group is, and that one is caught here.
#
# WHAT COUNTS AS STUCK (#6289), for a run that has started (status
# `in_progress`, or `queued` with a job that already ran):
#   * a job has been `queued` with no runner for STUCK_JOB_MINUTES or more
#     (measured from the job's created_at), or
#   * this attempt is older than STUCK_RUN_MINUTES, whatever its jobs are doing.
#   Every stuck run is REPORTED (exit 1, the watchdog goes red). It is
#   CANCELLED only when cancelling it can lose nothing, i.e. all of:
#     - it is attempt 1 of a `push` run on main/master: the coalesced group.
#       Never a tag, a dispatch (a promote, a candidate's own build), the
#       schedule, a release/** push, or a re-run (`run_attempt` > 1 is how a
#       Release Candidate rebuilds its own commit, in a group of its own);
#     - no job of it is running: nothing is mid-build ("a run that has started
#       finishes", #2099), the remaining work is all waiting for a runner;
#     - a newer push run for the same branch is waiting (pending/queued): the
#       newer commit supersedes this one, and its run republishes every image
#       and moves `:main` / `:dev` itself. Cancelling also frees the queued
#       build from the pool, so the pool builds one commit fewer;
#     - no Release Candidate run is active: a candidate may be waiting for
#       THIS commit's images. It would re-run a cancelled run (and can), but
#       the re-run joins the back of the pool's queue, so the watchdog leaves
#       the run alone and only reports it while a candidate is in flight.
#   Anything the watchdog cannot prove (an API read that failed) holds the
#   cancel and reports instead.
#
# OUTPUT (stdout), one line per stale or stuck run:
#   stale run_id=<id> sha=<sha> branch=<b> event=<e> attempt=<n> age_min=<m> action=<reported|cancelled|cancel-failed>
#   stuck run_id=<id> sha=<sha> branch=<b> event=<e> attempt=<n> age_min=<m> queued_min=<m|-> action=<reported|cancelled|cancel-failed> hold=<why|-> job="<name|->"
# Exit: 0 nothing stale or stuck; 1 at least one (reported/cancelled); 30
#       the API could not be read (NOT a verdict).
#
# Env:
#   STALE_REPO          owner/name (default $GITHUB_REPOSITORY)
#   STALE_WORKFLOW      workflow file (default docker-publish.yml)
#   STALE_MINUTES       queued-with-no-runner threshold (default 30)
#   STUCK_JOB_MINUTES   one job queued with no runner, in a started run (default 45)
#   STUCK_RUN_MINUTES   attempt age ceiling for a started run (default 240)
#   STALE_ACTION        report | cancel (default report)
#   STALE_SHA           only consider runs for this head_sha (optional)
#   STALE_CANDIDATE_WORKFLOW  workflow whose active runs hold a cancel
#                       (default release-candidate.yml)
#   STALE_NOW           epoch seconds to measure against (tests; default now)
#   GH_TOKEN            actions: read to report, actions: write to cancel
set -uo pipefail

REPO="${STALE_REPO:-${GITHUB_REPOSITORY:-artifact-keeper/artifact-keeper}}"
WORKFLOW="${STALE_WORKFLOW:-docker-publish.yml}"
MINUTES="${STALE_MINUTES:-30}"
JOB_MINUTES="${STUCK_JOB_MINUTES:-45}"
RUN_MINUTES="${STUCK_RUN_MINUTES:-240}"
ACTION="${STALE_ACTION:-report}"
ONLY_SHA="${STALE_SHA:-}"
CANDIDATE_WORKFLOW="${STALE_CANDIDATE_WORKFLOW:-release-candidate.yml}"
NOW="${STALE_NOW:-$(date +%s)}"

for pair in "STALE_MINUTES=${MINUTES}" "STUCK_JOB_MINUTES=${JOB_MINUTES}" "STUCK_RUN_MINUTES=${RUN_MINUTES}"; do
  v="${pair#*=}"
  if [[ ! "$v" =~ ^[0-9]+$ || "$v" -lt 1 ]]; then
    echo "${pair%%=*} must be a positive integer (got '${v}')" >&2; exit 30
  fi
done
case "$ACTION" in report|cancel) ;; *) echo "STALE_ACTION must be report or cancel (got '${ACTION}')" >&2; exit 30 ;; esac
if [[ -n "$ONLY_SHA" && ! "$ONLY_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "STALE_SHA must be a 40-hex sha (got '${ONLY_SHA}')" >&2; exit 30
fi

RUN_JQ='.workflow_runs[] | [.id, .head_sha, .head_branch, .event, .status, (.run_attempt // 1), (.run_started_at // .created_at), .created_at] | @tsv'
rows=""
for st in queued in_progress; do
  query="repos/${REPO}/actions/workflows/${WORKFLOW}/runs?status=${st}&per_page=100"
  [[ -n "$ONLY_SHA" ]] && query="${query}&head_sha=${ONLY_SHA}"
  part="$(gh api "$query" --jq "$RUN_JQ" 2>/dev/null)" \
    || { echo "could not list ${st} ${WORKFLOW} runs; indeterminate" >&2; exit 30; }
  [[ -n "$part" ]] && rows+="${part}"$'\n'
done

to_epoch() { date -u -d "$1" +%s 2>/dev/null; }

cancel_run() {
  if gh api -X POST "repos/${REPO}/actions/runs/$1/cancel" --silent 2>/dev/null; then
    echo cancelled
  elif gh api -X POST "repos/${REPO}/actions/runs/$1/force-cancel" --silent 2>/dev/null; then
    # A run that never got a runner can refuse a normal cancel (409).
    echo cancelled
  else
    echo cancel-failed
  fi
}

# Is a newer push run for this branch waiting for the group? 0 yes, 1 no,
# 2 could not tell (holds the cancel).
superseded() {
  local branch="$1" created="$2" n
  n="$(gh api "repos/${REPO}/actions/workflows/${WORKFLOW}/runs?branch=${branch}&event=push&per_page=50" \
    --jq "[.workflow_runs[] | select((.status == \"pending\" or .status == \"queued\" or .status == \"waiting\" or .status == \"requested\") and .created_at > \"${created}\")] | length" \
    2>/dev/null)" || return 2
  [[ "$n" =~ ^[0-9]+$ ]] || return 2
  (( n > 0 )) && return 0
  return 1
}

# Is any Release Candidate run active? 0 yes, 1 no, 2 could not tell.
candidate_active() {
  local n
  n="$(gh api "repos/${REPO}/actions/workflows/${CANDIDATE_WORKFLOW}/runs?per_page=30" \
    --jq '[.workflow_runs[] | select(.status != "completed")] | length' 2>/dev/null)" || return 2
  [[ "$n" =~ ^[0-9]+$ ]] || return 2
  (( n > 0 )) && return 0
  return 1
}

found=0
seen=" "
while IFS=$'\t' read -r id sha branch event status attempt started created; do
  [[ -z "$id" ]] && continue
  [[ "$seen" == *" ${id} "* ]] && continue   # listed under both statuses mid-transition
  seen+="${id} "
  [[ "$status" == "queued" || "$status" == "in_progress" ]] || continue
  [[ -z "$ONLY_SHA" || "$sha" == "$ONLY_SHA" ]] || continue
  t="$(to_epoch "$started")" || t=""
  if [[ -z "$t" ]]; then
    echo "  run ${id}: unparseable start time '${started}'; skipped" >&2; continue
  fi
  age=$(( (NOW - t) / 60 ))
  if (( age < MINUTES && age < JOB_MINUTES && age < RUN_MINUTES )); then
    echo "  run ${id} (${branch}@${sha:0:7}) ${status} ${age}m; under every threshold" >&2
    continue
  fi
  # One read of the jobs: status, runner, when it was queued, name.
  jobs="$(gh api "repos/${REPO}/actions/runs/${id}/jobs?per_page=100" \
    --jq '.jobs[] | [.status, (if (.runner_name // "") == "" then "-" else .runner_name end), .created_at, .name] | @tsv' 2>/dev/null)" \
    || { echo "  run ${id}: could not list its jobs; skipped (indeterminate)" >&2; continue; }

  started_jobs=0; running_jobs=0; oldest_q=""; oldest_name=""
  while IFS=$'\t' read -r jstatus jrunner jcreated jname; do
    [[ -z "$jstatus" ]] && continue
    [[ "$jstatus" != "queued" || "$jrunner" != "-" ]] && started_jobs=$((started_jobs + 1))
    [[ "$jstatus" != "completed" && "$jstatus" != "queued" ]] && running_jobs=$((running_jobs + 1))
    [[ "$jstatus" == "queued" && "$jrunner" != "-" ]] && running_jobs=$((running_jobs + 1))
    if [[ "$jstatus" == "queued" && "$jrunner" == "-" ]]; then
      jt="$(to_epoch "$jcreated")" || jt=""
      [[ -z "$jt" ]] && continue
      jq_min=$(( (NOW - jt) / 60 ))
      if [[ -z "$oldest_q" ]] || (( jq_min > oldest_q )); then oldest_q="$jq_min"; oldest_name="$jname"; fi
    fi
  done <<< "$jobs"

  # ── #6080: queued, nothing started ──────────────────────────────────────
  if [[ "$status" == "queued" && "$started_jobs" -eq 0 ]]; then
    if (( age < MINUTES )); then
      echo "  run ${id} (${branch}@${sha:0:7}) queued ${age}m; under the ${MINUTES}m threshold" >&2
      continue
    fi
    found=1
    result=reported
    [[ "$ACTION" == "cancel" ]] && result="$(cancel_run "$id")"
    echo "stale run_id=${id} sha=${sha} branch=${branch} event=${event} attempt=${attempt} age_min=${age} action=${result}"
    continue
  fi

  # ── #6289: started, but a job waits for a runner, or the run is too old ─
  if [[ -n "$oldest_q" ]] && (( oldest_q >= JOB_MINUTES )); then
    :
  elif (( age >= RUN_MINUTES )); then
    :
  else
    echo "  run ${id} (${branch}@${sha:0:7}): ${started_jobs} job(s) started, longest runner wait ${oldest_q:-0}m; not stuck" >&2
    continue
  fi
  found=1
  hold=""
  if [[ "$event" != "push" || ( "$branch" != "main" && "$branch" != "master" ) ]]; then
    hold="not-a-main-push"
  elif [[ "$attempt" != "1" ]]; then
    hold="re-run"
  elif (( running_jobs > 0 )); then
    hold="job-running"
  elif [[ -z "$oldest_q" ]]; then
    hold="no-queued-job"
  else
    superseded "$branch" "$created"; s=$?
    if (( s == 1 )); then hold="not-superseded"
    elif (( s == 2 )); then hold="superseded-unknown"
    else
      candidate_active; c=$?
      if (( c == 0 )); then hold="candidate-active"
      elif (( c == 2 )); then hold="candidate-unknown"
      fi
    fi
  fi
  result=reported
  if [[ -z "$hold" ]]; then
    if [[ "$ACTION" == "cancel" ]]; then result="$(cancel_run "$id")"; else hold="report-mode"; fi
  fi
  echo "stuck run_id=${id} sha=${sha} branch=${branch} event=${event} attempt=${attempt} age_min=${age} queued_min=${oldest_q:--} action=${result} hold=${hold:--} job=\"${oldest_name:--}\""
done <<< "$rows"

exit "$found"
