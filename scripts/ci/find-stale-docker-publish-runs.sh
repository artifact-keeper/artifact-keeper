#!/usr/bin/env bash
#
# Find (and optionally cancel) Docker Publish runs that are stuck QUEUED with
# no runner (#6080).
#
# WHY THIS EXISTS
#   A run that never gets a runner stays `queued` indefinitely (main@ea9425b6
#   sat 75 minutes). While it does, it holds its concurrency group's running
#   slot, so the next run in that group stays `pending` with zero jobs, and a
#   Release Candidate waiting on either of them waits out its timeout. Nobody
#   is told; somebody has to notice and cancel it by hand.
#
# WHAT COUNTS AS STALE (deliberately narrow)
#   * the run's status is `queued`: not ONE of its jobs has started. The first
#     job, publish-preflight, runs on a GitHub-hosted runner and normally
#     starts within a minute, so this is not "the amd64 pool is busy" -- a run
#     waiting for that pool is already `in_progress`, and is left alone;
#   * this attempt started more than STALE_MINUTES ago (`run_started_at`,
#     which a re-run resets);
#   * the jobs API agrees: no job has a runner assigned or has left `queued`.
#   `pending` runs (waiting for their concurrency group) are not stale: the
#   run holding the group is, and that one is caught here.
#
# OUTPUT (stdout), one line per stale run:
#   stale run_id=<id> sha=<sha> branch=<b> event=<e> attempt=<n> age_min=<m> action=<reported|cancelled|cancel-failed>
# Exit: 0 nothing stale; 1 at least one stale run (reported/cancelled); 30
#       the API could not be read (NOT a verdict).
#
# Env:
#   STALE_REPO      owner/name (default $GITHUB_REPOSITORY)
#   STALE_WORKFLOW  workflow file (default docker-publish.yml)
#   STALE_MINUTES   threshold (default 30)
#   STALE_ACTION    report | cancel (default report)
#   STALE_SHA       only consider runs for this head_sha (optional)
#   STALE_NOW       epoch seconds to measure against (tests; default now)
#   GH_TOKEN        actions: read to report, actions: write to cancel
set -uo pipefail

REPO="${STALE_REPO:-${GITHUB_REPOSITORY:-artifact-keeper/artifact-keeper}}"
WORKFLOW="${STALE_WORKFLOW:-docker-publish.yml}"
MINUTES="${STALE_MINUTES:-30}"
ACTION="${STALE_ACTION:-report}"
ONLY_SHA="${STALE_SHA:-}"
NOW="${STALE_NOW:-$(date +%s)}"

if [[ ! "$MINUTES" =~ ^[0-9]+$ || "$MINUTES" -lt 1 ]]; then
  echo "STALE_MINUTES must be a positive integer (got '${MINUTES}')" >&2; exit 30
fi
case "$ACTION" in report|cancel) ;; *) echo "STALE_ACTION must be report or cancel (got '${ACTION}')" >&2; exit 30 ;; esac
if [[ -n "$ONLY_SHA" && ! "$ONLY_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "STALE_SHA must be a 40-hex sha (got '${ONLY_SHA}')" >&2; exit 30
fi

query="repos/${REPO}/actions/workflows/${WORKFLOW}/runs?status=queued&per_page=100"
[[ -n "$ONLY_SHA" ]] && query="${query}&head_sha=${ONLY_SHA}"
rows="$(gh api "$query" \
  --jq '.workflow_runs[] | [.id, .head_sha, .head_branch, .event, .status, (.run_attempt // 1), (.run_started_at // .created_at)] | @tsv' \
  2>/dev/null)" || { echo "could not list queued ${WORKFLOW} runs; indeterminate" >&2; exit 30; }

to_epoch() { date -u -d "$1" +%s 2>/dev/null; }

found=0
while IFS=$'\t' read -r id sha branch event status attempt started; do
  [[ -z "$id" ]] && continue
  [[ "$status" == "queued" ]] || continue
  [[ -z "$ONLY_SHA" || "$sha" == "$ONLY_SHA" ]] || continue
  t="$(to_epoch "$started")" || t=""
  if [[ -z "$t" ]]; then
    echo "  run ${id}: unparseable start time '${started}'; skipped" >&2; continue
  fi
  age=$(( (NOW - t) / 60 ))
  if (( age < MINUTES )); then
    echo "  run ${id} (${branch}@${sha:0:7}) queued ${age}m; under the ${MINUTES}m threshold" >&2
    continue
  fi
  # The run-level status says no job started; the jobs list must agree before
  # anything is cancelled. Any job that has a runner or left `queued` means
  # this run is moving, whatever its summary status says.
  started_jobs="$(gh api "repos/${REPO}/actions/runs/${id}/jobs?per_page=100" \
    --jq '[.jobs[] | select(.status != "queued" or ((.runner_name // "") != ""))] | length' 2>/dev/null)" \
    || { echo "  run ${id}: could not list its jobs; skipped (indeterminate)" >&2; continue; }
  if [[ ! "$started_jobs" =~ ^[0-9]+$ ]]; then
    echo "  run ${id}: unreadable jobs answer '${started_jobs}'; skipped" >&2; continue
  fi
  if (( started_jobs > 0 )); then
    echo "  run ${id}: ${started_jobs} job(s) already have a runner; not stale" >&2
    continue
  fi
  found=1
  result=reported
  if [[ "$ACTION" == "cancel" ]]; then
    if gh api -X POST "repos/${REPO}/actions/runs/${id}/cancel" --silent 2>/dev/null; then
      result=cancelled
    elif gh api -X POST "repos/${REPO}/actions/runs/${id}/force-cancel" --silent 2>/dev/null; then
      # A run that never got a runner can refuse a normal cancel (409).
      result=cancelled
    else
      result=cancel-failed
    fi
  fi
  echo "stale run_id=${id} sha=${sha} branch=${branch} event=${event} attempt=${attempt} age_min=${age} action=${result}"
done <<< "$rows"

exit "$found"
