#!/usr/bin/env bash
#
# Keep the nightly release gate out of a release candidate's way (#6073).
#
# The nightly gate (.github/workflows/nightly-release-gate.yml) and a Release
# Candidate both run the full artifact-keeper-test release gate on the same
# self-hosted pool (ak-e2e-runners). The pool fits one gate at a time. A
# candidate is release work and the nightly is advisory, so the candidate
# always wins. GitHub concurrency groups cannot express that: they work within
# one group, they have no priority, and release-candidate.yml cannot be
# changed to cancel the nightly, because a maintenance line's candidate
# requires its release-candidate.yml to be byte-identical to main's. So the
# nightly gives way by itself, in two places:
#
#   --once   before the gate starts. Exit 3 when a run of a watched workflow
#            (default release-candidate.yml) is queued, waiting or running,
#            so the nightly skips the night instead of queueing behind it.
#   --watch  for as long as the gate runs. Polls the watched workflows and,
#            the first time one of their runs is not completed, cancels the
#            nightly run (SENTINEL_RUN_ID). Cancelling is safe: the gate's
#            teardown and every cleanup step are `if: always()`, so they still
#            run and no namespace leaks. A cancelled nightly records nothing:
#            it opens, updates and closes no issue and writes no status.
#            The watch ends when the job named SENTINEL_DONE_JOB appears in
#            the nightly run (the report job, which starts only after every
#            gate leg has finished), or when the budget runs out (GitHub's
#            6-hour hosted-job limit), in which case it hands over to the
#            next sentinel job.
#
# An API error is never a reason to cancel anything: --once reports INFRA
# (exit 30) and the workflow goes ahead, --watch logs it and polls again.
#
# OUTPUT (stdout, also appended to $GITHUB_OUTPUT when set):
#   --once:   outranked=true|false  [outranked_by=<run url>]
#   --watch:  result=preempted|done|handoff  [outranked_by=<run url>]
#
# EXIT
#   --once:   0 clear, 3 outranked, 30 could not check
#   --watch:  0 (preempted, done or handoff), 2 usage error
#
# Env:
#   SENTINEL_REPO            owner/name (default artifact-keeper/artifact-keeper)
#   SENTINEL_WATCH           workflow files that outrank the nightly, separated
#                            by spaces (default release-candidate.yml)
#   SENTINEL_RUN_ID          --watch: the nightly run to cancel
#   SENTINEL_DONE_JOB        --watch: job name that means the gate has finished
#   SENTINEL_POLL_SECONDS    --watch: seconds between polls (default 180)
#   SENTINEL_DONE_EVERY      --watch: check for the done job every N polls
#                            (default 3; the job list is several pages)
#   SENTINEL_BUDGET_SECONDS  --watch: hand over after this long (default 17400)
#
set -uo pipefail

MODE="${1:-}"
REPO="${SENTINEL_REPO:-artifact-keeper/artifact-keeper}"
WATCH="${SENTINEL_WATCH:-release-candidate.yml}"
POLL="${SENTINEL_POLL_SECONDS:-180}"
DONE_EVERY="${SENTINEL_DONE_EVERY:-3}"
BUDGET="${SENTINEL_BUDGET_SECONDS:-17400}"

emit() {
  echo "$1"
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then echo "$1" >> "$GITHUB_OUTPUT"; fi
}

# Prints the first watched run that is not completed, as "<id> <status> <url>".
# Exit 0 found, 1 none, 30 when any watched workflow could not be read.
find_outranking() {
  local wf out rc=1
  for wf in $WATCH; do
    if ! out="$(gh api "repos/${REPO}/actions/workflows/${wf}/runs?per_page=20" \
        --jq '.workflow_runs[] | select(.status != "completed") | "\(.id) \(.status) \(.html_url)"' 2>/dev/null)"; then
      echo "sentinel: could not list runs of ${wf}" >&2
      rc=30
      continue
    fi
    if [[ -n "$out" ]]; then
      head -n1 <<<"$out"
      return 0
    fi
  done
  return "$rc"
}

# Exit 0 when SENTINEL_DONE_JOB is among the nightly run's jobs.
gate_done() {
  local names
  names="$(gh api --paginate "repos/${REPO}/actions/runs/${SENTINEL_RUN_ID}/jobs?per_page=100&filter=latest" \
    --jq '.jobs[].name' 2>/dev/null)" || return 1
  grep -qxF -- "${SENTINEL_DONE_JOB}" <<<"$names"
}

case "$MODE" in
  --once)
    rc=0; hit="$(find_outranking)" || rc=$?
    case "$rc" in
      0)
        emit "outranked=true"
        emit "outranked_by=${hit##* }"
        echo "::notice title=Nightly gate skipped::a release candidate is in flight (${hit}). It runs the same gate on the same pool and outranks the nightly; tonight's nightly does not run." >&2
        exit 3 ;;
      1)
        emit "outranked=false"
        exit 0 ;;
      *)
        emit "outranked=false"
        echo "::warning title=Could not check for a release candidate::listing ${WATCH} failed. Starting the nightly anyway; the watch job cancels it if a candidate turns up." >&2
        exit 30 ;;
    esac
    ;;
  --watch)
    if [[ ! "${SENTINEL_RUN_ID:-}" =~ ^[0-9]+$ || -z "${SENTINEL_DONE_JOB:-}" ]]; then
      echo "sentinel: --watch needs SENTINEL_RUN_ID and SENTINEL_DONE_JOB" >&2
      exit 2
    fi
    start=$(date +%s)
    polls=0
    while true; do
      rc=0; hit="$(find_outranking)" || rc=$?
      if [[ "$rc" -eq 0 ]]; then
        emit "result=preempted"
        emit "outranked_by=${hit##* }"
        echo "::warning title=Nightly gate pre-empted::a release candidate started (${hit}). Cancelling this nightly so the candidate has the pool; teardown still runs. Nothing is recorded for tonight." >&2
        if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
          printf '## Nightly gate pre-empted\n\nA release candidate started: %s\n\nThis run was cancelled so the candidate gets the self-hosted pool. It records no verdict, opens or closes no issue and writes no commit status.\n' "${hit##* }" >> "$GITHUB_STEP_SUMMARY"
        fi
        if ! gh api -X POST "repos/${REPO}/actions/runs/${SENTINEL_RUN_ID}/cancel" >/dev/null 2>&1; then
          echo "::error title=Could not cancel the nightly::POST runs/${SENTINEL_RUN_ID}/cancel failed. Cancel it by hand so the candidate gets the pool." >&2
        fi
        exit 0
      elif [[ "$rc" -eq 30 ]]; then
        echo "sentinel: watch poll failed; trying again in ${POLL}s" >&2
      fi
      polls=$((polls + 1))
      if (( polls % DONE_EVERY == 0 )) && gate_done; then
        emit "result=done"
        exit 0
      fi
      if (( $(date +%s) - start >= BUDGET )); then
        emit "result=handoff"
        exit 0
      fi
      sleep "$POLL"
    done
    ;;
  *)
    echo "usage: nightly-gate-sentinel.sh --once|--watch" >&2
    exit 2 ;;
esac
