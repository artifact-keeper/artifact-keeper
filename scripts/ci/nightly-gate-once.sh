#!/usr/bin/env bash
#
# One nightly release gate per night, from whichever scheduled trigger GitHub
# starts first (#6155).
#
# GitHub starts the scheduled workflows in this repository hours late: the
# nightly's `0 8 * * *` started at 17:20, 16:55, 17:00, 16:39 and 15:52 UTC on
# 2026-11-17..21, and the weekly crons were 7-9 hours late too. A late start
# is not a dropped one, but a schedule can also be dropped under load, and a
# night skipped because a release candidate held the pool used to be lost.
# So nightly-release-gate.yml has several scheduled triggers a few hours
# apart, and this script lets only the first one that gets that far run the
# gate:
#
#   A scheduled run goes ahead unless another scheduled run of the same
#   workflow, created in the last ONCE_WINDOW_HOURS (default 12), already
#   REPORTED a gate: its `Report nightly gate results` job (ONCE_REPORT_JOB)
#   ended success or failure. A run that skipped, was pre-empted by a
#   candidate (cancelled) or never got that far does not count, so the next
#   trigger tries again.
#
# The workflow's concurrency group runs these one at a time, so an earlier
# run has finished by the time a later one gets here. The window has to be
# longer than the spread of one night's triggers and shorter than the gap
# from the last trigger to the next night's first; with triggers four hours
# apart and 12 hours, both margins are four hours.
#
# It also reports how late GitHub started this run: ONCE_CRON (the trigger's
# `github.event.schedule`, "M H * * *") against the clock, in the log and the
# step summary. That is the number the nightly timeline depends on.
#
# An API error is never a reason to skip a night: exit 30 and the gate runs.
#
# OUTPUT (stdout, also appended to $GITHUB_OUTPUT when set):
#   already=true|false  [already_by=<run url>]  [late_minutes=<n>]
#
# EXIT 0 run the gate, 3 a gate was already reported tonight (skip),
#      30 could not check (run), 2 usage error.
#
# Env:
#   ONCE_REPO          owner/name (default artifact-keeper/artifact-keeper)
#   ONCE_WORKFLOW      workflow file (default nightly-release-gate.yml)
#   ONCE_RUN_ID        this run, never counted
#   ONCE_WINDOW_HOURS  default 12
#   ONCE_REPORT_JOB    default "Report nightly gate results"
#   ONCE_CRON          the cron expression that fired, optional
#   ONCE_NOW           epoch seconds (tests; default now)
#
set -uo pipefail

REPO="${ONCE_REPO:-artifact-keeper/artifact-keeper}"
WF="${ONCE_WORKFLOW:-nightly-release-gate.yml}"
WINDOW="${ONCE_WINDOW_HOURS:-12}"
REPORT_JOB="${ONCE_REPORT_JOB:-Report nightly gate results}"
NOW="${ONCE_NOW:-$(date +%s)}"
SERVER="${GITHUB_SERVER_URL:-https://github.com}"

emit() {
  echo "$1"
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then echo "$1" >> "$GITHUB_OUTPUT"; fi
}
summary() {
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then printf '%s\n' "$1" >> "$GITHUB_STEP_SUMMARY"; fi
}

if [[ ! "${ONCE_RUN_ID:-}" =~ ^[0-9]+$ || ! "$WINDOW" =~ ^[0-9]+$ || ! "$NOW" =~ ^[0-9]+$ ]]; then
  echo "nightly-gate-once: needs ONCE_RUN_ID, and ONCE_WINDOW_HOURS / ONCE_NOW must be numbers" >&2
  exit 2
fi

# ── how late did this start ──────────────────────────────────────────────────
# Only the daily "M H * * *" form the workflow uses; anything else is left out.
if [[ "${ONCE_CRON:-}" =~ ^([0-9]{1,2})\ ([0-9]{1,2})\ \*\ \*\ \*$ ]]; then
  m="${BASH_REMATCH[1]}"; h="${BASH_REMATCH[2]}"
  day_start=$(( NOW - NOW % 86400 ))
  due=$(( day_start + 10#$h * 3600 + 10#$m * 60 ))
  (( due <= NOW )) || due=$(( due - 86400 ))
  late=$(( (NOW - due) / 60 ))
  emit "late_minutes=${late}"
  msg="$(printf 'Scheduled for %02d:%02d UTC, started %s UTC: %dh%02dm late.' \
    "$((10#$h))" "$((10#$m))" "$(date -u -d "@${NOW}" +%H:%M 2>/dev/null || echo '?')" $((late / 60)) $((late % 60)))"
  echo "nightly-gate-once: ${msg}" >&2
  summary "### Schedule lag"$'\n\n'"${msg}"
fi

# ── was a gate already reported tonight ──────────────────────────────────────
since="$(date -u -d "@$(( NOW - WINDOW * 3600 ))" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)" || {
  echo "nightly-gate-once: needs GNU date" >&2; exit 2; }

if ! runs="$(gh api "repos/${REPO}/actions/workflows/${WF}/runs?event=schedule&created=%3E%3D${since}&per_page=50" \
    --jq '.workflow_runs[] | "\(.id) \(.created_at)"' 2>/dev/null)"; then
  emit "already=false"
  echo "::warning title=Could not check for tonight's gate::listing the scheduled runs of ${WF} failed. Running the gate; at worst it runs twice tonight." >&2
  exit 30
fi

while read -r id created; do
  [[ "$id" =~ ^[0-9]+$ && "$id" != "$ONCE_RUN_ID" ]] || continue
  if ! jobs="$(gh api --paginate "repos/${REPO}/actions/runs/${id}/jobs?per_page=100&filter=latest" \
      --jq '.jobs[] | "\(.conclusion)\t\(.name)"' 2>/dev/null)"; then
    emit "already=false"
    echo "::warning title=Could not check for tonight's gate::reading the jobs of run ${id} failed. Running the gate; at worst it runs twice tonight." >&2
    exit 30
  fi
  while IFS=$'\t' read -r conclusion name; do
    [[ "$name" == "$REPORT_JOB" ]] || continue
    if [[ "$conclusion" == success || "$conclusion" == failure ]]; then
      url="${SERVER}/${REPO}/actions/runs/${id}"
      emit "already=true"
      emit "already_by=${url}"
      echo "::notice title=Nightly gate already ran::the scheduled run ${id} (created ${created}) reported tonight's gate (${url}). This trigger is a backstop; nothing more runs." >&2
      summary "### Nightly gate already ran"$'\n\n'"Scheduled run ${url} (created ${created}) reported tonight's gate. This later trigger is a backstop and skips."
      exit 3
    fi
  done <<<"$jobs"
done <<<"$runs"

emit "already=false"
exit 0
