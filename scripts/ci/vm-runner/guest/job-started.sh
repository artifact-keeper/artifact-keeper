#!/usr/bin/env bash
# ACTIONS_RUNNER_HOOK_JOB_STARTED: record which job this VM is running.
logger -t akvm-job "AKVM event=job_started repository=${GITHUB_REPOSITORY:-} run_id=${GITHUB_RUN_ID:-} run_attempt=${GITHUB_RUN_ATTEMPT:-} job=${GITHUB_JOB:-} workflow_ref=${GITHUB_WORKFLOW_REF:-} sha=${GITHUB_SHA:-} ref=${GITHUB_REF:-} github_event=${GITHUB_EVENT_NAME:-} actor=${GITHUB_ACTOR:-}"
echo "ak-vm-runner: job runs in a throwaway VM ($(hostname)); kernel $(uname -r)"
