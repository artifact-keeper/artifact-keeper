#!/usr/bin/env bash
# ACTIONS_RUNNER_HOOK_JOB_COMPLETED
logger -t akvm-job "AKVM event=job_completed repository=${GITHUB_REPOSITORY:-} run_id=${GITHUB_RUN_ID:-} job=${GITHUB_JOB:-}"
