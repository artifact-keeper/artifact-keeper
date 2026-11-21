#!/usr/bin/env bash
#
# Dispatch release-cli-caches.yml on main for release-candidate.yml's
# `warm-cli-caches` job (#4927), and survive a GitHub API blip doing it (#6089).
#
# WHY THIS EXISTS
#   The warm-up is an optimisation: without it the tag run builds the CLI
#   binaries cold, which costs time and nothing else. A single HTTP 502 on the
#   dispatch (Release Candidate run 43912490439) still turned the job red. So:
#     * HTTP 5xx, 429 and errors with no HTTP status (connection reset, DNS)
#       are retried with backoff;
#     * if they persist, a ::warning:: says the tag run will build cold and the
#       script exits 0;
#     * any other HTTP status (404 missing workflow, 403 permissions) exits 1,
#       because retrying cannot fix it. The job keeps `continue-on-error`, so
#       that shows as a red step without failing the candidate run.
#   Only this dispatch is soft. Nothing in the gate or the certification may
#   call this script.
#
# Env:
#   GITHUB_REPOSITORY        owner/name (required)
#   WARMUP_BACKOFF_SECONDS   sleeps between attempts (default "10 30 60",
#                            so 4 attempts)
#   SHA                      the candidate commit, only for the log line
set -euo pipefail

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
read -r -a backoff <<<"${WARMUP_BACKOFF_SECONDS-10 30 60}"

err="$(mktemp)"
trap 'rm -f "$err"' EXIT

attempt=0
while :; do
  attempt=$((attempt + 1))
  if gh workflow run release-cli-caches.yml --repo "${GITHUB_REPOSITORY}" --ref main 2>"$err"; then
    echo "Dispatched Release CLI Caches on main's tip for candidate ${SHA:-unknown}. Let it finish before the promote, or the tag run builds cold."
    exit 0
  fi
  cat "$err" >&2
  status="$(grep -oE 'HTTP [0-9]{3}' "$err" | head -n1 | cut -c6- || true)"
  case "$status" in
    5[0-9][0-9]|429|"") ;;
    *)
      echo "::error::Dispatching release-cli-caches.yml failed (HTTP ${status:-status unknown}), retrying will not fix it."
      exit 1 ;;
  esac
  if [ "$attempt" -gt "${#backoff[@]}" ]; then
    echo "::warning::Could not dispatch release-cli-caches.yml after ${attempt} attempts (last HTTP ${status:-status unknown}). The tag run will build the CLI binaries cold."
    exit 0
  fi
  delay="${backoff[$((attempt - 1))]}"
  echo "Dispatch attempt ${attempt} got HTTP ${status:-status unknown}, retrying in ${delay}s." >&2
  sleep "$delay"
done
