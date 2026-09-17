#!/usr/bin/env bash
# =============================================================================
# run-measured-build.sh — run one compile step, record its peak RSS in the job
#                         summary, and retry it once if it was OOM-killed
#                         (#3856)
# =============================================================================
#
# WHY
# The coverage job's instrumented build sits close enough to the runner's
# memory ceiling that ordinary variance decides whether it finishes: the same
# lib-test crate that builds on `main` was SIGKILL'd on PRs that changed no
# library code at all (#3841, #3846). Two things were missing, and this script
# is both of them:
#
#   1. A NUMBER. Nobody could say how much headroom the build actually has,
#      only that it sometimes ran out, so every mitigation was a guess. Each
#      run now writes its peak RSS to the job summary, so the headroom is
#      measured on every PR instead of argued about.
#   2. A way to survive the dice roll WITHOUT hiding it. `gh run rerun`
#      refuses when the PR touches `.github/workflows/`, so a contributor's
#      only recovery was force-pushing an amended commit to get a fresh head
#      SHA. One automatic retry costs a few minutes; the SIGKILL is still
#      written to the job summary, so the trend stays visible and does not
#      quietly become someone's normal.
#
# The retry is deliberately narrow. ONLY a SIGKILL is retried — a real compile
# error, a missing file, a cc failure in a vendored source are all reported on
# the first attempt, exactly as before. "SIGKILL" means either the command
# itself died on signal 9 (exit 137), or cargo reported that one of its child
# rustc processes did:
#
#     error: process didn't exit successfully: `rustc --crate-name ...
#       -C instrument-coverage` (signal: 9 (SIGKILL))
#
# which is the shape #3856 actually observed — cargo exits 101 there, not 137,
# so an exit-status-only test would never fire.
#
# Usage:  run-measured-build.sh <label> <command> [args...]
#
#   <label>  names the step in the job summary table ("lib", "bins", ...).
#
# Exits with the command's own status once it stops being retryable.
#
# Env:
#   GITHUB_STEP_SUMMARY   markdown summary file; the table is skipped if unset
#   MEASURED_BUILD_RETRIES  SIGKILL retries allowed (default 1; 0 disables)
#   MEASURED_BUILD_TIME_BIN  override the GNU time binary (tests)
# =============================================================================
# NOT `set -e`: a failing command is the interesting case and is handled below.
set -uo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: run-measured-build.sh <label> <command> [args...]" >&2
  exit 2
fi

LABEL="$1"
shift

RETRIES="${MEASURED_BUILD_RETRIES:-1}"
SUMMARY="${GITHUB_STEP_SUMMARY:-}"
HEADING="### Instrumented build: peak memory"

# GNU time (not the bash keyword) is what reports maximum RSS. It is present on
# the runner image; if it ever is not, measurement degrades to "n/a" and the
# build still runs and still retries — a missing measurement must never fail a
# build that would otherwise pass.
TIME_BIN="${MEASURED_BUILD_TIME_BIN:-/usr/bin/time}"
if ! { [ -x "$TIME_BIN" ] && "$TIME_BIN" -v true >/dev/null 2>&1; }; then
  echo "run-measured-build: no GNU time at ${TIME_BIN}; running unmeasured" >&2
  TIME_BIN=""
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
LOG="$WORK/output.log"
TIMING="$WORK/timing.txt"

summary_line() { # <markdown>
  [ -n "$SUMMARY" ] || return 0
  printf '%s\n' "$1" >>"$SUMMARY"
}

# The table header is written by whichever invocation gets there first; the
# lib and bins passes then append a row each.
if [ -n "$SUMMARY" ] && ! grep -Fqx "$HEADING" "$SUMMARY" 2>/dev/null; then
  summary_line "$HEADING"
  summary_line ""
  summary_line "| target | attempt | peak RSS | result |"
  summary_line "| --- | --- | --- | --- |"
fi

# "Maximum resident set size (kbytes)" -> human-readable, or "n/a".
peak_rss() {
  local kb=""
  [ -s "$TIMING" ] && kb="$(sed -n \
    's/.*Maximum resident set size (kbytes):[[:space:]]*\([0-9][0-9]*\).*/\1/p' \
    "$TIMING" | tail -1)"
  if [ -z "$kb" ]; then
    echo "n/a"
  else
    awk -v kb="$kb" 'BEGIN {
      if (kb >= 1048576) printf "%.2f GiB", kb / 1048576
      else printf "%.1f MiB", kb / 1024
    }'
  fi
}

# A SIGKILL is either ours (exit 137) or one a child reports: cargo prints
# "(signal: 9 (SIGKILL))" for a killed rustc, GNU time "Command terminated by
# signal 9", sccache "Compile terminated by signal 9" (#1515). Deliberately
# not a bare /SIGKILL/ — that would match a compile error quoting the word.
was_sigkilled() { # <status>
  [ "$1" -eq 137 ] && return 0
  local f
  for f in "$LOG" "$TIMING"; do
    [ -s "$f" ] || continue
    grep -Eq 'signal: 9 \(SIGKILL\)|erminated by signal 9' "$f" && return 0
  done
  return 1
}

attempt=1
while :; do
  : >"$TIMING"
  if [ -n "$TIME_BIN" ]; then
    "$TIME_BIN" -v -o "$TIMING" "$@" 2>&1 | tee "$LOG"
  else
    "$@" 2>&1 | tee "$LOG"
  fi
  status="${PIPESTATUS[0]}"
  rss="$(peak_rss)"

  echo "run-measured-build: ${LABEL} attempt ${attempt} exited ${status}, peak RSS ${rss}"

  if [ "$status" -eq 0 ]; then
    summary_line "| ${LABEL} | ${attempt} | ${rss} | ok |"
    exit 0
  fi

  if was_sigkilled "$status"; then
    if [ "$attempt" -le "$RETRIES" ]; then
      # Recorded BEFORE the retry: a SIGKILL that a retry papers over is still
      # a SIGKILL, and the summary is where the trend has to stay visible.
      summary_line "| ${LABEL} | ${attempt} | ${rss} | ⚠️ SIGKILL (out of memory) — retrying |"
      echo "::warning title=Instrumented build OOM-killed (#3856)::The ${LABEL} instrumented build was SIGKILL'd (peak RSS ${rss}); retrying once. If this is not rare, the build needs a lower -j or a larger runner."
      attempt=$((attempt + 1))
      continue
    fi
    summary_line "| ${LABEL} | ${attempt} | ${rss} | ⚠️ SIGKILL (out of memory) — retries exhausted |"
  else
    summary_line "| ${LABEL} | ${attempt} | ${rss} | failed (exit ${status}) |"
  fi
  exit "$status"
done
