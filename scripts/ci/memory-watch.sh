#!/usr/bin/env bash
#
# Sample a hosted runner's memory while a compile runs, and summarise it
# (#6242).
#
# WHY THIS EXISTS
#   Check Rust's clippy was bimodal on the 16 GB hosted VM: 5-6 minutes, or
#   10-11 minutes, or stalled until the job ceiling cancelled it. A
#   cancelled job keeps no log (BlobNotFound), and the only number a green
#   run left was the job cgroup's memory.peak, which includes page cache and
#   sat at 15.0 GiB on every run, fast or slow. Neither says which process
#   held the memory or whether the VM was swapping. This records, every few
#   seconds, what is available, how much swap is in use and how much the
#   compiler processes hold, so a slow run and a stall both leave numbers.
#
# USAGE
#   memory-watch.sh start  <file> [interval-seconds]   start sampling in the
#                                                      background; returns at once
#   memory-watch.sh sample <file>                      append one sample now
#   memory-watch.sh report <file>                      print the summary
#   memory-watch.sh stop   <file>                      stop the sampler
#
# FILE FORMAT, one tab-separated line per sample:
#   epoch  mem_available_mib  swap_used_mib  compiler_rss_sum_mib  compiler_rss_max_mib  compiler_procs
# "Compiler" is every rustc and clippy-driver process. RSS is resident memory
# only: what a process has in swap is not in it, so a thrashing compile
# shows LOW rss next to HIGH swap_used, which is the signature to look for.
#
# Report-only: every subcommand exits 0 unless its arguments are wrong, so it
# can never turn a job red.
#
# Env (tests): MEMWATCH_MEMINFO (default /proc/meminfo), MEMWATCH_PS (a
# command printing "<rss-kib> <comm>" lines; default ps).
set -uo pipefail

cmd="${1:-}"; file="${2:-}"
if [[ -z "$cmd" || -z "$file" ]]; then
  echo "usage: memory-watch.sh start|sample|report|stop <file> [interval]" >&2
  exit 2
fi

MEMINFO="${MEMWATCH_MEMINFO:-/proc/meminfo}"

ps_lines() {
  if [[ -n "${MEMWATCH_PS:-}" ]]; then
    bash -c "$MEMWATCH_PS"
  else
    ps -eo rss=,comm= 2>/dev/null
  fi
}

sample() {
  local avail swap_total swap_free procs
  avail="$(awk '/^MemAvailable:/ { print int($2 / 1024) }' "$MEMINFO" 2>/dev/null)"
  swap_total="$(awk '/^SwapTotal:/ { print int($2 / 1024) }' "$MEMINFO" 2>/dev/null)"
  swap_free="$(awk '/^SwapFree:/ { print int($2 / 1024) }' "$MEMINFO" 2>/dev/null)"
  procs="$(ps_lines | awk '
      $2 == "rustc" || $2 == "clippy-driver" { n++; s += $1; if ($1 > m) m = $1 }
      END { printf "%d\t%d\t%d", s / 1024, m / 1024, n }')"
  printf '%s\t%s\t%s\t%s\n' "$(date +%s)" "${avail:-0}" \
    "$(( ${swap_total:-0} - ${swap_free:-0} ))" "$procs" >> "$file"
}

case "$cmd" in
  sample)
    sample ;;
  start)
    interval="${3:-5}"
    [[ "$interval" =~ ^[0-9]+$ && "$interval" -ge 1 ]] || { echo "interval must be a positive integer" >&2; exit 2; }
    : > "$file"
    (
      trap 'exit 0' TERM
      while true; do sample; sleep "$interval"; done
    ) >/dev/null 2>&1 &
    echo "$!" > "${file}.pid"
    echo "memory-watch: sampling every ${interval}s into ${file} (pid $!)" ;;
  stop)
    if [[ -f "${file}.pid" ]]; then
      kill "$(cat "${file}.pid")" 2>/dev/null || true
      rm -f "${file}.pid"
    fi ;;
  report)
    if [[ ! -s "$file" ]]; then
      echo "memory-watch: no samples in ${file}"
      exit 0
    fi
    awk -F'\t' '
      NF >= 6 {
        n++
        if (n == 1) { t0 = $1; minavail = $2 }
        t1 = $1
        if ($2 < minavail) minavail = $2
        if ($3 > maxswap) maxswap = $3
        if ($4 > maxsum) { maxsum = $4; maxsum_t = $1; maxsum_n = $6 }
        if ($5 > maxone) maxone = $5
        if ($3 >= 1024) swapping++
        if ($2 < 1024) starved++
      }
      END {
        if (n == 0) { print "memory-watch: no parseable samples"; exit }
        printf "memory-watch: %d samples over %ds\n", n, t1 - t0
        printf "  compiler RSS, all processes, peak: %.2f GiB (%d processes, %ds in)\n", maxsum / 1024, maxsum_n, maxsum_t - t0
        printf "  compiler RSS, one process, peak:   %.2f GiB\n", maxone / 1024
        printf "  MemAvailable, lowest:              %.2f GiB\n", minavail / 1024
        printf "  swap in use, highest:              %.2f GiB\n", maxswap / 1024
        printf "  samples with >= 1 GiB swapped:     %d of %d\n", swapping, n
        printf "  samples with < 1 GiB available:    %d of %d\n", starved, n
      }' "$file" ;;
  *)
    echo "unknown subcommand '${cmd}'" >&2; exit 2 ;;
esac
exit 0
