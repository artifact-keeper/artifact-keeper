#!/usr/bin/env bash
#
# Self-test for scripts/ci/memory-watch.sh (#6242).
#
# The sampler is what leaves numbers behind when Check Rust's clippy runs
# slow or stalls on the hosted VM, so the two things that must hold are:
# it reads /proc/meminfo and the compiler processes correctly (a sampler
# that records zeros proves nothing), and it never fails the job it watches.
# /proc/meminfo and ps are replaced by fixtures; no real sampling, ~1s.
#
# Usage: bash scripts/ci/test-memory-watch.sh
set -uo pipefail

W="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/memory-watch.sh"
[ -f "$W" ] || { echo "cannot find memory-watch.sh next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
pass() { printf '  PASS  %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*"; fails=$((fails + 1)); }

meminfo() { # <avail-kib> <swap-total-kib> <swap-free-kib>
  printf 'MemTotal:       16367000 kB\nMemFree:          100000 kB\nMemAvailable:   %s kB\nSwapTotal:      %s kB\nSwapFree:       %s kB\n' \
    "$1" "$2" "$3" > "$WORK/meminfo"
}

echo "memory-watch.sh"

# 1. One sample: MemAvailable and swap in MiB, and only rustc/clippy-driver
#    counted towards the compiler sum and max (cargo and the runner are not).
meminfo 2097152 15728640 13631488
printf '%s\n' "8388608 clippy-driver" "4194304 rustc" "1048576 cargo" "524288 Runner.Worker" > "$WORK/ps.txt"
: > "$WORK/s.tsv"
MEMWATCH_MEMINFO="$WORK/meminfo" MEMWATCH_PS="cat $WORK/ps.txt" bash "$W" sample "$WORK/s.tsv"
IFS=$'\t' read -r _ avail swap sum max n < "$WORK/s.tsv"
if [ "$avail" = 2048 ] && [ "$swap" = 2048 ] && [ "$sum" = 12288 ] && [ "$max" = 8192 ] && [ "$n" = 2 ]; then
  pass "sample reads MemAvailable, swap in use and compiler RSS (2048/2048/12288/8192/2)"
else
  fail "sample: got avail=$avail swap=$swap sum=$sum max=$max n=$n"
fi

# 2. The report names the peaks and counts the thrashing samples.
printf '%s\n' \
  $'1000\t9000\t0\t4000\t4000\t2' \
  $'1005\t600\t3000\t14000\t12000\t3' \
  $'1010\t800\t5000\t9000\t8000\t2' > "$WORK/r.tsv"
out="$(bash "$W" report "$WORK/r.tsv")"
for needle in "3 samples over 10s" "all processes, peak: 13.67 GiB (3 processes, 5s in)" \
              "one process, peak:   11.72 GiB" "lowest:              0.59 GiB" \
              "highest:              4.88 GiB" ">= 1 GiB swapped:     2 of 3" "< 1 GiB available:    2 of 3"; do
  if grep -qF -- "$needle" <<< "$out"; then pass "report: $needle"; else fail "report lacks '$needle'"; printf '%s\n' "$out" | sed 's/^/      /'; fi
done

# 2b. ...and a timeline, one sample per 30 s: the first sample and the
#     next one at least 30 s later (here only the first; 1010 is 10 s in).
if grep -qE '^ +0 +8\.79 +0\.00 +3\.91 +2$' <<< "$out" && ! grep -qE '^ +10 ' <<< "$out"; then
  pass "report: 30-second timeline"
else
  fail "report: timeline"; printf '%s\n' "$out" | sed 's/^/      /'
fi

# 3. Report-only: a missing or empty file is a line of output, exit 0.
rc=0; out="$(bash "$W" report "$WORK/absent.tsv")" || rc=$?
if [ "$rc" = 0 ] && grep -qF "no samples" <<< "$out"; then pass "missing file -> 'no samples', exit 0"; else fail "missing file: rc=$rc out=$out"; fi

# 4. A missing /proc/meminfo or ps still appends a line and exits 0.
rc=0; MEMWATCH_MEMINFO="$WORK/nope" MEMWATCH_PS="false" bash "$W" sample "$WORK/z.tsv" || rc=$?
if [ "$rc" = 0 ] && [ "$(wc -l < "$WORK/z.tsv" | tr -d ' ')" = 1 ]; then pass "unreadable sources -> a zero sample, exit 0"; else fail "unreadable sources: rc=$rc"; fi

# 5. start/stop: the sampler runs in the background and stops.
meminfo 8388608 0 0
MEMWATCH_MEMINFO="$WORK/meminfo" MEMWATCH_PS="cat $WORK/ps.txt" bash "$W" start "$WORK/bg.tsv" 1 >/dev/null
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -s "$WORK/bg.tsv" ] && break; sleep 0.3; done
bash "$W" stop "$WORK/bg.tsv"
if [ -s "$WORK/bg.tsv" ] && [ ! -e "$WORK/bg.tsv.pid" ]; then pass "start samples in the background; stop ends it"; else fail "start/stop"; fi

# 6. Bad usage is the only non-zero exit.
rc=0; bash "$W" report >/dev/null 2>&1 || rc=$?
if [ "$rc" = 2 ]; then pass "missing file argument -> exit 2"; else fail "missing argument: rc=$rc"; fi

echo
if [ "$fails" -gt 0 ]; then echo "${fails} case(s) FAILED"; exit 1; fi
echo "all cases passed"
