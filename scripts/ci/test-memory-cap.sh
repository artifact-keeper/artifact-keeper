#!/usr/bin/env bash
#
# Self-test for scripts/ci/memory-cap.sh (#6242), plus the ci.yml wiring it
# exists for.
#
# The cap is what keeps the hosted runner agent alive while a backend
# compile that needs more than the VM's RAM swaps, so what must hold is:
# memory.high is MemTotal minus the reserve, the command really runs inside
# the new cgroup, a setup failure degrades to an uncapped run (a warning,
# never a red job), the command's exit status comes through, and every
# step that compiles the backend crate on a 16 GB hosted runner is still
# capped. A fake cgroup tree stands in for /sys/fs/cgroup; ~1s.
#
# Usage: bash scripts/ci/test-memory-cap.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
C="$HERE/memory-cap.sh"
CI="$HERE/../../.github/workflows/ci.yml"
[ -f "$C" ] || { echo "cannot find memory-cap.sh next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
pass() { printf '  PASS  %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*"; fails=$((fails + 1)); }

# A 16 GiB VM (16777216 kB) and a cgroup root with the memory controller.
printf 'MemTotal:       16777216 kB\nMemAvailable:   15000000 kB\n' > "$WORK/meminfo"
mkroot() {
  rm -rf "$WORK/cg"; mkdir -p "$WORK/cg"
  echo "cpuset cpu io memory pids" > "$WORK/cg/cgroup.controllers"
  echo "cpu io memory pids" > "$WORK/cg/cgroup.subtree_control"
}
run() { # <args...>  -> $out, $rc
  rc=0
  out="$(MEMCAP_CGROUP_ROOT="$WORK/cg" MEMCAP_MEMINFO="$WORK/meminfo" MEMCAP_SUDO="" MEMCAP_NAME=t \
    bash "$C" "$@" 2>&1)" || rc=$?
}

echo "memory-cap.sh"

# 1. memory.high = 16384 - 2816 MiB = 13568 MiB, and the command runs as a
#    process the script moved into the cgroup (its pid is in cgroup.procs).
mkroot
# shellcheck disable=SC2016  # $PPID is the child's, expanded in the child
run -- bash -c 'echo "child of $PPID"'
high="$(cat "$WORK/cg/t/memory.high" 2>/dev/null)"
moved="$(cat "$WORK/cg/t/cgroup.procs" 2>/dev/null)"
if [ "$rc" = 0 ] && [ "$high" = $((13568 * 1048576)) ] && grep -qx "child of ${moved}" <<< "$out"; then
  pass "default reserve: memory.high 13568 MiB, command runs inside the cgroup"
else
  fail "default: rc=$rc high=$high moved=$moved"; printf '%s\n' "$out" | sed 's/^/      /'
fi

# 2. --reserve-mib changes the limit.
mkroot
run --reserve-mib 4096 true
if [ "$rc" = 0 ] && [ "$(cat "$WORK/cg/t/memory.high")" = $((12288 * 1048576)) ]; then
  pass "--reserve-mib 4096 -> memory.high 12288 MiB"
else
  fail "--reserve-mib: rc=$rc high=$(cat "$WORK/cg/t/memory.high" 2>/dev/null)"
fi

# 3. The command's exit status is the script's.
mkroot
run -- bash -c 'exit 7'
if [ "$rc" = 7 ]; then pass "exit status passes through (7)"; else fail "exit status: rc=$rc"; fi

# 4. The summary line reports peak and throttling from the cgroup files.
mkroot
run -- bash -c 'echo 15032385536 > "'"$WORK"'/cg/t/memory.peak"; printf "low 0\nhigh 42\nmax 0\n" > "'"$WORK"'/cg/t/memory.events"'
if grep -qF "memory.peak 14.00 GiB, swap peak n/a, throttled 42 times" <<< "$out"; then
  pass "summary: memory.peak and memory.events high"
else
  fail "summary"; printf '%s\n' "$out" | sed 's/^/      /'
fi

# 5. No memory controller: a ::warning::, the command still runs, exit 0.
mkroot; echo "cpu io pids" > "$WORK/cg/cgroup.controllers"
run -- echo ran
if [ "$rc" = 0 ] && grep -qF "::warning title=Compile not memory-capped" <<< "$out" && grep -qx ran <<< "$out" && [ ! -d "$WORK/cg/t" ]; then
  pass "no memory controller -> warning, uncapped run"
else
  fail "no controller: rc=$rc"; printf '%s\n' "$out" | sed 's/^/      /'
fi

# 6. Unreadable MemTotal: the same.
mkroot
rc=0; out="$(MEMCAP_CGROUP_ROOT="$WORK/cg" MEMCAP_MEMINFO="$WORK/nope" MEMCAP_SUDO="" MEMCAP_NAME=t bash "$C" echo ran 2>&1)" || rc=$?
if [ "$rc" = 0 ] && grep -qF "cannot read MemTotal" <<< "$out" && grep -qx ran <<< "$out"; then
  pass "unreadable MemTotal -> warning, uncapped run"
else
  fail "no meminfo: rc=$rc"; printf '%s\n' "$out" | sed 's/^/      /'
fi

# 7. A cgroup it cannot create (sudo refuses): warning, uncapped, exit 0.
mkroot
rc=0; out="$(MEMCAP_CGROUP_ROOT="$WORK/cg" MEMCAP_MEMINFO="$WORK/meminfo" MEMCAP_SUDO="false" MEMCAP_NAME=t bash "$C" echo ran 2>&1)" || rc=$?
if [ "$rc" = 0 ] && grep -qF "cannot create" <<< "$out" && grep -qx ran <<< "$out"; then
  pass "sudo refused -> warning, uncapped run"
else
  fail "sudo refused: rc=$rc"; printf '%s\n' "$out" | sed 's/^/      /'
fi

# 8. A reserve that leaves under 1 GiB is refused rather than starving the build.
mkroot
run --reserve-mib 16000 echo ran
if [ "$rc" = 0 ] && grep -qF "leaves under 1 GiB" <<< "$out" && [ ! -d "$WORK/cg/t" ]; then
  pass "oversized reserve -> warning, uncapped run"
else
  fail "oversized reserve: rc=$rc"; printf '%s\n' "$out" | sed 's/^/      /'
fi

# 9. Bad usage is the only non-zero exit of its own.
rc=0; bash "$C" >/dev/null 2>&1 || rc=$?
rc2=0; bash "$C" --reserve-mib x true >/dev/null 2>&1 || rc2=$?
if [ "$rc" = 2 ] && [ "$rc2" = 2 ]; then pass "no command / bad reserve -> exit 2"; else fail "usage: rc=$rc rc2=$rc2"; fi

echo
echo "ci.yml wiring"

# 10. Every step that compiles the backend crate on a 16 GB hosted runner
#     runs it under the cap, and the image build caps buildkitd and adds
#     swap. These are the steps whose runners died or stalled (#6242).
if [ -f "$CI" ]; then
  python3 - "$CI" <<'PY' || fails=$((fails + 1))
import sys, re
text = open(sys.argv[1]).read()

def job(name):
    m = re.search(r'^  %s:\n(.*?)(?=^  [a-z0-9-]+:\n|\Z)' % re.escape(name), text, re.S | re.M)
    return m.group(1) if m else ""

def step(body, title):
    m = re.search(r'^      - name: %s\n(.*?)(?=^      - |\Z)' % re.escape(title), body, re.S | re.M)
    return m.group(1) if m else ""

bad = 0
def check(ok, msg):
    global bad
    print(("  PASS  " if ok else "  FAIL  ") + msg)
    if not ok:
        bad += 1

unit = job("test-backend-unit-shard")
build = step(unit, "Build instrumented test binaries")
check(re.search(r"^        timeout-minutes: (\d+)$", build, re.M) is not None
      and int(re.search(r"^        timeout-minutes: (\d+)$", build, re.M).group(1)) <= 30,
      "unit shards: the instrumented build step has its own timeout of at most 30 minutes")
check(build.count("scripts/ci/memory-cap.sh") >= 2,
      "unit shards: the lib and bins instrumented builds run under memory-cap.sh")
check("Add swap" in unit and "memory-watch.sh start" in unit and "memory-watch.sh report" in unit,
      "unit shards: swap, and the memory sampler started and reported")

clippy = step(job("check-rust"), "Run Clippy")
check("scripts/ci/memory-cap.sh" in clippy, "check-rust: clippy runs under memory-cap.sh")

img = job("build-backend-image")
check("Add swap" in img, "build-backend-image: adds swap before the build")
check(re.search(r'driver-opts:[^\n]*\n(?:\s+[^\n]*\n)*?\s+memory=\d+[mg]', img) is not None
      and re.search(r"memory-swap=\d+[mg]", img) is not None,
      "build-backend-image: buildkitd has a memory limit with swap allowed")
sys.exit(1 if bad else 0)
PY
else
  fail "cannot find ci.yml at $CI"
fi

echo
if [ "$fails" -gt 0 ]; then echo "${fails} case(s) FAILED"; exit 1; fi
echo "all cases passed"
