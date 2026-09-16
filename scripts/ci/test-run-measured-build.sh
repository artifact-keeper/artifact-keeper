#!/usr/bin/env bash
# Self-test for run-measured-build.sh (#3856).
#
# The wrapper only earns its place if the retry is NARROW and the SIGKILL is
# still visible afterwards, and neither is observable on a green run: the
# interesting cases only happen when the runner is out of memory, which is
# exactly what cannot be reproduced on demand. So each case below stands a
# fake command in for the instrumented build — one that exits 137, one that
# prints cargo's "(signal: 9 (SIGKILL))" line and exits 101 the way a killed
# child rustc really does, one that fails for an ordinary reason, and one that
# fails once and then succeeds — and asserts the exit status, the number of
# attempts, and what landed in the step summary.
#
# Usage: bash scripts/ci/test-run-measured-build.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$HERE/run-measured-build.sh"

pass=0
fail=0

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# A fake build command. Each invocation appends a line to $tmp/attempts so the
# test can count how many times it ran; MODE decides how it behaves, and
# "flaky-*" modes fail on the first attempt only.
cat >"$tmp/fake-build" <<'EOF'
#!/usr/bin/env bash
echo "compiling $*"
n=$(( $(wc -l <"$ATTEMPTS" 2>/dev/null || echo 0) + 1 ))
echo "attempt" >>"$ATTEMPTS"
case "$MODE" in
  ok)        exit 0 ;;
  sigkill)   kill -9 $$ ;;
  cargo-oom)
    echo "error: process didn't exit successfully: \`rustc --crate-name artifact_keeper_backend -C instrument-coverage\` (signal: 9 (SIGKILL))" >&2
    exit 101 ;;
  compile-error)
    echo "error[E0425]: cannot find value \`nope\` in this scope" >&2
    exit 101 ;;
  flaky-sigkill)
    [ "$n" -eq 1 ] && kill -9 $$
    exit 0 ;;
  flaky-cargo-oom)
    if [ "$n" -eq 1 ]; then
      echo "error: could not compile (signal: 9 (SIGKILL))" >&2
      exit 101
    fi
    exit 0 ;;
esac
EOF
chmod +x "$tmp/fake-build"

run_case() { # <label> <mode> ; sets status/attempts/summary for the assertions
  local label="$1" mode="$2"
  : >"$tmp/attempts"
  : >"$tmp/summary.md"
  status=0
  MODE="$mode" ATTEMPTS="$tmp/attempts" GITHUB_STEP_SUMMARY="$tmp/summary.md" \
    "$RUNNER" "$label" "$tmp/fake-build" --workspace --lib --no-run \
    >"$tmp/stdout.log" 2>&1 || status=$?
  attempts="$(wc -l <"$tmp/attempts")"
  summary="$(cat "$tmp/summary.md")"
}

check() { # <label> <expected> <actual>
  if [ "$2" = "$3" ]; then
    echo "  ok   $1"
    pass=$((pass + 1))
  else
    echo "  FAIL $1: expected '$2', got '$3'"
    fail=$((fail + 1))
  fi
}

check_contains() { # <label> <needle> <haystack>
  case "$3" in
    *"$2"*)
      echo "  ok   $1"
      pass=$((pass + 1)) ;;
    *)
      echo "  FAIL $1: '$2' not found in:"
      printf '%s\n' "$3" | sed 's/^/        /'
      fail=$((fail + 1)) ;;
  esac
}

echo "run-measured-build self-test"

# A green build runs once, exits 0, and still records a measurement.
run_case lib ok
check "green build exits 0" 0 "$status"
check "green build is not retried" 1 "$attempts"
check_contains "green build records a peak RSS row" "| lib | 1 |" "$summary"
check_contains "green build is reported ok" "| ok |" "$summary"

# The measurement is a real number, not a placeholder, when GNU time is there.
if [ -x /usr/bin/time ] && /usr/bin/time -v true >/dev/null 2>&1; then
  check_contains "peak RSS is a real measurement, not n/a" "iB |" "$summary"
else
  echo "  skip GNU time unavailable; peak RSS reported as n/a"
fi

# The step itself dying on signal 9 (exit 137) is retried exactly once.
run_case lib sigkill
check "unrecoverable SIGKILL exits 137" 137 "$status"
check "SIGKILL is retried exactly once" 2 "$attempts"
check_contains "first SIGKILL is written to the summary" "SIGKILL (out of memory) — retrying" "$summary"
check_contains "exhausted retries stay in the summary" "retries exhausted" "$summary"

# #3856's actual shape: the child rustc is killed, cargo survives and exits
# 101. An exit-status-only test would miss this entirely.
run_case lib cargo-oom
check "cargo-reported SIGKILL propagates cargo's status" 101 "$status"
check "cargo-reported SIGKILL is retried once" 2 "$attempts"
check_contains "cargo-reported SIGKILL is in the summary" "SIGKILL (out of memory)" "$summary"

# Everything that is not a SIGKILL must fail on the first attempt, unchanged.
run_case lib compile-error
check "a compile error is not retried" 1 "$attempts"
check "a compile error keeps its exit status" 101 "$status"
check_contains "a compile error is reported as a failure" "failed (exit 101)" "$summary"

# The case the retry exists for: one OOM, then a clean build.
run_case lib flaky-sigkill
check "a single SIGKILL then success exits 0" 0 "$status"
check "the retry actually ran" 2 "$attempts"
check_contains "the SIGKILL is recorded even though the step passed" "SIGKILL (out of memory) — retrying" "$summary"
check_contains "the successful retry is recorded too" "| lib | 2 |" "$summary"

run_case bins flaky-cargo-oom
check "a single cargo-reported OOM then success exits 0" 0 "$status"
check "the cargo-reported OOM retry ran" 2 "$attempts"
check_contains "the retried target is named in the summary" "| bins | 2 |" "$summary"

# Retries are configurable and 0 disables them, so the wrapper can measure
# without ever re-rolling if the trend data says a retry is the wrong answer.
: >"$tmp/attempts"
: >"$tmp/summary.md"
status=0
MODE=sigkill ATTEMPTS="$tmp/attempts" GITHUB_STEP_SUMMARY="$tmp/summary.md" \
  MEASURED_BUILD_RETRIES=0 \
  "$RUNNER" lib "$tmp/fake-build" >/dev/null 2>&1 || status=$?
check "MEASURED_BUILD_RETRIES=0 disables the retry" 1 "$(wc -l <"$tmp/attempts")"
check "MEASURED_BUILD_RETRIES=0 still fails" 137 "$status"
check_contains "MEASURED_BUILD_RETRIES=0 still records the SIGKILL" "SIGKILL (out of memory)" "$(cat "$tmp/summary.md")"

# Without GNU time the build must still run, retry, and report — a missing
# measurement may never turn a passing build red.
: >"$tmp/attempts"
: >"$tmp/summary.md"
status=0
MODE=flaky-cargo-oom ATTEMPTS="$tmp/attempts" GITHUB_STEP_SUMMARY="$tmp/summary.md" \
  MEASURED_BUILD_TIME_BIN="$tmp/no-such-time" \
  "$RUNNER" lib "$tmp/fake-build" >/dev/null 2>&1 || status=$?
check "no GNU time still succeeds after the retry" 0 "$status"
check "no GNU time still retries" 2 "$(wc -l <"$tmp/attempts")"
check_contains "no GNU time reports n/a rather than failing" "n/a" "$(cat "$tmp/summary.md")"

# Missing arguments are a usage error, not a build verdict.
status=0
"$RUNNER" lib >/dev/null 2>&1 || status=$?
check "a missing command is a usage error" 2 "$status"

# No summary file configured (local runs) must not be fatal.
status=0
MODE=ok ATTEMPTS="$tmp/attempts" "$RUNNER" lib "$tmp/fake-build" >/dev/null 2>&1 || status=$?
check "an unset GITHUB_STEP_SUMMARY is tolerated" 0 "$status"

echo "  $pass passed, $fail failed"
[ "$fail" -eq 0 ]
