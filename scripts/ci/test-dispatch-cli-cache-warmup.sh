#!/usr/bin/env bash
#
# Self-test for scripts/ci/dispatch-cli-cache-warmup.sh (#6089).
#
# A 5xx or 429 on the warm-up dispatch is retried and, if it persists, only
# warns. Any other failure must still fail the job. Stubs `gh` with a scripted
# answer per attempt; no network, ~1s.
#
# Usage: bash scripts/ci/test-dispatch-cli-cache-warmup.sh
set -uo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dispatch-cli-cache-warmup.sh"
[ -f "$SCRIPT" ] || { echo "cannot find dispatch-cli-cache-warmup.sh next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

STUB="$WORK/bin"; mkdir -p "$STUB"
# FAKE_ANSWERS: one word per attempt, "ok", an HTTP status, or "neterr".
# Each call appends its argv to $WORK/calls.
cat > "$STUB/gh" <<'STUBGH'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FAKE_CALLS"
n="$(wc -l < "$FAKE_CALLS" | tr -d ' ')"
read -r -a answers <<<"$FAKE_ANSWERS"
a="${answers[$((n - 1))]:-ok}"
case "$a" in
  ok) exit 0 ;;
  neterr) echo 'Post "https://api.github.com/...": dial tcp: lookup api.github.com: no such host' >&2; exit 1 ;;
  *) echo "could not create workflow dispatch event: HTTP ${a}: Error (https://api.github.com/repos/o/r/actions/workflows/1/dispatches)" >&2; exit 1 ;;
esac
STUBGH
chmod +x "$STUB/gh"

# <label> <answers> <expected-exit> <expected-calls> <expected-annotation or "">
expect() {
  local label="$1" answers="$2" want_rc="$3" want_calls="$4" want_note="$5" out got_rc=0 calls
  : > "$WORK/calls"
  out="$(PATH="$STUB:$PATH" FAKE_CALLS="$WORK/calls" FAKE_ANSWERS="$answers" \
    GITHUB_REPOSITORY=o/r SHA=abc WARMUP_BACKOFF_SECONDS="0 0 0" \
    bash "$SCRIPT" 2>&1)" || got_rc=$?
  calls="$(wc -l < "$WORK/calls" | tr -d ' ')"
  if [ "$got_rc" != "$want_rc" ] || [ "$calls" != "$want_calls" ]; then
    fail "$label (wanted rc=${want_rc} calls=${want_calls}, got rc=${got_rc} calls=${calls})"
  elif [ -n "$want_note" ] && ! grep -qF -- "$want_note" <<<"$out"; then
    fail "$label (no '${want_note}' in output)"
  else
    pass "$label"
  fi
}

echo "dispatch-cli-cache-warmup.sh self-test"

expect "success on the first attempt -> one call, exit 0" \
  "ok" 0 1 "Dispatched Release CLI Caches"
expect "502 then success -> retried, exit 0" \
  "502 ok" 0 2 "Dispatched Release CLI Caches"
expect "429 then 503 then success -> retried, exit 0" \
  "429 503 ok" 0 3 "Dispatched Release CLI Caches"
expect "502 on every attempt -> 4 calls, warning, exit 0" \
  "502 502 502 502" 0 4 "::warning::"
expect "429 on every attempt -> 4 calls, warning, exit 0" \
  "429 429 429 429" 0 4 "tag run will build the CLI binaries cold"
expect "404 -> no retry, error, exit 1" \
  "404" 1 1 "::error::"
expect "403 -> no retry, error, exit 1" \
  "403" 1 1 "::error::"
expect "502 then 404 -> stops at the 404, exit 1" \
  "502 404" 1 2 "::error::"
expect "error with no HTTP status -> no retry, exit 1" \
  "neterr" 1 1 "::error::"

if [ "$fails" -eq 0 ]; then echo "all dispatch-cli-cache-warmup.sh cases passed"; exit 0; fi
echo "${fails} dispatch-cli-cache-warmup.sh case(s) FAILED"; exit 1
