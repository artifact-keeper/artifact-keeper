#!/usr/bin/env bash
# =============================================================================
# test-apt-install-bounded.sh — the bounded apt install (#6272) gives up on a
#                               hung mirror, retries on azure, and never
#                               time-boxes the unpack
# =============================================================================
#
# Runs scripts/ci/apt-install-bounded.sh against a stub `apt-get` whose
# behaviour depends on the mirror list it sees: hang, fail fast, or succeed.
# No network, no root, ~10s (a 2s per-attempt timeout). Needs GNU `timeout`.
#
# Usage: bash scripts/ci/test-apt-install-bounded.sh
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/scripts/ci/apt-install-bounded.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

failures=0
pass() { echo "  ok   $1"; }
fail() { echo "  FAIL $1" >&2; failures=$((failures + 1)); }

# The stub: MODE_SLOW says what the image's (non-azure) mirror does on
# update, MODE_AZURE what azure does. The final, real install (no
# --download-only) sleeps longer than the per-attempt timeout, so it only
# succeeds if it runs without one.
cat > "$WORK/apt-get" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "$STUB_LOG"
if grep -q azure "$APT_MIRRORS_FILE" 2>/dev/null; then mode="$MODE_AZURE"; else mode="$MODE_SLOW"; fi
case "$1" in
  update)
    case "$mode" in
      hang) sleep 30 ;;
      fail) echo "E: Failed to fetch (stub network error)" >&2; exit 100 ;;
    esac
    ;;
  install)
    if [ "$2" = "--download-only" ]; then exit 0; fi
    sleep 3
    echo installed >> "$STUB_LOG"
    ;;
esac
STUB
chmod +x "$WORK/apt-get"

# run <mode-slow> <mode-azure> [packages...] -> sets rc, elapsed
run() {
  local slow="$1" azure="$2"; shift 2
  : > "$WORK/log"
  printf 'http://us-east-2.ec2.archive.ubuntu.com/ubuntu/\tpriority:1\n' > "$WORK/mirrors"
  local start=$SECONDS
  rc=0
  env APT_GET="$WORK/apt-get" SUDO="" APT_MIRRORS_FILE="$WORK/mirrors" \
      APT_ATTEMPT_TIMEOUT=2s APT_RETRY_SLEEP=0 STUB_LOG="$WORK/log" \
      MODE_SLOW="$slow" MODE_AZURE="$azure" \
      bash "$SCRIPT" "$@" > "$WORK/out" 2>&1 || rc=$?
  elapsed=$((SECONDS - start))
}

echo "apt-install-bounded.sh"

run ok ok protobuf-compiler
if [ "$rc" = 0 ] && grep -qx installed "$WORK/log" && grep -qx 'install -y protobuf-compiler' "$WORK/log"; then
  pass "healthy mirror: downloads, then installs (the unpack outlives the 2s attempt timeout)"
else
  fail "healthy mirror: rc=$rc"; sed 's/^/        /' "$WORK/out" "$WORK/log" >&2
fi
if ! grep -q azure "$WORK/mirrors"; then
  pass "healthy mirror: the mirror list is left alone"
else
  fail "healthy mirror: the mirror list was rewritten"
fi

run hang ok protobuf-compiler libprotobuf-dev
if [ "$rc" = 0 ] && grep -qx installed "$WORK/log" && grep -q azure "$WORK/mirrors" && [ "$elapsed" -lt 20 ]; then
  pass "hung mirror: the attempt is killed and the retry on azure installs (${elapsed}s)"
else
  fail "hung mirror: rc=$rc elapsed=${elapsed}s"; sed 's/^/        /' "$WORK/out" "$WORK/log" >&2
fi
if grep -q 'title=Slow apt mirror' "$WORK/out"; then
  pass "hung mirror: the fallback is announced as a warning"
else
  fail "hung mirror: no ::warning for the fallback"
fi

run fail ok protobuf-compiler
if [ "$rc" = 0 ] && grep -qx installed "$WORK/log" && [ "$(grep -c '^update' "$WORK/log")" = 2 ]; then
  pass "network error: fails fast, the second attempt installs"
else
  fail "network error: rc=$rc"; sed 's/^/        /' "$WORK/out" "$WORK/log" >&2
fi

run hang hang protobuf-compiler
if [ "$rc" = 1 ] && ! grep -qx installed "$WORK/log" && [ "$(grep -c '^update' "$WORK/log")" = 3 ] && [ "$elapsed" -lt 20 ]; then
  pass "every mirror hung: gives up after 3 bounded attempts, no install (${elapsed}s)"
else
  fail "every mirror hung: rc=$rc elapsed=${elapsed}s"; sed 's/^/        /' "$WORK/out" "$WORK/log" >&2
fi
if grep -q 'title=apt download failed' "$WORK/out"; then
  pass "every mirror hung: reported as an ::error"
else
  fail "every mirror hung: no ::error"
fi

run ok ok
if [ "$rc" = 2 ]; then
  pass "no packages: usage error"
else
  fail "no packages: rc=$rc, want 2"
fi

echo
if [ "$failures" -gt 0 ]; then
  echo "FAILED: $failures assertion(s)" >&2
  exit 1
fi
echo "all passed"
