#!/usr/bin/env bash
# Self-test for .githooks/pre-push (#5182).
#
# The hook ran plain `cargo test` and claimed to need no database, so it could
# not pass on a clean checkout and every push had to bypass it. CI does not run
# the hook, so nothing noticed. Each case below runs the real hook against a
# stub `cargo` and asserts what it ran and how it exited: by default it needs
# nothing but cargo, and the opt-in test run uses CI's runner and says what is
# missing rather than failing on tests that have nothing to do with the change.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
HOOK="$ROOT/.githooks/pre-push"

pass=0
fail=0

ok() {
  echo "  ok   $1"
  pass=$((pass + 1))
}

ko() {
  echo "  FAIL $1"
  fail=$((fail + 1))
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir "$tmp/stub" "$tmp/empty"
cat >"$tmp/stub/cargo" <<'EOF'
#!/bin/sh
echo "$* | offline=${SQLX_OFFLINE:-} require_db=${AK_TESTS_REQUIRE_DB:-} jwt=${JWT_SECRET:-}" >>"$STUB_LOG"
case "$1" in
  check) exit "${STUB_CHECK_RC:-0}" ;;
  nextest)
    if [ "$2" = "--version" ]; then
      exit "${STUB_NEXTEST_VERSION_RC:-0}"
    fi
    exit "${STUB_NEXTEST_RC:-0}"
    ;;
esac
echo "stub cargo: the hook must not run 'cargo $1'" >&2
exit 99
EOF
chmod +x "$tmp/stub/cargo"

log="$tmp/cargo.log"
out="$tmp/output"

run_hook() { # <VAR=value>... ; sets $status
  : >"$log"
  status=0
  env -u AK_PRE_PUSH_TESTS -u DATABASE_URL -u JWT_SECRET -u AK_TESTS_REQUIRE_DB -u SQLX_OFFLINE \
    STUB_LOG="$log" PATH="$tmp/stub:$PATH" "$@" sh "$HOOK" >"$out" 2>&1 || status=$?
}

expect() { # <label> <expected-status> <expected-cargo-subcommand-count>
  local label="$1" want_status="$2" want_runs="$3" runs
  runs="$(grep -cv -- '--version' "$log" || true)"
  if [ "$status" -eq "$want_status" ] && [ "$runs" -eq "$want_runs" ]; then
    ok "$label"
  else
    ko "$label: exit $status (want $want_status), $runs cargo runs (want $want_runs)"
    cat "$log" "$out"
  fi
}

mentions() { # <label> <file> <fixed-string>
  if grep -qF -- "$3" "$2"; then
    ok "$1"
  else
    ko "$1: no '$3' in $2"
    cat "$2"
  fi
}

echo "pre-push hook self-test"

# The clean checkout: cargo and nothing else.
run_hook
expect "default run passes with only cargo" 0 1
mentions "default run checks the whole workspace offline" "$log" \
  "check --workspace --all-targets | offline=true"
mentions "default run says the tests were not run" "$out" "unit tests not run here"

run_hook STUB_CHECK_RC=1
expect "a compile error blocks the push" 1 1
mentions "a compile error says so" "$out" "Build failed"

# No cargo at all: not this hook's call to make.
: >"$log"
status=0
env -u AK_PRE_PUSH_TESTS PATH="$tmp/empty" /bin/sh "$HOOK" >"$out" 2>&1 || status=$?
expect "no cargo skips the checks" 0 0

# The opt-in run stops on what is missing, before spending a test build.
run_hook AK_PRE_PUSH_TESTS=1 STUB_NEXTEST_VERSION_RC=101 DATABASE_URL=postgresql://h/db
expect "opt-in without nextest fails before testing" 1 1
mentions "opt-in without nextest says how to install it" "$out" "cargo install cargo-nextest"

run_hook AK_PRE_PUSH_TESTS=1
expect "opt-in without a database fails before testing" 1 1
mentions "opt-in without a database says how to get one" "$out" "./scripts/dev.sh start"

# The opt-in run itself.
run_hook AK_PRE_PUSH_TESTS=1 DATABASE_URL=postgresql://h/db
expect "opt-in with its setup passes" 0 2
mentions "opt-in runs CI's runner and fails on an unreachable database" "$log" \
  "nextest run --workspace --lib --test-threads 8 | offline=true require_db=1 jwt=pre-push-hook"

run_hook AK_PRE_PUSH_TESTS=1 DATABASE_URL=postgresql://h/db JWT_SECRET=mine
mentions "opt-in keeps the caller's JWT_SECRET" "$log" "jwt=mine"

run_hook AK_PRE_PUSH_TESTS=1 DATABASE_URL=postgresql://h/db STUB_NEXTEST_RC=100
expect "a failing test blocks the push" 1 2
mentions "a failing test says so" "$out" "Unit tests failed"

# The runner has to stay the one CI uses, and the docs have to say what the
# hook needs (the other half of #5182).
mentions "CI still runs the hook's runner" "$ROOT/.github/workflows/ci.yml" \
  "cargo nextest run --workspace --lib"
mentions "CONTRIBUTING documents the opt-in" "$ROOT/CONTRIBUTING.md" "AK_PRE_PUSH_TESTS=1"
for doc in CONTRIBUTING.md TESTING.md scripts/setup-hooks.sh .githooks/pre-commit; do
  if grep -nE 'cargo test --workspace|[Nn]o database need' "$ROOT/$doc"; then
    ko "$doc must not name the old hook command or say no database is needed"
  else
    ok "$doc matches what the hook needs"
  fi
done

echo "pre-push hook self-test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
