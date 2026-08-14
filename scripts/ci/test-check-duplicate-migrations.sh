#!/usr/bin/env bash
#
# Self-test for scripts/ci/check-duplicate-migrations.sh (#3313).
#
# The interesting cases are the ones a naive string-prefix dedup gets wrong:
# a duplicate only visible after numeric normalisation (007 vs 7), and a gap
# that must WARN without failing. The plain-duplicate case is the regression
# guard: it is the exact shape that aborts the backend at startup (#1128).
#
# Usage: bash scripts/ci/test-check-duplicate-migrations.sh
set -uo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/check-duplicate-migrations.sh"
[ -f "$SCRIPT" ] || { echo "cannot find check-duplicate-migrations.sh next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0

pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

run_case() { # <label> <expected-exit> <expected-substring> <file>...
  local label="$1" want="$2" needle="$3"
  shift 3
  local dir out got
  dir="$(mktemp -d "$WORK/case.XXXXXX")"
  local f
  for f in "$@"; do : > "$dir/$f"; done
  out="$(MIGRATIONS_DIR="$dir" bash "$SCRIPT" 2>&1)"
  got=$?
  if [ "$got" != "$want" ]; then
    fail "$label: expected exit $want, got $got"
    printf '%s\n' "$out" | sed 's/^/        /' >&2
  elif [ -n "$needle" ] && ! printf '%s\n' "$out" | grep -qF "$needle"; then
    fail "$label: exit $got correct but output lacks '$needle'"
    printf '%s\n' "$out" | sed 's/^/        /' >&2
  else
    pass "$label (exit $got)"
  fi
}

echo "check-duplicate-migrations (#3313)"

# 1. Clean, contiguous set passes with no warning.
run_case "unique contiguous versions -> clean" 0 "no duplicates" \
  001_a.sql 002_b.sql 003_c.sql

# 2. THE REGRESSION (#1128 / the 193->195 near-miss): two files claim the
#    same version. Mergeable CLEAN in git; must be red here.
run_case "duplicate version -> fail" 1 "duplicate migration version 193" \
  192_a.sql 193_b.sql 193_c.sql

# 3. Numeric normalisation: 007 and 7 are the same sqlx version even though
#    their string prefixes differ. A string dedup passes this; we must not.
run_case "leading-zero duplicate -> fail" 1 "duplicate migration version 7" \
  007_a.sql 7_b.sql

# 4. A gap WARNS but does not block (legitimate gaps exist in history and
#    renumbering shipped migrations is the mistake being guarded against).
run_case "gap in sequence -> warn, exit 0" 0 "gap(s) in migration version sequence" \
  001_a.sql 003_c.sql

# 5. A file sqlx cannot order is an error, not silently skipped.
run_case "non-numeric prefix -> fail" 1 "no numeric version prefix" \
  001_a.sql notes.sql

# 6. Missing directory is INFRA (exit 2), not a pass.
out="$(MIGRATIONS_DIR="$WORK/does-not-exist" bash "$SCRIPT" 2>&1)"; got=$?
if [ "$got" = "2" ] && printf '%s\n' "$out" | grep -qF "INFRA"; then
  pass "missing directory -> INFRA (exit 2)"
else
  fail "missing directory: expected exit 2 with INFRA, got $got"
fi

# 7. The real tree must be clean (this is the live gate over
#    backend/migrations/ — if this fails, main has a duplicate RIGHT NOW).
out="$(bash "$SCRIPT" 2>&1)"; got=$?
if [ "$got" = "0" ]; then
  pass "backend/migrations/ on this tree is duplicate-free"
else
  fail "backend/migrations/ has a duplicate or unparseable version:"
  printf '%s\n' "$out" | sed 's/^/        /' >&2
fi

echo
if [ "$fails" -eq 0 ]; then
  echo "all check-duplicate-migrations cases passed"
  exit 0
fi
echo "$fails case(s) failed"
exit 1
