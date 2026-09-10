#!/usr/bin/env bash
# Self-test for check-docs-test-command.sh (#3479).
#
# The guard is only worth having if it can fail, so each case below builds a
# throwaway repo shape and asserts the exit status: the drifted shapes that
# actually occurred (docs naming the superseded runner; CI moving without the
# docs following) must be rejected, and the corrected shape accepted.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD="$HERE/check-docs-test-command.sh"

pass=0
fail=0

make_tree() { # <dir> <ci-command> <doc-command>
  local dir="$1" ci_cmd="$2" doc_cmd="$3"
  mkdir -p "$dir/.github/workflows"
  cat >"$dir/.github/workflows/ci.yml" <<EOF
jobs:
  test-backend-unit:
    steps:
      - name: Run unit tests
        run: $ci_cmd
EOF
  cat >"$dir/CLAUDE.md" <<EOF
### Pre-push Quality Checklist

\`\`\`bash
cargo fmt --check
$doc_cmd
\`\`\`
EOF
}

check() { # <label> <expected-status> <dir>
  local label="$1" expected="$2" dir="$3" status=0
  "$GUARD" "$dir" >/dev/null 2>&1 || status=$?
  if [ "$status" -eq "$expected" ]; then
    echo "  ok   $label (exit $status)"
    pass=$((pass + 1))
  else
    echo "  FAIL $label: expected exit $expected, got $status"
    fail=$((fail + 1))
  fi
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "check-docs-test-command self-test"

# Corrected shape: CI and the docs name the same runner.
make_tree "$tmp/good" \
  "cargo nextest run --workspace --lib --test-threads 8" \
  "cargo nextest run --workspace --lib --test-threads 8"
check "matching runner is accepted" 0 "$tmp/good"

# The #3479 shape: CI moved to nextest, the checklist still says cargo test.
make_tree "$tmp/stale-doc" \
  "cargo nextest run --workspace --lib --test-threads 8" \
  "cargo test --workspace --lib"
check "docs naming the superseded runner is rejected" 1 "$tmp/stale-doc"

# The docs name neither runner (e.g. the checklist line was deleted).
make_tree "$tmp/missing-doc" \
  "cargo nextest run --workspace --lib --test-threads 8" \
  "cargo build --workspace"
check "docs missing the runner entirely is rejected" 1 "$tmp/missing-doc"

# CI moves off nextest without the docs (or this guard) following.
make_tree "$tmp/ci-moved" \
  "cargo test --workspace --lib" \
  "cargo nextest run --workspace --lib --test-threads 8"
check "CI moving away from the documented runner is rejected" 1 "$tmp/ci-moved"

# A tree with no CLAUDE.md is a usage error, not a drift verdict.
mkdir -p "$tmp/no-doc/.github/workflows"
echo "run: cargo nextest run --workspace --lib" >"$tmp/no-doc/.github/workflows/ci.yml"
check "a missing CLAUDE.md is a usage error" 2 "$tmp/no-doc"

# The real repository must pass.
check "this repository passes" 0 "$(cd "$HERE/../.." && pwd)"

echo "  $pass passed, $fail failed"
[ "$fail" -eq 0 ]
