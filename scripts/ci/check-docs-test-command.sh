#!/usr/bin/env bash
# Guard: the unit-test command CLAUDE.md tells contributors to run before
# pushing must be the runner CI actually invokes (#3479).
#
# This defect class — documentation describing a gate configuration that has
# since moved — is invisible to every other check in the repo. Docs are not
# compiled, linted or executed, so the drift only surfaces when a contributor
# follows the checklist, sees failures unrelated to their change, and learns to
# ignore red. That is worse than the failure itself.
#
# The invariant is deliberately narrow: whatever runner CI uses for the
# `--workspace --lib` unit-test job, CLAUDE.md must name the same one and must
# not still name the superseded one anywhere.
#
# Usage: check-docs-test-command.sh [repo-root]
set -euo pipefail

ROOT="${1:-$(git rev-parse --show-toplevel 2>/dev/null || echo .)}"
CI_FILE="$ROOT/.github/workflows/ci.yml"
DOC_FILE="$ROOT/CLAUDE.md"

# The runner CI invokes, and the one it replaced.
RUNNER="cargo nextest run --workspace --lib"
SUPERSEDED="cargo test --workspace --lib"

fail=0
bad() {
  echo "ERROR: $*" >&2
  fail=1
}

[ -f "$CI_FILE" ] || {
  echo "ERROR: $CI_FILE not found" >&2
  exit 2
}
[ -f "$DOC_FILE" ] || {
  echo "ERROR: $DOC_FILE not found" >&2
  exit 2
}

if ! grep -qF -- "$RUNNER" "$CI_FILE"; then
  bad "CI no longer runs '$RUNNER'. Whatever replaced it, CLAUDE.md and this guard must be updated together — that is the whole point of this check."
fi

if ! grep -qF -- "$RUNNER" "$DOC_FILE"; then
  bad "CLAUDE.md does not document '$RUNNER', which is the command CI runs for the unit-test gate."
fi

if grep -nF -- "$SUPERSEDED" "$DOC_FILE"; then
  bad "CLAUDE.md still names '$SUPERSEDED' (lines above). That runner is not what CI uses and does not pass on a clean tree (#3479); refer to plain 'cargo test' without the full flag string if you need to mention it in prose."
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "OK: CLAUDE.md's unit-test command matches CI's ($RUNNER)"
