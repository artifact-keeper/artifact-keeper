#!/usr/bin/env bash
#
# Self-test for scripts/ci/assert-changelog-documents-version.sh (#3771).
# The check moved out of release.yml so the candidate can run it on a commit;
# this pins that the move changed nothing: a documented stable version passes,
# a missing or empty section is refused, a prerelease is exempt.
set -uo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assert-changelog-documents-version.sh"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
fails=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

expect() { # <label> <want-rc> <version> <file>
  local rc=0
  bash "$SCRIPT" "$3" "$4" >/dev/null 2>&1 || rc=$?
  if [ "$rc" = "$2" ]; then pass "$1"; else fail "$1 (wanted rc=$2, got $rc)"; fi
}

cat > "$WORK/good.md" <<'MD'
# Changelog

## [Unreleased]

## [1.9.0] - 2026-09-08

### Fixed

- **A fix** (#1). Prose.

## [1.8.2] - 2026-09-01
MD
cat > "$WORK/empty.md" <<'MD'
## [Unreleased]

## [1.9.0] - 2026-09-08

## [1.8.2] - 2026-09-01

- old
MD
cat > "$WORK/missing.md" <<'MD'
## [Unreleased]

## [1.8.2] - 2026-09-01

- old
MD

echo "assert-changelog-documents-version.sh self-test"
expect "documented stable version -> 0"          0 1.9.0   "$WORK/good.md"
expect "v-prefixed tag accepted -> 0"            0 v1.9.0  "$WORK/good.md"
expect "heading present, no content -> 1"        1 1.9.0   "$WORK/empty.md"
expect "no heading at all -> 1"                  1 1.9.0   "$WORK/missing.md"
expect "prerelease is exempt -> 0"               0 1.9.0-rc.1 "$WORK/missing.md"
expect "changelog file missing -> 1"             1 1.9.0   "$WORK/nope.md"
# A section written by the fragment assembler (the release prep since
# changes/unreleased/) is what this check reads at the cut: it must pass, and
# the fresh [Unreleased] the assembler leaves must not count as the release.
mkdir -p "$WORK/asm/changes/unreleased"
cp "$WORK/missing.md" "$WORK/asm/CHANGELOG.md"
printf -- '---\nsection: Fixed\nissues: [#4200]\n---\n- **A fix** (#4200). Prose.\n' \
  > "$WORK/asm/changes/unreleased/4200-a-fix.md"
if python3 "$(dirname "$SCRIPT")/changelog-fragments.py" assemble 1.9.0 --date 2026-09-08 \
    --changelog "$WORK/asm/CHANGELOG.md" --dir "$WORK/asm/changes/unreleased" 2>/dev/null; then
  expect "section written by the fragment assembler -> 0" 0 1.9.0 "$WORK/asm/CHANGELOG.md"
  expect "...and a version it did not write -> 1"         1 1.9.1 "$WORK/asm/CHANGELOG.md"
else
  fail "the assembler refused the fixture"
fi
rc=0; out="$(bash "$SCRIPT" 1.9.0 "$WORK/missing.md" 2>&1)" || rc=$?
if [ "$rc" = "1" ] && printf '%s' "$out" | grep -qF "scripts/release/assemble-changelog.sh 1.9.0"; then
  pass "missing section names the assembler as the fix"
else
  fail "missing section should point at scripts/release/assemble-changelog.sh (rc=$rc)"
fi
rc=0; bash "$SCRIPT" >/dev/null 2>&1 || rc=$?
if [ "$rc" = "2" ]; then pass "no arguments -> usage (2)"; else fail "usage (got $rc)"; fi

echo
if [ "$fails" -eq 0 ]; then echo "all assert-changelog-documents-version.sh cases passed"; exit 0; fi
echo "${fails} case(s) FAILED"; exit 1
