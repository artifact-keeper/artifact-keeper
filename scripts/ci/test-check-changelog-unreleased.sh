#!/usr/bin/env bash
#
# Self-test for scripts/ci/check-changelog-unreleased.sh (#3433).
#
# The regression case is case 2: the exact shape `7aab4b7 chore(release):
# prepare 1.7.5` left behind — a dated version heading at the top with no
# `## [Unreleased]` above it. Everything else exists so the gate cannot pass
# by accident (a heading that merely mentions Unreleased, an `### Added`
# subsection reached first, a file with no version headings at all).
#
# Usage: bash scripts/ci/test-check-changelog-unreleased.sh
set -uo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/check-changelog-unreleased.sh"
[ -f "$SCRIPT" ] || {
  echo "cannot find check-changelog-unreleased.sh next to this test" >&2
  exit 2
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
n=0

pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() {
  printf '  \033[31mFAIL\033[0m  %s\n' "$*"
  fails=$((fails + 1))
}

run_case() { # <label> <expected-exit> <expected-substring> <changelog body on stdin>
  local label="$1" want="$2" needle="$3" f out got
  n=$((n + 1))
  f="$WORK/changelog.$n.md"
  cat > "$f"
  out="$(CHANGELOG_FILE="$f" bash "$SCRIPT" 2>&1)"
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

echo "check-changelog-unreleased (#3433)"

# 1. The correct shape: a fresh empty Unreleased above the newest release.
run_case "open [Unreleased] above the newest release -> clean" 0 "## [Unreleased]" << 'EOF'
# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [1.8.0] - 2026-08-17

### Fixed
- something
EOF

# 2. THE REGRESSION (#3433): the 1.7.5 prep promoted the heading and opened
#    nothing above it. Entries merged into a released section, silently.
run_case "newest heading is a released version -> fail" 1 "expected '## [Unreleased]'" << 'EOF'
# Changelog

## [1.7.5] - 2026-08-14

### Fixed
- an entry that actually belongs to 1.8.0
EOF

# 3. A heading that merely mentions the word is not an open section. Dating
#    `[Unreleased]` is the same mistake wearing the right name.
run_case "dated [Unreleased] heading -> fail" 1 "expected '## [Unreleased]'" << 'EOF'
# Changelog

## [Unreleased] - 2026-08-14

### Fixed
- x
EOF

# 4. `### Added` must not be mistaken for a version heading (grep anchored on
#    '^## \[' rather than 'Unreleased' anywhere).
run_case "subsection heading before the first version heading -> still checked" 1 "expected '## [Unreleased]'" << 'EOF'
# Changelog

### Added
- stray subsection

## [1.8.0] - 2026-08-17
- x
EOF

# 5. No version headings at all is its own error, not a pass.
run_case "no version headings -> fail" 1 "no '## [' version heading" << 'EOF'
# Changelog

Nothing here yet.
EOF

# 6. Trailing whitespace on the heading is tolerated (editors add it).
#    Written with printf rather than a heredoc so the trailing spaces survive
#    every editor and formatter that touches this file.
printf '# Changelog\n\n## [Unreleased]   \n\n## [1.8.0] - 2026-08-17\n' > "$WORK/trailing.md"
out="$(CHANGELOG_FILE="$WORK/trailing.md" bash "$SCRIPT" 2>&1)"
got=$?
if [ "$got" = "0" ]; then
  pass "trailing whitespace on the heading tolerated (exit 0)"
else
  fail "trailing whitespace: expected exit 0, got $got"
  printf '%s\n' "$out" | sed 's/^/        /' >&2
fi

# 7. Missing file is INFRA (exit 2), not a pass.
out="$(CHANGELOG_FILE="$WORK/nope.md" bash "$SCRIPT" 2>&1)"
got=$?
if [ "$got" = "2" ] && printf '%s\n' "$out" | grep -qF "INFRA"; then
  pass "missing changelog -> INFRA (exit 2)"
else
  fail "missing changelog: expected exit 2 with INFRA, got $got"
fi

# 8. The real tree must be clean — this is the live gate over CHANGELOG.md.
#    If this fails, main is stranding entries RIGHT NOW.
out="$(bash "$SCRIPT" 2>&1)"
got=$?
if [ "$got" = "0" ]; then
  pass "CHANGELOG.md on this tree has an open [Unreleased] section"
else
  fail "CHANGELOG.md on this tree: expected exit 0, got $got"
  printf '%s\n' "$out" | sed 's/^/        /' >&2
fi

echo
if [ "$fails" -gt 0 ]; then
  echo "$fails case(s) failed"
  exit 1
fi
echo "all cases passed"
