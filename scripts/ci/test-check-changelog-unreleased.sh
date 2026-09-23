#!/usr/bin/env bash
#
# Self-test for scripts/ci/check-changelog-unreleased.sh (#3433, #3676).
#
# The regression case is case 2: the exact shape `7aab4b7 chore(release):
# prepare 1.7.5` left behind — a dated version heading at the top with no
# `## [Unreleased]` above it. Everything else exists so the gate cannot pass
# by accident (a heading that merely mentions Unreleased, an `### Added`
# subsection reached first, a file with no version headings at all).
#
# Cases 9-13 cover the second assertion (#3676): at most one of each `### `
# heading inside `[Unreleased]`. The duplicate-heading shape merges cleanly
# and reads fine, so the only thing that can catch it is a check — and the
# check has to stay SCOPED to `[Unreleased]`, because released sections
# legitimately repeat prose subheadings and rewriting history is not the ask.
#
# Cases 14-24 cover the third assertion: every CHANGELOG fragment under
# changes/unreleased/ is valid. Each rule gets a fixture that breaks exactly
# that rule, so dropping the rule turns its case red; the transition case
# (bullets still under `[Unreleased]` next to fragments) must stay green.
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

echo "check-changelog-unreleased (#3433, #3676)"

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

# 9. One of each subsection heading is the normal shape.
run_case "[Unreleased] with distinct subsection headings -> clean" 0 "no duplicate" << 'EOF'
# Changelog

## [Unreleased]

### Added
- a

### Fixed
- b

### Security
- c

## [1.8.0] - 2026-08-17

### Fixed
- something
EOF

# 10. THE #3676 SHAPE: a second `### Security` block appended under the same
#     version. Both blocks are well-formed, so only a duplicate check sees it.
run_case "[Unreleased] with two ### Security blocks -> fail" 1 "### Security" << 'EOF'
# Changelog

## [Unreleased]

### Security
- **one** (#1)

### Added
- **two** (#2)

### Security
- **three** (#3)

## [1.8.0] - 2026-08-17
EOF

# 11. Released sections are historical text — several in this repo repeat a
#     prose `### Upgrade note — …` heading, and none of them are going to be
#     rewritten. The check must stop at the next `## [` heading.
run_case "duplicate heading inside a RELEASED section only -> clean" 0 "no duplicate" << 'EOF'
# Changelog

## [Unreleased]

### Fixed
- **only one here** (#1)

## [1.8.0] - 2026-08-17

### Fixed
- x

### Upgrade note — a

### Fixed
- y
EOF

# 12. Trailing whitespace must not let a duplicate through, for the same
#     reason case 6 tolerates it on the version heading.
printf '# Changelog\n\n## [Unreleased]\n\n### Fixed   \n- a\n\n### Fixed\n- b\n' > "$WORK/dup-ws.md"
out="$(CHANGELOG_FILE="$WORK/dup-ws.md" bash "$SCRIPT" 2>&1)"
got=$?
if [ "$got" = "1" ] && printf '%s\n' "$out" | grep -qF "### Fixed"; then
  pass "duplicate heading differing only in trailing whitespace -> fail (exit 1)"
else
  fail "trailing-whitespace duplicate: expected exit 1 naming '### Fixed', got $got"
  printf '%s\n' "$out" | sed 's/^/        /' >&2
fi

# 13. A freshly cut, empty [Unreleased] has no subsection headings at all.
run_case "empty [Unreleased] straight after a cut -> clean" 0 "no duplicate" << 'EOF'
# Changelog

## [Unreleased]

## [1.8.0] - 2026-08-17

### Fixed
- something
EOF

# ── fragments (third assertion) ───────────────────────────────────────────
#
# Each case gets its own directory: CHANGELOG.md plus changes/unreleased/
# holding one fragment, whose name and content are the arguments.
FRAG_GOOD=$'---\nsection: Fixed\nissues: [#4145, #4129]\n---\n- **A fix** (#4145, #4129). Why and what.\n\n  A second paragraph.\n'
frag_case() { # <label> <expected-exit> <expected-substring> <file name> <content>
  local label="$1" want="$2" needle="$3" name="$4" body="$5" d out got
  n=$((n + 1))
  d="$WORK/frag.$n"
  mkdir -p "$d/changes/unreleased"
  printf '# Changelog\n\n## [Unreleased]\n\n## [1.8.0] - 2026-08-17\n\n### Fixed\n- old\n' > "$d/CHANGELOG.md"
  printf '%s' "$body" > "$d/changes/unreleased/$name"
  out="$(CHANGELOG_FILE="$d/CHANGELOG.md" bash "$SCRIPT" 2>&1)"
  got=$?
  if [ "$got" != "$want" ]; then
    fail "$label: expected exit $want, got $got"
    printf '%s\n' "$out" | sed 's/^/        /' >&2
  elif [ -n "$needle" ] && ! printf '%s\n' "$out" | grep -qF -- "$needle"; then
    fail "$label: exit $got correct but output lacks '$needle'"
    printf '%s\n' "$out" | sed 's/^/        /' >&2
  else
    pass "$label (exit $got)"
  fi
}

# 14. The normal shape: one valid multi-paragraph fragment.
frag_case "valid fragment -> clean" 0 "1 CHANGELOG fragment(s) valid" \
  "4145-conda-repodata-deadlock.md" "$FRAG_GOOD"

# 15. A name the assembler would not order (no leading number) is refused.
frag_case "fragment name without a number -> fail" 1 "is not '<pr-or-issue-number>-<slug>.md'" \
  "conda-repodata-deadlock.md" "$FRAG_GOOD"

# 16. ...and so is one with capitals / underscores in the slug.
frag_case "fragment slug not lowercase-hyphenated -> fail" 1 "is not '<pr-or-issue-number>-<slug>.md'" \
  "4145-Conda_Deadlock.md" "$FRAG_GOOD"

# 17. A section outside Keep a Changelog's six would render nowhere.
frag_case "unknown section -> fail" 1 "section 'Bugfixes' is not one of" \
  "4145-x.md" "${FRAG_GOOD/section: Fixed/section: Bugfixes}"

# 18. No citation at all: check 5 could never reconcile the entry.
frag_case "empty issues list -> fail" 1 "issues is empty" \
  "4145-x.md" $'---\nsection: Fixed\nissues: []\n---\n- **A fix**. Why and what.\n'

# 19. An issue the front matter claims but the rendered text never mentions
#     would be invisible in CHANGELOG.md, which is what check 5 reads.
frag_case "issues entry the body never cites -> fail" 1 "issues lists #4999 but the body never cites it" \
  "4145-x.md" "${FRAG_GOOD/issues: \[#4145, #4129\]/issues: [#4145, #4999]}"

# 20. Front matter only, no bullet.
frag_case "empty body -> fail" 1 "body is empty" \
  "4145-x.md" $'---\nsection: Fixed\nissues: [#4145]\n---\n\n'

# 21. Two entries in one file: the unit of review and of ordering is one.
frag_case "two bullets in one fragment -> fail" 1 "2 top-level '- ' bullets" \
  "4145-x.md" $'---\nsection: Fixed\nissues: [#4145]\n---\n- **One** (#4145).\n- **Two** (#4145).\n'

# 22. No front matter: the section cannot be known.
frag_case "missing front matter -> fail" 1 "must start with a '---' front-matter line" \
  "4145-x.md" $'- **A fix** (#4145).\n'

# 23. A fragment dropped in changes/ instead of changes/unreleased/ would never
#     be assembled -- silently undocumented. Repo-state, so it fails here.
n=$((n + 1))
d="$WORK/frag.$n"
mkdir -p "$d/changes/unreleased"
printf '# Changelog\n\n## [Unreleased]\n' > "$d/CHANGELOG.md"
printf '%s' "$FRAG_GOOD" > "$d/changes/4145-misplaced.md"
out="$(CHANGELOG_FILE="$d/CHANGELOG.md" bash "$SCRIPT" 2>&1)"
got=$?
if [ "$got" = "1" ] && printf '%s\n' "$out" | grep -qF "not read by the assembler"; then
  pass "fragment outside changes/unreleased/ -> fail (exit 1)"
else
  fail "fragment outside changes/unreleased/: expected exit 1, got $got"
  printf '%s\n' "$out" | sed 's/^/        /' >&2
fi

# 24. THE TRANSITION WINDOW. A PR opened before fragments existed adds its
#     bullet under [Unreleased]; next to valid fragments that must still pass.
n=$((n + 1))
d="$WORK/frag.$n"
mkdir -p "$d/changes/unreleased"
printf '# Changelog\n\n## [Unreleased]\n\n### Fixed\n\n- **legacy bullet** (#4100).\n\n## [1.8.0] - 2026-08-17\n' > "$d/CHANGELOG.md"
printf '%s' "$FRAG_GOOD" > "$d/changes/unreleased/4145-x.md"
out="$(CHANGELOG_FILE="$d/CHANGELOG.md" bash "$SCRIPT" 2>&1)"
got=$?
if [ "$got" = "0" ]; then
  pass "legacy [Unreleased] bullet next to fragments -> clean (exit 0)"
else
  fail "legacy [Unreleased] bullet next to fragments: expected exit 0, got $got"
  printf '%s\n' "$out" | sed 's/^/        /' >&2
fi

# 25. Fragments present but the validator is not: INFRA, never a pass.
n=$((n + 1))
d="$WORK/frag.$n"
mkdir -p "$d/scripts/ci" "$d/changes/unreleased"
cp "$SCRIPT" "$d/scripts/ci/"
printf '# Changelog\n\n## [Unreleased]\n' > "$d/CHANGELOG.md"
printf '%s' "$FRAG_GOOD" > "$d/changes/unreleased/4145-x.md"
out="$(bash "$d/scripts/ci/check-changelog-unreleased.sh" 2>&1)"
got=$?
if [ "$got" = "2" ] && printf '%s\n' "$out" | grep -qF "INFRA"; then
  pass "fragments but no validator -> INFRA (exit 2)"
else
  fail "fragments but no validator: expected exit 2 with INFRA, got $got"
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
  pass "CHANGELOG.md and changes/unreleased/ on this tree are clean"
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
