#!/usr/bin/env bash
#
# Self-test for scripts/ci/check-conflict-markers.sh (#3676).
#
# The gate is a single grep, so the risk is not that it stops working -- it is
# that it works on the wrong things. Both directions are exercised here:
#
#   - it must FAIL on each of the three marker forms, in a Markdown file (the
#     #3664 shape), in a workflow file, and on an ours/theirs block whose
#     `=======` line is the only one of the three present;
#   - it must PASS on the near-misses that occur in real content: a run of
#     angle brackets with no trailing space (ASCII art, a shell heredoc
#     delimiter), a Markdown setext underline of some length other than seven,
#     an indented marker inside a fenced code block that documents conflicts,
#     and a genuine conflicted hunk inside a *.diff / *.patch file.
#
# Every marker in this file is BUILT AT RUN TIME from the variables below and
# never written literally at column 0 -- otherwise this test would itself be
# the thing the live gate reports.
#
# Usage: bash scripts/ci/test-check-conflict-markers.sh
set -uo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/check-conflict-markers.sh"
[ -f "$SCRIPT" ] || {
  echo "cannot find check-conflict-markers.sh next to this test" >&2
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

# The three marker lines, assembled so they never appear literally here.
OPEN="$(printf '<%.0s' 1 2 3 4 5 6 7) ours"
MID="$(printf '=%.0s' 1 2 3 4 5 6 7)"
CLOSE="$(printf '>%.0s' 1 2 3 4 5 6 7) theirs"

# Sets $r to a fresh throwaway repository. A function that PRINTED the path
# would run in a subshell, and the case counter would not survive it -- every
# case would then share one repo and inherit the previous case's markers.
make_repo() {
  n=$((n + 1))
  r="$WORK/repo.$n"
  mkdir -p "$r"
  git -C "$r" init -q -b main . > /dev/null
  git -C "$r" config user.email t@example.com
  git -C "$r" config user.name t
  git -C "$r" config commit.gpgsign false
  printf '# fixture\n' > "$r/README.md"
}

write_file() { # <repo> <relative path> ; content on stdin
  mkdir -p "$(dirname "$1/$2")"
  cat > "$1/$2"
}

commit_all() { git -C "$1" add -A && git -C "$1" commit -qm fixture > /dev/null; }

run_case() { # <label> <expected-exit> <expected-substring> <repo>
  local label="$1" want="$2" needle="$3" repo="$4" out got
  out="$(CONFLICT_MARKER_ROOT="$repo" bash "$SCRIPT" 2>&1)"
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

echo "check-conflict-markers (#3676)"

# 1. A clean repo.
make_repo
printf 'nothing to see\n' > "$r/CHANGELOG.md"
commit_all "$r"
run_case "clean repo -> pass" 0 "none in tracked files" "$r"

# 2. THE REGRESSION (#3664/#3675): a full conflict block left in CHANGELOG.md
#    between two bullets. Markdown, so nothing else in CI would have noticed.
make_repo
{
  printf '## [Unreleased]\n\n### Security\n\n- **one** (#1).\n'
  printf '%s\n' "$OPEN"
  printf -- '- **two** (#2).\n'
  printf '%s\n' "$MID"
  printf -- '- **three** (#3).\n'
  printf '%s\n' "$CLOSE"
} > "$r/CHANGELOG.md"
commit_all "$r"
run_case "conflict block in CHANGELOG.md -> fail" 1 "Committed git conflict markers" "$r"

# 3. Each marker form must fail ON ITS OWN. A half-resolved conflict where
#    only one line survived is the easy thing to miss by eye.
for form in OPEN MID CLOSE; do
  make_repo
  printf 'a\n%s\nb\n' "${!form}" | write_file "$r" .github/workflows/note.yml
  commit_all "$r"
  run_case "lone marker ($form) in a YAML file -> fail" 1 "conflict" "$r"
done

# 4. Angle brackets with NO trailing space are not a marker: heredoc
#    delimiters, ASCII arrows and redirect chains all start lines like this.
make_repo
printf '%s\n%s\n' "$(printf '<%.0s' 1 2 3 4 5 6 7)HEREDOC" "$(printf '>%.0s' 1 2 3 4 5 6 7 8)" > "$r/notes.md"
commit_all "$r"
run_case "angle-bracket run without a trailing space -> pass" 0 "none in tracked files" "$r"

# 5. A Markdown setext underline is a row of `=` as long as its title, which
#    is seven characters only by coincidence. Six and eight must pass; the
#    exactly-seven case is accepted as the price of catching the real marker.
make_repo
printf 'Title\n%s\n\nHeading\n%s\n' "$(printf '=%.0s' 1 2 3 4 5 6)" "$(printf '=%.0s' 1 2 3 4 5 6 7 8)" > "$r/doc.md"
commit_all "$r"
run_case "setext underlines of six and eight -> pass" 0 "none in tracked files" "$r"

# 6. Documentation that SHOWS a conflict, indented inside a fenced block, is
#    not a conflict. The pattern is anchored at column 0 for this reason --
#    this file and check-conflict-markers.sh both depend on it.
make_repo
{
  printf 'A conflict looks like:\n\n'
  printf '    %s\n' "$OPEN"
  printf '    %s\n' "$MID"
  printf '    %s\n' "$CLOSE"
} > "$r/CONTRIBUTING.md"
commit_all "$r"
run_case "indented markers inside prose -> pass" 0 "none in tracked files" "$r"

# 7. *.diff and *.patch legitimately carry whatever they carry, at any depth.
make_repo
printf '%s\n%s\n%s\n' "$OPEN" "$MID" "$CLOSE" > "$r/fixture.patch"
printf '%s\n%s\n%s\n' "$OPEN" "$MID" "$CLOSE" | write_file "$r" tests/data/conflicted.diff
commit_all "$r"
run_case "markers inside *.patch and a nested *.diff -> pass" 0 "none in tracked files" "$r"

# 8. UNTRACKED files are not the repository's content. A contributor's local
#    conflicted scratch file must not fail everyone else's CI.
make_repo
commit_all "$r"
printf '%s\n%s\n%s\n' "$OPEN" "$MID" "$CLOSE" > "$r/scratch.md"
run_case "markers in an untracked file -> pass" 0 "none in tracked files" "$r"

# 9. The offending lines must be NAMED. A gate that says only "markers found"
#    sends the reader looking through the whole tree.
make_repo
printf 'x\n%s\ny\n' "$MID" | write_file "$r" deep/nested/file.yaml
commit_all "$r"
out="$(CONFLICT_MARKER_ROOT="$r" bash "$SCRIPT" 2>&1)"
got=$?
if [ "$got" = "1" ] && printf '%s\n' "$out" | grep -qF "deep/nested/file.yaml:2:"; then
  pass "failure output names the file and line (exit 1)"
else
  fail "failure output should name deep/nested/file.yaml:2 (exit $got)"
  printf '%s\n' "$out" | sed 's/^/        /' >&2
fi

# 10. A directory that is not a git repository is INFRA, never a pass -- an
#     unmeasurable tree must not read as a clean one.
out="$(CONFLICT_MARKER_ROOT="$WORK/not-a-repo" bash "$SCRIPT" 2>&1)"
got=$?
if [ "$got" = "2" ] && printf '%s\n' "$out" | grep -qF "INFRA"; then
  pass "non-repository -> INFRA (exit 2)"
else
  fail "non-repository: expected exit 2 with INFRA, got $got"
fi

# 11. The real tree must be clean -- this is the live gate over this checkout.
out="$(bash "$SCRIPT" 2>&1)"
got=$?
if [ "$got" = "0" ]; then
  pass "this checkout has no committed conflict markers"
else
  fail "this checkout: expected exit 0, got $got"
  printf '%s\n' "$out" | sed 's/^/        /' >&2
fi

echo
if [ "$fails" -gt 0 ]; then
  echo "$fails case(s) failed"
  exit 1
fi
echo "all cases passed"
