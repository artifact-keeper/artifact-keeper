#!/usr/bin/env bash
#
# CI gate for issue #3676: nothing in this repository rejected committed git
# conflict markers.
#
# What happened: `d980ea92` (#3664) merged into `main` with CHANGELOG.md still
# carrying a three-line conflict block between two `[Unreleased]` ->
# `### Security` bullets, and every check was green. The markers sat on `main`
# for ~3 hours and three later PRs inherited them through their merges of main
# before #3675 removed them. Had 1.9.0 been cut in that window, the promoted
# CHANGELOG section and the release notes would have carried them verbatim.
#
# Nothing caught it because nothing looks: check-changelog-unreleased.sh only
# asserts the first `## [` heading, release-preflight.sh check 5 reconciles
# bullets by `#NNNN` reference (both bullets were intact, so it passed too),
# and no other check reads the file at all.
#
# The same shape can hit any file. A `.sql` migration or a `.rs` source would
# fail to compile, so the compiler is the gate there -- but Markdown, YAML
# comments, `.env.example`, Helm templates and workflow files all merge, ship
# and run with the markers still in them. So the scan is repo-wide rather than
# CHANGELOG-only.
#
# The assertion is one `git grep` over the TRACKED files:
#
#     ^<<<<<<<␣   ^=======$   ^>>>>>>>␣
#
# anchored at column 0. The two `<`/`>` forms require the trailing space that
# git always writes before the branch/label name, so a run of angle brackets
# in prose or in an ASCII diagram does not match; `=======` must be exactly
# seven characters on its own line, so a Markdown setext underline (which is
# as long as its title) does not match either.
#
# diff3-style conflicts additionally write a `|||||||` base line. It is
# deliberately NOT matched: every diff3 conflict also contains the `=======`
# line, so the conflict is still caught, and `|` at column 0 is a legitimate
# Markdown table row.
#
# Exclusions:
#   *.diff, *.patch  -- a patch file legitimately contains whatever the patch
#                       contains, including a conflicted hunk.
#   fixtures         -- none. Every test in this repo that needs a conflict
#                       marker builds it at run time from a variable (see
#                       test-check-conflict-markers.sh), precisely so that no
#                       tracked file has to be exempted. Add a path to
#                       FIXTURE_EXCLUDES below only if that ever stops being
#                       true, and say why here.
#
# Env:
#   CONFLICT_MARKER_ROOT  repository to scan (default: this repo's root);
#                         exists so the self-test can point at fixture repos.
#
# Exit codes: 0 clean, 1 conflict markers are committed, 2 infra (not a git
# repository / git grep could not run).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCAN_ROOT="${CONFLICT_MARKER_ROOT:-$ROOT}"

if ! git -C "$SCAN_ROOT" rev-parse --git-dir > /dev/null 2>&1; then
  echo "INFRA: not a git repository: $SCAN_ROOT" >&2
  exit 2
fi

# Git pathspecs are fnmatch WITHOUT FNM_PATHNAME, so `*` matches `/` too and a
# bare `*.diff` already covers every directory depth.
FIXTURE_EXCLUDES=()
PATHSPECS=(':!*.diff' ':!*.patch' "${FIXTURE_EXCLUDES[@]+"${FIXTURE_EXCLUDES[@]}"}")

# `-I` so a binary blob that happens to contain the byte sequence is reported
# as neither a match nor an error.
PATTERN='^(<{7} |={7}$|>{7} )'

matches=''
rc=0
matches="$(git -C "$SCAN_ROOT" grep -I -nE "$PATTERN" -- . "${PATHSPECS[@]}")" || rc=$?

case "$rc" in
  0) ;;                     # matched -> markers are committed
  1)                        # no match -> clean
    echo "conflict markers: none in tracked files (excluding *.diff, *.patch)"
    exit 0
    ;;
  *)
    echo "INFRA: git grep failed with exit $rc in $SCAN_ROOT" >&2
    exit 2
    ;;
esac

count="$(printf '%s\n' "$matches" | grep -c . || true)"
echo "::error title=Committed git conflict markers::${count} line(s) in tracked files look like an unresolved git conflict (#3676)."
echo
printf '%s\n' "$matches" | sed 's/^/  /'
echo
echo "These are the literal markers git writes into a file it could not merge."
echo "A source file would fail to compile, but Markdown, YAML, Helm templates"
echo "and workflow files ship with them intact -- CHANGELOG.md did, on main,"
echo "for three hours (#3664, #3675)."
echo
echo "Fix: resolve the conflict and remove the marker lines, then re-run."
echo "If a file legitimately contains them (a *.diff / *.patch fixture),"
echo "exclude it by path in scripts/ci/check-conflict-markers.sh and say why."
exit 1
