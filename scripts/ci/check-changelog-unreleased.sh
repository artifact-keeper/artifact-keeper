#!/usr/bin/env bash
#
# CI gate for issue #3433: a release-prep commit that renames
# `## [Unreleased]` to `## [X.Y.Z]` WITHOUT opening a fresh empty
# `## [Unreleased]` above it silently strands every entry that lands after.
#
# What happened: `7aab4b7 chore(release): prepare 1.7.5` did exactly that.
# Every PR branch cut before the rename still anchored its CHANGELOG hunk on
# the old heading, so the entries merged cleanly into the *renamed, already
# released* section. No conflict. No warning. 30 entries of 1.8.0 work ended
# up under `## [1.7.5]` — a version that produced no images and no release
# object (#3429) — and would have shipped undocumented. Two were
# upgrade-affecting: #3286 (storage accounting) and #3231 (Rekor SET).
#
# The assertion is deliberately the cheapest thing that would have caught it:
# the FIRST `## [` heading in CHANGELOG.md must be exactly `## [Unreleased]`.
# That is a repo-state invariant, not a diff check, so it fires on whichever
# PR notices it first rather than depending on who made the change — and it
# cannot be satisfied by a heading that merely contains the word.
#
# Scope, stated honestly: this runs in the `shell-tests` job, which is skipped
# on docs-only PRs. A CHANGELOG-only PR that removed the heading would
# therefore not be caught until the next code PR. That is delayed detection,
# not a hole: the real failure mode is a release-prep commit, and those always
# touch Cargo.toml, so they always run this.
#
# Second assertion (#3676): `## [Unreleased]` may contain at most ONE of each
# `### ` heading. That is the shape the #3664 merges nearly produced — the
# merge that shipped conflict markers on `main` for three hours was one hunk
# away from instead appending a SECOND `### Security` block, which merges
# cleanly, reads fine, and quietly splits one release's entries into two lists
# that the promotion then carries into the release notes as written. Duplicate
# headings also hide entries from anyone reading the section top-down, and the
# reconciliation in release-preflight.sh check 5 is by `#NNNN`, so it sees
# nothing wrong. Only `[Unreleased]` is checked: released sections are
# historical text and several legitimately carry repeated prose subheadings.
#
# Env:
#   CHANGELOG_FILE  file to check (default CHANGELOG.md at the repo root);
#                   exists so the self-test can point at fixtures.
#
# Exit codes: 0 clean, 1 the first heading is not `## [Unreleased]` or
# `[Unreleased]` repeats a `### ` heading, 2 infra (file missing).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHANGELOG_FILE="${CHANGELOG_FILE:-$ROOT/CHANGELOG.md}"

if [[ ! -f "$CHANGELOG_FILE" ]]; then
  echo "INFRA: changelog not found: $CHANGELOG_FILE" >&2
  exit 2
fi

# Keep-a-Changelog version headings are `## [...]` at column 0. Anything
# else (`# Changelog`, `### Added`, prose) is not a version heading.
first_heading="$(grep -m1 '^## \[' "$CHANGELOG_FILE" || true)"

if [[ -z "$first_heading" ]]; then
  echo "::error::$(basename "$CHANGELOG_FILE") has no '## [' version heading at all." \
    "Expected '## [Unreleased]' at the top of the version list (#3433)."
  exit 1
fi

# Trailing whitespace is tolerated; a date suffix is not — `## [Unreleased] -
# 2026-01-01` means the section has been dated, i.e. released.
trimmed="${first_heading%"${first_heading##*[![:space:]]}"}"
if [[ "$trimmed" != "## [Unreleased]" ]]; then
  echo "::error title=CHANGELOG has no open [Unreleased] section::First version heading in $(basename "$CHANGELOG_FILE") is '${first_heading}', expected '## [Unreleased]'."
  echo
  echo "A release prep promotes '## [Unreleased]' to '## [X.Y.Z] - <date>' and"
  echo "MUST open a fresh empty '## [Unreleased]' above it (RELEASING.md step 3)."
  echo "Without it, PR branches cut before the promotion merge their entries"
  echo "into the ALREADY-RELEASED section with no conflict and no warning —"
  echo "that is how 30 entries of 1.8.0 work ended up filed under [1.7.5]"
  echo "(#3433)."
  echo
  echo "Fix: add"
  echo
  echo "  ## [Unreleased]"
  echo
  echo "immediately above '${first_heading}' in $(basename "$CHANGELOG_FILE")."
  exit 1
fi

echo "CHANGELOG: first version heading is '## [Unreleased]'"

# ── at most one of each `### ` heading inside [Unreleased] (#3676) ──────────
#
# The section runs from the `## [Unreleased]` line to the next `## [` heading
# (or EOF, on a changelog that has never been cut). Headings are compared with
# trailing whitespace stripped, for the same reason the check above tolerates
# it.
duplicates="$(awk '
  /^## \[/ { inside = ($0 ~ /^## \[Unreleased\][[:space:]]*$/); next }
  !inside { next }
  /^### / {
    h = $0
    sub(/[[:space:]]+$/, "", h)
    seen[h]++
    if (seen[h] == 2) print h
  }
' "$CHANGELOG_FILE")"

if [[ -n "$duplicates" ]]; then
  echo
  echo "::error title=CHANGELOG [Unreleased] repeats a subsection heading::$(printf '%s' "$duplicates" | grep -c .) heading(s) appear more than once inside '## [Unreleased]' in $(basename "$CHANGELOG_FILE")."
  echo
  printf '%s\n' "$duplicates" | sed 's/^/  /'
  echo
  echo "A second '### Added'/'### Fixed'/'### Security' block under the same"
  echo "version merges cleanly and reads fine, so nothing else notices — but it"
  echo "splits one release's entries into two lists. Whatever reads the section"
  echo "top-down (a reviewer, the promoted release notes) sees only the first,"
  echo "and release-preflight.sh check 5 reconciles by '#NNNN' so it sees no"
  echo "problem at all. This is the shape the #3664 merges nearly produced"
  echo "(#3676)."
  echo
  echo "Fix: move the bullets into the existing block and delete the duplicate"
  echo "heading, keeping the Keep-a-Changelog order (Added, Changed,"
  echo "Deprecated, Removed, Fixed, Security)."
  exit 1
fi

echo "CHANGELOG: [Unreleased] has no duplicate '### ' heading"
