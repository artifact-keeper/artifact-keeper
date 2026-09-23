#!/usr/bin/env bash
#
# CI gate for issue #3797: a PR's CHANGELOG bullet silently lands inside an
# ALREADY-RELEASED section.
#
# How it happens, with nobody doing anything wrong: a branch opened before a
# release cut adds its bullet under `## [Unreleased]`. The cut renames that
# heading to `## [X.Y.Z] - <date>` and opens a fresh empty `[Unreleased]`
# above it. When the branch later merges `main`, git still finds the heading
# the hunk was anchored to — it just has a different name now — so the merge
# is CLEAN and the bullet ends up documented against a version that shipped
# without it. Four PRs hit this in one day (#3570, which reached `main` before
# it was caught, plus #3619, #3627 and #3628).
#
# Nothing else looks: the merge is clean, check-changelog-unreleased.sh only
# asserts that an `[Unreleased]` section exists, and release-preflight.sh
# check 5 reconciles bullets by `#NNNN` reference wherever they sit. The only
# thing that can tell the difference is a DIFF against the merge base, which
# is why this gate is pull-request-scoped rather than a repo-state invariant
# like its two siblings.
#
# Three assertions, in the order they fire:
#
#   1. FAIL — every bullet this PR ADDS must sit under `## [Unreleased]`.
#      Computed from `git diff -U0 <merge-base> HEAD -- CHANGELOG.md`, so a
#      bullet that merely moved with a heading rename (what a release prep
#      does) is not an addition and is not flagged.
#
#   2. FAIL — no `### ` heading may be left with nothing under it. Removing a
#      bullet strands its heading; that happened on `main` in #3795 and was
#      cleaned up separately in #3791. "Nothing under it" means no non-blank
#      line before the next heading, so the prose `### Upgrade note — …`
#      subsections that released versions carry are not empty.
#
#   3. WARN — an added bullet should carry a `#NNNN` reference. Release
#      preflight check 5 reconciles `vX.Y.Z..HEAD` against the pending
#      section by each bullet's first `#NNNN`; a bullet that has none
#      contributes no reference and makes a commit look undocumented at cut
#      time, which is the most expensive moment to find it. A warning, not a
#      failure: some entries genuinely have no issue.
#
# Assertions 2 and 3 only run when the PR touches CHANGELOG.md at all, so a
# PR is never failed for state it did not create.
#
# FRAGMENTS. A PR's entry is now normally a file under changes/unreleased/
# rather than a bullet here (one file per PR, so no merge conflicts with every
# other open PR; see changes/README.md). A PR that adds a valid fragment and
# leaves CHANGELOG.md alone passes. Two more assertions cover that path:
#
#   4. FAIL -- every fragment this PR adds or edits must be valid (the same
#      rules check-changelog-unreleased.sh applies to the whole directory,
#      reported here against the PR that introduced the problem).
#
#   5. FAIL -- a file this PR adds under changes/ must be directly in
#      changes/unreleased/. Anywhere else it is never assembled, so the entry
#      silently never reaches a release.
#
# TRANSITION. A bullet added under `## [Unreleased]` still passes assertion 1
# (PRs opened before fragments existed), with a notice pointing at the
# fragment path. And a release prep now ASSEMBLES the fragments into a new
# `## [X.Y.Z]` section, so it adds bullets under a heading that is not
# `[Unreleased]`. Those are not the #3570 shape: the heading they sit under is
# itself added by this branch, whereas a stranded bullet sits under a heading
# that already exists on the base branch. Bullets under a heading the branch
# adds are therefore exempt from assertions 1 and 3.
#
# Usage:  check-changelog-placement.sh [<base-ref>]        (default origin/main)
#
# Env:
#   GITHUB_EVENT_NAME  when set to anything but a pull request, the gate is a
#                      no-op — there is no "what this branch added" to compute.
#                      Unset (a local run) is treated as a pull request.
#   CHANGELOG_PATH     repo-relative changelog (default CHANGELOG.md); exists
#                      so the self-test can build fixture repos.
#   CHANGES_PATH       repo-relative fragment root (default changes).
#
# Exit codes: 0 clean (warnings do not fail), 1 a bullet is misplaced, a
# heading was left empty, or a fragment is invalid or misplaced, 2 infra (not
# a git repo, base ref or merge base unavailable — the shallow-clone case —
# or the fragment validator missing).
set -euo pipefail

BASE_REF="${1:-origin/main}"
CHANGELOG_PATH="${CHANGELOG_PATH:-CHANGELOG.md}"
CHANGES_PATH="${CHANGES_PATH:-changes}"
EVENT="${GITHUB_EVENT_NAME:-pull_request}"
FRAGMENT_TOOL="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/changelog-fragments.py"

if [[ "$EVENT" != "pull_request" && "$EVENT" != "pull_request_target" ]]; then
  echo "check-changelog-placement: no-op on '${EVENT}' events."
  echo "  This gate compares the bullets a BRANCH adds against its merge base"
  echo "  with the base branch. On a push, a tag or a dispatch there is no such"
  echo "  comparison to make; the repo-state invariants live in"
  echo "  check-changelog-unreleased.sh instead (#3797)."
  exit 0
fi

if ! git rev-parse --git-dir > /dev/null 2>&1; then
  echo "INFRA: not a git repository: $PWD" >&2
  exit 2
fi

if ! git rev-parse --verify --quiet "${BASE_REF}^{commit}" > /dev/null; then
  echo "INFRA: base ref '${BASE_REF}' does not resolve." >&2
  echo "       The job must fetch it, e.g." >&2
  echo "         git fetch --no-tags origin \"\$GITHUB_BASE_REF:refs/remotes/origin/\$GITHUB_BASE_REF\"" >&2
  exit 2
fi

MERGE_BASE="$(git merge-base HEAD "$BASE_REF" 2>/dev/null || true)"
if [[ -z "$MERGE_BASE" ]]; then
  echo "INFRA: no merge base between HEAD and '${BASE_REF}'." >&2
  echo "       A depth-1 checkout has no common ancestor to find; the job needs" >&2
  echo "       actions/checkout with fetch-depth: 0. Reporting INFRA rather" >&2
  echo "       than guessing a base, which would silently change the verdict." >&2
  exit 2
fi

echo "CHANGELOG placement: comparing HEAD against merge-base ${MERGE_BASE} (${BASE_REF})"

rc=0
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

# ── 4 + 5. fragments this branch adds or edits ─────────────────────────────
#
# Read from HEAD's tree, not the worktree, for the same reason as the
# changelog below. Deleted fragments are not checked: deleting them is what a
# release prep does.
FRAG_FILES=()
while IFS= read -r path; do
  [[ -z "$path" ]] && continue
  rel="${path#"${CHANGES_PATH}/"}"
  if [[ "$rel" == "README.md" || "$rel" == "unreleased/.gitkeep" ]]; then
    continue
  fi
  if [[ "$rel" != unreleased/* || "${rel#unreleased/}" == */* ]]; then
    echo "::error file=${path},title=CHANGELOG fragment in the wrong place::${path} is not directly in ${CHANGES_PATH}/unreleased/, so the release cut will never assemble it and the entry will not reach any release."
    rc=1
    continue
  fi
  mkdir -p "$SCRATCH/frag"
  git show "HEAD:${path}" > "$SCRATCH/frag/$(basename "$path")"
  FRAG_FILES+=("$SCRATCH/frag/$(basename "$path")")
done < <(git diff --name-only --no-renames --diff-filter=AM "$MERGE_BASE" HEAD -- "$CHANGES_PATH")

if [[ ${#FRAG_FILES[@]} -gt 0 ]]; then
  if [[ ! -f "$FRAGMENT_TOOL" ]] || ! command -v python3 > /dev/null 2>&1; then
    echo "INFRA: this branch adds CHANGELOG fragments but ${FRAGMENT_TOOL} or python3 is missing." >&2
    exit 2
  fi
  if frag_out="$(python3 "$FRAGMENT_TOOL" validate "${FRAG_FILES[@]}")"; then
    echo "  ${#FRAG_FILES[@]} CHANGELOG fragment(s) added or edited on this branch, all valid"
    printf '%s\n' "$frag_out" | grep '^::warning' | sed "s|${SCRATCH}/frag/|${CHANGES_PATH}/unreleased/|g" || true
  else
    printf '%s\n' "$frag_out" | sed "s|${SCRATCH}/frag/|${CHANGES_PATH}/unreleased/|g"
    echo
    echo "A fragment this branch adds is not valid, so the release cut would refuse"
    echo "to assemble it. See changes/README.md for the format."
    rc=1
  fi
fi

DIFF="$(git diff -U0 "$MERGE_BASE" HEAD -- "$CHANGELOG_PATH")"
if [[ -z "$DIFF" ]]; then
  echo "  ${CHANGELOG_PATH} is unchanged on this branch — nothing to place."
  if [[ "$rc" -eq 0 ]]; then
    echo "CHANGELOG placement: clean"
  fi
  exit "$rc"
fi

# HEAD's committed changelog, not the worktree: the diff above is between two
# trees, so the line numbers it reports are line numbers in THIS file.
HEAD_FILE="$SCRATCH/CHANGELOG.head"
git show "HEAD:${CHANGELOG_PATH}" > "$HEAD_FILE"

# Version headings this branch ADDS -- a release prep assembling fragments
# into a new `## [X.Y.Z]` section. Bullets under one of these are the cut
# itself, not a bullet stranded under a shipped release (see the header).
ADDED_HEADINGS="$(printf '%s\n' "$DIFF" | awk '
  /^\+\+\+/ { next }
  /^\+## \[/ { h = substr($0, 2); sub(/[[:space:]]+$/, "", h); print h }
')"

# ── 1. bullets this branch adds, with their line number in HEAD ─────────────
#
# `-U0` means there are no context lines, so every `+` line is an addition and
# the new-side line counter only advances on `+`. A top-level bullet is `- ` at
# column 0; continuation paragraphs inside a bullet are indented, so they are
# correctly not counted as bullets of their own.
ADDED="$(printf '%s\n' "$DIFF" | awk '
  /^\+\+\+/ { next }
  /^@@/ {
    split($3, p, ",")           # $3 is "+<start>" or "+<start>,<count>"
    n = substr(p[1], 2) + 0
    next
  }
  /^\+/ {
    line = substr($0, 2)
    if (line ~ /^- /) printf "%d\t%s\n", n, line
    n++
  }
')"

if [[ -n "$ADDED" ]]; then
  # Attach each added bullet to the `## [` heading (and the `### ` subheading)
  # it sits under in HEAD. Unit-separator (\037) delimited, not tab: `read`
  # collapses runs of a whitespace IFS character, so an empty subheading (a
  # bullet directly under a `## [` heading) shifted the bullet into the
  # subheading field and the row was skipped as blank.
  PLACED="$(printf '%s\n' "$ADDED" | awk -F'\t' '
    NR == FNR { bullet[$1 + 0] = $2; next }
    /^## \[/  { vh = $0; sub(/[[:space:]]+$/, "", vh); sh = ""; next }
    /^### /   { sh = $0; sub(/[[:space:]]+$/, "", sh); next }
    (FNR in bullet) { printf "%s\037%s\037%s\n", vh, sh, bullet[FNR] }
  ' - "$HEAD_FILE")"

  misplaced=0
  legacy=0
  assembled=0
  while IFS=$'\037' read -r vh sh bullet; do
    [[ -z "$bullet" ]] && continue
    if [[ "$vh" == "## [Unreleased]" ]]; then
      legacy=$((legacy + 1))
      continue
    fi
    if [[ -n "$vh" ]] && printf '%s\n' "$ADDED_HEADINGS" | grep -qxF -- "$vh"; then
      assembled=$((assembled + 1))
      continue
    fi
    misplaced=$((misplaced + 1))
    if [[ -z "$vh" ]]; then
      where="before the first '## [' heading"
    else
      where="'${vh}'${sh:+ / '${sh}'}"
    fi
    echo "::error title=CHANGELOG bullet landed outside [Unreleased]::This branch adds a bullet under ${where}, which is not '## [Unreleased]' (#3797)."
    echo "  bullet: ${bullet}"
  done <<< "$PLACED"

  if [[ "$misplaced" -gt 0 ]]; then
    echo
    echo "${misplaced} bullet(s) this branch adds are filed against a version that"
    echo "has already shipped. This is what a clean merge looks like after a"
    echo "release cut renames '## [Unreleased]' to '## [X.Y.Z] - <date>': the"
    echo "heading your hunk was anchored to still exists, so git merges without"
    echo "a conflict and the entry documents a release it was not in (#3570,"
    echo "#3619, #3627, #3628)."
    echo
    echo "Fix: move the bullet(s) up into the '## [Unreleased]' section."
    rc=1
  else
    if [[ "$assembled" -gt 0 ]]; then
      echo "  ${assembled} added bullet(s) under a version heading this branch adds (a release prep assembling the fragments)"
    fi
    if [[ "$legacy" -gt 0 ]]; then
      echo "  ${legacy} added bullet(s), all under '## [Unreleased]'"
      echo "::notice title=CHANGELOG entry could be a fragment::This branch adds ${legacy} bullet(s) under '## [Unreleased]' in ${CHANGELOG_PATH}. That still works during the transition, but it is the one file every other PR also edits: a fragment in ${CHANGES_PATH}/unreleased/ (see ${CHANGES_PATH}/README.md) cannot conflict."
    fi
  fi

  # ── 3. WARN: a bullet with no `#NNNN` is invisible to preflight check 5 ───
  #
  # Same extraction as release-preflight.sh: the PRIMARY reference of an entry
  # is the first `#NNNN` on the top-level `- ` line.
  while IFS=$'\037' read -r vh _sh bullet; do
    [[ -z "$bullet" ]] && continue
    if [[ "$vh" != "## [Unreleased]" ]]; then
      continue # misplaced (already an error) or assembled (validated as a fragment)
    fi
    if ! printf '%s' "$bullet" | grep -qE '#[0-9][0-9]+'; then
      echo "::warning title=CHANGELOG bullet has no #NNNN reference::An added bullet's first reference is not a '#NNNN', so release-preflight check 5 will not reconcile it against any commit (#3797)."
      echo "  bullet: ${bullet}"
    fi
  done <<< "$PLACED"
fi

# ── 2. headings left with nothing under them ───────────────────────────────
EMPTY="$(awk '
  function flush() { if (h != "" && !content) printf "%d\t%s\n", hl, h }
  /^### / { flush(); h = $0; hl = FNR; content = 0; next }
  /^## /  { flush(); h = ""; content = 0; next }
  { if (h != "" && $0 ~ /[^[:space:]]/) content = 1 }
  END { flush() }
' "$HEAD_FILE")"

if [[ -n "$EMPTY" ]]; then
  while IFS=$'\t' read -r lineno heading; do
    [[ -z "$heading" ]] && continue
    echo "::error title=CHANGELOG heading left empty::${CHANGELOG_PATH}:${lineno}: '${heading}' has no content before the next heading (#3797)."
  done <<< "$EMPTY"
  echo
  echo "Removing or moving the last bullet under a heading strands the heading."
  echo "It renders as an empty section and, on a release cut, is promoted into"
  echo "the release notes exactly as written (#3795, cleaned up in #3791)."
  echo
  echo "Fix: delete the heading, or put the bullet back under it."
  rc=1
fi

if [[ "$rc" -eq 0 ]]; then
  echo "CHANGELOG placement: clean"
fi
exit "$rc"
