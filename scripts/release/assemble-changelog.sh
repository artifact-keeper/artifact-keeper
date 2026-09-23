#!/usr/bin/env bash
#
# Assemble the CHANGELOG fragments into the release section (RELEASING.md
# step 3).
#
# Every PR adds one file under changes/unreleased/ instead of editing
# CHANGELOG.md, so no two PRs touch the same file and a merge no longer puts
# every other open PR into conflict (the rebase cascade measured in the
# 2026-09 CI survey: 76 % of merges touched CHANGELOG.md). The release prep
# runs this once:
#
#   * renders every fragment into a new `## [X.Y.Z] - <date>` section directly
#     below `## [Unreleased]`, sections in Keep a Changelog order (Added,
#     Changed, Deprecated, Removed, Fixed, Security), entries within a section
#     ordered by the number in the file name, then the file name -- so two
#     runs over the same tree write the same bytes;
#   * merges in any bullets still written under `## [Unreleased]` (PRs opened
#     before fragments existed; they come first within their section, in the
#     order they were written) and carries through any other `### ` heading
#     there (`### Sponsors`, `### Thank You`, an upgrade note) verbatim;
#   * leaves `## [Unreleased]` holding only its one-line pointer to
#     changes/unreleased/, which keeps check-changelog-unreleased.sh (#3433)
#     satisfied without a separate step;
#   * deletes the fragment files it rendered.
#
# If more PRs merge after the prep and before the tag, run it again with
# --append: the new fragments are merged INTO the `## [X.Y.Z]` section
# directly below `## [Unreleased]` rather than given a second heading. Without
# --append an existing `## [X.Y.Z]` is refused -- a Cargo.toml nobody bumped
# names the version that already shipped, and filing new entries under it is
# the #3433 shape. --append is also refused once the vX.Y.Z tag exists.
#
# Usage:
#   scripts/release/assemble-changelog.sh [--check] [--append] [--date YYYY-MM-DD] [X.Y.Z]
#
#   X.Y.Z    the version being cut (default: the workspace version in
#            Cargo.toml, which step 2 of RELEASING.md has already bumped)
#   --check  dry run: validate the fragments and print the section that would
#            be written to stdout; change nothing
#   --append merge into this cut's existing, untagged `## [X.Y.Z]` section
#   --date   the release date (default: today, UTC)
#
# The parsing, validation and rendering live in
# scripts/ci/changelog-fragments.py, which the CI gates also call, so the
# fragment rules cannot drift between what CI accepts and what a cut renders.
#
# Exit codes: 0 done, 1 invalid fragments or a CHANGELOG this refuses to
# rewrite, 2 usage / infra.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HELPER="$ROOT/scripts/ci/changelog-fragments.py"

usage() {
  cat << EOF
usage: $(basename "$0") [--check] [--append] [--date YYYY-MM-DD] [X.Y.Z]
EOF
}

check=()
append=()
date_arg=()
version=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --check | --dry-run) check=(--check); shift ;;
    --append) append=(--append); shift ;;
    --date)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      date_arg=(--date "$2"); shift 2 ;;
    -h | --help) usage; exit 0 ;;
    -*) usage >&2; echo "unknown option '$1'" >&2; exit 2 ;;
    *)
      [[ -z "$version" ]] || { usage >&2; exit 2; }
      version="${1#v}"; shift ;;
  esac
done

if [[ ! -f "$HELPER" ]]; then
  echo "INFRA: $HELPER is missing" >&2
  exit 2
fi
command -v python3 > /dev/null 2>&1 || { echo "INFRA: python3 is not on PATH" >&2; exit 2; }

if [[ -z "$version" ]]; then
  # The workspace version: the first column-0 `version = "..."` after
  # `[workspace.package]`, which is the line the version bump edits.
  version="$(awk '
    /^\[/ { inside = ($0 == "[workspace.package]"); next }
    inside && /^version[[:space:]]*=/ { gsub(/^version[[:space:]]*=[[:space:]]*"|".*$/, ""); print; exit }
  ' "$ROOT/Cargo.toml")"
  if [[ -z "$version" ]]; then
    echo "INFRA: could not read the workspace version from $ROOT/Cargo.toml; pass X.Y.Z" >&2
    exit 2
  fi
  echo "version: ${version} (from Cargo.toml)" >&2
fi

if [[ ${#append[@]} -gt 0 ]] && git -C "$ROOT" rev-parse -q --verify "refs/tags/v${version}" > /dev/null 2>&1; then
  echo "::error::v${version} is already tagged; its CHANGELOG section is history. Bump the version and assemble a new section instead." >&2
  exit 1
fi

if [[ ${#date_arg[@]} -eq 0 ]]; then
  date_arg=(--date "$(date -u +%F)")
fi

exec python3 "$HELPER" assemble "$version" "${date_arg[@]}" "${check[@]}" "${append[@]}" \
  --changelog "$ROOT/CHANGELOG.md" --dir "$ROOT/changes/unreleased"
