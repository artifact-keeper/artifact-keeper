#!/usr/bin/env bash
#
# Refuse a release whose bookkeeping does not describe it (issue #3537).
#
#   usage: assert-release-bookkeeping.sh <tag>
#   env:   GH_TOKEN, GITHUB_REPOSITORY
#
# Four of the last eight releases shipped with wrong release bookkeeping, and
# every one was found by a human days later rather than by this pipeline. The
# only automated check asserted that a `## [X.Y.Z]` CHANGELOG heading exists
# and is non-empty -- a heading can exist, be non-empty, and describe a
# different release. This script asserts the three things that were actually
# wrong.
#
#   1. A stable `vX.Y.Z` MUST have a curated `.github/release-notes/X.Y.Z.md`.
#      v1.7.1 had none. release.yml's "Resolve release notes" step tested
#      `if [ -f "$F" ]` and, finding nothing, fell back to
#      `generate_release_notes: true` with a log line and no failure. Auto-notes
#      do not promote the CHANGELOG, so 8 `[Unreleased]` entries that had
#      already shipped stayed put, including an upgrade note telling 1.7.1
#      operators to act "before upgrading to 1.7.2" when they had already been
#      exposed for a week (#3318). Prerelease tags keep the fallback: an -rc is
#      a candidate, not a documented release, and RELEASING.md says so.
#
#   2. The CHANGELOG's FIRST `## [` heading must be `## [Unreleased]`, at
#      release time and not only on PRs. `scripts/ci/check-changelog-unreleased.sh`
#      (#3433) is the same assertion in the shell-tests job, and this delegates
#      to it rather than restating it, so there is one definition. The PR-time
#      run is not sufficient on its own: `7aab4b79 chore(release): prepare
#      1.7.5` performed exactly the rename the gate exists to catch, and a
#      release-prep commit can reach a tag without any PR-time run having seen
#      the tree in that state.
#
#   3. `.github/release-notes/` must not hold a file for a version that has
#      neither a git tag nor a GitHub Release. That is the inverse mistake, and
#      an instance is live: `1.7.5.md` sits on `main` for a version that
#      produced no images, no release object, and whose tag no longer exists
#      (#3429). A stale notes file is not harmless -- it is what a human reads
#      when reconstructing what shipped, and it is one rename away from being
#      published as some other version's body.
#
# WHICH REF IS READ, and why it matters. Every check here reads the CHECKED-OUT
# ref -- the one being released -- never `main`. `main` and `release/1.7.x`
# hold DISJOINT halves of the 1.7.x curated notes set: `main` has
# 1.7.0/1.7.3/1.7.4/1.7.5/1.8.0/1.8.1 and `release/1.7.x` has
# 1.7.0/1.7.3/1.7.4/1.7.6/1.7.8. The 1.7.6 and 1.7.8 notes are NOT missing;
# they are on the branch those releases were cut from, which is the ref
# release.yml reads. A check that assumed `main` would fail two correct
# releases and pass nothing extra. (artifact-keeper-test's
# `version-set-integrity` makes exactly that assumption for the CHANGELOG,
# falling back to main's copy when the tag's cannot be read. Out of scope
# here, but it is the same trap.)
#
# Exit codes follow the sibling `assert-release-absent.sh`: 0 clean, 1 refuse
# (INCLUDING "could not prove", which fails closed), 2 usage error. An API we
# cannot read is not an API that said yes: without repository access, every
# version looks untagged and unreleased, so check 3 would manufacture orphans.
# It proves readability first and refuses explicitly if it cannot.

set -uo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <tag>" >&2
  exit 2
fi

TAG="$1"
VERSION="${TAG#v}"
NOTES_DIR=".github/release-notes"
problems=0

refuse() { echo "::error title=$1::$2"; problems=$((problems + 1)); }

if [[ -z "${GITHUB_REPOSITORY:-}" ]]; then
  echo "::error title=Release bookkeeping unverifiable::GITHUB_REPOSITORY is not set; cannot resolve tags or releases."
  exit 1
fi

# A final release is X.Y.Z with no prerelease suffix. Everything else (-rc.N,
# -beta.N) is a candidate.
STABLE=0
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] && STABLE=1

echo "== release bookkeeping for ${TAG} =="
echo "ref: $(git rev-parse --short HEAD 2>/dev/null || echo '?')   stable: $([[ "$STABLE" == 1 ]] && echo yes || echo 'no (prerelease)')"
echo

# ── 1. curated release notes exist for a stable release ─────────────────────
echo "1) curated release notes"
NOTES_FILE="${NOTES_DIR}/${VERSION}.md"
if [[ "$STABLE" != 1 ]]; then
  echo "  ${TAG} is a prerelease; generate_release_notes remains the documented fallback. Skipped."
elif [[ ! -f "$NOTES_FILE" ]]; then
  refuse "Curated release notes missing" \
    "${NOTES_FILE} does not exist on this ref. A stable release publishes a curated body, never GitHub's auto-generated PR dump (RELEASING.md \"Release-notes style\"). Author it, commit it alongside the CHANGELOG promotion, and re-cut. This is the check v1.7.1 did not have: the fallback was silent, so the release published auto-notes and the CHANGELOG was never promoted (#3318, #3537)."
  echo "  NOTE: the notes file is read from THIS ref, not from main. If this is a"
  echo "        release branch, the file belongs on the release branch."
elif [[ ! -s "$NOTES_FILE" ]]; then
  refuse "Curated release notes empty" \
    "${NOTES_FILE} exists but is empty. An empty body_path publishes an empty release."
else
  echo "  ${NOTES_FILE} present ($(wc -l < "$NOTES_FILE" | tr -d ' ') lines). OK."
fi
echo

# ── 2. the CHANGELOG still has an open [Unreleased] section ─────────────────
echo "2) CHANGELOG has an open [Unreleased] section"
CHANGELOG_GATE="scripts/ci/check-changelog-unreleased.sh"
if [[ ! -f "$CHANGELOG_GATE" ]]; then
  refuse "CHANGELOG gate missing" \
    "${CHANGELOG_GATE} is not present on this ref, so the [Unreleased] invariant cannot be checked. It is the #3433 gate; port it to this branch."
else
  gate_out="$(bash "$CHANGELOG_GATE" 2>&1)"
  gate_rc=$?
  printf '%s\n' "$gate_out" | sed 's/^/  /'
  if [[ "$gate_rc" -ne 0 ]]; then
    refuse "CHANGELOG has no open [Unreleased] section" \
      "The first '## [' heading in CHANGELOG.md is not '## [Unreleased]' on the ref being released. A release prep must open a fresh empty one above the promoted heading; without it, later PRs merge into the released section with no conflict (#3433)."
  fi
fi
echo

# ── 3. no curated notes for a version that never happened ───────────────────
echo "3) no orphaned curated notes"
if [[ "$STABLE" != 1 ]]; then
  echo "  ${TAG} is a prerelease; skipped."
elif [[ ! -d "$NOTES_DIR" ]]; then
  echo "  no ${NOTES_DIR}/ on this ref; nothing to check."
else
  # Prove the token can read this repository FIRST. Otherwise a bad token, a
  # renamed repository or a permissions change answers 404 for every lookup,
  # and every notes file would be reported as an orphan.
  if ! gh api "repos/${GITHUB_REPOSITORY}" --silent >/dev/null 2>&1; then
    refuse "Release bookkeeping unverifiable" \
      "Cannot read repos/${GITHUB_REPOSITORY}. Without repository access every version looks untagged, so this fails closed rather than inventing orphans."
  else
    # Two cheap listings instead of a lookup per file. A published Release
    # always has a tag, so the second list is usually redundant -- but a tag
    # can be DELETED after the fact (v1.7.5's was, despite the ruleset), and a
    # release that still exists is not an orphan.
    known_tags="$(gh api "repos/${GITHUB_REPOSITORY}/git/matching-refs/tags/v" --paginate \
                    --jq '.[].ref' 2>/dev/null | sed 's#^refs/tags/##' || true)"
    known_rels="$(gh api "repos/${GITHUB_REPOSITORY}/releases?per_page=100" --paginate \
                    --jq '.[].tag_name' 2>/dev/null || true)"
    if [[ -z "$known_tags" ]]; then
      refuse "Release bookkeeping unverifiable" \
        "The tag listing for ${GITHUB_REPOSITORY} came back empty, which cannot be true for a repository that has releases. Failing closed rather than reporting every notes file as an orphan."
    else
      orphans=0
      for f in "${NOTES_DIR}"/*.md; do
        [[ -e "$f" ]] || continue
        base="$(basename "$f" .md)"
        # Only version-named files are claims about a release.
        [[ "$base" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "  ${f}: not a version-named file, skipped"; continue; }
        # The version being released has no Release yet -- that is the point of
        # this run -- and its tag is what triggered it.
        [[ "$base" == "$VERSION" ]] && { echo "  ${base}: the version being released. OK."; continue; }
        if printf '%s\n' "$known_tags" | grep -qx "v${base}"; then
          echo "  ${base}: tag v${base} exists. OK."
        elif printf '%s\n' "$known_rels" | grep -qx "v${base}"; then
          echo "  ${base}: no tag, but a Release exists. OK."
        else
          orphans=$((orphans + 1))
          refuse "Orphaned release-notes file" \
            "${NOTES_DIR}/${base}.md describes version ${base}, which has neither a git tag nor a GitHub Release. Either that release never happened and the file should be deleted, or the version it names is wrong. ${base} is not what this run is publishing, so nothing here will fix itself (#3429, #3537)."
        fi
      done
      [[ "$orphans" -eq 0 ]] && echo "  every version-named notes file maps to a tag or a Release."
    fi
  fi
fi
echo

if [[ "$problems" -gt 0 ]]; then
  echo "REFUSED: ${problems} bookkeeping problem(s) for ${TAG}."
  exit 1
fi
echo "Release bookkeeping for ${TAG} is consistent. OK."
