#!/usr/bin/env bash
#
# Self-test for .github/scripts/assert-release-bookkeeping.sh and for the
# release.yml arm it backs up (issue #3537).
#
# WHY THIS EXISTS
#   These gates fire on `v*` tag pushes -- a handful of runs per release, and
#   the interesting cases are ones nobody wants to reproduce live. A release
#   that publishes with no curated notes cannot be un-published; the run that
#   would have shown the bug is the one that already shipped v1.7.1. So the
#   failure modes are exercised here, offline.
#
#   Every case that must BLOCK is constructed as a bad state and asserted red.
#   Delete the stable-vs-prerelease branch from check 1 and case 2 goes green;
#   delete the orphan loop and case 6 does; soften the unreadable-API handling
#   to a pass and cases 9 and 10 do. That is the property being asserted --
#   the repository already carries gates that structurally cannot fail, and
#   this is not one of them.
#
# HOW
#   The script reaches GitHub only through `gh`, so a stub first on PATH
#   replays canned tag/release listings. Fixtures are throwaway directories,
#   so no repository state is involved. Part B extracts the "Resolve release
#   notes" run-block straight out of release.yml and executes it, which is the
#   only way to assert on YAML that no test otherwise runs.
#
# Usage: bash scripts/ci/test-assert-release-bookkeeping.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SCRIPT="$ROOT/.github/scripts/assert-release-bookkeeping.sh"
CHANGELOG_GATE="$HERE/check-changelog-unreleased.sh"
RELEASE_YML="$ROOT/.github/workflows/release.yml"
[ -f "$SCRIPT" ] || { echo "cannot find assert-release-bookkeeping.sh" >&2; exit 2; }
[ -f "$CHANGELOG_GATE" ] || { echo "cannot find check-changelog-unreleased.sh" >&2; exit 2; }
[ -f "$RELEASE_YML" ] || { echo "cannot find release.yml" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0

pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

# --- gh stub ----------------------------------------------------------------
# Replays:
#   FAKE_REPO_UNREADABLE=1   `gh api repos/<slug>` fails      (unverifiable)
#   FAKE_TAGS                newline list of tag names        (matching-refs)
#   FAKE_RELEASES            newline list of release tag_names
STUB="$WORK/bin"; mkdir -p "$STUB"
cat > "$STUB/gh" <<'STUBGH'
#!/usr/bin/env bash
case "$2" in
  *matching-refs/tags*)
    [ -n "${FAKE_TAGS-}" ] && printf '%s\n' "$FAKE_TAGS" | sed 's#^#refs/tags/#'
    exit 0 ;;
  *releases?per_page*|*releases*)
    [ -n "${FAKE_RELEASES-}" ] && printf '%s\n' "$FAKE_RELEASES"
    exit 0 ;;
esac
# `gh api repos/<owner>/<name> --silent`: the readability probe.
[ "${FAKE_REPO_UNREADABLE-0}" = "1" ] && exit 1
exit 0
STUBGH
chmod +x "$STUB/gh"

# --- fixture builder --------------------------------------------------------
# <dir> <first-changelog-heading> <notes-file...>
make_fixture() {
  local dir="$1" heading="$2"; shift 2
  rm -rf "$dir"
  mkdir -p "$dir/.github/scripts" "$dir/.github/release-notes" "$dir/scripts/ci"
  cp "$SCRIPT" "$dir/.github/scripts/"
  cp "$CHANGELOG_GATE" "$dir/scripts/ci/"
  {
    printf '# Changelog\n\n'
    printf '%s\n\n' "$heading"
    printf '### Fixed\n- a thing (#1)\n'
  } > "$dir/CHANGELOG.md"
  local n
  for n in "$@"; do printf '# Artifact Keeper %s\n\nbody\n' "$n" > "$dir/.github/release-notes/$n.md"; done
  git -C "$dir" init -q
  git -C "$dir" -c user.email=t@t -c user.name=t add -A >/dev/null 2>&1
  git -C "$dir" -c user.email=t@t -c user.name=t commit -qm init
}

expect() { # <label> <expected-exit> <expected-substring> <dir> <tag>
  local label="$1" want="$2" needle="$3" dir="$4" tag="$5" got
  ( cd "$dir" && PATH="$STUB:$PATH" GITHUB_REPOSITORY=artifact-keeper/artifact-keeper \
      bash .github/scripts/assert-release-bookkeeping.sh "$tag" >"$WORK/out.txt" 2>&1 )
  got=$?
  if [ "$got" != "$want" ]; then
    fail "$label: expected exit $want, got $got"
    sed 's/^/        /' "$WORK/out.txt" >&2
  elif [ -n "$needle" ] && ! grep -qF "$needle" "$WORK/out.txt"; then
    fail "$label: exit $got correct but output lacks '$needle'"
    sed 's/^/        /' "$WORK/out.txt" >&2
  else
    pass "$label (exit $got)"
  fi
}

ALL_TAGS=$'v1.7.0\nv1.7.3\nv1.7.4\nv1.8.0\nv1.8.1'

echo "assert-release-bookkeeping: curated notes (#3318)"

# 1. The correct shape. Guards against a gate that refuses every release.
make_fixture "$WORK/ok" "## [Unreleased]" 1.8.0 1.8.1 1.8.2
FAKE_TAGS="$ALL_TAGS" \
  expect "stable with curated notes, open [Unreleased], no orphans -> OK" 0 "is consistent" "$WORK/ok" v1.8.2

# 2. THE v1.7.1 REGRESSION: a stable tag with no curated notes file. This is
#    the exact state v1.7.1 was cut in, and release.yml published it.
make_fixture "$WORK/nonotes" "## [Unreleased]" 1.8.0 1.8.1
FAKE_TAGS="$ALL_TAGS" \
  expect "stable with NO curated notes -> refused" 1 "Curated release notes missing" "$WORK/nonotes" v1.8.2

# 3. ...and the fallback must SURVIVE for prereleases, which is the whole
#    reason the silent branch existed. An -rc is a candidate, not a documented
#    release.
FAKE_TAGS="$ALL_TAGS" \
  expect "prerelease with no curated notes -> OK (fallback preserved)" 0 "prerelease" "$WORK/nonotes" v1.8.2-rc.1

# 4. A file that exists but is empty publishes an empty release body.
make_fixture "$WORK/emptynotes" "## [Unreleased]" 1.8.0 1.8.1
: > "$WORK/emptynotes/.github/release-notes/1.8.2.md"
FAKE_TAGS="$ALL_TAGS" \
  expect "stable with an EMPTY curated notes file -> refused" 1 "Curated release notes empty" "$WORK/emptynotes" v1.8.2

echo
echo "assert-release-bookkeeping: open [Unreleased] at release time (#3433)"

# 5. THE v1.7.5 SHAPE, reached at release time rather than on a PR: the prep
#    renamed the heading and opened nothing above it. The PR-time gate never
#    saw this tree; the tag does.
make_fixture "$WORK/renamed" "## [1.8.2] - 2026-08-24" 1.8.0 1.8.1 1.8.2
FAKE_TAGS="$ALL_TAGS" \
  expect "no open [Unreleased] at the tag -> refused" 1 "no open [Unreleased] section" "$WORK/renamed" v1.8.2

# 5b. A ref that does not carry the gate script cannot assert the invariant,
#     and must not report that as a pass. This is the live state of
#     release/1.7.x, which cut three of the last six releases.
make_fixture "$WORK/nogate" "## [Unreleased]" 1.8.0 1.8.1 1.8.2
rm -f "$WORK/nogate/scripts/ci/check-changelog-unreleased.sh"
FAKE_TAGS="$ALL_TAGS" \
  expect "[Unreleased] gate absent from the ref -> refused" 1 "CHANGELOG gate missing" "$WORK/nogate" v1.8.2

echo
echo "assert-release-bookkeeping: orphaned notes files (#3429)"

# 6. THE INVERSE MISTAKE, live on main today: 1.7.5.md for a version that
#    produced no images, no release object, and whose tag no longer exists.
make_fixture "$WORK/orphan" "## [Unreleased]" 1.7.5 1.8.0 1.8.1 1.8.2
FAKE_TAGS="$ALL_TAGS" \
  expect "notes file for an untagged, unreleased version -> refused" 1 "Orphaned release-notes file" "$WORK/orphan" v1.8.2

# 7. A tag that was DELETED after its release published is not an orphan --
#    the release is still the thing operators read. Without this arm the check
#    would be wrong in the one direction that costs a real release.
FAKE_TAGS="$ALL_TAGS" FAKE_RELEASES=$'v1.7.5' \
  expect "notes file whose tag is gone but Release remains -> OK" 0 "but a Release exists" "$WORK/orphan" v1.8.2

# 8. The version being released has no Release yet, by construction. It must
#    not be reported as its own orphan.
make_fixture "$WORK/selfonly" "## [Unreleased]" 1.8.2
FAKE_TAGS="$ALL_TAGS" \
  expect "the version being released is not its own orphan" 0 "the version being released" "$WORK/selfonly" v1.8.2

echo
echo "assert-release-bookkeeping: an API we cannot read is not an API that said yes"

# 9. An unreadable repository answers 404 for every lookup, which would make
#    every notes file look orphaned. It must refuse explicitly rather than
#    manufacture findings -- and it must NOT pass.
FAKE_REPO_UNREADABLE=1 FAKE_TAGS="$ALL_TAGS" \
  expect "repository unreadable -> refused, explicitly" 1 "unverifiable" "$WORK/ok" v1.8.2

# 10. An empty tag listing cannot be true for a repository with releases;
#     treating it as "no tags exist" would orphan everything.
FAKE_TAGS="" \
  expect "empty tag listing -> refused, explicitly" 1 "came back empty" "$WORK/ok" v1.8.2

# 11. Usage error is exit 2, distinct from a refusal.
( cd "$WORK/ok" && PATH="$STUB:$PATH" bash .github/scripts/assert-release-bookkeeping.sh >/dev/null 2>&1 )
rc=$?
if [ "$rc" = "2" ]; then pass "no argument -> usage error (exit 2)"; else fail "no argument: expected exit 2, got $rc"; fi

echo
echo "release.yml: the notes fallback is prerelease-only"

# Part B. The arm that actually decides is a `run:` block inside release.yml,
# which nothing else in CI executes. Extract it and run it, so a revert to the
# silent `else` is a red test rather than a review miss.
python3 - "$RELEASE_YML" "$WORK/resolve-notes.sh" <<'PY'
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1]))
body = None
for job in doc["jobs"].values():
    for step in job.get("steps", []) or []:
        if step.get("name") == "Resolve release notes":
            body = step["run"]
if body is None:
    # NON-VACUITY: a test that silently passes because its subject moved is
    # the defect this file exists to prevent.
    sys.exit("release.yml has no 'Resolve release notes' step -- this test has lost its subject")
token = "${{ steps.version.outputs.version }}"
if token not in body:
    sys.exit("'Resolve release notes' no longer reads the resolved version -- test subject changed")
open(sys.argv[2], "w").write(body.replace(token, '"$TEST_VER"'))
PY
[ -s "$WORK/resolve-notes.sh" ] || { echo "  could not extract the step body" >&2; exit 1; }

run_resolve() { # <version> <create notes file? yes/no>
  local ver="$1" create="$2"
  rm -rf "$WORK/relyml"; mkdir -p "$WORK/relyml/.github/release-notes"
  [ "$create" = yes ] && printf 'body\n' > "$WORK/relyml/.github/release-notes/${ver}.md"
  ( cd "$WORK/relyml" && TEST_VER="$ver" GITHUB_OUTPUT="$WORK/gh_output" \
      bash "$WORK/resolve-notes.sh" >"$WORK/out.txt" 2>&1 )
}

run_resolve 1.8.2 yes
rc=$?
if [ "$rc" = "0" ] && grep -q 'generate=false' "$WORK/gh_output"; then
  pass "stable with curated notes -> body_path, generate=false (exit 0)"
else
  fail "stable with curated notes: expected exit 0 and generate=false"
  sed 's/^/        /' "$WORK/out.txt" >&2
fi

# THE v1.7.1 MECHANISM. Reverting this arm to the old silent `else` turns this
# case green, which is precisely what must not be possible.
run_resolve 1.8.2 no
rc=$?
if [ "$rc" = "1" ] && grep -qF "Curated release notes missing" "$WORK/out.txt"; then
  pass "stable with no curated notes -> hard failure (exit 1)"
else
  fail "stable with no curated notes: expected exit 1 with an error annotation"
  sed 's/^/        /' "$WORK/out.txt" >&2
fi

run_resolve 1.8.2-rc.1 no
rc=$?
if [ "$rc" = "0" ] && grep -q 'generate=true' "$WORK/gh_output"; then
  pass "prerelease with no curated notes -> auto-notes fallback kept (exit 0)"
else
  fail "prerelease with no curated notes: expected exit 0 and generate=true"
  sed 's/^/        /' "$WORK/out.txt" >&2
fi

echo
if [ "$fails" -gt 0 ]; then
  echo "$fails case(s) failed"
  exit 1
fi
echo "all cases passed"
