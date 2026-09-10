#!/usr/bin/env bash
#
# Self-test for scripts/ci/resolve-certified-ref.sh and for the dispatch-ref
# guard in .github/workflows/release-candidate.yml (maintenance-line
# candidates).
#
# WHY THIS EXISTS
#   The resolver decides WHICH COMMITS main's Release Candidate may certify.
#   Get it wrong in the permissive direction and a commit on no release line
#   becomes releasable; get it wrong in the strict direction and a security
#   patch cannot be cut. Neither can be exercised by opening a PR, so
#   the whole world it reads -- the version at the commit, the two ancestry
#   comparisons, the case-sensitive refs lookup and the three workflow blob
#   ids -- is stubbed behind a `gh` on PATH, and this runs offline in ~1s.
#
#   Most cases assert a REFUSAL, because that is the failure direction that
#   matters: an arbitrary branch, a case variant of a real release branch, a
#   commit on neither branch, and -- the backstop for the window in which an
#   admin has the release ruleset toggled off -- a commit whose
#   release-candidate.yml is not the copy main carries. The guard section at
#   the end pins the decision that keeps the signing identity unwidened.
#
# Usage: bash scripts/ci/test-resolve-certified-ref.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESOLVER="${HERE}/resolve-certified-ref.sh"
WORKFLOW="${HERE}/../../.github/workflows/release-candidate.yml"
[ -f "$RESOLVER" ] || { echo "cannot find resolve-certified-ref.sh next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

SHA_A=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
MB=cccccccccccccccccccccccccccccccccccccccc

STUB="$WORK/bin"; mkdir -p "$STUB"

# `gh api` stub. The world is described by W_* env vars; every call the
# resolver can make is answered from them, and anything else is a loud 64 so
# a new call cannot be added without a decision here.
#   W_VERSION     the `version = "..."` line Cargo.toml carries at the commit
#   W_MAIN_STATUS status of compare main...<sha>  (behind|identical|ahead|diverged)
#   W_MERGE_BASE  merge_base_commit.sha of that comparison
#   W_REL_REF     what the refs API answers for the derived branch ('' = 404)
#   W_REL_STATUS  status of compare <branch>...<sha>
#   W_BLOB_SHA / W_BLOB_MAIN
#                 release-candidate.yml's blob id at the commit ('' = 404) and
#                 on main's tip
#   W_FAIL        a path fragment whose call fails as a non-404 error
cat > "$STUB/gh" <<'STUBGH'
#!/usr/bin/env bash
[ "${1:-}" = "api" ] || { echo "stub gh: unexpected '${1:-}'" >&2; exit 64; }
shift
path=""; raw=0; want_jq=""
while [ $# -gt 0 ]; do
  case "$1" in
    -H) case "$2" in *raw+json*) raw=1 ;; esac; shift 2 ;;
    --jq) want_jq="$2"; shift 2 ;;
    repos/*) path="$1"; shift ;;
    *) shift ;;
  esac
done
[ -n "$path" ] || { echo "stub gh: no repos/ path" >&2; exit 64; }
if [ -n "${W_FAIL:-}" ] && case "$path" in *"$W_FAIL"*) true ;; *) false ;; esac; then
  echo "gh: Internal Server Error (HTTP 500)" >&2; exit 1
fi
notfound() { echo "gh: Not Found (HTTP 404)" >&2; exit 1; }
emit() { if [ -n "$want_jq" ]; then jq -r "$want_jq" <<<"$1"; else printf '%s' "$1"; fi; }
case "$path" in
  */contents/Cargo.toml*)
    [ "$raw" = 1 ] || { echo "stub gh: Cargo.toml must be read raw" >&2; exit 64; }
    printf '[package]\nname = "artifact-keeper"\nversion = "%s"\n' "${W_VERSION}" ;;
  */contents/.github/workflows/release-candidate.yml*)
    ref="${path##*ref=}"
    case "$ref" in
      main) b="${W_BLOB_MAIN}" ;;
      *)    b="${W_BLOB_SHA}" ;;
    esac
    [ -n "$b" ] || notfound
    emit "$(jq -nc --arg s "$b" '{sha:$s}')" ;;
  */git/ref/heads/*)
    [ -n "${W_REL_REF}" ] || notfound
    emit "$(jq -nc --arg r "$W_REL_REF" '{ref:$r}')" ;;
  */compare/main...*)
    emit "$(jq -nc --arg s "$W_MAIN_STATUS" --arg m "$W_MERGE_BASE" '{status:$s,merge_base_commit:{sha:$m}}')" ;;
  */compare/*)
    emit "$(jq -nc --arg s "$W_REL_STATUS" '{status:$s}')" ;;
  *) echo "stub gh: unhandled ${path}" >&2; exit 64 ;;
esac
STUBGH
chmod +x "$STUB/gh"

# A world where the commit sits on release/1.9.x with main's workflow file.
reset_world() {
  export W_VERSION=1.9.1
  export W_MAIN_STATUS=diverged
  export W_MERGE_BASE="$MB"
  export W_REL_REF=refs/heads/release/1.9.x
  export W_REL_STATUS=behind
  export W_BLOB_SHA=blob1111
  export W_BLOB_MAIN=blob1111
  export W_FAIL=""
}

# <label> <expected-exit> <expected-substring>; world from exported W_*.
expect() {
  local label="$1" want="$2" needle="$3" got=0 out
  out="$( PATH="$STUB:$PATH" CERTREF_REPO=artifact-keeper/artifact-keeper \
      GITHUB_OUTPUT="" bash "$RESOLVER" "${SHA:-$SHA_A}" 2>&1 )" || got=$?
  if [ "$got" = "$want" ] && printf '%s' "$out" | grep -qF -- "$needle"; then
    pass "$label"
  else
    fail "$label (wanted exit ${want} containing '${needle}', got exit ${got})"
    printf '%s\n' "$out" | sed 's/^/        /' | tail -n 5
  fi
}

echo "resolve-certified-ref.sh self-test"

# ── the two accepted shapes ─────────────────────────────────────────────────
reset_world
expect "a commit on release/1.9.x resolves to that line" 0 "certified_ref=refs/heads/release/1.9.x"

reset_world; W_MAIN_STATUS=behind
expect "a commit on main still resolves to main" 0 "certified_ref=refs/heads/main"

reset_world; W_MAIN_STATUS=identical
expect "the tip of main resolves to main" 0 "certified_ref=refs/heads/main"

# A commit that is on BOTH -- a maintenance commit forward-merged to main --
# resolves to main, deterministically, and is not subject to the content pin.
reset_world; W_MAIN_STATUS=behind; W_REL_STATUS=behind; W_BLOB_SHA=blobOLD
expect "a commit on both lines resolves to main, deterministically" 0 "certified_ref=refs/heads/main"

# ── the refusals ────────────────────────────────────────────────────────────
# An arbitrary topic branch: the commit is on neither main nor the release
# line its own Cargo.toml names, whatever branch it may be reachable from.
reset_world; W_REL_STATUS=diverged
expect "a commit on an arbitrary branch is refused" 1 "is on neither branch"

reset_world; W_MAIN_STATUS=ahead; W_REL_STATUS=ahead
expect "a commit no branch has merged is refused" 1 "is on neither branch"

# Git refs are case-sensitive and the compare API is not to be trusted for it.
# The DERIVED name is always lowercase, so this catches a refs API that
# answered with a different ref than the one asked for -- a prefix match, or a
# case-folded one.
reset_world; W_REL_REF=refs/heads/Release/1.9.x
expect "the refs API answering a case variant is refused" 1 "case-sensitive"

reset_world; W_REL_REF=refs/heads/release/1.9.X
expect "the refs API answering a different .x suffix is refused" 1 "case-sensitive"

reset_world; W_REL_REF=refs/heads/release/1.9.x-old
expect "the refs API answering a longer name is refused" 1 "case-sensitive"

reset_world; W_REL_REF=""
expect "a version whose release line does not exist is refused" 1 "does not exist"

# THE CONTENT PIN: an edited release-candidate.yml on a line that would
# otherwise be allowed to certify -- and, since finding 3, a STALE one too.
# Only main's CURRENT copy is accepted, because the merge base is chosen by
# whoever chose the commit's parent.
reset_world; W_BLOB_SHA=blobEVIL
expect "an edited release-candidate.yml on a line is refused" 1 "is not main's current copy"

reset_world; W_BLOB_SHA=blobOLD
expect "a STALE release-candidate.yml on a line is refused, not blessed" 1 "cherry-pick"

reset_world; W_BLOB_SHA=""
expect "a line with no release-candidate.yml at all is refused" 1 "does not exist at"

# On main the pin decides nothing and says so, rather than passing vacuously.
reset_world; W_MAIN_STATUS=behind; W_BLOB_SHA=blobANYTHING
expect "on main the content pin is skipped explicitly, not vacuously passed" 0 "content pin not applicable"

# ── shape and measurement ───────────────────────────────────────────────────
reset_world; W_VERSION=1.9.1-rc.1
expect "a prerelease version is refused" 1 "stable X.Y.Z"

reset_world; W_VERSION=""
expect "a Cargo.toml with no version is refused" 1 "stable X.Y.Z"

reset_world; W_FAIL="compare/main"
expect "an unreadable comparison is INFRA, never a pass" 2 "could not compare"

reset_world; W_VERSION=01.9.1
expect "a leading-zero version is refused" 1 "stable X.Y.Z"

reset_world; W_VERSION=1.9
expect "a two-component version is refused" 1 "stable X.Y.Z"

reset_world; W_FAIL="contents/Cargo.toml"
expect "an unreadable Cargo.toml is INFRA, never a pass" 2 "could not read Cargo.toml"

reset_world; W_FAIL="git/ref/heads"
expect "an unreadable refs lookup is INFRA, never a pass" 2 "could not look up"

reset_world; W_FAIL="compare/release"
expect "an unreadable release-line comparison is INFRA, never a pass" 2 "could not compare"

reset_world; W_FAIL="release-candidate.yml"
expect "an unreadable workflow blob is INFRA, never a pass" 2 "could not read"

reset_world
SHA=abc expect "a short sha is INFRA (exit 2)" 2 "40-character"
unset SHA

# ── the dispatch-ref guard in release-candidate.yml ─────────────────────────
# The candidate certifies maintenance commits FROM MAIN, so the guard must
# stay main-only. This is the regression test for that decision: the day
# someone widens the guard to accept `refs/heads/release/*`, the signing
# identity widens with it and the "create a release/* ref, put an edited
# release-candidate.yml on it, satisfy the exact pin" attack becomes
# reachable again. Read out of the workflow that actually ships.
echo "release-candidate.yml dispatch-ref guard"
if [ ! -f "$WORKFLOW" ]; then
  fail "cannot find release-candidate.yml to read the guard from"
else
  # Deliberately single-quoted: this is the literal text that must appear in
  # the workflow, not something to expand here.
  # shellcheck disable=SC2016
  if grep -q '\[\[ "${GITHUB_REF}" != "refs/heads/main" \]\]' "$WORKFLOW"; then
    pass "the guard refuses every dispatch ref but refs/heads/main"
  else
    fail "release-candidate.yml no longer carries the exact main-only dispatch guard"
  fi
  if grep -qE '=~ \^refs/heads/release' "$WORKFLOW"; then
    fail "the dispatch guard accepts a release/* ref -- that widens the signing identity (see the header of assert-candidate-certified.sh)"
  else
    pass "the guard does not accept a release/* ref, so the signing identity stays unwidened"
  fi
fi

# ── FINDING 1: no code from the certified commit runs in release-candidate.yml ─
# The certification's whole value is that only main's release-candidate.yml
# can mint one. That is a property of the JOB, not just of the workflow file:
# `certify` holds `id-token: write` and `attestations: write` for every one of
# its steps, so a single `actions/checkout` at the certified sha would hand a
# maintenance commit arbitrary shell with the signing identity in scope --
# attempt 2's attack, relocated from the workflow file to the scripts beside
# it. The structural rule that prevents it is: EVERY checkout in this workflow
# is `refs/heads/main`, and the certified commit enters only as named DATA
# paths. Both halves are pinned here, because both are one careless line away.
echo "release-candidate.yml runs no code from the certified commit"
if [ ! -f "$WORKFLOW" ]; then
  fail "cannot find release-candidate.yml"
else
  # shellcheck disable=SC2016  # literal workflow text, not for expansion here
  if grep -q 'ref: ${{ needs.resolve.outputs.sha }}' "$WORKFLOW"; then
    fail "a job checks out the CERTIFIED SHA -- its scripts/ci would execute with the job's token in scope (adversarial review, finding 1)"
  else
    pass "no job checks out the certified sha"
  fi

  checkouts="$(grep -c 'uses: actions/checkout@' "$WORKFLOW" || true)"
  main_refs="$(grep -c '^          ref: refs/heads/main$' "$WORKFLOW" || true)"
  if [ "$checkouts" -gt 0 ] && [ "$checkouts" = "$main_refs" ]; then
    pass "all ${checkouts} checkouts are refs/heads/main"
  else
    fail "${checkouts} checkout(s) but ${main_refs} pinned to refs/heads/main -- every one must be main's tooling"
  fi

  # The certified commit may still be READ. Each `git checkout <sha> -- ...`
  # must name only data the bookkeeping asserts ON; a script path here would
  # reintroduce the finding by the back door. The marker is the workflow's
  # literal text -- `$SHA` there is the workflow's variable, not this test's.
  # shellcheck disable=SC2016
  marker='git checkout "$SHA" -- '
  bad=0
  overlays="$(grep -F -- "$marker" "$WORKFLOW" || true)"
  if [ -n "$overlays" ]; then
    while IFS= read -r line; do
      for path in ${line#*"$marker"}; do
        case "$path" in
          CHANGELOG.md|.github/release-notes) ;;
          *) fail "the certified commit is overlaid at '${path}', which is not release bookkeeping data"; bad=1 ;;
        esac
      done
    done <<EOF_OVERLAY
$overlays
EOF_OVERLAY
  fi
  if [ "$bad" = 0 ]; then
    pass "the certified commit is overlaid only as release bookkeeping data"
  fi
fi

if [ "$fails" -eq 0 ]; then echo "all resolve-certified-ref.sh cases passed"; exit 0; fi
echo "${fails} resolve-certified-ref.sh case(s) FAILED"; exit 1
