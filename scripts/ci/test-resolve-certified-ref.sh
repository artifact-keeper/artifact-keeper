#!/usr/bin/env bash
#
# Self-test for scripts/ci/resolve-certified-ref.sh and for the dispatch-ref
# guard in .github/workflows/release-candidate.yml (release-branch candidates).
#
# WHY THIS EXISTS
#   The resolver decides WHICH signing identity a certification must carry.
#   Get it wrong in the permissive direction and an attacker-controlled branch
#   becomes an accepted signer; get it wrong in the strict direction and a
#   security patch cannot be cut. Neither can be exercised by opening a PR, so
#   the whole world it reads -- the version at the commit, the two ancestry
#   comparisons, the case-sensitive refs lookup and the three workflow blob
#   ids -- is stubbed behind a `gh` on PATH, and this runs offline in ~1s.
#
#   Most cases assert a REFUSAL, because that is the failure direction that
#   matters: an arbitrary branch, a case variant of a real release branch, a
#   commit on neither branch, and -- the attack the content pin exists for --
#   a commit whose release-candidate.yml is not the copy main carries.
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
#   W_BLOB_SHA / W_BLOB_MB / W_BLOB_MAIN
#                 release-candidate.yml's blob id at the commit / at the merge
#                 base ('' = 404) / on main's tip
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
      "$W_MERGE_BASE") b="${W_BLOB_MB}" ;;
      main)            b="${W_BLOB_MAIN}" ;;
      *)               b="${W_BLOB_SHA}" ;;
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
  export W_BLOB_MB=blob1111
  export W_BLOB_MAIN=blob2222
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
expect "a commit on release/1.9.x resolves to that branch" 0 "certified_ref=refs/heads/release/1.9.x"

reset_world; W_MAIN_STATUS=behind; W_BLOB_MB="$W_BLOB_SHA"
expect "a commit on main still resolves to main" 0 "certified_ref=refs/heads/main"

reset_world; W_MAIN_STATUS=identical; W_BLOB_MB="$W_BLOB_SHA"
expect "the tip of main resolves to main" 0 "certified_ref=refs/heads/main"

# The documented remedy for a stale merge-base copy: cherry-pick main's
# CURRENT release-candidate.yml onto the maintenance branch.
reset_world; W_BLOB_MB=blob0000; W_BLOB_MAIN="$W_BLOB_SHA"
expect "a forward-ported workflow (main's current copy) is accepted" 0 "forward-ported"

# ── the refusals ────────────────────────────────────────────────────────────
# An arbitrary topic branch: the commit is on neither main nor the release
# line its own Cargo.toml names, whatever branch it may be reachable from.
reset_world; W_REL_STATUS=diverged
expect "a commit on an arbitrary branch is refused" 1 "is on neither branch"

reset_world; W_MAIN_STATUS=ahead; W_REL_STATUS=ahead
expect "a commit no branch has merged is refused" 1 "is on neither branch"

# Git refs are case-sensitive and the compare API is not to be trusted for it.
reset_world; W_REL_REF=refs/heads/Release/1.9.x
expect "a case variant of the release branch is refused" 1 "case-sensitive"

reset_world; W_REL_REF=refs/heads/release/1.9.X
expect "a case variant of the .x suffix is refused" 1 "case-sensitive"

reset_world; W_REL_REF=""
expect "a version whose release branch does not exist is refused" 1 "does not exist"

# THE CONTENT PIN: an edited release-candidate.yml on a branch that would
# otherwise be allowed to sign.
reset_world; W_BLOB_SHA=blobEVIL
expect "an edited release-candidate.yml is refused" 1 "byte for byte"

reset_world; W_BLOB_SHA=blobEVIL; W_MAIN_STATUS=behind
expect "the content pin also applies to a commit on main" 1 "byte for byte"

reset_world; W_BLOB_SHA=""
expect "a branch with no release-candidate.yml at all is refused" 1 "does not exist at"

# ── shape and measurement ───────────────────────────────────────────────────
reset_world; W_VERSION=1.9.1-rc.1
expect "a prerelease version is refused" 1 "stable X.Y.Z"

reset_world; W_VERSION=""
expect "a Cargo.toml with no version is refused" 1 "stable X.Y.Z"

reset_world; W_FAIL="compare/main"
expect "an unreadable comparison is INFRA, never a pass" 2 "could not compare"

reset_world; W_FAIL="contents/Cargo.toml"
expect "an unreadable Cargo.toml is INFRA, never a pass" 2 "could not read Cargo.toml"

reset_world
SHA=abc expect "a short sha is INFRA (exit 2)" 2 "40-character"
unset SHA

# ── the dispatch-ref guard in release-candidate.yml ─────────────────────────
# The guard runs before any checkout, so it cannot live in a script; the
# regex is read back OUT OF THE WORKFLOW and exercised here, so the thing
# under test is the text that actually ships.
echo "release-candidate.yml dispatch-ref guard"
if [ ! -f "$WORKFLOW" ]; then
  fail "cannot find release-candidate.yml to read the guard from"
else
  guard_re="$(sed -n 's/.*=~ \(\^refs\/heads\/release[^ ]*\$\).*/\1/p' "$WORKFLOW" | head -1)"
  if [ -z "$guard_re" ]; then
    fail "release-candidate.yml carries no anchored refs/heads/release regex"
  else
    pass "guard regex found in the workflow: ${guard_re}"
    check_ref() { # <ref> <accept|refuse>
      local ref="$1" want="$2" ok=0
      [[ "$ref" == "refs/heads/main" || "$ref" =~ $guard_re ]] || ok=1
      case "$want" in
        accept) if [ "$ok" = 0 ]; then pass "guard accepts ${ref}"; else fail "guard REFUSES ${ref}"; fi ;;
        refuse) if [ "$ok" = 1 ]; then pass "guard refuses ${ref}"; else fail "guard ACCEPTS ${ref}"; fi ;;
      esac
    }
    check_ref refs/heads/main             accept
    check_ref refs/heads/release/1.9.x    accept
    check_ref refs/heads/release/10.20.x  accept
    check_ref refs/heads/Main             refuse
    check_ref refs/heads/Release/1.9.x    refuse
    check_ref refs/heads/release/1.9.X    refuse
    check_ref refs/heads/release/1.9.x-evil refuse
    check_ref refs/heads/release/1.9.0    refuse
    check_ref refs/heads/feat/evil        refuse
    check_ref refs/heads/xrefs/heads/release/1.9.x refuse
    check_ref refs/tags/v1.9.1            refuse
  fi
fi

if [ "$fails" -eq 0 ]; then echo "all resolve-certified-ref.sh cases passed"; exit 0; fi
echo "${fails} resolve-certified-ref.sh case(s) FAILED"; exit 1
