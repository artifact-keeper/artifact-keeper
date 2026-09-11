#!/usr/bin/env bash
#
# Self-test for scripts/ci/resolve-certified-ref.sh and for the parts of
# .github/workflows/release-candidate.yml that CI must pin: the dispatch-ref
# guard, the audit that no code from the certified commit runs, and the
# certification predicate (extracted and EXECUTED).
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
  # Most content cases are about the moment of BLESSING, which is the only
  # time main's current copy is demanded.
  export CERTREF_REQUIRE_MAIN_WORKFLOW=1
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
expect "an edited release-candidate.yml on a line is refused at blessing" 1 "is not main's current copy"

reset_world; W_BLOB_SHA=blobOLD
expect "a STALE release-candidate.yml on a line is refused at blessing" 1 "cherry-pick"

reset_world; W_BLOB_SHA=""
expect "a line with no release-candidate.yml at all is refused" 1 "does not exist at"

# BLESSED ONCE (r2, finding N1). Outside the candidate the resolver only
# REPORTS the blob; main's tip moving must never invalidate a certification
# that already exists, or an unrelated merge strands it permanently.
reset_world; CERTREF_REQUIRE_MAIN_WORKFLOW=0; W_BLOB_MAIN=blobMAINMOVED
expect "main's workflow moving does not invalidate a certified commit" 0 "certified_ref=refs/heads/release/1.9.x"

reset_world; CERTREF_REQUIRE_MAIN_WORKFLOW=0; W_BLOB_MAIN=blobMAINMOVED
expect "the blob at the commit is reported for the verifier to compare" 0 "workflow_blob=blob1111"

reset_world
expect "blessing reports the same blob it demanded" 0 "workflow_blob=blob1111"

# On main the pin decides nothing and says so, rather than passing vacuously.
reset_world; W_MAIN_STATUS=behind; W_BLOB_SHA=blobANYTHING
expect "on main nothing is demanded, explicitly, rather than vacuously passed" 0 "nothing to demand"

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
# its steps, so any route that puts the certified commit's tree on disk there
# hands a maintenance commit arbitrary shell with the signing identity in
# scope -- attempt 2's attack, relocated from the workflow file to the scripts
# beside it.
#
# Three routes are checked (r2 N3, widened in r3): any action given a `ref:`
# other than main -- not just `actions/checkout`, since a third-party action
# takes the same input; any `git` command that can write another tree
# (`checkout`, `switch`, `restore`, `archive`, `worktree`, `read-tree`), with
# the verb matched anywhere after `git` so global options like `git -C .`
# cannot hide it; and any fetch of a commit archive over HTTP
# (`tarball`/`zipball`/`/archive/`), because `| tar xz` is as good as a
# checkout. The only permitted way for the commit's tree to touch the disk is
# a pathspec-scoped checkout of release bookkeeping DATA.
#
# BE HONEST ABOUT WHAT THIS IS: a text audit of the workflow, not a parse of
# it. It catches the routes named above in the forms they are written in, and
# the fixtures below are the evidence for each. It cannot catch a tree
# smuggled in by something it does not know to look for -- an action that
# fetches by digest, a script that reconstructs files from `git cat-file`, a
# `uses:` of a local composite action. It is a tripwire on the known routes,
# and the reason it is worth having is that those are the routes an ordinary
# edit takes.
#
# The check is a function so it can be run against fixtures that reintroduce
# the hole -- a test that has never been shown to fail is not a test.
audit_workflow() { # <file>; echoes one `verdict:reason` line per problem
  local wf="$1" line paths path marker body
  # The workflow's literal text. `$SHA` here is the WORKFLOW's variable, so
  # the marker must never be expanded by this shell.
  # shellcheck disable=SC2016
  marker='git checkout "$SHA" -- '
  # Comments are not code; a comment that merely NAMES one of these commands
  # must not trip the audit.
  body="$(sed 's/^[[:space:]]*#.*$//' "$wf")"

  # 1. Every `ref:` an action is given must be main. Counting
  #    `actions/checkout` alone missed a third-party checkout action taking
  #    the same input (r3, item 2), and this covers any action with a `ref`.
  local refs bad_refs
  refs="$(grep -cE '^[[:space:]]+ref:[[:space:]]' <<<"$body" || true)"
  [ "$refs" -gt 0 ] || echo "no-checkouts:the workflow gives no action a ref at all"
  bad_refs="$(grep -E '^[[:space:]]+ref:[[:space:]]' <<<"$body" | grep -vE '^[[:space:]]+ref: refs/heads/main$' || true)"
  if [ -n "$bad_refs" ]; then
    while IFS= read -r line; do
      [ -n "$line" ] && echo "declarative:${line# }"
    done <<EOF_REFS
$bad_refs
EOF_REFS
  fi

  # 2. Any git command that can put another tree on disk. The verb is matched
  #    anywhere after `git`, so global options (`git -C .`, `-c`) cannot hide
  #    it (r3, item 2), and `read-tree` is included.
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    case "$line" in
      *"$marker"*) paths="${line#*"$marker"}" ;;
      *) echo "git-cmd:${line# }"; continue ;;
    esac
    for path in $paths; do
      case "$path" in
        CHANGELOG.md|.github/release-notes) ;;
        *) echo "overlay-path:${path}" ;;
      esac
    done
  done <<EOF_GIT
$(grep -E 'git .*(checkout|switch|restore|archive|worktree|read-tree)' <<<"$body" || true)
EOF_GIT

  # 3. The tree can also arrive over HTTP. GitHub serves any commit as an
  #    archive, and `| tar xz` is as good as a checkout (r3, item 2).
  local archives
  archives="$(grep -E 'tarball|zipball|/archive/' <<<"$body" || true)"
  [ -z "$archives" ] || printf 'archive-fetch:%s\n' "$(tr -s ' ' <<<"$archives")"
}

echo "release-candidate.yml runs no code from the certified commit"
if [ ! -f "$WORKFLOW" ]; then
  fail "cannot find release-candidate.yml"
else
  problems="$(audit_workflow "$WORKFLOW")"
  if [ -z "$problems" ]; then
    pass "no route puts the certified commit's tree on disk except the bookkeeping overlay"
  else
    fail "release-candidate.yml exposes the certified commit's tree:"
    printf '%s\n' "$problems" | sed 's/^/          /'
  fi
fi

# The audit must FAIL on each way the hole comes back. Fixtures, not prose.
fixture() { # <name> <body>
  local f="$WORK/wf-$1.yml"
  printf '%s\n' "$2" > "$f"
  if [ -n "$(audit_workflow "$f")" ]; then
    pass "the audit catches: $1"
  else
    fail "the audit MISSES: $1 -- finding 1 would come back silently"
  fi
}
BASE='      - uses: actions/checkout@abc
        with:
          ref: refs/heads/main'
fixture "a declarative checkout of the certified sha" \
  "$BASE
      - uses: actions/checkout@abc
        with:
          ref: \${{ needs.resolve.outputs.sha }}"
fixture "a declarative checkout of an env alias for it" \
  "$BASE
      - uses: actions/checkout@abc
        with:
          ref: \${{ env.SHA }}"
fixture "a forced git checkout inside a run block" \
  "$BASE
      - run: git fetch origin \"\$SHA\" && git checkout --force \"\$SHA\""
fixture "a braced git checkout smuggling a script path" \
  "$BASE
      - run: git checkout \"\${SHA}\" -- CHANGELOG.md .github/release-notes scripts/ci"
fixture "the exact overlay form with a script path appended" \
  "$BASE
      - run: git checkout \"\$SHA\" -- CHANGELOG.md .github/release-notes scripts/ci"
fixture "a git switch to the certified sha" \
  "$BASE
      - run: git switch --detach \"\$SHA\""
fixture "a git archive of the certified sha extracted in place" \
  "$BASE
      - run: git archive \"\$SHA\" | tar -x"
fixture "a second worktree at the certified sha" \
  "$BASE
      - run: git worktree add /tmp/c \"\$SHA\""
fixture "a git checkout hidden behind a global option" \
  "$BASE
      - run: git -C . checkout --force \"\$SHA\""
fixture "a git checkout hidden behind -c" \
  "$BASE
      - run: git -c core.fsmonitor=false checkout \"\$SHA\""
fixture "a THIRD-PARTY checkout action given the certified sha" \
  "      - uses: some-org/checkout-action@v1
        with:
          ref: \${{ needs.resolve.outputs.sha }}"
fixture "the commit fetched as a tarball over HTTP" \
  "$BASE
      - run: gh api repos/o/r/tarball/\$SHA | tar xz"
fixture "the commit fetched as a zipball over HTTP" \
  "$BASE
      - run: curl -L https://github.com/o/r/archive/\$SHA.zip -o c.zip"
fixture "git read-tree materialising the certified sha" \
  "$BASE
      - run: git read-tree -u --reset \"\$SHA\""

# ...and must PASS the shape that actually ships, so it is not merely strict.
printf '%s\n' "$BASE
      - run: git checkout \"\$SHA\" -- CHANGELOG.md .github/release-notes" > "$WORK/wf-ok.yml"
if [ -z "$(audit_workflow "$WORK/wf-ok.yml")" ]; then
  pass "the audit accepts the bookkeeping overlay it is meant to allow"
else
  fail "the audit rejects the shipped overlay shape -- it would block every edit"
fi

# ── the certification predicate, EXECUTED ───────────────────────────────────
# The suites stub `gh` and audit text; the workflow's own inline shell was
# covered only by actionlint's embedded shellcheck. That is exactly the gap
# that let an apostrophe inside the single-quoted jq program through until a
# re-run happened to catch it -- a bug that would have broken every
# certification at runtime, not in CI (r3, item 3). So the predicate step is
# extracted from the workflow and RUN here, offline, and its output is
# checked for the fields the verifier reads back.
echo "release-candidate.yml builds a valid certification predicate"
if [ ! -f "$WORKFLOW" ]; then
  fail "cannot find release-candidate.yml"
elif ! command -v jq >/dev/null 2>&1; then
  fail "jq is not on PATH; the predicate cannot be executed"
else
  prog="$(awk '
    /^ +jq -n \\$/      { f = 1 }
    f                   { sub(/^          /, ""); print }
    /certification\/predicate\.json$/ { if (f) exit }
  ' "$WORKFLOW")"
  if [ -z "$prog" ]; then
    fail "could not find the jq predicate program in release-candidate.yml"
  else
    pdir="$WORK/pred"; mkdir -p "$pdir/certification"
    {
      echo 'set -euo pipefail'
      echo 'SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
      echo 'VERSION=1.9.1'
      echo 'CERTIFIED_REF=refs/heads/release/1.9.x'
      echo 'WORKFLOW_BLOB=b1b1b1b1'
      echo 'GITHUB_RUN_ID=4242'
      echo 'GITHUB_RUN_ATTEMPT=1'
      echo 'GITHUB_SERVER_URL=https://github.com'
      echo 'GITHUB_REPOSITORY=artifact-keeper/artifact-keeper'
      echo 'PUBLISH_RUN_ID=99'
      echo 'ADAPTER_VERSION=2.3.4'
      echo 'BACKEND_DIGEST=sha256:1111111111111111111111111111111111111111111111111111111111111111'
      echo 'OPENSCAP_DIGEST=sha256:2222222222222222222222222222222222222222222222222222222222222222'
      echo 'ADAPTER_DIGEST=sha256:3333333333333333333333333333333333333333333333333333333333333333'
      echo 'BACKEND_IMAGE=ghcr.io/o/r-backend'
      echo 'OPENSCAP_IMAGE=ghcr.io/o/r-openscap'
      echo 'ADAPTER_IMAGE=ghcr.io/o/r-scanner-adapter'
      printf '%s\n' "$prog"
    } > "$pdir/run.sh"
    out=""; rc=0
    out="$(cd "$pdir" && bash run.sh 2>&1)" || rc=$?
    if [ "$rc" != 0 ]; then
      fail "the predicate step does not run (exit ${rc}) -- a quoting or jq error that CI would otherwise meet at a real cut"
      printf '%s\n' "$out" | sed 's/^/          /' | tail -n 4
    elif ! jq -e . "$pdir/certification/predicate.json" >/dev/null 2>&1; then
      fail "the predicate step ran but did not write valid JSON"
    else
      pass "the predicate step runs and writes valid JSON"
      # Every field the verifier reads back must be present and correct;
      # a predicate that parses but omits one blocks a real promote.
      for probe in \
        '.commit_sha == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' \
        '.version == "1.9.1"' \
        '.certified_ref == "refs/heads/release/1.9.x"' \
        '.certified_workflow_blob == "b1b1b1b1"' \
        '.candidate_run_id == "4242"' \
        '.gate_run_id == "4242"' \
        '(.digests | keys) == ["backend","openscap","scanner_adapter"]' \
        '.sha_tag == "sha-aaaaaaa"'
      do
        if jq -e "$probe" "$pdir/certification/predicate.json" >/dev/null 2>&1; then
          pass "predicate: ${probe}"
        else
          fail "predicate: ${probe} -- the verifier reads this field"
        fi
      done
    fi
  fi
fi

if [ "$fails" -eq 0 ]; then echo "all resolve-certified-ref.sh cases passed"; exit 0; fi
echo "${fails} resolve-certified-ref.sh case(s) FAILED"; exit 1
