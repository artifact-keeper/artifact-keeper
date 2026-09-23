#!/usr/bin/env bash
# =============================================================================
# test-resolve-verified-tree.sh — the push-time tree check skips only what a
#                                 merged PR really proved
# =============================================================================
#
# resolve-verified-tree.sh lets a push to main skip the Rust jobs. Its only
# dangerous direction is a false "verified=true": a push whose tree was never
# built and tested green would then carry a green CI Complete. So most legs
# here are the refusals -- a different tree, a head that did not contain the
# parent, a skipped or red Rust job on the head, a check run from another app,
# a rust-cache key change, a PR merged elsewhere, every API failure -- and
# each must come back verified=false with exit 0 (fail open: the jobs run).
#
# HOW
#   The script reaches GitHub only through `gh api`. A stub `gh` first on PATH
#   serves canned JSON from $API/<endpoint path with / as _>.json and runs the
#   script's own --jq expression over it with jq -r, so the jq in the script
#   is exercised, not bypassed. check-runs honour the server-side check_name
#   and app_id filters for real. A missing fixture is an API error.
#   No network, ~1s.
#
# Usage: bash scripts/ci/test-resolve-verified-tree.sh
# =============================================================================
set -uo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/resolve-verified-tree.sh"
[ -f "$SCRIPT" ] || { echo "cannot find resolve-verified-tree.sh next to this test" >&2; exit 2; }
command -v jq >/dev/null 2>&1 || { echo "this test needs jq" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0

pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

REPO=artifact-keeper/artifact-keeper
SQUASH=5555555555555555555555555555555555555555
PARENT=1111111111111111111111111111111111111111
HEAD_A=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
HEAD_B=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
TREE=7777777777777777777777777777777777777777
OTHER_TREE=8888888888888888888888888888888888888888

# --- gh stub -----------------------------------------------------------------
STUB="$WORK/bin"; mkdir -p "$STUB"
cat > "$STUB/gh" <<'STUBGH'
#!/usr/bin/env bash
[ "$1" = api ] || exit 1
shift
endpoint="" jqexpr="" check_name="" app_id=""
while [ $# -gt 0 ]; do
  case "$1" in
    -X|--method) shift ;;
    --paginate) ;;
    --jq) shift; jqexpr="$1" ;;
    -f|-F)
      shift
      case "$1" in
        check_name=*) check_name="${1#check_name=}" ;;
        app_id=*)     app_id="${1#app_id=}" ;;
      esac
      ;;
    *) [ -z "$endpoint" ] && endpoint="$1" ;;
  esac
  shift
done
case "$endpoint" in
  */check-runs)
    sha="${endpoint%/check-runs}"; sha="${sha##*/}"
    f="$API/checkruns_${sha}.json"
    [ -f "$f" ] || exit 1
    # Server-side filters: name and app. Rows are {name, conclusion, app_id}.
    body=$(jq --arg n "$check_name" --arg a "$app_id" \
      '{check_runs: [.[] | select(.name == $n and ((.app_id|tostring) == $a))]}' "$f") || exit 1
    ;;
  *)
    f="$API/$(printf '%s' "$endpoint" | tr '/' '_').json"
    [ -f "$f" ] || exit 1
    body=$(cat "$f")
    ;;
esac
if [ -n "$jqexpr" ]; then
  printf '%s' "$body" | jq -r "$jqexpr"
else
  printf '%s\n' "$body"
fi
STUBGH
chmod +x "$STUB/gh"

# --- fixture helpers ---------------------------------------------------------
API=""
new_case() { API="$WORK/api-$1"; rm -rf "$API"; mkdir -p "$API"; }
put() { printf '%s\n' "$2" > "$API/$(printf '%s' "$1" | tr '/' '_').json"; }
commit()  { put "repos/$REPO/git/commits/$1" "{\"sha\":\"$1\",\"tree\":{\"sha\":\"$2\"},\"parents\":[{\"sha\":\"$3\"}]}"; }
files()   { put "repos/$REPO/commits/$SQUASH" "$(jq -cn '{files: [$ARGS.positional[] | {filename: .}]}' --args "$@")"; }
pulls()   { put "repos/$REPO/commits/$SQUASH/pulls" "$1"; }
compare() { put "repos/$REPO/compare/$PARENT...$1" "{\"status\":\"$2\"}"; }
checks()  { printf '%s\n' "$2" > "$API/checkruns_$1.json"; }

GREEN_ALL='[
  {"name":"✅ CI Complete","conclusion":"success","app_id":15368},
  {"name":"🦀 Check Rust","conclusion":"success","app_id":15368},
  {"name":"🧪 Backend Unit Tests","conclusion":"success","app_id":15368},
  {"name":"🔗 Backend Integration Tests","conclusion":"success","app_id":15368}]'

# The healthy shape: squash of PR #42, which was rebased on main (contains
# PARENT) and whose head has the same tree and green checks.
baseline() {
  new_case "$1"
  commit "$SQUASH" "$TREE" "$PARENT"
  files backend/src/main.rs CHANGELOG.md
  pulls "[{\"number\":42,\"merged_at\":\"2026-09-22T10:00:00Z\",\"head\":{\"sha\":\"$HEAD_A\"},\"base\":{\"ref\":\"main\"}}]"
  commit "$HEAD_A" "$TREE" "$PARENT"
  compare "$HEAD_A" ahead
  checks "$HEAD_A" "$GREEN_ALL"
}

# expect <label> <want verified> <want integration_verified> <reason substring> [sha] [branch]
expect() {
  local label="$1" want_v="$2" want_i="$3" needle="$4" sha="${5:-$SQUASH}" branch="${6:-main}" rc=0
  ( PATH="$STUB:$PATH" API="$API" GITHUB_REPOSITORY="$REPO" \
      bash "$SCRIPT" "$sha" "$branch" >"$WORK/out" 2>"$WORK/err" ) || rc=$?
  local v i
  v=$(sed -n 's/^verified=//p' "$WORK/out")
  i=$(sed -n 's/^integration_verified=//p' "$WORK/out")
  if [ "$rc" != 0 ]; then
    fail "$label: exit $rc (the script must fail open with exit 0)"; sed 's/^/        /' "$WORK/err" >&2
  elif [ "$v" != "$want_v" ] || [ "$i" != "$want_i" ]; then
    fail "$label: got verified=$v integration_verified=$i, want $want_v/$want_i"
    sed 's/^/        /' "$WORK/out" "$WORK/err" >&2
  elif ! grep -qF -- "$needle" "$WORK/out"; then
    fail "$label: verdict right but reason lacks '$needle'"; sed 's/^/        /' "$WORK/out" >&2
  else
    pass "$label"
  fi
}

echo "resolve-verified-tree.sh: proven trees"

baseline ok
expect "up-to-date PR head with the same tree and green checks -> verified" \
  true true "proven by PR #42"

baseline identical
compare "$HEAD_A" identical
expect "head identical to the parent (empty squash) still counts as containing it" \
  true true "proven by PR #42"

baseline nointeg
checks "$HEAD_A" '[
  {"name":"✅ CI Complete","conclusion":"success","app_id":15368},
  {"name":"🦀 Check Rust","conclusion":"success","app_id":15368},
  {"name":"🧪 Backend Unit Tests","conclusion":"success","app_id":15368},
  {"name":"🔗 Backend Integration Tests","conclusion":"skipped","app_id":15368}]'
expect "integration skipped on the PR -> Rust verified, integration still runs" \
  true false "proven by PR #42"

baseline second
pulls "[{\"number\":41,\"merged_at\":\"2026-09-22T09:00:00Z\",\"head\":{\"sha\":\"$HEAD_B\"},\"base\":{\"ref\":\"main\"}},
        {\"number\":42,\"merged_at\":\"2026-09-22T10:00:00Z\",\"head\":{\"sha\":\"$HEAD_A\"},\"base\":{\"ref\":\"main\"}}]"
commit "$HEAD_B" "$OTHER_TREE" "$PARENT"
expect "first associated PR does not match, second does -> verified by the second" \
  true true "proven by PR #42"

baseline release
pulls "[{\"number\":42,\"merged_at\":\"2026-09-22T10:00:00Z\",\"head\":{\"sha\":\"$HEAD_A\"},\"base\":{\"ref\":\"release/1.10.x\"}}]"
expect "a PR merged into release/1.10.x verifies a push to release/1.10.x" \
  true true "proven by PR #42" "$SQUASH" release/1.10.x

echo "resolve-verified-tree.sh: refusals (must run the jobs)"

baseline tree
commit "$HEAD_A" "$OTHER_TREE" "$PARENT"
expect "head tree differs from the pushed tree" false false "has tree $OTHER_TREE"

baseline diverged
compare "$HEAD_A" diverged
expect "head does not contain the parent (its CI tested another merge)" \
  false false "does not contain $PARENT"

baseline behind
compare "$HEAD_A" behind
expect "compare status behind is not containment" false false "does not contain"

baseline skippedrust
checks "$HEAD_A" '[
  {"name":"✅ CI Complete","conclusion":"success","app_id":15368},
  {"name":"🦀 Check Rust","conclusion":"skipped","app_id":15368},
  {"name":"🧪 Backend Unit Tests","conclusion":"skipped","app_id":15368}]'
expect "Rust jobs skipped on the PR (CI-only PR) prove nothing" false false "'🦀 Check Rust' is failure"

baseline redcomplete
checks "$HEAD_A" '[
  {"name":"✅ CI Complete","conclusion":"failure","app_id":15368},
  {"name":"🦀 Check Rust","conclusion":"success","app_id":15368},
  {"name":"🧪 Backend Unit Tests","conclusion":"success","app_id":15368}]'
expect "CI Complete red on the head" false false "'✅ CI Complete' is failure"

baseline pending
checks "$HEAD_A" '[
  {"name":"✅ CI Complete","conclusion":null,"app_id":15368},
  {"name":"🦀 Check Rust","conclusion":"success","app_id":15368},
  {"name":"🧪 Backend Unit Tests","conclusion":"success","app_id":15368}]'
expect "CI Complete still running on the head" false false "'✅ CI Complete' is failure"

baseline mixed
checks "$HEAD_A" '[
  {"name":"✅ CI Complete","conclusion":"success","app_id":15368},
  {"name":"🦀 Check Rust","conclusion":"success","app_id":15368},
  {"name":"🧪 Backend Unit Tests","conclusion":"success","app_id":15368},
  {"name":"🧪 Backend Unit Tests","conclusion":"failure","app_id":15368}]'
expect "any non-success among the latest runs of a name refuses" false false "'🧪 Backend Unit Tests' is failure"

baseline otherapp
checks "$HEAD_A" '[
  {"name":"✅ CI Complete","conclusion":"success","app_id":99999},
  {"name":"🦀 Check Rust","conclusion":"success","app_id":99999},
  {"name":"🧪 Backend Unit Tests","conclusion":"success","app_id":99999}]'
expect "same-named check runs from another app are not CI verdicts" false false "is none"

baseline lock
files Cargo.lock backend/src/main.rs
expect "Cargo.lock changed: the push must run to save a fresh rust-cache" false false "rust-cache key input"

baseline nested
files backend/Cargo.toml
expect "a nested Cargo.toml is a cache key input too" false false "backend/Cargo.toml"

baseline toolchain
files rust-toolchain.toml
expect "rust-toolchain.toml changed" false false "rust-toolchain.toml"

baseline elsewhere
pulls "[{\"number\":42,\"merged_at\":\"2026-09-22T10:00:00Z\",\"head\":{\"sha\":\"$HEAD_A\"},\"base\":{\"ref\":\"develop\"}}]"
expect "PR merged into another branch" false false "merged into develop"

baseline unmerged
pulls "[{\"number\":42,\"merged_at\":null,\"head\":{\"sha\":\"$HEAD_A\"},\"base\":{\"ref\":\"main\"}}]"
expect "associated PR not merged (a direct push that happens to match)" false false "no merged pull request"

baseline nopr
pulls '[]'
expect "no associated PR (direct push)" false false "no merged pull request"

echo "resolve-verified-tree.sh: API failures fail open"

baseline e1
rm -f "$API/repos_${REPO//\//_}_git_commits_${SQUASH}.json"
expect "pushed commit unreadable" false false "could not read commit"

baseline e2
rm -f "$API/repos_${REPO//\//_}_commits_${SQUASH}.json"
expect "changed-file listing fails" false false "could not list the files"

baseline e2b
put "repos/$REPO/commits/$SQUASH" '{"sha":"x"}'
expect "changed-file listing without .files (too large)" false false "could not list the files"

baseline e3
rm -f "$API/repos_${REPO//\//_}_commits_${SQUASH}_pulls.json"
expect "associated-PR listing fails" false false "could not list the pull requests"

baseline e4
rm -f "$API/repos_${REPO//\//_}_git_commits_${HEAD_A}.json"
expect "PR head commit unreadable" false false "could not read PR #42 head"

baseline e5
rm -f "$API/repos_${REPO//\//_}_compare_${PARENT}...${HEAD_A}.json"
expect "compare fails" false false "could not compare"

baseline e6
rm -f "$API/checkruns_${HEAD_A}.json"
expect "check-runs lookup fails" false false "is error"

baseline e7
put "repos/$REPO/git/commits/$SQUASH" "{\"sha\":\"$SQUASH\",\"tree\":{\"sha\":\"$TREE\"},\"parents\":[]}"
expect "root commit (no parent)" false false "no parent"

baseline badsha
expect "malformed pushed sha" false false "not a 40-hex" "not-a-sha"

echo "resolve-verified-tree.sh: usage"
rc=0; ( PATH="$STUB:$PATH" GITHUB_REPOSITORY="$REPO" bash "$SCRIPT" >/dev/null 2>&1 ) || rc=$?
if [ "$rc" = 2 ]; then pass "missing arguments -> exit 2"; else fail "missing arguments: exit $rc, want 2"; fi
rc=0; ( PATH="$STUB:$PATH" GITHUB_REPOSITORY="" bash "$SCRIPT" "$SQUASH" main >/dev/null 2>&1 ) || rc=$?
if [ "$rc" = 2 ]; then pass "missing GITHUB_REPOSITORY -> exit 2"; else fail "missing GITHUB_REPOSITORY: exit $rc, want 2"; fi

echo
if [ "$fails" -gt 0 ]; then
  echo "resolve-verified-tree.sh: $fails case(s) FAILED"
  exit 1
fi
echo "resolve-verified-tree.sh: all cases passed"
