#!/usr/bin/env bash
# Self-test for scripts/ci/coverage-merge-base.sh.
#
# The merge base decides which lines the new-code gate calls "added by this
# PR". The failure it replaces: a 200-commit shallow window, then a fallback
# to the base TIP, so a branch further behind main than that measured other
# PRs' lines as its own (#1646). Builds a local origin whose main is 250
# commits past the branch point, checks out the PR MERGE commit at depth 1
# (as actions/checkout does), stubs `gh` for the compare API, and asserts the
# resolved commit, that it is fetched, and that the diff from it holds only
# the PR's file. Offline, ~3s.
#
# Usage: bash scripts/ci/test-coverage-merge-base.sh
set -uo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/coverage-merge-base.sh"
[ -f "$SCRIPT" ] || { echo "cannot find coverage-merge-base.sh next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t
export GIT_CONFIG_NOSYSTEM=1 HOME="$WORK/home"; mkdir -p "$HOME"
git config --global init.defaultBranch main
git config --global advice.detachedHead false

# --- origin: main 250 commits past the branch point, a PR, its merge commit --
SEED="$WORK/seed"
git init -q "$SEED"
(
  cd "$SEED" || exit 1
  echo base > main.txt && git add main.txt && git commit -qm base
  git branch feature
  for i in $(seq 1 250); do echo "$i" > main.txt; git commit -qam "main $i"; done
  git checkout -q feature
  echo pr > pr.rs && git add pr.rs && git commit -qm "the PR"
  git checkout -q main
  git merge -q --no-ff --no-edit feature
  git branch pr-merge
  git reset -q --hard HEAD~1
) || { echo "INFRA: could not build the fixture repo" >&2; exit 2; }
BRANCH_POINT="$(git -C "$SEED" merge-base main feature)"
TIP="$(git -C "$SEED" rev-parse main)"
MERGE="$(git -C "$SEED" rev-parse pr-merge)"
PR_HEAD="$(git -C "$SEED" rev-parse feature)"
ORIGIN="$WORK/origin.git"
git clone -q --bare "$SEED" "$ORIGIN"
git -C "$ORIGIN" config uploadpack.allowAnySHA1InWant true   # GitHub serves any reachable sha

# checkout <sha> -> a fresh depth-1 clone at that commit in $WORK/co
checkout() {
  rm -rf "$WORK/co"
  git init -q "$WORK/co"
  git -C "$WORK/co" remote add origin "file://$ORIGIN"
  git -C "$WORK/co" fetch -q --no-tags --depth=1 origin "$1"
  git -C "$WORK/co" checkout -q FETCH_HEAD
}

# --- stub gh: the compare API --------------------------------------------------
STUB="$WORK/bin"; mkdir -p "$STUB"
cat > "$STUB/gh" <<'STUBGH'
#!/usr/bin/env bash
echo "$*" >> "$GH_LOG"
[ "${FAKE_GH_FAIL-0}" = 1 ] && exit 1
case "$2" in
  */compare/*...*) printf '%s\n' "$FAKE_MB" ;;
  *) exit 64 ;;
esac
STUBGH
chmod +x "$STUB/gh"

# resolve <measured-sha> -> $got / $rc, in the depth-1 clone
resolve() {
  got="" rc=0
  : > "$WORK/gh.log"
  got="$(cd "$WORK/co" && PATH="$STUB:$PATH" GH_LOG="$WORK/gh.log" \
    GITHUB_REPOSITORY=o/r BASE_REF=main MEASURED_SHA="$1" \
    bash "$SCRIPT" 2>"$WORK/err")" || rc=$?
}

echo "coverage-merge-base.sh"

checkout "$MERGE"
if git -C "$WORK/co" cat-file -e "${TIP}^{commit}" 2>/dev/null; then
  fail "fixture: the depth-1 clone already has the base commit"
fi

FAKE_MB="$TIP" resolve "$MERGE"
if [ "$rc" = 0 ] && [ "$got" = "$TIP" ]; then pass "compare API answer is used (merge commit -> its first parent)"
else fail "API answer: rc=$rc got '$got' want $TIP"; sed 's/^/        | /' "$WORK/err" >&2; fi
grep -q "repos/o/r/compare/main...$MERGE" "$WORK/gh.log" \
  && pass "asks compare/<base-ref>...<measured sha>" || fail "gh was called as: $(cat "$WORK/gh.log")"
git -C "$WORK/co" cat-file -e "${TIP}^{tree}" 2>/dev/null \
  && pass "the merge base is fetched (depth 1) so git diff can use it" || fail "merge base not fetched"
changed="$(git -C "$WORK/co" diff --name-only "$TIP" | tr '\n' ' ')"
[ "$changed" = "pr.rs " ] && pass "250 commits behind main: the diff holds only the PR's file" \
  || fail "diff from the resolved base lists: '$changed' (want only pr.rs)"
# What the old tip/branch-point confusion would have measured, for contrast.
git -C "$WORK/co" fetch -q --depth=1 origin "$BRANCH_POINT"
phantom="$(git -C "$WORK/co" diff --name-only "$BRANCH_POINT" | tr '\n' ' ')"
[ "$phantom" = "main.txt pr.rs " ] && pass "(diffing from the branch point instead would add main's main.txt)" \
  || fail "contrast case: '$phantom'"

checkout "$MERGE"
FAKE_GH_FAIL=1 resolve "$MERGE"
[ "$rc" = 0 ] && [ "$got" = "$TIP" ] && pass "API down, merge commit: first parent from the commit object" \
  || { fail "fallback: rc=$rc got '$got' want $TIP"; sed 's/^/        | /' "$WORK/err" >&2; }

checkout "$MERGE"
FAKE_MB="not-a-sha" resolve "$MERGE"
[ "$rc" = 0 ] && [ "$got" = "$TIP" ] && pass "garbage API answer is not trusted (falls back)" \
  || fail "garbage answer: rc=$rc got '$got'"

checkout "$PR_HEAD"
FAKE_MB="$BRANCH_POINT" resolve "$PR_HEAD"
[ "$rc" = 0 ] && [ "$got" = "$BRANCH_POINT" ] && pass "a PR-head checkout gets its branch point from the API" \
  || fail "head checkout: rc=$rc got '$got'"

checkout "$PR_HEAD"
FAKE_GH_FAIL=1 resolve "$PR_HEAD"
[ "$rc" = 1 ] && [ -z "$got" ] && grep -q 'No merge base' "$WORK/err" \
  && pass "API down and not a merge commit: exit 1, no guess (never the base tip)" \
  || fail "no-answer case: rc=$rc got '$got'"

checkout "$MERGE"
FAKE_MB=1111111111111111111111111111111111111111 resolve "$MERGE"
[ "$rc" = 1 ] && [ -z "$got" ] && pass "a merge base that cannot be fetched: exit 1" \
  || fail "unfetchable: rc=$rc got '$got'"

echo
if [ "$fails" -gt 0 ]; then
  echo "coverage-merge-base.sh: $fails case(s) FAILED"
  exit 1
fi
echo "coverage-merge-base.sh: all cases passed"
