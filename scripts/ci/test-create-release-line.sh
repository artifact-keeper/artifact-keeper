#!/usr/bin/env bash
#
# Self-test for scripts/release/create-release-line.sh (#3798).
#
# WHY THIS EXISTS
#   The script runs once or twice a year, by hand, on a workstation, against a
#   ruleset with no bypass actors -- and for the length of one API call it is
#   the only thing holding `release/*` protection open. There is no run to
#   watch for a regression in, and the two failure directions are both
#   expensive: a precondition that stopped refusing would put an unreviewed
#   commit at the root of a release line, and a restore that stopped happening
#   would leave the ruleset in `evaluate` with nobody looking.
#
#   So `gh` is stubbed on PATH (every call answered from a fixture, anything
#   unexpected a loud 64) and `git` is real, against a throwaway repo with a
#   local bare `origin`. Offline, ~2s.
#
#   Most cases assert a REFUSAL, because that is the direction that matters,
#   and two of them pin the properties that are invisible on a green run:
#   `--dry-run` issues no PUT/POST at all, and a FAILED ref creation still
#   restores enforcement=active.
#
# Usage: bash scripts/ci/test-create-release-line.sh
set -uo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../release/create-release-line.sh"
[ -f "$SCRIPT" ] || {
  echo "cannot find scripts/release/create-release-line.sh" >&2
  exit 2
}
command -v jq > /dev/null || { echo "jq is required by this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() {
  printf '  \033[31mFAIL\033[0m  %s\n' "$*"
  fails=$((fails + 1))
}

# ── fixture: a bare origin and a clone ──────────────────────────────────────
#
# main:  m1 (version 1.9.0, tagged v1.9.0) -> m2 (version 1.10.0)
# side:  s1, off main and never pushed -- the "not reachable from main" case.
ORIGIN="$WORK/origin.git"
REPO="$WORK/clone"
git init -q --bare -b main "$ORIGIN"
git init -q -b main "$REPO"
cd "$REPO" || exit 2
git config user.email t@example.com
git config user.name t
git config commit.gpgsign false
printf '[workspace.package]\nversion = "1.9.0"\n' > Cargo.toml
git add Cargo.toml && git commit -qm "m1"
SHA_190="$(git rev-parse HEAD)"
git tag v1.9.0
printf '[workspace.package]\nversion = "1.10.0"\n' > Cargo.toml
git add Cargo.toml && git commit -qm "m2"
SHA_110="$(git rev-parse HEAD)"
git remote add origin "$ORIGIN"
git push -q origin main --tags
git checkout -q -b side "$SHA_190"
printf '[workspace.package]\nversion = "1.9.0"\nextra = 1\n' > Cargo.toml
git add Cargo.toml && git commit -qm "s1 off main"
SHA_SIDE="$(git rev-parse HEAD)"
git checkout -q main
git fetch -q origin

# ── gh stub ─────────────────────────────────────────────────────────────────
#
# State lives in two files: $GH_RULESET (the ruleset JSON, whose .enforcement
# the PUT rewrites) and $GH_LOG (one line per call, which is how the no-call
# and restore-on-failure cases are asserted). W_CREATE_FAIL makes the ref
# creation fail; W_ADMIN answers .permissions.admin; W_RESTORE_FAIL makes the
# restoring PUT fail, which must be shouted about rather than logged;
# W_APPROVALS makes the ruleset GET report a different review count (#6216).
STUB="$WORK/bin"
mkdir -p "$STUB"
cat > "$STUB/gh" <<'STUBGH'
#!/usr/bin/env bash
[ "${1:-}" = "api" ] || { echo "stub gh: unexpected '${1:-}'" >&2; exit 64; }
shift
method=GET; path=""; want_jq=""; input=""; f_sha=""
while [ $# -gt 0 ]; do
  case "$1" in
    -X) method="$2"; shift 2 ;;
    --jq) want_jq="$2"; shift 2 ;;
    --input) input="$2"; shift 2 ;;
    -f) case "$2" in sha=*) f_sha="${2#sha=}" ;; esac; shift 2 ;;
    repos/* | user) [ -n "$path" ] || path="$1"; shift ;;
    *) shift ;;
  esac
done
echo "${method} ${path}" >> "$GH_LOG"
emit() { if [ -n "$want_jq" ]; then jq -r "$want_jq" <<< "$1"; else printf '%s' "$1"; fi; }
case "${method} ${path}" in
  "GET user") emit '{"login":"release-admin"}' ;;
  "PUT "*/rulesets/*)
    [ "$input" = "-" ] || { echo "stub gh: ruleset PUT must read --input -" >&2; exit 64; }
    body="$(cat)"
    want="$(jq -r '.enforcement' <<< "$body")"
    [ "$want" = "active" ] || [ "$want" = "evaluate" ] || { echo "stub gh: bad enforcement '$want'" >&2; exit 64; }
    # The body must carry ONLY enforcement: a PUT that echoed the whole
    # ruleset back would silently rewrite whatever it was holding.
    [ "$(jq -r 'keys | join(",")' <<< "$body")" = "enforcement" ] \
      || { echo "stub gh: ruleset PUT body must be exactly {enforcement}" >&2; exit 64; }
    if [ "$want" = "active" ] && [ -n "${W_RESTORE_FAIL:-}" ]; then exit 1; fi
    jq --arg e "$want" '.enforcement = $e | .updated_at = "2026-09-20T12:00:00.000Z"' \
      "$GH_RULESET" > "$GH_RULESET.tmp" && mv "$GH_RULESET.tmp" "$GH_RULESET"
    emit "$(cat "$GH_RULESET")" ;;
  "GET "*/rulesets/*)
    ruleset="$(cat "$GH_RULESET")"
    if [ -n "${W_APPROVALS:-}" ]; then
      ruleset="$(jq --argjson n "$W_APPROVALS" \
        '(.rules[] | select(.type == "pull_request") | .parameters.required_approving_review_count) = $n' \
        <<< "$ruleset")"
    fi
    emit "$ruleset" ;;
  # ── the test-suite repository (#4372) ──
  "GET repos/artifact-keeper/artifact-keeper-test")
    emit "$(jq -nc --argjson p "${W_TESTS_PUSH:-true}" '{permissions:{push:$p}}')" ;;
  "GET repos/artifact-keeper/artifact-keeper-test/branches/"*)
    # Like the real gh: a 404 still prints the error body to stdout.
    [ -s "$GH_TESTS_REF" ] || { printf '%s' '{"message":"Branch not found","status":"404"}'; echo "gh: Branch not found (HTTP 404)" >&2; exit 1; }
    emit "$(jq -nc --arg s "$(cat "$GH_TESTS_REF")" '{commit:{sha:$s}}')" ;;
  "GET repos/artifact-keeper/artifact-keeper-test/compare/"*)
    emit "$(jq -nc --arg s "${W_TESTS_COMPARE:-behind}" '{status:$s}')" ;;
  "POST repos/artifact-keeper/artifact-keeper-test/git/refs")
    [ -z "${W_TESTS_CREATE_FAIL:-}" ] || { echo "gh: Reference update failed (HTTP 422)" >&2; exit 1; }
    printf '%s' "$f_sha" > "$GH_TESTS_REF"
    emit '{}' ;;
  "GET repos/artifact-keeper/artifact-keeper/actions/runs/"*)
    emit "$(jq -nc --arg n "${W_RUN_NAME:-Release Candidate}" --arg c "${W_RUN_CONCLUSION:-success}" --arg s "$TESTS_GATE_SHA" \
      '{name:$n, conclusion:$c, referenced_workflows:[{path:"artifact-keeper/artifact-keeper-test/.github/workflows/release-gate.yml@main", ref:"refs/heads/main", sha:$s}]}')" ;;
  "POST "*/git/refs)
    [ -z "${W_CREATE_FAIL:-}" ] || { echo "gh: Reference update failed (HTTP 422)" >&2; exit 1; }
    git --git-dir="$GH_ORIGIN" update-ref "$GH_REF" "$GH_SHA"
    emit "$(jq -nc --arg r "$GH_REF" '{ref:$r}')" ;;
  "GET "*/rules/branches/*)
    emit '[{"type":"pull_request"},{"type":"required_status_checks"},{"type":"non_fast_forward"},{"type":"deletion"}]' ;;
  "GET repos/"*) emit "$(jq -nc --argjson a "${W_ADMIN:-true}" '{permissions:{admin:$a}}')" ;;
  *) echo "stub gh: unhandled '${method} ${path}'" >&2; exit 64 ;;
esac
STUBGH
chmod +x "$STUB/gh"

# The ref the stub is allowed to create, and at which sha. Passed in rather
# than parsed out of the POST so a case cannot pass by creating the wrong ref.
export GH_ORIGIN="$ORIGIN" GH_REF="refs/heads/release/1.9.x" GH_SHA="$SHA_190"

# The test-suite repository's release/1.9.x lives in one file: empty means the
# branch does not exist. TESTS_GATE_SHA is what the certifying candidate run
# records as its release-gate.yml commit; TESTS_OTHER is a sha given directly.
export GH_TESTS_REF="$WORK/tests-ref"
export TESTS_GATE_SHA="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
TESTS_OTHER="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
: > "$GH_TESTS_REF"

RULESET_JSON="$WORK/ruleset.json"
jq -nc '{id:20038606,name:"Release branch protection",enforcement:"active",
         conditions:{ref_name:{include:["refs/heads/release/[0-9]*.[0-9]*.x"],exclude:[]}},
         rules:[
           {type:"pull_request",parameters:{
             required_approving_review_count:1,
             dismiss_stale_reviews_on_push:true,
             require_last_push_approval:true,
             require_code_owner_review:false,
             required_review_thread_resolution:false,
             dismissal_restriction:{enabled:false,allowed_actors:[]},
             required_reviewers:[],
             allowed_merge_methods:["merge","squash","rebase"]}},
           {type:"required_status_checks"},{type:"non_fast_forward"},{type:"deletion"}],
         bypass_actors:[],updated_at:"2026-09-20T00:43:13.203Z"}' > "$RULESET_JSON"

# <label> <expected-exit> <expected-substring> [args...]; the log is left in
# $LOG for the caller to inspect.
LOG=""
run_case() {
  local label="$1" want="$2" needle="$3" got=0 out
  shift 3
  LOG="$WORK/log.$$"
  : > "$LOG"
  cp "$RULESET_JSON" "$WORK/live.json"
  rm -f "$REPO"/release-line-*.json
  out="$(cd "$REPO" && PATH="$STUB:$PATH" GH_LOG="$LOG" GH_RULESET="$WORK/live.json" \
    RELEASE_LINE_REPO=artifact-keeper/artifact-keeper RELEASE_LINE_RULESET=20038606 \
    RELEASE_LINE_TESTS_REPO=artifact-keeper/artifact-keeper-test \
    bash "$SCRIPT" "$@" 2>&1)" || got=$?
  if [ "$got" != "$want" ]; then
    fail "$label: expected exit $want, got $got"
    printf '%s\n' "$out" | sed 's/^/        /' >&2
    return 1
  fi
  if [ -n "$needle" ] && ! printf '%s\n' "$out" | grep -qF -- "$needle"; then
    fail "$label: exit $got correct but output lacks '$needle'"
    printf '%s\n' "$out" | sed 's/^/        /' >&2
    return 1
  fi
  pass "$label (exit $got)"
  return 0
}

echo "create-release-line (#3798)"

# ── the branch name is not a free choice ────────────────────────────────────
# `release/1.9.1` and `release/1.9.x-hotfix` fall OUTSIDE the ruleset's
# narrowed include pattern, so creating one would produce an unprotected
# branch that still reads as a release line.
run_case "three-component <X.Y> -> refused" 1 "must be exactly two numbers" 1.9.1
run_case "non-numeric <X.Y> -> refused" 1 "must be exactly two numbers" 1.x
run_case "no arguments -> usage" 1 "usage:" 

# ── the root commit must be one main actually has ───────────────────────────
run_case "sha not reachable from origin/main -> refused" 1 "not reachable from origin/main" 1.9 "$SHA_SIDE"
run_case "abbreviated sha -> refused" 1 "full 40-character commit sha" 1.9 "${SHA_190:0:12}"

# ── ...carrying this line's version ─────────────────────────────────────────
run_case "Cargo.toml version on another line -> refused" 1 "is not on the 1.9 line" 1.9 "$SHA_110"

# ── no default commit when the tag is absent ────────────────────────────────
run_case "no v1.11.0 tag and no explicit sha -> refused" 1 "there is no tag v1.11.0" 1.11

# ── not an admin ────────────────────────────────────────────────────────────
W_ADMIN=false run_case "not a repo admin -> refused" 1 "must be authenticated as an admin" 1.9

# ── every refusal above must have happened before anything was relaxed ──────
if [ -s "$LOG" ] && grep -qE '^(PUT|POST) ' "$LOG"; then
  fail "a refusal issued a mutating call"
  sed 's/^/        /' "$LOG" >&2
else
  pass "refusals issue no PUT/POST"
fi

# ── the matching test-suite branch (#4372): refused before anything moves ──
refusal_no_mutation() { # <label> <needle> [args...]
  local label="$1" needle="$2"
  shift 2
  if run_case "$label" 1 "$needle" "$@"; then
    if grep -qE '^(PUT|POST) ' "$LOG"; then
      fail "$label: issued a mutating call"
      sed 's/^/        /' "$LOG" >&2
    fi
  fi
}
refusal_no_mutation "no tests ref and no tests branch -> refused" "has no release/1.9.x" 1.9
refusal_no_mutation "both --tests-* options -> refused" "not both" \
  --tests-from-run 42 --tests-sha "$TESTS_OTHER" 1.9
refusal_no_mutation "non-numeric run id -> refused" "numeric run id" --tests-from-run abc 1.9
W_RUN_CONCLUSION=failure refusal_no_mutation "a failed candidate run -> refused" "certified nothing" \
  --tests-from-run 42 1.9
W_RUN_NAME="Release Preflight" refusal_no_mutation "a run that is not a candidate -> refused" \
  "is not a Release Candidate run" --tests-from-run 42 1.9
refusal_no_mutation "abbreviated tests sha -> refused" "not a full 40-character sha" \
  --tests-sha "${TESTS_OTHER:0:12}" 1.9
W_TESTS_COMPARE=diverged refusal_no_mutation "tests sha not on the suite's main -> refused" \
  "is not on artifact-keeper/artifact-keeper-test main" --tests-sha "$TESTS_OTHER" 1.9
W_TESTS_PUSH=false refusal_no_mutation "no push access to the suite repo -> refused" \
  "must be able to push to" --tests-sha "$TESTS_OTHER" 1.9

# ── #6216: do not relax a ruleset that does not require a second person ─────
W_APPROVALS=0 refusal_no_mutation "zero required approvals -> refused" \
  "requires 0 approving review(s)" --tests-from-run 42 1.9

# ── --dry-run changes nothing ───────────────────────────────────────────────
if run_case "--dry-run -> plan only" 0 "every precondition passed" --dry-run --tests-from-run 42 1.9; then
  if grep -qE '^(PUT|POST) ' "$LOG"; then
    fail "--dry-run issued a mutating call"
    sed 's/^/        /' "$LOG" >&2
  elif [ -n "$(ls "$REPO"/release-line-*.json 2> /dev/null)" ]; then
    fail "--dry-run wrote a ruleset snapshot"
  elif git --git-dir="$ORIGIN" rev-parse --verify --quiet refs/heads/release/1.9.x > /dev/null; then
    fail "--dry-run created the ref"
  elif [ -s "$GH_TESTS_REF" ]; then
    fail "--dry-run created the test-suite branch"
  else
    pass "--dry-run issued no PUT/POST, wrote no snapshot, created no ref"
  fi
fi

# ── a FAILED ref creation still restores enforcement ────────────────────────
# The whole point of the EXIT trap. Without it the ruleset stays in `evaluate`
# and `release/*` protection is off with nobody looking.
if W_CREATE_FAIL=1 run_case "ref creation fails -> non-zero" 1 "" --tests-from-run 42 1.9; then
  if [ "$(jq -r '.enforcement' "$WORK/live.json")" = "active" ] \
    && [ "$(grep -c '^PUT ' "$LOG")" = "2" ]; then
    pass "ref creation failure restores enforcement=active"
  else
    fail "ref creation failure left enforcement='$(jq -r '.enforcement' "$WORK/live.json")'"
    sed 's/^/        /' "$LOG" >&2
  fi
fi

# ...and a restore that ITSELF fails must be shouted about, not logged.
W_CREATE_FAIL=1 W_RESTORE_FAIL=1 \
  run_case "restore itself fails -> CRITICAL" 1 "STILL in 'evaluate'" --tests-from-run 42 1.9
if [ -s "$GH_TESTS_REF" ]; then
  fail "a failed backend ref creation still created the test-suite branch"
fi

# ── happy path, so the gate above is not vacuous ────────────────────────────
git --git-dir="$ORIGIN" update-ref -d refs/heads/release/1.9.x 2> /dev/null || true
if run_case "creates the line and prints the audit summary" 0 "audit summary" --tests-from-run 42 1.9; then
  if [ "$(git --git-dir="$ORIGIN" rev-parse refs/heads/release/1.9.x)" = "$SHA_190" ] \
    && [ "$(jq -r '.enforcement' "$WORK/live.json")" = "active" ]; then
    pass "the ref points at the v1.9.0 commit and enforcement is active again"
  else
    fail "happy path left the wrong ref or enforcement"
  fi
  if [ "$(cat "$GH_TESTS_REF")" = "$TESTS_GATE_SHA" ]; then
    pass "the test-suite branch is at the certifying run's release-gate commit"
  else
    fail "the test-suite branch is at '$(cat "$GH_TESTS_REF")', not the run's gate commit"
  fi
fi

# ── and then refuses to do it twice ─────────────────────────────────────────
run_case "the line already exists -> refused" 1 "already exists" 1.9

# ── an existing line + a tests ref: only the test branch, no toggle ─────────
: > "$GH_TESTS_REF"
if run_case "existing line, missing test branch -> test branch only" 0 "ruleset was not touched" \
  --tests-sha "$TESTS_OTHER" 1.9; then
  if grep -qE '^PUT ' "$LOG"; then
    fail "the test-branch-only path toggled the ruleset"
  elif [ "$(cat "$GH_TESTS_REF")" != "$TESTS_OTHER" ]; then
    fail "the test-suite branch is at '$(cat "$GH_TESTS_REF")', not ${TESTS_OTHER}"
  else
    pass "test-branch-only path created it at the given sha with no ruleset PUT"
  fi
fi

# ── ...and is idempotent: an existing test branch is left where it is ───────
if run_case "existing test branch -> left as is" 0 "left as is" --tests-from-run 42 1.9; then
  if grep -qE '^(PUT|POST) ' "$LOG"; then
    fail "an existing test branch drew a mutating call"
  elif [ "$(cat "$GH_TESTS_REF")" != "$TESTS_OTHER" ]; then
    fail "an existing test branch was moved"
  else
    pass "an existing test branch is not moved and nothing is written"
  fi
fi
git --git-dir="$ORIGIN" update-ref -d refs/heads/release/1.9.x 2> /dev/null || true
: > "$GH_TESTS_REF"

# ── a failed test-branch creation after the line exists: loud, retryable ───
if W_TESTS_CREATE_FAIL=1 run_case "test branch creation fails -> non-zero, says how to retry" 1 \
  "Re-run this script with the same arguments" --tests-from-run 42 1.9; then
  if [ "$(jq -r '.enforcement' "$WORK/live.json")" != "active" ]; then
    fail "test branch failure left enforcement='$(jq -r '.enforcement' "$WORK/live.json")'"
  fi
fi
git --git-dir="$ORIGIN" update-ref -d refs/heads/release/1.9.x 2> /dev/null || true

echo
if [ "$fails" -gt 0 ]; then
  echo "$fails case(s) failed"
  exit 1
fi
echo "all cases passed"
