#!/usr/bin/env bash
#
# Self-test for scripts/ci/check-e2e-proof.py (the end-to-end proof policy for
# bug fixes: require-e2e-proof.yml and release-preflight.sh check 7).
#
# WHY THIS EXISTS
#   The check is silent on every PR that is not a bug fix, and on most bug
#   fixes it either passes or nags. The dangerous direction is fail-open: a
#   proof line hidden in an HTML comment, a test PR that never went red, a
#   test PR against the wrong release line, or an exemption with no reason
#   must not read as a proof. Each of those is a case below that has to FAIL.
#   The release backstop is the same species: an issue whose tier exists but
#   is not wired into the gate, or that was deferred with needs-e2e-test, has
#   no proof the gate enforces.
#
# HOW
#   The script reaches GitHub only through `gh api`. A stub `gh` first on PATH
#   answers from a JSON "world" file per case ({"GET": {endpoint: answer},
#   "graphql": answer}); an endpoint the world does not list is a 404, the
#   value "__FAIL__" is a 502, and {"__text__": "..."} is served the way the
#   contents API serves a file. Writes (the deferred label copy) are appended
#   to a log the cases read back. Offline, ~2s.
#
# Usage: bash scripts/ci/test-check-e2e-proof.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/check-e2e-proof.py"
LEDGER="$HERE/e2e-exemptions.tsv"
[ -f "$SCRIPT" ] || { echo "cannot find check-e2e-proof.py next to this test" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

STUB="$WORK/bin"; mkdir -p "$STUB"
cat > "$STUB/gh" <<'STUBGH'
#!/usr/bin/env python3
import base64, json, os, re, sys
args = sys.argv[1:]
world = json.load(open(os.environ["GH_WORLD"]))
if args[:2] == ["api", "graphql"]:
    ans = world.get("graphql")
    if ans is None or ans == "__FAIL__":
        sys.stderr.write("gh: HTTP 502\n"); sys.exit(1)
    print(json.dumps(ans)); sys.exit(0)
method, endpoint, i = "GET", None, 1
while i < len(args):
    a = args[i]
    if a in ("-X", "--method"): method = args[i + 1]; i += 2; continue
    if a in ("-H", "--input", "-f", "-F"): i += 2; continue
    endpoint = a; i += 1
if method != "GET":
    with open(os.environ["GH_WRITES"], "a") as fh:
        fh.write(f"{method} {endpoint} {sys.stdin.read()}\n")
    print("{}"); sys.exit(0)
page = re.search(r"[?&]page=(\d+)", endpoint)
if page and page.group(1) != "1":
    print("[]"); sys.exit(0)
key = re.sub(r"[?&](per_page|page)=\d+", "", endpoint)
key = key.replace("&", "?", 1) if "?" not in key else key
ans = world.get("GET", {}).get(key)
if ans is None:
    sys.stderr.write("gh: Not Found (HTTP 404)\n"); sys.exit(1)
if ans == "__FAIL__":
    sys.stderr.write("gh: Server Error (HTTP 502)\n"); sys.exit(1)
if isinstance(ans, dict) and "__text__" in ans:
    ans = {"content": base64.b64encode(ans["__text__"].encode()).decode()}
print(json.dumps(ans))
STUBGH
chmod +x "$STUB/gh"

export R=artifact-keeper/artifact-keeper
export T=artifact-keeper/artifact-keeper-test

# --- shared fixtures ---------------------------------------------------------
# Issue 100 is a bug, 101 a feature. Test PR 7 is the good proof for #100.
VALID_BODY='Adds tier range-serves-1120 (artifact-keeper#100).

## Validation

- `ak-backend:1.11.13`: **RED**, 2 passed, 3 failed. FIX #100 fails.
- `ak-backend:main`: **GREEN**, 5 of 5.

Not yet wired into run.sh all, the release-gate matrix or matrix.md.'
jq -n --arg vb "$VALID_BODY" '{
  GET: {
    ("repos/\(env.R)/issues/100"): {number: 100, labels: [{name: "type:bug"}]},
    ("repos/\(env.R)/issues/101"): {number: 101, labels: [{name: "type:feature"}]},
    ("repos/\(env.R)/issues/102"): {number: 102, labels: [{name: "type:bug"}, {name: "needs-e2e-test"}]},
    ("repos/\(env.R)/issues/103"): {number: 103, labels: [{name: "type:bug"}, {name: "ci"}]},
    ("repos/\(env.R)/pulls/1/files"): [{filename: "backend/src/api/handlers/range.rs"}],
    ("repos/\(env.R)/pulls/1/commits"): [],
    ("repos/\(env.T)/pulls/7"): {number: 7, state: "open", merged: false, base: {ref: "main"},
                              title: "test(dtf): range-serves-1120: ranges (artifact-keeper#100)", body: $vb},
    ("repos/\(env.T)/pulls/7/files"): [{filename: "deploy-test/harness/tiers/range-serves-1120/oracle.sh"}],
    ("repos/\(env.T)/contents/deploy-test/harness/tiers/range-serves-1120/manifest?ref=main"):
        {__text__: "PROFILES=\"storage.filesystem\"\nORACLE=\"oracle.sh\"\nCOVERS=\"100 99\"\n"},
    ("repos/\(env.T)/contents/deploy-test/harness/tiers/range-serves-1120/oracle.sh?ref=main"):
        {__text__: "begin_test \"FIX #100: a range is served\"\n"},
    ("repos/\(env.T)/contents/deploy-test/harness/tiers/smoke/manifest?ref=main"):
        {__text__: "PROFILES=\"storage.filesystem\"\nORACLE=\"oracle.sh\"\n"},
    ("repos/\(env.T)/contents/tests/formats/test-range.sh?ref=main"):
        {__text__: "# regression for artifact-keeper #100\n"}
  }
}' > "$WORK/base.json"

# <event overrides (jq)> <world overrides (jq)> -> writes $WORK/event.json, $WORK/world.json
setup() {
  jq -n '{pull_request: {number: 1, title: "fix(range): serve ranges (#100)", body: "Closes #100",
           labels: [], base: {ref: "main"}, head: {ref: "fix/100-range"}}}' \
    | jq "$1" > "$WORK/event.json"
  jq "$2" "$WORK/base.json" > "$WORK/world.json"
  : > "$WORK/writes.log"
}

run_pr() {
  ( PATH="$STUB:$PATH" GH_WORLD="$WORK/world.json" GH_WRITES="$WORK/writes.log" \
      python3 "$SCRIPT" pr --event "$WORK/event.json" --repo "$R" "$@" >"$WORK/out.txt" 2>&1 )
  echo $?
}

# <label> <expected-exit> <expected-substring> <event-jq> <world-jq> [extra args]
expect_pr() {
  local label="$1" want="$2" needle="$3" got
  setup "$4" "$5"; shift 5
  got="$(run_pr "$@")"
  if [ "$got" != "$want" ]; then
    fail "$label: expected exit $want, got $got"; sed 's/^/        /' "$WORK/out.txt" >&2
  elif ! grep -qF -- "$needle" "$WORK/out.txt"; then
    fail "$label: exit $got correct but output lacks '$needle'"; sed 's/^/        /' "$WORK/out.txt" >&2
  else
    pass "$label (exit $got)"
  fi
}
body() { printf '.pull_request.body = %s' "$(jq -Rn --arg b "$1" '$b')"; }

echo "check-e2e-proof.py pr: which PRs need a proof"
expect_pr "feature PR -> no proof needed" 0 "not a bug PR" \
  '.pull_request.title = "feat(x): y" | .pull_request.body = "Closes #101" | .pull_request.head.ref = "feat/x"' '.'
expect_pr "fix title alone makes a bug PR" 1 "missing end-to-end proof" \
  '.pull_request.body = "Closes #101" | .pull_request.head.ref = "feat/x"' '.'
expect_pr "fix/* branch alone makes a bug PR" 1 "missing end-to-end proof" \
  '.pull_request.title = "refactor: z (#101)" | .pull_request.body = "Closes #101"' '.'
expect_pr "type:bug issue alone makes a bug PR" 1 "missing end-to-end proof" \
  '.pull_request.title = "refactor: z" | .pull_request.head.ref = "x"' '.'
expect_pr "bug PR, title type chore -> automatic exemption" 0 "title type 'chore' is exempt" \
  '.pull_request.title = "chore(deps): bump x (#100)"' '.'
expect_pr "bug PR, diff only in docs and scripts -> automatic exemption" 0 "the diff touches only" \
  '.' '.GET["repos/\(env.R)/pulls/1/files"] = [{filename: "docs/a.md"}, {filename: "scripts/ci/x.sh"}, {filename: "Cargo.lock"}]'
expect_pr "bug PR, diff in backend and docs -> not exempt" 1 "missing end-to-end proof" \
  '.' '.GET["repos/\(env.R)/pulls/1/files"] = [{filename: "docs/a.md"}, {filename: "backend/src/x.rs"}]'

echo
echo "check-e2e-proof.py pr: test-PR proofs"
expect_pr "valid test PR -> PASS" 0 "proves #100" "$(body $'Closes #100\n\nE2E: artifact-keeper-test#7')" '.'
expect_pr "owner-qualified test PR reference -> PASS" 0 "proves #100" "$(body $'Closes #100\n- E2E: artifact-keeper/artifact-keeper-test#7')" '.'
expect_pr "proof line inside an HTML comment does not count" 1 "missing end-to-end proof" \
  "$(body $'Closes #100\n<!--\nE2E: artifact-keeper-test#7\n-->')" '.'
expect_pr "proof line inside a code block does not count" 1 "missing end-to-end proof" \
  "$(body $'Closes #100\n```\nE2E: artifact-keeper-test#7\n```')" '.'
expect_pr "test PR closed without merging -> FAIL" 1 "closed without merging" \
  "$(body $'Closes #100\nE2E: artifact-keeper-test#7')" '.GET["repos/\(env.T)/pulls/7"].state = "closed"'
expect_pr "merged test PR -> PASS" 0 "merged" \
  "$(body $'Closes #100\nE2E: artifact-keeper-test#7')" '.GET["repos/\(env.T)/pulls/7"] |= (.state = "closed" | .merged = true)'
expect_pr "test PR that does not exist -> FAIL" 1 "is not a pull request" \
  "$(body $'Closes #100\nE2E: artifact-keeper-test#8')" '.'
expect_pr "test PR touching neither tiers nor tests -> FAIL" 1 "touches neither" \
  "$(body $'Closes #100\nE2E: artifact-keeper-test#7')" '.GET["repos/\(env.T)/pulls/7/files"] = [{filename: "README.md"}]'
expect_pr "test PR that names another issue -> FAIL" 1 "does not name artifact-keeper#100" \
  "$(body $'Closes #100\nE2E: artifact-keeper-test#7')" \
  '.GET["repos/\(env.T)/pulls/7"] |= (.title = "test(dtf): x (#100)" | .body = (.body | sub("artifact-keeper#100"; "artifact-keeper#999")))'
expect_pr "title convention (artifact-keeper#99, #100) names #100" 0 "proves #100" \
  "$(body $'Closes #100\nE2E: artifact-keeper-test#7')" \
  '.GET["repos/\(env.T)/pulls/7"] |= (.title = "test(dtf): x (artifact-keeper#99, #100)" | .body = (.body | sub("artifact-keeper#100"; "")))'
expect_pr "test PR without a Validation section -> FAIL" 1 "no \`## Validation\` section" \
  "$(body $'Closes #100\nE2E: artifact-keeper-test#7')" '.GET["repos/\(env.T)/pulls/7"].body = "artifact-keeper#100, trust me"'
expect_pr "Validation without a RED line (never shown failing) -> FAIL" 1 "no RED line" \
  "$(body $'Closes #100\nE2E: artifact-keeper-test#7')" '.GET["repos/\(env.T)/pulls/7"].body |= sub("\\*\\*RED\\*\\*"; "red-ish")'
expect_pr "Validation without a GREEN line -> FAIL" 1 "no GREEN line" \
  "$(body $'Closes #100\nE2E: artifact-keeper-test#7')" '.GET["repos/\(env.T)/pulls/7"].body |= sub("\\*\\*GREEN\\*\\*"; "fine")'
expect_pr "RED/GREEN outside the Validation section do not count" 1 "no \`## Validation\` section" \
  "$(body $'Closes #100\nE2E: artifact-keeper-test#7')" '.GET["repos/\(env.T)/pulls/7"].body |= sub("## Validation"; "Validation:")'
expect_pr "release-line PR citing a main test PR -> FAIL" 1 "must target the same-named branch" \
  "$(body $'Closes #100\nE2E: artifact-keeper-test#7') | .pull_request.base.ref = \"release/1.11.x\"" '.'
expect_pr "release-line PR citing a release-line test PR -> PASS" 0 "proves #100" \
  "$(body $'Closes #100\nE2E: artifact-keeper-test#7') | .pull_request.base.ref = \"release/1.11.x\"" \
  '.GET["repos/\(env.T)/pulls/7"].base.ref = "release/1.11.x"'
expect_pr "two bug issues, the test PR names one -> FAIL" 1 "no declared proof covers #103" \
  "$(body $'Closes #100\nCloses #103\nE2E: artifact-keeper-test#7')" '.'
expect_pr "unrecognised proof line -> FAIL" 1 "unrecognised proof line" \
  "$(body $'Closes #100\nE2E: I ran it by hand')" '.'

echo
echo "check-e2e-proof.py pr: tier and suite proofs"
expect_pr "existing tier that COVERS the issue -> PASS" 0 "tier 'range-serves-1120' on main covers #100" \
  "$(body $'Closes #100\nE2E: tier range-serves-1120')" '.'
expect_pr "existing tier that does not cover it -> FAIL" 1 "neither COVERS nor has" \
  "$(body $'Closes #100\nE2E: tier smoke')" '.'
expect_pr "tier that does not exist -> FAIL" 1 "does not exist" \
  "$(body $'Closes #100\nE2E: tier nope')" '.'
expect_pr "tier read from the release line's branch" 1 "does not exist on artifact-keeper/artifact-keeper-test@release/1.11.x" \
  "$(body $'Closes #100\nE2E: tier range-serves-1120') | .pull_request.base.ref = \"release/1.11.x\"" '.'
expect_pr "suite that names the issue -> PASS" 0 "suite tests/formats/test-range.sh on main names #100" \
  "$(body $'Closes #100\nE2E: suite tests/formats/test-range.sh')" '.'
expect_pr "suite that does not exist -> FAIL" 1 "does not exist" \
  "$(body $'Closes #100\nE2E: suite tests/formats/test-none.sh')" '.'

echo
echo "check-e2e-proof.py pr: exemptions, flakes, deferral"
expect_pr "E2E-Exempt with the label -> PASS" 0 "exempt (deps)" \
  "$(body $'Closes #100\nE2E-Exempt: deps: bumps libz-sys for RUSTSEC-2026-0418') | .pull_request.labels = [{name: \"no-e2e-required\"}]" '.'
expect_pr "E2E-Exempt without the label -> FAIL" 1 "also needs the label no-e2e-required" \
  "$(body $'Closes #100\nE2E-Exempt: deps: bumps libz-sys for RUSTSEC-2026-0418')" '.'
expect_pr "unknown exemption category -> FAIL" 1 "unknown exemption category 'hard'" \
  "$(body $'Closes #100\nE2E-Exempt: hard: too hard to test end to end') | .pull_request.labels = [{name: \"no-e2e-required\"}]" '.'
expect_pr "exemption with no reason -> FAIL" 1 "needs a reason" \
  "$(body $'Closes #100\nE2E-Exempt: docs: ok') | .pull_request.labels = [{name: \"no-e2e-required\"}]" '.'
expect_pr "race-window that names no test -> FAIL" 1 "must name the barrier/failpoint/stress test" \
  "$(body $'Closes #100\nE2E-Exempt: race-window: the window is a few microseconds wide') | .pull_request.labels = [{name: \"no-e2e-required\"}]" '.'
expect_pr "race-window naming its test -> PASS" 0 "exempt (race-window)" \
  "$(body $'Closes #100\nE2E-Exempt: race-window: forced by upload_against_a_fresh_gc_lease_is_refused_retryably_4980') | .pull_request.labels = [{name: \"no-e2e-required\"}]" '.'
expect_pr "internal-unreachable naming no test -> FAIL" 1 "must name the unit/integration test" \
  "$(body $'Closes #100\nE2E-Exempt: internal-unreachable: no client can reach this code') | .pull_request.labels = [{name: \"no-e2e-required\"}]" '.'
expect_pr "embargoed with a GHSA id -> PASS" 0 "exempt (embargoed)" \
  "$(body $'Closes #100\nE2E-Exempt: embargoed: GHSA-2x3c-4v5f-6g7h: harmless facet only until disclosure') | .pull_request.labels = [{name: \"no-e2e-required\"}]" '.'
expect_pr "embargoed without a GHSA id -> FAIL" 1 "embargoed needs" \
  "$(body $'Closes #100\nE2E-Exempt: embargoed: secret, trust me on this one') | .pull_request.labels = [{name: \"no-e2e-required\"}]" '.'
expect_pr "Flake-Proof with the ci label on the issue -> PASS" 0 "flake fix" \
  "$(body $'Closes #103\nFlake-Proof: reproduced with stress-ng --cpu 24; 200 consecutive passes under --test-threads 32')" '.'
expect_pr "Flake-Proof without a ci/testing label -> FAIL" 1 "needs the ci or testing label" \
  "$(body $'Closes #100\nFlake-Proof: reproduced with stress-ng --cpu 24; 200 consecutive passes under --test-threads 32')" '.'
expect_pr "Flake-Proof without the pass count -> FAIL" 1 "Flake-Proof must read" \
  "$(body $'Closes #103\nFlake-Proof: it does not flake any more')" '.'
expect_pr "needs-e2e-test, no line -> deferred PASS" 0 "deferred (needs-e2e-test)" \
  '.pull_request.labels = [{name: "needs-e2e-test"}]' '.'
if grep -qF "POST repos/$R/issues/100/labels" "$WORK/writes.log" && grep -qF '"needs-e2e-test"' "$WORK/writes.log"; then
  pass "deferral copies needs-e2e-test to the issue"
else
  fail "deferral did not copy the label: $(cat "$WORK/writes.log")"
fi
expect_pr "deferral with --no-write writes nothing" 0 "would copy needs-e2e-test to #100" \
  '.pull_request.labels = [{name: "needs-e2e-test"}]' '.' --no-write
if [ -s "$WORK/writes.log" ]; then fail "--no-write still wrote: $(cat "$WORK/writes.log")"; else pass "--no-write left the issue alone"; fi
expect_pr "deferral when the issue already has the label" 0 "#102 already carries needs-e2e-test" \
  '.pull_request.labels = [{name: "needs-e2e-test"}] | .pull_request.body = "Closes #102"' '.'

echo
echo "check-e2e-proof.py pr: release-line inheritance and infra"
inherit_world() {
  printf '%s' '.GET["repos/'"$R"'/pulls/1/commits"] = [{commit: {message: "fix: y\n\n(cherry picked from commit abcdef1234567)"}}]
   | .GET["repos/'"$R"'/commits/abcdef1234567/pulls"] = [{number: 50, title: "fix(x): y (#100)", base: {ref: "main"}, labels: [{name: "no-e2e-required"}], body: "'"$1"'"}]
   | .GET["repos/'"$R"'/pulls/50/files"] = [{filename: "backend/src/x.rs"}]'
}
expect_pr "backport inherits the original PR's exemption" 0 "inherited from #50" \
  '.pull_request.base.ref = "release/1.11.x"' "$(inherit_world 'Closes #100\nE2E-Exempt: build-ci: compile fix only, no runtime effect')"
expect_pr "backport of an unexempt PR still needs a proof" 1 "missing end-to-end proof" \
  '.pull_request.base.ref = "release/1.11.x"' "$(inherit_world 'Closes #100')"
expect_pr "the trailer is not honoured on main" 1 "missing end-to-end proof" \
  '.' "$(inherit_world 'Closes #100\nE2E-Exempt: build-ci: compile fix only, no runtime effect')"
expect_pr "API failure is INFRA, not a verdict" 2 "INFRA" \
  "$(body $'Closes #100\nE2E: artifact-keeper-test#7')" '.GET["repos/\(env.T)/pulls/7"] = "__FAIL__"'

# --- milestone ----------------------------------------------------------------
echo
echo "check-e2e-proof.py milestone: the release backstop"
TESTS="$WORK/tests"
mkdir -p "$TESTS/deploy-test/harness/tiers/"{wired,unwired,advisory} "$TESTS/.github/workflows" "$TESTS/tests/formats"
printf 'PROFILES="x"\nORACLE="oracle.sh"\nCOVERS="200"\n' > "$TESTS/deploy-test/harness/tiers/wired/manifest"
printf 'begin_test "FIX #200: works"\n' > "$TESTS/deploy-test/harness/tiers/wired/oracle.sh"
printf 'PROFILES="x"\nORACLE="oracle.sh"\nCOVERS="201"\n' > "$TESTS/deploy-test/harness/tiers/unwired/manifest"
printf 'begin_test "FIX #201: works"\n' > "$TESTS/deploy-test/harness/tiers/unwired/oracle.sh"
printf 'PROFILES="x"\nORACLE="oracle.sh"\nCOVERS="206"\n' > "$TESTS/deploy-test/harness/tiers/advisory/manifest"
printf 'begin_test "FIX #206: works"\n' > "$TESTS/deploy-test/harness/tiers/advisory/oracle.sh"
printf '# covers artifact-keeper #205\n' > "$TESTS/tests/formats/test-x.sh"
cat > "$TESTS/.github/workflows/release-gate.yml" <<'YML'
jobs:
  format-tests:
    strategy:
      matrix:
        include:
          - group: decoy
            tiers: unwired
  dtf-gate:
    strategy:
      matrix:
        include:
          - group: core
            tiers: smoke wired
  dtf-advisory:
    strategy:
      matrix:
        include:
          - group: timing
            tiers: advisory
YML
printf '# header\n4814\ttest-only\tFlaky unit test; the fix changes only the test.\n' > "$WORK/ledger.tsv"

# issue <n> <labels-json> <closing PRs json> [stateReason]
issue() { printf '{"number":%s,"title":"bug %s","stateReason":"%s","labels":{"nodes":%s},"closedByPullRequestsReferences":{"nodes":%s}}' \
  "$1" "$1" "${4:-COMPLETED}" "$2" "$3"; }
cpr() { # <n> <title> <body> <labels-json>
  jq -cn --argjson n "$1" --arg t "$2" --arg b "$3" --argjson l "$4" \
    '{number: $n, title: $t, body: $b, merged: true, headRefName: "fix/x", baseRefName: "main", labels: {nodes: $l}}'; }
BUG='[{"name":"type:bug"}]'
ms_world() { # <issue nodes, comma separated> [extra jq]
  jq -n --argjson nodes "[$1]" '{
    GET: {("repos/\(env.R)/milestones?state=all"): [{number: 52, title: "1.12.0"}],
          ("repos/\(env.R)/pulls/300/files"): [{filename: "backend/src/x.rs"}],
          ("repos/\(env.R)/pulls/301/files"): [{filename: "docs/x.md"}]},
    graphql: {data: {repository: {milestone: {issues: {pageInfo: {hasNextPage: false, endCursor: null}, nodes: $nodes}}}}}
  }' | jq "${2:-.}" > "$WORK/world.json"
}
run_ms() {
  ( PATH="$STUB:$PATH" GH_WORLD="$WORK/world.json" GH_WRITES="$WORK/writes.log" \
      python3 "$SCRIPT" milestone --milestone "${MS:-1.12.0}" --tests-dir "$TESTS" --repo "$R" \
      --exemptions "${LEDGER_FILE:-$WORK/ledger.tsv}" >"$WORK/out.txt" 2>&1 )
  echo $?
}
expect_ms() { # <label> <want> <needle> <nodes> [extra jq]
  local label="$1" want="$2" needle="$3" got
  ms_world "$4" "${5:-.}"
  got="$(run_ms)"
  if [ "$got" != "$want" ]; then
    fail "$label: expected exit $want, got $got"; sed 's/^/        /' "$WORK/out.txt" >&2
  elif ! grep -qF -- "$needle" "$WORK/out.txt"; then
    fail "$label: exit $got correct but output lacks '$needle'"; sed 's/^/        /' "$WORK/out.txt" >&2
  else
    pass "$label (exit $got)"
  fi
}
P300="$(cpr 300 'fix(x): y' 'Closes' '[]')"
expect_ms "wired tier that COVERS the bug -> READY" 0 "tier wired (dtf-gate)" "$(issue 200 "$BUG" "[$P300]")"
expect_ms "tier in dtf-advisory counts, and says so" 0 "tier advisory (dtf-advisory)" "$(issue 206 "$BUG" "[$P300]")"
expect_ms "tier that COVERS but is not wired -> NOT READY" 1 "UNWIRED" "$(issue 201 "$BUG" "[$P300]")"
expect_ms "no tier, no exemption -> NOT READY" 1 "MISSING" "$(issue 202 "$BUG" "[$P300]")"
expect_ms "deferred with needs-e2e-test -> NOT READY" 1 "DEFERRED" \
  "$(issue 202 '[{"name":"type:bug"},{"name":"needs-e2e-test"}]' "[$P300]")"
expect_ms "ledger row -> READY" 0 "ledger: test-only" "$(issue 4814 "$BUG" "[$P300]")"
expect_ms "closing PR's E2E-Exempt with label -> READY" 0 "#302: deps" \
  "$(issue 203 "$BUG" "[$(cpr 302 'fix(deps): x' 'E2E-Exempt: deps: bump for RUSTSEC-2026-0001' '[{"name":"no-e2e-required"}]')]")"
expect_ms "closing PR's E2E-Exempt without the label -> NOT READY" 1 "MISSING" \
  "$(issue 203 "$BUG" "[$(cpr 300 'fix(deps): x' 'E2E-Exempt: deps: bump for RUSTSEC-2026-0001' '[]')]")"
expect_ms "closing PR whose diff is docs only -> READY" 0 "diff only in" "$(issue 204 "$BUG" "[$(cpr 301 'fix: x' '' '[]')]")"
expect_ms "suite named by the closing PR -> READY" 0 "suite tests/formats/test-x.sh" \
  "$(issue 205 "$BUG" "[$(cpr 300 'fix: x' 'E2E: suite tests/formats/test-x.sh' '[]')]")"
expect_ms "not-planned issues are skipped" 0 "closed as not_planned" "$(issue 207 "$BUG" '[]' NOT_PLANNED)"
expect_ms "mixed: one missing blocks the whole milestone" 1 "NOT READY: 1 closed bug" \
  "$(issue 200 "$BUG" "[$P300]"),$(issue 202 "$BUG" "[$P300]"),$(issue 4814 "$BUG" '[]')"
MS=9.9.9 expect_ms "unknown milestone is INFRA" 2 "does not exist" "$(issue 200 "$BUG" '[]')"
expect_ms "graphql failure is INFRA" 2 "INFRA" "$(issue 200 "$BUG" '[]')" '.graphql = "__FAIL__"'
printf '4980\trace-window\tthe window is a few microseconds wide\n' > "$WORK/bad.tsv"
LEDGER_FILE="$WORK/bad.tsv" expect_ms "ledger race-window row naming no test is refused" 2 "must name its test" "$(issue 200 "$BUG" '[]')"
LEDGER_FILE="$LEDGER" expect_ms "the real ledger parses" 0 "READY" "$(issue 200 "$BUG" "[$P300]")"

echo
if [ "$fails" -gt 0 ]; then
  echo "test-check-e2e-proof: $fails case(s) FAILED"
  exit 1
fi
echo "test-check-e2e-proof: all cases passed"
