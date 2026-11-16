#!/usr/bin/env bash
#
# Self-test for scripts/ci/nightly-gate-report.js (#6073).
#
# The report owns the acceptance criteria: a red tier opens exactly ONE
# issue, a repeat failure updates it, a green night closes it, and the issue
# names the first red commit range. It also writes the record #6075 trusts,
# so a skipped or never-run tier must never read as green, and a narrow or
# self-test run must never write the commit status. Stubs `gh`; offline, ~1s.
#
# Usage: bash scripts/ci/test-nightly-gate-report.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/nightly-gate-report.js"
[ -f "$SCRIPT" ] || { echo "cannot find nightly-gate-report.js next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

echo "pure functions"
if node - "$SCRIPT" <<'NODE'
const r = require(process.argv[2]);
const assert = require('assert');
const eq = assert.deepStrictEqual;
eq(r.tierKey('dtf-gate (storage-1.11.0, quota-native-and-rpm-races s3-copy-lengt...'), 'dtf-gate/storage-1.11.0');
eq(r.tierKey('resilience-tests (crash)'), 'resilience-tests/crash');
eq(r.tierKey('dtf-gate (fixes-1.12.0-replication-delete-restore...'), 'dtf-gate/fixes-1.12.0-replication-delete-restore');
eq(r.tierKey('repo-tests'), 'repo-tests');

const J = (n, c) => ({ name: `Gate [main] / ${n}`, conclusion: c, html_url: `u/${n}` });
let c = r.classifyLine([J('deploy', 'success'), J('repo-tests', 'failure'), J('stress-tests', 'success'),
  J('collect-results', 'failure'), { name: 'Gate [1.11.x] / mesh-tests', conclusion: 'failure' }], 'Gate [main]');
eq([c.verdict, c.red], ['red', ['repo-tests']]);
c = r.classifyLine([J('deploy', 'success'), J('mesh-tests', 'failure'), J('collect-results', 'success')], 'Gate [main]');
eq([c.verdict, c.red], ['green', ['mesh-tests']]);                  // non-blocking red is still tracked
c = r.classifyLine([J('deploy', 'success'), J('collect-results', 'failure')], 'Gate [main]');
eq(c.red, ['collect-results']);                                      // red with no red job: the aggregate is the tier
c = r.classifyLine([J('deploy', 'failure'), J('repo-tests', 'skipped')], 'Gate [main]');
eq([c.verdict, c.red], ['incomplete', ['deploy']]);
eq(r.classifyLine([], 'Gate [main]').verdict, 'missing');
c = r.classifyLine([J('dtf-gate (a, x)', 'success'), J('dtf-gate (a, y...', 'timed_out'), J('collect-results', 'failure')], 'Gate [main]');
eq(c.red, ['dtf-gate/a']);                                           // two jobs, one key: the worst wins

const cur = { sha: 'c'.repeat(40), run_id: 9 };
const rec = (run, sha, concl) => ({ run_id: run, lines: [{ line: 'main', sha, tests_sha: `t${run}`, tiers: concl ? { t: { conclusion: concl } } : {} }] });
let g = r.redRange('main', 't', cur, [rec(8, 'b'.repeat(40), 'failure'), rec(7, 'x', 'skipped'), rec(6, null, null), rec(5, 'a'.repeat(40), 'success'), rec(4, 'z', 'failure')]);
eq([g.firstRed.sha, g.firstRed.run_id, g.lastGreen.sha, g.lastGreen.tests_sha], ['b'.repeat(40), 8, 'a'.repeat(40), 't5']);
g = r.redRange('main', 't', cur, []);
eq([g.firstRed.sha, g.lastGreen], [cur.sha, null]);

const ctx = { repo: 'o/r', server: 'https://g', runId: 9, suite: 'all' };
const line = { line: 'main', branch: 'main', sha: cur.sha, verdict: 'red', red: ['a', 'b'],
  tiers: { a: { conclusion: 'failure' }, b: { conclusion: 'failure' }, c: { conclusion: 'success' }, d: { conclusion: 'skipped' } } };
const issue = (n, key) => ({ number: n, body: `x <!-- nightly-gate-tier: ${key} --> y` });
const open = [issue(1, 'main|a'), issue(2, 'main|c'), issue(3, 'main|d'), issue(4, 'main|gone'), issue(5, '1.11.x|b'), issue(6, 'main|a')];
const range = () => ({ firstRed: cur, lastGreen: { sha: 'a'.repeat(40), run_id: 5 }, walked: 1 });
let acts = r.planIssues(ctx, line, open, range);
eq(acts.map((a) => [a.type, a.number || a.key]), [['comment', 1], ['open', 'main|b'], ['close', 2]]);
assert.match(acts[1].body, /<!-- nightly-gate-tier: main\|b -->/);
assert.match(acts[1].body, /compare\/a{40}\.\.\.c{40}/);
// a complete green full-suite night also closes the issue of a tier that no longer exists
acts = r.planIssues(ctx, { ...line, verdict: 'green', red: [], tiers: { c: { conclusion: 'success' } } }, open, range);
eq(acts.map((a) => [a.type, a.number]).sort(), [['close', 1], ['close', 2], ['close', 3], ['close', 4]]);
// ... but not after a narrow suite, where an absent tier simply did not run
acts = r.planIssues({ ...ctx, suite: 'search' }, { ...line, verdict: 'green', red: [], tiers: {} }, open, range);
eq(acts, []);
NODE
then pass "tier keys, verdicts, red ranges and issue plans"; else fail "pure-function assertions (see the stack above)"; fi

echo "end to end"
STUB="$WORK/bin"; mkdir -p "$STUB"
# FAKE_JOBS / FAKE_ISSUES: JSON lines the --jq of the real call would print.
# FAKE_HISTORY: earlier run ids, newest first; $FAKE_DIR/hist-<id>.json is
# that run's verdict.json (missing = the run has no artifact).
cat > "$STUB/gh" <<'STUBGH'
#!/usr/bin/env bash
echo "gh $*" >> "$FAKE_LOG"
if [ "$1" = run ] && [ "$2" = download ]; then
  id="$3"; dir="${!#}"
  [ -f "$FAKE_DIR/hist-$id.json" ] || exit 1
  cp "$FAKE_DIR/hist-$id.json" "$dir/verdict.json"; exit 0
fi
[ "$1" = api ] || exit 64
shift
[ "$1" = --paginate ] && shift
[ "$1" = -X ] && { echo 1; exit 0; }
case "$1" in
  */actions/runs/*/jobs*) printf '%s\n' "$FAKE_JOBS" ;;
  */issues\?state=open*) if [ -n "$FAKE_ISSUES" ]; then printf "%s\n" "$FAKE_ISSUES"; fi ;;
  */actions/workflows/*/runs*) printf '%s\n' $FAKE_HISTORY ;;
  */issues) echo 4242 ;;
  */issues/*/comments) echo 1 ;;
  */statuses/*) echo 1 ;;
  *) exit 64 ;;
esac
STUBGH
chmod +x "$STUB/gh"

SHA=cccccccccccccccccccccccccccccccccccccccc
OLD=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
MID=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
LINES="[{\"line\":\"main\",\"branch\":\"main\",\"sha\":\"$SHA\",\"tests_ref\":\"main\",\"tests_sha\":\"t3\"},{\"line\":\"1.11.x\",\"branch\":\"release/1.11.x\",\"error\":\"no successful Docker Publish run on release/1.11.x\"}]"
job() { printf '{"name":"Gate [main] / %s","conclusion":"%s","html_url":"https://g/job/%s"}' "$1" "$2" "${1%% *}"; }
JOBS="$(job deploy success; echo; job 'dtf-gate (storage-1.11.0, a b...' failure; echo; job repo-tests success; echo; job collect-results failure)"
hist() { printf '{"schema":1,"run_id":%s,"self_test":%s,"lines":[{"line":"main","sha":"%s","tests_sha":"%s","tiers":{"dtf-gate/storage-1.11.0":{"conclusion":"%s"}}}]}' "$@"; }
mkdir -p "$WORK/d"
hist 8 false "$MID" t2 failure > "$WORK/d/hist-8.json"
hist 7 true  "$MID" t2 success > "$WORK/d/hist-7.json"     # self-test records are not evidence
hist 5 false "$OLD" t1 success > "$WORK/d/hist-5.json"

report() { # extra env assignments...
  : > "$WORK/log"
  RC=0
  OUT="$(env PATH="$STUB:$PATH" FAKE_LOG="$WORK/log" FAKE_DIR="$WORK/d" FAKE_JOBS="$JOBS" \
    FAKE_HISTORY="99 8 7 6 5" REPORT_REPO=o/r REPORT_RUN_ID=99 REPORT_LINES_JSON="$LINES" \
    REPORT_OUT="$WORK/verdict.json" GITHUB_STEP_SUMMARY='' "$@" node "$SCRIPT" 2>&1)" || RC=$?
}
calls() { grep -c -- "$1" "$WORK/log"; }

report FAKE_ISSUES='' REPORT_TRACK=true REPORT_STATUS=true
if [ "$RC" = 0 ] && [ "$(calls 'repos/o/r/issues -f title=Nightly gate \[main\]: dtf-gate/storage-1.11.0 is red')" = 1 ] \
   && [ "$(calls 'repos/o/r/issues -f')" = 1 ]; then
  pass "a red tier with no issue opens exactly one"
else fail "open (rc=$RC): $OUT"; fi
if grep -q "compare/${OLD}...${MID}" "$WORK/log" && grep -q 'compare/t1...t2' "$WORK/log"; then
  pass "the issue names the first red range: last green ${OLD:0:7} .. first red ${MID:0:7}, tests t1..t2"
else fail "range not in the issue body: $(grep -E "Last green|First red|range" "$WORK/log")"; fi
if [ "$(calls 'run download 99')" = 0 ] && [ "$(calls 'run download 6')" = 1 ] && [ "$(calls 'run download 4')" = 0 ]; then
  pass "the walk skips this run, reads past a missing artifact and stops at the last green"
else fail "history walk: $(grep download "$WORK/log")"; fi
if [ "$(calls "statuses/${SHA} -f state=failure -f context=release-gate/nightly")" = 1 ] && [ "$(calls statuses/)" = 1 ]; then
  pass "one advisory failure status on the tested commit, none for the unresolved line"
else fail "status: $(grep statuses "$WORK/log")"; fi
if [ "$(jq -r '.lines[0].verdict, .lines[0].red[0], .lines[1].verdict, .certification, .lines[0].tests_sha' "$WORK/verdict.json" | tr '\n' ' ')" = "red dtf-gate/storage-1.11.0 unresolved false t3 " ]; then
  pass "the verdict record names the sha, tests sha, verdict and red tiers, and says it is no certification"
else fail "verdict.json: $(cat "$WORK/verdict.json")"; fi

ISSUE='{"number":17,"title":"x","body":"<!-- nightly-gate-tier: main|dtf-gate/storage-1.11.0 -->"}'
report FAKE_ISSUES="$ISSUE" REPORT_TRACK=true
if [ "$(calls 'issues/17/comments -f body=Still red')" = 1 ] && [ "$(calls 'repos/o/r/issues -f')" = 0 ] && [ "$(calls 'run download')" = 0 ]; then
  pass "a repeat failure comments on the open issue and opens no second one"
else fail "repeat: $(cat "$WORK/log")"; fi

JOBS="$(job deploy success; echo; job 'dtf-gate (storage-1.11.0, a b...' success; echo; job collect-results success)" \
  report FAKE_ISSUES="$ISSUE" REPORT_TRACK=true REPORT_STATUS=true
if [ "$(calls 'issues/17/comments -f body=Green again')" = 1 ] && [ "$(calls '-X PATCH repos/o/r/issues/17 -f state=closed')" = 1 ] \
   && [ "$(calls 'state=success -f context=release-gate/nightly')" = 1 ]; then
  pass "recovery closes the issue and the status turns green"
else fail "recovery: $(cat "$WORK/log")"; fi

report FAKE_ISSUES="$ISSUE" REPORT_TRACK=true REPORT_STATUS=true REPORT_SUITE=search
if [ "$(calls statuses/)" = 0 ]; then pass "a narrow suite writes no commit status"; else fail "narrow status: $(grep statuses "$WORK/log")"; fi

report FAKE_ISSUES='' REPORT_TRACK=true REPORT_STATUS=true REPORT_SELF_TEST=true
if [ "$RC" = 0 ] && [ "$(grep -c -E 'issues -f|comments|PATCH|statuses/' "$WORK/log")" = 0 ] && [[ "$OUT" == *"[dry run] OPEN"* ]] \
   && [ "$(jq -r .self_test "$WORK/verdict.json")" = true ]; then
  pass "a self-test plans its writes, makes none, and marks its record"
else fail "self-test: $(cat "$WORK/log")"; fi

report FAKE_ISSUES='' REPORT_TRACK=true REPORT_STATUS=true REPORT_RUN_ATTEMPT=2
if [ "$(grep -c -E 'issues|statuses/' "$WORK/log")" = 0 ]; then pass "a re-run attempt tracks nothing"; else fail "re-run: $(cat "$WORK/log")"; fi

report FAKE_ISSUES='' REPORT_TRACK=false REPORT_STATUS=false
if [ "$(grep -c -E 'issues|statuses/' "$WORK/log")" = 0 ] && [ -s "$WORK/verdict.json" ]; then
  pass "an untracked dispatch still records a verdict, touches no issue"
else fail "untracked: $(cat "$WORK/log")"; fi

echo
if [ "$fails" -ne 0 ]; then echo "$fails check(s) failed"; exit 1; fi
echo "all nightly-gate-report checks passed"
