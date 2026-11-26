#!/usr/bin/env node
// Turn a nightly release-gate run into a verdict record, tracking issues and
// an advisory commit status (#6073).
//
// INPUT: the jobs of one workflow run (the nightly's own, or with
// REPORT_JOBS_RUN_ID any other run, for a dry-run self-test), and the lines
// the run tested (nightly-gate-lines.sh's JSON). Every gate job of a line is
// named "<prefix> / <gate job>", the prefix being "Gate [<line>]" in the
// nightly. A TIER is one gate job, keyed by its job id plus its first matrix
// value: "dtf-gate (storage-1.11.0, quota-... s3-...)" is
// "dtf-gate/storage-1.11.0", "resilience-tests (crash)" is
// "resilience-tests/crash", "repo-tests" is "repo-tests".
//
// VERDICT, per line: green when the gate's own `collect-results` job, which
// applies its blocking rules, succeeded; red when it did not; incomplete
// when the line has no collect-results job (the leg never ran). Red TIERS are
// every gate job that ended failure, timed_out, cancelled or
// startup_failure, blocking or not: a red non-blocking tier (stress-tests,
// cli-smoke, a dtf-advisory group) is still drift someone has to look at.
// collect-results itself is only a tier when the verdict is red and no
// other job is, so it never duplicates the tier that turned it red.
//
// ISSUES (REPORT_TRACK=true). One open issue per red (line, tier), found by
// the marker `<!-- nightly-gate-tier: <line>|<tier> -->` among open issues
// labelled `release-gate` (a lane's: `nightly-lane`, see LANES):
//   red, no issue    open one, naming the first red commit and the last
//                    green one before it: the range the cause is in. Both
//                    come from earlier runs' verdict records (the
//                    `nightly-gate-verdict` artifact), walked newest first
//                    past runs where the tier did not run, until one where
//                    it was green.
//   red, issue open  comment: still red at <sha>.
//   green, issue     comment and close.
//   tier absent      after a COMPLETE green full-suite run of the line, an
//                    open issue whose tier no longer exists is closed too
//                    (the group was renamed or removed).
//   skipped or not run: nothing; that is not evidence either way.
//
// THE RECORD #6075 READS. Two places, both keyed by the tested commit:
//   * the artifact `nightly-gate-verdict` (verdict.json, schema 1) on the
//     nightly run, with every line's sha, digest, tests ref and sha, verdict
//     and tiers;
//   * a commit status `release-gate/nightly` on the tested commit (success /
//     failure), written only for a complete full-suite run (REPORT_STATUS).
// Neither is a release certification, and nothing on the release path reads
// them as one: the certification is the signed attestation that only
// release-candidate.yml on main can produce (assert-candidate-certified.sh
// pins that signing identity). This script holds no id-token and attests
// nothing.
//
// Env:
//   REPORT_REPO            owner/name
//   REPORT_RUN_ID          this run (verdict record, links, history walk)
//   REPORT_RUN_ATTEMPT     this run's attempt (default 1)
//   REPORT_JOBS_RUN_ID     the run whose jobs are read (default REPORT_RUN_ID)
//   REPORT_JOB_PREFIX      prefix template, {line} replaced (default "Gate [{line}]")
//   REPORT_LINES_JSON      nightly-gate-lines.sh output
//   REPORT_SUITE           the gate's test_suite (default all)
//   REPORT_EVENT           schedule | workflow_dispatch
//   REPORT_SELF_TEST       true: dry run, and the record is marked self_test
//   REPORT_TRACK           true: open, update and close issues
//   REPORT_STATUS          true: write the commit status (full suite only)
//   REPORT_DRY_RUN         true: print the planned writes, make none
//   REPORT_WORKFLOW        workflow file for the history walk
//                          (default nightly-release-gate.yml)
//   REPORT_HISTORY_RUNS    how many earlier runs the walk may read (default 60:
//                          up to three scheduled runs a night since #6155,
//                          and a backstop that skipped carries no record)
//   REPORT_OUT             where verdict.json goes (default ./verdict.json)
//   REPORT_SERVER_URL      default https://github.com
//   REPORT_LANE            a nightly LANE outside the gate (#6121: s3),
//                          lowercase [a-z0-9-]: see LANES below
//   GITHUB_STEP_SUMMARY    appended to when set
//
// LANES. The nightly also runs lanes that are not part of the release gate
// (the S3 format matrix, #6121). Each lane is reported by its
// own run of this script with REPORT_LANE set, and is kept apart from the
// gate everywhere a gate result could act on it:
//   * its issues are keyed by the line "<line>~<lane>" (marker
//     `main~s3|<tier>`), so the gate's "tier no longer exists" closing,
//     which only looks at "<line>|" keys, never closes a lane issue, and a
//     lane never closes a gate issue;
//   * its record goes to the artifact `nightly-lane-verdict-<lane>` (kind
//     nightly-lane), and its history walk reads only that artifact, so
//     #6075 and preflight, which read `nightly-gate-verdict`, never see it;
//   * its issues are labelled `nightly-lane`, not `release-gate`, so a red
//     lane does not read as a gate failure, and its lookup of open issues
//     searches only that label;
//   * it never writes the `release-gate/nightly` commit status.
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const SCHEMA = 1;
const ARTIFACT = 'nightly-gate-verdict';
const LANE_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;
const STATUS_CONTEXT = 'release-gate/nightly';
const AGGREGATE = 'collect-results';
const GATE_LABEL = 'release-gate';
const LANE_LABEL = 'nightly-lane';

// The tracking label: the gate's issues are `release-gate`, a lane's are
// `nightly-lane` (a red lane is not a gate failure).
function trackingLabel(lane) {
  return lane ? LANE_LABEL : GATE_LABEL;
}
const RED = new Set(['failure', 'timed_out', 'cancelled', 'startup_failure']);
const MARKER_RE = /<!-- nightly-gate-tier: (.+?) -->/;

// ── pure helpers (exported for the self-test) ─────────────────────────────────

function tierKey(name) {
  const m = /^(.*?) \((.*)$/.exec(name.trim());
  if (!m) return name.trim();
  const first = m[2].split(',')[0].replace(/\)$/, '').replace(/(\.\.\.|…)$/, '').trim();
  return first ? `${m[1].trim()}/${first}` : m[1].trim();
}

function worst(a, b) {
  if (!a) return b;
  if (RED.has(a) || RED.has(b)) return RED.has(a) ? a : b;
  if (a === 'success' && b === 'success') return 'success';
  return a === 'success' ? b : a;
}

// jobs: [{name, conclusion, html_url}] -> {verdict, tiers, red}
function classifyLine(jobs, prefix) {
  const head = `${prefix} / `;
  const tiers = {};
  for (const j of jobs) {
    if (!j.name || !j.name.startsWith(head)) continue;
    const key = tierKey(j.name.slice(head.length));
    const prev = tiers[key];
    const conclusion = j.conclusion || 'pending';
    tiers[key] = {
      conclusion: prev ? worst(prev.conclusion, conclusion) : conclusion,
      url: prev && RED.has(prev.conclusion) ? prev.url : j.html_url,
    };
  }
  const agg = tiers[AGGREGATE];
  let verdict;
  if (!agg) verdict = Object.keys(tiers).length ? 'incomplete' : 'missing';
  else verdict = agg.conclusion === 'success' ? 'green' : 'red';
  let red = Object.keys(tiers).filter((k) => k !== AGGREGATE && RED.has(tiers[k].conclusion));
  if (verdict === 'red' && red.length === 0) red = [AGGREGATE];
  red.sort();
  return { verdict, tiers, red };
}

function issueKey(line, tier) {
  return `${line}|${tier}`;
}

// The line key a lane's issues and records use: "main" -> "main~s3".
function laneLine(line, lane) {
  return lane ? `${line}~${lane}` : line;
}

function artifactName(lane) {
  return lane ? `nightly-lane-verdict-${lane}` : ARTIFACT;
}

// "the nightly full release gate" or "the nightly s3 lane".
function what(ctx) {
  return ctx.lane ? `nightly ${ctx.lane} lane` : 'nightly full release gate';
}

function markerOf(body) {
  const m = MARKER_RE.exec(body || '');
  return m ? m[1] : null;
}

// history: earlier verdict records, newest first. Returns the first red
// commit of the current streak and the last green one before it.
function redRange(line, tier, current, history) {
  let firstRed = current;
  let lastGreen = null;
  let walked = 0;
  for (const rec of history) {
    walked += 1;
    const l = (rec.lines || []).find((x) => x.line === line);
    const t = l && l.tiers && l.tiers[tier];
    if (!t) continue;
    if (t.conclusion === 'success') {
      lastGreen = { sha: l.sha, tests_sha: l.tests_sha, run_id: rec.run_id };
      break;
    }
    if (RED.has(t.conclusion)) firstRed = { sha: l.sha, tests_sha: l.tests_sha, run_id: rec.run_id };
  }
  return { firstRed, lastGreen, walked };
}

function short(sha) {
  return sha ? sha.slice(0, 7) : 'unknown';
}

function openBody(ctx, line, tier, range) {
  const { repo, server } = ctx;
  const c = (sha) => (sha ? `[\`${short(sha)}\`](${server}/${repo}/commit/${sha})` : '_none on record_');
  const run = (id) => (id ? `[run ${id}](${server}/${repo}/actions/runs/${id})` : '');
  const fr = range.firstRed;
  const lg = range.lastGreen;
  const rows = [
    `| Line | \`${line.branch}\` |`,
    `| Tier | \`${tier}\` |`,
    `| First red commit | ${c(fr.sha)} ${run(fr.run_id)} |`,
    `| Last green commit | ${lg ? `${c(lg.sha)} ${run(lg.run_id)}` : `_none in the last ${range.walked} nightly runs_`} |`,
  ];
  if (lg && lg.sha && fr.sha && lg.sha !== fr.sha) {
    rows.push(`| Backend range | ${server}/${repo}/compare/${lg.sha}...${fr.sha} |`);
  } else if (lg && lg.sha === fr.sha) {
    rows.push('| Backend range | the same commit was green before: the change is in the tests, the harness or the runners |');
  }
  const testsRepo = 'artifact-keeper/artifact-keeper-test';
  if (lg && lg.tests_sha && fr.tests_sha && lg.tests_sha !== fr.tests_sha) {
    rows.push(`| Tests range (\`${line.tests_ref || 'main'}\`) | ${server}/${testsRepo}/compare/${lg.tests_sha}...${fr.tests_sha} |`);
  } else if (fr.tests_sha) {
    rows.push(`| Tests (\`${line.tests_ref || 'main'}\`) | \`${short(fr.tests_sha)}\` |`);
  }
  const job = line.tiers[tier] && line.tiers[tier].url;
  return [
    `<!-- nightly-gate-tier: ${issueKey(line.line, tier)} -->`,
    `The ${what(ctx)} is red on \`${tier}\` for \`${line.branch}\`.`,
    '',
    '| | |',
    '|---|---|',
    ...rows,
    `| Failing job | ${job || run(ctx.runId)} |`,
    `| ${ctx.lane ? 'Lane' : 'Gate'} verdict that night | ${line.verdict} |`,
    '',
    'The cause is in the backend range, the tests range, or neither (a flake or a runner problem). ' +
      'This issue is managed by `nightly-release-gate.yml` (#6073): it gets a comment each night the tier is still red ' +
      'and is closed the first night it is green. It is advisory and blocks nothing' +
      `${ctx.lane ? `, and the ${ctx.lane} lane is not part of the release gate` : ''}. ` +
      'Close it by hand if the tier was renamed or removed and no complete green run has closed it yet.',
    '',
  ].join('\n');
}

// Plan every issue write for one line. Pure.
function planIssues(ctx, line, openIssues, rangeFor) {
  const actions = [];
  const mine = new Map();
  for (const is of openIssues) {
    const key = markerOf(is.body);
    if (!key || !key.startsWith(`${line.line}|`)) continue;
    const tier = key.slice(line.line.length + 1);
    if (!mine.has(tier)) mine.set(tier, is.number);
  }
  const runLink = `${ctx.server}/${ctx.repo}/actions/runs/${ctx.runId}`;
  for (const tier of line.red) {
    const job = line.tiers[tier] && line.tiers[tier].url;
    if (mine.has(tier)) {
      actions.push({
        type: 'comment',
        number: mine.get(tier),
        body: `Still red at \`${short(line.sha)}\` (${job || runLink}).`,
      });
    } else {
      const range = rangeFor(tier);
      actions.push({
        type: 'open',
        key: issueKey(line.line, tier),
        title: ctx.lane
          ? `Nightly ${ctx.lane} lane [${line.line.replace(/~[^~]*$/, '')}]: ${tier} is red`
          : `Nightly gate [${line.line}]: ${tier} is red`,
        body: openBody(ctx, line, tier, range),
      });
    }
  }
  const completeGreen = line.verdict === 'green' && ctx.suite === 'all';
  for (const [tier, number] of mine) {
    if (line.red.includes(tier)) continue;
    const t = line.tiers[tier];
    if (t && t.conclusion === 'success') {
      actions.push({
        type: 'close',
        number,
        body: `Green again at \`${short(line.sha)}\` (${t.url || runLink}). Closing.`,
      });
    } else if (!t && completeGreen) {
      actions.push({
        type: 'close',
        number,
        body: `\`${tier}\` is no longer part of the ${ctx.lane ? `${ctx.lane} lane` : 'gate'} for \`${line.branch}\`, and the ${ctx.lane ? 'lane' : 'full gate'} was green at \`${short(line.sha)}\` (${runLink}). Closing.`,
      });
    }
  }
  return actions;
}

// ── I/O ───────────────────────────────────────────────────────────────────────

function gh(args, opts = {}) {
  return execFileSync('gh', args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, ...opts });
}

function jsonLines(text) {
  return text.split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l));
}

function listJobs(repo, runId) {
  return jsonLines(gh(['api', '--paginate',
    `repos/${repo}/actions/runs/${runId}/jobs?per_page=100&filter=latest`,
    '--jq', '.jobs[] | {name, conclusion, html_url}']));
}

function listOpenIssues(repo, label) {
  return jsonLines(gh(['api', '--paginate',
    `repos/${repo}/issues?state=open&labels=${label}&per_page=100`,
    '--jq', '.[] | select(.pull_request | not) | {number, title, body}']));
}

// Lazily reads earlier runs' verdict records, newest first.
function historyReader(repo, workflow, currentRunId, limit, artifact = ARTIFACT) {
  let ids = null;
  const records = [];
  let next = 0;
  const load = () => {
    if (ids) return;
    try {
      ids = gh(['api', `repos/${repo}/actions/workflows/${workflow}/runs?status=completed&per_page=${limit + 1}`,
        '--jq', '.workflow_runs[].id'], { stdio: ['ignore', 'pipe', 'pipe'] }).split('\n').filter(Boolean)
        .filter((id) => id !== String(currentRunId)).slice(0, limit);
    } catch (e) {
      console.error(`history: could not list runs of ${workflow}: ${e.message}`);
      ids = [];
    }
  };
  return {
    *[Symbol.iterator]() {
      load();
      for (let i = 0; ; i += 1) {
        while (records.length <= i && next < ids.length) {
          const id = ids[next++];
          const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nightly-verdict-'));
          try {
            gh(['run', 'download', id, '-R', repo, '-n', artifact, '-D', dir], { stdio: ['ignore', 'pipe', 'pipe'] });
            const rec = JSON.parse(fs.readFileSync(path.join(dir, 'verdict.json'), 'utf8'));
            if (rec.schema === SCHEMA && !rec.self_test) records.push(rec);
          } catch (e) {
            // A run without a record: pre-empted, skipped or expired. Not evidence.
          } finally {
            fs.rmSync(dir, { recursive: true, force: true });
          }
        }
        if (i >= records.length) return;
        yield records[i];
      }
    },
  };
}

function applyAction(repo, a, dry, label) {
  const say = { open: `OPEN   "${a.title}"`, comment: `COMMENT #${a.number}`, close: `CLOSE  #${a.number}` }[a.type];
  console.log(`${dry ? '[dry run] ' : ''}${say}`);
  if (dry) {
    console.log(a.body.split('\n').map((l) => `    ${l}`).join('\n'));
    return a.type === 'open' ? 0 : a.number;
  }
  if (a.type === 'open') {
    const args = ['api', `repos/${repo}/issues`, '-f', `title=${a.title}`, '-f', `body=${a.body}`];
    for (const l of ['automated', label]) args.push('-f', `labels[]=${l}`);
    return Number(gh([...args, '--jq', '.number']).trim());
  }
  gh(['api', `repos/${repo}/issues/${a.number}/comments`, '-f', `body=${a.body}`, '--jq', '.id']);
  if (a.type === 'close') {
    gh(['api', '-X', 'PATCH', `repos/${repo}/issues/${a.number}`, '-f', 'state=closed', '-f', 'state_reason=completed', '--jq', '.number']);
  }
  return a.number;
}

function main() {
  const env = process.env;
  const repo = env.REPORT_REPO;
  const runId = env.REPORT_RUN_ID;
  if (!repo || !/^\d+$/.test(runId || '')) {
    console.error('nightly-gate-report: REPORT_REPO and REPORT_RUN_ID are required');
    process.exit(2);
  }
  const truthy = (v) => v === 'true';
  const lane = env.REPORT_LANE || '';
  if (lane && !LANE_RE.test(lane)) {
    console.error(`nightly-gate-report: REPORT_LANE '${lane}' is not [a-z0-9-]`);
    process.exit(2);
  }
  const selfTest = truthy(env.REPORT_SELF_TEST);
  const dry = selfTest || truthy(env.REPORT_DRY_RUN);
  const ctx = {
    repo,
    runId,
    server: env.REPORT_SERVER_URL || 'https://github.com',
    suite: env.REPORT_SUITE || 'all',
    lane,
  };
  const attempt = Number(env.REPORT_RUN_ATTEMPT || '1');
  const prefixTpl = env.REPORT_JOB_PREFIX || 'Gate [{line}]';
  const resolved = JSON.parse(env.REPORT_LINES_JSON || '[]');
  const jobs = listJobs(repo, env.REPORT_JOBS_RUN_ID || runId);

  const lines = resolved.map((l) => {
    // The job prefix names the plain line ("S3 [main]"); issues and records
    // use the lane's key ("main~s3").
    if (l.error) return { ...l, line: laneLine(l.line, lane), verdict: 'unresolved', tiers: {}, red: [] };
    const c = classifyLine(jobs, prefixTpl.replace('{line}', l.line));
    return { ...l, ...c, line: laneLine(l.line, lane) };
  });

  const record = {
    schema: SCHEMA,
    kind: lane ? 'nightly-lane' : 'nightly-release-gate',
    lane: lane || null,
    certification: false,
    run_id: Number(runId),
    run_attempt: attempt,
    jobs_run_id: Number(env.REPORT_JOBS_RUN_ID || runId),
    event: env.REPORT_EVENT || '',
    suite: ctx.suite,
    self_test: selfTest,
    recorded_at: new Date().toISOString(),
    lines: lines.map((l) => ({
      line: l.line,
      branch: l.branch,
      sha: l.sha || null,
      digest: l.digest || null,
      version: l.version || null,
      tests_ref: l.tests_ref || null,
      tests_sha: l.tests_sha || null,
      verdict: l.verdict,
      error: l.error || null,
      red: l.red,
      tiers: Object.fromEntries(Object.entries(l.tiers).map(([k, v]) => [k, { conclusion: v.conclusion }])),
    })),
  };
  const out = env.REPORT_OUT || 'verdict.json';
  fs.writeFileSync(out, `${JSON.stringify(record, null, 2)}\n`);
  console.log(`wrote ${out}`);

  const summary = [lane ? `## Nightly ${lane} lane` : '## Nightly release gate', '', '_Advisory. Not a release certification._', '',
    '| Line | Commit | Tests | Verdict | Red tiers |', '|---|---|---|---|---|'];
  for (const l of lines) {
    summary.push(`| \`${l.branch}\` | ${l.sha ? `\`${short(l.sha)}\`` : '-'} | ${l.tests_ref ? `\`${l.tests_ref}@${short(l.tests_sha)}\`` : '-'} | ${l.verdict}${l.error ? ` (${l.error})` : ''} | ${l.red.map((t) => `\`${t}\``).join(', ') || '-'} |`);
  }

  if (attempt > 1) {
    console.log('re-run attempt: the gate did not run again (see the workflow), so nothing is tracked');
  } else if (truthy(env.REPORT_TRACK) || selfTest) {
    const open = listOpenIssues(repo, trackingLabel(lane));
    const history = historyReader(repo, env.REPORT_WORKFLOW || 'nightly-release-gate.yml', runId,
      Number(env.REPORT_HISTORY_RUNS || '60'), artifactName(lane));
    summary.push('', '### Tracking issues', '');
    for (const l of lines) {
      if (l.verdict !== 'green' && l.verdict !== 'red') continue;
      const current = { sha: l.sha, tests_sha: l.tests_sha, run_id: Number(runId) };
      const actions = planIssues(ctx, l, open, (tier) => redRange(l.line, tier, current, history));
      for (const a of actions) {
        const n = applyAction(repo, a, dry, trackingLabel(lane));
        summary.push(`- ${a.type} ${n ? `#${n}` : `"${a.title}"`}${dry ? ' (dry run)' : ''}`);
      }
    }
  }

  // A lane is not the gate: the release-gate/nightly status is the gate's alone.
  if (truthy(env.REPORT_STATUS) && attempt === 1 && ctx.suite === 'all' && !selfTest && !lane) {
    for (const l of lines) {
      if (l.verdict !== 'green' && l.verdict !== 'red') continue;
      const desc = l.verdict === 'green'
        ? 'Advisory nightly full gate: green. Not a release certification.'
        : `Advisory nightly full gate: red (${l.red.length} tier${l.red.length === 1 ? '' : 's'}). Not a certification.`;
      const args = ['api', `repos/${repo}/statuses/${l.sha}`,
        '-f', `state=${l.verdict === 'green' ? 'success' : 'failure'}`,
        '-f', `context=${STATUS_CONTEXT}`,
        '-f', `description=${desc.slice(0, 140)}`,
        '-f', `target_url=${ctx.server}/${repo}/actions/runs/${runId}`, '--jq', '.id'];
      console.log(`${dry ? '[dry run] ' : ''}STATUS ${STATUS_CONTEXT}=${l.verdict} on ${l.sha}`);
      if (!dry) gh(args);
    }
  }

  if (env.GITHUB_STEP_SUMMARY) fs.appendFileSync(env.GITHUB_STEP_SUMMARY, `${summary.join('\n')}\n`);
  console.log(summary.join('\n'));
}

module.exports = { trackingLabel, tierKey, classifyLine, redRange, planIssues, markerOf, issueKey, openBody, laneLine, artifactName };

if (require.main === module) main();
