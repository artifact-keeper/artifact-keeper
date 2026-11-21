#!/usr/bin/env node
// Classify the findings of the weekly Scheduled Container Scan (#4799).
//
// `:dev` tracks main, so every finding there is live on main and actionable.
// `:latest` is the frozen last stable release: a finding there that is absent
// from `:dev` was already fixed on main and clears on the next stable publish.
// It must not open a scan issue (#4799), and it must never be suppressed in
// .trivyignore -- that would record an exception for a build we no longer
// produce. OpenSCAP has no :dev scan, so its findings stay actionable.
//
// INPUT (--dir, default '.'): scanned-images.txt (name|ref|version|created),
// backend-trivy.sarif, backend-dev-trivy.sarif, openscap-trivy.sarif. A
// missing SARIF file means the scan was skipped or failed: when the dev file
// is missing the classification is unknown, so every latest finding is kept
// actionable rather than silently dismissed.
//
// OUTPUT (--out, default ./findings.json): JSON with `summaries` (the issue
// body lines), `totalFindings`, `actionableFindings` and `staleFindings`.
//
// Usage: node scripts/ci/trivy-findings.js [--dir DIR] [--out FILE]

'use strict';

const fs = require('fs');
const path = require('path');

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const TARGETS = [
  ['Backend (latest)', 'backend-trivy.sarif'],
  ['Backend (dev)', 'backend-dev-trivy.sarif'],
  ['OpenSCAP', 'openscap-trivy.sarif'],
];

function readSarif(dir, file) {
  const full = path.join(dir, file);
  if (!fs.existsSync(full)) return null;
  return JSON.parse(fs.readFileSync(full, 'utf8'));
}

// One trivy-action SARIF report -> counts, locations and one entry per result.
function summarizeSarif(sarif) {
  const run = (sarif && sarif.runs && sarif.runs[0]) || {};
  const results = run.results || [];
  const rules = {};
  for (const rule of (run.tool && run.tool.driver && run.tool.driver.rules) || []) rules[rule.id] = rule;
  const bySeverity = {};
  const locations = {};
  const entries = [];
  for (const result of results) {
    const properties = (rules[result.ruleId] || {}).properties || {};
    const tags = properties.tags || [];
    const severity = SEVERITIES.find((s) => tags.includes(s)) || 'UNKNOWN';
    bySeverity[severity] = (bySeverity[severity] || 0) + 1;
    const location = ((result.locations || [])[0] || {}).physicalLocation || {};
    const uri = (location.artifactLocation || {}).uri || 'unknown';
    locations[uri] = (locations[uri] || 0) + 1;
    entries.push({ ruleId: result.ruleId, severity, location: uri });
  }
  return { count: results.length, bySeverity, locations, entries };
}

function readProvenance(dir) {
  const provenance = {};
  const file = path.join(dir, 'scanned-images.txt');
  if (!fs.existsSync(file)) return provenance;
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    const [name, ref, version, created] = line.split('|');
    provenance[name] = { ref, version, created };
  }
  return provenance;
}

function severityText(summary) {
  return Object.entries(summary.bySeverity).map(([s, n]) => `${n} ${s}`).join(', ');
}

function locationText(summary) {
  return Object.entries(summary.locations).map(([l, n]) => `\`${l}\` (${n})`).join(', ');
}

function summaryLine(name, provenance, summary, present) {
  const p = provenance[name];
  const meta = p ? ` — \`${p.ref}\` (version \`${p.version}\`, built ${p.created})` : '';
  if (!present) return `- **${name}**: Scan skipped or failed${meta}`;
  if (summary.count === 0) return `- **${name}**: 0 findings${meta}`;
  return `- **${name}**: ${summary.count} finding(s) — ${severityText(summary)}${meta}\n  - Located in: ${locationText(summary)}`;
}

// The decision the workflow acts on. A latest finding whose rule id also
// appears on dev is live on main; one that does not is an already-fixed
// finding in the frozen release image.
function classify(latestSarif, devSarif, openscapSarif) {
  const latest = summarizeSarif(latestSarif);
  const dev = summarizeSarif(devSarif);
  const openscap = summarizeSarif(openscapSarif);
  const devRuleIds = new Set(dev.entries.map((e) => e.ruleId));
  const devAvailable = devSarif !== null;
  const liveLatest = devAvailable ? latest.entries.filter((e) => devRuleIds.has(e.ruleId)) : latest.entries;
  const staleFindings = devAvailable
    ? latest.entries.filter((e) => !devRuleIds.has(e.ruleId)).map((e) => ({ name: 'Backend (latest)', ...e }))
    : [];
  return {
    totalFindings: latest.count + dev.count + openscap.count,
    actionableFindings: dev.count + openscap.count + liveLatest.length,
    staleFindings,
    summaries: {
      'Backend (latest)': latest,
      'Backend (dev)': dev,
      OpenSCAP: openscap,
    },
  };
}

// `collect` is what the workflow's github-script calls; `run` is the CLI form
// used by the self-test. Both share the same classification.
function collect(dir) {
  const reports = Object.fromEntries(TARGETS.map(([name, file]) => [name, readSarif(dir, file)]));
  const result = classify(reports['Backend (latest)'], reports['Backend (dev)'], reports.OpenSCAP);
  const provenance = readProvenance(dir);
  return {
    totalFindings: result.totalFindings,
    actionableFindings: result.actionableFindings,
    staleFindings: result.staleFindings,
    summaries: TARGETS.map(([name]) =>
      summaryLine(name, provenance, result.summaries[name], reports[name] !== null)),
  };
}

function run(dir, out) {
  const payload = collect(dir);
  fs.writeFileSync(out, JSON.stringify(payload, null, 2) + '\n');
  return payload;
}

function main() {
  const args = process.argv.slice(2);
  const value = (flag, fallback) => {
    const i = args.indexOf(flag);
    return i === -1 ? fallback : args[i + 1];
  };
  const dir = value('--dir', '.');
  const out = value('--out', path.join(dir, 'findings.json'));
  const payload = run(dir, out);
  console.log(`Total findings: ${payload.totalFindings}`);
  console.log(`Actionable findings: ${payload.actionableFindings}`);
  console.log(`Already fixed on main: ${payload.staleFindings.length}`);
}

if (require.main === module) main();

module.exports = { readSarif, summarizeSarif, readProvenance, classify, summaryLine, collect, run, TARGETS };
