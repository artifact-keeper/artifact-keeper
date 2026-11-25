#!/usr/bin/env bash
#
# Self-test for scripts/ci/trivy-findings.js (#4799).
#
# The rule it pins: a finding in the frozen :latest image that is absent from
# a :dev image built at least as recently is already fixed on main and must not
# open a weekly scan issue; a finding still on :dev must. An older or failed
# dev scan is unknown, so it keeps every latest finding actionable rather than
# dismissing findings silently. Offline, no dependencies beyond node.
#
# Usage: bash scripts/ci/test-trivy-findings.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/trivy-findings.js"
[ -f "$SCRIPT" ] || { echo "cannot find trivy-findings.js next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

# One SARIF report with rules at the severities trivy tags them with.
sarif() {
  node -e '
    const ids = process.argv.slice(1);
    const rules = ids.map((id) => ({ id, properties: { tags: [id.startsWith("H") ? "HIGH" : "MEDIUM"] } }));
    const results = ids.map((id) => ({ ruleId: id, locations: [{ physicalLocation: { artifactLocation: { uri: "usr/local/bin/buildctl" } } }] }));
    process.stdout.write(JSON.stringify({ runs: [{ tool: { driver: { rules } }, results }] }));
  ' "$@"
}

echo "pure functions"
if node - "$SCRIPT" <<'NODE'
const r = require(process.argv[2]);
const assert = require('assert');
const eq = assert.deepStrictEqual;

const report = (...ids) => ({ runs: [{ tool: { driver: { rules: ids.map((id) => ({ id, properties: { tags: [id.startsWith('H-') ? 'HIGH' : 'MEDIUM'] } })) } },
  results: ids.map((id) => ({ ruleId: id, locations: [{ physicalLocation: { artifactLocation: { uri: 'usr/local/bin/buildctl' } } }] })) }] });
const built = (latest, dev) => ({
  'Backend (latest)': { created: latest },
  'Backend (dev)': { created: dev },
});
const newerDev = built('2026-10-18T04:25:12.548251033Z', '2026-10-19T11:36:49.132745673Z');

const s = r.summarizeSarif(report('CVE-A', 'CVE-A', 'CVE-B'));
eq([s.count, s.bySeverity.MEDIUM, s.locations['usr/local/bin/buildctl'], s.entries.length], [3, 3, 3, 3]);
eq(r.summarizeSarif(null).count, 0);
eq(r.summarizeSarif(report('H-1')).bySeverity.HIGH, 1);

// #4799 itself: three MEDIUM findings in :latest, none on a newer :dev.
let c = r.classify(report('CVE-2026-53493', 'CVE-2026-53495', 'CVE-2026-95838'), report(), report(), newerDev);
eq([c.totalFindings, c.actionableFindings], [3, 0]);
eq(c.staleFindings.map((f) => f.ruleId), ['CVE-2026-53493', 'CVE-2026-53495', 'CVE-2026-95838']);

// A finding still present on :dev is live on main and stays actionable.
c = r.classify(report('CVE-A', 'CVE-B'), report('CVE-A'), report(), newerDev);
eq([c.totalFindings, c.actionableFindings], [3, 2]);
eq(c.staleFindings.map((f) => f.ruleId), ['CVE-B']);

// An equally new :dev image also proves a missing finding was fixed.
c = r.classify(report('CVE-A'), report(), report(), built('2026-10-19T11:36:49Z', '2026-10-19T11:36:49Z'));
eq([c.actionableFindings, c.staleFindings.length], [0, 1]);

// Right after a release :dev can lag :latest: a clean older scan proves
// nothing, so the finding stays actionable (#4799).
c = r.classify(report('CVE-A'), report(), report(), built('2026-10-19T11:36:49Z', '2026-10-18T04:25:12Z'));
eq([c.actionableFindings, c.staleFindings.length], [1, 0]);

// Unknown build times are not proof either.
c = r.classify(report('CVE-A'), report(), report(), built('2026-10-19T11:36:49Z', 'unknown'));
eq([c.actionableFindings, c.staleFindings.length], [1, 0]);
c = r.classify(report('CVE-A'), report(), report());
eq([c.actionableFindings, c.staleFindings.length], [1, 0]);

// OpenSCAP has no dev counterpart: its findings always stay actionable.
c = r.classify(report(), report(), report('CVE-A'), newerDev);
eq(c.actionableFindings, 1);
eq(c.staleFindings, []);

// An absent dev report is unknown, not clean: keep every latest finding.
c = r.classify(report('CVE-A'), null, report(), newerDev);
eq([c.actionableFindings, c.staleFindings.length], [1, 0]);

// Issue body lines keep their existing shape.
const p = { 'Backend (latest)': { ref: 'x:latest', version: 'main', created: '2026-10-18T04:25:12Z' } };
eq(r.summaryLine('Backend (latest)', p, s, true),
  '- **Backend (latest)**: 3 finding(s) — 3 MEDIUM — `x:latest` (version `main`, built 2026-10-18T04:25:12Z)\n  - Located in: `usr/local/bin/buildctl` (3)');
eq(r.summaryLine('Backend (dev)', {}, r.summarizeSarif(report()), true), '- **Backend (dev)**: 0 findings');
eq(r.summaryLine('OpenSCAP', {}, r.summarizeSarif(report()), false), '- **OpenSCAP**: Scan skipped or failed');
NODE
then pass "pure classification and summary logic"; else fail "pure classification and summary logic"; fi

echo "cli with fixture reports"
mkdir -p "$WORK/clean-dev"
sarif CVE-2026-53493 CVE-2026-53495 CVE-2026-95838 > "$WORK/clean-dev/backend-trivy.sarif"
sarif > "$WORK/clean-dev/backend-dev-trivy.sarif"
sarif > "$WORK/clean-dev/openscap-trivy.sarif"
printf 'Backend (latest)|ghcr.io/o/b:latest|main|2026-10-18T04:25:12.548251033Z\n' > "$WORK/clean-dev/scanned-images.txt"
printf 'Backend (dev)|ghcr.io/o/b:dev|main|2026-10-19T11:36:49.132745673Z\n' >> "$WORK/clean-dev/scanned-images.txt"
if node "$SCRIPT" --dir "$WORK/clean-dev" --out "$WORK/clean-dev/findings.json" >/dev/null 2>&1 \
   && node -e '
     const d = require(process.argv[1]); const a = require("assert");
     a.strictEqual(d.actionableFindings, 0);
     a.strictEqual(d.totalFindings, 3);
     a.strictEqual(d.staleFindings.length, 3);
     a.ok(d.summaries[0].includes("3 MEDIUM"));
   ' "$WORK/clean-dev/findings.json"
then pass "stale :latest-only findings are not actionable"; else fail "stale :latest-only findings are not actionable"; fi

mkdir -p "$WORK/live-dev"
sarif CVE-A CVE-B > "$WORK/live-dev/backend-trivy.sarif"
sarif CVE-A > "$WORK/live-dev/backend-dev-trivy.sarif"
sarif > "$WORK/live-dev/openscap-trivy.sarif"
printf 'Backend (latest)|ghcr.io/o/b:latest|main|2026-10-18T04:25:12Z\n' > "$WORK/live-dev/scanned-images.txt"
printf 'Backend (dev)|ghcr.io/o/b:dev|main|2026-10-19T11:36:49Z\n' >> "$WORK/live-dev/scanned-images.txt"
if node "$SCRIPT" --dir "$WORK/live-dev" --out "$WORK/live-dev/findings.json" >/dev/null 2>&1 \
   && node -e '
     const d = require(process.argv[1]); const a = require("assert");
     a.strictEqual(d.actionableFindings, 2);
     a.deepStrictEqual(d.staleFindings.map((f) => f.ruleId), ["CVE-B"]);
   ' "$WORK/live-dev/findings.json"
then pass "a finding still on :dev stays actionable"; else fail "a finding still on :dev stays actionable"; fi

mkdir -p "$WORK/older-dev"
sarif CVE-A > "$WORK/older-dev/backend-trivy.sarif"
sarif > "$WORK/older-dev/backend-dev-trivy.sarif"
sarif > "$WORK/older-dev/openscap-trivy.sarif"
printf 'Backend (latest)|ghcr.io/o/b:latest|main|2026-10-19T11:36:49Z\n' > "$WORK/older-dev/scanned-images.txt"
printf 'Backend (dev)|ghcr.io/o/b:dev|main|2026-10-18T04:25:12Z\n' >> "$WORK/older-dev/scanned-images.txt"
if node "$SCRIPT" --dir "$WORK/older-dev" --out "$WORK/older-dev/findings.json" >/dev/null 2>&1 \
   && node -e '
      const d = require(process.argv[1]); const a = require("assert");
      a.strictEqual(d.actionableFindings, 1);
      a.strictEqual(d.staleFindings.length, 0);
    ' "$WORK/older-dev/findings.json"
then pass "a clean but older :dev scan keeps findings actionable"; else fail "a clean but older :dev scan keeps findings actionable"; fi

mkdir -p "$WORK/no-dev"
sarif CVE-A > "$WORK/no-dev/backend-trivy.sarif"
if node "$SCRIPT" --dir "$WORK/no-dev" --out "$WORK/no-dev/findings.json" >/dev/null 2>&1 \
   && node -e '
     const d = require(process.argv[1]); const a = require("assert");
     a.strictEqual(d.actionableFindings, 1);
     a.strictEqual(d.staleFindings.length, 0);
     a.ok(d.summaries[1].includes("Scan skipped or failed"));
   ' "$WORK/no-dev/findings.json"
then pass "a failed dev scan keeps findings actionable"; else fail "a failed dev scan keeps findings actionable"; fi

echo "workflow entry point"
# The workflow calls collect() from github-script rather than the CLI.
if node - "$SCRIPT" "$WORK/clean-dev" <<'NODE'
const r = require(process.argv[2]);
const assert = require('assert');
const d = r.collect(process.argv[3]);
assert.strictEqual(d.actionableFindings, 0);
assert.strictEqual(d.staleFindings.length, 3);
assert.strictEqual(d.summaries.length, 3);
assert.ok(d.summaries[2].includes('0 findings'));
NODE
then pass "collect() used by the workflow classifies the #4799 reports"; else fail "collect() used by the workflow classifies the #4799 reports"; fi

if [ "$fails" -eq 0 ]; then echo "PASS: trivy-findings self-test"; else echo "FAIL: $fails check(s)"; exit 1; fi
