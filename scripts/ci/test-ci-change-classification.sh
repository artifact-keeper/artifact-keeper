#!/usr/bin/env bash
# =============================================================================
# test-ci-change-classification.sh — ci.yml's `changes` gate skips the Rust
#                                    jobs only when nothing they read changed
# =============================================================================
#
# The `changes` job decides, per pull request, whether the Rust jobs
# run at all, and on a push whether a merged PR already
# proved the tree. Its dangerous direction is a false `rust=false`: the
# required contexts then report skipped-as-success on a change that could
# have turned them red. That is only visible in a PR's CI summary, so the
# decision is pinned here instead.
#
# HOW
#   The step's script is extracted from .github/workflows/ci.yml itself (not
#   a copy), with a stub `gh` answering the pulls/files listing, and run
#   against fixture file lists. Then the drift check: every script referenced
#   by a job gated on `needs.changes.outputs.rust` must classify as a Rust
#   input, so wiring a new scripts/ci/*.sh into a Rust job without listing it
#   in the gate fails here. A second drift check (#6115) scans the backend
#   sources for files outside backend/ that a test reads (include_str!,
#   relative paths, .github/workflows): each must be a Rust input, or a
#   workflow covered by the Workflow Contract Tests job. Last, CI Complete's
#   own step and the "Backend
#   Unit Tests" aggregate's step are run against job results: a gate-skipped
#   Rust job passes there only when the gate said so, an integration job
#   skipped by its path filter passes only when that filter was off, and the
#   Security Audit is advisory in a merge group exactly as on a PR. A few
#   structural assertions pin the merge-path layout (hosted Rust jobs, the
#   merge_group trigger, the advisory image jobs outside CI Complete).
#   Needs python3 + PyYAML (as the other workflow
#   gates do). No network, ~2s.
#
# Usage: bash scripts/ci/test-ci-change-classification.sh
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKFLOW="${WORKFLOW:-$ROOT/.github/workflows/ci.yml}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0

pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

# --- extract the step and the Rust jobs' script references ------------------
python3 - "$WORKFLOW" "$WORK" <<'PY' || { echo "INFRA: could not extract the changes step from $WORKFLOW" >&2; exit 2; }
import re, sys, yaml
wf = yaml.safe_load(open(sys.argv[1]))
work = sys.argv[2]
steps = [s for s in wf['jobs']['changes']['steps'] if s.get('id') == 'filter']
if len(steps) != 1:
    sys.exit('expected exactly one step with id: filter in jobs.changes')
open(f'{work}/filter.sh', 'w').write(steps[0]['run'])
# Every repository path a Rust-gated job's steps mention.
refs = set()
gated = []
for name, job in wf['jobs'].items():
    if 'needs.changes.outputs.rust' not in str(job.get('if', '')):
        continue
    gated.append(name)
    for st in job.get('steps', []):
        text = yaml.safe_dump(st)
        refs.update(re.findall(r'(?<![\w/.-])(?:\./)?((?:scripts|\.github/(?:scripts|actions))/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)', text))
        for u in re.findall(r'uses:\s*\./(\S+)', text):
            refs.add(u)
# CI Complete's verdict step, and the RESULT_* names it reads.
cc = [s for s in wf['jobs']['ci-complete']['steps'] if 'run' in s]
if len(cc) != 1:
    sys.exit('expected exactly one run step in jobs.ci-complete')
open(f'{work}/complete.sh', 'w').write(cc[0]['run'])
open(f'{work}/results.txt', 'w').write('\n'.join(k for k in cc[0].get('env', {}) if k.startswith('RESULT_')) + '\n')
open(f'{work}/gated.txt', 'w').write('\n'.join(sorted(gated)) + '\n')
# The "Backend Unit Tests" aggregate's step, and the integration condition
# it re-evaluates.
tu = [s for s in wf['jobs']['test-backend-unit']['steps'] if 'run' in s]
if len(tu) != 1:
    sys.exit('expected exactly one run step in jobs.test-backend-unit')
open(f'{work}/unit.sh', 'w').write(tu[0]['run'])
wanted = str(tu[0].get('env', {}).get('INTEGRATION_WANTED', ''))
integ_if = str(wf['jobs']['test-backend-integration'].get('if', ''))
m = re.fullmatch(r'\$\{\{\s*(.*?)\s*\}\}', wanted.strip())
wanted_expr = m.group(1) if m else ''
open(f'{work}/wanted.txt', 'w').write(wanted_expr + '\n')
open(f'{work}/integ_if.txt', 'w').write(integ_if + '\n')
# Structure of the merge path, one fact per line for the shell to assert.
on = wf.get('on', wf.get(True, {}))
facts = []
facts.append('trigger_merge_group=' + str('merge_group' in (on or {})).lower())
for j in ('check-rust', 'windows-cross-check', 'test-backend-integration', 'test-backend-unit', 'ci-complete'):
    facts.append(f'runs_on_{j}=' + str(wf['jobs'][j].get('runs-on')))
cc_needs = wf['jobs']['ci-complete'].get('needs', [])
for j in ('smoke-e2e', 'build-backend-image', 'build-openscap-image', 'windows-cross-check'):
    facts.append(f'cc_needs_{j}=' + str(j in cc_needs).lower())
# The Windows cross-check (#6022) must run exactly when Check Rust does.
facts.append('windows_if_matches_check_rust=' + str(
    str(wf['jobs']['windows-cross-check'].get('if')) == str(wf['jobs']['check-rust'].get('if'))).lower())
facts.append('ubuntu_latest=' + str('ubuntu-latest' in open(sys.argv[1]).read()).lower())
# rust-cache entries saved under a PR or merge-group ref are never restored
# by anyone else and push `main`'s own entries out of the 10 GiB quota.
leaky = []
for name, job in wf['jobs'].items():
    for st in job.get('steps', []):
        if 'Swatinem/rust-cache' in str(st.get('uses', '')):
            cond = str((st.get('with') or {}).get('save-if', ''))
            if "!= 'pull_request'" not in cond or "!= 'merge_group'" not in cond:
                leaky.append(name)
facts.append('cache_saves_off_main=' + (','.join(sorted(set(leaky))) or 'none'))
open(f'{work}/facts.txt', 'w').write('\n'.join(facts) + '\n')
open(f'{work}/refs.txt', 'w').write('\n'.join(sorted(refs)) + '\n')
# The Workflow Contract Tests job (#6115): its condition, the lib-test
# module prefixes in CONTRACT_FILTER, the shard it builds and the
# integration targets it names.
wc = wf['jobs'].get('workflow-contracts') or {}
flt = str((wc.get('env') or {}).get('CONTRACT_FILTER', ''))
m = re.fullmatch(r'test\(/\^\(([A-Za-z0-9_:|]+)\)::/\)', flt.strip())
mods = m.group(1).split('|') if m else []
open(f'{work}/contract_modules.txt', 'w').write('\n'.join(mods) + '\n')
wc_text = yaml.safe_dump(wc.get('steps', []))
open(f'{work}/contract_targets.txt', 'w').write('\n'.join(sorted(set(re.findall(r'--test ([A-Za-z0-9_]+)', wc_text)))) + '\n')
open(f'{work}/contract_shards.txt', 'w').write('\n'.join(sorted(set(re.findall(r'test-shard-([a-z0-9-]+)', wc_text)))) + '\n')
open(f'{work}/contract_if.txt', 'w').write(str(wc.get('if', '')) + '\n')
PY

# Every file outside backend/ that a backend source reads, one
# `reader<TAB>path` per line, `.github/workflows/*` for a directory read:
# relative path literals (include_str!, include_bytes!, a read at test time)
# resolved against the source's directory, or backend/ for a
# CARGO_MANIFEST_DIR-relative "/../x", and the joins onto .github/workflows.
python3 - "$ROOT" "$WORK" <<'PY' || { echo "INFRA: could not scan the backend sources" >&2; exit 2; }
import os, re, sys
root, work = sys.argv[1], sys.argv[2]
rel_lit = re.compile(r'"(/?(?:\.\./)+[A-Za-z0-9_.@/-]+)"')
wf_join = re.compile(r'join\("\.github/workflows(/[A-Za-z0-9_.-]+)?"\)')
wf_chain = re.compile(r'join\("\.github"\)\s*\.join\("workflows"\)(?:\s*\.join\("([A-Za-z0-9_.-]+)"\))?')
pairs = set()
for top in ('backend/src', 'backend/tests', 'backend/build.rs'):
    base = os.path.join(root, top)
    if os.path.isfile(base):
        paths = [base]
    else:
        paths = [os.path.join(d, f) for d, _, fs in os.walk(base) for f in fs if f.endswith('.rs')]
    for path in paths:
        reader = os.path.relpath(path, root)
        src = open(path, encoding='utf-8', errors='replace').read()
        for lit in rel_lit.findall(src):
            start = os.path.join(root, 'backend') if lit.startswith('/') else os.path.dirname(path)
            target = os.path.normpath(os.path.join(start, lit.lstrip('/')))
            rel = os.path.relpath(target, root)
            if rel.startswith('..') or rel.startswith('backend/') or not os.path.isfile(target):
                continue
            pairs.add((reader, rel))
        for sub in wf_join.findall(src):
            pairs.add((reader, '.github/workflows' + sub if sub else '.github/workflows/*'))
        for name in wf_chain.findall(src):
            pairs.add((reader, '.github/workflows/' + name if name else '.github/workflows/*'))
open(f'{work}/readers.txt', 'w').write(''.join(f'{r}\t{p}\n' for r, p in sorted(pairs)))
PY

grep -q . "$WORK/gated.txt" || { fail "no job in ci.yml is gated on needs.changes.outputs.rust"; }
for required in check-rust windows-cross-check test-backend-unit; do
  grep -qx "$required" "$WORK/gated.txt" \
    || fail "required job $required is not gated on needs.changes.outputs.rust"
done

# --- stub gh: the pulls/files listing ---------------------------------------
# FAKE_FILES holds one changed file per line, `new<TAB>old` for a rename. The
# listings are answered as the API shapes them (pulls/files: an array of file
# objects; compare: an object with a `files` array, a rename carrying
# `previous_filename`) and filtered through the step's OWN --jq expression,
# so a jq that drops the rename's old path fails here.
STUB="$WORK/bin"; mkdir -p "$STUB"
cat > "$STUB/fake-listing.py" <<'STUBPY'
import json, os, sys
files = []
for line in os.environ.get("FAKE_FILES", "").splitlines():
    if not line:
        continue
    new, _, old = line.partition("\t")
    entry = {"filename": new, "status": "modified"}
    if old:
        entry.update(status="renamed", previous_filename=old)
    files.append(entry)
json.dump({"files": files} if sys.argv[1] == "compare" else files, sys.stdout)
STUBPY
cat > "$STUB/gh" <<'STUBGH'
#!/usr/bin/env bash
[ "${FAKE_GH_FAIL-0}" = 1 ] && exit 1
jq_expr=""
prev=""
for a in "$@"; do [ "$prev" = "--jq" ] && jq_expr="$a"; prev="$a"; done
listing() { python3 "$(dirname "$0")/fake-listing.py" "$1" | jq -r "$jq_expr"; }
case "$*" in
  *pulls/*/files*) listing pulls ;;
  *compare/*)
    [ "${FAKE_COMPARE_FAIL-0}" = 1 ] && exit 1
    listing compare ;;
  *pulls/*)
    [ "${FAKE_LABELS_FAIL-0}" = 1 ] && exit 1
    printf '%s\n' "${FAKE_LABELS-}" | tr ',' '\n' ;;
  *) exit 1 ;;
esac
STUBGH
chmod +x "$STUB/gh"

# run_filter <event> [files...] -> leaves outputs in $WORK/out
run_filter() {
  local event="$1"; shift
  local files; files=$(printf '%s\n' "$@")
  : > "$WORK/out"
  ( cd "${RUN_DIR:-$WORK}" && PATH="$STUB:$PATH" GITHUB_OUTPUT="$WORK/out" \
      GITHUB_REPOSITORY=artifact-keeper/artifact-keeper GH_TOKEN=x \
      EVENT_NAME="$event" PR_NUMBER=1 PUSH_SHA=5555555555555555555555555555555555555555 \
      PUSH_BRANCH=main FAKE_FILES="$files" FAKE_GH_FAIL="${FAKE_GH_FAIL-0}" \
      PR_LABELS="${PR_LABELS-}" FAKE_LABELS="${FAKE_LABELS-}" FAKE_LABELS_FAIL="${FAKE_LABELS_FAIL-0}" \
      FAKE_COMPARE_FAIL="${FAKE_COMPARE_FAIL-0}" \
      MG_BASE_SHA="${MG_BASE_SHA-1111111111111111111111111111111111111111}" \
      MG_HEAD_SHA="${MG_HEAD_SHA-2222222222222222222222222222222222222222}" \
      bash --noprofile --norc -eo pipefail "$WORK/filter.sh" >"$WORK/log" 2>&1 )
}
get() { sed -n "s/^$1=//p" "$WORK/out" | tail -1; }

# expect <label> <want "code backend manifest rust"> <event> [files...]
expect() {
  local label="$1" want="$2" event="$3"; shift 3
  if ! run_filter "$event" "$@"; then
    fail "$label: the step exited non-zero"; sed 's/^/        /' "$WORK/log" >&2; return
  fi
  local got
  got="$(get code) $(get backend) $(get manifest) $(get rust)"
  if [ "$got" = "$want" ]; then
    pass "$label"
  else
    fail "$label: got [code backend manifest rust] = [$got], want [$want]"
    sed 's/^/        /' "$WORK/log" >&2
  fi
}

echo "ci.yml changes gate: pull requests"
#                                                   code  backend manifest rust
expect "docs only"                                 "false false false false" pull_request README.md site/index.html docs/guide.md
expect "release notes only (markdown)"             "false false false false" pull_request .github/release-notes/1.11.0.md
expect "release notes, non-markdown"               "true false false false"  pull_request .github/release-notes/assets/diagram.svg
expect "docs/ non-markdown asset"                  "true false false false"  pull_request docs/audits/diagram.png
expect "a shell gate no Rust job runs"             "true false false false"  pull_request scripts/ci/check-conflict-markers.sh scripts/ci/test-check-conflict-markers.sh
expect "release scripts"                           "true false false false"  pull_request scripts/release/create-release-line.sh
expect "CI-only mix plus docs"                     "true false false false"  pull_request scripts/ci/test-foo.sh CHANGELOG.md docs/x.png
expect "ci.yml itself (contract tests, #6115)"     "true false false false"  pull_request .github/workflows/ci.yml
expect "another workflow (contract tests)"         "true false false false"  pull_request .github/workflows/docker-publish.yml
expect "workflows plus CI scripts and docs"        "true false false false"  pull_request .github/workflows/release.yml scripts/ci/test-foo.sh scripts/release/x.sh docs/guide.md
expect "workflow plus backend code"                "true true false true"    pull_request .github/workflows/ci.yml backend/src/main.rs
expect ".github/scripts"                           "true false false false"  pull_request .github/scripts/floating-tag-plan.sh
expect "dependabot, CODEOWNERS, issue templates"   "true false false false"  pull_request .github/dependabot.yml .github/CODEOWNERS .github/ISSUE_TEMPLATE/bug_report.yml .github/actionlint.yaml
expect "coverage policy (sets the Rust verdict)"   "true false false true"   pull_request .github/coverage-gate.json
expect "duplication baseline"                      "true false false true"   pull_request .github/duplication-baseline.json
expect "a composite action could run in a Rust job" "true false false true"  pull_request .github/actions/setup/action.yml
expect "a .github file nobody listed"              "true false false true"   pull_request .github/new-thing.json
expect "a doc a Rust test reads"                   "true false false true"   pull_request docs/air-gapped.md
expect "another doc a Rust test reads"             "true false false true"   pull_request docs/security/scan-on-proxy.md
expect "rust-toolchain.toml"                       "true false false true"   pull_request rust-toolchain.toml
expect "toolchain setup script"                    "true false false true"   pull_request scripts/ci/setup-pinned-toolchain.sh
expect "nextest config (Tier 2 test groups)"       "true true false true"    pull_request .config/nextest.toml
expect "measured-build wrapper (Tier 2 build)"     "true true false true"    pull_request scripts/ci/run-measured-build.sh
expect "migration-ledger allowlist (not .sh)"      "true false false true"   pull_request scripts/ci/migration-ledger-allowlist.txt
expect "jscpd source prep (.py, coverage uses it)" "true false false true"   pull_request scripts/ci/jscpd-prepare-sources.py
expect "CI-only file plus backend code"            "true true false true"    pull_request scripts/ci/test-foo.sh backend/src/main.rs
expect "Cargo.lock"                                "true true true true"     pull_request Cargo.lock
expect "nested Cargo.toml"                         "true true true true"     pull_request backend/Cargo.toml
expect "anything unrecognised is a Rust input"     "true false false true"   pull_request docker/Dockerfile.backend
expect "a script in scripts/ but outside ci/"      "true false false true"   pull_request scripts/e2e-setup.sh
FAKE_GH_FAIL=1 expect "file listing fails -> full CI" "true true true true"  pull_request whatever
# A rename is classified by both of its paths: the old one left the tree.
TAB=$'\t'
expect "rename of a Rust source to .md"            "true true false true"    pull_request "backend/src/x.md${TAB}backend/src/x.rs"
expect "rename of Cargo.toml to .md"               "true true true true"     pull_request "notes/Cargo.md${TAB}Cargo.toml"
expect "rename between docs stays docs-only"       "false false false false" pull_request "docs/new.md${TAB}docs/old.md"
expect "rename of docs onto a Rust path"           "true true false true"    pull_request "backend/src/x.rs${TAB}docs/x.md"
many=(); for i in $(seq 1 2999); do many+=("docs/p$i.md"); done
expect "PR listing just under the 3000-file cap"   "false false false false" pull_request "${many[@]}"
many+=("docs/p3000.md")
expect "PR listing at the 3000-file cap -> full CI" "true true true true"   pull_request "${many[@]}"
many=(); for i in $(seq 1 1500); do many+=("docs/n$i.md${TAB}docs/o$i.md"); done
expect "1500 renames are 1500 files, not 3000 paths" "false false false false" pull_request "${many[@]}"

# expect_kv <label> <"key=value ..."> <event> [files...] -- any outputs.
expect_kv() {
  local label="$1" want="$2" event="$3"; shift 3
  if ! run_filter "$event" "$@"; then
    fail "$label: the step exited non-zero"; sed 's/^/        /' "$WORK/log" >&2; return
  fi
  local kv k v bad=""
  for kv in $want; do
    k="${kv%%=*}"; v="${kv#*=}"
    [ "$(get "$k")" = "$v" ] || bad="$bad $k=$(get "$k") (want $v)"
  done
  if [ -z "$bad" ]; then
    pass "$label"
  else
    fail "$label:$bad"; sed 's/^/        /' "$WORK/log" >&2
  fi
}

echo "ci.yml changes gate: the integration job's inputs (tests) and labels"
expect_kv "backend/src only: integration not needed"   "tests=false rust=true"  pull_request backend/src/main.rs
expect_kv "a backend/tests change"                     "tests=true"              pull_request backend/tests/age_gate_tests.rs
expect_kv "a migration"                                "tests=true backend=true" pull_request backend/migrations/200_x.sql
expect_kv "ci.yml itself"                              "tests=true"              pull_request .github/workflows/ci.yml
expect_kv "another workflow is not an integration input" "tests=false rust=false" pull_request .github/workflows/docker-publish.yml
expect_kv "Markdown under backend/tests/ is docs"      "tests=false code=false"  pull_request backend/tests/README.md
expect_kv "docs only"                                  "tests=false"             pull_request README.md
FAKE_GH_FAIL=1 expect_kv "file listing fails -> integration runs" "tests=true rust=true" pull_request whatever
expect_kv "no labels"                                  "ci_full=false ci_image=false" pull_request backend/src/main.rs
FAKE_LABELS="bug,ci:full" expect_kv "live label ci:full"      "ci_full=true ci_image=false" pull_request backend/src/main.rs
FAKE_LABELS="ci:image" expect_kv "live label ci:image"        "ci_full=false ci_image=true" pull_request backend/src/main.rs
FAKE_LABELS="ci:fullish,xci:image" expect_kv "labels match exactly" "ci_full=false ci_image=false" pull_request backend/src/main.rs
FAKE_LABELS_FAIL=1 PR_LABELS="ci:image,ci:full" \
  expect_kv "live label read fails -> the payload's labels" "ci_full=true ci_image=true" pull_request backend/src/main.rs

echo "ci.yml changes gate: workflow contract tests and ci:full (#6115)"
expect_kv "ci.yml: contract tests, no scan gate"       "workflow_contracts=true workflow_scan_gate=false rust=false" pull_request .github/workflows/ci.yml
expect_kv "docker-publish.yml: the scan gate target too" "workflow_contracts=true workflow_scan_gate=true rust=false" pull_request .github/workflows/docker-publish.yml
expect_kv "scripts only: no contract tests"            "workflow_contracts=false workflow_scan_gate=false rust=false" pull_request scripts/ci/test-foo.sh
expect_kv "backend code: contract flag off"            "workflow_contracts=false rust=true" pull_request backend/src/main.rs
expect_kv "workflow + backend: Rust jobs run"          "workflow_contracts=true rust=true" pull_request .github/workflows/ci.yml backend/src/main.rs
expect_kv "workflow README is docs"                    "workflow_contracts=false code=false" pull_request .github/workflows/README.md
FAKE_LABELS="ci:full" expect_kv "ci:full on a workflow PR runs the Rust jobs" "rust=true backend=true ci_full=true" pull_request .github/workflows/release.yml
FAKE_LABELS="ci:full" expect_kv "ci:full on a docs-only PR stays docs-only"   "code=false rust=false" pull_request README.md
FAKE_GH_FAIL=1 expect_kv "file listing fails -> contract flags on, Rust on" "rust=true workflow_contracts=true workflow_scan_gate=true" pull_request whatever
expect_kv "merge group, workflow only"                 "rust=false workflow_contracts=true" merge_group .github/workflows/ci.yml
expect_kv "workflow_dispatch: Rust jobs, no contract job" "rust=true workflow_contracts=false workflow_scan_gate=false" workflow_dispatch

echo "ci.yml changes gate: the scanner adapter's Go job (scanner_adapter, #4437)"
expect_kv "adapter Go source"                          "scanner_adapter=true"  pull_request docker/scanner-adapter/scan.go
expect_kv "adapter Dockerfile"                         "scanner_adapter=true"  pull_request docker/Dockerfile.scanner-adapter
expect_kv "ci.yml itself exercises the Go job"         "scanner_adapter=true"  pull_request .github/workflows/ci.yml
expect_kv "adapter README is docs"                     "scanner_adapter=false code=false" pull_request docker/scanner-adapter/README.md
expect_kv "backend code: no Go job"                    "scanner_adapter=false" pull_request backend/src/main.rs
expect_kv "another Dockerfile: no Go job"              "scanner_adapter=false" pull_request docker/Dockerfile.backend
FAKE_GH_FAIL=1 expect_kv "file listing fails -> Go job runs" "scanner_adapter=true" pull_request whatever
expect_kv "merge group, adapter source"                "scanner_adapter=true"  merge_group docker/scanner-adapter/server.go
expect_kv "merge group, docs only"                     "scanner_adapter=false" merge_group docs/guide.md
expect_kv "workflow_dispatch runs the Go job"          "scanner_adapter=true"  workflow_dispatch

echo "ci.yml changes gate: merge groups (classified from base..head)"
#                                                   code  backend manifest rust
expect "merge group, docs only"                    "false false false false" merge_group README.md docs/guide.md
expect "merge group, backend code"                 "true true false true"    merge_group backend/src/main.rs
expect "merge group, Cargo.lock"                   "true true true true"     merge_group Cargo.lock backend/src/main.rs
expect "merge group, CI-only scripts"              "true false false false"  merge_group scripts/ci/test-foo.sh
expect "merge group, rename of a Rust source to .md" "true true false true"  merge_group "backend/src/x.md${TAB}backend/src/x.rs"
expect_kv "merge group, backend code: tests off, integration still runs by event" "tests=false" merge_group backend/src/main.rs
FAKE_LABELS="ci:full,ci:image" expect_kv "merge group ignores labels" "ci_full=false ci_image=false" merge_group backend/src/main.rs
FAKE_COMPARE_FAIL=1 expect "merge group, compare fails -> full CI" "true true true true" merge_group backend/src/main.rs
FAKE_COMPARE_FAIL=1 expect_kv "merge group, compare fails -> tests too" "tests=true" merge_group backend/src/main.rs
MG_BASE_SHA="" expect "merge group without a base sha -> full CI" "true true true true" merge_group README.md
many=(); for i in $(seq 1 300); do many+=("docs/p$i.md"); done
expect "merge group listing at the 300-file cap -> full CI" "true true true true" merge_group "${many[@]}"

echo "ci.yml changes gate: pushes"
expect "workflow_dispatch runs everything"         "true true true true"     workflow_dispatch
FAKE_LABELS="ci:full" expect_kv "workflow_dispatch: tests on, no labels" "tests=true ci_full=false ci_image=false" workflow_dispatch
# The checkout of the tree script is push-only; without it the step fails open.
RUN_DIR="$WORK/empty"; mkdir -p "$RUN_DIR"
RUN_DIR="$RUN_DIR" expect "push without the tree script -> full CI" "true true true true" push
# A fake tree script stands in for resolve-verified-tree.sh (tested on its own).
fake_tree() {
  RUN_DIR="$WORK/fake-$1"; mkdir -p "$RUN_DIR/scripts/ci"
  printf '#!/usr/bin/env bash\n%s\n' "$2" > "$RUN_DIR/scripts/ci/resolve-verified-tree.sh"
}
fake_tree verified 'printf "verified=true\nreason=tree T proven by PR #42 at H\n"'
RUN_DIR="$RUN_DIR" expect "push, tree proven" "true true true false" push
RUN_DIR="$RUN_DIR" expect_kv "push: integration inputs always on" "tests=true" push
if grep -qx 'rust_skip_reason=tree T proven by PR #42 at H' "$WORK/out"; then
  pass "the proof is carried to CI Complete's summary"
else
  fail "rust_skip_reason missing: $(cat "$WORK/out")"
fi
fake_tree notverified 'printf "verified=false\nreason=r\n"'
RUN_DIR="$RUN_DIR" expect "push, not proven" "true true true true" push
fake_tree crash 'printf "verified=true\n"; exit 3'
RUN_DIR="$RUN_DIR" expect "push, tree script exits non-zero -> fail open" "true true true true" push
fake_tree garbage 'printf "verified=truish\nverified=true-ish\n"'
RUN_DIR="$RUN_DIR" expect "push, garbage verdict -> fail open" "true true true true" push

echo "ci.yml changes gate: every Rust-job input classifies as one"
unset RUN_DIR
n=0
while IFS= read -r ref; do
  [ -n "$ref" ] || continue
  n=$((n + 1))
  run_filter pull_request "$ref" || { fail "$ref: step failed"; continue; }
  if [ "$(get rust)" = true ]; then
    pass "$ref (used by: $(tr '\n' ' ' < "$WORK/gated.txt"))"
  else
    fail "$ref is executed by a Rust job but a PR changing only it would skip the Rust jobs; add it to the Rust-input arm of the changes gate"
  fi
done < "$WORK/refs.txt"
[ "$n" -gt 0 ] || fail "found no script references in the Rust jobs -- the extraction is broken"

echo "ci.yml changes gate: every file a backend test reads runs a test that reads it (#6115)"
# A path read from outside backend/ must make a PR run the Rust jobs, or be a
# workflow the Workflow Contract Tests job reads with the same test.
contract_if="$(cat "$WORK/contract_if.txt")"
case "$contract_if" in
  *"needs.changes.outputs.rust == 'false'"*"needs.changes.outputs.workflow_contracts != 'false'"*)
    pass "the contract job runs exactly when the Rust jobs skip and a workflow changed (fail-open)" ;;
  *) fail "workflow-contracts' condition lost a clause: $contract_if" ;;
esac
if [ "$(grep -c . "$WORK/contract_shards.txt")" = 1 ]; then
  contract_shard="$(cat "$WORK/contract_shards.txt")"
  pass "the contract job builds one shard ($contract_shard)"
else
  contract_shard=""
  fail "the contract job must build exactly one test shard: $(tr '\n' ' ' < "$WORK/contract_shards.txt")"
fi
# module_of backend/src/a/b.rs -> a::b ; a/mod.rs -> a
module_of() {
  local m="${1#backend/src/}"; m="${m%.rs}"; m="${m%/mod}"; printf '%s\n' "${m//\//::}"
}
covered_module() {
  local mod="$1" p
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    case "$mod" in "$p"|"$p"::*) return 0 ;; esac
  done < "$WORK/contract_modules.txt"
  return 1
}
n=0
while IFS=$'\t' read -r reader path; do
  [ -n "$reader" ] || continue
  n=$((n + 1))
  probe="$path"; [ "$path" = ".github/workflows/*" ] && probe=".github/workflows/zz-any.yml"
  run_filter pull_request "$probe" || { fail "$path: step failed"; continue; }
  if [ "$(get rust)" = true ]; then
    pass "$reader reads $path, a Rust input"
    continue
  fi
  if [ "$(get workflow_contracts)" != true ]; then
    fail "$reader reads $path, but a PR changing only $path runs no Rust test; add it to the Rust-input arm of the changes gate"
    continue
  fi
  case "$reader" in
    backend/src/*)
      mod="$(module_of "$reader")"
      gate="$(grep -oE 'ak_test_shard = "[a-z0-9-]+"' "$ROOT/$reader" | sort -u | sed 's/.*"\(.*\)"/\1/' | tr '\n' ' ')"
      if ! covered_module "$mod"; then
        fail "$reader ($mod) reads $path; add $mod to CONTRACT_FILTER in the workflow-contracts job"
      elif [ -n "$gate" ] && [ "$gate" != "$contract_shard " ]; then
        fail "$reader reads $path, but its tests are gated to shard(s) [$gate], not the contract job's $contract_shard"
      else
        pass "$reader reads $path; the contract job runs $mod"
      fi ;;
    backend/tests/*)
      target="$(basename "$reader" .rs)"
      if ! grep -qx "$target" "$WORK/contract_targets.txt"; then
        fail "$reader reads $path; add --test $target to the workflow-contracts job"
      elif [ "$(get workflow_scan_gate)" != true ]; then
        fail "$reader reads $path, but the contract job builds --test $target only when docker-publish.yml changes; widen workflow_scan_gate"
      else
        pass "$reader reads $path; the contract job runs --test $target"
      fi ;;
    *) fail "$reader reads $path; only backend/src and backend/tests readers can be covered by the contract job" ;;
  esac
done < "$WORK/readers.txt"
[ "$n" -gt 0 ] || fail "found no backend source reading a file outside backend/ -- the scan is broken"

echo "ci.yml CI Complete: skipped Rust jobs pass only when the gate said so"
# complete <label> <want rc 0|1> <event> <code> <backend> <rust> [RESULT_X=value ...]
# Every RESULT_* defaults to success and MANIFEST_CHANGED to false; the
# KEY=value arguments override either.
complete() {
  local label="$1" want="$2" event="$3" code="$4" backend="$5" rust="$6"; shift 6
  local -a envs=()
  while IFS= read -r k; do [ -n "$k" ] && envs+=("$k=success"); done < "$WORK/results.txt"
  envs+=("$@")
  local rc=0
  # From the repository root, as the job runs it: the step calls
  # scripts/ci/coverage-gate-decision.sh by relative path.
  ( cd "$ROOT" && env GITHUB_EVENT_NAME="$event" GITHUB_STEP_SUMMARY="$WORK/summary" \
      CODE_CHANGED="$code" BACKEND_CHANGED="$backend" MANIFEST_CHANGED=false BUMP_ONLY=false \
      RUST_CHANGED="$rust" RUST_SKIP_REASON="" "${envs[@]}" \
      bash --noprofile --norc -eo pipefail "$WORK/complete.sh" >/dev/null 2>&1 ) || rc=$?
  if [ "$rc" = "$want" ]; then pass "$label"; else fail "$label: CI Complete exited $rc, want $want"; sed 's/^/        /' "$WORK/summary" >&2; fi
  : > "$WORK/summary"
}
SKIP_RUST=(RESULT_CHECK_RUST=skipped RESULT_WINDOWS_CHECK=skipped RESULT_UNIT=skipped RESULT_COVERAGE=skipped)
complete "CI-only PR: skipped Rust jobs pass"                       0 pull_request true false false "${SKIP_RUST[@]}"
complete "Rust inputs changed: a skipped Check Rust fails"          1 pull_request true false true  "${SKIP_RUST[@]}"
complete "gate output missing: a skipped Check Rust fails"          1 pull_request true false ""    "${SKIP_RUST[@]}"
complete "CI-only PR: shell-tests must still succeed"               1 pull_request true false false "${SKIP_RUST[@]}" RESULT_SHELL=skipped
complete "CI-only PR: a failed Rust job still fails"                1 pull_request true false false RESULT_CHECK_RUST=failure
complete "proven push: skipped Rust jobs pass"                      0 push true true false "${SKIP_RUST[@]}" RESULT_VERSION_PIN=skipped
complete "unproven push: a skipped unit job fails"                  1 push true true true RESULT_UNIT=skipped RESULT_VERSION_PIN=skipped

echo "ci.yml CI Complete: the Windows cross-check (#6022)"
complete "Rust inputs changed: Windows check red -> fails"          1 pull_request true true true RESULT_WINDOWS_CHECK=failure
complete "Rust inputs changed: Windows check skipped -> fails"      1 pull_request true true true RESULT_WINDOWS_CHECK=skipped
complete "Rust inputs changed: Windows check cancelled -> fails"    1 pull_request true true true RESULT_WINDOWS_CHECK=cancelled
complete "gate output missing: Windows check skipped -> fails"      1 pull_request true false "" "${SKIP_RUST[@]}"
complete "merge group: Windows check red -> fails"                  1 merge_group true true true RESULT_VERSION_PIN=skipped RESULT_COVERAGE=skipped RESULT_WINDOWS_CHECK=failure
complete "unproven push: Windows check skipped -> fails"            1 push true true true RESULT_VERSION_PIN=skipped RESULT_WINDOWS_CHECK=skipped
complete "CI-only PR: a failed Windows check still fails"           1 pull_request true false false "${SKIP_RUST[@]}" RESULT_WINDOWS_CHECK=failure
complete "docs-only PR: Windows check skipped -> passes"            0 pull_request false false false "${SKIP_RUST[@]}" RESULT_SHELL=skipped RESULT_SECURITY=skipped
if grep -qx RESULT_WINDOWS_CHECK "$WORK/results.txt"; then
  pass "CI Complete reads the Windows cross-check's result"
else
  fail "CI Complete does not read RESULT_WINDOWS_CHECK"
fi

echo "ci.yml CI Complete: the Workflow Contract Tests (#6115)"
complete "workflow-only PR: contract tests green -> passes"          0 pull_request true false false "${SKIP_RUST[@]}" WORKFLOW_CONTRACTS=true
complete "workflow-only PR: contract tests red -> fails"             1 pull_request true false false "${SKIP_RUST[@]}" WORKFLOW_CONTRACTS=true RESULT_WORKFLOW_CONTRACTS=failure
complete "workflow-only PR: contract tests skipped -> fails"         1 pull_request true false false "${SKIP_RUST[@]}" WORKFLOW_CONTRACTS=true RESULT_WORKFLOW_CONTRACTS=skipped
complete "Rust skipped, workflow flag missing: skip -> fails"        1 pull_request true false false "${SKIP_RUST[@]}" WORKFLOW_CONTRACTS= RESULT_WORKFLOW_CONTRACTS=skipped
complete "scripts-only PR: contract tests skipped -> passes"         0 pull_request true false false "${SKIP_RUST[@]}" WORKFLOW_CONTRACTS=false RESULT_WORKFLOW_CONTRACTS=skipped
complete "Rust jobs ran: contract tests skipped -> passes"           0 pull_request true true true WORKFLOW_CONTRACTS=true RESULT_WORKFLOW_CONTRACTS=skipped
complete "Rust jobs ran, contract tests somehow red -> fails"        1 pull_request true true true WORKFLOW_CONTRACTS=true RESULT_WORKFLOW_CONTRACTS=failure
complete "proven push: contract tests skipped -> passes"             0 push true true false "${SKIP_RUST[@]}" RESULT_VERSION_PIN=skipped WORKFLOW_CONTRACTS=false RESULT_WORKFLOW_CONTRACTS=skipped
complete "docs-only PR: contract tests skipped -> passes"            0 pull_request false false false "${SKIP_RUST[@]}" RESULT_SHELL=skipped RESULT_SECURITY=skipped WORKFLOW_CONTRACTS=false RESULT_WORKFLOW_CONTRACTS=skipped

echo "ci.yml CI Complete: the Security Audit rule"
NOPIN=(RESULT_VERSION_PIN=skipped RESULT_COVERAGE=skipped)
complete "merge group, audit red, manifest unchanged -> advisory"   0 merge_group true true true "${NOPIN[@]}" RESULT_SECURITY=failure
complete "merge group, audit red, manifest changed -> blocks"       1 merge_group true true true "${NOPIN[@]}" RESULT_SECURITY=failure MANIFEST_CHANGED=true
complete "merge group, audit red, manifest unknown -> blocks"       1 merge_group true true true "${NOPIN[@]}" RESULT_SECURITY=failure MANIFEST_CHANGED=
complete "PR, audit red, manifest unchanged -> advisory"            0 pull_request true true true RESULT_SECURITY=failure
complete "PR, audit red, manifest changed -> blocks"                1 pull_request true true true RESULT_SECURITY=failure MANIFEST_CHANGED=true
complete "push, audit red -> blocks"                                1 push true true true "${NOPIN[@]}" RESULT_SECURITY=failure
complete "dispatch, audit red -> blocks (manifest is always true)"  1 workflow_dispatch true true true "${NOPIN[@]}" RESULT_SECURITY=failure MANIFEST_CHANGED=true

echo "ci.yml CI Complete: merge groups"
complete "merge group, all green, PR-only gates skipped -> passes"  0 merge_group true true true "${NOPIN[@]}"
complete "merge group, a failed Backend Unit Tests -> fails"        1 merge_group true true true "${NOPIN[@]}" RESULT_UNIT=failure
complete "merge group, a skipped Check Rust with Rust inputs -> fails" 1 merge_group true true true "${NOPIN[@]}" RESULT_CHECK_RUST=skipped
complete "merge group, docs-only group -> passes"                   0 merge_group false false false "${NOPIN[@]}" "${SKIP_RUST[@]}" RESULT_SHELL=skipped RESULT_SECURITY=skipped
complete "PR, a skipped version-pin gate still fails"               1 pull_request true true true RESULT_VERSION_PIN=skipped

echo "ci.yml CI Complete: the scanner adapter's Go job (#4437)"
complete "PR, no adapter input: Go job skipped -> passes"           0 pull_request true true true SCANNER_ADAPTER_CHANGED=false RESULT_SCANNER_ADAPTER=skipped
complete "PR, adapter changed: Go job skipped -> fails"             1 pull_request true true true SCANNER_ADAPTER_CHANGED=true RESULT_SCANNER_ADAPTER=skipped
complete "PR, gate output missing: Go job skipped -> fails"         1 pull_request true true true SCANNER_ADAPTER_CHANGED= RESULT_SCANNER_ADAPTER=skipped
complete "PR, adapter changed: Go job red -> fails"                 1 pull_request true true true SCANNER_ADAPTER_CHANGED=true RESULT_SCANNER_ADAPTER=failure
complete "PR, no adapter input, yet Go job red -> fails"            1 pull_request true true true SCANNER_ADAPTER_CHANGED=false RESULT_SCANNER_ADAPTER=failure
complete "PR, adapter changed: Go job green -> passes"              0 pull_request true true true SCANNER_ADAPTER_CHANGED=true
# The image jobs are not inputs any more: a red image result cannot reach it.
if grep -q 'RESULT_SMOKE\|RESULT_BUILD_BACKEND\|RESULT_BUILD_OPENSCAP' "$WORK/results.txt"; then
  fail "CI Complete still reads an image-job result: $(tr '\n' ' ' < "$WORK/results.txt")"
else
  pass "CI Complete reads no image-job result"
fi

echo "ci.yml Backend Unit Tests: the integration job may skip only by design"
# unit <label> <want rc> <shards> <integration> <wanted>
unit() {
  local label="$1" want="$2" rc=0
  ( RESULT_SHARDS="$3" RESULT_INTEGRATION="$4" INTEGRATION_WANTED="$5" \
      bash --noprofile --norc -eo pipefail "$WORK/unit.sh" >"$WORK/log" 2>&1 ) || rc=$?
  if [ "$rc" = "$want" ]; then pass "$label"; else fail "$label: exited $rc, want $want"; sed 's/^/        /' "$WORK/log" >&2; fi
}
unit "PR without test changes: integration skipped by design -> passes" 0 success skipped false
unit "integration wanted but skipped -> fails"                          1 success skipped true
unit "wanted unknown (gate died) and skipped -> fails"                  1 success skipped ""
unit "integration green"                                                0 success success true
unit "integration red"                                                  1 success failure true
unit "integration cancelled though not wanted -> fails"                 1 success cancelled false
unit "a failing unit shard -> fails"                                    1 failure success true
unit "a failing unit shard with integration skipped by design -> fails" 1 failure skipped false
unit "a skipped shard -> fails"                                         1 skipped skipped false
# INTEGRATION_WANTED must be the integration job's own condition, verbatim:
# if the two drift, a skip could pass that the job did not intend.
wanted="$(cat "$WORK/wanted.txt")"
if [ -n "$wanted" ] && grep -qF "&& (${wanted}) }}" "$WORK/integ_if.txt"; then
  pass "INTEGRATION_WANTED is the integration job's own condition"
else
  fail "INTEGRATION_WANTED [$wanted] is not the trailing clause of the integration job's if: $(cat "$WORK/integ_if.txt")"
fi
case "$wanted" in
  *"github.event_name == 'merge_group'"*"needs.changes.outputs.tests != 'false'"*"needs.changes.outputs.ci_full == 'true'"*)
    pass "the integration condition covers merge_group, the tests filter (fail-open) and ci:full" ;;
  *) fail "the integration condition lost a clause: $wanted" ;;
esac

echo "ci.yml merge path: layout"
fact() { sed -n "s/^$1=//p" "$WORK/facts.txt"; }
want_fact() {
  if [ "$(fact "$1")" = "$2" ]; then pass "$3"; else fail "$3: $1=$(fact "$1"), want $2"; fi
}
want_fact trigger_merge_group true "ci.yml triggers on merge_group (required checks must report in the queue)"
for j in check-rust windows-cross-check test-backend-integration test-backend-unit ci-complete; do
  want_fact "runs_on_$j" ubuntu-24.04 "$j runs on pinned GitHub-hosted ubuntu-24.04"
done
for j in smoke-e2e build-backend-image build-openscap-image; do
  want_fact "cc_needs_$j" false "CI Complete does not wait for advisory $j"
done
want_fact cc_needs_windows-cross-check false "CI Complete does not wait for the Windows cross-check while it is advisory (#6022)"
want_fact windows_if_matches_check_rust true "the Windows cross-check's condition is Check Rust's, verbatim"
want_fact ubuntu_latest false "no job floats on ubuntu-latest"
want_fact cache_saves_off_main none "every rust-cache saves only outside pull requests and merge groups"
# ci_test_surface reads every `--test <name>` in the workflow text, comments
# included, as a target: a dangling one turns the contract tests red, and on
# a workflow-only PR nothing else would show it before they run.
dangling=""
while IFS= read -r t; do
  [ -n "$t" ] && [ ! -f "$ROOT/backend/tests/$t.rs" ] && dangling="$dangling $t"
done < <(grep -oE -- '--test [A-Za-z0-9_]+' "$WORKFLOW" | awk '{print $2}' | sort -u)
if [ -z "$dangling" ]; then
  pass "every --test name in ci.yml is a backend/tests target"
else
  fail "ci.yml names --test targets with no backend/tests/<name>.rs (comments count):$dangling"
fi

echo
if [ "$fails" -gt 0 ]; then
  echo "ci.yml changes gate: $fails case(s) FAILED"
  exit 1
fi
echo "ci.yml changes gate: all cases passed"
