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
#   in the gate fails here. Last, CI Complete's own step is run against job
#   results to prove a gate-skipped Rust job passes there, and only then.
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
open(f'{work}/refs.txt', 'w').write('\n'.join(sorted(refs)) + '\n')
PY

grep -q . "$WORK/gated.txt" || { fail "no job in ci.yml is gated on needs.changes.outputs.rust"; }
for required in check-rust test-backend-unit; do
  grep -qx "$required" "$WORK/gated.txt" \
    || fail "required job $required is not gated on needs.changes.outputs.rust"
done

# --- stub gh: the pulls/files listing ---------------------------------------
STUB="$WORK/bin"; mkdir -p "$STUB"
cat > "$STUB/gh" <<'STUBGH'
#!/usr/bin/env bash
[ "${FAKE_GH_FAIL-0}" = 1 ] && exit 1
case "$*" in
  *pulls/*/files*) printf '%s\n' "${FAKE_FILES-}" ;;
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
expect "ci.yml itself"                             "true true false true"    pull_request .github/workflows/ci.yml
expect "another workflow (Rust tests read them)"   "true false false true"   pull_request .github/workflows/docker-publish.yml
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

echo "ci.yml changes gate: pushes"
expect "workflow_dispatch runs everything"         "true true true true"     workflow_dispatch
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

# The Rust test suite reads workflow files directly (ci_test_surface.rs,
# config.rs, workflow_scan_gate_tests.rs). While it does, a workflow-only PR
# must run the Rust jobs.
if grep -rqE '\.github/workflows|join\("\.github"\)' "$ROOT/backend/src" "$ROOT/backend/tests" 2>/dev/null; then
  run_filter pull_request .github/workflows/stale.yml
  if [ "$(get rust)" = true ]; then
    pass "workflow files are Rust inputs while backend tests read .github/workflows"
  else
    fail "backend tests read .github/workflows, yet a workflow-only PR skips the Rust jobs"
  fi
fi

echo "ci.yml CI Complete: skipped Rust jobs pass only when the gate said so"
# complete <label> <want rc 0|1> <event> <code> <backend> <rust> [RESULT_X=value ...]
# Every RESULT_* defaults to success; the arguments override.
complete() {
  local label="$1" want="$2" event="$3" code="$4" backend="$5" rust="$6"; shift 6
  local -a envs=()
  while IFS= read -r k; do [ -n "$k" ] && envs+=("$k=success"); done < "$WORK/results.txt"
  envs+=("$@")
  local rc=0
  # From the repository root, as the job runs it: the step calls
  # scripts/ci/coverage-gate-decision.sh by relative path.
  ( cd "$ROOT" && env "${envs[@]}" GITHUB_EVENT_NAME="$event" GITHUB_STEP_SUMMARY="$WORK/summary" \
      CODE_CHANGED="$code" BACKEND_CHANGED="$backend" MANIFEST_CHANGED=false BUMP_ONLY=false \
      RUST_CHANGED="$rust" RUST_SKIP_REASON="" \
      bash --noprofile --norc -eo pipefail "$WORK/complete.sh" >/dev/null 2>&1 ) || rc=$?
  if [ "$rc" = "$want" ]; then pass "$label"; else fail "$label: CI Complete exited $rc, want $want"; sed 's/^/        /' "$WORK/summary" >&2; fi
  : > "$WORK/summary"
}
SKIP_RUST=(RESULT_CHECK_RUST=skipped RESULT_UNIT=skipped RESULT_COVERAGE=skipped RESULT_SMOKE=skipped)
complete "CI-only PR: skipped Rust jobs pass"                       0 pull_request true false false "${SKIP_RUST[@]}"
complete "Rust inputs changed: a skipped Check Rust fails"          1 pull_request true false true  "${SKIP_RUST[@]}"
complete "gate output missing: a skipped Check Rust fails"          1 pull_request true false ""    "${SKIP_RUST[@]}"
complete "CI-only PR: shell-tests must still succeed"               1 pull_request true false false "${SKIP_RUST[@]}" RESULT_SHELL=skipped
complete "CI-only PR: a failed Rust job still fails"                1 pull_request true false false RESULT_CHECK_RUST=failure
complete "proven push: skipped Rust jobs pass"                      0 push true true false "${SKIP_RUST[@]}" RESULT_VERSION_PIN=skipped
complete "unproven push: a skipped unit job fails"                  1 push true true true RESULT_UNIT=skipped RESULT_VERSION_PIN=skipped

echo
if [ "$fails" -gt 0 ]; then
  echo "ci.yml changes gate: $fails case(s) FAILED"
  exit 1
fi
echo "ci.yml changes gate: all cases passed"
