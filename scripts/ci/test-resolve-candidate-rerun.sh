#!/usr/bin/env bash
#
# Self-test for scripts/ci/resolve-candidate-rerun.sh (issue #6076).
#
# WHY THIS EXISTS
#   The resolver decides what a Release Candidate rerun runs and whether it may
#   run at all. Its dangerous direction is fail-OPEN: rerunning the wrong
#   commit, following up a run that is not a real candidate, trusting a record
#   some later job replaced, or leaving a failed group out of the rerun so the
#   certification covers a group nobody passed. Each of those is constructed
#   here and must BLOCK. The happy path pins the exact only_jobs tokens,
#   including both shapes of a dtf-gate leg's job name.
#
# HOW
#   The resolver reaches GitHub only through `gh`, so a stub `gh` first on
#   PATH answers from fixture files the cases write. No network, ~1s.
#
# Usage: bash scripts/ci/test-resolve-candidate-rerun.sh
set -uo pipefail

RESOLVER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/resolve-candidate-rerun.sh"
[ -f "$RESOLVER" ] || { echo "cannot find resolve-candidate-rerun.sh next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

REPO=artifact-keeper/artifact-keeper
OF=43891235522
SELF=43999999999
SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
GATE_A=0495cf0389b14ecb63bc62b510d58e9c33425d6c
GATE_B=1111111111111111111111111111111111111111
TESTS_SHA=2222222222222222222222222222222222222222
NOW="$(date -u -d 2026-11-16T18:00:00Z +%s)"
F="$WORK/fixtures"; mkdir -p "$F"

# --- gh stub -----------------------------------------------------------------
STUB="$WORK/bin"; mkdir -p "$STUB"
cat > "$STUB/gh" <<'STUBGH'
#!/usr/bin/env bash
F="$FAKE_DIR"
if [ "$1" = run ] && [ "$2" = download ]; then
  rid="$3"; dir=""; while [ $# -gt 0 ]; do [ "$1" = --dir ] && dir="$2"; shift; done
  src="$F/record.json"; [ "$rid" = "$FAKE_OF" ] || src="$F/record_${rid}.json"
  [ -f "$src" ] || exit 1
  cp "$src" "$dir/record.json"; exit 0
fi
[ "$1" = api ] || exit 1
shift
path=""; filter=""
while [ $# -gt 0 ]; do
  case "$1" in
    --paginate) ;;
    --jq) filter="$2"; shift ;;
    *) path="$1" ;;
  esac
  shift
done
[ "${FAKE_API_FAIL-}" = 1 ] && { echo "HTTP 502" >&2; exit 1; }
case "$path" in
  */actions/runs/"$FAKE_OF"/attempts/1/jobs*) file="$F/orig_jobs.json" ;;
  */actions/runs/"$FAKE_SELF"/jobs*)          file="$F/self_jobs.json" ;;
  */actions/runs/"$FAKE_OF"/attempts/1)       file="$F/orig_run.json" ;;
  */actions/runs/"$FAKE_OF"/artifacts*)       file="$F/arts.json" ;;
  */actions/runs/"$FAKE_SELF")                file="$F/self_run.json" ;;
  */contents/*ref=*)                          file="$F/blob_${path##*ref=}.json" ;;
  */actions/workflows/release-candidate.yml/runs*) file="$F/runs.json" ;;
  */actions/runs/*/artifacts*) rid="${path#*/actions/runs/}"; file="$F/arts_${rid%%/*}.json" ;;
  */actions/runs/*)            file="$F/run_${path##*/actions/runs/}.json" ;;
  *) echo "stub: unexpected path $path" >&2; exit 1 ;;
esac
[ -f "$file" ] || { echo "HTTP 404 $path" >&2; exit 1; }
if [ -n "$filter" ]; then jq -r "$filter" "$file"; else cat "$file"; fi
STUBGH
chmod +x "$STUB/gh"

G="Release Gate (Full Suite)"
job() { jq -nc --arg n "$1" --arg c "$2" --arg t "${3:-2026-11-16T16:00:00Z}" '{name: $n, conclusion: $c, completed_at: $t}'; }

reset_case() {
  rm -f "$F"/*
  jq -n --arg r "$REPO" --arg g "$GATE_A" '{
    repository: {full_name: $r}, head_repository: {full_name: $r},
    path: ".github/workflows/release-candidate.yml", event: "workflow_dispatch",
    head_branch: "main", status: "completed", conclusion: "failure",
    created_at: "2026-11-16T14:57:22Z", triggering_actor: {login: "brandonrc"},
    referenced_workflows: [{path: "artifact-keeper/artifact-keeper-test/.github/workflows/release-gate.yml@main", sha: $g, ref: "refs/heads/main"}]
  }' > "$F/orig_run.json"
  jq -n --arg g "$GATE_A" '{referenced_workflows: [{path: "artifact-keeper/artifact-keeper-test/.github/workflows/release-gate.yml@main", sha: $g}]}' > "$F/self_run.json"
  {
    job "Resolve the commit and its version" success
    job "Wait for a successful Docker Publish run" success
    job "Require a green Release Preflight for this commit" success
    job "Release bookkeeping for the commit" success
    job "Resolve the commit's published images" success
    job "Record what this candidate tests" success 2026-11-16T14:59:00Z
    job "Certify the commit" skipped
    job "Refuse a re-run of the gate" skipped
    job "$G / version-set-integrity" success
    job "$G / clean-install-smoke-with-deps" skipped
    job "$G / webhook-tests" success
    job "$G / collect-results" failure
    job "$G / dtf-gate (core, smoke isolation)" success
    job "$G / dtf-gate (storage-1.11.0, quota-native-and-rpm-races maven-upload-tx-and-quality-s3 s3-copy-lengt..." failure
    job "$G / dtf-gate (conda-1.11.0-b)" failure
    job "$G / format-tests (jvm)" success
    job "$G / format-tests (python)" cancelled
  } | jq -s '{jobs: .}' > "$F/orig_jobs.json"
  {
    job "$G / version-set-integrity" success
    job "$G / dtf-gate (core)" success
    job "$G / dtf-gate (storage-1.11.0)" success
    job "$G / collect-results" success
  } | jq -s '{jobs: .}' > "$F/self_jobs.json"
  jq -n '{artifacts: [{name: "release-candidate-record", expired: false, created_at: "2026-11-16T14:58:59Z"}]}' > "$F/arts.json"
  jq -n --arg s "$SHA" --arg run "$OF" --arg t "$TESTS_SHA" \
    '{commit_sha: $s, candidate_run_id: $run, gate_scope: "full", tests: {sha: $t, branch: "main"},
      digests: {backend: "sha256:b", openscap: "sha256:o", scanner_adapter: "sha256:a"}}' > "$F/record.json"
  echo '{"sha":"blobA"}' > "$F/blob_${GATE_A}.json"
  # Candidate runs since the original: the original and this run only.
  jq -n --argjson a "$OF" --argjson b "$SELF" '{workflow_runs: [{id: $a}, {id: $b}]}' > "$F/runs.json"
  CASE_TESTS=same; CASE_SHA="$SHA"; CASE_OF="$OF"; CASE_MODE=resolve; FAKE_API_FAIL=0
}

# expect <label> <exit> <substring>
expect() {
  local label="$1" want="$2" needle="$3" got=0
  ( PATH="$STUB:$PATH" FAKE_DIR="$F" FAKE_OF="$OF" FAKE_SELF="$SELF" FAKE_API_FAIL="$FAKE_API_FAIL" \
      RERUN_REPO="$REPO" RERUN_OF="$CASE_OF" RERUN_SHA="$CASE_SHA" RERUN_TESTS="$CASE_TESTS" \
      RERUN_SELF_RUN_ID="$SELF" RERUN_NOW="$NOW" GITHUB_OUTPUT='' \
      bash "$RESOLVER" "$CASE_MODE" >"$WORK/out.txt" 2>&1 ) || got=$?
  if [ "$got" != "$want" ]; then
    fail "$label: expected exit $want, got $got"; sed 's/^/        /' "$WORK/out.txt" >&2
  elif ! grep -qF -- "$needle" "$WORK/out.txt"; then
    fail "$label: exit $got correct but output lacks '$needle'"; sed 's/^/        /' "$WORK/out.txt" >&2
  else
    pass "$label (exit $got)"
  fi
}
edit() { local f="$F/$1"; jq "$2" "$f" > "$f.new" && mv "$f.new" "$f"; }
edit_jobs() { local f="$F/orig_jobs.json"; jq -c ".jobs |= ($1)" "$f" > "$f.new" && mv "$f.new" "$f"; }

echo "candidate rerun resolver: what the rerun runs"
reset_case
expect "selects every non-success gate job and leg, by token" 0 \
  "rerun_jobs=clean-install-smoke-with-deps collect-results dtf-gate/conda-1.11.0-b dtf-gate/storage-1.11.0 format-tests"
expect "same mode pins the original's tests tree" 0 "pin_tests_sha=${TESTS_SHA}"
expect "same mode, unchanged gate" 0 "gate_changed=false"
expect "the original's actor is reported" 0 "original_actor=brandonrc"

echo "candidate rerun resolver: which tests"
reset_case; edit self_run.json ".referenced_workflows[0].sha = \"$GATE_B\""; echo '{"sha":"blobA"}' > "$F/blob_${GATE_B}.json"
expect "test repo moved but release-gate.yml is byte-identical: still same" 0 "gate_changed=false"
reset_case; edit self_run.json ".referenced_workflows[0].sha = \"$GATE_B\""; echo '{"sha":"blobB"}' > "$F/blob_${GATE_B}.json"
expect "release-gate.yml changed, tests=same -> BLOCKED" 1 "dispatch again with tests=moved"
CASE_TESTS=moved
expect "release-gate.yml changed, tests=moved -> allowed and flagged" 0 "gate_changed=true"
expect "tests=moved pins nothing" 0 "pin_tests_sha="$'\n'
reset_case; CASE_TESTS=sideways
expect "an unknown tests mode -> BLOCKED" 1 "tests must be 'same' or 'moved'"

echo "candidate rerun resolver: the original must be a failed candidate"
reset_case; edit orig_run.json '.conclusion = "success"'
expect "original succeeded -> BLOCKED" 1 "nothing to rerun"
reset_case; edit orig_run.json '.status = "in_progress"'
expect "original still running -> BLOCKED" 1 "has not completed"
reset_case; edit orig_run.json '.path = ".github/workflows/ci.yml"'
expect "a run of another workflow -> BLOCKED" 1 "not .github/workflows/release-candidate.yml"
reset_case; edit orig_run.json '.head_branch = "release/1.11.x"'
expect "a dispatch on another branch -> BLOCKED" 1 "only a dispatch on main"
reset_case; edit orig_run.json '.event = "push"'
expect "not a dispatch -> BLOCKED" 1 "only a dispatch on main"
reset_case; edit orig_run.json '.head_repository.full_name = "someone/artifact-keeper"'
expect "a fork's run -> BLOCKED" 1 "is not a run of"
reset_case; edit orig_run.json '.created_at = "2026-11-12T14:57:22Z"'
expect "older than 72 h -> BLOCKED" 1 "more than 72 h ago"
reset_case; CASE_OF="$SELF"
expect "rerun_of names this run -> BLOCKED" 1 "names this run"
reset_case; CASE_OF="4389x"
expect "rerun_of not digits -> BLOCKED" 1 "must be a run id"
reset_case; CASE_SHA="${SHA:0:7}"
expect "a short sha -> BLOCKED" 1 "full 40-hex sha"

echo "candidate rerun resolver: its jobs"
reset_case; edit_jobs '(.[] | select(.name == "Resolve the commit'"'"'s published images") | .conclusion) = "failure"'
expect "images did not resolve -> BLOCKED" 1 "'Resolve the commit's published images' is 'failure'"
reset_case; edit_jobs 'map(select(.name != "Record what this candidate tests"))'
expect "a candidate from before #6076 (no record job) -> BLOCKED" 1 "'Record what this candidate tests' is 'absent'"
reset_case; edit_jobs '(.[] | select(.name == "Certify the commit") | .conclusion) = "success"'
expect "original certified -> BLOCKED" 1 "already certified"
reset_case; edit_jobs 'map(select(.name | startswith("Release Gate") | not))'
expect "the gate never ran -> BLOCKED" 1 "the gate never ran"
reset_case; edit_jobs 'map(if (.name | startswith("Release Gate")) then .conclusion = "success" else . end)'
expect "every gate job green (failure elsewhere) -> BLOCKED" 1 "outside the gate"

echo "candidate rerun resolver: its record"
reset_case; echo '{"artifacts": []}' > "$F/arts.json"
expect "no record -> BLOCKED" 1 "exactly one 'release-candidate-record'"
reset_case; edit arts.json '.artifacts += .artifacts'
expect "two records -> BLOCKED" 1 "exactly one 'release-candidate-record'"
reset_case; edit arts.json '.artifacts[0].created_at = "2026-11-16T16:40:00Z"'
expect "record replaced after the record job (by a gate job) -> BLOCKED" 1 "is not the record that job wrote"
reset_case; edit arts.json '.artifacts[0].expired = true'
expect "record expired -> BLOCKED" 1 "has expired"
reset_case; edit record.json '.commit_sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"'
expect "the original tested another commit -> BLOCKED" 1 "A rerun certifies the same commit"
reset_case; edit record.json '.gate_scope = "rerun" | .rerun.of = "1"'
expect "the original was itself a rerun -> BLOCKED" 1 "was itself a rerun"
reset_case; edit record.json '.candidate_run_id = "1"'
expect "a record naming another run -> BLOCKED" 1 "record names run '1'"
reset_case; rm "$F/record.json"
expect "record unreadable -> INFRA" 2 "INFRA"

echo "candidate rerun resolver: at most one rerun per candidate"
# prior_run <id> <conclusion> <record jq or 'none'>: an earlier dispatch since the original
prior_run() {
  local id="$1" conc="$2" rec="$3"
  jq --argjson id "$id" '.workflow_runs += [{id: $id}]' "$F/runs.json" > "$F/runs.new" && mv "$F/runs.new" "$F/runs.json"
  jq -n --arg c "$conc" '{conclusion: $c, status: "completed"}' > "$F/run_${id}.json"
  if [ "$rec" = none ]; then
    echo '{"artifacts": []}' > "$F/arts_${id}.json"
  else
    echo '{"artifacts": [{"name": "release-candidate-record"}]}' > "$F/arts_${id}.json"
    jq -n "$rec" > "$F/record_${id}.json"
  fi
}
reset_case; prior_run 43900000001 failure "{gate_scope: \"rerun\", rerun: {of: \"$OF\"}}"
expect "an earlier rerun of this original that failed -> BLOCKED" 1 "has already been rerun once, by run 43900000001 (failure)"
expect "the refusal says to dispatch a fresh candidate" 1 "dispatch a fresh Release Candidate"
reset_case; prior_run 43900000002 cancelled "{gate_scope: \"rerun\", rerun: {of: \"$OF\"}}"
expect "an earlier rerun that was cancelled still counts -> BLOCKED" 1 "by run 43900000002 (cancelled)"
reset_case; prior_run 43900000003 success "{gate_scope: \"rerun\", rerun: {of: \"$OF\"}}"
expect "an earlier rerun that certified -> BLOCKED" 1 "has already been rerun once"
reset_case; prior_run 43900000004 failure "{gate_scope: \"rerun\", rerun: {of: \"43800000000\"}}"
expect "a rerun of a DIFFERENT original does not count" 0 "rerun_jobs="
reset_case; prior_run 43900000005 failure '{gate_scope: "full", rerun: null}'
expect "a later full candidate on the same commit does not count" 0 "rerun_jobs="
reset_case; prior_run 43900000006 failure none
expect "a dispatch refused before its record (no gate ran) does not count" 0 "rerun_jobs="
reset_case; prior_run 43900000007 failure '{gate_scope: "full", rerun: null}'; prior_run 43900000008 failure "{gate_scope: \"rerun\", rerun: {of: \"$OF\"}}"
expect "the earlier rerun is found among other runs -> BLOCKED" 1 "by run 43900000008"

echo "candidate rerun resolver: infra is never a pass"
reset_case; FAKE_API_FAIL=1
expect "API down -> INFRA" 2 "INFRA"

echo "candidate rerun resolver: coverage (certify)"
reset_case; CASE_MODE=coverage
expect "every gate job of the rerun ran in the original" 0 "also ran in the original"
edit self_jobs.json ".jobs += [$(job "$G / dtf-gate (brand-new-group)" success), $(job "$G / brand-new-tests" success)]"
expect "a gate job or leg the original never ran -> BLOCKED" 1 "brand-new-tests dtf-gate/brand-new-group"
# #6163, the first real rerun (44106249514): only_jobs named a suite and no
# dtf-gate leg, so GitHub listed the whole matrix as ONE skipped job with its
# name unexpanded. It is not a leg and must not refuse certification.
reset_case; CASE_MODE=coverage
printf '%s' '{"jobs":[]}' > "$F/self_jobs.json"
edit self_jobs.json ".jobs += [$(job "$G / version-set-integrity" success), $(job "$G / webhook-tests" success), $(job "$G / collect-results" success), $(job "$G / dtf-gate (\${{ matrix.group }})" skipped)]"
expect "suite-only rerun: the skipped unexpanded dtf-gate matrix is not a new leg" 0 "also ran in the original"
# ...but only the PLACEHOLDER is dropped. A real job the gate gained since the
# original, skipped by this rerun, was tested by neither run: still refused.
edit self_jobs.json ".jobs += [$(job "$G / brand-new-tests" skipped)]"
expect "a skipped job the original never ran is still BLOCKED" 1 "brand-new-tests"
# ...nor a skipped dtf-gate LEG the original never ran (the matrix expanded),
reset_case; CASE_MODE=coverage
edit self_jobs.json ".jobs += [$(job "$G / dtf-gate (brand-new-group)" skipped)]"
expect "a skipped dtf-gate leg the original never ran is still BLOCKED" 1 "dtf-gate/brand-new-group"
# ...nor ANOTHER matrix skipped as a whole: only the dtf-gate placeholder is
# dropped, by its exact name.
reset_case; CASE_MODE=coverage
edit self_jobs.json ".jobs += [$(job "$G / brand-new-matrix (\${{ matrix.x }})" skipped)]"
expect "another unexpanded matrix the original never ran is still BLOCKED" 1 "brand-new-matrix"

if [ "$fails" -ne 0 ]; then
  echo "candidate rerun resolver: $fails case(s) FAILED"
  exit 1
fi
echo "candidate rerun resolver: all cases passed"
