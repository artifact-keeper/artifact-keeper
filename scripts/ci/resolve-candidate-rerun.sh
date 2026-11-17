#!/usr/bin/env bash
#
# Decide what a Release Candidate RERUN may run, from the run it follows up
# (issue #6076).
#
# WHY THIS EXISTS
#   A candidate refuses "Re-run failed jobs" (#3774): GitHub replays the gate's
#   attempt-1 `deploy` outputs, and the re-run would skip `Certify the commit`.
#   That guard stays. A rerun is instead a NEW dispatch of release-candidate.yml
#   with `rerun_of=<original run id>` and a reason. It re-resolves everything a
#   fresh candidate does (commit, preflight, bookkeeping, images) and then runs
#   only the gate jobs, and the single dtf-gate legs, that did not pass in the
#   original, through the gate's `only_jobs` input (artifact-keeper-test#830).
#   This script reads the original and says what that set is.
#
# WHAT IT TRUSTS, AND WHY
#   * The original run's identity, attempt-1 conclusion, job list and job
#     conclusions come from the Actions API: GitHub writes them, no job can.
#   * Which tests ran comes from the run's `referenced_workflows` (GitHub's
#     record of the release-gate.yml commit the run resolved) and from the
#     original's `release-candidate-record` artifact (tests sha and branch, the
#     digests it tested). Any job of a run can upload an artifact to it, so the
#     record is accepted only when it is the ONLY one of that name and was
#     created no later than the original's `Record what this candidate tests`
#     job completed: that job runs before any gate job exists, and replacing
#     the artifact later (upload-artifact `overwrite`) gives it a later
#     created_at. The rerun also re-resolves the digests itself and refuses
#     when they differ from the record (release-candidate.yml, `record`).
#
# WHAT IS REFUSED
#   * an original that is not a dispatch of THIS workflow on main in this
#     repository, did not complete, or did not FAIL on attempt 1;
#   * an original older than RERUN_MAX_AGE_HOURS (the gate's chart, web image
#     and runners float between runs; a rerun recovers a flake, it does not
#     assemble a certification over a week);
#   * an original whose pre-gate jobs did not all succeed, whose gate never
#     ran, or that certified anyway;
#   * an original that was itself a rerun: a rerun always names the full run;
#   * an original that has ALREADY been rerun: at most one rerun per candidate.
#     Any earlier dispatch of this workflow whose release-candidate-record says
#     `rerun.of` = this original counts, whatever its conclusion: a failed or
#     cancelled rerun still used up the one allowed. (The candidate's
#     concurrency group is keyed by the sha, so two reruns of one original
#     cannot overlap: the second starts only once the first has finished, by
#     which time its record exists if its gate ever started.);
#   * a different commit than the one dispatched;
#   * in `tests=same` mode, a release-gate.yml whose content changed since the
#     original (dispatch with `tests=moved` to accept that, recorded);
#   * nothing to rerun (the failure was outside the gate: dispatch afresh).
#
# MODES
#   resolve (default)  prints the key=value lines below (and appends them to
#                      GITHUB_OUTPUT when set)
#   coverage           run by `certify`: every gate job or dtf-gate leg of
#                      THIS run must also exist in the original, so a group the
#                      gate gained since (tests=moved) cannot go untested
#
# Env:
#   RERUN_REPO           owner/name (default artifact-keeper/artifact-keeper)
#   RERUN_OF             the original run id (digits)
#   RERUN_SHA            the 40-hex commit this rerun certifies
#   RERUN_TESTS          same | moved
#   RERUN_SELF_RUN_ID    this run's id
#   RERUN_MAX_AGE_HOURS  default 72
#   RERUN_NOW            epoch seconds (tests only; default now)
#   RERUN_GATE_JOB       the caller's gate job name (default "Release Gate (Full Suite)")
#   RERUN_TEST_REPO      default artifact-keeper/artifact-keeper-test
#   GH_TOKEN             actions: read on RERUN_REPO
#
# Output (resolve):
#   rerun_jobs=<space-separated only_jobs tokens>
#   original_run_id= original_actor= original_created_at=
#   original_gate_sha= original_gate_blob= self_gate_sha= self_gate_blob=
#   gate_changed=true|false (release-gate.yml content differs from the original's)
#   pin_tests_sha=<original's tests sha in same mode, else empty>
#   original_record=<the original's record, compact JSON>
#
# Exit: 0 ok, 1 BLOCKED (refused), 2 INFRA (could not measure; not a pass).
set -uo pipefail

REPO="${RERUN_REPO:-artifact-keeper/artifact-keeper}"
MODE="${1:-resolve}"
OF="${RERUN_OF:-}"
SHA="${RERUN_SHA:-}"
TESTS="${RERUN_TESTS:-same}"
SELF="${RERUN_SELF_RUN_ID:-}"
MAX_AGE_H="${RERUN_MAX_AGE_HOURS:-72}"
NOW="${RERUN_NOW:-$(date +%s)}"
GATE_JOB="${RERUN_GATE_JOB:-Release Gate (Full Suite)}"
TEST_REPO="${RERUN_TEST_REPO:-artifact-keeper/artifact-keeper-test}"
WORKFLOW_PATH=.github/workflows/release-candidate.yml
GATE_PATH=".github/workflows/release-gate.yml"
RECORD_NAME=release-candidate-record
RECORD_JOB="Record what this candidate tests"
PRE_GATE_JOBS=("Resolve the commit and its version" "Wait for a successful Docker Publish run"
  "Require a green Release Preflight for this commit" "Release bookkeeping for the commit"
  "Resolve the commit's published images" "$RECORD_JOB")

blocked() { echo "::error title=Rerun refused::$1" >&2; printf 'BLOCKED: %s\n' "$1" >&2; exit 1; }
infra()   { echo "::error title=Rerun could not be resolved::$1 Retry; do not interpret as a pass." >&2; printf 'INFRA: %s\n' "$1" >&2; exit 2; }

command -v gh >/dev/null 2>&1 || infra "gh is not on PATH."
command -v jq >/dev/null 2>&1 || infra "jq is not on PATH."
[[ "$OF" =~ ^[0-9]{1,20}$ ]] || blocked "rerun_of must be a run id (digits), got '${OF}'."
[[ "$SELF" =~ ^[0-9]{1,20}$ ]] || infra "RERUN_SELF_RUN_ID is not set."
[[ "$OF" != "$SELF" ]] || blocked "rerun_of names this run."

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

api() { # <path> [jq filter] -- fails as INFRA, never as an empty answer
  local out
  out="$(gh api "$1" ${2:+--jq "$2"} 2>"$WORK/err")" || infra "GET $1 failed: $(head -c 300 "$WORK/err")"
  printf '%s' "$out"
}
jobs_of() { # <run id> <attempt path segment or empty> -> JSON array of {name, conclusion, completed_at}
  local out
  out="$(gh api --paginate "repos/${REPO}/actions/runs/$1${2}/jobs?per_page=100" \
    --jq '.jobs[] | {name, conclusion, completed_at}' 2>"$WORK/err")" || infra "listing the jobs of run $1 failed: $(head -c 300 "$WORK/err")"
  jq -s 'unique_by(.name + "\u0000" + (.completed_at // ""))' <<<"$out"
}
# The only_jobs token a gate job stands for: its job id, or dtf-gate/<group>
# for a dtf-gate leg. Leg names are "dtf-gate (<group>)" since
# artifact-keeper-test#830, "dtf-gate (<group>, <tiers...>)" before, and long
# ones are cut with "..." -- the group always comes first.
# shellcheck disable=SC2016 # a jq program, not shell
KEYS_JQ='
  ($gate + " / ") as $p
  | [ .[] | select(.name | startswith($p))
      | .key = (.name | ltrimstr($p)
          | if test("^dtf-gate \\(") then "dtf-gate/" + (sub("^dtf-gate \\("; "") | split(", ")[0] | sub("\\)$"; "") | sub("\\.\\.\\.$"; ""))
            else sub(" \\(.*$"; "") end) ]'

orig_jobs="$(jobs_of "$OF" /attempts/1)" || exit $?
orig_keys="$(jq --arg gate "$GATE_JOB" "$KEYS_JQ" <<<"$orig_jobs")"

if [[ "$MODE" == coverage ]]; then
  self_jobs="$(jobs_of "$SELF" "")" || exit $?
  # #6163: when only_jobs names no dtf-gate leg, the gate's job-level `if:`
  # skips the whole matrix and GitHub lists ONE skipped job with the
  # unexpanded name `dtf-gate (${{ matrix.group }})`. That is not a leg; it
  # keyed as `dtf-gate/${{ matrix.group }}` and refused every suite-only
  # rerun. Drop exactly that placeholder, by its full name. Every OTHER
  # skipped job stays a key on purpose, including another matrix skipped as
  # a whole: a job the gate gained since the original and that this rerun
  # skipped was tested by neither run, and must still refuse.
  # shellcheck disable=SC2016 # a jq program, not shell
  placeholder="${GATE_JOB} / dtf-gate (\${{ matrix.group }})"
  dropped="$(jq -r --arg p "$placeholder" '.[] | select(.conclusion == "skipped" and .name == $p) | .name' <<<"$self_jobs")"
  if [[ -n "$dropped" ]]; then
    while IFS= read -r d; do
      echo "coverage: ignoring '${d}': an unexpanded matrix this rerun skipped as a whole (#6163)."
    done <<<"$dropped"
    self_jobs="$(jq -c --arg p "$placeholder" '[.[] | select((.conclusion == "skipped" and .name == $p) | not)]' <<<"$self_jobs")"
  fi
  self_keys="$(jq --arg gate "$GATE_JOB" "$KEYS_JQ" <<<"$self_jobs")"
  [[ "$(jq length <<<"$self_keys")" -gt 0 ]] || infra "this run lists no '${GATE_JOB} / ...' jobs."
  new="$(jq -r --argjson o "$orig_keys" '[.[].key] - [$o[].key] | unique | join(" ")' <<<"$self_keys")"
  if [[ -n "$new" ]]; then
    blocked "this run's gate has job(s) or dtf-gate leg(s) the original run ${OF} never ran: ${new}. The gate gained them after the original, so no run tested them on this commit. Dispatch a fresh candidate."
  fi
  echo "coverage: every gate job and dtf-gate leg of this run also ran in the original ${OF}."
  exit 0
fi

[[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || blocked "a rerun needs the commit as a full 40-hex sha (got '${SHA}')."
[[ "$TESTS" == same || "$TESTS" == moved ]] || blocked "tests must be 'same' or 'moved', got '${TESTS}'."
[[ "$MAX_AGE_H" =~ ^[0-9]+$ ]] || infra "RERUN_MAX_AGE_HOURS is not a number."

# --- 1. the original run itself (attempt 1) ----------------------------------
run="$(api "repos/${REPO}/actions/runs/${OF}/attempts/1")" || exit $?
field() { jq -r "$1 // empty" <<<"$run"; }
[[ "$(field .repository.full_name)" == "$REPO" && "$(field .head_repository.full_name)" == "$REPO" ]] \
  || blocked "run ${OF} is not a run of ${REPO}."
[[ "$(field .path)" == "$WORKFLOW_PATH" ]] || blocked "run ${OF} is a run of '$(field .path)', not ${WORKFLOW_PATH}."
[[ "$(field .event)" == workflow_dispatch && "$(field .head_branch)" == main ]] \
  || blocked "run ${OF} is a '$(field .event)' run on '$(field .head_branch)'; only a dispatch on main is a candidate."
[[ "$(field .status)" == completed ]] || blocked "run ${OF} has not completed (status '$(field .status)'). Wait for it."
[[ "$(field .conclusion)" == failure ]] || blocked "run ${OF} concluded '$(field .conclusion)' on attempt 1, not failure: there is nothing to rerun."
created="$(field .created_at)"
created_s="$(date -u -d "$created" +%s 2>/dev/null)" || infra "cannot parse run ${OF}'s created_at '${created}'."
if (( NOW - created_s > MAX_AGE_H * 3600 )); then
  blocked "run ${OF} started ${created}, more than ${MAX_AGE_H} h ago. Dispatch a fresh candidate."
fi
orig_actor="$(field .triggering_actor.login)"

# --- 2. its jobs ---------------------------------------------------------------
for j in "${PRE_GATE_JOBS[@]}"; do
  c="$(jq -r --arg n "$j" '[.[] | select(.name == $n) | .conclusion] | first // "absent"' <<<"$orig_jobs")"
  [[ "$c" == success ]] || blocked "the original run's '${j}' is '${c}'. A rerun follows up a candidate whose gate ran on resolved, releasable inputs; this one did not get that far (or predates #6076). Dispatch a fresh candidate."
done
cert="$(jq -r '[.[] | select(.name == "Certify the commit") | .conclusion] | first // "absent"' <<<"$orig_jobs")"
[[ "$cert" != success ]] || blocked "run ${OF} already certified the commit."
[[ "$(jq length <<<"$orig_keys")" -gt 0 ]] || blocked "run ${OF} has no '${GATE_JOB} / ...' jobs: the gate never ran. Dispatch a fresh candidate."
rerun_jobs="$(jq -r 'group_by(.key) | map(select(any(.[]; .conclusion != "success")) | .[0].key) | sort | join(" ")' <<<"$orig_keys")"
[[ -n "$rerun_jobs" ]] || blocked "every gate job of run ${OF} succeeded, so its failure was outside the gate. Fix that and dispatch a fresh candidate."
for t in $rerun_jobs; do
  [[ "$t" =~ ^[a-z0-9][a-z0-9-]{0,63}(/[a-z0-9][a-z0-9.-]{0,63})?$ ]] || infra "derived an only_jobs token '${t}' the gate would refuse."
done

# --- 3. its record -----------------------------------------------------------
arts="$(api "repos/${REPO}/actions/runs/${OF}/artifacts?name=${RECORD_NAME}&per_page=100")" || exit $?
[[ "$(jq '[.artifacts[] | select(.name == "'"$RECORD_NAME"'")] | length' <<<"$arts")" -eq 1 ]] \
  || blocked "run ${OF} must carry exactly one '${RECORD_NAME}' artifact; it has $(jq '[.artifacts[] | select(.name == "'"$RECORD_NAME"'")] | length' <<<"$arts")."
art="$(jq -c '.artifacts[] | select(.name == "'"$RECORD_NAME"'")' <<<"$arts")"
[[ "$(jq -r .expired <<<"$art")" == false ]] || blocked "run ${OF}'s ${RECORD_NAME} artifact has expired."
art_created="$(jq -r .created_at <<<"$art")"
rec_done="$(jq -r --arg n "$RECORD_JOB" '[.[] | select(.name == $n) | .completed_at] | first // empty' <<<"$orig_jobs")"
a_s="$(date -u -d "$art_created" +%s 2>/dev/null)" || infra "cannot parse the record's created_at '${art_created}'."
r_s="$(date -u -d "$rec_done" +%s 2>/dev/null)" || infra "cannot parse '${RECORD_JOB}' completed_at '${rec_done}'."
(( a_s <= r_s )) || blocked "run ${OF}'s ${RECORD_NAME} was created at ${art_created}, after '${RECORD_JOB}' completed (${rec_done}): it is not the record that job wrote."
mkdir -p "$WORK/rec"
gh run download "$OF" --repo "$REPO" --name "$RECORD_NAME" --dir "$WORK/rec" >/dev/null 2>"$WORK/err" \
  || infra "downloading run ${OF}'s ${RECORD_NAME} failed: $(head -c 300 "$WORK/err")"
record="$(jq -c . "$WORK/rec/record.json" 2>/dev/null)" || blocked "run ${OF}'s ${RECORD_NAME} has no readable record.json."
rec() { jq -r "$1 // empty" <<<"$record"; }
[[ "$(rec .commit_sha)" == "$SHA" ]] || blocked "run ${OF} tested commit '$(rec .commit_sha)', not ${SHA}. A rerun certifies the same commit as its original."
[[ "$(rec .candidate_run_id)" == "$OF" ]] || blocked "run ${OF}'s record names run '$(rec .candidate_run_id)'."
[[ "$(rec .gate_scope)" == full ]] || blocked "run ${OF} was itself a rerun (of $(rec .rerun.of)). Name the full run it followed up: a rerun reruns every group that run did not pass."

# --- 4. at most one rerun per candidate --------------------------------------
# Every dispatch of this workflow on main since the original started, except
# the original and this run. A run with no record never reached its gate (it
# was refused earlier), so it ran nothing and does not count.
since="$(jq -rn --arg t "$created" '$t | @uri')"
later="$(gh api --paginate "repos/${REPO}/actions/workflows/release-candidate.yml/runs?event=workflow_dispatch&branch=main&created=%3E%3D${since}&per_page=100" \
  --jq '.workflow_runs[] | .id' 2>"$WORK/err")" || infra "listing the candidate runs since ${created} failed: $(head -c 300 "$WORK/err")"
for rid in $later; do
  [[ "$rid" =~ ^[0-9]+$ && "$rid" != "$OF" && "$rid" != "$SELF" ]] || continue
  n="$(api "repos/${REPO}/actions/runs/${rid}/artifacts?name=${RECORD_NAME}&per_page=100" '[.artifacts[] | select(.name == "'"$RECORD_NAME"'")] | length')" || exit $?
  [[ "$n" -gt 0 ]] || continue
  mkdir -p "$WORK/later/${rid}"
  gh run download "$rid" --repo "$REPO" --name "$RECORD_NAME" --dir "$WORK/later/${rid}" >/dev/null 2>"$WORK/err" \
    || infra "downloading run ${rid}'s ${RECORD_NAME} failed: $(head -c 300 "$WORK/err")"
  prior_of="$(jq -r '.rerun.of // empty' "$WORK/later/${rid}/record.json" 2>/dev/null)" \
    || infra "run ${rid}'s ${RECORD_NAME} has no readable record.json."
  if [[ "$prior_of" == "$OF" ]]; then
    prior_conc="$(api "repos/${REPO}/actions/runs/${rid}" '.conclusion // .status')" || exit $?
    blocked "run ${OF} has already been rerun once, by run ${rid} (${prior_conc}). At most one rerun per candidate: dispatch a fresh Release Candidate on ${SHA} instead."
  fi
done

# --- 5. which tests --------------------------------------------------------------
gate_sha_of() { jq -r --arg p "${TEST_REPO}/${GATE_PATH}@" '[.referenced_workflows[]? | select(.path | startswith($p)) | .sha] | first // empty' <<<"$1"; }
blob_of() { api "repos/${TEST_REPO}/contents/${GATE_PATH}?ref=$1" .sha; }
orig_gate_sha="$(gate_sha_of "$run")"
self_run="$(api "repos/${REPO}/actions/runs/${SELF}")" || exit $?
self_gate_sha="$(gate_sha_of "$self_run")"
[[ "$orig_gate_sha" =~ ^[0-9a-f]{40}$ ]] || infra "run ${OF} records no ${TEST_REPO} release-gate.yml commit."
[[ "$self_gate_sha" =~ ^[0-9a-f]{40}$ ]] || infra "this run records no ${TEST_REPO} release-gate.yml commit."
orig_gate_blob="$(blob_of "$orig_gate_sha")" || exit $?
self_gate_blob="$orig_gate_blob"
if [[ "$self_gate_sha" != "$orig_gate_sha" ]]; then self_gate_blob="$(blob_of "$self_gate_sha")" || exit $?; fi
[[ -n "$orig_gate_blob" && -n "$self_gate_blob" ]] || infra "could not read the release-gate.yml blob ids."
gate_changed=false
pin=""
if [[ "$self_gate_blob" != "$orig_gate_blob" ]]; then
  if [[ "$TESTS" == same ]]; then
    blocked "release-gate.yml changed since run ${OF} (${TEST_REPO}@${orig_gate_sha:0:12} -> @${self_gate_sha:0:12}), so this rerun would not run the gate the original ran. If the change is intended (a merged test-only fix), dispatch again with tests=moved; it is recorded in the certification."
  fi
  gate_changed=true
fi
# same: pin the original's tests tree. moved: the tree is resolved afresh; the
# `record` job compares what it got with the original and records the move.
if [[ "$TESTS" == same ]]; then
  pin="$(rec .tests.sha)"
  [[ "$pin" =~ ^[0-9a-f]{40}$ ]] || blocked "run ${OF}'s record names no tests sha to pin."
fi

emit() { printf '%s=%s\n' "$1" "$2"; [[ -z "${GITHUB_OUTPUT:-}" ]] || printf '%s=%s\n' "$1" "$2" >> "$GITHUB_OUTPUT"; }
emit rerun_jobs "$rerun_jobs"
emit original_run_id "$OF"
emit original_actor "$orig_actor"
emit original_created_at "$created"
emit original_gate_sha "$orig_gate_sha"
emit original_gate_blob "$orig_gate_blob"
emit self_gate_sha "$self_gate_sha"
emit self_gate_blob "$self_gate_blob"
emit gate_changed "$gate_changed"
emit pin_tests_sha "$pin"
emit original_record "$record"
