#!/usr/bin/env bash
#
# Find the workflow run a `gh workflow run` just started, and follow it to a
# verdict (issues #3771, #3772).
#
# WHY THIS EXISTS
#   `gh workflow run` returns nothing that identifies the run it created, so
#   release.yml's promote-floating-tags job locates it afterwards: the newest
#   `workflow_dispatch` run of the workflow, on the expected ref, created after
#   a timestamp taken just before the dispatch. The candidate and promote
#   workflows dispatch three more workflows the same way (the preflight, and
#   Docker Publish twice), so the selection and the polling live here once,
#   with the same rules, and are self-tested offline.
#
#   The rules are the ones that job already applies, stated:
#     * the run must be on FOLLOW_REF (head_branch) -- a dispatch on another
#       ref of the same workflow is not ours;
#     * it must have been created at or after FOLLOW_SINCE -- an older dispatch
#       for the same ref is not ours either (the caller backdates SINCE by a
#       couple of minutes because a runner clock is compared against GitHub's);
#     * of the matches, the NEWEST is taken;
#     * webhook fan-out lags, so a run is given FOLLOW_APPEAR_SECONDS to show
#       up before the dispatch is declared dead;
#     * once seen, it is polled until `completed`; only `success` is a pass.
#
# OUTPUT (stdout), one line, machine-readable; details go to stderr:
#   run_id=<id> conclusion=success        exit 0
#   run_id=<id> conclusion=<other>        exit 1   (completed, not success)
#   run_id=<id> status=<s>                exit 0 with FOLLOW_WAIT=false
#   run_id= state=none                    exit 21  (never appeared)
#   run_id= state=infra                   exit 30  (API kept failing)
#
# Env:
#   FOLLOW_REPO           owner/name (default artifact-keeper/artifact-keeper)
#   FOLLOW_WORKFLOW       (required) workflow file, e.g. docker-publish.yml
#   FOLLOW_REF            (required) head_branch the run must carry (branch or
#                         tag NAME, e.g. main or v1.9.0)
#   FOLLOW_SINCE          (required) ISO-8601 UTC lower bound on created_at
#   FOLLOW_SHA            optional head_sha the run must carry
#   FOLLOW_APPEAR_SECONDS how long to wait for the run to appear (default 600)
#   FOLLOW_POLL_SECONDS   poll interval (default 30; the self-test sets 0)
#   FOLLOW_WAIT           `false` to stop once the run is found (default true)
#
set -uo pipefail

REPO="${FOLLOW_REPO:-artifact-keeper/artifact-keeper}"
WORKFLOW="${FOLLOW_WORKFLOW:-}"
REF="${FOLLOW_REF:-}"
SINCE="${FOLLOW_SINCE:-}"
SHA="${FOLLOW_SHA:-}"
APPEAR="${FOLLOW_APPEAR_SECONDS:-600}"
POLL="${FOLLOW_POLL_SECONDS:-30}"
WAIT="${FOLLOW_WAIT:-true}"

for v in WORKFLOW REF SINCE; do
  if [[ -z "${!v}" ]]; then
    echo "run_id= state=infra"
    echo "FOLLOW_${v} must be set" >&2
    exit 30
  fi
done

SERVER="${GITHUB_SERVER_URL:-https://github.com}"

find_run() {
  gh api "repos/${REPO}/actions/workflows/${WORKFLOW}/runs?event=workflow_dispatch&per_page=50" \
    --jq '.workflow_runs[] | [.id, .head_branch, .head_sha, .created_at] | @tsv' 2>/dev/null \
    | awk -F'\t' -v ref="$REF" -v since="$SINCE" -v sha="$SHA" \
        'NF >= 4 && $2 == ref && $4 >= since && (sha == "" || $3 == sha)' \
    | sort -t$'\t' -k4,4 | tail -n 1 | cut -f1
}

deadline=$(( $(date +%s) + APPEAR ))
run_id=""
api_failures=0
while true; do
  if out="$(find_run)"; then
    run_id="$out"
    [[ -n "$run_id" ]] && break
  else
    api_failures=$((api_failures + 1))
  fi
  if [[ "$(date +%s)" -ge "$deadline" ]]; then
    if [[ "$api_failures" -gt 0 && -z "$run_id" ]]; then
      echo "run_id= state=infra"
      echo "could not list ${WORKFLOW} runs for ${APPEAR}s; whether the dispatch started is unknown" >&2
      exit 30
    fi
    echo "run_id= state=none"
    echo "no ${WORKFLOW} workflow_dispatch run on ${REF} created since ${SINCE} appeared within ${APPEAR}s" >&2
    exit 21
  fi
  echo "  no ${WORKFLOW} run on ${REF} visible yet; waiting ${POLL}s..." >&2
  sleep "$POLL"
done

echo "Following ${WORKFLOW} run ${run_id}: ${SERVER}/${REPO}/actions/runs/${run_id}" >&2

if [[ "$WAIT" != "true" ]]; then
  echo "run_id=${run_id} status=found"
  exit 0
fi

while true; do
  state="$(gh api "repos/${REPO}/actions/runs/${run_id}" \
    --jq '.status + " " + (.conclusion // "-")' 2>/dev/null || echo "unknown -")"
  status="${state%% *}"; conclusion="${state#* }"
  if [[ "$status" == "completed" ]]; then
    echo "run_id=${run_id} conclusion=${conclusion}"
    [[ "$conclusion" == "success" ]] && exit 0
    echo "${WORKFLOW} run ${run_id} concluded '${conclusion}'" >&2
    exit 1
  fi
  echo "  run ${run_id}: ${status}; waiting ${POLL}s..." >&2
  sleep "$POLL"
done
