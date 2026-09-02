#!/usr/bin/env bash
#
# Locate the docker-publish run that vouches for the commit being released
# (issue #3640).
#
# WHY THIS EXISTS
#   release.yml's `resolve-candidate-digest` job must not let the release gate
#   start until a docker-publish pipeline for the EXACT commit+ref being
#   released has completed successfully. It used to find that run with a query
#   hard-filtered to `event=push`, which deadlocks a re-tagged release:
#
#     * Image immutability makes the re-tag's push-triggered docker-publish
#       fail at "Refuse to overwrite a published backend version" -- correct,
#       and permanent: that run can never be made green.
#     * The documented recovery (#2698) -- dispatch docker-publish with
#       `promote_version=X.Y.Z` at the tag -- succeeds, but is
#       `event=workflow_dispatch`, so the resolver never saw it. v1.8.2 hit
#       exactly this: push run 33514800258 failed on immutability, promote
#       run 33522347257 succeeded, release blocked forever.
#
#   So this script accepts a SUCCESSFUL run for the same head_sha AND
#   head_branch from EITHER `push` or `workflow_dispatch`, preferring the most
#   recent success (the promote-floating-tags job in release.yml already
#   trusts workflow_dispatch runs selected the same way).
#
# WHY THIS DOES NOT WEAKEN bytes-tested == bytes-published
#   This selection is a liveness/ordering gate ("a publish pipeline for these
#   exact sources completed green"), not the digest identity assertion. The
#   digest the gate tests is read from the registry AFTER this passes, and
#   verify-images-published re-asserts it at the end. Two properties keep the
#   dispatch acceptance sound:
#     * PROMOTE mode rebuilds nothing: docker-publish.yml skips every build
#       job when promote_version is set and re-points tags at the digest
#       `:X.Y.Z` ALREADY names on ghcr.
#     * The digest-aware republish guard (`assert-version-digest-consistent`)
#       runs in every mode: once `:X.Y.Z` resolves, no run of any kind can
#       re-point it to different content -- only re-apply the same digest.
#   So any successful same-commit run, push or dispatch, leaves `:X.Y.Z`
#   naming bytes that guard has pinned, and those are the bytes the gate then
#   pulls by digest.
#
# WHAT STAYS CLOSED
#   * No successful run of either kind -> BLOCKED (a missing or failed publish
#     must stay RED; "assume the promote happened" is not a verdict).
#   * A success for a DIFFERENT sha is invisible: both queries filter
#     server-side on head_sha.
#   * A success for the same sha on a DIFFERENT ref (e.g. the main-branch push
#     build of the very commit the tag points at -- real: run 33510770762 for
#     v1.8.2's commit) is rejected by the head_branch filter: a main build
#     publishes :main/:dev, never the version tag, and must not vouch for it.
#   * `schedule` runs are not queried at all.
#
# OUTPUT (stdout), one line, machine-readable:
#   state=resolved run_id=<id>              exit 0
#   state=pending  run_id=<id> status=<s>   exit 10  (newest unfinished run)
#   state=blocked                           exit 20  (runs exist, all
#                                                     completed, none green)
#   state=none                              exit 21  (no matching runs yet)
#   state=infra                             exit 30  (could not query; NOT a
#                                                     verdict either way)
#
# Env:
#   RESOLVE_SHA       (required) 40-hex commit being released
#   RESOLVE_REF       (required) ref name the release runs on (e.g. v1.8.2)
#   RESOLVE_REPO      owner/name  (default artifact-keeper/artifact-keeper)
#   RESOLVE_WORKFLOW  workflow file (default docker-publish.yml)
#
set -uo pipefail

SHA="${RESOLVE_SHA:-}"
REF="${RESOLVE_REF:-}"
REPO="${RESOLVE_REPO:-artifact-keeper/artifact-keeper}"
WORKFLOW="${RESOLVE_WORKFLOW:-docker-publish.yml}"

if [[ ! "$SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "state=infra reason=bad-sha" ; echo "RESOLVE_SHA must be a full 40-char sha (got '${SHA}')" >&2
  exit 30
fi
if [[ -z "$REF" ]]; then
  echo "state=infra reason=bad-ref" ; echo "RESOLVE_REF must be set" >&2
  exit 30
fi

# One query per accepted event, both pinned server-side to head_sha so a stale
# success for another commit can never appear in the candidate set at all.
# per_page mirrors the existing idioms (push: 20, dispatch: 50 as in
# promote-floating-tags).
fetch() { # $1 = event, $2 = per_page
  gh api \
    "repos/${REPO}/actions/workflows/${WORKFLOW}/runs?event=$1&head_sha=${SHA}&per_page=$2" \
    --jq '.workflow_runs[] | [.id, .event, .head_branch, .status, (.conclusion // "-"), .created_at] | @tsv' \
    2>/dev/null
}

query_failed=0
push_tsv="$(fetch push 20)"            || query_failed=1
dispatch_tsv="$(fetch workflow_dispatch 50)" || query_failed=1
if [[ "$query_failed" -eq 1 ]]; then
  echo "state=infra reason=api"
  echo "could not query ${WORKFLOW} runs for ${SHA}; indeterminate, retry" >&2
  exit 30
fi

# Keep only runs for OUR ref, newest last (sort_by(.created_at) | last, in
# TSV form). The Actions API's own ordering is never trusted (#3338 lesson).
runs_sorted="$(printf '%s\n%s\n' "$push_tsv" "$dispatch_tsv" \
  | awk -F'\t' -v ref="$REF" 'NF >= 6 && $3 == ref' \
  | sort -t$'\t' -k6,6)"

n_runs=0
success_id=""                      # newest success wins (input is oldest->newest)
pending_id=""; pending_status=""   # newest unfinished likewise
# shellcheck disable=SC2034  # r_branch: already filtered by the awk above;
# kept in the TSV so the log lines and the self-test stub share one schema.
while IFS=$'\t' read -r r_id r_event r_branch r_status r_conclusion r_created; do
  [[ -z "$r_id" ]] && continue
  n_runs=$((n_runs + 1))
  echo "  candidate: run ${r_id} event=${r_event} status=${r_status} conclusion=${r_conclusion} created=${r_created}" >&2
  if [[ "$r_status" == "completed" && "$r_conclusion" == "success" ]]; then
    success_id="$r_id"
  elif [[ "$r_status" != "completed" ]]; then
    pending_id="$r_id"; pending_status="$r_status"
  fi
done <<< "$runs_sorted"

if [[ -n "$success_id" ]]; then
  echo "state=resolved run_id=${success_id}"
  exit 0
fi
if [[ -n "$pending_id" ]]; then
  echo "state=pending run_id=${pending_id} status=${pending_status}"
  exit 10
fi
if [[ "$n_runs" -gt 0 ]]; then
  echo "state=blocked"
  echo "all ${n_runs} ${WORKFLOW} run(s) for ${REF}@${SHA} completed without success" >&2
  exit 20
fi
echo "state=none"
exit 21
