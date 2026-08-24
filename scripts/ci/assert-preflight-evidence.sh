#!/usr/bin/env bash
#
# Release gate: refuse to cut a tag unless a GREEN Release Preflight ran
# against the exact commit being released (issue #3538).
#
# WHY THIS EXISTS
#   A guard's absence is invisible; only its failure is visible. Two of the
#   most expensive incidents in the 1.7.x line were both this shape, and
#   neither was a bug in the preflight itself -- the preflight was right, or
#   would have been right, and nothing required its verdict.
#
#   v1.7.5. `docker/scanner-adapter/VERSION` was not bumped when
#   `Dockerfile.scanner-adapter` changed, so the tag's Docker Publish hit the
#   never-republish guard, the chain stopped, and the immutable tag had to be
#   abandoned. Preflight check 4 (#3339) exists precisely to catch that, was
#   merged on 2026-08-13, and was simply never run: the Actions API shows zero
#   Release Preflight runs between 2026-08-14T14:19Z and 2026-08-17T13:51Z.
#   Cost: ~38h and a burned version number.
#
#   v1.7.7. The preflight DID run and it was RIGHT. Run 32377238021
#   (2026-08-20T13:57Z) printed `[FAIL] Docker Publish for HEAD did NOT cleanly
#   publish the manifest -- a tag cut WILL stall on the same gate.` Two
#   dispatches at 21:22Z reported the follow-up publish's `verdict does not
#   exist yet`. `v1.7.7` was tagged at 21:40:17Z, eighteen minutes later, and
#   the in-flight docker-publish concluded `failure` nineteen seconds after the
#   tag push. The pipeline called it correctly, hours early, and the cut
#   proceeded anyway.
#
#   Nothing anywhere asserted "a preflight ran against this commit". This
#   script is that assertion.
#
# THE RULE, in one sentence:
#   every Release Preflight run for this commit must have COMPLETED, and the
#   newest completed one must have concluded `success` AND left the
#   `release-preflight-<sha>` evidence artifact naming this commit.
#
#   Each clause is load-bearing:
#     * "every run must have completed" -- an in-flight run is a verdict that
#       DOES NOT EXIST YET. Treating one as absent, or as harmless, is exactly
#       the v1.7.7 shape. A concurrent re-run that blocks a release for forty
#       seconds is a cost worth paying to make that impossible.
#     * "the NEWEST completed one" -- checks 1, 3 and 4 measure state outside
#       the tree (release-branch suppressions, a Docker Publish run, the
#       registry), so the same commit can legitimately go red after being
#       green. A superseded green is not evidence. Accepting "some green run
#       exists" would re-import the revoked "the red is cosmetic, promote
#       anyway" reasoning at the level of run selection.
#     * "left the evidence artifact naming this commit" -- the Actions API's
#       `head_sha` is the sha of the ref the run was DISPATCHED on, which is
#       the sha it audited only if no `ref:` input was given and the branch did
#       not move between dispatch and checkout. release-preflight.yml computes
#       `git rev-parse HEAD` inside the run and puts it in the artifact NAME,
#       so the evidence states which tree it is about. Skipping this would
#       leave the gate satisfiable by a verdict about a different branch --
#       which is not hypothetical: release-preflight.yml hardcoded `ref: main`
#       until v1.7.8, so v1.7.5, v1.7.6 and v1.7.7 were each cut from
#       release/1.7.x on a transcript that had audited main.
#
# BREAK GLASS
#   The freeze policy requires a documented hotfix path ("skip schedule, never
#   integrity"). This gate is schedule/readiness, not integrity: it predicts
#   whether the chain will stall, it does not certify the bytes. So it is
#   override-able -- and the three gates that DO certify bytes
#   (resolve-candidate-digest, release-gate, verify-images-published) are not
#   touched by this and stay required.
#
#   The override is a trailer in the ANNOTATED TAG's own message:
#
#       git tag -a v1.8.2 -m "Release 1.8.2
#
#       Preflight-Override: cut off-branch at 635496d0; preflight run 12345
#       audited that tree locally, transcript attached to #3538"
#
#   Why there and nowhere else:
#     * release.yml has no `workflow_dispatch` (it was deliberately removed, so
#       the version released cannot drift from the ref tested) -- there is no
#       workflow input to hang it on, and adding one back to carry a bypass
#       would be a strange thing to reintroduce.
#     * A repository variable or secret is MUTABLE and not scoped to a release:
#       set once, it silently disarms the gate for every future tag, and the
#       next operator cannot see it in anything they read.
#     * The tag object is IMMUTABLE (ruleset 19144026 restricts updates and
#       deletions on refs/tags/v*), it is created by the same command that
#       starts the release, and it is scoped to exactly one version. An
#       override cannot be added after the fact, cannot leak to the next
#       release, and is readable forever by anyone doing `git show v1.8.2`.
#   A reason is REQUIRED (>= 20 characters of it). A trailer with no reason,
#   or a token one, is REFUSED rather than honoured -- a silent bypass is the
#   thing being fixed, so a lazy bypass must not be easier than the fix.
#   Whenever an override is honoured, the verdict it overrode is printed in
#   full, annotated as a workflow warning, and written to the run summary.
#
# Exit codes (mirrors release-preflight.sh so the two read alike):
#   0  evidence present (or a valid override was applied)
#   1  BLOCKED -- no green preflight for this commit
#   2  INFRA   -- could not measure (gh/network/API). NOT a pass; an
#                 indeterminate verdict must never read as evidence.
#
# Env:
#   GATE_SHA          (required) 40-hex commit being released
#   GATE_TAG          tag name, for the override lookup. Empty disables it.
#   GATE_REPO         owner/name (default: derived from the origin remote)
#   GATE_WORKFLOW     workflow file to require (default release-preflight.yml)
#   GATE_TAG_MESSAGE  annotated tag message, if already known. Set by the
#                     self-test so it never touches the network; also lets a
#                     human dry-run the decision locally.
#   GITHUB_STEP_SUMMARY  appended to when set.
#
set -euo pipefail

RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; RST=$'\033[0m'
[[ -t 1 ]] || { RED=""; GRN=""; YEL=""; RST=""; }

SHA="${GATE_SHA:-}"
TAG="${GATE_TAG:-}"
WORKFLOW="${GATE_WORKFLOW:-release-preflight.yml}"
MIN_REASON_CHARS=20

if [[ ! "$SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "INFRA: GATE_SHA must be a full 40-character commit sha (got '${SHA}')" >&2
  exit 2
fi

REPO="${GATE_REPO:-}"
if [[ -z "$REPO" ]]; then
  origin="$(git config --get remote.origin.url 2>/dev/null || true)"
  REPO="$(printf '%s' "$origin" | sed -E 's#(git@[^:]+:|https?://[^/]+/)##; s#\.git$##')"
  [[ -z "$REPO" ]] && REPO="artifact-keeper/artifact-keeper"
fi

SERVER="${GITHUB_SERVER_URL:-https://github.com}"
run_url() { printf '%s/%s/actions/runs/%s' "$SERVER" "$REPO" "$1"; }

# Collected for the run summary; printed whether we pass, block or override.
verdict=""        # one of: ok | blocked | infra
verdict_line=""
declare -a detail=()
say() { detail+=("$1"); printf '  %s\n' "$1"; }

echo "== release preflight evidence gate =="
echo "repo:     $REPO"
echo "commit:   $SHA"
echo "tag:      ${TAG:-<none>}"
echo "workflow: $WORKFLOW"
echo

command -v gh >/dev/null 2>&1 || {
  echo "INFRA: gh is not on PATH -- cannot look for preflight evidence" >&2
  exit 2
}

# ---------------------------------------------------------------------------
# 1. every Release Preflight run for this exact commit
# ---------------------------------------------------------------------------
# `head_sha=` resolves server-side; recency is never used to pick a run (the
# #3338 lesson, one layer out).
if ! runs_tsv="$(gh api \
      "repos/${REPO}/actions/workflows/${WORKFLOW}/runs?head_sha=${SHA}&per_page=100" \
      --jq '.workflow_runs[] | [.id, .status, (.conclusion // ""), .created_at, .event] | @tsv' \
      2>/dev/null)"; then
  echo "INFRA: could not query ${WORKFLOW} runs for ${SHA}" >&2
  exit 2
fi

# Newest first, by created_at, rather than trusting the API's ordering.
runs_sorted="$(printf '%s' "$runs_tsv" | grep -v '^$' | sort -t$'\t' -k4,4r || true)"

pending_id=""; pending_status=""
newest_id=""; newest_conclusion=""; newest_created=""; newest_event=""
n_runs=0
while IFS=$'\t' read -r r_id r_status r_conclusion r_created r_event; do
  [[ -z "$r_id" ]] && continue
  n_runs=$((n_runs + 1))
  if [[ "$r_status" != "completed" ]]; then
    # Remember the newest not-yet-finished run to name in the message.
    [[ -z "$pending_id" ]] && { pending_id="$r_id"; pending_status="$r_status"; }
  elif [[ -z "$newest_id" ]]; then
    newest_id="$r_id"; newest_conclusion="$r_conclusion"
    newest_created="$r_created"; newest_event="$r_event"
  fi
done <<< "$runs_sorted"

if [[ "$n_runs" -eq 0 ]]; then
  verdict="blocked"
  verdict_line="No Release Preflight has ever run against this commit."
  say "$verdict_line"
  say "Nothing has asserted that ${SHA} is releasable. That is the v1.7.5"
  say "shape: check 4 existed and would have caught the collision, and simply"
  say "was not run."
  say "-> run the 'Release Preflight' workflow on this commit, get READY, then"
  say "   re-run this release (or re-tag if the tag is already spent)."
elif [[ -n "$pending_id" ]]; then
  # Deliberately checked BEFORE the completed-run verdict: a green run plus a
  # newer in-flight one is still an unfinished measurement of these bytes.
  verdict="blocked"
  verdict_line="A Release Preflight for this commit is still '${pending_status}' -- its verdict does not exist yet."
  say "$verdict_line"
  say "waiting on run ${pending_id}: $(run_url "$pending_id")"
  say "This is the v1.7.7 shape exactly: on 2026-08-20 two preflight dispatches"
  say "reported 'verdict does not exist yet' and v1.7.7 was tagged 18 minutes"
  say "later; the run they were waiting on concluded 'failure'."
  say "-> wait for run ${pending_id} to finish, then re-run this release."
elif [[ -z "$newest_id" ]]; then
  # Unreachable in practice (n_runs>0 with neither pending nor completed) but
  # an unexplained state must not fall through as a pass.
  verdict="infra"
  verdict_line="Could not classify the ${n_runs} preflight run(s) for this commit."
  say "$verdict_line"
elif [[ "$newest_conclusion" != "success" ]]; then
  verdict="blocked"
  verdict_line="The newest Release Preflight for this commit concluded '${newest_conclusion:-<none>}'."
  say "$verdict_line"
  say "run ${newest_id} (${newest_event}, ${newest_created}): $(run_url "$newest_id")"
  say "A red preflight is a measurement, not a formality: it says this cut will"
  say "stall on a gate that has already been observed to fail."
  say "-> fix what it reported, get a green preflight on the new commit, and"
  say "   cut from that."
else
  # ------------------------------------------------------------------------
  # 2. the green run must state which tree it audited
  # ------------------------------------------------------------------------
  want_artifact="release-preflight-${SHA}"
  if ! artifacts="$(gh api \
        "repos/${REPO}/actions/runs/${newest_id}/artifacts?per_page=100" \
        --jq '.artifacts[].name' 2>/dev/null)"; then
    echo "INFRA: could not list artifacts of preflight run ${newest_id}" >&2
    exit 2
  fi
  if printf '%s\n' "$artifacts" | grep -qxF "$want_artifact"; then
    verdict="ok"
    verdict_line="Green Release Preflight run ${newest_id} audited ${SHA}."
    say "$verdict_line"
    say "run ${newest_id} (${newest_event}, ${newest_created}): $(run_url "$newest_id")"
    say "evidence artifact: ${want_artifact}"
  else
    verdict="blocked"
    verdict_line="Preflight run ${newest_id} is green but carries no evidence that it audited ${SHA}."
    say "$verdict_line"
    say "run ${newest_id}: $(run_url "$newest_id")"
    say "expected artifact '${want_artifact}'; found: ${artifacts:-<none>}"
    say "The Actions API reports that run's head_sha as this commit, but head_sha"
    say "is the sha of the ref the run was DISPATCHED on. The artifact carries the"
    say "sha the run actually checked out. They differ when a 'ref' input pointed"
    say "the audit elsewhere, or when the branch moved between dispatch and"
    say "checkout -- the case where a READY transcript is about a different tree."
    say "-> re-run 'Release Preflight' on this exact commit."
  fi
fi

# ---------------------------------------------------------------------------
# 3. break glass: an annotated-tag trailer, with a real reason
# ---------------------------------------------------------------------------
override_reason=""
override_state="absent"   # absent | applied | rejected | unnecessary | unreadable
tag_message="${GATE_TAG_MESSAGE-}"

if [[ -z "${GATE_TAG_MESSAGE+x}" && -n "$TAG" ]]; then
  obj="$(gh api "repos/${REPO}/git/ref/tags/${TAG}" --jq '"\(.object.type) \(.object.sha)"' 2>/dev/null || true)"
  obj_type="${obj%% *}"; obj_sha="${obj##* }"
  if [[ "$obj_type" == "tag" && -n "$obj_sha" ]]; then
    tag_message="$(gh api "repos/${REPO}/git/tags/${obj_sha}" --jq '.message' 2>/dev/null || true)"
  elif [[ -z "$obj" ]]; then
    override_state="unreadable"
  fi
  # A lightweight tag has no message and therefore no override. That is not an
  # error; it just means break-glass is unavailable, which is the default.
fi

if [[ -n "$tag_message" ]]; then
  raw="$(printf '%s\n' "$tag_message" | grep -im1 '^[[:space:]]*Preflight-Override:' || true)"
  if [[ -n "$raw" ]]; then
    override_reason="${raw#*:}"
    # trim both ends
    override_reason="${override_reason#"${override_reason%%[![:space:]]*}"}"
    override_reason="${override_reason%"${override_reason##*[![:space:]]}"}"
    if [[ "${#override_reason}" -lt "$MIN_REASON_CHARS" ]]; then
      override_state="rejected"
    elif [[ "$verdict" == "ok" ]]; then
      override_state="unnecessary"
    else
      override_state="applied"
    fi
  fi
fi

# An override is scoped to the readiness verdict. It never converts an INFRA
# result into a pass: "I could not measure" is not a risk a human can knowingly
# accept, because there is no measurement to accept.
if [[ "$override_state" == "applied" && "$verdict" == "infra" ]]; then
  override_state="rejected-infra"
fi

echo

case "$override_state" in
  applied)
    printf '%s[OVERRIDDEN]%s %s\n' "$YEL" "$RST" "$verdict_line"
    echo "::warning title=Release preflight gate overridden::${TAG:-this tag} was cut without a green Release Preflight for ${SHA}. Reason: ${override_reason}"
    echo "  reason: ${override_reason}"
    echo "  source: Preflight-Override: trailer in the annotated tag ${TAG}"
    echo "  This is a recorded, tag-scoped decision. Whoever wrote that trailer"
    echo "  owns the outcome if the chain stalls on what the preflight predicts."
    ;;
  rejected)
    printf '%s[BLOCKED]%s A Preflight-Override: trailer is present but its reason is too short.\n' "$RED" "$RST"
    echo "  got ${#override_reason} character(s); at least ${MIN_REASON_CHARS} are required."
    echo "::error title=Preflight override rejected::The Preflight-Override: trailer on ${TAG:-this tag} carries no usable reason. A bypass without a stated reason is the silent bypass this gate exists to remove."
    ;;
  rejected-infra)
    printf '%s[BLOCKED]%s A Preflight-Override: trailer cannot override an INFRA result.\n' "$RED" "$RST"
    echo "  The gate could not measure anything; there is no verdict to accept the risk of."
    ;;
  unnecessary)
    printf '%s[note]%s A Preflight-Override: trailer is present but was not needed.\n' "$YEL" "$RST"
    echo "  reason: ${override_reason}"
    ;;
  unreadable)
    echo "  note: could not read the annotated tag ${TAG}; an override trailer, if any, was not seen."
    ;;
esac

# ---------------------------------------------------------------------------
# 4. verdict + run summary
# ---------------------------------------------------------------------------
summary_status=""
case "$verdict:$override_state" in
  ok:*)            exit_code=0; summary_status="PASS" ;;
  *:applied)       exit_code=0; summary_status="OVERRIDDEN" ;;
  infra:*)         exit_code=2; summary_status="INFRA" ;;
  *)               exit_code=1; summary_status="BLOCKED" ;;
esac

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "### Release preflight evidence: ${summary_status}"
    echo
    echo "| | |"
    echo "|---|---|"
    echo "| commit | \`${SHA}\` |"
    echo "| tag | \`${TAG:-<none>}\` |"
    echo "| preflight runs for this commit | ${n_runs} |"
    echo "| verdict | ${verdict_line} |"
    if [[ "$override_state" == "applied" ]]; then
      echo "| **override** | \`Preflight-Override:\` trailer on \`${TAG}\` |"
      echo "| **override reason** | ${override_reason} |"
    fi
    echo
    for line in "${detail[@]}"; do echo "- ${line}"; done
  } >> "$GITHUB_STEP_SUMMARY"
fi

echo
case "$summary_status" in
  PASS)       printf '%sREADY%s: %s\n' "$GRN" "$RST" "$verdict_line" ;;
  OVERRIDDEN) printf '%sOVERRIDDEN%s: released without preflight evidence, by explicit tag-recorded decision.\n' "$YEL" "$RST" ;;
  INFRA)      printf '%sINFRA%s: the preflight evidence could not be measured. Retry; do not interpret as a pass.\n' "$YEL" "$RST" ;;
  *)
    printf '%sBLOCKED%s: %s\n' "$RED" "$RST" "$verdict_line"
    echo "::error title=No green Release Preflight for this commit::${verdict_line} See the job log for what to do."
    ;;
esac
exit "$exit_code"
