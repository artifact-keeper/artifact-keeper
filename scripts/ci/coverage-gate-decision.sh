#!/usr/bin/env bash
# =============================================================================
# coverage-gate-decision.sh — does this pull request's coverage block merge?
# =============================================================================
#
# Called by ✅ CI Complete (ci.yml). Exit 0: coverage does not block (passed,
# skipped by design, exempt, or shadow mode). Exit 1: it blocks, and CI
# Complete -- a required context -- fails. It never needs a branch-protection
# change: "📊 Code Coverage" stays a non-required context that shows its own
# red/green, and this script is the only place that decides whether that red
# counts.
#
# POLICY (.github/coverage-gate.json -- change the phase there, not here)
#   mode            shadow  -> never blocks; the summary says what enforce
#                              WOULD do, so the pass rate under the corrected
#                              (production-only) rule is visible first.
#                   enforce -> a floor or new-code failure blocks, unless
#                              exempt (below).
#   enforce_after   YYYY-MM-DD (UTC). PRs CREATED before it are exempt, so
#                   no in-flight PR is stranded by the switch; before that
#                   date every PR is therefore exempt.
#   grace_label     a PR carrying it is exempt (maintainer's call per PR).
#   override_label  the audited override, see below.
# An unreadable or invalid config fails CLOSED: enforce, no date grace.
#
# EXEMPTIONS (checked only when coverage failed)
#   1. Override: the override label is on the PR AND its most recent
#      `labeled` event (issue events API) was by a user whose repository role
#      is admin or maintain (collaborator permission API, `role_name`) AND
#      a PR comment `/coverage-override <reason>` exists by such a user. Who
#      applied it, who wrote the reason, and the reason go to the step
#      summary and a ::notice. A label without a qualifying comment, or
#      applied by anyone else, is reported and NOT honoured.
#   2. Draft PRs (ci.yml also runs on ready_for_review, so the exemption
#      ends with a fresh verdict the moment the PR leaves draft).
#   3. PR created before enforce_after.
#   4. The grace label.
# Labels, draft state and creation time are read live from the pulls API,
# because "Re-run failed jobs" replays the original event payload; the
# payload values (PR_DRAFT / PR_CREATED_AT / PR_LABELS) are the fallback.
#
# WHAT "FAILED" MEANS
#   - Backend Unit Tests SKIPPED by a skip rule (COVERAGE_SKIP_REASON set:
#     docs-only, version-bump-only, no Rust-job inputs) -> no coverage is
#     expected; passes.
#   - Backend Unit Tests failed/cancelled -> nothing was measured; fails with
#     that reason (the unit job fails CI on its own as well).
#   - coverage-gates reported floor=fail or newcode=fail -> fails with the
#     numbers.
#   - coverage-gates failed/cancelled/skipped without a verdict -> fails as
#     "not measured". jscpd is advisory and never counts.
#
# ROLLOUT (mode/enforce_after in the config; no code change per phase)
#   Phase 0  shadow, enforce_after 2026-10-08 (this change): every PR shows
#            "would pass / would fail" in CI Complete's summary.
#   Phase 1  set "mode": "enforce" once the shadow numbers look right.
#            PRs created before 2026-10-08 stay exempt; PRs created on or
#            after it are blocked by a floor or new-code failure unless
#            draft, grace-labelled or overridden.
#   Phase 2  when no PR created before enforce_after is still open the date
#            rule is inert; optionally stop using the grace label. The
#            audited override and the draft exemption remain.
#
# INPUT (environment; everything optional unless noted)
#   GITHUB_EVENT_NAME  (required) only pull_request is gated
#   RESULT_UNIT, RESULT_COVERAGE        needs.<job>.result
#   COVERAGE_FLOOR, COVERAGE_NEWCODE    pass | fail | na  (coverage-gates outputs)
#   COVERAGE_FLOOR_PCT, COVERAGE_NEWCODE_PCT, COVERAGE_JSCPD
#   COVERAGE_SKIP_REASON                non-empty when the Rust jobs were skipped by design
#   GITHUB_REPOSITORY, PR_NUMBER, GH_TOKEN, PR_DRAFT, PR_CREATED_AT, PR_LABELS (comma-joined)
#   COVERAGE_GATE_CONFIG  default .github/coverage-gate.json
# OUTPUT
#   Lines appended to $GITHUB_STEP_SUMMARY, and one machine-readable line on
#   stdout: `coverage-gate: <outcome>` (pass | skip | fail | exempt:<why> |
#   shadow-pass | shadow-fail | shadow-exempt:<why>).
#
# Tested by scripts/ci/test-coverage-gate-decision.sh (stubbed gh).
# =============================================================================
set -uo pipefail

SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/null}"
CONFIG="${COVERAGE_GATE_CONFIG:-.github/coverage-gate.json}"
REPO="${GITHUB_REPOSITORY:-}"
PR="${PR_NUMBER:-}"

say() { printf '%s\n' "$*" >> "$SUMMARY"; }
outcome() { echo "coverage-gate: $1"; }

# --- policy -----------------------------------------------------------------
mode=enforce enforce_after="" grace_label=coverage-grace override_label=coverage-override
config_note=""
if cfg=$(jq -er '[.mode, .enforce_after, .grace_label, .override_label] | map(. // "" | tostring) | @tsv' "$CONFIG" 2>/dev/null); then
  IFS=$'\t' read -r c_mode c_after c_grace c_override <<<"$cfg"
  if [[ "$c_mode" != shadow && "$c_mode" != enforce ]]; then
    config_note="mode '${c_mode}' is not shadow|enforce"
  elif [[ -n "$c_after" && ! "$c_after" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
    config_note="enforce_after '${c_after}' is not YYYY-MM-DD"
  else
    mode="$c_mode" enforce_after="$c_after"
    [ -n "$c_grace" ] && grace_label="$c_grace"
    [ -n "$c_override" ] && override_label="$c_override"
  fi
else
  config_note="$CONFIG is missing or not valid JSON"
fi
if [ -n "$config_note" ]; then
  say "⚠️ coverage gate config: ${config_note} -- enforcing with no date grace (fails closed)"
fi

# --- what happened ------------------------------------------------------------
unit="${RESULT_UNIT:-}" cov="${RESULT_COVERAGE:-}"
floor="${COVERAGE_FLOOR:-}" newcode="${COVERAGE_NEWCODE:-}"
detail="floor ${COVERAGE_FLOOR_PCT:-?}% (${floor:-none}), new code ${COVERAGE_NEWCODE_PCT:-?}% (${newcode:-none})"

jscpd_note() {
  if [ "${COVERAGE_JSCPD:-}" = fail ]; then
    say "⚠️ duplication over 3% (advisory: jscpd measures whole changed files, #1619)"
  fi
}

if [ "${GITHUB_EVENT_NAME:-}" != pull_request ]; then
  # coverage-gates runs on pull requests only; the push run still uploads
  # lcov-coverage for main.
  if [ "$cov" = success ]; then say "✅ coverage"; else say "⏭️ coverage (pull requests only)"; fi
  outcome pass
  exit 0
fi

status=fail reason=""
if [ "$unit" = skipped ]; then
  if [ -n "${COVERAGE_SKIP_REASON:-}" ]; then
    status=skip reason="Backend Unit Tests skipped by design (${COVERAGE_SKIP_REASON}); no coverage expected"
  else
    reason="Backend Unit Tests was skipped outside the skip rules, so nothing was measured"
  fi
elif [ "$unit" != success ]; then
  reason="Backend Unit Tests ${unit:-did not report}: no coverage was measured -- fix that job first"
elif [ "$floor" = fail ] || [ "$newcode" = fail ]; then
  reason="below threshold: ${detail}"
elif [ "$cov" = success ]; then
  status=pass
elif [ "$cov" = skipped ] && [ -n "${COVERAGE_SKIP_REASON:-}" ]; then
  status=skip reason="coverage gates skipped by design (${COVERAGE_SKIP_REASON})"
else
  reason="coverage gates ${cov:-did not report} before reaching a verdict (${detail}): not measured"
fi

case "$status" in
  pass)
    say "✅ coverage (${detail})"
    jscpd_note
    if [ "$mode" = shadow ]; then outcome shadow-pass; else outcome pass; fi
    exit 0 ;;
  skip)
    say "⏭️ coverage: ${reason}"
    outcome skip
    exit 0 ;;
esac

# --- failed: exempt? ----------------------------------------------------------
draft="${PR_DRAFT:-false}" created="${PR_CREATED_AT:-}" labels=",${PR_LABELS:-},"
if [ -n "$REPO" ] && [ -n "$PR" ] \
   && live=$(gh api "repos/${REPO}/pulls/${PR}" 2>/dev/null) \
   && live_tsv=$(jq -er '[(.draft | tostring), .created_at, ([.labels[].name] | join(","))] | @tsv' <<<"$live" 2>/dev/null); then
  IFS=$'\t' read -r draft created live_labels <<<"$live_tsv"
  labels=",${live_labels},"
fi
has_label() { [[ "$labels" == *",$1,"* ]]; }

declare -A role_cache=()
privileged() { # <login> -> 0 when admin or maintain; sets $role
  local login="$1"
  if [ -z "${role_cache[$login]+x}" ]; then
    role_cache[$login]=$(gh api "repos/${REPO}/collaborators/${login}/permission" --jq '.role_name' 2>/dev/null || echo unknown)
  fi
  role="${role_cache[$login]}"
  [[ "$role" == admin || "$role" == maintain ]]
}

override_by="" override_comment_by="" override_at="" override_reason="" override_why=""
check_override() {
  local events comments actor login created_at text
  events=$(gh api --paginate "repos/${REPO}/issues/${PR}/events" 2>/dev/null) \
    || { override_why="the issue events API failed"; return 1; }
  actor=$(jq -rs --arg l "$override_label" '
      add // [] | map(select((.event == "labeled" or .event == "unlabeled") and .label.name == $l))
      | last | if . == null or .event != "labeled" then "" else .actor.login end' <<<"$events" 2>/dev/null)
  [ -n "$actor" ] || { override_why="no 'labeled' event for ${override_label} was found"; return 1; }
  privileged "$actor" \
    || { override_why="${override_label} was applied by ${actor}, whose role is ${role} (needs admin or maintain)"; return 1; }
  override_by="$actor"
  comments=$(gh api --paginate "repos/${REPO}/issues/${PR}/comments" 2>/dev/null) \
    || { override_why="the issue comments API failed"; return 1; }
  while IFS=$'\t' read -r login created_at text; do
    [ -n "$login" ] || continue
    if privileged "$login"; then
      override_comment_by="$login" override_at="$created_at" override_reason="$text"
      return 0
    fi
  done < <(jq -rs '
      add // [] | map(select(.body | test("^\\s*/coverage-override[ \\t]+\\S")))
      | reverse | .[]
      | [.user.login, .created_at,
         (.body | sub("^\\s*/coverage-override[ \\t]+"; "") | split("\n")[0] | gsub("\t"; " ") | .[0:300])]
      | @tsv' <<<"$comments" 2>/dev/null)
  override_why="no '/coverage-override <reason>' comment by an admin or maintainer"
  return 1
}

exempt=""
if has_label "$override_label"; then
  if check_override; then
    exempt=override
    msg="coverage override: label by ${override_by}, reason by ${override_comment_by}: ${override_reason}"
    echo "::notice title=Coverage gate overridden::${msg} (${detail})"
    say "🔓 coverage overridden -- label \`${override_label}\` applied by **${override_by}**, \`/coverage-override\` by **${override_comment_by}** (${override_at}): ${override_reason} (${detail})"
  else
    say "⚠️ \`${override_label}\` is on this PR but is NOT honoured: ${override_why}"
  fi
fi
if [ -z "$exempt" ] && [ "$draft" = true ]; then
  exempt=draft
elif [ -z "$exempt" ] && [ -n "$enforce_after" ] && [ -n "$created" ] && [[ "${created:0:10}" < "$enforce_after" ]]; then
  exempt=created-before-${enforce_after}
elif [ -z "$exempt" ] && has_label "$grace_label"; then
  exempt=grace-label
fi

if [ "$mode" = shadow ]; then
  if [ -n "$exempt" ]; then
    say "👀 coverage (shadow mode, not blocking): ${reason}. Under enforcement this PR would be EXEMPT (${exempt})."
    outcome "shadow-exempt:${exempt}"
  else
    say "👀 coverage (shadow mode, not blocking): ${reason}. Under enforcement this PR would FAIL CI Complete."
    outcome shadow-fail
  fi
  jscpd_note
  exit 0
fi

if [ -n "$exempt" ]; then
  case "$exempt" in
    override) ;;
    draft) say "⚠️ coverage: ${reason} -- not blocking while the PR is a draft" ;;
    grace-label) say "⚠️ coverage: ${reason} -- not blocking: \`${grace_label}\` label" ;;
    *) say "⚠️ coverage: ${reason} -- not blocking: PR opened before ${enforce_after}" ;;
  esac
  jscpd_note
  outcome "exempt:${exempt}"
  exit 0
fi

say "❌ coverage: ${reason}. See the 📊 Code Coverage job summary for the uncovered lines; a maintainer can override with the \`${override_label}\` label plus a \`/coverage-override <reason>\` comment."
jscpd_note
outcome fail
exit 1
