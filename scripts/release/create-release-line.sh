#!/usr/bin/env bash
#
# Create a release line: refs/heads/release/<X.Y>.x  (issue #3798)
#
# WHY A SCRIPT, AND WHY CREATION IS BLOCKED IN THE FIRST PLACE
# -----------------------------------------------------------
# Ruleset 20038606 ("Release branch protection") governs
# `refs/heads/release/[0-9]*.[0-9]*.x` with `pull_request`,
# `required_status_checks` (both contexts pinned to app 15368,
# `do_not_enforce_on_create: false`), `non_fast_forward`, `deletion`, and NO
# bypass actors. The `pull_request` rule requires one approving review, with
# stale approvals dismissed on push and the last push approved by someone other
# than the pusher (#6216). A required status check cannot exist on a ref that
# does not exist yet, so the very push that would create a release line is refused:
#
#   remote: - Required status check "Verify commits trace back to main" is expected.
#
# #3798 settled that this is the right posture rather than a bug, after both
# alternatives were tried and rejected:
#
#   * `do_not_enforce_on_create: true` does unblock creation -- but
#     `required_status_checks` was the ONLY rule blocking it (`pull_request`
#     never did), so waiving it left ref creation under `release/*` entirely
#     unguarded: any write-access user could push `release/<anything>.x` at any
#     commit, with no PR, no CI and no ancestry check. That is load-bearing
#     beyond untidiness -- the certified-release flow's safety rests on an
#     untrusted actor being unable to create a `release/*` ref at all. Applied,
#     demonstrated to be a hole, reverted.
#   * a standing bypass actor permanently weakens a branch class that is today
#     STRONGER than `main` (no bypass at all, pull request required).
#
# So cutting a line stays a rare privileged act that costs a deliberate,
# temporary, admin-only enforcement toggle. This script is that toggle done the
# same way every time: every precondition checked BEFORE anything is relaxed,
# the ruleset restored from an EXIT trap so it cannot be left relaxed, the
# before/after JSON diffed field by field, and an audit summary printed for the
# release PR or the issue.
#
# Deleting a release line needs the same toggle for the same reason: the
# `deletion` rule has no bypass actor either.
#
# THE MATCHING TEST-SUITE BRANCH (#4372)
# --------------------------------------
# The Release Gate is artifact-keeper-test's release-gate.yml@main, and every
# one of its jobs runs scripts/switch-tests-ref.sh (artifact-keeper-test#420):
# if that repository has a `release/X.Y.x` for the candidate's version, the
# suite runs from it, otherwise from main. Without the branch a maintenance
# candidate is gated by main's suite, which keeps gaining companion tests for
# features the line never gets -- that is what failed ten suites on the
# v1.10.2 candidate (#4350). So a line is created in BOTH repositories, the
# test branch at the suite commit that certified the line's first release:
#
#   --tests-from-run <id>  the successful Release Candidate run that certified
#                          v<X.Y>.0; the commit is the release-gate.yml sha
#                          GitHub recorded for that run (`referenced_workflows`)
#   --tests-sha <sha>      that commit, given directly (40 hex)
#
# The commit must be on artifact-keeper-test's main. artifact-keeper-test has
# no ruleset on `release/*`, so this is a plain ref creation, outside the
# toggle window, and nothing needs dispatching: the gate reads the branch when
# a candidate runs. It is idempotent: a test branch that already exists is
# left where it is (backported companion tests are cherry-picked onto it,
# artifact-keeper-test#424, so its tip legitimately moves), and re-running the
# script for a line whose backend branch already exists only creates the test
# branch -- which is how a failed test-branch creation is retried, and how an
# older line gets one.
#
# Runs locally, on a workstation, by a human admin -- so the messages here are
# plain text, not `::error` workflow annotations.
#
# Usage:  create-release-line.sh [--dry-run] [--tests-from-run <id> | --tests-sha <sha>] <X.Y> [<sha>]
#
# Env:
#   RELEASE_LINE_REPO        owner/repo   (default artifact-keeper/artifact-keeper)
#   RELEASE_LINE_RULESET     ruleset id   (default 20038606)
#   RELEASE_LINE_TESTS_REPO  owner/repo   (default artifact-keeper/artifact-keeper-test)
#
# Exit codes: 0 created (or dry run passed), 1 refused / failed.
set -euo pipefail

REPO="${RELEASE_LINE_REPO:-artifact-keeper/artifact-keeper}"
RULESET="${RELEASE_LINE_RULESET:-20038606}"
TESTS_REPO="${RELEASE_LINE_TESTS_REPO:-artifact-keeper/artifact-keeper-test}"
DRY_RUN=0
TESTS_RUN=""
TESTS_SHA=""
RELAXED_SECONDS=0

usage() {
  cat <<USAGE
usage: $(basename "$0") [--dry-run] [--tests-from-run <id> | --tests-sha <sha>] <X.Y> [<sha>]

Creates refs/heads/release/<X.Y>.x at <sha> (default: the commit tagged
v<X.Y>.0) by putting ruleset ${RULESET} into 'evaluate' for the length of one
API call and back to 'active' from a trap, then creates the matching
release/<X.Y>.x in ${TESTS_REPO} at the suite commit that certified v<X.Y>.0.

  --dry-run               run every check and print the plan; change nothing
  --tests-from-run <id>   the successful Release Candidate run that certified
                          v<X.Y>.0; the test branch starts at the release-gate
                          commit that run used
  --tests-sha <sha>       the test-suite commit, given directly (40 hex)

One of the two --tests-* options is required unless ${TESTS_REPO} already has
the branch. If release/<X.Y>.x already exists here, only the test branch is
created.
USAGE
}

die() {
  echo "refused: $*" >&2
  exit 1
}

# A line created under a zero-approval ruleset would be just as writable by one
# person as the topic branches it came from. #6216 found that "pull request
# required" was set with required_approving_review_count = 0, so refuse to open
# the ruleset window until the review requirement is actually in place.
assert_review_requirement() {
  local ruleset review count stale last_push
  ruleset="$(gh api "repos/${REPO}/rulesets/${RULESET}")" \
    || die "could not read ruleset ${RULESET}; cannot check its review requirement."
  review="$(jq -c '.rules[]? | select(.type == "pull_request") | .parameters' <<< "$ruleset")"
  [[ -n "$review" && "$review" != "null" ]] \
    || die "ruleset ${RULESET} has no pull_request rule; a release PR needs a second reviewer (#6216)."
  count="$(jq -r '.required_approving_review_count // 0' <<< "$review")"
  [[ "$count" =~ ^[0-9]+$ && "$count" -ge 1 ]] \
    || die "ruleset ${RULESET} requires ${count} approving review(s); at least 1 is required (#6216)."
  stale="$(jq -r '.dismiss_stale_reviews_on_push // false' <<< "$review")"
  [[ "$stale" == "true" ]] \
    || die "ruleset ${RULESET} does not dismiss stale approvals on push (#6216)."
  last_push="$(jq -r '.require_last_push_approval // false' <<< "$review")"
  [[ "$last_push" == "true" ]] \
    || die "ruleset ${RULESET} does not require the last push to be approved by someone else (#6216)."
}

args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --tests-from-run)
      [[ $# -ge 2 ]] || die "--tests-from-run needs a run id."
      TESTS_RUN="$2"; shift 2 ;;
    --tests-sha)
      [[ $# -ge 2 ]] || die "--tests-sha needs a commit sha."
      TESTS_SHA="$2"; shift 2 ;;
    -h | --help) usage; exit 0 ;;
    -*) usage >&2; die "unknown option '$1'." ;;
    *) args+=("$1"); shift ;;
  esac
done
if [[ ${#args[@]} -lt 1 || ${#args[@]} -gt 2 ]]; then
  usage >&2
  exit 1
fi
LINE="${args[0]}"
SHA="${args[1]:-}"
[[ -z "$TESTS_RUN" || -z "$TESTS_SHA" ]] \
  || die "pass --tests-from-run or --tests-sha, not both."
[[ -z "$TESTS_RUN" || "$TESTS_RUN" =~ ^[1-9][0-9]*$ ]] \
  || die "--tests-from-run takes a numeric run id (got '${TESTS_RUN}')."

# The branch name is the ruleset's include pattern, not a free choice. The
# pattern was narrowed to `refs/heads/release/[0-9]*.[0-9]*.x` so working
# branches (`release/1.9.1-prep`) stop being governed by it -- which means any
# other shape under `release/` would create an UNPROTECTED branch that still
# looks like a release line to a reader.
[[ "$LINE" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] \
  || die "<X.Y> must be exactly two numbers, e.g. 1.10 (got '${LINE}'). The only branch this creates is release/X.Y.x."
BRANCH="release/${LINE}.x"

# 1. Admin, because only an admin can edit a ruleset. Ask GitHub rather than
#    assume: otherwise a non-admin finds out half way through, after the plan
#    has been printed as though it would work.
admin="$(gh api "repos/${REPO}" --jq '.permissions.admin' 2> /dev/null || true)"
[[ "$admin" == "true" ]] \
  || die "gh must be authenticated as an admin of ${REPO} (.permissions.admin = '${admin:-<unreadable>}')."

# 1a. The ruleset restored after the window must still require a second person.
assert_review_requirement

# 2. A clean fetch. Every ancestry answer below is read from local refs; a
#    stale origin/main would make them lies rather than checks.
git fetch --quiet --tags origin \
  || die "'git fetch origin' failed; refusing to reason about a stale origin/main."

# 3. The line must not already exist. Re-running is not free: the second POST
#    fails, but only after the ruleset has already been relaxed. The one
#    exception is a run that names a test-suite commit: that only creates the
#    test branch (retrying a failed one, or giving an older line one), and
#    never touches the ruleset.
BACKEND_EXISTS=0
if git ls-remote --exit-code --heads origin "refs/heads/${BRANCH}" > /dev/null 2>&1; then
  [[ -n "$TESTS_RUN$TESTS_SHA" ]] \
    || die "${BRANCH} already exists; an existing line needs no toggle (RELEASING.md, 'Patch releases from a release/X.Y.x branch'). To give it a ${TESTS_REPO} branch, re-run with --tests-from-run or --tests-sha."
  BACKEND_EXISTS=1
fi

VERSION=""
if [[ $BACKEND_EXISTS -eq 0 ]]; then
  # 4. The commit. Default to the tag that opened the line: that is what a cut
  #    actually wants, and a hand-typed sha is where this goes wrong.
  TAG="v${LINE}.0"
  TAG_NOTE=""
  if [[ -z "$SHA" ]]; then
    SHA="$(git rev-parse --verify --quiet "refs/tags/${TAG}^{commit}" || true)"
    [[ -n "$SHA" ]] \
      || die "there is no tag ${TAG}, so there is no default commit; pass the full 40-character sha explicitly."
    TAG_NOTE=", tagged ${TAG}"
  fi
  [[ "$SHA" =~ ^[0-9a-f]{40}$ ]] \
    || die "'${SHA}' is not a full 40-character commit sha. Abbreviations and ref names are refused; the sha is what the audit line records."
  git rev-parse --verify --quiet "${SHA}^{commit}" > /dev/null \
    || die "${SHA} is not a commit in this clone."

  # 5. Reachable from main. The release line's whole premise is that its content
  #    came through main -- 'Verify commits trace back to main' enforces it for
  #    every later commit, and nothing enforces it for the root one but this.
  git merge-base --is-ancestor "$SHA" origin/main \
    || die "${SHA} is not reachable from origin/main. A release line starts at a commit that is on main."

  # 6. ...and the version at that commit must belong to THIS line, or the branch
  #    name and `resolve-certified-ref.sh`'s derivation from Cargo.toml disagree
  #    from the first commit onwards.
  cargo_toml="$(git show "${SHA}:Cargo.toml" 2> /dev/null)" || die "${SHA} has no Cargo.toml."
  VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' <<< "$cargo_toml" | head -1)"
  [[ "$VERSION" == "${LINE}."* ]] \
    || die "Cargo.toml at ${SHA} says version '${VERSION:-<none>}', which is not on the ${LINE} line."
fi

# 7. The test-suite branch (#4372). Resolved and checked here, before
#    anything is relaxed, like everything above.
tests_push="$(gh api "repos/${TESTS_REPO}" --jq '.permissions.push' 2> /dev/null || true)"
[[ "$tests_push" == "true" ]] \
  || die "gh must be able to push to ${TESTS_REPO} (.permissions.push = '${tests_push:-<unreadable>}')."
# On a 404, gh still prints the error body to stdout, so the exit status and
# the shape of the answer are what decide, not whether anything was printed.
TESTS_EXISTING="$(gh api "repos/${TESTS_REPO}/branches/${BRANCH//\//%2F}" --jq '.commit.sha' 2> /dev/null)" \
  || TESTS_EXISTING=""
[[ -z "$TESTS_EXISTING" || "$TESTS_EXISTING" =~ ^[0-9a-f]{40}$ ]] \
  || die "could not read ${BRANCH} in ${TESTS_REPO} (got '${TESTS_EXISTING}')."
TESTS_NOTE=""
if [[ -n "$TESTS_RUN" ]]; then
  run_info="$(gh api "repos/${REPO}/actions/runs/${TESTS_RUN}" \
    --jq '[.name, .conclusion, ([.referenced_workflows[]? | select(.path | startswith("'"${TESTS_REPO}"'/.github/workflows/release-gate.yml@")) | .sha] | first // "")] | join(" ")' \
    2> /dev/null)" || die "could not read run ${TESTS_RUN} of ${REPO}."
  read -r -a run_fields <<< "$run_info"
  # name is "Release Candidate": two words, then conclusion, then the sha.
  [[ "${run_fields[0]:-} ${run_fields[1]:-}" == "Release Candidate" ]] \
    || die "run ${TESTS_RUN} is not a Release Candidate run ('${run_info}')."
  [[ "${run_fields[2]:-}" == "success" ]] \
    || die "run ${TESTS_RUN} concluded '${run_fields[2]:-<none>}', not success: it certified nothing."
  TESTS_SHA="${run_fields[3]:-}"
  [[ -n "$TESTS_SHA" ]] \
    || die "run ${TESTS_RUN} records no ${TESTS_REPO} release-gate.yml commit; pass --tests-sha instead."
  TESTS_NOTE=", the release-gate.yml commit of Release Candidate run ${TESTS_RUN}"
fi
if [[ -n "$TESTS_SHA" ]]; then
  [[ "$TESTS_SHA" =~ ^[0-9a-f]{40}$ ]] \
    || die "test-suite commit '${TESTS_SHA}' is not a full 40-character sha."
  # compare main...<sha>: 'behind' or 'identical' means <sha> is on main.
  tests_rel="$(gh api "repos/${TESTS_REPO}/compare/main...${TESTS_SHA}" --jq '.status' 2> /dev/null || true)"
  [[ "$tests_rel" == "behind" || "$tests_rel" == "identical" ]] \
    || die "${TESTS_SHA} is not on ${TESTS_REPO} main (compare status '${tests_rel:-<unreadable>}')."
elif [[ -z "$TESTS_EXISTING" ]]; then
  die "${TESTS_REPO} has no ${BRANCH}; pass --tests-from-run <the Release Candidate run that certified v${LINE}.0> or --tests-sha <40-hex>, so the line's candidates are not gated by main's suite (#4372)."
fi
if [[ -n "$TESTS_EXISTING" ]]; then
  TESTS_PLAN="exists at ${TESTS_EXISTING}; left as is"
  [[ -z "$TESTS_SHA" || "$TESTS_SHA" == "$TESTS_EXISTING" ]] \
    || TESTS_PLAN+=" (not moved to ${TESTS_SHA}: its tip carries cherry-picked companion tests, artifact-keeper-test#424)"
else
  TESTS_PLAN="create at ${TESTS_SHA}${TESTS_NOTE}"
fi

WHO="$(gh api user --jq '.login' 2> /dev/null || echo '<unknown>')"
STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if [[ $BACKEND_EXISTS -eq 1 ]]; then
  cat <<PLAN
== create release line ==
repo:    ${REPO}
branch:  refs/heads/${BRANCH} (exists; not touched, ruleset not toggled)
tests:   ${TESTS_REPO} refs/heads/${BRANCH}: ${TESTS_PLAN}
by:      ${WHO} at ${STARTED}
PLAN
else
  cat <<PLAN
== create release line ==
repo:    ${REPO}
branch:  refs/heads/${BRANCH}
sha:     ${SHA} (version ${VERSION}${TAG_NOTE})
ruleset: ${RULESET} -> evaluate, create the ref, -> active
tests:   ${TESTS_REPO} refs/heads/${BRANCH}: ${TESTS_PLAN}
by:      ${WHO} at ${STARTED}
PLAN
fi

if [[ $DRY_RUN -eq 1 ]]; then
  echo "--dry-run: every precondition passed and nothing was changed."
  exit 0
fi

# Outside the toggle window: artifact-keeper-test has no ruleset on release/*.
# Verified afterwards rather than assumed, like the backend ref.
TESTS_AUDIT=""
create_tests_branch() {
  if [[ -n "$TESTS_EXISTING" ]]; then
    TESTS_AUDIT="\`${TESTS_REPO}\` \`refs/heads/${BRANCH}\` already existed at \`${TESTS_EXISTING}\`; left as is."
    return 0
  fi
  gh api -X POST "repos/${TESTS_REPO}/git/refs" -f "ref=refs/heads/${BRANCH}" -f "sha=${TESTS_SHA}" > /dev/null \
    || die "could not create ${BRANCH} in ${TESTS_REPO}. Re-run this script with the same arguments: the backend line now exists, so it only creates the test branch."
  local got
  got="$(gh api "repos/${TESTS_REPO}/branches/${BRANCH//\//%2F}" --jq '.commit.sha' 2> /dev/null)" || got=""
  [[ "$got" == "$TESTS_SHA" ]] \
    || die "${TESTS_REPO} refs/heads/${BRANCH} points at '${got:-<missing>}', not ${TESTS_SHA}."
  TESTS_AUDIT="Created \`${TESTS_REPO}\` \`refs/heads/${BRANCH}\` at \`${TESTS_SHA}\`${TESTS_NOTE}."
}

if [[ $BACKEND_EXISTS -eq 1 ]]; then
  create_tests_branch
  cat <<AUDIT

== audit summary -- paste into the issue that asked for the line ==
\`refs/heads/${BRANCH}\` already existed in ${REPO}; the ruleset was not touched.
${TESTS_AUDIT}
Actor: ${WHO}. At: ${STARTED} UTC.
AUDIT
  exit 0
fi

BEFORE="./release-line-${LINE}-ruleset-before.json"
AFTER="./release-line-${LINE}-ruleset-after.json"

set_enforcement() { # <active|evaluate>
  printf '{"enforcement":"%s"}' "$1" \
    | gh api -X PUT "repos/${REPO}/rulesets/${RULESET}" --input - > /dev/null
}

# The window is closed from an EXIT trap, not from the happy path, so that a
# failed ref creation -- or a Ctrl-C, or a die() below -- cannot leave
# `release/*` protection switched off.
relaxed=0
relaxed_at=0
restore() {
  [[ $relaxed -eq 1 ]] || return 0
  relaxed=0
  RELAXED_SECONDS=$((SECONDS - relaxed_at))
  if set_enforcement active; then
    echo "ruleset ${RULESET}: enforcement=active restored after ${RELAXED_SECONDS}s."
  else
    echo "CRITICAL: ruleset ${RULESET} is STILL in 'evaluate' -- release/* protection is OFF. Restore it by hand, now:" >&2
    echo "  printf '{\"enforcement\":\"active\"}' | gh api -X PUT repos/${REPO}/rulesets/${RULESET} --input -" >&2
    exit 1
  fi
}
trap restore EXIT

gh api "repos/${REPO}/rulesets/${RULESET}" > "$BEFORE" \
  || die "could not snapshot ruleset ${RULESET}; nothing was changed."

set_enforcement evaluate || die "could not set enforcement=evaluate; nothing was changed."
relaxed=1
relaxed_at=$SECONDS
echo "ruleset ${RULESET}: enforcement=evaluate (window open)."

gh api -X POST "repos/${REPO}/git/refs" -f "ref=refs/heads/${BRANCH}" -f "sha=${SHA}" > /dev/null
restore

gh api "repos/${REPO}/rulesets/${RULESET}" > "$AFTER" \
  || die "${BRANCH} was created but the after-snapshot failed; check ruleset ${RULESET} by hand."

# Field by field: the window is the only moment anything else could have moved
# the ruleset, and "I put enforcement back" is a weaker claim than "nothing
# else changed". enforcement and updated_at are the two expected to differ.
if ! diff -u \
  <(jq -S 'del(.enforcement, .updated_at)' "$BEFORE") \
  <(jq -S 'del(.enforcement, .updated_at)' "$AFTER"); then
  die "ruleset ${RULESET} changed during the window beyond enforcement/updated_at (diff above). Review ${BEFORE} vs ${AFTER} before cutting anything."
fi

# The branch must come out GOVERNED. A ref created outside the include pattern
# would look identical from here; this is what proves it is not.
rules="$(gh api "repos/${REPO}/rules/branches/${BRANCH//\//%2F}" --jq '[.[].type] | sort | join(",")')"
for want in pull_request required_status_checks non_fast_forward deletion; do
  [[ ",${rules}," == *",${want},"* ]] \
    || die "refs/heads/${BRANCH} exists but is not governed by '${want}' (rules: ${rules:-<none>}). Investigate before cutting anything from it."
done
remote_sha="$(git ls-remote origin "refs/heads/${BRANCH}" | awk '{print $1}')"
[[ "$remote_sha" == "$SHA" ]] \
  || die "refs/heads/${BRANCH} points at '${remote_sha:-<missing>}', not ${SHA}."

create_tests_branch

cat <<AUDIT

== audit summary -- paste into the release PR, or the issue that asked for the line ==
Created \`refs/heads/${BRANCH}\` at \`${SHA}\` (Cargo.toml version ${VERSION}${TAG_NOTE}).
Actor: ${WHO}. Window: ${STARTED} -> $(date -u +%Y-%m-%dT%H:%M:%SZ) UTC.
Ruleset ${RULESET} was in \`evaluate\` for ${RELAXED_SECONDS}s and is \`active\` again;
before/after JSON identical apart from enforcement and updated_at
(${BEFORE}, ${AFTER}).
Branch reports rules: ${rules}.
${TESTS_AUDIT}
AUDIT
