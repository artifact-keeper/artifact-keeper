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
# bypass actors. A required status check cannot exist on a ref that does not
# exist yet, so the very push that would create a release line is refused:
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
# Runs locally, on a workstation, by a human admin -- so the messages here are
# plain text, not `::error` workflow annotations.
#
# Usage:  create-release-line.sh [--dry-run] <X.Y> [<sha>]
#
# Env:
#   RELEASE_LINE_REPO     owner/repo   (default artifact-keeper/artifact-keeper)
#   RELEASE_LINE_RULESET  ruleset id   (default 20038606)
#
# Exit codes: 0 created (or dry run passed), 1 refused / failed.
set -euo pipefail

REPO="${RELEASE_LINE_REPO:-artifact-keeper/artifact-keeper}"
RULESET="${RELEASE_LINE_RULESET:-20038606}"
DRY_RUN=0
RELAXED_SECONDS=0

usage() {
  cat <<USAGE
usage: $(basename "$0") [--dry-run] <X.Y> [<sha>]

Creates refs/heads/release/<X.Y>.x at <sha> (default: the commit tagged
v<X.Y>.0) by putting ruleset ${RULESET} into 'evaluate' for the length of one
API call and back to 'active' from a trap.

  --dry-run   run every check and print the plan; change nothing
USAGE
}

die() {
  echo "refused: $*" >&2
  exit 1
}

args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
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

# 2. A clean fetch. Every ancestry answer below is read from local refs; a
#    stale origin/main would make them lies rather than checks.
git fetch --quiet --tags origin \
  || die "'git fetch origin' failed; refusing to reason about a stale origin/main."

# 3. The line must not already exist. Re-running is not free: the second POST
#    fails, but only after the ruleset has already been relaxed.
if git ls-remote --exit-code --heads origin "refs/heads/${BRANCH}" > /dev/null 2>&1; then
  die "${BRANCH} already exists; an existing line needs no toggle (RELEASING.md, 'Patch releases from a release/X.Y.x branch')."
fi

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

WHO="$(gh api user --jq '.login' 2> /dev/null || echo '<unknown>')"
STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat <<PLAN
== create release line ==
repo:    ${REPO}
branch:  refs/heads/${BRANCH}
sha:     ${SHA} (version ${VERSION}${TAG_NOTE})
ruleset: ${RULESET} -> evaluate, create the ref, -> active
by:      ${WHO} at ${STARTED}
PLAN

if [[ $DRY_RUN -eq 1 ]]; then
  echo "--dry-run: every precondition passed and nothing was changed."
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

cat <<AUDIT

== audit summary -- paste into the release PR, or the issue that asked for the line ==
Created \`refs/heads/${BRANCH}\` at \`${SHA}\` (Cargo.toml version ${VERSION}${TAG_NOTE}).
Actor: ${WHO}. Window: ${STARTED} -> $(date -u +%Y-%m-%dT%H:%M:%SZ) UTC.
Ruleset ${RULESET} was in \`evaluate\` for ${RELAXED_SECONDS}s and is \`active\` again;
before/after JSON identical apart from enforcement and updated_at
(${BEFORE}, ${AFTER}).
Branch reports rules: ${rules}.
AUDIT
