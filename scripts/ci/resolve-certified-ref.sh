#!/usr/bin/env bash
#
# Which branch is allowed to have certified this commit -- decided from
# REPOSITORY STATE ALONE, never from a dispatch input (issues #3771, #3772;
# release-branch candidates).
#
# WHY THIS EXISTS
#   The release-candidate certification is trusted because of ONE thing: the
#   Sigstore certificate's SubjectAlternativeName, pinned byte-for-byte to
#   `.../release-candidate.yml@<ref>`. While `<ref>` was only ever
#   `refs/heads/main`, "which ref" needed no thought. A patch release is cut
#   from `release/X.Y.x`, so the candidate runs there and signs with THAT
#   ref -- and the moment more than one ref can sign, "which ref" becomes the
#   whole security question.
#
#   It is answered here, and only here, so every consumer answers it the same
#   way. Two rules, both derived, neither typed:
#
#     1. THE REF. The certified commit must be an ancestor of `main`; if it is
#        not, it must be an ancestor of `refs/heads/release/<X>.<Y>.x`, where
#        X and Y are read from `Cargo.toml` AT THAT COMMIT. The branch name is
#        therefore a function of the commit's own content and the repository's
#        refs. A `release/*` wildcard is never used and no caller may name the
#        branch: an attacker who could pick the name would only have to put
#        their version in Cargo.toml and their branch name would be "derived".
#        Existence is checked case-sensitively against the git-refs API
#        (`refs/heads/release/1.9.x` and `refs/heads/release/1.9.X` are
#        different refs; GitHub's compare API is more forgiving than git is).
#
#     2. THE CONTENT (defence in depth). The attack this is defending against
#        is an EDITED release-candidate.yml on a branch that is allowed to
#        sign -- gate removed, everything else intact. Pinning the ref does
#        not catch that, so the FILE is pinned too: `release-candidate.yml` at
#        the certified commit must be byte-identical (same git blob id) to the
#        copy `main` carries at the MERGE BASE of main and that commit, i.e.
#        the copy main had when the release line was cut. A copy that was
#        never on main cannot certify anything.
#
#        Forward-porting is not blocked: cherry-picking main's CURRENT
#        release-candidate.yml onto a maintenance branch is the documented
#        remedy when the merge-base copy is out of date, so main's tip copy is
#        accepted as well, loudly. Both accepted blobs are copies that live on
#        main; nothing else is.
#
# WHAT IT IS NOT
#   Not an authorisation check. It says which ref *would* be allowed to sign
#   for this commit; `gh attestation verify` still has to prove that ref
#   actually did. See scripts/ci/assert-candidate-certified.sh.
#
# Output: `key=value` lines on STDOUT (and appended to $GITHUB_OUTPUT when
# set); all human chatter on STDERR, so a caller can read stdout directly.
#   certified_ref=refs/heads/release/1.9.x
#   certified_branch=release/1.9.x
#   version=1.9.1
#   merge_base=<40-hex>
#
# Exit codes (same vocabulary as assert-candidate-certified.sh):
#   0  resolved
#   1  BLOCKED -- the commit is on no releasable branch, or the workflow file
#      at it is not a copy that lives on main
#   2  INFRA   -- could not measure (API). NOT a pass.
#
# Env / args:
#   $1 or CERTREF_SHA         (required) 40-hex commit
#   CERTREF_REPO / CERT_REPO  owner/name (default artifact-keeper/artifact-keeper)
#   CERTREF_MAIN_BRANCH       default `main`
#   CERTREF_WORKFLOW_PATH     default .github/workflows/release-candidate.yml
#   GH_TOKEN                  for gh
#
set -uo pipefail

SHA="${1:-${CERTREF_SHA:-}}"
REPO="${CERTREF_REPO:-${CERT_REPO:-artifact-keeper/artifact-keeper}}"
MAIN_BRANCH="${CERTREF_MAIN_BRANCH:-main}"
WORKFLOW_PATH="${CERTREF_WORKFLOW_PATH:-.github/workflows/release-candidate.yml}"

blocked() { echo "::error title=Commit is on no releasable branch::$1" >&2; printf 'BLOCKED: %s\n' "$1" >&2; exit 1; }
infra()   { echo "::error title=Certified ref could not be resolved::$1 Retry; do not interpret as a pass." >&2; printf 'INFRA: %s\n' "$1" >&2; exit 2; }

[[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || infra "a full 40-character commit sha is required (got '${SHA}')."
command -v gh >/dev/null 2>&1 || infra "gh is not on PATH."
command -v jq >/dev/null 2>&1 || infra "jq is not on PATH."

ERRF="$(mktemp)"
trap 'rm -f "$ERRF"' EXIT

# `gh api` with the one distinction that matters: a 404 is an answer ("not
# there"), anything else is a failure to measure. Prints the body; returns 0
# on success, 3 on a clean 404, 2 on anything else.
api() {
  local out rc=0
  : >"$ERRF"
  out="$(gh api "$@" 2>"$ERRF")" || rc=$?
  if [[ "$rc" -ne 0 ]]; then
    grep -q 'HTTP 404' "$ERRF" && return 3
    return 2
  fi
  printf '%s' "$out"
  return 0
}
api_err() { tr '\n' ' ' <"$ERRF"; }

raw_at() { # <ref> <path>
  api -H 'Accept: application/vnd.github.raw+json' "repos/${REPO}/contents/$2?ref=$1"
}
blob_at() { # <ref> <path> -> the git blob id, i.e. content identity
  api "repos/${REPO}/contents/$2?ref=$1" --jq '.sha'
}

# ── the version at the commit, which names the maintenance line ──────────────
rc=0; cargo_toml="$(raw_at "$SHA" Cargo.toml)" || rc=$?
case "$rc" in
  0) ;;
  3) blocked "${SHA} has no Cargo.toml (is it a commit in ${REPO}?)." ;;
  *) infra "could not read Cargo.toml at ${SHA} ($(api_err))." ;;
esac
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' <<<"$cargo_toml" | head -1)"
if [[ ! "$VERSION" =~ ^([0-9]+)\.([0-9]+)\.[0-9]+$ ]]; then
  blocked "Cargo.toml at ${SHA} says version '${VERSION:-<none>}'. A certified commit names a stable X.Y.Z; prereleases keep the -rc.N tag path."
fi
MAJOR="${BASH_REMATCH[1]}"; MINOR="${BASH_REMATCH[2]}"
REL_BRANCH="release/${MAJOR}.${MINOR}.x"

echo "== certified ref =="                >&2
echo "repo:    ${REPO}"                   >&2
echo "commit:  ${SHA}"                    >&2
echo "version: ${VERSION}"                >&2

# ── 1. ancestor of main? ─────────────────────────────────────────────────────
# `compare/<base>...<head>`: `behind` means head is an ancestor of base,
# `identical` means they are the same commit. Both mean "on main".
rc=0; cmp_main="$(api "repos/${REPO}/compare/${MAIN_BRANCH}...${SHA}")" || rc=$?
case "$rc" in
  0) ;;
  3) infra "${MAIN_BRANCH} could not be compared with ${SHA} (404); the branch or the commit is missing." ;;
  *) infra "could not compare ${MAIN_BRANCH}...${SHA} ($(api_err))." ;;
esac
main_status="$(jq -r '.status // empty' <<<"$cmp_main")"
MERGE_BASE="$(jq -r '.merge_base_commit.sha // empty' <<<"$cmp_main")"
[[ "$MERGE_BASE" =~ ^[0-9a-f]{40}$ ]] || infra "the comparison of ${MAIN_BRANCH} with ${SHA} named no merge base."

if [[ "$main_status" == "behind" || "$main_status" == "identical" ]]; then
  CERTIFIED_BRANCH="$MAIN_BRANCH"
  echo "ref:     refs/heads/${MAIN_BRANCH} (${SHA} is on ${MAIN_BRANCH}: ${main_status})" >&2
else
  # ── 2. else the maintenance line the version names ─────────────────────────
  # Case-sensitively: git refs are, and the compare API is not to be trusted
  # for that. `release/1.9.X` is a different branch and must not resolve here.
  rc=0; ref_json="$(api "repos/${REPO}/git/ref/heads/${REL_BRANCH}")" || rc=$?
  case "$rc" in
    0) ;;
    3) blocked "${SHA} is '${main_status}' relative to ${MAIN_BRANCH} and refs/heads/${REL_BRANCH} does not exist. A commit is certified from ${MAIN_BRANCH} or from the maintenance branch its own Cargo.toml names (${VERSION} -> ${REL_BRANCH}); cut that branch first, or certify a commit that is on ${MAIN_BRANCH}." ;;
    *) infra "could not look up refs/heads/${REL_BRANCH} ($(api_err))." ;;
  esac
  actual_ref="$(jq -r '.ref // empty' <<<"$ref_json")"
  if [[ "$actual_ref" != "refs/heads/${REL_BRANCH}" ]]; then
    blocked "the refs API answered '${actual_ref:-<none>}' for refs/heads/${REL_BRANCH}. Git refs are case-sensitive and only the exact name is accepted."
  fi
  rc=0; cmp_rel="$(api "repos/${REPO}/compare/${REL_BRANCH}...${SHA}")" || rc=$?
  case "$rc" in
    0) ;;
    3) blocked "refs/heads/${REL_BRANCH} could not be compared with ${SHA} (404)." ;;
    *) infra "could not compare ${REL_BRANCH}...${SHA} ($(api_err))." ;;
  esac
  rel_status="$(jq -r '.status // empty' <<<"$cmp_rel")"
  if [[ "$rel_status" != "behind" && "$rel_status" != "identical" ]]; then
    blocked "${SHA} is on neither branch: '${main_status}' relative to ${MAIN_BRANCH}, '${rel_status}' relative to ${REL_BRANCH}. Cargo.toml at that commit says ${VERSION}, so ${REL_BRANCH} is the only maintenance line it could be certified from."
  fi
  CERTIFIED_BRANCH="$REL_BRANCH"
  echo "ref:     refs/heads/${REL_BRANCH} (${SHA} is on it: ${rel_status}; ${main_status} relative to ${MAIN_BRANCH})" >&2
fi

# ── 3. the content pin: the signing workflow must be a copy that is on main ──
# Ref and content are pinned separately because the attack is an EDITED
# workflow on a ref that is allowed to sign. Costs three API calls.
rc=0; blob_here="$(blob_at "$SHA" "$WORKFLOW_PATH")" || rc=$?
case "$rc" in
  0) ;;
  3) blocked "${WORKFLOW_PATH} does not exist at ${SHA}. Cherry-pick it from ${MAIN_BRANCH} alongside the rest of the candidate flow." ;;
  *) infra "could not read ${WORKFLOW_PATH} at ${SHA} ($(api_err))." ;;
esac
rc=0; blob_base="$(blob_at "$MERGE_BASE" "$WORKFLOW_PATH")" || rc=$?
case "$rc" in
  0|3) ;;
  *) infra "could not read ${WORKFLOW_PATH} at the merge base ${MERGE_BASE} ($(api_err))." ;;
esac
if [[ -n "$blob_base" && "$blob_here" == "$blob_base" ]]; then
  echo "workflow: ${WORKFLOW_PATH} at ${SHA} is ${MAIN_BRANCH}'s copy at the merge base ${MERGE_BASE:0:7} (blob ${blob_here:0:12})." >&2
else
  rc=0; blob_tip="$(blob_at "$MAIN_BRANCH" "$WORKFLOW_PATH")" || rc=$?
  case "$rc" in
    0) ;;
    3) infra "${WORKFLOW_PATH} does not exist on ${MAIN_BRANCH}; there is nothing to pin the content to." ;;
    *) infra "could not read ${WORKFLOW_PATH} on ${MAIN_BRANCH} ($(api_err))." ;;
  esac
  if [[ "$blob_here" != "$blob_tip" ]]; then
    blocked "${WORKFLOW_PATH} at ${SHA} (blob ${blob_here:0:12}) is neither ${MAIN_BRANCH}'s copy at the merge base ${MERGE_BASE:0:7} (${blob_base:0:12}) nor ${MAIN_BRANCH}'s current copy (${blob_tip:0:12}). The workflow that signs a certification must be a copy that lives on ${MAIN_BRANCH}, byte for byte -- an edited copy on a branch that is allowed to sign is exactly what this refuses. Cherry-pick ${MAIN_BRANCH}'s ${WORKFLOW_PATH} onto ${CERTIFIED_BRANCH} instead of editing it there."
  fi
  echo "::notice title=Forward-ported release-candidate.yml::${WORKFLOW_PATH} at ${SHA} is ${MAIN_BRANCH}'s CURRENT copy (blob ${blob_here:0:12}), not the copy at the merge base ${MERGE_BASE:0:7}. Accepted: it is still a copy that lives on ${MAIN_BRANCH}." >&2
  echo "workflow: ${WORKFLOW_PATH} at ${SHA} is ${MAIN_BRANCH}'s current copy (blob ${blob_here:0:12}), forward-ported." >&2
fi

emit() {
  echo "$1=$2"
  [[ -n "${GITHUB_OUTPUT:-}" ]] && echo "$1=$2" >> "$GITHUB_OUTPUT"
  return 0
}
emit certified_ref "refs/heads/${CERTIFIED_BRANCH}"
emit certified_branch "$CERTIFIED_BRANCH"
emit version "$VERSION"
emit merge_base "$MERGE_BASE"
exit 0
