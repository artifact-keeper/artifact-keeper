#!/usr/bin/env bash
#
# Which lines the nightly release gate tests tonight, and which image each
# one tests (#6073).
#
# A LINE is `main` or an active maintenance branch `release/X.Y.x`. A branch
# is active when its newest commit is less than LINES_ACTIVE_DAYS old (default
# 30): 1.11.x, which still gets backports, is tested; release/1.10.x and
# older, untouched for months, are not. LINES_OVERRIDE (the dispatch input or
# the NIGHTLY_GATE_LINES repository variable) replaces the derivation.
#
# A line's IMAGE is the `sha-<short>` set from that branch's newest
# SUCCESSFUL Docker Publish run (push or workflow_dispatch; schedule runs
# are not considered), so it is what a candidate cut from that line today
# would test. As in release-candidate.yml's `images` job, the backend tag
# must resolve to a digest and the image's recorded revision must BE the
# commit, or the line is reported as unresolved rather than tested.
#
# The TESTS REF is not chosen here. The gate picks it at every job with
# artifact-keeper-test's scripts/switch-tests-ref.sh, from Cargo.toml at the
# tested commit, exactly as it does for a candidate. When LINES_TESTS_DIR
# names a checkout of artifact-keeper-test at main, the same script is run
# here so the verdict can RECORD which tests ref and commit the line was
# measured against. The gate checks the tests out again in each job, so a
# push to the tests branch mid-run can make the gate's tests newer than the
# recorded commit; that is noted in the verdict, not prevented.
#
# OUTPUT: a JSON array on stdout, one object per line:
#   {"line":"main","branch":"main","sha":"<40>","short":"<7>",
#    "digest":"sha256:...","publish_run":<id>,"version":"X.Y.Z",
#    "tests_ref":"main|release/X.Y.x","tests_sha":"<40>"}
# or, for a line that cannot be tested tonight,
#   {"line":"1.11.x","branch":"release/1.11.x","error":"<why>"}
# Exit 0 when at least one line resolved, 1 when none did, 2 usage error.
#
# Env:
#   LINES_REPO          owner/name (default artifact-keeper/artifact-keeper)
#   LINES_OVERRIDE      lines to test, separated by spaces or commas:
#                       main, 1.11.x or release/1.11.x
#   LINES_ACTIVE_DAYS   activity window for maintenance branches (default 30)
#   LINES_NOW           epoch seconds to measure the window from (tests)
#   LINES_GIT_DIR       backend checkout whose origin/release/* refs are
#                       fetched (default .)
#   LINES_DIGEST_CMD    default .github/scripts/registry-tag-digest.sh
#   LINES_REVISION_CMD  default .github/scripts/registry-tag-revision.sh
#   LINES_TESTS_DIR     optional artifact-keeper-test checkout at main
#   GHCR_TOKEN          read by the registry helpers
#
set -uo pipefail

REPO="${LINES_REPO:-artifact-keeper/artifact-keeper}"
DAYS="${LINES_ACTIVE_DAYS:-30}"
NOW="${LINES_NOW:-$(date +%s)}"
GIT_DIR_="${LINES_GIT_DIR:-.}"
DIGEST_CMD="${LINES_DIGEST_CMD:-.github/scripts/registry-tag-digest.sh}"
REVISION_CMD="${LINES_REVISION_CMD:-.github/scripts/registry-tag-revision.sh}"
TESTS_DIR="${LINES_TESTS_DIR:-}"
IMAGE="${REPO#*/}-backend"
OWNER="${REPO%%/*}"

if ! [[ "$DAYS" =~ ^[0-9]+$ ]]; then
  echo "nightly-gate-lines: LINES_ACTIVE_DAYS must be a number" >&2
  exit 2
fi

# ── which lines ───────────────────────────────────────────────────────────────
lines=()
if [[ -n "${LINES_OVERRIDE:-}" ]]; then
  for l in ${LINES_OVERRIDE//,/ }; do
    l="${l#release/}"
    if [[ "$l" != main && ! "$l" =~ ^[0-9]+\.[0-9]+\.x$ ]]; then
      echo "nightly-gate-lines: '${l}' is not main or X.Y.x" >&2
      exit 2
    fi
    lines+=("$l")
  done
else
  lines+=(main)
  cutoff=$((NOW - DAYS * 86400))
  while read -r name when; do
    [[ "$name" =~ ^release/[0-9]+\.[0-9]+\.x$ ]] || continue
    (( when >= cutoff )) || continue
    lines+=("${name#release/}")
  done < <(git -C "$GIT_DIR_" for-each-ref --format='%(refname:strip=3) %(committerdate:unix)' \
             'refs/remotes/origin/release/' | sort -k1,1Vr)
fi

# ── one line ──────────────────────────────────────────────────────────────────
resolve_line() { # <line> -> one JSON object on stdout; exit 1 when unresolved
  local line="$1" branch sha short digest rev run version tests_ref tests_sha
  branch="main"; [[ "$line" == main ]] || branch="release/${line}"
  bad() { jq -cn --arg line "$line" --arg branch "$branch" --arg error "$1" \
            '{line: $line, branch: $branch, error: $error}'; return 1; }

  if ! run="$(gh api "repos/${REPO}/actions/workflows/docker-publish.yml/runs?branch=${branch}&status=success&per_page=30" \
      --jq '[.workflow_runs[] | select(.event == "push" or .event == "workflow_dispatch")]
            | sort_by(.created_at) | reverse | .[0] // empty | "\(.id) \(.head_sha)"' 2>/dev/null)"; then
    bad "could not list Docker Publish runs for ${branch}"; return
  fi
  if [[ -z "$run" ]]; then
    bad "no successful Docker Publish run on ${branch}"; return
  fi
  sha="${run#* }"; run="${run%% *}"
  if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ]]; then
    bad "Docker Publish run ${run} has no usable head sha"; return
  fi
  short="${sha:0:7}"

  digest="$("$DIGEST_CMD" ghcr.io "${OWNER}/${IMAGE}" "sha-${short}" 2>/dev/null || true)"
  if [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    bad "ghcr.io/${OWNER}/${IMAGE}:sha-${short} is '${digest:-unreadable}'"; return
  fi
  rev="$("$REVISION_CMD" ghcr.io "${OWNER}/${IMAGE}" "sha-${short}" 2>/dev/null || true)"
  if [[ "$rev" != "$sha" ]]; then
    bad "ghcr.io/${OWNER}/${IMAGE}:sha-${short} records revision '${rev:-none}', not ${sha}"; return
  fi

  version="$(git -C "$GIT_DIR_" show "${sha}:Cargo.toml" 2>/dev/null \
               | sed -n 's/^version = "\([^"]*\)"/\1/p' | head -1)"

  tests_ref=""; tests_sha=""
  if [[ -n "$TESTS_DIR" ]]; then
    # The gate's own decision, made by the gate's own script.
    if (cd "$TESTS_DIR" && git checkout --quiet --detach origin/main \
          && BACKEND_TAG="sha-${short}" scripts/switch-tests-ref.sh >&2); then
      tests_ref="$(cat "${TESTS_DIR}/deploy-test/.tests-ref" 2>/dev/null || echo main)"
      tests_sha="$(git -C "$TESTS_DIR" rev-parse HEAD)"
    else
      echo "nightly-gate-lines: switch-tests-ref.sh failed for ${line}; tests ref not recorded" >&2
    fi
  fi

  jq -cn --arg line "$line" --arg branch "$branch" --arg sha "$sha" --arg short "$short" \
         --arg digest "$digest" --argjson run "$run" --arg version "$version" \
         --arg tests_ref "$tests_ref" --arg tests_sha "$tests_sha" \
    '{line: $line, branch: $branch, sha: $sha, short: $short, digest: $digest,
      publish_run: $run, version: $version, tests_ref: $tests_ref, tests_sha: $tests_sha}'
}

ok=0
objs=()
for l in "${lines[@]}"; do
  if obj="$(resolve_line "$l")"; then ok=$((ok + 1)); else
    echo "nightly-gate-lines: ${l}: $(jq -r .error <<<"$obj")" >&2
  fi
  objs+=("$obj")
done
printf '%s\n' "${objs[@]}" | jq -cs .
(( ok > 0 ))
