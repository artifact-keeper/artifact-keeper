#!/usr/bin/env bash
#
# May this Docker Publish run move its branch's floating tags? (#6080)
#
# WHY THIS EXISTS
#   docker-publish.yml used to put every push to a branch in ONE concurrency
#   group per ref. GitHub keeps only one PENDING run per group, so a merge
#   landing while an earlier commit's run was still waiting REPLACED it: the
#   older run ended "cancelled" with zero jobs and its `sha-<sha>` images
#   never existed. When that commit was a Release Candidate, the candidate's
#   "Wait for a successful Docker Publish run" failed and the whole candidate
#   died (57a8ac57, 2026-11-10). Hence a merge freeze on main for every cut.
#
#   The group is now per COMMIT, so nothing can displace a push run. The one
#   thing the per-ref queue really bought was ORDER: runs finished in merge
#   order, so the branch's floating tags (`:main`, `:dev`, `:X.Y-dev`, and
#   the `:release-X.Y.x` branch tag) always ended on the newest commit. With
#   runs in parallel an older commit's run can finish last. This script keeps
#   the tags monotonic without a queue: a run moves them only when its commit
#   is not BEHIND the commit they already name.
#
# THE DECISION (one probe tag per branch, read from the image being written)
#   refs/heads/main            probe `:dev`
#   refs/heads/release/X.Y.x   probe `:X.Y-dev`
#   anything else              no probe -> move (today's behaviour)
#
#   probe tag's recorded revision  compare <rev>...<sha>   decision
#   absent / unreadable            -                       move
#   == this commit                 -                       move (re-run)
#   a commit                       ahead | identical       move
#   a commit                       behind                  KEEP (newer published)
#   a commit                       diverged                move (rewritten
#                                                          history: last writer
#                                                          wins, as before)
#   a commit                       API failure             move
#
#   Every doubt resolves to "move", which is exactly what the workflow did
#   before this guard existed: the guard can only ever withhold a floating
#   tag from a run whose commit is provably older than the one the tag
#   already names. It never touches `sha-<sha>`, the exact version tag, a
#   signature or an attestation.
#
#   RESIDUAL RACE, stated: two runs that both read the probe before either
#   writes can still finish older-last. The window is the few seconds between
#   this read and the `imagetools create` in the same job; the next merge
#   corrects it.
#
# OUTPUT
#   stdout: `move=true|false reason=<word> probe=<tag> current=<sha|state>`
#   $GITHUB_OUTPUT (when set): `move=true|false`
#   exit 0 always, except a usage error (exit 2).
#
# Usage: decide-branch-floating-tags.sh <ghcr repository, e.g. owner/name-backend>
# Env:
#   FLOATING_SHA    commit this run built         (default $GITHUB_SHA)
#   FLOATING_REF    ref this run publishes for    (default $GITHUB_REF)
#   FLOATING_REPO   owner/name for the compare API (default $GITHUB_REPOSITORY)
#   FLOATING_REVISION_CMD  registry-tag-revision.sh to use (tests stub it)
#   GH_TOKEN, GHCR_TOKEN   as for gh and registry-tag-revision.sh
set -uo pipefail

if [[ $# -ne 1 || -z "$1" ]]; then
  echo "usage: $0 <ghcr repository>" >&2
  exit 2
fi
IMAGE="$1"
SHA="${FLOATING_SHA:-${GITHUB_SHA:-}}"
REF="${FLOATING_REF:-${GITHUB_REF:-}}"
REPO="${FLOATING_REPO:-${GITHUB_REPOSITORY:-artifact-keeper/artifact-keeper}}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REVISION_CMD="${FLOATING_REVISION_CMD:-${HERE}/../../.github/scripts/registry-tag-revision.sh}"

decide() { # <move> <reason> <probe> <current>
  echo "move=$1 reason=$2 probe=${3:--} current=${4:--}"
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "move=$1" >> "$GITHUB_OUTPUT"
  fi
  if [[ "$1" == "false" ]]; then
    echo "::notice title=Floating tags left alone::${IMAGE}:${3} already names ${4}, which is newer than ${SHA}; this run publishes sha-${SHA:0:7} only (#6080)."
  fi
  exit 0
}

if [[ ! "$SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "::warning title=Floating-tag guard skipped::no 40-hex commit (got '${SHA}'); moving the floating tags as before." >&2
  decide true no-sha "" ""
fi

probe=""
if [[ "$REF" == "refs/heads/main" ]]; then
  probe="dev"
elif [[ "$REF" =~ ^refs/heads/release/([0-9]+\.[0-9]+)\.x$ ]]; then
  probe="${BASH_REMATCH[1]}-dev"
else
  decide true no-probe "" ""
fi

current="$(bash "$REVISION_CMD" ghcr.io "$IMAGE" "$probe" 2>/dev/null)" || true
if [[ ! "$current" =~ ^[0-9a-f]{40}$ ]]; then
  decide true "probe-${current:-unreadable}" "$probe" "${current:-unreadable}"
fi
if [[ "$current" == "$SHA" ]]; then
  decide true same-commit "$probe" "$current"
fi

status="$(gh api "repos/${REPO}/compare/${current}...${SHA}" --jq '.status' 2>/dev/null)" || status=""
case "$status" in
  ahead|identical) decide true "$status" "$probe" "$current" ;;
  behind)          decide false behind "$probe" "$current" ;;
  diverged)
    echo "::warning title=Floating tag history diverged::${IMAGE}:${probe} names ${current}, which shares no line with ${SHA}; moving it (last writer wins)." >&2
    decide true diverged "$probe" "$current" ;;
  *)
    echo "::warning title=Floating-tag guard could not compare::compare ${current:0:7}...${SHA:0:7} gave '${status:-no answer}'; moving the floating tags as before." >&2
    decide true compare-unknown "$probe" "$current" ;;
esac
