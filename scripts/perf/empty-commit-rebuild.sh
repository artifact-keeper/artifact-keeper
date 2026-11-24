#!/usr/bin/env bash
# =============================================================================
# scripts/perf/empty-commit-rebuild.sh - what one commit that changes no
# source costs an incremental dev build of the backend (#6181)
# =============================================================================
# In a git work tree of this repository: build the backend once to warm the
# target dir, time a no-op rebuild, then RUNS times make an empty commit and
# time the rebuild after it. Each rebuild runs with cargo's fingerprint log, so
# the units it recompiled, and the first reason cargo gives for each, are
# recorded next to the wall time.
#
# Before #6181, build.rs watched HEAD and baked `git rev-parse HEAD` into the
# crate, so every commit reran it and recompiled the whole backend (lib, both
# binaries). After it, the empty commit leaves every unit Fresh.
#
# IT COMMITS. Each run adds RUNS empty commits to HEAD, so it refuses to run
# on a branch: use a throwaway worktree on a detached HEAD, e.g.
#   git worktree add --detach /tmp/ak-perf origin/main && cd /tmp/ak-perf
# or set EMPTY_COMMIT_REBUILD_ALLOW_BRANCH=1 in a clone you will throw away.
#
# MODE=git-sha times the other case instead: a build that sets GIT_SHA (as a
# shipped build, or a local `GIT_SHA=$(git rev-parse HEAD) cargo build`, does)
# and sees a new value on each commit. The backend must recompile then, since
# it embeds the value; what the step shows is how much else reruns with it.
# Since ak-build-info (#6181) only that crate's tiny build script does, not
# the backend's proto codegen. This mode makes no commits.
#
# Usage (from that work tree):
#   scripts/perf/empty-commit-rebuild.sh [label]
# Env:
#   MODE          empty-commit (default) or git-sha
#   RUNS          empty commits (or GIT_SHA values) to time (default 3)
#   CARGO_ARGS    what to build (default "build -p artifact-keeper-backend")
#   GIT_SHA       must be unset: it is what a shipped build sets, and it hides
#                 the dev-build behaviour this measures. The script refuses it.
# Output: a table on stdout and <label>.tsv (label, step, seconds, units
# recompiled, first dirty reason) in the current directory. Logs go to
# <label>-<step>.log. Needs bash 5 (EPOCHREALTIME), git and cargo.
# The commits it makes are left in place; drop them with
#   git reset --hard HEAD~<RUNS>   (or just remove the worktree)
# =============================================================================
set -euo pipefail

LABEL="${1:-run}"
RUNS="${RUNS:-3}"
MODE="${MODE:-empty-commit}"
case "$MODE" in
  empty-commit | git-sha) ;;
  *) echo "empty-commit-rebuild: MODE must be empty-commit or git-sha" >&2; exit 2 ;;
esac
read -r -a CARGO_CMD <<<"${CARGO_ARGS:-build -p artifact-keeper-backend}"

if [[ -n "${GIT_SHA:-}" ]]; then
  echo "empty-commit-rebuild: unset GIT_SHA first (a shipped build sets it; this measures a dev build)" >&2
  exit 2
fi
if [[ -z "${EPOCHREALTIME:-}" ]]; then
  echo "empty-commit-rebuild: needs bash 5 (EPOCHREALTIME)" >&2
  exit 2
fi
git rev-parse --is-inside-work-tree >/dev/null
if [[ "$MODE" == empty-commit ]] && branch="$(git symbolic-ref -q --short HEAD)" && [[ "${EMPTY_COMMIT_REBUILD_ALLOW_BRANCH:-0}" != 1 ]]; then
  echo "empty-commit-rebuild: HEAD is branch '${branch}', and this script commits to HEAD." >&2
  echo "  Run it in a throwaway worktree on a detached HEAD (git worktree add --detach <dir> origin/main)," >&2
  echo "  or set EMPTY_COMMIT_REBUILD_ALLOW_BRANCH=1 in a clone you will throw away." >&2
  exit 2
fi
if ! [[ "$RUNS" =~ ^[0-9]+$ ]]; then
  echo "empty-commit-rebuild: RUNS must be a number" >&2
  exit 2
fi

out="${LABEL}.tsv"
printf 'label\tstep\tseconds\trecompiled\tfirst_dirty_reason\n' >"$out"

# measure <step>: one timed cargo run with the fingerprint log on.
measure() {
  local step="$1" log="${LABEL}-$1.log" t0 t1 secs units reason
  t0="$EPOCHREALTIME"
  CARGO_LOG=cargo::core::compiler::fingerprint=info cargo "${CARGO_CMD[@]}" >"$log" 2>&1
  t1="$EPOCHREALTIME"
  secs="$(awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.1f", b - a }')"
  # "Compiling <pkg> v<ver> (<path>)": one line per package rustc ran for.
  units="$(grep -cE '^ *Compiling ' "$log" || true)"
  reason="$(grep -m1 -oE 'dirty: .*' "$log" | cut -c1-160 || true)"
  printf '%s\t%s\t%s\t%s\t%s\n' "$LABEL" "$step" "$secs" "$units" "${reason:--}" >>"$out"
  printf '%-10s %-8s %8ss  recompiled %-3s %s\n' "$LABEL" "$step" "$secs" "$units" "${reason:--}"
}

echo "== ${LABEL} (${MODE}): warming the target dir (cargo ${CARGO_CMD[*]})"
if [[ "$MODE" == git-sha ]]; then
  # A distinct 40-hex value per step, as consecutive commits would give.
  GIT_SHA="$(printf '%040d' 0)"
  export GIT_SHA
  measure warm
  measure noop
  for i in $(seq 1 "$RUNS"); do
    GIT_SHA="$(printf '%040d' "$i")"
    measure "sha-${i}"
  done
  unset GIT_SHA
else
  measure warm
  measure noop
  for i in $(seq 1 "$RUNS"); do
    git commit --quiet --allow-empty --no-verify -m "perf: empty commit ${i} (#6181)"
    measure "commit-${i}"
  done
fi
echo "wrote ${out}"
