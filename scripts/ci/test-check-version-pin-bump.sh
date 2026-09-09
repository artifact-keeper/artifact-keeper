#!/usr/bin/env bash
#
# Self-test for scripts/ci/check-version-pin-bump.sh (#3754).
#
# The gate is silent on almost every PR -- nearly nothing touches a
# version-pinned component -- so a regression in it (an inverted comparison, a
# two-dot diff, a probe answer read as absence) would be invisible until the
# next release cut it failed to prevent. That is the same shape as #3551: a
# control that is quiet when healthy is indistinguishable from one that does
# not work.
#
# The two directions both have to be exercised, and the dangerous one is
# FAIL-OPEN. A gate that never fires is exactly as useful as no gate, and it
# looks identical on every green PR. So the cases below are weighted toward
# "must still block": the collision itself, and the three ways an answer could
# be missing (unreadable registry, missing probe, unreadable component table),
# none of which may be reported as a pass.
#
# Registry answers are replayed through PREFLIGHT_TAG_STATE_CMD, the same knob
# release-preflight.sh's self-test uses, so this needs no network, no docker
# daemon and no credential. Builds throwaway git repos, ~1s.
#
# Usage: bash scripts/ci/test-check-version-pin-bump.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/check-version-pin-bump.sh"
TABLE="$HERE/version-pinned-components.txt"
[ -f "$SCRIPT" ] || { echo "cannot find check-version-pin-bump.sh next to this test" >&2; exit 2; }
[ -f "$TABLE" ] || { echo "cannot find version-pinned-components.txt next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0

pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

git_() { git -C "$REPO" -c user.email=t@t -c user.name=t "$@"; }

# --- probe stub -------------------------------------------------------------
# Replays $FAKE_TAG_STATE with registry-tag-state.sh's contract: the answer on
# stdout, exit 1 for `indeterminate`.
PROBES="$WORK/probes"; mkdir -p "$PROBES"
cat > "$PROBES/state" <<'STUBSTATE'
#!/usr/bin/env bash
echo "${FAKE_TAG_STATE-absent}"
[ "${FAKE_TAG_STATE-absent}" = "indeterminate" ] && exit 1
exit 0
STUBSTATE
chmod +x "$PROBES/state"

# --- fixture repo -----------------------------------------------------------
#
#   main:  m1 (VERSION 1.2.8) -> m2 (an unrelated backend change)
#   one branch per case, all forked from m1 so the cases cannot interfere.
#
# m2 exists for the three-dot case: work that lands on the base AFTER a branch
# forks must not be attributed to that branch. With a two-dot diff it would be,
# and a PR touching nothing would fail on someone else's adapter change.
REPO="$WORK/repo"
mkdir -p "$REPO/scripts/ci" "$REPO/docker/scanner-adapter" "$REPO/backend/src"
cp "$SCRIPT" "$REPO/scripts/ci/check-version-pin-bump.sh"
cp "$TABLE" "$REPO/scripts/ci/version-pinned-components.txt"
printf '1.2.8\n' > "$REPO/docker/scanner-adapter/VERSION"
printf 'FROM ghcr.io/artifact-keeper/trivy@sha256:aaa AS trivy\n' \
  > "$REPO/docker/Dockerfile.scanner-adapter"
printf 'v1\n' > "$REPO/backend/src/lib.rs"
git_ init -q -b main .
git_ add -A
git_ commit -qm "m1: base"
git_ branch -q fork-point

printf 'v2\n' > "$REPO/backend/src/lib.rs"
git_ add -A
git_ commit -qm "m2: an unrelated change on the base branch"

run_case() { # <label> <expected-exit> <expected-substring> <branch> [base]
  local label="$1" want="$2" needle="$3" branch="$4" base="${5:-main}" got
  git_ checkout -q "$branch"
  ( cd "$REPO" && VERSION_PIN_REPO=artifact-keeper/artifact-keeper \
      PREFLIGHT_TAG_STATE_CMD="$PROBES/state" \
      bash scripts/ci/check-version-pin-bump.sh "$base" > "$WORK/out.txt" 2>&1 )
  got=$?
  if [ "$got" != "$want" ]; then
    fail "$label: expected exit $want, got $got"
    sed 's/^/        /' "$WORK/out.txt" >&2
  elif [ -n "$needle" ] && ! grep -qF "$needle" "$WORK/out.txt"; then
    fail "$label: exit $got correct but output lacks '$needle'"
    sed 's/^/        /' "$WORK/out.txt" >&2
  else
    pass "$label (exit $got)"
  fi
}

echo "check-version-pin-bump.sh (#3754):"

# --- 1. THE REGRESSION: the #3579 shape -------------------------------------
# Adapter sources changed, VERSION left at an ALREADY PUBLISHED value. This is
# the case the gate exists for, and it must be able to fail: flip the `present`
# branch to a pass and this goes red.
git_ checkout -q -b unbumped fork-point
printf 'FROM ghcr.io/artifact-keeper/trivy@sha256:bbb AS trivy\n' \
  > "$REPO/docker/Dockerfile.scanner-adapter"
git_ commit -aqm "repoint trivy, no VERSION bump"
FAKE_TAG_STATE=present \
  run_case "sources changed, VERSION unchanged, tag published -> blocked" 1 \
    "ALREADY PUBLISHED" unbumped

# ...and the message has to carry the remedy, not just a refusal. A gate that
# fails without naming the one line to change is a gate people re-run.
FAKE_TAG_STATE=present \
  run_case "the failure names the VERSION file and the fix" 1 \
    "bump the VERSION file" unbumped

# --- 2. the fix passes ------------------------------------------------------
git_ checkout -q -b bumped fork-point
printf 'FROM ghcr.io/artifact-keeper/trivy@sha256:bbb AS trivy\n' \
  > "$REPO/docker/Dockerfile.scanner-adapter"
printf '1.2.9\n' > "$REPO/docker/scanner-adapter/VERSION"
git_ commit -aqm "repoint trivy and bump VERSION"
FAKE_TAG_STATE=present \
  run_case "sources changed and VERSION bumped -> ok" 0 "1.2.8 -> 1.2.9" bumped

# --- 3. the ordinary PR -----------------------------------------------------
# Nothing under the component's source paths moved. This must not probe the
# registry or block, or every PR in the repository pays for the gate.
git_ checkout -q -b untouched fork-point
printf 'v3\n' > "$REPO/backend/src/lib.rs"
git_ commit -aqm "a change nowhere near the adapter"
FAKE_TAG_STATE=present \
  run_case "sources unchanged -> ok" 0 "sources unchanged" untouched

# A whitespace-only difference in the VERSION file is not a bump: the publish
# job derives the same tag from it either way.
git_ checkout -q -b whitespace fork-point
printf 'FROM ghcr.io/artifact-keeper/trivy@sha256:bbb AS trivy\n' \
  > "$REPO/docker/Dockerfile.scanner-adapter"
printf '  1.2.8  \n\n' > "$REPO/docker/scanner-adapter/VERSION"
git_ commit -aqm "reformat VERSION, repoint trivy"
FAKE_TAG_STATE=present \
  run_case "a whitespace-only VERSION edit is not a bump -> blocked" 1 \
    "ALREADY PUBLISHED" whitespace

# --- 4. unpublished is not a collision --------------------------------------
# A version nobody has published yet can move as often as it likes; the cut
# creates it. Guards against a gate that blocks a component's whole
# development cycle between releases.
FAKE_TAG_STATE=absent \
  run_case "sources changed, VERSION unchanged, tag unpublished -> ok" 0 \
    "unpublished -- the cut will create it" unbumped

# --- 5. three-dot: the base's own work is not this branch's ------------------
# `unbumped` forked at m1; the base has moved to m2 since. A two-dot diff would
# also be wrong in the other direction here, so the assertion is on the branch
# that touched NOTHING: it must stay green even after the base gains commits.
FAKE_TAG_STATE=present \
  run_case "base commits after the fork are not this branch's changes -> ok" 0 \
    "sources unchanged" untouched

# --- 6. could not measure is never a pass -----------------------------------
# The three ways an answer can be missing. Each must be INFRA (exit 2)
# specifically: exit 0 would fail open, and exit 1 would tell an author to bump
# a VERSION over what is actually a registry outage.
FAKE_TAG_STATE=indeterminate \
  run_case "registry unreadable -> INFRA, not a pass" 2 "INFRA" unbumped

git_ checkout -q unbumped
out="$(cd "$REPO" && VERSION_PIN_REPO=artifact-keeper/artifact-keeper \
  PREFLIGHT_TAG_STATE_CMD="$WORK/no-such-probe" \
  bash scripts/ci/check-version-pin-bump.sh main 2>&1)"; rc=$?
if [ $rc -eq 2 ] && grep -q "registry probe not found" <<<"$out"; then
  pass "missing registry probe -> INFRA, not a pass (exit 2)"
else
  fail "missing registry probe -> INFRA, not a pass (got exit $rc)"; sed 's/^/        /' <<<"$out" >&2
fi

out="$(cd "$REPO" && VERSION_PIN_REPO=artifact-keeper/artifact-keeper \
  PREFLIGHT_TAG_STATE_CMD="$PROBES/state" \
  VERSION_PINNED_COMPONENTS_FILE="$WORK/no-such-table" \
  bash scripts/ci/check-version-pin-bump.sh main 2>&1)"; rc=$?
if [ $rc -eq 2 ] && grep -q "component table" <<<"$out"; then
  pass "unreadable component table -> INFRA, not an empty component set (exit 2)"
else
  fail "unreadable component table -> INFRA, not an empty component set (got exit $rc)"; sed 's/^/        /' <<<"$out" >&2
fi

# A base ref that does not resolve is the depth-1-checkout shape: the diff
# cannot be computed at all, so there is nothing to report but INFRA.
out="$(cd "$REPO" && VERSION_PIN_REPO=artifact-keeper/artifact-keeper \
  PREFLIGHT_TAG_STATE_CMD="$PROBES/state" \
  bash scripts/ci/check-version-pin-bump.sh no/such/ref 2>&1)"; rc=$?
if [ $rc -eq 2 ] && grep -q "does not resolve" <<<"$out"; then
  pass "unresolvable base ref -> INFRA (exit 2)"
else
  fail "unresolvable base ref -> INFRA (got exit $rc)"; sed 's/^/        /' <<<"$out" >&2
fi

# --- 7. the table this gate shares with the preflight -----------------------
# The point of scripts/ci/version-pinned-components.txt is that check 4 and
# this gate cannot drift apart. If the extraction is ever reverted on one side,
# the two stop agreeing silently -- so assert the shared file is what the
# preflight reads.
if grep -q 'VERSION_PINNED_COMPONENTS_FILE' "$HERE/release-preflight.sh"; then
  pass "release-preflight.sh reads the shared component table"
else
  fail "release-preflight.sh no longer reads the shared component table"
fi

echo ""
if [ "$fails" -eq 0 ]; then
  echo "all check-version-pin-bump cases passed"
else
  echo "$fails case(s) failed"
  exit 1
fi
