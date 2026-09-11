#!/usr/bin/env bash
# Self-test for .github/scripts/floating-tag-plan.sh.
#
# The script is the ONLY thing standing between a promote dispatch and a
# floating tag: `apply-floating-tags` in docker-publish.yml advances exactly
# the tags this prints, and nothing else. Its interesting cases are all ones
# that occur roughly once per release and are invisible when everything is
# normal -- a backport that must move `:X.Y` but not `:latest`, a superseded
# patch that must move neither, a version whose images exist but whose release
# was never published (the v1.7.2/1.7.5 shape) -- so they get asserted here
# rather than discovered on a cut.
#
# Pure stdin/stdout, no network, no registry, ~1s.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLAN="$HERE/../../.github/scripts/floating-tag-plan.sh"

pass=0
fail=0

# Extra flags handed to the plan script by `check`; the adapter cases below
# set `--with-major`, the backend cases run with none.
FLAGS=()

# <label> <target> <releases, newline-separated> <expected-exit> <expected-stdout>
check() {
  local label="$1" target="$2" releases="$3" want_status="$4" want_out="$5"
  local status=0 out
  out="$(printf '%s' "$releases" | "$PLAN" ${FLAGS[@]+"${FLAGS[@]}"} "$target" 2>/dev/null)" || status=$?
  if [ "$status" -ne "$want_status" ]; then
    echo "  FAIL $label: expected exit $want_status, got $status"
    fail=$((fail + 1))
    return
  fi
  if [ "$out" != "$want_out" ]; then
    echo "  FAIL $label: expected stdout [$(echo "$want_out" | tr '\n' ',')], got [$(echo "$out" | tr '\n' ',')]"
    fail=$((fail + 1))
    return
  fi
  echo "  ok   $label"
  pass=$((pass + 1))
}

RELEASES=$'v1.8.2\nv1.8.1\nv1.8.0\nv1.7.9\nv1.7.8\n'

echo "floating-tag-plan.sh"

# The ordinary cut: newest release overall and newest in its series, so both
# floating tags follow it.
check "newest release takes :X.Y and :latest" 1.8.2 "$RELEASES" 0 $'1.8\nlatest'

# A maintenance patch to an older line. `:1.7` must follow it; `:latest` must
# NOT -- moving `:latest` backwards to a backport is the failure mode the
# series rule exists for, and it needs no special case.
check "backport takes :X.Y only" 1.7.9 "$RELEASES" 0 "1.7"

# Re-promoting an already-superseded patch (a recovery re-run, or an operator
# completing a half-published old version) must move nothing.
check "superseded patch takes nothing" 1.8.1 "$RELEASES" 0 ""
check "superseded backport takes nothing" 1.7.8 "$RELEASES" 0 ""

# THE v1.7.2 / v1.7.5 SHAPE. Images published, gate never certified them, no
# release object was ever created (1.7.5's git tag was later deleted and
# ghcr.io/...-backend:1.7.5 is still pullable today). A version in that state
# must not be reachable from any floating tag.
check "version with no published release is refused" 1.7.5 "$RELEASES" 4 ""

# Prereleases never take floating tags -- today's `!contains('-')` condition,
# restated where the decision now lives.
check "prerelease target refused" 1.8.2-rc.1 "$RELEASES" 3 ""
check "prerelease target refused (v-prefixed)" v1.9.0-beta.1 "$RELEASES" 3 ""

# An empty published set means nothing has been certified, so nothing may be
# named. Fails closed rather than defaulting to "sure, take latest".
check "empty release list refused" 1.8.2 "" 4 ""

# `v` prefix on either side is normalised, since the caller pipes raw
# `tag_name` values straight from the releases API.
check "v-prefixed target normalised" v1.8.2 "$RELEASES" 0 $'1.8\nlatest'

# Lines that are not stable X.Y.Z are ignored, so a repository that also tags
# SDK/component releases or prereleases in the same list does not confuse the
# ordering. `v1.9.0-rc.1` must NOT count as "newer than 1.8.2".
check "non-semver and prerelease lines ignored" 1.8.2 \
  $'sdk-v2.3.4\nv1.9.0-rc.1\nv1.8.2\nv1.8.1\n' 0 $'1.8\nlatest'

# Ordering is numeric per field, not lexical: a lexical sort puts "1.9.0"
# above "1.10.0" and would hold `:latest` on the older release forever.
check "1.10.0 outranks 1.9.0 numerically" 1.10.0 $'v1.9.0\nv1.10.0\n' 0 $'1.10\nlatest'
check "1.9.0 does not outrank 1.10.0" 1.9.0 $'v1.9.0\nv1.10.0\n' 0 "1.9"
check "patch ordering is numeric too" 1.8.10 $'v1.8.9\nv1.8.10\n' 0 $'1.8\nlatest'
check "older patch loses to 1.8.10" 1.8.9 $'v1.8.9\nv1.8.10\n' 0 ""

# Duplicate entries (the same version present as more than one tag shape) must
# not change the verdict.
check "duplicates tolerated" 1.8.2 $'v1.8.2\n1.8.2\nv1.8.1\n' 0 $'1.8\nlatest'

# ── scanner-adapter (#3770) ──────────────────────────────────────────────────
# The adapter's published set is the adapter VERSION each published backend
# release ships, so it has duplicates (releases that did not bump it) and
# gaps (adapter versions built but never released). The target is the adapter
# version the promoted ref ships. `--with-major` adds the `:X` alias the
# chart pins.
FLAGS=(--with-major)

# The adapter VERSIONs carried by v1.9.0 (1.2.10), v1.8.2 (1.2.8), v1.8.1
# (1.2.7), v1.8.0 (1.2.5) and an older 1.7.x that did not bump (1.2.5).
ADAPTER_PUBLISHED=$'1.2.10\n1.2.8\n1.2.7\n1.2.5\n1.2.5\n'

# Promote of the highest published release: its adapter version takes the
# whole floating line.
check "adapter: version shipped by the newest release takes :X.Y, :X and :latest" \
  1.2.10 "$ADAPTER_PUBLISHED" 0 $'1.2\n1\nlatest'

# Promote of a lower release (a backport, or a recovery re-run of an older
# version) must not move any adapter floating tag backwards.
check "adapter: version shipped by a lower release takes nothing" \
  1.2.8 "$ADAPTER_PUBLISHED" 0 ""
check "adapter: version shipped only by old releases takes nothing" \
  1.2.5 "$ADAPTER_PUBLISHED" 0 ""

# THE v1.9.0 TAG-PUSH SHAPE. The just-built adapter 1.2.10 is on both
# registries, but no published release carries it yet (the release object is
# only created after the gate). It must be refused, not advanced: this is
# what a normal build used to do six times before any gate ran.
check "adapter: just-built version with no published release is refused" \
  1.2.10 $'1.2.8\n1.2.7\n1.2.5\n' 4 ""

# REAL HISTORY: v1.8.0 shipped adapter 1.2.5 after the later-cut backport
# v1.7.8 had shipped 1.2.6. Promoting the newest BACKEND release must then
# leave every adapter floating tag on 1.2.6 -- and release.yml's post-promote
# assert derives its expectation from this same verdict, so a correct release
# of that shape stays green instead of going false-red.
check "adapter: newest backend release shipping an older adapter takes nothing" \
  1.2.5 $'1.2.5\n1.2.6\n1.2.3\n' 0 ""
check "adapter: the backport that ships the newer adapter owns the line" \
  1.2.6 $'1.2.5\n1.2.6\n1.2.3\n' 0 $'1.2\n1\nlatest'

# The major alias follows its own line: a 1.2.x patch while 1.3.0 is
# published moves `:1.2` only, and a new major takes everything while the
# previous major keeps `:1` (but not `:latest`).
check "adapter: patch in an older minor takes :X.Y only" \
  1.2.11 $'1.3.0\n1.2.11\n1.2.8\n' 0 "1.2"
check "adapter: new major takes :X.Y, :X and :latest" \
  2.0.0 $'2.0.0\n1.3.0\n' 0 $'2.0\n2\nlatest'
check "adapter: previous major keeps :X.Y and :X, not :latest" \
  1.3.0 $'2.0.0\n1.3.0\n' 0 $'1.3\n1'

# An adapter prerelease/candidate never takes a floating tag either.
check "adapter: prerelease target refused" 1.3.0-rc.1 "$ADAPTER_PUBLISHED" 3 ""

# Without the flag the output is unchanged, so the backend/openscap callers
# see exactly what they always did.
FLAGS=()
check "no --with-major: :X is not emitted" 1.2.10 "$ADAPTER_PUBLISHED" 0 $'1.2\nlatest'

# Usage error is distinct from a policy refusal, so a workflow bug does not
# look like "this version may not be promoted".
usage_status=0
"$PLAN" >/dev/null 2>&1 || usage_status=$?
if [ "$usage_status" -eq 2 ]; then
  echo "  ok   missing argument exits 2"
  pass=$((pass + 1))
else
  echo "  FAIL missing argument: expected exit 2, got $usage_status"
  fail=$((fail + 1))
fi

echo ""
echo "  ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
