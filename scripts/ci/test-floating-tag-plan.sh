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

# <label> <target> <releases, newline-separated> <expected-exit> <expected-stdout>
check() {
  local label="$1" target="$2" releases="$3" want_status="$4" want_out="$5"
  local status=0 out
  out="$(printf '%s' "$releases" | "$PLAN" "$target" 2>/dev/null)" || status=$?
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
