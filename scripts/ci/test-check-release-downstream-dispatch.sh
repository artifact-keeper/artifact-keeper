#!/usr/bin/env bash
# Self-test for check-release-downstream-dispatch.sh (#3789, #3896, #3897).
#
# The failure this gate exists for is SILENT: a downstream workflow that stops
# being dispatched simply does not run, and every release still looks green.
# So each plausible edit that reopens the gap is applied to a copy of the real
# workflows and must be refused:
#
#   * a downstream workflow losing `workflow_dispatch` (the #3897 shape);
#   * its dispatch input no longer `required`;
#   * its `release: published` trigger removed (hand releases stop running it);
#   * release.yml no longer dispatching it (the #3896 shape);
#   * the dispatch kept but never followed to a verdict;
#   * the dispatching job losing `needs: release` or `actions: write`;
#   * the AMI dispatch running for prereleases, or the announcement skipping
#     them -- the policy RELEASING.md states;
#   * an input or a release-payload field interpolated straight into a run
#     script;
#   * a downstream job gated on `github.event_name == 'release'`.
#
# Throwaway copies in a temp dir; no network, ~1s.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
GUARD="$HERE/check-release-downstream-dispatch.sh"
WF="$ROOT/.github/workflows"
FILES=(release.yml ami-build.yml release-announce.yml sync-openapi-spec.yml)

pass=0
fail=0

check() { # <label> <expected-status> <workflow-dir> [expected-substring]
  local label="$1" expected="$2" dir="$3" needle="${4:-}" status=0 out
  out="$("$GUARD" "$dir" 2>&1)" || status=$?
  if [ "$status" -ne "$expected" ]; then
    echo "  FAIL $label: expected exit $expected, got $status"
    # shellcheck disable=SC2001  # sed is the clearest way to indent a block
    echo "$out" | sed 's/^/       | /'
    fail=$((fail + 1))
    return
  fi
  if [ -n "$needle" ] && ! grep -qF -- "$needle" <<<"$out"; then
    echo "  FAIL $label: exit $status was right but output did not mention '$needle'"
    # shellcheck disable=SC2001  # sed is the clearest way to indent a block
    echo "$out" | sed 's/^/       | /'
    fail=$((fail + 1))
    return
  fi
  echo "  ok   $label (exit $status)"
  pass=$((pass + 1))
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

n=0
# fresh copy of the real workflows; prints its path
fresh() {
  n=$((n + 1))
  local d="$tmp/case$n"
  mkdir -p "$d"
  for f in "${FILES[@]}"; do cp "$WF/$f" "$d/$f"; done
  echo "$d"
}

# mutate <dir> <file> <python expression over `s`> -- the edit must change it
mutate() {
  python3 - "$1/$2" "$3" <<'PY'
import sys
path, expr = sys.argv[1], sys.argv[2]
s = open(path, encoding="utf-8").read()
new = eval(expr, {"s": s, "re": __import__("re")})
if new == s:
    sys.exit(f"mutation did not apply to {path}: {expr}")
open(path, "w", encoding="utf-8").write(new)
PY
}

echo "check-release-downstream-dispatch.sh"

d="$(fresh)"
check "the real workflows pass" 0 "$d" "OK:"

d="$(fresh)"
mutate "$d" release-announce.yml "re.sub(r'  workflow_dispatch:\n    inputs:\n      tag:\n(        .*\n)+', '', s, count=1)"
check "announce without workflow_dispatch is refused" 1 "$d" "release-announce.yml has no \`workflow_dispatch\`"

d="$(fresh)"
mutate "$d" ami-build.yml "s.replace('''Release)\"\n        required: true''', '''Release)\"\n        required: false''', 1)"
check "an optional AMI version input is refused" 1 "$d" "input \`version\` with"

d="$(fresh)"
mutate "$d" release-announce.yml "s.replace('''on:\n  release:\n    types: [published]\n''', 'on:\n', 1)"
check "announce without the release trigger is refused" 1 "$d" "lost \`on.release.types"

d="$(fresh)"
mutate "$d" release.yml "s.replace('gh workflow run ami-build.yml', 'echo skipped ami-build.yml', 1)"
check "release.yml not dispatching the AMI build is refused" 1 "$d" "no job running \`gh workflow run ami-build.yml\`"

d="$(fresh)"
mutate "$d" release.yml "s.replace('gh workflow run release-announce.yml', 'echo skipped release-announce.yml', 1)"
check "release.yml not dispatching the announcement is refused" 1 "$d" "no job running \`gh workflow run release-announce.yml\`"

d="$(fresh)"
mutate "$d" release.yml "s.replace('gh workflow run sync-openapi-spec.yml', 'echo skipped sync-openapi-spec.yml', 1)"
check "release.yml not dispatching the spec sync is refused" 1 "$d" "no job running \`gh workflow run sync-openapi-spec.yml\`"

d="$(fresh)"
mutate "$d" release.yml "s.replace('FOLLOW_WORKFLOW: release-announce.yml', 'FOLLOW_WORKFLOW: something-else.yml', 1)"
check "a dispatch that is never followed is refused" 1 "$d" "never follows it"

d="$(fresh)"
mutate "$d" release.yml "re.sub(r'(  ami-build:\n(?:    .*\n)*?)    needs: \[release\]\n', r'\1    needs: [build-binaries]\n', s, count=1)"
check "an AMI dispatch not after the release is refused" 1 "$d" "does not \`needs: release\`"

d="$(fresh)"
mutate "$d" release.yml "s.replace('      actions: write   # dispatch release-announce.yml', '      actions: read   # dispatch release-announce.yml', 1)"
check "a dispatcher without actions: write is refused" 1 "$d" "actions: write"

d="$(fresh)"
mutate "$d" release.yml "s.replace(\" && !contains(github.ref_name, '-') }}\", ' }}', 1)"
check "an AMI build for prereleases is refused" 1 "$d" "must skip prereleases"

d="$(fresh)"
mutate "$d" release.yml "re.sub(r\"(  release-announce:\n(?:    .*\n|\s*#.*\n)*?    if: \\$\\{\\{ !cancelled\(\) && needs.release.result == 'success')\", r\"\1 && !contains(github.ref_name, '-')\", s, count=1)"
check "an announcement that skips prereleases is refused" 1 "$d" "meant to run for them too"

d="$(fresh)"
mutate "$d" release.yml "s.replace('-f version=\"\${GITHUB_REF_NAME#v}\"', '', 1)"
check "an AMI dispatch without the version input is refused" 1 "$d" "-f version="

d="$(fresh)"
mutate "$d" release-announce.yml "s.replace('          INPUT_TAG: \${{ inputs.tag }}\n', '', 1).replace('TAG=\"\${INPUT_TAG}\"', 'TAG=\"\${{ inputs.tag }}\"', 1)"
check "an input interpolated into a run script is refused" 1 "$d" "interpolates"

d="$(fresh)"
mutate "$d" ami-build.yml "s.replace('          RELEASE_TAG: \${{ github.event.release.tag_name }}\n', '', 1).replace('VERSION=\"\${RELEASE_TAG#v}\"', 'VERSION=\"\${{ github.event.release.tag_name }}\"', 1)"
check "a release-payload field interpolated into a run script is refused" 1 "$d" "github.event.release.*"

d="$(fresh)"
mutate "$d" release-announce.yml "s.replace('    runs-on: ubuntu-latest\n', \"    if: github.event_name == 'release'\n    runs-on: ubuntu-latest\n\", 1)"
check "a downstream job gated on the release event is refused" 1 "$d" "gated on \`github.event_name == 'release'\`"

d="$(fresh)"
rm "$d/ami-build.yml"
check "a missing downstream workflow is refused" 1 "$d" "ami-build.yml not found"

echo
echo "passed: $pass  failed: $fail"
[ "$fail" -eq 0 ]
