#!/usr/bin/env bash
# Self-test for .github/scripts/adapter-published-set.sh.
#
# The resolver feeds the adapter's floating-tag rule on both the promote side
# and the release-side assert, so its failure modes decide whether a
# backwards move is possible: a release silently dropped from the set can
# only make an OLDER adapter version look newest. `gh` is stubbed on PATH
# with the two real 404 message shapes and a transient error; no network.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESOLVER="$HERE/../../.github/scripts/adapter-published-set.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Stub `gh api ... ?ref=<tag>`: the fixture maps a tag to a VERSION, to a
# 404 shape, or to a server error, mirroring what the real CLI prints.
cat > "$tmp/gh" <<'STUB'
#!/usr/bin/env bash
all="$*"; ref="${all##*ref=}"
case "$ref" in
  v1.8.2) printf '1.2.8\n' ;;
  v1.8.1) printf ' 1.2.7\r\n' ;;
  v1.1.0) echo '{"message":"Not Found","status":"404"}'; echo 'gh: Not Found (HTTP 404)' >&2; exit 1 ;;
  v9.9.9) echo '{"message":"No commit found for the ref v9.9.9","status":"404"}'; echo 'gh: No commit found for the ref v9.9.9 (HTTP 404)' >&2; exit 1 ;;
  v5.0.0) echo 'gh: Internal Server Error (HTTP 500)' >&2; exit 1 ;;
  *) echo "stub: unexpected ref $ref" >&2; exit 99 ;;
esac
STUB
chmod +x "$tmp/gh"
export PATH="$tmp:$PATH" GITHUB_REPOSITORY=o/r GH_TOKEN=x

pass=0
fail=0

# <label> <stdin> <expected-exit> <expected-stdout>
check() {
  local label="$1" input="$2" want_status="$3" want_out="$4" status=0 out
  out="$(printf '%s' "$input" | "$RESOLVER" 2>/dev/null)" || status=$?
  if [ "$status" -ne "$want_status" ]; then
    echo "  FAIL $label: expected exit $want_status, got $status"
    fail=$((fail + 1)); return
  fi
  if [ "$out" != "$want_out" ]; then
    echo "  FAIL $label: expected [$(echo "$want_out" | tr '\n' ',')], got [$(echo "$out" | tr '\n' ',')]"
    fail=$((fail + 1)); return
  fi
  echo "  ok   $label"
  pass=$((pass + 1))
}

echo "adapter-published-set.sh"
check "resolves the adapter version each release ships, whitespace trimmed" \
  $'v1.8.2\nv1.8.1\n' 0 $'1.2.8\n1.2.7'
check "a release that predates the VERSION file is ignored" \
  $'v1.8.2\nv1.1.0\n' 0 "1.2.8"
check "a published release whose tag is missing fails closed" \
  $'v1.8.2\nv9.9.9\n' 1 "1.2.8"
check "a transient error fails closed" \
  $'v1.8.2\nv5.0.0\nv1.8.1\n' 1 "1.2.8"
check "blank lines are skipped" \
  $'\nv1.8.2\n\n' 0 "1.2.8"
check "empty input resolves to an empty set" "" 0 ""

echo ""
echo "  ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
