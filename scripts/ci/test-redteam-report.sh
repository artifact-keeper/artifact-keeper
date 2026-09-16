#!/usr/bin/env bash
# =============================================================================
# test-redteam-report.sh — the red-team suite must report what it measured
# =============================================================================
#
# WHY (#3491)
# A security suite whose OUTPUT is wrong is worse than no suite: it was run
# against 1.8.0, passed, and its report could not be read by `jq`, its summary
# said "Passed: 1 checks" after dozens of PASS lines, and the checks that did
# fire reported the server's REFUSALS as CRITICALs. All three came from the
# same place — run-all.sh INVOKES each test script rather than sourcing it, so
# every counter and every "have I written a finding yet" flag reset per script.
#
# None of that is visible from a green run, and reproducing it needs a live
# registry, a docker network and a redteam image. So drive lib.sh and
# run-all.sh directly against a stub `curl`: no network, no container, ~1s.
#
# Usage: bash scripts/ci/test-redteam-report.sh
# =============================================================================
set -uo pipefail

REDTEAM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../redteam" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0

ok()   { echo "  ok   — $1"; pass=$((pass + 1)); }
bad()  { echo "  FAIL — $1"; [ -n "${2:-}" ] && echo "$2" | sed 's/^/         /'; fail=$((fail + 1)); }
check() { # check <condition-rc> <name> [context]
  if [ "$1" -eq 0 ]; then ok "$2"; else bad "$2" "${3:-}"; fi
}

# --- a stub registry -------------------------------------------------------
# Answers the three shapes lib.sh uses: the health probe, the login POST, and
# any request that asks for %{http_code}.
STUB="$TMP/bin"; mkdir -p "$STUB"
cat > "$STUB/curl" <<'STUBSH'
#!/usr/bin/env bash
want_code=0
url=""
for a in "$@"; do
  case "$a" in
    '%{http_code}') want_code=1 ;;
    http://*|https://*) url="$a" ;;
  esac
done
case "$url" in
  */health) exit 0 ;;
  */api/v1/auth/login) echo '{"access_token":"stub-token"}'; exit 0 ;;
esac
[ "$want_code" = 1 ] && { echo "200"; exit 0; }
echo '{}'
STUBSH
chmod +x "$STUB/curl"

# --- a throwaway copy of the suite with synthetic test scripts --------------
# scaffold <name> <"fail"|"clean">
scaffold() {
  local d="$TMP/$1"
  rm -rf "$d"; mkdir -p "$d/tests"
  cp "$REDTEAM_DIR/lib.sh" "$REDTEAM_DIR/run-all.sh" "$d/"

  cat > "$d/tests/01-alpha.sh" <<'T1'
source "$(dirname "$0")/../lib.sh"
pass "alpha one"
pass "alpha two"
warn "alpha warned"
add_finding "LOW" "alpha/one" "first finding" "evidence one"
exit 0
T1

  if [ "$2" = fail ]; then
    # A description carrying a double quote and a newline: the old report
    # interpolated these raw, so a finding could break the JSON by itself.
    cat > "$d/tests/02-beta.sh" <<'T2'
source "$(dirname "$0")/../lib.sh"
pass "beta one"
fail "beta found something"
add_finding "HIGH" "beta/one" "a \"quoted\" description
with a newline" "evidence two"
exit 0
T2
    cat > "$d/tests/03-gamma.sh" <<'T3'
source "$(dirname "$0")/../lib.sh"
pass "gamma one"
exit 3
T3
  else
    cat > "$d/tests/02-beta.sh" <<'T4'
source "$(dirname "$0")/../lib.sh"
pass "beta one"
exit 0
T4
  fi
  echo "$d"
}

run_suite() { # run_suite <dir> <results-dir>; echoes nothing, sets RC/OUT
  OUT="$(PATH="$STUB:$PATH" RESULTS_DIR="$2" REGISTRY_URL="http://stub.invalid" \
    bash "$1/run-all.sh" 2>&1)"
  RC=$?
}

echo "redteam report + counters:"

# ===========================================================================
# 1. A run with findings
# ===========================================================================
DIR="$(scaffold withfail fail)"
RES="$TMP/results-fail"
run_suite "$DIR" "$RES"
REPORT="$RES/redteam-report.json"

# The headline #3491 defect: findings contributed by different scripts were
# concatenated with no separator, so nothing could read the report.
jq empty "$REPORT" 2>/dev/null
check $? "the report is valid JSON with findings from more than one script" "$(cat "$REPORT" 2>/dev/null)"

[ "$(jq '.findings | length' "$REPORT" 2>/dev/null)" = "2" ]
check $? "both findings are present" "$(cat "$REPORT" 2>/dev/null)"

[ "$(jq -r '.findings[1].test' "$REPORT" 2>/dev/null)" = "beta/one" ]
check $? "a description containing a quote and a newline survives as JSON"

# The counters: every script ran in its own process, so these only add up if
# the state is shared on disk. 4 passes here (3 from the scripts + "Backend is
# ready") plus one for the shared token.
[ "$(jq '.summary.pass' "$REPORT" 2>/dev/null)" -ge 4 ]
check $? "PASS counts accumulate across scripts (not reset per script)" "$OUT"

[ "$(jq '.summary.fail' "$REPORT" 2>/dev/null)" = "1" ]
check $? "FAIL counts survive the subshell boundary"

[ "$(jq '.summary.warn' "$REPORT" 2>/dev/null)" -ge 1 ]
check $? "WARN counts survive the subshell boundary"

grep -qE "Passed:.* [0-9]+ checks" <<<"$OUT" && ! grep -qE "Passed:.* 1 checks" <<<"$OUT"
check $? "the printed summary is not the per-script reset value" "$OUT"

[ "$RC" -ne 0 ]
check $? "the run exits non-zero when a check failed" "$OUT"

# ===========================================================================
# 2. A clean run
# ===========================================================================
DIR="$(scaffold clean clean)"
RES="$TMP/results-clean"
run_suite "$DIR" "$RES"
REPORT="$RES/redteam-report.json"

jq empty "$REPORT" 2>/dev/null
check $? "a run with ONE finding still produces valid JSON" "$(cat "$REPORT" 2>/dev/null)"

[ "$RC" -eq 0 ]
check $? "a run with no failed checks exits 0" "$OUT"

# ===========================================================================
# 3. One login per run, shared by every script
# ===========================================================================
# Tests 04 and 10 spend the login rate-limit window on purpose; before the
# shared token, every later script logged in for itself, was throttled, and
# skipped with "Could not authenticate".
DIR="$(scaffold token clean)"
RES="$TMP/results-token"
cat > "$DIR/tests/03-token.sh" <<'T5'
source "$(dirname "$0")/../lib.sh"
t=$(auth_token) || t=""
[ -n "$t" ] && pass "script obtained a token" || fail "script could not authenticate"
T5
# Count logins by having the stub append to a file.
cat > "$STUB/curl" <<STUBSH
#!/usr/bin/env bash
want_code=0
url=""
for a in "\$@"; do
  case "\$a" in
    '%{http_code}') want_code=1 ;;
    http://*|https://*) url="\$a" ;;
  esac
done
case "\$url" in
  */health) exit 0 ;;
  */api/v1/auth/login) echo x >> "$TMP/logins"; echo '{"access_token":"stub-token"}'; exit 0 ;;
esac
[ "\$want_code" = 1 ] && { echo "200"; exit 0; }
echo '{}'
STUBSH
chmod +x "$STUB/curl"
: > "$TMP/logins"
run_suite "$DIR" "$RES"

[ "$(wc -l < "$TMP/logins")" -eq 1 ]
check $? "the suite logs in exactly once and shares the token" "logins: $(wc -l < "$TMP/logins")"

grep -q "script obtained a token" <<<"$OUT"
check $? "a later script gets the shared token instead of re-authenticating" "$OUT"

echo ""
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
