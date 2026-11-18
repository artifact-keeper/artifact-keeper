#!/usr/bin/env bash
# =============================================================================
# test-nextest-junit-summary.sh — the JUnit summary must name every flaky and
# failed test, and must never fail the job itself
# =============================================================================
#
# nextest-junit-summary.py turns nextest's JUnit into the job-summary block of
# the unit and integration test jobs (#6172). A flaky pass is green, so this
# block is the only place it shows; a parser that missed `<flakyFailure>`
# would hide every flake again. Drives it against two real nextest 0.9.143
# reports (scripts/ci/fixtures/nextest-junit-*.xml, from a three-test crate:
# one steady pass, one fail-then-pass, one deterministic failure), under the
# `nightly` profile (retries) and the `ci` profile (no retries).
#
# No network, no cargo, ~1s.
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/nextest-junit-summary.py"
NIGHTLY="$HERE/fixtures/nextest-junit-nightly.xml"
CI="$HERE/fixtures/nextest-junit-ci.xml"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0

# expect <want rc> <name> <args...> -- <patterns...>: run the script with
# <args>, check its exit status and that every pattern appears in its
# combined output. A pattern prefixed with '!' must NOT appear.
expect() {
  local want="$1" name="$2"; shift 2
  local args=() out rc ok=1 pat
  while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do args+=("$1"); shift; done
  shift
  out="$(python3 -I "$SCRIPT" "${args[@]}" 2>&1)"; rc=$?
  [ "$rc" = "$want" ] || { echo "  rc=$rc, want $want"; ok=0; }
  for pat in "$@"; do
    if [ "${pat#!}" != "$pat" ]; then
      if grep -qF -- "${pat#!}" <<<"$out"; then echo "  unexpected: ${pat#!}"; ok=0; fi
    elif ! grep -qF -- "$pat" <<<"$out"; then
      echo "  missing: $pat"; ok=0
    fi
  done
  if [ "$ok" = 1 ]; then pass=$((pass + 1)); echo "PASS $name"
  else fail=$((fail + 1)); echo "FAIL $name"; printf '    | %s\n' "${out//$'\n'/$'\n'    | }"; fi
}

expect 0 "nightly: a fail-then-pass is FLAKY, not failed" "T" "$NIGHTLY" -- \
  "3 tests in 1 JUnit report(s): **1 failed**, **1 flaky**" \
  "- \`flakecrate tests::flaky_once (passed after 1 failed attempt)\`" \
  "::warning title=Flaky test (T)::flakecrate tests::flaky_once" \
  "!::error title=Failed test (T)::flakecrate tests::flaky_once"

expect 0 "nightly: a failure on every retry is FAILED, not flaky" "T" "$NIGHTLY" -- \
  "::error title=Failed test (T)::flakecrate tests::always_fails" \
  "!always_fails (passed"

expect 0 "nightly: a steady pass is in neither list" "T" "$NIGHTLY" -- \
  "!tests::steady"

expect 0 "ci (no retries): the same test is a plain failure, nothing flaky" "T" "$CI" -- \
  "**2 failed**, **0 flaky**" \
  "::error title=Failed test (T)::flakecrate tests::flaky_once" \
  "!**Flaky**"

expect 0 "several reports are totalled" "T" "$NIGHTLY" "$CI" -- \
  "6 tests in 2 JUnit report(s): **3 failed**, **1 flaky**"

expect 0 "a missing report is named, and is not an error" "T" "$CI" "$TMP/absent.xml" -- \
  "3 tests in 1 JUnit report(s)" \
  "\`$TMP/absent.xml\`: FileNotFoundError"

printf '<testsuites><testsuite' > "$TMP/truncated.xml"
expect 0 "a truncated report is named, and is not an error" "T" "$TMP/truncated.xml" -- \
  "0 tests in 0 JUnit report(s)" \
  "\`$TMP/truncated.xml\`: ParseError"

expect 0 "a workflow-command message is escaped" "50% (a)" "$CI" -- \
  "::error title=Failed test (50%25 (a))::"

expect 2 "no report at all is a usage error" "T" -- "usage:"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
