#!/usr/bin/env bash
# Self-test for scripts/ci/coverage-gate-decision.sh -- the coverage merge
# gate's decision matrix.
#
# The script is the only thing standing between "📊 Code Coverage failed" and
# "this PR cannot merge", so both directions are pinned: a failure must block
# in enforce mode unless a listed exemption applies, and every exemption must
# be exactly as narrow as documented -- in particular the maintainer override
# must not be honoured for a label or comment from someone without admin or
# maintain. Runs mode x creation date x draft x grace label exhaustively for a
# failing gate, then the override, job-result and config cases. Stubs `gh`;
# offline, ~2s.
#
# Usage: bash scripts/ci/test-coverage-gate-decision.sh
set -uo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/coverage-gate-decision.sh"
[ -f "$SCRIPT" ] || { echo "cannot find coverage-gate-decision.sh next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

# --- stub gh -------------------------------------------------------------------
# FAKE_PR        JSON for pulls/<n> (unset: the call fails -> payload fallback)
# FAKE_EVENTS    JSON array for issues/<n>/events
# FAKE_COMMENTS  JSON array for issues/<n>/comments
# FAKE_ROLES     "login=role ..." for collaborators/<login>/permission
STUB="$WORK/bin"; mkdir -p "$STUB"
cat > "$STUB/gh" <<'STUBGH'
#!/usr/bin/env bash
echo "$*" >> "$GH_LOG"
[ "$1" = api ] || exit 64
shift
[ "$1" = --paginate ] && shift
case "$1" in
  repos/o/r/pulls/7) [ -n "${FAKE_PR-}" ] || exit 1; printf '%s\n' "$FAKE_PR" ;;
  repos/o/r/issues/7/events) [ -n "${FAKE_EVENTS-}" ] || exit 1; printf '%s\n' "$FAKE_EVENTS" ;;
  repos/o/r/issues/7/comments) [ -n "${FAKE_COMMENTS-}" ] || exit 1; printf '%s\n' "$FAKE_COMMENTS" ;;
  repos/o/r/collaborators/*/permission)
    login="${1#repos/o/r/collaborators/}"; login="${login%/permission}"
    for pair in ${FAKE_ROLES-}; do
      [ "${pair%%=*}" = "$login" ] && { echo "${pair#*=}"; exit 0; }
    done
    echo none ;;
  *) exit 64 ;;
esac
STUBGH
chmod +x "$STUB/gh"

config() { # <mode> <enforce_after>
  printf '{"mode":"%s","enforce_after":"%s","grace_label":"coverage-grace","override_label":"coverage-override"}\n' "$1" "$2" > "$WORK/config.json"
}

# decide [VAR=value ...] -> $rc, $got (the `coverage-gate:` line), summary in $WORK/summary
# Defaults: a pull request whose unit job passed and whose new-code gate failed.
decide() {
  : > "$WORK/summary"; : > "$WORK/gh.log"
  rc=0
  got="$(env -i PATH="$STUB:$PATH" HOME="$WORK" GH_LOG="$WORK/gh.log" \
      GITHUB_STEP_SUMMARY="$WORK/summary" COVERAGE_GATE_CONFIG="$WORK/config.json" \
      GITHUB_EVENT_NAME=pull_request GITHUB_REPOSITORY=o/r PR_NUMBER=7 GH_TOKEN=x \
      RESULT_UNIT=success RESULT_COVERAGE=failure \
      COVERAGE_FLOOR=pass COVERAGE_FLOOR_PCT=77.10 COVERAGE_NEWCODE=fail COVERAGE_NEWCODE_PCT=41 \
      PR_DRAFT=false PR_CREATED_AT=2026-10-20T09:00:00Z PR_LABELS= \
      "$@" bash "$SCRIPT" 2>"$WORK/err" | grep '^coverage-gate: ')" || rc=$?
  got="${got#coverage-gate: }"
}

# expect <label> <want-rc> <want-outcome> [VAR=value ...]
expect() {
  local label="$1" want_rc="$2" want="$3"; shift 3
  decide "$@"
  if [ "$rc" = "$want_rc" ] && [ "$got" = "$want" ]; then
    pass "$label"
  else
    fail "$label: got rc=$rc '$got', want rc=$want_rc '$want'"
    sed 's/^/        | /' "$WORK/summary" "$WORK/err" >&2
  fi
}
summary_has() { # <label> <fixed string>
  if grep -qF -- "$2" "$WORK/summary"; then pass "$1"; else fail "$1: summary lacks '$2'"; sed 's/^/        | /' "$WORK/summary" >&2; fi
}

pr_json() { # <draft> <created_at> <labels csv>
  local labels="" l
  IFS=',' read -ra ls <<<"$3"
  for l in "${ls[@]}"; do [ -n "$l" ] && labels="${labels:+$labels,}{\"name\":\"$l\"}"; done
  printf '{"draft":%s,"created_at":"%s","labels":[%s]}' "$1" "$2" "$labels"
}

AFTER=2026-10-08
OLD=2026-09-20T12:00:00Z   # created before enforce_after
NEW=2026-10-20T09:00:00Z   # created on/after it

echo "coverage-gate-decision.sh: failing gate, mode x created x draft x grace label (32 cases)"
for mode in shadow enforce; do
  config "$mode" "$AFTER"
  for created in old new; do
    for draft in false true; do
      for grace in no yes; do
        at=$NEW; [ "$created" = old ] && at=$OLD
        labels=""; [ "$grace" = yes ] && labels="coverage-grace"
        why=""
        if [ "$draft" = true ]; then why=draft
        elif [ "$created" = old ]; then why="created-before-$AFTER"
        elif [ "$grace" = yes ]; then why=grace-label
        fi
        if [ "$mode" = shadow ]; then
          want_rc=0; if [ -n "$why" ]; then want="shadow-exempt:$why"; else want=shadow-fail; fi
        else
          if [ -n "$why" ]; then want_rc=0 want="exempt:$why"; else want_rc=1 want=fail; fi
        fi
        expect "$mode created=$created draft=$draft grace=$grace -> $want" "$want_rc" "$want" \
          FAKE_PR="$(pr_json "$draft" "$at" "$labels")"
      done
    done
  done
done

config enforce "$AFTER"
echo "coverage-gate-decision.sh: live PR state beats the (re-run) event payload"
expect "grace label added after the run: honoured from the pulls API" 0 exempt:grace-label \
  FAKE_PR="$(pr_json false "$NEW" coverage-grace)" PR_LABELS=
expect "label removed since: the stale payload label is ignored" 1 fail \
  FAKE_PR="$(pr_json false "$NEW" "")" PR_LABELS=coverage-grace
expect "pulls API down: payload values are the fallback" 0 exempt:draft PR_DRAFT=true
expect "pulls API down, nothing exempt in the payload: blocks" 1 fail

echo "coverage-gate-decision.sh: the audited override"
LABELED_BY() { printf '[{"event":"labeled","label":{"name":"coverage-override"},"actor":{"login":"%s"}}]' "$1"; }
COMMENT_BY() { printf '[{"user":{"login":"%s"},"created_at":"2026-10-21T10:00:00Z","body":"/coverage-override %s"}]' "$1" "$2"; }
OV_PR="$(pr_json false "$NEW" coverage-override)"
ROLES="alice=admin carol=maintain bob=write dave=triage"

expect "admin label + admin comment: override" 0 exempt:override \
  FAKE_PR="$OV_PR" FAKE_ROLES="$ROLES" FAKE_EVENTS="$(LABELED_BY alice)" \
  FAKE_COMMENTS="$(COMMENT_BY alice 'moved code, covered by integration tests')"
summary_has "summary names who applied the label" 'applied by **alice**'
summary_has "summary carries the reason" 'moved code, covered by integration tests'
summary_has "summary names who wrote the reason" '`/coverage-override` by **alice** (2026-10-21T10:00:00Z)'
summary_has "summary keeps the failed numbers" 'new code 41% (fail)'
expect "maintain label + admin comment: override" 0 exempt:override \
  FAKE_PR="$OV_PR" FAKE_ROLES="$ROLES" FAKE_EVENTS="$(LABELED_BY carol)" \
  FAKE_COMMENTS="$(COMMENT_BY alice 'ok')"
expect "label by a writer: NOT honoured, blocks" 1 fail \
  FAKE_PR="$OV_PR" FAKE_ROLES="$ROLES" FAKE_EVENTS="$(LABELED_BY bob)" \
  FAKE_COMMENTS="$(COMMENT_BY alice 'ok')"
summary_has "and says why" 'applied by bob, whose role is write'
expect "admin label, comment only by a writer: NOT honoured" 1 fail \
  FAKE_PR="$OV_PR" FAKE_ROLES="$ROLES" FAKE_EVENTS="$(LABELED_BY alice)" \
  FAKE_COMMENTS="$(COMMENT_BY bob 'please')"
expect "admin label, no comment: NOT honoured" 1 fail \
  FAKE_PR="$OV_PR" FAKE_ROLES="$ROLES" FAKE_EVENTS="$(LABELED_BY alice)" FAKE_COMMENTS='[]'
expect "admin label, comment without a reason: NOT honoured" 1 fail \
  FAKE_PR="$OV_PR" FAKE_ROLES="$ROLES" FAKE_EVENTS="$(LABELED_BY alice)" \
  FAKE_COMMENTS='[{"user":{"login":"alice"},"created_at":"x","body":"/coverage-override"}]'
expect "the LATEST labeled event counts (re-applied by a triager)" 1 fail \
  FAKE_PR="$OV_PR" FAKE_ROLES="$ROLES" \
  FAKE_EVENTS='[{"event":"labeled","label":{"name":"coverage-override"},"actor":{"login":"alice"}},{"event":"unlabeled","label":{"name":"coverage-override"},"actor":{"login":"dave"}},{"event":"labeled","label":{"name":"coverage-override"},"actor":{"login":"dave"}}]' \
  FAKE_COMMENTS="$(COMMENT_BY alice ok)"
expect "events API down: NOT honoured" 1 fail \
  FAKE_PR="$OV_PR" FAKE_ROLES="$ROLES" FAKE_COMMENTS="$(COMMENT_BY alice ok)"
expect "a comment without the label: nothing to honour" 1 fail \
  FAKE_PR="$(pr_json false "$NEW" "")" FAKE_ROLES="$ROLES" FAKE_EVENTS="$(LABELED_BY alice)" \
  FAKE_COMMENTS="$(COMMENT_BY alice ok)"
grep -q 'issues/7/events' "$WORK/gh.log" && fail "without the label the events API was still queried" \
  || pass "without the label no override lookup is made"
config shadow "$AFTER"
expect "shadow mode reports the override it would honour" 0 shadow-exempt:override \
  FAKE_PR="$OV_PR" FAKE_ROLES="$ROLES" FAKE_EVENTS="$(LABELED_BY alice)" FAKE_COMMENTS="$(COMMENT_BY alice ok)"
config enforce "$AFTER"

echo "coverage-gate-decision.sh: job results"
expect "gates passed" 0 pass RESULT_COVERAGE=success COVERAGE_NEWCODE=pass
expect "gates passed, new code N/A" 0 pass RESULT_COVERAGE=success COVERAGE_NEWCODE=na
expect "gates passed, only jscpd over 3%: advisory" 0 pass RESULT_COVERAGE=success COVERAGE_NEWCODE=pass COVERAGE_JSCPD=fail
summary_has "jscpd is reported as advisory" 'advisory'
expect "floor failed" 1 fail COVERAGE_FLOOR=fail COVERAGE_NEWCODE=pass FAKE_PR="$(pr_json false "$NEW" "")"
summary_has "the reason carries the numbers" 'floor 77.10% (fail), new code 41% (pass)'
expect "unit skipped by a skip rule: no coverage expected" 0 skip \
  RESULT_UNIT=skipped RESULT_COVERAGE=skipped COVERAGE_FLOOR= COVERAGE_NEWCODE= COVERAGE_SKIP_REASON=docs-only
expect "unit skipped WITHOUT a skip rule: fails" 1 fail \
  RESULT_UNIT=skipped RESULT_COVERAGE=skipped COVERAGE_FLOOR= COVERAGE_NEWCODE= FAKE_PR="$(pr_json false "$NEW" "")"
summary_has "and says nothing was measured" 'skipped outside the skip rules'
expect "unit job failed: fails with that reason" 1 fail \
  RESULT_UNIT=failure COVERAGE_FLOOR=error COVERAGE_NEWCODE=error FAKE_PR="$(pr_json false "$NEW" "")"
summary_has "the reason names the unit job" 'Backend Unit Tests failure: no coverage was measured'
expect "unit job failed on an old PR: still exempt by date" 0 "exempt:created-before-$AFTER" \
  RESULT_UNIT=failure COVERAGE_FLOOR=error COVERAGE_NEWCODE=error FAKE_PR="$(pr_json false "$OLD" "")"
expect "unit cancelled: fails" 1 fail RESULT_UNIT=cancelled FAKE_PR="$(pr_json false "$NEW" "")"
expect "gates job failed before a verdict: not measured, fails" 1 fail \
  COVERAGE_FLOOR= COVERAGE_NEWCODE= FAKE_PR="$(pr_json false "$NEW" "")"
summary_has "and says so" 'before reaching a verdict'
expect "gates job cancelled: fails" 1 fail RESULT_COVERAGE=cancelled COVERAGE_FLOOR= COVERAGE_NEWCODE= FAKE_PR="$(pr_json false "$NEW" "")"
expect "gates skipped while the unit job ran: fails" 1 fail RESULT_COVERAGE=skipped COVERAGE_FLOOR= COVERAGE_NEWCODE= FAKE_PR="$(pr_json false "$NEW" "")"
expect "push: coverage is pull-request only" 0 pass GITHUB_EVENT_NAME=push RESULT_COVERAGE=skipped
config shadow "$AFTER"
expect "shadow mode, gates passed" 0 shadow-pass RESULT_COVERAGE=success COVERAGE_NEWCODE=pass
expect "shadow mode never blocks, even with nothing measured" 0 shadow-fail RESULT_UNIT=failure FAKE_PR="$(pr_json false "$NEW" "")"

echo "coverage-gate-decision.sh: the policy file fails closed"
printf 'not json' > "$WORK/config.json"
expect "unreadable config: enforce, no date grace" 1 fail FAKE_PR="$(pr_json false "$OLD" "")"
summary_has "and says so" 'fails closed'
printf '{"mode":"off","enforce_after":"%s"}' "$AFTER" > "$WORK/config.json"
expect "unknown mode: enforce, no date grace" 1 fail FAKE_PR="$(pr_json false "$OLD" "")"
printf '{"mode":"shadow","enforce_after":"next week"}' > "$WORK/config.json"
expect "malformed date: enforce, no date grace" 1 fail FAKE_PR="$(pr_json false "$OLD" "")"
printf '{"mode":"enforce","enforce_after":""}' > "$WORK/config.json"
expect "enforce with no date: an old PR is not exempt" 1 fail FAKE_PR="$(pr_json false "$OLD" "")"

REPO_CONFIG="$(cd "$(dirname "$SCRIPT")/../.." && pwd)/.github/coverage-gate.json"
if jq -e '(.mode == "shadow" or .mode == "enforce") and (.enforce_after | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$")) and (.floor_percent | type == "number") and (.newcode_percent | type == "number") and (.newcode_min_lines | type == "number")' "$REPO_CONFIG" >/dev/null 2>&1; then
  pass "the repository's .github/coverage-gate.json is valid"
else
  fail "the repository's .github/coverage-gate.json is missing or invalid"
fi

echo
if [ "$fails" -gt 0 ]; then
  echo "coverage-gate-decision.sh: $fails case(s) FAILED"
  exit 1
fi
echo "coverage-gate-decision.sh: all cases passed"
