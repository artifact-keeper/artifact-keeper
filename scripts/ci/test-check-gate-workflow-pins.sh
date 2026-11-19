#!/usr/bin/env bash
#
# Self-test for scripts/ci/check-gate-workflow-pins.sh (issue #6170).
#
# WHY THIS EXISTS
#   Both modes are silent on almost every PR, so a guard that stopped firing
#   would look exactly like one that works. The dangerous direction is
#   fail-OPEN: a caller back on `@main`, callers on different commits, a
#   caller the parse did not see, or a pin that is not on artifact-keeper-test
#   main. Each is constructed here and must fail; an API failure must be INFRA
#   (exit 2), never a pass. The repository's own workflows must pass `check`.
#
# HOW
#   `check` reads fixture workflow directories. `reachable` runs in a scratch
#   git repository (base commit, then a branch commit) with a stub `gh` first
#   on PATH that answers the compare call from FAKE_* variables. Offline, ~2s.
#
# Usage: bash scripts/ci/test-check-gate-workflow-pins.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/check-gate-workflow-pins.sh"
ROOT="$(cd "$HERE/../.." && pwd)"
[ -f "$SCRIPT" ] || { echo "cannot find check-gate-workflow-pins.sh next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

A=987bccd15df3fd4c9c24bf78436ce12fb5bd5783
B=1111111111111111111111111111111111111111
T=artifact-keeper/artifact-keeper-test/.github/workflows

# caller <job> <workflow> <ref> [extra `with:` lines...]
caller() {
  local job="$1" wf="$2" ref="$3"; shift 3
  printf '  %s:\n    uses: %s/%s@%s # artifact-keeper-test main as of 2026-11-18\n    with:\n      backend_tag: x\n' "$job" "$T" "$wf" "$ref"
  local l; for l in "$@"; do printf '      %s\n' "$l"; done
}
# wf <dir> <file> <body>: a workflow file whose jobs are <body>
wf() { mkdir -p "$1"; printf 'name: t\non: workflow_dispatch\njobs:\n%s\n' "$3" > "$1/$2"; }

# expect <label> <exit> <substring> -- <command...>
expect() {
  local label="$1" want="$2" needle="$3" got=0; shift 4
  ( "$@" ) >"$WORK/out.txt" 2>&1 || got=$?
  if [ "$got" != "$want" ]; then
    fail "$label: expected exit $want, got $got"; sed 's/^/        /' "$WORK/out.txt" >&2
  elif ! grep -qF -- "$needle" "$WORK/out.txt"; then
    fail "$label: exit $got correct but output lacks '$needle'"; sed 's/^/        /' "$WORK/out.txt" >&2
  else
    pass "$label (exit $got)"
  fi
}

echo "gate pin guard: check"
expect "this repository's workflows pass" 0 "one artifact-keeper/artifact-keeper-test commit" -- \
  bash -c "cd '$ROOT' && bash '$SCRIPT' check"

D="$WORK/ok"
wf "$D" a.yml "$(caller gate release-gate.yml "$A" 'iac_ref: main' 'web_tag: latest')"
wf "$D" b.yml "$(caller s3 nightly-s3-formats.yml "$A" "iac_ref: \${{ inputs.iac_ref }}")"
expect "one sha across files: ok" 0 "2 caller(s), one" -- bash "$SCRIPT" check "$D"
expect "iac_ref: main is KNOWN, not a failure" 0 "KNOWN a.yml job gate (release-gate.yml): passes iac_ref: main" -- bash "$SCRIPT" check "$D"
expect "web_tag: latest is KNOWN, not a failure" 0 "passes web_tag: latest (allow-listed until #6170 slice 2)" -- bash "$SCRIPT" check "$D"
expect "an expression iac_ref is not flagged" 0 "2 known slice-2 finding(s)" -- bash "$SCRIPT" check "$D"

D="$WORK/main"
wf "$D" a.yml "$(caller gate release-gate.yml "$A")
$(caller s3 nightly-s3-formats.yml main)"
expect "a caller back on @main -> BLOCKED" 1 "at '@main', not a 40-hex commit" -- bash "$SCRIPT" check "$D"

D="$WORK/case"
wf "$D" a.yml "$(caller gate release-gate.yml "$A")
  odd:
    uses: Artifact-Keeper/artifact-keeper-test/.github/workflows/release-gate.yml@main"
expect "Artifact-Keeper/artifact-keeper-test...@main (other case) -> BLOCKED" 1 "at '@main', not a 40-hex commit" -- bash "$SCRIPT" check "$D"

D="$WORK/short"
wf "$D" a.yml "$(caller gate release-gate.yml "${A:0:12}")"
expect "a short sha -> BLOCKED" 1 "not a 40-hex commit" -- bash "$SCRIPT" check "$D"

D="$WORK/tag"
wf "$D" a.yml "$(caller gate release-gate.yml v1.2.3)"
expect "a tag -> BLOCKED" 1 "at '@v1.2.3'" -- bash "$SCRIPT" check "$D"

D="$WORK/split"
wf "$D" a.yml "$(caller gate release-gate.yml "$A")"
wf "$D" b.yml "$(caller gate release-gate.yml "$B")"
expect "two callers on different commits -> BLOCKED" 1 "pin 2 different" -- bash "$SCRIPT" check "$D"

D="$WORK/none"
wf "$D" a.yml "  build:
    runs-on: ubuntu-latest
    steps:
      - run: true"
expect "no caller at all -> BLOCKED, not a vacuous pass" 1 "would pass vacuously" -- bash "$SCRIPT" check "$D"

D="$WORK/hidden"
wf "$D" a.yml "$(caller gate release-gate.yml "$A")"
printf 'x-unparsed:\n  uses: %s/release-gate.yml@main\n' "$T" >> "$D/a.yml"
expect "a uses: line outside a job -> BLOCKED" 1 "but the YAML parse found 1 caller job(s)" -- bash "$SCRIPT" check "$D"

echo "gate pin guard: reachable"
R="$WORK/repo"
git init -q -b main "$R"
git -C "$R" config user.email t@example.com; git -C "$R" config user.name t
wf "$R/.github/workflows" a.yml "$(caller gate release-gate.yml main)
$(caller s3 nightly-s3-formats.yml main)"
git -C "$R" add -A; git -C "$R" commit -qm base
git -C "$R" checkout -qb pin
wf "$R/.github/workflows" a.yml "$(caller gate release-gate.yml "$A")
$(caller s3 nightly-s3-formats.yml "$A")"
git -C "$R" commit -qam pin

STUB="$WORK/bin"; mkdir -p "$STUB"
cat > "$STUB/gh" <<'STUBGH'
#!/usr/bin/env bash
echo "$*" >> "$FAKE_CALLS"
[ "$1" = api ] || exit 1
case "$2" in repos/artifact-keeper/artifact-keeper-test/compare/*...main) ;; *) echo "stub: unexpected $2" >&2; exit 1 ;; esac
[ -n "${FAKE_HTTP:-}" ] && { echo "gh: Not Found (HTTP ${FAKE_HTTP})" >&2; exit 1; }
echo "$FAKE_STATUS"
STUBGH
chmod +x "$STUB/gh"

reach() { # <status|""> <http|""> [base]
  ( cd "$R" && PATH="$STUB:$PATH" FAKE_CALLS="$WORK/calls" FAKE_STATUS="$1" FAKE_HTTP="$2" \
      GITHUB_BASE_REF='' bash "$SCRIPT" reachable "${3:-main}" )
}
expect "a new pin main is ahead of -> ok" 0 "on artifact-keeper/artifact-keeper-test main (ahead)" -- reach ahead ""
expect "a new pin at main's head -> ok" 0 "(identical)" -- reach identical ""
: > "$WORK/calls"; reach ahead "" >/dev/null 2>&1
if [ "$(grep -c . "$WORK/calls")" = 1 ] && grep -qF "compare/${A}...main" "$WORK/calls"; then
  pass "five callers on one new sha: one compare call, for that sha"
else
  fail "expected one compare call for ${A}, got: $(cat "$WORK/calls")"
fi
expect "a pin ahead of main (branch-only commit) -> BLOCKED" 1 "compare says behind" -- reach behind ""
expect "a pin diverged from main (force-pushed away) -> BLOCKED" 1 "compare says diverged" -- reach diverged ""
expect "no such commit (404) -> BLOCKED" 1 "has no such commit" -- reach "" 404
expect "an API failure -> INFRA, not a pass" 2 "INFRA: GET compare" -- reach "" 502
expect "an unexpected status -> INFRA" 2 "answered status 'weird'" -- reach weird ""
expect "a base ref that is not there -> INFRA" 2 "is not available" -- reach ahead "" no-such-branch
: > "$WORK/calls"
expect "no pin changed: nothing to check" 0 "nothing to check" -- reach diverged "" pin
if [ -s "$WORK/calls" ]; then fail "no pin changed, yet gh was called: $(cat "$WORK/calls")"; else pass "no pin changed: no API call"; fi

echo
if [ "$fails" -ne 0 ]; then echo "check-gate-workflow-pins: ${fails} FAILED"; exit 1; fi
echo "check-gate-workflow-pins: all passed"
