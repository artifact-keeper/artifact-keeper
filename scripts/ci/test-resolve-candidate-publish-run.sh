#!/usr/bin/env bash
#
# Self-test for scripts/ci/resolve-candidate-publish-run.sh (issue #3640).
#
# WHY THIS EXISTS
#   The resolver decides whether a docker-publish pipeline vouches for the
#   commit being released. Its two dangerous directions are exercised here:
#     * fail-OPEN: a success for a different sha, a different ref (the
#       main-branch build of the same commit), or no success at all must
#       BLOCK, and an unfinished run is a verdict that does not exist yet
#       (the v1.7.7 shape);
#     * fail-CLOSED-forever: the v1.8.2 deadlock -- the tag push's publish
#       fails on immutability (permanently un-greenable) while the documented
#       promote dispatch (#2698) succeeded for the same commit+ref. Case 2 is
#       that exact shape and goes red if the event=push-only selection is
#       reintroduced.
#
# HOW
#   The resolver reaches GitHub only through `gh`, so a stub `gh` first on
#   PATH replays canned Actions API answers. The stub honours the server-side
#   `head_sha` filter for real (rows are tagged with the sha they belong to
#   and only returned when the query asks for it), so the stale-success case
#   tests the actual mechanism, not a shortcut. No network, ~1s.
#
# Usage: bash scripts/ci/test-resolve-candidate-publish-run.sh
set -uo pipefail

RESOLVER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/resolve-candidate-publish-run.sh"
[ -f "$RESOLVER" ] || { echo "cannot find resolve-candidate-publish-run.sh next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0

pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

SHA_A=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
SHA_B=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

# --- gh stub ---------------------------------------------------------------
# Replays  .../actions/workflows/<wf>/runs?event=<e>&head_sha=<sha>&...
#   FAKE_PUSH_RUNS / FAKE_DISPATCH_RUNS: TSV rows
#       id \t event \t head_branch \t status \t conclusion \t created_at
#   FAKE_RUNS_SHA:  the sha the canned rows belong to; rows are returned only
#                   when the query's head_sha matches (server-side filter).
#   FAKE_RUNS_FAIL: 1 -> the API call fails.
STUB="$WORK/bin"; mkdir -p "$STUB"
cat > "$STUB/gh" <<'STUBGH'
#!/usr/bin/env bash
case "$1" in
  api)
    case "$2" in
      *actions/workflows/*/runs*)
        [ "${FAKE_RUNS_FAIL-0}" = "1" ] && exit 1
        url="$2"
        qsha="${url##*head_sha=}"; qsha="${qsha%%&*}"
        [ "$qsha" = "${FAKE_RUNS_SHA-}" ] || exit 0
        case "$url" in
          *event=push*)              [ -n "${FAKE_PUSH_RUNS-}" ]     && printf '%s\n' "$FAKE_PUSH_RUNS" ;;
          *event=workflow_dispatch*) [ -n "${FAKE_DISPATCH_RUNS-}" ] && printf '%s\n' "$FAKE_DISPATCH_RUNS" ;;
        esac
        exit 0
        ;;
    esac
    ;;
esac
exit 0
STUBGH
chmod +x "$STUB/gh"

# <label> <expected-exit> <expected-substring>
# Reads the scenario from FAKE_* / CASE_* already exported by the caller.
expect() {
  local label="$1" want="$2" needle="$3" got=0
  ( PATH="$STUB:$PATH" \
      RESOLVE_REPO=artifact-keeper/artifact-keeper \
      RESOLVE_SHA="${CASE_SHA:-$SHA_A}" \
      RESOLVE_REF="${CASE_REF:-v9.9.9}" \
      RESOLVE_REPORT_CANCELLED="${CASE_REPORT_CANCELLED-}" \
      FAKE_PUSH_RUNS="${FAKE_PUSH_RUNS-}" \
      FAKE_DISPATCH_RUNS="${FAKE_DISPATCH_RUNS-}" \
      FAKE_RUNS_SHA="${FAKE_RUNS_SHA-$SHA_A}" \
      FAKE_RUNS_FAIL="${FAKE_RUNS_FAIL-0}" \
      bash "$RESOLVER" >"$WORK/out.txt" 2>&1 ) || got=$?
  if [ "$got" != "$want" ]; then
    fail "$label: expected exit $want, got $got"
    sed 's/^/        /' "$WORK/out.txt" >&2
  elif ! grep -qF -- "$needle" "$WORK/out.txt"; then
    fail "$label: exit $got correct but output lacks '$needle'"
    sed 's/^/        /' "$WORK/out.txt" >&2
  else
    pass "$label (exit $got)"
  fi
}

reset_case() {
  FAKE_PUSH_RUNS=""; FAKE_DISPATCH_RUNS=""
  FAKE_RUNS_SHA="$SHA_A"; FAKE_RUNS_FAIL=0
  CASE_SHA="$SHA_A"; CASE_REF=v9.9.9; CASE_REPORT_CANCELLED=""
}

echo "candidate publish-run resolver: the legs"

# 1. The normal release: the tag push's own docker-publish succeeded.
reset_case
FAKE_PUSH_RUNS=$'101\tpush\tv9.9.9\tcompleted\tsuccess\t2026-09-01T13:00:00Z'
expect "push run succeeded -> resolved" 0 \
  "state=resolved run_id=101"

# 2. THE v1.8.2 DEADLOCK. The re-tag's push publish failed on image
#    immutability (permanently red) and the documented promote dispatch
#    (#2698) succeeded for the same commit+ref. Must resolve to the dispatch
#    run; with an event=push-only selection this leg goes red.
reset_case
FAKE_PUSH_RUNS=$'201\tpush\tv9.9.9\tcompleted\tfailure\t2026-09-01T13:00:00Z'
FAKE_DISPATCH_RUNS=$'202\tworkflow_dispatch\tv9.9.9\tcompleted\tsuccess\t2026-09-01T14:00:00Z'
expect "push failed, promote dispatch succeeded -> resolved to the dispatch run" 0 \
  "state=resolved run_id=202"

# 3. Both failed: nothing vouches. Fail closed, do not assume a promote.
reset_case
FAKE_PUSH_RUNS=$'301\tpush\tv9.9.9\tcompleted\tfailure\t2026-09-01T13:00:00Z'
FAKE_DISPATCH_RUNS=$'302\tworkflow_dispatch\tv9.9.9\tcompleted\tfailure\t2026-09-01T14:00:00Z'
expect "push and dispatch both failed -> BLOCKED" 20 \
  "state=blocked"

# 4. No run of either kind exists (yet). Distinct from blocked so the caller
#    can keep waiting for webhook fan-out inside its appear-deadline.
reset_case
expect "no runs at all -> none (caller blocks at its deadline)" 21 \
  "state=none"

# 5. A success exists only for a DIFFERENT sha. The server-side head_sha
#    filter must keep it invisible: stale green is not evidence.
reset_case
FAKE_RUNS_SHA="$SHA_B"
FAKE_PUSH_RUNS=$'501\tpush\tv9.9.9\tcompleted\tsuccess\t2026-09-01T13:00:00Z'
FAKE_DISPATCH_RUNS=$'502\tworkflow_dispatch\tv9.9.9\tcompleted\tsuccess\t2026-09-01T14:00:00Z'
expect "successes exist only for another sha -> not resolved" 21 \
  "state=none"

# 6. Same sha, different ref: the main-branch build of the very commit the
#    tag points at (real shape: run 33510770762 next to v1.8.2). It publishes
#    :main/:dev, never the version tag, and must not vouch for the release.
reset_case
FAKE_PUSH_RUNS=$'601\tpush\tmain\tcompleted\tsuccess\t2026-09-01T12:59:45Z\n602\tpush\tv9.9.9\tcompleted\tfailure\t2026-09-01T13:40:26Z'
expect "main-branch success for the same sha -> BLOCKED, not resolved" 20 \
  "state=blocked"

# 7. A run is still going. An unfinished run is a verdict that does not exist
#    yet (the v1.7.7 lesson); the caller keeps following, nothing passes.
reset_case
FAKE_PUSH_RUNS=$'701\tpush\tv9.9.9\tin_progress\t-\t2026-09-01T13:00:00Z'
expect "push run in flight -> pending, names the run" 10 \
  "state=pending run_id=701"

# 8. Failed push + a promote dispatch still running: pending, not blocked --
#    the recovery in flight must not be called dead.
reset_case
FAKE_PUSH_RUNS=$'801\tpush\tv9.9.9\tcompleted\tfailure\t2026-09-01T13:00:00Z'
FAKE_DISPATCH_RUNS=$'802\tworkflow_dispatch\tv9.9.9\tqueued\t-\t2026-09-01T14:00:00Z'
expect "push failed, dispatch queued -> pending on the dispatch" 10 \
  "state=pending run_id=802"

# 9. Two successes: the most recent one is taken (created_at, not API order).
reset_case
FAKE_PUSH_RUNS=$'901\tpush\tv9.9.9\tcompleted\tsuccess\t2026-09-01T13:00:00Z'
FAKE_DISPATCH_RUNS=$'902\tworkflow_dispatch\tv9.9.9\tcompleted\tsuccess\t2026-09-01T15:00:00Z'
expect "multiple successes -> the most recent wins" 0 \
  "state=resolved run_id=902"

# 10. The API is down. Indeterminate is neither green nor red -- it must be
#     distinguishable from a genuine block so the caller can retry.
reset_case
FAKE_RUNS_FAIL=1
expect "API failure -> infra, distinct from blocked" 30 \
  "state=infra"

# 11. Malformed inputs are infra, not a quiet pass.
reset_case
CASE_SHA=deadbeef
expect "short sha -> infra" 30 \
  "state=infra reason=bad-sha"

echo
echo "main pushes coalesce; the Release Candidate re-runs a replaced run (#6242)"

# 12. The candidate's commit was REPLACED while pending by a newer main push
#     (cancelled, zero jobs). With RESOLVE_REPORT_CANCELLED=1 -- what
#     release-candidate.yml sets -- that is state=cancelled naming the run to
#     re-run, not a failed build.
reset_case
CASE_REF=main; CASE_REPORT_CANCELLED=1
FAKE_PUSH_RUNS=$'1201\tpush\tmain\tcompleted\tcancelled\t2026-11-18T19:00:00Z'
expect "replaced main push run, candidate mode -> cancelled, names the run" 22 \
  "state=cancelled run_id=1201"

# 13. Without the opt-in (release.yml's tag path) the same answer stays a
#     block: a tag push is never coalesced, so its cancelled run is a stop.
reset_case
CASE_REF=main
FAKE_PUSH_RUNS=$'1301\tpush\tmain\tcompleted\tcancelled\t2026-11-18T19:00:00Z'
expect "cancelled push run, default mode -> still BLOCKED" 20 \
  "state=blocked"

# 14. A FAILED build is never re-run by the candidate: only cancelled is.
reset_case
CASE_REF=main; CASE_REPORT_CANCELLED=1
FAKE_PUSH_RUNS=$'1401\tpush\tmain\tcompleted\tfailure\t2026-11-18T19:00:00Z'
expect "failed main push run, candidate mode -> BLOCKED, not re-run" 20 \
  "state=blocked"

# 15. Once re-run, the same run id is in flight, then green: pending, then
#     resolved -- the candidate path completes on the re-run attempt.
reset_case
CASE_REF=main; CASE_REPORT_CANCELLED=1
FAKE_PUSH_RUNS=$'1501\tpush\tmain\tin_progress\t-\t2026-11-18T19:00:00Z'
expect "re-run in flight -> pending on the same run" 10 \
  "state=pending run_id=1501"
FAKE_PUSH_RUNS=$'1501\tpush\tmain\tcompleted\tsuccess\t2026-11-18T19:00:00Z'
expect "re-run green -> resolved to the same run" 0 \
  "state=resolved run_id=1501"

# 16. A success anywhere still wins over a cancelled run (a promote dispatch
#     on main that shares the sha does not make the push run matter).
reset_case
CASE_REF=main; CASE_REPORT_CANCELLED=1
FAKE_PUSH_RUNS=$'1601\tpush\tmain\tcompleted\tcancelled\t2026-11-18T19:00:00Z'
FAKE_DISPATCH_RUNS=$'1602\tworkflow_dispatch\tmain\tcompleted\tsuccess\t2026-11-18T20:00:00Z'
expect "cancelled push run but a green run for the sha -> resolved" 0 \
  "state=resolved run_id=1602"

# --- the workflow wiring this depends on ------------------------------------
# The resolver's state=cancelled is only half of the contract: the candidate
# must act on it, a re-run must not be replaceable, and release.yml must not
# opt in. Read straight from the workflow files.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DP="$ROOT/.github/workflows/docker-publish.yml"
RC="$ROOT/.github/workflows/release-candidate.yml"
RY="$ROOT/.github/workflows/release.yml"

wire() { # <label> <command...>: PASS when the command succeeds
  local label="$1"; shift
  if "$@"; then pass "$label"; else fail "$label"; fi
}
has() { grep -qF -- "$2" <<< "$1"; }   # <text> <fixed string>
group="$(awk '/^concurrency:/{c=1; next} c && /^  group:/{print; exit}' "$DP")"
cip="$(awk '/^concurrency:/{c=1; next} c && /^  cancel-in-progress:/{print $2; exit}' "$DP")"
publish_job="$(awk '/^  publish:$/{p=1; print; next} p && /^  [a-z][a-z0-9_-]*:$/{exit} p' "$RC")"
# shellcheck disable=SC2016 # literal workflow text, not shell expansions
{
  wire "docker-publish: main pushes share one group (no per-commit suffix on main)" \
    has "$group" "github.ref != 'refs/heads/main'"
  wire "docker-publish: other branch pushes keep a group per commit (#6080)" \
    has "$group" "format('-{0}', github.sha)"
  wire "docker-publish: a re-run attempt gets a group of its own (cannot be replaced)" \
    has "$group" "format('-attempt-{0}', github.run_attempt)"
  wire "docker-publish: cancel-in-progress is the literal false (#2099)" \
    test "$cip" = false
  wire "release-candidate publish job: actions: write (to re-run)" \
    has "$publish_job" "      actions: write"
  wire "release-candidate publish job: opts in to state=cancelled" \
    has "$publish_job" "RESOLVE_REPORT_CANCELLED=1"
  wire "release-candidate publish job: handles exit 22" \
    has "$publish_job" "              22)"
  wire "release-candidate publish job: re-runs the cancelled run" \
    has "$publish_job" 'gh run rerun "${CANCELLED_RUN}"'
  wire "release.yml: does not opt in (a cancelled tag run stays a block)" \
    bash -c '! grep -qF RESOLVE_REPORT_CANCELLED "$1"' _ "$RY"
}

echo
if [ "$fails" -gt 0 ]; then
  echo "${fails} case(s) FAILED"
  exit 1
fi
echo "all cases passed"
