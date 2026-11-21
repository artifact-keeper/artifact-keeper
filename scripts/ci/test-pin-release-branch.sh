#!/usr/bin/env bash
# Self-test for pin-release-branch.sh and its wiring (#6338).
#
# The failure it guards is late and expensive: Create Release gets a 403 from
# GITHUB_TOKEN at the very end of a release run when the commit is no longer a
# branch tip (1.12.3: four failed attempts, then a hand-made branch). So:
#   * the script: create the pin, accept an existing pin at the same commit,
#     refuse to move one at another commit, report an API refusal, remove only
#     its own pin, never fail on unpin;
#   * the wiring: release-promote pins before it creates the tag, release.yml
#     pins before Create Release and unpins only after it.
#
# A stub `gh` first on PATH records the calls. No network, ~1s.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SCRIPT="$HERE/pin-release-branch.sh"
WF="$ROOT/.github/workflows"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
pass() { printf '  ok   %s\n' "$*"; }
fail() { printf '  FAIL %s\n' "$*"; fails=$((fails + 1)); }

SHA=3036a861fa50fb3311f60414a746ed86f2ace95a
OTHER=4b2ac6430000000000000000000000000000000a

# FAKE_AT: the commit publish/<tag> names ("" = 404). FAKE_GET_FAIL=1: the
# lookup fails with a 5xx. FAKE_POST_FAIL / FAKE_DELETE_FAIL=1: the write is
# refused. Every call is appended to $CALLS.
mkdir -p "$WORK/bin"
cat >"$WORK/bin/gh" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$CALLS"
[[ "$1" == api ]] || exit 0
case "$*" in
  *"-X POST"*)   [[ "${FAKE_POST_FAIL-0}" == 1 ]] && { echo 'HTTP 403: Resource not accessible by integration' >&2; exit 1; }; exit 0 ;;
  *"-X DELETE"*) [[ "${FAKE_DELETE_FAIL-0}" == 1 ]] && { echo 'HTTP 403: Resource not accessible by integration' >&2; exit 1; }; exit 0 ;;
  *git/ref/heads/*)
    [[ "${FAKE_GET_FAIL-0}" == 1 ]] && { echo 'HTTP 502: Bad Gateway' >&2; exit 1; }
    [[ -z "${FAKE_AT-}" ]] && { echo 'gh: Not Found (HTTP 404)' >&2; exit 1; }
    echo "$FAKE_AT" ;;
esac
STUB
chmod +x "$WORK/bin/gh"

# run <label> <want-exit> <want-call-regex|-> <reject-call-regex|-> <mode> [env...]
run() {
  local label="$1" want="$2" need="$3" reject="$4" mode="$5"; shift 5
  : >"$WORK/calls"
  local rc=0 out
  out="$(env PATH="$WORK/bin:$PATH" CALLS="$WORK/calls" GITHUB_REPOSITORY=o/r "$@" \
    bash "$SCRIPT" "$mode" v1.12.3 "$SHA" 2>&1)" || rc=$?
  if [[ "$rc" -ne "$want" ]]; then fail "$label: exit $rc, want $want"; printf '       | %s\n' "${out//$'\n'/$'\n'       | }"; return; fi
  if [[ "$need" != - ]] && ! grep -qE -- "$need" "$WORK/calls"; then fail "$label: no call matching '$need'"; sed 's/^/       | /' "$WORK/calls"; return; fi
  if [[ "$reject" != - ]] && grep -qE -- "$reject" "$WORK/calls"; then fail "$label: unexpected call matching '$reject'"; sed 's/^/       | /' "$WORK/calls"; return; fi
  pass "$label"
}

echo "pin-release-branch.sh"
run "pin creates publish/<tag> at the commit when absent" 0 \
  "-X POST repos/o/r/git/refs -f ref=refs/heads/publish/v1.12.3 -f sha=$SHA" - pin FAKE_AT=
run "pin accepts an existing pin at the same commit, writes nothing" 0 - "-X (POST|DELETE)" pin FAKE_AT="$SHA"
run "pin refuses a branch at another commit and does not move it" 1 - "-X (POST|DELETE|PATCH)" pin FAKE_AT="$OTHER"
run "pin reports a refused create" 1 "-X POST" - pin FAKE_AT= FAKE_POST_FAIL=1
run "pin reports a failed lookup (not a 404) without writing" 1 - "-X POST" pin FAKE_GET_FAIL=1
run "unpin deletes its own pin" 0 "-X DELETE repos/o/r/git/refs/heads/publish/v1.12.3" - unpin FAKE_AT="$SHA"
run "unpin leaves a branch at another commit alone" 0 - "-X DELETE" unpin FAKE_AT="$OTHER"
run "unpin is a no-op when the pin is gone" 0 - "-X DELETE" unpin FAKE_AT=
run "unpin never fails on a refused delete" 0 "-X DELETE" - unpin FAKE_AT="$SHA" FAKE_DELETE_FAIL=1
run "unpin never fails on a failed lookup" 0 - "-X DELETE" unpin FAKE_GET_FAIL=1
rc=0; env GITHUB_REPOSITORY=o/r bash "$SCRIPT" pin v1.12.3 not-a-sha >/dev/null 2>&1 || rc=$?
if [[ "$rc" -eq 2 ]]; then pass "a bad sha is a usage error"; else fail "a bad sha: exit $rc, want 2"; fi

echo "wiring"
# Line number of the first line matching <regex> in <file>; 0 when none.
line_of() { grep -nE -- "$2" "$1" | head -1 | cut -d: -f1 || true; }
P="$WF/release-promote.yml"; R="$WF/release.yml"
pin_p="$(line_of "$P" 'pin-release-branch\.sh pin ')"; tag_p="$(line_of "$P" 'name: Create the annotated release tag')"
if [[ -n "$pin_p" && -n "$tag_p" && "$pin_p" -lt "$tag_p" ]]; then pass "release-promote pins before it creates the tag"
else fail "release-promote must run 'pin-release-branch.sh pin' before 'Create the annotated release tag' (pin=${pin_p:-none} tag=${tag_p:-none})"; fi
# The pin step must not share the tag step's `if:`: a re-dispatch with the tag
# already there still needs the pin.
blk="$(awk '/name: Pin a branch at the release commit/{f=1} f&&/^      - name: /&&!/Pin a branch/{exit} f' "$P")"
if [[ -n "$blk" ]] && ! grep -qE '^ +if:' <<<"$blk"; then pass "release-promote pins on every dispatch (no if:)"
else fail "the release-promote pin step is missing or conditional"; fi
pin_r="$(line_of "$R" 'pin-release-branch\.sh pin ')"; cr_r="$(line_of "$R" '^      - name: Create Release$')"
unpin_r="$(line_of "$R" 'pin-release-branch\.sh unpin ')"; job_r="$(line_of "$R" '^  release:$')"
if [[ -n "$job_r" && -n "$pin_r" && -n "$cr_r" && -n "$unpin_r" && "$job_r" -lt "$pin_r" && "$pin_r" -lt "$cr_r" && "$cr_r" -lt "$unpin_r" ]]; then
  pass "release.yml: pin, then Create Release, then unpin, in the release job"
else fail "release.yml order wrong (job=${job_r:-none} pin=${pin_r:-none} create=${cr_r:-none} unpin=${unpin_r:-none})"; fi
blk="$(awk '/name: Remove the release pin branch/{f=1} f&&/^      - name: /&&!/Remove the release pin/{exit} f' "$R")"
if [[ -n "$blk" ]] && ! grep -qE '^ +if:' <<<"$blk"; then pass "release.yml unpins only on success (default if, so a failed Create Release keeps the pin)"
else fail "the release.yml unpin step is missing or has its own if: (an always() would drop the pin a re-run needs)"; fi

echo
if [[ "$fails" -eq 0 ]]; then echo "test-pin-release-branch: all passed"; else echo "test-pin-release-branch: $fails failed"; exit 1; fi
