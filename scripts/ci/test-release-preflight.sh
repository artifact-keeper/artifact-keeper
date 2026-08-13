#!/usr/bin/env bash
#
# Self-test for scripts/ci/release-preflight.sh check 3 (issue #3308).
#
# WHY THIS EXISTS
#   Check 3 measures whether main's last Docker Publish published its manifest.
#   It used to `warn` on a red result and let the script exit 0, so the tool
#   printed "a tag cut will likely stall" and "READY: ... Safe to cut the tag."
#   in the same run. That is worse than no preflight, because it launders a
#   measured red into an explicit go-ahead.
#
#   The failure is invisible to any test that only checks the happy path: with
#   a GREEN Docker Publish the buggy and the fixed script are identical. So the
#   case that must be covered is specifically the MEASURED-RED one, and the
#   test has to be able to fail. Revert line 156's `bad` back to `warn` and
#   case 2 below goes red; that is the property being asserted.
#
# HOW
#   The script reaches GitHub only through `gh`. We put a stub `gh` first on
#   PATH that replays canned job conclusions, so no network and no repo state
#   is involved. Checks 1 and 2 are neutralised (a temp repo with a matching
#   version set and no release/* branches) so the exit code isolates check 3.
#
# Usage: bash scripts/ci/test-release-preflight.sh
set -uo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/release-preflight.sh"
[ -f "$SCRIPT" ] || { echo "cannot find release-preflight.sh next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0

pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

# --- a minimal repo that satisfies checks 1 and 2 ---------------------------
REPO_DIR="$WORK/repo"
mkdir -p "$REPO_DIR/scripts/ci" "$REPO_DIR/backend/src/api"
cp "$SCRIPT" "$REPO_DIR/scripts/ci/release-preflight.sh"
printf 'version = "9.9.9"\n' > "$REPO_DIR/Cargo.toml"
printf 'version = "9.9.9"\n' > "$REPO_DIR/backend/src/api/openapi.rs"
printf 'name = "artifact-keeper-backend"\nversion = "9.9.9"\n' > "$REPO_DIR/Cargo.lock"
# No .trivyignore => check 1 warns and skips, which is not blocking.
git -C "$REPO_DIR" init -q
git -C "$REPO_DIR" remote add origin https://github.com/artifact-keeper/artifact-keeper.git
git -C "$REPO_DIR" -c user.email=t@t -c user.name=t add -A
git -C "$REPO_DIR" -c user.email=t@t -c user.name=t commit -qm init

# `git ls-remote --heads origin 'release/*'` must succeed and return nothing.
STUB="$WORK/bin"; mkdir -p "$STUB"
cat > "$STUB/git" <<'STUBGIT'
#!/usr/bin/env bash
for a in "$@"; do [ "$a" = "ls-remote" ] && exit 0; done
exec /usr/bin/git "$@"
STUBGIT
chmod +x "$STUB/git"

# --- gh stub: replays $FAKE_SECURITY_SCAN / $FAKE_MANIFEST ------------------
cat > "$STUB/gh" <<'STUBGH'
#!/usr/bin/env bash
case "$1" in
  run)
    case "$2" in
      list) echo "${FAKE_RUN_ID-12345}" ;;
      view)
        # Which of the two `gh run view` calls is this? The jq for Security
        # Scan mentions that name; the other is the manifest.
        if printf '%s ' "$@" | grep -q 'Security Scan'; then
          echo "${FAKE_SECURITY_SCAN-success}"
        else
          echo "${FAKE_MANIFEST-success}"
        fi
        ;;
    esac
    ;;
esac
exit 0
STUBGH
chmod +x "$STUB/gh"

run_case() {
  ( cd "$REPO_DIR" && PATH="$STUB:$PATH" \
      PREFLIGHT_REPO=artifact-keeper/artifact-keeper \
      bash scripts/ci/release-preflight.sh >"$WORK/out.txt" 2>&1 )
  echo $?
}

expect() { # <label> <expected-exit> <expected-substring>
  local label="$1" want="$2" needle="$3" got
  got="$(run_case)"
  if [ "$got" != "$want" ]; then
    fail "$label: expected exit $want, got $got"
    sed 's/^/        /' "$WORK/out.txt" >&2
  elif ! grep -qF "$needle" "$WORK/out.txt"; then
    fail "$label: exit $got correct but output lacks '$needle'"
    sed 's/^/        /' "$WORK/out.txt" >&2
  else
    pass "$label (exit $got)"
  fi
}

echo "release-preflight check 3 (#3308)"

# 1. Green publish stays READY. Guards against over-correcting into a gate
#    that blocks every cut.
FAKE_SECURITY_SCAN=success FAKE_MANIFEST=success \
  expect "green Docker Publish -> READY" 0 "READY"

# 2. THE REGRESSION. A measured red must block. Reverting `bad` to `warn` on
#    the measured-red branch of check 3 turns this red.
FAKE_SECURITY_SCAN=failure FAKE_MANIFEST=skipped \
  expect "red Docker Publish -> NOT READY" 1 "NOT READY"

# 3. Security Scan green but the manifest did not publish is still red: the
#    manifest is the thing the release chain consumes.
FAKE_SECURITY_SCAN=success FAKE_MANIFEST=skipped \
  expect "manifest skipped -> NOT READY" 1 "NOT READY"

# 4. Could not measure is NOT a readiness verdict -- it is INFRA (exit 2).
#    Distinct from both "green" and "red"; retryable.
FAKE_RUN_ID="" FAKE_SECURITY_SCAN=success FAKE_MANIFEST=success \
  expect "unqueryable run -> INFRA" 2 "INFRA"

# 5. The explicit human override reports the red but does not block. Separate
#    from PREFLIGHT_SKIP_DOCKER_HEALTH on purpose: "I looked, it is red,
#    proceeding" and "I did not look" must read differently.
( cd "$REPO_DIR" && PATH="$STUB:$PATH" PREFLIGHT_REPO=x/y \
    FAKE_SECURITY_SCAN=failure FAKE_MANIFEST=skipped PREFLIGHT_ALLOW_RED_PUBLISH=1 \
    bash scripts/ci/release-preflight.sh >"$WORK/out.txt" 2>&1 )
rc=$?
if [ "$rc" -eq 0 ] && grep -qF "PREFLIGHT_ALLOW_RED_PUBLISH=1 was set" "$WORK/out.txt"; then
  pass "explicit override -> READY, and says so (exit 0)"
else
  fail "explicit override: expected exit 0 with the override noted, got $rc"
  sed 's/^/        /' "$WORK/out.txt" >&2
fi

echo
if [ "$fails" -eq 0 ]; then
  echo "all release-preflight check-3 cases passed"
  exit 0
fi
echo "$fails case(s) failed"
exit 1
