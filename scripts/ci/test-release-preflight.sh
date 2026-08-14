#!/usr/bin/env bash
#
# Self-test for scripts/ci/release-preflight.sh checks 1, 3 and 4
# (issues #3308, #3309, #3338 and #3339).
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
#   test has to be able to fail. Revert the measured-red branch's `bad` back to
#   `warn` and case 2 below goes red; that is the property being asserted.
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

# `git ls-remote --heads origin 'release/*'` must succeed; it returns
# $FAKE_RELEASE_REFS (ls-remote wire format) so the check-1 cases can
# simulate active release branches, and nothing by default.
STUB="$WORK/bin"; mkdir -p "$STUB"
cat > "$STUB/git" <<'STUBGIT'
#!/usr/bin/env bash
for a in "$@"; do
  if [ "$a" = "ls-remote" ]; then
    [ -n "${FAKE_RELEASE_REFS-}" ] && printf '%s\n' "$FAKE_RELEASE_REFS"
    exit 0
  fi
done
exec /usr/bin/git "$@"
STUBGIT
chmod +x "$STUB/git"

# --- gh stub ----------------------------------------------------------------
# Replays:
#   * the head_sha-scoped Docker Publish run query (#3338):
#       FAKE_API_FAIL=1     -> the query itself fails       (INFRA path)
#       FAKE_RUN_ID=""      -> no run exists for the commit (not-built path)
#       FAKE_RUN_STATUS     -> run status (default completed)
#   * job conclusions via $FAKE_SECURITY_SCAN / $FAKE_MANIFEST
#   * a release branch's .trivyignore via $FAKE_REL_TRIVYIGNORE (#3309); the
#     real call pipes `--jq .content` through `base64 -d`, so the stub emits
#     the base64 of the fixture text.
cat > "$STUB/gh" <<'STUBGH'
#!/usr/bin/env bash
case "$1" in
  api)
    case "$2" in
      *actions/workflows/docker-publish.yml/runs*)
        [ "${FAKE_API_FAIL-0}" = "1" ] && exit 1
        run_id="${FAKE_RUN_ID-12345}"
        [ -n "$run_id" ] && echo "$run_id ${FAKE_RUN_STATUS-completed}"
        exit 0
        ;;
      *contents/.trivyignore*)
        if [ -n "${FAKE_REL_TRIVYIGNORE-}" ]; then
          printf '%s\n' "$FAKE_REL_TRIVYIGNORE" | base64
          exit 0
        fi
        exit 1
        ;;
    esac
    ;;
  run)
    case "$2" in
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
  # Check 4 is exercised by its own fixture below; skip it here so these exit
  # codes stay a statement about check 3 alone.
  ( cd "$REPO_DIR" && PATH="$STUB:$PATH" \
      PREFLIGHT_REPO=artifact-keeper/artifact-keeper \
      PREFLIGHT_SKIP_VERSION_PIN=1 \
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

echo "release-preflight check 3 (#3308, #3338)"

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
FAKE_API_FAIL=1 FAKE_SECURITY_SCAN=success FAKE_MANIFEST=success \
  expect "unqueryable runs -> INFRA" 2 "INFRA"

# 4b. THE #3338 DISTINCTION: the query succeeded and there is NO run for this
#     commit. That is "not built yet" -- a fourth outcome. It must NOT read
#     as INFRA (nothing to retry), and it must NOT read as a pass (the images
#     the tag would pin do not exist).
FAKE_RUN_ID="" FAKE_SECURITY_SCAN=success FAKE_MANIFEST=success \
  expect "no run for this commit -> NOT READY (not built)" 1 "NOT been built"

# 4c. A run that exists but has not finished has no verdict yet. Blocking:
#     treating in-flight as absent or as green would launder an unfinished
#     measurement (#3338).
FAKE_RUN_STATUS=in_progress FAKE_SECURITY_SCAN=success FAKE_MANIFEST=success \
  expect "run still in progress -> NOT READY (wait)" 1 "still 'in_progress'"

# 5. The explicit human override reports the red but does not block. Separate
#    from PREFLIGHT_SKIP_DOCKER_HEALTH on purpose: "I looked, it is red,
#    proceeding" and "I did not look" must read differently.
( cd "$REPO_DIR" && PATH="$STUB:$PATH" PREFLIGHT_REPO=x/y \
    FAKE_SECURITY_SCAN=failure FAKE_MANIFEST=skipped PREFLIGHT_ALLOW_RED_PUBLISH=1 \
    PREFLIGHT_SKIP_VERSION_PIN=1 \
    bash scripts/ci/release-preflight.sh >"$WORK/out.txt" 2>&1 )
rc=$?
if [ "$rc" -eq 0 ] && grep -qF "PREFLIGHT_ALLOW_RED_PUBLISH=1 was set" "$WORK/out.txt"; then
  pass "explicit override -> READY, and says so (exit 0)"
else
  fail "explicit override: expected exit 0 with the override noted, got $rc"
  sed 's/^/        /' "$WORK/out.txt" >&2
fi

echo
echo "release-preflight check 1 (#3309)"

# --- check 1 fixtures -------------------------------------------------------
#   Check 1 used to demand that main's suppression token set be a strict
#   SUPERSET of every release branch's, which made every token permanent: a
#   suppression provably dead for main's images could not be deleted while
#   any release branch still listed it (#3309, the nine stuck tokens). The
#   fix accepts an explicit `# RETIRED: <token>` tombstone as accounting for
#   a release-branch token. Both directions must hold: a tombstone permits a
#   deliberate removal (case 2), and its existence must NOT swallow a real
#   forward-port miss (case 1) -- delete the `retired_tokens` handling from
#   check 1 and case 2 goes red; make it too broad and case 1 does.
REL_REFS=$'0000000000000000000000000000000000000000\trefs/heads/release/1.6.x'

expect1() { # <label> <expected-exit> <expected-substring> <main-trivyignore> <release-trivyignore>
  local label="$1" want="$2" needle="$3" main_ti="$4" rel_ti="$5" got
  printf '%s\n' "$main_ti" > "$REPO_DIR/.trivyignore"
  ( cd "$REPO_DIR" && PATH="$STUB:$PATH" \
      PREFLIGHT_REPO=artifact-keeper/artifact-keeper \
      FAKE_RELEASE_REFS="$REL_REFS" \
      FAKE_REL_TRIVYIGNORE="$rel_ti" \
      PREFLIGHT_SKIP_VERSION_PIN=1 \
      bash scripts/ci/release-preflight.sh >"$WORK/out.txt" 2>&1 )
  got=$?
  rm -f "$REPO_DIR/.trivyignore"
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

# 1. THE #3039 CASE STILL HARD-FAILS: a suppression on release/* that main
#    neither carries nor tombstones is a forward-port miss.
expect1 "release token unaccounted on main -> NOT READY" 1 "main is MISSING suppressions" \
  "CVE-2099-0001" \
  "CVE-2099-0001
CVE-2099-0002"

# 2. THE #3309 FIX: a token main deliberately removed is accounted for by a
#    machine-read tombstone, so removal is possible without disabling the
#    gate -- and the transcript says the coverage came from a tombstone.
expect1 "release token tombstoned on main -> READY" 0 "via RETIRED tombstones" \
  "CVE-2099-0001
# RETIRED: CVE-2099-0002 (2026-08-14, measured absent from main's images, #3309)" \
  "CVE-2099-0001
CVE-2099-0002"

# 3. Live coverage still passes untouched (the pre-#3309 happy path).
expect1 "release tokens all live on main -> READY" 0 "READY" \
  "CVE-2099-0001
CVE-2099-0002" \
  "CVE-2099-0001
CVE-2099-0002"

# 4. A token listed BOTH live and retired is a contradiction, not a choice
#    the gate silently makes for you.
expect1 "token both live and tombstoned -> NOT READY" 1 "BOTH as live suppressions" \
  "CVE-2099-0001
# RETIRED: CVE-2099-0001" \
  "CVE-2099-0001"

echo
echo "release-preflight check 4 (#3339)"

# --- check 4 fixture --------------------------------------------------------
#   Check 4 asks: is this component's pinned version tag already published from
#   DIFFERENT sources? v1.7.2 was tagged with docker/scanner-adapter/VERSION at
#   1.2.2 while #3315 had re-pinned the trivy base image in
#   docker/Dockerfile.scanner-adapter. The tag's Docker Publish refused to
#   republish 1.2.2, which skipped every remaining manifest and stopped the
#   release chain on an immutable tag that then had to be deleted by hand.
#
#   The reason this needs a pre-tag check rather than trusting CI: the publish
#   job only evaluates the exact tag when `stable_requested` is true, which
#   needs a clean `refs/tags/v*`. Docker Publish on main passed on the very
#   same commit, and an `-rc.N` tag would have passed too. So the green path
#   here is not the interesting one -- case 2 is, and it must be able to fail.
#   Revert `bad` to `warn` on the changed-sources branch of check 4 and it goes
#   red.
#
#   Registry answers are replayed through the two probe-command overrides, so
#   there is no network, no docker daemon and no credential involved.
REPO4="$WORK/repo4"
mkdir -p "$REPO4/scripts/ci" "$REPO4/backend/src/api" "$REPO4/docker/scanner-adapter"
cp "$SCRIPT" "$REPO4/scripts/ci/release-preflight.sh"
printf 'version = "9.9.9"\n' > "$REPO4/Cargo.toml"
printf 'version = "9.9.9"\n' > "$REPO4/backend/src/api/openapi.rs"
printf 'name = "artifact-keeper-backend"\nversion = "9.9.9"\n' > "$REPO4/Cargo.lock"
printf '1.2.2\n' > "$REPO4/docker/scanner-adapter/VERSION"
printf 'FROM ghcr.io/artifact-keeper/trivy@sha256:aaa AS trivy\n' \
  > "$REPO4/docker/Dockerfile.scanner-adapter"
git -C "$REPO4" init -q
git -C "$REPO4" remote add origin https://github.com/artifact-keeper/artifact-keeper.git
git -C "$REPO4" -c user.email=t@t -c user.name=t add -A
git -C "$REPO4" -c user.email=t@t -c user.name=t commit -qm published
# The commit the published 1.2.2 image would be annotated with.
PUBLISHED_REV="$(git -C "$REPO4" rev-parse HEAD)"

# Now re-pin the base image WITHOUT bumping VERSION: the #3315 shape exactly.
printf 'FROM ghcr.io/artifact-keeper/trivy@sha256:bbb AS trivy\n' \
  > "$REPO4/docker/Dockerfile.scanner-adapter"
git -C "$REPO4" -c user.email=t@t -c user.name=t add -A
git -C "$REPO4" -c user.email=t@t -c user.name=t commit -qm 'repin trivy, no VERSION bump'
CHANGED_REV="$(git -C "$REPO4" rev-parse HEAD)"

# git stub: ls-remote succeeds with no release/* branches, and fetch is refused
# so a test can never reach the network for a commit it does not have.
STUB4="$WORK/bin4"; mkdir -p "$STUB4"
cat > "$STUB4/git" <<'STUBGIT4'
#!/usr/bin/env bash
for a in "$@"; do
  [ "$a" = "ls-remote" ] && exit 0
  [ "$a" = "fetch" ] && exit 1
done
exec /usr/bin/git "$@"
STUBGIT4
chmod +x "$STUB4/git"
cp "$STUB/gh" "$STUB4/gh"

# Probe stubs: replay $FAKE_TAG_STATE / $FAKE_TAG_REVISION.
PROBES="$WORK/probes"; mkdir -p "$PROBES"
cat > "$PROBES/state" <<'STUBSTATE'
#!/usr/bin/env bash
echo "${FAKE_TAG_STATE-absent}"
[ "${FAKE_TAG_STATE-absent}" = "indeterminate" ] && exit 1
exit 0
STUBSTATE
cat > "$PROBES/revision" <<'STUBREV'
#!/usr/bin/env bash
echo "${FAKE_TAG_REVISION-none}"
case "${FAKE_TAG_REVISION-none}" in
  [0-9a-f][0-9a-f]*) exit 0 ;;
  *) exit 1 ;;
esac
STUBREV
chmod +x "$PROBES/state" "$PROBES/revision"

expect4() { # <label> <expected-exit> <expected-substring>
  local label="$1" want="$2" needle="$3" got
  ( cd "$REPO4" && PATH="$STUB4:$PATH" \
      PREFLIGHT_REPO=artifact-keeper/artifact-keeper \
      PREFLIGHT_TAG_STATE_CMD="$PROBES/state" \
      PREFLIGHT_TAG_REVISION_CMD="$PROBES/revision" \
      bash scripts/ci/release-preflight.sh >"$WORK/out.txt" 2>&1 )
  got=$?
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

# 1. GREEN, the ordinary case: the pinned version is not published yet, so the
#    cut will create it. Guards against a gate that blocks every release.
FAKE_TAG_STATE=absent \
  expect4 "adapter version unpublished -> READY" 0 "READY"

# 2. GREEN, the subtle one: the tag IS published, but from these exact sources.
#    An unchanged-source rebuild is legitimate (it re-points the floating tags
#    for base-image errata), so this must NOT be treated as a collision.
FAKE_TAG_STATE=present FAKE_TAG_REVISION="$CHANGED_REV" \
  expect4 "published, sources unchanged -> READY" 0 "READY"

# 3. THE REGRESSION (the v1.7.2 shape). Published from an earlier commit whose
#    scanner-adapter sources differ from HEAD, with VERSION still 1.2.2.
FAKE_TAG_STATE=present FAKE_TAG_REVISION="$PUBLISHED_REV" \
  expect4 "published, sources CHANGED -> NOT READY" 1 "NOT READY"

# 3b. ...and it must name the file that has to be bumped, not just fail.
FAKE_TAG_STATE=present FAKE_TAG_REVISION="$PUBLISHED_REV" \
  expect4 "collision names the VERSION file to bump" 1 "bump docker/scanner-adapter/VERSION"

# 4. Could not measure is NOT a readiness verdict -- an unreadable registry is
#    INFRA (exit 2), never a pass and never a failure. Same lesson as #3308.
FAKE_TAG_STATE=indeterminate \
  expect4 "registry unreadable -> INFRA" 2 "INFRA"

# 5. Published but with no provenance annotation is MEASURED, not infra: the
#    publish job hard-fails on it too, so it blocks rather than retries.
FAKE_TAG_STATE=present FAKE_TAG_REVISION=none \
  expect4 "published without provenance -> NOT READY" 1 "NOT READY"

echo
if [ "$fails" -eq 0 ]; then
  echo "all release-preflight cases passed"
  exit 0
fi
echo "$fails case(s) failed"
exit 1
