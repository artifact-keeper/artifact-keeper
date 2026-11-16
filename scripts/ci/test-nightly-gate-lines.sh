#!/usr/bin/env bash
#
# Self-test for scripts/ci/nightly-gate-lines.sh (#6073).
#
# The resolver decides which lines the nightly gate tests and which bytes.
# Testing a stale maintenance line wastes the pool for hours; testing an
# image whose recorded revision is not the commit would put a verdict on the
# wrong commit, which #6075 then trusts. Stubs `gh` and the registry helpers
# and builds a scratch git repository for the branch dates; offline, ~1s.
#
# Usage: bash scripts/ci/test-nightly-gate-lines.sh
set -uo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/nightly-gate-lines.sh"
[ -f "$SCRIPT" ] || { echo "cannot find nightly-gate-lines.sh next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

NOW=1794800000
DAY=86400

# A repository whose origin/release/* refs carry chosen commit dates, and
# whose commits carry a Cargo.toml version.
REPO="$WORK/repo"
git init -q "$REPO"
commit_at() { # <epoch> <version> -> sha
  printf '[package]\nversion = "%s"\n' "$2" > "$REPO/Cargo.toml"
  git -C "$REPO" add Cargo.toml
  GIT_COMMITTER_DATE="@$1" GIT_AUTHOR_DATE="@$1" \
    git -C "$REPO" -c user.name=t -c user.email=t@t commit -q --allow-empty -m "v$2"
  git -C "$REPO" rev-parse HEAD
}
SHA_MAIN=$(commit_at $((NOW - DAY)) 1.12.0)
SHA_111=$(commit_at $((NOW - 2 * DAY)) 1.11.14)
SHA_110=$(commit_at $((NOW - 40 * DAY)) 1.10.2)
SHA_19=$(commit_at $((NOW - 90 * DAY)) 1.9.9)
git -C "$REPO" update-ref refs/remotes/origin/release/1.11.x "$SHA_111"
git -C "$REPO" update-ref refs/remotes/origin/release/1.10.x "$SHA_110"
git -C "$REPO" update-ref refs/remotes/origin/release/1.9.x "$SHA_19"
git -C "$REPO" update-ref refs/remotes/origin/feature/x "$SHA_111"

STUB="$WORK/bin"; mkdir -p "$STUB"
# FAKE_RUN_<branch with / and . as _>: "<run id> <head sha>" for the newest
# successful push/dispatch Docker Publish run, empty for none.
cat > "$STUB/gh" <<'STUBGH'
#!/usr/bin/env bash
[ "$1" = "api" ] || exit 64
case "$2" in
  *docker-publish.yml/runs*)
    [ "${FAKE_LIST_FAIL:-0}" = "1" ] && exit 1
    b="${2#*branch=}"; b="${b%%&*}"; v="FAKE_RUN_${b//[\/.]/_}"
    [ -n "${!v-}" ] && printf '%s\n' "${!v}"
    exit 0 ;;
esac
exit 64
STUBGH
# Digest: FAKE_DIGEST_<tag>, default a good digest. Revision: FAKE_REV_<tag>,
# default the sha the stub was told about in FAKE_SHA_<tag>.
cat > "$STUB/digest" <<'STUB'
#!/usr/bin/env bash
v="FAKE_DIGEST_${3//-/_}"; d="${!v-sha256:$(printf 'a%.0s' {1..64})}"
echo "$d"; [[ "$d" == sha256:* ]]
STUB
cat > "$STUB/revision" <<'STUB'
#!/usr/bin/env bash
v="FAKE_REV_${3//-/_}"; echo "${!v-none}"
STUB
chmod +x "$STUB"/*

run() {
  RC=0
  OUT="$(cd "$REPO" && env PATH="$STUB:$PATH" LINES_REPO=o/r LINES_NOW=$NOW LINES_GIT_DIR="$REPO" \
    LINES_DIGEST_CMD="$STUB/digest" LINES_REVISION_CMD="$STUB/revision" \
    FAKE_RUN_main="11 $SHA_MAIN" FAKE_RUN_release_1_11_x="12 $SHA_111" FAKE_RUN_release_1_10_x="13 $SHA_110" \
    "FAKE_REV_sha_${SHA_MAIN:0:7}=$SHA_MAIN" "FAKE_REV_sha_${SHA_111:0:7}=$SHA_111" "FAKE_REV_sha_${SHA_110:0:7}=$SHA_110" \
    "$@" bash "$SCRIPT" 2>/dev/null)" || RC=$?
}
q() { jq -r "$1" <<<"$OUT" 2>/dev/null; }

run
if [ "$RC" = 0 ] && [ "$(q '[.[].line] | join(" ")')" = "main 1.11.x" ]; then
  pass "default lines: main and the active 1.11.x; 1.10.x (40 days) and 1.9.x are not active"
else fail "default lines (rc=$RC): $OUT"; fi
if [ "$(q '.[0].sha')" = "$SHA_MAIN" ] && [ "$(q '.[0].short')" = "${SHA_MAIN:0:7}" ] \
   && [ "$(q '.[0].publish_run')" = 11 ] && [ "$(q '.[0].version')" = 1.12.0 ] \
   && [ "$(q '.[1].branch')" = release/1.11.x ] && [ "$(q '.[1].version')" = 1.11.14 ]; then
  pass "each line carries its commit, publish run, version and branch"
else fail "line fields: $OUT"; fi

run LINES_ACTIVE_DAYS=60
if [ "$(q '[.[].line] | join(" ")')" = "main 1.11.x 1.10.x" ]; then pass "a wider window includes 1.10.x, newest line first"
else fail "60-day window: $OUT"; fi

run LINES_OVERRIDE="release/1.10.x,main"
if [ "$RC" = 0 ] && [ "$(q '[.[].line] | join(" ")')" = "1.10.x main" ]; then pass "override replaces the derivation and accepts release/ prefixes"
else fail "override: $OUT"; fi

run LINES_OVERRIDE="main; rm -rf /"
if [ "$RC" = 2 ]; then pass "an override that is not main or X.Y.x is refused"; else fail "bad override rc=$RC"; fi

run FAKE_RUN_release_1_11_x=""
if [ "$RC" = 0 ] && [ "$(q '.[1].error')" = "no successful Docker Publish run on release/1.11.x" ] && [ "$(q '.[0].error')" = null ]; then
  pass "a line with no published image is reported, the others still resolve"
else fail "no publish run (rc=$RC): $OUT"; fi

run "FAKE_REV_sha_${SHA_MAIN:0:7}=$SHA_111"
if [[ "$(q '.[0].error')" == *"records revision '${SHA_111}', not ${SHA_MAIN}"* ]]; then
  pass "an image built from another commit is refused"
else fail "revision mismatch: $OUT"; fi

run "FAKE_DIGEST_sha_${SHA_MAIN:0:7}=indeterminate"
if [[ "$(q '.[0].error')" == *"is 'indeterminate'"* ]]; then pass "an unreadable digest is refused, never guessed"
else fail "indeterminate digest: $OUT"; fi

run FAKE_LIST_FAIL=1
if [ "$RC" = 1 ] && [ "$(q '[.[] | select(.error)] | length')" = 2 ]; then pass "no line resolved: exit 1, every line explained"
else fail "all unresolved (rc=$RC): $OUT"; fi

echo
if [ "$fails" -ne 0 ]; then echo "$fails check(s) failed"; exit 1; fi
echo "all nightly-gate-lines checks passed"
