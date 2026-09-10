#!/usr/bin/env bash
#
# Self-test for scripts/ci/assert-adapter-exact-version.sh (issue #3773).
#
# The check mirrors docker-publish.yml's stable-tag-only adapter decision so
# the candidate exercises it before any tag exists. Every refusing leg of the
# publish job is reproduced here against stubbed registry probes and a
# throwaway git repository: registries disagreeing, a changed-source rebuild,
# a VERSION collision, missing provenance, and an unreadable registry (INFRA,
# never a pass). Offline, ~1s.
#
# Usage: bash scripts/ci/test-assert-adapter-exact-version.sh
set -uo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assert-adapter-exact-version.sh"
[ -f "$SCRIPT" ] || { echo "cannot find assert-adapter-exact-version.sh next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

# --- a repository with three commits -----------------------------------------
#   C1: VERSION=1.2.9, adapter sources v1
#   C2: VERSION=1.2.9, unrelated file changed (sources unchanged)
#   C3: VERSION=1.2.9, Dockerfile.scanner-adapter changed (sources changed)
REPO="$WORK/repo"; mkdir -p "$REPO/docker/scanner-adapter"
git -C "$REPO" init -q
git -C "$REPO" config user.email t@example.com; git -C "$REPO" config user.name t
echo 1.2.9 > "$REPO/docker/scanner-adapter/VERSION"
echo 'FROM alpine' > "$REPO/docker/Dockerfile.scanner-adapter"
echo 'go' > "$REPO/docker/scanner-adapter/main.go"
git -C "$REPO" add -A && git -C "$REPO" commit -qm c1
C1="$(git -C "$REPO" rev-parse HEAD)"
echo readme > "$REPO/README.md"
git -C "$REPO" add -A && git -C "$REPO" commit -qm c2
C2="$(git -C "$REPO" rev-parse HEAD)"
echo '# comment' >> "$REPO/docker/Dockerfile.scanner-adapter"
git -C "$REPO" add -A && git -C "$REPO" commit -qm c3
C3="$(git -C "$REPO" rev-parse HEAD)"

# --- probe stubs ---------------------------------------------------------------
STUB="$WORK/bin"; mkdir -p "$STUB"
cat > "$STUB/state" <<'S'
#!/usr/bin/env bash
case "$1" in ghcr.io) v="${FAKE_GHCR_STATE:-present}" ;; docker.io) v="${FAKE_HUB_STATE:-present}" ;; esac
echo "$v"; [ "$v" = indeterminate ] && exit 1; exit 0
S
cat > "$STUB/rev" <<'S'
#!/usr/bin/env bash
echo "${FAKE_REV:-none}"; case "${FAKE_REV:-none}" in none|indeterminate) exit 1 ;; *) exit 0 ;; esac
S
chmod +x "$STUB/state" "$STUB/rev"

# <label> <want-rc> <sha> <needle>
expect() {
  local label="$1" want="$2" sha="$3" needle="$4" got=0 out
  out="$( cd "$REPO" && ADAPTER_SHA="$sha" \
      ADAPTER_TAG_STATE_CMD="$STUB/state" ADAPTER_TAG_REVISION_CMD="$STUB/rev" \
      bash "$SCRIPT" 2>&1 )" || got=$?
  if [ "$got" = "$want" ] && printf '%s' "$out" | grep -qF -- "$needle"; then
    pass "$label"
  else
    fail "$label (wanted exit ${want} containing '${needle}', got exit ${got})"
    printf '%s\n' "$out" | sed 's/^/        /' | tail -n 5
  fi
}

echo "assert-adapter-exact-version.sh self-test"

FAKE_GHCR_STATE=absent FAKE_HUB_STATE=absent \
  expect "absent on both -> ok, will be created" 0 "$C2" "new on both registries"

FAKE_REV="$C1" \
  expect "present, sources unchanged -> ok" 0 "$C2" "sources are unchanged"

FAKE_REV="$C1" \
  expect "present, sources changed -> BLOCKED (VERSION bump required)" 1 "$C3" "Bump docker/scanner-adapter/VERSION"

FAKE_GHCR_STATE=present FAKE_HUB_STATE=absent \
  expect "registries disagree -> BLOCKED" 1 "$C2" "partial publish"

FAKE_REV=none \
  expect "published with no provenance -> BLOCKED" 1 "$C2" "no valid source revision"

FAKE_GHCR_STATE=indeterminate \
  expect "ghcr unreadable -> INFRA (exit 2)" 2 "$C2" "unable to prove"

FAKE_REV=indeterminate \
  expect "revision unreadable -> INFRA (exit 2)" 2 "$C2" "could not read the source revision"

# VERSION collision: the published image was built from a commit whose VERSION
# file says something else.
mkdir -p "$WORK/x"; ( cd "$REPO" && echo 1.2.8 > docker/scanner-adapter/VERSION && git commit -qam c4 )
C4="$(git -C "$REPO" rev-parse HEAD)"
FAKE_REV="$C4" \
  expect "published from a commit with another VERSION -> BLOCKED (collision)" 1 "$C2" "version collision"

expect "malformed sha -> INFRA (exit 2)" 2 "nope" "40-character"

echo
if [ "$fails" -eq 0 ]; then echo "all assert-adapter-exact-version.sh cases passed"; exit 0; fi
echo "${fails} assert-adapter-exact-version.sh case(s) FAILED"; exit 1
