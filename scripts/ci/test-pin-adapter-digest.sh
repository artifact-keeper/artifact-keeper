#!/usr/bin/env bash
#
# Self-test for scripts/ci/pin-adapter-digest.sh (issue #4076): which adapter
# digest the candidate certifies. The registry probes are stubbed, so this is
# offline, ~1s. Every refusing leg must exit 1 and write no outputs.
#
# Usage: bash scripts/ci/test-pin-adapter-digest.sh
set -uo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pin-adapter-digest.sh"
[ -f "$SCRIPT" ] || { echo "cannot find pin-adapter-digest.sh next to this test" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

OWNER=cccccccccccccccccccccccccccccccccccccccc
D_REBUILD=sha256:1111111111111111111111111111111111111111111111111111111111111111
D_PUB=sha256:2222222222222222222222222222222222222222222222222222222222222222
D_OTHER=sha256:9999999999999999999999999999999999999999999999999999999999999999
IMG=ghcr.io/artifact-keeper/artifact-keeper-scanner-adapter

# A repository with two commits: OLD carries a pre-#4076 verifier, NEW one
# that understands scanner_adapter_decision.
REPO="$WORK/repo"; mkdir -p "$REPO/scripts/ci"
git -C "$REPO" init -q
git -C "$REPO" config user.email t@example.com; git -C "$REPO" config user.name t
echo 'digests[$k] only' > "$REPO/scripts/ci/assert-candidate-certified.sh"
git -C "$REPO" add -A && git -C "$REPO" commit -qm old
OLD="$(git -C "$REPO" rev-parse HEAD)"
echo 'reads .scanner_adapter_decision' > "$REPO/scripts/ci/assert-candidate-certified.sh"
git -C "$REPO" commit -qam new
NEW="$(git -C "$REPO" rev-parse HEAD)"

STUB="$WORK/bin"; mkdir -p "$STUB"
# digest probe: <registry> <repository> <tag>; :VERSION from FAKE_VERSION_DIGEST,
# sha-<owner> from FAKE_OWNER_DIGEST.
cat > "$STUB/digest" <<'S'
#!/usr/bin/env bash
case "$3" in sha-*) v="${FAKE_OWNER_DIGEST-}" ;; *) v="${FAKE_VERSION_DIGEST-}" ;; esac
[ -n "$v" ] || v=indeterminate
echo "$v"; case "$v" in sha256:*) exit 0 ;; *) exit 1 ;; esac
S
# consistency guard: refuses when FAKE_HUB_DISAGREES=1; records its arguments.
cat > "$STUB/consistent" <<'S'
#!/usr/bin/env bash
echo "$*" > "${FAKE_CONSISTENT_ARGS:-/dev/null}"
[ "${FAKE_HUB_DISAGREES:-0}" = 1 ] && { echo "docker.io differs" >&2; exit 1; }
exit 0
S
chmod +x "$STUB/digest" "$STUB/consistent"

# <label> <want-exit> <needle> <exact GITHUB_OUTPUT, '' = must be empty>; scenario from env.
expect() {
  local label="$1" want="$2" needle="$3" wantout="$4" got=0 out gho
  gho="$WORK/gho.$RANDOM"; : > "$gho"
  out="$( cd "$REPO" && GITHUB_OUTPUT="$gho" SHORT=abcdef1 ADAPTER_IMAGE="$IMG" \
      PIN_DIGEST_CMD="$STUB/digest" PIN_CONSISTENT_CMD="$STUB/consistent" \
      bash "$SCRIPT" 2>&1 )" || got=$?
  if [ "$got" = "$want" ] && printf '%s' "$out" | grep -qF -- "$needle" && [ "$(cat "$gho")" = "$wantout" ]; then
    pass "$label"
  else
    fail "$label (wanted exit ${want} containing '${needle}', got exit ${got}); output / GITHUB_OUTPUT:"
    printf '%s\n' "$out" | sed 's/^/        /' | tail -n 4
    sed 's/^/        > /' "$gho"
  fi
}

export ADAPTER_VERSION=1.3.0 REBUILD_DIGEST="$D_REBUILD" CERT_SHA="$NEW"
unset CERTIFIED_BRANCH DECISION OWNER_REV FAKE_VERSION_DIGEST FAKE_OWNER_DIGEST FAKE_HUB_DISAGREES FAKE_CONSISTENT_ARGS GITHUB_OUTPUT

echo "pin-adapter-digest.sh self-test"

DECISION=new OWNER_REV='' \
  expect "new -> the rebuild at sha-<sha>" 0 "is new" \
  "$(printf 'adapter_digest=%s\nadapter_tag=sha-abcdef1\nadapter_image_ref=%s:sha-abcdef1@%s\nadapter_decision=new\nadapter_owner_rev=' "$D_REBUILD" "$IMG" "$D_REBUILD")"

DECISION=new REBUILD_DIGEST=unreadable \
  expect "new, rebuild digest unknown -> refused" 1 "not a sha256 digest" ""

FAKE_CONSISTENT_ARGS="$WORK/args" DECISION=stays OWNER_REV="$OWNER" FAKE_VERSION_DIGEST="$D_PUB" FAKE_OWNER_DIGEST="$D_PUB" \
  expect "stays, provenance and hub agree -> the published :VERSION" 0 "stays" \
  "$(printf 'adapter_digest=%s\nadapter_tag=1.3.0\nadapter_image_ref=%s:1.3.0@%s\nadapter_decision=stays\nadapter_owner_rev=%s' "$D_PUB" "$IMG" "$D_PUB" "$OWNER")"
if [ "$(cat "$WORK/args" 2>/dev/null)" = "1.3.0 ${D_PUB} ghcr.io|artifact-keeper/artifact-keeper-scanner-adapter docker.io|artifactkeeper/scanner-adapter" ]; then
  pass "stays asks the digest guard about :1.3.0 on both registries"
else
  fail "digest guard called with '$(cat "$WORK/args" 2>/dev/null)'"
fi

DECISION=stays OWNER_REV="$OWNER" FAKE_VERSION_DIGEST="$D_PUB" FAKE_OWNER_DIGEST="$D_OTHER" \
  expect "stays, :VERSION is not the owner's sha tag -> refused" 1 "provenance mismatch" ""

DECISION=stays OWNER_REV="$OWNER" FAKE_VERSION_DIGEST="$D_PUB" FAKE_OWNER_DIGEST="" \
  expect "stays, owner's sha tag unreadable -> refused" 1 "provenance mismatch" ""

DECISION=stays OWNER_REV="$OWNER" FAKE_VERSION_DIGEST="" FAKE_OWNER_DIGEST="$D_PUB" \
  expect "stays, :VERSION unreadable -> refused" 1 "Published scanner adapter unreadable" ""

DECISION=stays OWNER_REV="$OWNER" FAKE_VERSION_DIGEST="$D_PUB" FAKE_OWNER_DIGEST="$D_PUB" FAKE_HUB_DISAGREES=1 \
  expect "stays, Docker Hub names other bytes -> refused" 1 "registries disagree" ""

DECISION=stays OWNER_REV="abc123" FAKE_VERSION_DIGEST="$D_PUB" FAKE_OWNER_DIGEST="$D_PUB" \
  expect "stays with a malformed owner_rev -> refused" 1 "named no owning revision" ""

DECISION=stays OWNER_REV="" FAKE_VERSION_DIGEST="$D_PUB" FAKE_OWNER_DIGEST="$D_PUB" \
  expect "stays with no owner_rev -> refused" 1 "named no owning revision" ""

# The burned-version guard: a commit whose own verifier predates #4076 cannot
# take a "stays" certification (release.yml on its tag would refuse it).
CERT_SHA="$OLD" CERTIFIED_BRANCH=release/1.10.x DECISION=stays OWNER_REV="$OWNER" FAKE_VERSION_DIGEST="$D_PUB" FAKE_OWNER_DIGEST="$D_PUB" \
  expect "stays on a commit with a pre-#4076 verifier -> refused, names the backport" 1 "Backport #4076 to release/1.10.x first" ""
# ...but "new" is fine there: every verifier accepts the sha-<sha> rebuild.
CERT_SHA="$OLD" DECISION=new OWNER_REV='' \
  expect "new on a commit with a pre-#4076 verifier -> ok" 0 "is new" \
  "$(printf 'adapter_digest=%s\nadapter_tag=sha-abcdef1\nadapter_image_ref=%s:sha-abcdef1@%s\nadapter_decision=new\nadapter_owner_rev=' "$D_REBUILD" "$IMG" "$D_REBUILD")"
CERT_SHA=nope DECISION=stays OWNER_REV="$OWNER" FAKE_VERSION_DIGEST="$D_PUB" FAKE_OWNER_DIGEST="$D_PUB" \
  expect "stays without a full certified sha -> refused" 1 "CERT_SHA must be" ""
CERT_SHA="$(printf 'd%.0s' $(seq 40))" DECISION=stays OWNER_REV="$OWNER" FAKE_VERSION_DIGEST="$D_PUB" FAKE_OWNER_DIGEST="$D_PUB" \
  expect "stays on a commit that is not in the repository -> refused" 1 "predates #4076" ""

DECISION=maybe \
  expect "unknown decision -> refused" 1 "decision='maybe'" ""

DECISION="" \
  expect "empty decision -> refused" 1 "decision=''" ""

DECISION=new ADAPTER_VERSION="" \
  expect "no adapter version -> refused" 1 "ADAPTER_VERSION is empty" ""

echo
if [ "$fails" -eq 0 ]; then echo "all pin-adapter-digest.sh cases passed"; exit 0; fi
echo "${fails} pin-adapter-digest.sh case(s) FAILED"; exit 1
