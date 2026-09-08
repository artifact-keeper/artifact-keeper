#!/usr/bin/env bash
#
# Self-test for .github/scripts/registry-tag-digest.sh (issue #3771).
#
# The probe is what the candidate and promote flows use to learn which digest
# a `sha-<sha>` or `:X.Y.Z` tag names, and what the release compares the
# certification against. The dangerous direction is a wrong or invented
# answer: a 404 read as absence from a repository we could not read, a 5xx
# read as anything, or a digest fabricated when the registry gave none. Each
# of those legs is exercised here against a stub `curl` that replays canned
# HTTP answers -- no network, ~1s.
#
# Usage: bash scripts/ci/test-registry-tag-digest.sh
set -uo pipefail

PROBE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/.github/scripts/registry-tag-digest.sh"
[ -f "$PROBE" ] || { echo "cannot find .github/scripts/registry-tag-digest.sh" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails + 1)); }

DIGEST=sha256:0000000000000000000000000000000000000000000000000000000000000abc

# --- curl stub ---------------------------------------------------------------
# Three request shapes, told apart by URL:
#   /token?...        -> {"token":"t"}                    (FAKE_TOKEN_FAIL=1: empty)
#   /tags/list?...    -> HTTP $FAKE_LIST_CODE, empty body
#   /manifests/<tag>  -> HTTP $FAKE_MANIFEST_CODE, body $FAKE_MANIFEST_BODY,
#                        header Docker-Content-Digest when FAKE_HEADER=1
STUB="$WORK/bin"; mkdir -p "$STUB"
cat > "$STUB/curl" <<'STUBCURL'
#!/usr/bin/env bash
out=""; hdr=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -D) hdr="$2"; shift 2 ;;
    -w|-H|-u|--max-time|--proto) shift 2 ;;
    http*) url="$1"; shift ;;
    *) shift ;;
  esac
done
case "$url" in
  *"/token?"*)
    [ "${FAKE_TOKEN_FAIL:-0}" = "1" ] && { printf '{}'; exit 0; }
    printf '{"token":"t"}'; exit 0 ;;
  *"/tags/list?"*)
    printf '%s' "${FAKE_LIST_CODE:-200}"; exit 0 ;;
  *"/manifests/"*)
    [ -n "$out" ] && printf '%s' "${FAKE_MANIFEST_BODY:-}" > "$out"
    if [ -n "$hdr" ]; then
      if [ "${FAKE_HEADER:-1}" = "1" ]; then
        printf 'HTTP/2 %s\r\ndocker-content-digest: %s\r\n\r\n' "${FAKE_MANIFEST_CODE:-200}" "${FAKE_DIGEST}" > "$hdr"
      else
        printf 'HTTP/2 %s\r\n\r\n' "${FAKE_MANIFEST_CODE:-200}" > "$hdr"
      fi
    fi
    printf '%s' "${FAKE_MANIFEST_CODE:-200}"; exit 0 ;;
esac
exit 7
STUBCURL
chmod +x "$STUB/curl"

# <label> <expected-stdout> <expected-exit>
expect() {
  local label="$1" want_out="$2" want_rc="$3" got_out got_rc=0
  got_out="$(PATH="$STUB:$PATH" FAKE_DIGEST="$DIGEST" bash "$PROBE" ghcr.io artifact-keeper/x sha-abc1234 2>/dev/null)" || got_rc=$?
  if [ "$got_out" = "$want_out" ] && [ "$got_rc" = "$want_rc" ]; then
    pass "$label"
  else
    fail "$label (wanted '${want_out}' rc=${want_rc}, got '${got_out}' rc=${got_rc})"
  fi
}

echo "registry-tag-digest.sh self-test"

# 1. the normal answer: header digest
FAKE_MANIFEST_CODE=200 FAKE_HEADER=1 FAKE_MANIFEST_BODY='{"schemaVersion":2}' \
  expect "200 with Docker-Content-Digest -> that digest" "$DIGEST" 0

# 2. no header: the body's own sha256 is the digest, never nothing
body='{"schemaVersion":2,"manifests":[]}'
want="sha256:$(printf '%s' "$body" | sha256sum | awk '{print $1}')"
FAKE_MANIFEST_CODE=200 FAKE_HEADER=0 FAKE_MANIFEST_BODY="$body" \
  expect "200 without the header -> sha256 of the body" "$want" 0

# 3. a definitive absence
FAKE_MANIFEST_CODE=404 FAKE_MANIFEST_BODY='{"errors":[{"code":"MANIFEST_UNKNOWN"}]}' \
  expect "404 MANIFEST_UNKNOWN from a readable repo -> absent" absent 1

# 4. a 404 that says nothing (auth shape) is NOT absence
FAKE_MANIFEST_CODE=404 FAKE_MANIFEST_BODY='<html>not found</html>' \
  expect "404 without MANIFEST_UNKNOWN -> indeterminate" indeterminate 1

# 5. a registry outage is not an answer
FAKE_MANIFEST_CODE=503 FAKE_MANIFEST_BODY='' \
  expect "503 -> indeterminate" indeterminate 1

# 6. no read access proven -> the manifest answer is never consulted
FAKE_LIST_CODE=401 FAKE_MANIFEST_CODE=404 FAKE_MANIFEST_BODY='{"errors":[{"code":"MANIFEST_UNKNOWN"}]}' \
  expect "tag listing 401 -> indeterminate even on a MANIFEST_UNKNOWN 404" indeterminate 1

# 7. no token
FAKE_TOKEN_FAIL=1 \
  expect "no pull token -> indeterminate" indeterminate 1

# 8. a header carrying garbage is not trusted as a digest
got="$(PATH="$STUB:$PATH" FAKE_MANIFEST_CODE=200 FAKE_HEADER=1 FAKE_MANIFEST_BODY="$body" FAKE_DIGEST="not-a-digest" \
  bash "$PROBE" ghcr.io artifact-keeper/x sha-abc1234 2>/dev/null)"
if [ "$got" = "$want" ]; then pass "malformed header digest -> falls back to the body digest"; else fail "malformed header digest (got '$got')"; fi

# 9. usage
got_rc=0; got="$(bash "$PROBE" ghcr.io only-two 2>/dev/null)" || got_rc=$?
if [ "$got" = "indeterminate" ] && [ "$got_rc" = "1" ]; then pass "bad usage -> indeterminate, exit 1"; else fail "bad usage (got '$got' rc=$got_rc)"; fi

echo
if [ "$fails" -eq 0 ]; then echo "all registry-tag-digest.sh cases passed"; exit 0; fi
echo "${fails} registry-tag-digest.sh case(s) FAILED"; exit 1
