#!/usr/bin/env bash
# =============================================================================
# test-check-curl-advisories.sh — the curl advisory watch must catch what it must
# =============================================================================
#
# check-curl-advisories.py is silent when healthy, and with curl's own feed
# clean against the current pin it is healthy almost every day. A regression
# in the range arithmetic (an inverted comparison, a gap between two fixed
# releases read as affected or the reverse) would stay invisible until the day
# it mattered (#6003). This drives it against scripts/ci/fixtures/curl-vuln.json
# (three real records from https://curl.se/docs/vuln.json: one `both`, one
# `lib`, one `tool`, each with curl's multi-branch fixed ranges) and against
# small hand-written feeds for the shapes the real feed does not carry today.
#
# Builds throwaway repositories, no network, ~1s.
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="$HERE/check-curl-advisories.py"
FIXTURE="$HERE/fixtures/curl-vuln.json"
REPO="$(cd "$HERE/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0

# repo <name> <backend pin or ""> <openscap pin or "">: a throwaway repository
# with the two Dockerfiles, each carrying just its CURL_VERSION line.
repo() {
  local d="$TMP/$1"
  rm -rf "$d"; mkdir -p "$d/docker"
  if [ -n "$2" ]; then printf 'FROM x AS curl-bin\nARG CURL_VERSION=%s\n' "$2" > "$d/docker/Dockerfile.backend"
  else printf 'FROM x AS curl-bin\n' > "$d/docker/Dockerfile.backend"; fi
  if [ -n "$3" ]; then printf 'FROM x AS curl-builder\nARG CURL_VERSION=%s\n' "$3" > "$d/docker/Dockerfile.openscap"
  else printf 'FROM x AS curl-builder\n' > "$d/docker/Dockerfile.openscap"; fi
  echo "$d"
}

# feed <name> <json>: a hand-written feed file.
feed() { printf '%s\n' "$2" > "$TMP/$1.json"; echo "$TMP/$1.json"; }

OUT=""
# expect <want rc> <name> <repo> <feed> [grep patterns that must appear...]
# A pattern prefixed with '!' must NOT appear.
expect() {
  local want="$1" name="$2" dir="$3" src="$4"; shift 4
  local rc ok=1 pat
  OUT="$(python3 -I "$GATE" --repo-root "$dir" --feed "$src" 2>&1)"; rc=$?
  [ "$rc" -eq "$want" ] || ok=0
  for pat in "$@"; do
    if [ "${pat:0:1}" = '!' ]; then
      grep -qF -- "${pat:1}" <<<"$OUT" && ok=0
    else
      grep -qF -- "$pat" <<<"$OUT" || ok=0
    fi
  done
  if [ "$ok" -eq 1 ]; then
    echo "  ok   — $name"; pass=$((pass + 1))
  else
    echo "  FAIL — $name (wanted rc=$want, got rc=$rc; patterns: $*)"
    sed 's/^/         /' <<<"$OUT"
    fail=$((fail + 1))
  fi
}

echo "check-curl-advisories.py:"

# --- the issue's own test: an old pin is flagged ------------------------------
expect 1 "8.10.0 is flagged in both images, naming the advisory" \
  "$(repo old 8.10.0 8.10.0)" "$FIXTURE" \
  "docker/Dockerfile.backend: CURL_VERSION=8.10.0 (curl tool, libcurl linked statically): AFFECTED" \
  "docker/Dockerfile.openscap: CURL_VERSION=8.10.0 (libcurl shared library only): AFFECTED" \
  "AFFECTED  CVE-2026-107929" "AFFECTED  CVE-2026-92391"

# Scope: the tool-only advisory hits the backend (it ships the curl tool) and
# is only an n/a note for OpenSCAP (it ships libcurl; its curl is an RPM).
expect 1 "a tool-only advisory hits the backend pin" \
  "$(repo tool 8.10.0 8.23.0)" "$FIXTURE" "AFFECTED  CVE-2026-92390" \
  "docker/Dockerfile.openscap: CURL_VERSION=8.23.0 (libcurl shared library only): clean"
expect 0 "a tool-only advisory is n/a for the libcurl-only OpenSCAP pin" \
  "$(repo toolonly 8.23.0 8.10.0)" "$(feed toolonly "$(jq '[.[]|select(.database_specific.affects=="tool")]' "$FIXTURE")")" \
  "n/a       CVE-2026-92390" "!AFFECTED"

# --- the current pins ---------------------------------------------------------
# The fixture's newest fix is 8.23.0, so any pin at or past it is clean; the
# report must name the pin it actually read from each Dockerfile.
backend_pin="$(sed -n 's/^ARG CURL_VERSION=//p' "$REPO/docker/Dockerfile.backend")"
openscap_pin="$(sed -n 's/^ARG CURL_VERSION=//p' "$REPO/docker/Dockerfile.openscap")"
expect 0 "the repository's current pins are clean against the fixture and reported as read" \
  "$REPO" "$FIXTURE" \
  "docker/Dockerfile.backend: CURL_VERSION=${backend_pin} " \
  "docker/Dockerfile.openscap: CURL_VERSION=${openscap_pin} " "!AFFECTED"

# --- range arithmetic on curl's multi-branch ranges ---------------------------
# 107929: introduced 8.9.0, fixed 8.14.3, introduced 8.15.0, fixed 8.16.2,
# introduced 8.17.0, fixed 8.20.2, introduced 8.21.0, fixed 8.23.0.
for v in 8.9.0 8.14.2 8.15.0 8.20.1 8.21.0 8.22.0; do
  expect 1 "$v sits inside an affected range" \
    "$(repo "in-$v" "$v" "$v")" "$FIXTURE" "AFFECTED  CVE-2026-107929"
done
for v in 8.14.3 8.16.2 8.20.2 8.23.0 8.24.0 9.0.0; do
  expect 0 "$v is a fixed release or past the last fix" \
    "$(repo "out-$v" "$v" "$v")" "$FIXTURE" "!AFFECTED"
done
expect 0 "8.8.0 predates every introduced event" \
  "$(repo pre 8.8.0 8.8.0)" "$(feed only107929 "$(jq '[.[]|select(.id=="CURL-CVE-2026-107929")]' "$FIXTURE")")" "!AFFECTED"

# --- shapes the real feed may grow into ---------------------------------------
expect 1 "a record with only an explicit versions list still flags its version" \
  "$(repo versions 8.23.0 8.23.0)" "$(feed versions '[{"id":"X-1","aliases":["CVE-X-1"],"database_specific":{"affects":"lib"},"affected":[{"versions":["8.23.0"]}]}]')" \
  "AFFECTED  CVE-X-1"
expect 1 "a last_affected event includes that version" \
  "$(repo lastaff 8.23.0 8.24.0)" "$(feed lastaff '[{"id":"X-2","database_specific":{"affects":"both"},"affected":[{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"last_affected":"8.23.0"}]}]}]}]')" \
  "docker/Dockerfile.backend: CURL_VERSION=8.23.0 (curl tool, libcurl linked statically): AFFECTED" \
  "docker/Dockerfile.openscap: CURL_VERSION=8.24.0 (libcurl shared library only): clean"
expect 1 "an unknown affects scope counts as a hit, not as n/a" \
  "$(repo scope 8.23.0 8.23.0)" "$(feed scope '[{"id":"X-3","database_specific":{"affects":"plugin"},"affected":[{"ranges":[{"type":"SEMVER","events":[{"introduced":"8.0.0"}]}]}]}]')" \
  "docker/Dockerfile.openscap: CURL_VERSION=8.23.0 (libcurl shared library only): AFFECTED"

# --- unmeasurable is never clean (exit 2) -------------------------------------
GOOD="$(repo good 8.23.0 8.23.0)"
expect 2 "a Dockerfile without a CURL_VERSION pin is INFRA" "$(repo nopin 8.23.0 "")" "$FIXTURE" "INFRA:" "Dockerfile.openscap"
expect 2 "a pin that is not a plain X.Y.Z version is INFRA" "$(repo rc 8.23.0-rc1 8.23.0)" "$FIXTURE" "INFRA:"
expect 2 "a missing feed is INFRA" "$GOOD" "$TMP/does-not-exist.json" "INFRA:"
expect 2 "a feed that is not JSON is INFRA" "$GOOD" "$(feed html '<html>503</html>')" "INFRA:"
expect 2 "an empty feed is INFRA" "$GOOD" "$(feed empty '[]')" "INFRA:"
expect 2 "an unknown range event type is INFRA" "$GOOD" \
  "$(feed event '[{"id":"X-4","affected":[{"ranges":[{"type":"SEMVER","events":[{"introduced":"8.0.0"},{"patched":"8.30.0"}]}]}]}]')" "INFRA:" "patched"
expect 2 "a record with neither a SEMVER range nor a version list is INFRA" "$GOOD" \
  "$(feed norange '[{"id":"X-5","affected":[{"ranges":[{"type":"GIT","events":[{"introduced":"abc"}]}]}]}]')" "INFRA:"

echo
echo "check-curl-advisories.py: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
