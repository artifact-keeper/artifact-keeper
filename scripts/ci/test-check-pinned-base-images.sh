#!/usr/bin/env bash
# Self-test for check-pinned-base-images.sh (#3755).
#
# The interesting property of that check is not that it can spot a CVE -- it is
# how it grades the three answers it can get, and grading is exactly the kind of
# thing that looks fine in a green run. A version that treated "I could not
# reach the registry" as a pass, or that failed the build every time the sibling
# rebuilt for errata, would be indistinguishable from a correct one for weeks.
# So each grade is asserted directly here:
#
#   * newest tag + clean scan                -> pass, silently;
#   * a CRITICAL/HIGH fixed finding          -> fail, WITH the remedy, because a
#                                               finding whose fix nobody can find
#                                               ends up in .trivyignore instead;
#   * a newer tag but the pin still clean    -> warn and pass, because the
#                                               sibling rebuilds weekly and
#                                               chasing every rebuild buys a
#                                               VERSION bump a week and no
#                                               security (#3307);
#   * any probe that cannot answer           -> INFRA (exit 2), never a pass;
#   * an image with no upstream mapping      -> INFRA, not silence;
#   * no digest pin found at all             -> INFRA, because the pins vanishing
#                                               is itself the regression.
#
# It also pins the two things the check is only useful if it gets right: the
# scan must be handed the repository's own .trivyignore, and the real probe must
# still carry the publish gate's three flags.
#
# All probes are stubbed through the PINNED_BASE_*_CMD indirection; throwaway
# fixtures in a temp dir, no network, ~1s.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD="$HERE/check-pinned-base-images.sh"

TRIVY_IMAGE='ghcr.io/artifact-keeper/trivy'
R1='sha256:37317c08e42f6202ea5087f800739d0943cf8f17749a0a14b86951c5986b0c39'
R2='sha256:279d5967de9267732bc7e55b82942772c62df639978edb43882544a13150651c'

pass=0
fail=0

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# make_repo <dir> <pinned-digest>   ("" = a floating tag, i.e. no digest pin)
make_repo() {
  local dir="$1" digest="$2"
  mkdir -p "$dir/docker"
  echo '# residual CVEs in the bundled scanner CLIs' > "$dir/.trivyignore"
  {
    echo 'FROM golang:1.26 AS build'
    if [ -n "$digest" ]; then
      echo "FROM ${TRIVY_IMAGE}@${digest} AS trivy"
    else
      echo "FROM ${TRIVY_IMAGE}:0.74.0-r1 AS trivy"
    fi
    echo 'FROM alpine:3.24 AS runtime'
  } > "$dir/docker/Dockerfile.scanner-adapter"
}

# make_stub <path> <exit-code> <stdout...>
make_stub() {
  local path="$1" rc="$2"
  shift 2
  {
    echo '#!/usr/bin/env bash'
    # shellcheck disable=SC2016,SC2028  # emitting stub source, not running it
    echo 'printf "%s\n" "$@" >> "${STUB_ARGS_LOG:-/dev/null}"'
    for line in "$@"; do
      printf 'printf "%%s\\n" %q\n' "$line"
    done
    echo "exit $rc"
  } > "$path"
  chmod +x "$path"
}

check() { # <label> <expected-status> <repo-dir> [expected-substring...]
  local label="$1" expected="$2" dir="$3"
  shift 3
  local status=0 out
  out="$("$GUARD" "$dir" 2>&1)" || status=$?
  if [ "$status" -ne "$expected" ]; then
    echo "  FAIL $label: expected exit $expected, got $status"
    # shellcheck disable=SC2001  # sed is the clearest way to indent a block
    echo "$out" | sed 's/^/       | /'
    fail=$((fail + 1))
    return
  fi
  local needle
  for needle in "$@"; do
    if ! grep -qF -- "$needle" <<<"$out"; then
      echo "  FAIL $label: exit $status was right but output did not mention '$needle'"
      # shellcheck disable=SC2001  # sed is the clearest way to indent a block
      echo "$out" | sed 's/^/       | /'
      fail=$((fail + 1))
      return
    fi
  done
  echo "  ok   $label (exit $status)"
  pass=$((pass + 1))
}

echo "check-pinned-base-images.sh self-test"
echo

# Tag probes: the sibling's git tags, newest last is what `sort -V` must pick.
make_stub "$tmp/tags-r2" 0 'v0.73.0-r1' 'v0.74.0-r2' 'v0.73.0-r2' 'v0.74.0-r1'
make_stub "$tmp/tags-r1" 0 'v0.73.0-r1' 'v0.73.0-r2' 'v0.74.0-r1'
make_stub "$tmp/tags-fail" 1 ''

# Digest probes: what the newest registry tag resolves to.
make_stub "$tmp/digest-r2" 0 "$R2"
make_stub "$tmp/digest-r1" 0 "$R1"
make_stub "$tmp/digest-fail" 1 ''

# Scan probes: TSV findings, or nothing for a clean scan. Exit non-zero only
# means "could not scan".
make_stub "$tmp/scan-clean" 0
make_stub "$tmp/scan-fail" 1 ''
{
  echo '#!/usr/bin/env bash'
  # shellcheck disable=SC2016,SC2028  # emitting stub source, not running it
  echo 'printf "%s\n" "$@" >> "${STUB_ARGS_LOG:-/dev/null}"'
  printf 'printf "HIGH\\tCVE-2026-84304\\tgoogle.golang.org/grpc\\t1.76.0\\t1.76.2\\n"\n'
  echo 'exit 0'
} > "$tmp/scan-cve"
chmod +x "$tmp/scan-cve"

export PINNED_BASE_TAGS_CMD PINNED_BASE_DIGEST_CMD PINNED_BASE_SCAN_CMD

# --- 1. the pin is the newest tag and it scans clean -> pass ----------------
make_repo "$tmp/fresh" "$R2"
PINNED_BASE_TAGS_CMD="$tmp/tags-r2"
PINNED_BASE_DIGEST_CMD="$tmp/digest-r2"
PINNED_BASE_SCAN_CMD="$tmp/scan-clean"
check 'newest pin, clean scan -> pass' 0 "$tmp/fresh" \
  'OK' 'newest published tag, and it scans clean' 'v0.74.0-r2'

# --- 2. the pin is vulnerable -> fail, with the remedy ----------------------
# The remedy is load-bearing: a finding reported without "open the override PR
# upstream, then repoint and bump VERSION" is a finding whose cheapest apparent
# fix is another .trivyignore line.
make_repo "$tmp/vuln" "$R1"
PINNED_BASE_TAGS_CMD="$tmp/tags-r1"
PINNED_BASE_DIGEST_CMD="$tmp/digest-r1"
PINNED_BASE_SCAN_CMD="$tmp/scan-cve"
check 'vulnerable pin -> fail with remedy' 1 "$tmp/vuln" \
  'VULNERABLE' \
  'CVE-2026-84304' \
  'open the dependency override PR in artifact-keeper/trivy' \
  'repoint the digest in docker/Dockerfile.scanner-adapter and bump' \
  'docker/scanner-adapter/VERSION' \
  'FAIL'

# --- 3. a newer tag exists but the pin still scans clean -> warn, pass ------
make_repo "$tmp/stale" "$R1"
PINNED_BASE_TAGS_CMD="$tmp/tags-r2"
PINNED_BASE_DIGEST_CMD="$tmp/digest-r2"
PINNED_BASE_SCAN_CMD="$tmp/scan-clean"
check 'stale but clean pin -> warn, still pass' 0 "$tmp/stale" \
  'WARNING' 'Moving the pin is optional' '1 stale-but-clean'

# --- 4. a probe cannot answer -> INFRA, never a pass ------------------------
# Each probe independently, because "unmeasured" must not be reachable from any
# one of them by accident.
make_repo "$tmp/infra" "$R2"
PINNED_BASE_TAGS_CMD="$tmp/tags-fail"
PINNED_BASE_DIGEST_CMD="$tmp/digest-r2"
PINNED_BASE_SCAN_CMD="$tmp/scan-clean"
check 'tag probe unavailable -> INFRA' 2 "$tmp/infra" \
  'INFRA' 'freshness unknown'

PINNED_BASE_TAGS_CMD="$tmp/tags-r2"
PINNED_BASE_DIGEST_CMD="$tmp/digest-fail"
check 'digest probe unavailable -> INFRA' 2 "$tmp/infra" \
  'INFRA' 'could not resolve'

PINNED_BASE_DIGEST_CMD="$tmp/digest-r2"
PINNED_BASE_SCAN_CMD="$tmp/scan-fail"
check 'scan probe unavailable -> INFRA' 2 "$tmp/infra" \
  'INFRA' 'unmeasured, which is not the same as clean'

# A vulnerable pin alongside an unmeasurable one must still exit 1: a finding we
# did measure is not softened into a retry by a later one we could not
# (release-preflight.sh ranks its exits the same way).
make_repo "$tmp/mixed" "$R1"
printf 'FROM ghcr.io/artifact-keeper/grype@%s AS grype\n' "$R2" \
  >> "$tmp/mixed/docker/Dockerfile.backend"
PINNED_BASE_TAGS_CMD="$tmp/tags-r1"
PINNED_BASE_DIGEST_CMD="$tmp/digest-fail"
PINNED_BASE_SCAN_CMD="$tmp/scan-cve"
check 'exit 1 outranks exit 2' 1 "$tmp/mixed" 'FAIL' 'INFRA'

# --- 5. an image this script cannot map -> INFRA, not silence ---------------
make_repo "$tmp/unmapped" "$R2"
printf 'FROM quay.io/someone/base@%s AS other\n' "$R1" \
  > "$tmp/unmapped/docker/Dockerfile.other"
PINNED_BASE_TAGS_CMD="$tmp/tags-r2"
PINNED_BASE_DIGEST_CMD="$tmp/digest-r2"
PINNED_BASE_SCAN_CMD="$tmp/scan-clean"
check 'unmapped image -> INFRA' 2 "$tmp/unmapped" \
  'INFRA' 'no upstream mapping for quay.io/someone/base' 'source_repo_for_image'

# --- 6. no digest pin at all -> INFRA --------------------------------------
make_repo "$tmp/unpinned" ''
check 'no digest pin found -> INFRA' 2 "$tmp/unpinned" \
  'INFRA' 'found no digest-pinned FROM'

# --- 7. the scan is handed THIS repository's .trivyignore ------------------
# The gate it is pre-empting passes `trivyignores: '.trivyignore'`; scanning
# without it would report suppressed CVEs the publish gate does not block on.
make_repo "$tmp/ignorefile" "$R2"
PINNED_BASE_SCAN_CMD="$tmp/scan-clean"
STUB_ARGS_LOG="$tmp/args.log" "$GUARD" "$tmp/ignorefile" >/dev/null 2>&1 || true
if grep -qxF "$tmp/ignorefile/.trivyignore" "$tmp/args.log" 2>/dev/null &&
   grep -qxF "${TRIVY_IMAGE}@${R2}" "$tmp/args.log" 2>/dev/null; then
  echo "  ok   scan probe receives the pinned ref and the repo .trivyignore"
  pass=$((pass + 1))
else
  echo "  FAIL scan probe did not receive the pinned ref and the repo .trivyignore"
  sed 's/^/       | /' "$tmp/args.log" 2>/dev/null || true
  fail=$((fail + 1))
fi

# --- 8. the REAL probe still carries the publish gate's configuration ------
# The stubs above can never catch drift here, and this is the one thing the
# check must not get wrong: scanning looser than the gate cries wolf, scanning
# tighter misses the finding it exists to catch (docker-publish.yml
# `Trivy gate - Scanner Adapter`, guarded by check-trivy-gate-severity.sh).
missing=()
for flag in '--severity CRITICAL,HIGH' '--ignore-unfixed' '--ignorefile'; do
  grep -qF -- "$flag" "$GUARD" || missing+=("$flag")
done
if [ ${#missing[@]} -eq 0 ]; then
  echo "  ok   real scan probe applies the publish gate's flags"
  pass=$((pass + 1))
else
  echo "  FAIL real scan probe no longer applies: ${missing[*]}"
  fail=$((fail + 1))
fi

echo
echo "passed: $pass  failed: $fail"
[ "$fail" -eq 0 ]
