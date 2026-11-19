#!/usr/bin/env bash
# =============================================================================
# apt-install-bounded.sh — install apt packages on a hosted runner without
#                          letting a slow or broken mirror eat the job
# =============================================================================
#
# WHY (#6272, #6242)
#   `sudo apt-get update && sudo apt-get install -y protobuf-compiler` has no
#   deadline of its own. On a runner whose apt mirror crawls (the image's
#   us-east-2.ec2.archive.ubuntu.com at 50-100 kB/s) it sat until the job's
#   45-minute ceiling (Workflow Contract Tests, run 44478388591); on another
#   run it failed fast on a network error with no second try.
#
# HOW
#   Only the DOWNLOAD is time-boxed: each attempt runs `apt-get update` and
#   `apt-get install --download-only` under one `timeout` (APT_ATTEMPT_TIMEOUT,
#   default 3m) with apt's own per-file retries. A failed or timed-out first
#   attempt rewrites /etc/apt/apt-mirrors.txt (the `mirror+file:` list the
#   hosted ubuntu images read) to azure.archive.ubuntu.com, then
#   archive.ubuntu.com, and tries again, up to APT_ATTEMPTS (default 3)
#   times: worst case 3 x 3 minutes of download. The real install then runs from the
#   local archive with no timeout: one killed during unpack would leave dpkg
#   half-configured, and every later apt call fails on "dpkg was interrupted".
#   The calling step must still carry its own `timeout-minutes` (pinned by
#   scripts/ci/test-ci-change-classification.sh) as the outer bound.
#
#   Packages come from the image's Ubuntu release, so the version stays the
#   one the build already uses (noble: protobuf-compiler 3.21.12, which
#   tonic-prost-build / prost-build accept). Recommends are installed as
#   before: protobuf-compiler's Recommends libprotobuf-dev carries the
#   well-known .proto files (timestamp.proto) backend/build.rs imports.
#
# Usage: bash scripts/ci/apt-install-bounded.sh <package>...
#
# Test hooks (scripts/ci/test-apt-install-bounded.sh): APT_GET, SUDO,
# APT_MIRRORS_FILE, APT_ATTEMPTS.
# =============================================================================
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <package>..." >&2
  exit 2
fi

APT_GET="${APT_GET:-apt-get}"
SUDO="${SUDO-sudo}"
APT_ATTEMPT_TIMEOUT="${APT_ATTEMPT_TIMEOUT:-3m}"
APT_MIRRORS_FILE="${APT_MIRRORS_FILE:-/etc/apt/apt-mirrors.txt}"
APT_ATTEMPTS="${APT_ATTEMPTS:-3}"
FALLBACK_MIRRORS=$'http://azure.archive.ubuntu.com/ubuntu/\tpriority:1\nhttp://archive.ubuntu.com/ubuntu/\tpriority:2'

echo "apt-install-bounded: $* (download capped at ${APT_ATTEMPT_TIMEOUT} per attempt, ${APT_ATTEMPTS} attempts)"
echo "apt mirrors: $(tr '\n' ' ' < "$APT_MIRRORS_FILE" 2>/dev/null || echo '(none)')"

fetch() {
  # One deadline over update + download, as in ci.yml's Windows cross-check;
  # -k: SIGKILL 30s later if apt ignores the TERM.
  # shellcheck disable=SC2016,SC2086  # expanded by the inner bash; $SUDO is empty or one word
  $SUDO timeout -k 30s "$APT_ATTEMPT_TIMEOUT" bash -c '
    apt=$1; shift
    "$apt" update -o Acquire::Retries=3 \
      && "$apt" install --download-only -y -o Acquire::Retries=3 "$@"
  ' _ "$APT_GET" "$@"
}

attempt=1
until fetch "$@"; do
  if [ "$attempt" -ge "$APT_ATTEMPTS" ]; then
    echo "::error title=apt download failed::$* did not download in ${APT_ATTEMPTS} attempts of ${APT_ATTEMPT_TIMEOUT}, on the image's mirror or on azure/archive.ubuntu.com."
    exit 1
  fi
  echo "::warning title=Slow apt mirror::downloading $* failed or did not finish in ${APT_ATTEMPT_TIMEOUT} (attempt ${attempt}/${APT_ATTEMPTS}); retrying on azure.archive.ubuntu.com / archive.ubuntu.com."
  # shellcheck disable=SC2086
  printf '%s\n' "$FALLBACK_MIRRORS" | $SUDO tee "$APT_MIRRORS_FILE" >/dev/null || true
  attempt=$((attempt + 1))
  sleep "${APT_RETRY_SLEEP:-5}"
done

# shellcheck disable=SC2086
$SUDO "$APT_GET" install -y "$@"
