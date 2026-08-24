#!/usr/bin/env bash
# =============================================================================
# check-toolchain-pin.sh — the Rust toolchain may not change without a diff
# =============================================================================
#
# WHY (#3551)
# On 2026-08-24 `main` went red, and with it every open pull request and the
# release chain, on 555 `clippy::result_large_err` errors in 555 functions that
# nobody had touched. The cause was not in the tree: the self-hosted
# `ak-ci-runners` image picked up Rust 1.98.0 and `🦀 Check Rust` compiled with
# it, because that job installs no toolchain at all and every other Rust job
# asked for `dtolnay/rust-toolchain@stable`, which resolves at run time. The
# compiler was an untracked, uncontrolled input. `rust-toolchain.toml` now pins
# it, and this gate keeps the pin honest in the two ways it can quietly rot:
#
#   1. A workflow re-floats. `rust-toolchain.toml` is only load-bearing for a
#      job that lets rustup choose; a `@stable` / `@nightly` / `@master` ref, or
#      a `toolchain:` input naming a different version, overrides or fights it.
#      Every `dtolnay/rust-toolchain@<ref>` in .github/workflows must name the
#      pinned version.
#   2. The pin turns out to be inert. A runner image whose cargo is not a rustup
#      shim ignores `rust-toolchain.toml` entirely; the file would sit in the
#      repo looking like protection while the compiler kept floating. Run with
#      `--active` inside a job that compiles and the gate asserts the rustc that
#      job is actually about to use — so a pin that does not take hold fails
#      loudly and immediately, rather than the next time upstream ships a lint.
#
# No network, no cargo build. Static mode is ~1s.
#
# Usage:
#   ./scripts/ci/check-toolchain-pin.sh            # static checks only
#   ./scripts/ci/check-toolchain-pin.sh --active   # + assert the live rustc
#
# Env:
#   REPO_ROOT   directory to inspect (default: the repository this script is in)
# =============================================================================
set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
TOOLCHAIN_FILE="$REPO_ROOT/rust-toolchain.toml"
WORKFLOW_DIR="$REPO_ROOT/.github/workflows"

CHECK_ACTIVE=0
[ "${1:-}" = "--active" ] && CHECK_ACTIVE=1

fail() { echo "FAIL: $*" >&2; failures=$((failures + 1)); }
failures=0

# --- 1. the pin exists and names a concrete version -------------------------
if [ ! -f "$TOOLCHAIN_FILE" ]; then
  echo "FAIL: $TOOLCHAIN_FILE is missing." >&2
  echo "      Without it the compiler is whatever the runner image ships, and" >&2
  echo "      an upstream release can turn main red with no change of ours (#3551)." >&2
  exit 1
fi

PINNED="$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
  "$TOOLCHAIN_FILE" | head -1)"

if [ -z "$PINNED" ]; then
  fail "rust-toolchain.toml has no [toolchain] channel = \"...\" entry."
elif ! [[ "$PINNED" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then
  fail "rust-toolchain.toml pins channel = \"$PINNED\", which still floats.
      A pin has to name a version (e.g. \"1.98.0\"). 'stable', 'beta' and
      'nightly' resolve at run time, which is the thing being fixed."
else
  echo "  pinned channel: $PINNED  (rust-toolchain.toml)"
fi

# --- 2. no workflow re-floats or contradicts the pin ------------------------
# Anchored to `uses:` so that prose ABOUT the floating ref -- the comments in
# ci.yml and rust-toolchain.toml that explain #3551 -- is not mistaken for the
# thing itself. Also catches any `toolchain:` input handed to the action.
if [ -d "$WORKFLOW_DIR" ]; then
  while IFS= read -r hit; do
    file="${hit%%:*}"
    rest="${hit#*:}"
    line="${rest%%:*}"
    ref="$(sed 's#.*dtolnay/rust-toolchain@##; s#[[:space:]].*##; s#\r##' <<<"$hit")"
    if [ "$ref" != "$PINNED" ]; then
      fail "$(basename "$file"):$line uses dtolnay/rust-toolchain@$ref.
      Expected @$PINNED to match rust-toolchain.toml. A channel ref
      ('stable'/'beta'/'nightly'/'master') resolves at run time, which is
      exactly how #3551 reached main."
    fi
  done < <(grep -rnE "^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*dtolnay/rust-toolchain@" \
    "$WORKFLOW_DIR" || true)

  while IFS= read -r hit; do
    file="${hit%%:*}"
    rest="${hit#*:}"
    line="${rest%%:*}"
    val="$(sed 's/.*toolchain:[[:space:]]*//; s/[[:space:]#].*//; s/["'"'"']//g; s/\r//' <<<"$hit")"
    if [ -n "$val" ] && [ "$val" != "$PINNED" ]; then
      fail "$(basename "$file"):$line sets 'toolchain: $val', which overrides
      rust-toolchain.toml's $PINNED for that job."
    fi
  done < <(grep -rn "^[[:space:]]*toolchain:[[:space:]]*[^[:space:]]" "$WORKFLOW_DIR" || true)
fi

# --- 3. the pin is actually in force ----------------------------------------
if [ "$CHECK_ACTIVE" = "1" ]; then
  if ! command -v rustc >/dev/null 2>&1; then
    fail "--active was requested but no rustc is on PATH."
  else
    active="$(cd "$REPO_ROOT" && rustc --version 2>/dev/null | awk '{print $2}')"
    echo "  active rustc:   $active  ($(cd "$REPO_ROOT" && rustc --version))"
    # "1.98" in the file legitimately matches rustc 1.98.0.
    if [ "$active" != "$PINNED" ] && [ "${active%.*}" != "$PINNED" ]; then
      fail "rust-toolchain.toml pins $PINNED but this job is compiling with
      rustc $active, so the pin is NOT in force here. Most likely this
      runner's cargo/rustc are not rustup shims and ignore the toolchain
      file; that job needs an explicit
      'uses: dtolnay/rust-toolchain@$PINNED' step (#3551)."
    fi
  fi
fi

if [ "$failures" -gt 0 ]; then
  echo "" >&2
  echo "$failures toolchain-pin problem(s). See rust-toolchain.toml for how to" >&2
  echo "take a compiler upgrade deliberately." >&2
  exit 1
fi

if [ "$CHECK_ACTIVE" = "1" ]; then
  echo "OK: Rust toolchain pin is consistent and in force."
else
  echo "OK: Rust toolchain pin is consistent."
fi
