#!/usr/bin/env bash
# =============================================================================
# setup-pinned-toolchain.sh — make rust-toolchain.toml satisfiable on the
#                             self-hosted ak-ci-runners image (#3551)
# =============================================================================
#
# WHY
# The ak-ci-runners image bakes Rust in with rustup at RUSTUP_HOME=/usr/local/
# rustup, and that directory is root-owned and READ-ONLY to the user the job
# runs as. rustup honours `rust-toolchain.toml` there — verified, it tries —
# but the moment the pinned version is not already present it has to materialise
# it, and cannot:
#
#     info: syncing channel updates for 1.98.0-x86_64-unknown-linux-gnu
#     error: could not create temp file /usr/local/rustup/tmp/... 
#     Caused by: Permission denied (os error 13)
#
# so every cargo invocation in the job dies before it compiles anything. A pin
# is only worth having if the runner can actually honour it.
#
# WHAT THIS DOES
# Gives rustup a writable home in RUNNER_TEMP (pod-local, ephemeral, one job
# each) and symlinks the toolchains the image already provides into it, so
# nothing is copied and nothing is re-downloaded in the common case. Then, if
# the image's own toolchain IS the pinned version but is installed under some
# other name (`stable-x86_64-unknown-linux-gnu`), it is linked under the pinned
# name as well — which is what `rustup toolchain link` does, and it is gated on
# the version actually matching, so this can never dress a different compiler up
# as the pinned one.
#
# If the image's toolchain is NOT the pinned version, nothing is linked under
# the pinned name and rustup downloads the pinned toolchain into the now-
# writable home. That is the slow path, it costs about a minute, and it happens
# exactly once per job on the pull request that takes a Rust upgrade — which is
# the pull request that is supposed to be doing that work.
#
# Writes RUSTUP_HOME to $GITHUB_ENV for the rest of the job.
#
# Usage:  ./scripts/ci/setup-pinned-toolchain.sh
# =============================================================================
set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
TOOLCHAIN_FILE="$REPO_ROOT/rust-toolchain.toml"

if [ ! -f "$TOOLCHAIN_FILE" ]; then
  echo "no rust-toolchain.toml at $TOOLCHAIN_FILE — nothing to set up" >&2
  exit 0
fi

PINNED="$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
  "$TOOLCHAIN_FILE" | head -1)"
if [ -z "$PINNED" ]; then
  echo "rust-toolchain.toml has no channel — nothing to set up" >&2
  exit 0
fi

if ! command -v rustup >/dev/null 2>&1; then
  # Not a rustup environment; the toolchain file is inert here and
  # check-toolchain-pin.sh --active is what will say so.
  echo "no rustup on PATH — nothing to set up"
  exit 0
fi

# Locate the rustup home currently in effect.
CUR="${RUSTUP_HOME:-}"
if [ -z "$CUR" ]; then
  for cand in /usr/local/rustup "$HOME/.rustup"; do
    if [ -d "$cand/toolchains" ]; then CUR="$cand"; break; fi
  done
fi
if [ -z "$CUR" ] || [ ! -d "$CUR/toolchains" ]; then
  echo "could not locate a rustup home — leaving rustup to its own devices"
  exit 0
fi

if [ -w "$CUR" ] && [ -w "$CUR/toolchains" ]; then
  echo "rustup home $CUR is writable; rustup can honour the pin unaided"
  exit 0
fi

NEW="${RUNNER_TEMP:-/tmp}/rustup-pinned"
echo "rustup home $CUR is read-only to this job; relocating to $NEW"
mkdir -p "$NEW/toolchains"
cp -a "$CUR/settings.toml" "$NEW/settings.toml" 2>/dev/null || true

for t in "$CUR"/toolchains/*; do
  [ -d "$t" ] || continue
  ln -sfn "$t" "$NEW/toolchains/$(basename "$t")"
done

# The host triple, read OUTSIDE the repository so rust-toolchain.toml does not
# apply and this cannot trip the very install problem it is here to avoid.
HOST="$( (cd / && rustc -vV 2>/dev/null) | sed -n 's/^host: //p' )"
if [ -z "$HOST" ]; then
  echo "could not determine the host triple; rustup will resolve the pin itself"
else
  WANT="$PINNED-$HOST"
  if [ -e "$NEW/toolchains/$WANT" ]; then
    echo "toolchain $WANT is already present"
  else
    for t in "$CUR"/toolchains/*; do
      [ -x "$t/bin/rustc" ] || continue
      v="$("$t/bin/rustc" --version 2>/dev/null | awk '{print $2}')" || continue
      if [ "$v" = "$PINNED" ]; then
        echo "image toolchain $(basename "$t") IS rustc $v; linking it as $WANT"
        ln -sfn "$t" "$NEW/toolchains/$WANT"
        break
      fi
    done
    if [ ! -e "$NEW/toolchains/$WANT" ]; then
      echo "image provides no rustc $PINNED; rustup will download it into $NEW"
    fi
  fi
fi

export RUSTUP_HOME="$NEW"
if [ -n "${GITHUB_ENV:-}" ]; then
  echo "RUSTUP_HOME=$NEW" >> "$GITHUB_ENV"
fi
echo "RUSTUP_HOME=$NEW"
