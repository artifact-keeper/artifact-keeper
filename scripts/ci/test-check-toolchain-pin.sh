#!/usr/bin/env bash
# =============================================================================
# test-check-toolchain-pin.sh — the toolchain-pin gate must catch what it must
# =============================================================================
#
# check-toolchain-pin.sh only speaks up when something is wrong, and when the
# repository is correctly pinned that is never — so a regression in the gate
# itself (a typo in the grep, an inverted comparison) would be invisible for as
# long as it takes upstream to ship the next lint. That is the failure mode
# #3551 already cost a day to: a control that is silent when healthy is
# indistinguishable from one that does not work.
#
# Builds throwaway repositories, no network, ~1s.
# =============================================================================
set -uo pipefail

GATE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/check-toolchain-pin.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0

# scaffold <dir> <toolchain.toml body or ""> <workflow body or "">
scaffold() {
  local d="$TMP/$1"; shift
  rm -rf "$d"; mkdir -p "$d/.github/workflows" "$d/scripts/ci"
  [ -n "$1" ] && printf '%s\n' "$1" > "$d/rust-toolchain.toml"
  shift
  [ -n "${1:-}" ] && printf '%s\n' "$1" > "$d/.github/workflows/build.yml"
  echo "$d"
}

expect() { # expect <want rc: ok|bad> <name> <dir> [args...]
  local want="$1" name="$2" dir="$3"; shift 3
  local out rc
  out="$(REPO_ROOT="$dir" "$GATE" "$@" 2>&1)"; rc=$?
  if { [ "$want" = ok ] && [ $rc -eq 0 ]; } || { [ "$want" = bad ] && [ $rc -ne 0 ]; }; then
    echo "  ok   — $name"; pass=$((pass + 1))
  else
    echo "  FAIL — $name (wanted $want, rc=$rc)"; echo "$out" | sed 's/^/         /'
    fail=$((fail + 1))
  fi
}

PINNED='[toolchain]
channel = "1.98.0"'
GOOD_WF='jobs:
  b:
    steps:
      - uses: dtolnay/rust-toolchain@1.98.0'

echo "check-toolchain-pin.sh:"

# --- the healthy shape passes ------------------------------------------------
expect ok "a pinned repo with matching workflow refs passes" \
  "$(scaffold good "$PINNED" "$GOOD_WF")"

# --- the exact #3551 regression: nothing pins the compiler -------------------
expect bad "a repo with no rust-toolchain.toml fails" \
  "$(scaffold nofile "" "$GOOD_WF")"

# --- a file that exists but still floats -------------------------------------
for ch in stable beta nightly; do
  expect bad "channel = \"$ch\" is rejected — it still resolves at run time" \
    "$(scaffold "float-$ch" "[toolchain]
channel = \"$ch\"" "$GOOD_WF")"
done

expect bad "a rust-toolchain.toml with no channel at all fails" \
  "$(scaffold nochannel '[toolchain]
components = ["clippy"]' "$GOOD_WF")"

# --- a workflow that re-floats behind the pin's back -------------------------
for ref in stable master nightly; do
  expect bad "dtolnay/rust-toolchain@$ref in a workflow is rejected" \
    "$(scaffold "wf-$ref" "$PINNED" "jobs:
  b:
    steps:
      - uses: dtolnay/rust-toolchain@$ref")"
done

expect bad "a workflow pinned to a DIFFERENT version is rejected" \
  "$(scaffold wf-skew "$PINNED" "jobs:
  b:
    steps:
      - uses: dtolnay/rust-toolchain@1.97.0")"

expect bad "a 'toolchain:' input that overrides the pin is rejected" \
  "$(scaffold wf-input "$PINNED" "$GOOD_WF
        with:
          toolchain: nightly")"

expect ok "a 'toolchain:' input equal to the pin is accepted" \
  "$(scaffold wf-input-ok "$PINNED" "$GOOD_WF
        with:
          toolchain: 1.98.0")"

# --- prose about the floating ref is not the floating ref --------------------
# ci.yml and rust-toolchain.toml both explain #3551 in comments that necessarily
# quote `dtolnay/rust-toolchain@stable`. A gate that cannot tell a comment from
# a `uses:` fails the very change that introduces it.
expect ok "a COMMENT mentioning dtolnay/rust-toolchain@stable does not fail" \
  "$(scaffold wf-comment "$PINNED" "jobs:
  b:
    steps:
      # We used to say dtolnay/rust-toolchain@stable here, which floated.
      - uses: dtolnay/rust-toolchain@1.98.0")"

# --- a repo with no Rust workflows at all is not a failure -------------------
expect ok "a pinned repo with no dtolnay steps passes" \
  "$(scaffold nowf "$PINNED" "jobs:
  b:
    steps:
      - run: echo hi")"

# --- --active: the pin must be provably in force ----------------------------
# Simulated with a stub rustc, so this runs identically on a runner with no
# Rust installed and cannot be fooled by the host's real toolchain.
STUBDIR="$TMP/stub"; mkdir -p "$STUBDIR"
printf '#!/bin/sh\necho "rustc 1.98.0 (88d9e12ae 2026-08-18)"\n' > "$STUBDIR/rustc"
chmod +x "$STUBDIR/rustc"
d="$(scaffold active "$PINNED" "$GOOD_WF")"
out="$(PATH="$STUBDIR:$PATH" REPO_ROOT="$d" "$GATE" --active 2>&1)"; rc=$?
if [ $rc -eq 0 ]; then echo "  ok   — --active passes when the live rustc matches the pin"; pass=$((pass + 1))
else echo "  FAIL — --active passes when the live rustc matches the pin"; echo "$out" | sed 's/^/         /'; fail=$((fail + 1)); fi

# The case that matters: the file says one thing, the compiler is another.
# This is #3551 itself, and it is what proves the pin is not merely decorative
# on a runner image whose cargo ignores rust-toolchain.toml.
printf '#!/bin/sh\necho "rustc 1.99.0 (deadbeef0 2026-10-01)"\n' > "$STUBDIR/rustc"
out="$(PATH="$STUBDIR:$PATH" REPO_ROOT="$d" "$GATE" --active 2>&1)"; rc=$?
if [ $rc -ne 0 ]; then echo "  ok   — --active FAILS when the live rustc drifts from the pin"; pass=$((pass + 1))
else echo "  FAIL — --active FAILS when the live rustc drifts from the pin"; echo "$out" | sed 's/^/         /'; fail=$((fail + 1)); fi

echo ""
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
