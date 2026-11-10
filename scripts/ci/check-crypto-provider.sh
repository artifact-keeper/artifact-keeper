#!/usr/bin/env bash
# Assert the backend links exactly one cryptographic provider (#5578).
#
# The FIPS 140-3 claim (#5577) rests on every security function running
# inside the aws-lc-rs module, so nothing in the dependency graph may bring
# ring, OpenSSL or native-tls back in. A new crate with a `native-tls` or
# `ring` default feature is the usual way that happens, so this runs on every
# PR rather than only on release builds.
#
# Usage: scripts/ci/check-crypto-provider.sh [extra cargo args, e.g. --features fips]
set -euo pipefail

cd "$(dirname "$0")/../.."

forbidden=(ring openssl-sys openssl native-tls tokio-native-tls hyper-tls)
status=0
for crate in "${forbidden[@]}"; do
  # `cargo tree -i` prints the inverse dependency chain when the crate is in
  # the resolved graph, "nothing to print" when it is only a stale lockfile
  # entry, and an error when it is absent altogether. Only the first is a
  # failure.
  if out=$(cargo tree --workspace -i "$crate" --depth 1 "$@" 2>/dev/null) && [ -n "$out" ]; then
    echo "::error::$crate is in the dependency graph:"
    echo "$out"
    status=1
  fi
done

# Exactly one rustls provider is wired in: aws-lc-rs must be present (a
# non-empty inverse tree, not just an exit status: a lockfile-only crate
# prints "nothing to print" and exits 0), and rustls must not have its
# `ring` feature enabled by anyone.
if ! cargo tree --workspace -i aws-lc-rs --depth 0 "$@" 2>/dev/null | grep -q '^aws-lc-rs'; then
  echo "::error::aws-lc-rs is not in the dependency graph"
  status=1
fi

# Entropy sources outside the facade (#5579). clippy cannot see through the
# `rand08` crate alias and does not flag unit-struct expressions, so this is
# a textual gate: any OS/thread RNG use outside backend/src/crypto/ must be
# on a line, or directly under a line, annotated NON-SECURITY.
rng_hits=$(grep -rnE 'OsRng|SysRng|rand::rng\(\)|rand::random\b|thread_rng\(\)' backend/src --include='*.rs' \
  | grep -vE '^backend/src/crypto/' \
  | grep -vE 'NON-SECURITY|^\S+:\s*//' || true)
if [ -n "$rng_hits" ]; then
  # Allow a hit whose previous line carries the NON-SECURITY allow.
  bad=""
  while IFS= read -r hit; do
    f=${hit%%:*}; rest=${hit#*:}; n=${rest%%:*}
    # The allow sits on the statement, which rustfmt may wrap: look two
    # lines back.
    prev=$(sed -n "$((n-2)),$((n-1))p" "$f")
    case "$prev" in *NON-SECURITY*) ;; *) bad="$bad
$hit" ;; esac
  done <<< "$rng_hits"
  if [ -n "$bad" ]; then
    echo "::error::security randomness outside crate::crypto::rng (annotate backoff jitter with NON-SECURITY):$bad"
    status=1
  fi
fi
if cargo tree --workspace -e features -i rustls "$@" 2>/dev/null | grep -q 'rustls feature "ring"'; then
  echo "::error::something enables the rustls \"ring\" feature"
  status=1
fi

if [ "$status" -eq 0 ]; then
  echo "crypto provider check: aws-lc-rs only (no ring, no OpenSSL, no native-tls)"
fi
exit "$status"
