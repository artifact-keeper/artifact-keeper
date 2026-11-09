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

# Exactly one rustls provider is wired in: aws-lc-rs must be present, and
# rustls must not have its `ring` feature enabled by anyone.
if ! cargo tree --workspace -i aws-lc-rs --depth 0 "$@" >/dev/null 2>&1; then
  echo "::error::aws-lc-rs is not in the dependency graph"
  status=1
fi
if cargo tree --workspace -e features -i rustls "$@" 2>/dev/null | grep -q 'rustls feature "ring"'; then
  echo "::error::something enables the rustls \"ring\" feature"
  status=1
fi

if [ "$status" -eq 0 ]; then
  echo "crypto provider check: aws-lc-rs only (no ring, no OpenSSL, no native-tls)"
fi
exit "$status"
