#!/usr/bin/env bash
# Assert what the backend's FIPS build (`--no-default-features --features
# fips`, docs/fips.md) links, from the resolved dependency graph alone (no
# compile): the AWS-LC FIPS module is in, and no second crypto provider that
# would bypass it is. Run from the repository root; needs only cargo.
#
#   ring                    a second rustls provider; the FIPS build must not
#                           link it at all (sqlx would use it for Postgres).
#   native-tls, openssl-sys TLS outside the FIPS provider (OpenSSL).
#
# The default build is checked the other way round: it must still link `ring`
# and must NOT link the FIPS module, so the `fips` feature cannot leak into it.
set -euo pipefail

pkg=artifact-keeper-backend
fips=(-p "$pkg" -e normal --no-default-features --features fips)
dflt=(-p "$pkg" -e normal)
forbidden=(ring native-tls openssl-sys)
status=0

linked() { # <package> <cargo tree args...>: exit 0 when the graph links it
  local name="$1"; shift
  cargo tree "$@" --prefix none -f '{p}' 2>/dev/null | grep -q "^${name} v"
}

for crate in "${forbidden[@]}"; do
  if linked "$crate" "${fips[@]}"; then
    echo "::error title=FIPS build links ${crate}::the fips build must not link ${crate}; reverse dependencies:"
    cargo tree "${fips[@]}" -i "$crate" --depth 3 || true
    status=1
  else
    echo "ok: fips build does not link ${crate}"
  fi
done

if linked aws-lc-fips-sys "${fips[@]}"; then
  version="$(cargo tree "${fips[@]}" --prefix none -f '{p}' | sed -n 's/^aws-lc-fips-sys v\([^ ]*\).*/\1/p' | head -1)"
  echo "ok: fips build links aws-lc-fips-sys ${version} (see docs/fips-crypto-inventory.md for the AWS-LC FIPS module version and certificate status)"
else
  echo "::error title=FIPS build does not link aws-lc-fips-sys::the fips feature no longer selects the AWS-LC FIPS module"
  status=1
fi

if linked aws-lc-fips-sys "${dflt[@]}"; then
  echo "::error title=Default build links aws-lc-fips-sys::the fips feature leaked into the default build"
  status=1
else
  echo "ok: default build does not link aws-lc-fips-sys"
fi
if ! linked ring "${dflt[@]}"; then
  echo "::error title=Default build lost ring::the default build must keep the ring rustls provider"
  status=1
else
  echo "ok: default build links ring"
fi

exit "$status"
