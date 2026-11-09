#!/usr/bin/env bash
# Assert fips-module-manifest.toml matches the versions Cargo.lock resolves
# for the FIPS build (#5581). A module bump must be a reviewed diff to the
# manifest, never a side effect of `cargo update`.
set -euo pipefail

cd "$(dirname "$0")/../.."

manifest_version() {
  sed -nE "s/^$1 = \"([^\"]+)\"/\1/p" fips-module-manifest.toml | head -1
}

lock_version() {
  awk -v name="name = \"$1\"" '$0 == name { getline; sub(/^version = "/, ""); sub(/"$/, ""); print; exit }' Cargo.lock
}

status=0
for pair in "aws_lc_rs:aws-lc-rs" "aws_lc_fips_sys:aws-lc-fips-sys"; do
  key=${pair%%:*}
  crate=${pair##*:}
  want=$(manifest_version "$key")
  have=$(lock_version "$crate")
  if [ -z "$have" ]; then
    # aws-lc-fips-sys only enters the lockfile once the fips feature has been
    # resolved; resolve it without building so the check is meaningful.
    cargo tree -p artifact-keeper-backend --features fips -i "$crate" --depth 0 >/dev/null 2>&1 || true
    have=$(lock_version "$crate")
  fi
  if [ "$want" != "$have" ]; then
    echo "::error::fips-module-manifest.toml says $key = \"$want\" but Cargo.lock resolves $crate $have"
    status=1
  else
    echo "$crate $have matches the manifest"
  fi
done
exit "$status"
