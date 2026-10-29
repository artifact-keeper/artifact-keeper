# Backend fuzz targets

Coverage-guided targets for parsers that read untrusted upload bytes. They
need a nightly toolchain and `cargo-fuzz`; CI does not build them (the
bounded mutation tests next to each parser run in every CI build instead).

| Target | Code under test |
|---|---|
| `iso_locate` | `src/services/iso_rootfs/locator.rs`, the ISO9660 rootfs locator (#1966) |

## Running a campaign

```sh
rustup toolchain install nightly --profile minimal
cargo +nightly install cargo-fuzz --locked

cd backend
# Seed corpus: the test writer's images plus real xorriso media.
AK_ISO_FUZZ_CORPUS=$PWD/fuzz/corpus/iso_locate \
  cargo test --lib services::iso_rootfs::tests::write_fuzz_seed_corpus -- --ignored

cd fuzz
cargo +nightly fuzz run iso_locate corpus/iso_locate -- \
  -max_len=524288 -rss_limit_mb=2048 -timeout=5 -max_total_time=1800
```

`-max_len` must cover the volume descriptor at byte 32768 and a few
directory sectors; the default (4096) never reaches it. A crash is written to
`artifacts/iso_locate/`; reproduce it with
`cargo +nightly fuzz run iso_locate artifacts/iso_locate/<file>`, add the
input as a unit test in `src/services/iso_rootfs/tests.rs`, then fix.
