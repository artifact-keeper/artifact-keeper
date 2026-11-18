---
section: Fixed
issues: [#5940]
---
- **The native client tests no longer write the developer's own client config** (#5940). `test-npm.sh` ran a bare `npm config set`, so a local run left the test registry and its credentials in `~/.npmrc`, and `test-cargo.sh` and `test-maven.sh` overwrote `~/.cargo/config.toml` and `~/.m2/settings.xml`. npm, cargo, Maven, Helm and the conda fallback now keep their config in the script's work dir, and `scripts/ci/check-native-tests-user-config.sh` fails CI on a native test that writes user-level config again.
