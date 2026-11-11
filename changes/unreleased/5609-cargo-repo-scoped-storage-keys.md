---
section: Fixed
issues: [#5609]
---
- **Cargo crates are stored under repository-scoped keys on cloud storage, so two registries can hold the same crate version** ([#5609]). On S3, GCS or Azure, a published `.crate` file was written to the flat key `cargo/<name>/<version>/<name>-<version>.crate`, which every repository shares. Publishing a crate version another Cargo repository already held (a staging and a production registry, two teams vendoring the same crate) therefore failed with `409 CONFLICT` "refusing cross-repository overwrite". New crates now go to `cargo/<repository-id>/...`. Crates stored before keep serving from the key their row records and no longer block other registries from publishing that version. Nothing is migrated, and filesystem storage and `STORAGE_KEY_SCHEME=flat` keep the flat keys.
