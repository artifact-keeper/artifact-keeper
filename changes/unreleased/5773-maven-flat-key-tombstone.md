---
section: Fixed
issues: [#5773]
---
- **A deleted Maven artifact answers 404 on the hosted repository's native route instead of staying downloadable until the trash purge** (#5773). The legacy flat-key fallback served `maven/{path}` whenever the storage backend was filesystem, so a soft-deleted artifact's bytes remained reachable and `mvn` could still resolve a withdrawn version. The fallback now refuses a path the catalog has a soft-deleted row for, the same tombstone applies to the stored `.sha1`/`.md5`/`.sha256`/`.sha512` sidecars, and true pre-catalog objects without any row stay readable.
