---
section: Fixed
issues: [#5072]
---
- **Precomputed RPM repodata revisions no longer stay behind when a repository's storage location changes** (#5072). The builder recorded one location per root, the current revision's, and deleted superseded revisions through it, so revisions written to the previous `storage_backend` / `storage_path` were never deleted there. Each revision's claim now records where it is written (`rpm_repodata_revisions`, migration 311), and builds, emptied roots and deleted repositories delete every revision through its own location. That also covers a build that died before its swap. A delete that fails during a build stays recorded and is retried by the next build. Served repodata is unaffected. Objects stranded in an older location before this release are not known to the builder and are not removed.
