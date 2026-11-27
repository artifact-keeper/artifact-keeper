---
section: Added
issues: [#6519]
---
- **A migration can keep the source's creation and last-download dates** (#6519). Set `import_source_timestamps: true` in the job's `config`. A migrated artifact then gets the source creation date as `created_at` (for Nexus the earlier of `blobCreated` and `lastModified`, for Artifactory the AQL `created`) and, for Nexus, one download-history row at the asset's `lastDownloaded`, so lifecycle policies, stale-artifact analytics and the last-download stat see the source's history. A delta run refreshes both for artifacts it skips. Off by default, since old artifacts become eligible for `max_age` and `no_downloads_days` policies at once. `updated_at` and OCI images are unchanged. See `docs/migration-source-timestamps.md`.
