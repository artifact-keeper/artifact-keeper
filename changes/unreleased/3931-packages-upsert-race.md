---
section: Fixed
issues: [#3931]
---
- **Concurrent publishes of the same package version no longer fail the catalog upsert with a `size_bytes` NOT NULL violation** (#3931). Two racing publishers could hit a statement-snapshot race in the `package_versions` upsert CTE that wrote `COALESCE(NULL, NULL)` into `packages.size_bytes`; the statement now retries on exactly that 23502 race with a fresh snapshot. The publish itself was never affected — the symptom was a missing catalog row plus an error log.
