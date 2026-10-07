---
section: Fixed
issues: [#4426]
---
- **The scan reuse index now covers only scans this instance ran itself** (#4426). The partial index behind hash-based scan reuse gains `origin = 'local_scan'` in its predicate, matching the filter the reuse query already applies, so scan evidence imported from a bundle is never indexed as a reuse candidate. The index is rebuilt online by migrations 273 to 275 (`CREATE INDEX CONCURRENTLY` under a new name, `idx_scan_results_dedup_local`, then `DROP INDEX CONCURRENTLY` of the old one), so the upgrade does not block scan writes. The build reads `scan_results` twice and needs disk space for the new index next to the old one until the drop.
