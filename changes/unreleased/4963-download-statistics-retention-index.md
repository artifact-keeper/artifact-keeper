---
section: Fixed
issues: [#4963, #4541]
---
- **A download statistics retention pass no longer scans the whole table when it runs out of rows to delete** (#4963, #4541). With `DOWNLOAD_STATS_RETENTION_DAYS` set, the last batch of every pass read all of `download_statistics` and `proxy_download_statistics`, because nothing indexed the download time, so the hourly pass cost a full table read even with nothing to trim. Migrations 313 and 315 add an index on `downloaded_at` to each table, built online with `CREATE INDEX CONCURRENTLY` so downloads keep being recorded during the upgrade, and each batch now reads through it. Every recorded download writes one more index entry.
