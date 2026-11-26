---
section: Changed
issues: [#3094]
---
- **`GET /api/v1/admin/stats` no longer counts the catalogue and the download history on every call** (#3094). It ran nine statements, four of them a `COUNT(*)` over `artifacts`, `proxy_cache_artifacts`, `download_statistics` and `proxy_download_statistics`, so the page got slower as the instance grew. Migration 414 adds statement-level triggers that append each write's net row change to a new `row_count_deltas` table, in the writing transaction. The endpoint now reads those counts and everything else in two statements, and reads none of the four large tables. The byte totals already came from the usage ledger (#3134).

  The figures are unchanged: exact counts, not estimates. The triggers only insert, so concurrent writers never wait on a shared counter row. Rows that predate the upgrade are counted once, online, shortly after startup. Until then the endpoint keeps the live `COUNT(*)`. A scheduler job folds the delta rows every minute and re-checks every count against the table once a day, on one replica.

  Measured with `scripts/perf/admin-stats-large-catalog.sh` (1M artifacts, 2M downloads, 300k cached objects and proxy downloads): the endpoint's p50 fell from 134 ms to 4.3 ms, and p95 from 162 ms to 14 ms. The four `COUNT(*)` queries scanned 3.55M rows; the counts read now scans 8. The migration only creates two tables and the triggers and reads no rows.

  **Rolling back to 1.12.x:** the triggers stay and keep appending to `row_count_deltas`, but no 1.12 binary compacts it, so the table grows with every write. While on the older release, fold it periodically with the one statement in `docs/operations/rollback.md`. Do not drop the triggers.
