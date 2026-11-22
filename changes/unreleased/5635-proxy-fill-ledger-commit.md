---
section: Changed
issues: [#5635]
---
- **Concurrent cold proxy fills into one Remote no longer queue behind each other on its usage-ledger row. The fill's catalog write now commits without waiting for the WAL flush; set `PROXY_CACHE_CATALOG_SYNC_COMMIT=true` to keep synchronous commits** (#5635). Each fill writes one `proxy_cache_artifacts` row, and migration 182's trigger charges the Remote's `repository_usage_ledger` row in the same transaction. Every fill into that Remote charges the same row, and a synchronous commit held its lock through the commit's disk flush, so fills committed one flush at a time. A cold `npm ci` through one Remote logged 1 to 6.8 s upserts.

  That one statement now sets `synchronous_commit = off` for its own transaction only. The row lock is released as soon as the commit is recorded. Measured with `scripts/perf/proxy-fill-catalog-contention.sh`, 2,000 cold fills into one generic Remote at 64 concurrency: the upsert p50 fell from 86-94 ms to 1.4-1.5 ms, p99 from 1.2-1.3 s to 13-50 ms, and the worst from 1.7-2.6 s to 53-108 ms. The burst took 3.8-4.7 s instead of 9.6-10.5 s. The ledger stays exact and in the same transaction as the row; nothing reads it differently.

  The trade-off, which is the default: if the database server crashes, or fails over to a standby, the catalog rows of up to about 3 x `wal_writer_delay` of fills (600 ms with the default 200 ms) can be lost, together with their ledger charges.
  - **Recovery.** A lost row comes back only if its file is read again, through the sidecar backfill. Until then its bytes are missing from quota, from cache-cap eviction and from the periodic re-scan.
  - **Storage.** Storage GC never deletes `proxy-cache/` objects, so the file is kept. An explicit cache purge removes it.
  - **Safety.** Nothing is served ungated. The scan gate reads verdicts by the sidecar's digest, and the Package Age Policy hold is read from the sidecar and from the hold row written synchronously before the fill. Neither is the lost row. Nothing else commits asynchronously, and authentication, quota admission and scanning are unchanged.
  - **Follow-ups.** A recovery sweep that re-catalogs such files without waiting for a read is #6429. Moving `proxy_bytes` to an insert-only delta ledger, so fills can commit synchronously again and this default can be retired, is #6430.

  See `docs/security/proxy-cache-commit-after-gate.md`.
