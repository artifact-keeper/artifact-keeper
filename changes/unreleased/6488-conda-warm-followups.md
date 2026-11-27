---
section: Fixed
issues: [#6488]
---
- **Close the remaining conda-warm follow-ups** (#6488). A warm fetch that hits the per-item deadline now stops its upstream body with the item instead of handing it to the shared detached-drain pool, so a retry cannot race a still-running download and the fetch-concurrency cap covers every upstream body a warm starts. A checksum mismatch is evicted only after the cache commit is confirmed, and a mismatched entry left by a late commit is removed on the next lookup. Every upstream byte now counts toward `CONDA_WARM_MAX_JOB_BYTES`, whatever the item's final state: blocked and failed answers, over-cap responses and timed-out retries all contribute, while a cached entry's size does not. The running total updates as bytes arrive and accumulates across attempts, including after a restart.

  Regression coverage: unit tests for stopped drains, commit/evict order, mismatched cache lookups and byte accounting; a live proxy-cache test for `cached`; and the extended `conda-warm-from-lockfile` tier in artifact-keeper-test.
