# Design note: commit proxied bytes to the cache only after the scan gate

Status: shipped in 1.12.0 (#4514, item 2 of #4365). This note started as a
proposal comparing two options; it now records what was built and why.

## The gap

`proxy_helpers::serve_scanned_proxy_file` used to fetch a package through
`ProxyService::fetch_artifact_with_cache_path_capped`, which wrote the body to
the proxy cache before `gate_proxy_scan_serve` decided. A refused pull
therefore left the refused bytes warm. The format routes re-ran the gate on
every read, and the generic download route refuses for scanning repositories
(#4442), so the exposure was the readers that serve a warm entry without a
verdict check: the presigned redirect to a cached object
(`try_member_cache_redirect`, `proxy_cache_fresh_redirect`), the streaming
cache hit (`ProxyService::streaming_cached_artifact_by_path` and the
streaming fetch), the cached metadata probe
(`ProxyService::cached_metadata_if_servable`), and a non-scanning Remote
member of a scanning Virtual addressed directly.

## The two options considered

1. **Publish after the gate.** A buffered fetch that does not publish, and an
   explicit publish once the gate serves.
2. **Keep write-through, mark the outcome.** Record the gate outcome in
   `__cache_meta__.json` and make every cache reader refuse a `blocked`
   entry.

Option 1 alone leaves entries written before the change in place; option 2
alone needs a sidecar field that old replicas ignore during a rolling
upgrade. What shipped is a hybrid that needs neither a sidecar field nor a
migration.

## What shipped

### Redirects to a cached package consult the stored verdict

Verdicts are stored per SHA-256 in `proxy_scan_results`, and every sidecar
records the `checksum_sha256` of the bytes it describes. The presigned
redirect helpers that serve only files the format gates (the PyPI
distribution redirect and `proxy_cache_fresh_redirect`) look up the verdict
for the sidecar's digest under the Remote's own scan configuration
(`ProxyService::cache_scan_gate`, decided by the pure
`proxy_scan_service::decide_cache_scan_gate` with the reuse rules of the
buffered gate). A blocking verdict is not redirected to, and under
`fail_closed` neither is a body without a reusable `clean` verdict graded as
a coordinate the bytes carry themselves.

The Virtual member redirect and the streaming and metadata cache hits are
not changed. On a Remote that scans, a file the format gates never reaches
them: the Virtual walk and the direct route send it through
`serve_scanned_proxy_file`, which re-runs the gate on every read, cache hits
included. What they serve there is what the format serves unscanned (a Maven
POM, an index document), and that is served whatever any stored verdict
says.

### Inconclusive fills are not committed

`ProxyService::fetch_artifact_with_cache_path_capped_deferred` is the
buffered capped fetch with the commit of a fresh fill held back in a
`DeferredCommitSlot`. `serve_scanned_proxy_file` uses it:

- **Served** (`clean`, `pending` under `fail_open`, `recorded` under
  `record_only`): `ProxyService::publish_deferred` commits the body exactly
  as the buffered fetch would have, then the bytes are served.
- **Blocked** (`403`): the body is committed, as before, and not evicted.
  Every read of it through the scanning Remote is refused from its stored
  verdict, and the cached copy is what keeps the file in the cache listing,
  the blocked counts, the policy-blocks queue and the rescan endpoint, all of
  which find refused content through its `proxy_cache_artifacts` row.
- **Inconclusive under `fail_closed`** (`423`): the body is dropped. The
  gate could not vouch for it, so nothing unscanned is left in the cache.
- **Refused by the format itself** before the gate (a Cargo `cksum` or a
  Maven `.sha1` mismatch): the body is dropped.
- **Refused by a Package Age Policy hold** (`409`): the body is committed,
  as before, so the hold is recorded and can be released.

The served bytes are the buffer that was scanned, so there is no window
between the bytes graded and the bytes served.

## Trade-offs, as settled

- **Why blocked bodies stay cached.** Dropping or evicting them was the
  original proposal. It would make the refused file invisible to every
  surface that reports blocked proxied content, make it impossible to
  rescan, and cost an upstream fetch on every repeat pull of a refused
  package. The readers of a scanning Remote already refuse it, so caching
  it leaks nothing through them.
- **Re-fetch of inconclusive files.** An inconclusive file is fetched again
  on its next pull, bounded by `PROXY_SCAN_MAX_BYTES` (200 MiB). Concurrent
  pulls of one path on one replica do not fetch it again while the gate
  decides: the held fill is registered like a streaming publish in its tail
  phase, and a request that misses the entry waits up to 35 seconds (the
  inline scan budget plus five) for the decision, at most once in the cache
  read and once in the single-flight re-check; after a drop, the waiters
  fetch and gate the file themselves (their fetches take the single-flight
  lease one at a time, so a slow upstream on a body near the scan cap can
  still run a late pull into the 65-second hydration wait). With the
  cross-replica single-flight locks
  (`PROXY_SINGLEFLIGHT_ADVISORY_LOCKS_ENABLED=true`) a request
  that loses the lock polls for the cache entry instead, so after a drop it
  waits out the hydration wait (65 seconds) before it fetches the file
  itself; served and blocked fills are committed and found as before. Keeping
  dropped bytes for a retry is left to a spool keyed by the full cache key
  (#4533, 1.13.0).
- **Client disconnects.** A request that is cancelled while the gate
  decides drops its held fill, including one the gate would have served;
  the next pull fetches it again.
- **Stale entries.** A stale mutable entry whose refill is inconclusive keeps
  its previous body in the cache; every read revalidates it again.
- **Rolling upgrades.** No sidecar field and no migration. During a rollout
  a replica without the change still commits inconclusive fills, exactly as
  before.

## What is left

A non-scanning Remote member of a scanning Virtual, addressed directly,
serves by its own configuration: it does not scan, so its format route
streams what its cache or its upstream hold, including a package the Virtual
refused (a refused body stays in the member's cache). To enforce the
Virtual's policy for every client, enable scan-on-proxy on the member too, or
do not grant clients read access to the member.

## Catalog writes commit asynchronously (1.13.0, #5635)

A fill that the gate serves is committed in three steps: the content object, then its sidecar, then its `proxy_cache_artifacts` row. That row's upsert also charges the Remote's `repository_usage_ledger` row, which every fill into the Remote shares. Since 1.13.0 that single statement runs with `synchronous_commit = off`, for its own transaction only. Concurrent fills therefore no longer queue on the ledger row one WAL flush at a time. Every other write, including the hold row that `mark_hold_fetching` records before a held fill answers `409`, commits synchronously as before.

**What can be lost.** A crash of the database server, or a failover to a standby (which is the same thing for an unflushed commit), can lose the catalog rows of up to about 3 x `wal_writer_delay` of fills. That is 600 ms with the default 200 ms. Each row is lost together with its ledger charge, so the ledger stays consistent with the catalog. The object and sidecar stay in storage, and storage GC never deletes `proxy-cache/` keys.

**What that costs.** A lost row comes back only if its file is read again: a read re-catalogs it from the sidecar (`backfill_from_sidecar`). Until then the file's bytes are missing from:
- the Remote's quota and cache-cap figures;
- cache-cap eviction;
- the periodic re-scan.

An explicit cache purge removes the file. A sweep that re-catalogs such files without waiting for a read is tracked in #6429. Moving `proxy_bytes` to an insert-only delta ledger, so that fills can commit synchronously without the queue, is tracked in #6430.

**Why nothing is served ungated.** No serve-time check reads the lost row:
- the scan gate looks verdicts up by the sidecar's `checksum_sha256` in `proxy_scan_results`;
- the Package Age Policy hold is read from the sidecar, and from the hold row committed synchronously before the fill;
- authentication and authorization do not involve the catalog.

A lost row can make the file invisible to accounting, but never servable past a check.

**Turning it off.** Set `PROXY_CACHE_CATALOG_SYNC_COMMIT=true` to commit these rows synchronously, as before 1.13.0. The cost is that concurrent cold fills into one Remote queue on its ledger row again. Measured at 64 concurrent fills, the upsert p99 goes back from 13-50 ms to 1.2-1.3 s (`scripts/perf/proxy-fill-catalog-contention.sh`).
