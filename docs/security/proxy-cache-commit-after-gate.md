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
