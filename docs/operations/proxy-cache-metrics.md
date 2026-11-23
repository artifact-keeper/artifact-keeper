# Proxy cache write metrics

A proxy (Remote) repository serves the upstream body to the client and writes
it to the proxy cache at the same time. When the cache write fails, the client
still gets its bytes; only the cache entry is lost, and the next request for
the same path goes upstream again. Before 1.12.0 that failure was visible in
the logs only, so a storage backend that refused every cache write looked
healthy from monitoring while every request was a cache miss (#4319).

| Metric | Type | Labels | Moves when |
|---|---|---|---|
| `ak_proxy_cache_publish_failures_total` | counter | `backend`, `class` | a proxy cache write is abandoned because a storage step failed |
| `ak_proxy_cache_lookups_total` | counter | `repository`, `result` | a cache lookup ends (`hit`, `miss`, `miss_*`, `negative_hit`, `error`); see below |
| `ak_proxy_cache_checksum_mismatch_total` | counter | `repository` | a body did not match the checksum its path promises and was not cached |
| `ak_proxy_cache_quota_exceeded_total` | counter | `repository` | an object larger than the repository quota was served without a cache write |
| `ak_proxy_cache_recatalog_total` | counter | `outcome` | the re-catalog sweep listed keys (`scanned`), restored a lost catalog row (`recataloged`), left a sidecar alone (`skipped_negative`, `skipped_young`, `skipped_stale`, `skipped_no_content`, `skipped_size_mismatch`, `skipped_unreadable`, `skipped_deleted`), skipped a Remote whose listing failed (`remote_error`), met a row written meanwhile (`met_row`), took back a row for an entry purged meanwhile (`raced`) or failed a write (`failed`); see `docs/operations/proxy-cache-ha.md` |
| `ak_proxy_cache_recatalog_bytes_total` | counter | | bytes the re-catalog sweep put back on Remotes' usage ledgers |

`backend` is the storage backend the proxy cache runs on (`filesystem`, `s3`,
`gcs`; see `STORAGE_BACKEND`). `class` says which step failed:

| `class` | The step that failed |
|---|---|
| `put_failed` | writing the body: the buffered write, or the streamed write into the private staging key |
| `copy_rejected` | the server-side copy from the staging key onto the cache key (an S3-compatible API that refuses `CopyObject`, for example) |
| `publish_mismatch` | the copy reported success but the cache key does not hold the staged bytes (a different size, or the ETag of an empty object) |
| `commit_failed` | the metadata sidecar that makes the entry visible could not be written |

A body abandoned for a reason that is not the backend's, such as an upstream
connection that broke mid-body, an object over the repository's single-object
ceiling, or a client that disconnected, is not counted here.

## What `ak_proxy_cache_lookups_total` counts

One increment per proxied request that consults the cache, for `GET` and
`HEAD` alike, on both fetch paths:

| Path | Serves | `result` values |
|---|---|---|
| streaming | package files, blobs, Hugging Face files, every proxied `HEAD` | `hit`, `miss`, `negative_hit` |
| buffered | metadata documents (indexes, packuments, `model_info`) | `hit`, `miss_no_metadata`, `miss_expired`, `miss_no_content`, `miss_checksum_mismatch`, `error` |

`miss` means the streaming lookup found no entry it could serve (absent,
evicted, or stale and not revalidated) and the request went upstream. A
handler that probes the cache before fetching counts that request once.
Until #5322 the streaming path did not count at all, so the hit
ratio described metadata documents only.

```promql
# Proxy cache hit ratio per repository, all request methods and both paths.
sum by (repository) (rate(ak_proxy_cache_lookups_total{result="hit"}[5m]))
  / sum by (repository) (rate(ak_proxy_cache_lookups_total[5m]))
```

## Example alert

```promql
# Any proxy cache write failing on a backend for five minutes.
sum by (backend, class) (rate(ak_proxy_cache_publish_failures_total[5m])) > 0
```

Each failure is also logged at `warn` with the cache key and the error, so the
counter tells you that writes are failing and the log tells you which and why.

## Detached fills

A cache fill can outlive the request that started it (#5220, #5509): a
buffered fill runs on its own task from the start, and the rest of a streamed
body whose client stopped reading is drained on its own task so the cache entry
still commits. `PROXY_UPSTREAM_MAX_DETACHED_FILLS` (default 16, `0` keeps every
fill in its request) caps how many run at once, buffered fills and drains
together.

| Metric | Type | Labels | Moves when |
|---|---|---|---|
| `ak_proxy_detached_fills_total` | counter | `kind`, `outcome` | a detached fill takes a permit (`started`), ends within its deadline (`finished`, cached or not), is dropped at its deadline (`abandoned`), or finds no permit free (`refused`) |
| `ak_proxy_detached_fills_in_flight` | gauge | `kind` | detached fills running now |
| `ak_proxy_detached_fills_limit` | gauge | | the `PROXY_UPSTREAM_MAX_DETACHED_FILLS` this process runs with |
| `ak_proxy_fill_followers_inherited_total` | counter | | a request waiting on a buffered fill took that fill's fetch-deadline verdict instead of fetching again (see below) |

`kind` is `buffered` or `stream_drain`. On `refused`:

- a `buffered` fill runs in its request instead, so it is cancelled if the
  client goes away and a retry starts from scratch;
- a `stream_drain` is not started, so the body is dropped unfinished and the
  object is not cached.

A `refused` rate that does not drop to zero means the cap is too low for the
traffic. The first refusal, and then at most one a minute, is also logged at
`warn` with the number held back since the previous line; the rest are at
`debug`. An abandoned drain is logged the same way.

The deadline of a detached fill is `PROXY_UPSTREAM_FETCH_DEADLINE_SECS` plus a
60-second commit allowance. For a buffered fill it counts from the start of the
fill. For a drain it counts from the moment the client went away, not from the
start of the download.

**A request waiting on a fill takes the fill's fetch deadline (1.13.0).** When
a buffered fill's upstream fetch hits `PROXY_UPSTREAM_FETCH_DEADLINE_SECS`,
every request of this process that was already waiting on it answers with the
same verdict: the stale copy under stale-if-error when there is one, else the
`502`. Before, the first of them became the next leader and asked the same
upstream again, so it answered after about twice the deadline. A request that
arrives after the deadline fetches as usual. With
`PROXY_SINGLEFLIGHT_ADVISORY_LOCKS_ENABLED`, a request waiting on another
replica's fill still fetches once itself.

```promql
# The detached-fill cap is turning fills away.
sum by (kind) (rate(ak_proxy_detached_fills_total{outcome="refused"}[5m])) > 0
```
