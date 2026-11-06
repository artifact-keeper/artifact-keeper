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
