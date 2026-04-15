# P0 Proxy Safeguards (v1.1.3)

| Field       | Value                      |
|-------------|----------------------------|
| Issue       | #737                       |
| Branch      | `release/1.1.x`            |
| Target      | v1.1.3 patch release       |
| Authors     | @khan                      |
| Status      | Draft                      |

## Problem

`ProxyService::fetch_from_upstream` calls `response.bytes().await` on line 494
of `proxy_service.rs`, which reads the entire upstream response body into a
single `Bytes` allocation. There is no limit on how large that body can be, and
there is no limit on how many fetches can run concurrently. When multiple
clients request large artifacts through proxy/remote repositories at the same
time, each fetch allocates a full copy of the artifact in heap memory. A burst
of parallel requests for multi-gigabyte artifacts (Docker layers, Maven shaded
JARs, large ML model files) can exhaust available memory and kill the process.

The `read_upstream_response` helper (line 461) extracts headers but never
inspects `Content-Length` before consuming the body. The `ProxyService` struct
(line 62) holds no concurrency primitives, so there is nothing preventing
unbounded parallel fetches. The reqwest `Client` built in `ProxyService::new`
(line 74) does not configure connection pool limits, allowing unbounded
connection fan-out to upstream registries.

## Scope

Two targeted safeguards that bound proxy memory consumption without
architectural changes. These ship on the `release/1.1.x` branch as a patch
release. The full streaming proxy rewrite (replacing `response.bytes()` with
chunked `AsyncRead` piped to storage) is deferred to v1.2.0.

This design does NOT change:
- Handler signatures or response types
- Storage service interface
- Database schema
- Cache metadata format
- Public API contract

## Design

### 1. Concurrent fetch semaphore (`PROXY_MAX_CONCURRENT_FETCHES`)

Add a `tokio::sync::Semaphore` to the `ProxyService` struct, sized by a new
config value `PROXY_MAX_CONCURRENT_FETCHES` (default: 20).

```rust
pub struct ProxyService {
    db: PgPool,
    storage: Arc<StorageService>,
    http_client: Client,
    token_cache: RwLock<HashMap<String, (String, Instant, u64)>>,
    /// Limits the number of concurrent upstream fetches to bound peak memory.
    fetch_semaphore: Arc<tokio::sync::Semaphore>,
    /// How long to wait for a semaphore permit before returning 503.
    queue_timeout: Duration,
}
```

**Acquire point:** at the top of `fetch_from_upstream`, before the HTTP request
is sent. This ensures the semaphore covers both the network transfer and the
`response.bytes()` allocation.

**Release point:** when `fetch_from_upstream` returns (either Ok or Err). The
`SemaphorePermit` is held as a local variable within the method scope, so it
drops automatically on return. This means the permit is held while the bytes
are being read from the network, but released before the caller caches or
returns the content. The bytes remain in memory after release, but the
semaphore's purpose is bounding the number of _active network transfers_, not
total memory. The per-artifact size limit (below) handles the per-allocation
bound.

**Timeout behavior:** use `tokio::time::timeout` wrapping
`semaphore.acquire()`. If the timeout expires, return a `503 Service
Unavailable` error with the message "Proxy upstream fetch queue is full" and a
`Retry-After` header. The timeout value comes from `PROXY_QUEUE_TIMEOUT_SECS`
(default: 30). The 503 is surfaced by returning `AppError::ServiceUnavailable`,
which the error handler maps to HTTP 503.

**Peak memory bound:** with this safeguore in place, maximum proxy memory
consumption is approximately:

```
concurrent_fetches * max_artifact_size_bytes
= 20 * 2 GB
= 40 GB (theoretical worst case)
```

In practice, most artifacts are far smaller than 2 GB, so real peak memory will
be a fraction of this. Operators running on memory-constrained hosts should
lower both values.

**Metric:** increment `ak_proxy_fetches_in_flight` gauge when the permit is
acquired, decrement when the permit is released. Use the `metrics::gauge!`
macro consistent with existing gauges in `metrics_service.rs` and
`middleware/metrics.rs`.

```rust
async fn fetch_from_upstream(
    &self,
    url: &str,
    repo_id: Uuid,
) -> Result<(Bytes, Option<String>, Option<String>, String)> {
    let permit = tokio::time::timeout(self.queue_timeout, self.fetch_semaphore.acquire())
        .await
        .map_err(|_| {
            tracing::warn!(
                url = %url,
                timeout_secs = self.queue_timeout.as_secs(),
                "Proxy fetch queue full, rejecting request"
            );
            AppError::ServiceUnavailable(
                "Proxy upstream fetch queue is full. Try again later.".into(),
            )
        })?
        .map_err(|_| AppError::Internal("Fetch semaphore closed".into()))?;

    gauge!("ak_proxy_fetches_in_flight").increment(1.0);
    let _guard = scopeguard::defer(|| {
        gauge!("ak_proxy_fetches_in_flight").decrement(1.0);
        drop(permit);
    });

    // ... existing fetch logic ...
}
```

Note: if `scopeguard` is not already a dependency, implement the guard as a
small `Drop` struct or simply decrement the gauge before each return point. The
`scopeguard` crate is a zero-cost abstraction that avoids missing a decrement
on early error returns, but both approaches are acceptable.

### 2. Per-artifact size limit (`PROXY_MAX_ARTIFACT_SIZE_BYTES`)

Check the upstream response size before reading the full body. Two checks are
needed because not all upstreams send `Content-Length`.

**Check A: Content-Length header present.** After receiving the response headers
but before calling `response.bytes()`, read the `Content-Length` header. If the
value exceeds `PROXY_MAX_ARTIFACT_SIZE_BYTES` (default: 2,147,483,648 = 2 GB),
return `502 Bad Gateway` immediately without reading the body. Log a warning
with the artifact URL and declared size.

```rust
async fn read_upstream_response(
    response: reqwest::Response,
    url: &str,
    max_size: u64,
) -> Result<(Bytes, Option<String>, Option<String>, String)> {
    // ... existing status checks ...

    // Check Content-Length before reading the body
    if let Some(content_length) = response.content_length() {
        if content_length > max_size {
            tracing::warn!(
                url = %url,
                content_length,
                max_size,
                "Upstream artifact exceeds size limit, rejecting"
            );
            return Err(AppError::BadGateway(format!(
                "Upstream artifact size ({} bytes) exceeds the configured limit ({} bytes)",
                content_length, max_size
            )));
        }
    }

    // ... existing header extraction ...

    let content = response.bytes().await.map_err(/* ... */)?;

    // Check B: actual body size (handles missing or lying Content-Length)
    if content.len() as u64 > max_size {
        tracing::warn!(
            url = %url,
            actual_size = content.len(),
            max_size,
            "Upstream artifact body exceeds size limit after download"
        );
        return Err(AppError::BadGateway(format!(
            "Upstream artifact size ({} bytes) exceeds the configured limit ({} bytes)",
            content.len(), max_size
        )));
    }

    // ... rest unchanged ...
}
```

**Why not stream with a counting wrapper?** A streaming byte counter would let
us abort mid-transfer instead of after the full download. However, that
requires changing the response consumption from `response.bytes()` to a chunked
reader, which is exactly the v1.2.0 streaming rewrite. For v1.1.3, the
`Content-Length` pre-check catches the common case (most registries send
`Content-Length`), and the post-read check is a safety net.

**Signature change:** `read_upstream_response` gains a `max_size: u64`
parameter. All call sites in `fetch_from_upstream` pass
`self.max_artifact_size`. This is an internal-only method, so no public API
changes.

### 3. Reqwest connection pool limits

The `Client` built in `ProxyService::new` currently uses reqwest defaults for
connection pooling. Under burst load with many distinct upstream registries,
this can result in unbounded idle connections consuming file descriptors.

Add pool limits to the client builder:

```rust
let http_client = crate::services::http_client::base_client_builder()
    .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
    .user_agent("artifact-keeper-proxy/1.0")
    .pool_max_idle_per_host(50)
    .pool_idle_timeout(Duration::from_secs(90))
    .build()
    .expect("Failed to create HTTP client");
```

These values are hardcoded (not configurable) since they are operational
defaults that rarely need tuning. The limits apply only to the proxy service's
client, not the shared `default_client()` used elsewhere.

The `base_client_builder()` function in `http_client.rs` is not modified.
The pool settings are applied only at the `ProxyService::new` call site
because other HTTP clients in the application (webhook delivery, OIDC
discovery, etc.) have different connection patterns and should not inherit
proxy-specific pool sizing.

## Config additions

Three new fields on the `Config` struct, following the existing `env_parse`
pattern used for `MAX_UPLOAD_SIZE`, `LIFECYCLE_CHECK_INTERVAL_SECS`, etc.

```rust
// In Config struct:

/// Maximum concurrent upstream proxy fetches. Bounds peak memory from
/// parallel proxy downloads. Set to 0 to disable (not recommended).
pub proxy_max_concurrent_fetches: u32,

/// Maximum artifact size in bytes that the proxy will fetch from upstream.
/// Requests for artifacts larger than this are rejected with 502.
pub proxy_max_artifact_size_bytes: u64,

/// Seconds to wait for a proxy fetch permit before returning 503.
pub proxy_queue_timeout_secs: u64,
```

```rust
// In Config::from_env():

proxy_max_concurrent_fetches: env_parse("PROXY_MAX_CONCURRENT_FETCHES", 20),
proxy_max_artifact_size_bytes: env_parse("PROXY_MAX_ARTIFACT_SIZE_BYTES", 2_147_483_648_u64),
proxy_queue_timeout_secs: env_parse("PROXY_QUEUE_TIMEOUT_SECS", 30),
```

```rust
// In redacted_debug! macro:

show proxy_max_concurrent_fetches,
show proxy_max_artifact_size_bytes,
show proxy_queue_timeout_secs,
```

## Error variants

Two new `AppError` variants are needed. If they do not already exist:

- `AppError::ServiceUnavailable(String)` -> HTTP 503 with `Retry-After` header
- `AppError::BadGateway(String)` -> HTTP 502

Check `backend/src/error.rs` for existing variants before adding. If
`ServiceUnavailable` already exists (the rate limiter returns 429, not 503),
add both. The `Retry-After` header for 503 responses should be set to the
value of `PROXY_QUEUE_TIMEOUT_SECS`.

## Files to modify

| File | Changes |
|------|---------|
| `backend/src/config.rs` | Add 3 fields + `from_env` parsing + `redacted_debug` entries |
| `backend/src/services/proxy_service.rs` | Add semaphore + size checks + gauge metric |
| `backend/src/services/http_client.rs` | No changes (pool limits applied at call site) |
| `backend/src/error.rs` | Add `ServiceUnavailable` and `BadGateway` variants if missing |
| `.env.example` | Add `PROXY_MAX_CONCURRENT_FETCHES`, `PROXY_MAX_ARTIFACT_SIZE_BYTES`, `PROXY_QUEUE_TIMEOUT_SECS` with comments |

## Testing strategy

### Unit tests (no database required, `cargo test --lib`)

**Semaphore behavior:**

1. `test_proxy_semaphore_limits_concurrent_fetches` - spawn N+1 tasks where N
   is the semaphore size, verify the (N+1)th task does not proceed until one
   of the first N completes.

2. `test_proxy_semaphore_timeout_returns_503` - create a semaphore of size 1,
   hold the permit, attempt a second acquire with a short timeout, verify it
   returns `AppError::ServiceUnavailable`.

3. `test_proxy_semaphore_releases_on_error` - verify the permit is released
   when `fetch_from_upstream` returns an error (e.g., upstream 500). This
   prevents permit leaks from poisoning the semaphore.

**Size limit checks:**

4. `test_proxy_rejects_oversized_content_length` - construct a mock response
   with `Content-Length: 3000000000` and a limit of 2 GB, verify
   `read_upstream_response` returns `AppError::BadGateway` without reading
   the body.

5. `test_proxy_allows_content_length_within_limit` - construct a mock response
   with `Content-Length` under the limit, verify it proceeds normally.

6. `test_proxy_rejects_oversized_body_no_content_length` - construct a mock
   response with no `Content-Length` whose body exceeds the limit, verify the
   post-read check returns `AppError::BadGateway`.

7. `test_proxy_allows_body_within_limit_no_content_length` - construct a mock
   response with no `Content-Length` whose body is within limits, verify
   success.

**Config parsing:**

8. `test_proxy_config_defaults` - verify `env_parse` returns the expected
   defaults (20, 2147483648, 30) when env vars are unset.

9. `test_proxy_config_custom_values` - set env vars and verify `env_parse`
   picks them up.

### Integration validation

Integration tests are not required for this patch, but operators should verify
the fix under realistic load before rolling out:

- Run the existing `scripts/stress/run-concurrent-uploads.sh` against a proxy
  repository to confirm that the semaphore rejects overflow requests with 503
  instead of OOMing.
- Monitor `ak_proxy_fetches_in_flight` via Prometheus/Grafana to confirm the
  gauge tracks concurrent proxy fetches.
- Verify that `PROXY_MAX_ARTIFACT_SIZE_BYTES=1048576` (1 MB) correctly rejects
  a download of a larger artifact with 502.

## Rollout and migration notes

- All new config values have safe defaults. Existing deployments that do not
  set the new environment variables get the protective behavior automatically.
- No database migrations.
- No handler signature changes. The `fetch_artifact` and `fetch_upstream_direct`
  public methods retain their existing signatures.
- Fully backward compatible. No breaking changes to the public API, CLI, or
  SDK.
- Operators on memory-constrained hosts (< 4 GB) should set
  `PROXY_MAX_CONCURRENT_FETCHES=5` and `PROXY_MAX_ARTIFACT_SIZE_BYTES=536870912`
  (512 MB) to keep peak proxy memory under 2.5 GB.

## What this does NOT fix (v1.2.0 scope)

- **Streaming proxy:** the entire artifact is still loaded into memory. v1.2.0
  will pipe chunks from the upstream response directly to storage, reducing
  per-artifact memory to a fixed buffer size (e.g., 8 MB).
- **Response streaming to client:** handlers currently return `Bytes` to the
  HTTP response. v1.2.0 will return a `Body::from_stream()` so the client
  receives data as it arrives.
- **Per-repository concurrency limits:** the semaphore is global. v1.2.0 may
  add per-upstream-host limits to prevent a single slow registry from
  consuming all permits.
