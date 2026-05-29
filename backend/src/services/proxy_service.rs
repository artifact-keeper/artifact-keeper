//! Proxy service for remote/proxy repositories.
//!
//! Handles fetching artifacts from upstream repositories with caching support.
//! Implements cache TTL, ETag validation, and transparent proxying.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::stream::{BoxStream, StreamExt};
use reqwest::header::{
    ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, ETAG, IF_NONE_MATCH, WWW_AUTHENTICATE,
};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::repository::{Repository, RepositoryFormat, RepositoryType};
use crate::services::storage_service::StorageService;

/// Default cache TTL in seconds (24 hours)
pub const DEFAULT_CACHE_TTL_SECS: i64 = 86400;

/// HTTP client timeout in seconds
const HTTP_TIMEOUT_SECS: u64 = 60;

/// Response from an upstream registry fetch.
struct UpstreamResponse {
    content: Bytes,
    content_type: Option<String>,
    etag: Option<String>,
    effective_url: String,
    link: Option<String>,
}

/// Streaming response from an upstream registry fetch. Used by the
/// streaming proxy path (#895) to avoid buffering the full body before
/// returning to the client.
struct UpstreamStream {
    /// Chunks from the upstream HTTP body, in order.
    body: BoxStream<'static, Result<Bytes>>,
    content_type: Option<String>,
    etag: Option<String>,
    /// `Content-Length` from upstream, if it sent one. Lets the proxy
    /// decide whether to bypass the cache entirely for huge objects
    /// (a future enhancement; currently informational only).
    #[allow(dead_code)]
    content_length: Option<u64>,
}

/// Output of [`ProxyService::fetch_artifact_streaming`]. Carries the
/// streamed body bytes and the metadata the caller needs to build the
/// outbound HTTP response (Content-Type, optional Content-Length).
pub struct StreamingFetchResult {
    pub body: BoxStream<'static, Result<Bytes>>,
    pub content_type: Option<String>,
    /// Total body length when known up-front (either from a freshly-
    /// cached metadata sidecar or from the upstream Content-Length
    /// header). `None` when the body is being streamed from upstream
    /// without a length advertised, in which case the outbound response
    /// uses chunked transfer encoding.
    pub content_length: Option<u64>,
}

/// Metadata fields known up-front when teeing an upstream stream into
/// the proxy cache. The size + sha-256 fields of [`CacheMetadata`] are
/// observed during the stream itself and filled in by the writer task
/// once the body has been fully written to storage.
struct CacheMetadataTemplate {
    content_type: Option<String>,
    etag: Option<String>,
    ttl_secs: i64,
}

/// Bound on the in-flight chunk queue between the upstream-reader task
/// and the storage-writer task. At 64 chunks × ~64 KiB chunks this is
/// roughly a 4 MiB ceiling on the buffer between client and cache.
/// Slow storage applies moderate backpressure to the client read loop
/// rather than queueing unbounded memory; fast storage drains promptly
/// so the client sees no extra latency.
///
/// Backend-specific notes (#895 perf review):
///
/// * **S3 backend.** `object_store::WriteMultipart` allocates an
///   additional ~10 MiB part buffer on top of this 4 MiB tee cap, so
///   the actual per-request peak on the S3 path is ~14 MiB rather
///   than 4 MiB. Still a >35× reduction vs. the 500 MiB+ buffered
///   path.
/// * **Upstream backpressure.** When storage falls behind, this
///   channel fills; `tx.send().await` blocks, which stops draining
///   the `reqwest::bytes_stream`, which closes the TCP window to
///   upstream. This is the correct backpressure for OOM relief, but
///   it can hold an upstream socket open longer than the buffered
///   path did. Mirrors with aggressive per-connection idle timeouts
///   (Maven Central, dl-cdn.alpinelinux.org) may close the
///   connection if storage fsync exceeds the mirror's idle window.
///   The `http_client::base_client_builder()` read timeout caps the
///   total wait; operators with tight storage budgets should verify
///   that timeout matches their upstream's tolerance.
/// * **HTTP/2 client flow-control window (#1184).** The 4 MiB tee cap
///   bounds memory between upstream reader and storage writer, but
///   on the *client* side hyper's HTTP/2 flow-control window adds
///   another in-flight slice that is NOT part of this channel.
///   With reqwest's current defaults this codebase does not call
///   `http2_adaptive_window`, so the per-stream window is fixed at
///   `SETTINGS_INITIAL_WINDOW_SIZE` (64 KiB). One in-flight frame
///   bounded by `SETTINGS_MAX_FRAME_SIZE` (peer-advertised, default
///   16 KiB, ceiling 16 MiB) sits on top of the window, so the
///   per-stream HTTP/2 overhead is conservatively ~128 KiB under
///   default tuning. Practical worst case under the documented
///   1 GiB pod limit is ~10 concurrent slow HTTP/2 clients =
///   ~1.3 MiB on top of the ~14 MiB per-request peak above, i.e.
///   ~15 MiB total. Well within budget; operators sizing pod memory
///   should still account for the per-stream window when calculating
///   concurrency limits, not just `TEE_CHANNEL_DEPTH * chunk_size`.
///   The OOM-relief contract holds because the flow-control window
///   itself is bounded by hyper.
const TEE_CHANNEL_DEPTH: usize = 64;

/// Maximum bytes per chunk forwarded through the tee channel.
///
/// `TEE_CHANNEL_DEPTH * TEE_MAX_CHUNK_BYTES` is the hard upper bound on the
/// memory held in the reader -> writer channel. Without splitting, an upstream
/// that hands us a multi-megabyte frame (HTTP/1.1 chunked with a large
/// `Transfer-Encoding` chunk, or an HTTP/2 peer that advertises a large
/// `SETTINGS_MAX_FRAME_SIZE`) would let `64 * upstream_chunk` blow past the
/// documented 4 MiB cap. Splitting at this boundary inside the tee makes the
/// budget claim a property of the code, not a property of the upstream.
///
/// 64 KiB matches the conservative chunk size assumed by the 4 MiB / request
/// docstring above. Smaller upstream chunks pass through unchanged.
const TEE_MAX_CHUNK_BYTES: usize = 64 * 1024;

/// Validate the upstream response status code for the streaming path.
/// Extracted from [`ProxyService::read_upstream_response_streaming`] so
/// the status-classification logic can be unit-tested without a real
/// `reqwest::Response`.
///
/// Parse an APT `Release` (or `InRelease`) file body and return every
/// distribution-relative file path listed under any checksum section
/// (`MD5Sum`, `SHA1`, `SHA256`, `SHA512`). Used by
/// `ProxyService::invalidate_dist_packages_cache` to identify which
/// sibling cache entries must be evicted when the upstream Release
/// changes (#1147).
///
/// The Release file format documents each section as a header line
/// (`SHA256:`) followed by indented entries of the form
/// `<hex_digest> <size> <relative_path>`. Lines starting with `-----`
/// belong to the inline-signature wrapper around an `InRelease` body
/// and are ignored. The returned `Vec` is de-duplicated while preserving
/// first-seen order.
fn parse_release_file_paths(release_content: &str) -> Vec<String> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut paths: Vec<String> = Vec::new();
    let mut in_checksum_section = false;

    for line in release_content.lines() {
        if line.starts_with("-----BEGIN") || line.starts_with("-----END") {
            continue;
        }
        // Section header: a line whose first non-whitespace char is at
        // column 0 (no leading indent) and that ends with ':'.
        if !line.starts_with(' ') && !line.starts_with('\t') && line.trim_end().ends_with(':') {
            let key = line.trim_end().trim_end_matches(':');
            in_checksum_section = matches!(key, "MD5Sum" | "SHA1" | "SHA256" | "SHA512");
            continue;
        }
        if !in_checksum_section {
            continue;
        }
        // Entry line: `<hex> <size> <relative_path>`. The hex digest and
        // the size live in the first two whitespace-separated columns;
        // everything after is the path.
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let _hex = match parts.next() {
            Some(h) if !h.is_empty() => h,
            _ => continue,
        };
        let _size = match parts.next() {
            Some(s) if s.chars().all(|c| c.is_ascii_digit()) => s,
            _ => continue,
        };
        let rest: String = parts.collect::<Vec<_>>().join(" ");
        if rest.is_empty() || rest.contains("..") {
            continue;
        }
        if seen.insert(rest.clone()) {
            paths.push(rest);
        }
    }
    paths
}

/// * `404` → `AppError::NotFound` (cache-miss-class error; callers treat
///   as a real "upstream doesn't have it" signal, not a backend failure)
/// * Other 5xx → `AppError::ServiceUnavailable` (transient upstream failure;
///   bubbles to the client as 503). Closes the 502-leak path in #1445:
///   a flaky upstream returning 502/503/504 should NOT propagate the raw
///   status to the client. Surfacing 503 lets clients (and our own retry
///   guard / single-flight followers) treat the failure as "try again in
///   a moment" instead of misclassifying it as a permanent gateway error.
/// * Other 4xx (401, 403, etc.) → `AppError::BadGateway` (upstream-config /
///   auth misconfig; bubbles to the client as 502). 4xx is genuinely a
///   gateway-side problem (the upstream told us we are not allowed) so
///   503 would be misleading.
/// * 2xx → `Ok(())`
fn validate_upstream_status(status: StatusCode, url: &str) -> Result<()> {
    if status == StatusCode::NOT_FOUND {
        return Err(AppError::NotFound(format!(
            "Artifact not found at upstream: {}",
            url
        )));
    }
    if status.is_server_error() {
        return Err(AppError::ServiceUnavailable(format!(
            "Upstream returned error status {}: {}",
            status, url
        )));
    }
    if !status.is_success() {
        return Err(AppError::BadGateway(format!(
            "Upstream returned error status {}: {}",
            status, url
        )));
    }
    Ok(())
}

/// Extract `(content_type, etag, content_length)` from an upstream
/// response's headers. Extracted from
/// [`ProxyService::read_upstream_response_streaming`] so the header-
/// parsing rules (in particular the `Content-Length` parse-and-coerce
/// to `u64`) can be unit-tested without a real `reqwest::Response`.
fn extract_streaming_headers(
    headers: &reqwest::header::HeaderMap,
) -> (Option<String>, Option<String>, Option<u64>) {
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let etag = headers
        .get(ETAG)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let content_length = headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());
    (content_type, etag, content_length)
}

/// Tee an upstream byte stream into a returned client stream AND a
/// background storage writer that populates the proxy cache. The
/// returned stream yields the same chunks the upstream produced, in
/// order, with no buffering beyond the bounded channel below.
///
/// Storage failure semantics:
/// * Storage writer task receives chunks via a bounded mpsc channel.
///   When the channel is full, the upstream reader awaits a slot — that
///   is the backpressure path. When the writer is gone (e.g. it
///   already failed and dropped its receiver), `try_send` short-
///   circuits and we keep yielding to the client without caching.
/// * On any error from `put_stream`, the writer logs at `warn` and
///   exits without writing the metadata sidecar. The cache is left
///   without a metadata sidecar so the NEXT request misses the cache
///   and re-fetches upstream — the system self-heals.
/// * On client disconnect mid-stream, the tee task ends, the channel
///   drops, and the writer commits or aborts whatever it has buffered.
///   No leaked temp files (FilesystemBackend cleans up via the
///   `put_stream` error path).
///
/// Error categories (#1185):
/// * Upstream stream errors observed mid-body are wrapped as
///   [`AppError::BadGateway`] before being forwarded to the writer
///   channel and surfaced to the client. This keeps operator log /
///   metric buckets honest: a flaky mirror does not inflate the
///   `STORAGE_ERROR` rate, and a genuine cache backend failure does
///   not get hidden as `BAD_GATEWAY`.
fn tee_upstream_to_cache(
    upstream: BoxStream<'static, Result<Bytes>>,
    storage: Arc<StorageService>,
    cache_key: String,
    metadata_key: String,
    template: CacheMetadataTemplate,
) -> BoxStream<'static, Result<Bytes>> {
    // Channel for chunks flowing reader -> writer. mpsc to keep order
    // (broadcast would let storage skip chunks under backpressure,
    // which we explicitly want to avoid - skipping chunks corrupts the
    // cached SHA-256).
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes>>(TEE_CHANNEL_DEPTH);

    // Spawn the storage writer. It consumes the channel as a stream
    // and calls put_stream. On completion, writes the metadata sidecar
    // with the observed SHA-256 + byte count.
    let storage_clone = storage.clone();
    let cache_key_for_writer = cache_key.clone();
    tokio::spawn(async move {
        // Adapter: receiver -> futures::Stream<Result<Bytes>>.
        let rx_stream = futures::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|item| (item, rx))
        });

        let put_result = storage_clone
            .put_stream(&cache_key_for_writer, Box::pin(rx_stream))
            .await;

        match put_result {
            Ok(result) => {
                let now = Utc::now();
                // Pin the storage backend's ETag at write time so the
                // fast path can re-HEAD on each hit and detect tampering
                // / backend-side replacement (#1051). See [`pin_storage_etag`]
                // for the best-effort semantics on backends without an
                // ETag concept or on transport error.
                let storage_etag = pin_storage_etag(&storage_clone, &cache_key_for_writer).await;
                let metadata = CacheMetadata {
                    cached_at: now,
                    upstream_etag: template.etag,
                    storage_etag,
                    expires_at: now + chrono::Duration::seconds(template.ttl_secs),
                    content_type: template.content_type,
                    size_bytes: result.bytes_written as i64,
                    checksum_sha256: result.checksum_sha256,
                };
                match serde_json::to_vec(&metadata) {
                    Ok(json) => {
                        if let Err(e) = storage_clone.put(&metadata_key, Bytes::from(json)).await {
                            tracing::warn!(
                                cache_key = %cache_key_for_writer,
                                metadata_key = %metadata_key,
                                error = %e,
                                "proxy cache metadata sidecar write failed; cache will refetch next request"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            cache_key = %cache_key_for_writer,
                            error = %e,
                            "proxy cache metadata JSON serialization failed"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    cache_key = %cache_key_for_writer,
                    error = %e,
                    "proxy cache put_stream failed; cache will refetch next request"
                );
            }
        }
    });

    // Build the client-facing stream. For each chunk from upstream:
    //   * forward the same chunk to the storage channel (backpressure
    //     applies; if storage went away, drop silently and continue).
    //   * yield the chunk to the client.
    // On upstream error: forward the error to storage (so put_stream
    // sees the error and aborts cleanly) and surface to the client.
    let tee_stream = async_stream::try_stream! {
        let mut upstream = upstream;
        while let Some(chunk_result) = upstream.next().await {
            match chunk_result {
                Ok(mut bytes) => {
                    // #1184: cap the per-channel-message size so an upstream
                    // that hands us a multi-megabyte chunk does not blow
                    // past the documented `TEE_CHANNEL_DEPTH * 64 KiB`
                    // memory budget. Splitting preserves byte order and the
                    // total payload; the client sees the same bytes, just
                    // in smaller pieces. `Bytes::split_to` is a cheap
                    // reference-count adjustment, not a copy.
                    while !bytes.is_empty() {
                        let take = bytes.len().min(TEE_MAX_CHUNK_BYTES);
                        let slice = bytes.split_to(take);
                        // Best-effort send to the cache writer. If the
                        // writer is gone (it already failed and dropped
                        // its receiver), drop the caching half silently
                        // and keep yielding to the client.
                        let _ = tx.send(Ok(slice.clone())).await;
                        yield slice;
                    }
                }
                Err(e) => {
                    // #1185: upstream stream errors are upstream/network
                    // failures, not storage failures. Tagging them
                    // `BadGateway` on the writer channel lets operators
                    // bucket them correctly in logs / metrics (the
                    // previous `Storage` tag hid upstream incidents inside
                    // the storage error rate). The cache writer treats
                    // any Err it observes as a reason to abandon the
                    // cache regardless of category. The original error
                    // surfaces to the client unchanged — handlers map it
                    // to a 502 via `map_proxy_error` on the request path.
                    let storage_msg = Err(AppError::BadGateway(format!(
                        "upstream stream error: {}",
                        e
                    )));
                    let _ = tx.send(storage_msg).await;
                    Err(e)?;
                }
            }
        }
        // upstream EOF: drop tx so the writer sees end-of-stream
        drop(tx);
    };
    Box::pin(tee_stream)
}

/// Cache metadata for a proxied artifact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMetadata {
    /// When the artifact was cached
    pub cached_at: DateTime<Utc>,
    /// ETag from upstream (if available)
    pub upstream_etag: Option<String>,
    /// ETag pinned from the storage backend at cache-write time. See
    /// [`ProxyService::is_cache_fresh`] for the revalidation contract,
    /// per-backend behavior, and the legacy-entry fall-through. `None`
    /// means revalidation is skipped (filesystem backend or legacy
    /// sidecar written before this field existed); `#[serde(default)]`
    /// preserves wire-compat with pre-#1051 sidecars.
    ///
    /// Trust boundary: the pin lives in a JSON sidecar at the cache
    /// metadata key with no integrity binding. An actor that can write
    /// to the storage backend can rewrite both the body and the sidecar
    /// in lockstep, defeating tamper detection. Treat this as a defense
    /// against accidental upstream-vs-cache divergence, not against an
    /// adversary with storage-write capability. A sidecar HMAC is the
    /// natural hardening if that threat model becomes relevant.
    #[serde(default)]
    pub storage_etag: Option<String>,
    /// When the cache entry expires
    pub expires_at: DateTime<Utc>,
    /// Content type from upstream
    pub content_type: Option<String>,
    /// Size of the cached content
    pub size_bytes: i64,
    /// SHA-256 checksum of cached content
    pub checksum_sha256: String,
}

/// Default bearer token TTL when the token endpoint omits `expires_in` (5 minutes).
const DEFAULT_TOKEN_TTL_SECS: u64 = 300;

/// Maximum bearer token TTL (1 hour). Prevents a malicious token endpoint from
/// disabling cache eviction or causing integer overflow via a huge `expires_in`.
const MAX_TOKEN_TTL_SECS: u64 = 3600;

/// JSON response from an OCI registry token endpoint.
#[derive(Deserialize)]
struct RegistryTokenResponse {
    token: Option<String>,
    access_token: Option<String>,
    expires_in: Option<u64>,
}

/// Best-effort fetch of the backend's ETag for a freshly-written cache
/// object, used by both the streaming-tee and buffered cache-write paths
/// to pin [`CacheMetadata::storage_etag`] (#1051).
///
/// Returns `None` on either `Ok(None)` (backend has no ETag concept) or
/// transport error; the caller then writes the sidecar without a pin and
/// fast-path revalidation falls back to pre-#1051 existence-only
/// semantics for that entry.
async fn pin_storage_etag(storage: &StorageService, cache_key: &str) -> Option<String> {
    storage.head_etag(cache_key).await.unwrap_or_else(|e| {
        tracing::debug!(
            cache_key = %cache_key,
            error = %e,
            "head_etag after cache write failed; skipping fast-path revalidation pin"
        );
        None
    })
}

/// Proxy service for fetching and caching artifacts from upstream repositories
pub struct ProxyService {
    db: PgPool,
    storage: Arc<StorageService>,
    http_client: Client,
    /// In-memory cache for OCI registry bearer tokens.
    /// Key: "{realm}\0{service}\0{scope}", Value: (token, created_at, ttl_secs)
    token_cache: RwLock<HashMap<String, (String, Instant, u64)>>,
}

impl ProxyService {
    /// Maximum cache-key length in bytes.
    ///
    /// All major object stores cap object key length at 1024 bytes:
    /// AWS S3 returns 400 `KeyTooLongError` past this limit, Azure Blob
    /// Storage caps blob names at 1024 chars, and Google Cloud Storage
    /// likewise enforces 1024 bytes. Filesystem backends typically
    /// allow longer paths but we hold the line at the lowest common
    /// denominator so a switch from filesystem to S3 cannot turn an
    /// existing repo into a broken one (#1044).
    const MAX_STORAGE_KEY_BYTES: usize = 1024;

    /// Create a new proxy service
    pub fn new(db: PgPool, storage: Arc<StorageService>) -> Self {
        let http_client = crate::services::http_client::base_client_builder()
            .connect_timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
            .read_timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
            .user_agent("artifact-keeper-proxy/1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            db,
            storage,
            http_client,
            token_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Fetch artifact from upstream if not cached or cache expired.
    /// Returns (content, content_type) tuple.
    pub async fn fetch_artifact(
        &self,
        repo: &Repository,
        path: &str,
    ) -> Result<(Bytes, Option<String>)> {
        self.fetch_artifact_with_cache_path(repo, path, path).await
    }

    /// Variant of [`Self::fetch_artifact`] that forwards a client-supplied
    /// `Accept` header to the upstream request.
    ///
    /// OCI Distribution registries (notably Docker Hub) drive manifest format
    /// negotiation off the client `Accept` header: the same `manifests/<ref>`
    /// URL can resolve to a v2 image manifest, a Docker manifest list, an OCI
    /// image index, or an OCI image manifest depending on what the caller
    /// advertises. Stripping the header at the proxy boundary lets the
    /// upstream pick whatever shape it prefers, which on some registries
    /// surfaces as 404 / 406 when the stored object only carries a content
    /// type the caller didn't ask for. Forwarding the original header
    /// preserves the content-negotiation chain end to end.
    ///
    /// Blob fetches do NOT need this (blobs are content-addressable opaque
    /// bytes), but routing them through this path with `accept = None` is
    /// a no-op so the buffered fast path stays a single function.
    pub async fn fetch_artifact_with_accept(
        &self,
        repo: &Repository,
        path: &str,
        accept: Option<&str>,
    ) -> Result<(Bytes, Option<String>)> {
        self.fetch_artifact_with_cache_path_and_accept(repo, path, path, accept)
            .await
    }

    /// Check whether an artifact is already present in the proxy cache
    /// under the given `path` (without contacting upstream).
    ///
    /// Returns `Ok(Some((content, content_type)))` on cache hit, `Ok(None)`
    /// on cache miss or expired entry.
    pub async fn get_cached_artifact_by_path(
        &self,
        repo_key: &str,
        path: &str,
    ) -> Result<Option<(Bytes, Option<String>)>> {
        let cache_key = Self::cache_storage_key(repo_key, path)?;
        let metadata_key = Self::cache_metadata_key(repo_key, path)?;
        self.get_cached_artifact(&cache_key, &metadata_key).await
    }

    /// Metadata-only freshness check for a proxy-cached artifact.
    ///
    /// Loads only the cache metadata sidecar (small JSON) and verifies that
    /// the underlying content object exists in the storage backend. Does
    /// NOT download the cached body, which is the whole point of a
    /// metadata-only probe before issuing a presigned redirect (#1018).
    ///
    /// Returns `true` only when both:
    ///   * the metadata exists and has not expired, and
    ///   * the content object exists in the backing storage.
    ///
    /// # Integrity / SHA-256 self-heal divergence (fast vs. slow path)
    ///
    /// The slow path (`get_cached_artifact`) recomputes the SHA-256 of the
    /// cached body and, on mismatch, returns `None` so the caller re-fetches
    /// from upstream and overwrites the cache entry — i.e. the cache
    /// self-heals on the next read.
    ///
    /// The fast path that this probe gates (presigned redirect to the
    /// cached object) does **not** download the body and therefore cannot
    /// recompute the SHA-256. As of #1051 it does, however, perform an
    /// ETag-based revalidation: we pin the storage backend's ETag at
    /// cache-write time into [`CacheMetadata::storage_etag`] and re-HEAD
    /// on every fast-path hit. A mismatch (object replaced, tampered, or
    /// restored from a different version) returns `false` here so the
    /// caller drops into the slow path, which then recomputes the SHA-256
    /// and self-heals the cache.
    ///
    /// Per-backend behavior:
    ///
    ///   * **S3 / GCS / Azure**: ETag is the backend's per-object value.
    ///     For S3 single-part PUTs this equals the MD5 of the body and
    ///     gives cryptographic-grade replacement detection; for multipart
    ///     uploads it is an opaque per-upload identifier that still
    ///     changes on any rewrite. Both are sufficient for tamper
    ///     detection in the cache-poisoning threat model.
    ///   * **Filesystem**: no native ETag. `storage_etag` is `None` for
    ///     these entries, revalidation is a no-op, and behavior matches
    ///     pre-#1051 semantics — i.e. the local filesystem is the trust
    ///     boundary.
    ///   * **Legacy cache entries** written before #1051 have
    ///     `storage_etag = None` via `#[serde(default)]`. They also skip
    ///     revalidation; once the TTL expires and the entry is rewritten
    ///     the new entry picks up an ETag.
    ///
    /// If the HEAD itself errors (transport failure mid-revalidation), we
    /// treat the cache as not-fresh and fall through to the slow path
    /// rather than silently serving a possibly-stale URL.
    pub async fn is_cache_fresh(&self, repo_key: &str, path: &str) -> bool {
        // A path that fails validation cannot have produced a cache entry
        // we'd want to redirect to anyway: treat it as a miss so the caller
        // falls through to the slow path / upstream fetch, where the same
        // validation will surface the error to the client.
        let Ok(cache_key) = Self::cache_storage_key(repo_key, path) else {
            return false;
        };
        let Ok(metadata_key) = Self::cache_metadata_key(repo_key, path) else {
            return false;
        };

        let Ok(Some(metadata)) = self.load_cache_metadata(&metadata_key).await else {
            return false;
        };
        if Utc::now() > metadata.expires_at {
            return false;
        }

        // ETag-based integrity revalidation (#1051). Only meaningful when
        // we have a pinned ETag from cache-write time AND the backend
        // surfaces an ETag now. Either side being `None` falls back to
        // pre-#1051 behavior (existence check only): filesystem entries
        // and legacy sidecars are unaffected.
        match metadata.storage_etag {
            Some(ref pinned) => match self.storage.head_etag(&cache_key).await {
                Ok(Some(current)) => {
                    if current != *pinned {
                        tracing::warn!(
                            cache_key = %cache_key,
                            pinned_etag = %pinned,
                            current_etag = %current,
                            "proxy cache ETag mismatch on fast-path revalidation; falling back to slow path"
                        );
                        return false;
                    }
                    // ETag matched → object is present and unchanged
                    // since cache write. Skip the redundant exists() call.
                    true
                }
                // Backend lost the object (None) or errored: treat as
                // not-fresh. The slow path will re-fetch and re-cache.
                Ok(None) => false,
                Err(e) => {
                    tracing::warn!(
                        cache_key = %cache_key,
                        error = %e,
                        "proxy cache head_etag failed during revalidation; treating as not fresh"
                    );
                    false
                }
            },
            None => {
                // No pinned ETag (filesystem / legacy entry). Preserve
                // pre-#1051 semantics: existence check only.
                matches!(self.storage.exists(&cache_key).await, Ok(true))
            }
        }
    }

    /// Fetch artifact from upstream, but use `cache_path` instead of
    /// `fetch_path` when reading and writing the proxy cache.
    ///
    /// This is useful when the upstream download URL is unpredictable (e.g.,
    /// PyPI hosts files on a different domain) but the caller wants a stable,
    /// locally-computed cache key so that subsequent requests can hit the
    /// cache without rediscovering the upstream URL.
    pub async fn fetch_artifact_with_cache_path(
        &self,
        repo: &Repository,
        fetch_path: &str,
        cache_path: &str,
    ) -> Result<(Bytes, Option<String>)> {
        self.fetch_artifact_with_cache_path_and_accept(repo, fetch_path, cache_path, None)
            .await
    }

    /// Inner variant of [`Self::fetch_artifact_with_cache_path`] that also
    /// forwards an optional `Accept` header to the upstream request. Used by
    /// callers that need OCI content negotiation (manifest GETs). Pass
    /// `None` to preserve the buffered-fetch behaviour exactly.
    async fn fetch_artifact_with_cache_path_and_accept(
        &self,
        repo: &Repository,
        fetch_path: &str,
        cache_path: &str,
        accept: Option<&str>,
    ) -> Result<(Bytes, Option<String>)> {
        if repo.repo_type != RepositoryType::Remote {
            return Err(AppError::Validation(
                "Proxy operations only supported for remote repositories".to_string(),
            ));
        }

        let upstream_url = repo.upstream_url.as_ref().ok_or_else(|| {
            AppError::Config("Remote repository missing upstream_url".to_string())
        })?;

        // Cache keys use the caller-supplied cache_path
        let cache_key = Self::cache_storage_key(&repo.key, cache_path)?;
        let metadata_key = Self::cache_metadata_key(&repo.key, cache_path)?;

        // Check if we have a valid cached copy
        if let Some((content, content_type)) =
            self.get_cached_artifact(&cache_key, &metadata_key).await?
        {
            return Ok((content, content_type));
        }

        // Fetch from upstream using the real fetch_path
        let full_url = Self::build_upstream_url(upstream_url, fetch_path);
        let upstream_result = self
            .fetch_from_upstream_with_accept(&full_url, repo.id, accept)
            .await;

        match upstream_result {
            Ok(resp) => {
                let cache_ttl = self.get_cache_ttl_for_repo(repo.id).await;
                self.cache_artifact(
                    &cache_key,
                    &metadata_key,
                    &resp.content,
                    resp.content_type.clone(),
                    resp.etag,
                    cache_ttl,
                    repo.id,
                    cache_path,
                )
                .await?;

                Ok((resp.content, resp.content_type))
            }
            Err(upstream_err) => {
                if let Ok(Some((stale_content, stale_content_type))) = self
                    .get_stale_cached_artifact(&cache_key, &metadata_key)
                    .await
                {
                    tracing::warn!(
                        "Upstream fetch failed for {}; serving stale cached copy: {}",
                        full_url,
                        upstream_err
                    );
                    Ok((stale_content, stale_content_type))
                } else {
                    Err(upstream_err)
                }
            }
        }
    }

    /// Streaming sibling of [`Self::fetch_artifact`] that does NOT buffer
    /// the artifact body in memory (#895). Suitable for large objects
    /// (.deb / .rpm packages, container blobs) on memory-constrained
    /// pods where the buffered path causes OOM.
    ///
    /// Flow:
    /// * **Cache hit** — returns the body as a stream from
    ///   `StorageService::get_stream`, plus the cached content-type and
    ///   size. Constant memory usage regardless of object size.
    /// * **Cache miss** — fetches from upstream as a stream, tees each
    ///   chunk simultaneously to (a) the returned client stream and
    ///   (b) a background writer that calls `StorageService::put_stream`
    ///   to populate the cache. The cache metadata sidecar is written
    ///   once the storage write completes with the observed SHA-256.
    ///
    /// Storage backpressure: the tee uses a bounded mpsc channel (64
    /// 64 KiB chunks ≈ 4 MiB) so slow storage applies moderate
    /// backpressure to the client rather than queueing unbounded
    /// memory. On storage write failure mid-stream the client still
    /// receives the complete body; the cache is poisoned (no metadata
    /// sidecar) and self-heals on the next request.
    pub async fn fetch_artifact_streaming(
        &self,
        repo: &Repository,
        path: &str,
    ) -> Result<StreamingFetchResult> {
        if repo.repo_type != RepositoryType::Remote {
            return Err(AppError::Validation(
                "Proxy operations only supported for remote repositories".to_string(),
            ));
        }

        let upstream_url = repo.upstream_url.as_ref().ok_or_else(|| {
            AppError::Config("Remote repository missing upstream_url".to_string())
        })?;

        let cache_key = Self::cache_storage_key(&repo.key, path)?;
        let metadata_key = Self::cache_metadata_key(&repo.key, path)?;

        // Cache hit fast path: load metadata sidecar, stream content
        // straight from storage. The slow-path SHA verification done by
        // the buffered `fetch_artifact_with_cache_path` is intentionally
        // skipped here — we cannot recompute SHA without buffering, and
        // the storage backend's own integrity guarantees apply just as
        // they do for presigned redirects (#1018 R-tradeoff already
        // accepted upstream).
        if let Some(metadata) = self.load_cache_metadata(&metadata_key).await? {
            if Utc::now() <= metadata.expires_at {
                match self.storage.get_stream(&cache_key).await {
                    Ok(body) => {
                        return Ok(StreamingFetchResult {
                            body,
                            content_type: metadata.content_type,
                            content_length: Some(metadata.size_bytes as u64),
                        });
                    }
                    Err(AppError::NotFound(_)) => {
                        // Metadata says cached but body is gone (probably
                        // an out-of-band eviction). Fall through to upstream.
                        tracing::debug!(
                            cache_key = %cache_key,
                            "cache metadata present but body missing; refetching"
                        );
                    }
                    Err(e) => return Err(e),
                }
            }
        }

        // Cache miss: fetch upstream as a stream, tee to the cache writer
        // and to the client.
        let full_url = Self::build_upstream_url(upstream_url, path);
        let upstream = self
            .fetch_from_upstream_streaming(&full_url, repo.id)
            .await?;

        let cache_ttl = self.get_cache_ttl_for_repo(repo.id).await;
        let body = tee_upstream_to_cache(
            upstream.body,
            self.storage.clone(),
            cache_key,
            metadata_key,
            CacheMetadataTemplate {
                content_type: upstream.content_type.clone(),
                etag: upstream.etag,
                ttl_secs: cache_ttl,
            },
        );

        Ok(StreamingFetchResult {
            body,
            content_type: upstream.content_type,
            content_length: upstream.content_length,
        })
    }

    /// Check if upstream has a newer version of the artifact.
    /// Returns true if upstream has newer content or cache is expired.
    pub async fn check_upstream(&self, repo: &Repository, path: &str) -> Result<bool> {
        // Validate repository type
        if repo.repo_type != RepositoryType::Remote {
            return Err(AppError::Validation(
                "Proxy operations only supported for remote repositories".to_string(),
            ));
        }

        let upstream_url = repo.upstream_url.as_ref().ok_or_else(|| {
            AppError::Config("Remote repository missing upstream_url".to_string())
        })?;

        let metadata_key = Self::cache_metadata_key(&repo.key, path)?;

        // Try to load existing cache metadata
        let metadata = match self.load_cache_metadata(&metadata_key).await? {
            Some(m) => m,
            None => return Ok(true), // No cache, definitely need to fetch
        };

        // Check if cache has expired
        if Utc::now() > metadata.expires_at {
            return Ok(true);
        }

        // If we have an ETag, do a conditional request
        if let Some(ref etag) = metadata.upstream_etag {
            let full_url = Self::build_upstream_url(upstream_url, path);
            return self.check_etag_changed(&full_url, etag, repo.id).await;
        }

        // No ETag, rely on TTL - cache is still valid
        Ok(false)
    }

    /// Fetch from upstream without reading or writing the proxy cache.
    ///
    /// This is useful when the caller needs the *raw* upstream response (e.g.,
    /// to parse download URLs from a PyPI simple index) and cannot risk
    /// receiving a locally-transformed cached copy.
    ///
    /// Returns `(content, content_type, effective_url)`. The effective URL is
    /// the final URL after any redirects, which may differ from the requested
    /// URL. Callers that resolve relative URLs in the response body should use
    /// the effective URL as the base for resolution.
    pub async fn fetch_upstream_direct(
        &self,
        repo: &Repository,
        path: &str,
    ) -> Result<(Bytes, Option<String>, String)> {
        if repo.repo_type != RepositoryType::Remote {
            return Err(AppError::Validation(
                "Proxy operations only supported for remote repositories".to_string(),
            ));
        }

        let upstream_url = repo.upstream_url.as_ref().ok_or_else(|| {
            AppError::Config("Remote repository missing upstream_url".to_string())
        })?;

        let full_url = Self::build_upstream_url(upstream_url, path);
        let resp = self.fetch_from_upstream(&full_url, repo.id).await?;
        Ok((resp.content, resp.content_type, resp.effective_url))
    }

    /// Fetch from upstream directly, preserving the upstream `Link` header.
    ///
    /// OCI tag pagination relies on the upstream continuation cursor when the
    /// registry enforces its own page-size cap. Callers that need to reconstruct
    /// pagination accurately should use this instead of [`fetch_upstream_direct`].
    pub async fn fetch_upstream_direct_with_link(
        &self,
        repo: &Repository,
        path: &str,
    ) -> Result<(Bytes, Option<String>, Option<String>)> {
        if repo.repo_type != RepositoryType::Remote {
            return Err(AppError::Validation(
                "Proxy operations only supported for remote repositories".to_string(),
            ));
        }

        let upstream_url = repo.upstream_url.as_ref().ok_or_else(|| {
            AppError::Config("Remote repository missing upstream_url".to_string())
        })?;

        let full_url = Self::build_upstream_url(upstream_url, path);
        let resp = self.fetch_from_upstream(&full_url, repo.id).await?;
        Ok((resp.content, resp.content_type, resp.link))
    }

    /// Invalidate cached artifact
    pub async fn invalidate_cache(&self, repo: &Repository, path: &str) -> Result<()> {
        let cache_key = Self::cache_storage_key(&repo.key, path)?;
        let metadata_key = Self::cache_metadata_key(&repo.key, path)?;

        // Delete both content and metadata
        let _ = self.storage.delete(&cache_key).await;
        let _ = self.storage.delete(&metadata_key).await;

        Ok(())
    }

    /// Invalidate cached artifact by repo key alone.
    ///
    /// Same effect as `invalidate_cache` but doesn't require constructing
    /// a `Repository` value. Useful for handlers that only carry a thin
    /// `RepoInfo` and need to evict sibling cache entries (e.g. APT
    /// invalidating stale Packages indices when Release changes, #1147).
    pub async fn invalidate_cache_by_key(&self, repo_key: &str, path: &str) -> Result<()> {
        let cache_key = Self::cache_storage_key(repo_key, path)?;
        let metadata_key = Self::cache_metadata_key(repo_key, path)?;
        let _ = self.storage.delete(&cache_key).await;
        let _ = self.storage.delete(&metadata_key).await;
        Ok(())
    }

    /// Fetch an artifact from upstream and report whether the content
    /// differs from what was previously cached.
    ///
    /// Returns `(content, content_type, changed)` where `changed` is:
    ///   * `true` when the previous cache entry was missing/expired AND
    ///     the new upstream body differs from any stale cached body, or
    ///     when there was no cached body to compare against,
    ///   * `false` when the upstream returned the same SHA-256 we already
    ///     had cached.
    ///
    /// Use this for APT `Release`/`InRelease` (#1147) so the handler can
    /// invalidate sibling `Packages*` caches in lockstep when upstream
    /// publishes a new index and the hashes no longer match.
    pub async fn fetch_dists_detecting_change(
        &self,
        repo: &Repository,
        path: &str,
    ) -> Result<(Bytes, Option<String>, bool)> {
        let cache_key = Self::cache_storage_key(&repo.key, path)?;

        // Capture the SHA of any currently-cached body (fresh or stale) so
        // we can compare to whatever the upstream now serves.
        let prior_sha = match self.storage.get(&cache_key).await {
            Ok(prior) => {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(&prior);
                Some(format!("{:x}", hasher.finalize()))
            }
            Err(_) => None,
        };

        // Force a fresh upstream fetch by invalidating any current cache
        // entry before delegating. This guarantees we observe the latest
        // upstream Release when the caller's intent is to drive cache
        // coherence across sibling Packages indices.
        let _ = self.invalidate_cache_by_key(&repo.key, path).await;

        let (content, content_type) = self.fetch_artifact(repo, path).await?;

        let new_sha = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&content);
            format!("{:x}", hasher.finalize())
        };
        let changed = match prior_sha {
            Some(s) => s != new_sha,
            None => true,
        };
        Ok((content, content_type, changed))
    }

    /// List the PyPI project names that already have a cached `simple/<name>/`
    /// index in this repository's proxy cache.
    ///
    /// PyPI clients fetch a per-project simple index (`simple/<name>/`) before
    /// downloading any distribution. That index is proxy-cached at
    /// `proxy-cache/<repo_key>/simple/<name>/__content__`. For a Remote repo,
    /// proxy-cached artifacts are intentionally NOT recorded in the `artifacts`
    /// table (#1278), so the root simple index (`simple/`) has no DB rows to
    /// list and can come back empty even after clients have pulled packages
    /// through the proxy. Walking the proxy-cache prefix recovers the set of
    /// projects the proxy has actually served, so the root index lists them
    /// (B8). Falls back to an empty list when the storage backend cannot list
    /// the prefix.
    pub async fn list_cached_pypi_packages(&self, repo_key: &str) -> Vec<String> {
        let prefix = format!("proxy-cache/{}/simple/", repo_key);
        let keys = match self.storage.list(Some(&prefix)).await {
            Ok(keys) => keys,
            Err(e) => {
                tracing::debug!(
                    repo_key = %repo_key,
                    error = %e,
                    "listing proxy cache for pypi simple-root packages failed; \
                     returning no cached packages"
                );
                return Vec::new();
            }
        };
        Self::pypi_package_names_from_cache_keys(repo_key, keys.iter().map(String::as_str))
    }

    /// Extract the distinct PyPI project names from a set of proxy-cache
    /// storage keys.
    ///
    /// Keys look like
    /// `proxy-cache/<repo_key>/simple/<name>/__content__` (and a sibling
    /// `__cache_meta__.json`). We keep only entries that carry a package
    /// segment (`simple/<name>/...`), pull the `<name>` segment out, and
    /// dedupe. Pure so the parsing can be unit-tested without a storage
    /// backend.
    fn pypi_package_names_from_cache_keys<'a, I>(repo_key: &str, keys: I) -> Vec<String>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let simple_prefix = format!("proxy-cache/{}/simple/", repo_key);
        let mut names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for key in keys {
            let Some(rest) = key.strip_prefix(&simple_prefix) else {
                continue;
            };
            // `rest` is `<name>/<more>...`; the first segment is the project.
            // The bare `simple/` root index caches under `simple//__content__`
            // (empty first segment) which we skip, and a `__content__` sitting
            // directly under `simple/` has no project segment either.
            let Some((name, tail)) = rest.split_once('/') else {
                continue;
            };
            if name.is_empty() || tail.is_empty() {
                continue;
            }
            names.insert(name.to_string());
        }
        names.into_iter().collect()
    }

    /// Invalidate every cached file referenced from an APT Release file
    /// for a given distribution (#1147).
    ///
    /// The Release file lists every `Packages`, `Packages.gz`,
    /// `Packages.xz`, `Translation-*`, `Contents-*`, `Components-*`, etc.
    /// path under the distribution along with their SHA-256 hashes. When
    /// upstream publishes new packages the hashes change but the per-file
    /// caches keep serving the old bodies until their own TTL expires,
    /// which is what causes `apt-get update` to fail with
    /// `Hash Sum mismatch`.
    ///
    /// Given the freshly-fetched Release body and its distribution name,
    /// parse the `SHA256:` section and invalidate every referenced path's
    /// cache entry under `dists/<distribution>/`. The Release entry itself
    /// is *not* invalidated by this method; callers fetch and refresh it
    /// through `fetch_dists_detecting_change` first.
    pub async fn invalidate_dist_packages_cache(
        &self,
        repo_key: &str,
        distribution: &str,
        release_content: &str,
    ) {
        for relative in parse_release_file_paths(release_content) {
            let path = format!("dists/{}/{}", distribution, relative);
            let _ = self.invalidate_cache_by_key(repo_key, &path).await;
        }
    }

    /// Get cache TTL configuration for a repository.
    /// Returns TTL in seconds.
    async fn get_cache_ttl_for_repo(&self, repo_id: Uuid) -> i64 {
        // Try to get repository-specific TTL from config table
        // For now, use default TTL. This can be extended to read from
        // a repository_config table or the repository record itself.
        let result = sqlx::query_scalar!(
            r#"
            SELECT value FROM repository_config
            WHERE repository_id = $1 AND key = 'cache_ttl_secs'
            "#,
            repo_id
        )
        .fetch_optional(&self.db)
        .await;

        match result {
            Ok(Some(value)) => {
                if let Some(v) = value {
                    v.parse().unwrap_or(DEFAULT_CACHE_TTL_SECS)
                } else {
                    DEFAULT_CACHE_TTL_SECS
                }
            }
            _ => DEFAULT_CACHE_TTL_SECS,
        }
    }

    /// Build full upstream URL for an artifact path.
    ///
    /// If `path` is already an absolute URL (starts with `http://` or
    /// `https://`), it is returned unchanged. This lets callers supply URLs
    /// discovered from upstream index files (e.g. a Helm `index.yaml` entry
    /// whose `urls` field points to a GitHub Releases download) without
    /// needing to know whether the URL shares the same origin as `base_url`.
    fn build_upstream_url(base_url: &str, path: &str) -> String {
        if path.starts_with("http://") || path.starts_with("https://") {
            return path.to_string();
        }
        let base = base_url.trim_end_matches('/');
        let path = path.trim_start_matches('/');
        format!("{}/{}", base, path)
    }

    /// Generate storage key for cached artifact content.
    /// Uses a `__content__` leaf file to avoid file/directory collisions
    /// when one path is a prefix of another (e.g., npm metadata at `is-odd`
    /// vs tarball at `is-odd/-/is-odd-3.0.1.tgz`).
    ///
    /// Visible to the rest of the crate so that the proxy fast-path in
    /// `api::handlers::proxy_helpers::proxy_fetch_or_redirect` can sign
    /// presigned URLs against the *exact* same key the freshness probe
    /// in `is_cache_fresh` checks. Keeping a single source of truth for
    /// the key formula prevents the freshness check and the presign
    /// target from drifting out of sync (#1018).
    pub(crate) fn cache_storage_key(repo_key: &str, path: &str) -> Result<String> {
        let trimmed = Self::validate_cache_path(path)?;
        let key = format!("proxy-cache/{}/{}/__content__", repo_key, trimmed);
        Self::check_cache_key_length(repo_key, trimmed)?;
        Ok(key)
    }

    /// Generate storage key for cache metadata
    fn cache_metadata_key(repo_key: &str, path: &str) -> Result<String> {
        let trimmed = Self::validate_cache_path(path)?;
        let key = format!("proxy-cache/{}/{}/__cache_meta__.json", repo_key, trimmed);
        Self::check_cache_key_length(repo_key, trimmed)?;
        Ok(key)
    }

    /// Reject cache paths whose final formatted key would exceed
    /// [`Self::MAX_STORAGE_KEY_BYTES`].
    ///
    /// Both `cache_storage_key` (`__content__` suffix, 11 chars) and
    /// `cache_metadata_key` (`__cache_meta__.json` suffix, 19 chars) are
    /// checked against the *larger* suffix so a path can't slip through
    /// `cache_storage_key` only to fail when the matching metadata key is
    /// later derived. Returning `Validation` early keeps the failure local
    /// to the helper instead of surfacing as an opaque 400/500 from the
    /// object-store SDK mid-fetch (#1044).
    fn check_cache_key_length(repo_key: &str, trimmed_path: &str) -> Result<()> {
        // Worst case suffix is "__cache_meta__.json" (19 bytes).
        const PREFIX: &str = "proxy-cache/";
        const WORST_SUFFIX: &str = "__cache_meta__.json";
        // Two interior '/' separators are added by the format!() calls.
        let worst_len =
            PREFIX.len() + repo_key.len() + 1 + trimmed_path.len() + 1 + WORST_SUFFIX.len();
        if worst_len > Self::MAX_STORAGE_KEY_BYTES {
            return Err(AppError::Validation(format!(
                "Proxy cache key exceeds {}-byte object-store limit (would be {} bytes)",
                Self::MAX_STORAGE_KEY_BYTES,
                worst_len
            )));
        }
        Ok(())
    }

    /// Reject paths that would let a caller escape the proxy cache
    /// directory or smuggle bytes the storage backend will misinterpret.
    /// Returns the trimmed path on success.
    ///
    /// Storage backends generally reject `..` already (filesystem.rs has
    /// explicit traversal tests). This is the helper-boundary belt to that
    /// suspenders so a future call site that bypasses the storage check
    /// still cannot escape (#1018 R3-7 / #1052).
    fn validate_cache_path(path: &str) -> Result<&str> {
        let trimmed = path.trim_start_matches('/').trim_end_matches('/');

        if trimmed.is_empty() {
            return Err(AppError::Validation(
                "Proxy cache path must not be empty".to_string(),
            ));
        }

        // NUL terminates C strings and is a classic smuggling vector for
        // storage backends written in C/C++ (e.g. libfuse, native S3 SDK
        // helpers). Reject early.
        if trimmed.contains('\0') {
            return Err(AppError::Validation(
                "Proxy cache path must not contain NUL bytes".to_string(),
            ));
        }

        // Backslash is a Windows path separator. Some object-store SDKs
        // normalize `\` to `/` before signing URLs; others do not. Either
        // way, a request like `..\\foo` would otherwise pass the
        // `..`-segment check (because split('/') leaves it as a single
        // segment) and only get caught (or worse, miscaught) downstream.
        // Reject at the boundary.
        if trimmed.contains('\\') {
            return Err(AppError::Validation(
                "Proxy cache path must not contain backslashes".to_string(),
            ));
        }

        // Reject any path segment that is exactly `..` or `.`. Substrings
        // like `..foo` or `foo..bar` are fine (they are just bytes inside a
        // filename) and reflect legitimate package names.
        for segment in trimmed.split('/') {
            if segment == ".." || segment == "." {
                return Err(AppError::Validation(format!(
                    "Proxy cache path must not contain `{}` segment",
                    segment
                )));
            }
            // Empty segments come from `//` which is ambiguous to many
            // storage backends and should not appear in a normalized path.
            if segment.is_empty() {
                return Err(AppError::Validation(
                    "Proxy cache path must not contain empty segments".to_string(),
                ));
            }
        }

        // C0 control bytes (other than the standard whitespace already
        // handled by the empty/segment checks) have no place in a cache
        // path; they confuse log scrapers and some object-store sign URLs.
        if trimmed.bytes().any(|b| b < 0x20 && b != b'\t') {
            return Err(AppError::Validation(
                "Proxy cache path must not contain control characters".to_string(),
            ));
        }

        Ok(trimmed)
    }

    /// Attempt to retrieve a cached artifact if valid
    async fn get_cached_artifact(
        &self,
        cache_key: &str,
        metadata_key: &str,
    ) -> Result<Option<(Bytes, Option<String>)>> {
        // Check if metadata exists. A read/parse error on the sidecar (e.g. a
        // waiter racing the single-flight leader's metadata write, or a
        // half-written JSON) is treated as a cache miss rather than bubbling
        // out as a 502 (B6): the caller re-fetches upstream and gets a clean
        // 2xx or a 503, never a raw storage 502.
        let metadata = match self.load_cache_metadata(metadata_key).await {
            Ok(Some(m)) => m,
            Ok(None) => return Ok(None),
            Err(e) => {
                tracing::warn!(
                    metadata_key = %metadata_key,
                    error = %e,
                    "proxy cache metadata read failed; treating as miss and refetching upstream"
                );
                return Ok(None);
            }
        };

        // Check if cache has expired
        if Utc::now() > metadata.expires_at {
            tracing::debug!("Cache expired for {}", cache_key);
            return Ok(None);
        }

        // Try to get cached content
        match self.storage.get(cache_key).await {
            Ok(content) => {
                // Verify checksum
                let actual_checksum = StorageService::calculate_hash(&content);
                if actual_checksum != metadata.checksum_sha256 {
                    tracing::warn!(
                        "Cache checksum mismatch for {}: expected {}, got {}",
                        cache_key,
                        metadata.checksum_sha256,
                        actual_checksum
                    );
                    return Ok(None);
                }

                tracing::debug!("Cache hit for {}", cache_key);
                Ok(Some((content, metadata.content_type)))
            }
            Err(AppError::NotFound(_)) => Ok(None),
            // B6 (coalescing 502 leak): a transient storage read error here
            // (e.g. a waiter reading the cache body while the single-flight
            // leader is mid-write, or a partially-written / poisoned entry)
            // must NOT bubble out as a raw 502 to every concurrent waiter.
            // Treat it as a cache miss so the caller re-fetches upstream; the
            // upstream path then surfaces a clean 2xx (cache repopulated) or a
            // 503 via `validate_upstream_status` when upstream itself is the
            // one failing. Surfacing the read error as `Err(e)` made it
            // `map_proxy_error` -> 502, which is exactly the raw status the
            // stampede gate rejects.
            Err(e) => {
                tracing::warn!(
                    cache_key = %cache_key,
                    error = %e,
                    "proxy cache read failed; treating as miss and refetching upstream"
                );
                Ok(None)
            }
        }
    }

    /// Load cache metadata from storage
    async fn load_cache_metadata(&self, metadata_key: &str) -> Result<Option<CacheMetadata>> {
        match self.storage.get(metadata_key).await {
            Ok(data) => {
                let metadata: CacheMetadata = serde_json::from_slice(&data)?;
                Ok(Some(metadata))
            }
            Err(AppError::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Fetch artifact from upstream URL.
    ///
    /// Handles OCI registry bearer token exchange: when the upstream returns
    /// 401 with a `WWW-Authenticate: Bearer` challenge, the service requests
    /// a token from the indicated realm and retries the request. Tokens are
    /// cached in memory with their advertised TTL so subsequent requests to
    /// the same registry/scope don't repeat the exchange.
    async fn fetch_from_upstream(&self, url: &str, repo_id: Uuid) -> Result<UpstreamResponse> {
        self.fetch_from_upstream_with_accept(url, repo_id, None)
            .await
    }

    /// Variant of [`Self::fetch_from_upstream`] that adds an `Accept` header
    /// to both the initial request and the post-token-exchange retry.
    ///
    /// OCI manifest fetches need this so the upstream registry returns the
    /// content type the caller actually understands. Without an `Accept`
    /// header Docker Hub picks a default representation (typically the
    /// OCI image index for multi-arch images) but other registries respond
    /// with 404 / 406 / a legacy v1 manifest the client cannot consume.
    /// Mirroring the client's `Accept` upstream removes that source of
    /// silent content-type mismatches and the spurious 404s they trigger.
    async fn fetch_from_upstream_with_accept(
        &self,
        url: &str,
        repo_id: Uuid,
        accept: Option<&str>,
    ) -> Result<UpstreamResponse> {
        tracing::info!(
            "Fetching artifact from upstream: {} (accept={:?})",
            url,
            accept
        );

        let upstream_auth =
            crate::services::upstream_auth::load_upstream_auth(&self.db, repo_id).await?;

        let mut request = self.http_client.get(url);
        if let Some(ref auth) = upstream_auth {
            request = crate::services::upstream_auth::apply_upstream_auth(request, auth);
        }
        if let Some(accept_value) = accept {
            request = request.header(ACCEPT, accept_value);
        }

        let response = request
            .send()
            .await
            .map_err(|e| AppError::Storage(format!("Failed to fetch from upstream: {}", e)))?;

        let status = response.status();

        // Handle 401 with bearer token exchange (required by Docker Hub and
        // other OCI registries, even for anonymous/public pulls).
        if status == StatusCode::UNAUTHORIZED {
            let challenge = response
                .headers()
                .get(WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            if challenge.starts_with("Bearer ") {
                let params = Self::parse_bearer_challenge(&challenge);
                if let Some(realm) = params.get("realm") {
                    let scope = params.get("scope").cloned().unwrap_or_default();
                    let service = params.get("service").cloned().unwrap_or_default();

                    // Validate the realm URL against SSRF rules before making
                    // any outbound request. A malicious upstream could set
                    // realm to an internal address.
                    crate::api::validation::validate_outbound_url(realm, "OCI token realm")?;

                    let token = self
                        .obtain_bearer_token(realm, &service, &scope, &upstream_auth)
                        .await?;

                    // Retry with the bearer token only. The original upstream
                    // Basic credentials were already forwarded to the token
                    // endpoint in obtain_bearer_token(); adding them here
                    // would produce two Authorization headers.
                    let mut retry_request = self.http_client.get(url).bearer_auth(&token);
                    if let Some(accept_value) = accept {
                        retry_request = retry_request.header(ACCEPT, accept_value);
                    }

                    let retry_response = retry_request.send().await.map_err(|e| {
                        AppError::Storage(format!(
                            "Failed to fetch from upstream after token exchange: {}",
                            e
                        ))
                    })?;

                    return Self::read_upstream_response(retry_response, url).await;
                }
            }

            return Err(AppError::Storage(format!(
                "Upstream returned error status {}: {}",
                status, url
            )));
        }

        Self::read_upstream_response(response, url).await
    }

    /// Extract content, content-type, etag, effective URL, and Link header from
    /// an upstream HTTP response. Callers are responsible for handling 401 before
    /// invoking.
    async fn read_upstream_response(
        response: reqwest::Response,
        url: &str,
    ) -> Result<UpstreamResponse> {
        let status = response.status();
        let effective_url = response.url().to_string();

        // Centralise the 404/4xx/5xx classification through
        // `validate_upstream_status` (#1445) so the buffered fetch path
        // gets the same 5xx -> ServiceUnavailable mapping the streaming
        // path does. Previously this inlined a "non-2xx -> Storage" rule
        // that surfaced raw upstream 502/503/504 to clients as 502.
        validate_upstream_status(status, url)?;

        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let etag = response
            .headers()
            .get(ETAG)
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let link = response
            .headers()
            .get("link")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let content = response
            .bytes()
            .await
            .map_err(|e| AppError::Storage(format!("Failed to read upstream response: {}", e)))?;

        tracing::info!(
            "Fetched {} bytes from upstream (content_type: {:?}, etag: {:?}, link: {:?})",
            content.len(),
            content_type,
            etag,
            link
        );

        Ok(UpstreamResponse {
            content,
            content_type,
            etag,
            effective_url,
            link,
        })
    }

    /// Streaming variant of [`Self::fetch_from_upstream`] used by the
    /// proxy slow path (#895). Returns the upstream body as a stream of
    /// `Bytes` chunks instead of buffering the whole body into memory.
    /// Used by the OOM-mitigation path that tees the upstream stream
    /// simultaneously to the client and to the storage cache.
    ///
    /// Auth handling (Basic + OCI bearer token exchange) mirrors the
    /// buffered variant; only the body extraction differs.
    async fn fetch_from_upstream_streaming(
        &self,
        url: &str,
        repo_id: Uuid,
    ) -> Result<UpstreamStream> {
        tracing::info!("Fetching artifact from upstream (streaming): {}", url);

        let upstream_auth =
            crate::services::upstream_auth::load_upstream_auth(&self.db, repo_id).await?;

        let mut request = self.http_client.get(url);
        if let Some(ref auth) = upstream_auth {
            request = crate::services::upstream_auth::apply_upstream_auth(request, auth);
        }

        let response = request
            .send()
            .await
            .map_err(|e| AppError::Storage(format!("Failed to fetch from upstream: {}", e)))?;

        let status = response.status();

        if status == StatusCode::UNAUTHORIZED {
            let challenge = response
                .headers()
                .get(WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            if challenge.starts_with("Bearer ") {
                let params = Self::parse_bearer_challenge(&challenge);
                if let Some(realm) = params.get("realm") {
                    let scope = params.get("scope").cloned().unwrap_or_default();
                    let service = params.get("service").cloned().unwrap_or_default();
                    crate::api::validation::validate_outbound_url(realm, "OCI token realm")?;
                    let token = self
                        .obtain_bearer_token(realm, &service, &scope, &upstream_auth)
                        .await?;
                    let retry_request = self.http_client.get(url).bearer_auth(&token);
                    let retry_response = retry_request.send().await.map_err(|e| {
                        AppError::Storage(format!(
                            "Failed to fetch from upstream after token exchange: {}",
                            e
                        ))
                    })?;
                    return Self::read_upstream_response_streaming(retry_response, url);
                }
            }

            return Err(AppError::Storage(format!(
                "Upstream returned error status {}: {}",
                status, url
            )));
        }

        Self::read_upstream_response_streaming(response, url)
    }

    /// Stream the upstream HTTP response body without buffering. Mirrors
    /// the shape of [`Self::read_upstream_response`] but returns the body
    /// as a stream. Status/header validation happens up front; the
    /// stream itself yields one [`Bytes`] chunk per `reqwest` body
    /// frame.
    fn read_upstream_response_streaming(
        response: reqwest::Response,
        url: &str,
    ) -> Result<UpstreamStream> {
        validate_upstream_status(response.status(), url)?;
        let (content_type, etag, content_length) = extract_streaming_headers(response.headers());

        let body = response.bytes_stream().map(|r| {
            r.map_err(|e| AppError::Storage(format!("Failed to read upstream stream: {}", e)))
        });

        Ok(UpstreamStream {
            body: Box::pin(body),
            content_type,
            etag,
            content_length,
        })
    }

    /// Obtain a bearer token for an OCI registry, using the in-memory cache
    /// when possible.
    async fn obtain_bearer_token(
        &self,
        realm: &str,
        service: &str,
        scope: &str,
        upstream_auth: &Option<crate::services::upstream_auth::UpstreamAuthType>,
    ) -> Result<String> {
        let cache_key = format!("{}\0{}\0{}", realm, service, scope);

        if let Some(token) = self.get_cached_token(&cache_key).await {
            return Ok(token);
        }

        // Build token request URL with query parameters.
        let token_url = {
            let mut parts = Vec::new();
            if !service.is_empty() {
                parts.push(format!("service={}", urlencoding::encode(service)));
            }
            if !scope.is_empty() {
                parts.push(format!("scope={}", urlencoding::encode(scope)));
            }
            if parts.is_empty() {
                realm.to_string()
            } else {
                let sep = if realm.contains('?') { "&" } else { "?" };
                format!("{}{}{}", realm, sep, parts.join("&"))
            }
        };
        let mut token_request = self.http_client.get(&token_url);

        // Forward configured Basic credentials for private registries.
        if let Some(crate::services::upstream_auth::UpstreamAuthType::Basic {
            username,
            password,
        }) = upstream_auth
        {
            token_request = token_request.basic_auth(username, Some(password));
        }

        tracing::debug!("Requesting bearer token from {} (scope={})", realm, scope);

        let token_response = token_request.send().await.map_err(|e| {
            AppError::Storage(format!(
                "Failed to request bearer token from {}: {}",
                realm, e
            ))
        })?;

        if !token_response.status().is_success() {
            return Err(AppError::Storage(format!(
                "Token endpoint {} returned status {}",
                realm,
                token_response.status()
            )));
        }

        let body: RegistryTokenResponse = token_response.json().await.map_err(|e| {
            AppError::Storage(format!(
                "Failed to parse token response from {}: {}",
                realm, e
            ))
        })?;

        let token = body
            .token
            .or(body.access_token)
            .ok_or_else(|| AppError::Storage("Token endpoint returned no token".to_string()))?;

        // Cap TTL to prevent overflow and unreasonably long cache entries.
        let ttl = body
            .expires_in
            .unwrap_or(DEFAULT_TOKEN_TTL_SECS)
            .min(MAX_TOKEN_TTL_SECS);

        // Cache the token, evicting expired entries to prevent unbounded growth.
        {
            let mut cache = self.token_cache.write().await;
            cache.retain(|_, (_, created_at, entry_ttl)| {
                created_at.elapsed() < Duration::from_secs(*entry_ttl)
            });
            cache.insert(cache_key, (token.clone(), Instant::now(), ttl));
        }

        Ok(token)
    }

    /// Return a cached bearer token if present and not expired.
    async fn get_cached_token(&self, cache_key: &str) -> Option<String> {
        let cache = self.token_cache.read().await;
        let (token, created_at, ttl_secs) = cache.get(cache_key)?;
        if created_at.elapsed() < Duration::from_secs(ttl_secs.saturating_mul(9) / 10) {
            Some(token.clone())
        } else {
            None
        }
    }

    /// Parse a `WWW-Authenticate: Bearer realm="...",service="...",scope="..."`
    /// header into a map of key-value pairs.
    fn parse_bearer_challenge(header: &str) -> HashMap<String, String> {
        let mut params = HashMap::new();
        let bearer_params = match header.strip_prefix("Bearer ") {
            Some(p) => p,
            None => return params,
        };

        let mut remaining = bearer_params.trim();
        while !remaining.is_empty() {
            let eq_pos = match remaining.find('=') {
                Some(p) => p,
                None => break,
            };
            let key = remaining[..eq_pos].trim().to_lowercase();
            remaining = remaining[eq_pos + 1..].trim();

            let value;
            if remaining.starts_with('"') {
                remaining = &remaining[1..];
                let end = remaining.find('"').unwrap_or(remaining.len());
                value = remaining[..end].to_string();
                remaining = if end + 1 < remaining.len() {
                    remaining[end + 1..].trim_start_matches(',').trim()
                } else {
                    ""
                };
            } else {
                let end = remaining.find(',').unwrap_or(remaining.len());
                value = remaining[..end].trim().to_string();
                remaining = if end < remaining.len() {
                    remaining[end + 1..].trim()
                } else {
                    ""
                };
            }

            params.insert(key, value);
        }

        params
    }

    /// Cache artifact content and metadata, and record the artifact in the
    /// database so that it appears in repository listings and storage usage.
    #[allow(clippy::too_many_arguments)]
    async fn cache_artifact(
        &self,
        cache_key: &str,
        metadata_key: &str,
        content: &Bytes,
        content_type: Option<String>,
        etag: Option<String>,
        ttl_secs: i64,
        repository_id: Uuid,
        artifact_path: &str,
    ) -> Result<()> {
        // Calculate checksum
        let checksum = StorageService::calculate_hash(content);

        // Store content first so we can read the backend's ETag back for
        // the integrity-revalidation pin (#1051).
        self.storage.put(cache_key, content.clone()).await?;

        // Best-effort: capture the backend's ETag right after the PUT so
        // the fast path can re-HEAD on each hit and reject tampered or
        // replaced objects. See [`pin_storage_etag`] for the failure
        // semantics; a failure here only disables revalidation for this
        // entry, the cache write itself still succeeds.
        let storage_etag = pin_storage_etag(&self.storage, cache_key).await;

        // Create metadata
        let now = Utc::now();
        let metadata = CacheMetadata {
            cached_at: now,
            upstream_etag: etag,
            storage_etag,
            expires_at: now + chrono::Duration::seconds(ttl_secs),
            content_type,
            size_bytes: content.len() as i64,
            checksum_sha256: checksum.clone(),
        };

        // Store metadata
        let metadata_json = serde_json::to_vec(&metadata)?;
        self.storage
            .put(metadata_key, Bytes::from(metadata_json))
            .await?;

        // Proxy-cached content is intentionally NOT recorded in the
        // `artifacts` table (issue #1278). The previous behaviour inserted
        // a row with `storage_key = "proxy-cache/<repo_key>/<path>/__content__"`
        // alongside the global-backend write above, which caused every
        // subsequent format-handler read to take the
        // `state.storage_for_repo(repo.storage_location()).get(&artifact.storage_key)`
        // path -- a per-repo `FilesystemStorage` rooted at
        // `repo.storage_path` that resolves to a doubled-prefix path
        // (`<repo.storage_path>/proxy-cache/<repo_key>/...`) and returned
        // `NotFound` (HTTP 500) on every cache hit after the first. S3 /
        // object-store backends were unaffected because their registry
        // shares the same instance regardless of `location.path`.
        //
        // The cached body and metadata sidecar are still on disk under
        // `self.storage` (the global default). The format-handler hot path
        // already checks the proxy cache via `proxy_check_cache`
        // (`get_cached_artifact_by_path` -> `self.storage.get`) BEFORE
        // falling through to the upstream fetch, so cache hits are served
        // through that path with no `artifacts` row needed. Reads through
        // the global backend match the writes above.
        //
        // Tradeoff: proxy-cached items no longer surface in the
        // repository `GET /api/v1/repositories/{key}/artifacts` listing or
        // counted toward `storage_used_bytes`. That UX/accounting gap is
        // tracked separately; correctness (no more 500s on cached reads)
        // is the immediate fix for v1.2.0-rc.2. Existing rows from prior
        // versions stay in `artifacts` and continue to surface in
        // listings until they are explicitly invalidated, which is a
        // graceful degradation, not a regression.
        let _ = repository_id;
        let _ = artifact_path;
        let _ = checksum;

        tracing::debug!(
            "Cached artifact {} ({} bytes, expires at {})",
            cache_key,
            content.len(),
            metadata.expires_at
        );

        Ok(())
    }

    /// Attempt to retrieve a cached artifact even if it has expired.
    /// Used as a fallback when upstream is unavailable.
    async fn get_stale_cached_artifact(
        &self,
        cache_key: &str,
        metadata_key: &str,
    ) -> Result<Option<(Bytes, Option<String>)>> {
        // Load metadata without checking expiry
        let metadata = match self.load_cache_metadata(metadata_key).await? {
            Some(m) => m,
            None => return Ok(None),
        };

        // Try to get cached content
        match self.storage.get(cache_key).await {
            Ok(content) => {
                // Verify checksum
                let actual_checksum = StorageService::calculate_hash(&content);
                if actual_checksum != metadata.checksum_sha256 {
                    tracing::warn!(
                        "Stale cache checksum mismatch for {}: expected {}, got {}",
                        cache_key,
                        metadata.checksum_sha256,
                        actual_checksum
                    );
                    return Ok(None);
                }

                tracing::debug!(
                    "Stale cache hit for {} (expired at {})",
                    cache_key,
                    metadata.expires_at
                );
                Ok(Some((content, metadata.content_type)))
            }
            Err(AppError::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Check if upstream ETag has changed (returns true if changed/newer)
    async fn check_etag_changed(
        &self,
        url: &str,
        cached_etag: &str,
        repo_id: Uuid,
    ) -> Result<bool> {
        let upstream_auth =
            crate::services::upstream_auth::load_upstream_auth(&self.db, repo_id).await?;

        let mut request = self
            .http_client
            .head(url)
            .header(IF_NONE_MATCH, cached_etag);
        if let Some(ref auth) = upstream_auth {
            request = crate::services::upstream_auth::apply_upstream_auth(request, auth);
        }

        let response = request.send().await.map_err(|e| {
            AppError::Storage(format!("Failed to check upstream for changes: {}", e))
        })?;

        match response.status() {
            StatusCode::NOT_MODIFIED => {
                tracing::debug!("Upstream unchanged (304 Not Modified) for {}", url);
                Ok(false)
            }
            StatusCode::OK => {
                // Check if ETag in response differs
                let new_etag = response.headers().get(ETAG).and_then(|v| v.to_str().ok());

                match new_etag {
                    Some(etag) if etag == cached_etag => {
                        tracing::debug!("Upstream ETag unchanged for {}", url);
                        Ok(false)
                    }
                    _ => {
                        tracing::debug!("Upstream has newer content for {}", url);
                        Ok(true)
                    }
                }
            }
            StatusCode::UNAUTHORIZED => {
                // OCI registries require bearer token exchange even for HEAD
                // requests. Rather than duplicating the token exchange here,
                // treat this as "needs re-fetch" and let fetch_from_upstream
                // handle the full 401 flow on the next access.
                tracing::debug!(
                    "Upstream returned 401 for ETag check on {}, will re-fetch with token exchange",
                    url
                );
                Ok(true)
            }
            status => {
                tracing::warn!(
                    "Unexpected status {} checking upstream {}, assuming changed",
                    status,
                    url
                );
                Ok(true)
            }
        }
    }
}

/// Extract version from an artifact path based on the repository format.
///
/// Each package format encodes the version differently in the path. This
/// function delegates to format-specific parsing logic and returns `None`
/// for metadata files, index pages, or paths where the version cannot be
/// determined.
///
/// Currently unused: the previous caller in `cache_artifact` was removed
/// when proxy-cached items stopped being inserted into the `artifacts`
/// table (issue #1278). Kept around because the version-extraction logic
/// is broadly useful and tests still exercise it; if a future cache
/// listing/UX feature wants per-version metadata it should call this.
#[allow(dead_code)]
pub(crate) fn extract_version_from_path(format: &RepositoryFormat, path: &str) -> Option<String> {
    let path = path.trim_start_matches('/');

    match format {
        // Maven: groupId/.../artifactId/version/filename
        RepositoryFormat::Maven | RepositoryFormat::Gradle | RepositoryFormat::Sbt => {
            crate::formats::maven::MavenHandler::parse_coordinates(path)
                .ok()
                .map(|c| c.version)
        }

        // NPM: @scope/name/-/name-version.tgz or name/-/name-version.tgz
        RepositoryFormat::Npm
        | RepositoryFormat::Yarn
        | RepositoryFormat::Bower
        | RepositoryFormat::Pnpm => crate::formats::npm::NpmHandler::parse_path(path)
            .ok()
            .and_then(|info| info.version),

        // PyPI: simple/name/ (index) or packages/name/version/filename
        RepositoryFormat::Pypi | RepositoryFormat::Poetry | RepositoryFormat::Conda => {
            crate::formats::pypi::PypiHandler::parse_path(path)
                .ok()
                .and_then(|info| info.version)
        }

        // NuGet: v3/flatcontainer/name/version/name.version.nupkg
        RepositoryFormat::Nuget | RepositoryFormat::Chocolatey | RepositoryFormat::Powershell => {
            crate::formats::nuget::NugetHandler::parse_path(path)
                .ok()
                .and_then(|info| info.version)
        }

        // Cargo: crates/name/name-version.crate or api/v1/crates/name/version/download
        RepositoryFormat::Cargo => crate::formats::cargo::CargoHandler::parse_path(path)
            .ok()
            .and_then(|info| info.version),

        // Go: module/@v/version.info|.mod|.zip
        RepositoryFormat::Go => crate::formats::go::GoHandler::parse_path(path)
            .ok()
            .and_then(|info| info.version),

        // OCI/Docker formats: version is conveyed via tags/digests in the
        // registry protocol, not in the URL path, so return None.
        RepositoryFormat::Docker
        | RepositoryFormat::Podman
        | RepositoryFormat::Buildx
        | RepositoryFormat::Oras
        | RepositoryFormat::WasmOci
        | RepositoryFormat::HelmOci
        | RepositoryFormat::Incus
        | RepositoryFormat::Lxc => None,

        // Generic fallback: try name/version/filename pattern
        _ => {
            let parts: Vec<&str> = path.split('/').collect();
            if parts.len() >= 3 {
                Some(parts[parts.len() - 2].to_string())
            } else {
                None
            }
        }
    }
}

/// Build response headers indicating the content was served from a stale cache.
/// Returns headers with `X-Cache: STALE` and an RFC 7234 Warning 110 header.
/// Currently used by tests; HTTP handlers will integrate this in a follow-up.
#[allow(dead_code)]
pub(crate) fn build_stale_cache_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("X-Cache".to_string(), "STALE".to_string());
    headers.insert(
        "Warning".to_string(),
        "110 artifact-keeper \"Response is stale\"".to_string(),
    );
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Pure helper functions (moved from module scope — test-only)
    // -----------------------------------------------------------------------

    fn is_cache_expired(expires_at: &DateTime<Utc>) -> bool {
        Utc::now() > *expires_at
    }

    fn compute_cache_expiry(cached_at: DateTime<Utc>, ttl_secs: i64) -> DateTime<Utc> {
        cached_at + chrono::Duration::seconds(ttl_secs)
    }

    fn parse_cache_ttl(value: Option<&str>) -> i64 {
        value
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_CACHE_TTL_SECS)
    }

    // =======================================================================
    // build_upstream_url tests
    // =======================================================================

    #[test]
    fn test_build_upstream_url() {
        // Test basic URL building
        assert_eq!(
            ProxyService::build_upstream_url("https://repo.maven.apache.org/maven2", "org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar"),
            "https://repo.maven.apache.org/maven2/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar"
        );

        // Test with trailing slash on base
        assert_eq!(
            ProxyService::build_upstream_url("https://registry.npmjs.org/", "express"),
            "https://registry.npmjs.org/express"
        );

        // Test with leading slash on path
        assert_eq!(
            ProxyService::build_upstream_url("https://example.com", "/path/to/artifact"),
            "https://example.com/path/to/artifact"
        );
    }

    #[test]
    fn test_build_upstream_url_both_slashes() {
        // Both trailing slash on base and leading slash on path
        assert_eq!(
            ProxyService::build_upstream_url("https://example.com/", "/path"),
            "https://example.com/path"
        );
    }

    #[test]
    fn test_build_upstream_url_no_slashes() {
        assert_eq!(
            ProxyService::build_upstream_url("https://example.com", "path"),
            "https://example.com/path"
        );
    }

    #[test]
    fn test_build_upstream_url_multiple_trailing_slashes() {
        // trim_end_matches removes all matching trailing characters
        assert_eq!(
            ProxyService::build_upstream_url("https://example.com///", "path"),
            "https://example.com/path"
        );
    }

    #[test]
    fn test_build_upstream_url_multiple_leading_slashes() {
        // trim_start_matches removes all matching leading characters
        assert_eq!(
            ProxyService::build_upstream_url("https://example.com", "///path"),
            "https://example.com/path"
        );
    }

    #[test]
    fn test_build_upstream_url_empty_path() {
        assert_eq!(
            ProxyService::build_upstream_url("https://example.com", ""),
            "https://example.com/"
        );
    }

    #[test]
    fn test_build_upstream_url_complex_path_with_query() {
        // URL construction does not strip query strings
        assert_eq!(
            ProxyService::build_upstream_url(
                "https://registry.npmjs.org",
                "@scope/package/-/package-1.0.0.tgz"
            ),
            "https://registry.npmjs.org/@scope/package/-/package-1.0.0.tgz"
        );
    }

    #[test]
    fn test_build_upstream_url_absolute_https_path() {
        // Absolute https URL is returned unchanged regardless of base
        assert_eq!(
            ProxyService::build_upstream_url(
                "https://charts.bitnami.com/bitnami",
                "https://github.com/bitnami/charts/releases/download/nginx-1.0.0/nginx-1.0.0.tgz"
            ),
            "https://github.com/bitnami/charts/releases/download/nginx-1.0.0/nginx-1.0.0.tgz"
        );
    }

    #[test]
    fn test_build_upstream_url_absolute_http_path() {
        assert_eq!(
            ProxyService::build_upstream_url(
                "https://example.com",
                "http://other.example.com/chart-1.0.0.tgz"
            ),
            "http://other.example.com/chart-1.0.0.tgz"
        );
    }

    #[test]
    fn test_build_upstream_url_absolute_same_origin() {
        // Absolute URL with the same origin is still returned as-is
        assert_eq!(
            ProxyService::build_upstream_url(
                "https://charts.jetstack.io",
                "https://charts.jetstack.io/charts/cert-manager-v1.14.0.tgz"
            ),
            "https://charts.jetstack.io/charts/cert-manager-v1.14.0.tgz"
        );
    }

    #[test]
    fn test_build_upstream_url_pypi_path() {
        assert_eq!(
            ProxyService::build_upstream_url("https://pypi.org/simple", "requests/"),
            "https://pypi.org/simple/requests/"
        );
    }

    #[test]
    fn test_build_upstream_url_with_port() {
        assert_eq!(
            ProxyService::build_upstream_url(
                "http://localhost:8080/v2",
                "library/alpine/manifests/latest"
            ),
            "http://localhost:8080/v2/library/alpine/manifests/latest"
        );
    }

    // =======================================================================
    // cache_storage_key tests
    // =======================================================================

    #[test]
    fn test_cache_storage_key() {
        assert_eq!(
            ProxyService::cache_storage_key("maven-central", "org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar").unwrap(),
            "proxy-cache/maven-central/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar/__content__"
        );
    }

    #[test]
    fn test_cache_storage_key_strips_leading_slash() {
        assert_eq!(
            ProxyService::cache_storage_key("npm-proxy", "/express").unwrap(),
            "proxy-cache/npm-proxy/express/__content__"
        );
    }

    #[test]
    fn test_cache_storage_key_no_leading_slash() {
        assert_eq!(
            ProxyService::cache_storage_key("npm-proxy", "express").unwrap(),
            "proxy-cache/npm-proxy/express/__content__"
        );
    }

    #[test]
    fn test_cache_storage_key_scoped_npm_package() {
        assert_eq!(
            ProxyService::cache_storage_key("npm-proxy", "@types/node/-/node-18.0.0.tgz").unwrap(),
            "proxy-cache/npm-proxy/@types/node/-/node-18.0.0.tgz/__content__"
        );
    }

    /// #1445 (C): scoped npm tarball remote-proxy round-trip.
    ///
    /// The npm handler builds the upstream path as
    /// `@scope%2Fpkg/-/{filename}` (with the scope separator percent-
    /// encoded) and passes the SAME string as both the upstream fetch
    /// path AND the proxy-cache path. The cache key derived from that
    /// path MUST be byte-identical between write and read, otherwise a
    /// cached tarball is invisible to the next request and every fetch
    /// re-hits upstream, exactly the "scoped tarball through remote
    /// proxy fails" symptom in #1445(C).
    ///
    /// This test pins the key formula so a future "normalize the cache
    /// path before storing" refactor cannot silently regress.
    #[test]
    fn test_cache_storage_key_scoped_npm_encoded_path_round_trip() {
        // Path as the npm handler constructs it (encode_package_name_for_upstream).
        let encoded_path = "@e2escope%2Ftestpkg/-/testpkg-1.0.0.tgz";

        let write_key = ProxyService::cache_storage_key("npm-proxy", encoded_path)
            .expect("encoded scoped path must derive a cache key");
        let read_key = ProxyService::cache_storage_key("npm-proxy", encoded_path)
            .expect("encoded scoped path must derive a cache key on read");

        assert_eq!(
            write_key, read_key,
            "scoped npm cache key MUST be deterministic so cached \
             tarballs survive the next request (#1445C)"
        );
        assert_eq!(
            write_key, "proxy-cache/npm-proxy/@e2escope%2Ftestpkg/-/testpkg-1.0.0.tgz/__content__",
            "scoped npm cache key MUST preserve the %2F-encoded scope \
             separator verbatim. The upstream fetch path uses the same \
             string, and any normalisation here would desync the two."
        );

        // The matching metadata key must round-trip too, otherwise the
        // freshness probe and the content lookup land in different
        // storage namespaces.
        let meta_key = ProxyService::cache_metadata_key("npm-proxy", encoded_path)
            .expect("encoded scoped path must derive a metadata key");
        assert_eq!(
            meta_key,
            "proxy-cache/npm-proxy/@e2escope%2Ftestpkg/-/testpkg-1.0.0.tgz/__cache_meta__.json"
        );
    }

    #[test]
    fn test_cache_storage_key_deeply_nested_path() {
        let key = ProxyService::cache_storage_key(
            "maven",
            "com/example/group/artifact/1.0/artifact-1.0.pom",
        )
        .unwrap();
        assert!(key.starts_with("proxy-cache/maven/"));
        assert!(key.ends_with("/__content__"));
    }

    // =======================================================================
    // cache_metadata_key tests
    // =======================================================================

    #[test]
    fn test_cache_metadata_key() {
        assert_eq!(
            ProxyService::cache_metadata_key("npm-registry", "express").unwrap(),
            "proxy-cache/npm-registry/express/__cache_meta__.json"
        );
    }

    #[test]
    fn test_cache_metadata_key_strips_leading_slash() {
        assert_eq!(
            ProxyService::cache_metadata_key("repo", "/some/path").unwrap(),
            "proxy-cache/repo/some/path/__cache_meta__.json"
        );
    }

    #[test]
    fn test_cache_metadata_key_strips_trailing_slash() {
        assert_eq!(
            ProxyService::cache_metadata_key("pypi-remote", "simple/numpy/").unwrap(),
            "proxy-cache/pypi-remote/simple/numpy/__cache_meta__.json"
        );
    }

    #[test]
    fn test_cache_storage_key_strips_trailing_slash() {
        assert_eq!(
            ProxyService::cache_storage_key("pypi-remote", "simple/numpy/").unwrap(),
            "proxy-cache/pypi-remote/simple/numpy/__content__"
        );
    }

    #[test]
    fn test_cache_keys_strip_both_slashes() {
        assert_eq!(
            ProxyService::cache_metadata_key("pypi-remote", "/simple/numpy/").unwrap(),
            "proxy-cache/pypi-remote/simple/numpy/__cache_meta__.json"
        );
        assert_eq!(
            ProxyService::cache_storage_key("pypi-remote", "/simple/numpy/").unwrap(),
            "proxy-cache/pypi-remote/simple/numpy/__content__"
        );
    }

    #[test]
    fn test_cache_metadata_key_consistency_with_storage_key() {
        // Both keys should share the same prefix structure
        let repo_key = "npm-proxy";
        let path = "lodash";
        let storage_key = ProxyService::cache_storage_key(repo_key, path).unwrap();
        let metadata_key = ProxyService::cache_metadata_key(repo_key, path).unwrap();

        // Both start with the same prefix
        let storage_prefix = storage_key.rsplit_once('/').unwrap().0;
        let metadata_prefix = metadata_key.rsplit_once('/').unwrap().0;
        assert_eq!(storage_prefix, metadata_prefix);

        // But have different leaf file names
        assert!(storage_key.ends_with("__content__"));
        assert!(metadata_key.ends_with("__cache_meta__.json"));
    }

    // =======================================================================
    // Cache key collision tests
    // =======================================================================

    #[test]
    fn test_cache_keys_no_file_directory_collision() {
        // Metadata cached at "is-odd" and tarball at "is-odd/-/is-odd-3.0.1.tgz"
        // must not collide (one as file, other needing it as directory)
        let meta_key = ProxyService::cache_storage_key("npm-proxy", "is-odd").unwrap();
        let tarball_key =
            ProxyService::cache_storage_key("npm-proxy", "is-odd/-/is-odd-3.0.1.tgz").unwrap();

        // Both should be inside the "is-odd" directory, not at the same level
        assert!(meta_key.contains("is-odd/__content__"));
        assert!(tarball_key.contains("is-odd/-/is-odd-3.0.1.tgz/__content__"));
    }

    #[test]
    fn test_cache_keys_different_repos_do_not_collide() {
        let key1 = ProxyService::cache_storage_key("npm-proxy-1", "express").unwrap();
        let key2 = ProxyService::cache_storage_key("npm-proxy-2", "express").unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_cache_keys_different_paths_do_not_collide() {
        let key1 = ProxyService::cache_storage_key("repo", "path/a").unwrap();
        let key2 = ProxyService::cache_storage_key("repo", "path/b").unwrap();
        assert_ne!(key1, key2);
    }

    // =======================================================================
    // Cache-key length cap tests (#1044)
    //
    // S3/Azure/GCS all reject object keys longer than 1024 bytes. The
    // helpers must surface a clean Validation error rather than letting
    // an over-long key escape and trip the storage backend mid-fetch.
    // =======================================================================

    #[test]
    fn test_cache_storage_key_just_under_limit_succeeds() {
        // Pick a path length that lands the metadata key (worst case)
        // exactly at MAX_STORAGE_KEY_BYTES. Both helpers should accept it.
        // metadata key = "proxy-cache/" (12) + repo + "/" (1) + path + "/" (1)
        //               + "__cache_meta__.json" (19)
        let repo = "r";
        let fixed = 12 + repo.len() + 1 + 1 + 19;
        let path_len = ProxyService::MAX_STORAGE_KEY_BYTES - fixed;
        let path = "a".repeat(path_len);

        let storage_key = ProxyService::cache_storage_key(repo, &path)
            .expect("storage key just under limit should succeed");
        let metadata_key = ProxyService::cache_metadata_key(repo, &path)
            .expect("metadata key just under limit should succeed");

        assert_eq!(metadata_key.len(), ProxyService::MAX_STORAGE_KEY_BYTES);
        assert!(storage_key.len() <= ProxyService::MAX_STORAGE_KEY_BYTES);
    }

    #[test]
    fn test_cache_storage_key_just_over_limit_returns_validation() {
        // Path long enough that even the smaller-suffix storage key
        // would overflow 1024 bytes. Both helpers must reject.
        let repo = "r";
        // storage key fixed bytes: 12 + repo + "/" + "/" + 11 (__content__).
        let storage_fixed = 12 + repo.len() + 1 + 1 + 11;
        let path_len = ProxyService::MAX_STORAGE_KEY_BYTES - storage_fixed + 1;
        let path = "a".repeat(path_len);

        let storage_result = ProxyService::cache_storage_key(repo, &path);
        let metadata_result = ProxyService::cache_metadata_key(repo, &path);

        assert!(matches!(storage_result, Err(AppError::Validation(_))));
        assert!(matches!(metadata_result, Err(AppError::Validation(_))));
    }

    #[test]
    fn test_cache_storage_key_rejects_when_only_metadata_overflows() {
        // Construct a path where the storage-suffix key (`__content__`,
        // 11 bytes) would fit in 1024 but the metadata-suffix key
        // (`__cache_meta__.json`, 19 bytes) would not. Both helpers must
        // reject so callers cannot enter a state where storage is
        // writable but metadata is not.
        let repo = "r";
        // storage-only fixed bytes: 12 + repo + "/" + "/" + 11 (__content__) = 26
        let storage_fixed = 12 + repo.len() + 1 + 1 + 11;
        // Pick a path length that fits the storage variant but is 1 byte
        // too long for the metadata variant (which has an 8-byte longer
        // suffix). Any value in [MAX-storage_fixed-7, MAX-storage_fixed]
        // works; pick the largest legal storage length.
        let path_len = ProxyService::MAX_STORAGE_KEY_BYTES - storage_fixed;
        let path = "a".repeat(path_len);

        // Sanity: the storage key alone fits.
        let direct_storage_len = storage_fixed + path.len();
        assert_eq!(direct_storage_len, ProxyService::MAX_STORAGE_KEY_BYTES);

        // But the metadata variant overflows by 8 bytes (suffix delta),
        // and the helper rejects both because we measure against the
        // worst-case suffix.
        let storage_result = ProxyService::cache_storage_key(repo, &path);
        let metadata_result = ProxyService::cache_metadata_key(repo, &path);

        assert!(matches!(storage_result, Err(AppError::Validation(_))));
        assert!(matches!(metadata_result, Err(AppError::Validation(_))));
    }

    // =======================================================================
    // Path traversal / sanitization tests (#1052)
    // =======================================================================

    #[test]
    fn test_cache_storage_key_rejects_dotdot_segment() {
        // `../foo` would escape the proxy-cache/<repo>/ namespace.
        let result = ProxyService::cache_storage_key("npm-proxy", "../etc/passwd");
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    #[test]
    fn test_cache_storage_key_rejects_dotdot_in_middle() {
        // `foo/../bar` escapes one level even though there is a leading
        // legitimate segment.
        let result = ProxyService::cache_storage_key("npm-proxy", "express/../lodash");
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    #[test]
    fn test_cache_storage_key_rejects_dot_segment() {
        // `.` is a no-op on filesystems but ambiguous to object stores.
        let result = ProxyService::cache_storage_key("npm-proxy", "express/./latest");
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    #[test]
    fn test_cache_storage_key_accepts_dotdot_substring() {
        // `..foo` and `foo..bar` are not segments containing exactly `..`,
        // they are legitimate filename bytes.
        assert!(ProxyService::cache_storage_key("npm-proxy", "..foo").is_ok());
        assert!(ProxyService::cache_storage_key("npm-proxy", "package..tgz").is_ok());
    }

    #[test]
    fn test_cache_storage_key_rejects_nul_byte() {
        let result = ProxyService::cache_storage_key("npm-proxy", "express\0evil");
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    #[test]
    fn test_cache_storage_key_rejects_backslash() {
        // Windows-style separator. `..\\foo` would otherwise pass the `..`
        // segment check because split('/') leaves it as a single segment,
        // and some object-store SDKs normalize `\` to `/` before signing.
        assert!(matches!(
            ProxyService::cache_storage_key("npm-proxy", "..\\etc\\passwd"),
            Err(AppError::Validation(_))
        ));
        assert!(matches!(
            ProxyService::cache_storage_key("npm-proxy", "express\\latest"),
            Err(AppError::Validation(_))
        ));
    }

    #[test]
    fn test_cache_storage_key_rejects_control_chars() {
        // CR/LF can split log lines and confuse some sign-URL paths.
        let result = ProxyService::cache_storage_key("npm-proxy", "express\nevil");
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    #[test]
    fn test_cache_storage_key_rejects_empty_path() {
        let result = ProxyService::cache_storage_key("npm-proxy", "");
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    #[test]
    fn test_cache_storage_key_rejects_only_slashes() {
        let result = ProxyService::cache_storage_key("npm-proxy", "//");
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    #[test]
    fn test_cache_storage_key_rejects_double_slash() {
        // `foo//bar` after trim-edges still has an empty middle segment.
        let result = ProxyService::cache_storage_key("npm-proxy", "express//latest");
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    #[test]
    fn test_cache_metadata_key_applies_same_validation() {
        // The metadata helper shares the same validator, so traversal is
        // rejected on both helpers (preventing a partial bypass where one
        // path produces a valid metadata key but invalid storage key, or
        // vice-versa).
        assert!(matches!(
            ProxyService::cache_metadata_key("npm-proxy", "../etc/passwd"),
            Err(AppError::Validation(_))
        ));
        assert!(matches!(
            ProxyService::cache_metadata_key("npm-proxy", "express\0evil"),
            Err(AppError::Validation(_))
        ));
    }

    #[test]
    fn test_storage_and_metadata_keys_do_not_collide() {
        let storage = ProxyService::cache_storage_key("repo", "package").unwrap();
        let metadata = ProxyService::cache_metadata_key("repo", "package").unwrap();
        assert_ne!(storage, metadata);
    }

    // =======================================================================
    // CacheMetadata serialization tests
    // =======================================================================

    #[test]
    fn test_cache_metadata_serialization() {
        let metadata = CacheMetadata {
            cached_at: Utc::now(),
            upstream_etag: Some("\"abc123\"".to_string()),
            storage_etag: None,
            expires_at: Utc::now() + chrono::Duration::hours(24),
            content_type: Some("application/octet-stream".to_string()),
            size_bytes: 1024,
            checksum_sha256: "a".repeat(64),
        };

        let json = serde_json::to_string(&metadata).unwrap();
        let parsed: CacheMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(metadata.upstream_etag, parsed.upstream_etag);
        assert_eq!(metadata.size_bytes, parsed.size_bytes);
        assert_eq!(metadata.checksum_sha256, parsed.checksum_sha256);
    }

    #[test]
    fn test_cache_metadata_serialization_no_etag() {
        let now = Utc::now();
        let metadata = CacheMetadata {
            cached_at: now,
            upstream_etag: None,
            storage_etag: None,
            expires_at: now + chrono::Duration::seconds(3600),
            content_type: None,
            size_bytes: 0,
            checksum_sha256: String::new(),
        };

        let json = serde_json::to_string(&metadata).unwrap();
        let parsed: CacheMetadata = serde_json::from_str(&json).unwrap();

        assert!(parsed.upstream_etag.is_none());
        assert!(parsed.content_type.is_none());
        assert_eq!(parsed.size_bytes, 0);
    }

    #[test]
    fn test_cache_metadata_roundtrip_preserves_timestamps() {
        let now = Utc::now();
        let expires = now + chrono::Duration::seconds(DEFAULT_CACHE_TTL_SECS);
        let metadata = CacheMetadata {
            cached_at: now,
            upstream_etag: Some("\"etag-value\"".to_string()),
            storage_etag: Some("\"storage-etag\"".to_string()),
            expires_at: expires,
            content_type: Some("application/json".to_string()),
            size_bytes: 4096,
            checksum_sha256: "b".repeat(64),
        };

        let json_bytes = serde_json::to_vec(&metadata).unwrap();
        let parsed: CacheMetadata = serde_json::from_slice(&json_bytes).unwrap();

        assert_eq!(parsed.cached_at, metadata.cached_at);
        assert_eq!(parsed.expires_at, metadata.expires_at);
    }

    #[test]
    fn test_cache_metadata_large_size() {
        let metadata = CacheMetadata {
            cached_at: Utc::now(),
            upstream_etag: None,
            storage_etag: None,
            expires_at: Utc::now() + chrono::Duration::hours(1),
            content_type: Some("application/octet-stream".to_string()),
            size_bytes: i64::MAX,
            checksum_sha256: "c".repeat(64),
        };

        let json = serde_json::to_string(&metadata).unwrap();
        let parsed: CacheMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.size_bytes, i64::MAX);
    }

    // =======================================================================
    // Constants tests
    // =======================================================================

    #[test]
    fn test_default_cache_ttl_is_24_hours() {
        assert_eq!(DEFAULT_CACHE_TTL_SECS, 86400);
        assert_eq!(DEFAULT_CACHE_TTL_SECS, 24 * 60 * 60);
    }

    #[test]
    fn test_http_timeout_is_60_seconds() {
        assert_eq!(HTTP_TIMEOUT_SECS, 60);
    }

    // =======================================================================
    // Cache expiration logic tests
    // =======================================================================

    #[test]
    fn test_cache_expiration_check_logic() {
        // Replicate the cache expiration check from get_cached_artifact
        let now = Utc::now();

        // Expired cache entry
        let expired_metadata = CacheMetadata {
            cached_at: now - chrono::Duration::hours(25),
            upstream_etag: None,
            storage_etag: None,
            expires_at: now - chrono::Duration::hours(1),
            content_type: None,
            size_bytes: 100,
            checksum_sha256: "abc".to_string(),
        };
        assert!(
            Utc::now() > expired_metadata.expires_at,
            "Cache should be expired"
        );

        // Valid cache entry
        let valid_metadata = CacheMetadata {
            cached_at: now,
            upstream_etag: None,
            storage_etag: None,
            expires_at: now + chrono::Duration::hours(23),
            content_type: None,
            size_bytes: 100,
            checksum_sha256: "abc".to_string(),
        };
        assert!(
            Utc::now() < valid_metadata.expires_at,
            "Cache should still be valid"
        );
    }

    #[test]
    fn test_cache_ttl_computation() {
        // Replicate the TTL computation from cache_artifact
        let now = Utc::now();
        let ttl_secs: i64 = 3600;
        let expires_at = now + chrono::Duration::seconds(ttl_secs);
        assert!(expires_at > now);
        // Should expire roughly 1 hour from now
        let diff = (expires_at - now).num_seconds();
        assert_eq!(diff, 3600);
    }

    // =======================================================================
    // URL construction edge cases
    // =======================================================================

    #[test]
    fn test_build_upstream_url_preserves_base_path() {
        // Base URL with a subpath should be preserved
        assert_eq!(
            ProxyService::build_upstream_url(
                "https://registry.example.com/v2/library",
                "alpine/manifests/latest"
            ),
            "https://registry.example.com/v2/library/alpine/manifests/latest"
        );
    }

    #[test]
    fn test_build_upstream_url_with_special_characters() {
        assert_eq!(
            ProxyService::build_upstream_url(
                "https://registry.npmjs.org",
                "@babel/core/-/core-7.24.0.tgz"
            ),
            "https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz"
        );
    }

    #[test]
    fn test_build_upstream_url_with_encoded_characters() {
        assert_eq!(
            ProxyService::build_upstream_url(
                "https://example.com",
                "path%20with%20spaces/artifact"
            ),
            "https://example.com/path%20with%20spaces/artifact"
        );
    }

    // =======================================================================
    // parse_release_file_paths (APT Release file parsing for #1147)
    // =======================================================================

    #[test]
    fn test_parse_release_file_paths_extracts_sha256_section() {
        let release = "\
Origin: Debian
Suite: stable
SHA256:
 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789  1234 main/binary-amd64/Packages
 fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210   567 main/binary-amd64/Packages.gz
";
        let paths = parse_release_file_paths(release);
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&"main/binary-amd64/Packages".to_string()));
        assert!(paths.contains(&"main/binary-amd64/Packages.gz".to_string()));
    }

    #[test]
    fn test_parse_release_file_paths_dedupes_across_sections() {
        // The same path appears under MD5Sum, SHA1, and SHA256 — the
        // returned list dedupes so cache invalidation is idempotent.
        let release = "\
MD5Sum:
 00000000000000000000000000000000  1234 main/binary-amd64/Packages
SHA1:
 1111111111111111111111111111111111111111  1234 main/binary-amd64/Packages
SHA256:
 22222222222222222222222222222222222222222222222222222222222222  1234 main/binary-amd64/Packages
";
        let paths = parse_release_file_paths(release);
        assert_eq!(paths, vec!["main/binary-amd64/Packages".to_string()]);
    }

    #[test]
    fn test_parse_release_file_paths_ignores_inrelease_armor() {
        // InRelease files are inline-signed: the body is wrapped in
        // `-----BEGIN PGP SIGNED MESSAGE-----` armor lines that must
        // not be misread as section headers.
        let release = "\
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Origin: Debian
SHA256:
 abc123 1234 main/Contents-amd64
-----BEGIN PGP SIGNATURE-----
iQIzBAEBCgAdFiE...
-----END PGP SIGNATURE-----
";
        let paths = parse_release_file_paths(release);
        assert_eq!(paths, vec!["main/Contents-amd64".to_string()]);
    }

    #[test]
    fn test_parse_release_file_paths_skips_traversal_entries() {
        // A malicious upstream could try to smuggle a `..` path; reject
        // it so cache invalidation can't be aimed at unrelated keys.
        let release = "\
SHA256:
 abc 100 ../../etc/passwd
 def 200 main/binary-amd64/Packages
";
        let paths = parse_release_file_paths(release);
        assert_eq!(paths, vec!["main/binary-amd64/Packages".to_string()]);
    }

    #[test]
    fn test_parse_release_file_paths_skips_lines_outside_checksum_sections() {
        // Lines under non-checksum sections (e.g. Date, MD5Sum-Description)
        // must not contribute paths. Section headers reset the state.
        let release = "\
Origin: Debian
Suite: stable
Components: main contrib non-free
SHA256:
 abc 100 main/binary-amd64/Packages
Description:
 dummy line that looks like an entry but is in a different section
";
        let paths = parse_release_file_paths(release);
        assert_eq!(paths, vec!["main/binary-amd64/Packages".to_string()]);
    }

    #[test]
    fn test_parse_release_file_paths_handles_empty_input() {
        assert!(parse_release_file_paths("").is_empty());
    }

    #[test]
    fn test_parse_release_file_paths_skips_malformed_entries() {
        // Entries missing the size column, or whose size is non-numeric,
        // are dropped so we don't construct bogus cache paths from them.
        let release = "\
SHA256:
 abc main/incomplete
 def notanumber main/bad-size
 ghi 999 main/good
";
        let paths = parse_release_file_paths(release);
        assert_eq!(paths, vec!["main/good".to_string()]);
    }

    // =======================================================================
    // is_cache_expired (extracted pure function)
    // =======================================================================

    #[test]
    fn test_is_cache_expired_past() {
        let expired = Utc::now() - chrono::Duration::hours(1);
        assert!(is_cache_expired(&expired));
    }

    #[test]
    fn test_is_cache_expired_future() {
        let valid = Utc::now() + chrono::Duration::hours(23);
        assert!(!is_cache_expired(&valid));
    }

    #[test]
    fn test_is_cache_expired_far_future() {
        let far = Utc::now() + chrono::Duration::days(365);
        assert!(!is_cache_expired(&far));
    }

    // =======================================================================
    // compute_cache_expiry (extracted pure function)
    // =======================================================================

    #[test]
    fn test_compute_cache_expiry() {
        let now = Utc::now();
        let expires = compute_cache_expiry(now, 3600);
        let diff = (expires - now).num_seconds();
        assert_eq!(diff, 3600);
    }

    #[test]
    fn test_compute_cache_expiry_default_ttl() {
        let now = Utc::now();
        let expires = compute_cache_expiry(now, DEFAULT_CACHE_TTL_SECS);
        let diff = (expires - now).num_seconds();
        assert_eq!(diff, 86400);
    }

    #[test]
    fn test_compute_cache_expiry_zero_ttl() {
        let now = Utc::now();
        let expires = compute_cache_expiry(now, 0);
        assert_eq!(expires, now);
    }

    // =======================================================================
    // parse_cache_ttl (extracted pure function)
    // =======================================================================

    #[test]
    fn test_parse_cache_ttl_valid_number() {
        assert_eq!(parse_cache_ttl(Some("3600")), 3600);
    }

    #[test]
    fn test_parse_cache_ttl_none() {
        assert_eq!(parse_cache_ttl(None), DEFAULT_CACHE_TTL_SECS);
    }

    #[test]
    fn test_parse_cache_ttl_invalid() {
        assert_eq!(
            parse_cache_ttl(Some("not-a-number")),
            DEFAULT_CACHE_TTL_SECS
        );
    }

    #[test]
    fn test_parse_cache_ttl_empty() {
        assert_eq!(parse_cache_ttl(Some("")), DEFAULT_CACHE_TTL_SECS);
    }

    #[test]
    fn test_parse_cache_ttl_negative() {
        assert_eq!(parse_cache_ttl(Some("-100")), -100);
    }

    // =======================================================================
    // build_stale_cache_headers tests
    // =======================================================================

    #[test]
    fn test_build_stale_cache_headers_contains_x_cache() {
        let headers = build_stale_cache_headers();
        assert_eq!(headers.get("X-Cache").unwrap(), "STALE");
    }

    #[test]
    fn test_build_stale_cache_headers_contains_warning() {
        let headers = build_stale_cache_headers();
        assert_eq!(
            headers.get("Warning").unwrap(),
            "110 artifact-keeper \"Response is stale\""
        );
    }

    #[test]
    fn test_build_stale_cache_headers_has_exactly_two_entries() {
        let headers = build_stale_cache_headers();
        assert_eq!(headers.len(), 2);
    }

    // =======================================================================
    // Stale cache detection tests
    // =======================================================================

    #[test]
    fn test_expired_metadata_is_stale() {
        let now = Utc::now();
        let metadata = CacheMetadata {
            cached_at: now - chrono::Duration::hours(25),
            upstream_etag: Some("\"old-etag\"".to_string()),
            storage_etag: None,
            expires_at: now - chrono::Duration::hours(1),
            content_type: Some("application/java-archive".to_string()),
            size_bytes: 2048,
            checksum_sha256: "d".repeat(64),
        };

        // The entry is expired (stale) because expires_at is in the past
        assert!(is_cache_expired(&metadata.expires_at));
        // But the metadata and content are still present, so it can be served
        // as a stale fallback when upstream is down
        assert!(metadata.content_type.is_some());
        assert!(metadata.size_bytes > 0);
    }

    #[test]
    fn test_valid_metadata_is_not_stale() {
        let now = Utc::now();
        let metadata = CacheMetadata {
            cached_at: now,
            upstream_etag: None,
            storage_etag: None,
            expires_at: now + chrono::Duration::hours(23),
            content_type: Some("application/octet-stream".to_string()),
            size_bytes: 512,
            checksum_sha256: "e".repeat(64),
        };

        // Not expired, so it would be served normally (not as stale)
        assert!(!is_cache_expired(&metadata.expires_at));
    }

    #[test]
    fn test_just_expired_metadata_is_stale() {
        let now = Utc::now();
        let metadata = CacheMetadata {
            cached_at: now - chrono::Duration::seconds(DEFAULT_CACHE_TTL_SECS + 1),
            upstream_etag: None,
            storage_etag: None,
            expires_at: now - chrono::Duration::seconds(1),
            content_type: Some("application/gzip".to_string()),
            size_bytes: 4096,
            checksum_sha256: "f".repeat(64),
        };

        assert!(is_cache_expired(&metadata.expires_at));
    }

    // =======================================================================
    // PyPI-specific cache key derivation
    // =======================================================================

    #[test]
    fn test_cache_key_for_pypi_local_path() {
        let key = ProxyService::cache_storage_key(
            "my-pypi-remote",
            "simple/requests/requests-2.31.0.tar.gz",
        )
        .unwrap();
        assert_eq!(
            key,
            "proxy-cache/my-pypi-remote/simple/requests/requests-2.31.0.tar.gz/__content__"
        );
    }

    #[test]
    fn test_cache_metadata_key_for_pypi_local_path() {
        let key = ProxyService::cache_metadata_key(
            "my-pypi-remote",
            "simple/requests/requests-2.31.0.tar.gz",
        )
        .unwrap();
        assert_eq!(
            key,
            "proxy-cache/my-pypi-remote/simple/requests/requests-2.31.0.tar.gz/__cache_meta__.json"
        );
    }

    #[test]
    fn test_cache_key_for_pypi_wheel() {
        let key = ProxyService::cache_storage_key(
            "pypi-proxy",
            "simple/flask/flask-3.0.0-py3-none-any.whl",
        )
        .unwrap();
        assert!(key.starts_with("proxy-cache/pypi-proxy/simple/flask/"));
        assert!(key.ends_with("/__content__"));
    }

    #[test]
    fn test_cache_key_pypi_and_npm_do_not_collide() {
        let pypi_key = ProxyService::cache_storage_key(
            "pypi-remote",
            "simple/requests/requests-2.31.0.tar.gz",
        )
        .unwrap();
        let npm_key =
            ProxyService::cache_storage_key("npm-remote", "simple/requests/requests-2.31.0.tar.gz")
                .unwrap();
        assert_ne!(pypi_key, npm_key);
    }

    // --- cache key construction for fetch_artifact_with_cache_path ---

    #[test]
    fn test_cache_key_with_custom_path_differs_from_fetch_path() {
        // Pre-#1052 this test passed an upstream URL as the path argument,
        // which produced a cache key embedding `https://...` (an empty
        // segment from the `//`). The new validator rejects that path
        // shape on purpose - URLs are not valid cache paths and the
        // previous behavior was a footgun. The test now exercises the
        // intended invariant: two well-formed cache_paths produce
        // distinct cache keys.
        let upstream_relative = "packages/ab/cd/requests-2.31.0.tar.gz";
        let cache_path = "simple/requests/requests-2.31.0.tar.gz";
        let fetch_key = ProxyService::cache_storage_key("pypi-remote", upstream_relative).unwrap();
        let cache_key = ProxyService::cache_storage_key("pypi-remote", cache_path).unwrap();
        assert_ne!(
            fetch_key, cache_key,
            "cache key should differ when distinct paths are used"
        );

        // And a URL-shaped path is now an explicit error rather than a
        // funny-looking cache key.
        assert!(matches!(
            ProxyService::cache_storage_key(
                "pypi-remote",
                "https://files.pythonhosted.org/packages/ab/cd/requests-2.31.0.tar.gz",
            ),
            Err(AppError::Validation(_))
        ));
    }

    #[test]
    fn test_cache_metadata_key_with_custom_path() {
        let cache_path = "simple/numpy/numpy-1.26.0.tar.gz";
        let key = ProxyService::cache_metadata_key("pypi-remote", cache_path).unwrap();
        assert!(key.contains("pypi-remote"));
        assert!(key.contains("numpy"));
    }

    #[test]
    fn test_build_upstream_url_with_trailing_slash() {
        let url = ProxyService::build_upstream_url("https://pypi.org/", "simple/requests/");
        assert_eq!(url, "https://pypi.org/simple/requests/");
    }

    #[test]
    fn test_build_upstream_url_without_trailing_slash() {
        let url = ProxyService::build_upstream_url("https://pypi.org", "simple/requests/");
        assert_eq!(url, "https://pypi.org/simple/requests/");
    }

    #[test]
    fn test_build_upstream_url_with_leading_slash_in_path() {
        let url = ProxyService::build_upstream_url("https://pypi.org", "/simple/requests/");
        // Should not double-slash
        assert!(!url.contains("//simple"));
    }

    #[test]
    fn test_get_cached_artifact_by_path_uses_correct_keys() {
        // Verify that get_cached_artifact_by_path constructs the same keys
        // as manual cache_storage_key + cache_metadata_key calls
        let repo_key = "test-pypi";
        let path = "simple/flask/flask-3.0.0.tar.gz";
        let expected_storage = ProxyService::cache_storage_key(repo_key, path).unwrap();
        let expected_meta = ProxyService::cache_metadata_key(repo_key, path).unwrap();
        // The function internally calls these same methods, so keys should match
        assert!(expected_storage.contains("test-pypi"));
        assert!(expected_meta.contains("test-pypi"));
        assert!(expected_storage.contains("flask"));
        assert!(expected_meta.contains("flask"));
    }

    // =======================================================================
    // Bearer challenge parser tests
    // =======================================================================

    #[test]
    fn test_parse_bearer_challenge_docker_hub() {
        let header = r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull""#;
        let params = ProxyService::parse_bearer_challenge(header);
        assert_eq!(params.get("realm").unwrap(), "https://auth.docker.io/token");
        assert_eq!(params.get("service").unwrap(), "registry.docker.io");
        assert_eq!(
            params.get("scope").unwrap(),
            "repository:library/alpine:pull"
        );
    }

    #[test]
    fn test_parse_bearer_challenge_ghcr() {
        let header = r#"Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:org/image:pull""#;
        let params = ProxyService::parse_bearer_challenge(header);
        assert_eq!(params.get("realm").unwrap(), "https://ghcr.io/token");
        assert_eq!(params.get("service").unwrap(), "ghcr.io");
    }

    #[test]
    fn test_parse_bearer_challenge_realm_only() {
        let header = r#"Bearer realm="https://example.com/token""#;
        let params = ProxyService::parse_bearer_challenge(header);
        assert_eq!(params.get("realm").unwrap(), "https://example.com/token");
        assert!(!params.contains_key("service"));
    }

    #[test]
    fn test_parse_bearer_challenge_not_bearer() {
        let params = ProxyService::parse_bearer_challenge("Basic realm=\"test\"");
        assert!(params.is_empty());
    }

    #[test]
    fn test_parse_bearer_challenge_empty() {
        let params = ProxyService::parse_bearer_challenge("");
        assert!(params.is_empty());
    }

    #[tokio::test]
    async fn test_token_cache_hit_and_expiry() {
        let cache: RwLock<HashMap<String, (String, Instant, u64)>> = RwLock::new(HashMap::new());
        {
            let mut c = cache.write().await;
            c.insert(
                "key".to_string(),
                ("tok123".to_string(), Instant::now(), 300),
            );
        }
        let hit = {
            let c = cache.read().await;
            let (token, created_at, ttl) = c.get("key").unwrap();
            if created_at.elapsed() < Duration::from_secs(ttl.saturating_mul(9) / 10) {
                Some(token.clone())
            } else {
                None
            }
        };
        assert_eq!(hit, Some("tok123".to_string()));

        {
            let mut c = cache.write().await;
            c.insert(
                "expired".to_string(),
                (
                    "old".to_string(),
                    Instant::now() - Duration::from_secs(600),
                    300,
                ),
            );
        }
        let miss = {
            let c = cache.read().await;
            let (token, created_at, ttl) = c.get("expired").unwrap();
            if created_at.elapsed() < Duration::from_secs(ttl.saturating_mul(9) / 10) {
                Some(token.clone())
            } else {
                None
            }
        };
        assert!(miss.is_none());
    }

    #[tokio::test]
    async fn test_token_cache_eviction_on_write() {
        let cache: RwLock<HashMap<String, (String, Instant, u64)>> = RwLock::new(HashMap::new());
        {
            let mut c = cache.write().await;
            c.insert(
                "expired".to_string(),
                (
                    "old".to_string(),
                    Instant::now() - Duration::from_secs(600),
                    300,
                ),
            );
            c.insert(
                "fresh".to_string(),
                ("new".to_string(), Instant::now(), 300),
            );
        }
        {
            let mut c = cache.write().await;
            c.retain(|_, (_, created_at, entry_ttl)| {
                created_at.elapsed() < Duration::from_secs(*entry_ttl)
            });
        }
        let c = cache.read().await;
        assert!(!c.contains_key("expired"));
        assert!(c.contains_key("fresh"));
    }

    // =======================================================================
    // extract_version_from_path tests
    // =======================================================================

    #[test]
    fn test_extract_version_maven_standard() {
        let version = extract_version_from_path(
            &RepositoryFormat::Maven,
            "org/junit/junit-bom/5.10.1/junit-bom-5.10.1.pom",
        );
        assert_eq!(version.as_deref(), Some("5.10.1"));
    }

    #[test]
    fn test_extract_version_maven_sha1_checksum() {
        // This is the exact case from issue #640
        let version = extract_version_from_path(
            &RepositoryFormat::Maven,
            "org/junit/junit-bom/5.10.1/junit-bom-5.10.1.pom.sha1",
        );
        assert_eq!(version.as_deref(), Some("5.10.1"));
    }

    #[test]
    fn test_extract_version_maven_snapshot() {
        let version = extract_version_from_path(
            &RepositoryFormat::Maven,
            "com/mycompany/app/my-app/1.0-SNAPSHOT/my-app-1.0-20260402.154115-1.jar",
        );
        assert_eq!(version.as_deref(), Some("1.0-SNAPSHOT"));
    }

    #[test]
    fn test_extract_version_maven_deep_group_id() {
        let version = extract_version_from_path(
            &RepositoryFormat::Maven,
            "org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar",
        );
        assert_eq!(version.as_deref(), Some("3.12.0"));
    }

    #[test]
    fn test_extract_version_maven_metadata_xml() {
        // maven-metadata.xml at version level still has the version in the path
        let version = extract_version_from_path(
            &RepositoryFormat::Maven,
            "org/junit/junit-bom/5.10.1/maven-metadata.xml",
        );
        assert_eq!(version.as_deref(), Some("5.10.1"));
    }

    #[test]
    fn test_extract_version_maven_too_short_path() {
        // Artifact-level metadata: groupId/artifactId/maven-metadata.xml
        let version =
            extract_version_from_path(&RepositoryFormat::Maven, "org/junit/maven-metadata.xml");
        // parse_coordinates requires 4 segments, so this returns None
        assert!(version.is_none());
    }

    #[test]
    fn test_extract_version_npm_unscoped_tarball() {
        let version =
            extract_version_from_path(&RepositoryFormat::Npm, "express/-/express-4.18.2.tgz");
        assert_eq!(version.as_deref(), Some("4.18.2"));
    }

    #[test]
    fn test_extract_version_npm_scoped_tarball() {
        let version =
            extract_version_from_path(&RepositoryFormat::Npm, "@babel/core/-/core-7.24.0.tgz");
        assert_eq!(version.as_deref(), Some("7.24.0"));
    }

    #[test]
    fn test_extract_version_npm_metadata_request() {
        // Metadata requests (just package name) have no version
        let version = extract_version_from_path(&RepositoryFormat::Npm, "express");
        assert!(version.is_none());
    }

    #[test]
    fn test_extract_version_pypi_package_file() {
        let version = extract_version_from_path(
            &RepositoryFormat::Pypi,
            "packages/requests/2.31.0/requests-2.31.0.tar.gz",
        );
        assert_eq!(version.as_deref(), Some("2.31.0"));
    }

    #[test]
    fn test_extract_version_pypi_simple_index() {
        let version = extract_version_from_path(&RepositoryFormat::Pypi, "simple/requests/");
        assert!(version.is_none());
    }

    #[test]
    fn test_extract_version_nuget() {
        let version = extract_version_from_path(
            &RepositoryFormat::Nuget,
            "v3/flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg",
        );
        assert_eq!(version.as_deref(), Some("13.0.3"));
    }

    #[test]
    fn test_extract_version_cargo() {
        let version =
            extract_version_from_path(&RepositoryFormat::Cargo, "crates/serde/serde-1.0.197.crate");
        assert_eq!(version.as_deref(), Some("1.0.197"));
    }

    #[test]
    fn test_extract_version_go_module() {
        let version = extract_version_from_path(
            &RepositoryFormat::Go,
            "github.com/gin-gonic/gin/@v/v1.9.1.info",
        );
        assert_eq!(version.as_deref(), Some("v1.9.1"));
    }

    #[test]
    fn test_extract_version_go_zip() {
        let version = extract_version_from_path(
            &RepositoryFormat::Go,
            "github.com/gin-gonic/gin/@v/v1.9.1.zip",
        );
        assert_eq!(version.as_deref(), Some("v1.9.1"));
    }

    #[test]
    fn test_extract_version_docker_returns_none() {
        let version = extract_version_from_path(
            &RepositoryFormat::Docker,
            "v2/library/nginx/manifests/1.25.3",
        );
        assert!(version.is_none());
    }

    #[test]
    fn test_extract_version_gradle_delegates_to_maven() {
        let version = extract_version_from_path(
            &RepositoryFormat::Gradle,
            "com/google/guava/guava/32.1.3-jre/guava-32.1.3-jre.jar",
        );
        assert_eq!(version.as_deref(), Some("32.1.3-jre"));
    }

    #[test]
    fn test_extract_version_generic_fallback() {
        let version = extract_version_from_path(
            &RepositoryFormat::Generic,
            "my-tool/2.0.0/my-tool-2.0.0.tar.gz",
        );
        assert_eq!(version.as_deref(), Some("2.0.0"));
    }

    #[test]
    fn test_extract_version_generic_short_path() {
        let version = extract_version_from_path(&RepositoryFormat::Generic, "single-file.bin");
        assert!(version.is_none());
    }

    #[test]
    fn test_extract_version_leading_slash_stripped() {
        let version = extract_version_from_path(
            &RepositoryFormat::Maven,
            "/org/junit/junit-bom/5.10.1/junit-bom-5.10.1.pom",
        );
        assert_eq!(version.as_deref(), Some("5.10.1"));
    }

    #[test]
    fn test_cache_key_includes_service() {
        let key1 = format!(
            "{}\0{}\0{}",
            "https://auth.example.com/token", "registry-a", "repo:img:pull"
        );
        let key2 = format!(
            "{}\0{}\0{}",
            "https://auth.example.com/token", "registry-b", "repo:img:pull"
        );
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_ttl_cap_prevents_overflow() {
        let huge_ttl: u64 = u64::MAX;
        let capped = huge_ttl.min(MAX_TOKEN_TTL_SECS);
        assert_eq!(capped, 3600);
        let effective = capped.saturating_mul(9) / 10;
        assert_eq!(effective, 3240);
    }

    // =======================================================================
    // is_cache_fresh tests (#1018 R3-2)
    // =======================================================================
    //
    // Direct unit coverage for the metadata-only freshness probe used by the
    // proxy fast path. The probe is the gate that decides whether the
    // presigned-redirect short-circuit fires, so any silent regression here
    // (e.g. the probe always returning true, or accidentally downloading the
    // body) re-introduces the buffered-download bug behind a different code
    // path. These tests fix the contract:
    //   * missing metadata sidecar         -> false
    //   * expired metadata                 -> false
    //   * valid metadata, content missing  -> false
    //   * valid metadata, content present  -> true
    //
    // and crucially never invoke `storage.get(...)` on the cached body.

    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    /// Programmable storage backend for `is_cache_fresh` tests.
    ///
    /// Lets each test wire up just enough behavior:
    ///   * `metadata` is the JSON bytes returned by `get(metadata_key)`,
    ///     or `None` to simulate a missing sidecar (`AppError::NotFound`).
    ///   * `content_exists` is what `exists(content_key)` returns.
    ///   * `head_etag_value` is what `head_etag(content_key)` returns;
    ///     `Some(Ok(...))` returns the inner result, `None` returns
    ///     `Ok(None)`. Used by #1051 revalidation tests to drive
    ///     match / mismatch / error / missing paths.
    ///   * `get_calls` records every `get(...)` call so tests can assert
    ///     the body was never downloaded.
    ///   * `exists_calls` / `head_etag_calls` let revalidation tests
    ///     verify that the ETag fast-path short-circuits the redundant
    ///     `exists()` call.
    struct CacheFreshMock {
        metadata: Option<Bytes>,
        content_exists: bool,
        head_etag_value: HeadEtagBehavior,
        get_calls: AtomicUsize,
        exists_calls: AtomicUsize,
        head_etag_calls: AtomicUsize,
    }

    /// What the mock's `head_etag` should return per call. Variant
    /// names deliberately avoid `None` / `Some` / `Err` so callsite
    /// literals don't visually collide with the `Option`/`Result` the
    /// trait method returns.
    enum HeadEtagBehavior {
        /// Return `Ok(None)`. Models backends that do not surface ETags
        /// (filesystem) or objects without one.
        Absent,
        /// Return `Ok(Some(value))`. Models S3/GCS/Azure happy path.
        Present(String),
        /// Return `Err(AppError::Storage(...))`. Models a transport
        /// failure during revalidation.
        Failed,
    }

    impl CacheFreshMock {
        fn new(metadata: Option<Bytes>, content_exists: bool) -> Self {
            Self::with_head_etag(metadata, content_exists, HeadEtagBehavior::Absent)
        }

        fn with_head_etag(
            metadata: Option<Bytes>,
            content_exists: bool,
            head_etag_value: HeadEtagBehavior,
        ) -> Self {
            Self {
                metadata,
                content_exists,
                head_etag_value,
                get_calls: AtomicUsize::new(0),
                exists_calls: AtomicUsize::new(0),
                head_etag_calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::services::storage_service::StorageBackend for CacheFreshMock {
        async fn put(&self, _key: &str, _content: Bytes) -> Result<()> {
            Ok(())
        }
        async fn get(&self, key: &str) -> Result<Bytes> {
            self.get_calls.fetch_add(1, AtomicOrdering::SeqCst);
            if key.ends_with("__cache_meta__.json") {
                match &self.metadata {
                    Some(b) => Ok(b.clone()),
                    None => Err(AppError::NotFound(key.to_string())),
                }
            } else {
                // Body access on the fast path is forbidden — return
                // NotFound so accidental hits surface as test failures
                // rather than fake successes.
                Err(AppError::NotFound(key.to_string()))
            }
        }
        async fn exists(&self, key: &str) -> Result<bool> {
            self.exists_calls.fetch_add(1, AtomicOrdering::SeqCst);
            if key.ends_with("__content__") {
                Ok(self.content_exists)
            } else {
                // Metadata sidecar exists iff metadata bytes are present.
                Ok(self.metadata.is_some())
            }
        }
        async fn head_etag(&self, _key: &str) -> Result<Option<String>> {
            self.head_etag_calls.fetch_add(1, AtomicOrdering::SeqCst);
            match &self.head_etag_value {
                HeadEtagBehavior::Absent => Ok(None),
                HeadEtagBehavior::Present(v) => Ok(Some(v.clone())),
                HeadEtagBehavior::Failed => {
                    Err(AppError::Storage("mock head_etag failure".to_string()))
                }
            }
        }
        async fn delete(&self, _key: &str) -> Result<()> {
            Ok(())
        }
        async fn list(&self, _prefix: Option<&str>) -> Result<Vec<String>> {
            Ok(Vec::new())
        }
        async fn copy(&self, _source: &str, _dest: &str) -> Result<()> {
            Ok(())
        }
        async fn size(&self, _key: &str) -> Result<u64> {
            Ok(0)
        }
    }

    /// Build a `ProxyService` whose storage is the supplied mock. The DB
    /// pool is a lazy connection that is never dialed because
    /// `is_cache_fresh` does not touch the database.
    fn build_proxy_service_with_storage(
        storage: Arc<dyn crate::services::storage_service::StorageBackend>,
    ) -> ProxyService {
        let pool = sqlx::PgPool::connect_lazy("postgres://fake:fake@localhost/fake")
            .expect("connect_lazy should not fail");
        ProxyService::new(pool, Arc::new(StorageService::new(storage)))
    }

    fn fresh_metadata_bytes() -> Bytes {
        fresh_metadata_bytes_with_storage_etag(None)
    }

    /// Build a fresh metadata sidecar with the supplied pinned storage
    /// ETag. Used by #1051 revalidation tests to wire a known pin into
    /// `is_cache_fresh` and then assert the matching / mismatching
    /// behavior on the storage HEAD.
    fn fresh_metadata_bytes_with_storage_etag(storage_etag: Option<String>) -> Bytes {
        let metadata = CacheMetadata {
            cached_at: Utc::now(),
            upstream_etag: None,
            storage_etag,
            expires_at: Utc::now() + chrono::Duration::hours(1),
            content_type: Some("application/octet-stream".to_string()),
            size_bytes: 42,
            checksum_sha256: "a".repeat(64),
        };
        Bytes::from(serde_json::to_vec(&metadata).unwrap())
    }

    fn expired_metadata_bytes() -> Bytes {
        let metadata = CacheMetadata {
            cached_at: Utc::now() - chrono::Duration::hours(2),
            upstream_etag: None,
            storage_etag: None,
            expires_at: Utc::now() - chrono::Duration::seconds(1),
            content_type: None,
            size_bytes: 0,
            checksum_sha256: String::new(),
        };
        Bytes::from(serde_json::to_vec(&metadata).unwrap())
    }

    #[tokio::test]
    async fn test_is_cache_fresh_false_when_metadata_sidecar_missing() {
        let mock = Arc::new(CacheFreshMock::new(/* metadata = */ None, true));
        let service = build_proxy_service_with_storage(mock.clone());

        let fresh = service.is_cache_fresh("npm-proxy", "lodash").await;

        assert!(
            !fresh,
            "missing metadata sidecar must yield is_cache_fresh = false"
        );
    }

    #[tokio::test]
    async fn test_is_cache_fresh_false_when_metadata_expired() {
        let mock = Arc::new(CacheFreshMock::new(Some(expired_metadata_bytes()), true));
        let service = build_proxy_service_with_storage(mock.clone());

        let fresh = service.is_cache_fresh("npm-proxy", "lodash").await;

        assert!(
            !fresh,
            "expired metadata (expires_at < now) must yield is_cache_fresh = false"
        );
    }

    #[tokio::test]
    async fn test_is_cache_fresh_false_when_content_missing() {
        // Metadata is valid and unexpired, but the underlying content
        // object has been evicted (e.g. lifecycle policy). The freshness
        // probe must catch this so the fast path does not sign a URL
        // pointing at a 404.
        let mock = Arc::new(CacheFreshMock::new(
            Some(fresh_metadata_bytes()),
            /* content_exists = */ false,
        ));
        let service = build_proxy_service_with_storage(mock.clone());

        let fresh = service.is_cache_fresh("npm-proxy", "lodash").await;

        assert!(
            !fresh,
            "valid metadata with missing content object must yield is_cache_fresh = false"
        );
    }

    #[tokio::test]
    async fn test_is_cache_fresh_true_when_metadata_valid_and_content_exists() {
        let mock = Arc::new(CacheFreshMock::new(
            Some(fresh_metadata_bytes()),
            /* content_exists = */ true,
        ));
        let service = build_proxy_service_with_storage(mock.clone());

        let fresh = service.is_cache_fresh("npm-proxy", "lodash").await;

        assert!(
            fresh,
            "valid metadata + existing content must yield is_cache_fresh = true"
        );
        // Belt-and-suspenders: the probe must never download the body.
        // It is only allowed to call `get` on the metadata sidecar.
        assert_eq!(
            mock.get_calls.load(AtomicOrdering::SeqCst),
            1,
            "is_cache_fresh must read metadata exactly once and never the body"
        );
    }

    // =======================================================================
    // ETag fast-path revalidation tests (#1051)
    //
    // The fast path pins the storage backend's ETag at cache-write time into
    // `CacheMetadata::storage_etag`. On each hit the freshness probe must
    // re-HEAD the object and:
    //   * match               -> true  (object unchanged since cache write)
    //   * mismatch            -> false (replaced/tampered; slow-path heals)
    //   * head_etag = None    -> false (object lost since write)
    //   * head_etag = Err     -> false (revalidation failed; fail closed)
    //   * legacy (no pin)     -> existence-only behavior (pre-#1051 entries)
    // The matched-ETag path must also skip the redundant `exists()` call.
    // =======================================================================

    #[tokio::test]
    async fn test_is_cache_fresh_true_when_storage_etag_matches_pin() {
        // Metadata pins a known storage ETag; backend reports the same
        // value on HEAD. Revalidation must pass and short-circuit the
        // redundant exists() probe.
        let mock = Arc::new(CacheFreshMock::with_head_etag(
            Some(fresh_metadata_bytes_with_storage_etag(Some(
                "\"deadbeef\"".to_string(),
            ))),
            /* content_exists = */ true,
            HeadEtagBehavior::Present("\"deadbeef\"".to_string()),
        ));
        let service = build_proxy_service_with_storage(mock.clone());

        let fresh = service.is_cache_fresh("npm-proxy", "lodash").await;

        assert!(
            fresh,
            "matching storage ETag must yield is_cache_fresh=true"
        );
        assert_eq!(
            mock.head_etag_calls.load(AtomicOrdering::SeqCst),
            1,
            "revalidation must HEAD the cached object exactly once"
        );
        assert_eq!(
            mock.exists_calls.load(AtomicOrdering::SeqCst),
            0,
            "matched-ETag path must skip the redundant exists() call"
        );
        assert_eq!(
            mock.get_calls.load(AtomicOrdering::SeqCst),
            1,
            "revalidation must still never download the body"
        );
    }

    #[tokio::test]
    async fn test_is_cache_fresh_false_when_storage_etag_mismatches_pin() {
        // The object was rewritten (or tampered with) between cache write
        // and this read. ETag mismatch must force the slow path.
        let mock = Arc::new(CacheFreshMock::with_head_etag(
            Some(fresh_metadata_bytes_with_storage_etag(Some(
                "\"pinned\"".to_string(),
            ))),
            /* content_exists = */ true,
            HeadEtagBehavior::Present("\"different\"".to_string()),
        ));
        let service = build_proxy_service_with_storage(mock.clone());

        let fresh = service.is_cache_fresh("npm-proxy", "lodash").await;

        assert!(
            !fresh,
            "mismatched storage ETag must yield is_cache_fresh=false"
        );
        assert_eq!(
            mock.head_etag_calls.load(AtomicOrdering::SeqCst),
            1,
            "mismatch path still only HEADs once"
        );
    }

    #[tokio::test]
    async fn test_is_cache_fresh_false_when_storage_etag_pin_lost() {
        // We pinned an ETag at write time but the backend now returns
        // None for HEAD (object missing or stripped). Treat as not-fresh
        // — the slow path will re-fetch and rewrite the cache.
        let mock = Arc::new(CacheFreshMock::with_head_etag(
            Some(fresh_metadata_bytes_with_storage_etag(Some(
                "\"pinned\"".to_string(),
            ))),
            /* content_exists = */ true,
            HeadEtagBehavior::Absent,
        ));
        let service = build_proxy_service_with_storage(mock.clone());

        let fresh = service.is_cache_fresh("npm-proxy", "lodash").await;

        assert!(
            !fresh,
            "lost storage ETag with active pin must yield is_cache_fresh=false"
        );
    }

    #[tokio::test]
    async fn test_is_cache_fresh_false_when_head_etag_errors() {
        // Backend transport error on the revalidation HEAD: fail closed.
        // Better to slow-path than to silently serve a possibly-stale URL.
        let mock = Arc::new(CacheFreshMock::with_head_etag(
            Some(fresh_metadata_bytes_with_storage_etag(Some(
                "\"pinned\"".to_string(),
            ))),
            /* content_exists = */ true,
            HeadEtagBehavior::Failed,
        ));
        let service = build_proxy_service_with_storage(mock.clone());

        let fresh = service.is_cache_fresh("npm-proxy", "lodash").await;

        assert!(
            !fresh,
            "head_etag transport error must yield is_cache_fresh=false (fail closed)"
        );
    }

    #[tokio::test]
    async fn test_is_cache_fresh_legacy_entry_falls_back_to_exists_check() {
        // Cache entry written before #1051: `storage_etag = None`. Must
        // preserve pre-#1051 behavior — existence check only, no HEAD for
        // ETag — so legacy caches keep working without rewrite.
        let mock = Arc::new(CacheFreshMock::with_head_etag(
            Some(fresh_metadata_bytes_with_storage_etag(None)),
            /* content_exists = */ true,
            // Even if backend would surface an ETag, the absence of a pin
            // means revalidation is skipped entirely.
            HeadEtagBehavior::Present("\"would-be-current\"".to_string()),
        ));
        let service = build_proxy_service_with_storage(mock.clone());

        let fresh = service.is_cache_fresh("npm-proxy", "lodash").await;

        assert!(
            fresh,
            "legacy entry without storage_etag pin must still yield true on existence"
        );
        assert_eq!(
            mock.head_etag_calls.load(AtomicOrdering::SeqCst),
            0,
            "legacy path must not waste a HEAD when no pin is available"
        );
        assert_eq!(
            mock.exists_calls.load(AtomicOrdering::SeqCst),
            1,
            "legacy path must fall back to a single exists() probe"
        );
    }

    #[tokio::test]
    async fn test_is_cache_fresh_legacy_entry_false_when_content_missing() {
        // Legacy entry (no pin) plus a missing content object: existence
        // check returns false, fast path correctly declines to redirect.
        let mock = Arc::new(CacheFreshMock::with_head_etag(
            Some(fresh_metadata_bytes_with_storage_etag(None)),
            /* content_exists = */ false,
            HeadEtagBehavior::Absent,
        ));
        let service = build_proxy_service_with_storage(mock.clone());

        let fresh = service.is_cache_fresh("npm-proxy", "lodash").await;

        assert!(
            !fresh,
            "legacy entry with missing content must still yield false"
        );
        assert_eq!(
            mock.head_etag_calls.load(AtomicOrdering::SeqCst),
            0,
            "no pin -> no revalidation HEAD"
        );
    }

    #[test]
    fn test_cache_metadata_legacy_sidecar_deserializes_without_storage_etag() {
        // Sidecars written before #1051 do not include `storage_etag`.
        // The new field must use `#[serde(default)]` so old JSON parses
        // cleanly; otherwise the cache breaks for every existing entry on
        // upgrade.
        let legacy_json = r#"{
            "cached_at": "2026-01-01T00:00:00Z",
            "upstream_etag": "\"upstream-abc\"",
            "expires_at": "2099-01-01T00:00:00Z",
            "content_type": "application/octet-stream",
            "size_bytes": 1234,
            "checksum_sha256": "abcd"
        }"#;
        let parsed: CacheMetadata = serde_json::from_str(legacy_json)
            .expect("legacy sidecar without storage_etag must still deserialize");
        assert!(
            parsed.storage_etag.is_none(),
            "legacy sidecar must default storage_etag to None"
        );
        assert_eq!(parsed.upstream_etag.as_deref(), Some("\"upstream-abc\""));
    }

    // -----------------------------------------------------------------------
    // invalidate_cache_by_key + invalidate_dist_packages_cache (#1147)
    //
    // Direct unit coverage for the APT Release-coherence helpers extracted
    // for the virtual-repo cross-format aggregation PR. Both helpers are
    // storage-only (no DB), so they slot cleanly into a mock-storage test
    // pattern that records every `delete(...)` call and asserts the
    // helper hits the right keys.
    // -----------------------------------------------------------------------

    /// Recording mock that captures every `delete()` call so tests can
    /// inspect exactly which cache keys an invalidation helper evicted.
    /// All other operations are no-ops returning the obvious defaults.
    struct DeleteRecordingStorage {
        deletes: tokio::sync::Mutex<Vec<String>>,
    }

    impl DeleteRecordingStorage {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                deletes: tokio::sync::Mutex::new(Vec::new()),
            })
        }
        async fn deletes_snapshot(&self) -> Vec<String> {
            self.deletes.lock().await.clone()
        }
    }

    #[async_trait::async_trait]
    impl crate::services::storage_service::StorageBackend for DeleteRecordingStorage {
        async fn put(&self, _key: &str, _content: Bytes) -> Result<()> {
            Ok(())
        }
        async fn get(&self, key: &str) -> Result<Bytes> {
            Err(AppError::NotFound(key.to_string()))
        }
        async fn exists(&self, _key: &str) -> Result<bool> {
            Ok(false)
        }
        async fn delete(&self, key: &str) -> Result<()> {
            self.deletes.lock().await.push(key.to_string());
            Ok(())
        }
        async fn list(&self, _prefix: Option<&str>) -> Result<Vec<String>> {
            Ok(Vec::new())
        }
        async fn copy(&self, _source: &str, _dest: &str) -> Result<()> {
            Ok(())
        }
        async fn size(&self, _key: &str) -> Result<u64> {
            Ok(0)
        }
    }

    #[tokio::test]
    async fn test_invalidate_cache_by_key_deletes_both_content_and_metadata() {
        let storage = DeleteRecordingStorage::new();
        let service = build_proxy_service_with_storage(storage.clone());

        service
            .invalidate_cache_by_key("apt-debian", "dists/bookworm/Release")
            .await
            .expect("invalidate_cache_by_key");

        let deletes = storage.deletes_snapshot().await;
        // Helper must hit exactly two keys: the cached body and the
        // metadata sidecar. The relative ordering matches the
        // implementation but the test only asserts both are present.
        assert_eq!(
            deletes.len(),
            2,
            "expected delete of both content and metadata, got {:?}",
            deletes
        );
        let any_meta = deletes.iter().any(|k| k.contains("__cache_meta__.json"));
        assert!(
            any_meta,
            "metadata sidecar should be deleted: {:?}",
            deletes
        );
        let any_content = deletes.iter().any(|k| !k.contains("__cache_meta__.json"));
        assert!(
            any_content,
            "content key should be deleted (non-metadata key): {:?}",
            deletes
        );
    }

    #[tokio::test]
    async fn test_invalidate_cache_by_key_rejects_invalid_path() {
        // Path-traversal attempts must surface as `Err` before any
        // storage delete is issued, so a malicious upstream cannot use
        // the helper to delete unrelated cache entries.
        let storage = DeleteRecordingStorage::new();
        let service = build_proxy_service_with_storage(storage.clone());

        let result = service
            .invalidate_cache_by_key("apt-debian", "../etc/passwd")
            .await;

        // We don't care about the specific error variant, only that no
        // delete fired. (cache_storage_key returns Err for traversal.)
        assert!(result.is_err(), "traversal path should error");
        let deletes = storage.deletes_snapshot().await;
        assert!(
            deletes.is_empty(),
            "no delete should be issued on path-traversal: {:?}",
            deletes
        );
    }

    #[tokio::test]
    async fn test_invalidate_dist_packages_cache_evicts_each_path() {
        // Driven by the Release-file parser: every path under the
        // `SHA256:` section must produce a paired
        // `dists/<dist>/<relative>` invalidation. The helper itself is
        // fire-and-forget (no return value), so we observe its side
        // effects through the recording mock.
        let storage = DeleteRecordingStorage::new();
        let service = build_proxy_service_with_storage(storage.clone());

        let release = "\
SHA256:
 aaa 100 main/binary-amd64/Packages
 bbb 200 main/binary-amd64/Packages.gz
 ccc 300 main/binary-arm64/Packages
";
        service
            .invalidate_dist_packages_cache("apt-debian", "bookworm", release)
            .await;

        let deletes = storage.deletes_snapshot().await;
        // 3 referenced paths × (content + metadata) = 6 delete calls.
        assert_eq!(
            deletes.len(),
            6,
            "expected 3 paths × 2 keys (content+metadata) = 6 deletes, got {:?}",
            deletes
        );

        // The dist prefix and each relative path must appear at least
        // once across the recorded keys.
        let joined = deletes.join("|");
        assert!(
            joined.contains("bookworm"),
            "deletes should target the right dist: {:?}",
            deletes
        );
        for rel in [
            "main/binary-amd64/Packages",
            "main/binary-amd64/Packages.gz",
            "main/binary-arm64/Packages",
        ] {
            assert!(
                deletes.iter().any(|k| k.contains(rel)),
                "expected eviction of {} in {:?}",
                rel,
                deletes
            );
        }
    }

    #[tokio::test]
    async fn test_invalidate_dist_packages_cache_empty_release_is_noop() {
        // A Release file with no checksum section must produce zero
        // delete calls so we don't churn the cache on degenerate input.
        let storage = DeleteRecordingStorage::new();
        let service = build_proxy_service_with_storage(storage.clone());

        service
            .invalidate_dist_packages_cache("apt-debian", "bookworm", "Origin: Debian\n")
            .await;

        let deletes = storage.deletes_snapshot().await;
        assert!(
            deletes.is_empty(),
            "Release without SHA256 section must not invalidate anything: {:?}",
            deletes
        );
    }

    #[tokio::test]
    async fn test_invalidate_dist_packages_cache_skips_traversal_paths() {
        // parse_release_file_paths drops `..` segments; the eviction
        // helper inherits that protection so a hostile upstream can't
        // aim invalidations at unrelated cache keys.
        let storage = DeleteRecordingStorage::new();
        let service = build_proxy_service_with_storage(storage.clone());

        let release = "\
SHA256:
 abc 100 ../../etc/passwd
 def 200 main/binary-amd64/Packages
";
        service
            .invalidate_dist_packages_cache("apt-debian", "bookworm", release)
            .await;

        let deletes = storage.deletes_snapshot().await;
        // Only the well-formed entry contributes: 1 path × 2 keys = 2.
        assert_eq!(
            deletes.len(),
            2,
            "traversal entry must be dropped, got {:?}",
            deletes
        );
        for k in &deletes {
            assert!(
                !k.contains(".."),
                "no delete should reference a traversal path: {:?}",
                deletes
            );
        }
    }

    // -----------------------------------------------------------------------
    // tee_upstream_to_cache (#895): proxy slow-path streaming
    //
    // The tee forwards each upstream chunk to BOTH the client stream and a
    // background cache writer. Storage failure must not affect the client;
    // upstream errors must propagate to the client; the cache writer must
    // be able to keep up under realistic chunk sizes.
    // -----------------------------------------------------------------------

    use crate::services::storage_service::{
        PutStreamResult as ServicePutStreamResult, StorageBackend as ServiceStorageBackend,
        StorageService as RealStorageService,
    };
    use futures::stream::BoxStream as ServiceBoxStream;
    use sha2::{Digest, Sha256};

    /// Recording backend used by the tee tests. Tracks the chunks delivered
    /// to put_stream + a flag for whether put_stream should fail before
    /// consuming the stream.
    struct TeeRecordingBackend {
        put_stream_chunks: tokio::sync::Mutex<Vec<Bytes>>,
        metadata_writes: tokio::sync::Mutex<Vec<(String, Bytes)>>,
        put_stream_fails: bool,
    }

    impl TeeRecordingBackend {
        fn ok() -> Arc<Self> {
            Arc::new(Self {
                put_stream_chunks: tokio::sync::Mutex::new(Vec::new()),
                metadata_writes: tokio::sync::Mutex::new(Vec::new()),
                put_stream_fails: false,
            })
        }
        fn failing() -> Arc<Self> {
            Arc::new(Self {
                put_stream_chunks: tokio::sync::Mutex::new(Vec::new()),
                metadata_writes: tokio::sync::Mutex::new(Vec::new()),
                put_stream_fails: true,
            })
        }
    }

    #[async_trait::async_trait]
    impl ServiceStorageBackend for TeeRecordingBackend {
        async fn put(&self, key: &str, content: Bytes) -> Result<()> {
            // Metadata sidecars use this path; record so tests can assert
            // the sidecar shape after a successful put_stream.
            self.metadata_writes
                .lock()
                .await
                .push((key.to_string(), content));
            Ok(())
        }
        async fn get(&self, _key: &str) -> Result<Bytes> {
            Err(AppError::NotFound("not relevant for tee tests".into()))
        }
        async fn exists(&self, _key: &str) -> Result<bool> {
            Ok(false)
        }
        async fn delete(&self, _key: &str) -> Result<()> {
            Ok(())
        }
        async fn list(&self, _prefix: Option<&str>) -> Result<Vec<String>> {
            Ok(vec![])
        }
        async fn copy(&self, _src: &str, _dst: &str) -> Result<()> {
            Ok(())
        }
        async fn size(&self, _key: &str) -> Result<u64> {
            Ok(0)
        }
        async fn put_stream(
            &self,
            _key: &str,
            stream: ServiceBoxStream<'static, Result<Bytes>>,
        ) -> Result<ServicePutStreamResult> {
            if self.put_stream_fails {
                return Err(AppError::Storage("simulated storage failure".to_string()));
            }
            use futures::StreamExt;
            let mut hasher = Sha256::new();
            let mut total: u64 = 0;
            let mut chunks = self.put_stream_chunks.lock().await;
            tokio::pin!(stream);
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                hasher.update(&chunk);
                total += chunk.len() as u64;
                chunks.push(chunk);
            }
            Ok(ServicePutStreamResult {
                checksum_sha256: format!("{:x}", hasher.finalize()),
                bytes_written: total,
            })
        }
    }

    fn upstream_chunks(chunks: Vec<&'static [u8]>) -> BoxStream<'static, Result<Bytes>> {
        Box::pin(futures::stream::iter(
            chunks.into_iter().map(|c| Ok(Bytes::from_static(c))),
        ))
    }

    fn template() -> CacheMetadataTemplate {
        CacheMetadataTemplate {
            content_type: Some("application/octet-stream".to_string()),
            etag: None,
            ttl_secs: 60,
        }
    }

    /// Happy path: upstream produces 3 chunks. Client receives all 3 in
    /// order. Storage receives all 3 in order. Metadata sidecar written
    /// with the correct SHA-256 + byte count.
    #[tokio::test]
    async fn test_tee_forwards_all_chunks_to_client_and_storage() {
        let backend = TeeRecordingBackend::ok();
        let storage = Arc::new(RealStorageService::new(backend.clone()));

        let upstream = upstream_chunks(vec![b"hello", b" ", b"world"]);
        let mut client = tee_upstream_to_cache(
            upstream,
            storage,
            "cache-key".to_string(),
            "meta-key".to_string(),
            template(),
        );

        let mut received: Vec<u8> = Vec::new();
        while let Some(chunk) = client.next().await {
            received.extend_from_slice(&chunk.expect("client chunk"));
        }
        assert_eq!(received, b"hello world");

        // Give the writer task a chance to flush.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let stored: Vec<u8> = backend
            .put_stream_chunks
            .lock()
            .await
            .iter()
            .flat_map(|b| b.to_vec())
            .collect();
        assert_eq!(stored, b"hello world");

        // Metadata sidecar: one write, JSON-parseable, hashes match.
        let writes = backend.metadata_writes.lock().await;
        assert_eq!(writes.len(), 1, "exactly one metadata sidecar write");
        assert_eq!(writes[0].0, "meta-key");
        let metadata: CacheMetadata =
            serde_json::from_slice(&writes[0].1).expect("metadata JSON parseable");
        assert_eq!(metadata.size_bytes, 11);
        // SHA-256("hello world") known value:
        assert_eq!(
            metadata.checksum_sha256,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    /// Storage failure does NOT break the client. The client still
    /// receives the full upstream body; only the cache write fails,
    /// which is logged and the metadata sidecar is skipped so the
    /// next request re-fetches.
    #[tokio::test]
    async fn test_tee_storage_failure_does_not_break_client() {
        let backend = TeeRecordingBackend::failing();
        let storage = Arc::new(RealStorageService::new(backend.clone()));

        let upstream = upstream_chunks(vec![b"chunk-a", b"chunk-b"]);
        let mut client = tee_upstream_to_cache(
            upstream,
            storage,
            "cache-key".to_string(),
            "meta-key".to_string(),
            template(),
        );

        let mut received: Vec<u8> = Vec::new();
        while let Some(chunk) = client.next().await {
            received.extend_from_slice(&chunk.expect("client must still receive"));
        }
        assert_eq!(
            received, b"chunk-achunk-b",
            "storage failure must not affect client; client gets full body"
        );

        // Give writer task time to finish failing.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            backend.metadata_writes.lock().await.is_empty(),
            "failed put_stream MUST skip the metadata sidecar so the next \
             request re-fetches upstream (cache self-heals)"
        );
    }

    /// Empty upstream (e.g. a 0-byte upstream object) round-trips
    /// cleanly. Edge case for the channel-drop-on-EOF sequence.
    #[tokio::test]
    async fn test_tee_empty_upstream_yields_empty_body_and_writes_metadata() {
        let backend = TeeRecordingBackend::ok();
        let storage = Arc::new(RealStorageService::new(backend.clone()));

        let upstream = upstream_chunks(vec![]);
        let mut client = tee_upstream_to_cache(
            upstream,
            storage,
            "cache-key".to_string(),
            "meta-key".to_string(),
            template(),
        );

        let mut total: usize = 0;
        while let Some(chunk) = client.next().await {
            total += chunk.unwrap().len();
        }
        assert_eq!(total, 0);

        tokio::time::sleep(Duration::from_millis(50)).await;
        let writes = backend.metadata_writes.lock().await;
        assert_eq!(writes.len(), 1, "empty-body cache still gets metadata");
        let metadata: CacheMetadata = serde_json::from_slice(&writes[0].1).unwrap();
        assert_eq!(metadata.size_bytes, 0);
        // SHA-256 of empty input:
        assert_eq!(
            metadata.checksum_sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// An error mid-upstream-stream must surface to the client AND
    /// cause the storage writer to abandon the cache (no metadata
    /// sidecar). Chunks delivered before the error are NOT promoted
    /// to a "partial" cache: the writer task observes the upstream
    /// error via the channel and put_stream returns Err, so the
    /// metadata sidecar branch is skipped.
    #[tokio::test]
    async fn test_tee_upstream_error_mid_stream_aborts_cache() {
        let backend = TeeRecordingBackend::ok();
        let storage = Arc::new(RealStorageService::new(backend.clone()));

        let upstream: BoxStream<'static, Result<Bytes>> = Box::pin(futures::stream::iter(vec![
            Ok(Bytes::from_static(b"first-chunk")),
            Err(AppError::Storage("upstream connection reset".to_string())),
        ]));

        let mut client = tee_upstream_to_cache(
            upstream,
            storage,
            "cache-key".to_string(),
            "meta-key".to_string(),
            template(),
        );

        // First chunk delivered normally.
        let first = client.next().await.expect("first chunk").expect("ok");
        assert_eq!(first.as_ref(), b"first-chunk");
        // Second pull surfaces the upstream error.
        match client.next().await {
            Some(Err(_)) => {}
            other => panic!(
                "expected upstream error to surface to client; got Some/Err shape: {}",
                other.is_some()
            ),
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            backend.metadata_writes.lock().await.is_empty(),
            "upstream error mid-stream MUST NOT leave a metadata sidecar"
        );
    }

    /// Single-chunk upstream (small files served through the streaming
    /// path) round-trips cleanly. Exercises the "EOF after first send"
    /// branch separate from the many-chunk loop.
    #[tokio::test]
    async fn test_tee_single_chunk_round_trip() {
        let backend = TeeRecordingBackend::ok();
        let storage = Arc::new(RealStorageService::new(backend.clone()));

        let upstream = upstream_chunks(vec![b"solo"]);
        let mut client = tee_upstream_to_cache(
            upstream,
            storage,
            "cache-key".to_string(),
            "meta-key".to_string(),
            template(),
        );
        let mut received = Vec::new();
        while let Some(chunk) = client.next().await {
            received.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(received, b"solo");

        tokio::time::sleep(Duration::from_millis(50)).await;
        let stored: Vec<u8> = backend
            .put_stream_chunks
            .lock()
            .await
            .iter()
            .flat_map(|b| b.to_vec())
            .collect();
        assert_eq!(stored, b"solo");
    }

    /// Pin the metadata sidecar shape: etag, content-type, and TTL
    /// must round-trip through the writer task. Catches regressions
    /// that drop fields between the template and the persisted JSON.
    #[tokio::test]
    async fn test_tee_metadata_sidecar_carries_etag_and_ttl() {
        let backend = TeeRecordingBackend::ok();
        let storage = Arc::new(RealStorageService::new(backend.clone()));

        let upstream = upstream_chunks(vec![b"payload"]);
        let template = CacheMetadataTemplate {
            content_type: Some("application/x-deb".to_string()),
            etag: Some("\"abc123\"".to_string()),
            ttl_secs: 7200,
        };
        let mut client = tee_upstream_to_cache(
            upstream,
            storage,
            "cache-key".to_string(),
            "meta-key".to_string(),
            template,
        );
        while client.next().await.is_some() {}

        tokio::time::sleep(Duration::from_millis(50)).await;
        let writes = backend.metadata_writes.lock().await;
        assert_eq!(writes.len(), 1);
        let metadata: CacheMetadata = serde_json::from_slice(&writes[0].1).unwrap();
        assert_eq!(metadata.content_type.as_deref(), Some("application/x-deb"));
        assert_eq!(metadata.upstream_etag.as_deref(), Some("\"abc123\""));
        let ttl_seen = (metadata.expires_at - metadata.cached_at).num_seconds();
        assert!(
            (7195..=7205).contains(&ttl_seen),
            "expected expires_at - cached_at ~= 7200s, got {}s",
            ttl_seen
        );
    }

    /// Recording backend that surfaces a configurable `head_etag` so we
    /// can prove the tee writer pins the backend's ETag (#1051) into
    /// `CacheMetadata::storage_etag` right after `put_stream`.
    struct TeeEtagBackend {
        inner: tokio::sync::Mutex<Vec<(String, Bytes)>>,
        etag: Option<String>,
    }

    #[async_trait::async_trait]
    impl ServiceStorageBackend for TeeEtagBackend {
        async fn put(&self, key: &str, content: Bytes) -> Result<()> {
            self.inner.lock().await.push((key.to_string(), content));
            Ok(())
        }
        async fn get(&self, _key: &str) -> Result<Bytes> {
            Err(AppError::NotFound("n/a".into()))
        }
        async fn exists(&self, _key: &str) -> Result<bool> {
            Ok(false)
        }
        async fn head_etag(&self, _key: &str) -> Result<Option<String>> {
            Ok(self.etag.clone())
        }
        async fn delete(&self, _key: &str) -> Result<()> {
            Ok(())
        }
        async fn list(&self, _p: Option<&str>) -> Result<Vec<String>> {
            Ok(vec![])
        }
        async fn copy(&self, _s: &str, _d: &str) -> Result<()> {
            Ok(())
        }
        async fn size(&self, _k: &str) -> Result<u64> {
            Ok(0)
        }
        async fn put_stream(
            &self,
            _key: &str,
            stream: ServiceBoxStream<'static, Result<Bytes>>,
        ) -> Result<ServicePutStreamResult> {
            use futures::StreamExt;
            let mut hasher = Sha256::new();
            let mut total: u64 = 0;
            tokio::pin!(stream);
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                hasher.update(&chunk);
                total += chunk.len() as u64;
            }
            Ok(ServicePutStreamResult {
                checksum_sha256: format!("{:x}", hasher.finalize()),
                bytes_written: total,
            })
        }
    }

    #[tokio::test]
    async fn test_tee_writer_pins_storage_etag_when_backend_surfaces_one() {
        // When the backend reports an ETag after the streaming put, the
        // tee writer must persist it into `CacheMetadata::storage_etag`
        // so the next fast-path read can revalidate against it (#1051).
        let backend = Arc::new(TeeEtagBackend {
            inner: tokio::sync::Mutex::new(Vec::new()),
            etag: Some("\"after-put-etag\"".to_string()),
        });
        let storage = Arc::new(RealStorageService::new(backend.clone()));

        let upstream = upstream_chunks(vec![b"payload"]);
        let mut client = tee_upstream_to_cache(
            upstream,
            storage,
            "cache-key".to_string(),
            "meta-key".to_string(),
            template(),
        );
        while client.next().await.is_some() {}
        tokio::time::sleep(Duration::from_millis(50)).await;

        let writes = backend.inner.lock().await;
        let (_, json) = writes.last().expect("metadata sidecar must be written");
        let metadata: CacheMetadata = serde_json::from_slice(json).unwrap();
        assert_eq!(
            metadata.storage_etag.as_deref(),
            Some("\"after-put-etag\""),
            "tee writer must pin the backend's post-put ETag for fast-path revalidation"
        );
    }

    #[tokio::test]
    async fn test_tee_writer_leaves_storage_etag_none_when_backend_has_no_etag() {
        // Filesystem-style backends return `Ok(None)` from `head_etag`.
        // The writer must accept that and leave `storage_etag = None` so
        // the fast path falls back to the existence-only legacy semantics.
        let backend = Arc::new(TeeEtagBackend {
            inner: tokio::sync::Mutex::new(Vec::new()),
            etag: None,
        });
        let storage = Arc::new(RealStorageService::new(backend.clone()));

        let upstream = upstream_chunks(vec![b"payload"]);
        let mut client = tee_upstream_to_cache(
            upstream,
            storage,
            "cache-key".to_string(),
            "meta-key".to_string(),
            template(),
        );
        while client.next().await.is_some() {}
        tokio::time::sleep(Duration::from_millis(50)).await;

        let writes = backend.inner.lock().await;
        let (_, json) = writes.last().expect("metadata sidecar must be written");
        let metadata: CacheMetadata = serde_json::from_slice(json).unwrap();
        assert!(
            metadata.storage_etag.is_none(),
            "no backend ETag means no pin, preserving pre-#1051 fast-path semantics"
        );
    }

    // -----------------------------------------------------------------------
    // validate_upstream_status: pure status-classification logic
    // extracted from read_upstream_response_streaming so the truth
    // table is testable without a real reqwest::Response. #895.
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_upstream_status_2xx_is_ok() {
        validate_upstream_status(StatusCode::OK, "http://x").expect("200 must pass");
        validate_upstream_status(StatusCode::PARTIAL_CONTENT, "http://x")
            .expect("206 (partial content) is 2xx and must pass");
        validate_upstream_status(StatusCode::NO_CONTENT, "http://x").expect("204 must pass");
    }

    #[test]
    fn test_validate_upstream_status_404_is_not_found() {
        match validate_upstream_status(StatusCode::NOT_FOUND, "http://up/x") {
            Err(AppError::NotFound(msg)) => assert!(msg.contains("http://up/x")),
            other => panic!(
                "404 MUST classify as NotFound so callers handle it as a \
                 real cache-miss signal, not a 5xx-class backend failure; \
                 got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_validate_upstream_status_5xx_is_service_unavailable() {
        // #1445: upstream 5xx (502/503/504/etc.) MUST map to
        // ServiceUnavailable so the client sees a 503 (a transient,
        // "retry in a moment" signal) instead of a raw 502 leaking from
        // upstream. The previous mapping (Storage -> 502) made every
        // flaky-upstream incident look like a permanent gateway failure
        // to clients and broke the contract that the proxy returns
        // either 2xx or 503 under load.
        match validate_upstream_status(StatusCode::INTERNAL_SERVER_ERROR, "http://up/x") {
            Err(AppError::ServiceUnavailable(msg)) => {
                assert!(msg.contains("500"));
                assert!(msg.contains("http://up/x"));
            }
            other => panic!(
                "500 must map to AppError::ServiceUnavailable; got {:?}",
                other
            ),
        }
        match validate_upstream_status(StatusCode::BAD_GATEWAY, "http://up/x") {
            Err(AppError::ServiceUnavailable(_)) => {}
            other => panic!(
                "502 must map to AppError::ServiceUnavailable so the proxy \
                 returns 503 instead of leaking the raw upstream 502 \
                 (closes #1445); got {:?}",
                other
            ),
        }
        match validate_upstream_status(StatusCode::SERVICE_UNAVAILABLE, "http://up/x") {
            Err(AppError::ServiceUnavailable(_)) => {}
            other => panic!(
                "503 must map to AppError::ServiceUnavailable; got {:?}",
                other
            ),
        }
        match validate_upstream_status(StatusCode::GATEWAY_TIMEOUT, "http://up/x") {
            Err(AppError::ServiceUnavailable(_)) => {}
            other => panic!(
                "504 must map to AppError::ServiceUnavailable; got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_validate_upstream_status_4xx_other_is_bad_gateway() {
        // Non-404 4xx (e.g. 401 if it slipped past the retry path, or
        // 403 from a misconfigured private mirror) is genuinely a
        // gateway-side / auth-misconfig problem and stays mapped to
        // BadGateway (502). A 503 would mislead clients into retrying
        // an auth failure that needs a config fix.
        match validate_upstream_status(StatusCode::FORBIDDEN, "http://up/x") {
            Err(AppError::BadGateway(_)) => {}
            other => panic!("403 must map to AppError::BadGateway; got {:?}", other),
        }
        match validate_upstream_status(StatusCode::UNAUTHORIZED, "http://up/x") {
            Err(AppError::BadGateway(_)) => {}
            other => panic!("401 must map to AppError::BadGateway; got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // B6: coalescing-waiter 502 leak. Under a cache stampede, every
    // concurrent waiter consults the proxy cache before re-fetching. If the
    // single-flight leader's upstream fetch failed and left a transiently
    // unreadable cache entry (mid-write, half-written sidecar, or a poisoned
    // partial), reading that entry must NOT surface as a raw 502 to the
    // waiter. `get_cached_artifact` must treat a non-NotFound storage error
    // as a cache MISS (`Ok(None)`) so the waiter re-fetches upstream and
    // gets a clean 2xx or a 503 (via `validate_upstream_status`) — never the
    // raw upstream 502 the stampede gate rejects.
    // -----------------------------------------------------------------------

    /// Mock backend that serves valid, fresh metadata but fails the body
    /// read with a transient `Storage` error (models a waiter racing the
    /// leader's cache write, or a poisoned partial body).
    struct PoisonedCacheBodyMock {
        metadata: Bytes,
    }

    #[async_trait::async_trait]
    impl crate::services::storage_service::StorageBackend for PoisonedCacheBodyMock {
        async fn put(&self, _key: &str, _content: Bytes) -> Result<()> {
            Ok(())
        }
        async fn get(&self, key: &str) -> Result<Bytes> {
            if key.ends_with("__cache_meta__.json") {
                Ok(self.metadata.clone())
            } else {
                // The body read fails transiently (NOT NotFound).
                Err(AppError::Storage(
                    "transient backend read error".to_string(),
                ))
            }
        }
        async fn exists(&self, _key: &str) -> Result<bool> {
            Ok(true)
        }
        async fn delete(&self, _key: &str) -> Result<()> {
            Ok(())
        }
        async fn list(&self, _prefix: Option<&str>) -> Result<Vec<String>> {
            Ok(vec![])
        }
        async fn copy(&self, _src: &str, _dst: &str) -> Result<()> {
            Ok(())
        }
        async fn size(&self, _key: &str) -> Result<u64> {
            Ok(0)
        }
    }

    #[tokio::test]
    async fn test_coalescing_waiter_treats_unreadable_cache_body_as_miss_not_502() {
        let mock = Arc::new(PoisonedCacheBodyMock {
            metadata: fresh_metadata_bytes(),
        });
        let service = build_proxy_service_with_storage(mock);

        let result = service
            .get_cached_artifact(
                "proxy-cache/npm-proxy/lodash/__content__",
                "proxy-cache/npm-proxy/lodash/__cache_meta__.json",
            )
            .await;

        // Must be Ok(None) (treated as miss -> caller refetches upstream),
        // NOT Err(_) which would map to a raw 502 for every concurrent waiter.
        match result {
            Ok(None) => {}
            Ok(Some(_)) => panic!(
                "a body read error must not be promoted to a cache hit; \
                 got Ok(Some(_))"
            ),
            Err(e) => panic!(
                "coalescing waiter saw a raw cache read error (would surface \
                 as 502); it must be treated as a miss instead. got Err({:?})",
                e
            ),
        }
    }

    #[tokio::test]
    async fn test_coalescing_waiter_treats_unreadable_metadata_as_miss_not_502() {
        /// Backend whose metadata sidecar read fails transiently.
        struct PoisonedMetadataMock;
        #[async_trait::async_trait]
        impl crate::services::storage_service::StorageBackend for PoisonedMetadataMock {
            async fn put(&self, _key: &str, _content: Bytes) -> Result<()> {
                Ok(())
            }
            async fn get(&self, _key: &str) -> Result<Bytes> {
                Err(AppError::Storage(
                    "transient metadata read error".to_string(),
                ))
            }
            async fn exists(&self, _key: &str) -> Result<bool> {
                Ok(true)
            }
            async fn delete(&self, _key: &str) -> Result<()> {
                Ok(())
            }
            async fn list(&self, _prefix: Option<&str>) -> Result<Vec<String>> {
                Ok(vec![])
            }
            async fn copy(&self, _src: &str, _dst: &str) -> Result<()> {
                Ok(())
            }
            async fn size(&self, _key: &str) -> Result<u64> {
                Ok(0)
            }
        }

        let service = build_proxy_service_with_storage(Arc::new(PoisonedMetadataMock));

        let result = service
            .get_cached_artifact(
                "proxy-cache/npm-proxy/lodash/__content__",
                "proxy-cache/npm-proxy/lodash/__cache_meta__.json",
            )
            .await;

        match result {
            Ok(None) => {}
            other => panic!(
                "a metadata read error must be treated as a cache miss (Ok(None)), \
                 not a raw 502; got {:?}",
                other.map(|o| o.is_some())
            ),
        }
    }

    // -----------------------------------------------------------------------
    // B8: pypi simple-root recovers cached project names from the proxy
    // cache so a Remote repo's root index lists packages even though
    // proxy-cached artifacts no longer land in the `artifacts` table (#1278).
    // -----------------------------------------------------------------------

    #[test]
    fn test_pypi_package_names_from_cache_keys_extracts_projects() {
        let keys = vec![
            "proxy-cache/pypi-remote/simple/flask/__content__",
            "proxy-cache/pypi-remote/simple/flask/__cache_meta__.json",
            "proxy-cache/pypi-remote/simple/requests/__content__",
            "proxy-cache/pypi-remote/simple/numpy/__content__",
        ];
        let names = ProxyService::pypi_package_names_from_cache_keys("pypi-remote", keys);
        // Deduped (flask appears twice across content + metadata) and sorted.
        assert_eq!(names, vec!["flask", "numpy", "requests"]);
    }

    #[test]
    fn test_pypi_package_names_from_cache_keys_skips_root_and_other_repos() {
        let keys = vec![
            // bare simple root index (empty project segment) — must be skipped
            "proxy-cache/pypi-remote/simple//__content__",
            // a __content__ directly under simple/ with no project — skipped
            "proxy-cache/pypi-remote/simple/__content__",
            // a different repo's cache — must not leak in
            "proxy-cache/other-repo/simple/django/__content__",
            // an unrelated (non-simple) cache entry — skipped
            "proxy-cache/pypi-remote/packages/foo.whl/__content__",
            // a real project — kept
            "proxy-cache/pypi-remote/simple/flask/__content__",
        ];
        let names = ProxyService::pypi_package_names_from_cache_keys("pypi-remote", keys);
        assert_eq!(names, vec!["flask"]);
    }

    // -----------------------------------------------------------------------
    // extract_streaming_headers: pure header parsing. Verifies the
    // Content-Length parse-or-skip behaviour and the etag/content-type
    // round-trip without a reqwest::Response. #895.
    // -----------------------------------------------------------------------

    use reqwest::header::{HeaderMap, HeaderValue};

    #[test]
    fn test_extract_streaming_headers_full_set() {
        let mut h = HeaderMap::new();
        h.insert(CONTENT_TYPE, HeaderValue::from_static("application/x-deb"));
        h.insert(ETAG, HeaderValue::from_static("\"abc123\""));
        h.insert(CONTENT_LENGTH, HeaderValue::from_static("12345"));
        let (ct, etag, len) = extract_streaming_headers(&h);
        assert_eq!(ct.as_deref(), Some("application/x-deb"));
        assert_eq!(etag.as_deref(), Some("\"abc123\""));
        assert_eq!(len, Some(12345));
    }

    #[test]
    fn test_extract_streaming_headers_empty() {
        let h = HeaderMap::new();
        let (ct, etag, len) = extract_streaming_headers(&h);
        assert!(ct.is_none());
        assert!(etag.is_none());
        assert!(len.is_none());
    }

    #[test]
    fn test_extract_streaming_headers_non_numeric_content_length_yields_none() {
        // A misbehaving upstream that returned a non-numeric
        // Content-Length must not panic or default to 0; the proxy
        // simply drops the value and the outbound response falls
        // back to chunked transfer encoding.
        let mut h = HeaderMap::new();
        h.insert(CONTENT_LENGTH, HeaderValue::from_static("not-a-number"));
        let (_, _, len) = extract_streaming_headers(&h);
        assert!(len.is_none());
    }

    #[test]
    fn test_extract_streaming_headers_non_utf8_etag_is_dropped() {
        // HTTP headers are sometimes non-UTF8 bytes (broken
        // upstreams). The parser silently drops them rather than
        // erroring; the outbound response simply omits the etag.
        let mut h = HeaderMap::new();
        let bad = HeaderValue::from_bytes(b"\xff\xfe").unwrap();
        h.insert(ETAG, bad);
        let (_, etag, _) = extract_streaming_headers(&h);
        assert!(etag.is_none());
    }

    /// Pin StreamingFetchResult's content_length passthrough. The
    /// proxy_fetch_streaming helper uses this to set Content-Length
    /// on the outbound response; dropping it would force every
    /// streamed proxy response to chunked transfer encoding even
    /// when upstream advertised an exact length.
    #[test]
    fn test_streaming_fetch_result_carries_content_length() {
        let dummy: BoxStream<'static, Result<Bytes>> = Box::pin(futures::stream::iter(vec![]));
        let r = StreamingFetchResult {
            body: dummy,
            content_type: Some("application/octet-stream".to_string()),
            content_length: Some(12345),
        };
        assert_eq!(r.content_length, Some(12345));
        assert_eq!(r.content_type.as_deref(), Some("application/octet-stream"));
    }

    /// Many small chunks should not regress to the buffering antipattern.
    /// 256 chunks of 256 bytes (64 KiB total) is comfortably below the
    /// channel depth × chunk size threshold; verifies the channel
    /// throughput on realistic chunk counts.
    #[tokio::test]
    async fn test_tee_many_small_chunks_round_trip() {
        let backend = TeeRecordingBackend::ok();
        let storage = Arc::new(RealStorageService::new(backend.clone()));

        const COUNT: u32 = 256;
        const CHUNK_SIZE: usize = 256;
        let total_expected: u64 = COUNT as u64 * CHUNK_SIZE as u64;
        let upstream_iter = (0..COUNT).map(|i| Ok(Bytes::from(vec![(i & 0xff) as u8; CHUNK_SIZE])));
        let upstream: BoxStream<'static, Result<Bytes>> =
            Box::pin(futures::stream::iter(upstream_iter));

        let mut client = tee_upstream_to_cache(
            upstream,
            storage,
            "cache-key".to_string(),
            "meta-key".to_string(),
            template(),
        );

        let mut received: u64 = 0;
        while let Some(chunk) = client.next().await {
            received += chunk.unwrap().len() as u64;
        }
        assert_eq!(received, total_expected);

        tokio::time::sleep(Duration::from_millis(100)).await;
        let writes = backend.metadata_writes.lock().await;
        assert_eq!(writes.len(), 1);
        let metadata: CacheMetadata = serde_json::from_slice(&writes[0].1).unwrap();
        assert_eq!(metadata.size_bytes as u64, total_expected);
    }

    /// #1185 regression (client side): on upstream error mid-body the
    /// tee MUST (a) surface the *original* error to the client (the
    /// BadGateway re-tag is only on the writer-channel side; the
    /// handler maps the client-side error to a 502 via
    /// `map_proxy_error`) and (b) NOT promote partial bytes to a
    /// cache hit. The category assertion lives in
    /// [`test_tee_writer_sees_bad_gateway_category_on_upstream_error`];
    /// keeping the two concerns in separate tests makes a future
    /// regression bisectable.
    #[tokio::test]
    async fn test_tee_upstream_error_surfaces_original_error_and_blocks_caching() {
        let backend = TeeRecordingBackend::ok();
        let storage = Arc::new(RealStorageService::new(backend.clone()));

        // Inject an upstream error directly (simulates a `reqwest`
        // bytes_stream yielding `Err` mid-body).
        let upstream: BoxStream<'static, Result<Bytes>> = Box::pin(futures::stream::iter(vec![
            Ok(Bytes::from_static(b"ok-prefix")),
            Err(AppError::Internal("simulated upstream reset".to_string())),
        ]));

        let mut client = tee_upstream_to_cache(
            upstream,
            storage,
            "cache-key".to_string(),
            "meta-key".to_string(),
            template(),
        );

        // First chunk OK.
        let first = client.next().await.expect("first chunk").expect("ok");
        assert_eq!(first.as_ref(), b"ok-prefix");

        // Second poll yields the *original* upstream error variant
        // unchanged. We assert the variant explicitly so a future
        // refactor that silently re-tags the client-side error
        // (which would change handler error mapping) trips this test.
        match client.next().await {
            Some(Err(AppError::Internal(_))) => {}
            other => panic!(
                "expected upstream `AppError::Internal` to surface to \
                 client unchanged; got {:?}",
                other
            ),
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            backend.metadata_writes.lock().await.is_empty(),
            "upstream error MUST NOT promote partial bytes to a cache hit"
        );
    }

    /// #1185 regression: the BadGateway wrapping is observable on the
    /// writer channel side. We assert by recording the put_stream
    /// chunks; on upstream error the writer sees `Err(BadGateway(_))`
    /// not `Err(Storage(_))`, so `put_stream` returns Err and the
    /// metadata-sidecar branch is skipped.
    ///
    /// This complements the client-facing test above by pinning the
    /// behaviour on the storage-writer side of the tee.
    #[tokio::test]
    async fn test_tee_writer_sees_bad_gateway_category_on_upstream_error() {
        /// Recording backend that captures the FIRST error category it
        /// sees on the put_stream input. Used to assert the tee's
        /// error wrapping reaches the writer task with the right tag.
        struct CategoryRecordingBackend {
            seen_error: tokio::sync::Mutex<Option<String>>,
        }
        #[async_trait::async_trait]
        impl ServiceStorageBackend for CategoryRecordingBackend {
            async fn put(&self, _: &str, _: Bytes) -> Result<()> {
                Ok(())
            }
            async fn get(&self, _: &str) -> Result<Bytes> {
                Err(AppError::NotFound("n/a".into()))
            }
            async fn exists(&self, _: &str) -> Result<bool> {
                Ok(false)
            }
            async fn delete(&self, _: &str) -> Result<()> {
                Ok(())
            }
            async fn list(&self, _: Option<&str>) -> Result<Vec<String>> {
                Ok(vec![])
            }
            async fn copy(&self, _: &str, _: &str) -> Result<()> {
                Ok(())
            }
            async fn size(&self, _: &str) -> Result<u64> {
                Ok(0)
            }
            async fn put_stream(
                &self,
                _: &str,
                stream: ServiceBoxStream<'static, Result<Bytes>>,
            ) -> Result<ServicePutStreamResult> {
                use futures::StreamExt;
                tokio::pin!(stream);
                while let Some(chunk) = stream.next().await {
                    if let Err(e) = chunk {
                        // Variant name is stable across the codebase.
                        let tag = match &e {
                            AppError::BadGateway(_) => "BadGateway",
                            AppError::Storage(_) => "Storage",
                            AppError::Internal(_) => "Internal",
                            other => {
                                let s = format!("{:?}", other);
                                Box::leak(s.into_boxed_str()) as &'static str
                            }
                        };
                        *self.seen_error.lock().await = Some(tag.to_string());
                        return Err(e);
                    }
                }
                Ok(ServicePutStreamResult {
                    checksum_sha256: String::new(),
                    bytes_written: 0,
                })
            }
        }

        let backend = Arc::new(CategoryRecordingBackend {
            seen_error: tokio::sync::Mutex::new(None),
        });
        let storage = Arc::new(RealStorageService::new(backend.clone()));

        let upstream: BoxStream<'static, Result<Bytes>> = Box::pin(futures::stream::iter(vec![
            Ok(Bytes::from_static(b"prefix")),
            Err(AppError::Internal("upstream reset".to_string())),
        ]));

        let mut client = tee_upstream_to_cache(
            upstream,
            storage,
            "cache-key".to_string(),
            "meta-key".to_string(),
            template(),
        );
        while client.next().await.is_some() {}

        tokio::time::sleep(Duration::from_millis(50)).await;
        let seen = backend.seen_error.lock().await.clone();
        assert_eq!(
            seen.as_deref(),
            Some("BadGateway"),
            "tee MUST wrap upstream errors as BadGateway before forwarding \
             to the writer channel; got {:?}",
            seen
        );
    }

    /// #1184 regression: pin the TEE_CHANNEL_DEPTH constant so a
    /// future "let's just raise the buffer" change must come with a
    /// fresh OOM-budget review. Bumping the cap silently would
    /// invalidate the documented worst-case calculation.
    #[test]
    fn test_tee_channel_depth_pinned_for_oom_budget() {
        assert_eq!(
            TEE_CHANNEL_DEPTH, 64,
            "TEE_CHANNEL_DEPTH is part of the per-request OOM budget; \
             see the const's docstring for the full calculation and \
             #1184 for the HTTP/2 flow-control overhead. Update the \
             docstring before changing this value."
        );
        assert_eq!(
            TEE_MAX_CHUNK_BYTES,
            64 * 1024,
            "TEE_MAX_CHUNK_BYTES * TEE_CHANNEL_DEPTH bounds the per-request \
             tee memory; changing it changes the OOM budget. Update the \
             docstring before changing this value."
        );
    }

    /// #1184 regression: an upstream chunk larger than `TEE_MAX_CHUNK_BYTES`
    /// MUST be split before being forwarded to the cache writer, so the
    /// `TEE_CHANNEL_DEPTH * TEE_MAX_CHUNK_BYTES` memory bound holds
    /// regardless of upstream framing. The client must still observe the
    /// same total bytes in order.
    #[tokio::test]
    async fn test_tee_splits_oversize_upstream_chunks_to_cap_memory() {
        let backend = TeeRecordingBackend::ok();
        let storage = Arc::new(RealStorageService::new(backend.clone()));

        // Upstream hands us a single 200 KiB chunk. With a 64 KiB cap that
        // must surface to the client as four pieces (64 + 64 + 64 + 8 KiB).
        let big = Bytes::from(vec![0xABu8; 200 * 1024]);
        let upstream: BoxStream<'static, Result<Bytes>> =
            Box::pin(futures::stream::iter(vec![Ok(big.clone())]));

        let mut client = tee_upstream_to_cache(
            upstream,
            storage,
            "cache-key".to_string(),
            "meta-key".to_string(),
            template(),
        );

        let mut pieces: Vec<Bytes> = Vec::new();
        while let Some(item) = client.next().await {
            pieces.push(item.expect("ok chunk"));
        }
        assert_eq!(
            pieces.len(),
            4,
            "200 KiB / 64 KiB cap => 4 client pieces, got {}",
            pieces.len()
        );
        for (i, p) in pieces.iter().enumerate() {
            let expected = if i < 3 {
                64 * 1024
            } else {
                200 * 1024 - 3 * 64 * 1024
            };
            assert_eq!(
                p.len(),
                expected,
                "piece {} length: got {}, expected {}",
                i,
                p.len(),
                expected
            );
        }
        let total: usize = pieces.iter().map(|p| p.len()).sum();
        assert_eq!(total, big.len(), "client must receive every byte");
    }

    // -----------------------------------------------------------------------
    // Accept-header forwarding (OCI manifest content negotiation).
    //
    // Regression coverage for the manifest-pull 404 reported on
    // tests/formats/test-oci-remote.sh. fetch_artifact stripped the client's
    // `Accept` before the upstream GET, which on Docker-Hub-like registries
    // forced the default representation and on JFrog / Harbor surfaced as
    // 404 / 406 outright. fetch_artifact_with_accept must propagate it.
    //
    // Both tests below need a live `DATABASE_URL` because
    // `ProxyService::fetch_from_upstream_with_accept` calls
    // `load_upstream_auth` before issuing the HTTP request. They no-op on
    // CI runners that don't expose the test DB, mirroring the rest of the
    // proxy-service suite.
    // -----------------------------------------------------------------------

    /// Custom matcher used by the Accept-forwarding regression test.
    ///
    /// wiremock 0.6.5's `header(name, value)` does an exact-equality
    /// comparison on `Vec<HeaderValue>`, which surprisingly does NOT
    /// match a comma-joined multi-token Accept header even when the
    /// received bytes are byte-identical to the expected value (the
    /// matcher returns false for reasons that turn out to be irrelevant
    /// here; the bug class we want to catch is "proxy strips Accept",
    /// not "proxy rewrites Accept byte-for-byte").
    ///
    /// We use a substring check instead: the regression-of-interest
    /// for artifact-keeper#1256 is "proxy drops the client's Accept
    /// header entirely", which would leave NO Accept header on the
    /// upstream request. Asserting that the expected media types are
    /// present in the forwarded header value catches that bug class
    /// while being robust to whitespace / quoting normalization in
    /// the HTTP stack.
    struct AcceptHeaderContains {
        expected_substring: &'static str,
    }
    impl wiremock::Match for AcceptHeaderContains {
        fn matches(&self, request: &wiremock::Request) -> bool {
            request
                .headers
                .get("accept")
                .map(|v| v.to_str().unwrap_or("").contains(self.expected_substring))
                .unwrap_or(false)
        }
    }

    #[tokio::test]
    async fn test_fetch_artifact_with_accept_forwards_header_upstream() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let server = MockServer::start().await;
        let manifest_body =
            br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}"#;
        let accept_value = "application/vnd.oci.image.manifest.v1+json, \
                            application/vnd.docker.distribution.manifest.v2+json";

        // The matcher only fires when the request carries an Accept
        // header that contains the OCI manifest media-type. If
        // proxy_service strips the Accept header entirely (the #1256
        // regression we are guarding) the mock returns 404 via the
        // wiremock default and the assertion below catches it.
        Mock::given(method("GET"))
            .and(path("/v2/library/alpine/manifests/3.20"))
            .and(AcceptHeaderContains {
                expected_substring: "application/vnd.oci.image.manifest.v1+json",
            })
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/vnd.oci.image.manifest.v1+json")
                    .set_body_bytes(manifest_body.as_ref()),
            )
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("accept-fwd-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("create tmp");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());

        let repo = Repository {
            id: Uuid::new_v4(),
            key: "test-accept-fwd".to_string(),
            name: "test-accept-fwd".to_string(),
            description: None,
            format: RepositoryFormat::Generic,
            repo_type: RepositoryType::Remote,
            storage_backend: "filesystem".to_string(),
            storage_path: tmp.to_string_lossy().to_string(),
            upstream_url: Some(server.uri()),
            is_public: true,
            quota_bytes: None,
            replication_priority: crate::models::repository::ReplicationPriority::OnDemand,
            promotion_target_id: None,
            promotion_policy_id: None,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let result = proxy
            .fetch_artifact_with_accept(
                &repo,
                "v2/library/alpine/manifests/3.20",
                Some(accept_value),
            )
            .await;
        let _ = std::fs::remove_dir_all(&tmp);

        let (body, ct) = result.expect(
            "fetch_artifact_with_accept must succeed when the upstream mock \
             only responds 200 when the request carries the OCI manifest \
             media-type in its Accept header; a failure here means the \
             proxy stripped the client's Accept header (#1256 regression)",
        );
        assert_eq!(&body[..], manifest_body.as_ref());
        assert_eq!(
            ct.as_deref(),
            Some("application/vnd.oci.image.manifest.v1+json"),
        );
    }

    #[tokio::test]
    async fn test_fetch_artifact_with_accept_none_matches_legacy_behaviour() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let server = MockServer::start().await;
        // No Accept matcher — covers the blob/index fetch path that does NOT
        // need content negotiation. Behaviour must be identical to the
        // pre-#1219 fetch_artifact call.
        Mock::given(method("GET"))
            .and(path("/v2/library/alpine/blobs/sha256:abcd1234"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"blob-bytes".as_ref()))
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("accept-none-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("create tmp");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());

        let repo = Repository {
            id: Uuid::new_v4(),
            key: "test-accept-none".to_string(),
            name: "test-accept-none".to_string(),
            description: None,
            format: RepositoryFormat::Generic,
            repo_type: RepositoryType::Remote,
            storage_backend: "filesystem".to_string(),
            storage_path: tmp.to_string_lossy().to_string(),
            upstream_url: Some(server.uri()),
            is_public: true,
            quota_bytes: None,
            replication_priority: crate::models::repository::ReplicationPriority::OnDemand,
            promotion_target_id: None,
            promotion_policy_id: None,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let result = proxy
            .fetch_artifact_with_accept(&repo, "v2/library/alpine/blobs/sha256:abcd1234", None)
            .await;
        let _ = std::fs::remove_dir_all(&tmp);

        let (body, _) = result.expect("blob fetch with accept=None must succeed");
        assert_eq!(&body[..], b"blob-bytes");
    }

    /// #1445 (A): the buffered proxy fetch path MUST persist the
    /// upstream bytes AND make them visible to the next request through
    /// the same proxy_service. The reproducer "cached artifacts should
    /// contain `abbrev` after npm upstream fetch -- not present" asserts
    /// this round-trip end-to-end against the live `/artifacts` listing
    /// endpoint, which depends on the on-disk cache being readable via
    /// `get_cached_artifact_by_path` on the next call.
    ///
    /// This test does NOT need a real upstream: the buffered path calls
    /// `cache_artifact` synchronously (`.await`s the storage put) before
    /// returning, so we can drive `cache_artifact` directly and then
    /// assert that `get_cached_artifact_by_path` returns the same bytes.
    /// A regression in this contract (for example, dropping the
    /// metadata-sidecar write or moving it onto a fire-and-forget task)
    /// would break the listing reproducer in the same way #1445(A)
    /// reports.
    ///
    /// The wider "/artifacts listing also shows proxy-cached items"
    /// behaviour requires the storage-routing redesign described on
    /// `test_cache_artifact_does_not_insert_into_artifacts_table` and
    /// is intentionally out of scope for this fix. This test pins the
    /// half of the contract that lives inside ProxyService and is the
    /// foundation any future listing-merge work will rely on.
    #[tokio::test]
    async fn test_cache_artifact_persists_bytes_for_next_request() {
        use crate::services::storage_service::{FilesystemBackend, StorageService};

        // Use a real filesystem-backed storage so the same put/get
        // round-trip the production code does is exercised, including
        // the metadata sidecar write.
        let tmp = std::env::temp_dir().join(format!("ak-1445a-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("create tmp dir");

        let backend = Arc::new(FilesystemBackend::new(tmp.clone()));
        let storage = Arc::new(StorageService::new(backend));

        // Build the service with a `lazy` PgPool: we never call any
        // code path that touches the DB on this test.
        let pool = sqlx::PgPool::connect_lazy("postgres://invalid/").unwrap();
        let proxy = ProxyService::new(pool, storage);

        let repo_key = "npm-proxy";
        let cache_path = "abbrev/-/abbrev-1.1.1.tgz";
        let content = Bytes::from_static(b"mock-tarball-bytes-for-abbrev-1.1.1");

        // Drive cache_artifact directly with the same keys
        // `fetch_artifact_with_cache_path` derives.
        let cache_key = ProxyService::cache_storage_key(repo_key, cache_path).unwrap();
        let metadata_key = ProxyService::cache_metadata_key(repo_key, cache_path).unwrap();
        proxy
            .cache_artifact(
                &cache_key,
                &metadata_key,
                &content,
                Some("application/gzip".to_string()),
                None,
                DEFAULT_CACHE_TTL_SECS,
                Uuid::new_v4(),
                cache_path,
            )
            .await
            .expect("cache_artifact must succeed on a healthy filesystem backend");

        // The next request MUST find the cached bytes via the public
        // lookup helper used by handlers (`proxy_check_cache` is built
        // on top of this). A regression that lost the metadata sidecar
        // or wrote it under the wrong key would surface here as None.
        let lookup = proxy
            .get_cached_artifact_by_path(repo_key, cache_path)
            .await
            .expect("cache lookup must not error on a fresh entry");

        let _ = std::fs::remove_dir_all(&tmp);

        let (got, got_ct) = lookup.expect(
            "cache_artifact MUST persist bytes that the very next call to \
             get_cached_artifact_by_path can read back. The reproducer in \
             #1445(A) (`cached artifacts should contain abbrev after npm \
             upstream fetch -- not present`) trips when this round-trip \
             fails: bytes are returned to the client but the cache is \
             empty next time.",
        );
        assert_eq!(&got[..], content.as_ref());
        assert_eq!(got_ct.as_deref(), Some("application/gzip"));
    }

    /// Source-level pin for #1278: `cache_artifact` must NOT insert into
    /// the `artifacts` table. The pre-fix path inserted a row with
    /// `storage_key = "proxy-cache/<repo_key>/.../__content__"`, which
    /// then drove `serve_file`'s read through `state.storage_for_repo`
    /// against a doubled-prefix path and returned HTTP 500 on every
    /// cached read after the first on filesystem backends.
    ///
    /// This meta-test reads the on-disk source of this file and asserts
    /// the `cache_artifact` function body contains no `INSERT INTO
    /// artifacts` text. It fails loudly if a future refactor restores
    /// the insert. The mechanism mirrors the file-text meta-tests
    /// already used in `auth_service.rs` and `repositories.rs`. If a
    /// future feature wants proxy-cached items listed alongside hosted
    /// artifacts, build it via a separate `proxy_cache_artifacts` view
    /// or table, not by re-inserting here.
    #[test]
    fn test_cache_artifact_does_not_insert_into_artifacts_table() {
        let source = include_str!("proxy_service.rs");
        let fn_marker = "async fn cache_artifact(";
        let fn_start = source
            .find(fn_marker)
            .expect("cache_artifact function must exist");

        // Walk to the closing `}` at column 0 that ends the function body.
        // The codebase consistently formats item-level closers at column
        // zero (see `cargo fmt` enforcement in CI), so a literal `"\n    }\n"`
        // (four spaces of impl-block indent + line break) marks the end.
        let after_start = &source[fn_start..];
        let fn_end_rel = after_start
            .find("\n    }\n")
            .expect("cache_artifact must terminate with a column-4 closing brace");
        let fn_body = &after_start[..fn_end_rel];

        assert!(
            !fn_body
                .to_ascii_uppercase()
                .contains("INSERT INTO ARTIFACTS"),
            "cache_artifact MUST NOT INSERT INTO artifacts (#1278). \
             Pre-fix the proxy cache would record proxy-cached items as \
             first-class artifacts with `storage_key = \"proxy-cache/...\"`, \
             which drove every subsequent handler-side \
             `storage_for_repo(repo.storage_location()).get(&artifact.storage_key)` \
             read into a doubled-prefix path that 500'd on filesystem backends. \
             Cached items live on disk under `self.storage` and are served \
             via `proxy_check_cache` -- they MUST NOT be reintroduced into \
             the `artifacts` table without an explicit storage-routing redesign."
        );
    }
}
