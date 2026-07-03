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
use once_cell::sync::Lazy;
use regex::Regex;
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
use crate::services::cache_classifier;
use crate::services::metrics_service::record_proxy_cache_lookup;
use crate::services::proxy_hydration::{
    Coordinator, HydrationCoordinator, StreamHandle, StreamHeaders,
};
use crate::services::quarantine_service;
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
    /// `Last-Modified` header from upstream, persisted into the cache sidecar
    /// so a later conditional revalidation can send `If-Modified-Since` (#1611).
    last_modified: Option<String>,
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

impl From<StreamHandle> for StreamingFetchResult {
    /// Lower a coordinator [`StreamHandle`] (leader or follower) into the
    /// handler-facing fetch result. Shared by every streaming exit path so the
    /// field mapping lives in exactly one place (#1631 layer 2).
    fn from(handle: StreamHandle) -> Self {
        Self {
            body: handle.body,
            content_type: handle.headers.content_type,
            content_length: handle.headers.content_length,
        }
    }
}

impl std::fmt::Debug for StreamingFetchResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamingFetchResult")
            .field("content_type", &self.content_type)
            .field("content_length", &self.content_length)
            .field("body", &"<stream>")
            .finish()
    }
}

impl StreamingFetchResult {
    /// Collect the entire stream into a single `Bytes` buffer.
    ///
    /// Use only when the caller needs the full content for parsing.
    /// Normal download paths should pass `self.body` directly to
    /// `Body::from_stream`.
    pub async fn collect(self) -> Result<Bytes> {
        use futures::StreamExt;
        let mut buf = Vec::new();
        let mut stream = self.body;
        while let Some(chunk) = stream.next().await {
            buf.extend_from_slice(&chunk?);
        }
        Ok(Bytes::from(buf))
    }
}

/// Metadata fields known up-front when teeing an upstream stream into
/// the proxy cache. The size + sha-256 fields of [`CacheMetadata`] are
/// observed during the stream itself and filled in by the writer task
/// once the body has been fully written to storage.
struct CacheMetadataTemplate {
    content_type: Option<String>,
    etag: Option<String>,
    /// `Last-Modified` from upstream (#1611). `None` on the streaming path,
    /// which does not currently surface the header into the tee template.
    last_modified: Option<String>,
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

/// Remove credential-bearing URL material before rendering an upstream target
/// into logs or [`AppError`] messages.
fn redact_url_for_diagnostics(url: &str) -> String {
    if let Ok(mut parsed) = reqwest::Url::parse(url) {
        parsed.set_query(None);
        parsed.set_fragment(None);
        return parsed.to_string();
    }

    let query_pos = url.find('?');
    let fragment_pos = url.find('#');
    let end = match (query_pos, fragment_pos) {
        (Some(q), Some(f)) => q.min(f),
        (Some(q), None) => q,
        (None, Some(f)) => f,
        (None, None) => url.len(),
    };
    url[..end].to_string()
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
    let diagnostic_url = redact_url_for_diagnostics(url);
    if status == StatusCode::NOT_FOUND {
        return Err(AppError::NotFound(format!(
            "Artifact not found at upstream: {}",
            diagnostic_url
        )));
    }
    if status.is_server_error() {
        return Err(AppError::ServiceUnavailable(format!(
            "Upstream returned error status {}: {}",
            status, diagnostic_url
        )));
    }
    if !status.is_success() {
        return Err(AppError::BadGateway(format!(
            "Upstream returned error status {}: {}",
            status, diagnostic_url
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

/// Whether a freshly streamed proxy-cache write should be committed or
/// rejected. A rejected object is deleted (and its metadata sidecar skipped)
/// so the next request refetches upstream and self-heals.
#[derive(Debug, PartialEq, Eq)]
enum StreamWriteOutcome {
    /// Write is good; persist the metadata sidecar.
    Commit,
    /// Zero-byte body — never cache it (#1365).
    RejectEmpty,
    /// Bytes written disagree with the upstream `Content-Length`, i.e. the
    /// stream was truncated/interrupted mid-body. Committing it would poison
    /// the cache and serve a corrupt archive (#1912).
    RejectTruncated { expected: u64, actual: u64 },
}

/// Classify a completed streaming cache write. `expected_len` is the upstream
/// `Content-Length` when known; truncation is only enforced when it is present
/// (a chunked/auto-decompressed response strips it, so we cannot validate and
/// must not falsely reject).
fn classify_stream_write(bytes_written: u64, expected_len: Option<u64>) -> StreamWriteOutcome {
    if bytes_written == 0 {
        return StreamWriteOutcome::RejectEmpty;
    }
    match expected_len {
        Some(expected) if bytes_written != expected => StreamWriteOutcome::RejectTruncated {
            expected,
            actual: bytes_written,
        },
        _ => StreamWriteOutcome::Commit,
    }
}

/// Decide whether to emit a "scan-on-proxy is configured but did not run"
/// warning for a freshly cached upstream artifact.
///
/// Background (#1274): the `scan_on_proxy` per-repo flag exists in
/// `scan_configs` and is surfaced in the UI, but the security scanner
/// pipeline operates exclusively on rows in the `artifacts` table
/// (`scan_results.artifact_id` is `NOT NULL REFERENCES artifacts(id)`,
/// migration 022:21). Proxy-cached content is intentionally NOT recorded
/// in `artifacts` (#1278, enforced by the `cache_artifact` meta-test), so
/// there is no row to scan and nowhere to persist a `scan_results` record.
/// A real scan-on-proxy implementation needs a dedicated proxy-cache
/// artifact model and is tracked for v1.3.0.
///
/// Until that lands, the worst failure mode is *silent*: an operator
/// enables "Scan on Proxy", pulls packages, sees zero scans, and assumes
/// they are protected. This helper drives a loud, structured warning so
/// the gap is observable in logs/alerts instead of being invisible.
///
/// Returns `true` only when scan-on-proxy is enabled for the repo AND the
/// cache write actually created a new entry (`newly_cached`). A plain
/// cache hit re-serves already-cached bytes and must not log on every
/// request; a failed/empty cache write (`newly_cached == false`) created
/// nothing to warn about.
pub(crate) fn should_warn_proxy_scan_skipped(proxy_scan_enabled: bool, newly_cached: bool) -> bool {
    proxy_scan_enabled && newly_cached
}

/// Build the operator-facing message for the scan-on-proxy gap (#1274), or
/// `None` when no warning is warranted.
///
/// Returns `Some(message)` only when [`should_warn_proxy_scan_skipped`] is
/// true. Pulling both the gate decision and the message text into one pure
/// function keeps the async wrapper trivial and lets the wording (which an
/// operator may grep for or alert on) be asserted directly in unit tests.
pub(crate) fn proxy_scan_skipped_warning(
    proxy_scan_enabled: bool,
    newly_cached: bool,
    artifact_path: &str,
) -> Option<String> {
    if !should_warn_proxy_scan_skipped(proxy_scan_enabled, newly_cached) {
        return None;
    }
    Some(format!(
        "scan_on_proxy is enabled for this repository but proxied artifacts are not \
         yet scanned (#1274): the security scanner operates on the `artifacts` table \
         and proxy-cached content is not recorded there (#1278). The artifact '{}' \
         was cached UNSCANNED. Run a manual scan or host the package instead of \
         proxying it if a scan is required.",
        artifact_path
    ))
}

/// A single proxy-cached artifact, reconstructed from the storage backend
/// for the repository artifact-listing endpoint (#1548, web #424).
///
/// Proxy-cached items are not in the `artifacts` table (#1280), so this is
/// assembled from the on-disk `__content__` key and its `__cache_meta__.json`
/// sidecar rather than from a database row. There is no DB id, version, or
/// download count to report, so the listing handler synthesizes the parts of
/// `ArtifactResponse` it can and leaves the rest at their natural defaults.
#[derive(Debug, Clone)]
pub struct CachedArtifactEntry {
    /// Logical artifact path relative to the repository root, e.g.
    /// `is-odd/-/is-odd-3.0.1.tgz`.
    pub path: String,
    /// Final path segment, used as the display name.
    pub name: String,
    /// Cached body size in bytes (from the sidecar).
    pub size_bytes: i64,
    /// SHA-256 of the cached body (from the sidecar).
    pub checksum_sha256: String,
    /// Content type recorded at cache-write time, defaulting to
    /// `application/octet-stream` when upstream did not send one.
    pub content_type: String,
    /// When the entry was first cached (from the sidecar).
    pub cached_at: DateTime<Utc>,
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
    /// `Last-Modified` value from upstream, used to send `If-Modified-Since`
    /// on conditional revalidation of a mutable entry past its TTL (#1611).
    /// `None` for entries written before this field existed (`#[serde(default)]`
    /// preserves wire-compat) or when upstream sent no `Last-Modified`.
    #[serde(default)]
    pub last_modified: Option<String>,
    /// When set and in the future, this entry is a *negative cache* of an
    /// upstream 404 (#1611): it holds no usable body and a read must respond
    /// 404 without contacting upstream until this instant passes. `None` for a
    /// normal positive cache entry. `#[serde(default)]` keeps pre-#1611
    /// sidecars deserializing.
    #[serde(default)]
    pub negative_cached_until: Option<DateTime<Utc>>,
    /// Package Age Policy hold for this entry (#1770): when set and in the
    /// future, reads must respond 409 Conflict (via the pure
    /// `quarantine_service::check_download_allowed` gate) until the instant
    /// passes. The window is based on the upstream release date when known
    /// (#1771). `None` for entries written before this field existed or with
    /// the policy disabled at write time; `#[serde(default)]` preserves
    /// wire-compat with pre-existing sidecars.
    #[serde(default)]
    pub quarantine_until: Option<DateTime<Utc>>,
    /// When the cache entry expires
    pub expires_at: DateTime<Utc>,
    /// Content type from upstream
    pub content_type: Option<String>,
    /// Size of the cached content
    pub size_bytes: i64,
    /// SHA-256 checksum of cached content
    pub checksum_sha256: String,
}

impl CacheMetadata {
    /// Project this sidecar into the pure [`cache_classifier::CacheEntry`] the
    /// freshness evaluator consumes, given the path's classified mutability.
    /// Keeps the storage type and the pure evaluator decoupled (#1611).
    pub(crate) fn as_cache_entry(
        &self,
        mutability: crate::services::cache_classifier::Mutability,
    ) -> crate::services::cache_classifier::CacheEntry {
        crate::services::cache_classifier::CacheEntry {
            mutability,
            expires_at: self.expires_at,
            negative_cached_until: self.negative_cached_until,
        }
    }
}

/// Gate a proxy read on a Package Age Policy hold window (#1770).
///
/// Reuses the pure `quarantine_service::check_download_allowed` decision the
/// hosted download paths already use: a `quarantine_until` in the future
/// blocks the read with 409 Conflict; an elapsed window or an absent hold
/// (legacy sidecar, or policy disabled at write time) allows it. The error
/// MUST propagate to the handler — never be degraded to a cache `Miss`, which
/// would refetch upstream and loop.
fn check_quarantine_until(quarantine_until: Option<DateTime<Utc>>) -> Result<()> {
    match quarantine_until {
        Some(until) => {
            quarantine_service::check_download_allowed(Some("quarantined"), Some(until), Utc::now())
        }
        None => Ok(()),
    }
}

/// Parse an HTTP `Last-Modified` header value (RFC 7231 IMF-fixdate, which is
/// RFC 2822-compatible) into a UTC timestamp. Returns `None` for absent or
/// unparseable values so callers fall back to ingestion time (#1771).
fn parse_http_date(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc2822(value)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// Outcome of the up-front cache read on the buffered proxy path (#1611).
///
/// Lets [`ProxyService::read_cached_with_revalidation`] resolve all four
/// freshness states (Fresh hit, NegativeHit, Stale→revalidated hit, Miss) into
/// the three actions the caller cares about: serve a body, return 404, or fetch
/// upstream.
enum CacheReadOutcome {
    /// Serve this cached (or freshly revalidated) body + content type.
    Hit(Bytes, Option<String>),
    /// A negative-cached upstream 404 is still within its TTL: respond 404.
    NegativeHit,
    /// No usable entry; the caller must fetch from upstream.
    Miss,
}

/// Streaming sibling of [`CacheReadOutcome`] (#1611 streaming-path parity).
///
/// The streaming proxy path cannot buffer a body into `Bytes`, so a hit carries
/// a fully-built [`StreamingFetchResult`] (body stream + headers) instead. The
/// three actions are otherwise identical to the buffered path: serve a body,
/// return a cached 404, or fetch upstream.
enum StreamingCacheReadOutcome {
    /// Serve this cached (or freshly revalidated) streamed body.
    Hit(StreamingFetchResult),
    /// A negative-cached upstream 404 is still within its TTL: respond 404.
    NegativeHit,
    /// No usable entry; the caller must elect a streaming leader / fetch
    /// upstream.
    Miss,
}

/// Verdict of a conditional revalidation of a stale (mutable, past-TTL) cache
/// entry, shared by the buffered ([`ProxyService::revalidate_stale`]) and
/// streaming ([`ProxyService::revalidate_stale_streaming`]) paths (#1611).
///
/// Both paths run the identical correctness core — ETag presence, the
/// conditional `If-None-Match` request, TTL extension on 304, and the
/// `stale-if-error` grace-window check — and differ ONLY in how they materialize
/// the cached body (buffered `Bytes` vs. a storage stream). Factoring the
/// decision here keeps that core in one place (and off the jscpd duplication
/// gate) while letting each caller retrieve the body in its own representation.
enum RevalidationVerdict {
    /// 304 Not Modified: the TTL has already been extended in place; serve the
    /// existing cached body.
    ServeRevalidated,
    /// Upstream changed (200 / different ETag) or there is no cheap validator:
    /// fall back to a full refill via the single-flight coordinator.
    Refill,
    /// Upstream was unreachable (5xx / timeout / transport) within the
    /// `stale-if-error` grace window: serve the stale body we already hold.
    ServeStaleIfError,
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
/// Extract the repository key from a proxy-cache storage key for the
/// Prometheus `repository` label. Cache keys are formatted by
/// `cache_storage_key` as `proxy-cache/<repo_key>/<path>/__content__`;
/// the metadata sidecar uses the same prefix. If the key doesn't match
/// this shape (e.g. caller passed a non-cache key), we fall back to
/// `"unknown"` so the counter stays low-cardinality and never panics on
/// a malformed input. Used by `record_proxy_cache_lookup` callsites.
fn repo_key_from_cache_key(cache_key: &str) -> &str {
    cache_key
        .strip_prefix("proxy-cache/")
        .and_then(|s| s.split('/').next())
        .filter(|s| !s.is_empty())
        .unwrap_or("unknown")
}

/// Matches the shape of an S3 *multipart* upload ETag: 32 hex digits (the MD5
/// of the concatenated part digests) followed by `-<partcount>`, e.g.
/// `d41d8cd98f00b204e9800998ecf8427e-3`.
///
/// Unlike a single-part ETag — which is the raw MD5 of the whole object body —
/// a multipart ETag is an *opaque per-upload* value. Two replicas re-uploading
/// byte-identical content produce different multipart ETags because the value
/// depends on the upload's part boundaries, not just the bytes. It is therefore
/// NOT a content hash and must not be used to prove two objects differ (#2120).
static MULTIPART_ETAG_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[0-9a-fA-F]{32}-\d+$").unwrap());

/// True when `etag` has the S3 multipart-upload shape (see
/// [`MULTIPART_ETAG_RE`]). Surrounding double quotes — which S3 / `object_store`
/// carry on the raw ETag header value — are stripped before matching so both
/// `"<md5>-2"` and `<md5>-2` are recognized. Pure and side-effect free.
fn is_multipart_etag(etag: &str) -> bool {
    MULTIPART_ETAG_RE.is_match(etag.trim_matches('"'))
}

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

/// Storage keys for a single proxy-cache entry: the artifact body and its
/// `__cache_meta__.json` sidecar.
///
/// Both keys are derived together from the same `(repo_key, path)` pair and
/// share identical validation; they differ only in their trailing suffix.
/// [`CacheKeys::derive`] is the single source of truth for that formula so the
/// content key (used for presigned URLs / freshness probes) and the metadata
/// key (the cache sidecar) cannot drift apart (#1018). The legacy
/// [`ProxyService::cache_storage_key`] / `cache_metadata_key` helpers are thin
/// shims over this type.
pub(crate) struct CacheKeys {
    /// Storage key for the cached artifact body (`__content__` suffix).
    pub(crate) content: String,
    /// Storage key for the cache metadata sidecar (`__cache_meta__.json`).
    pub(crate) metadata: String,
}

impl CacheKeys {
    /// Derive both the content and metadata storage keys for a proxy-cache
    /// entry, running the shared `validate_cache_path` + `check_cache_key_length`
    /// validation exactly once.
    ///
    /// Byte-for-byte equivalent to calling
    /// [`ProxyService::cache_storage_key`] and `cache_metadata_key`
    /// individually: same validation order, same error values, same key format.
    pub(crate) fn derive(repo_key: &str, path: &str) -> Result<CacheKeys> {
        let trimmed = ProxyService::validate_cache_path(path)?;
        let content = format!("proxy-cache/{}/{}/__content__", repo_key, trimmed);
        let metadata = format!("proxy-cache/{}/{}/__cache_meta__.json", repo_key, trimmed);
        ProxyService::check_cache_key_length(repo_key, trimmed)?;
        Ok(CacheKeys { content, metadata })
    }
}

/// Owns the proxy-cache body + `__cache_meta__.json` sidecar lifecycle
/// (#1618 S7 — first structural extraction).
///
/// This is a pure structural relocation of the cache read/write/invalidate/
/// freshness operations that previously lived as scattered methods on
/// [`ProxyService`]. [`ProxyService`] now holds a `CacheStore` and its public
/// cache methods delegate here; no behavior, logging, error type, ordering,
/// or call-site signature changed in the move.
///
/// Wraps the same `Arc<StorageService>` handle [`ProxyService`] already uses
/// for these operations, so reads and writes target the global default
/// backend exactly as before (#1278).
pub(crate) struct CacheStore {
    storage: Arc<StorageService>,
}

impl CacheStore {
    /// Construct a `CacheStore` over the given storage handle.
    pub(crate) fn new(storage: Arc<StorageService>) -> Self {
        Self { storage }
    }

    /// Load cache metadata from storage.
    ///
    /// Relocated verbatim from `ProxyService::load_cache_metadata`: `NotFound`
    /// is a miss (`Ok(None)`), any other storage error propagates.
    async fn load_metadata(&self, metadata_key: &str) -> Result<Option<CacheMetadata>> {
        match self.storage.get(metadata_key).await {
            Ok(data) => {
                let metadata: CacheMetadata = serde_json::from_slice(&data)?;
                Ok(Some(metadata))
            }
            Err(AppError::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Shared cache-read path behind the fresh (`allow_stale = false`) and
    /// stale (`allow_stale = true`) lookups. Relocated verbatim from
    /// `ProxyService::get_cached`; every divergence is preserved exactly:
    ///
    /// * **Metadata read error.** Fresh treats a sidecar read/parse error as a
    ///   cache miss (B6 — a waiter racing the single-flight leader's metadata
    ///   write, or half-written JSON, must not bubble out as a 502). Stale
    ///   propagates the error via `?`.
    /// * **Expiry gate.** Fresh returns a miss once `Utc::now() > expires_at`;
    ///   stale skips the gate entirely (that is the point of the fallback).
    /// * **Body read error.** Fresh swallows a transient storage read error as
    ///   a miss (B6); stale propagates it.
    /// * **Log wording.** Fresh logs "Cache …"; stale logs "Stale cache …" and
    ///   includes the expiry timestamp on a hit.
    ///
    /// The checksum verification (and its miss-on-mismatch) is identical for
    /// both flags.
    async fn get(
        &self,
        cache_key: &str,
        metadata_key: &str,
        allow_stale: bool,
    ) -> Result<Option<(Bytes, Option<String>)>> {
        // Per-branch proxy-cache observability (#1263 follow-up / PR #1284).
        // Only the FRESH lookup (`allow_stale == false`) is counted: that is
        // the single per-request cache-read decision the original PR
        // instrumented on `get_cached_artifact`. The stale fallback
        // (`allow_stale == true`) is a *second* body read that only runs
        // after the fresh read already recorded a `miss_*`/`error` outcome
        // for the same request (via `revalidate_stale`), so counting it too
        // would double-count. The repo label is derived from the cache_key
        // prefix; see `repo_key_from_cache_key`.
        let repo_label = repo_key_from_cache_key(cache_key);

        // Load metadata. Fresh treats a read/parse error as a miss (B6); stale
        // propagates it via `?` to match the original behavior precisely.
        let metadata = if allow_stale {
            match self.load_metadata(metadata_key).await? {
                Some(m) => m,
                None => return Ok(None),
            }
        } else {
            match self.load_metadata(metadata_key).await {
                Ok(Some(m)) => m,
                Ok(None) => {
                    tracing::debug!(
                        cache_key = %cache_key,
                        metadata_key = %metadata_key,
                        "Proxy cache miss: metadata sidecar absent"
                    );
                    record_proxy_cache_lookup(repo_label, "miss_no_metadata");
                    return Ok(None);
                }
                Err(e) => {
                    tracing::warn!(
                        metadata_key = %metadata_key,
                        error = %e,
                        "proxy cache metadata read failed; treating as miss and refetching upstream"
                    );
                    record_proxy_cache_lookup(repo_label, "error");
                    return Ok(None);
                }
            }
        };

        // Fresh reads enforce the expiry gate; the stale fallback skips it.
        if !allow_stale && Utc::now() > metadata.expires_at {
            tracing::debug!(
                cache_key = %cache_key,
                expires_at = %metadata.expires_at,
                "Proxy cache miss: entry expired"
            );
            record_proxy_cache_lookup(repo_label, "miss_expired");
            return Ok(None);
        }

        // Try to get cached content
        match self.storage.get(cache_key).await {
            Ok(content) => {
                // Verify checksum (identical for fresh and stale)
                let actual_checksum = StorageService::calculate_hash(&content);
                if actual_checksum != metadata.checksum_sha256 {
                    if allow_stale {
                        tracing::warn!(
                            "Stale cache checksum mismatch for {}: expected {}, got {}",
                            cache_key,
                            metadata.checksum_sha256,
                            actual_checksum
                        );
                    } else {
                        tracing::warn!(
                            cache_key = %cache_key,
                            expected = %metadata.checksum_sha256,
                            actual = %actual_checksum,
                            "Proxy cache miss: checksum mismatch (cache will be refilled)"
                        );
                        record_proxy_cache_lookup(repo_label, "miss_checksum_mismatch");
                    }
                    return Ok(None);
                }

                if allow_stale {
                    tracing::debug!(
                        "Stale cache hit for {} (expired at {})",
                        cache_key,
                        metadata.expires_at
                    );
                } else {
                    tracing::debug!(cache_key = %cache_key, "Proxy cache hit");
                    record_proxy_cache_lookup(repo_label, "hit");
                }
                Ok(Some((content, metadata.content_type)))
            }
            Err(AppError::NotFound(_)) => {
                if !allow_stale {
                    tracing::debug!(
                        cache_key = %cache_key,
                        "Proxy cache miss: content object absent (metadata existed)"
                    );
                    record_proxy_cache_lookup(repo_label, "miss_no_content");
                }
                Ok(None)
            }
            // B6 (coalescing 502 leak): a transient storage read error here
            // (e.g. a waiter reading the cache body while the single-flight
            // leader is mid-write, or a partially-written / poisoned entry)
            // must NOT bubble out as a raw 502 to every concurrent waiter.
            // Treat it as a cache miss so the caller re-fetches upstream; the
            // upstream path then surfaces a clean 2xx (cache repopulated) or a
            // 503 via `validate_upstream_status` when upstream itself is the
            // one failing. Surfacing the read error as `Err(e)` made it
            // `map_proxy_error` -> 502, which is exactly the raw status the
            // stampede gate rejects. The stale fallback keeps the original
            // propagate-the-error behavior.
            Err(e) => {
                if allow_stale {
                    Err(e)
                } else {
                    tracing::warn!(
                        cache_key = %cache_key,
                        error = %e,
                        "proxy cache read failed; treating as miss and refetching upstream"
                    );
                    record_proxy_cache_lookup(repo_label, "error");
                    Ok(None)
                }
            }
        }
    }

    /// Evict a cache entry: derive both keys, then delete the content and
    /// metadata blobs in that order, ignoring delete errors.
    ///
    /// Relocated verbatim from `ProxyService::invalidate_cache_keys` (the
    /// shared invalidate core from #1618 S3).
    async fn invalidate(&self, keys: &CacheKeys) -> Result<()> {
        // Delete both content and metadata
        let _ = self.storage.delete(&keys.content).await;
        let _ = self.storage.delete(&keys.metadata).await;

        Ok(())
    }

    /// Metadata-only freshness probe with #1051 ETag revalidation.
    ///
    /// Relocated verbatim from `ProxyService::is_cache_fresh` (the body that
    /// runs once the keys are derived). Returns `true` only when the metadata
    /// exists, is unexpired, and the content object passes ETag revalidation
    /// (or, for filesystem/legacy entries with no pinned ETag, an existence
    /// check).
    async fn is_fresh(&self, keys: &CacheKeys) -> bool {
        let cache_key = &keys.content;

        let Ok(Some(metadata)) = self.load_metadata(&keys.metadata).await else {
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
            Some(ref pinned) => match self.storage.head_etag(cache_key).await {
                Ok(Some(current)) => {
                    if current != *pinned {
                        // #2120: S3 multipart ETags are opaque per-upload
                        // values, not content hashes. Two replicas re-uploading
                        // byte-identical pull-through content mint DIFFERENT
                        // multipart ETags, so a value mismatch does NOT imply
                        // the object changed. When either side is multipart-
                        // shaped, treat the mismatch as inconclusive and fall
                        // back to an existence check rather than forcing the
                        // slow path — which would re-fetch + re-upload, mint yet
                        // another ETag, and thrash the fast path permanently.
                        // Single-part (real-MD5) ETags keep full
                        // mismatch = not-fresh semantics below. The robust
                        // cross-replica single-flight fix is tracked in #1609.
                        if is_multipart_etag(pinned) || is_multipart_etag(&current) {
                            tracing::debug!(
                                cache_key = %cache_key,
                                pinned_etag = %pinned,
                                current_etag = %current,
                                "proxy cache multipart ETag mismatch on fast-path revalidation; falling back to existence check (#2120)"
                            );
                            return matches!(self.storage.exists(cache_key).await, Ok(true));
                        }
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
                matches!(self.storage.exists(cache_key).await, Ok(true))
            }
        }
    }
}

/// Owns the post-proxy persistence concern — seam (b) of the #1618 refactor
/// (S9). Both write-to-cache paths funnel through here:
///
/// * [`Self::write_buffered`] ← `ProxyService::cache_artifact` /
///   `CacheStore::write` — the buffered path that has the whole body in
///   memory.
/// * [`Self::tee_stream`] ← the `tee_upstream_to_cache` free function — the
///   streaming path that tees the upstream body to the client AND a
///   background cache writer concurrently.
///
/// This is a pure structural relocation: no behavior, logging, error type,
/// ordering, or call-site signature changed in the move. The two paths
/// previously each independently implemented the same load-bearing
/// invariants, all preserved here byte-for-byte and annotated `// #1618 S9`
/// so future editors do not "fix" them:
///
/// 1. **#1365 zero-byte guard.** Neither path ever caches an empty body
///    (buffered: skip the write; streaming: skip the sidecar + delete the
///    empty object). Same log string in both.
/// 2. **#1051 ETag pin.** `pin_storage_etag` is read off the backend right
///    after the content write and stored in the sidecar so the fast path can
///    revalidate; a backend with no ETag concept falls back to pre-#1051
///    existence-only semantics.
/// 3. **Body → sidecar write ordering.** The content object is written
///    first, then the cache-metadata sidecar. Never reordered.
///
/// Streaming-tee failure semantics ([`Self::tee_stream`]) are unchanged: a
/// cache-write failure must not corrupt the client stream, upstream errors
/// surface to the client while the writer abandons the cache, etc. See that
/// method's doc for the full contract.
///
/// Wraps the same `Arc<StorageService>` handle [`ProxyService`] already uses
/// for cache writes, so writes target the global default backend exactly as
/// before (#1278).
pub(crate) struct CachePersister {
    storage: Arc<StorageService>,
}

impl CachePersister {
    /// Construct a `CachePersister` over the given storage handle.
    pub(crate) fn new(storage: Arc<StorageService>) -> Self {
        Self { storage }
    }

    /// Cache artifact content and its metadata sidecar (buffered path).
    ///
    /// Relocated verbatim from `ProxyService::cache_artifact` /
    /// `CacheStore::write` (#1618 S9; the DB-write side was already removed
    /// under #1278). Preserves the #1365 zero-byte guard, the #1051 ETag
    /// pin, and the identical write ordering (content first, then sidecar).
    #[allow(clippy::too_many_arguments)]
    async fn write_buffered(
        &self,
        cache_key: &str,
        metadata_key: &str,
        content: &Bytes,
        content_type: Option<String>,
        etag: Option<String>,
        last_modified: Option<String>,
        ttl_secs: i64,
        repository_id: Uuid,
        artifact_path: &str,
        quarantine_until: Option<DateTime<Utc>>,
    ) -> Result<()> {
        // #1618 S9 / #1365: never cache a zero-byte body on the buffered
        // path either. An empty upstream response (204 / empty 200) must
        // not become a fresh cache entry that a later request serves as
        // `Content-Length: 0`. Skip the write entirely so the next request
        // refetches from upstream; the caller treats a cache miss as the
        // normal path. The streaming sibling [`Self::tee_stream`] applies
        // the same guard after `put_stream`.
        if content.is_empty() {
            tracing::warn!(
                cache_key = %cache_key,
                "proxy upstream returned an empty body; not caching the zero-byte \
                 object so the next request refetches upstream"
            );
            return Ok(());
        }

        // Calculate checksum
        let checksum = StorageService::calculate_hash(content);

        // #1618 S9: body → sidecar write ordering. Store content first so we
        // can read the backend's ETag back for the integrity-revalidation
        // pin (#1051).
        self.storage.put(cache_key, content.clone()).await?;

        // #1618 S9 / #1051: best-effort capture of the backend's ETag right
        // after the PUT so the fast path can re-HEAD on each hit and reject
        // tampered or replaced objects. See [`pin_storage_etag`] for the
        // failure semantics; a failure here only disables revalidation for
        // this entry, the cache write itself still succeeds.
        let storage_etag = pin_storage_etag(&self.storage, cache_key).await;

        // Create metadata
        let now = Utc::now();
        let metadata = CacheMetadata {
            cached_at: now,
            upstream_etag: etag,
            storage_etag,
            last_modified,
            negative_cached_until: None,
            // Package Age Policy hold resolved by the caller (#1770): recorded
            // on the sidecar (NOT the `artifacts` table, per #1278) so every
            // read path can gate on it.
            quarantine_until,
            expires_at: now + chrono::Duration::seconds(ttl_secs),
            content_type,
            size_bytes: content.len() as i64,
            checksum_sha256: checksum,
        };

        // #1618 S9: sidecar written second, after the content object above.
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

        tracing::debug!(
            "Cached artifact {} ({} bytes, expires at {})",
            cache_key,
            content.len(),
            metadata.expires_at
        );

        Ok(())
    }

    /// Tee an upstream byte stream into a returned client stream AND a
    /// background storage writer that populates the proxy cache (streaming
    /// path). The returned stream yields the same chunks the upstream
    /// produced, in order, with no buffering beyond the bounded channel
    /// below.
    ///
    /// Relocated verbatim from the `tee_upstream_to_cache` free function
    /// (#1618 S9). Storage failure semantics:
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
    fn tee_stream(
        &self,
        upstream: BoxStream<'static, Result<Bytes>>,
        cache_key: String,
        metadata_key: String,
        template: CacheMetadataTemplate,
        expected_len: Option<u64>,
    ) -> BoxStream<'static, Result<Bytes>> {
        let storage = Arc::clone(&self.storage);

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
                Ok(result) => match classify_stream_write(result.bytes_written, expected_len) {
                    StreamWriteOutcome::Commit => {
                        let now = Utc::now();
                        // #1618 S9 / #1051: pin the storage backend's ETag at
                        // write time so the fast path can re-HEAD on each hit
                        // and detect tampering / backend-side replacement. See
                        // [`pin_storage_etag`] for the best-effort semantics on
                        // backends without an ETag concept or on transport
                        // error.
                        let storage_etag =
                            pin_storage_etag(&storage_clone, &cache_key_for_writer).await;
                        let metadata = CacheMetadata {
                            cached_at: now,
                            upstream_etag: template.etag,
                            storage_etag,
                            last_modified: template.last_modified,
                            negative_cached_until: None,
                            // The streaming leader refuses to open upstream at all
                            // while the repo's Package Age Policy is enabled
                            // (#1770), so a tee'd entry is never under a hold.
                            quarantine_until: None,
                            expires_at: now + chrono::Duration::seconds(template.ttl_secs),
                            content_type: template.content_type,
                            size_bytes: result.bytes_written as i64,
                            checksum_sha256: result.checksum_sha256,
                        };
                        match serde_json::to_vec(&metadata) {
                            Ok(json) => {
                                // #1618 S9: sidecar written second, after the
                                // streaming content write (put_stream) above.
                                if let Err(e) =
                                    storage_clone.put(&metadata_key, Bytes::from(json)).await
                                {
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
                    rejected => {
                        // Reject path for both guards (#1365 empty, #1912
                        // truncated): writing a sidecar would mark a corrupt
                        // object as a fresh cache hit. An empty body (a 204, a
                        // 200 with `Content-Length: 0`, or a HEAD-style probe
                        // reaching the download path) would serve
                        // `Content-Length: 0` (e.g. Gradle fails parsing the
                        // POM: "Content is not allowed in prolog."); a truncated
                        // body (stream cut mid-download below the advertised
                        // `Content-Length`) would serve a short, SHA-mismatched
                        // blob and clients hit "unexpected BufError" extracting
                        // the archive. Skip the sidecar (entry treated as a
                        // miss) and delete the bad object so a later GET
                        // refetches upstream (self-heal). The buffered sibling
                        // [`Self::write_buffered`] applies the empty-body guard
                        // before the content write.
                        match rejected {
                            StreamWriteOutcome::RejectTruncated { expected, actual } => {
                                tracing::warn!(
                                    cache_key = %cache_key_for_writer,
                                    expected_bytes = expected,
                                    written_bytes = actual,
                                    "proxy upstream body was truncated (written != Content-Length); \
                                     not caching the partial object (no metadata sidecar) so the \
                                     next request refetches upstream"
                                );
                            }
                            _ => {
                                tracing::warn!(
                                    cache_key = %cache_key_for_writer,
                                    "proxy upstream returned an empty body; not caching the \
                                     zero-byte object (no metadata sidecar) so the next request \
                                     refetches upstream"
                                );
                            }
                        }
                        if let Err(e) = storage_clone.delete(&cache_key_for_writer).await {
                            tracing::debug!(
                                cache_key = %cache_key_for_writer,
                                error = %e,
                                "best-effort delete of rejected proxy-cache object failed; \
                                 the missing metadata sidecar still forces a refetch"
                            );
                        }
                    }
                },
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
}

/// Owns the upstream HTTP fetch + OCI bearer-token-exchange lifecycle
/// (#1618 S8 — the highest-risk structural extraction).
///
/// This is a pure structural relocation of the upstream-facing methods that
/// previously lived directly on [`ProxyService`]: the buffered fetch
/// (`fetch_buffered` ← `fetch_from_upstream_with_accept`), the streaming fetch
/// (`fetch_stream` ← `fetch_from_upstream_streaming`), the ETag revalidation
/// HEAD (`check_etag_changed`), and the OCI bearer-token cache
/// (`obtain_bearer_token` / `get_cached_token` / `parse_bearer_challenge`).
/// [`ProxyService`] now holds an `UpstreamClient` and the corresponding methods
/// delegate here; no behavior, logging, error type, ordering, header set, or
/// call-site signature changed in the move.
///
/// Holds the same `http_client`, the bearer `token_cache`, and a `db` handle
/// (used only to load per-repo upstream auth via
/// `upstream_auth::load_upstream_auth`) that [`ProxyService`] used before.
///
/// The two fetch paths each previously inlined an identical 401 Bearer
/// state machine; it is now extracted ONCE into [`Self::exchange_bearer_then`].
/// The caller-supplied `build_request` closure is what preserves the
/// **intentional OCI `Accept`-header asymmetry** — see that method's doc.
pub(crate) struct UpstreamClient {
    db: PgPool,
    http_client: Client,
    /// In-memory cache for OCI registry bearer tokens.
    /// Key: "{realm}\0{service}\0{scope}", Value: (token, created_at, ttl_secs)
    token_cache: RwLock<HashMap<String, (String, Instant, u64)>>,
}

impl UpstreamClient {
    /// Construct an `UpstreamClient` over the given HTTP client and db handle.
    /// Starts with an empty bearer-token cache (matching the previous
    /// `ProxyService::new` initialization exactly).
    pub(crate) fn new(db: PgPool, http_client: Client) -> Self {
        Self {
            db,
            http_client,
            token_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Buffered upstream fetch. Relocated verbatim from
    /// `ProxyService::fetch_from_upstream_with_accept`.
    ///
    /// Variant of the plain fetch that adds an `Accept` header to BOTH the
    /// initial request and the post-token-exchange retry.
    ///
    /// OCI manifest fetches need this so the upstream registry returns the
    /// content type the caller actually understands. Without an `Accept`
    /// header Docker Hub picks a default representation (typically the
    /// OCI image index for multi-arch images) but other registries respond
    /// with 404 / 406 / a legacy v1 manifest the client cannot consume.
    /// Mirroring the client's `Accept` upstream removes that source of
    /// silent content-type mismatches and the spurious 404s they trigger.
    async fn fetch_buffered(
        &self,
        url: &str,
        repo_id: Uuid,
        accept: Option<&str>,
    ) -> Result<UpstreamResponse> {
        let diagnostic_url = redact_url_for_diagnostics(url);
        tracing::info!(
            "Fetching artifact from upstream: {} (accept={:?})",
            diagnostic_url,
            accept
        );

        let upstream_auth =
            crate::services::upstream_auth::load_upstream_auth(&self.db, repo_id).await?;

        let mut request = self.http_client.get(url);
        if let Some(ref auth) = upstream_auth {
            request = crate::services::upstream_auth::apply_upstream_auth(request, auth);
        }
        // BUFFERED path sets `Accept` on the INITIAL request. The streaming
        // path deliberately does NOT — see `exchange_bearer_then` /
        // `fetch_stream` for why this asymmetry is intentional (#1618 S8).
        if let Some(accept_value) = accept {
            request = request.header(ACCEPT, accept_value);
        }

        let response = request.send().await.map_err(|e| {
            AppError::Storage(format!(
                "Failed to fetch from upstream {}: {}",
                diagnostic_url,
                e.without_url()
            ))
        })?;

        let status = response.status();

        // Handle 401 with bearer token exchange (required by Docker Hub and
        // other OCI registries, even for anonymous/public pulls).
        if status == StatusCode::UNAUTHORIZED {
            // The buffered closure RE-ADDS `Accept` on the bearer retry,
            // mirroring the initial request. The bearer-exchange helper itself
            // never touches `Accept`; the closure owns that decision so the
            // buffered/streaming asymmetry is preserved (#1618 S8).
            if let Some(retry_response) = self
                .exchange_bearer_then(response, url, &upstream_auth, |req| {
                    if let Some(accept_value) = accept {
                        req.header(ACCEPT, accept_value)
                    } else {
                        req
                    }
                })
                .await?
            {
                return Self::read_upstream_response(retry_response, url).await;
            }

            return Err(AppError::Storage(format!(
                "Upstream returned error status {}: {}",
                status, diagnostic_url
            )));
        }

        Self::read_upstream_response(response, url).await
    }

    /// Extract content, content-type, etag, effective URL, and Link header from
    /// an upstream HTTP response. Callers are responsible for handling 401 before
    /// invoking. Relocated verbatim from `ProxyService::read_upstream_response`.
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

        let last_modified = response
            .headers()
            .get(reqwest::header::LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let link = response
            .headers()
            .get("link")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        #[allow(clippy::disallowed_methods)]
        // STREAMING-EXEMPT: proxy upstream fetch buffered; tracked for streaming copy to storage in a later #1608 phase
        let content = response.bytes().await.map_err(|e| {
            AppError::Storage(format!(
                "Failed to read upstream response: {}",
                e.without_url()
            ))
        })?;

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
            last_modified,
            effective_url,
            link,
        })
    }

    /// Streaming upstream fetch. Relocated verbatim from
    /// `ProxyService::fetch_from_upstream_streaming` (#895).
    ///
    /// Returns the upstream body as a stream of `Bytes` chunks instead of
    /// buffering the whole body into memory. Used by the OOM-mitigation path
    /// that tees the upstream stream simultaneously to the client and to the
    /// storage cache.
    ///
    /// Auth handling (Basic + OCI bearer token exchange) mirrors the
    /// buffered variant; only the body extraction differs — and, critically,
    /// the streaming path sets NO `Accept` header anywhere (see below).
    async fn fetch_stream(&self, url: &str, repo_id: Uuid) -> Result<UpstreamStream> {
        let diagnostic_url = redact_url_for_diagnostics(url);
        tracing::info!(
            "Fetching artifact from upstream (streaming): {}",
            diagnostic_url
        );

        let upstream_auth =
            crate::services::upstream_auth::load_upstream_auth(&self.db, repo_id).await?;

        let mut request = self.http_client.get(url);
        if let Some(ref auth) = upstream_auth {
            request = crate::services::upstream_auth::apply_upstream_auth(request, auth);
        }
        // NOTE: the streaming path intentionally sets NO `Accept` header on the
        // initial request, in contrast to the buffered path which sets it on
        // both the initial request and the retry. This asymmetry is deliberate
        // and MUST NOT be "unified" — do not add `Accept` here (#1618 S8 review).

        let response = request.send().await.map_err(|e| {
            AppError::Storage(format!(
                "Failed to fetch from upstream {}: {}",
                diagnostic_url,
                e.without_url()
            ))
        })?;

        let status = response.status();

        if status == StatusCode::UNAUTHORIZED {
            // The streaming closure is the IDENTITY transform: it adds NO
            // `Accept` header on the bearer retry, preserving the asymmetry
            // with the buffered path (#1618 S8).
            if let Some(retry_response) = self
                .exchange_bearer_then(response, url, &upstream_auth, |req| req)
                .await?
            {
                return Self::read_upstream_response_streaming(retry_response, url);
            }

            return Err(AppError::Storage(format!(
                "Upstream returned error status {}: {}",
                status, diagnostic_url
            )));
        }

        Self::read_upstream_response_streaming(response, url)
    }

    /// Shared OCI 401 Bearer-challenge state machine, extracted ONCE from the
    /// previously copy-pasted blocks in the buffered and streaming fetch paths
    /// (#1618 S8).
    ///
    /// Given the upstream's 401 `response`, this:
    /// 1. parses the `WWW-Authenticate: Bearer ...` challenge,
    /// 2. validates the advertised realm against SSRF rules
    ///    (`validate_outbound_url`) BEFORE any outbound request,
    /// 3. obtains a bearer token (cache hit or token-endpoint exchange), and
    /// 4. rebuilds a fresh GET via the caller-supplied `build_request` closure
    ///    (already carrying `bearer_auth(token)`), sends it, and returns the
    ///    RAW [`reqwest::Response`].
    ///
    /// Returns `Ok(Some(response))` when the 401 carried a usable Bearer
    /// challenge and the retry was issued; `Ok(None)` when the response was not
    /// a parseable Bearer challenge (the caller then maps that to the original
    /// "Upstream returned error status" error, exactly as before).
    ///
    /// CRITICAL — this helper deliberately returns the raw response and does
    /// NOT read the body: the caller picks `read_upstream_response` (buffered,
    /// fully buffered) vs `read_upstream_response_streaming` (streaming, bounded
    /// memory). Reading the body here would collapse streaming into buffering
    /// and break its bounded-memory guarantee (#1618 S8 review).
    ///
    /// CRITICAL — this helper NEVER sets an `Accept` header. The OCI `Accept`
    /// asymmetry between the buffered and streaming paths is intentional and is
    /// owned entirely by the caller's `build_request` closure: the buffered
    /// caller re-adds `Accept` on the retry, the streaming caller adds nothing.
    /// Do NOT "helpfully" add `Accept` here (#1618 S8 review).
    async fn exchange_bearer_then<F>(
        &self,
        response: reqwest::Response,
        url: &str,
        upstream_auth: &Option<crate::services::upstream_auth::UpstreamAuthType>,
        build_request: F,
    ) -> Result<Option<reqwest::Response>>
    where
        F: FnOnce(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
    {
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
                    .obtain_bearer_token(realm, &service, &scope, upstream_auth)
                    .await?;

                // Retry with the bearer token only. The original upstream
                // Basic credentials were already forwarded to the token
                // endpoint in obtain_bearer_token(); adding them here
                // would produce two Authorization headers.
                //
                // The caller's `build_request` closure decides whether to
                // re-add `Accept` (buffered: yes; streaming: no) — see the
                // method doc on the intentional asymmetry (#1618 S8).
                let retry_request = build_request(self.http_client.get(url).bearer_auth(&token));

                let retry_diagnostic_url = redact_url_for_diagnostics(url);
                let retry_response = retry_request.send().await.map_err(|e| {
                    AppError::Storage(format!(
                        "Failed to fetch from upstream {} after token exchange: {}",
                        retry_diagnostic_url,
                        e.without_url()
                    ))
                })?;

                return Ok(Some(retry_response));
            }
        }

        Ok(None)
    }

    /// Stream the upstream HTTP response body without buffering. Mirrors
    /// the shape of [`Self::read_upstream_response`] but returns the body
    /// as a stream. Status/header validation happens up front; the
    /// stream itself yields one [`Bytes`] chunk per `reqwest` body
    /// frame. Relocated verbatim from
    /// `ProxyService::read_upstream_response_streaming`.
    fn read_upstream_response_streaming(
        response: reqwest::Response,
        url: &str,
    ) -> Result<UpstreamStream> {
        validate_upstream_status(response.status(), url)?;
        let (content_type, etag, content_length) = extract_streaming_headers(response.headers());

        let body = response.bytes_stream().map(|r| {
            r.map_err(|e| {
                AppError::Storage(format!(
                    "Failed to read upstream stream: {}",
                    e.without_url()
                ))
            })
        });

        Ok(UpstreamStream {
            body: Box::pin(body),
            content_type,
            etag,
            content_length,
        })
    }

    /// Obtain a bearer token for an OCI registry, using the in-memory cache
    /// when possible. Relocated verbatim from
    /// `ProxyService::obtain_bearer_token`.
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

    /// Return a cached bearer token if present and not expired. Relocated
    /// verbatim from `ProxyService::get_cached_token`.
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
    /// header into a map of key-value pairs. Relocated verbatim from
    /// `ProxyService::parse_bearer_challenge`.
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

    /// Check if upstream ETag has changed (returns true if changed/newer).
    /// Relocated verbatim from `ProxyService::check_etag_changed`.
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

/// Proxy service for fetching and caching artifacts from upstream repositories
pub struct ProxyService {
    db: PgPool,
    storage: Arc<StorageService>,
    /// Owns the cache body/metadata/invalidate/freshness lifecycle (#1618 S7).
    /// The cache-facing public methods on `ProxyService` delegate here.
    cache_store: CacheStore,
    /// Owns the post-proxy persistence concern (#1618 S9, seam (b)): the
    /// buffered (`cache_artifact`) and streaming (tee) write-to-cache paths
    /// both route through here. Holds the same global-default storage handle.
    cache_persister: CachePersister,
    /// Owns the upstream HTTP fetch + OCI bearer-token-exchange lifecycle
    /// (#1618 S8). The upstream-facing methods on `ProxyService`
    /// (`fetch_from_upstream*`, `check_etag_changed`, `parse_bearer_challenge`)
    /// delegate here. It holds the shared `http_client` and the bearer
    /// `token_cache` that previously lived directly on `ProxyService`.
    upstream_client: UpstreamClient,
    /// Single-flight coordinator for proxy cache hydration (#1631 layer 1).
    /// The buffered slow path (`fetch_artifact_with_cache_path_and_accept`)
    /// elects a leader through this seam; the leader runs the upstream fetch +
    /// cache write while followers wait and re-check the cache. Injected as a
    /// concrete field, mirroring `CacheStore`/`UpstreamClient`/`CachePersister`
    /// (#1618 S7/S8/S9).
    ///
    /// // #1631 layer 2: the streaming path (`fetch_artifact_streaming`) will
    /// //               coordinate through a streaming entry point on this same
    /// //               seam (broadcast fan-out, not buffered re-check).
    /// // #1631 layer 3: a cross-replica advisory-lock decorator (#1609)
    /// //               replaces this field with a wrapping `Coordinator` impl,
    /// //               selected by config via the [`HydrationCoordinator`] enum.
    coordinator: HydrationCoordinator,
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

        let cache_store = CacheStore::new(Arc::clone(&storage));
        let cache_persister = CachePersister::new(Arc::clone(&storage));
        let upstream_client = UpstreamClient::new(db.clone(), http_client);
        // #1631 layer 1/3: select the single-flight coordinator from config.
        // Defaults to the in-process buffered coordinator; multi-replica
        // deployments opt into the cross-replica advisory-lock decorator (#1609)
        // with `PROXY_SINGLEFLIGHT_ADVISORY_LOCKS_ENABLED=true`. Call sites are
        // unchanged — both variants implement the same `Coordinator` seam.
        let coordinator = HydrationCoordinator::from_env(db.clone());

        Self {
            db,
            storage,
            cache_store,
            cache_persister,
            upstream_client,
            coordinator,
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
    ///     gives cryptographic-grade replacement detection; a genuine
    ///     mismatch there still forces the slow path. For S3 *multipart*
    ///     uploads the ETag is an opaque per-upload identifier (not a
    ///     content hash): byte-identical re-uploads on different replicas
    ///     mint different values, so a mismatch is not a reliable
    ///     "replaced" signal. Per #2120 a multipart-shaped ETag mismatch
    ///     therefore falls back to an existence check (relying on cache
    ///     TTL for staleness) instead of thrashing the fast path. The
    ///     robust cross-replica single-flight fix is tracked in #1609.
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
    /// Storage backend handle that owns the proxy cache objects.
    ///
    /// Proxy-cache content lives at the storage root (`proxy-cache/<repo>/...`)
    /// with no configured key prefix. Presigning a cache key MUST go through
    /// this handle — the same one `is_cache_fresh` and the cache reads/writes
    /// use — so the signed key matches where the object actually lives. Signing
    /// via a prefixed handle yields a key the object store has no object for.
    pub(crate) fn cache_storage_backend(
        &self,
    ) -> std::sync::Arc<dyn crate::services::storage_service::StorageBackend> {
        self.storage.backend()
    }

    pub async fn is_cache_fresh(&self, repo_key: &str, path: &str) -> bool {
        // A path that fails validation cannot have produced a cache entry
        // we'd want to redirect to anyway: treat it as a miss so the caller
        // falls through to the slow path / upstream fetch, where the same
        // validation will surface the error to the client.
        let Ok(keys) = CacheKeys::derive(repo_key, path) else {
            return false;
        };
        self.cache_store.is_fresh(&keys).await
    }

    /// Gate a presigned-redirect fast path on a Package Age Policy hold (#2075).
    ///
    /// The redirect fast path (`proxy_fetch_or_redirect` and the virtual-member
    /// proxy redirect) short-circuits a fresh cache hit into a 302 pointing at a
    /// presigned URL without ever pulling the body through the backend. That skips
    /// the quarantine gate the buffered/streaming fetch paths enforce via
    /// [`check_quarantine_until`], so on redirect-capable backends a fresh entry
    /// still inside its hold window would be handed out. This probe closes that
    /// gap: it loads the same cache sidecar and applies the identical hold
    /// decision BEFORE any redirect is issued.
    ///
    /// Mirrors the B6-safe stance elsewhere in this service (see the follower
    /// re-check in `fetch_artifact_with_cache_path_and_accept`): a missing
    /// sidecar, an absent hold, an elapsed hold, or a sidecar READ error all
    /// resolve to `Ok(())` ("no hold known"). Only a sidecar recording a
    /// still-active `quarantine_until` returns `Err` (Conflict/Authorization),
    /// which the handler maps to 409/403 — no redirect, no upstream refetch.
    pub async fn cache_quarantine_gate(&self, repo_key: &str, path: &str) -> Result<()> {
        let metadata_key = Self::cache_metadata_key(repo_key, path)?;
        if let Some(metadata) = self
            .load_cache_metadata(&metadata_key)
            .await
            .unwrap_or(None)
        {
            check_quarantine_until(metadata.quarantine_until)?;
        }
        Ok(())
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

    /// Variant of [`Self::fetch_artifact_with_cache_path`] that also forwards
    /// an optional `Accept` header to the upstream request. Used by callers
    /// that need content negotiation: OCI manifest GETs, and the PyPI
    /// simple-index proxy requesting the PEP 691 JSON representation under a
    /// format-qualified `cache_path`. Pass `None` to preserve the buffered
    /// fetch behaviour exactly.
    pub async fn fetch_artifact_with_cache_path_and_accept(
        &self,
        repo: &Repository,
        fetch_path: &str,
        cache_path: &str,
        accept: Option<&str>,
    ) -> Result<(Bytes, Option<String>)> {
        let upstream_url = Self::remote_target(repo)?;

        // Cache keys use the caller-supplied cache_path
        let cache_key = Self::cache_storage_key(&repo.key, cache_path)?;
        let metadata_key = Self::cache_metadata_key(&repo.key, cache_path)?;

        // #1611: classify the path and evaluate cache freshness up front.
        //   * Immutable Fresh hit  -> serve directly, NEVER contact upstream.
        //   * Mutable   Fresh hit  -> serve directly (within TTL).
        //   * NegativeHit           -> short-circuit a cached upstream 404.
        //   * Stale (mutable, past TTL) -> conditional revalidation below.
        //   * Miss                  -> single-flight upstream fetch below.
        match self
            .read_cached_with_revalidation(repo, fetch_path, cache_path, &cache_key, &metadata_key)
            .await?
        {
            CacheReadOutcome::Hit(content, content_type) => return Ok((content, content_type)),
            CacheReadOutcome::NegativeHit => {
                return Err(AppError::NotFound(format!(
                    "Upstream returned 404 (negative-cached) for {}",
                    fetch_path
                )));
            }
            CacheReadOutcome::Miss => { /* fall through to single-flight upstream fetch */ }
        }

        let hydration_lease_key = format!("proxy-cache:{}", cache_key);
        // #1631 layer 1: buffered single-flight via the injected coordinator
        // seam (was a direct `coordinate_proxy_hydration` call). The streaming
        // path below (`fetch_artifact_streaming`) is the layer-2 plug-in point.
        self.coordinator.coordinate(
            &hydration_lease_key,
            || async {
                let cached = self.get_cached_artifact(&cache_key, &metadata_key).await?;
                if cached.is_some() {
                    // Package Age Policy (#1770): a follower re-checking the
                    // cache must not serve an entry the leader just wrote
                    // under an active hold. The sidecar load mirrors the
                    // B6-safe stance (read error -> no hold known).
                    if let Some(metadata) =
                        self.load_cache_metadata(&metadata_key).await.unwrap_or(None)
                    {
                        check_quarantine_until(metadata.quarantine_until)?;
                    }
                    return Ok(cached);
                }
                // #1609: a remote cluster leader may have just recorded a
                // negative (404) sidecar while this follower was polling. Surface
                // a fresh negative hit as NotFound so the follower short-circuits
                // the leader-recorded 404 instead of re-fetching upstream after
                // the wait deadline (bounded to <=1 extra 404/replica without it).
                if let Some(metadata) = self.load_cache_metadata(&metadata_key).await.unwrap_or(None)
                {
                    if metadata
                        .negative_cached_until
                        .is_some_and(|until| until > Utc::now())
                    {
                        return Err(AppError::NotFound(format!(
                            "Upstream returned 404 (negative-cached) for {}",
                            fetch_path
                        )));
                    }
                }
                Ok(cached)
            },
            || async {
                let full_url = Self::build_upstream_url(upstream_url, fetch_path);
                let upstream_result = self
                    .fetch_from_upstream_with_accept(&full_url, repo.id, accept)
                    .await;

                match upstream_result {
                    Ok(resp) => {
                        // #1611: mutability-aware TTL (immutable -> forever).
                        let cache_ttl = self.cache_ttl_for_path(repo, cache_path).await;
                        // Package Age Policy (#1770): resolve the hold window
                        // BEFORE caching so the sidecar records it; the window
                        // is based on the upstream release date when known
                        // (#1771).
                        let quarantine_until = self
                            .quarantine_until_for_new_entry(repo.id, resp.last_modified.as_deref())
                            .await;
                        // B6 (coalescing 502 leak, remaining path): the upstream fetch
                        // already SUCCEEDED -- `resp.content` is in hand. A failure to
                        // persist the cache entry must NOT fail the client request.
                        // Under a cold-cache stampede, N concurrent waiters all miss
                        // the cache and all race to write the SAME cache file; one of
                        // those writes can transiently fail (e.g. ENOENT from a
                        // create_dir_all/File::create race against a sibling writer, a
                        // half-renamed temp file, or a poisoned entry). Propagating
                        // that write error via `?` surfaced as `AppError::Io` ->
                        // `map_proxy_error` -> raw 502, which is exactly the leak the
                        // stampede gate rejects (`200 502 200 ...`). Treat the cache
                        // write as best-effort: log at warn and still serve the bytes
                        // we fetched. The cache self-heals on the next request (the
                        // streaming path already documents this self-healing).
                        if let Err(cache_err) = self
                            .cache_artifact(
                                &cache_key,
                                &metadata_key,
                                &resp.content,
                                resp.content_type.clone(),
                                resp.etag,
                                resp.last_modified,
                                cache_ttl,
                                repo.id,
                                cache_path,
                                quarantine_until,
                            )
                            .await
                        {
                            tracing::warn!(
                                cache_key = %cache_key,
                                error = %cache_err,
                                "proxy cache write failed after successful upstream fetch; \
                                 serving fetched bytes and leaving cache to self-heal on next request"
                            );
                        } else {
                            // New artifact cached from upstream: surface the
                            // scan-on-proxy gap (#1274) so an enabled-but-
                            // unimplemented setting fails loudly, not silently.
                            self.warn_if_proxy_scan_unsupported(repo.id, cache_path)
                                .await;

                            // #1999: index the newly-cached Maven artifact into
                            // the package catalog (packages/package_versions
                            // only — never the artifacts table, preserving
                            // #1278). Best-effort: failures are swallowed and
                            // never fail the client's proxy fetch.
                            let checksum = StorageService::calculate_hash(&resp.content);
                            self.index_cached_package(
                                repo.id,
                                cache_path,
                                resp.content.len() as i64,
                                Some(&checksum),
                            )
                            .await;
                        }

                        // Package Age Policy (#1770): hold the just-fetched
                        // bytes too — the policy must block the FIRST response,
                        // not only later cache hits, and must hold even when
                        // the best-effort cache write above failed.
                        check_quarantine_until(quarantine_until)?;

                        Ok((resp.content, resp.content_type))
                    }
                    Err(upstream_err) => {
                        // #1611 negative caching: a definitive upstream 404 is
                        // recorded with a short TTL so a hot loop of misses on a
                        // not-yet-published artifact does not hammer upstream.
                        // We do NOT serve stale for a 404 (the object is gone /
                        // never existed); propagate the 404.
                        if matches!(upstream_err, AppError::NotFound(_)) {
                            self.write_negative_cache(&cache_key, &metadata_key, cache_path)
                                .await;
                            return Err(upstream_err);
                        }
                        // Transient error (5xx / timeout / transport): RFC 5861
                        // stale-if-error — serve the stale body we already hold.
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
            },
            || {
                AppError::Storage(format!(
                    "Timed out waiting for proxy cache hydration: {}",
                    cache_key
                ))
            },
        )
        .await
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
        self.fetch_artifact_streaming_with_cache_path(repo, path, path)
            .await
    }

    /// Streaming sibling of [`Self::fetch_artifact_with_cache_path`]: fetch
    /// from upstream using `fetch_path` for the URL but key the proxy cache
    /// on `cache_path`. This lets format handlers whose upstream download
    /// URL differs from the canonical artifact path (e.g. PyPI, where wheels
    /// live on files.pythonhosted.org while the cache key is
    /// `simple/{project}/{filename}`) use the streaming path instead of
    /// buffering whole package files in memory.
    ///
    /// `cache_path` drives every cache-semantics decision (storage keys,
    /// TTL classification, negative caching, scan-on-proxy warning);
    /// `fetch_path` is only ever combined with the repo's upstream URL to
    /// build the outbound request.
    pub async fn fetch_artifact_streaming_with_cache_path(
        &self,
        repo: &Repository,
        fetch_path: &str,
        cache_path: &str,
    ) -> Result<StreamingFetchResult> {
        // #1631 layer 2 (#1694): single-flight the cold-cache streaming path so
        // N concurrent requests for the same uncached object open upstream ONCE.
        // The streaming coordinator's followers subscribe to the leader's
        // broadcast instead of re-checking the cache mid-flight (the body is not
        // cached until the tee completes). The fall-back outcome (`Ok(None)`)
        // re-enters the cache hit / leader election below — by then the leader is
        // usually done and the cache is warm. We loop a bounded number of times
        // to avoid an unbounded re-enter storm; in practice one re-enter hits the
        // warm cache or wins the election outright.
        const STREAM_REENTER_BUDGET: usize = 8;
        for _ in 0..STREAM_REENTER_BUDGET {
            if let Some(result) = self
                .try_fetch_artifact_streaming_once(repo, fetch_path, cache_path)
                .await?
            {
                return Ok(result);
            }
        }
        // Exhausted re-enters (pathological contention): do one final
        // uncoordinated attempt so the request never spuriously fails.
        self.fetch_artifact_streaming_uncoordinated(repo, fetch_path, cache_path)
            .await
    }

    /// Streaming cache probe: serve `cache_path` straight from the proxy
    /// cache as a stream, without contacting upstream on a miss.
    ///
    /// Returns `Ok(None)` on a cache miss (including a stale entry that
    /// failed revalidation) and `Err(NotFound)` when the path is
    /// negative-cached. Callers that treat the probe as best-effort (the
    /// PyPI download pre-check) map both to "miss" and fall through to the
    /// full fetch, which re-applies the negative-cache gate itself.
    ///
    /// Revalidation of a stale mutable entry uses `cache_path` as the
    /// upstream path — the same behavior the buffered
    /// [`Self::get_cached_artifact_by_path`] probe had implicitly, since
    /// package files classify as immutable and never revalidate in
    /// practice.
    pub async fn streaming_cached_artifact_by_path(
        &self,
        repo: &Repository,
        cache_path: &str,
    ) -> Result<Option<StreamingFetchResult>> {
        let cache_key = Self::cache_storage_key(&repo.key, cache_path)?;
        let metadata_key = Self::cache_metadata_key(&repo.key, cache_path)?;
        self.try_streaming_cache_hit(repo, cache_path, cache_path, &cache_key, &metadata_key)
            .await
    }

    /// One coordinated attempt of the streaming fetch. Returns `Ok(None)` when
    /// the streaming coordinator asked the caller to fall back (re-enter):
    /// either a late would-be follower that would miss leading bytes, or a
    /// follower whose leader vanished before publishing headers. The caller
    /// loops; a re-enter typically lands on the now-warm cache.
    async fn try_fetch_artifact_streaming_once(
        &self,
        repo: &Repository,
        fetch_path: &str,
        cache_path: &str,
    ) -> Result<Option<StreamingFetchResult>> {
        let cache_key = Self::cache_storage_key(&repo.key, cache_path)?;
        let metadata_key = Self::cache_metadata_key(&repo.key, cache_path)?;

        // Cache hit fast path: load metadata sidecar, stream content
        // straight from storage. The slow-path SHA verification done by
        // the buffered `fetch_artifact_with_cache_path` is intentionally
        // skipped here — we cannot recompute SHA without buffering, and
        // the storage backend's own integrity guarantees apply just as
        // they do for presigned redirects (#1018 R-tradeoff already
        // accepted upstream).
        if let Some(result) = self
            .try_streaming_cache_hit(repo, fetch_path, cache_path, &cache_key, &metadata_key)
            .await?
        {
            return Ok(Some(result));
        }

        // Cache miss: elect a single streaming leader. The leader opens
        // upstream once and tees to client + cache; followers subscribe to its
        // broadcast. `Ok(None)` means fall back / re-enter.
        let stream_lease_key = format!("proxy-stream:{cache_key}");
        let handle = self
            .coordinator
            .coordinate_stream(&stream_lease_key, || {
                self.open_streaming_leader(
                    repo,
                    fetch_path,
                    cache_path,
                    cache_key.clone(),
                    metadata_key.clone(),
                )
            })
            .await?;

        Ok(handle.map(StreamingFetchResult::from))
    }

    /// Streaming cache-hit fast path, factored out so both the coordinated
    /// attempt and the uncoordinated fall-back share one implementation.
    /// Returns `Ok(None)` on a miss (no fresh sidecar, or sidecar present but
    /// body evicted), in which case the caller fetches upstream.
    async fn try_streaming_cache_hit(
        &self,
        repo: &Repository,
        fetch_path: &str,
        cache_path: &str,
        cache_key: &str,
        metadata_key: &str,
    ) -> Result<Option<StreamingFetchResult>> {
        match self
            .read_cached_with_revalidation_streaming(
                repo,
                fetch_path,
                cache_path,
                cache_key,
                metadata_key,
            )
            .await?
        {
            StreamingCacheReadOutcome::Hit(result) => Ok(Some(result)),
            StreamingCacheReadOutcome::NegativeHit => Err(AppError::NotFound(format!(
                "Upstream returned 404 (negative-cached) for {}",
                cache_path
            ))),
            StreamingCacheReadOutcome::Miss => Ok(None),
        }
    }

    /// Streaming sibling of [`Self::read_cached_with_revalidation`] (#1611
    /// streaming-path parity). Drives the SAME
    /// [`cache_classifier::Freshness`] state machine the buffered path does, so
    /// the streaming proxy honors immutability, negative caching, and
    /// conditional revalidation rather than gating only on raw `expires_at`:
    ///
    /// * **Miss / no metadata** -> [`StreamingCacheReadOutcome::Miss`].
    /// * **NegativeHit** -> [`StreamingCacheReadOutcome::NegativeHit`] (cached 404).
    /// * **Fresh** -> stream the cached body. Immutable paths land here on every
    ///   hit and therefore NEVER contact upstream (the load-bearing invariant).
    /// * **Stale** (mutable, past TTL) -> conditional revalidation via the shared
    ///   [`Self::revalidate_verdict`] core; 304 extends the TTL and streams the
    ///   cached body, any other outcome degrades to `Miss` so the single-flight
    ///   streaming leader refills.
    ///
    /// B6 is preserved: a transient sidecar read/parse error is treated as a
    /// `Miss` (refetch), never propagated as a 502.
    async fn read_cached_with_revalidation_streaming(
        &self,
        repo: &Repository,
        fetch_path: &str,
        cache_path: &str,
        cache_key: &str,
        metadata_key: &str,
    ) -> Result<StreamingCacheReadOutcome> {
        let mutability = cache_classifier::classify(&repo.format, cache_path);

        // A sidecar read/parse error is treated as "no entry" (Miss) — the same
        // B6-safe stance as the buffered path.
        let metadata = self.load_cache_metadata(metadata_key).await.unwrap_or(None);
        let entry = metadata.as_ref().map(|m| m.as_cache_entry(mutability));

        match cache_classifier::evaluate(entry.as_ref(), Utc::now()) {
            cache_classifier::Freshness::Miss => Ok(StreamingCacheReadOutcome::Miss),
            cache_classifier::Freshness::NegativeHit => Ok(StreamingCacheReadOutcome::NegativeHit),
            cache_classifier::Freshness::Fresh => {
                // Immutable hits reach here and never touch upstream.
                let metadata = metadata.expect("fresh implies metadata present");
                // Package Age Policy (#1770): a held entry must 409 — checked
                // AFTER freshness evaluation; the error propagates and is
                // never degraded to a Miss (which would refetch upstream).
                check_quarantine_until(metadata.quarantine_until)?;
                match self.open_cached_stream(cache_key, &metadata).await? {
                    Some(result) => Ok(StreamingCacheReadOutcome::Hit(result)),
                    None => Ok(StreamingCacheReadOutcome::Miss),
                }
            }
            cache_classifier::Freshness::Stale => {
                let metadata = metadata.expect("stale implies metadata present");
                match self
                    .revalidate_verdict(repo, fetch_path, metadata_key, &metadata)
                    .await
                {
                    // 304 extended the TTL; stream the cached body.
                    RevalidationVerdict::ServeRevalidated
                    | RevalidationVerdict::ServeStaleIfError => {
                        // Package Age Policy (#1770): gate the revalidated /
                        // stale-if-error body the same way as a fresh hit.
                        check_quarantine_until(metadata.quarantine_until)?;
                        match self.open_cached_stream(cache_key, &metadata).await? {
                            Some(result) => Ok(StreamingCacheReadOutcome::Hit(result)),
                            None => Ok(StreamingCacheReadOutcome::Miss),
                        }
                    }
                    // Changed / no validator / past grace: refill upstream.
                    RevalidationVerdict::Refill => Ok(StreamingCacheReadOutcome::Miss),
                }
            }
        }
    }

    /// Open a streaming read of a cached body and pair it with the sidecar's
    /// content-type / size. Returns `Ok(None)` when the sidecar says cached but
    /// the body is gone (out-of-band eviction) so the caller refetches (B6).
    async fn open_cached_stream(
        &self,
        cache_key: &str,
        metadata: &CacheMetadata,
    ) -> Result<Option<StreamingFetchResult>> {
        match self.storage.get_stream(cache_key).await {
            Ok(body) => Ok(Some(StreamingFetchResult {
                body,
                content_type: metadata.content_type.clone(),
                content_length: Some(metadata.size_bytes as u64),
            })),
            Err(AppError::NotFound(_)) => {
                tracing::debug!(
                    cache_key = %cache_key,
                    "cache metadata present but body missing; refetching"
                );
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// The streaming leader body: open upstream ONCE, tee to client + cache,
    /// and hand the coordinator a [`StreamHandle`] it fans out to followers.
    /// All cache-correctness invariants (#1365 zero-byte guard, #1051 ETag pin,
    /// body→sidecar ordering) stay inside [`CachePersister::tee_stream`] — this
    /// method does not touch bytes.
    async fn open_streaming_leader(
        &self,
        repo: &Repository,
        fetch_path: &str,
        cache_path: &str,
        cache_key: String,
        metadata_key: String,
    ) -> Result<StreamHandle> {
        // Package Age Policy (#1770): the streaming path has no buffered
        // upstream `Last-Modified` to base a release-date hold on (#1771), so
        // a repo with the policy enabled conservatively refuses to open a new
        // streaming fetch outright. Entries cached while the policy was off
        // are unaffected (gated by their sidecar on the hit path above), and
        // the error propagates as 409 rather than degrading to a fall-back.
        let quarantine_config = quarantine_service::resolve_config(&self.db, repo.id).await;
        if quarantine_service::should_quarantine(&quarantine_config) {
            return Err(AppError::Conflict(
                "Artifact is quarantined and pending security review".to_string(),
            ));
        }

        let upstream_url = Self::remote_target(repo)?;
        let full_url = Self::build_upstream_url(upstream_url, fetch_path);
        let upstream = match self.fetch_from_upstream_streaming(&full_url, repo.id).await {
            Ok(upstream) => upstream,
            Err(err) => {
                return self
                    .handle_streaming_leader_upstream_error(
                        cache_path,
                        &cache_key,
                        &metadata_key,
                        err,
                    )
                    .await;
            }
        };

        // #1611: classify the path. Immutable paths (versioned artifacts, OCI
        // blobs) cache effectively forever; mutable indexes get the short
        // conservative TTL (or the repo-configured override). Classification
        // keys off `cache_path` — the canonical artifact identity — not the
        // upstream-specific download URL.
        let cache_ttl = self.cache_ttl_for_path(repo, cache_path).await;

        // Cache miss + successful upstream fetch: a new artifact is being
        // cached. Surface the scan-on-proxy gap (#1274) before teeing to
        // the background cache writer so an enabled-but-unimplemented
        // setting is observable in logs rather than silently doing nothing.
        self.warn_if_proxy_scan_unsupported(repo.id, cache_path)
            .await;

        // #1999: index the newly-cached Maven artifact into the package
        // catalog (packages/package_versions only — never the artifacts
        // table, preserving #1278). The streaming tee computes the checksum
        // only after the body is fully written, so it is unknown here; pass
        // the upstream Content-Length when advertised (0 otherwise) and no
        // checksum. Best-effort: failures never fail the client's fetch.
        self.index_cached_package(
            repo.id,
            cache_path,
            upstream.content_length.unwrap_or(0) as i64,
            None,
        )
        .await;

        let headers = StreamHeaders {
            content_type: upstream.content_type.clone(),
            content_length: upstream.content_length,
        };

        let body = self.cache_persister.tee_stream(
            upstream.body,
            cache_key,
            metadata_key,
            CacheMetadataTemplate {
                content_type: upstream.content_type,
                etag: upstream.etag,
                last_modified: None,
                ttl_secs: cache_ttl,
            },
            upstream.content_length,
        );

        Ok(StreamHandle { body, headers })
    }

    /// Apply the buffered path's upstream-error correctness to the streaming
    /// leader (#1611 streaming-path parity). Mirrors the buffered produce
    /// closure's `Err(upstream_err)` arm:
    ///
    /// * **404** -> write the negative-cache marker so a hot loop of misses on a
    ///   not-yet-published artifact does not hammer upstream, then propagate the
    ///   404. We never serve stale for a 404 (the object is gone / never existed).
    /// * **transient (5xx / timeout / transport)** -> RFC 5861 `stale-if-error`:
    ///   stream the stale body we already hold (regardless of TTL — the entry was
    ///   already past TTL or absent), else propagate the original error.
    async fn handle_streaming_leader_upstream_error(
        &self,
        path: &str,
        cache_key: &str,
        metadata_key: &str,
        upstream_err: AppError,
    ) -> Result<StreamHandle> {
        if matches!(upstream_err, AppError::NotFound(_)) {
            self.write_negative_cache(cache_key, metadata_key, path)
                .await;
            return Err(upstream_err);
        }

        // Transient failure: serve the stale body if we still hold one. The
        // sidecar (if present) carries the content-type / size for the headers;
        // a missing sidecar falls back to no content-type and an unknown length.
        if let Ok(body) = self.storage.get_stream(cache_key).await {
            let metadata = self.load_cache_metadata(metadata_key).await.unwrap_or(None);
            tracing::warn!(
                cache_key = %cache_key,
                error = %upstream_err,
                "streaming upstream fetch failed; serving stale cached copy (stale-if-error)"
            );
            let headers = StreamHeaders {
                content_type: metadata.as_ref().and_then(|m| m.content_type.clone()),
                content_length: metadata.as_ref().map(|m| m.size_bytes as u64),
            };
            return Ok(StreamHandle { body, headers });
        }

        Err(upstream_err)
    }

    /// Uncoordinated streaming fetch (cache hit fast path + direct upstream tee
    /// with no single-flight). Used as the last-resort fall-back after the
    /// coordinated path exhausts its re-enter budget under pathological
    /// contention, so a request never spuriously fails. This is the original
    /// pre-#1694 behavior, preserved verbatim minus the inlined cache hit.
    async fn fetch_artifact_streaming_uncoordinated(
        &self,
        repo: &Repository,
        fetch_path: &str,
        cache_path: &str,
    ) -> Result<StreamingFetchResult> {
        let cache_key = Self::cache_storage_key(&repo.key, cache_path)?;
        let metadata_key = Self::cache_metadata_key(&repo.key, cache_path)?;

        if let Some(result) = self
            .try_streaming_cache_hit(repo, fetch_path, cache_path, &cache_key, &metadata_key)
            .await?
        {
            return Ok(result);
        }

        let handle = self
            .open_streaming_leader(repo, fetch_path, cache_path, cache_key, metadata_key)
            .await?;
        Ok(StreamingFetchResult::from(handle))
    }

    /// Check if upstream has a newer version of the artifact.
    /// Returns true if upstream has newer content or cache is expired.
    pub async fn check_upstream(&self, repo: &Repository, path: &str) -> Result<bool> {
        // Validate repository type
        let upstream_url = Self::remote_target(repo)?;

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
        let upstream_url = Self::remote_target(repo)?;

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
        let upstream_url = Self::remote_target(repo)?;

        let full_url = Self::build_upstream_url(upstream_url, path);
        let resp = self.fetch_from_upstream(&full_url, repo.id).await?;
        Ok((resp.content, resp.content_type, resp.link))
    }

    /// Invalidate cached artifact
    pub async fn invalidate_cache(&self, repo: &Repository, path: &str) -> Result<()> {
        self.invalidate_cache_keys(&repo.key, path).await
    }

    /// Invalidate cached artifact by repo key alone.
    ///
    /// Same effect as `invalidate_cache` but doesn't require constructing
    /// a `Repository` value. Useful for handlers that only carry a thin
    /// `RepoInfo` and need to evict sibling cache entries (e.g. APT
    /// invalidating stale Packages indices when Release changes, #1147).
    pub async fn invalidate_cache_by_key(&self, repo_key: &str, path: &str) -> Result<()> {
        self.invalidate_cache_keys(repo_key, path).await
    }

    /// Shared invalidation core for [`Self::invalidate_cache`] (keyed off
    /// `repo.key`) and [`Self::invalidate_cache_by_key`] (keyed off a bare
    /// `repo_key`). The two public methods differ only in how they obtain the
    /// repo key; the eviction itself — derive both cache keys, then delete the
    /// content and metadata blobs in that order, ignoring delete errors — is
    /// identical, so it lives here as a single source of truth (#1618 S3).
    async fn invalidate_cache_keys(&self, repo_key: &str, path: &str) -> Result<()> {
        let keys = CacheKeys::derive(repo_key, path)?;
        self.cache_store.invalidate(&keys).await
    }

    /// Read the proxy cache metadata blob (`cached_at`, `expires_at`,
    /// `upstream_etag`, `storage_etag`, `content_type`, `size_bytes`) for
    /// a given path on a repository, without checking expiry.
    ///
    /// Returns `Ok(None)` when no metadata blob exists (e.g. a Remote-typed
    /// artifact that was direct-uploaded and has never been fetched through
    /// the proxy) or when the underlying storage rejects the path
    /// (path-traversal segments are rejected by `cache_metadata_key`).
    /// Errors from a transient storage failure on the GET propagate as
    /// `Err(...)` so callers can choose between bubbling up and tolerating.
    ///
    /// Used by `get_artifact_metadata` (#1541) to surface cache freshness
    /// alongside the static artifact metadata in a single round-trip,
    /// without exposing the metadata-blob storage key derivation to
    /// handlers.
    pub async fn get_cache_metadata(
        &self,
        repo_key: &str,
        path: &str,
    ) -> Result<Option<CacheMetadata>> {
        let metadata_key = match Self::cache_metadata_key(repo_key, path) {
            Ok(k) => k,
            Err(_) => return Ok(None),
        };
        self.load_cache_metadata(&metadata_key).await
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

    /// List the artifacts a remote repository has cached through the proxy.
    ///
    /// Proxy-cached items are not tracked in the `artifacts` table (#1278 /
    /// #1280): caching them there reintroduced a doubled-prefix storage path
    /// bug on filesystem backends. The body and a JSON metadata sidecar still
    /// live on disk under `proxy-cache/<repo_key>/<path>/{__content__,
    /// __cache_meta__.json}`, so this walks that prefix to recover the set of
    /// objects the proxy has actually served. The repository artifact-listing
    /// endpoint merges these into its response so remote-cached packages show
    /// up in the UI and can be scanned (#1548, web #424).
    ///
    /// Returns an empty list when the storage backend cannot list the prefix.
    /// Each entry's `size_bytes`, `checksum_sha256`, `content_type`, and
    /// `cached_at` come from the sidecar; entries whose sidecar is missing or
    /// unreadable are skipped (a half-written or legacy cache write).
    pub async fn list_cached_artifacts(&self, repo_key: &str) -> Vec<CachedArtifactEntry> {
        let paths = self.list_cached_paths(repo_key).await;
        self.load_cached_entries(repo_key, &paths).await
    }

    /// List the logical paths of every proxy-cached artifact for a repo
    /// **without** loading any sidecar metadata.
    ///
    /// This is the cheap first half of a paginated cached listing (#1571):
    /// the caller filters + slices these path strings down to the requested
    /// page (both listing filters — path prefix and substring `q` — are
    /// purely path-based) and then loads sidecars for just that page via
    /// [`Self::load_cached_entries`]. That turns a cached listing from O(N)
    /// sidecar reads on every request into O(page) reads, which is what
    /// previously made large proxy caches expensive to page through.
    ///
    /// Returns paths sorted + deduped (see [`Self::cached_artifact_paths`]),
    /// or an empty list when the storage backend cannot list the prefix.
    pub async fn list_cached_paths(&self, repo_key: &str) -> Vec<String> {
        let prefix = format!("proxy-cache/{}/", repo_key);
        let keys = match self.storage.list(Some(&prefix)).await {
            Ok(keys) => keys,
            Err(e) => {
                tracing::debug!(
                    repo_key = %repo_key,
                    error = %e,
                    "listing proxy cache for repository artifact listing failed; \
                     returning no cached artifacts"
                );
                return Vec::new();
            }
        };

        Self::cached_artifact_paths(repo_key, keys.iter().map(String::as_str))
    }

    /// Load sidecar metadata for a specific, already-paginated set of cached
    /// `paths`, returning the assembled entries sorted by path.
    ///
    /// Pairs with [`Self::list_cached_paths`] so a cached listing only reads
    /// the sidecars for the requested page rather than every object in the
    /// cache (#1571). Sidecars are loaded concurrently with bounded
    /// parallelism (#1608); `buffer_unordered` yields out of order, so the
    /// collected entries are re-sorted by path to stay deterministic. Paths
    /// whose sidecar is missing or unreadable are skipped, matching the
    /// previous whole-cache load.
    pub async fn load_cached_entries(
        &self,
        repo_key: &str,
        paths: &[String],
    ) -> Vec<CachedArtifactEntry> {
        let mut entries: Vec<CachedArtifactEntry> = futures::stream::iter(paths.iter().cloned())
            .map(|path| async move {
                let metadata_key = Self::cache_metadata_key(repo_key, &path).ok()?;
                match self.load_cache_metadata(&metadata_key).await {
                    Ok(Some(m)) => Some(Self::build_cached_entry(path, m)),
                    Ok(None) => None,
                    Err(e) => {
                        tracing::debug!(
                            repo_key = %repo_key,
                            path = %path,
                            error = %e,
                            "reading proxy cache sidecar failed; skipping entry"
                        );
                        None
                    }
                }
            })
            .buffer_unordered(Self::LIST_CACHED_SIDECAR_CONCURRENCY)
            .filter_map(|entry| async move { entry })
            .collect()
            .await;

        entries.sort_by(|a, b| a.path.cmp(&b.path));
        entries
    }

    /// Bounded concurrency for the per-path sidecar reads in
    /// [`Self::list_cached_artifacts`] (#1608). Keeps the storage backend from
    /// being hit with one in-flight request per cached path on large repos
    /// while still collapsing the previously sequential O(N) round-trips.
    const LIST_CACHED_SIDECAR_CONCURRENCY: usize = 32;

    /// Assemble a [`CachedArtifactEntry`] from a logical path and its loaded
    /// sidecar metadata. Pure (no I/O) so the field mapping — name extraction
    /// and the `application/octet-stream` content-type default — is unit-testable
    /// without a storage backend.
    fn build_cached_entry(path: String, metadata: CacheMetadata) -> CachedArtifactEntry {
        let name = path.rsplit('/').next().unwrap_or(&path).to_string();
        CachedArtifactEntry {
            path,
            name,
            size_bytes: metadata.size_bytes,
            checksum_sha256: metadata.checksum_sha256,
            content_type: metadata
                .content_type
                .unwrap_or_else(|| "application/octet-stream".to_string()),
            cached_at: metadata.cached_at,
        }
    }

    /// Recover the distinct logical artifact paths from a set of proxy-cache
    /// storage keys.
    ///
    /// Content lives at `proxy-cache/<repo_key>/<path>/__content__`; the
    /// sibling `__cache_meta__.json` and any other leaf are ignored. Strips
    /// the `proxy-cache/<repo_key>/` prefix and the `/__content__` suffix to
    /// return `<path>`, deduped and sorted. Pure so the parsing can be
    /// unit-tested without a storage backend.
    fn cached_artifact_paths<'a, I>(repo_key: &str, keys: I) -> Vec<String>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let prefix = format!("proxy-cache/{}/", repo_key);
        let mut paths: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for key in keys {
            let Some(rest) = key.strip_prefix(&prefix) else {
                continue;
            };
            let Some(path) = rest.strip_suffix("/__content__") else {
                continue;
            };
            if path.is_empty() {
                continue;
            }
            paths.insert(path.to_string());
        }
        paths.into_iter().collect()
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

    /// Mutability-aware cache TTL for a specific proxied path (#1611).
    ///
    /// * **Immutable** paths (versioned Maven artifacts, OCI digest blobs, PyPI
    ///   wheels, npm tarballs, `.crate` files) get an effectively-infinite TTL;
    ///   [`cache_classifier::evaluate`] short-circuits them as `Fresh` on every
    ///   hit so upstream is never contacted again.
    /// * **Mutable** paths (indexes, packuments, tag manifests) use the
    ///   repo-configured `cache_ttl_secs` override if present, else the
    ///   conservative [`cache_classifier::MUTABLE_DEFAULT_TTL_SECS`]. They are
    ///   conditionally revalidated once past TTL.
    ///
    /// Centralising the decision here keeps the write-time TTL and the
    /// read-time freshness evaluation consistent: both classify the same way.
    async fn cache_ttl_for_path(&self, repo: &Repository, path: &str) -> i64 {
        match cache_classifier::classify(&repo.format, path) {
            cache_classifier::Mutability::Immutable => {
                cache_classifier::Mutability::Immutable.write_ttl_secs()
            }
            cache_classifier::Mutability::Mutable { default_ttl_secs } => {
                // A repo-level override still applies to mutable paths; fall
                // back to the conservative classifier default otherwise.
                self.get_cache_ttl_override(repo.id)
                    .await
                    .unwrap_or(default_ttl_secs)
            }
        }
    }

    /// Read the optional repo-level `cache_ttl_secs` override. Returns `None`
    /// when unset/unparseable so callers can apply a context-appropriate
    /// default (the mutable classifier default, or [`DEFAULT_CACHE_TTL_SECS`]).
    async fn get_cache_ttl_override(&self, repo_id: Uuid) -> Option<i64> {
        let result = sqlx::query_scalar!(
            r#"
            SELECT value FROM repository_config
            WHERE repository_id = $1 AND key = 'cache_ttl_secs'
            "#,
            repo_id
        )
        .fetch_optional(&self.db)
        .await
        .ok()??;
        result.and_then(|v| v.parse().ok())
    }

    /// Validate that `repo` is a remote proxy and return its upstream URL.
    ///
    /// Performs the two checks shared by every proxy fetch/check method, in
    /// order: the repository must be a [`RepositoryType::Remote`] (otherwise
    /// [`AppError::Validation`]), and it must have an `upstream_url`
    /// (otherwise [`AppError::Config`]). The returned `&str` borrows from
    /// `repo`, so it stays valid across the `.await` points inside the
    /// hydration closures that use it.
    fn remote_target(repo: &Repository) -> Result<&str> {
        if repo.repo_type != RepositoryType::Remote {
            return Err(AppError::Validation(
                "Proxy operations only supported for remote repositories".to_string(),
            ));
        }

        repo.upstream_url
            .as_deref()
            .ok_or_else(|| AppError::Config("Remote repository missing upstream_url".to_string()))
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
        CacheKeys::derive(repo_key, path).map(|k| k.content)
    }

    /// Whether `storage_key` addresses proxy-cache content.
    ///
    /// Proxy-cache keys are `proxy-cache/<repo_key>/<path>/__content__` and live
    /// at the storage root (no global key prefix), unlike hosted artifacts. The
    /// distinction matters when presigning: cache keys must be signed through
    /// the no-prefix [`Self::cache_storage_backend`] handle (#1555).
    pub fn is_proxy_cache_key(storage_key: &str) -> bool {
        storage_key.starts_with("proxy-cache/")
    }

    /// Purge every proxy-cache object for a repository from the global default
    /// storage backend, returning the number of keys deleted.
    ///
    /// Proxy-cached content is keyed by the repository *key* (not its id) and
    /// is intentionally NOT recorded in the `artifacts` table (#1278), so the
    /// repository-delete path that purges `artifacts`-backed objects never sees
    /// these blobs. Left behind, the whole `proxy-cache/<repo_key>/` subtree
    /// outlives the repository; a later repository created with the same key
    /// derives the same cache keys and would serve the deleted repository's
    /// stale upstream content instead of fetching from its own upstream (#2047,
    /// a content-integrity / supply-chain hazard).
    ///
    /// This lists the entire `proxy-cache/<repo_key>/` prefix on the same
    /// global-default backend the cache writer uses (`self.storage`) and deletes
    /// every returned key. Listing the raw keys (rather than reconstructing
    /// logical paths via [`Self::cached_artifact_paths`]) is deliberate: it
    /// covers the `__content__` body, the `__cache_meta__.json` sidecar, AND
    /// negative-cache sidecars that exist with no `__content__` companion, so a
    /// previously cached 404 is re-evaluated against the new upstream too.
    ///
    /// Best-effort: a listing failure yields a no-op (logged by the caller via
    /// the returned `Result`), and individual `NotFound` deletes are tolerated
    /// so a concurrent eviction does not turn the purge into an error. The
    /// prefix is repo-key scoped, so calling this for a hosted repository (which
    /// has no proxy cache) is a harmless empty list.
    pub async fn purge_repo_cache(&self, repo_key: &str) -> Result<usize> {
        let prefix = format!("proxy-cache/{}/", repo_key);
        let keys = self.storage.list(Some(&prefix)).await?;
        let mut deleted = 0usize;
        for key in keys {
            match self.storage.delete(&key).await {
                Ok(()) => deleted += 1,
                Err(AppError::NotFound(_)) => {}
                Err(e) => {
                    tracing::warn!(
                        repo_key = %repo_key,
                        storage_key = %key,
                        error = %e,
                        "failed to purge proxy-cache object on repository delete"
                    );
                }
            }
        }
        Ok(deleted)
    }

    /// Generate storage key for cache metadata
    fn cache_metadata_key(repo_key: &str, path: &str) -> Result<String> {
        CacheKeys::derive(repo_key, path).map(|k| k.metadata)
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

    /// Attempt to retrieve a cached artifact if valid.
    ///
    /// Thin shim over [`Self::get_cached`] with `allow_stale = false`: the
    /// expiry gate is enforced and a transient metadata/body read error is
    /// swallowed as a cache miss (B6) rather than surfaced as a 502.
    async fn get_cached_artifact(
        &self,
        cache_key: &str,
        metadata_key: &str,
    ) -> Result<Option<(Bytes, Option<String>)>> {
        self.get_cached(cache_key, metadata_key, false).await
    }

    /// Up-front cache read with #1611 classification + conditional
    /// revalidation. Drives the [`cache_classifier::Freshness`] state machine:
    ///
    /// * **Miss / no metadata** -> [`CacheReadOutcome::Miss`] (fetch upstream).
    /// * **NegativeHit** -> [`CacheReadOutcome::NegativeHit`] (cached 404).
    /// * **Fresh** -> serve the cached body. Immutable paths land here on every
    ///   hit and therefore NEVER contact upstream (the load-bearing invariant).
    /// * **Stale** (mutable, past TTL) -> conditional revalidation via
    ///   [`Self::revalidate_stale`]; a 304 extends the entry and serves it, any
    ///   other outcome degrades to `Miss` so the single-flight refill runs.
    ///
    /// B6 is preserved: a transient body/metadata read error surfaces as a
    /// cache `Miss` (via `get_cached_artifact`), never a propagated 502.
    async fn read_cached_with_revalidation(
        &self,
        repo: &Repository,
        fetch_path: &str,
        cache_path: &str,
        cache_key: &str,
        metadata_key: &str,
    ) -> Result<CacheReadOutcome> {
        let mutability = cache_classifier::classify(&repo.format, cache_path);

        // Load the sidecar to evaluate freshness. A read/parse error is treated
        // as "no entry" (Miss) — same B6-safe stance as the fresh read path.
        let metadata = self.load_cache_metadata(metadata_key).await.unwrap_or(None);
        let entry = metadata.as_ref().map(|m| m.as_cache_entry(mutability));

        match cache_classifier::evaluate(entry.as_ref(), Utc::now()) {
            cache_classifier::Freshness::Miss => Ok(CacheReadOutcome::Miss),
            cache_classifier::Freshness::NegativeHit => Ok(CacheReadOutcome::NegativeHit),
            cache_classifier::Freshness::Fresh => {
                // Package Age Policy (#1770): a held entry must 409 — checked
                // AFTER freshness evaluation, and the error propagates rather
                // than degrading to a Miss (which would refetch upstream).
                check_quarantine_until(
                    metadata
                        .as_ref()
                        .expect("fresh implies metadata present")
                        .quarantine_until,
                )?;
                // Serve the body. Immutable hits reach here and never touch
                // upstream. `get_cached_artifact` re-verifies checksum + body
                // presence; a missing/poisoned body degrades to Miss (B6).
                match self.get_cached_artifact(cache_key, metadata_key).await? {
                    Some((content, content_type)) => {
                        Ok(CacheReadOutcome::Hit(content, content_type))
                    }
                    None => Ok(CacheReadOutcome::Miss),
                }
            }
            cache_classifier::Freshness::Stale => {
                // Safe: Stale only arises when metadata is present.
                let stale_metadata = metadata.as_ref().expect("stale implies metadata present");
                let outcome = self
                    .revalidate_stale(repo, fetch_path, cache_key, metadata_key, stale_metadata)
                    .await?;
                // Package Age Policy (#1770): gate a revalidated /
                // stale-if-error body the same way as a fresh hit. A Refill
                // (Miss) is NOT gated here — the upstream refetch records and
                // enforces its own hold window.
                if matches!(outcome, CacheReadOutcome::Hit(..)) {
                    check_quarantine_until(stale_metadata.quarantine_until)?;
                }
                Ok(outcome)
            }
        }
    }

    /// Cache-only, classifier- and quarantine-aware buffered read for the
    /// virtual metadata first-match resolver (#2069).
    ///
    /// Unlike [`Self::get_cached_artifact_by_path`] (a raw, expiry-only read)
    /// this runs the #1611 freshness classifier and the #1770 Package-Age-Policy
    /// gate; unlike [`Self::read_cached_with_revalidation`] it NEVER contacts
    /// upstream — a stale mutable entry is reported as a miss so the caller can
    /// fall through to its own (parallel) upstream fetch instead of serializing
    /// a revalidation here.
    ///
    /// Returns:
    /// * `Ok(Some((body, content_type)))` — a fresh, non-quarantined cache hit;
    /// * `Ok(None)` — miss / negative-cache / stale (caller re-fetches upstream);
    /// * `Err(Conflict)` — a fresh entry held by Package-Age-Policy, so the
    ///   caller skips this member (matching the buffered fetch path, which also
    ///   surfaces the 409 rather than serving the held bytes).
    pub async fn cached_metadata_if_servable(
        &self,
        repo: &Repository,
        cache_path: &str,
    ) -> Result<Option<(Bytes, Option<String>)>> {
        let cache_key = Self::cache_storage_key(&repo.key, cache_path)?;
        let metadata_key = Self::cache_metadata_key(&repo.key, cache_path)?;
        let mutability = cache_classifier::classify(&repo.format, cache_path);
        let metadata = self
            .load_cache_metadata(&metadata_key)
            .await
            .unwrap_or(None);
        let entry = metadata.as_ref().map(|m| m.as_cache_entry(mutability));
        match cache_classifier::evaluate(entry.as_ref(), Utc::now()) {
            cache_classifier::Freshness::Fresh => {
                check_quarantine_until(
                    metadata
                        .as_ref()
                        .expect("fresh implies metadata present")
                        .quarantine_until,
                )?;
                self.get_cached_artifact(&cache_key, &metadata_key).await
            }
            // Miss / NegativeHit / Stale: no upstream contact here — the caller
            // falls through to its own (parallel) upstream fetch.
            _ => Ok(None),
        }
    }

    /// Conditionally revalidate a stale (mutable, past-TTL) cache entry (#1611
    /// §2.2). Sends `If-None-Match` (and `If-Modified-Since` when available)
    /// derived from the cached validators:
    ///
    /// * **304 Not Modified** -> extend `expires_at` in place and serve the
    ///   cached body (cheap; no body transfer).
    /// * **changed (200 / different ETag)** -> [`CacheReadOutcome::Miss`] so the
    ///   caller's existing single-flight coordinator refills the entry once.
    /// * **upstream error (5xx / timeout)** -> stale-if-error: serve the stale
    ///   body within [`cache_classifier::STALE_IF_ERROR_GRACE_SECS`] of expiry,
    ///   else `Miss`.
    /// * **no validators** -> `Miss` (cannot revalidate cheaply; refill).
    async fn revalidate_stale(
        &self,
        repo: &Repository,
        fetch_path: &str,
        cache_key: &str,
        metadata_key: &str,
        metadata: &CacheMetadata,
    ) -> Result<CacheReadOutcome> {
        match self
            .revalidate_verdict(repo, fetch_path, metadata_key, metadata)
            .await
        {
            RevalidationVerdict::Refill => Ok(CacheReadOutcome::Miss),
            RevalidationVerdict::ServeRevalidated => {
                match self
                    .get_stale_cached_artifact(cache_key, metadata_key)
                    .await
                {
                    Ok(Some((content, content_type))) => {
                        tracing::debug!(cache_key = %cache_key, "304 revalidation: extended TTL, serving cached body");
                        Ok(CacheReadOutcome::Hit(content, content_type))
                    }
                    // Body vanished between probe and read: refill.
                    _ => Ok(CacheReadOutcome::Miss),
                }
            }
            RevalidationVerdict::ServeStaleIfError => {
                if let Ok(Some((content, content_type))) = self
                    .get_stale_cached_artifact(cache_key, metadata_key)
                    .await
                {
                    return Ok(CacheReadOutcome::Hit(content, content_type));
                }
                Ok(CacheReadOutcome::Miss)
            }
        }
    }

    /// Shared conditional-revalidation correctness core for a stale (mutable,
    /// past-TTL) entry (#1611 §2.2). Performs the cheap `If-None-Match` probe and
    /// the `stale-if-error` grace-window check, then returns a
    /// [`RevalidationVerdict`] describing the action — WITHOUT materializing the
    /// body, so the buffered ([`Self::revalidate_stale`]) and streaming
    /// ([`Self::revalidate_stale_streaming`]) callers can each retrieve the
    /// cached body in their own representation (`Bytes` vs. a storage stream).
    ///
    /// As a side effect, a 304 extends `expires_at` in place before returning
    /// [`RevalidationVerdict::ServeRevalidated`].
    ///
    /// * **no ETag validator** -> [`RevalidationVerdict::Refill`] (cannot
    ///   revalidate cheaply).
    /// * **304 Not Modified** -> extend TTL, [`RevalidationVerdict::ServeRevalidated`].
    /// * **changed (200 / different ETag)** -> [`RevalidationVerdict::Refill`].
    /// * **upstream error within grace** -> [`RevalidationVerdict::ServeStaleIfError`].
    /// * **upstream error past grace** -> [`RevalidationVerdict::Refill`].
    async fn revalidate_verdict(
        &self,
        repo: &Repository,
        fetch_path: &str,
        metadata_key: &str,
        metadata: &CacheMetadata,
    ) -> RevalidationVerdict {
        let Some(etag) = metadata.upstream_etag.clone() else {
            // No ETag validator: a cheap conditional request is impossible.
            // Fall back to a full single-flight refill.
            return RevalidationVerdict::Refill;
        };

        let Ok(upstream_url) = Self::remote_target(repo) else {
            return RevalidationVerdict::Refill;
        };
        let full_url = Self::build_upstream_url(upstream_url, fetch_path);

        match self.check_etag_changed(&full_url, &etag, repo.id).await {
            Ok(false) => {
                // 304 Not Modified: extend the TTL and serve the cached body.
                let new_ttl = self.cache_ttl_for_path(repo, fetch_path).await;
                self.extend_cache_expiry(metadata_key, metadata, new_ttl)
                    .await;
                RevalidationVerdict::ServeRevalidated
            }
            // Changed upstream: let the single-flight coordinator refill once.
            Ok(true) => RevalidationVerdict::Refill,
            Err(err) => {
                // Upstream unreachable mid-revalidation: stale-if-error within
                // the grace window, else fall through to a refill attempt.
                let within_grace = Utc::now()
                    < metadata.expires_at
                        + chrono::Duration::seconds(cache_classifier::STALE_IF_ERROR_GRACE_SECS);
                if within_grace {
                    tracing::warn!(
                        metadata_key = %metadata_key,
                        error = %err,
                        "revalidation failed; serving stale within stale-if-error grace"
                    );
                    RevalidationVerdict::ServeStaleIfError
                } else {
                    RevalidationVerdict::Refill
                }
            }
        }
    }

    /// Re-stamp a cache entry's `expires_at` after a successful 304
    /// revalidation, preserving every other sidecar field (#1611). Best-effort:
    /// a write failure only means the entry revalidates again sooner.
    async fn extend_cache_expiry(
        &self,
        metadata_key: &str,
        metadata: &CacheMetadata,
        ttl_secs: i64,
    ) {
        let mut extended = metadata.clone();
        extended.expires_at = Utc::now() + chrono::Duration::seconds(ttl_secs);
        match serde_json::to_vec(&extended) {
            Ok(json) => {
                if let Err(e) = self.storage.put(metadata_key, Bytes::from(json)).await {
                    tracing::warn!(metadata_key = %metadata_key, error = %e, "failed to extend cache TTL after 304");
                }
            }
            Err(e) => {
                tracing::warn!(metadata_key = %metadata_key, error = %e, "failed to serialize extended cache metadata");
            }
        }
    }

    /// Write a negative-cache sidecar recording an upstream 404 (#1611). The
    /// entry holds no body; [`cache_classifier::evaluate`] returns
    /// `NegativeHit` until `negative_cached_until` passes, after which it is a
    /// `Miss`. Best-effort: a write failure simply means the next request
    /// re-asks upstream.
    async fn write_negative_cache(&self, cache_key: &str, metadata_key: &str, cache_path: &str) {
        // Drop any stale positive body so a future read can never serve it
        // alongside the negative marker.
        let _ = self.storage.delete(cache_key).await;

        let now = Utc::now();
        let neg_ttl = chrono::Duration::seconds(cache_classifier::NEGATIVE_CACHE_TTL_SECS);
        let metadata = CacheMetadata {
            cached_at: now,
            upstream_etag: None,
            storage_etag: None,
            last_modified: None,
            quarantine_until: None,
            negative_cached_until: Some(now + neg_ttl),
            // expires_at mirrors the negative window so any expiry-only reader
            // also treats it as expired once the window passes.
            expires_at: now + neg_ttl,
            content_type: None,
            size_bytes: 0,
            checksum_sha256: String::new(),
        };
        match serde_json::to_vec(&metadata) {
            Ok(json) => {
                if let Err(e) = self.storage.put(metadata_key, Bytes::from(json)).await {
                    tracing::debug!(metadata_key = %metadata_key, error = %e, "failed to write negative-cache entry");
                } else {
                    tracing::debug!(cache_path = %cache_path, "negative-cached upstream 404");
                }
            }
            Err(e) => {
                tracing::debug!(error = %e, "failed to serialize negative-cache metadata");
            }
        }
    }

    /// Shared cache-read path behind [`Self::get_cached_artifact`] (fresh) and
    /// [`Self::get_stale_cached_artifact`] (stale fallback). The two callers
    /// were near-duplicates; `allow_stale` reproduces every divergence exactly:
    ///
    /// * **Metadata read error.** Fresh treats a sidecar read/parse error as a
    ///   cache miss (B6 — a waiter racing the single-flight leader's metadata
    ///   write, or half-written JSON, must not bubble out as a 502). Stale
    ///   propagates the error via `?`.
    /// * **Expiry gate.** Fresh returns a miss once `Utc::now() > expires_at`;
    ///   stale skips the gate entirely (that is the point of the fallback).
    /// * **Body read error.** Fresh swallows a transient storage read error as
    ///   a miss (B6); stale propagates it.
    /// * **Log wording.** Fresh logs "Cache …"; stale logs "Stale cache …" and
    ///   includes the expiry timestamp on a hit.
    ///
    /// The checksum verification (and its miss-on-mismatch) is identical for
    /// both flags.
    async fn get_cached(
        &self,
        cache_key: &str,
        metadata_key: &str,
        allow_stale: bool,
    ) -> Result<Option<(Bytes, Option<String>)>> {
        self.cache_store
            .get(cache_key, metadata_key, allow_stale)
            .await
    }

    /// Load cache metadata from storage.
    ///
    /// Thin delegation to [`CacheStore::load_metadata`] (#1618 S7).
    async fn load_cache_metadata(&self, metadata_key: &str) -> Result<Option<CacheMetadata>> {
        self.cache_store.load_metadata(metadata_key).await
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
    /// Thin delegation to [`UpstreamClient::fetch_buffered`] (#1618 S8). The
    /// buffered path's OCI `Accept` semantics (set on the initial request AND
    /// re-added on the bearer retry) live there; this signature and every
    /// external call site are unchanged.
    async fn fetch_from_upstream_with_accept(
        &self,
        url: &str,
        repo_id: Uuid,
        accept: Option<&str>,
    ) -> Result<UpstreamResponse> {
        self.upstream_client
            .fetch_buffered(url, repo_id, accept)
            .await
    }

    /// Streaming variant of [`Self::fetch_from_upstream`] used by the
    /// proxy slow path (#895). Returns the upstream body as a stream of
    /// `Bytes` chunks instead of buffering the whole body into memory.
    ///
    /// Thin delegation to [`UpstreamClient::fetch_stream`] (#1618 S8). The
    /// streaming path deliberately sets NO `Accept` header (the intentional
    /// asymmetry with the buffered path); that decision lives there.
    async fn fetch_from_upstream_streaming(
        &self,
        url: &str,
        repo_id: Uuid,
    ) -> Result<UpstreamStream> {
        self.upstream_client.fetch_stream(url, repo_id).await
    }

    /// Parse a `WWW-Authenticate: Bearer realm="...",service="...",scope="..."`
    /// header into a map of key-value pairs.
    ///
    /// Thin delegation to [`UpstreamClient::parse_bearer_challenge`] (#1618 S8);
    /// retained on `ProxyService` so the existing bearer-challenge-parse unit
    /// tests keep calling `ProxyService::parse_bearer_challenge` unchanged.
    /// The runtime callers now use [`UpstreamClient::parse_bearer_challenge`]
    /// directly, so this wrapper exists only for the test oracle.
    #[cfg(test)]
    fn parse_bearer_challenge(header: &str) -> HashMap<String, String> {
        UpstreamClient::parse_bearer_challenge(header)
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
        last_modified: Option<String>,
        ttl_secs: i64,
        repository_id: Uuid,
        artifact_path: &str,
        quarantine_until: Option<DateTime<Utc>>,
    ) -> Result<()> {
        self.cache_persister
            .write_buffered(
                cache_key,
                metadata_key,
                content,
                content_type,
                etag,
                last_modified,
                ttl_secs,
                repository_id,
                artifact_path,
                quarantine_until,
            )
            .await
    }

    /// Resolve the Package Age Policy hold window for a newly cached proxy
    /// entry (#1770). Returns `None` when the repository's quarantine policy
    /// is disabled. The window is measured from the upstream release date
    /// (`Last-Modified`) when present and parseable, falling back to the
    /// ingestion time (#1771): an upstream release older than the configured
    /// window yields an already-elapsed hold, so old packages are not re-held
    /// from their first proxy fetch.
    async fn quarantine_until_for_new_entry(
        &self,
        repository_id: Uuid,
        last_modified: Option<&str>,
    ) -> Option<DateTime<Utc>> {
        let config = quarantine_service::resolve_config(&self.db, repository_id).await;
        if !quarantine_service::should_quarantine(&config) {
            return None;
        }
        let release = last_modified.and_then(parse_http_date);
        Some(quarantine_service::quarantine_until_from_release(
            &config,
            release,
            Utc::now(),
        ))
    }

    /// Emit a structured warning when a brand-new artifact is cached from
    /// upstream through a repository that has `scan_on_proxy` enabled.
    ///
    /// See [`should_warn_proxy_scan_skipped`] for the rationale (#1274):
    /// scan-on-proxy is not yet wired to the scanner pipeline because
    /// proxy-cached items are deliberately absent from the `artifacts`
    /// table (#1278). This makes the no-op observable instead of silent.
    ///
    /// Best-effort: a failure to read the scan config never affects the
    /// proxy fetch. Called only on the new-cache path, never on cache hits.
    ///
    /// Reads the `scan_on_proxy` flag directly from `scan_configs` (mirrors
    /// `ScanConfigService::is_proxy_scan_enabled`) so `ProxyService` does not
    /// need a service handle on the hot cache-write path. A read failure or
    /// missing config row degrades to `false` (no warning); the decision and
    /// message are produced by the unit-tested pure
    /// [`proxy_scan_skipped_warning`]. `newly_cached = true` because this is
    /// only invoked on the new-cache path.
    async fn warn_if_proxy_scan_unsupported(&self, repository_id: Uuid, artifact_path: &str) {
        let proxy_scan_enabled = sqlx::query_scalar!(
            r#"SELECT scan_on_proxy FROM scan_configs WHERE repository_id = $1"#,
            repository_id
        )
        .fetch_optional(&self.db)
        .await
        .ok()
        .flatten()
        .unwrap_or(false);

        if let Some(message) = proxy_scan_skipped_warning(proxy_scan_enabled, true, artifact_path) {
            tracing::warn!(repository_id = %repository_id, "{}", message);
        }
    }

    /// Index a newly proxy-cached artifact into the `packages` /
    /// `package_versions` catalog (#1999).
    ///
    /// Proxy-cached artifacts are deliberately NOT written to the `artifacts`
    /// table (#1278 / #1280): doing so reintroduced a doubled-prefix storage
    /// bug on filesystem backends, and the contract is pinned by the meta-test
    /// `test_cache_artifact_does_not_insert_into_artifacts_table`. As a result
    /// the package catalog — populated only by the local-upload handlers via
    /// [`PackageService::try_create_or_update_from_artifact`] — stayed empty for
    /// remote/proxy repositories, so `GET /api/v1/packages` and Maven component
    /// grouping returned nothing for cached artifacts (#1999, regression in
    /// 1.2.1).
    ///
    /// This best-effort helper closes that gap WITHOUT touching the `artifacts`
    /// table: it writes ONLY `packages` / `package_versions` rows (idempotent
    /// `ON CONFLICT` upsert), so a second pull of the same GAV (cache hit) does
    /// not double the catalog and the #1278 meta-test stays green.
    ///
    /// Invariants:
    /// * Called ONLY on the new-cache branch (the same gated spot as
    ///   [`Self::warn_if_proxy_scan_unsupported`]), so it fires once per new
    ///   write and never on cache hits.
    /// * Maven checksum sidecars (`.sha1` / `.md5`) and `maven-metadata.xml`
    ///   are skipped — they are not packages.
    /// * A path with no extractable version yields no row.
    /// * Indexing failure must NOT fail the client's proxy fetch:
    ///   [`PackageService::try_create_or_update_from_artifact`] swallows + logs.
    ///
    /// The repository format is resolved from the DB by `repository_id` rather
    /// than taken from the caller: the proxy fetch path operates on a synthetic
    /// `Repository` whose `format` is always `Generic`
    /// (`proxy_helpers::build_remote_repo`), so trusting it would skip every
    /// real Maven repo.
    async fn index_cached_package(
        &self,
        repository_id: Uuid,
        artifact_path: &str,
        size_bytes: i64,
        checksum_sha256: Option<&str>,
    ) {
        // Resolve the real repository format (the synthetic proxy `Repository`
        // carries `Generic`, not the configured format). A read failure or
        // unparseable format degrades to "not indexed" (best-effort).
        let format_text: Option<String> =
            sqlx::query_scalar(r#"SELECT format::text FROM repositories WHERE id = $1"#)
                .bind(repository_id)
                .fetch_optional(&self.db)
                .await
                .ok()
                .flatten();
        let Some(repo_format) = catalog_indexable_format(format_text.as_deref()) else {
            // Only Maven-family proxy repos populate the catalog for now
            // (#1999). Other formats keep the pre-fix behavior until their
            // grouping/listing paths are taught to read from the catalog too.
            return;
        };

        let Some(name) = maven_proxy_package_name(artifact_path) else {
            return;
        };
        let Some(version) = extract_version_from_path(&repo_format, artifact_path) else {
            return;
        };

        // The streaming tee computes the checksum only after the body is fully
        // written, so it is unknown at this gated spot; fall back to an empty
        // string. The buffered path passes the real digest. Either way the
        // catalog row exists; a later buffered pull refreshes the digest.
        let checksum = checksum_sha256.unwrap_or("");

        let pkg_svc = crate::services::package_service::PackageService::new(self.db.clone());
        pkg_svc
            .try_create_or_update_from_artifact(
                repository_id,
                &name,
                &version,
                size_bytes,
                checksum,
                None,
                None,
            )
            .await;
    }

    /// Attempt to retrieve a cached artifact even if it has expired.
    /// Used as a fallback when upstream is unavailable.
    ///
    /// Thin shim over [`Self::get_cached`] with `allow_stale = true`: the
    /// expiry gate is skipped and metadata/body read errors propagate (the
    /// caller is already in an upstream-unavailable fallback), while the
    /// checksum is still verified.
    async fn get_stale_cached_artifact(
        &self,
        cache_key: &str,
        metadata_key: &str,
    ) -> Result<Option<(Bytes, Option<String>)>> {
        self.get_cached(cache_key, metadata_key, true).await
    }

    /// Check if upstream ETag has changed (returns true if changed/newer).
    ///
    /// Thin delegation to [`UpstreamClient::check_etag_changed`] (#1618 S8).
    async fn check_etag_changed(
        &self,
        url: &str,
        cached_etag: &str,
        repo_id: Uuid,
    ) -> Result<bool> {
        self.upstream_client
            .check_etag_changed(url, cached_etag, repo_id)
            .await
    }
}

/// Derive the package-catalog name (`groupId:artifactId`) for a Maven-family
/// proxy-cached artifact path (#1999), or `None` if the path is not a Maven
/// package asset that should be indexed.
///
/// Skip rules (these are not packages):
/// * Maven checksum sidecars — `*.sha1`, `*.md5`, `*.sha256`, `*.sha512`, `*.asc`.
/// * `maven-metadata.xml` (and its own checksum sidecars).
/// * Any path that does not parse as Maven coordinates
///   (`groupId/artifactId/version/filename`).
///
/// Using `groupId:artifactId` (rather than the bare `artifactId` that the
/// local-upload path stores) keeps proxy package names globally unambiguous and
/// lets the remote component-grouping branch reconstruct the `groupId` /
/// `artifactId` split without consulting the storage path.
pub(crate) fn maven_proxy_package_name(path: &str) -> Option<String> {
    let path = path.trim_start_matches('/');
    let filename = path.rsplit('/').next().unwrap_or(path);
    let lower = filename.to_ascii_lowercase();

    // Checksum / signature sidecars are not packages.
    const SKIP_SUFFIXES: [&str; 5] = [".sha1", ".md5", ".sha256", ".sha512", ".asc"];
    if SKIP_SUFFIXES.iter().any(|s| lower.ends_with(s)) {
        return None;
    }

    // Maven metadata index files are not packages.
    if lower == "maven-metadata.xml" || lower.starts_with("maven-metadata.xml.") {
        return None;
    }

    let coords = crate::formats::maven::MavenHandler::parse_coordinates(path).ok()?;
    Some(format!("{}:{}", coords.group_id, coords.artifact_id))
}

/// Map a repository `format::text` value to the [`RepositoryFormat`] whose
/// proxy-cached artifacts are indexed into the package catalog (#1999).
///
/// Only the Maven family is indexed for now; every other format (including a
/// missing/unknown value) returns `None`, leaving the pre-fix behavior intact.
/// Factored out of [`ProxyService::index_cached_package`] so the eligibility
/// decision is unit-testable without a database round-trip.
pub(crate) fn catalog_indexable_format(format_text: Option<&str>) -> Option<RepositoryFormat> {
    match format_text {
        Some("maven") => Some(RepositoryFormat::Maven),
        Some("gradle") => Some(RepositoryFormat::Gradle),
        Some("sbt") => Some(RepositoryFormat::Sbt),
        _ => None,
    }
}

/// Extract version from an artifact path based on the repository format.
///
/// Each package format encodes the version differently in the path. This
/// function delegates to format-specific parsing logic and returns `None`
/// for metadata files, index pages, or paths where the version cannot be
/// determined.
///
/// Called by [`ProxyService::index_cached_package`] (#1999) to populate the
/// package catalog for proxy-cached Maven artifacts, and exercised directly by
/// the unit tests below.
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
    // Package Age Policy on the proxy sidecar (#1770 / #1771)
    // -----------------------------------------------------------------------

    #[test]
    fn test_check_quarantine_until_none_allows() {
        assert!(check_quarantine_until(None).is_ok());
    }

    #[test]
    fn test_check_quarantine_until_future_blocks_with_conflict() {
        let until = Utc::now() + chrono::Duration::minutes(30);
        let err = check_quarantine_until(Some(until)).unwrap_err();
        match err {
            AppError::Conflict(_) => {}
            other => panic!("expected 409 Conflict, got {other:?}"),
        }
    }

    #[test]
    fn test_check_quarantine_until_past_allows() {
        let until = Utc::now() - chrono::Duration::minutes(1);
        assert!(check_quarantine_until(Some(until)).is_ok());
    }

    #[test]
    fn test_parse_http_date_rfc7231_imf_fixdate() {
        let parsed = parse_http_date("Tue, 05 May 2026 01:10:54 GMT").expect("parseable");
        assert_eq!(parsed.to_rfc3339(), "2026-05-05T01:10:54+00:00");
    }

    #[test]
    fn test_parse_http_date_rejects_garbage() {
        assert!(parse_http_date("not-a-date").is_none());
        assert!(parse_http_date("").is_none());
    }

    // -----------------------------------------------------------------------
    // #1555 proxy-cache key discrimination
    //
    // `is_proxy_cache_key` decides whether a storage key must be presigned
    // through the no-prefix proxy backend (`cache_storage_backend`) instead of
    // the prefixed repo handle. Hosted/content-addressed artifacts MUST keep
    // the prefixed handle, so the predicate must match ONLY the
    // `proxy-cache/` layout — getting this wrong reintroduces the prefix bug
    // (signing a key the object store has no object for) or, worse, routes
    // hosted artifacts through the wrong handle.
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_proxy_cache_key_matches_proxy_cache_layout() {
        assert!(ProxyService::is_proxy_cache_key(
            "proxy-cache/pypi-remote/pkg/pkg-1.0.0-py3-none-any.whl/__content__"
        ));
        assert!(ProxyService::is_proxy_cache_key(
            "proxy-cache/repo/p/__content__"
        ));
        // Bare prefix (defensive): still classified as proxy-cache.
        assert!(ProxyService::is_proxy_cache_key("proxy-cache/"));
    }

    #[test]
    fn test_is_proxy_cache_key_rejects_hosted_and_prefixed_keys() {
        // Content-addressed hosted artifact under the global prefix — must NOT
        // be treated as proxy-cache (keeps the prefixed repo handle).
        assert!(!ProxyService::is_proxy_cache_key(
            "artifact-keeper/cas/ab/cdef0123456789"
        ));
        // A prefixed key that merely *contains* `proxy-cache/` later in the
        // path must not match: the cache layout is always at the root.
        assert!(!ProxyService::is_proxy_cache_key(
            "artifact-keeper/proxy-cache/repo/pkg/__content__"
        ));
        assert!(!ProxyService::is_proxy_cache_key("cas/deadbeef"));
        assert!(!ProxyService::is_proxy_cache_key(""));
        // Substring, not a path segment prefix — must not match.
        assert!(!ProxyService::is_proxy_cache_key("not-proxy-cache/x"));
    }

    #[test]
    fn test_legacy_sidecar_without_quarantine_deserializes_to_none() {
        // A sidecar written before the quarantine field existed (and before
        // last_modified / negative_cached_until / storage_etag) must still
        // deserialize, with quarantine_until defaulting to None.
        let legacy = r#"{
            "cached_at": "2026-01-01T00:00:00Z",
            "upstream_etag": null,
            "expires_at": "2030-01-01T00:00:00Z",
            "content_type": "application/octet-stream",
            "size_bytes": 10,
            "checksum_sha256": "abc"
        }"#;
        let meta: CacheMetadata = serde_json::from_str(legacy).expect("legacy sidecar parses");
        assert!(meta.quarantine_until.is_none());
        assert!(check_quarantine_until(meta.quarantine_until).is_ok());
    }

    #[test]
    fn test_sidecar_round_trips_quarantine_until() {
        let until = Utc::now() + chrono::Duration::minutes(120);
        let meta = CacheMetadata {
            cached_at: Utc::now(),
            upstream_etag: None,
            storage_etag: None,
            last_modified: None,
            quarantine_until: Some(until),
            negative_cached_until: None,
            expires_at: Utc::now() + chrono::Duration::hours(24),
            content_type: Some("application/octet-stream".to_string()),
            size_bytes: 10,
            checksum_sha256: "abc".to_string(),
        };
        let json = serde_json::to_vec(&meta).unwrap();
        let back: CacheMetadata = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.quarantine_until, Some(until));
        assert!(check_quarantine_until(back.quarantine_until).is_err());
    }

    // -----------------------------------------------------------------------
    // should_warn_proxy_scan_skipped — scan-on-proxy gap warning gate (#1274)
    // -----------------------------------------------------------------------

    #[test]
    fn test_proxy_scan_warns_only_when_enabled_and_newly_cached() {
        // The exact condition the warning fires on: setting enabled AND a
        // brand-new cache entry was created from upstream.
        assert!(should_warn_proxy_scan_skipped(true, true));
    }

    #[test]
    fn test_proxy_scan_no_warn_when_disabled() {
        // scan_on_proxy off => never warn, even on a fresh cache write.
        assert!(!should_warn_proxy_scan_skipped(false, true));
    }

    #[test]
    fn test_proxy_scan_no_warn_on_cache_hit() {
        // A plain cache hit (nothing newly cached) must not warn on every
        // request, even with the setting enabled.
        assert!(!should_warn_proxy_scan_skipped(true, false));
    }

    #[test]
    fn test_proxy_scan_no_warn_when_disabled_and_cache_hit() {
        assert!(!should_warn_proxy_scan_skipped(false, false));
    }

    #[test]
    fn test_proxy_scan_warning_message_includes_path_and_issue_refs() {
        let msg = proxy_scan_skipped_warning(true, true, "react/-/react-18.2.0.tgz")
            .expect("warning must be produced when enabled + newly cached");
        // Operators grep/alert on these tokens; pin them.
        assert!(msg.contains("scan_on_proxy is enabled"));
        assert!(msg.contains("#1274"));
        assert!(msg.contains("#1278"));
        assert!(msg.contains("UNSCANNED"));
        assert!(msg.contains("react/-/react-18.2.0.tgz"));
    }

    #[test]
    fn test_proxy_scan_warning_message_none_when_disabled() {
        assert!(proxy_scan_skipped_warning(false, true, "any/path").is_none());
    }

    #[test]
    fn test_proxy_scan_warning_message_none_on_cache_hit() {
        assert!(proxy_scan_skipped_warning(true, false, "any/path").is_none());
    }

    // -----------------------------------------------------------------------
    // Pure helper functions (moved from module scope — test-only)
    // -----------------------------------------------------------------------

    fn is_cache_expired(expires_at: &DateTime<Utc>) -> bool {
        Utc::now() > *expires_at
    }

    /// Pure mirror of the expiry gate inside `ProxyService::get_cached`:
    /// `if !allow_stale && Utc::now() > metadata.expires_at { miss }`.
    ///
    /// Returns `true` when the gate blocks the entry (fresh read of an expired
    /// entry). The stale path (`allow_stale = true`) never blocks here, which
    /// is the sole staleness divergence on the happy path — the checksum
    /// verification that follows runs identically for both flags.
    fn cache_expiry_gate_blocks(allow_stale: bool, expires_at: &DateTime<Utc>) -> bool {
        !allow_stale && Utc::now() > *expires_at
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

    /// Equivalence oracle for the S1 refactor (#1628): `CacheKeys::derive` must
    /// produce byte-identical results to the legacy `cache_storage_key` /
    /// `cache_metadata_key` helpers, including identical error behavior. The
    /// helpers are already thin shims over `derive`, so this test pins the
    /// contract for any future change to either side.
    #[test]
    fn test_cache_keys_derive_equivalent_to_legacy_helpers() {
        // Compare Result<String> via to_string() so both the Ok key value and
        // the exact Err message are part of the equivalence check.
        fn as_msg(r: Result<String>) -> std::result::Result<String, String> {
            r.map_err(|e| e.to_string())
        }

        // A near-max-length path: the worst-case (metadata) key lands exactly
        // at MAX_STORAGE_KEY_BYTES, so both keys derive successfully.
        let repo = "r";
        let fixed = 12 + repo.len() + 1 + 1 + 19; // see just_under_limit test
        let near_max_path = "a".repeat(ProxyService::MAX_STORAGE_KEY_BYTES - fixed);

        // A path that overflows even the smaller content suffix: both must err.
        let over_limit_path =
            "b".repeat(ProxyService::MAX_STORAGE_KEY_BYTES - (12 + repo.len() + 1 + 1 + 11) + 1);

        let cases: &[(&str, &str)] = &[
            // Normal path.
            (
                "maven-central",
                "org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar",
            ),
            // Needs normalization (leading + trailing slash trimmed).
            ("pypi-remote", "/simple/numpy/"),
            // Path-traversal attempt: must still error identically.
            ("npm-proxy", "express/../lodash"),
            // NUL-byte smuggling: another error path.
            ("npm-proxy", "express\0evil"),
            // Empty path after trimming: error path.
            ("npm-proxy", "//"),
            // Near-max-length key (success at the boundary).
            (repo, near_max_path.as_str()),
            // Over-limit key (length validation error).
            (repo, over_limit_path.as_str()),
        ];

        for (repo_key, path) in cases {
            let derived = CacheKeys::derive(repo_key, path);
            let derived_content = derived.as_ref().map(|k| k.content.clone()).ok();
            let derived_metadata = derived.as_ref().map(|k| k.metadata.clone()).ok();

            // Content key equivalence (Ok value and Err message).
            assert_eq!(
                as_msg(CacheKeys::derive(repo_key, path).map(|k| k.content)),
                as_msg(ProxyService::cache_storage_key(repo_key, path)),
                "content key mismatch for ({repo_key:?}, {path:?})"
            );
            // Metadata key equivalence (Ok value and Err message).
            assert_eq!(
                as_msg(CacheKeys::derive(repo_key, path).map(|k| k.metadata)),
                as_msg(ProxyService::cache_metadata_key(repo_key, path)),
                "metadata key mismatch for ({repo_key:?}, {path:?})"
            );

            // The struct fields must agree with the legacy helpers directly.
            assert_eq!(
                derived_content,
                ProxyService::cache_storage_key(repo_key, path).ok(),
                "CacheKeys.content mismatch for ({repo_key:?}, {path:?})"
            );
            assert_eq!(
                derived_metadata,
                ProxyService::cache_metadata_key(repo_key, path).ok(),
                "CacheKeys.metadata mismatch for ({repo_key:?}, {path:?})"
            );
        }
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
            last_modified: None,
            negative_cached_until: None,
            quarantine_until: None,
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
            last_modified: None,
            negative_cached_until: None,
            quarantine_until: None,
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
            last_modified: None,
            negative_cached_until: None,
            quarantine_until: None,
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
            last_modified: None,
            negative_cached_until: None,
            quarantine_until: None,
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
            last_modified: None,
            negative_cached_until: None,
            quarantine_until: None,
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
            last_modified: None,
            negative_cached_until: None,
            quarantine_until: None,
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
    fn test_get_cached_expiry_gate_flag_behavior() {
        // Exercises the `allow_stale` flag of `ProxyService::get_cached` via
        // its pure mirror `cache_expiry_gate_blocks`. The flag's only happy-
        // path divergence is whether the expiry gate is enforced; the checksum
        // verification that runs afterward is identical for both flags, so a
        // hit returned by either flag is still checksum-verified.
        let now = Utc::now();
        let expired = now - chrono::Duration::hours(1);
        let valid = now + chrono::Duration::hours(23);

        // allow_stale = false (get_cached_artifact): expired entry is rejected.
        assert!(
            cache_expiry_gate_blocks(false, &expired),
            "fresh read must reject an expired entry"
        );
        // allow_stale = false: a still-valid entry passes the gate and proceeds
        // to checksum verification.
        assert!(
            !cache_expiry_gate_blocks(false, &valid),
            "fresh read must accept a still-valid entry"
        );

        // allow_stale = true (get_stale_cached_artifact): the gate is skipped
        // for expired entries...
        assert!(
            !cache_expiry_gate_blocks(true, &expired),
            "stale read must skip the expiry gate for an expired entry"
        );
        // ...and equally never blocks a valid entry.
        assert!(
            !cache_expiry_gate_blocks(true, &valid),
            "stale read must never block on expiry"
        );

        // Sanity: only the fresh+expired combination blocks; everything else
        // falls through to the shared (checksum-verified) hit path.
        assert!(is_cache_expired(&expired));
        assert!(!is_cache_expired(&valid));
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
            last_modified: None,
            negative_cached_until: None,
            quarantine_until: None,
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
            last_modified: None,
            negative_cached_until: None,
            quarantine_until: None,
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
            last_modified: None,
            negative_cached_until: None,
            quarantine_until: None,
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

    // =======================================================================
    // maven_proxy_package_name — package-catalog name derivation + skip logic
    // for proxy-cached Maven artifacts (#1999)
    // =======================================================================

    #[test]
    fn test_maven_proxy_package_name_jar() {
        assert_eq!(
            maven_proxy_package_name(
                "org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar"
            )
            .as_deref(),
            Some("org.apache.commons:commons-lang3")
        );
    }

    #[test]
    fn test_maven_proxy_package_name_pom() {
        assert_eq!(
            maven_proxy_package_name("org/junit/junit-bom/5.10.1/junit-bom-5.10.1.pom").as_deref(),
            Some("org.junit:junit-bom")
        );
    }

    #[test]
    fn test_maven_proxy_package_name_leading_slash() {
        // The cache_path may arrive with a leading slash; it must be trimmed.
        assert_eq!(
            maven_proxy_package_name("/org/junit/junit-bom/5.10.1/junit-bom-5.10.1.jar").as_deref(),
            Some("org.junit:junit-bom")
        );
    }

    #[test]
    fn test_maven_proxy_package_name_skips_sha1() {
        // Checksum sidecars are not packages and must NOT create a row.
        assert!(
            maven_proxy_package_name("org/junit/junit-bom/5.10.1/junit-bom-5.10.1.jar.sha1")
                .is_none()
        );
    }

    #[test]
    fn test_maven_proxy_package_name_skips_md5() {
        assert!(
            maven_proxy_package_name("org/junit/junit-bom/5.10.1/junit-bom-5.10.1.pom.md5")
                .is_none()
        );
    }

    #[test]
    fn test_maven_proxy_package_name_skips_signature_and_other_checksums() {
        for path in [
            "org/junit/junit-bom/5.10.1/junit-bom-5.10.1.jar.asc",
            "org/junit/junit-bom/5.10.1/junit-bom-5.10.1.jar.sha256",
            "org/junit/junit-bom/5.10.1/junit-bom-5.10.1.jar.sha512",
        ] {
            assert!(
                maven_proxy_package_name(path).is_none(),
                "expected {path} to be skipped"
            );
        }
    }

    #[test]
    fn test_maven_proxy_package_name_skips_maven_metadata() {
        // Version-level maven-metadata.xml (and its checksums) are index files.
        assert!(
            maven_proxy_package_name("org/junit/junit-bom/5.10.1/maven-metadata.xml").is_none()
        );
        assert!(
            maven_proxy_package_name("org/junit/junit-bom/5.10.1/maven-metadata.xml.sha1")
                .is_none()
        );
    }

    #[test]
    fn test_maven_proxy_package_name_skips_unparseable_path() {
        // Too few segments to be a GAV → no package.
        assert!(maven_proxy_package_name("org/junit/something.jar").is_none());
    }

    #[test]
    fn test_catalog_indexable_format_maven_family() {
        assert_eq!(
            catalog_indexable_format(Some("maven")),
            Some(RepositoryFormat::Maven)
        );
        assert_eq!(
            catalog_indexable_format(Some("gradle")),
            Some(RepositoryFormat::Gradle)
        );
        assert_eq!(
            catalog_indexable_format(Some("sbt")),
            Some(RepositoryFormat::Sbt)
        );
    }

    #[test]
    fn test_catalog_indexable_format_other_formats_not_indexed() {
        for f in ["npm", "pypi", "docker", "generic", "cargo", "nuget"] {
            assert!(
                catalog_indexable_format(Some(f)).is_none(),
                "{f} must not be catalog-indexed yet"
            );
        }
    }

    #[test]
    fn test_catalog_indexable_format_missing_value() {
        assert!(catalog_indexable_format(None).is_none());
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
            last_modified: None,
            negative_cached_until: None,
            quarantine_until: None,
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
            last_modified: None,
            negative_cached_until: None,
            quarantine_until: None,
            expires_at: Utc::now() - chrono::Duration::seconds(1),
            content_type: None,
            size_bytes: 0,
            checksum_sha256: String::new(),
        };
        Bytes::from(serde_json::to_vec(&metadata).unwrap())
    }

    /// Build a fresh sidecar carrying the supplied Package Age Policy hold
    /// (`quarantine_until`). Used to drive `cache_quarantine_gate` (#2075)
    /// through the held / elapsed / no-hold states.
    fn metadata_bytes_with_quarantine(quarantine_until: Option<DateTime<Utc>>) -> Bytes {
        let metadata = CacheMetadata {
            cached_at: Utc::now(),
            upstream_etag: None,
            storage_etag: None,
            last_modified: None,
            negative_cached_until: None,
            quarantine_until,
            expires_at: Utc::now() + chrono::Duration::hours(1),
            content_type: Some("application/octet-stream".to_string()),
            size_bytes: 42,
            checksum_sha256: "a".repeat(64),
        };
        Bytes::from(serde_json::to_vec(&metadata).unwrap())
    }

    #[tokio::test]
    async fn test_cache_quarantine_gate_blocks_when_hold_active() {
        let until = Utc::now() + chrono::Duration::minutes(30);
        let mock = Arc::new(CacheFreshMock::new(
            Some(metadata_bytes_with_quarantine(Some(until))),
            true,
        ));
        let service = build_proxy_service_with_storage(mock.clone());

        let err = service
            .cache_quarantine_gate("npm-proxy", "lodash")
            .await
            .expect_err("an active hold must block the redirect fast path");
        match err {
            AppError::Conflict(_) => {}
            other => panic!("expected Conflict for an active hold, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_cache_quarantine_gate_allows_when_hold_elapsed() {
        let until = Utc::now() - chrono::Duration::minutes(30);
        let mock = Arc::new(CacheFreshMock::new(
            Some(metadata_bytes_with_quarantine(Some(until))),
            true,
        ));
        let service = build_proxy_service_with_storage(mock.clone());

        assert!(
            service
                .cache_quarantine_gate("npm-proxy", "lodash")
                .await
                .is_ok(),
            "an elapsed hold must not block the redirect"
        );
    }

    #[tokio::test]
    async fn test_cache_quarantine_gate_allows_when_no_hold() {
        let mock = Arc::new(CacheFreshMock::new(
            Some(metadata_bytes_with_quarantine(None)),
            true,
        ));
        let service = build_proxy_service_with_storage(mock.clone());

        assert!(
            service
                .cache_quarantine_gate("npm-proxy", "lodash")
                .await
                .is_ok(),
            "a sidecar with no hold must not block the redirect"
        );
    }

    #[tokio::test]
    async fn test_cache_quarantine_gate_allows_when_sidecar_missing() {
        let mock = Arc::new(CacheFreshMock::new(/* metadata = */ None, true));
        let service = build_proxy_service_with_storage(mock.clone());

        assert!(
            service
                .cache_quarantine_gate("npm-proxy", "lodash")
                .await
                .is_ok(),
            "a missing sidecar means no hold known -> allow"
        );
    }

    #[tokio::test]
    async fn test_cache_quarantine_gate_allows_on_sidecar_read_error() {
        // Malformed JSON makes load_metadata return Err (not NotFound); the
        // B6-safe stance degrades that to "no hold known" -> Ok, so a transient
        // sidecar read/parse failure never blocks a legitimate redirect.
        let mock = Arc::new(CacheFreshMock::new(
            Some(Bytes::from_static(b"{ not valid json")),
            true,
        ));
        let service = build_proxy_service_with_storage(mock.clone());

        assert!(
            service
                .cache_quarantine_gate("npm-proxy", "lodash")
                .await
                .is_ok(),
            "a sidecar read/parse error must be treated as no hold known"
        );
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

    // =======================================================================
    // Multipart-ETag tolerance on fast-path revalidation (#2120)
    //
    // S3 multipart ETags are opaque per-upload values (<md5hex>-<partcount>),
    // NOT content hashes. Two replicas re-uploading byte-identical pull-through
    // content mint DIFFERENT multipart ETags, which under the strict #1051
    // rule made every fast-path hit re-fetch + re-upload forever. When either
    // the pinned or the current ETag is multipart-shaped, a value mismatch is
    // now treated as inconclusive and falls back to an existence check.
    // Single-part (real-MD5) ETags keep FULL mismatch = not-fresh semantics.
    // =======================================================================

    #[test]
    fn test_is_multipart_etag_recognizes_multipart_shape() {
        // 32 hex digits + "-" + part count, with and without the surrounding
        // quotes S3 / object_store carry on the raw header value.
        assert!(is_multipart_etag("d41d8cd98f00b204e9800998ecf8427e-3"));
        assert!(is_multipart_etag("\"d41d8cd98f00b204e9800998ecf8427e-3\""));
        assert!(is_multipart_etag("D41D8CD98F00B204E9800998ECF8427E-12"));
        assert!(is_multipart_etag("00000000000000000000000000000000-1"));
    }

    #[test]
    fn test_is_multipart_etag_rejects_singlepart_and_junk() {
        // A bare MD5 (single-part ETag) is NOT multipart.
        assert!(!is_multipart_etag("d41d8cd98f00b204e9800998ecf8427e"));
        assert!(!is_multipart_etag("\"d41d8cd98f00b204e9800998ecf8427e\""));
        // Wrong hex length, missing/garbled part count, or non-hex.
        assert!(!is_multipart_etag("deadbeef-2"));
        assert!(!is_multipart_etag("d41d8cd98f00b204e9800998ecf8427e-"));
        assert!(!is_multipart_etag("d41d8cd98f00b204e9800998ecf8427e-x"));
        assert!(!is_multipart_etag("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-2"));
        assert!(!is_multipart_etag(""));
    }

    #[tokio::test]
    async fn test_is_cache_fresh_true_when_multipart_pin_vs_singlepart_current_and_present() {
        // Pinned ETag is multipart-shaped; current HEAD returns a different,
        // single-part value. Because the pin is multipart the mismatch is
        // inconclusive and we fall back to an existence check — object present
        // → fresh (no thrash). #2120.
        let mock = Arc::new(CacheFreshMock::with_head_etag(
            Some(fresh_metadata_bytes_with_storage_etag(Some(
                "\"d41d8cd98f00b204e9800998ecf8427e-4\"".to_string(),
            ))),
            /* content_exists = */ true,
            HeadEtagBehavior::Present("\"d41d8cd98f00b204e9800998ecf8427e\"".to_string()),
        ));
        let service = build_proxy_service_with_storage(mock.clone());

        let fresh = service.is_cache_fresh("npm-proxy", "lodash").await;

        assert!(
            fresh,
            "multipart-shaped pin mismatch with object present must fall back to existence → fresh"
        );
        assert_eq!(
            mock.head_etag_calls.load(AtomicOrdering::SeqCst),
            1,
            "still HEADs exactly once"
        );
        assert_eq!(
            mock.exists_calls.load(AtomicOrdering::SeqCst),
            1,
            "multipart mismatch path falls back to a single exists() probe"
        );
    }

    #[tokio::test]
    async fn test_is_cache_fresh_true_when_multipart_vs_multipart_differ_and_present() {
        // Both pinned and current are multipart ETags for the same content but
        // with different part counts (classic cross-replica re-upload). Object
        // present → fresh. #2120.
        let mock = Arc::new(CacheFreshMock::with_head_etag(
            Some(fresh_metadata_bytes_with_storage_etag(Some(
                "\"d41d8cd98f00b204e9800998ecf8427e-4\"".to_string(),
            ))),
            /* content_exists = */ true,
            HeadEtagBehavior::Present("\"d41d8cd98f00b204e9800998ecf8427e-7\"".to_string()),
        ));
        let service = build_proxy_service_with_storage(mock.clone());

        let fresh = service.is_cache_fresh("npm-proxy", "lodash").await;

        assert!(
            fresh,
            "multipart-vs-multipart mismatch with object present must yield fresh"
        );
    }

    #[tokio::test]
    async fn test_is_cache_fresh_false_when_multipart_mismatch_but_content_gone() {
        // Multipart mismatch but the existence fallback finds no object:
        // still not fresh. Guards against serving a presigned URL to a 404.
        let mock = Arc::new(CacheFreshMock::with_head_etag(
            Some(fresh_metadata_bytes_with_storage_etag(Some(
                "\"d41d8cd98f00b204e9800998ecf8427e-4\"".to_string(),
            ))),
            /* content_exists = */ false,
            HeadEtagBehavior::Present("\"d41d8cd98f00b204e9800998ecf8427e-7\"".to_string()),
        ));
        let service = build_proxy_service_with_storage(mock.clone());

        let fresh = service.is_cache_fresh("npm-proxy", "lodash").await;

        assert!(
            !fresh,
            "multipart mismatch with missing content must still yield not-fresh"
        );
    }

    #[tokio::test]
    async fn test_is_cache_fresh_singlepart_mismatch_still_not_fresh() {
        // Both ETags are single-part (real MD5) and differ: this is a genuine
        // replacement signal and MUST keep the strict #1051 not-fresh behavior
        // — the #2120 tolerance is scoped to multipart-shaped ETags only.
        let mock = Arc::new(CacheFreshMock::with_head_etag(
            Some(fresh_metadata_bytes_with_storage_etag(Some(
                "\"d41d8cd98f00b204e9800998ecf8427e\"".to_string(),
            ))),
            /* content_exists = */ true,
            HeadEtagBehavior::Present("\"ffffffffffffffffffffffffffffffff\"".to_string()),
        ));
        let service = build_proxy_service_with_storage(mock.clone());

        let fresh = service.is_cache_fresh("npm-proxy", "lodash").await;

        assert!(
            !fresh,
            "single-part ETag mismatch must remain not-fresh (no multipart tolerance)"
        );
        assert_eq!(
            mock.exists_calls.load(AtomicOrdering::SeqCst),
            0,
            "single-part mismatch must NOT fall back to an existence probe"
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

    // -----------------------------------------------------------------------
    // purge_repo_cache (#2047)
    //
    // Repository delete must purge the whole `proxy-cache/<repo_key>/` subtree
    // from the global default backend so a later repo created with the same key
    // cannot serve the deleted repo's stale upstream content. The helper is
    // storage-only (list + delete), so a recording mock that serves a fixed key
    // set from `list` and captures every `delete` pins the contract.
    // -----------------------------------------------------------------------

    /// Recording mock that serves a fixed key set from `list(prefix)` (filtered
    /// by prefix) and captures every `delete()` call, with a configurable
    /// listing failure to exercise the best-effort error path.
    struct PrefixListDeleteStorage {
        keys: Vec<String>,
        deletes: tokio::sync::Mutex<Vec<String>>,
        list_fails: bool,
    }

    impl PrefixListDeleteStorage {
        fn new(keys: Vec<&str>) -> Arc<Self> {
            Arc::new(Self {
                keys: keys.into_iter().map(String::from).collect(),
                deletes: tokio::sync::Mutex::new(Vec::new()),
                list_fails: false,
            })
        }
        fn failing_list() -> Arc<Self> {
            Arc::new(Self {
                keys: Vec::new(),
                deletes: tokio::sync::Mutex::new(Vec::new()),
                list_fails: true,
            })
        }
        async fn deletes_snapshot(&self) -> Vec<String> {
            self.deletes.lock().await.clone()
        }
    }

    #[async_trait::async_trait]
    impl crate::services::storage_service::StorageBackend for PrefixListDeleteStorage {
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
        async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>> {
            if self.list_fails {
                return Err(AppError::Storage("mock list failure".to_string()));
            }
            let p = prefix.unwrap_or("");
            Ok(self
                .keys
                .iter()
                .filter(|k| k.starts_with(p))
                .cloned()
                .collect())
        }
        async fn copy(&self, _source: &str, _dest: &str) -> Result<()> {
            Ok(())
        }
        async fn size(&self, _key: &str) -> Result<u64> {
            Ok(0)
        }
    }

    #[tokio::test]
    async fn test_purge_repo_cache_deletes_entire_repo_key_subtree() {
        // Two cached entries (body + sidecar each) plus a negative-cache
        // sidecar with no `__content__` companion, all under the target repo
        // key, and an unrelated repo's entry that must be left untouched.
        let storage = PrefixListDeleteStorage::new(vec![
            "proxy-cache/rpm-remote/repodata/repomd.xml/__content__",
            "proxy-cache/rpm-remote/repodata/repomd.xml/__cache_meta__.json",
            "proxy-cache/rpm-remote/Packages/foo.rpm/__content__",
            "proxy-cache/rpm-remote/Packages/foo.rpm/__cache_meta__.json",
            // Negative-cache sidecar: a previously-404'd path, sidecar only.
            "proxy-cache/rpm-remote/missing/pkg.rpm/__cache_meta__.json",
            // Different repo that happens to share a key prefix substring:
            // must NOT be purged (prefix is slash-terminated).
            "proxy-cache/rpm-remote-other/repodata/repomd.xml/__content__",
        ]);
        let service = build_proxy_service_with_storage(storage.clone());

        let deleted = service
            .purge_repo_cache("rpm-remote")
            .await
            .expect("purge should succeed");

        let deletes = storage.deletes_snapshot().await;
        assert_eq!(deleted, 5, "should report 5 purged keys, got {:?}", deletes);
        // Every object under the target repo key — content, sidecar, AND the
        // negative-cache-only sidecar — must be gone.
        for k in [
            "proxy-cache/rpm-remote/repodata/repomd.xml/__content__",
            "proxy-cache/rpm-remote/repodata/repomd.xml/__cache_meta__.json",
            "proxy-cache/rpm-remote/Packages/foo.rpm/__content__",
            "proxy-cache/rpm-remote/Packages/foo.rpm/__cache_meta__.json",
            "proxy-cache/rpm-remote/missing/pkg.rpm/__cache_meta__.json",
        ] {
            assert!(deletes.iter().any(|d| d == k), "expected delete of {k}");
        }
        // A different repo's cache must survive.
        assert!(
            !deletes
                .iter()
                .any(|d| d.starts_with("proxy-cache/rpm-remote-other/")),
            "must not purge a sibling repo's cache: {:?}",
            deletes
        );
    }

    #[tokio::test]
    async fn test_purge_repo_cache_empty_for_repo_with_no_cache() {
        // A hosted repo (or a remote that was never fetched) has no
        // proxy-cache objects: the helper must be a clean no-op, not an error.
        let storage = PrefixListDeleteStorage::new(vec![
            "proxy-cache/some-other-repo/repodata/repomd.xml/__content__",
        ]);
        let service = build_proxy_service_with_storage(storage.clone());

        let deleted = service
            .purge_repo_cache("hosted-repo")
            .await
            .expect("purge should succeed");

        assert_eq!(
            deleted, 0,
            "no keys should be purged for a repo with no cache"
        );
        assert!(
            storage.deletes_snapshot().await.is_empty(),
            "no delete should fire when nothing matches the prefix"
        );
    }

    #[tokio::test]
    async fn test_purge_repo_cache_propagates_list_failure() {
        // A listing failure surfaces as Err so the caller can log it; the
        // caller (delete_repository) swallows it so the delete still proceeds.
        let storage = PrefixListDeleteStorage::failing_list();
        let service = build_proxy_service_with_storage(storage.clone());

        let result = service.purge_repo_cache("rpm-remote").await;

        assert!(result.is_err(), "list failure should surface as Err");
        assert!(
            storage.deletes_snapshot().await.is_empty(),
            "no delete should fire when listing failed"
        );
    }

    // -----------------------------------------------------------------
    // get_cache_metadata (#1541)
    //
    // The handler-side structural test (in repositories.rs) only pins the
    // source-shape; these tests exercise the actual runtime path through
    // the new pub method to make sure (a) the metadata key derivation
    // hands the right key to the storage, (b) the deserialise path
    // returns the populated struct, (c) a missing blob collapses cleanly
    // to `Ok(None)`, and (d) a path the metadata-key validator rejects
    // (e.g. `..` traversal) returns `Ok(None)` rather than bubbling --
    // matching the handler's "cache fields just stay None on a bad
    // input" tolerance.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn test_get_cache_metadata_returns_metadata_for_existing_path() {
        let mock = Arc::new(CacheFreshMock::new(Some(fresh_metadata_bytes()), true));
        let service = build_proxy_service_with_storage(mock.clone());

        let meta = service
            .get_cache_metadata("npm-proxy", "lodash")
            .await
            .expect("get_cache_metadata should not error on a present blob");

        let meta = meta.expect("metadata should be Some when the blob exists");
        // The fresh_metadata_bytes() helper pins these two fields; the
        // others are exercised by the existing is_cache_fresh tests.
        assert_eq!(meta.size_bytes, 42);
        assert!(
            meta.expires_at > Utc::now(),
            "fresh metadata should not be already-expired"
        );
    }

    #[tokio::test]
    async fn test_get_cache_metadata_returns_none_when_blob_missing() {
        let mock = Arc::new(CacheFreshMock::new(/* metadata = */ None, true));
        let service = build_proxy_service_with_storage(mock.clone());

        let result = service
            .get_cache_metadata("npm-proxy", "never-fetched")
            .await
            .expect("missing blob must NOT bubble as Err");

        assert!(
            result.is_none(),
            "missing metadata blob must collapse to Ok(None) so the \
             handler can leave cache_expires_at / cache_cached_at unset \
             rather than failing the whole metadata response"
        );
    }

    #[tokio::test]
    async fn test_get_cache_metadata_returns_none_for_path_traversal() {
        // The metadata-key derivation rejects `..` segments before the
        // storage is ever touched. The new pub wrapper translates that
        // rejection into Ok(None) (rather than bubbling the Err) so the
        // handler does not have to special-case it; the cache rows
        // simply don't render for the request.
        let storage = DeleteRecordingStorage::new();
        let service = build_proxy_service_with_storage(storage.clone());

        let result = service
            .get_cache_metadata("npm-proxy", "../etc/passwd")
            .await
            .expect("path-traversal must NOT surface as Err on this path");

        assert!(result.is_none(), "expected Ok(None) for invalid path");
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
        deletes: tokio::sync::Mutex<Vec<String>>,
        put_stream_fails: bool,
    }

    impl TeeRecordingBackend {
        fn ok() -> Arc<Self> {
            Arc::new(Self {
                put_stream_chunks: tokio::sync::Mutex::new(Vec::new()),
                metadata_writes: tokio::sync::Mutex::new(Vec::new()),
                deletes: tokio::sync::Mutex::new(Vec::new()),
                put_stream_fails: false,
            })
        }
        fn failing() -> Arc<Self> {
            Arc::new(Self {
                put_stream_chunks: tokio::sync::Mutex::new(Vec::new()),
                metadata_writes: tokio::sync::Mutex::new(Vec::new()),
                deletes: tokio::sync::Mutex::new(Vec::new()),
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
        async fn delete(&self, key: &str) -> Result<()> {
            self.deletes.lock().await.push(key.to_string());
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

    /// Test shim that preserves the original `tee_upstream_to_cache` free-fn
    /// call shape (#1618 S9 moved the body into [`CachePersister::tee_stream`]).
    /// Constructs a `CachePersister` over the given storage and delegates, so
    /// the established streaming-tee tests keep their `(upstream, storage, …)`
    /// signature unchanged.
    fn tee_upstream_to_cache(
        upstream: BoxStream<'static, Result<Bytes>>,
        storage: Arc<StorageService>,
        cache_key: String,
        metadata_key: String,
        template: CacheMetadataTemplate,
    ) -> BoxStream<'static, Result<Bytes>> {
        CachePersister::new(storage).tee_stream(upstream, cache_key, metadata_key, template, None)
    }

    fn template() -> CacheMetadataTemplate {
        CacheMetadataTemplate {
            content_type: Some("application/octet-stream".to_string()),
            etag: None,
            last_modified: None,
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

    /// #1365 regression: an empty upstream body (a 204, an empty 200, or a
    /// HEAD-style probe that reaches the streaming download path) must NOT
    /// be cached. The client still receives the empty body for this
    /// request, but the writer must (a) skip the metadata sidecar so a
    /// later GET is a cache miss, and (b) delete the zero-byte object it
    /// wrote so the next request refetches the real body from upstream.
    /// Before the fix the writer persisted a `size_bytes: 0` sidecar,
    /// which a subsequent GET served as `Content-Length: 0`, breaking
    /// Gradle POM parsing ("Content is not allowed in prolog.").
    #[tokio::test]
    async fn test_tee_empty_upstream_is_not_cached() {
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
        assert_eq!(total, 0, "client receives the empty body for this request");

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            backend.metadata_writes.lock().await.is_empty(),
            "zero-byte upstream body MUST NOT write a metadata sidecar; \
             otherwise the next GET serves a Content-Length: 0 cache hit (#1365)"
        );
        assert_eq!(
            backend.deletes.lock().await.as_slice(),
            ["cache-key".to_string()],
            "the empty cache object must be deleted so the next request refetches"
        );
    }

    #[test]
    fn test_classify_stream_write_rejects_empty() {
        assert_eq!(
            classify_stream_write(0, None),
            StreamWriteOutcome::RejectEmpty
        );
        assert_eq!(
            classify_stream_write(0, Some(10)),
            StreamWriteOutcome::RejectEmpty
        );
    }

    #[test]
    fn test_classify_stream_write_commits_when_length_unknown_or_matching() {
        assert_eq!(classify_stream_write(11, None), StreamWriteOutcome::Commit);
        assert_eq!(
            classify_stream_write(11, Some(11)),
            StreamWriteOutcome::Commit
        );
    }

    #[test]
    fn test_classify_stream_write_rejects_size_mismatch() {
        assert_eq!(
            classify_stream_write(11, Some(100)),
            StreamWriteOutcome::RejectTruncated {
                expected: 100,
                actual: 11,
            }
        );
        // A body longer than advertised is equally corrupt; reject it too.
        assert_eq!(
            classify_stream_write(120, Some(100)),
            StreamWriteOutcome::RejectTruncated {
                expected: 100,
                actual: 120,
            }
        );
    }

    /// #1912 regression: a truncated upstream body (bytes written < the
    /// advertised `Content-Length`) must NOT be cached. Committing it would
    /// serve a short, SHA-mismatched archive on the next GET and clients hit
    /// "unexpected BufError" extracting it. The writer must skip the metadata
    /// sidecar and delete the partial object so the next request refetches.
    #[tokio::test]
    async fn test_tee_truncated_upstream_is_not_cached() {
        let backend = TeeRecordingBackend::ok();
        let storage = Arc::new(RealStorageService::new(backend.clone()));

        // Upstream advertises 100 bytes but only delivers 11.
        let upstream = upstream_chunks(vec![&b"first-chunk"[..]]);
        let mut client = CachePersister::new(storage).tee_stream(
            upstream,
            "cache-key".to_string(),
            "meta-key".to_string(),
            template(),
            Some(100),
        );

        let mut total: usize = 0;
        while let Some(chunk) = client.next().await {
            total += chunk.unwrap().len();
        }
        assert_eq!(
            total, 11,
            "client still receives the (truncated) body it got"
        );

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            backend.metadata_writes.lock().await.is_empty(),
            "truncated upstream body MUST NOT write a metadata sidecar (#1912)"
        );
        assert_eq!(
            backend.deletes.lock().await.as_slice(),
            ["cache-key".to_string()],
            "the truncated cache object must be deleted so the next request refetches"
        );
    }

    /// A complete streamed body whose byte count matches the advertised
    /// `Content-Length` is cached normally — the #1912 guard does not fire on
    /// well-formed responses.
    #[tokio::test]
    async fn test_tee_complete_upstream_with_matching_length_is_cached() {
        let backend = TeeRecordingBackend::ok();
        let storage = Arc::new(RealStorageService::new(backend.clone()));

        let upstream = upstream_chunks(vec![&b"first-chunk"[..]]);
        let mut client = CachePersister::new(storage).tee_stream(
            upstream,
            "cache-key".to_string(),
            "meta-key".to_string(),
            template(),
            Some(11),
        );
        while let Some(chunk) = client.next().await {
            let _ = chunk.unwrap();
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            backend.metadata_writes.lock().await.len(),
            1,
            "a complete body with a matching Content-Length writes its sidecar"
        );
        assert!(
            backend.deletes.lock().await.is_empty(),
            "a complete body must not be deleted"
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
            last_modified: None,
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
    // CachePersister::write_buffered (#1618 S9): the buffered write-to-cache
    // path. Recording backend captures every `put` in order so a test can
    // assert the body→sidecar write ordering, the #1051 ETag pin, and the
    // #1365 zero-byte guard without a real storage backend.
    // -----------------------------------------------------------------------

    /// Records every `put(key, body)` in call order and surfaces a
    /// configurable `head_etag`. Shared by the buffered-path tests below so
    /// they do not each re-implement a stub backend (jscpd).
    struct BufferedRecordingBackend {
        puts: tokio::sync::Mutex<Vec<(String, Bytes)>>,
        etag: Option<String>,
    }

    impl BufferedRecordingBackend {
        fn new(etag: Option<&str>) -> Arc<Self> {
            Arc::new(Self {
                puts: tokio::sync::Mutex::new(Vec::new()),
                etag: etag.map(|s| s.to_string()),
            })
        }
    }

    #[async_trait::async_trait]
    impl ServiceStorageBackend for BufferedRecordingBackend {
        async fn put(&self, key: &str, content: Bytes) -> Result<()> {
            self.puts.lock().await.push((key.to_string(), content));
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
            _stream: ServiceBoxStream<'static, Result<Bytes>>,
        ) -> Result<ServicePutStreamResult> {
            unreachable!("buffered path does not call put_stream")
        }
    }

    /// Run `write_buffered` against a recording backend and return the
    /// recorded `put` calls. Keeps the per-test setup in one place.
    async fn run_write_buffered(
        backend: Arc<BufferedRecordingBackend>,
        content: &Bytes,
        etag: Option<String>,
    ) -> Vec<(String, Bytes)> {
        let storage = Arc::new(RealStorageService::new(backend.clone()));
        let persister = CachePersister::new(storage);
        persister
            .write_buffered(
                "proxy-cache/repo/path/__content__",
                "proxy-cache/repo/path/__cache_meta__.json",
                content,
                Some("application/octet-stream".to_string()),
                etag,
                None,
                3600,
                Uuid::nil(),
                "repo/path",
                None,
            )
            .await
            .expect("write_buffered should succeed");
        backend.puts.lock().await.clone()
    }

    /// Happy path: body is written FIRST, then the sidecar (#1618 S9 write
    /// ordering). The sidecar carries the correct size, checksum, content
    /// type, upstream etag, and the #1051 pinned storage ETag.
    #[tokio::test]
    async fn test_write_buffered_writes_body_then_sidecar_and_pins_etag() {
        let backend = BufferedRecordingBackend::new(Some("\"backend-etag\""));
        let body = Bytes::from_static(b"hello world");
        let puts = run_write_buffered(backend, &body, Some("\"upstream-etag\"".to_string())).await;

        assert_eq!(puts.len(), 2, "exactly one body put and one sidecar put");
        // #1618 S9: content object first.
        assert_eq!(puts[0].0, "proxy-cache/repo/path/__content__");
        assert_eq!(puts[0].1.as_ref(), b"hello world");
        // #1618 S9: sidecar second.
        assert_eq!(puts[1].0, "proxy-cache/repo/path/__cache_meta__.json");

        let metadata: CacheMetadata =
            serde_json::from_slice(&puts[1].1).expect("sidecar JSON parseable");
        assert_eq!(metadata.size_bytes, 11);
        // SHA-256("hello world") known value:
        assert_eq!(
            metadata.checksum_sha256,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
        assert_eq!(
            metadata.content_type.as_deref(),
            Some("application/octet-stream")
        );
        assert_eq!(metadata.upstream_etag.as_deref(), Some("\"upstream-etag\""));
        // #1051 pin: the backend's post-put ETag is recorded.
        assert_eq!(metadata.storage_etag.as_deref(), Some("\"backend-etag\""));
        let ttl_seen = (metadata.expires_at - metadata.cached_at).num_seconds();
        assert!(
            (3595..=3605).contains(&ttl_seen),
            "expected expires_at - cached_at ~= 3600s, got {}s",
            ttl_seen
        );
    }

    /// #1051 fall-through: a backend with no ETag concept (filesystem /
    /// legacy) leaves `storage_etag = None`, preserving pre-#1051 fast-path
    /// existence-only revalidation semantics.
    #[tokio::test]
    async fn test_write_buffered_leaves_etag_none_when_backend_has_no_etag() {
        let backend = BufferedRecordingBackend::new(None);
        let body = Bytes::from_static(b"payload");
        let puts = run_write_buffered(backend, &body, None).await;

        assert_eq!(puts.len(), 2);
        let metadata: CacheMetadata = serde_json::from_slice(&puts[1].1).unwrap();
        assert!(
            metadata.storage_etag.is_none(),
            "no backend ETag means no pin (pre-#1051 semantics)"
        );
    }

    /// #1618 S9 / #1365: an empty body must NOT be cached on the buffered
    /// path. No content put, no sidecar put — the next request refetches.
    #[tokio::test]
    async fn test_write_buffered_empty_body_is_not_cached() {
        let backend = BufferedRecordingBackend::new(Some("\"etag\""));
        let body = Bytes::new();
        let puts = run_write_buffered(backend, &body, None).await;
        assert!(
            puts.is_empty(),
            "zero-byte body must skip BOTH the content and sidecar writes (#1365)"
        );
    }

    // -----------------------------------------------------------------------
    // validate_upstream_status: pure status-classification logic
    // extracted from read_upstream_response_streaming so the truth
    // table is testable without a real reqwest::Response. #895.
    // -----------------------------------------------------------------------

    #[test]
    fn test_redact_url_for_diagnostics_strips_query_and_fragment() {
        let signed = "https://provider-bucket.s3.amazonaws.com/releases/pkg.zip\
                      ?X-Amz-Signature=deadbeef&X-Amz-Credential=AKIAEXAMPLE#section";
        assert_eq!(
            redact_url_for_diagnostics(signed),
            "https://provider-bucket.s3.amazonaws.com/releases/pkg.zip"
        );

        assert_eq!(
            redact_url_for_diagnostics("packages/pkg.zip?token=secret#frag"),
            "packages/pkg.zip"
        );
    }

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

    #[test]
    fn test_validate_upstream_status_redacts_signed_url_diagnostics() {
        let signed_url = "https://provider-bucket.s3.amazonaws.com/releases/pkg.zip\
                          ?X-Amz-Signature=deadbeef&X-Amz-Credential=AKIAEXAMPLE#frag";

        match validate_upstream_status(StatusCode::FORBIDDEN, signed_url) {
            Err(AppError::BadGateway(msg)) => {
                assert!(msg.contains("https://provider-bucket.s3.amazonaws.com/releases/pkg.zip"));
                assert!(
                    !msg.contains("X-Amz") && !msg.contains("deadbeef") && !msg.contains("#frag"),
                    "signed URL material must not appear in diagnostics: {msg}"
                );
            }
            other => panic!("403 must map to redacted AppError::BadGateway; got {other:?}"),
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

    #[test]
    fn test_cached_artifact_paths_extracts_content_keys() {
        let keys = vec![
            "proxy-cache/npm-remote/is-odd/-/is-odd-3.0.1.tgz/__content__",
            "proxy-cache/npm-remote/is-odd/-/is-odd-3.0.1.tgz/__cache_meta__.json",
            "proxy-cache/npm-remote/lodash/__content__",
            "proxy-cache/npm-remote/lodash/__cache_meta__.json",
        ];
        let paths = ProxyService::cached_artifact_paths("npm-remote", keys);
        // Only content keys, sidecars dropped, prefix + suffix stripped, sorted.
        assert_eq!(
            paths,
            vec![
                "is-odd/-/is-odd-3.0.1.tgz".to_string(),
                "lodash".to_string()
            ]
        );
    }

    #[test]
    fn test_cached_artifact_paths_skips_other_repos_and_empty() {
        let keys = vec![
            // different repo's cache — must not leak in
            "proxy-cache/other-remote/express/__content__",
            // non-content leaf — skipped
            "proxy-cache/npm-remote/express/__cache_meta__.json",
            // empty logical path (bare repo root) — skipped
            "proxy-cache/npm-remote/__content__",
            // a real entry — kept
            "proxy-cache/npm-remote/express/__content__",
        ];
        let paths = ProxyService::cached_artifact_paths("npm-remote", keys);
        assert_eq!(paths, vec!["express".to_string()]);
    }

    // -----------------------------------------------------------------------
    // list_cached_artifacts: storage-backed read path (#1548 / web #424).
    // Exercises the full method against a mock backend: the prefix list, the
    // sidecar read per logical path, the missing-sidecar skip, the
    // content-type default, and the listing-error -> empty fallback. The
    // pure key parsing is covered by the cached_artifact_paths tests above.
    // -----------------------------------------------------------------------

    /// Storage backend that returns a fixed key set from `list()` and serves
    /// sidecar JSON from `get()` for keys present in `sidecars`. `list_fails`
    /// drives the listing-error path.
    struct CachedListingMock {
        keys: Vec<String>,
        sidecars: std::collections::HashMap<String, Bytes>,
        list_fails: bool,
    }

    #[async_trait::async_trait]
    impl crate::services::storage_service::StorageBackend for CachedListingMock {
        async fn put(&self, _key: &str, _content: Bytes) -> Result<()> {
            Ok(())
        }
        async fn get(&self, key: &str) -> Result<Bytes> {
            match self.sidecars.get(key) {
                Some(b) => Ok(b.clone()),
                None => Err(AppError::NotFound(key.to_string())),
            }
        }
        async fn exists(&self, _key: &str) -> Result<bool> {
            Ok(true)
        }
        async fn head_etag(&self, _key: &str) -> Result<Option<String>> {
            Ok(None)
        }
        async fn delete(&self, _key: &str) -> Result<()> {
            Ok(())
        }
        async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>> {
            if self.list_fails {
                return Err(AppError::Storage("mock list failure".to_string()));
            }
            Ok(match prefix {
                Some(p) => self
                    .keys
                    .iter()
                    .filter(|k| k.starts_with(p))
                    .cloned()
                    .collect(),
                None => self.keys.clone(),
            })
        }
        async fn copy(&self, _source: &str, _dest: &str) -> Result<()> {
            Ok(())
        }
        async fn size(&self, _key: &str) -> Result<u64> {
            Ok(0)
        }
    }

    fn sidecar_bytes(
        size: i64,
        checksum: &str,
        content_type: Option<&str>,
        cached_at: chrono::DateTime<chrono::Utc>,
    ) -> Bytes {
        let metadata = CacheMetadata {
            cached_at,
            upstream_etag: None,
            storage_etag: None,
            last_modified: None,
            negative_cached_until: None,
            quarantine_until: None,
            expires_at: cached_at + chrono::Duration::hours(1),
            content_type: content_type.map(|s| s.to_string()),
            size_bytes: size,
            checksum_sha256: checksum.to_string(),
        };
        Bytes::from(serde_json::to_vec(&metadata).unwrap())
    }

    fn content_key(repo: &str, path: &str) -> String {
        format!("proxy-cache/{}/{}/__content__", repo, path)
    }
    fn meta_key(repo: &str, path: &str) -> String {
        format!("proxy-cache/{}/{}/__cache_meta__.json", repo, path)
    }

    #[test]
    fn test_build_cached_entry_maps_fields_and_extracts_name() {
        let now = Utc::now();
        let metadata = CacheMetadata {
            cached_at: now,
            upstream_etag: None,
            storage_etag: None,
            last_modified: None,
            negative_cached_until: None,
            quarantine_until: None,
            expires_at: now + chrono::Duration::hours(1),
            content_type: Some("application/gzip".to_string()),
            size_bytes: 789,
            checksum_sha256: "d".repeat(64),
        };
        let entry =
            ProxyService::build_cached_entry("scope/-/scope-1.2.3.tgz".to_string(), metadata);
        assert_eq!(entry.path, "scope/-/scope-1.2.3.tgz");
        assert_eq!(
            entry.name, "scope-1.2.3.tgz",
            "name is the trailing segment"
        );
        assert_eq!(entry.size_bytes, 789);
        assert_eq!(entry.checksum_sha256, "d".repeat(64));
        assert_eq!(entry.content_type, "application/gzip");
        assert_eq!(entry.cached_at, now);
    }

    #[test]
    fn test_build_cached_entry_defaults_missing_content_type() {
        let now = Utc::now();
        let metadata = CacheMetadata {
            cached_at: now,
            upstream_etag: None,
            storage_etag: None,
            last_modified: None,
            negative_cached_until: None,
            quarantine_until: None,
            expires_at: now + chrono::Duration::hours(1),
            content_type: None,
            size_bytes: 1,
            checksum_sha256: "e".repeat(64),
        };
        // A path with no '/' must still produce a name equal to the whole path.
        let entry = ProxyService::build_cached_entry("flat-file.bin".to_string(), metadata);
        assert_eq!(entry.name, "flat-file.bin");
        assert_eq!(
            entry.content_type, "application/octet-stream",
            "missing content_type must default to application/octet-stream"
        );
    }

    #[tokio::test]
    async fn test_list_cached_artifacts_returns_entries_from_sidecars() {
        let repo = "npm-remote";
        let pa = "is-odd/-/is-odd-3.0.1.tgz";
        let pb = "lodash/-/lodash-4.17.21.tgz";
        let now = Utc::now();
        let mut sidecars = std::collections::HashMap::new();
        sidecars.insert(
            meta_key(repo, pa),
            sidecar_bytes(123, &"a".repeat(64), Some("application/gzip"), now),
        );
        // pb sidecar has no content_type -> entry should default it.
        sidecars.insert(
            meta_key(repo, pb),
            sidecar_bytes(456, &"b".repeat(64), None, now),
        );
        let keys = vec![
            content_key(repo, pa),
            meta_key(repo, pa),
            content_key(repo, pb),
            meta_key(repo, pb),
        ];
        let mock = Arc::new(CachedListingMock {
            keys,
            sidecars,
            list_fails: false,
        });
        let service = build_proxy_service_with_storage(mock);

        let mut entries = service.list_cached_artifacts(repo).await;
        entries.sort_by(|x, y| x.path.cmp(&y.path));
        assert_eq!(entries.len(), 2);

        let a = &entries[0];
        assert_eq!(a.path, pa);
        assert_eq!(a.name, "is-odd-3.0.1.tgz");
        assert_eq!(a.size_bytes, 123);
        assert_eq!(a.checksum_sha256, "a".repeat(64));
        assert_eq!(a.content_type, "application/gzip");

        let b = &entries[1];
        assert_eq!(b.name, "lodash-4.17.21.tgz");
        assert_eq!(
            b.content_type, "application/octet-stream",
            "missing content_type must default to application/octet-stream"
        );
    }

    #[tokio::test]
    async fn test_list_cached_artifacts_output_is_sorted_by_path() {
        // The batched (buffer_unordered) load yields sidecars out of order;
        // list_cached_artifacts must re-sort so callers get deterministic output.
        let repo = "npm-remote";
        let now = Utc::now();
        let paths = [
            "z/-/z-1.0.0.tgz",
            "a/-/a-1.0.0.tgz",
            "m/-/m-1.0.0.tgz",
            "b/-/b-1.0.0.tgz",
        ];
        let mut sidecars = std::collections::HashMap::new();
        let mut keys = Vec::new();
        for (i, p) in paths.iter().enumerate() {
            sidecars.insert(
                meta_key(repo, p),
                sidecar_bytes(
                    i as i64,
                    &"f".repeat(64),
                    Some("application/octet-stream"),
                    now,
                ),
            );
            keys.push(content_key(repo, p));
            keys.push(meta_key(repo, p));
        }
        let mock = Arc::new(CachedListingMock {
            keys,
            sidecars,
            list_fails: false,
        });
        let service = build_proxy_service_with_storage(mock);

        let entries = service.list_cached_artifacts(repo).await;
        let got: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(
            got,
            vec![
                "a/-/a-1.0.0.tgz",
                "b/-/b-1.0.0.tgz",
                "m/-/m-1.0.0.tgz",
                "z/-/z-1.0.0.tgz",
            ],
            "entries must be sorted by path regardless of sidecar load order"
        );
    }

    #[tokio::test]
    async fn test_list_cached_artifacts_skips_entry_with_corrupt_sidecar() {
        // A sidecar that is present but unparseable makes load_cache_metadata
        // return Err; that single bad path must be skipped (logged) without
        // failing the whole listing. Guards the error-tolerance of the batched
        // load (#1608).
        let repo = "npm-remote";
        let good = "ok/-/ok-1.0.0.tgz";
        let corrupt = "bad/-/bad-1.0.0.tgz";
        let now = Utc::now();
        let mut sidecars = std::collections::HashMap::new();
        sidecars.insert(
            meta_key(repo, good),
            sidecar_bytes(10, &"c".repeat(64), Some("application/octet-stream"), now),
        );
        // Present but invalid JSON -> serde parse error -> Err arm.
        sidecars.insert(
            meta_key(repo, corrupt),
            Bytes::from_static(b"{not valid json"),
        );
        let keys = vec![
            content_key(repo, good),
            meta_key(repo, good),
            content_key(repo, corrupt),
            meta_key(repo, corrupt),
        ];
        let mock = Arc::new(CachedListingMock {
            keys,
            sidecars,
            list_fails: false,
        });
        let service = build_proxy_service_with_storage(mock);

        let entries = service.list_cached_artifacts(repo).await;
        assert_eq!(
            entries.len(),
            1,
            "an entry whose sidecar is corrupt must be skipped, not fail the listing"
        );
        assert_eq!(entries[0].path, good);
    }

    #[tokio::test]
    async fn test_list_cached_artifacts_skips_entry_with_missing_sidecar() {
        let repo = "npm-remote";
        let good = "ok/-/ok-1.0.0.tgz";
        let bad = "broken/-/broken-1.0.0.tgz"; // content listed, no sidecar
        let now = Utc::now();
        let mut sidecars = std::collections::HashMap::new();
        sidecars.insert(
            meta_key(repo, good),
            sidecar_bytes(10, &"c".repeat(64), Some("application/octet-stream"), now),
        );
        let keys = vec![
            content_key(repo, good),
            meta_key(repo, good),
            content_key(repo, bad),
        ];
        let mock = Arc::new(CachedListingMock {
            keys,
            sidecars,
            list_fails: false,
        });
        let service = build_proxy_service_with_storage(mock);

        let entries = service.list_cached_artifacts(repo).await;
        assert_eq!(
            entries.len(),
            1,
            "an entry whose sidecar is missing must be skipped"
        );
        assert_eq!(entries[0].path, good);
    }

    #[tokio::test]
    async fn test_list_cached_artifacts_empty_when_listing_fails() {
        let mock = Arc::new(CachedListingMock {
            keys: Vec::new(),
            sidecars: std::collections::HashMap::new(),
            list_fails: true,
        });
        let service = build_proxy_service_with_storage(mock);
        assert!(
            service.list_cached_artifacts("npm-remote").await.is_empty(),
            "a storage listing error must yield no cached artifacts"
        );
    }

    /// Storage mock that counts every `get` (sidecar read) so a test can
    /// assert the two-phase cached listing only reads the requested page's
    /// sidecars rather than every object in the cache (#1571).
    struct CountingCacheMock {
        keys: Vec<String>,
        sidecars: std::collections::HashMap<String, Bytes>,
        get_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl crate::services::storage_service::StorageBackend for CountingCacheMock {
        async fn put(&self, _key: &str, _content: Bytes) -> Result<()> {
            Ok(())
        }
        async fn get(&self, key: &str) -> Result<Bytes> {
            self.get_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            match self.sidecars.get(key) {
                Some(b) => Ok(b.clone()),
                None => Err(AppError::NotFound(key.to_string())),
            }
        }
        async fn exists(&self, _key: &str) -> Result<bool> {
            Ok(true)
        }
        async fn head_etag(&self, _key: &str) -> Result<Option<String>> {
            Ok(None)
        }
        async fn delete(&self, _key: &str) -> Result<()> {
            Ok(())
        }
        async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>> {
            Ok(match prefix {
                Some(p) => self
                    .keys
                    .iter()
                    .filter(|k| k.starts_with(p))
                    .cloned()
                    .collect(),
                None => self.keys.clone(),
            })
        }
        async fn copy(&self, _source: &str, _dest: &str) -> Result<()> {
            Ok(())
        }
        async fn size(&self, _key: &str) -> Result<u64> {
            Ok(0)
        }
    }

    #[tokio::test]
    async fn test_list_cached_paths_reads_no_sidecars() {
        // #1571: recovering the path set must not read a single sidecar, so the
        // caller can filter + page the paths before paying for any metadata I/O.
        let repo = "npm-remote";
        let now = Utc::now();
        let all = ["a/-/a-1.tgz", "b/-/b-1.tgz", "c/-/c-1.tgz"];
        let mut sidecars = std::collections::HashMap::new();
        let mut keys = Vec::new();
        for p in all {
            sidecars.insert(
                meta_key(repo, p),
                sidecar_bytes(1, &"a".repeat(64), None, now),
            );
            keys.push(content_key(repo, p));
            keys.push(meta_key(repo, p));
        }
        let get_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mock = std::sync::Arc::new(CountingCacheMock {
            keys,
            sidecars,
            get_count: get_count.clone(),
        });
        let service = build_proxy_service_with_storage(mock);

        let paths = service.list_cached_paths(repo).await;
        assert_eq!(paths, vec!["a/-/a-1.tgz", "b/-/b-1.tgz", "c/-/c-1.tgz"]);
        assert_eq!(
            get_count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "listing cached paths must not read any sidecar"
        );
    }

    #[tokio::test]
    async fn test_load_cached_entries_reads_only_requested_paths() {
        // #1571: loading a single-path page out of a 3-object cache must read
        // exactly one sidecar, not all three (the old O(N)-per-listing cost).
        let repo = "npm-remote";
        let now = Utc::now();
        let all = ["a/-/a-1.tgz", "b/-/b-1.tgz", "c/-/c-1.tgz"];
        let mut sidecars = std::collections::HashMap::new();
        let mut keys = Vec::new();
        for p in all {
            sidecars.insert(
                meta_key(repo, p),
                sidecar_bytes(7, &"b".repeat(64), None, now),
            );
            keys.push(content_key(repo, p));
            keys.push(meta_key(repo, p));
        }
        let get_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mock = std::sync::Arc::new(CountingCacheMock {
            keys,
            sidecars,
            get_count: get_count.clone(),
        });
        let service = build_proxy_service_with_storage(mock);

        let page = vec!["b/-/b-1.tgz".to_string()];
        let entries = service.load_cached_entries(repo, &page).await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "b/-/b-1.tgz");
        assert_eq!(
            get_count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "loading a 1-path page must read exactly one sidecar, not the whole cache"
        );
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
            promotion_only: false,
            replication_priority: crate::models::repository::ReplicationPriority::OnDemand,
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

    /// `cached_metadata_if_servable` (#2069): the cache-only, classifier- and
    /// quarantine-aware read used by the virtual metadata first-match resolver.
    /// Pins the three load-bearing arms — a cold miss and a negative-cached 404
    /// both read back as `Ok(None)` (so the caller falls through to its parallel
    /// upstream fetch), and a fresh cache hit serves the body without contacting
    /// upstream.
    #[tokio::test]
    async fn test_cached_metadata_if_servable_miss_fresh_and_negative() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/index.json"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"INDEX-BODY".as_ref()))
            .mount(&server)
            .await;
        // "/missing.json" is intentionally NOT mounted → wiremock 404 → the
        // fetch negative-caches it.

        let tmp = std::env::temp_dir().join(format!("cached-meta-servable-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("create tmp");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());

        let repo = Repository {
            id: Uuid::new_v4(),
            key: "test-cached-meta-servable".to_string(),
            name: "test-cached-meta-servable".to_string(),
            description: None,
            format: RepositoryFormat::Generic,
            repo_type: RepositoryType::Remote,
            storage_backend: "filesystem".to_string(),
            storage_path: tmp.to_string_lossy().to_string(),
            upstream_url: Some(server.uri()),
            is_public: true,
            quota_bytes: None,
            promotion_only: false,
            replication_priority: crate::models::repository::ReplicationPriority::OnDemand,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Cold miss: nothing cached yet → Ok(None).
        let miss = proxy.cached_metadata_if_servable(&repo, "index.json").await;
        assert!(
            matches!(miss, Ok(None)),
            "uncached path must read back as a miss, got {miss:?}"
        );

        // Prime the cache via a real upstream fetch, then a FRESH hit must serve
        // the body (no upstream contact).
        let (body, _ct) = proxy
            .fetch_artifact(&repo, "index.json")
            .await
            .expect("prime cache from upstream");
        assert_eq!(&body[..], b"INDEX-BODY");
        match proxy.cached_metadata_if_servable(&repo, "index.json").await {
            Ok(Some((bytes, _))) => assert_eq!(&bytes[..], b"INDEX-BODY"),
            other => panic!("fresh cached entry must be servable, got {other:?}"),
        }

        // A negative-cached 404 reads back as Ok(None) (NOT an error, NOT a
        // served body) so the caller's Pass-2 fetch re-honors the negative cache.
        let _ = proxy.fetch_artifact(&repo, "missing.json").await; // 404 → negative cache
        let neg = proxy
            .cached_metadata_if_servable(&repo, "missing.json")
            .await;
        assert!(
            matches!(neg, Ok(None)),
            "negative-cached entry must map to Ok(None), got {neg:?}"
        );

        let _ = std::fs::remove_dir_all(&tmp);
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
            promotion_only: false,
            replication_priority: crate::models::repository::ReplicationPriority::OnDemand,
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

    // -----------------------------------------------------------------------
    // #1360: ghcr.io manifest pull. GitHub Container Registry returns 404
    // when the request's `Accept` header does not list a media type that
    // matches the stored manifest. The OCI handler's
    // `manifest_accept_for_upstream` helper supplements the client's
    // Accept with the canonical OCI/Docker manifest media-type set so
    // these strict upstreams still serve the request. This test pins the
    // wire-level contract: a wiremock upstream that only responds 200
    // when the request's Accept contains the OCI image-index media type
    // must succeed when the proxy is given the supplemented Accept value.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_fetch_manifest_with_canonical_accept_succeeds_against_strict_upstream() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let server = MockServer::start().await;

        // Strict ghcr-shaped upstream: respond 200 only when the request
        // carries the OCI image-index media type in Accept; otherwise the
        // wiremock default (404) fires, matching the user's reproducer
        // for `gurucomputing/headscale-ui:2026.03.17`.
        let manifest_body =
            br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}"#;
        Mock::given(method("GET"))
            .and(path("/v2/gurucomputing/headscale-ui/manifests/2026.03.17"))
            .and(AcceptHeaderContains {
                expected_substring: "application/vnd.oci.image.index.v1+json",
            })
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/vnd.oci.image.index.v1+json")
                    .set_body_bytes(manifest_body.as_ref()),
            )
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("ghcr-1360-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("create tmp");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());

        let repo = Repository {
            id: Uuid::new_v4(),
            key: "remote-container-ghcr".to_string(),
            name: "remote-container-ghcr".to_string(),
            description: None,
            format: RepositoryFormat::Generic,
            repo_type: RepositoryType::Remote,
            storage_backend: "filesystem".to_string(),
            storage_path: tmp.to_string_lossy().to_string(),
            upstream_url: Some(server.uri()),
            is_public: true,
            quota_bytes: None,
            promotion_only: false,
            replication_priority: crate::models::repository::ReplicationPriority::OnDemand,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // The canonical Accept value that the OCI manifest handler now
        // always sends. Contains the OCI image-index media type that the
        // strict upstream requires; older docker engines that only sent
        // the Docker manifest types would fail this match before #1360.
        let canonical_accept = "application/vnd.docker.distribution.manifest.v2+json, \
                                application/vnd.docker.distribution.manifest.list.v2+json, \
                                application/vnd.oci.image.index.v1+json, \
                                application/vnd.oci.image.manifest.v1+json";

        let result = proxy
            .fetch_artifact_with_accept(
                &repo,
                "v2/gurucomputing/headscale-ui/manifests/2026.03.17",
                Some(canonical_accept),
            )
            .await;
        let _ = std::fs::remove_dir_all(&tmp);

        let (body, ct) = result.expect(
            "ghcr-shaped upstream must succeed when proxy advertises the \
             canonical OCI Accept header set on manifest fetches (#1360)",
        );
        assert_eq!(&body[..], manifest_body.as_ref());
        assert_eq!(
            ct.as_deref(),
            Some("application/vnd.oci.image.index.v1+json"),
        );
    }

    /// Companion: the same strict upstream MUST 404 when the proxy sends
    /// only the Docker manifest media types (the pre-#1360 behaviour for
    /// older Docker clients). This pins the test fixture itself: if a
    /// future change makes the wiremock match too lax (e.g. matches on
    /// the absence of Accept) the regression value of the test above
    /// collapses.
    #[tokio::test]
    async fn test_strict_upstream_rejects_sparse_accept_header() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v2/gurucomputing/headscale-ui/manifests/2026.03.17"))
            .and(AcceptHeaderContains {
                expected_substring: "application/vnd.oci.image.index.v1+json",
            })
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ok".as_ref()))
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("ghcr-1360-neg-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("create tmp");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());

        let repo = Repository {
            id: Uuid::new_v4(),
            key: "remote-container-ghcr".to_string(),
            name: "remote-container-ghcr".to_string(),
            description: None,
            format: RepositoryFormat::Generic,
            repo_type: RepositoryType::Remote,
            storage_backend: "filesystem".to_string(),
            storage_path: tmp.to_string_lossy().to_string(),
            upstream_url: Some(server.uri()),
            is_public: true,
            quota_bytes: None,
            promotion_only: false,
            replication_priority: crate::models::repository::ReplicationPriority::OnDemand,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Sparse pre-#1360 Accept: only docker media types, no OCI ones.
        let sparse = "application/vnd.docker.distribution.manifest.v2+json";

        let result = proxy
            .fetch_artifact_with_accept(
                &repo,
                "v2/gurucomputing/headscale-ui/manifests/2026.03.17",
                Some(sparse),
            )
            .await;
        let _ = std::fs::remove_dir_all(&tmp);

        // The strict upstream must reject this request (default 404), so
        // the proxy surfaces NotFound. This confirms the wiremock fixture
        // actually discriminates on the OCI Accept content.
        match result {
            Err(crate::error::AppError::NotFound(_)) => {}
            other => panic!(
                "expected NotFound from strict upstream when proxy sends \
                 only Docker manifest media types in Accept, got: {:?}",
                other
            ),
        }
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
                None,
                DEFAULT_CACHE_TTL_SECS,
                Uuid::new_v4(),
                cache_path,
                None,
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

    /// Build a minimal Remote `Repository` pointing at `upstream_url` for
    /// the streaming proxy tests below. The storage path is unused by the
    /// streaming cache (which writes through `self.storage`), but the field
    /// is required by the struct.
    fn remote_repo_for(key: &str, upstream_url: &str, storage_path: &str) -> Repository {
        Repository {
            id: Uuid::new_v4(),
            key: key.to_string(),
            name: key.to_string(),
            description: None,
            format: RepositoryFormat::Maven,
            repo_type: RepositoryType::Remote,
            storage_backend: "filesystem".to_string(),
            storage_path: storage_path.to_string(),
            upstream_url: Some(upstream_url.to_string()),
            is_public: true,
            quota_bytes: None,
            promotion_only: false,
            replication_priority: crate::models::repository::ReplicationPriority::OnDemand,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn test_remote_target_returns_borrowed_upstream_for_remote_repo() {
        let repo = remote_repo_for(
            "maven-proxy",
            "https://repo.maven.apache.org/maven2",
            "/tmp/x",
        );
        let url = ProxyService::remote_target(&repo).expect("remote repo with upstream is valid");
        assert_eq!(url, "https://repo.maven.apache.org/maven2");
    }

    #[test]
    fn test_remote_target_rejects_non_remote_repo() {
        let mut repo = remote_repo_for("local", "https://example.com", "/tmp/x");
        repo.repo_type = RepositoryType::Local;
        let err = ProxyService::remote_target(&repo).expect_err("non-remote repo must be rejected");
        match err {
            AppError::Validation(msg) => {
                assert_eq!(
                    msg,
                    "Proxy operations only supported for remote repositories"
                );
            }
            other => panic!("expected AppError::Validation, got {other:?}"),
        }
    }

    #[test]
    fn test_remote_target_rejects_remote_repo_missing_upstream() {
        let mut repo = remote_repo_for("no-upstream", "https://example.com", "/tmp/x");
        repo.upstream_url = None;
        let err =
            ProxyService::remote_target(&repo).expect_err("missing upstream_url must be rejected");
        match err {
            AppError::Config(msg) => {
                assert_eq!(msg, "Remote repository missing upstream_url");
            }
            other => panic!("expected AppError::Config, got {other:?}"),
        }
    }

    /// #1365 end-to-end regression: a non-empty upstream Maven POM proxied
    /// through `fetch_artifact_streaming` must be cached at the full
    /// upstream byte length, and the second request must serve that same
    /// non-zero body from the cache (never `Content-Length: 0`).
    ///
    /// Drives the real streaming path (tee + filesystem `put_stream` +
    /// metadata sidecar) against a wiremock upstream, so it exercises the
    /// exact code that produced the zero-byte cache hit in the incident.
    #[tokio::test]
    async fn test_streaming_proxy_caches_full_length_pom() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // The streaming fetch loads per-repo upstream auth from the DB, so
        // this end-to-end test needs a real database. Skip gracefully when
        // DATABASE_URL is unset/unreachable (matches the other wiremock
        // proxy tests). The deterministic unit-level guard for #1365 lives
        // in `test_tee_empty_upstream_is_not_cached`, which needs no DB.
        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let pom = br#"<?xml version="1.0" encoding="UTF-8"?>
<project><modelVersion>4.0.0</modelVersion>
<groupId>io.sentry</groupId><artifactId>sentry</artifactId><version>8.42.0</version></project>"#;
        let pom_path = "io/sentry/sentry/8.42.0/sentry-8.42.0.pom";

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path(format!("/{pom_path}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/xml")
                    .set_body_bytes(pom.as_ref()),
            )
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("ak-1365-ok-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("create tmp dir");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        let repo_key = format!("maven-central-{}", Uuid::new_v4());
        let repo = remote_repo_for(&repo_key, &server.uri(), tmp.to_str().unwrap());

        // First request: cache miss, streamed from upstream and tee'd to cache.
        let first = proxy
            .fetch_artifact_streaming(&repo, pom_path)
            .await
            .expect("streaming fetch must succeed on a 200 upstream");
        let body = drain_stream(first.body).await;
        assert_eq!(
            body.len(),
            pom.len(),
            "first (miss) response must carry the full upstream POM length"
        );
        assert_eq!(&body[..], pom.as_ref());

        // Give the background cache writer time to flush the sidecar.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // The cache must now be fresh with the correct length.
        assert!(
            proxy.is_cache_fresh(&repo_key, pom_path).await,
            "a non-empty POM must produce a fresh cache entry"
        );

        // Second request: served from cache. Must be non-zero and full length.
        let second = proxy
            .fetch_artifact_streaming(&repo, pom_path)
            .await
            .expect("cached streaming fetch must succeed");
        assert_eq!(
            second.content_length,
            Some(pom.len() as u64),
            "cache hit must report the full POM length, never 0 (#1365)"
        );
        let cached_body = drain_stream(second.body).await;
        let _ = std::fs::remove_dir_all(&tmp);
        assert_eq!(
            &cached_body[..],
            pom.as_ref(),
            "cache hit must serve the full POM body, never an empty body (#1365)"
        );
    }

    /// #1365 end-to-end regression: an empty upstream body (a 204, an empty
    /// 200, or a HEAD-style probe reaching the streaming download path)
    /// must NOT poison the cache. After draining the empty first response,
    /// the entry must not be fresh, and once the upstream serves the real
    /// POM the next request must return the full non-empty body.
    #[tokio::test]
    async fn test_streaming_proxy_does_not_cache_empty_upstream_then_self_heals() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let pom = br#"<?xml version="1.0"?><project><artifactId>sentry</artifactId></project>"#;
        let pom_path = "io/sentry/sentry/8.42.0/sentry-8.42.0.pom";

        let server = MockServer::start().await;
        // First response: a valid 200 status but an empty body (the bug
        // trigger). `up_to_n_times(1)` so the second request gets the
        // real POM, proving the bad entry self-heals rather than sticking.
        Mock::given(method("GET"))
            .and(wm_path(format!("/{pom_path}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/xml")
                    .set_body_bytes(b"".as_ref()),
            )
            .with_priority(1)
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(wm_path(format!("/{pom_path}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/xml")
                    .set_body_bytes(pom.as_ref()),
            )
            .with_priority(2)
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("ak-1365-empty-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("create tmp dir");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        let repo_key = format!("maven-central-empty-{}", Uuid::new_v4());
        let repo = remote_repo_for(&repo_key, &server.uri(), tmp.to_str().unwrap());

        // First request: empty upstream body. Client gets the empty body
        // for THIS request, but nothing must be cached.
        let first = proxy
            .fetch_artifact_streaming(&repo, pom_path)
            .await
            .expect("streaming fetch must succeed even on an empty 200");
        let body = drain_stream(first.body).await;
        assert_eq!(
            body.len(),
            0,
            "first response mirrors the empty upstream body"
        );

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !proxy.is_cache_fresh(&repo_key, pom_path).await,
            "an empty upstream body MUST NOT create a fresh cache entry (#1365)"
        );

        // Second request: upstream now serves the real POM. The proxy must
        // refetch (the empty entry was not cached) and return the full body.
        let second = proxy
            .fetch_artifact_streaming(&repo, pom_path)
            .await
            .expect("refetch after empty upstream must succeed");
        let healed = drain_stream(second.body).await;
        let _ = std::fs::remove_dir_all(&tmp);
        assert_eq!(
            &healed[..],
            pom.as_ref(),
            "after the empty body was rejected, the next request must serve \
             the full upstream POM (self-heal), never a zero-byte cache hit (#1365)"
        );
    }

    /// Drain a streaming proxy body into a single `Vec<u8>`.
    async fn drain_stream(body: BoxStream<'static, Result<Bytes>>) -> Vec<u8> {
        let mut body = body;
        let mut out = Vec::new();
        while let Some(chunk) = body.next().await {
            out.extend_from_slice(&chunk.expect("stream chunk"));
        }
        out
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

    // -----------------------------------------------------------------------
    // get_cached(allow_stale) behavioral tests (#1630, S2 of #1618)
    //
    // `get_cached_artifact` (allow_stale = false) and
    // `get_stale_cached_artifact` (allow_stale = true) were collapsed into a
    // single private `get_cached`. The two paths diverge in THREE ways and
    // these tests pin every one against the flag:
    //   1. Expiry gate — enforced only for the fresh (false) path.
    //   2. Read-error policy — the fresh path SWALLOWS metadata/body read
    //      errors as a cache miss (Ok(None), B6); the stale path PROPAGATES
    //      them (Err). This is the dangerous divergence: a single B6 branch
    //      applied to both flags would silently turn the stale path from
    //      error-propagating into error-swallowing.
    //   3. Log wording — "Cache …" vs "Stale cache …" (not asserted here;
    //      logging is a side channel, but both code paths exist behind the
    //      flag and are covered by the cargo build/clippy gate).
    // The checksum verification is identical for both flags, so a hit
    // returned by either flag is still checksum-verified — asserted below.
    // -----------------------------------------------------------------------

    const META_KEY: &str = "proxy/get-cached/__cache_meta__.json";
    const BODY_KEY: &str = "proxy/get-cached/__content__";

    /// Per-key behavior for [`GetCachedMock`]: serve bytes, simulate a missing
    /// object (`AppError::NotFound`), or simulate a transient transport error
    /// (`AppError::Storage`) — the latter is what exercises the swallow-vs-
    /// propagate divergence.
    enum KeyResponse {
        Bytes(Bytes),
        Missing,
        Error,
    }

    /// Storage backend that serves a programmable response for the metadata
    /// key and the body key independently, so a single test can wire e.g. a
    /// valid sidecar plus a failing body read.
    struct GetCachedMock {
        metadata: KeyResponse,
        body: KeyResponse,
    }

    impl GetCachedMock {
        fn respond(key: &str, resp: &KeyResponse) -> Result<Bytes> {
            match resp {
                KeyResponse::Bytes(b) => Ok(b.clone()),
                KeyResponse::Missing => Err(AppError::NotFound(key.to_string())),
                KeyResponse::Error => Err(AppError::Storage(
                    "simulated transient read failure".to_string(),
                )),
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::services::storage_service::StorageBackend for GetCachedMock {
        async fn put(&self, _key: &str, _content: Bytes) -> Result<()> {
            Ok(())
        }
        async fn get(&self, key: &str) -> Result<Bytes> {
            if key == META_KEY {
                Self::respond(key, &self.metadata)
            } else {
                Self::respond(key, &self.body)
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

    /// Build a metadata sidecar whose checksum matches `body` and whose
    /// `expires_at` is in the past (`expired = true`) or the future.
    fn get_cached_metadata(body: &[u8], expired: bool) -> Bytes {
        let now = Utc::now();
        let expires_at = if expired {
            now - chrono::Duration::hours(1)
        } else {
            now + chrono::Duration::hours(1)
        };
        let metadata = CacheMetadata {
            cached_at: now - chrono::Duration::hours(2),
            upstream_etag: None,
            storage_etag: None,
            last_modified: None,
            negative_cached_until: None,
            quarantine_until: None,
            expires_at,
            content_type: Some("application/octet-stream".to_string()),
            size_bytes: body.len() as i64,
            checksum_sha256: StorageService::calculate_hash(body),
        };
        Bytes::from(serde_json::to_vec(&metadata).unwrap())
    }

    fn service_with(metadata: KeyResponse, body: KeyResponse) -> ProxyService {
        build_proxy_service_with_storage(Arc::new(GetCachedMock { metadata, body }))
    }

    // --- fetch_artifact_streaming_with_cache_path: key derivation -----------

    /// Map-backed storage that records every key requested via `get`, so
    /// tests can assert which cache keys the streaming path derives.
    struct RecordingMapStorage {
        entries: std::collections::HashMap<String, Bytes>,
        requested: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl crate::services::storage_service::StorageBackend for RecordingMapStorage {
        async fn put(&self, _key: &str, _content: Bytes) -> Result<()> {
            Ok(())
        }
        async fn get(&self, key: &str) -> Result<Bytes> {
            self.requested.lock().unwrap().push(key.to_string());
            self.entries
                .get(key)
                .cloned()
                .ok_or_else(|| AppError::NotFound(key.to_string()))
        }
        async fn exists(&self, key: &str) -> Result<bool> {
            Ok(self.entries.contains_key(key))
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
        async fn size(&self, key: &str) -> Result<u64> {
            Ok(self.entries.get(key).map(|b| b.len() as u64).unwrap_or(0))
        }
    }

    /// PyPI-shaped remote repo for the cache-path threading tests: wheels
    /// classify as immutable under [`cache_classifier`], so a cached entry
    /// streams without contacting upstream or the database.
    fn pypi_remote_repo(key: &str) -> Repository {
        let mut repo = remote_repo_for(key, "https://pypi.org/simple", "/tmp/x");
        repo.format = RepositoryFormat::Pypi;
        repo
    }

    async fn collect_streaming_body(
        mut body: futures::stream::BoxStream<'static, Result<Bytes>>,
    ) -> Bytes {
        let mut buf = Vec::new();
        while let Some(chunk) = body.next().await {
            buf.extend_from_slice(&chunk.unwrap());
        }
        Bytes::from(buf)
    }

    #[tokio::test]
    async fn test_streaming_with_cache_path_keys_cache_on_cache_path() {
        // The PyPI handler fetches wheels from files.pythonhosted.org-style
        // URLs but caches them under the stable simple/{project}/{file} key.
        // A cache hit must be found under `cache_path` even though
        // `fetch_path` points somewhere else entirely — and the fetch path
        // must never be used to derive a storage key.
        let cache_path = "simple/numpy/numpy-2.0.0-py3-none-any.whl";
        let fetch_path = "packages/ab/cd/numpy-2.0.0-py3-none-any.whl";
        let wheel_body = Bytes::from_static(b"fake wheel bytes");

        let keys = CacheKeys::derive("pypi-remote", cache_path).unwrap();
        let mut entries = std::collections::HashMap::new();
        entries.insert(keys.metadata.clone(), fresh_metadata_bytes());
        entries.insert(keys.content.clone(), wheel_body.clone());

        let storage = Arc::new(RecordingMapStorage {
            entries,
            requested: std::sync::Mutex::new(Vec::new()),
        });
        let svc = build_proxy_service_with_storage(storage.clone());
        let repo = pypi_remote_repo("pypi-remote");

        let result = svc
            .fetch_artifact_streaming_with_cache_path(&repo, fetch_path, cache_path)
            .await
            .expect("cached entry under cache_path must stream as a hit");

        let body = collect_streaming_body(result.body).await;
        assert_eq!(body, wheel_body);

        let requested = storage.requested.lock().unwrap();
        assert!(
            requested.iter().all(|k| !k.contains("packages/")),
            "no storage key may be derived from fetch_path; requested: {:?}",
            *requested
        );
    }

    #[tokio::test]
    async fn test_streaming_cached_artifact_by_path_returns_none_on_miss() {
        // Empty storage: the streaming probe must report a miss without
        // erroring (callers fall through to the full upstream fetch).
        let storage = Arc::new(RecordingMapStorage {
            entries: std::collections::HashMap::new(),
            requested: std::sync::Mutex::new(Vec::new()),
        });
        let svc = build_proxy_service_with_storage(storage);
        let repo = pypi_remote_repo("pypi-remote");

        let probe = svc
            .streaming_cached_artifact_by_path(&repo, "simple/numpy/numpy-2.0.0-py3-none-any.whl")
            .await
            .expect("a cache miss must not be an error");
        assert!(probe.is_none(), "missing sidecar must probe as a miss");
    }

    // --- Divergence #1: expiry gate -----------------------------------------

    #[tokio::test]
    async fn test_get_cached_fresh_rejects_expired_entry() {
        // allow_stale = false on an expired sidecar must miss before ever
        // reading the body.
        let body = b"payload";
        let svc = service_with(
            KeyResponse::Bytes(get_cached_metadata(body, /* expired = */ true)),
            KeyResponse::Bytes(Bytes::from_static(body)),
        );
        let out = svc.get_cached(BODY_KEY, META_KEY, false).await.unwrap();
        assert!(out.is_none(), "fresh read must reject an expired entry");
    }

    #[tokio::test]
    async fn test_get_cached_stale_serves_expired_entry() {
        // allow_stale = true skips the expiry gate and serves the body.
        let body = b"payload";
        let svc = service_with(
            KeyResponse::Bytes(get_cached_metadata(body, /* expired = */ true)),
            KeyResponse::Bytes(Bytes::from_static(body)),
        );
        let out = svc.get_cached(BODY_KEY, META_KEY, true).await.unwrap();
        let (content, ct) = out.expect("stale read must serve an expired entry");
        assert_eq!(&content[..], body);
        assert_eq!(ct.as_deref(), Some("application/octet-stream"));
    }

    // --- Checksum verification (identical for both flags) -------------------

    #[tokio::test]
    async fn test_get_cached_verifies_checksum_for_both_flags() {
        // The stored body does NOT match the sidecar checksum: both flags must
        // treat it as a miss, proving stale still verifies the checksum.
        let good = b"the-checksummed-bytes";
        let tampered = Bytes::from_static(b"different-bytes");

        // Fresh + valid sidecar + tampered body -> miss.
        let fresh = service_with(
            KeyResponse::Bytes(get_cached_metadata(good, /* expired = */ false)),
            KeyResponse::Bytes(tampered.clone()),
        );
        assert!(
            fresh
                .get_cached(BODY_KEY, META_KEY, false)
                .await
                .unwrap()
                .is_none(),
            "fresh read must reject a checksum mismatch"
        );

        // Stale + expired sidecar + tampered body -> still a miss (checksum is
        // verified even on the stale fallback path).
        let stale = service_with(
            KeyResponse::Bytes(get_cached_metadata(good, /* expired = */ true)),
            KeyResponse::Bytes(tampered),
        );
        assert!(
            stale
                .get_cached(BODY_KEY, META_KEY, true)
                .await
                .unwrap()
                .is_none(),
            "stale read must still reject a checksum mismatch"
        );
    }

    // --- Divergence #2: read-error policy (swallow vs propagate) ------------

    #[tokio::test]
    async fn test_get_cached_metadata_read_error_diverges_on_flag() {
        // A metadata sidecar read error: fresh swallows -> Ok(None); stale
        // propagates -> Err.
        let fresh = service_with(KeyResponse::Error, KeyResponse::Missing);
        let fresh_out = fresh.get_cached(BODY_KEY, META_KEY, false).await;
        assert!(
            matches!(fresh_out, Ok(None)),
            "fresh read must swallow a metadata read error as a cache miss (B6)"
        );

        let stale = service_with(KeyResponse::Error, KeyResponse::Missing);
        let stale_out = stale.get_cached(BODY_KEY, META_KEY, true).await;
        assert!(
            stale_out.is_err(),
            "stale read must propagate a metadata read error"
        );
    }

    #[tokio::test]
    async fn test_get_cached_body_read_error_diverges_on_flag() {
        // A valid sidecar but a transient body read error: fresh swallows ->
        // Ok(None); stale propagates -> Err.
        let body = b"payload";

        let fresh = service_with(
            KeyResponse::Bytes(get_cached_metadata(body, /* expired = */ false)),
            KeyResponse::Error,
        );
        let fresh_out = fresh.get_cached(BODY_KEY, META_KEY, false).await;
        assert!(
            matches!(fresh_out, Ok(None)),
            "fresh read must swallow a body read error as a cache miss (B6)"
        );

        // Stale uses an expired sidecar (its real-world state) + body error.
        let stale = service_with(
            KeyResponse::Bytes(get_cached_metadata(body, /* expired = */ true)),
            KeyResponse::Error,
        );
        let stale_out = stale.get_cached(BODY_KEY, META_KEY, true).await;
        assert!(
            stale_out.is_err(),
            "stale read must propagate a body read error"
        );
    }

    // --- NotFound is a miss for both flags (not an error) -------------------

    #[tokio::test]
    async fn test_get_cached_missing_body_is_miss_for_both_flags() {
        let body = b"payload";

        let fresh = service_with(
            KeyResponse::Bytes(get_cached_metadata(body, /* expired = */ false)),
            KeyResponse::Missing,
        );
        assert!(
            matches!(fresh.get_cached(BODY_KEY, META_KEY, false).await, Ok(None)),
            "fresh: missing body is a miss, not an error"
        );

        let stale = service_with(
            KeyResponse::Bytes(get_cached_metadata(body, /* expired = */ true)),
            KeyResponse::Missing,
        );
        assert!(
            matches!(stale.get_cached(BODY_KEY, META_KEY, true).await, Ok(None)),
            "stale: missing body is a miss, not an error"
        );
    }

    // =======================================================================
    // UpstreamClient coverage (#1618 S8).
    //
    // S8 relocated the upstream-fetch lifecycle (`fetch_buffered`,
    // `fetch_stream`, `read_upstream_response*`, `exchange_bearer_then`,
    // `obtain_bearer_token`, `get_cached_token`, `check_etag_changed`) into
    // `UpstreamClient`. Those network methods load per-repo auth from the DB
    // before issuing the HTTP request, so the unit tests below drive them end
    // to end against a `wiremock` upstream with a live `DATABASE_URL` (the
    // same fixture pattern the rest of this suite uses). They no-op on runners
    // without a test DB and run in CI's coverage job, which provisions one.
    //
    // The `obtain_bearer_token` cache-hit / TTL-cap / eviction decisions and
    // `get_cached_token` freshness math are pure (no network) and are tested
    // by constructing an `UpstreamClient` directly and seeding its token cache.
    // =======================================================================

    /// Build a Remote `Repository` whose `upstream_url` points at `upstream`.
    /// `repo.id` is random and intentionally absent from the DB: the upstream
    /// methods only run `load_upstream_auth`, whose query returns no rows
    /// (`Ok(None)`) for an unknown id and then proceeds to the HTTP request.
    fn wiremock_remote_repo(key: &str, upstream: &str, storage_path: &str) -> Repository {
        Repository {
            id: Uuid::new_v4(),
            key: key.to_string(),
            name: key.to_string(),
            description: None,
            format: RepositoryFormat::Generic,
            repo_type: RepositoryType::Remote,
            storage_backend: "filesystem".to_string(),
            storage_path: storage_path.to_string(),
            upstream_url: Some(upstream.to_string()),
            is_public: true,
            quota_bytes: None,
            promotion_only: false,
            replication_priority: crate::models::repository::ReplicationPriority::OnDemand,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    // -- get_cached_token: pure TTL-freshness decision -----------------------

    #[tokio::test]
    async fn test_get_cached_token_returns_fresh_entry_within_90pct_ttl() {
        // A token cached "just now" with a 1000s TTL is well inside the 90%
        // freshness window and must be returned verbatim.
        let pool = sqlx::PgPool::connect_lazy("postgres://invalid/").unwrap();
        let client = UpstreamClient::new(pool, Client::new());
        {
            let mut cache = client.token_cache.write().await;
            cache.insert(
                "k".to_string(),
                ("tok-fresh".to_string(), Instant::now(), 1000),
            );
        }
        assert_eq!(
            client.get_cached_token("k").await.as_deref(),
            Some("tok-fresh"),
            "a token inside the 90% TTL window is a cache hit",
        );
    }

    #[tokio::test]
    async fn test_get_cached_token_treats_aged_entry_past_90pct_as_miss() {
        // created_at far enough in the past that elapsed() >= ttl*9/10. With a
        // 10s TTL the window is 9s; backdate the entry by 20s so it is stale.
        let pool = sqlx::PgPool::connect_lazy("postgres://invalid/").unwrap();
        let client = UpstreamClient::new(pool, Client::new());
        {
            let mut cache = client.token_cache.write().await;
            let aged = Instant::now()
                .checked_sub(Duration::from_secs(20))
                .expect("subtract 20s");
            cache.insert("k".to_string(), ("tok-old".to_string(), aged, 10));
        }
        assert!(
            client.get_cached_token("k").await.is_none(),
            "an entry past 90% of its TTL must be treated as a miss",
        );
    }

    #[tokio::test]
    async fn test_get_cached_token_absent_key_is_miss() {
        let pool = sqlx::PgPool::connect_lazy("postgres://invalid/").unwrap();
        let client = UpstreamClient::new(pool, Client::new());
        assert!(client.get_cached_token("nope").await.is_none());
    }

    // -- obtain_bearer_token: cache hit short-circuit (no network) -----------

    #[tokio::test]
    async fn test_obtain_bearer_token_returns_cached_without_network() {
        // A fresh cache entry under the exact "{realm}\0{service}\0{scope}"
        // key must short-circuit before any token-endpoint request. The realm
        // points at an unroutable host so a network attempt would fail the
        // test; the cache hit makes it never happen.
        let pool = sqlx::PgPool::connect_lazy("postgres://invalid/").unwrap();
        let client = UpstreamClient::new(pool, Client::new());
        let realm = "http://127.0.0.1:0/token";
        let service = "registry.example";
        let scope = "repository:library/alpine:pull";
        let key = format!("{}\0{}\0{}", realm, service, scope);
        {
            let mut cache = client.token_cache.write().await;
            cache.insert(key, ("cached-bearer".to_string(), Instant::now(), 1000));
        }
        let token = client
            .obtain_bearer_token(realm, service, scope, &None)
            .await
            .expect("cache hit must return Ok without contacting the realm");
        assert_eq!(token, "cached-bearer");
    }

    // -- obtain_bearer_token: full token-endpoint exchange via wiremock ------

    #[tokio::test]
    async fn test_obtain_bearer_token_exchanges_and_caps_ttl() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Token endpoint echoes a token and an absurd expires_in; the TTL must
        // be capped at MAX_TOKEN_TTL_SECS by the caching logic.
        Mock::given(method("GET"))
            .and(path("/token"))
            .and(query_param("service", "reg.test"))
            .and(query_param("scope", "repository:img:pull"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "exchanged-token",
                "expires_in": 10_000_000u64,
            })))
            .mount(&server)
            .await;

        let pool = sqlx::PgPool::connect_lazy("postgres://invalid/").unwrap();
        let client = UpstreamClient::new(pool, Client::new());
        let realm = format!("{}/token", server.uri());

        let token = client
            .obtain_bearer_token(&realm, "reg.test", "repository:img:pull", &None)
            .await
            .expect("token exchange against a 200 token endpoint must succeed");
        assert_eq!(token, "exchanged-token");

        // The entry is now cached with the capped TTL, so a second call is a
        // cache hit (no second request is registered on the mock).
        let again = client
            .obtain_bearer_token(&realm, "reg.test", "repository:img:pull", &None)
            .await
            .expect("second call must hit the cache");
        assert_eq!(again, "exchanged-token");

        let cache = client.token_cache.read().await;
        let (_, _, ttl) = cache
            .get(&format!(
                "{}\0{}\0{}",
                realm, "reg.test", "repository:img:pull"
            ))
            .expect("entry cached");
        assert_eq!(
            *ttl, MAX_TOKEN_TTL_SECS,
            "an oversized expires_in must be capped at MAX_TOKEN_TTL_SECS",
        );
    }

    #[tokio::test]
    async fn test_obtain_bearer_token_uses_access_token_field_and_default_ttl() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // No `service`/`scope` params -> the token URL is the bare realm. The
        // response uses the `access_token` alias and omits `expires_in`, so the
        // default TTL applies.
        Mock::given(method("GET"))
            .and(path("/realm"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "alias-token",
            })))
            .mount(&server)
            .await;

        let pool = sqlx::PgPool::connect_lazy("postgres://invalid/").unwrap();
        let client = UpstreamClient::new(pool, Client::new());
        let realm = format!("{}/realm", server.uri());

        let token = client
            .obtain_bearer_token(&realm, "", "", &None)
            .await
            .expect("access_token alias must be accepted");
        assert_eq!(token, "alias-token");

        let cache = client.token_cache.read().await;
        let (_, _, ttl) = cache
            .get(&format!("{}\0\0", realm))
            .expect("entry cached under empty service/scope");
        assert_eq!(
            *ttl, DEFAULT_TOKEN_TTL_SECS,
            "a missing expires_in must fall back to DEFAULT_TOKEN_TTL_SECS",
        );
    }

    #[tokio::test]
    async fn test_obtain_bearer_token_errors_on_non_success_status() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let pool = sqlx::PgPool::connect_lazy("postgres://invalid/").unwrap();
        let client = UpstreamClient::new(pool, Client::new());
        let realm = format!("{}/token", server.uri());

        let err = client
            .obtain_bearer_token(&realm, "", "", &None)
            .await
            .expect_err("a 403 from the token endpoint must surface as an error");
        assert!(
            matches!(err, AppError::Storage(_)),
            "non-2xx token endpoint status maps to AppError::Storage, got {err:?}",
        );
    }

    #[tokio::test]
    async fn test_obtain_bearer_token_errors_when_response_has_no_token() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "expires_in": 60 })),
            )
            .mount(&server)
            .await;

        let pool = sqlx::PgPool::connect_lazy("postgres://invalid/").unwrap();
        let client = UpstreamClient::new(pool, Client::new());
        let realm = format!("{}/token", server.uri());

        let err = client
            .obtain_bearer_token(&realm, "", "", &None)
            .await
            .expect_err("a token response with neither token nor access_token must error");
        assert!(matches!(err, AppError::Storage(_)));
    }

    // -- fetch_buffered + read_upstream_response (success / error) -----------

    #[tokio::test]
    async fn test_fetch_buffered_returns_body_headers_and_etag() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pkg/file.bin"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/octet-stream")
                    .insert_header("etag", "\"v1\"")
                    .insert_header("link", "<next>; rel=next")
                    .set_body_bytes(b"buffered-bytes".as_ref()),
            )
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("s8-buf-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        let url = format!("{}/pkg/file.bin", server.uri());

        let resp = proxy
            .fetch_from_upstream(&url, Uuid::new_v4())
            .await
            .expect("buffered fetch of a 200 upstream must succeed");
        let _ = std::fs::remove_dir_all(&tmp);

        assert_eq!(&resp.content[..], b"buffered-bytes");
        assert_eq!(
            resp.content_type.as_deref(),
            Some("application/octet-stream")
        );
        assert_eq!(resp.etag.as_deref(), Some("\"v1\""));
        assert_eq!(resp.link.as_deref(), Some("<next>; rel=next"));
    }

    #[tokio::test]
    async fn test_fetch_buffered_maps_upstream_404_to_error() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/missing"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("s8-404-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        let url = format!("{}/missing", server.uri());

        let result = proxy.fetch_from_upstream(&url, Uuid::new_v4()).await;
        let _ = std::fs::remove_dir_all(&tmp);
        assert!(
            result.is_err(),
            "a 404 upstream must surface as an error, not a body",
        );
    }

    #[tokio::test]
    async fn test_fetch_buffered_maps_upstream_503_to_service_unavailable() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/down"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("s8-503-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        let url = format!("{}/down", server.uri());

        let result = proxy.fetch_from_upstream(&url, Uuid::new_v4()).await;
        let _ = std::fs::remove_dir_all(&tmp);
        let err = result
            .err()
            .expect("a 5xx upstream must surface as an error");
        assert!(
            matches!(err, AppError::ServiceUnavailable(_)),
            "5xx upstream must map to ServiceUnavailable, got {err:?}",
        );
    }

    // -- fetch_upstream_direct(+_with_link): drive fetch_buffered + headers --

    #[tokio::test]
    async fn test_fetch_upstream_direct_returns_effective_url() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/simple/foo/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_bytes(b"<html/>".as_ref()),
            )
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("s8-direct-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        let repo = wiremock_remote_repo("s8-direct", &server.uri(), tmp.to_str().unwrap());

        let (body, ct, effective) = proxy
            .fetch_upstream_direct(&repo, "simple/foo/")
            .await
            .expect("direct fetch must succeed");
        let _ = std::fs::remove_dir_all(&tmp);
        assert_eq!(&body[..], b"<html/>");
        assert_eq!(ct.as_deref(), Some("text/html"));
        assert!(
            effective.ends_with("/simple/foo/"),
            "effective url: {effective}"
        );
    }

    #[tokio::test]
    async fn test_fetch_upstream_direct_with_link_preserves_link_header() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/_catalog"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("link", "</v2/_catalog?last=z>; rel=\"next\"")
                    .set_body_bytes(b"{}".as_ref()),
            )
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("s8-link-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        let repo = wiremock_remote_repo("s8-link", &server.uri(), tmp.to_str().unwrap());

        let (_body, _ct, link) = proxy
            .fetch_upstream_direct_with_link(&repo, "v2/_catalog")
            .await
            .expect("direct-with-link fetch must succeed");
        let _ = std::fs::remove_dir_all(&tmp);
        assert_eq!(link.as_deref(), Some("</v2/_catalog?last=z>; rel=\"next\""));
    }

    // -- fetch_stream + read_upstream_response_streaming ---------------------

    #[tokio::test]
    async fn test_fetch_artifact_streaming_streams_upstream_body_on_cache_miss() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/blob"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/octet-stream")
                    .set_body_bytes(b"streamed-body".as_ref()),
            )
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("s8-stream-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        let repo = wiremock_remote_repo("s8-stream", &server.uri(), tmp.to_str().unwrap());

        let result = proxy
            .fetch_artifact_streaming(&repo, "blob")
            .await
            .expect("streaming fetch on a cache miss must succeed");
        assert_eq!(
            result.content_type.as_deref(),
            Some("application/octet-stream")
        );

        let mut collected = Vec::new();
        let mut body = result.body;
        while let Some(chunk) = body.next().await {
            collected.extend_from_slice(&chunk.expect("stream chunk must be Ok"));
        }
        let _ = std::fs::remove_dir_all(&tmp);
        assert_eq!(collected, b"streamed-body");
    }

    #[tokio::test]
    async fn test_fetch_artifact_streaming_maps_upstream_5xx_to_error() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/blob"))
            .respond_with(ResponseTemplate::new(502))
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("s8-stream5xx-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        let repo = wiremock_remote_repo("s8-stream5xx", &server.uri(), tmp.to_str().unwrap());

        let err = proxy
            .fetch_artifact_streaming(&repo, "blob")
            .await
            .expect_err("a 5xx upstream must fail the streaming fetch");
        let _ = std::fs::remove_dir_all(&tmp);
        assert!(matches!(err, AppError::ServiceUnavailable(_)), "{err:?}");
    }

    /// PyPI-shaped split (#895 follow-up): the upstream download URL
    /// (files.pythonhosted.org-style `packages/...` path) differs from the
    /// stable cache key (`simple/{project}/{file}`). The streaming leader
    /// must fetch `fetch_path` from upstream but tee the body into the
    /// cache under `cache_path`-derived keys only.
    #[tokio::test]
    async fn test_fetch_artifact_streaming_with_cache_path_tees_under_cache_path() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/packages/ab/cd/demo-1.0-py3-none-any.whl"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/zip")
                    .set_body_bytes(b"wheel-body".as_ref()),
            )
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("s8-cachepath-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        let repo = wiremock_remote_repo("pypi-split", &server.uri(), tmp.to_str().unwrap());

        let fetch_path = "packages/ab/cd/demo-1.0-py3-none-any.whl";
        let cache_path = "simple/demo/demo-1.0-py3-none-any.whl";
        let result = proxy
            .fetch_artifact_streaming_with_cache_path(&repo, fetch_path, cache_path)
            .await
            .expect("streaming fetch with split fetch/cache paths must succeed");

        let mut collected = Vec::new();
        let mut body = result.body;
        while let Some(chunk) = body.next().await {
            collected.extend_from_slice(&chunk.expect("stream chunk must be Ok"));
        }
        assert_eq!(collected, b"wheel-body");

        // The tee writes the cache in a background task after the client
        // stream drains; poll briefly for the content object to land.
        let content_rel = CacheKeys::derive("pypi-split", cache_path)
            .expect("derive")
            .content;
        let content_file = tmp.join(&content_rel);
        let mut cached = Vec::new();
        for _ in 0..50 {
            if let Ok(bytes) = std::fs::read(&content_file) {
                cached = bytes;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert_eq!(
            cached, b"wheel-body",
            "cache body must land under the cache_path-derived key"
        );
        // Nothing may be cached under a fetch_path-derived location.
        assert!(
            !tmp.join("proxy-cache/pypi-split/packages").exists(),
            "no cache entry may be derived from fetch_path"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// #1631 layer 2 (#1694): N concurrent cold-cache streaming requests for
    /// the SAME uncached path must open upstream exactly ONCE — one leader tees
    /// to client + cache, the rest follow its broadcast or land on the now-warm
    /// cache. The wiremock upstream is counted via a single 200 mock and the
    /// post-run `received_requests`, asserting the upstream was hit once.
    #[tokio::test]
    async fn test_fetch_artifact_streaming_single_flights_concurrent_cold_misses() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = MockServer::start().await;
        // A deliberately slow upstream so concurrent followers pile up behind
        // the leader rather than each racing to a fast independent fetch.
        Mock::given(method("GET"))
            .and(path("/blob"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/octet-stream")
                    .set_body_bytes(b"single-flight-body".as_ref())
                    .set_delay(std::time::Duration::from_millis(300)),
            )
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("s8-sf-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let proxy = Arc::new(tdh::build_proxy_service_with_fs(
            pool,
            tmp.to_str().unwrap(),
        ));
        let repo = Arc::new(wiremock_remote_repo(
            "s8-sf",
            &server.uri(),
            tmp.to_str().unwrap(),
        ));

        // Fire N concurrent streamers for the same uncached path.
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let proxy = Arc::clone(&proxy);
            let repo = Arc::clone(&repo);
            tasks.push(tokio::spawn(async move {
                let result = proxy
                    .fetch_artifact_streaming(&repo, "blob")
                    .await
                    .expect("concurrent streaming fetch must succeed");
                let mut body = result.body;
                let mut bytes = Vec::new();
                while let Some(chunk) = body.next().await {
                    bytes.extend_from_slice(&chunk.expect("chunk ok"));
                }
                bytes
            }));
        }

        for t in tasks {
            let bytes = t.await.expect("join");
            assert_eq!(bytes, b"single-flight-body", "every client gets full body");
        }

        // The upstream must have been hit AT MOST once for all 8 streamers.
        let hits = server
            .received_requests()
            .await
            .expect("recorded requests")
            .into_iter()
            .filter(|r| r.url.path() == "/blob")
            .count();
        let _ = std::fs::remove_dir_all(&tmp);
        assert_eq!(
            hits, 1,
            "single-flight: exactly one upstream open for N concurrent cold misses, got {hits}"
        );
    }

    // -- exchange_bearer_then: OCI 401 Bearer challenge handling -------------
    //
    // The full success path (parse challenge -> validate realm -> token
    // exchange -> bearer retry) cannot be exercised by a unit test: the only
    // host a wiremock server binds to is loopback, and loopback is a HARD SSRF
    // block in `validate_outbound_url` that the `UPSTREAM_ALLOW_PRIVATE_IPS`
    // toggle does NOT relax (api::validation::is_blocked_ipv4). So the realm
    // validation inside `exchange_bearer_then` rejects a loopback realm before
    // any token request. The two tests below pin the branches we CAN reach:
    //   1. a parseable Bearer challenge whose realm is SSRF-blocked surfaces
    //      the validation error (covers the parse + realm-extract + validate
    //      path of `exchange_bearer_then`), and
    //   2. a 401 that is NOT a Bearer challenge returns `Ok(None)` and the
    //      caller maps it to the original "upstream error status".

    #[tokio::test]
    async fn test_buffered_fetch_rejects_ssrf_bearer_realm() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = MockServer::start().await;
        // A 401 Bearer challenge whose realm points at a metadata/internal
        // address. `exchange_bearer_then` must parse the challenge, extract the
        // realm, and reject it via `validate_outbound_url` BEFORE issuing any
        // outbound token request (the anti-SSRF guard, #1618 S8 doc).
        Mock::given(method("GET"))
            .and(path("/v2/lib/img/manifests/latest"))
            .respond_with(ResponseTemplate::new(401).insert_header(
                "www-authenticate",
                "Bearer realm=\"http://169.254.169.254/latest/token\",service=\"reg\",scope=\"pull\"",
            ))
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("s8-ssrf-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        let url = format!("{}/v2/lib/img/manifests/latest", server.uri());

        let err = proxy
            .fetch_from_upstream(&url, Uuid::new_v4())
            .await
            .err()
            .expect("a Bearer realm pointing at an internal address must be rejected");
        let _ = std::fs::remove_dir_all(&tmp);
        assert!(
            matches!(err, AppError::Validation(_)),
            "an SSRF-blocked OCI token realm must surface as a validation error, got {err:?}",
        );
    }

    #[tokio::test]
    async fn test_buffered_fetch_401_without_bearer_challenge_errors() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = MockServer::start().await;
        // A 401 whose WWW-Authenticate is NOT a Bearer challenge: exchange
        // returns Ok(None) and the caller maps it to the original error.
        Mock::given(method("GET"))
            .and(path("/private"))
            .respond_with(
                ResponseTemplate::new(401).insert_header("www-authenticate", "Basic realm=\"x\""),
            )
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("s8-401basic-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        let url = format!("{}/private", server.uri());

        let err = proxy
            .fetch_from_upstream(&url, Uuid::new_v4())
            .await
            .err()
            .expect("a non-Bearer 401 must surface as an error");
        let _ = std::fs::remove_dir_all(&tmp);
        assert!(matches!(err, AppError::Storage(_)), "{err:?}");
    }

    // -- check_etag_changed via check_upstream (304 / changed / unchanged) ---

    #[tokio::test]
    async fn test_check_upstream_etag_304_reports_unchanged() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = MockServer::start().await;
        // Seed the cache by fetching once with an ETag.
        Mock::given(method("GET"))
            .and(path("/etagged"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"abc\"")
                    .set_body_bytes(b"body".as_ref()),
            )
            .mount(&server)
            .await;
        // HEAD revalidation returns 304 Not Modified.
        Mock::given(method("HEAD"))
            .and(path("/etagged"))
            .respond_with(ResponseTemplate::new(304))
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("s8-etag304-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        let repo = wiremock_remote_repo("s8-etag304", &server.uri(), tmp.to_str().unwrap());

        // Prime the cache (writes a metadata sidecar carrying upstream_etag).
        proxy
            .fetch_artifact(&repo, "etagged")
            .await
            .expect("prime cache");

        let changed = proxy
            .check_upstream(&repo, "etagged")
            .await
            .expect("etag check must succeed");
        let _ = std::fs::remove_dir_all(&tmp);
        assert!(!changed, "a 304 from the HEAD revalidation means unchanged");
    }

    #[tokio::test]
    async fn test_check_upstream_etag_changed_when_head_returns_new_etag() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/etagged2"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"old\"")
                    .set_body_bytes(b"body".as_ref()),
            )
            .mount(&server)
            .await;
        // HEAD returns 200 with a different ETag -> changed.
        Mock::given(method("HEAD"))
            .and(path("/etagged2"))
            .respond_with(ResponseTemplate::new(200).insert_header("etag", "\"new\""))
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("s8-etagchg-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        let repo = wiremock_remote_repo("s8-etagchg", &server.uri(), tmp.to_str().unwrap());

        proxy
            .fetch_artifact(&repo, "etagged2")
            .await
            .expect("prime cache");

        let changed = proxy
            .check_upstream(&repo, "etagged2")
            .await
            .expect("etag check must succeed");
        let _ = std::fs::remove_dir_all(&tmp);
        assert!(changed, "a different ETag on the HEAD means changed");
    }

    // -- fetch_dists_detecting_change: drives buffered fetch + SHA compare ---

    #[tokio::test]
    async fn test_fetch_dists_detecting_change_reports_changed_on_first_fetch() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dists/stable/Release"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"Release: v1".as_ref()))
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("s8-dists-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        let repo = wiremock_remote_repo("s8-dists", &server.uri(), tmp.to_str().unwrap());

        let (content, _ct, changed) = proxy
            .fetch_dists_detecting_change(&repo, "dists/stable/Release")
            .await
            .expect("dists fetch must succeed");
        let _ = std::fs::remove_dir_all(&tmp);
        assert_eq!(&content[..], b"Release: v1");
        assert!(
            changed,
            "first fetch with no prior body is always 'changed'"
        );
    }

    // -- get_cache_ttl_for_repo: DB lookup with default fallback -------------

    #[tokio::test]
    async fn test_fetch_artifact_with_cache_path_round_trips_then_serves_from_cache() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = MockServer::start().await;
        // The upstream is only allowed to be hit ONCE: the second request must
        // be served from the proxy cache, exercising the cache-hit fast path
        // in fetch_artifact_with_cache_path_and_accept and get_cache_ttl_for_repo.
        Mock::given(method("GET"))
            .and(path("/dl/pkg.tgz"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/gzip")
                    .set_body_bytes(b"tarball".as_ref()),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("s8-cachepath-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        let repo = wiremock_remote_repo("s8-cachepath", &server.uri(), tmp.to_str().unwrap());

        let (b1, ct1) = proxy
            .fetch_artifact_with_cache_path(&repo, "dl/pkg.tgz", "stable/pkg.tgz")
            .await
            .expect("first fetch hits upstream and caches");
        assert_eq!(&b1[..], b"tarball");
        assert_eq!(ct1.as_deref(), Some("application/gzip"));

        // Second call: upstream mock is exhausted (up_to_n_times(1)); a cache
        // hit is the only way this can succeed.
        let (b2, _ct2) = proxy
            .fetch_artifact_with_cache_path(&repo, "dl/pkg.tgz", "stable/pkg.tgz")
            .await
            .expect("second fetch must be served from the proxy cache");
        let _ = std::fs::remove_dir_all(&tmp);
        assert_eq!(&b2[..], b"tarball", "cached bytes must match upstream");
    }

    // -- parse_bearer_challenge: unquoted-value and trailing branches --------

    #[test]
    fn test_parse_bearer_challenge_unquoted_values() {
        // Unquoted, comma-separated params exercise the else-branch that reads
        // up to the next comma (lines around the unquoted-value path).
        let params = UpstreamClient::parse_bearer_challenge(
            "Bearer realm=https://auth.example/token,service=reg,scope=pull",
        );
        assert_eq!(
            params.get("realm").map(String::as_str),
            Some("https://auth.example/token")
        );
        assert_eq!(params.get("service").map(String::as_str), Some("reg"));
        assert_eq!(params.get("scope").map(String::as_str), Some("pull"));
    }

    #[test]
    fn test_parse_bearer_challenge_trailing_key_without_value_breaks() {
        // A dangling key with no '=' after a valid pair: the loop breaks on the
        // missing '=' so only the first pair is captured.
        let params = UpstreamClient::parse_bearer_challenge("Bearer realm=\"r\",dangling");
        assert_eq!(params.get("realm").map(String::as_str), Some("r"));
        assert!(!params.contains_key("dangling"));
    }

    #[test]
    fn test_parse_bearer_challenge_mixed_quoted_then_unquoted_tail() {
        // Quoted value followed by an unquoted final param (no trailing comma)
        // covers the `end < remaining.len()` false branch of the unquoted arm.
        let params =
            UpstreamClient::parse_bearer_challenge("Bearer realm=\"https://r/\",service=svc");
        assert_eq!(params.get("realm").map(String::as_str), Some("https://r/"));
        assert_eq!(params.get("service").map(String::as_str), Some("svc"));
    }

    // -- #1611 conditional revalidation matrix + negative caching ------------
    //
    // These tests prime a *stale* mutable cache entry directly on disk (a body
    // + a sidecar whose `expires_at` is in the past) and then drive
    // `fetch_artifact_with_cache_path`, asserting the §2.2 matrix:
    //   * 304 -> serve cached body, extend TTL, no body re-download.
    //   * 200/changed -> refill through the single-flight coordinator.
    //   * 404 -> negative cache + NotFound.
    //   * 5xx -> stale-if-error (serve the stale body).
    // Immutable paths are proven to NEVER contact upstream on a hit.

    /// Build a remote repo with a caller-chosen format so immutable-path
    /// classification can be exercised (the default helper uses `Generic`,
    /// which is always mutable).
    fn wiremock_remote_repo_fmt(
        key: &str,
        upstream: &str,
        storage_path: &str,
        format: RepositoryFormat,
    ) -> Repository {
        let mut repo = wiremock_remote_repo(key, upstream, storage_path);
        repo.format = format;
        repo
    }

    /// Write a stale (already-expired) cache entry — body + sidecar — straight
    /// to the filesystem backend under the keys `fetch_artifact_with_cache_path`
    /// derives, so a subsequent fetch sees a `Stale` entry it must revalidate.
    fn prime_stale_cache_entry(
        storage_root: &str,
        repo_key: &str,
        cache_path: &str,
        body: &[u8],
        upstream_etag: Option<&str>,
    ) {
        let now = Utc::now();
        let metadata = CacheMetadata {
            cached_at: now - chrono::Duration::hours(2),
            upstream_etag: upstream_etag.map(String::from),
            storage_etag: None,
            last_modified: None,
            negative_cached_until: None,
            quarantine_until: None,
            // Already expired -> Stale for a mutable path.
            expires_at: now - chrono::Duration::seconds(1),
            content_type: Some("application/octet-stream".to_string()),
            size_bytes: body.len() as i64,
            checksum_sha256: StorageService::calculate_hash(&Bytes::copy_from_slice(body)),
        };
        write_primed_cache_files(storage_root, repo_key, cache_path, Some(body), &metadata);
    }

    /// Shared on-disk primer for the proxy-cache test helpers: writes the body
    /// (when `Some`) at the content key and the JSON sidecar at the metadata key,
    /// creating parent dirs. Factored out of the three `prime_*` helpers so they
    /// differ only in the `CacheMetadata` they construct (keeps the duplication
    /// gate happy).
    fn write_primed_cache_files(
        storage_root: &str,
        repo_key: &str,
        cache_path: &str,
        body: Option<&[u8]>,
        metadata: &CacheMetadata,
    ) {
        let content_key = ProxyService::cache_storage_key(repo_key, cache_path).unwrap();
        let meta_key = ProxyService::cache_metadata_key(repo_key, cache_path).unwrap();
        let mut writes: Vec<(String, Bytes)> =
            vec![(meta_key, Bytes::from(serde_json::to_vec(metadata).unwrap()))];
        if let Some(body) = body {
            writes.push((content_key, Bytes::copy_from_slice(body)));
        }
        for (key, bytes) in writes {
            let full = std::path::Path::new(storage_root).join(&key);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(&full, &bytes).unwrap();
        }
    }

    #[tokio::test]
    async fn test_revalidate_304_serves_cached_body_and_skips_download() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = MockServer::start().await;
        // The conditional revalidation is a HEAD; a 304 means "unchanged".
        // No GET is mounted, so a body re-download would fail the test.
        Mock::given(method("HEAD"))
            .and(path("/meta.xml"))
            .respond_with(ResponseTemplate::new(304))
            .expect(1)
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("s1611-304-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        let repo = wiremock_remote_repo("s1611-304", &server.uri(), tmp.to_str().unwrap());
        prime_stale_cache_entry(
            tmp.to_str().unwrap(),
            "s1611-304",
            "meta.xml",
            b"cached-index",
            Some("\"v1\""),
        );

        let (body, _ct) = proxy
            .fetch_artifact_with_cache_path(&repo, "meta.xml", "meta.xml")
            .await
            .expect("304 revalidation must serve the cached body");
        let _ = std::fs::remove_dir_all(&tmp);
        assert_eq!(&body[..], b"cached-index", "304 must serve cached bytes");
    }

    #[tokio::test]
    async fn test_revalidate_changed_refills_from_upstream() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = MockServer::start().await;
        // HEAD returns 200 with a different ETag -> changed -> refill via GET.
        Mock::given(method("HEAD"))
            .and(path("/meta.xml"))
            .respond_with(ResponseTemplate::new(200).insert_header("etag", "\"v2\""))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/meta.xml"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"v2\"")
                    .set_body_bytes(b"new-index".as_ref()),
            )
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("s1611-chg-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        let repo = wiremock_remote_repo("s1611-chg", &server.uri(), tmp.to_str().unwrap());
        prime_stale_cache_entry(
            tmp.to_str().unwrap(),
            "s1611-chg",
            "meta.xml",
            b"old-index",
            Some("\"v1\""),
        );

        let (body, _ct) = proxy
            .fetch_artifact_with_cache_path(&repo, "meta.xml", "meta.xml")
            .await
            .expect("changed upstream must refill");
        let _ = std::fs::remove_dir_all(&tmp);
        assert_eq!(
            &body[..],
            b"new-index",
            "changed must serve refreshed bytes"
        );
    }

    #[tokio::test]
    async fn test_upstream_404_is_negative_cached() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = MockServer::start().await;
        // Upstream GET 404s exactly once; the negative cache must absorb the
        // second request so upstream is never re-hit.
        Mock::given(method("GET"))
            .and(path("/missing"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("s1611-neg-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        let repo = wiremock_remote_repo("s1611-neg", &server.uri(), tmp.to_str().unwrap());

        let first = proxy
            .fetch_artifact_with_cache_path(&repo, "missing", "missing")
            .await;
        assert!(
            matches!(first, Err(AppError::NotFound(_))),
            "first miss 404s"
        );

        let second = proxy
            .fetch_artifact_with_cache_path(&repo, "missing", "missing")
            .await;
        let _ = std::fs::remove_dir_all(&tmp);
        assert!(
            matches!(second, Err(AppError::NotFound(_))),
            "second request must be served from the negative cache (upstream expect(1))"
        );
    }

    #[tokio::test]
    async fn test_revalidate_transport_error_serves_stale_within_grace() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        // Point upstream at a dead port so the revalidation HEAD fails with a
        // transport error -> stale-if-error must serve the stale body.
        let dead_upstream = "http://127.0.0.1:1";
        let tmp = std::env::temp_dir().join(format!("s1611-sie-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        let repo = wiremock_remote_repo("s1611-sie", dead_upstream, tmp.to_str().unwrap());
        prime_stale_cache_entry(
            tmp.to_str().unwrap(),
            "s1611-sie",
            "meta.xml",
            b"stale-but-served",
            Some("\"v1\""),
        );

        let (body, _ct) = proxy
            .fetch_artifact_with_cache_path(&repo, "meta.xml", "meta.xml")
            .await
            .expect("stale-if-error must serve the stale body when upstream is down");
        let _ = std::fs::remove_dir_all(&tmp);
        assert_eq!(&body[..], b"stale-but-served");
    }

    #[tokio::test]
    async fn test_immutable_hit_never_contacts_upstream() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = MockServer::start().await;
        // Upstream serves the jar exactly ONCE. Any second contact (GET/HEAD)
        // would exceed expect(1) and fail the test, proving the immutable hit
        // is served purely from cache with no revalidation.
        Mock::given(method("GET"))
            .and(path("/com/example/app/1.0.0/app-1.0.0.jar"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/java-archive")
                    .set_body_bytes(b"jar-bytes".as_ref()),
            )
            .expect(1)
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("s1611-imm-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        // Maven + a versioned .jar path classifies Immutable -> forever TTL.
        let repo = wiremock_remote_repo_fmt(
            "s1611-imm",
            &server.uri(),
            tmp.to_str().unwrap(),
            RepositoryFormat::Maven,
        );
        let jar = "com/example/app/1.0.0/app-1.0.0.jar";

        // First fetch hits upstream once and caches with the immutable TTL.
        let (b1, _) = proxy
            .fetch_artifact_with_cache_path(&repo, jar, jar)
            .await
            .expect("first immutable fetch hits upstream and caches forever");
        assert_eq!(&b1[..], b"jar-bytes");

        // Second fetch must be served from cache with ZERO upstream contact.
        let (b2, _) = proxy
            .fetch_artifact_with_cache_path(&repo, jar, jar)
            .await
            .expect("immutable hit must serve from cache without upstream");
        let _ = std::fs::remove_dir_all(&tmp);
        assert_eq!(&b2[..], b"jar-bytes");
    }

    // -- #1611 streaming-path parity: the STREAMING proxy path must honor the
    //    same classify/evaluate/negative-cache/revalidation correctness as the
    //    buffered `read_cached_with_revalidation` path. These mirror the
    //    buffered §2.2 matrix above but drive `fetch_artifact_streaming`.

    /// Write a *fresh* (non-expired) cache entry — body + sidecar — straight to
    /// the filesystem backend under the keys the streaming path derives, so a
    /// subsequent streaming fetch sees a `Fresh` hit.
    fn prime_fresh_cache_entry(
        storage_root: &str,
        repo_key: &str,
        cache_path: &str,
        body: &[u8],
        ttl_secs: i64,
    ) {
        let now = Utc::now();
        let metadata = CacheMetadata {
            cached_at: now,
            upstream_etag: None,
            storage_etag: None,
            last_modified: None,
            negative_cached_until: None,
            quarantine_until: None,
            expires_at: now + chrono::Duration::seconds(ttl_secs),
            content_type: Some("application/octet-stream".to_string()),
            size_bytes: body.len() as i64,
            checksum_sha256: StorageService::calculate_hash(&Bytes::copy_from_slice(body)),
        };
        write_primed_cache_files(storage_root, repo_key, cache_path, Some(body), &metadata);
    }

    /// Write a negative-cache marker (upstream 404, body absent, within its
    /// short TTL) straight to disk so a streaming read sees a `NegativeHit`.
    fn prime_negative_cache_entry(storage_root: &str, repo_key: &str, cache_path: &str) {
        let now = Utc::now();
        let neg_ttl = chrono::Duration::seconds(cache_classifier::NEGATIVE_CACHE_TTL_SECS);
        let metadata = CacheMetadata {
            cached_at: now,
            upstream_etag: None,
            storage_etag: None,
            last_modified: None,
            quarantine_until: None,
            negative_cached_until: Some(now + neg_ttl),
            expires_at: now + neg_ttl,
            content_type: None,
            size_bytes: 0,
            checksum_sha256: String::new(),
        };
        write_primed_cache_files(storage_root, repo_key, cache_path, None, &metadata);
    }

    /// Streaming negative-cache: a primed 404 marker must short-circuit to a
    /// `NotFound` WITHOUT contacting upstream (no mock is mounted, so any
    /// upstream contact 404s on its own — but the key proof is that the marker
    /// is honored at all, which the pre-fix `expires_at`-only gate ignored).
    #[tokio::test]
    async fn test_streaming_honors_negative_cache_without_upstream() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = MockServer::start().await;
        // If the negative cache is honored, upstream is NEVER contacted. Mount a
        // GET that would 200 if (incorrectly) hit, then assert it never fires.
        Mock::given(method("GET"))
            .and(path("/missing"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"should-not-serve".as_ref()))
            .expect(0)
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("strm-neg-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        let repo = wiremock_remote_repo("strm-neg", &server.uri(), tmp.to_str().unwrap());
        prime_negative_cache_entry(tmp.to_str().unwrap(), "strm-neg", "missing");

        let result = proxy.fetch_artifact_streaming(&repo, "missing").await;
        let _ = std::fs::remove_dir_all(&tmp);
        assert!(
            matches!(result, Err(AppError::NotFound(_))),
            "a primed negative-cache marker must 404 from cache, not re-fetch upstream"
        );
    }

    /// Streaming leader negative-caches an upstream 404: a first miss 404s and
    /// records the marker; the second request is served from the negative cache
    /// with upstream contacted only once.
    #[tokio::test]
    async fn test_streaming_leader_negative_caches_404() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/missing"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("strm-leadneg-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        let repo = wiremock_remote_repo("strm-leadneg", &server.uri(), tmp.to_str().unwrap());

        let first = proxy.fetch_artifact_streaming(&repo, "missing").await;
        assert!(
            matches!(first, Err(AppError::NotFound(_))),
            "first streaming miss must 404"
        );

        let second = proxy.fetch_artifact_streaming(&repo, "missing").await;
        let _ = std::fs::remove_dir_all(&tmp);
        assert!(
            matches!(second, Err(AppError::NotFound(_))),
            "second streaming request must be served from the negative cache \
             written by the leader (upstream expect(1))"
        );
    }

    /// Streaming mutable revalidation: a stale mutable entry with an ETag whose
    /// upstream returns 304 must extend the TTL and serve the cached body via a
    /// cheap HEAD — no GET body re-download.
    #[tokio::test]
    async fn test_streaming_mutable_stale_revalidates_304() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = MockServer::start().await;
        // Only a HEAD (the conditional probe) is mounted; a GET would mean a
        // body re-download and fail the test.
        Mock::given(method("HEAD"))
            .and(path("/maven-metadata.xml"))
            .respond_with(ResponseTemplate::new(304))
            .expect(1)
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("strm-304-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        // Maven + maven-metadata.xml classifies Mutable, so a past-TTL entry is
        // Stale and must be conditionally revalidated.
        let repo = wiremock_remote_repo_fmt(
            "strm-304",
            &server.uri(),
            tmp.to_str().unwrap(),
            RepositoryFormat::Maven,
        );
        prime_stale_cache_entry(
            tmp.to_str().unwrap(),
            "strm-304",
            "maven-metadata.xml",
            b"cached-index",
            Some("\"v1\""),
        );

        let result = proxy
            .fetch_artifact_streaming(&repo, "maven-metadata.xml")
            .await
            .expect("304 streaming revalidation must serve the cached body");
        let body = drain_stream(result.body).await;
        let _ = std::fs::remove_dir_all(&tmp);
        assert_eq!(
            &body[..],
            b"cached-index",
            "304 must stream the cached bytes, never a stale-bypass or re-download"
        );
    }

    /// Streaming immutable hit NEVER contacts upstream: a primed fresh immutable
    /// entry is streamed straight from cache with zero upstream contact (no mock
    /// mounted means any contact 404s; `expect(0)` proves none happens).
    #[tokio::test]
    async fn test_streaming_immutable_hit_never_contacts_upstream() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = MockServer::start().await;
        // Any upstream contact at all is a bug for an immutable hit.
        Mock::given(any())
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("strm-imm-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());
        // Maven + a versioned .jar path classifies Immutable.
        let repo = wiremock_remote_repo_fmt(
            "strm-imm",
            &server.uri(),
            tmp.to_str().unwrap(),
            RepositoryFormat::Maven,
        );
        let jar = "com/example/app/1.0.0/app-1.0.0.jar";
        // Prime with a SHORT positive TTL: an `expires_at`-only gate would treat
        // it as expired and re-fetch, but an immutable classification keeps it
        // Fresh forever, so this proves the classifier (not raw expiry) drives
        // the streaming hit.
        prime_fresh_cache_entry(tmp.to_str().unwrap(), "strm-imm", jar, b"jar-bytes", 1);
        // Push past the primed TTL so only the immutable short-circuit can serve.
        std::thread::sleep(std::time::Duration::from_millis(1100));

        let result = proxy
            .fetch_artifact_streaming(&repo, jar)
            .await
            .expect("immutable streaming hit must serve from cache without upstream");
        let body = drain_stream(result.body).await;
        let _ = std::fs::remove_dir_all(&tmp);
        assert_eq!(
            &body[..],
            b"jar-bytes",
            "immutable streaming hit must serve cached bytes with no upstream contact"
        );
    }

    // ---- repo_key_from_cache_key (observability label extraction) ------

    #[test]
    fn test_repo_key_from_cache_key_content_key() {
        assert_eq!(
            repo_key_from_cache_key(
                "proxy-cache/pypi-remote/simple/click/click-8.0.0-py3-none-any.whl/__content__"
            ),
            "pypi-remote"
        );
    }

    #[test]
    fn test_repo_key_from_cache_key_metadata_key() {
        assert_eq!(
            repo_key_from_cache_key(
                "proxy-cache/npm-remote/lodash/-/lodash-4.17.21.tgz/__cache_meta__.json"
            ),
            "npm-remote"
        );
    }

    #[test]
    fn test_repo_key_from_cache_key_handles_dashes_and_underscores() {
        // Repo keys can include hyphens, underscores, and dots per
        // `validate_repository_key`. The split-by-`/` extractor should
        // preserve them verbatim.
        assert_eq!(
            repo_key_from_cache_key("proxy-cache/my_repo-v1.2/a/b/__content__"),
            "my_repo-v1.2"
        );
    }

    #[test]
    fn test_repo_key_from_cache_key_non_proxy_key_fallbacks_to_unknown() {
        // Defensive: if a caller hands us a non-proxy-cache key, the
        // function returns "unknown" instead of panicking so the
        // counter cardinality stays bounded.
        assert_eq!(
            repo_key_from_cache_key("maven/org/example/lib/1.0/lib-1.0.jar"),
            "unknown"
        );
        assert_eq!(repo_key_from_cache_key(""), "unknown");
        assert_eq!(repo_key_from_cache_key("proxy-cache/"), "unknown");
        assert_eq!(repo_key_from_cache_key("proxy-cache//foo"), "unknown");
    }
}
