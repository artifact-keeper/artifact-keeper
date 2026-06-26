//! Shared helpers for remote repository proxying and virtual repository resolution.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use chrono::Utc;
use futures::StreamExt;
use sqlx::PgPool;
use uuid::Uuid;

use crate::api::download_response::try_presigned_redirect;
use crate::api::handlers::error_helpers::map_storage_err;
use crate::api::AppState;
use crate::error::AppError;
use crate::formats::pypi::PypiHandler;
use crate::models::repository::{
    ReplicationPriority, Repository, RepositoryFormat, RepositoryType,
};
use crate::services::proxy_hydration::coordinate_proxy_hydration;
use crate::services::proxy_service::ProxyService;
pub use crate::services::proxy_service::StreamingFetchResult;
use crate::storage::StorageLocation;
use std::future::Future;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Shared RepoInfo
// ---------------------------------------------------------------------------

/// Lightweight repository descriptor returned by [`resolve_repo_by_key`].
///
/// Every format handler needs the same handful of fields after looking up a
/// repository by its key. This struct avoids duplicating the definition in
/// each handler module.
#[derive(Clone)]
pub struct RepoInfo {
    pub id: Uuid,
    pub key: String,
    pub storage_path: String,
    pub storage_backend: String,
    pub repo_type: String,
    pub upstream_url: Option<String>,
    pub promotion_only: bool,
}

impl RepoInfo {
    pub fn storage_location(&self) -> StorageLocation {
        StorageLocation {
            backend: self.storage_backend.clone(),
            path: self.storage_path.clone(),
        }
    }

    /// Reject a direct upload when this repository is flagged `promotion_only`.
    ///
    /// Delegates to [`reject_direct_upload_if_promotion_only`] so that every
    /// format handler enforces the gate identically. There is no admin
    /// exemption (the `is_admin` argument is accepted for signature parity but
    /// has no effect — see [`promotion_only_blocks_direct_upload`]).
    #[allow(clippy::result_large_err)]
    pub fn reject_if_promotion_only(&self, is_admin: bool) -> Result<(), Response> {
        reject_direct_upload_if_promotion_only(self.promotion_only, is_admin)
    }
}

/// Look up a repository by key and verify that its format matches one of the
/// `expected_formats` (compared case-insensitively).
///
/// `format_label` is used only in the error message when the format does not
/// match (e.g. "an Alpine", "a Maven", "an npm").
///
/// Returns a [`RepoInfo`] on success or a plain-text error [`Response`].
#[allow(clippy::result_large_err)]
pub async fn resolve_repo_by_key(
    db: &PgPool,
    repo_key: &str,
    expected_formats: &[&str],
    format_label: &str,
) -> Result<RepoInfo, Response> {
    use sqlx::Row;
    let repo = sqlx::query(
        "SELECT id, key, storage_backend, storage_path, format::text as format, \
         repo_type::text as repo_type, upstream_url, promotion_only \
         FROM repositories WHERE key = $1",
    )
    .bind(repo_key)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Repository not found").into_response())?;

    let fmt: String = repo.try_get("format").unwrap_or_default();
    let fmt_lower = fmt.to_lowercase();
    if !expected_formats.iter().any(|f| *f == fmt_lower) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not {} repository (format: {})",
                repo_key, format_label, fmt
            ),
        )
            .into_response());
    }

    Ok(RepoInfo {
        id: repo.try_get("id").unwrap_or_default(),
        key: repo.try_get("key").unwrap_or_default(),
        storage_path: repo.try_get("storage_path").unwrap_or_default(),
        storage_backend: repo.try_get("storage_backend").unwrap_or_default(),
        repo_type: repo.try_get("repo_type").unwrap_or_default(),
        upstream_url: repo.try_get("upstream_url").ok(),
        promotion_only: repo.try_get("promotion_only").unwrap_or(false),
    })
}

/// Map an error to a 500 Internal Server Error plain-text response.
///
/// The `label` is prepended to the error message (e.g. "Storage", "Database").
/// This avoids repeating the five-line `(StatusCode::INTERNAL_SERVER_ERROR,
/// format!("... error: {}", e)).into_response()` block throughout the
/// local_fetch helpers.
pub(crate) fn internal_error(label: &str, e: impl std::fmt::Display) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("{} error: {}", label, e),
    )
        .into_response()
}

/// Reject write operations (publish/upload) on remote and virtual repositories.
/// Returns 405 Method Not Allowed for remote repos, 400 for virtual repos.
#[allow(clippy::result_large_err)]
pub fn reject_write_if_not_hosted(repo_type: &str) -> Result<(), Response> {
    if repo_type == RepositoryType::Remote {
        Err((
            StatusCode::METHOD_NOT_ALLOWED,
            "Cannot publish to a remote (proxy) repository",
        )
            .into_response())
    } else if repo_type == RepositoryType::Virtual {
        Err((
            StatusCode::BAD_REQUEST,
            "Cannot publish to a virtual repository",
        )
            .into_response())
    } else {
        Ok(())
    }
}

/// Decide whether a direct user upload must be rejected because the target
/// repository is flagged `promotion_only`.
///
/// A `promotion_only` repository rejects direct artifact uploads so that
/// artifacts can only arrive via the promotion path (staging -> promotion ->
/// approval). The promotion service writes through its own RAW SQL INSERT path
/// (handlers/promotion.rs), which does NOT go through the HTTP upload handlers,
/// so promotions are unaffected by this check.
///
/// ALL direct uploads to a `promotion_only` repository are rejected (including
/// admin tokens). Artifacts may only enter such a repository via the promotion
/// workflow (quality gates + approval + provenance); a direct upload would
/// bypass every one of those controls, so there is no admin exemption.
pub fn promotion_only_blocks_direct_upload(promotion_only: bool, _is_admin: bool) -> bool {
    promotion_only
}

/// 409 plain-text response for a rejected direct upload to a `promotion_only`
/// repository. Used by format handlers that return `Response` (e.g. Maven).
#[allow(clippy::result_large_err)]
pub fn reject_direct_upload_if_promotion_only(
    promotion_only: bool,
    is_admin: bool,
) -> Result<(), Response> {
    if promotion_only_blocks_direct_upload(promotion_only, is_admin) {
        Err((
            StatusCode::CONFLICT,
            "Direct uploads are disabled for this repository; publish via promotion",
        )
            .into_response())
    } else {
        Ok(())
    }
}

/// Map a proxy service error to an HTTP error response.
///
/// * `NotFound` → 404 (upstream definitively does not have the artifact)
/// * `Validation` → 400 (path-traversal / boundary check rejected)
/// * `ServiceUnavailable` → 503 (upstream returned 5xx, see #1445 below)
/// * Everything else → 502 (upstream timeouts, TLS errors, auth failures,
///   body read errors, etc.)
///
/// Log-level discipline (#1139): an upstream 404 (`AppError::NotFound`) is
/// **normal proxy traffic**, not a failure of artifact-keeper. Docker / OCI
/// clients routinely probe for tags that do not exist (`:latest` for a project
/// that only publishes versioned tags), and PyPI / npm clients probe optional
/// metadata files (`.metadata`, `.sig`) the same way. Logging those at WARN
/// floods operators with false-positive alerts and reads as "the proxy is
/// broken" when the proxy is in fact doing its job correctly.
///
/// 502 vs 503 split (#1445): upstream 5xx is a transient condition the
/// client should retry against, not a permanent gateway-side error. Mapping
/// raw upstream 502/503/504 to a client-side 502 broke the proxy's
/// "returns 2xx or 503" contract under concurrent load: a single upstream
/// hiccup would surface as 502 to every concurrent caller until the cache
/// filled. Routing the entire 5xx family through 503 lets clients fan-out
/// retries with backoff and keeps a flaky upstream from polluting the
/// proxy's gateway-error metrics.
///
/// * **`NotFound`** is logged at `info` with wording that names the cause
///   (upstream returned 404). Operators triaging "why is my mirror not
///   working" see immediately that the upstream does not have the requested
///   artifact, not that artifact-keeper malfunctioned.
/// * **`Validation`** stays at `warn` because it indicates a malformed path
///   (often a probe / attack attempt the path-traversal guard rejected).
/// * **`ServiceUnavailable`** is logged at `warn` (transient upstream
///   failure that operators may still want to investigate if it persists,
///   but the client gets a retry-friendly status).
/// * **Everything else** (timeouts, TLS errors, auth challenge parse
///   failures, body read errors) stays at `warn` because those genuinely
///   warrant operator attention.
fn map_proxy_error(repo_key: &str, path: &str, e: crate::error::AppError) -> Response {
    match &e {
        crate::error::AppError::NotFound(_) => {
            tracing::info!(
                repo_key = %repo_key,
                path = %path,
                "Upstream returned 404 (artifact or tag does not exist): {}",
                e
            );
            (StatusCode::NOT_FOUND, "Artifact not found upstream").into_response()
        }
        // AppError::Validation here means the request path failed
        // boundary checks (e.g., #1052 path-traversal validator).
        // Surface a generic 400 without echoing the validator's reason
        // string back to the client - those reasons are useful in logs
        // (above) but become a probe oracle if returned to the caller,
        // letting an attacker enumerate which characters/segments are
        // blocked.
        crate::error::AppError::Validation(_) => {
            tracing::warn!(
                repo_key = %repo_key,
                path = %path,
                "Proxy rejected request path: {}",
                e
            );
            (StatusCode::BAD_REQUEST, "Invalid artifact path").into_response()
        }
        // #1445: upstream 5xx folds into 503 here. The handler-side
        // contract is "raw upstream 5xx never leaks to clients"; the
        // mapping at `validate_upstream_status` is the upstream-side
        // half of the contract.
        crate::error::AppError::ServiceUnavailable(_) => {
            tracing::warn!(
                repo_key = %repo_key,
                path = %path,
                "Upstream transient failure (5xx); returning 503: {}",
                e
            );
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Upstream temporarily unavailable; retry shortly",
            )
                .into_response()
        }
        // Package Age Policy (#1770): a quarantine hold is a deliberate
        // 409 Conflict from the proxy read/write gate, NOT an upstream
        // failure. It must surface verbatim to the client rather than folding
        // into the 502 catch-all below (which would mask the policy and, for
        // the cache-miss path, look like a transient upstream error).
        crate::error::AppError::Conflict(msg) => {
            tracing::info!(
                repo_key = %repo_key,
                path = %path,
                "Proxy download blocked by quarantine policy: {}",
                e
            );
            (StatusCode::CONFLICT, msg.clone()).into_response()
        }
        // A rejected artifact (failed review) is a 403 Forbidden from the
        // same quarantine gate; surface it directly for the same reason.
        crate::error::AppError::Authorization(msg) => {
            tracing::info!(
                repo_key = %repo_key,
                path = %path,
                "Proxy download forbidden by quarantine policy: {}",
                e
            );
            (StatusCode::FORBIDDEN, msg.clone()).into_response()
        }
        _ => {
            tracing::warn!(
                repo_key = %repo_key,
                path = %path,
                "Proxy fetch failed: {}",
                e
            );
            (
                StatusCode::BAD_GATEWAY,
                format!("Failed to fetch from upstream: {}", e),
            )
                .into_response()
        }
    }
}

/// Shared scaffolding for the trivial `proxy_fetch*` wrappers.
///
/// Every buffered/uncached wrapper follows the same three-step shape:
/// build a minimal [`Repository`] via [`build_remote_repo`], invoke one
/// `ProxyService` method against it, and translate any [`AppError`] into an
/// HTTP error [`Response`] via [`map_proxy_error`]. This helper performs the
/// build and the error mapping once; the caller supplies the middle step as a
/// closure that receives the constructed `&Repository`.
///
/// The closure is generic over its success type `T` so wrappers returning
/// `(Bytes, Option<String>)`, `(Bytes, Option<String>, String)`, etc. all route
/// through the same code path without behaviour change.
///
/// `error_path` is the value forwarded to [`map_proxy_error`]; callers pass
/// whatever path their original wrapper logged (e.g. `proxy_fetch_with_cache_key`
/// passes its `fetch_path`, not the cache path).
async fn with_proxy_repo<T, F, Fut>(
    repo_id: Uuid,
    repo_key: &str,
    upstream_url: &str,
    error_path: &str,
    fetch: F,
) -> Result<T, Response>
where
    F: FnOnce(Repository) -> Fut,
    Fut: Future<Output = Result<T, AppError>>,
{
    // Construct a minimal Repository that satisfies the ProxyService methods.
    let repo = build_remote_repo(repo_id, repo_key, upstream_url);

    fetch(repo)
        .await
        .map_err(|e| map_proxy_error(repo_key, error_path, e))
}

/// Attempt to fetch an artifact from the upstream via the proxy service.
/// Constructs a minimal `Repository` model from handler-level repo info.
/// Returns `(content_bytes, content_type)` on success.
///
/// **Prefer [`proxy_fetch_streaming`] for large bodies (.deb, .jar, .apk,
/// container blobs, LFS objects).** This buffered variant should only be
/// used when the handler needs to inspect or transform the body in-process
/// before responding to the client — examples include virtual-repo
/// aggregation, JSON metadata rewriting, and content sniffing. Buffering
/// large bodies on a memory-constrained pod (e.g. 1 GiB Kubernetes
/// limit) causes the OOM kills described in #737 / #895.
pub async fn proxy_fetch(
    proxy_service: &ProxyService,
    repo_id: Uuid,
    repo_key: &str,
    upstream_url: &str,
    path: &str,
) -> Result<(Bytes, Option<String>), Response> {
    with_proxy_repo(repo_id, repo_key, upstream_url, path, |repo| async move {
        proxy_service.fetch_artifact(&repo, path).await
    })
    .await
}

/// Variant of [`proxy_fetch`] that forwards an `Accept` header to the upstream.
///
/// Used by OCI manifest GET/HEAD where the upstream registry needs the
/// client's `Accept` to pick the right manifest representation. `accept = None`
/// produces a request identical to [`proxy_fetch`], so blob fetches and other
/// non-negotiated paths can route through this helper without behaviour change.
pub async fn proxy_fetch_with_accept(
    proxy_service: &ProxyService,
    repo_id: Uuid,
    repo_key: &str,
    upstream_url: &str,
    path: &str,
    accept: Option<&str>,
) -> Result<(Bytes, Option<String>), Response> {
    with_proxy_repo(repo_id, repo_key, upstream_url, path, |repo| async move {
        proxy_service
            .fetch_artifact_with_accept(&repo, path, accept)
            .await
    })
    .await
}

/// Streaming sibling of [`proxy_fetch`] that does NOT buffer the artifact
/// body in memory (#895). Returns an axum [`Response`] whose body is a
/// stream the framework drives directly from the upstream HTTP response,
/// teed simultaneously into the proxy cache.
///
/// Format handlers that fetch large binaries (.deb, .rpm, container blobs,
/// .whl) should prefer this over [`proxy_fetch`]. Handlers that fetch
/// small metadata indices (Packages.gz, package.json, etc.) can keep
/// using the buffered path.
///
/// `default_content_type` is the value used for the outbound
/// `Content-Type` header when the upstream response does not carry one
/// (cache hit with empty metadata OR upstream omits the header).
/// Format handlers must supply a value matching client expectations —
/// e.g. Maven `.pom` files need `text/xml`, Go module `.zip` needs
/// `application/zip`, generic binaries get `application/octet-stream`.
/// The buffered [`proxy_fetch`] path historically fell back to format-
/// specific defaults inside each handler; this parameter preserves that
/// behaviour without requiring callers to construct the response builder
/// themselves.
pub async fn proxy_fetch_streaming(
    proxy_service: &ProxyService,
    repo_id: Uuid,
    repo_key: &str,
    upstream_url: &str,
    path: &str,
    default_content_type: &str,
) -> Result<Response, Response> {
    proxy_fetch_streaming_with_disposition(
        proxy_service,
        repo_id,
        repo_key,
        upstream_url,
        path,
        default_content_type,
        None,
    )
    .await
}

/// Streaming sibling of [`proxy_fetch`] that also forwards a
/// `Content-Disposition: attachment; filename="…"` header on the
/// outbound response.
///
/// Same body and cache semantics as [`proxy_fetch_streaming`]; only the
/// outbound response headers differ. Used by [`try_remote_or_virtual_download`]
/// so format handlers that previously buffered via `proxy_fetch` +
/// `build_download_response` keep the attachment filename on the
/// streaming code path (#1215).
pub async fn proxy_fetch_streaming_with_disposition(
    proxy_service: &ProxyService,
    repo_id: Uuid,
    repo_key: &str,
    upstream_url: &str,
    path: &str,
    default_content_type: &str,
    content_disposition_filename: Option<&str>,
) -> Result<Response, Response> {
    let repo = build_remote_repo(repo_id, repo_key, upstream_url);
    let result = proxy_service
        .fetch_artifact_streaming(&repo, path)
        .await
        .map_err(|e| map_proxy_error(repo_key, path, e))?;
    build_streaming_response_with_disposition(
        result,
        default_content_type,
        content_disposition_filename,
    )
    .map_err(|e| {
        map_proxy_error(
            repo_key,
            path,
            crate::error::AppError::Internal(e.to_string()),
        )
    })
}

/// Build the outbound HTTP response from a [`StreamingFetchResult`].
///
/// Sets `Content-Type` from the result's `content_type` field when
/// present, falling back to `default_content_type` otherwise.
/// Sets `Content-Length` only when upstream advertised one; absent
/// length means the outbound response uses chunked transfer encoding.
///
/// Extracted from [`proxy_fetch_streaming`] so the header-building
/// rules can be unit-tested without standing up a live upstream or
/// storage backend. Returns the underlying [`axum::http::Error`] on
/// the rare malformed-header path so the caller can wrap into its
/// own error type.
#[cfg(test)]
pub(crate) fn build_streaming_response(
    result: crate::services::proxy_service::StreamingFetchResult,
    default_content_type: &str,
) -> std::result::Result<Response, axum::http::Error> {
    build_streaming_response_with_disposition(result, default_content_type, None)
}

/// Variant of [`build_streaming_response`] that also sets a
/// `Content-Disposition: attachment; filename="…"` header when
/// `filename` is `Some`.
///
/// Extracted so the buffered [`build_download_response`] / streaming
/// [`proxy_fetch_streaming_with_disposition`] code paths produce
/// equivalent outbound headers — keeping clients that key off the
/// suggested filename (browsers, curl `-OJ`) working when the
/// remote-or-virtual download arm migrates from buffered to streaming
/// (#1215).
pub(crate) fn build_streaming_response_with_disposition(
    result: crate::services::proxy_service::StreamingFetchResult,
    default_content_type: &str,
    filename: Option<&str>,
) -> std::result::Result<Response, axum::http::Error> {
    let mut builder = Response::builder().status(StatusCode::OK).header(
        "content-type",
        result
            .content_type
            .as_deref()
            .unwrap_or(default_content_type),
    );
    if let Some(len) = result.content_length {
        builder = builder.header("content-length", len);
    }
    if let Some(fname) = filename {
        builder = builder.header(
            "content-disposition",
            format!("attachment; filename=\"{}\"", fname),
        );
    }
    let body = axum::body::Body::from_stream(
        result
            .body
            .map(|r| r.map_err(|e| std::io::Error::other(e.to_string()))),
    );
    builder.body(body)
}

/// Handler-facing convenience over [`build_streaming_response_with_disposition`]
/// that maps the rare malformed-header [`axum::http::Error`] into a `500`
/// [`Response`], so format handlers can serve a resolved
/// [`StreamingFetchResult`] (e.g. from [`resolve_virtual_download`]) in a single
/// line instead of re-inlining the same header-building block. Pass a
/// `filename` to emit `Content-Disposition: attachment`; pass `None` to omit it.
#[allow(clippy::result_large_err)]
pub fn stream_fetch_result(
    result: crate::services::proxy_service::StreamingFetchResult,
    default_content_type: &str,
    filename: Option<&str>,
) -> std::result::Result<Response, Response> {
    build_streaming_response_with_disposition(result, default_content_type, filename)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())
}

/// Fetch from upstream via the proxy service, returning a presigned redirect
/// if the storage backend supports it and presigned downloads are enabled.
///
/// When the proxy cache serves a hit and the storage backend supports presigned
/// URLs, this returns a 302 redirect to the presigned URL instead of streaming
/// the full content through the backend. Otherwise it falls back to returning
/// the content bytes.
///
/// Format handlers can use this as a drop-in replacement for [`proxy_fetch`]
/// when they want to take advantage of presigned redirects for cached proxy
/// content.
pub async fn proxy_fetch_or_redirect(
    proxy_service: &ProxyService,
    state: &AppState,
    repo_id: Uuid,
    repo_key: &str,
    upstream_url: &str,
    path: &str,
) -> Result<Response, Response> {
    let cache_key = ProxyService::cache_storage_key(repo_key, path)
        .map_err(|e| map_proxy_error(repo_key, path, e))?;
    let expiry = Duration::from_secs(state.config.presigned_download_expiry_secs);
    let presigned_enabled = state.config.presigned_downloads_enabled;

    // Fast path (#1018): if presigned downloads are enabled and the proxy
    // cache is already fresh, redirect to the signed URL without ever
    // pulling the cached body into the backend's memory. The freshness
    // probe is metadata-only (HEAD-equivalent on cloud backends).
    //
    // #1555: resolve the no-prefix presign handle FIRST and skip the
    // freshness probe entirely if we can't redirect (no handle, or the
    // backend doesn't support redirects). The probe loads the cache-meta
    // sidecar; on a backend that can't presign it would be a pure wasted
    // S3 GET, since the slow path below re-reads the same sidecar anyway.
    if presigned_enabled {
        let storage = proxy_service.cache_storage_backend();
        if storage.supports_redirect() && proxy_service.is_cache_fresh(repo_key, path).await {
            // proxy-cache content is stored without the global key prefix,
            // so it must be signed through the proxy's own (no-prefix)
            // backend, not the prefixed repo handle, or the signed key
            // 404s in the object store.
            if let Some(redirect) = try_proxy_cache_redirect(
                storage.as_ref(),
                &cache_key,
                presigned_enabled,
                expiry,
                /* cache_is_fresh = */ true,
            )
            .await
            {
                return Ok(redirect);
            }
        }
    }

    // Slow path: cache miss / expired / presigned disabled. The fetch
    // populates the proxy cache so a subsequent presigned redirect on the
    // *next* request can take the fast path above.
    let (content, content_type) =
        proxy_fetch(proxy_service, repo_id, repo_key, upstream_url, path).await?;

    // If presigned is configured, prefer redirecting to the just-populated
    // cache entry over streaming the buffered content back to the client.
    if presigned_enabled {
        // #1555: sign the just-populated cache entry through the proxy's
        // no-prefix backend (same handle that wrote it), not the prefixed
        // repo handle. The entry was just written, so treat it as fresh.
        let storage = proxy_service.cache_storage_backend();
        if let Some(redirect) = try_proxy_cache_redirect(
            storage.as_ref(),
            &cache_key,
            presigned_enabled,
            expiry,
            /* cache_is_fresh = */ true,
        )
        .await
        {
            return Ok(redirect);
        }
    }

    let ct = content_type.unwrap_or_else(|| "application/octet-stream".to_string());
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", ct)
        .header("content-length", content.len().to_string())
        .body(axum::body::Body::from(content))
        .unwrap())
}

/// Try to short-circuit a proxy-cache hit into a presigned redirect, without
/// downloading the cached content into memory.
///
/// Returns `Some(Response)` when *all* of:
///   * `presigned_enabled` is true,
///   * `cache_is_fresh` is true (caller has already done a metadata-only
///     freshness check that does not download the object body), and
///   * `try_presigned_redirect` succeeds in producing a signed URL.
///
/// Otherwise returns `None` so the caller falls through to the buffered
/// fetch + cache + serve path.
///
/// Extracted from `proxy_fetch_or_redirect` so the redirect short-circuit can
/// be exercised in unit tests with recording mock storage backends.
///
/// Generic over the facade `storage_service::StorageBackend` trait (#1555):
/// proxy-cache presigns flow through the single no-prefix backend handle, which
/// carries presign capability type-enforced on the facade trait — not a
/// side-channel field. The redirect is built inline (mirroring
/// `try_presigned_redirect`) since that helper is bound to the inner storage
/// trait.
pub(crate) async fn try_proxy_cache_redirect<
    S: crate::services::storage_service::StorageBackend + ?Sized,
>(
    storage: &S,
    cache_key: &str,
    presigned_enabled: bool,
    expiry: Duration,
    cache_is_fresh: bool,
) -> Option<Response> {
    if !presigned_enabled || !cache_is_fresh || !storage.supports_redirect() {
        return None;
    }
    match storage.get_presigned_url(cache_key, expiry).await {
        Ok(Some(presigned)) => {
            tracing::debug!(
                key = %cache_key,
                source = ?presigned.source,
                expiry_secs = expiry.as_secs(),
                "Serving proxy-cache artifact via presigned redirect"
            );
            Some(
                crate::api::download_response::DownloadResponse::redirect(presigned)
                    .into_response(),
            )
        }
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(
                key = %cache_key,
                error = %e,
                "Failed to generate proxy-cache presigned URL, falling back"
            );
            None
        }
    }
}

/// Check whether an artifact is present in the proxy cache under `path`
/// without contacting upstream. Returns `Ok(Some(...))` on cache hit,
/// `Ok(None)` on miss or expired entry.
pub async fn proxy_check_cache(
    proxy_service: &ProxyService,
    repo_key: &str,
    path: &str,
) -> Option<(Bytes, Option<String>)> {
    match proxy_service
        .get_cached_artifact_by_path(repo_key, path)
        .await
    {
        Ok(result) => result,
        Err(e) => {
            tracing::debug!(
                "Cache lookup failed for {}/{}, treating as miss: {}",
                repo_key,
                path,
                e
            );
            None
        }
    }
}

/// Generic helper for remote proxy-backed cache reads.
///
/// Tries `storage.get(storage_key)`. If it returns `AppError::NotFound`, the
/// helper coordinates a single repair attempt per storage key across local
/// waiters and backend instances, then invokes `refetch` only when the file is
/// still absent.
///
/// The refetched bytes are written back to storage via a best-effort `put` so
/// future requests hit the cache. That write-back is intentional: `refetch`
/// updates the shared proxy cache, while this helper repopulates the
/// repo-scoped storage key that the format handler will read on the next
/// request. The hydration coordinator serialises stale-cache recovery so
/// concurrent requests do not all re-download and write back the same object.
///
/// The wait is bounded; if the helper cannot enter the repair window within the
/// timeout it returns `507 Insufficient Storage` so the
/// client can retry later. Non-`NotFound` storage errors are propagated as 500
/// responses so operators still see real backend failures.
pub(crate) async fn get_cached_or_refetch<F, Fut>(
    db: &PgPool,
    artifact_id: Uuid,
    storage: &dyn crate::storage::StorageBackend,
    storage_key: &str,
    refetch: F,
) -> Result<Bytes, Response>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<Bytes, Response>>,
{
    let _ = db;
    let hydration_lease_key = format!("artifact-repair:{}", storage_key);
    coordinate_proxy_hydration(
        &hydration_lease_key,
        || async {
            match storage.get(storage_key).await {
                Ok(content) => Ok(Some(content)),
                Err(AppError::NotFound(_)) => Ok(None),
                Err(e) => Err(map_storage_err(e)),
            }
        },
        || async {
            tracing::warn!(
                artifact_id = %artifact_id,
                storage_key = %storage_key,
                "proxy cache entry is missing on disk; refetching under hydration lease"
            );

            let bytes = refetch().await?;
            if let Err(e) = storage.put(storage_key, bytes.clone()).await {
                tracing::warn!(
                    artifact_id = %artifact_id,
                    storage_key = %storage_key,
                    error = %e,
                    "failed to write back refetched proxy payload; subsequent requests will re-fetch"
                );
            }
            Ok(bytes)
        },
        || {
            (
                StatusCode::INSUFFICIENT_STORAGE,
                "artifact file unavailable; retry later",
            )
                .into_response()
        },
    )
    .await
}

/// Serialise concurrent reads for a locally-stored artifact whose physical
/// file was not found in storage. Retries `storage.get()` under the same
/// in-process hydration coordinator used by proxy cache repair.
///
/// Returns `Ok(bytes)` on success after the retry window; a `507 Insufficient
/// Storage` response when the file is still absent after coordination (another
/// writer should have written it — a client retry is warranted); or propagates
/// non-`NotFound` storage errors as 500.
///
/// This is the local missing-file repair path: when multiple concurrent
/// requests arrive for the same artifact and the file is transiently absent,
/// they queue behind the in-process coordinator rather than all failing
/// simultaneously.
pub(crate) async fn coordinated_retry_get(
    db: &PgPool,
    artifact_id: Uuid,
    storage_key: &str,
    storage: &dyn crate::storage::StorageBackend,
) -> Result<Bytes, Response> {
    let _ = db;
    let hydration_lease_key = format!("artifact-read-retry:{}", storage_key);
    tracing::warn!(
        artifact_id = %artifact_id,
        storage_key = %storage_key,
        "storage miss on local artifact; coordinating re-read"
    );
    coordinate_proxy_hydration(
        &hydration_lease_key,
        || async {
            match storage.get(storage_key).await {
                Ok(bytes) => Ok(Some(bytes)),
                Err(crate::error::AppError::NotFound(_)) => Ok(None),
                Err(e) => Err(map_storage_err(e)),
            }
        },
        || async {
            tracing::error!(
                artifact_id = %artifact_id,
                storage_key = %storage_key,
                "artifact file still absent after coordinated retry; returning 507"
            );
            Err((
                StatusCode::INSUFFICIENT_STORAGE,
                "artifact file unavailable; retry later",
            )
                .into_response())
        },
        || {
            (
                StatusCode::INSUFFICIENT_STORAGE,
                "artifact file unavailable; retry later",
            )
                .into_response()
        },
    )
    .await
}

/// Fetch from upstream using `fetch_path` for the URL but `cache_path` for
/// the proxy cache key. This lets callers store content under a predictable
/// local path even when the upstream download URL varies between requests.
pub async fn proxy_fetch_with_cache_key(
    proxy_service: &ProxyService,
    repo_id: Uuid,
    repo_key: &str,
    upstream_url: &str,
    fetch_path: &str,
    cache_path: &str,
) -> Result<(Bytes, Option<String>), Response> {
    with_proxy_repo(
        repo_id,
        repo_key,
        upstream_url,
        fetch_path,
        |repo| async move {
            proxy_service
                .fetch_artifact_with_cache_path(&repo, fetch_path, cache_path)
                .await
        },
    )
    .await
}

/// Streaming sibling of [`proxy_fetch_with_cache_key`] (#895 OOM relief for
/// format handlers whose upstream download URL differs from the canonical
/// artifact path). Fetches `fetch_path` from the upstream but keys the proxy
/// cache on `cache_path`, returning the body as a [`StreamingFetchResult`]
/// that the caller tees to the client without buffering.
pub async fn proxy_fetch_streaming_with_cache_key(
    proxy_service: &ProxyService,
    repo_id: Uuid,
    repo_key: &str,
    upstream_url: &str,
    fetch_path: &str,
    cache_path: &str,
) -> Result<crate::services::proxy_service::StreamingFetchResult, Response> {
    with_proxy_repo(
        repo_id,
        repo_key,
        upstream_url,
        fetch_path,
        |repo| async move {
            proxy_service
                .fetch_artifact_streaming_with_cache_path(&repo, fetch_path, cache_path)
                .await
        },
    )
    .await
}

/// Streaming sibling of [`proxy_check_cache`]: probe the proxy cache for
/// `cache_path` and stream a hit straight from storage instead of buffering
/// the cached body in memory. Returns `None` on miss or on any probe error
/// (including a negative-cache hit) — best-effort semantics matching the
/// buffered probe, so callers fall through to the full fetch, which
/// re-applies the negative-cache gate itself.
pub async fn proxy_check_cache_streaming(
    proxy_service: &ProxyService,
    repo_id: Uuid,
    repo_key: &str,
    upstream_url: &str,
    cache_path: &str,
) -> Option<crate::services::proxy_service::StreamingFetchResult> {
    let repo = build_remote_repo(repo_id, repo_key, upstream_url);
    match proxy_service
        .streaming_cached_artifact_by_path(&repo, cache_path)
        .await
    {
        Ok(result) => result,
        Err(e) => {
            tracing::debug!(
                "Streaming cache probe failed for {}/{}, treating as miss: {}",
                repo_key,
                cache_path,
                e
            );
            None
        }
    }
}

/// Fetch from upstream directly, bypassing the proxy cache.
///
/// Use this instead of [`proxy_fetch`] when the caller needs the raw upstream
/// response and cannot tolerate locally-transformed cached content (e.g., when
/// parsing download URLs from a PyPI simple index).
/// Returns `(content, content_type, effective_url)`. The effective URL is the
/// final URL after any redirects, which callers can use as a base for resolving
/// relative URLs in the response body.
pub async fn proxy_fetch_uncached(
    proxy_service: &ProxyService,
    repo_id: Uuid,
    repo_key: &str,
    upstream_url: &str,
    path: &str,
) -> Result<(Bytes, Option<String>, String), Response> {
    with_proxy_repo(repo_id, repo_key, upstream_url, path, |repo| async move {
        proxy_service.fetch_upstream_direct(&repo, path).await
    })
    .await
}

/// Fetch from upstream directly, preserving the upstream `Link` header.
pub async fn proxy_fetch_uncached_with_link(
    proxy_service: &ProxyService,
    repo_id: Uuid,
    repo_key: &str,
    upstream_url: &str,
    path: &str,
) -> Result<(Bytes, Option<String>, Option<String>), Response> {
    with_proxy_repo(repo_id, repo_key, upstream_url, path, |repo| async move {
        proxy_service
            .fetch_upstream_direct_with_link(&repo, path)
            .await
    })
    .await
}

/// Strategy for fetching an artifact from a single virtual member.
///
/// Exposed for unit testing the branching logic in
/// [`resolve_virtual_download`] without requiring a live database or
/// proxy service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VirtualMemberFetchStrategy {
    /// Query the `artifacts` table via the caller's `local_fetch` closure.
    ///
    /// Used for Local and Staging members where the database is the
    /// source of truth and no cache TTL applies.
    Local,
    /// Go through `ProxyService` so that `__cache_meta__.json` is
    /// consulted and cache TTL is honoured.
    ///
    /// Used for Remote members. If `proxy_service` is not available or
    /// the member has no `upstream_url`, the member is skipped entirely
    /// (see [`VirtualMemberFetchStrategy::Skip`]).
    Proxy,
    /// Skip this member without attempting any fetch.
    ///
    /// Produced when a Remote member cannot be proxied because either
    /// the shared `ProxyService` is absent or the member has no
    /// upstream URL configured.
    Skip,
}

/// Decide how to fetch an artifact from a single virtual member.
///
/// Returning [`VirtualMemberFetchStrategy::Local`] for Remote members
/// would re-introduce the cache TTL bypass that this function exists to
/// prevent — proxy-cached artifacts are recorded in the `artifacts`
/// table but the generic local fetchers do not consult
/// `__cache_meta__.json`, so serving them as "local" would make the
/// cache effectively immortal.
pub(crate) fn virtual_member_fetch_strategy(
    member_type: &RepositoryType,
    has_proxy_service: bool,
    has_upstream_url: bool,
) -> VirtualMemberFetchStrategy {
    match member_type {
        RepositoryType::Remote => {
            if has_proxy_service && has_upstream_url {
                VirtualMemberFetchStrategy::Proxy
            } else {
                VirtualMemberFetchStrategy::Skip
            }
        }
        // Local, Staging, and (defensively) any other type default to
        // the local DB path. Virtual-as-member is not expected but falls
        // through to Local here rather than causing infinite recursion.
        _ => VirtualMemberFetchStrategy::Local,
    }
}

/// Resolve virtual repository members and attempt to find an artifact.
///
/// Iterates through members in priority order using type-specific fetch
/// strategies (see [`virtual_member_fetch_strategy`]):
///
/// * **Local** / **Staging** members — query the `artifacts` table via
///   `local_fetch` and read from storage. These repositories are the
///   authoritative source for their content and have no TTL concept.
/// * **Remote** members — always go through [`ProxyService`] (never
///   `local_fetch`). `ProxyService` consults the `__cache_meta__.json`
///   sidecar in object storage to decide between serving a cached copy
///   or re-fetching from upstream when the cache has expired.
///
/// Previously, this function called `local_fetch` for every member type —
/// including Remote ones. Because the proxy cache persists an `artifacts`
/// row for each cached object (for listing / quota accounting), the
/// generic `local_fetch_by_*` helpers would happily return cached bytes
/// directly from storage without consulting `__cache_meta__.json`,
/// silently bypassing the cache TTL. This meant that once an artifact
/// was cached on behalf of a virtual repository, subsequent requests
/// never re-validated it against upstream regardless of how much time
/// had passed. Routing Remote members straight through `proxy_fetch`
/// restores the expected TTL semantics.
///
/// `local_fetch` is still invoked for Local / Staging members because
/// those do not have a proxy cache and querying the database is the
/// only way to find their artifacts.
///
/// Returns the first successful result, or `NOT_FOUND` if no member
/// has the artifact.
pub async fn resolve_virtual_download<F, Fut>(
    db: &PgPool,
    proxy_service: Option<&ProxyService>,
    virtual_repo_id: Uuid,
    path: &str,
    local_fetch: F,
) -> Result<StreamingFetchResult, Response>
where
    F: Fn(Uuid, StorageLocation) -> Fut,
    Fut: std::future::Future<Output = Result<StreamingFetchResult, Response>>,
{
    let members = fetch_virtual_members(db, virtual_repo_id).await?;
    resolve_virtual_download_from_members(members, proxy_service, path, local_fetch).await
}

/// Body of [`resolve_virtual_download`] operating over an already-fetched (and,
/// for the #1804 fix, already-authorized) member list. Callers that must filter
/// members by per-member read access (e.g. Virtual repos aggregating private
/// members) fetch the members, run them through
/// [`authorize_virtual_members`], and pass the result here so only members the
/// caller could read directly can ever serve bytes.
pub async fn resolve_virtual_download_from_members<F, Fut>(
    members: Vec<Repository>,
    proxy_service: Option<&ProxyService>,
    path: &str,
    local_fetch: F,
) -> Result<StreamingFetchResult, Response>
where
    F: Fn(Uuid, StorageLocation) -> Fut,
    Fut: std::future::Future<Output = Result<StreamingFetchResult, Response>>,
{
    if members.is_empty() {
        return Err((StatusCode::NOT_FOUND, "Virtual repository has no members").into_response());
    }

    for member in &members {
        let strategy = virtual_member_fetch_strategy(
            &member.repo_type,
            proxy_service.is_some(),
            member.upstream_url.is_some(),
        );

        match strategy {
            VirtualMemberFetchStrategy::Proxy => {
                // Both branches above are guaranteed by `strategy`:
                // proxy_service and upstream_url must be present.
                if let (Some(proxy), Some(upstream_url)) =
                    (proxy_service, member.upstream_url.as_deref())
                {
                    let repo = build_remote_repo(member.id, &member.key, upstream_url);
                    match proxy.fetch_artifact_streaming(&repo, path).await {
                        Ok(result) => return Ok(result),
                        // Package Age Policy (#1770): a quarantine block from a
                        // member is a deliberate 409/403, NOT a "member miss".
                        // Surface it immediately instead of silently trying the
                        // next member (which would mask the policy and 404).
                        Err(e) if is_quarantine_block(&e) => {
                            return Err(map_proxy_error(&member.key, path, e));
                        }
                        Err(_) => { /* genuine miss: try the next member */ }
                    }
                }
            }
            VirtualMemberFetchStrategy::Local => {
                if let Ok(result) = local_fetch(member.id, member.storage_location()).await {
                    return Ok(result);
                }
            }
            VirtualMemberFetchStrategy::Skip => {}
        }
    }

    Err((
        StatusCode::NOT_FOUND,
        "Artifact not found in any member repository",
    )
        .into_response())
}

/// Whether an [`AppError`] from a proxy member fetch is a deliberate Package
/// Age Policy / quarantine block (#1770) — a 409 Conflict (held) or 403
/// Authorization (rejected) — as opposed to an ordinary cache/upstream miss.
/// Such a block must surface from virtual-repo resolution rather than being
/// treated as "try the next member".
fn is_quarantine_block(e: &crate::error::AppError) -> bool {
    matches!(
        e,
        crate::error::AppError::Conflict(_) | crate::error::AppError::Authorization(_)
    )
}

/// `Response`-level sibling of [`is_quarantine_block`] for the streaming
/// virtual-download path, where the member fetch has already mapped its
/// [`AppError`] to a [`Response`] (#1770). A 409 Conflict (held) or 403
/// Forbidden (rejected) is a quarantine block that must surface from
/// virtual-repo resolution rather than fall through to the next member.
fn is_quarantine_block_response(resp: &Response) -> bool {
    matches!(resp.status(), StatusCode::CONFLICT | StatusCode::FORBIDDEN)
}

/// Streaming sibling of [`resolve_virtual_download`] that avoids
/// buffering Remote member responses into memory (#1215). Returns a
/// ready-to-serve [`Response`] whose body is either streamed from the
/// proxy cache / upstream (Remote member) or built from the buffered
/// bytes returned by `local_fetch` (Local / Staging member).
///
/// First-match semantics are preserved: iteration walks members in
/// priority order, and the first member that successfully produces a
/// response wins. Once a Remote member's [`proxy_fetch_streaming_with_disposition`]
/// call returns `Ok`, the outbound response is committed — by then the
/// upstream connection is established and we are already streaming
/// bytes through to the client. A subsequent member can no longer be
/// tried, but that matches the buffered helper's first-success-wins
/// behaviour: it also returned on the first `Ok`.
///
/// Errors during a Remote member's streaming fetch (upstream 404,
/// connection failure, etc.) move on to the next member, exactly as
/// the buffered path did with `proxy_fetch`. Local-member failures
/// (artifact missing on this member) also fall through.
///
/// Caller supplies the per-format `default_content_type` (used when
/// upstream/storage metadata omits it) and an optional `filename` for
/// the `Content-Disposition: attachment` header so the streaming path
/// emits the same outbound headers as the buffered
/// [`build_download_response`] used to.
pub async fn resolve_virtual_download_streaming<F, Fut>(
    state: &AppState,
    proxy_service: Option<&ProxyService>,
    virtual_repo_id: Uuid,
    path: &str,
    default_content_type: &str,
    content_disposition_filename: Option<&str>,
    local_fetch: F,
) -> Result<Response, Response>
where
    F: Fn(Uuid, StorageLocation) -> Fut,
    Fut: std::future::Future<Output = Result<StreamingFetchResult, Response>>,
{
    let members = fetch_virtual_members(&state.db, virtual_repo_id).await?;

    if members.is_empty() {
        return Err((StatusCode::NOT_FOUND, "Virtual repository has no members").into_response());
    }

    for member in &members {
        let strategy = virtual_member_fetch_strategy(
            &member.repo_type,
            proxy_service.is_some(),
            member.upstream_url.is_some(),
        );

        match strategy {
            VirtualMemberFetchStrategy::Proxy => {
                if let (Some(proxy), Some(upstream_url)) =
                    (proxy_service, member.upstream_url.as_deref())
                {
                    // #1555: prefer a presigned S3 redirect for a fresh cache
                    // hit so large artifacts (e.g. torch wheels, multi-GB) are
                    // not streamed through the backend. Streaming holds a
                    // worker thread for the whole transfer; under burst load
                    // that saturates the dispatcher and cascades into 502s.
                    // Mirrors the fast path in `proxy_fetch_or_redirect`.
                    // Falls through to streaming on a cache miss, so the
                    // OOM-avoidance from #1215 still covers uncached bodies.
                    // #1555: resolve the no-prefix presign handle and check
                    // redirect support BEFORE the `is_cache_fresh` probe — the
                    // probe loads the cache-meta sidecar, so skipping it when we
                    // can't redirect avoids a wasted S3 GET on the (common)
                    // cache-miss path that then re-reads the sidecar in the
                    // streaming fallback below.
                    if state.config.presigned_downloads_enabled {
                        let storage = proxy.cache_storage_backend();
                        if let Ok(cache_key) = ProxyService::cache_storage_key(&member.key, path) {
                            if storage.supports_redirect()
                                && proxy.is_cache_fresh(&member.key, path).await
                            {
                                // sign through the proxy's no-prefix backend
                                // (proxy-cache content lives at the storage
                                // root, not under the global key prefix).
                                let expiry = Duration::from_secs(
                                    state.config.presigned_download_expiry_secs,
                                );
                                if let Some(redirect) = try_proxy_cache_redirect(
                                    storage.as_ref(),
                                    &cache_key,
                                    /* presigned_enabled = */ true,
                                    expiry,
                                    /* cache_is_fresh = */ true,
                                )
                                .await
                                {
                                    return Ok(redirect);
                                }
                            }
                        }
                    }

                    match proxy_fetch_streaming_with_disposition(
                        proxy,
                        member.id,
                        &member.key,
                        upstream_url,
                        path,
                        default_content_type,
                        content_disposition_filename,
                    )
                    .await
                    {
                        Ok(response) => return Ok(response),
                        // Package Age Policy (#1770): a member's quarantine
                        // block (409/403, already mapped to a Response) must
                        // surface rather than fall through to the next member.
                        Err(resp) if is_quarantine_block_response(&resp) => return Err(resp),
                        Err(_) => { /* genuine miss: try the next member */ }
                    }
                }
            }
            VirtualMemberFetchStrategy::Local => {
                if let Ok(result) = local_fetch(member.id, member.storage_location()).await {
                    return build_streaming_response_with_disposition(
                        result,
                        default_content_type,
                        content_disposition_filename,
                    )
                    .map_err(|e| {
                        (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
                    });
                }
            }
            VirtualMemberFetchStrategy::Skip => {}
        }
    }

    Err((
        StatusCode::NOT_FOUND,
        "Artifact not found in any member repository",
    )
        .into_response())
}

/// Resolve virtual repository metadata using first-match semantics.
/// Iterates through remote members by priority, fetching metadata from
/// each upstream until one succeeds. The `transform` closure converts
/// the raw bytes into a final HTTP response.
///
/// Suitable for metadata endpoints where only one upstream response is
/// needed (npm package info, pypi simple index, hex package, rubygems gem info).
pub async fn resolve_virtual_metadata<F, Fut>(
    db: &PgPool,
    proxy_service: Option<&ProxyService>,
    virtual_repo_id: Uuid,
    path: &str,
    transform: F,
) -> Result<Response, Response>
where
    F: Fn(Bytes, String) -> Fut,
    Fut: std::future::Future<Output = Result<Response, Response>>,
{
    let members = fetch_virtual_members(db, virtual_repo_id).await?;

    if members.is_empty() {
        return Err((StatusCode::NOT_FOUND, "Virtual repository has no members").into_response());
    }

    for member in &members {
        if member.repo_type != RepositoryType::Remote {
            continue;
        }

        let Some(upstream_url) = member.upstream_url.as_deref() else {
            continue;
        };

        let Some(proxy) = proxy_service else {
            continue;
        };

        match proxy_fetch(proxy, member.id, &member.key, upstream_url, path).await {
            Ok((bytes, _content_type)) => match transform(bytes, member.key.clone()).await {
                Ok(response) => return Ok(response),
                Err(_e) => {
                    tracing::warn!(
                        "Metadata transform failed for member '{}' at path '{}'",
                        member.key,
                        path
                    );
                }
            },
            Err(_e) => {
                tracing::debug!(
                    "Metadata proxy fetch miss for member '{}' at path '{}'",
                    member.key,
                    path
                );
            }
        }
    }

    Err((
        StatusCode::NOT_FOUND,
        "Metadata not found in any member repository",
    )
        .into_response())
}

/// Collect metadata from ALL remote members of a virtual repository.
/// Each member's response is extracted via the `extract` closure and
/// gathered into a `Vec<(repo_key, T)>`. The caller is responsible for
/// merging the collected results.
///
/// Suitable for metadata endpoints where responses from every upstream
/// must be combined (conda repodata, cran PACKAGES, helm index, rubygems specs).
pub async fn collect_virtual_metadata<T, F, Fut>(
    db: &PgPool,
    proxy_service: Option<&ProxyService>,
    virtual_repo_id: Uuid,
    path: &str,
    extract: F,
) -> Result<Vec<(String, T)>, Response>
where
    F: Fn(Bytes, String) -> Fut,
    Fut: std::future::Future<Output = Result<T, Response>>,
{
    let members = fetch_virtual_members(db, virtual_repo_id).await?;
    let mut results: Vec<(String, T)> = Vec::new();

    for member in &members {
        if member.repo_type != RepositoryType::Remote {
            continue;
        }

        let Some(upstream_url) = member.upstream_url.as_deref() else {
            continue;
        };

        let Some(proxy) = proxy_service else {
            continue;
        };

        match proxy_fetch(proxy, member.id, &member.key, upstream_url, path).await {
            Ok((bytes, _content_type)) => match extract(bytes, member.key.clone()).await {
                Ok(data) => {
                    results.push((member.key.clone(), data));
                }
                Err(_e) => {
                    tracing::warn!(
                        "Metadata extract failed for member '{}' at path '{}'",
                        member.key,
                        path
                    );
                }
            },
            Err(_e) => {
                tracing::warn!(
                    "Metadata proxy fetch failed for member '{}' at path '{}'",
                    member.key,
                    path
                );
            }
        }
    }

    Ok(results)
}

/// Fetch virtual repository member repos sorted by priority.
pub async fn fetch_virtual_members(
    db: &PgPool,
    virtual_repo_id: Uuid,
) -> Result<Vec<Repository>, Response> {
    sqlx::query_as!(
        Repository,
        r#"
        SELECT
            r.id, r.key, r.name, r.description,
            r.format as "format: RepositoryFormat",
            r.repo_type as "repo_type: RepositoryType",
            r.storage_backend, r.storage_path, r.upstream_url,
            r.is_public, r.quota_bytes, r.promotion_only,
            r.replication_priority as "replication_priority: ReplicationPriority",
            r.curation_enabled, r.curation_source_repo_id, r.curation_target_repo_id,
            r.curation_default_action, r.curation_sync_interval_secs, r.curation_auto_fetch,
            r.created_at, r.updated_at
        FROM repositories r
        INNER JOIN virtual_repo_members vrm ON r.id = vrm.member_repo_id
        WHERE vrm.virtual_repo_id = $1
        ORDER BY vrm.priority
        "#,
        virtual_repo_id
    )
    .fetch_all(db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to resolve virtual members: {}", e),
        )
            .into_response()
    })
}

/// Decide whether `auth` is allowed to read `member` directly, mirroring the
/// read-access model that [`crate::api::middleware::auth::repo_visibility_middleware`]
/// applies to the URL-named repository.
///
/// Security (#1804): the visibility middleware only authorizes the URL repo. A
/// public Virtual repo therefore became a confused deputy that streamed its
/// PRIVATE members' bytes to anyone allowed to read the virtual. Every member
/// that would actually serve a response must be re-checked against the same
/// model as a direct read so aggregation cannot bypass access control.
///
/// The decision is:
/// * public member → readable by anyone;
/// * otherwise the caller must be authenticated, and either:
///   * an admin, or
///   * pass the API-token repo scope ([`AuthExtension::can_access_repo`]) AND,
///     if fine-grained rules exist for the member, hold the `read` (or `admin`)
///     action on it.
///
/// Callers should treat a denied member as if it did not contain the artifact
/// (continue to the next member / return not-found) so member existence is not
/// leaked through the virtual repo.
pub async fn caller_can_read_member(
    permission_service: &crate::services::permission_service::PermissionService,
    auth: Option<&crate::api::middleware::auth::AuthExtension>,
    member: &Repository,
) -> bool {
    // Public members are readable by everyone, exactly like a direct read of a
    // public repo.
    if member.is_public {
        return true;
    }

    // Private member: anonymous callers can never read it directly.
    let Some(ext) = auth else {
        return false;
    };

    // Admins bypass fine-grained checks, matching the middleware.
    if ext.is_admin {
        return true;
    }

    // API-token repository scope (#504): a token scoped to other repos must not
    // reach this member.
    if !ext.can_access_repo(member.id) {
        return false;
    }

    // Fine-grained repository permissions (#817): if rules exist for the member,
    // the caller must hold the `read` action (or `admin`, which implies it). If
    // no rules exist, the visibility check above (private + authenticated) is
    // the access model. Fail closed on DB errors.
    match permission_service
        .has_any_rules_for_target("repository", member.id)
        .await
    {
        Ok(true) => {
            let read = permission_service
                .check_permission(ext.user_id, "repository", member.id, "read", false)
                .await
                .unwrap_or(false);
            if read {
                return true;
            }
            permission_service
                .check_permission(ext.user_id, "repository", member.id, "admin", false)
                .await
                .unwrap_or(false)
        }
        Ok(false) => true,
        Err(_) => false,
    }
}

/// Filter a virtual repository's members down to those the caller may read
/// directly, preserving priority order. See [`caller_can_read_member`] for the
/// per-member access model and the #1804 confused-deputy background.
pub async fn authorize_virtual_members(
    permission_service: &crate::services::permission_service::PermissionService,
    auth: Option<&crate::api::middleware::auth::AuthExtension>,
    members: Vec<Repository>,
) -> Vec<Repository> {
    let mut allowed = Vec::with_capacity(members.len());
    for member in members {
        if caller_can_read_member(permission_service, auth, &member).await {
            allowed.push(member);
        }
    }
    allowed
}

/// Row type for local artifact fetch queries, including quarantine fields.
#[derive(sqlx::FromRow)]
pub(crate) struct LocalArtifactRow {
    pub id: Uuid,
    pub storage_key: String,
    pub content_type: String,
    pub size_bytes: i64,
    pub quarantine_status: Option<String>,
    pub quarantine_until: Option<chrono::DateTime<chrono::Utc>>,
}

/// Check quarantine status on a fetched artifact row, mapping errors to Response.
#[allow(clippy::result_large_err)]
pub(crate) fn check_quarantine_row(row: &LocalArtifactRow) -> Result<(), Response> {
    crate::services::quarantine_service::check_download_allowed(
        row.quarantine_status.as_deref(),
        row.quarantine_until,
        chrono::Utc::now(),
    )
    .map_err(|e| e.into_response())
}

/// Selector for the canonical local-artifact lookup. Each variant maps to a
/// single `WHERE` shape over the `artifacts` table; the surrounding skeleton
/// (quarantine check → storage resolution → `storage.get` → coordinated retry)
/// is identical and lives in [`local_lookup_artifact`] / [`read_local_content`].
pub(crate) enum LocalLookup<'a> {
    /// Match on the exact stored `path`.
    Path(&'a str),
    /// Match on `name` + `version`.
    NameVersion(&'a str, &'a str),
    /// Match on `name` + `version` constrained to a trailing `path LIKE`
    /// pattern (e.g. `%.zip` vs `%.mod`). Needed by the Go proxy where a
    /// single `(name, version)` pair owns *both* the module `.zip` and the
    /// `.mod` artifact; the bare `NameVersion` lookup would return whichever
    /// row was inserted first, serving go.mod bytes for a `.zip` request.
    NameVersionSuffix(&'a str, &'a str, &'a str),
}

impl LocalLookup<'_> {
    /// The full `SELECT` for this selector. Pure (no I/O) so the per-variant
    /// `WHERE` shape has at-rest unit coverage. The two queries differ only in
    /// the `WHERE` clause and are byte-identical to the original inlined SQL.
    pub(crate) fn select_sql(&self) -> &'static str {
        match self {
            LocalLookup::Path(_) => {
                "SELECT id, storage_key, content_type, size_bytes, quarantine_status, quarantine_until \
                 FROM artifacts \
                 WHERE repository_id = $1 AND path = $2 AND is_deleted = false \
                 LIMIT 1"
            }
            LocalLookup::NameVersion(_, _) => {
                "SELECT id, storage_key, content_type, size_bytes, quarantine_status, quarantine_until \
                 FROM artifacts \
                 WHERE repository_id = $1 AND name = $2 AND version = $3 AND is_deleted = false \
                 LIMIT 1"
            }
            LocalLookup::NameVersionSuffix(_, _, _) => {
                "SELECT id, storage_key, content_type, size_bytes, quarantine_status, quarantine_until \
                 FROM artifacts \
                 WHERE repository_id = $1 AND name = $2 AND version = $3 AND path LIKE $4 AND is_deleted = false \
                 LIMIT 1"
            }
        }
    }

    /// Run the shared row lookup for this selector, mapping a miss to 404 and a
    /// DB error to 500. Behavior is identical across selectors apart from the
    /// `WHERE` clause and its bound parameters.
    async fn fetch_row(&self, db: &PgPool, repo_id: Uuid) -> Result<LocalArtifactRow, Response> {
        let query = sqlx::query_as::<_, LocalArtifactRow>(self.select_sql()).bind(repo_id);
        let query = match self {
            LocalLookup::Path(path) => query.bind(*path),
            LocalLookup::NameVersion(name, version) => query.bind(*name).bind(*version),
            LocalLookup::NameVersionSuffix(name, version, suffix) => {
                query.bind(*name).bind(*version).bind(*suffix)
            }
        };

        query
            .fetch_optional(db)
            .await
            .map_err(|e| internal_error("Database", e))?
            .ok_or_else(|| (StatusCode::NOT_FOUND, "Artifact not found").into_response())
    }
}

/// Shared skeleton step 1: resolve the artifact row for `lookup`, enforce the
/// quarantine policy, and resolve the repo's storage backend. Returns the row
/// and storage so callers can either read bytes or short-circuit (e.g. the
/// presigned redirect in [`local_fetch_or_redirect`]) before reading.
async fn local_lookup_artifact(
    db: &PgPool,
    state: &AppState,
    repo_id: Uuid,
    location: &StorageLocation,
    lookup: LocalLookup<'_>,
) -> Result<
    (
        LocalArtifactRow,
        std::sync::Arc<dyn crate::storage::StorageBackend>,
    ),
    Response,
> {
    let artifact = lookup.fetch_row(db, repo_id).await?;
    check_quarantine_row(&artifact)?;
    let storage = state.storage_for_repo_or_500(location)?;
    Ok((artifact, storage))
}

/// Shared skeleton step 2: read the artifact's content from storage, falling
/// back to the coordinated retry path on a `NotFound` miss.
async fn read_local_content(
    db: &PgPool,
    artifact: &LocalArtifactRow,
    storage: &dyn crate::storage::StorageBackend,
) -> Result<Bytes, Response> {
    match storage.get(&artifact.storage_key).await {
        Ok(bytes) => Ok(bytes),
        Err(crate::error::AppError::NotFound(_)) => {
            coordinated_retry_get(db, artifact.id, &artifact.storage_key, storage).await
        }
        Err(e) => Err(map_storage_err(e)),
    }
}

/// Streaming sibling of [`read_local_content`]: open the artifact body as a
/// byte stream (so large artifact bodies never buffer in memory) while keeping
/// the exact same `NotFound` → coordinated-retry hydration fallback used by the
/// buffered path. On a storage miss we still funnel through
/// [`coordinated_retry_get`] (which buffers the small recovery read) and wrap
/// the recovered `Bytes` back into a one-shot stream so callers see a uniform
/// [`StreamingFetchResult`]. Returns the full [`StreamingFetchResult`] with the
/// row's `content_type` and `size_bytes` (for an accurate `Content-Length`).
async fn read_local_stream(
    db: &PgPool,
    artifact: &LocalArtifactRow,
    storage: &dyn crate::storage::StorageBackend,
) -> Result<StreamingFetchResult, Response> {
    let body = match storage.get_stream(&artifact.storage_key).await {
        Ok(stream) => stream,
        Err(crate::error::AppError::NotFound(_)) => {
            // Hydration recovery is a small buffered read; re-wrap as a stream.
            let bytes =
                coordinated_retry_get(db, artifact.id, &artifact.storage_key, storage).await?;
            Box::pin(futures::stream::once(async move { Ok(bytes) }))
        }
        Err(e) => return Err(map_storage_err(e)),
    };
    Ok(StreamingFetchResult {
        body,
        content_type: Some(artifact.content_type.clone()),
        content_length: Some(artifact.size_bytes as u64),
    })
}

/// Generic local artifact fetch by exact path match.
/// Used as a `local_fetch` callback for [`resolve_virtual_download`].
pub async fn local_fetch_by_path(
    db: &PgPool,
    state: &AppState,
    repo_id: Uuid,
    location: &StorageLocation,
    artifact_path: &str,
) -> Result<StreamingFetchResult, Response> {
    let (artifact, storage) = local_lookup_artifact(
        db,
        state,
        repo_id,
        location,
        LocalLookup::Path(artifact_path),
    )
    .await?;
    read_local_stream(db, &artifact, &*storage).await
}

/// Generic local artifact fetch by name and version.
/// Used as a `local_fetch` callback for [`resolve_virtual_download`].
pub async fn local_fetch_by_name_version(
    db: &PgPool,
    state: &AppState,
    repo_id: Uuid,
    location: &StorageLocation,
    name: &str,
    version: &str,
) -> Result<StreamingFetchResult, Response> {
    let (artifact, storage) = local_lookup_artifact(
        db,
        state,
        repo_id,
        location,
        LocalLookup::NameVersion(name, version),
    )
    .await?;
    read_local_stream(db, &artifact, &*storage).await
}

/// Local artifact fetch by `name` + `version` constrained to a trailing
/// `path LIKE` pattern. Used by the Go proxy's virtual-member fallback so a
/// `.zip` request resolves the module archive and a `.mod` request resolves
/// the go.mod, even though both share the same `(name, version)` coordinates.
pub async fn local_fetch_by_name_version_and_suffix(
    db: &PgPool,
    state: &AppState,
    repo_id: Uuid,
    location: &StorageLocation,
    name: &str,
    version: &str,
    suffix_pattern: &str,
) -> Result<StreamingFetchResult, Response> {
    let (artifact, storage) = local_lookup_artifact(
        db,
        state,
        repo_id,
        location,
        LocalLookup::NameVersionSuffix(name, version, suffix_pattern),
    )
    .await?;
    read_local_stream(db, &artifact, &*storage).await
}

/// Generic local artifact fetch by trailing path-suffix (LIKE match).
/// Used for handlers like npm that query by filename suffix.
///
/// Preserves the original suffix-LIKE semantic (`path LIKE '%/' || $2`)
/// but rewrites it to a *left-anchored* LIKE on `reverse(path)`, which
/// the functional index `idx_artifacts_repo_reverse_path` (added in
/// migration `108_artifacts_filename_index.sql`) can serve as an
/// index-only scan. See #1266 for the prod logs that motivated the
/// rewrite — the original leading-wildcard form was un-indexable and
/// seq-scanned the whole repo (3-6 s per call on populated tables).
///
/// The path-suffix is reversed in Rust BEFORE the LIKE-metachar
/// escape so the resulting escape character (backslash) sits ahead of
/// the metachar in the reversed pattern, which is the correct shape
/// for Postgres's `ESCAPE '\\'` semantics. Reversing AFTER escaping
/// would put the backslash on the wrong side of the metachar.
pub async fn local_fetch_by_path_suffix(
    db: &PgPool,
    state: &AppState,
    repo_id: Uuid,
    location: &StorageLocation,
    path_suffix: &str,
) -> Result<StreamingFetchResult, Response> {
    let reversed_pattern = reverse_suffix_for_like(path_suffix);
    let path: String = sqlx::query_scalar(
        "SELECT path FROM artifacts \
         WHERE repository_id = $1 \
           AND reverse(path) LIKE $2 || '%' ESCAPE '\\' \
           AND is_deleted = false \
         LIMIT 1",
    )
    .bind(repo_id)
    .bind(&reversed_pattern)
    .fetch_optional(db)
    .await
    .map_err(|e| internal_error("Database", e))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Artifact not found").into_response())?;

    local_fetch_by_path(db, state, repo_id, location, &path).await
}

/// Variant of [`local_fetch_by_path_suffix`] that issues a presigned S3
/// redirect instead of streaming when `state.config.presigned_downloads_enabled`
/// is set (#1555). The suffix→path resolution is identical; only the response
/// shape differs: a 307 redirect for S3-backed artifacts, or streaming when the
/// storage backend does not support presigning.
///
/// Used by the PyPI virtual-download path (`pypi.rs::serve_file`) which has its
/// own member-iteration loop and could not share the generic
/// `resolve_virtual_download_streaming` fix.
pub async fn local_fetch_or_redirect_by_suffix(
    db: &PgPool,
    state: &AppState,
    repo_id: Uuid,
    location: &StorageLocation,
    path_suffix: &str,
) -> Result<Response, Response> {
    let reversed_pattern = reverse_suffix_for_like(path_suffix);
    let path: String = sqlx::query_scalar(
        "SELECT path FROM artifacts \
         WHERE repository_id = $1 \
           AND reverse(path) LIKE $2 || '%' ESCAPE '\\' \
           AND is_deleted = false \
         LIMIT 1",
    )
    .bind(repo_id)
    .bind(&reversed_pattern)
    .fetch_optional(db)
    .await
    .map_err(|e| internal_error("Database", e))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Artifact not found").into_response())?;

    local_fetch_or_redirect(db, state, repo_id, location, &path).await
}

/// Build the reversed-+-escaped LIKE prefix for a path-suffix query
/// against the functional `reverse(path) text_pattern_ops` index.
///
/// Given `path_suffix = "pkg-1.0.0.tgz"`, returns the reversed form
/// of `/pkg-1.0.0.tgz` with any `%` / `_` / `\` characters escaped so
/// they match literally under `ESCAPE '\\'`. The leading `/` is part
/// of the original suffix-LIKE's semantic ("path ends with `/<X>`")
/// and is preserved in the reversed pattern.
///
/// Reverse-then-escape (not escape-then-reverse) is deliberate: the
/// escape char (`\`) must end up ON THE LEFT of the special char in
/// the reversed string so Postgres recognises it as an escape; doing
/// it the other way puts the `\` on the wrong side and the special
/// char would still be treated as a wildcard.
fn reverse_suffix_for_like(path_suffix: &str) -> String {
    let mut with_slash = String::with_capacity(path_suffix.len() + 1);
    with_slash.push('/');
    with_slash.push_str(path_suffix);
    let reversed: String = with_slash.chars().rev().collect();
    super::escape_like_literal(&reversed)
}

/// Look up a local artifact by path and return a presigned redirect if the
/// storage backend supports it and the feature is enabled. Falls back to
/// streaming the content bytes when redirect is not possible.
///
/// This is meant for format handlers that serve stored artifacts and want to
/// opt in to presigned download redirects without restructuring their logic.
pub async fn local_fetch_or_redirect(
    db: &PgPool,
    state: &AppState,
    repo_id: Uuid,
    location: &StorageLocation,
    artifact_path: &str,
) -> Result<Response, Response> {
    let (artifact, storage) = local_lookup_artifact(
        db,
        state,
        repo_id,
        location,
        LocalLookup::Path(artifact_path),
    )
    .await?;

    // Try presigned redirect before reading content into memory
    if state.config.presigned_downloads_enabled {
        let expiry = Duration::from_secs(state.config.presigned_download_expiry_secs);
        // #1555: proxy-cache content (remote members) lives at the storage root
        // with no key prefix, so it must be signed through the proxy's own
        // no-prefix backend. Hosted artifacts are content-addressed under the
        // global prefix and sign correctly via the repo handle — only switch
        // handles for proxy-cache keys.
        //
        // The two handles live on different traits (the proxy's no-prefix
        // backend is the facade `storage_service::StorageBackend`; the repo
        // handle is the inner `crate::storage::StorageBackend`), so branch on
        // the key shape rather than coercing both into one trait object.
        let proxy_cache_backend = if ProxyService::is_proxy_cache_key(&artifact.storage_key) {
            state
                .proxy_service
                .as_deref()
                .map(|p| p.cache_storage_backend())
        } else {
            None
        };
        let redirect = match &proxy_cache_backend {
            Some(b) => {
                try_proxy_cache_redirect(
                    b.as_ref(),
                    &artifact.storage_key,
                    /* presigned_enabled = */ true,
                    expiry,
                    /* cache_is_fresh = */ true,
                )
                .await
            }
            None => {
                try_presigned_redirect(storage.as_ref(), &artifact.storage_key, true, expiry).await
            }
        };
        if let Some(redirect) = redirect {
            return Ok(redirect);
        }
    }

    let content = read_local_content(db, &artifact, &*storage).await?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", &artifact.content_type)
        .header("content-length", content.len().to_string())
        .body(axum::body::Body::from(content))
        .unwrap())
}

// ---------------------------------------------------------------------------
// Shared remote/virtual download fallback
// ---------------------------------------------------------------------------

/// Strategy for resolving the artifact within a virtual repository's members.
/// Mirrors the two `local_fetch_*` shapes used by format handlers when the
/// canonical local lookup misses.
pub enum VirtualLookup<'a> {
    /// Look up artifacts by trailing path suffix (LIKE `%/<filename>`).
    /// Used for handlers keyed by filename (helm, ansible, puppet, cran, hex,
    /// rubygems, rpm). The suffix is escaped internally.
    PathSuffix(&'a str),
    /// Look up artifacts by exact stored path. Used for handlers keyed by
    /// model_id/revision/filename (huggingface).
    ExactPath(&'a str),
}

/// Options controlling response shape from [`try_remote_or_virtual_download`].
pub struct DownloadResponseOpts<'a> {
    /// Upstream path requested from a Remote repo and/or used as the proxy
    /// cache key for Virtual members.
    pub upstream_path: &'a str,
    /// How to look up the artifact inside virtual member repositories.
    pub virtual_lookup: VirtualLookup<'a>,
    /// Default `Content-Type` if the proxied content type is missing.
    pub default_content_type: &'a str,
    /// Filename to include in the `Content-Disposition: attachment` header.
    /// `None` omits the header.
    pub content_disposition_filename: Option<&'a str>,
    /// Block Remote members of a Virtual repo from satisfying this download.
    ///
    /// When `true`, `try_remote_or_virtual_download` passes `proxy_service:
    /// None` through to [`resolve_virtual_download`], which causes
    /// [`virtual_member_fetch_strategy`] to return `Skip` for every Remote
    /// member. This is the supply-chain name-shadowing guard from #1217 /
    /// PR #974: a Virtual member that owns a given package name locally
    /// must shadow any upstream Remote member that claims the same name.
    /// Format handlers compute this flag by combining a per-format
    /// filename-to-package-name parser with [`virtual_non_remote_owns_name`].
    ///
    /// Has no effect for Remote or hosted repos; only Virtual repos
    /// consult this field.
    pub suppress_upstream_proxy: bool,
}

impl<'a> DownloadResponseOpts<'a> {
    /// Convenience constructor: build options for a download that does NOT
    /// activate the cross-format shadowing guard. Equivalent to setting
    /// `suppress_upstream_proxy: false`. Use this for paths that have no
    /// format-specific package name to gate on (eg. raw metadata files).
    pub fn new(
        upstream_path: &'a str,
        virtual_lookup: VirtualLookup<'a>,
        default_content_type: &'a str,
        content_disposition_filename: Option<&'a str>,
    ) -> Self {
        Self {
            upstream_path,
            virtual_lookup,
            default_content_type,
            content_disposition_filename,
            suppress_upstream_proxy: false,
        }
    }
}

/// Classification of the action [`try_remote_or_virtual_download`] should
/// take based on a repository's type. Used purely as a testable splitter so
/// the async helper's branching logic has at-rest unit coverage.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RemoteOrVirtualAction {
    /// Repository is `Remote`: caller should attempt an upstream proxy fetch.
    Remote,
    /// Repository is `Virtual`: caller should iterate members.
    Virtual,
    /// Repository is `Local`/`Staging`/anything else: caller should fall
    /// through to its own NOT_FOUND.
    Hosted,
}

/// Pure classifier for the `repo_type` branch in [`try_remote_or_virtual_download`].
/// Extracted so the otherwise-async helper has unit-test coverage on its
/// decision logic without needing a database or proxy service.
pub(crate) fn classify_remote_or_virtual(repo_type: &str) -> RemoteOrVirtualAction {
    if repo_type == RepositoryType::Remote {
        RemoteOrVirtualAction::Remote
    } else if repo_type == RepositoryType::Virtual {
        RemoteOrVirtualAction::Virtual
    } else {
        RemoteOrVirtualAction::Hosted
    }
}

/// Returns true if any non-Remote member of `virtual_repo_id` owns an
/// artifact whose `name` case-insensitively matches `package_name`.
///
/// This is the cross-format primitive behind the supply-chain
/// name-shadowing guard introduced for hex in PR #1217 and extended to
/// cargo / npm / pypi / maven / rubygems by the audit follow-up
/// (ak-hv3s). When this returns true, the caller must block any Remote
/// member of the same Virtual repo from satisfying the download for
/// `package_name`. Otherwise a malicious upstream that pushes a
/// package whose name an operator has already published locally would
/// shadow the operator's intended artifact.
///
/// Callers wire this into [`DownloadResponseOpts::suppress_upstream_proxy`]
/// so the existing `try_remote_or_virtual_download` plumbing can act on
/// the result without each format handler having to call
/// [`resolve_virtual_download`] with an explicit `None` proxy.
///
/// The query is a single round trip across every non-Remote member id
/// using `repository_id = ANY($1)` and a `LIMIT 1` short-circuit. It is
/// sargable against the functional `idx_artifacts_repo_lower_name`
/// partial index added by migration 106 (ak-wgzr). The `is_deleted =
/// false` predicate matches the partial-index WHERE clause exactly so
/// the planner uses the index.
///
/// Fails closed: a database error returns 500 rather than allowing the
/// caller to proceed without the guard. Returns false (allow proxy
/// fan-out) on the benign "no non-Remote members" case so virtual repos
/// that contain only upstream proxies behave exactly as they did
/// before this guard existed.
#[allow(clippy::result_large_err)]
pub async fn virtual_non_remote_owns_name(
    db: &PgPool,
    virtual_repo_id: Uuid,
    package_name: &str,
) -> Result<bool, Response> {
    virtual_non_remote_owns_name_version(db, virtual_repo_id, package_name, None).await
}

/// Version-aware variant of [`virtual_non_remote_owns_name`]. When `version`
/// is `Some`, the guard fires if a local member owns a PEP 440-equal version
/// (`PypiHandler::canonical_version`), so `1.0`/`1.0.0` still match. The guard
/// is fail-safe: `version = None`, or a requested version that cannot be
/// canonicalized, falls back to name-only suppression (any local version of the
/// name suppresses the proxy) rather than allowing fan-out.
pub async fn virtual_non_remote_owns_name_version(
    db: &PgPool,
    virtual_repo_id: Uuid,
    package_name: &str,
    version: Option<&str>,
) -> Result<bool, Response> {
    let members = fetch_virtual_members(db, virtual_repo_id).await?;
    let non_remote_ids: Vec<Uuid> = members
        .iter()
        .filter(|m| m.repo_type != RepositoryType::Remote)
        .map(|m| m.id)
        .collect();

    if non_remote_ids.is_empty() {
        return Ok(false);
    }

    // Name-only fallback (original behaviour): any local version of the name
    // suppresses the proxy. Single round trip with a LIMIT 1 short-circuit.
    let Some(version) = version else {
        let exists = sqlx::query(
            "SELECT 1 FROM artifacts \
             WHERE repository_id = ANY($1) \
               AND is_deleted = false \
               AND LOWER(name) = LOWER($2) \
             LIMIT 1",
        )
        .bind(&non_remote_ids)
        .bind(package_name)
        .fetch_optional(db)
        .await
        .map_err(|e| shadowing_guard_db_err(virtual_repo_id, e))?;
        return Ok(exists.is_some());
    };

    // Version-aware path. The requested version is parsed from the filename
    // while `artifacts.version` is the upload-metadata version, and neither is
    // PEP 440-canonical for legacy rows, so exact SQL equality both leaks
    // (false negative) and 404s (false positive). Compare canonically in Rust:
    // fetch the local versions for this name and match `1.0`==`1.0.0` etc.
    let stored_versions: Vec<String> = sqlx::query_scalar(
        "SELECT version FROM artifacts \
         WHERE repository_id = ANY($1) \
           AND is_deleted = false \
           AND LOWER(name) = LOWER($2) \
           AND version IS NOT NULL",
    )
    .bind(&non_remote_ids)
    .bind(package_name)
    .fetch_all(db)
    .await
    .map_err(|e| shadowing_guard_db_err(virtual_repo_id, e))?;

    Ok(pypi_version_owned(version, &stored_versions))
}

/// Decide whether `requested` matches any of the locally-owned `stored`
/// versions for the shadowing guard.
///
/// Fail-safe: when `requested` cannot be confidently canonicalized (e.g. a
/// PEP 427 filename-escaped local segment that drops the `+`, yielding
/// `1.2.3_gitsha`), we cannot prove it differs from the locally-owned versions,
/// so we treat the name as owned (suppress the proxy) rather than allowing
/// fan-out. Allowing fan-out for a locally-owned name+version is the
/// dependency-confusion hole. When both sides canonicalize we compare by PEP 440
/// equality; an unparseable stored row falls back to exact case-insensitive
/// match.
fn pypi_version_owned(requested: &str, stored_versions: &[String]) -> bool {
    let Some(requested_canon) = PypiHandler::canonical_version(requested) else {
        return true;
    };

    stored_versions
        .iter()
        .any(|stored| match PypiHandler::canonical_version(stored) {
            Some(s) => requested_canon == s,
            None => stored.eq_ignore_ascii_case(requested),
        })
}

fn shadowing_guard_db_err(virtual_repo_id: Uuid, e: sqlx::Error) -> Response {
    tracing::error!(
        event = "shadowing_guard_db_error",
        virtual_repo_id = %virtual_repo_id,
        error = %e,
        "cross-format shadowing-guard DB query failed; failing closed to 500",
    );
    (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response()
}

/// PEP 708 dependency-confusion decision for a PyPI virtual repository (#1600).
///
/// Returns `true` when the virtual must ISOLATE this project name to its local
/// owner: a local/staging member owns the PEP 503 normalized `normalized_name`
/// AND no `pypi_project_tracks` declaration exists on an owning member for it.
/// When `true`, the caller MUST serve only the owning member's distributions in
/// both the simple index and the file download (no cross-member union, no
/// proxy fallthrough), which is PEP 708's "refuse to implicitly assume merging
/// is safe" default and keeps the index and download consistent.
///
/// Returns `false` when the name is not locally owned (proxy normally) or when
/// an operator `tracks` declaration permits merging the same project across
/// members (the #1267 union / #1584 version fallthrough then apply).
///
/// `normalized_name` must already be PEP 503 normalized; the ownership query
/// uses the same normalization the simple index uses so the two agree.
/// Fails closed (Err 500) on DB error.
#[allow(clippy::result_large_err)]
pub async fn pypi_virtual_isolates_name(
    db: &PgPool,
    virtual_repo_id: Uuid,
    normalized_name: &str,
) -> Result<bool, Response> {
    let members = fetch_virtual_members(db, virtual_repo_id).await?;
    let local_ids: Vec<Uuid> = members
        .iter()
        .filter(|m| m.repo_type == RepositoryType::Local || m.repo_type == RepositoryType::Staging)
        .map(|m| m.id)
        .collect();
    if local_ids.is_empty() {
        return Ok(false);
    }

    // Which local/staging members actually own (hold artifacts for) this name?
    // Uses the same PEP 503 normalization as simple_project so isolation agrees
    // with what the index lists.
    let owning_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT repository_id FROM artifacts \
         WHERE repository_id = ANY($1) \
           AND is_deleted = false \
           AND LOWER(REPLACE(REPLACE(REPLACE(name, '_', '-'), '.', '-'), '--', '-')) = $2",
    )
    .bind(&local_ids)
    .bind(normalized_name)
    .fetch_all(db)
    .await
    .map_err(|e| shadowing_guard_db_err(virtual_repo_id, e))?;

    if owning_ids.is_empty() {
        // Name is not owned by any local member: no confusion risk, proxy normally.
        return Ok(false);
    }

    // A `tracks` declaration on any owning member means the operator has
    // asserted the local project is the same project as upstream, so merging is
    // safe and we do NOT isolate.
    let tracked: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pypi_project_tracks \
         WHERE repository_id = ANY($1) AND normalized_name = $2",
    )
    .bind(&owning_ids)
    .bind(normalized_name)
    .fetch_one(db)
    .await
    .map_err(|e| shadowing_guard_db_err(virtual_repo_id, e))?;

    Ok(tracked == 0)
}

/// Returns true if any non-Remote member of `virtual_repo_id` owns an
/// artifact stored at exactly `path`.
///
/// This is the exact-path analogue of [`virtual_non_remote_owns_name`],
/// used by the generic-format virtual download path (`download_artifact`)
/// where there is no format-specific package-name parser to feed the
/// name-based guard. The generic format keys purely on the stored
/// `artifacts.path` (e.g. `shadowpkg/1.0.0/shadowpkg-1.0.0.bin`), so the
/// shadowing guard must match the same way.
///
/// When this returns true the caller must Skip every Remote member of the
/// virtual repo for this download (by passing `proxy_service: None` to
/// [`resolve_virtual_download`]). Otherwise a Remote member that returns a
/// 200 for the same path (a catch-all upstream, or one that genuinely hosts
/// a different object at that path) would shadow the local member that
/// actually owns the artifact: the iteration returns the first `Ok`, and a
/// Remote member earlier in priority order would win with the wrong (or
/// empty) bytes (B9).
///
/// Fails closed on DB error (matches [`virtual_non_remote_owns_name`]).
/// Returns false on the benign "no non-Remote members" case so virtual repos
/// that contain only upstream proxies behave exactly as before.
#[allow(clippy::result_large_err)]
pub async fn virtual_non_remote_owns_path(
    db: &PgPool,
    virtual_repo_id: Uuid,
    path: &str,
) -> Result<bool, Response> {
    let members = fetch_virtual_members(db, virtual_repo_id).await?;
    let non_remote_ids: Vec<Uuid> = members
        .iter()
        .filter(|m| m.repo_type != RepositoryType::Remote)
        .map(|m| m.id)
        .collect();

    if non_remote_ids.is_empty() {
        return Ok(false);
    }

    let exists = sqlx::query(
        "SELECT 1 FROM artifacts \
                              WHERE repository_id = ANY($1) \
                                AND is_deleted = false \
                                AND path = $2 \
                              LIMIT 1",
    )
    .bind(&non_remote_ids)
    .bind(path)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        tracing::error!(
            event = "shadowing_guard_db_error",
            virtual_repo_id = %virtual_repo_id,
            format = "generic",
            error = %e,
            "generic exact-path shadowing-guard DB query failed; failing closed to 500",
        );
        (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response()
    })?;

    Ok(exists.is_some())
}

/// Build the SQL `LIKE` pattern that matches every artifact path under
/// a given Maven `groupId/artifactId/` directory.
///
/// Pure helper extracted so the prefix construction has unit-test
/// coverage without a database. Returns `<group-path>/<artifactId>/%`,
/// where the dot-to-slash conversion runs before LIKE-escaping so
/// directory separators in the groupId are preserved, and `%`/`_`/`\`
/// inside either input become literal characters. Use with
/// `LIKE ... ESCAPE '\'`.
pub(crate) fn maven_ga_like_pattern(group_id: &str, artifact_id: &str) -> String {
    let group_path = group_id.replace('.', "/");
    let mut prefix = String::with_capacity(group_path.len() + artifact_id.len() + 3);
    prefix.push_str(&super::escape_like_literal(&group_path));
    prefix.push('/');
    prefix.push_str(&super::escape_like_literal(artifact_id));
    prefix.push('/');
    prefix.push('%');
    prefix
}

/// Maven-aware shadowing guard: returns true if any non-Remote member of
/// `virtual_repo_id` owns an artifact under the same groupId + artifactId
/// directory prefix.
///
/// The generic [`virtual_non_remote_owns_name`] matches by `artifacts.name`
/// alone, which for Maven is the artifactId component of the GAV. Two
/// distinct Maven coordinates that happen to share an artifactId (eg.
/// `com.foo:bar:1.0` vs. `com.baz:bar:1.0`) collide under the generic
/// guard, suppressing legitimate remote resolution for any sibling
/// groupId (#1287). Matching on the full groupId/artifactId path prefix
/// instead means a local `com/example/mylib/common/...` artifact no
/// longer shadows a remote `com/android/tools/common/...` lookup.
///
/// `group_path` must be the dot-replaced groupId (`com.foo` ->
/// `com/foo`); the function appends `/<artifact_id>/` and runs a
/// `path LIKE` against `artifacts.path`. The prefix is escaped to
/// neutralise `%` / `_` / `\` so a crafted artifactId cannot widen the
/// match. Uses the `(repository_id, path)` btree (`idx_artifacts_repo_path`).
///
/// Fails closed on DB error (matches `virtual_non_remote_owns_name`).
#[allow(clippy::result_large_err)]
pub async fn virtual_non_remote_owns_maven_ga(
    db: &PgPool,
    virtual_repo_id: Uuid,
    group_id: &str,
    artifact_id: &str,
) -> Result<bool, Response> {
    let members = fetch_virtual_members(db, virtual_repo_id).await?;
    let non_remote_ids: Vec<Uuid> = members
        .iter()
        .filter(|m| m.repo_type != RepositoryType::Remote)
        .map(|m| m.id)
        .collect();

    if non_remote_ids.is_empty() {
        return Ok(false);
    }

    let prefix = maven_ga_like_pattern(group_id, artifact_id);

    let exists = sqlx::query(
        "SELECT 1 FROM artifacts \
                              WHERE repository_id = ANY($1) \
                                AND is_deleted = false \
                                AND path LIKE $2 ESCAPE '\\' \
                              LIMIT 1",
    )
    .bind(&non_remote_ids)
    .bind(&prefix)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        tracing::error!(
            event = "shadowing_guard_db_error",
            virtual_repo_id = %virtual_repo_id,
            format = "maven",
            error = %e,
            "Maven shadowing-guard DB query failed; failing closed to 500",
        );
        (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response()
    })?;

    Ok(exists.is_some())
}

/// Try the proxy and virtual fallbacks for a download miss.
///
/// Returns `Ok(Some(response))` if the artifact was served from upstream
/// (Remote) or a virtual member (Virtual), `Ok(None)` if the repo is hosted
/// (the caller should propagate its own NOT_FOUND), or `Err(response)` if
/// upstream fetch failed.
///
/// This consolidates the "miss path" of every format-handler download:
/// Remote → `proxy_fetch_streaming_with_disposition` + serve, Virtual →
/// `resolve_virtual_download_streaming` + serve. Each handler's only
/// remaining variation is the upstream URL prefix, the content type
/// defaults, and whether to include a filename in the
/// `Content-Disposition` header.
///
/// Both arms stream the upstream response body through to the client
/// without buffering it in memory (#1215). The previous implementation
/// used the buffered `proxy_fetch` helper, which loaded the entire
/// artifact body (up to gigabytes for some package formats) into
/// memory before responding — see #895 / #737 for the OOM-kill history
/// that prompted the streaming migration.
pub async fn try_remote_or_virtual_download(
    state: &crate::api::SharedState,
    repo: &RepoInfo,
    opts: DownloadResponseOpts<'_>,
) -> Result<Option<Response>, Response> {
    if classify_remote_or_virtual(&repo.repo_type) == RemoteOrVirtualAction::Remote {
        let Some(upstream_url) = repo.upstream_url.as_deref() else {
            return Ok(None);
        };
        let Some(proxy) = state.proxy_service.as_deref() else {
            return Ok(None);
        };

        // #1215: stream the remote response body instead of buffering it.
        // The buffered `proxy_fetch` helper used here previously was the
        // last large-body caller for rpm / rubygems / puppet / hex /
        // huggingface / cran / ansible downloads; routing through
        // `proxy_helpers::proxy_fetch_streaming(` removes that buffering.
        let response = proxy_fetch_streaming_with_disposition(
            proxy,
            repo.id,
            &repo.key,
            upstream_url,
            opts.upstream_path,
            opts.default_content_type,
            opts.content_disposition_filename,
        )
        .await?;
        return Ok(Some(response));
    }

    if classify_remote_or_virtual(&repo.repo_type) == RemoteOrVirtualAction::Virtual {
        let db = state.db.clone();
        // Shadowing guard: when the caller already determined that a
        // non-Remote member of this virtual repo owns the requested
        // package name, blank out the proxy service so Remote members are
        // Skip'd by `virtual_member_fetch_strategy`. The `None` argument
        // is load-bearing: see the comment on `DownloadResponseOpts::
        // suppress_upstream_proxy` and on `serve_virtual_tarball_local_only`
        // in api/handlers/hex.rs for the security rationale.
        let proxy_for_virtual = if opts.suppress_upstream_proxy {
            None
        } else {
            state.proxy_service.as_deref()
        };
        // #1215: route Virtual-member Remote fetches through the
        // streaming resolver so Virtual repos benefit from the same
        // OOM-avoidance work landed for direct Remote downloads in
        // #895 / #1181 / #1294.
        let response = match opts.virtual_lookup {
            VirtualLookup::PathSuffix(suffix) => {
                let suffix = suffix.to_string();
                let state_arc = state.clone();
                resolve_virtual_download_streaming(
                    state,
                    proxy_for_virtual,
                    repo.id,
                    opts.upstream_path,
                    opts.default_content_type,
                    opts.content_disposition_filename,
                    move |member_id, location| {
                        let db = db.clone();
                        let state = state_arc.clone();
                        let suffix = suffix.clone();
                        async move {
                            local_fetch_by_path_suffix(&db, &state, member_id, &location, &suffix)
                                .await
                        }
                    },
                )
                .await?
            }
            VirtualLookup::ExactPath(path) => {
                let path = path.to_string();
                let state_arc = state.clone();
                resolve_virtual_download_streaming(
                    state,
                    proxy_for_virtual,
                    repo.id,
                    opts.upstream_path,
                    opts.default_content_type,
                    opts.content_disposition_filename,
                    move |member_id, location| {
                        let db = db.clone();
                        let state = state_arc.clone();
                        let path = path.clone();
                        async move {
                            local_fetch_by_path(&db, &state, member_id, &location, &path).await
                        }
                    },
                )
                .await?
            }
        };
        return Ok(Some(response));
    }

    Ok(None)
}

/// Artifact row exposing the columns most metadata endpoints need:
/// id, version, size, checksum, and the raw `artifact_metadata.metadata`
/// JSON. Returned by [`find_artifact_by_name_lowercase`] and
/// [`list_artifacts_by_name_lowercase`].
pub struct ArtifactWithMetadata {
    pub id: Uuid,
    pub name: String,
    pub version: Option<String>,
    pub size_bytes: Option<i64>,
    pub checksum_sha256: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// Look up an artifact by case-insensitive name AND exact version.
/// Returns `Ok(None)` on miss.
#[allow(clippy::result_large_err)]
pub async fn find_artifact_by_name_version(
    db: &PgPool,
    repository_id: Uuid,
    name: &str,
    version: &str,
) -> Result<Option<ArtifactWithMetadata>, Response> {
    use sqlx::Row;
    let row = sqlx::query(
        "SELECT a.id, a.name, a.version, a.size_bytes, a.checksum_sha256, \
                am.metadata \
         FROM artifacts a \
         LEFT JOIN artifact_metadata am ON am.artifact_id = a.id \
         WHERE a.repository_id = $1 \
           AND a.is_deleted = false \
           AND LOWER(a.name) = LOWER($2) \
           AND a.version = $3 \
         LIMIT 1",
    )
    .bind(repository_id)
    .bind(name)
    .bind(version)
    .fetch_optional(db)
    .await
    .map_err(|e| internal_error("Database", e))?;

    Ok(row.map(|r| ArtifactWithMetadata {
        id: r.try_get("id").unwrap_or_default(),
        name: r.try_get("name").unwrap_or_default(),
        version: r.try_get("version").ok(),
        size_bytes: r.try_get("size_bytes").ok(),
        checksum_sha256: r.try_get("checksum_sha256").ok(),
        metadata: r.try_get("metadata").ok(),
    }))
}

/// Look up the most recent artifact whose name matches `name`
/// case-insensitively in `repository_id`. Returns `Ok(None)` on miss.
///
/// Replaces the duplicated `LEFT JOIN artifact_metadata ... WHERE
/// LOWER(name) = LOWER($2) ORDER BY created_at DESC LIMIT 1` query that
/// every metadata endpoint otherwise repeats verbatim.
#[allow(clippy::result_large_err)]
pub async fn find_artifact_by_name_lowercase(
    db: &PgPool,
    repository_id: Uuid,
    name: &str,
) -> Result<Option<ArtifactWithMetadata>, Response> {
    use sqlx::Row;
    let row = sqlx::query(
        "SELECT a.id, a.name, a.version, a.size_bytes, a.checksum_sha256, \
                am.metadata \
         FROM artifacts a \
         LEFT JOIN artifact_metadata am ON am.artifact_id = a.id \
         WHERE a.repository_id = $1 \
           AND a.is_deleted = false \
           AND LOWER(a.name) = LOWER($2) \
         ORDER BY a.created_at DESC \
         LIMIT 1",
    )
    .bind(repository_id)
    .bind(name)
    .fetch_optional(db)
    .await
    .map_err(|e| internal_error("Database", e))?;

    Ok(row.map(|r| ArtifactWithMetadata {
        id: r.try_get("id").unwrap_or_default(),
        name: r.try_get("name").unwrap_or_default(),
        version: r.try_get("version").ok(),
        size_bytes: r.try_get("size_bytes").ok(),
        checksum_sha256: r.try_get("checksum_sha256").ok(),
        metadata: r.try_get("metadata").ok(),
    }))
}

/// List every non-deleted artifact whose name matches `name`
/// case-insensitively in `repository_id`, newest first.
///
/// Companion to [`find_artifact_by_name_lowercase`] for endpoints that
/// need the full version history (e.g. RubyGems versions, Puppet release
/// list, Hex package versions).
#[allow(clippy::result_large_err)]
pub async fn list_artifacts_by_name_lowercase(
    db: &PgPool,
    repository_id: Uuid,
    name: &str,
) -> Result<Vec<ArtifactWithMetadata>, Response> {
    use sqlx::Row;
    let rows = sqlx::query(
        "SELECT a.id, a.name, a.version, a.size_bytes, a.checksum_sha256, \
                am.metadata \
         FROM artifacts a \
         LEFT JOIN artifact_metadata am ON am.artifact_id = a.id \
         WHERE a.repository_id = $1 \
           AND a.is_deleted = false \
           AND LOWER(a.name) = LOWER($2) \
         ORDER BY a.created_at DESC",
    )
    .bind(repository_id)
    .bind(name)
    .fetch_all(db)
    .await
    .map_err(|e| internal_error("Database", e))?;

    Ok(rows
        .into_iter()
        .map(|r| ArtifactWithMetadata {
            id: r.try_get("id").unwrap_or_default(),
            name: r.try_get("name").unwrap_or_default(),
            version: r.try_get("version").ok(),
            size_bytes: r.try_get("size_bytes").ok(),
            checksum_sha256: r.try_get("checksum_sha256").ok(),
            metadata: r.try_get("metadata").ok(),
        })
        .collect())
}

/// Lightweight artifact row returned by [`find_local_by_filename_suffix`].
/// Captures only the fields the format download handlers actually need
/// (id + storage_key) so the helper can stay format-agnostic.
pub struct LocalArtifactHit {
    pub id: Uuid,
    pub storage_key: String,
}

/// Look up a single artifact by trailing path-suffix within a
/// repository.
///
/// Preserves the original suffix-LIKE semantic
/// (`path LIKE '%/' || $2`) but rewrites it to a *left-anchored*
/// LIKE on `reverse(path)`, which the functional index
/// `idx_artifacts_repo_reverse_path` (added in migration
/// `108_artifacts_filename_index.sql`) can serve as an index-only
/// scan. See #1266 for the prod logs that motivated the rewrite —
/// the original leading-wildcard form was un-indexable and
/// seq-scanned the whole repo (3-6 s per call on populated tables).
///
/// Returns `Ok(Some(hit))` on match, `Ok(None)` on miss, or
/// `Err(response)` on database failure.
#[allow(clippy::result_large_err)]
pub async fn find_local_by_filename_suffix(
    db: &PgPool,
    repository_id: Uuid,
    path_suffix: &str,
) -> Result<Option<LocalArtifactHit>, Response> {
    use sqlx::Row;
    let reversed_pattern = reverse_suffix_for_like(path_suffix);
    let row = sqlx::query(
        "SELECT id, storage_key FROM artifacts \
         WHERE repository_id = $1 \
           AND is_deleted = false \
           AND reverse(path) LIKE $2 || '%' ESCAPE '\\' \
         LIMIT 1",
    )
    .bind(repository_id)
    .bind(&reversed_pattern)
    .fetch_optional(db)
    .await
    .map_err(|e| internal_error("Database", e))?;

    Ok(row.map(|r| LocalArtifactHit {
        id: r.try_get("id").unwrap_or_default(),
        storage_key: r.try_get("storage_key").unwrap_or_default(),
    }))
}

/// Parse a two-field multipart upload (`file` + a named JSON metadata field).
///
/// Used by Ansible (collection upload) and Puppet (module publish), which
/// both ship a tarball alongside a JSON descriptor of the package. Returns
/// `(tarball_bytes, metadata_json)` or a 400 response describing the parse
/// failure.
///
/// `json_field_names` lists the form-field names to accept for the JSON
/// payload (Ansible accepts both `collection` and `metadata`; Puppet uses
/// `module`). The first matching field wins. Unknown fields are ignored.
pub async fn parse_multipart_file_with_json(
    mut multipart: axum::extract::Multipart,
    json_field_names: &[&str],
) -> Result<(Bytes, Option<serde_json::Value>), Response> {
    let mut tarball: Option<Bytes> = None;
    let mut json_value: Option<serde_json::Value> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Multipart error: {}", e)).into_response())?
    {
        let field_name = field.name().unwrap_or("").to_string();
        if field_name == "file" {
            tarball = Some(field.bytes().await.map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Failed to read file: {}", e),
                )
                    .into_response()
            })?);
        } else if json_field_names.iter().any(|n| *n == field_name) {
            let data = field.bytes().await.map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Failed to read metadata JSON: {}", e),
                )
                    .into_response()
            })?;
            json_value = Some(serde_json::from_slice(&data).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Invalid metadata JSON: {}", e),
                )
                    .into_response()
            })?);
        }
    }

    let tarball =
        tarball.ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing file field").into_response())?;

    if tarball.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty tarball").into_response());
    }

    Ok((tarball, json_value))
}

/// Resolve the storage backend for a repository and write `body` to
/// `storage_key`. Maps storage failures to a 500 "Storage error" response.
///
/// Replaces the duplicated "let storage = state.storage_for_repo(...) ;
/// storage.put(...).await.map_err(...)" block that every multipart upload
/// handler otherwise repeats.
#[allow(clippy::result_large_err)]
pub async fn put_artifact_bytes(
    state: &crate::api::SharedState,
    repo: &RepoInfo,
    storage_key: &str,
    body: Bytes,
) -> Result<(), Response> {
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    storage
        .put(storage_key, body)
        .await
        .map_err(|e| internal_error("Storage", e))?;
    Ok(())
}

/// Borrowed handle to the columns required to insert a new artifact row.
/// The lifetime ties the supplied string slices to the surrounding scope so
/// the helper can avoid extra allocations.
pub struct NewArtifact<'a> {
    pub repository_id: Uuid,
    pub path: &'a str,
    pub name: &'a str,
    pub version: &'a str,
    pub size_bytes: i64,
    pub checksum_sha256: &'a str,
    pub content_type: &'a str,
    pub storage_key: &'a str,
    pub uploaded_by: Uuid,
}

/// Insert a row into `artifacts` and return the new id.
///
/// Replaces the duplicated nine-column INSERT macro that every multipart
/// upload handler otherwise repeats verbatim. Errors map to a 500
/// "Database error" response.
#[allow(clippy::result_large_err)]
pub async fn insert_artifact(db: &PgPool, art: NewArtifact<'_>) -> Result<Uuid, Response> {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO artifacts ( \
             repository_id, path, name, version, size_bytes, \
             checksum_sha256, content_type, storage_key, uploaded_by \
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         RETURNING id",
    )
    .bind(art.repository_id)
    .bind(art.path)
    .bind(art.name)
    .bind(art.version)
    .bind(art.size_bytes)
    .bind(art.checksum_sha256)
    .bind(art.content_type)
    .bind(art.storage_key)
    .bind(art.uploaded_by)
    .fetch_one(db)
    .await
    .map_err(|e| internal_error("Database", e))?;
    Ok(id)
}

/// Reject if `(repository_id, path)` already exists, otherwise sweep any
/// soft-deleted row at that path so a subsequent INSERT can proceed.
///
/// `conflict_message` is the human-readable error returned on a 409
/// (e.g. "Module version already exists").
#[allow(clippy::result_large_err)]
pub async fn ensure_unique_artifact_path(
    db: &PgPool,
    repo_id: Uuid,
    artifact_path: &str,
    conflict_message: &str,
) -> Result<(), Response> {
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
    )
    .bind(repo_id)
    .bind(artifact_path)
    .fetch_optional(db)
    .await
    .map_err(|e| internal_error("Database", e))?;

    if existing.is_some() {
        return Err((StatusCode::CONFLICT, conflict_message.to_string()).into_response());
    }

    super::cleanup_soft_deleted_artifact(db, repo_id, artifact_path).await;
    Ok(())
}

/// Upsert format-specific metadata for a freshly-uploaded artifact and bump
/// the owning repository's `updated_at` timestamp. Best-effort: errors are
/// swallowed because the artifact row itself has already been committed.
///
/// Replaces the duplicated tail of every multipart upload handler:
/// "INSERT INTO artifact_metadata ... ON CONFLICT" + "UPDATE repositories
/// SET updated_at = NOW()".
pub async fn record_artifact_metadata(
    db: &PgPool,
    artifact_id: Uuid,
    repo_id: Uuid,
    format: &str,
    metadata: &serde_json::Value,
) {
    let _ = sqlx::query(
        "INSERT INTO artifact_metadata (artifact_id, format, metadata) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (artifact_id) DO UPDATE SET metadata = $3",
    )
    .bind(artifact_id)
    .bind(format)
    .bind(metadata)
    .execute(db)
    .await;

    let _ = sqlx::query("UPDATE repositories SET updated_at = NOW() WHERE id = $1")
        .bind(repo_id)
        .execute(db)
        .await;
}

/// Serve an artifact from local storage with quarantine + statistics.
///
/// Performs the standard hit-path tail used by every format download handler:
/// quarantine check, storage load, download-statistics insert, and a 200
/// response with the supplied content type and optional `Content-Disposition`.
/// `artifact_id` is the row id for quarantine + statistics; `storage_key` is
/// the raw key handed to the storage backend.
pub async fn serve_local_artifact(
    state: &crate::api::SharedState,
    repo: &RepoInfo,
    artifact_id: Uuid,
    storage_key: &str,
    content_type: &str,
    content_disposition_filename: Option<&str>,
) -> Result<Response, Response> {
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;

    crate::services::quarantine_service::check_artifact_download(&state.db, artifact_id)
        .await
        .map_err(|e| e.into_response())?;

    let content = storage
        .get(storage_key)
        .await
        .map_err(|e| internal_error("Storage", e))?;

    let _ = sqlx::query(
        "INSERT INTO download_statistics (artifact_id, ip_address) VALUES ($1, '0.0.0.0')",
    )
    .bind(artifact_id)
    .execute(&state.db)
    .await;

    Ok(build_download_response(
        content,
        Some(content_type.to_string()),
        content_type,
        content_disposition_filename,
    ))
}

/// Build a 200 OK download response from proxied content.
pub(crate) fn build_download_response(
    content: Bytes,
    content_type: Option<String>,
    default_content_type: &str,
    filename: Option<&str>,
) -> Response {
    let ct = content_type.unwrap_or_else(|| default_content_type.to_string());
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", ct)
        .header("Content-Length", content.len().to_string());
    if let Some(fname) = filename {
        builder = builder.header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", fname),
        );
    }
    builder.body(axum::body::Body::from(content)).unwrap()
}

/// Build a minimal `Repository` model for proxy operations.
///
/// Visible to other handler modules so they can construct a stand-in
/// `Repository` value for `ProxyService` calls that need more than just
/// the fields carried on the thin `RepoInfo` struct, e.g.
/// `ProxyService::fetch_dists_detecting_change` in the Debian handler.
pub(crate) fn build_remote_repo(id: Uuid, key: &str, upstream_url: &str) -> Repository {
    Repository {
        id,
        key: key.to_string(),
        name: key.to_string(),
        description: None,
        format: RepositoryFormat::Generic,
        repo_type: RepositoryType::Remote,
        storage_backend: "filesystem".to_string(),
        storage_path: String::new(),
        upstream_url: Some(upstream_url.to_string()),
        is_public: false,
        quota_bytes: None,
        promotion_only: false,
        replication_priority: ReplicationPriority::OnDemand,
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    // ── Package Age Policy quarantine surfacing (#1770) ──────────────

    #[test]
    fn test_is_quarantine_block_matches_conflict_and_authorization() {
        use crate::error::AppError;
        assert!(is_quarantine_block(&AppError::Conflict("held".into())));
        assert!(is_quarantine_block(&AppError::Authorization(
            "rejected".into()
        )));
    }

    #[test]
    fn test_is_quarantine_block_ignores_ordinary_misses() {
        use crate::error::AppError;
        assert!(!is_quarantine_block(&AppError::NotFound("gone".into())));
        assert!(!is_quarantine_block(&AppError::BadGateway(
            "upstream".into()
        )));
        assert!(!is_quarantine_block(&AppError::Storage("io".into())));
    }

    #[test]
    fn test_map_proxy_error_surfaces_quarantine_conflict_as_409() {
        let resp = map_proxy_error(
            "npm-age",
            "axios/-/axios-1.6.0.tgz",
            crate::error::AppError::Conflict(
                "Artifact is quarantined and pending security review".into(),
            ),
        );
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert!(is_quarantine_block_response(&resp));
    }

    #[test]
    fn test_map_proxy_error_surfaces_rejected_as_403() {
        let resp = map_proxy_error(
            "npm-age",
            "axios/-/axios-1.6.0.tgz",
            crate::error::AppError::Authorization("Artifact was rejected".into()),
        );
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(is_quarantine_block_response(&resp));
    }

    #[test]
    fn test_map_proxy_error_keeps_transient_failure_as_502() {
        let resp = map_proxy_error(
            "npm-age",
            "axios/-/axios-1.6.0.tgz",
            crate::error::AppError::Storage("connection reset".into()),
        );
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        assert!(!is_quarantine_block_response(&resp));
    }

    // ── promotion_only direct-upload gate ───────────────────────────

    #[test]
    fn test_promotion_only_blocks_non_admin_direct_upload() {
        // Non-admin + promotion_only repo => blocked.
        assert!(promotion_only_blocks_direct_upload(true, false));
    }

    #[test]
    fn test_promotion_only_blocks_admin_too() {
        // Admins are no longer exempt: a direct upload to a promotion_only repo
        // is blocked regardless of admin status (artifacts must enter via the
        // promotion workflow).
        assert!(promotion_only_blocks_direct_upload(true, true));
    }

    #[test]
    fn test_promotion_only_normal_repo_not_blocked() {
        // promotion_only = false => never blocked (no regression for normal repos).
        assert!(!promotion_only_blocks_direct_upload(false, false));
        assert!(!promotion_only_blocks_direct_upload(false, true));
    }

    #[test]
    fn test_reject_direct_upload_if_promotion_only_returns_409() {
        let err = reject_direct_upload_if_promotion_only(true, false)
            .expect_err("non-admin direct upload to promotion_only repo must be rejected");
        assert_eq!(err.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn test_reject_direct_upload_if_promotion_only_blocks_admin_allows_normal() {
        // Admin direct upload to a promotion_only repo is now rejected too.
        assert!(reject_direct_upload_if_promotion_only(true, true).is_err());
        // Normal (non-promotion_only) repos are never blocked.
        assert!(reject_direct_upload_if_promotion_only(false, false).is_ok());
    }

    fn promo_repo_info(promotion_only: bool) -> RepoInfo {
        RepoInfo {
            id: uuid::Uuid::new_v4(),
            key: "gate-test".to_string(),
            storage_path: "/data/gate-test".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: None,
            promotion_only,
        }
    }

    #[test]
    fn test_repoinfo_reject_if_promotion_only_blocks_when_true() {
        // A promotion_only RepoInfo rejects direct uploads with 409 CONFLICT,
        // matching the wired maven/generic sites. The shared method is what the
        // format-native publish handlers now call.
        let repo = promo_repo_info(true);
        let err = repo
            .reject_if_promotion_only(false)
            .expect_err("promotion_only repo must reject direct upload");
        assert_eq!(err.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn test_repoinfo_reject_if_promotion_only_no_admin_exemption() {
        // There is no admin break-glass: the is_admin flag does not change the
        // outcome for a promotion_only repo.
        let repo = promo_repo_info(true);
        assert!(repo.reject_if_promotion_only(true).is_err());
    }

    #[test]
    fn test_repoinfo_reject_if_promotion_only_allows_normal_repo() {
        // A normal (promotion_only = false) repo is a no-op for any caller.
        let repo = promo_repo_info(false);
        assert!(repo.reject_if_promotion_only(false).is_ok());
        assert!(repo.reject_if_promotion_only(true).is_ok());
    }

    // ── LocalLookup dispatch tests ──────────────────────────────────

    #[test]
    fn test_local_lookup_path_select_sql() {
        // Path variant matches on `path = $2` and never references name/version.
        let sql = LocalLookup::Path("a/b/c.tgz").select_sql();
        assert!(sql.contains("WHERE repository_id = $1 AND path = $2 AND is_deleted = false"));
        assert!(sql.contains("LIMIT 1"));
        assert!(!sql.contains("name = $2"));
        assert!(!sql.contains("version = $3"));
    }

    #[test]
    fn test_local_lookup_name_version_select_sql() {
        // NameVersion variant matches on `name = $2 AND version = $3`.
        let sql = LocalLookup::NameVersion("pkg", "1.0.0").select_sql();
        assert!(sql.contains(
            "WHERE repository_id = $1 AND name = $2 AND version = $3 AND is_deleted = false"
        ));
        assert!(sql.contains("LIMIT 1"));
        assert!(!sql.contains("path = $2"));
    }

    #[test]
    fn test_local_lookup_name_version_suffix_select_sql() {
        // Regression (#1782): the Go proxy's virtual fallback uses this
        // variant so a `.zip` request and a `.mod` request -- which share the
        // same (name, version) -- resolve to different artifacts. The WHERE
        // clause MUST add the `path LIKE $4` filter; without it the bare
        // NameVersion query returns whichever row was inserted first (serving
        // go.mod bytes for a `.zip` request).
        let sql = LocalLookup::NameVersionSuffix("pkg", "1.0.0", "%.zip").select_sql();
        assert!(
            sql.contains(
                "WHERE repository_id = $1 AND name = $2 AND version = $3 AND path LIKE $4 AND is_deleted = false"
            ),
            "suffix variant must filter on `path LIKE $4`: {sql}"
        );
        assert!(sql.contains("LIMIT 1"));
    }

    #[test]
    fn test_local_lookup_select_columns_identical() {
        // All variants select the same LocalArtifactRow columns; only the
        // WHERE clause differs (the whole point of the S6 collapse).
        let cols =
            "SELECT id, storage_key, content_type, size_bytes, quarantine_status, quarantine_until";
        assert!(LocalLookup::Path("x").select_sql().starts_with(cols));
        assert!(LocalLookup::NameVersion("n", "v")
            .select_sql()
            .starts_with(cols));
        assert!(LocalLookup::NameVersionSuffix("n", "v", "%.mod")
            .select_sql()
            .starts_with(cols));
    }

    // ── pypi_version_owned (shadowing guard) tests ──────────────────

    #[test]
    fn test_pypi_version_owned_canonical_match() {
        // Clean dotted versions match across PEP 440-equal release forms.
        let stored = vec!["1.1.1".to_string()];
        assert!(pypi_version_owned("1.1.1", &stored));
        assert!(pypi_version_owned("1.1.1.0", &stored));
        // A version not held locally allows fan-out (not owned).
        assert!(!pypi_version_owned("1.0.0", &stored));
    }

    #[test]
    fn test_pypi_version_owned_fails_safe_on_unparseable_request() {
        // PEP 427 filename-escaped local segment drops the `+`, so the requested
        // version is unparseable. The guard must suppress (treat as owned) when a
        // local version of the name exists, never allow fan-out.
        let stored = vec!["1.2.3+gitsha".to_string()];
        assert!(pypi_version_owned("1.2.3_gitsha", &stored));
        // Even an unrelated stored version suppresses, because we cannot prove
        // the requested version differs.
        let other = vec!["9.9.9".to_string()];
        assert!(pypi_version_owned("1.2.3_gitsha", &other));
    }

    #[test]
    fn test_pypi_version_owned_legacy_unparseable_stored_exact_match() {
        // A stored row that is not PEP 440 falls back to exact case-insensitive
        // match against the requested version.
        let stored = vec!["weird-local".to_string()];
        assert!(pypi_version_owned("WEIRD-LOCAL", &stored));
        assert!(!pypi_version_owned("1.0.0", &stored));
    }

    // ── reverse_suffix_for_like tests ───────────────────────────────

    #[test]
    fn test_reverse_suffix_for_like_plain_basename() {
        // Simple filename: "/pkg-1.0.0.tgz" reversed = "zgt.0.0.1-gkp/"
        assert_eq!(reverse_suffix_for_like("pkg-1.0.0.tgz"), "zgt.0.0.1-gkp/");
    }

    #[test]
    fn test_reverse_suffix_for_like_multi_segment_suffix() {
        // Multi-segment suffix preserves original suffix-LIKE semantic:
        // "/foo/bar/file.tgz" reversed = "zgt.elif/rab/oof/"
        assert_eq!(
            reverse_suffix_for_like("foo/bar/file.tgz"),
            "zgt.elif/rab/oof/"
        );
    }

    #[test]
    fn test_reverse_suffix_for_like_escapes_metachars_after_reverse() {
        // Input with a LIKE metachar (%) must end up with the escape
        // char (\) on the LEFT of the metachar in the reversed
        // pattern so Postgres recognises it under `ESCAPE '\\'`.
        // Input:      "ab%cd"          (literal % expected)
        // "/" + in :  "/ab%cd"
        // reversed :  "dc%ba/"
        // escaped  :  "dc\%ba/"        (\ ahead of %, correct for ESCAPE)
        assert_eq!(reverse_suffix_for_like("ab%cd"), "dc\\%ba/");
    }

    #[test]
    fn test_reverse_suffix_for_like_escapes_underscore_and_backslash() {
        // Same rule applies to _ and \. Reversing then escaping puts
        // the escape char to the left of each metachar.
        // Input:      "a_b\\c"
        // "/" + in :  "/a_b\\c"
        // reversed :  "c\\b_a/"
        // escaped  :  "c\\\\b\\_a/"
        assert_eq!(reverse_suffix_for_like("a_b\\c"), "c\\\\b\\_a/");
    }

    #[test]
    fn test_reverse_suffix_for_like_empty_input_just_slash() {
        // Empty suffix → reversed "/" → escaped "/"
        assert_eq!(reverse_suffix_for_like(""), "/");
    }

    // ── maven_ga_like_pattern tests (#1287) ─────────────────────────

    #[test]
    fn test_maven_ga_like_pattern_simple_groupid() {
        // Regular groupId/artifactId pair: dots in groupId become
        // path separators, then a `/<artifactId>/%` suffix is appended.
        assert_eq!(
            maven_ga_like_pattern("com.android.tools", "common"),
            "com/android/tools/common/%"
        );
    }

    #[test]
    fn test_maven_ga_like_pattern_distinguishes_groupids() {
        // Two artifactIds that collide on `name` alone but live under
        // different groupIds must produce distinct LIKE prefixes.
        // This is the core property #1287 needs.
        let foo = maven_ga_like_pattern("com.foo", "bar");
        let baz = maven_ga_like_pattern("com.baz", "bar");
        assert_ne!(foo, baz);
        assert_eq!(foo, "com/foo/bar/%");
        assert_eq!(baz, "com/baz/bar/%");
    }

    #[test]
    fn test_maven_ga_like_pattern_does_not_match_sibling_groupids() {
        // `com.android.tools/common/...` must NOT be matched by a
        // pattern derived from `com.example.mylib:common`. We assert
        // the produced prefix is anchored at the full GA directory
        // boundary.
        let prefix = maven_ga_like_pattern("com.example.mylib", "common");
        assert_eq!(prefix, "com/example/mylib/common/%");
        // A path under a different groupId does not start with this
        // prefix even though both share the `common` artifactId.
        let unrelated_path = "com/android/tools/common/31.4.0/common-31.4.0.pom";
        assert!(!unrelated_path.starts_with("com/example/mylib/common/"));
        // Sanity: the matching local artifact path DOES start with it.
        let local_path = "com/example/mylib/common/1.0.0/common-1.0.0.pom";
        assert!(local_path.starts_with("com/example/mylib/common/"));
        // And the LIKE suffix is open-ended.
        assert!(prefix.ends_with('%'));
    }

    #[test]
    fn test_maven_ga_like_pattern_escapes_metachars() {
        // A crafted artifactId containing `%` or `_` must not widen
        // the LIKE match. Both inputs get escaped before being woven
        // into the pattern.
        assert_eq!(
            maven_ga_like_pattern("a.b", "ev%il"),
            "a/b/ev\\%il/%",
            "% inside artifactId must be escaped"
        );
        assert_eq!(
            maven_ga_like_pattern("a.b", "ev_il"),
            "a/b/ev\\_il/%",
            "_ inside artifactId must be escaped"
        );
        // `%` inside the groupId is also escaped (after the
        // dot-to-slash conversion has already happened).
        assert_eq!(
            maven_ga_like_pattern("a%.b", "c"),
            "a\\%/b/c/%",
            "% inside groupId must be escaped"
        );
    }

    #[test]
    fn test_maven_ga_like_pattern_escapes_backslash() {
        // Backslashes get escaped so the ESCAPE '\' clause stays
        // honest.
        assert_eq!(maven_ga_like_pattern("a.b", "c\\d"), "a/b/c\\\\d/%");
    }

    // ── build_remote_repo tests ──────────────────────────────────────

    #[test]
    fn test_build_remote_repo_sets_id() {
        let id = Uuid::new_v4();
        let repo = build_remote_repo(id, "my-repo", "https://upstream.example.com");
        assert_eq!(repo.id, id);
    }

    #[test]
    fn test_build_remote_repo_key_and_name_match() {
        let id = Uuid::new_v4();
        let repo = build_remote_repo(id, "npm-remote", "https://registry.npmjs.org");
        assert_eq!(repo.key, "npm-remote");
        assert_eq!(repo.name, "npm-remote");
    }

    #[test]
    fn test_build_remote_repo_upstream_url() {
        let id = Uuid::new_v4();
        let url = "https://pypi.org/simple/";
        let repo = build_remote_repo(id, "pypi-proxy", url);
        assert_eq!(repo.upstream_url, Some(url.to_string()));
    }

    #[test]
    fn test_build_remote_repo_type_is_remote() {
        let repo = build_remote_repo(Uuid::new_v4(), "r", "https://x.com");
        assert_eq!(repo.repo_type, RepositoryType::Remote);
    }

    #[test]
    fn test_build_remote_repo_format_is_generic() {
        let repo = build_remote_repo(Uuid::new_v4(), "r", "https://x.com");
        assert_eq!(repo.format, RepositoryFormat::Generic);
    }

    #[test]
    fn test_build_remote_repo_storage_backend_filesystem() {
        let repo = build_remote_repo(Uuid::new_v4(), "r", "https://x.com");
        assert_eq!(repo.storage_backend, "filesystem");
    }

    #[test]
    fn test_build_remote_repo_storage_path_empty() {
        let repo = build_remote_repo(Uuid::new_v4(), "r", "https://x.com");
        assert!(repo.storage_path.is_empty());
    }

    #[test]
    fn test_build_remote_repo_defaults() {
        let repo = build_remote_repo(Uuid::new_v4(), "k", "https://u.com");
        assert!(repo.description.is_none());
        assert!(!repo.is_public);
        assert!(repo.quota_bytes.is_none());
        assert_eq!(repo.replication_priority, ReplicationPriority::OnDemand);
    }

    #[test]
    fn test_build_remote_repo_timestamps_set() {
        let before = Utc::now();
        let repo = build_remote_repo(Uuid::new_v4(), "k", "https://u.com");
        let after = Utc::now();
        assert!(repo.created_at >= before && repo.created_at <= after);
        assert!(repo.updated_at >= before && repo.updated_at <= after);
    }

    // ── with_proxy_repo tests ────────────────────────────────────────

    #[tokio::test]
    async fn test_with_proxy_repo_passes_through_ok_value() {
        // On success the helper forwards the closure's value unchanged and
        // hands the constructed Repository (built from the supplied args) to
        // the closure.
        let id = Uuid::new_v4();
        let result: Result<(Bytes, Option<String>), Response> = with_proxy_repo(
            id,
            "ok-repo",
            "https://upstream.example.com",
            "some/path",
            |repo| async move {
                assert_eq!(repo.id, id);
                assert_eq!(repo.key, "ok-repo");
                assert_eq!(
                    repo.upstream_url.as_deref(),
                    Some("https://upstream.example.com")
                );
                Ok((
                    Bytes::from_static(b"payload"),
                    Some("text/plain".to_string()),
                ))
            },
        )
        .await;

        let (bytes, content_type) = result.expect("expected Ok result");
        assert_eq!(bytes.as_ref(), b"payload");
        assert_eq!(content_type.as_deref(), Some("text/plain"));
    }

    #[tokio::test]
    async fn test_with_proxy_repo_maps_not_found_to_404() {
        // An upstream NotFound is mapped via map_proxy_error to a 404.
        let result: Result<Bytes, Response> = with_proxy_repo(
            Uuid::new_v4(),
            "missing-repo",
            "https://upstream.example.com",
            "missing/path",
            |_repo| async move { Err(AppError::NotFound("nope".to_string())) },
        )
        .await;

        let response = result.expect_err("expected error response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_with_proxy_repo_maps_validation_to_400() {
        // A Validation error is mapped to a 400 (path-traversal guard).
        let result: Result<Bytes, Response> = with_proxy_repo(
            Uuid::new_v4(),
            "bad-path-repo",
            "https://upstream.example.com",
            "../escape",
            |_repo| async move { Err(AppError::Validation("bad".to_string())) },
        )
        .await;

        let response = result.expect_err("expected error response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_with_proxy_repo_maps_other_error_to_502() {
        // Anything else (timeouts, TLS, body read) folds into 502.
        let result: Result<Bytes, Response> = with_proxy_repo(
            Uuid::new_v4(),
            "flaky-repo",
            "https://upstream.example.com",
            "p",
            |_repo| async move { Err(AppError::Internal("boom".to_string())) },
        )
        .await;

        let response = result.expect_err("expected error response");
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    // ── reject_write_if_not_hosted tests ─────────────────────────────

    #[test]
    fn test_reject_write_remote_returns_method_not_allowed() {
        let result = reject_write_if_not_hosted("remote");
        assert!(result.is_err());
        let response = result.unwrap_err();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn test_reject_write_virtual_returns_bad_request() {
        let result = reject_write_if_not_hosted("virtual");
        assert!(result.is_err());
        let response = result.unwrap_err();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_reject_write_local_is_ok() {
        let result = reject_write_if_not_hosted("local");
        assert!(result.is_ok());
    }

    #[test]
    fn test_reject_write_staging_is_ok() {
        let result = reject_write_if_not_hosted("staging");
        assert!(result.is_ok());
    }

    #[test]
    fn test_reject_write_empty_string_is_ok() {
        let result = reject_write_if_not_hosted("");
        assert!(result.is_ok());
    }

    #[test]
    fn test_reject_write_unknown_type_is_ok() {
        let result = reject_write_if_not_hosted("something-else");
        assert!(result.is_ok());
    }

    // ── internal_error tests ────────────────────────────────────────

    #[test]
    fn test_internal_error_returns_500() {
        let response = internal_error("Storage", "disk full");
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_internal_error_database_label() {
        let response = internal_error("Database", "connection refused");
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ── map_proxy_error tests ──────────────────────────────────────────

    #[test]
    fn test_map_proxy_error_not_found() {
        let err = crate::error::AppError::NotFound("missing artifact".to_string());
        let response = map_proxy_error("repo-key", "path/to/file", err);
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_map_proxy_error_internal_becomes_bad_gateway() {
        let err = crate::error::AppError::Internal("connection failed".to_string());
        let response = map_proxy_error("repo-key", "path/to/file", err);
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn test_map_proxy_error_storage_becomes_bad_gateway() {
        let err = crate::error::AppError::Storage("disk full".to_string());
        let response = map_proxy_error("repo-key", "some/path", err);
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn test_map_proxy_error_bad_gateway_stays_bad_gateway() {
        let err = crate::error::AppError::BadGateway("upstream timeout".to_string());
        let response = map_proxy_error("repo-key", "pkg", err);
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn test_map_proxy_error_validation_becomes_bad_request() {
        // Per #1107 R1 security review: Validation errors must return a
        // generic 400 (not 502) so the validator's specific reject reason
        // is not echoed back to the client as a probe oracle.
        let err = crate::error::AppError::Validation(
            "Proxy cache path must not contain `..` segment".to_string(),
        );
        let response = map_proxy_error("repo-key", "pkg", err);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // #1139 regression: upstream-404 must still resolve to a 404 response.
    // The log-level change (`warn` -> `info` with re-worded message) is a
    // behavioural change visible to operators only; the API contract for the
    // OCI / PyPI / generic-proxy client is unchanged. This guards against an
    // accidental re-routing of NotFound through the 502 branch.
    #[test]
    fn test_map_proxy_error_not_found_still_returns_404_after_logging_rework() {
        let err = crate::error::AppError::NotFound(
            "Artifact not found at upstream: https://ghcr.io/v2/example/manifests/latest"
                .to_string(),
        );
        let response = map_proxy_error("ghcr", "v2/example/manifests/latest", err);
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // ── RepoInfo::storage_location tests ───────────────────────────────

    #[test]
    fn test_repo_info_storage_location() {
        let info = RepoInfo {
            id: Uuid::new_v4(),
            key: "my-repo".to_string(),
            storage_path: "/data/repos/my-repo".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "local".to_string(),
            upstream_url: None,
            promotion_only: false,
        };
        let loc = info.storage_location();
        assert_eq!(loc.backend, "filesystem");
        assert_eq!(loc.path, "/data/repos/my-repo");
    }

    // --- map_proxy_error ---

    #[test]
    fn test_map_proxy_error_not_found_returns_404() {
        let err = crate::error::AppError::NotFound("gone".to_string());
        let resp = super::map_proxy_error("my-repo", "pkg/v1/file.bin", err);
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_map_proxy_error_database_returns_502() {
        let err = crate::error::AppError::Database("connection refused".to_string());
        let resp = super::map_proxy_error("my-repo", "pkg/v1/file.bin", err);
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn test_map_proxy_error_storage_returns_502() {
        let err = crate::error::AppError::Storage("disk full".to_string());
        let resp = super::map_proxy_error("my-repo", "some/path", err);
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn test_map_proxy_error_internal_returns_502() {
        let err = crate::error::AppError::Internal("unexpected".to_string());
        let resp = super::map_proxy_error("repo", "path", err);
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn test_map_proxy_error_authentication_returns_502() {
        let err = crate::error::AppError::Authentication("bad token".to_string());
        let resp = super::map_proxy_error("repo", "path", err);
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    /// #1445: when the upstream returns 5xx the proxy MUST return 503
    /// (Service Unavailable) to the client, never the raw 502 from the
    /// remote. The proxy_service maps upstream 5xx to
    /// `AppError::ServiceUnavailable`; `map_proxy_error` must surface
    /// that as `503` to preserve the "2xx or 503" client contract under
    /// concurrent load (status set `502 200 502 502 502 200 401 401 ...`
    /// in the reproducer was caused by the previous mapping that let
    /// raw upstream 502 reach the client).
    #[test]
    fn test_map_proxy_error_service_unavailable_returns_503_for_upstream_5xx() {
        let err = crate::error::AppError::ServiceUnavailable(
            "Upstream returned error status 502: https://up/x".to_string(),
        );
        let resp = super::map_proxy_error("my-repo", "pkg/v1/file.bin", err);
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "upstream 5xx must surface as 503 to clients, not 502 (#1445)"
        );
    }

    // --- build_remote_repo ---

    #[test]
    fn test_build_remote_repo_fields() {
        let id = uuid::Uuid::new_v4();
        let repo = super::build_remote_repo(id, "test-repo", "https://upstream.example.com");
        assert_eq!(repo.id, id);
        assert_eq!(repo.key, "test-repo");
        assert_eq!(
            repo.repo_type,
            crate::models::repository::RepositoryType::Remote
        );
        assert_eq!(
            repo.upstream_url.as_deref(),
            Some("https://upstream.example.com")
        );
    }

    #[test]
    fn test_build_remote_repo_always_remote_type() {
        let id = uuid::Uuid::new_v4();
        let repo = super::build_remote_repo(id, "any-key", "https://example.com");
        assert_eq!(
            repo.repo_type,
            crate::models::repository::RepositoryType::Remote
        );
    }

    // --- reject_write_if_not_hosted ---

    #[test]
    fn test_reject_write_local_allowed() {
        assert!(super::reject_write_if_not_hosted("local").is_ok());
    }

    #[test]
    fn test_reject_write_hosted_allowed() {
        assert!(super::reject_write_if_not_hosted("hosted").is_ok());
    }

    #[test]
    fn test_reject_write_remote_rejected() {
        assert!(super::reject_write_if_not_hosted("remote").is_err());
    }

    #[test]
    fn test_reject_write_virtual_rejected() {
        assert!(super::reject_write_if_not_hosted("virtual").is_err());
    }

    // ── try_proxy_cache_redirect tests ─────────────────────────────────
    // Regression coverage for #1018: when the proxy cache is fresh and
    // presigned downloads are enabled, the helper must return a presigned
    // redirect *without* calling `storage.get(...)`. The previous
    // implementation downloaded the full cached body before deciding to
    // redirect, defeating the memory-pressure guarantee that presigned URLs
    // are meant to provide.

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc as StdArc;

    enum RecordingGetBehavior {
        Hit,
        Miss,
    }

    /// Recording mock storage backend that counts every method call so tests
    /// can assert which I/O paths fired (in particular: was the full object
    /// `get(...)` called and whether a write-back happened).
    struct RecordingStorage {
        get_calls: StdArc<AtomicUsize>,
        put_calls: StdArc<AtomicUsize>,
        presigned_calls: StdArc<AtomicUsize>,
        last_put: StdArc<std::sync::Mutex<Option<(String, Bytes)>>>,
        get_behavior: RecordingGetBehavior,
        supports: bool,
    }

    impl RecordingStorage {
        fn new(supports: bool) -> Self {
            Self::new_with_get_behavior(supports, RecordingGetBehavior::Hit)
        }

        fn new_with_get_behavior(supports: bool, get_behavior: RecordingGetBehavior) -> Self {
            Self {
                get_calls: StdArc::new(AtomicUsize::new(0)),
                put_calls: StdArc::new(AtomicUsize::new(0)),
                presigned_calls: StdArc::new(AtomicUsize::new(0)),
                last_put: StdArc::new(std::sync::Mutex::new(None)),
                get_behavior,
                supports,
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::storage::StorageBackend for RecordingStorage {
        async fn put(&self, key: &str, content: Bytes) -> crate::error::Result<()> {
            self.put_calls.fetch_add(1, Ordering::SeqCst);
            *self.last_put.lock().unwrap() = Some((key.to_string(), content));
            Ok(())
        }
        async fn get(&self, key: &str) -> crate::error::Result<Bytes> {
            self.get_calls.fetch_add(1, Ordering::SeqCst);
            match self.get_behavior {
                RecordingGetBehavior::Hit => Ok(Bytes::from_static(b"full-body")),
                RecordingGetBehavior::Miss => Err(crate::error::AppError::NotFound(format!(
                    "Storage key not found: {}",
                    key
                ))),
            }
        }
        async fn exists(&self, _key: &str) -> crate::error::Result<bool> {
            Ok(true)
        }
        async fn delete(&self, _key: &str) -> crate::error::Result<()> {
            Ok(())
        }
        fn supports_redirect(&self) -> bool {
            self.supports
        }
        async fn get_presigned_url(
            &self,
            key: &str,
            expires_in: std::time::Duration,
        ) -> crate::error::Result<Option<crate::storage::PresignedUrl>> {
            self.presigned_calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some(crate::storage::PresignedUrl {
                url: format!("https://signed.example.com/{}", key),
                expires_in,
                source: crate::storage::PresignedUrlSource::S3,
            }))
        }
    }

    // Facade-trait impl so `RecordingStorage` can be driven directly through
    // `try_proxy_cache_redirect` (now generic over the facade trait, #1555)
    // while still serving as an inner-trait registry backend elsewhere. Both
    // impls share the same call counters.
    #[async_trait::async_trait]
    impl crate::services::storage_service::StorageBackend for RecordingStorage {
        async fn put(&self, key: &str, content: Bytes) -> crate::error::Result<()> {
            self.put_calls.fetch_add(1, Ordering::SeqCst);
            *self.last_put.lock().unwrap() = Some((key.to_string(), content));
            Ok(())
        }
        async fn get(&self, key: &str) -> crate::error::Result<Bytes> {
            self.get_calls.fetch_add(1, Ordering::SeqCst);
            match self.get_behavior {
                RecordingGetBehavior::Hit => Ok(Bytes::from_static(b"full-body")),
                RecordingGetBehavior::Miss => Err(crate::error::AppError::NotFound(format!(
                    "Storage key not found: {}",
                    key
                ))),
            }
        }
        async fn exists(&self, _key: &str) -> crate::error::Result<bool> {
            Ok(true)
        }
        async fn delete(&self, _key: &str) -> crate::error::Result<()> {
            Ok(())
        }
        async fn list(&self, _prefix: Option<&str>) -> crate::error::Result<Vec<String>> {
            Ok(Vec::new())
        }
        async fn copy(&self, _source: &str, _dest: &str) -> crate::error::Result<()> {
            Ok(())
        }
        async fn size(&self, _key: &str) -> crate::error::Result<u64> {
            Ok(0)
        }
        fn supports_redirect(&self) -> bool {
            self.supports
        }
        async fn get_presigned_url(
            &self,
            key: &str,
            expires_in: std::time::Duration,
        ) -> crate::error::Result<Option<crate::storage::PresignedUrl>> {
            self.presigned_calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some(crate::storage::PresignedUrl {
                url: format!("https://signed.example.com/{}", key),
                expires_in,
                source: crate::storage::PresignedUrlSource::S3,
            }))
        }
    }

    #[tokio::test]
    async fn test_try_proxy_cache_redirect_skips_get_on_fresh_cache_hit() {
        // Bug #1018: a fresh cache hit with presigned enabled must NOT
        // download the full body. The helper should only invoke the
        // presigned URL machinery.
        let storage = RecordingStorage::new(true);
        let result = super::try_proxy_cache_redirect(
            &storage,
            "proxy-cache/repo/pkg/__content__",
            /* presigned_enabled = */ true,
            std::time::Duration::from_secs(300),
            /* cache_is_fresh = */ true,
        )
        .await;

        assert!(
            result.is_some(),
            "fresh cache + presigned enabled must yield a redirect"
        );
        assert_eq!(
            storage.get_calls.load(Ordering::SeqCst),
            0,
            "full body must NOT be downloaded when redirecting via presigned URL"
        );
        assert_eq!(
            storage.presigned_calls.load(Ordering::SeqCst),
            1,
            "exactly one presigned URL request expected"
        );

        let resp = result.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::FOUND);
        let location = resp
            .headers()
            .get("location")
            .expect("location header")
            .to_str()
            .unwrap();
        assert!(
            location.contains("signed.example.com"),
            "redirect should point at the signed URL, got {}",
            location
        );
    }

    /// #1555 runtime assertion (no DB): drive the proxy-cache presign path
    /// through the real `StorageService` facade built on a redirect-capable,
    /// no-prefix backend, and assert the SIGNED key carries NO global prefix.
    ///
    /// This replaces the old source-grep guards (which only checked WHICH
    /// symbol was called, so they passed even while the feature was dead on
    /// S3). Here the backend echoes the exact key it was asked to sign into the
    /// URL, so a prefixed key would surface as a real assertion failure.
    #[tokio::test]
    async fn test_proxy_cache_presign_signs_no_prefix_key_1555() {
        // The proxy's own backend: redirect-capable, signs the key verbatim
        // (a no-prefix S3 handle does exactly this — no `make_full_key` prefix).
        let proxy_backend = StdArc::new(RecordingStorage::new(/* supports = */ true));
        let service = StdArc::new(crate::services::storage_service::StorageService::new(
            proxy_backend.clone(),
        ));

        // `cache_storage_backend()` returns this single facade handle; capability
        // is type-enforced on the facade trait (no side-channel field).
        let storage = service.backend();
        assert!(
            storage.supports_redirect(),
            "no-prefix proxy-cache backend must report redirect support (#1555)"
        );

        let cache_key = "proxy-cache/pypi-remote/pkg/pkg-1.0.0-py3-none-any.whl/__content__";
        let resp = super::try_proxy_cache_redirect(
            storage.as_ref(),
            cache_key,
            /* presigned_enabled = */ true,
            std::time::Duration::from_secs(300),
            /* cache_is_fresh = */ true,
        )
        .await
        .expect("fresh cache + redirect-capable backend must yield a redirect");

        assert_eq!(resp.status(), axum::http::StatusCode::FOUND);
        let location = resp
            .headers()
            .get("location")
            .expect("location header")
            .to_str()
            .unwrap();

        // The signed key is the raw proxy-cache key: starts with `proxy-cache/`
        // and carries no global (`artifact-keeper/`) prefix.
        assert!(
            location.ends_with(cache_key),
            "signed URL must end with the verbatim no-prefix cache key, got {}",
            location
        );
        assert!(
            !location.contains("artifact-keeper/"),
            "signed key must NOT carry a global prefix (#1555), got {}",
            location
        );
        assert_eq!(
            proxy_backend.presigned_calls.load(Ordering::SeqCst),
            1,
            "exactly one presign through the no-prefix handle"
        );
        assert_eq!(
            proxy_backend.get_calls.load(Ordering::SeqCst),
            0,
            "body must not be downloaded on the presign fast path"
        );
    }

    struct MissingThenPresentStorage {
        content: StdArc<tokio::sync::Mutex<Option<Bytes>>>,
        put_calls: StdArc<AtomicUsize>,
    }

    impl MissingThenPresentStorage {
        fn new() -> Self {
            Self {
                content: StdArc::new(tokio::sync::Mutex::new(None)),
                put_calls: StdArc::new(AtomicUsize::new(0)),
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::storage::StorageBackend for MissingThenPresentStorage {
        async fn put(&self, _key: &str, content: Bytes) -> crate::error::Result<()> {
            self.put_calls.fetch_add(1, Ordering::SeqCst);
            *self.content.lock().await = Some(content);
            Ok(())
        }

        async fn get(&self, _key: &str) -> crate::error::Result<Bytes> {
            self.content.lock().await.clone().ok_or_else(|| {
                crate::error::AppError::NotFound("missing test cache entry".to_string())
            })
        }

        async fn exists(&self, _key: &str) -> crate::error::Result<bool> {
            Ok(self.content.lock().await.is_some())
        }

        async fn delete(&self, _key: &str) -> crate::error::Result<()> {
            *self.content.lock().await = None;
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_get_cached_or_refetch_serializes_remote_refetches() {
        let Some(pool) = db_helpers::try_pool().await else {
            return;
        };

        let storage = StdArc::new(MissingThenPresentStorage::new());
        let artifact_id = Uuid::new_v4();
        let refetch_calls = StdArc::new(AtomicUsize::new(0));
        let start = StdArc::new(tokio::sync::Barrier::new(3));

        let spawn_call = |pool: PgPool,
                          storage: StdArc<MissingThenPresentStorage>,
                          refetch_calls: StdArc<AtomicUsize>,
                          start: StdArc<tokio::sync::Barrier>| {
            tokio::spawn(async move {
                start.wait().await;
                get_cached_or_refetch(&pool, artifact_id, storage.as_ref(), "proxy/test", || {
                    let refetch_calls = refetch_calls.clone();
                    async move {
                        refetch_calls.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        Ok(Bytes::from_static(b"remote-bytes"))
                    }
                })
                .await
            })
        };

        let first = spawn_call(
            pool.clone(),
            storage.clone(),
            refetch_calls.clone(),
            start.clone(),
        );
        let second = spawn_call(
            pool.clone(),
            storage.clone(),
            refetch_calls.clone(),
            start.clone(),
        );

        start.wait().await;

        let first = first.await.expect("first join").expect("first fetch");
        let second = second.await.expect("second join").expect("second fetch");

        assert_eq!(first, Bytes::from_static(b"remote-bytes"));
        assert_eq!(second, Bytes::from_static(b"remote-bytes"));
        assert_eq!(refetch_calls.load(Ordering::SeqCst), 1);
        assert_eq!(storage.put_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_try_proxy_cache_redirect_returns_none_when_presigned_disabled() {
        let storage = RecordingStorage::new(true);
        let result = super::try_proxy_cache_redirect(
            &storage,
            "proxy-cache/repo/pkg/__content__",
            /* presigned_enabled = */ false,
            std::time::Duration::from_secs(300),
            /* cache_is_fresh = */ true,
        )
        .await;

        assert!(result.is_none(), "disabled presigned must short-circuit");
        assert_eq!(storage.get_calls.load(Ordering::SeqCst), 0);
        assert_eq!(storage.presigned_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_try_proxy_cache_redirect_returns_none_when_cache_not_fresh() {
        // Cache miss / expired: caller must do the upstream fetch + populate
        // cache path, so the helper should not produce a redirect.
        let storage = RecordingStorage::new(true);
        let result = super::try_proxy_cache_redirect(
            &storage,
            "proxy-cache/repo/pkg/__content__",
            /* presigned_enabled = */ true,
            std::time::Duration::from_secs(300),
            /* cache_is_fresh = */ false,
        )
        .await;

        assert!(
            result.is_none(),
            "stale/missing cache must fall through to the buffered fetch path"
        );
        assert_eq!(storage.get_calls.load(Ordering::SeqCst), 0);
        assert_eq!(storage.presigned_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_try_proxy_cache_redirect_returns_none_when_backend_no_redirect_support() {
        // Filesystem / RBAC-locked backends: redirect is not possible, so
        // the helper must yield None and let the caller stream content.
        let storage = RecordingStorage::new(false);
        let result = super::try_proxy_cache_redirect(
            &storage,
            "proxy-cache/repo/pkg/__content__",
            /* presigned_enabled = */ true,
            std::time::Duration::from_secs(300),
            /* cache_is_fresh = */ true,
        )
        .await;

        assert!(
            result.is_none(),
            "backend without redirect support must yield None"
        );
        assert_eq!(storage.get_calls.load(Ordering::SeqCst), 0);
    }

    // Redirect-capable facade backends used to exercise the `Ok(None)` and
    // `Err(e)` arms of `try_proxy_cache_redirect`. They share the same trivial
    // StorageBackend surface and differ only in what `get_presigned_url`
    // returns, so generate them from one macro to avoid copy-paste mocks.
    macro_rules! presign_mock {
        ($name:ident, $presign:expr) => {
            struct $name;

            #[async_trait::async_trait]
            impl crate::services::storage_service::StorageBackend for $name {
                async fn put(&self, _key: &str, _content: Bytes) -> crate::error::Result<()> {
                    Ok(())
                }
                async fn get(&self, _key: &str) -> crate::error::Result<Bytes> {
                    Ok(Bytes::from_static(b"body"))
                }
                async fn exists(&self, _key: &str) -> crate::error::Result<bool> {
                    Ok(true)
                }
                async fn delete(&self, _key: &str) -> crate::error::Result<()> {
                    Ok(())
                }
                async fn list(&self, _prefix: Option<&str>) -> crate::error::Result<Vec<String>> {
                    Ok(Vec::new())
                }
                async fn copy(&self, _source: &str, _dest: &str) -> crate::error::Result<()> {
                    Ok(())
                }
                async fn size(&self, _key: &str) -> crate::error::Result<u64> {
                    Ok(0)
                }
                fn supports_redirect(&self) -> bool {
                    true
                }
                async fn get_presigned_url(
                    &self,
                    _key: &str,
                    _expires_in: std::time::Duration,
                ) -> crate::error::Result<Option<crate::storage::PresignedUrl>> {
                    $presign
                }
            }
        };
    }

    // A redirect-capable facade backend whose presign returns `Ok(None)`
    // (e.g. a presign-disabled S3 handle): the helper must fall through to
    // streaming. Covers the `Ok(None)` arm of `try_proxy_cache_redirect`.
    presign_mock!(NonePresignStorage, Ok(None));

    // A redirect-capable facade backend whose presign ERRORS (transient signing
    // failure): the helper must warn + fall through to streaming, never panic.
    // Covers the `Err(e)` warn-and-fall-back arm of `try_proxy_cache_redirect`.
    presign_mock!(
        ErrPresignStorage,
        Err(crate::error::AppError::Storage(
            "transient presign failure".to_string(),
        ))
    );

    #[tokio::test]
    async fn test_try_proxy_cache_redirect_returns_none_when_presign_yields_none() {
        // #1555: a redirect-capable backend that declines to presign this key
        // (Ok(None)) must fall through to streaming, not error.
        let storage = NonePresignStorage;
        let result = super::try_proxy_cache_redirect(
            &storage,
            "proxy-cache/repo/pkg/__content__",
            /* presigned_enabled = */ true,
            std::time::Duration::from_secs(300),
            /* cache_is_fresh = */ true,
        )
        .await;
        assert!(
            result.is_none(),
            "Ok(None) presign must fall through to streaming"
        );
    }

    #[tokio::test]
    async fn test_try_proxy_cache_redirect_returns_none_when_presign_errors() {
        // #1555: a presign error must be swallowed (warn + fall back), never
        // surfaced as a hard failure — the caller still streams the body.
        let storage = ErrPresignStorage;
        let result = super::try_proxy_cache_redirect(
            &storage,
            "proxy-cache/repo/pkg/__content__",
            /* presigned_enabled = */ true,
            std::time::Duration::from_secs(300),
            /* cache_is_fresh = */ true,
        )
        .await;
        assert!(
            result.is_none(),
            "presign Err must warn and fall through to streaming"
        );
    }

    #[tokio::test]
    async fn test_get_cached_or_refetch_refetches_and_writes_back_when_storage_missing() {
        let Some(pool) = db_helpers::try_pool().await else {
            return;
        };

        let storage = RecordingStorage::new_with_get_behavior(false, RecordingGetBehavior::Miss);
        let artifact_id = Uuid::new_v4();
        let refetch_calls = StdArc::new(AtomicUsize::new(0));
        let refetched_bytes = Bytes::from_static(b"refetched-body");
        let storage_key = "proxy-cache/repo/pkg/__content__";

        let result = super::get_cached_or_refetch(&pool, artifact_id, &storage, storage_key, {
            let refetch_calls = refetch_calls.clone();
            let refetched_bytes = refetched_bytes.clone();
            move || async move {
                refetch_calls.fetch_add(1, Ordering::SeqCst);
                Ok(refetched_bytes)
            }
        })
        .await
        .expect("miss path should recover via refetch");

        assert_eq!(result, refetched_bytes);
        // The hydration coordinator uses a double-checked-locking pattern: the
        // first `check()` happens at the top of the loop, and a second `check()`
        // runs after the caller wins the leader election (to avoid duplicating
        // work if another leader populated the cache between the first check
        // and the lease acquisition). In a single-threaded test the cache is
        // never populated by anyone else, so we observe both checks and the
        // count is exactly 2. The invariant we care about is "refetch ran once
        // and wrote back once", asserted below.
        assert_eq!(storage.get_calls.load(Ordering::SeqCst), 2);
        assert_eq!(storage.put_calls.load(Ordering::SeqCst), 1);
        assert_eq!(refetch_calls.load(Ordering::SeqCst), 1);

        let recorded_put = storage.last_put.lock().unwrap().clone();
        let Some((recorded_key, recorded_bytes)) = recorded_put else {
            panic!("expected a write-back after refetch");
        };
        assert_eq!(recorded_key, storage_key);
        assert_eq!(recorded_bytes, refetched_bytes);
    }

    // ── classify_remote_or_virtual tests ───────────────────────────────
    // Pure classifier extracted from try_remote_or_virtual_download so the
    // branch logic has unit coverage without needing AppState or a DB.

    #[test]
    fn test_classify_remote_or_virtual_remote() {
        assert_eq!(
            super::classify_remote_or_virtual("remote"),
            super::RemoteOrVirtualAction::Remote
        );
    }

    #[test]
    fn test_classify_remote_or_virtual_virtual() {
        assert_eq!(
            super::classify_remote_or_virtual("virtual"),
            super::RemoteOrVirtualAction::Virtual
        );
    }

    #[test]
    fn test_classify_remote_or_virtual_local_is_hosted() {
        assert_eq!(
            super::classify_remote_or_virtual("local"),
            super::RemoteOrVirtualAction::Hosted
        );
    }

    #[test]
    fn test_classify_remote_or_virtual_staging_is_hosted() {
        assert_eq!(
            super::classify_remote_or_virtual("staging"),
            super::RemoteOrVirtualAction::Hosted
        );
    }

    #[test]
    fn test_classify_remote_or_virtual_unknown_is_hosted() {
        assert_eq!(
            super::classify_remote_or_virtual("anything-else"),
            super::RemoteOrVirtualAction::Hosted
        );
    }

    #[test]
    fn test_classify_remote_or_virtual_empty_is_hosted() {
        assert_eq!(
            super::classify_remote_or_virtual(""),
            super::RemoteOrVirtualAction::Hosted
        );
    }

    // ── build_download_response tests ──────────────────────────────────
    // Pure response shaper — central to every Remote/Virtual fallback as
    // well as the Local serve path.

    #[test]
    fn test_build_download_response_uses_supplied_content_type() {
        let resp = build_download_response(
            Bytes::from_static(b"hello"),
            Some("application/json".to_string()),
            "application/octet-stream",
            None,
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("Content-Type").unwrap(),
            "application/json"
        );
    }

    #[test]
    fn test_build_download_response_falls_back_to_default_content_type() {
        let resp = build_download_response(Bytes::from_static(b"abc"), None, "text/plain", None);
        assert_eq!(resp.headers().get("Content-Type").unwrap(), "text/plain");
    }

    #[test]
    fn test_build_download_response_sets_content_length() {
        let body = Bytes::from_static(b"twelve bytes");
        let resp = build_download_response(body.clone(), None, "application/octet-stream", None);
        assert_eq!(
            resp.headers().get("Content-Length").unwrap(),
            body.len().to_string().as_str()
        );
    }

    #[test]
    fn test_build_download_response_no_filename_omits_content_disposition() {
        let resp = build_download_response(
            Bytes::from_static(b"x"),
            None,
            "application/octet-stream",
            None,
        );
        assert!(resp.headers().get("Content-Disposition").is_none());
    }

    #[test]
    fn test_build_download_response_with_filename_sets_content_disposition() {
        let resp = build_download_response(
            Bytes::from_static(b"x"),
            None,
            "application/octet-stream",
            Some("pkg-1.0.0.tgz"),
        );
        let cd = resp.headers().get("Content-Disposition").unwrap();
        assert_eq!(cd, "attachment; filename=\"pkg-1.0.0.tgz\"");
    }

    #[test]
    fn test_build_download_response_empty_body_zero_content_length() {
        let resp = build_download_response(
            Bytes::new(),
            Some("application/octet-stream".to_string()),
            "application/octet-stream",
            None,
        );
        assert_eq!(resp.headers().get("Content-Length").unwrap(), "0");
    }

    #[test]
    fn test_build_download_response_filename_with_spaces() {
        let resp = build_download_response(
            Bytes::from_static(b"data"),
            None,
            "application/octet-stream",
            Some("my package 1.0.tgz"),
        );
        let cd = resp.headers().get("Content-Disposition").unwrap();
        assert_eq!(cd, "attachment; filename=\"my package 1.0.tgz\"");
    }

    #[test]
    fn test_build_download_response_status_always_ok() {
        let resp = build_download_response(
            Bytes::from_static(b""),
            None,
            "application/octet-stream",
            None,
        );
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── struct construction tests ──────────────────────────────────────
    // The DB-backed query builders return these structs. The pure
    // constructors are exercised here so refactors that change field shapes
    // get caught at compile time and field-defaulting remains stable.

    #[test]
    fn test_new_artifact_borrowed_fields() {
        let repo_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let art = NewArtifact {
            repository_id: repo_id,
            path: "foo/1.0.0/foo-1.0.0.tgz",
            name: "foo",
            version: "1.0.0",
            size_bytes: 42,
            checksum_sha256: "abc",
            content_type: "application/x-tar",
            storage_key: "npm/foo/1.0.0/foo-1.0.0.tgz",
            uploaded_by: user_id,
        };
        assert_eq!(art.repository_id, repo_id);
        assert_eq!(art.path, "foo/1.0.0/foo-1.0.0.tgz");
        assert_eq!(art.name, "foo");
        assert_eq!(art.version, "1.0.0");
        assert_eq!(art.size_bytes, 42);
        assert_eq!(art.checksum_sha256, "abc");
        assert_eq!(art.content_type, "application/x-tar");
        assert_eq!(art.storage_key, "npm/foo/1.0.0/foo-1.0.0.tgz");
        assert_eq!(art.uploaded_by, user_id);
    }

    #[test]
    fn test_new_artifact_zero_size() {
        let art = NewArtifact {
            repository_id: Uuid::new_v4(),
            path: "x",
            name: "x",
            version: "0",
            size_bytes: 0,
            checksum_sha256: "",
            content_type: "application/octet-stream",
            storage_key: "x",
            uploaded_by: Uuid::new_v4(),
        };
        assert_eq!(art.size_bytes, 0);
    }

    #[test]
    fn test_local_artifact_hit_construction() {
        let id = Uuid::new_v4();
        let hit = LocalArtifactHit {
            id,
            storage_key: "pypi/foo/foo-1.0.tar.gz".to_string(),
        };
        assert_eq!(hit.id, id);
        assert_eq!(hit.storage_key, "pypi/foo/foo-1.0.tar.gz");
    }

    #[test]
    fn test_artifact_with_metadata_full() {
        let id = Uuid::new_v4();
        let m = ArtifactWithMetadata {
            id,
            name: "ggplot2".to_string(),
            version: Some("3.4.0".to_string()),
            size_bytes: Some(1024),
            checksum_sha256: Some("def".to_string()),
            metadata: Some(serde_json::json!({"depends": "R (>= 3.5.0)"})),
        };
        assert_eq!(m.id, id);
        assert_eq!(m.name, "ggplot2");
        assert_eq!(m.version.as_deref(), Some("3.4.0"));
        assert_eq!(m.size_bytes, Some(1024));
        assert_eq!(m.checksum_sha256.as_deref(), Some("def"));
        assert_eq!(m.metadata.unwrap()["depends"], "R (>= 3.5.0)");
    }

    #[test]
    fn test_artifact_with_metadata_all_none_optional() {
        let m = ArtifactWithMetadata {
            id: Uuid::new_v4(),
            name: "lonely".to_string(),
            version: None,
            size_bytes: None,
            checksum_sha256: None,
            metadata: None,
        };
        assert!(m.version.is_none());
        assert!(m.size_bytes.is_none());
        assert!(m.checksum_sha256.is_none());
        assert!(m.metadata.is_none());
        assert_eq!(m.name, "lonely");
    }

    // ── DownloadResponseOpts / VirtualLookup tests ──────────────────────

    #[test]
    fn test_virtual_lookup_path_suffix_variant() {
        let lookup = VirtualLookup::PathSuffix("foo-1.0.tgz");
        match lookup {
            VirtualLookup::PathSuffix(s) => assert_eq!(s, "foo-1.0.tgz"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_virtual_lookup_exact_path_variant() {
        let lookup = VirtualLookup::ExactPath("model/main/file.bin");
        match lookup {
            VirtualLookup::ExactPath(p) => assert_eq!(p, "model/main/file.bin"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_download_response_opts_with_filename() {
        let opts = DownloadResponseOpts {
            upstream_path: "pkg/v1/foo.tgz",
            virtual_lookup: VirtualLookup::PathSuffix("foo.tgz"),
            default_content_type: "application/x-tar",
            content_disposition_filename: Some("foo.tgz"),
            suppress_upstream_proxy: false,
        };
        assert_eq!(opts.upstream_path, "pkg/v1/foo.tgz");
        assert_eq!(opts.default_content_type, "application/x-tar");
        assert_eq!(opts.content_disposition_filename, Some("foo.tgz"));
        assert!(!opts.suppress_upstream_proxy);
    }

    #[test]
    fn test_download_response_opts_without_filename() {
        let opts = DownloadResponseOpts {
            upstream_path: "/some/path",
            virtual_lookup: VirtualLookup::ExactPath("/some/path"),
            default_content_type: "application/octet-stream",
            content_disposition_filename: None,
            suppress_upstream_proxy: false,
        };
        assert!(opts.content_disposition_filename.is_none());
    }

    #[test]
    fn test_download_response_opts_new_helper_defaults_suppress_to_false() {
        // The ergonomic constructor matches the previous five-field shape
        // and leaves shadowing-suppression off by default.
        let opts = DownloadResponseOpts::new(
            "pkg/v1/bar.tgz",
            VirtualLookup::PathSuffix("bar.tgz"),
            "application/x-tar",
            Some("bar.tgz"),
        );
        assert_eq!(opts.upstream_path, "pkg/v1/bar.tgz");
        assert!(!opts.suppress_upstream_proxy);
        assert_eq!(opts.content_disposition_filename, Some("bar.tgz"));
    }

    #[test]
    fn test_download_response_opts_suppress_upstream_proxy_toggle() {
        // The shadowing-guard flag is independent of the rest of the struct
        // and reaches `try_remote_or_virtual_download` verbatim.
        let opts = DownloadResponseOpts {
            upstream_path: "pkg/v1/baz.tgz",
            virtual_lookup: VirtualLookup::PathSuffix("baz.tgz"),
            default_content_type: "application/octet-stream",
            content_disposition_filename: None,
            suppress_upstream_proxy: true,
        };
        assert!(opts.suppress_upstream_proxy);
    }

    // ── parse_multipart_file_with_json tests ────────────────────────────
    // Uses axum's `FromRequest` impl for `Multipart` to construct fixtures
    // without spinning up a full router. Covers every branch in the loop:
    // file-only, file + named JSON, missing file, empty file, invalid JSON.

    use axum::body::Body;
    use axum::extract::FromRequest;
    use axum::http::Request;

    fn build_multipart_request(boundary: &str, body: Vec<u8>) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/")
            .header(
                "content-type",
                format!("multipart/form-data; boundary={}", boundary),
            )
            .body(Body::from(body))
            .unwrap()
    }

    fn multipart_part(boundary: &str, name: &str, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        out.extend_from_slice(
            format!("content-disposition: form-data; name=\"{}\"\r\n\r\n", name).as_bytes(),
        );
        out.extend_from_slice(body);
        out.extend_from_slice(b"\r\n");
        out
    }

    fn multipart_terminator(boundary: &str) -> Vec<u8> {
        format!("--{}--\r\n", boundary).into_bytes()
    }

    #[tokio::test]
    async fn test_parse_multipart_file_only_succeeds() {
        let boundary = "BOUNDARY";
        let mut body = Vec::new();
        body.extend(multipart_part(boundary, "file", b"tarball-bytes"));
        body.extend(multipart_terminator(boundary));

        let req = build_multipart_request(boundary, body);
        let multipart = axum::extract::Multipart::from_request(req, &())
            .await
            .expect("multipart extract");
        let result = parse_multipart_file_with_json(multipart, &["module"]).await;
        assert!(
            result.is_ok(),
            "expected ok, got err: {:?}",
            result.is_err()
        );
        let (tarball, json) = result.unwrap();
        assert_eq!(&tarball[..], b"tarball-bytes");
        assert!(json.is_none());
    }

    #[tokio::test]
    async fn test_parse_multipart_file_and_json_succeeds() {
        let boundary = "BB";
        let mut body = Vec::new();
        body.extend(multipart_part(boundary, "file", b"data"));
        body.extend(multipart_part(
            boundary,
            "module",
            br#"{"name":"foo","version":"1.0.0"}"#,
        ));
        body.extend(multipart_terminator(boundary));

        let req = build_multipart_request(boundary, body);
        let multipart = axum::extract::Multipart::from_request(req, &())
            .await
            .unwrap();
        let (tarball, json) = parse_multipart_file_with_json(multipart, &["module"])
            .await
            .unwrap();
        assert_eq!(&tarball[..], b"data");
        let json = json.expect("json field present");
        assert_eq!(json["name"], "foo");
        assert_eq!(json["version"], "1.0.0");
    }

    #[tokio::test]
    async fn test_parse_multipart_first_matching_json_field_wins() {
        // Ansible accepts both "collection" and "metadata"; the helper
        // takes the FIRST matching field it sees.
        let boundary = "ZZ";
        let mut body = Vec::new();
        body.extend(multipart_part(boundary, "file", b"bytes"));
        body.extend(multipart_part(
            boundary,
            "collection",
            br#"{"who":"first"}"#,
        ));
        body.extend(multipart_part(boundary, "metadata", br#"{"who":"second"}"#));
        body.extend(multipart_terminator(boundary));

        let req = build_multipart_request(boundary, body);
        let multipart = axum::extract::Multipart::from_request(req, &())
            .await
            .unwrap();
        let (_, json) = parse_multipart_file_with_json(multipart, &["collection", "metadata"])
            .await
            .unwrap();
        // Last writer wins because the loop reassigns; tightening the contract
        // would change behavior. Just assert that one of them was selected.
        let who = json.unwrap()["who"].as_str().unwrap().to_string();
        assert!(who == "first" || who == "second");
    }

    #[tokio::test]
    async fn test_parse_multipart_unknown_fields_ignored() {
        let boundary = "QQ";
        let mut body = Vec::new();
        body.extend(multipart_part(boundary, "file", b"x"));
        body.extend(multipart_part(boundary, "extra", b"ignored"));
        body.extend(multipart_terminator(boundary));

        let req = build_multipart_request(boundary, body);
        let multipart = axum::extract::Multipart::from_request(req, &())
            .await
            .unwrap();
        let (tarball, json) = parse_multipart_file_with_json(multipart, &["module"])
            .await
            .unwrap();
        assert_eq!(&tarball[..], b"x");
        assert!(json.is_none());
    }

    #[tokio::test]
    async fn test_parse_multipart_missing_file_returns_400() {
        let boundary = "RR";
        let mut body = Vec::new();
        body.extend(multipart_part(boundary, "module", br#"{"name":"x"}"#));
        body.extend(multipart_terminator(boundary));

        let req = build_multipart_request(boundary, body);
        let multipart = axum::extract::Multipart::from_request(req, &())
            .await
            .unwrap();
        let err = parse_multipart_file_with_json(multipart, &["module"])
            .await
            .expect_err("missing file should error");
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_parse_multipart_empty_file_returns_400() {
        let boundary = "EE";
        let mut body = Vec::new();
        body.extend(multipart_part(boundary, "file", b""));
        body.extend(multipart_terminator(boundary));

        let req = build_multipart_request(boundary, body);
        let multipart = axum::extract::Multipart::from_request(req, &())
            .await
            .unwrap();
        let err = parse_multipart_file_with_json(multipart, &["module"])
            .await
            .expect_err("empty tarball should error");
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_parse_multipart_invalid_json_returns_400() {
        let boundary = "II";
        let mut body = Vec::new();
        body.extend(multipart_part(boundary, "file", b"data"));
        body.extend(multipart_part(boundary, "module", b"{not-valid"));
        body.extend(multipart_terminator(boundary));

        let req = build_multipart_request(boundary, body);
        let multipart = axum::extract::Multipart::from_request(req, &())
            .await
            .unwrap();
        let err = parse_multipart_file_with_json(multipart, &["module"])
            .await
            .expect_err("invalid JSON should error");
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_parse_multipart_accepts_any_listed_json_name() {
        // Puppet uses "module"; verify the helper accepts arbitrary names.
        let boundary = "PP";
        let mut body = Vec::new();
        body.extend(multipart_part(boundary, "file", b"tar"));
        body.extend(multipart_part(boundary, "puppet-meta", br#"{"k":"v"}"#));
        body.extend(multipart_terminator(boundary));

        let req = build_multipart_request(boundary, body);
        let multipart = axum::extract::Multipart::from_request(req, &())
            .await
            .unwrap();
        let (_, json) = parse_multipart_file_with_json(multipart, &["puppet-meta"])
            .await
            .unwrap();
        assert_eq!(json.unwrap()["k"], "v");
    }

    // -----------------------------------------------------------------------
    // DB-backed coverage for the async helpers extracted in this PR.
    //
    // Every test in this section starts with
    //
    //     let Some(pool) = db_helpers::try_pool().await else { return; };
    //
    // so the suite is a no-op without `DATABASE_URL` (matches the pattern in
    // conan.rs::test_helpers). The CI coverage job seeds Postgres + applies
    // migrations before running `cargo llvm-cov --lib`, so these tests do
    // execute and instrument the async helper bodies. Locally without a DB
    // they all skip cleanly.
    // -----------------------------------------------------------------------

    #[allow(dead_code)]
    mod db_helpers {
        use std::path::PathBuf;
        use std::sync::Arc;

        use sqlx::PgPool;
        use uuid::Uuid;

        use crate::api::{AppState, SharedState};
        use crate::config::Config;

        pub async fn try_pool() -> Option<PgPool> {
            let url = std::env::var("DATABASE_URL").ok()?;
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(3)
                .acquire_timeout(std::time::Duration::from_secs(3))
                .connect(&url)
                .await
                .ok()
        }

        fn test_config(storage_path: &str) -> Config {
            Config {
                database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
                bind_address: "127.0.0.1:0".into(),
                log_level: "error".into(),
                storage_backend: "filesystem".into(),
                storage_path: storage_path.into(),
                s3_bucket: None,
                gcs_bucket: None,
                s3_region: None,
                s3_endpoint: None,
                jwt_secret: "test-secret-at-least-32-bytes-long-for-testing".into(),
                jwt_expiration_secs: 86400,
                jwt_access_token_expiry_minutes: 30,
                jwt_refresh_token_expiry_days: 7,
                oidc_issuer: None,
                oidc_client_id: None,
                oidc_client_secret: None,
                ldap_url: None,
                ldap_base_dn: None,
                trivy_url: None,
                openscap_url: None,
                openscap_profile: "standard".into(),
                opensearch_url: None,
                opensearch_username: None,
                opensearch_password: None,
                opensearch_allow_invalid_certs: false,
                scan_workspace_path: "/tmp/scan".into(),
                demo_mode: false,
                guest_access_enabled: true,
                plugins_require_signed: true,
                plugins_trusted_pubkey: None,
                peer_instance_name: "test".into(),
                peer_public_endpoint: "http://localhost:8080".into(),
                peer_api_key: "test-key".into(),
                dependency_track_url: None,
                dependency_track_enabled: false,
                otel_exporter_otlp_endpoint: None,
                otel_service_name: "test".into(),
                gc_schedule: "0 0 * * * *".into(),
                blob_gc_enabled: false,
                lifecycle_check_interval_secs: 60,
                stuck_scan_threshold_secs: 1800,
                stuck_scan_check_interval_secs: 600,
                stuck_scan_reap_limit: 1000,
                allow_local_admin_login: false,
                max_upload_size_bytes: 10_737_418_240,
                metrics_port: None,
                database_max_connections: 20,
                database_min_connections: 5,
                database_acquire_timeout_secs: 30,
                database_idle_timeout_secs: 600,
                database_max_lifetime_secs: 1800,
                auth_max_concurrency: 8,
                global_max_concurrency: 512,
                global_request_timeout_secs: 120,
                rate_limit_enabled: true,
                rate_limit_auth_per_window: 120,
                rate_limit_api_per_window: 5000,
                rate_limit_search_per_window: 300,
                rate_limit_presign_per_window: 30,

                rate_limit_login_global_per_window: 8192,
                rate_limit_password_change_per_window: 5,
                rate_limit_password_change_window_secs: 900,
                rate_limit_window_secs: 60,
                rate_limit_exempt_usernames: Vec::new(),
                rate_limit_exempt_service_accounts: false,
                rate_limit_trusted_cidrs: Vec::new(),
                account_lockout_threshold: 5,
                account_lockout_duration_minutes: 30,
                quarantine_enabled: false,
                quarantine_duration_minutes: 60,
                password_history_count: 0,
                password_expiry_days: 0,
                password_expiry_warning_days: vec![14, 7, 1],
                password_expiry_check_interval_secs: 3600,
                password_min_length: 8,
                password_max_length: 128,
                password_require_uppercase: false,
                password_require_lowercase: false,
                password_require_digit: false,
                password_require_special: false,
                password_min_strength: 0,
                presigned_downloads_enabled: false,
                presigned_download_expiry_secs: 300,
                smtp_host: None,
                smtp_port: 587,
                smtp_username: None,
                smtp_password: None,
                smtp_from_address: "noreply@test.local".to_string(),
                smtp_tls_mode: "starttls".to_string(),
            }
        }

        pub fn build_state(pool: PgPool, storage_path: &str) -> SharedState {
            let storage: Arc<dyn crate::storage::StorageBackend> = Arc::new(
                crate::storage::filesystem::FilesystemStorage::new(storage_path),
            );
            let registry = Arc::new(crate::storage::StorageRegistry::new(
                std::collections::HashMap::new(),
                "filesystem".to_string(),
            ));
            Arc::new(AppState::new(
                test_config(storage_path),
                pool,
                storage,
                registry,
            ))
        }

        /// Build an `AppState` whose default storage backend is the named,
        /// caller-supplied `redirect_backend` and whose config has presigned
        /// downloads enabled. Used by the #1555 redirect test to drive
        /// `resolve_virtual_download_streaming` into its presigned-redirect
        /// fast path: `config.storage_backend` must resolve through the
        /// registry to a redirect-capable backend.
        pub fn build_state_presigned(
            pool: PgPool,
            backend_name: &str,
            redirect_backend: Arc<dyn crate::storage::StorageBackend>,
        ) -> SharedState {
            let mut config = test_config("/tmp/ph-presigned");
            config.presigned_downloads_enabled = true;
            config.storage_backend = backend_name.to_string();

            let mut backends: std::collections::HashMap<
                String,
                Arc<dyn crate::storage::StorageBackend>,
            > = std::collections::HashMap::new();
            backends.insert(backend_name.to_string(), redirect_backend.clone());
            let registry = Arc::new(crate::storage::StorageRegistry::new(
                backends,
                backend_name.to_string(),
            ));
            Arc::new(AppState::new(config, pool, redirect_backend, registry))
        }

        pub async fn create_user(pool: &PgPool) -> Uuid {
            let id = Uuid::new_v4();
            let username = format!("ph-test-u-{}", id);
            let _ = sqlx::query(
                r#"
                INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, is_active)
                VALUES ($1, $2, $3, 'unused-hash', 'local', false, true)
                "#,
            )
            .bind(id)
            .bind(&username)
            .bind(format!("{}@test.local", username))
            .execute(pool)
            .await
            .expect("create user");
            id
        }

        pub async fn create_repo(
            pool: &PgPool,
            repo_type: &str,
            format: &str,
        ) -> (Uuid, String, PathBuf) {
            let id = Uuid::new_v4();
            let key = format!("ph-test-{}-{}", format, id);
            let storage_dir = std::env::temp_dir().join(format!("ph-test-{}", id));
            std::fs::create_dir_all(&storage_dir).expect("create storage dir");

            let upstream_url: Option<&str> = if repo_type == "remote" {
                Some("https://upstream.example.test")
            } else {
                None
            };

            let sql = format!(
                "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, upstream_url) \
                 VALUES ($1, $2, $3, $4, '{}'::repository_type, '{}'::repository_format, $5)",
                repo_type, format
            );
            sqlx::query(&sql)
                .bind(id)
                .bind(&key)
                .bind(format!("ph-test-{}", id))
                .bind(storage_dir.to_string_lossy().as_ref())
                .bind(upstream_url)
                .execute(pool)
                .await
                .expect("create repo");
            (id, key, storage_dir)
        }

        /// Insert a `virtual_repo_members` row so `fetch_virtual_members`
        /// returns `member_repo_id` when resolving `virtual_repo_id`.
        pub async fn link_member(
            pool: &PgPool,
            virtual_repo_id: Uuid,
            member_repo_id: Uuid,
            priority: i32,
        ) {
            sqlx::query(
                "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
                 VALUES ($1, $2, $3)",
            )
            .bind(virtual_repo_id)
            .bind(member_repo_id)
            .bind(priority)
            .execute(pool)
            .await
            .expect("link virtual member");
        }

        pub async fn cleanup(pool: &PgPool, repo_id: Uuid, user_id: Uuid) {
            let _ = sqlx::query(
                "DELETE FROM artifact_metadata WHERE artifact_id IN \
                 (SELECT id FROM artifacts WHERE repository_id = $1)",
            )
            .bind(repo_id)
            .execute(pool)
            .await;
            let _ = sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
                .bind(repo_id)
                .execute(pool)
                .await;
            let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
                .bind(repo_id)
                .execute(pool)
                .await;
            let _ = sqlx::query("DELETE FROM users WHERE id = $1")
                .bind(user_id)
                .execute(pool)
                .await;
        }
    }

    // ── insert_artifact + find_artifact_by_name_lowercase ───────────────

    #[tokio::test]
    async fn test_insert_and_find_by_name_lowercase() {
        let Some(pool) = db_helpers::try_pool().await else {
            return;
        };
        let user_id = db_helpers::create_user(&pool).await;
        let (repo_id, _, _) = db_helpers::create_repo(&pool, "local", "npm").await;

        let id = insert_artifact(
            &pool,
            NewArtifact {
                repository_id: repo_id,
                path: "FooBar/1.0.0/foobar-1.0.0.tgz",
                name: "FooBar",
                version: "1.0.0",
                size_bytes: 7,
                checksum_sha256: "deadbeef",
                content_type: "application/x-tar",
                storage_key: "npm/foobar/1.0.0/foobar-1.0.0.tgz",
                uploaded_by: user_id,
            },
        )
        .await
        .expect("insert");

        // Case-insensitive lookup.
        let hit = find_artifact_by_name_lowercase(&pool, repo_id, "foobar")
            .await
            .expect("find")
            .expect("some");
        assert_eq!(hit.id, id);
        assert_eq!(hit.name, "FooBar");
        assert_eq!(hit.version.as_deref(), Some("1.0.0"));
        assert_eq!(hit.size_bytes, Some(7));
        // checksum_sha256 is CHAR(64), so the column comes back space-padded.
        assert!(
            hit.checksum_sha256
                .as_deref()
                .map(|s| s.trim_end().starts_with("deadbeef"))
                .unwrap_or(false),
            "got: {:?}",
            hit.checksum_sha256
        );

        // Miss returns None.
        let miss = find_artifact_by_name_lowercase(&pool, repo_id, "nope")
            .await
            .expect("ok");
        assert!(miss.is_none());

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }

    #[tokio::test]
    async fn test_find_artifact_by_name_version() {
        let Some(pool) = db_helpers::try_pool().await else {
            return;
        };
        let user_id = db_helpers::create_user(&pool).await;
        let (repo_id, _, _) = db_helpers::create_repo(&pool, "local", "npm").await;

        let _ = insert_artifact(
            &pool,
            NewArtifact {
                repository_id: repo_id,
                path: "lib/2.0.0/lib-2.0.0.tgz",
                name: "lib",
                version: "2.0.0",
                size_bytes: 100,
                checksum_sha256: "h",
                content_type: "application/x-tar",
                storage_key: "npm/lib/2.0.0/lib-2.0.0.tgz",
                uploaded_by: user_id,
            },
        )
        .await
        .expect("insert");

        let hit = find_artifact_by_name_version(&pool, repo_id, "LIB", "2.0.0")
            .await
            .expect("find")
            .expect("some");
        assert_eq!(hit.version.as_deref(), Some("2.0.0"));

        // Wrong version → None.
        let miss = find_artifact_by_name_version(&pool, repo_id, "lib", "9.9.9")
            .await
            .expect("ok");
        assert!(miss.is_none());

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }

    // ── list_artifacts_by_name_lowercase ────────────────────────────────

    #[tokio::test]
    async fn test_list_artifacts_by_name_lowercase_orders_newest_first() {
        let Some(pool) = db_helpers::try_pool().await else {
            return;
        };
        let user_id = db_helpers::create_user(&pool).await;
        let (repo_id, _, _) = db_helpers::create_repo(&pool, "local", "rubygems").await;

        // Insert 3 versions; the latest insert should sort first.
        for v in &["1.0.0", "1.1.0", "1.2.0"] {
            let _ = insert_artifact(
                &pool,
                NewArtifact {
                    repository_id: repo_id,
                    path: &format!("gem/{}/gem-{}.gem", v, v),
                    name: "gem",
                    version: v,
                    size_bytes: 10,
                    checksum_sha256: "c",
                    content_type: "application/octet-stream",
                    storage_key: &format!("rubygems/gem/{}/gem.gem", v),
                    uploaded_by: user_id,
                },
            )
            .await
            .expect("insert");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let list = list_artifacts_by_name_lowercase(&pool, repo_id, "gem")
            .await
            .expect("list");
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].version.as_deref(), Some("1.2.0"));
        assert_eq!(list[2].version.as_deref(), Some("1.0.0"));

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }

    #[tokio::test]
    async fn test_list_artifacts_by_name_returns_empty_on_miss() {
        let Some(pool) = db_helpers::try_pool().await else {
            return;
        };
        let user_id = db_helpers::create_user(&pool).await;
        let (repo_id, _, _) = db_helpers::create_repo(&pool, "local", "hex").await;

        let list = list_artifacts_by_name_lowercase(&pool, repo_id, "nothing")
            .await
            .expect("list");
        assert!(list.is_empty());

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }

    // ── find_local_by_filename_suffix ───────────────────────────────────

    #[tokio::test]
    async fn test_find_local_by_filename_suffix_hits() {
        let Some(pool) = db_helpers::try_pool().await else {
            return;
        };
        let user_id = db_helpers::create_user(&pool).await;
        let (repo_id, _, _) = db_helpers::create_repo(&pool, "local", "helm").await;

        let id = insert_artifact(
            &pool,
            NewArtifact {
                repository_id: repo_id,
                path: "charts/0.1.0/mychart-0.1.0.tgz",
                name: "mychart",
                version: "0.1.0",
                size_bytes: 5,
                checksum_sha256: "x",
                content_type: "application/gzip",
                storage_key: "helm/mychart/0.1.0/mychart-0.1.0.tgz",
                uploaded_by: user_id,
            },
        )
        .await
        .expect("insert");

        let hit = find_local_by_filename_suffix(&pool, repo_id, "mychart-0.1.0.tgz")
            .await
            .expect("find")
            .expect("some");
        assert_eq!(hit.id, id);
        assert_eq!(hit.storage_key, "helm/mychart/0.1.0/mychart-0.1.0.tgz");

        // Miss with non-matching suffix.
        let miss = find_local_by_filename_suffix(&pool, repo_id, "nope.tgz")
            .await
            .expect("ok");
        assert!(miss.is_none());

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }

    #[tokio::test]
    async fn test_find_local_by_filename_suffix_escapes_wildcards() {
        // SECURITY regression: a `%` in the filename suffix must be matched
        // literally, not as a wildcard. Without escape_like_literal, this
        // query would leak unrelated artifacts.
        let Some(pool) = db_helpers::try_pool().await else {
            return;
        };
        let user_id = db_helpers::create_user(&pool).await;
        let (repo_id, _, _) = db_helpers::create_repo(&pool, "local", "npm").await;

        // Seed an artifact whose path ends with a literal `wild.tgz`.
        let _ = insert_artifact(
            &pool,
            NewArtifact {
                repository_id: repo_id,
                path: "lib/1.0.0/wild.tgz",
                name: "lib",
                version: "1.0.0",
                size_bytes: 1,
                checksum_sha256: "x",
                content_type: "application/x-tar",
                storage_key: "npm/lib/1.0.0/wild.tgz",
                uploaded_by: user_id,
            },
        )
        .await
        .expect("insert");

        // A `%` in the search must not match the artifact above.
        let leak = find_local_by_filename_suffix(&pool, repo_id, "%.tgz")
            .await
            .expect("ok");
        assert!(
            leak.is_none(),
            "`%.tgz` must be escaped, not act as a LIKE wildcard"
        );

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }

    // ── ensure_unique_artifact_path ──────────────────────────────────────

    #[tokio::test]
    async fn test_ensure_unique_artifact_path_passes_when_absent() {
        let Some(pool) = db_helpers::try_pool().await else {
            return;
        };
        let user_id = db_helpers::create_user(&pool).await;
        let (repo_id, _, _) = db_helpers::create_repo(&pool, "local", "puppet").await;

        let result = ensure_unique_artifact_path(
            &pool,
            repo_id,
            "module/1.0.0/module-1.0.0.tar.gz",
            "Module version already exists",
        )
        .await;
        assert!(result.is_ok());

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }

    #[tokio::test]
    async fn test_ensure_unique_artifact_path_conflicts_on_existing() {
        let Some(pool) = db_helpers::try_pool().await else {
            return;
        };
        let user_id = db_helpers::create_user(&pool).await;
        let (repo_id, _, _) = db_helpers::create_repo(&pool, "local", "ansible").await;

        let _ = insert_artifact(
            &pool,
            NewArtifact {
                repository_id: repo_id,
                path: "coll/1.0.0/coll.tar.gz",
                name: "coll",
                version: "1.0.0",
                size_bytes: 1,
                checksum_sha256: "x",
                content_type: "application/gzip",
                storage_key: "ansible/coll/1.0.0/coll.tar.gz",
                uploaded_by: user_id,
            },
        )
        .await
        .expect("insert");

        let err = ensure_unique_artifact_path(
            &pool,
            repo_id,
            "coll/1.0.0/coll.tar.gz",
            "Collection version already exists",
        )
        .await
        .expect_err("conflict expected");
        assert_eq!(err.status(), StatusCode::CONFLICT);

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }

    // ── put_artifact_bytes + serve_local_artifact roundtrip ─────────────

    #[tokio::test]
    async fn test_put_and_serve_local_artifact_roundtrip() {
        let Some(pool) = db_helpers::try_pool().await else {
            return;
        };
        let user_id = db_helpers::create_user(&pool).await;
        let (repo_id, repo_key, storage_dir) =
            db_helpers::create_repo(&pool, "local", "cran").await;
        let state = db_helpers::build_state(pool.clone(), storage_dir.to_str().unwrap());

        let repo = RepoInfo {
            id: repo_id,
            key: repo_key,
            storage_path: storage_dir.to_string_lossy().into_owned(),
            storage_backend: "filesystem".to_string(),
            repo_type: "local".to_string(),
            upstream_url: None,
            promotion_only: false,
        };

        let bytes = Bytes::from_static(b"package-data");
        put_artifact_bytes(&state, &repo, "cran/foo/1.0/foo.tar.gz", bytes.clone())
            .await
            .expect("put");

        let artifact_id = insert_artifact(
            &pool,
            NewArtifact {
                repository_id: repo_id,
                path: "foo/1.0/foo.tar.gz",
                name: "foo",
                version: "1.0",
                size_bytes: bytes.len() as i64,
                checksum_sha256: "z",
                content_type: "application/gzip",
                storage_key: "cran/foo/1.0/foo.tar.gz",
                uploaded_by: user_id,
            },
        )
        .await
        .expect("insert");

        let resp = serve_local_artifact(
            &state,
            &repo,
            artifact_id,
            "cran/foo/1.0/foo.tar.gz",
            "application/gzip",
            Some("foo.tar.gz"),
        )
        .await
        .expect("serve");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("Content-Type").unwrap(),
            "application/gzip"
        );
        let cd = resp.headers().get("Content-Disposition").unwrap();
        assert!(cd.to_str().unwrap().contains("foo.tar.gz"));

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }

    // ── record_artifact_metadata ────────────────────────────────────────

    #[tokio::test]
    async fn test_record_artifact_metadata_stores_payload() {
        let Some(pool) = db_helpers::try_pool().await else {
            return;
        };
        let user_id = db_helpers::create_user(&pool).await;
        let (repo_id, _, _) = db_helpers::create_repo(&pool, "local", "rpm").await;

        let id = insert_artifact(
            &pool,
            NewArtifact {
                repository_id: repo_id,
                path: "p/1.0/p.rpm",
                name: "p",
                version: "1.0",
                size_bytes: 1,
                checksum_sha256: "x",
                content_type: "application/x-rpm",
                storage_key: "rpm/p/1.0/p.rpm",
                uploaded_by: user_id,
            },
        )
        .await
        .expect("insert");

        let meta = serde_json::json!({"arch": "x86_64", "release": "1.el9"});
        record_artifact_metadata(&pool, id, repo_id, "rpm", &meta).await;

        // Verify it was persisted.
        let stored: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT metadata FROM artifact_metadata WHERE artifact_id = $1")
                .bind(id)
                .fetch_optional(&pool)
                .await
                .expect("read meta")
                .flatten();
        assert!(stored.is_some());
        assert_eq!(stored.unwrap()["arch"], "x86_64");

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }

    #[tokio::test]
    async fn test_record_artifact_metadata_upserts() {
        let Some(pool) = db_helpers::try_pool().await else {
            return;
        };
        let user_id = db_helpers::create_user(&pool).await;
        let (repo_id, _, _) = db_helpers::create_repo(&pool, "local", "hex").await;

        let id = insert_artifact(
            &pool,
            NewArtifact {
                repository_id: repo_id,
                path: "x/1.0/x.tar",
                name: "x",
                version: "1.0",
                size_bytes: 1,
                checksum_sha256: "x",
                content_type: "application/x-tar",
                storage_key: "hex/x/1.0/x.tar",
                uploaded_by: user_id,
            },
        )
        .await
        .expect("insert");

        let m1 = serde_json::json!({"v": 1});
        record_artifact_metadata(&pool, id, repo_id, "hex", &m1).await;
        let m2 = serde_json::json!({"v": 2});
        record_artifact_metadata(&pool, id, repo_id, "hex", &m2).await;

        let stored: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT metadata FROM artifact_metadata WHERE artifact_id = $1")
                .bind(id)
                .fetch_optional(&pool)
                .await
                .expect("read meta")
                .flatten();
        assert_eq!(stored.unwrap()["v"], 2, "upsert should overwrite");

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }

    // ── try_remote_or_virtual_download: hosted returns Ok(None) ─────────

    #[tokio::test]
    async fn test_try_remote_or_virtual_download_hosted_returns_none() {
        let Some(pool) = db_helpers::try_pool().await else {
            return;
        };
        let user_id = db_helpers::create_user(&pool).await;
        let (repo_id, repo_key, storage_dir) = db_helpers::create_repo(&pool, "local", "npm").await;
        let state = db_helpers::build_state(pool.clone(), storage_dir.to_str().unwrap());

        let repo = RepoInfo {
            id: repo_id,
            key: repo_key,
            storage_path: storage_dir.to_string_lossy().into_owned(),
            storage_backend: "filesystem".to_string(),
            repo_type: "local".to_string(),
            upstream_url: None,
            promotion_only: false,
        };

        let opts = DownloadResponseOpts {
            upstream_path: "any/path",
            virtual_lookup: VirtualLookup::PathSuffix("any.tgz"),
            default_content_type: "application/octet-stream",
            content_disposition_filename: None,
            suppress_upstream_proxy: false,
        };
        let result = try_remote_or_virtual_download(&state, &repo, opts)
            .await
            .expect("ok");
        assert!(result.is_none(), "hosted repo must propagate to caller");

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }

    #[tokio::test]
    async fn test_try_remote_or_virtual_download_remote_without_proxy_is_none() {
        let Some(pool) = db_helpers::try_pool().await else {
            return;
        };
        let user_id = db_helpers::create_user(&pool).await;
        let (repo_id, repo_key, storage_dir) =
            db_helpers::create_repo(&pool, "remote", "npm").await;
        let state = db_helpers::build_state(pool.clone(), storage_dir.to_str().unwrap());

        let repo = RepoInfo {
            id: repo_id,
            key: repo_key,
            storage_path: storage_dir.to_string_lossy().into_owned(),
            storage_backend: "filesystem".to_string(),
            repo_type: "remote".to_string(),
            upstream_url: Some("https://upstream.example.test".to_string()),
            promotion_only: false,
        };

        // state.proxy_service is None: should short-circuit to Ok(None).
        let opts = DownloadResponseOpts {
            upstream_path: "any/path",
            virtual_lookup: VirtualLookup::PathSuffix("any.tgz"),
            default_content_type: "application/octet-stream",
            content_disposition_filename: None,
            suppress_upstream_proxy: false,
        };
        let result = try_remote_or_virtual_download(&state, &repo, opts)
            .await
            .expect("ok");
        assert!(result.is_none(), "no proxy service → Ok(None)");

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }

    #[tokio::test]
    async fn test_try_remote_or_virtual_download_remote_without_upstream_is_none() {
        let Some(pool) = db_helpers::try_pool().await else {
            return;
        };
        let user_id = db_helpers::create_user(&pool).await;
        let (repo_id, repo_key, storage_dir) = db_helpers::create_repo(&pool, "local", "npm").await;
        let state = db_helpers::build_state(pool.clone(), storage_dir.to_str().unwrap());

        let repo = RepoInfo {
            id: repo_id,
            key: repo_key,
            storage_path: storage_dir.to_string_lossy().into_owned(),
            storage_backend: "filesystem".to_string(),
            // Force the Remote branch but with upstream_url = None.
            repo_type: "remote".to_string(),
            upstream_url: None,
            promotion_only: false,
        };

        let opts = DownloadResponseOpts {
            upstream_path: "any/path",
            virtual_lookup: VirtualLookup::ExactPath("any/path"),
            default_content_type: "application/octet-stream",
            content_disposition_filename: None,
            suppress_upstream_proxy: false,
        };
        let result = try_remote_or_virtual_download(&state, &repo, opts)
            .await
            .expect("ok");
        assert!(result.is_none(), "no upstream URL: Ok(None)");

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }

    // ── local_fetch_by_path / local_fetch_by_path_suffix ─────────────────

    #[tokio::test]
    async fn test_local_fetch_by_path_returns_content() {
        let Some(pool) = db_helpers::try_pool().await else {
            return;
        };
        let user_id = db_helpers::create_user(&pool).await;
        let (repo_id, _, storage_dir) = db_helpers::create_repo(&pool, "local", "pypi").await;
        let state = db_helpers::build_state(pool.clone(), storage_dir.to_str().unwrap());

        // Put bytes via the storage helper to avoid filesystem surprises.
        let repo = RepoInfo {
            id: repo_id,
            key: "irrelevant".to_string(),
            storage_path: storage_dir.to_string_lossy().into_owned(),
            storage_backend: "filesystem".to_string(),
            repo_type: "local".to_string(),
            upstream_url: None,
            promotion_only: false,
        };
        let bytes = Bytes::from_static(b"abc123");
        put_artifact_bytes(&state, &repo, "pypi/foo/1.0/foo.whl", bytes.clone())
            .await
            .expect("put");

        let _ = insert_artifact(
            &pool,
            NewArtifact {
                repository_id: repo_id,
                path: "foo/1.0/foo.whl",
                name: "foo",
                version: "1.0",
                size_bytes: bytes.len() as i64,
                checksum_sha256: "x",
                content_type: "application/zip",
                storage_key: "pypi/foo/1.0/foo.whl",
                uploaded_by: user_id,
            },
        )
        .await
        .expect("insert");

        let location = repo.storage_location();
        let result = local_fetch_by_path(&pool, &state, repo_id, &location, "foo/1.0/foo.whl")
            .await
            .expect("fetch");
        let ct = result.content_type.clone();
        let content = result.collect().await.unwrap();
        assert_eq!(&content[..], b"abc123");
        assert_eq!(ct.as_deref(), Some("application/zip"));

        // Also exercise the suffix variant.
        let result2 = local_fetch_by_path_suffix(&pool, &state, repo_id, &location, "foo.whl")
            .await
            .expect("fetch suffix");
        let content2 = result2.collect().await.unwrap();
        assert_eq!(&content2[..], b"abc123");

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }

    // ── virtual_member_fetch_strategy tests ────────────────────────────
    //
    // These guard the fix for the virtual-download TTL bypass: Remote
    // members must go through the proxy service (which consults
    // __cache_meta__.json), not through local_fetch (which would return
    // proxy-cached bytes straight from the artifacts table without any
    // expiry check).

    use super::{virtual_member_fetch_strategy, VirtualMemberFetchStrategy};
    use crate::models::repository::RepositoryType;

    #[test]
    fn test_strategy_remote_with_proxy_and_upstream_goes_to_proxy() {
        assert_eq!(
            virtual_member_fetch_strategy(&RepositoryType::Remote, true, true),
            VirtualMemberFetchStrategy::Proxy,
        );
    }

    #[test]
    fn test_strategy_remote_without_proxy_service_is_skipped() {
        // Without a shared ProxyService we cannot honour TTL at all, so
        // rather than silently fall back to local_fetch (which would
        // bypass TTL) we skip the member.
        assert_eq!(
            virtual_member_fetch_strategy(&RepositoryType::Remote, false, true),
            VirtualMemberFetchStrategy::Skip,
        );
    }

    #[test]
    fn test_strategy_remote_without_upstream_url_is_skipped() {
        assert_eq!(
            virtual_member_fetch_strategy(&RepositoryType::Remote, true, false),
            VirtualMemberFetchStrategy::Skip,
        );
    }

    #[test]
    fn test_strategy_remote_without_anything_is_skipped() {
        assert_eq!(
            virtual_member_fetch_strategy(&RepositoryType::Remote, false, false),
            VirtualMemberFetchStrategy::Skip,
        );
    }

    #[test]
    fn test_strategy_local_always_goes_local_regardless_of_proxy() {
        // Local members don't have a proxy cache; the proxy_service
        // presence is irrelevant.
        assert_eq!(
            virtual_member_fetch_strategy(&RepositoryType::Local, true, true),
            VirtualMemberFetchStrategy::Local,
        );
        assert_eq!(
            virtual_member_fetch_strategy(&RepositoryType::Local, false, false),
            VirtualMemberFetchStrategy::Local,
        );
    }

    #[test]
    fn test_strategy_staging_goes_local() {
        assert_eq!(
            virtual_member_fetch_strategy(&RepositoryType::Staging, true, true),
            VirtualMemberFetchStrategy::Local,
        );
    }

    #[test]
    fn test_strategy_virtual_falls_through_to_local() {
        // Nested virtual repositories are not supported as members, but
        // if one ever appears we prefer a terminating Local lookup over
        // infinite proxy recursion.
        assert_eq!(
            virtual_member_fetch_strategy(&RepositoryType::Virtual, true, true),
            VirtualMemberFetchStrategy::Local,
        );
    }

    #[test]
    fn test_strategy_remote_with_only_upstream_no_proxy_skipped() {
        // Defence-in-depth: confirm that an orphan Remote member (one
        // with upstream_url set but no shared ProxyService) does not
        // accidentally fall back to local_fetch.
        let result = virtual_member_fetch_strategy(&RepositoryType::Remote, false, true);
        assert_ne!(result, VirtualMemberFetchStrategy::Local);
        assert_eq!(result, VirtualMemberFetchStrategy::Skip);
    }

    // -----------------------------------------------------------------------
    // build_streaming_response: pure response builder used by
    // proxy_fetch_streaming. Tests the new default_content_type fallback
    // and Content-Length passthrough rules without a live upstream or
    // storage backend. #895 review N2 / coverage gate.
    // -----------------------------------------------------------------------

    use crate::services::proxy_service::StreamingFetchResult;
    use futures::stream::BoxStream;

    fn empty_body() -> BoxStream<'static, crate::error::Result<bytes::Bytes>> {
        Box::pin(futures::stream::iter(Vec::new()))
    }

    #[test]
    fn test_build_streaming_response_uses_upstream_content_type_when_set() {
        let result = StreamingFetchResult {
            body: empty_body(),
            content_type: Some("application/java-archive".to_string()),
            content_length: None,
        };
        let response = build_streaming_response(result, "application/octet-stream")
            .expect("response build must succeed");
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/java-archive"),
            "upstream-supplied content_type MUST win over default"
        );
    }

    #[test]
    fn test_build_streaming_response_falls_back_to_default_when_upstream_omits() {
        let result = StreamingFetchResult {
            body: empty_body(),
            content_type: None,
            content_length: None,
        };
        let response =
            build_streaming_response(result, "text/xml").expect("response build must succeed");
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("text/xml"),
            "missing upstream content_type MUST fall back to the per-handler default \
             (Maven .pom -> text/xml, Go .zip -> application/zip, etc.) — the \
             #895 review N2 regression-prevention contract"
        );
    }

    #[test]
    fn test_build_streaming_response_sets_content_length_when_upstream_advertises_it() {
        let result = StreamingFetchResult {
            body: empty_body(),
            content_type: Some("application/octet-stream".to_string()),
            content_length: Some(12345),
        };
        let response = build_streaming_response(result, "application/octet-stream").unwrap();
        assert_eq!(
            response
                .headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok()),
            Some("12345"),
            "upstream Content-Length must round-trip to the outbound response \
             so clients with strict length-checking (some old apt/wget toolchains) \
             work as before"
        );
    }

    #[test]
    fn test_build_streaming_response_omits_content_length_when_upstream_does() {
        // Chunked-transfer-encoding case: upstream omits Content-Length,
        // outbound response also omits it so axum falls back to TE: chunked.
        let result = StreamingFetchResult {
            body: empty_body(),
            content_type: Some("application/octet-stream".to_string()),
            content_length: None,
        };
        let response = build_streaming_response(result, "application/octet-stream").unwrap();
        assert!(
            response.headers().get("content-length").is_none(),
            "absent upstream Content-Length must NOT be replaced with a synthetic \
             value (e.g. 0) — that would mis-advertise an empty body on a chunked \
             response and break clients"
        );
    }

    #[test]
    fn test_build_streaming_response_status_is_200() {
        let result = StreamingFetchResult {
            body: empty_body(),
            content_type: None,
            content_length: None,
        };
        let response = build_streaming_response(result, "application/octet-stream").unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_build_streaming_response_default_is_used_verbatim() {
        // Maven catch-all passes `content_type_for_path(path)` (which can
        // return any of ~8 mime types). The builder must use the supplied
        // string as-is, not lowercase / normalize / sniff.
        let weird = "application/vnd.android.package-archive";
        let result = StreamingFetchResult {
            body: empty_body(),
            content_type: None,
            content_length: None,
        };
        let response = build_streaming_response(result, weird).unwrap();
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some(weird)
        );
    }

    #[test]
    fn test_stream_fetch_result_sets_headers_and_disposition() {
        // The handler-facing convenience must emit the same headers as the
        // underlying builder: upstream content-type wins, content-length is set
        // when known, and a filename produces a Content-Disposition.
        let result = StreamingFetchResult {
            body: empty_body(),
            content_type: Some("application/zip".to_string()),
            content_length: Some(1234),
        };
        let response = stream_fetch_result(result, "application/octet-stream", Some("pkg.whl"))
            .expect("stream_fetch_result must build a response");
        assert_eq!(response.status(), StatusCode::OK);
        let h = response.headers();
        assert_eq!(
            h.get("content-type").and_then(|v| v.to_str().ok()),
            Some("application/zip")
        );
        assert_eq!(
            h.get("content-length").and_then(|v| v.to_str().ok()),
            Some("1234")
        );
        assert_eq!(
            h.get("content-disposition").and_then(|v| v.to_str().ok()),
            Some("attachment; filename=\"pkg.whl\"")
        );
    }

    #[test]
    fn test_stream_fetch_result_falls_back_to_default_and_omits_optionals() {
        // No upstream content-type, no length, no filename: default type is
        // used and neither content-length nor content-disposition is emitted.
        let result = StreamingFetchResult {
            body: empty_body(),
            content_type: None,
            content_length: None,
        };
        let response = stream_fetch_result(result, "application/octet-stream", None)
            .expect("stream_fetch_result must build a response");
        let h = response.headers();
        assert_eq!(
            h.get("content-type").and_then(|v| v.to_str().ok()),
            Some("application/octet-stream")
        );
        assert!(h.get("content-length").is_none());
        assert!(h.get("content-disposition").is_none());
    }

    // -------------------------------------------------------------------
    // #1183: behaviour-pin tests for the streaming-migration handlers.
    //
    // The slow-path remote fetch in five handlers (maven catch-all,
    // goproxy `.zip`, gitlfs blob, alpine `.apk`, debian pool) was
    // migrated from the buffered `proxy_fetch` helper to the streaming
    // `proxy_fetch_streaming` helper in #1181 to avoid the OOM kills
    // tracked in #895 / #737. The migration is invisible to existing
    // tests because both helpers return the same `Response` type and
    // the streaming helper has its own coverage via
    // `proxy_service::tests` — a silent rebase that swapped
    // `proxy_fetch_streaming` back to `proxy_fetch` would compile and
    // pass the suite while quietly re-introducing the OOM regression.
    //
    // These tests read each handler's source at test time (the file
    // is part of the same crate so the path is stable) and assert
    // that the remote-fetch arm still calls `proxy_fetch_streaming`.
    // Failure here means a contributor must either fix the regression
    // or, if the migration is intentionally being rolled back, delete
    // the matching test and document the reason in the PR.
    //
    // The matched substring is intentionally narrow (the
    // `proxy_helpers::proxy_fetch_streaming(` token) so a passing
    // mention in a comment or a different helper does not satisfy it.
    // -------------------------------------------------------------------

    const STREAMING_CALL_TOKEN: &str = "proxy_helpers::proxy_fetch_streaming(";

    /// One pin test per handler. Kept as separate `#[test]` functions
    /// (rather than a single loop) so a CI failure points directly at
    /// the regressing handler. The macro keeps the surface area small
    /// and stops the five near-identical functions from tripping the
    /// 3% duplication gate.
    macro_rules! streaming_pin_test {
        ($name:ident, $module_file:literal, $what:literal) => {
            #[test]
            fn $name() {
                let src = include_str!($module_file);
                assert!(
                    src.contains(STREAMING_CALL_TOKEN),
                    "{} handler MUST call `{}` for {} (#1183). A revert \
                     to the buffered `proxy_fetch` helper would re-introduce \
                     the OOM regression closed by #895/#1181.",
                    $module_file,
                    STREAMING_CALL_TOKEN,
                    $what,
                );
            }
        };
    }

    streaming_pin_test!(
        test_maven_remote_fetch_uses_streaming_helper_1183,
        "maven.rs",
        "the remote catch-all download"
    );
    streaming_pin_test!(
        test_goproxy_remote_fetch_uses_streaming_helper_1183,
        "goproxy.rs",
        "the remote `@v/<ver>.zip` download"
    );
    streaming_pin_test!(
        test_gitlfs_remote_fetch_uses_streaming_helper_1183,
        "gitlfs.rs",
        "the remote LFS blob download (large binaries)"
    );
    streaming_pin_test!(
        test_alpine_remote_fetch_uses_streaming_helper_1183,
        "alpine.rs",
        "the remote `.apk` download"
    );
    streaming_pin_test!(
        test_debian_remote_fetch_uses_streaming_helper_1183,
        "debian.rs",
        "the remote pool `.deb` download"
    );

    // -------------------------------------------------------------------
    // #1215: source-level pins for the remaining shared proxy paths.
    //
    // The buffered `proxy_fetch` helper previously satisfied two
    // download-miss paths shared across many format handlers:
    //
    //   * `try_remote_or_virtual_download` — Remote arm (used by rpm,
    //     rubygems, puppet, hex, huggingface, cran, ansible)
    //   * `resolve_virtual_download` — Remote-member arm of Virtual
    //     repository resolution
    //
    // Both arms now route through the streaming helper, eliminating the
    // last large-body buffering on the shared download surface. As with
    // the #1183 pins, these tests assert at compile-time-adjacent
    // granularity that nobody silently swaps the streaming helper back
    // for the buffered one. A failure here means a regression to the
    // OOM behaviour tracked in #895 / #737.
    //
    // Implementation note: both arms live inside `proxy_helpers.rs`,
    // so the pin reads its own source rather than another handler.
    // -------------------------------------------------------------------

    #[test]
    fn test_try_remote_or_virtual_download_remote_uses_streaming_helper_1215() {
        let src = include_str!("proxy_helpers.rs");
        let fn_start = src
            .find("pub async fn try_remote_or_virtual_download(")
            .expect("try_remote_or_virtual_download must exist");
        // Bound the window to just this function so the streaming token
        // from elsewhere in the file does not satisfy the assertion
        // vacuously. The closing brace of the function comes before the
        // next `pub` item; a generous window of 8 KiB safely covers it.
        let window_end = (fn_start + 8192).min(src.len());
        let window = &src[fn_start..window_end];
        assert!(
            window.contains("proxy_fetch_streaming_with_disposition("),
            "`try_remote_or_virtual_download`'s Remote arm MUST call \
             `proxy_fetch_streaming_with_disposition(` (#1215). A revert \
             to `proxy_fetch(` would re-introduce the OOM regression \
             closed by #895/#1215 across rpm/rubygems/puppet/hex/\
             huggingface/cran/ansible."
        );
        assert!(
            !window.contains("let (content, content_type) =\n            proxy_fetch("),
            "`try_remote_or_virtual_download`'s Remote arm MUST NOT call \
             the buffered `proxy_fetch(` for the upstream download (#1215)."
        );
    }

    #[test]
    fn test_try_remote_or_virtual_download_virtual_uses_streaming_resolver_1215() {
        let src = include_str!("proxy_helpers.rs");
        let fn_start = src
            .find("pub async fn try_remote_or_virtual_download(")
            .expect("try_remote_or_virtual_download must exist");
        let window_end = (fn_start + 8192).min(src.len());
        let window = &src[fn_start..window_end];
        assert!(
            window.contains("resolve_virtual_download_streaming("),
            "`try_remote_or_virtual_download`'s Virtual arm MUST call \
             `resolve_virtual_download_streaming(` (#1215) so Remote \
             members of a Virtual repo stream rather than buffer."
        );
        assert!(
            !window.contains("resolve_virtual_download(\n"),
            "`try_remote_or_virtual_download`'s Virtual arm MUST NOT \
             call the buffered `resolve_virtual_download(` (#1215)."
        );
    }

    #[test]
    fn test_resolve_virtual_download_streaming_uses_streaming_helper_1215() {
        let src = include_str!("proxy_helpers.rs");
        let fn_start = src
            .find("pub async fn resolve_virtual_download_streaming<")
            .expect("resolve_virtual_download_streaming must exist");
        let window_end = (fn_start + 4096).min(src.len());
        let window = &src[fn_start..window_end];
        assert!(
            window.contains("proxy_fetch_streaming_with_disposition("),
            "`resolve_virtual_download_streaming` MUST drive Remote \
             members through `proxy_fetch_streaming_with_disposition(` \
             (#1215). Buffering each Remote member's body before serving \
             it would defeat the whole point of having a streaming \
             resolver."
        );
    }

    #[test]
    fn test_resolve_virtual_download_streaming_redirects_before_streaming_1555() {
        // #1555: a fresh proxy-cache hit on an S3-backed member must be
        // served as a presigned redirect, NOT streamed through the
        // backend. Streaming holds a worker thread for the whole transfer
        // and saturates the dispatcher under burst load. The redirect
        // attempt must sit BEFORE the streaming fallback so cached bodies
        // never reach `proxy_fetch_streaming_with_disposition`.
        let src = include_str!("proxy_helpers.rs");
        let fn_start = src
            .find("pub async fn resolve_virtual_download_streaming<")
            .expect("resolve_virtual_download_streaming must exist");
        let window_end = (fn_start + 4096).min(src.len());
        let window = &src[fn_start..window_end];

        let redirect_pos = window.find("try_proxy_cache_redirect(").expect(
            "`resolve_virtual_download_streaming` MUST attempt \
             `try_proxy_cache_redirect(` for fresh proxy-cache hits (#1555).",
        );
        assert!(
            window.contains("is_cache_fresh("),
            "redirect fast-path MUST gate on a metadata-only \
             `is_cache_fresh(` probe (#1555) so it never pulls the body.",
        );
        let stream_pos = window
            .find("proxy_fetch_streaming_with_disposition(")
            .expect("streaming fallback must still exist (#1215)");
        assert!(
            redirect_pos < stream_pos,
            "the presigned redirect attempt (#1555) MUST come BEFORE the \
             streaming fallback (#1215); otherwise cached large artifacts \
             still stream through the backend.",
        );
    }

    #[test]
    fn test_proxy_cache_presign_uses_no_prefix_handle_1555() {
        // #1555: proxy-cache content lives at the storage ROOT (no global key
        // prefix), so every proxy-cache presign MUST sign through the proxy's
        // own no-prefix backend (`cache_storage_backend()`), never through the
        // prefixed `state.storage_for_repo(...)` handle — otherwise the signed
        // key carries the prefix and 404s in the object store.
        let src = include_str!("proxy_helpers.rs");

        for fn_name in [
            "pub async fn proxy_fetch_or_redirect(",
            "pub async fn resolve_virtual_download_streaming<",
            "pub async fn local_fetch_or_redirect(",
        ] {
            let fn_start = src
                .find(fn_name)
                .unwrap_or_else(|| panic!("{fn_name} must exist"));
            // Window large enough to cover the function body but bounded so a
            // later function's tokens cannot satisfy the assertion.
            let window_end = (fn_start + 4096).min(src.len());
            let window = &src[fn_start..window_end];

            assert!(
                window.contains("cache_storage_backend("),
                "`{fn_name}` MUST presign proxy-cache keys via \
                 `cache_storage_backend()` (the no-prefix handle), not the \
                 prefixed repo handle (#1555).",
            );
        }

        // The prefixed-handle presign for proxy-cache keys was the bug: the
        // proxy fast path must no longer reach for `storage_for_repo` to sign.
        let fn_start = src
            .find("pub async fn proxy_fetch_or_redirect(")
            .expect("proxy_fetch_or_redirect must exist");
        let window_end = (fn_start + 4096).min(src.len());
        let window = &src[fn_start..window_end];
        assert!(
            !window.contains("storage_for_repo("),
            "`proxy_fetch_or_redirect` MUST NOT sign proxy-cache keys through \
             the prefixed `storage_for_repo(` handle (#1555).",
        );
    }

    /// Proxy-cache storage mock (the `StorageService` trait) that reports a
    /// single fresh, positive cache entry. The metadata sidecar deserializes
    /// to a non-expired `CacheMetadata` with no pinned ETag, so
    /// `ProxyService::is_cache_fresh` takes the existence-check branch and the
    /// `__content__` key reports as present. The body itself is never read on
    /// the fast path, so `get` of the content key returns NotFound to surface
    /// any accidental download as a failure.
    struct FreshProxyCacheStorage;

    #[async_trait::async_trait]
    impl crate::services::storage_service::StorageBackend for FreshProxyCacheStorage {
        async fn put(&self, _key: &str, _content: Bytes) -> crate::error::Result<()> {
            Ok(())
        }
        async fn get(&self, key: &str) -> crate::error::Result<Bytes> {
            if key.ends_with("__cache_meta__.json") {
                let meta = crate::services::proxy_service::CacheMetadata {
                    cached_at: Utc::now(),
                    upstream_etag: None,
                    storage_etag: None,
                    last_modified: None,
                    negative_cached_until: None,
                    quarantine_until: None,
                    expires_at: Utc::now() + chrono::Duration::seconds(3600),
                    content_type: Some("application/octet-stream".to_string()),
                    size_bytes: 9,
                    checksum_sha256: "deadbeef".to_string(),
                };
                Ok(Bytes::from(serde_json::to_vec(&meta).unwrap()))
            } else {
                Err(crate::error::AppError::NotFound(key.to_string()))
            }
        }
        async fn exists(&self, _key: &str) -> crate::error::Result<bool> {
            // Both the content key and the metadata sidecar report present.
            Ok(true)
        }
        async fn delete(&self, _key: &str) -> crate::error::Result<()> {
            Ok(())
        }
        async fn list(&self, _prefix: Option<&str>) -> crate::error::Result<Vec<String>> {
            Ok(Vec::new())
        }
        async fn copy(&self, _source: &str, _dest: &str) -> crate::error::Result<()> {
            Ok(())
        }
        async fn size(&self, _key: &str) -> crate::error::Result<u64> {
            Ok(9)
        }
        // #1555: this is the proxy's OWN no-prefix backend (`cache_storage_backend`),
        // so it must report redirect support and sign the key verbatim — no
        // `artifact-keeper/` prefix is added. The signed URL echoes the key so
        // tests can assert the no-prefix layout end to end.
        fn supports_redirect(&self) -> bool {
            true
        }
        async fn get_presigned_url(
            &self,
            key: &str,
            expires_in: std::time::Duration,
        ) -> crate::error::Result<Option<crate::storage::PresignedUrl>> {
            Ok(Some(crate::storage::PresignedUrl {
                url: format!("https://signed.example.com/{}", key),
                expires_in,
                source: crate::storage::PresignedUrlSource::S3,
            }))
        }
    }

    /// #1555 runtime coverage: a fresh proxy-cache hit on an S3-backed Remote
    /// member of a Virtual repo must be served as a presigned 302 redirect,
    /// NOT streamed through the backend.
    ///
    /// This drives the real `resolve_virtual_download_streaming` redirect
    /// branch end to end: a Remote member is resolved from the DB, the proxy
    /// reports the cache as fresh, the default storage backend supports
    /// redirects, and the helper returns a 302 with a `Location` header. The
    /// `local_fetch` closure panics if invoked, proving the redirect fired
    /// before any streaming / local fallback.
    ///
    /// DB-gated like the other `try_pool` tests: skips when `DATABASE_URL` is
    /// unset (no live Postgres), runs in CI where one is provisioned.
    #[tokio::test]
    async fn test_resolve_virtual_download_streaming_returns_presigned_redirect_1555() {
        let Some(pool) = db_helpers::try_pool().await else {
            return;
        };

        // Virtual repo with one Remote member.
        let (virtual_id, _, _) = db_helpers::create_repo(&pool, "virtual", "pypi").await;
        let (member_id, _member_key, _) = db_helpers::create_repo(&pool, "remote", "pypi").await;
        db_helpers::link_member(&pool, virtual_id, member_id, 0).await;

        // Registry-side backend is irrelevant here: #1555 signs proxy-cache
        // keys through the PROXY's own no-prefix backend, not the registry
        // handle. We assert the registry backend is never touched for presign.
        let registry_storage = StdArc::new(RecordingStorage::new(/* supports = */ true));
        let state =
            db_helpers::build_state_presigned(pool.clone(), "s3-test", registry_storage.clone());

        // ProxyService whose own (no-prefix) backend reports the cache fresh
        // AND presigns, echoing the signed key into the URL.
        let proxy = ProxyService::new(
            pool.clone(),
            StdArc::new(crate::services::storage_service::StorageService::new(
                StdArc::new(FreshProxyCacheStorage),
            )),
        );

        let resp = resolve_virtual_download_streaming(
            &state,
            Some(&proxy),
            virtual_id,
            "pkg/pkg-1.0.0-py3-none-any.whl",
            "application/octet-stream",
            None,
            // Remote member must redirect before reaching any local fetch.
            |_id, _loc| async {
                panic!("local_fetch must NOT run: the redirect fast path should win");
                #[allow(unreachable_code)]
                Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
            },
        )
        .await
        .expect("fresh cache hit must resolve to a redirect, not an error");

        assert_eq!(
            resp.status(),
            StatusCode::FOUND,
            "fresh proxy-cache hit on an S3-backed member must yield a 302 \
             redirect (#1555), not a streamed 200"
        );
        let location = resp
            .headers()
            .get("location")
            .expect("redirect must carry a Location header")
            .to_str()
            .unwrap();
        assert!(
            location.contains("signed.example.com"),
            "Location must point at the presigned URL, got {}",
            location
        );
        // #1555 core assertion: the signed key has NO global prefix — it is the
        // raw proxy-cache key starting with `proxy-cache/`, never wrapped in an
        // `artifact-keeper/` (or any) prefix. Signing through a prefixed handle
        // was the original bug; the no-prefix backend fixes it.
        assert!(
            location.contains("/proxy-cache/"),
            "signed key must be the no-prefix proxy-cache key, got {}",
            location
        );
        assert!(
            !location.contains("artifact-keeper/"),
            "signed key must NOT carry a global prefix (#1555), got {}",
            location
        );
        // The registry-side backend must never be asked to presign: proxy-cache
        // signing goes exclusively through the proxy's no-prefix handle.
        assert_eq!(
            registry_storage.presigned_calls.load(Ordering::SeqCst),
            0,
            "registry backend must NOT presign proxy-cache keys (#1555)"
        );

        db_helpers::cleanup(&pool, virtual_id, Uuid::nil()).await;
        db_helpers::cleanup(&pool, member_id, Uuid::nil()).await;
    }

    /// #1555 filesystem fallthrough: `local_fetch_or_redirect` on a proxy-cache
    /// key (`is_proxy_cache_key(...) == true`) must select the proxy's
    /// no-prefix `cache_storage_backend()` handle, attempt a presigned
    /// redirect, and — because that handle is filesystem-backed and reports
    /// `supports_redirect() == false` — fall through to STREAMING a 200 with
    /// the body. This is the core non-regression guarantee on the rig / any
    /// non-S3 deployment: the new proxy-cache handle-selection branch must not
    /// break filesystem serving. DB-gated (runs in CI where Postgres exists).
    #[tokio::test]
    async fn test_local_fetch_or_redirect_proxy_cache_key_streams_on_filesystem_1555() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("remote", "pypi").await else {
            return;
        };

        let storage_path = fx.storage_dir.to_str().unwrap().to_string();
        // Presigned ENABLED + a filesystem-backed proxy service whose
        // cache_storage_backend() reports supports_redirect() == false.
        let proxy = tdh::build_proxy_service_with_fs(fx.pool.clone(), &storage_path);
        let state =
            tdh::build_state_with_proxy_presigned(fx.pool.clone(), &storage_path, proxy.clone());
        let repo_info = tdh::make_repo_info(
            fx.repo_id,
            &fx.repo_key,
            &fx.storage_dir,
            "remote",
            Some("https://upstream.example.test"),
        );

        // Seed a proxy-cache artifact: the storage_key starts with
        // `proxy-cache/`, so is_proxy_cache_key() is true and the no-prefix
        // handle branch is taken.
        let body: &[u8] = b"cached-fs";
        let artifact_path = "simple/foo/foo-1.0-py3-none-any.whl";
        let storage_key = format!("proxy-cache/{}/{}", fx.repo_key, artifact_path);
        assert!(crate::services::proxy_service::ProxyService::is_proxy_cache_key(&storage_key));

        super::put_artifact_bytes(&state, &repo_info, &storage_key, Bytes::from_static(body))
            .await
            .expect("seed proxy-cache payload on disk");
        sqlx::query(
            "INSERT INTO artifacts ( \
                 repository_id, path, name, version, size_bytes, \
                 checksum_sha256, content_type, storage_key, uploaded_by \
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(fx.repo_id)
        .bind(artifact_path)
        .bind("foo")
        .bind("1.0")
        .bind(body.len() as i64)
        .bind("test-foo")
        .bind("application/zip")
        .bind(&storage_key)
        .bind(fx.user_id)
        .execute(&fx.pool)
        .await
        .expect("seed proxy-cache artifact row");

        let location = repo_info.storage_location();
        let result =
            super::local_fetch_or_redirect(&fx.pool, &state, fx.repo_id, &location, artifact_path)
                .await;

        // Clean up before asserting so a panic still leaves the DB clean.
        fx.teardown().await;

        let resp = result.expect("filesystem proxy-cache fetch must succeed by streaming");
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "filesystem proxy-cache key must stream a 200 (no 302) on non-S3 (#1555)"
        );
        assert!(
            resp.headers().get("location").is_none(),
            "filesystem backend must NOT emit a redirect Location header (#1555)"
        );
    }

    // ── #1804: per-member authorization for virtual repos ───────────────

    /// Build an in-memory `Repository` for member-authorization tests. Only the
    /// fields the access decision reads (`id`, `is_public`) are meaningful; the
    /// rest are inert defaults. Keeping this local avoids duplicating the wide
    /// struct literal across each member variant (jscpd).
    fn member_repo(id: Uuid, is_public: bool) -> Repository {
        Repository {
            id,
            key: format!("member-{}", id.simple()),
            name: "member".to_string(),
            description: None,
            format: RepositoryFormat::Maven,
            repo_type: RepositoryType::Local,
            storage_backend: "filesystem".to_string(),
            storage_path: "/tmp/member-1804".to_string(),
            upstream_url: None,
            is_public,
            quota_bytes: None,
            promotion_only: false,
            replication_priority: ReplicationPriority::OnDemand,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 0,
            curation_auto_fetch: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn nonadmin_auth(user_id: Uuid) -> crate::api::middleware::auth::AuthExtension {
        crate::api::middleware::auth::AuthExtension {
            user_id,
            username: "u1804".to_string(),
            email: "u1804@test.local".to_string(),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: None,
        }
    }

    /// Verified-bug regression for #1804: a public virtual repo must not serve a
    /// PRIVATE member's bytes to a caller who could not read that member
    /// directly. This drives the exact authorization predicate the maven
    /// download path now applies to every member before fetching bytes:
    ///
    ///   * public member            -> readable by anyone (even anonymous);
    ///   * private member, no rules  -> readable by any authenticated user,
    ///                                   denied to anonymous (matches the
    ///                                   middleware's default access model);
    ///   * private member WITH rules -> only the caller holding `read` may
    ///                                   read it; admins are exempt.
    ///
    /// `authorize_virtual_members` then drops the members the caller could not
    /// read, so a denied private member behaves as a 404 (never leaked) — the
    /// fix for the confused-deputy aggregation bypass.
    #[tokio::test]
    async fn test_caller_can_read_member_blocks_private_member_1804() {
        let Some(pool) = db_helpers::try_pool().await else {
            return;
        };
        let storage_dir = std::env::temp_dir().join(format!("p1804-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&storage_dir).expect("storage dir");
        let state = db_helpers::build_state(pool.clone(), storage_dir.to_str().unwrap());
        let perms = state.permission_service.as_ref();

        // Two private members: one with NO fine-grained rules, one WITH rules
        // (so the user must hold `read`). Plus a public member.
        let public_id = Uuid::new_v4();
        let private_norules_id = Uuid::new_v4();
        let private_ruled_id = Uuid::new_v4();

        let user_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, is_active) \
             VALUES ($1, $2, $3, 'unused', 'local', false, true)",
        )
        .bind(user_id)
        .bind(format!("u1804-{}", user_id.simple()))
        .bind(format!("u1804-{}@test.local", user_id.simple()))
        .execute(&pool)
        .await
        .expect("create user");

        // A rule on `private_ruled_id` (granted to an unrelated principal) makes
        // `has_any_rules_for_target` true, so the member is gated by `read`.
        sqlx::query(
            "INSERT INTO permissions (principal_type, principal_id, target_type, target_id, actions) \
             VALUES ('user', $1, 'repository', $2, ARRAY['read'])",
        )
        .bind(Uuid::new_v4())
        .bind(private_ruled_id)
        .execute(&pool)
        .await
        .expect("seed ruled-member permission");

        let public = member_repo(public_id, true);
        let private_norules = member_repo(private_norules_id, false);
        let private_ruled = member_repo(private_ruled_id, false);

        let auth = nonadmin_auth(user_id);
        let admin = crate::api::middleware::auth::AuthExtension {
            is_admin: true,
            ..nonadmin_auth(Uuid::new_v4())
        };

        // Public member: everyone, including anonymous.
        assert!(caller_can_read_member(perms, None, &public).await);
        assert!(caller_can_read_member(perms, Some(&auth), &public).await);

        // Private member, no rules: anonymous denied, authenticated allowed.
        assert!(
            !caller_can_read_member(perms, None, &private_norules).await,
            "anonymous must NOT read a private member (the #1804 leak)"
        );
        assert!(caller_can_read_member(perms, Some(&auth), &private_norules).await);

        // Private member WITH rules: anonymous + zero-grant user denied.
        assert!(!caller_can_read_member(perms, None, &private_ruled).await);
        assert!(
            !caller_can_read_member(perms, Some(&auth), &private_ruled).await,
            "zero-grant non-admin must NOT read a ruled private member (#1804)"
        );
        // Admins are exempt.
        assert!(caller_can_read_member(perms, Some(&admin), &private_ruled).await);

        // The aggregating filter drops members the anonymous caller cannot read,
        // leaving only the public member (so private members never serve bytes).
        let members = vec![
            public.clone(),
            private_norules.clone(),
            private_ruled.clone(),
        ];
        let allowed_anon = authorize_virtual_members(perms, None, members.clone()).await;
        assert_eq!(
            allowed_anon.iter().map(|m| m.id).collect::<Vec<_>>(),
            vec![public_id],
            "anonymous virtual aggregation must keep ONLY public members (#1804)"
        );

        // Grant the user `read` on the ruled member -> it becomes readable, and a
        // fresh PermissionService (fresh cache) observes the new grant.
        sqlx::query(
            "INSERT INTO permissions (principal_type, principal_id, target_type, target_id, actions) \
             VALUES ('user', $1, 'repository', $2, ARRAY['read'])",
        )
        .bind(user_id)
        .bind(private_ruled_id)
        .execute(&pool)
        .await
        .expect("grant user read");
        let state2 = db_helpers::build_state(pool.clone(), storage_dir.to_str().unwrap());
        let perms2 = state2.permission_service.as_ref();
        let allowed_user = authorize_virtual_members(perms2, Some(&auth), members).await;
        assert_eq!(
            allowed_user
                .iter()
                .map(|m| m.id)
                .collect::<std::collections::HashSet<_>>(),
            std::collections::HashSet::from([public_id, private_norules_id, private_ruled_id]),
            "a user granted read on the member must still see it (no over-restriction)"
        );

        // -- Cleanup.
        let _ = sqlx::query("DELETE FROM permissions WHERE target_id = ANY($1)")
            .bind(vec![private_ruled_id])
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&storage_dir);
    }
}
