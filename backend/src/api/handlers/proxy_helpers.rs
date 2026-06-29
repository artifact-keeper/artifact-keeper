//! Shared helpers for remote repository proxying and virtual repository resolution.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use chrono::Utc;
use futures::StreamExt;
use sqlx::PgPool;
use uuid::Uuid;

use crate::api::download_response::try_presigned_redirect;
use crate::api::handlers::error_helpers::{map_db_err, map_storage_err};
use crate::api::AppState;
use crate::error::AppError;
use crate::formats::pypi::PypiHandler;
use crate::models::repository::{
    ReplicationPriority, Repository, RepositoryFormat, RepositoryType,
};
use crate::services::proxy_hydration::{Coordinator, HydrationCoordinator};
use crate::services::proxy_service::ProxyService;
pub use crate::services::proxy_service::StreamingFetchResult;
// Re-export the per-format buffered-metadata byte ceilings (#1608 Phase 4b /
// #2181) so format handlers select a cap via `proxy_helpers::<CONST>`.
pub use crate::services::proxy_service::{DEFAULT_METADATA_MAX_BYTES, LARGE_METADATA_MAX_BYTES};
use crate::storage::StorageLocation;
use std::future::Future;
use std::path::{Path, PathBuf};
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
    pub format: String,
    pub upstream_url: Option<String>,
    pub promotion_only: bool,
    pub age_gate_enabled: bool,
    pub age_gate_min_age_days: i32,
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
         repo_type::text as repo_type, upstream_url, promotion_only, \
         age_gate_enabled, age_gate_min_age_days \
         FROM repositories WHERE key = $1",
    )
    .bind(repo_key)
    .fetch_optional(db)
    .await
    // Route through map_db_err so a saturated pool surfaces as 503 (capacity
    // shed) instead of 500, and so the raw DB error text is not leaked to the
    // client. This is the first DB acquire on every proxy GET (#1437).
    .map_err(map_db_err)?
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
        format: fmt,
        upstream_url: repo.try_get("upstream_url").ok(),
        promotion_only: repo.try_get("promotion_only").unwrap_or(false),
        age_gate_enabled: repo.try_get("age_gate_enabled").unwrap_or(false),
        age_gate_min_age_days: repo.try_get("age_gate_min_age_days").unwrap_or(7),
    })
}

/// Map an error to a 500 Internal Server Error plain-text response.
///
/// The `label` is prepended to the error message (e.g. "Storage", "Database").
/// This avoids repeating the five-line `(StatusCode::INTERNAL_SERVER_ERROR,
/// format!("... error: {}", e)).into_response()` block throughout the
/// local_fetch helpers.
pub(crate) fn internal_error(label: &str, e: impl std::fmt::Display) -> Response {
    let text = e.to_string();
    // A saturated sqlx pool is a transient capacity event, not a server fault.
    // Every local/virtual-member artifact-lookup helper funnels DB errors
    // through here, so route pool timeouts via map_db_err to surface 503 +
    // Retry-After (clients back off) instead of a bare 500 (#1437). Non-DB
    // labels (e.g. "Storage") never produce this phrase, so they are unaffected.
    if crate::error::is_pool_timeout(&text) {
        return map_db_err(text);
    }
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("{} error: {}", label, text),
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

/// Decide whether a direct user delete must be rejected because the target
/// repository is flagged `promotion_only`.
///
/// A `promotion_only` repository is a release/production repository whose
/// contents may only be mutated through the promotion workflow (staging ->
/// promotion -> approval). The write gate already blocks direct uploads to
/// such repos; a direct DELETE is the symmetric mutation and would let a
/// principal with plain repo-write access permanently destroy a released
/// artifact, bypassing the same controls.
///
/// Unlike the upload gate, delete keeps an escape hatch for release-approvers
/// (`is_admin` == approver here: `approve_promotion` requires `is_admin`) so a
/// genuinely bad release can still be retracted through the API — mirroring the
/// admin exemption in `delete_blocked_by_immutability`. Non-admins are rejected.
///
/// The promotion service writes through its own RAW SQL path, which does not
/// traverse the HTTP delete handlers, so promotions are unaffected. A repo with
/// `promotion_only = false` is never affected (no-op for all callers).
pub fn promotion_only_blocks_direct_delete(promotion_only: bool, is_admin: bool) -> bool {
    promotion_only && !is_admin
}

/// 403 plain-text response for a rejected direct delete on a `promotion_only`
/// repository. Provided for `Response`-returning call sites so both delete
/// handlers share one message/shape.
#[allow(clippy::result_large_err)]
pub fn reject_direct_delete_if_promotion_only(
    promotion_only: bool,
    is_admin: bool,
) -> Result<(), Response> {
    if promotion_only_blocks_direct_delete(promotion_only, is_admin) {
        Err((
            StatusCode::FORBIDDEN,
            "Direct deletes are disabled for this release repository; retract via an approver/promotion workflow",
        )
            .into_response())
    } else {
        Ok(())
    }
}

/// Strip query strings and fragments before logging a proxy path. Some
/// split-path proxy callers fetch absolute, signed upstream URLs while caching
/// under a stable local key; the fetch target must remain raw for the outbound
/// request, but diagnostics must not preserve credential-bearing URL material.
fn redact_proxy_path_for_diagnostics(path: &str) -> String {
    if let Ok(mut parsed) = reqwest::Url::parse(path) {
        parsed.set_query(None);
        parsed.set_fragment(None);
        return parsed.to_string();
    }

    let query_pos = path.find('?');
    let fragment_pos = path.find('#');
    let end = match (query_pos, fragment_pos) {
        (Some(q), Some(f)) => q.min(f),
        (Some(q), None) => q,
        (None, Some(f)) => f,
        (None, None) => path.len(),
    };
    path[..end].to_string()
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
    let diagnostic_path = redact_proxy_path_for_diagnostics(path);
    match &e {
        crate::error::AppError::NotFound(_) => {
            tracing::info!(
                repo_key = %repo_key,
                path = %diagnostic_path,
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
                path = %diagnostic_path,
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
                path = %diagnostic_path,
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
                path = %diagnostic_path,
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
                path = %diagnostic_path,
                "Proxy download forbidden by quarantine policy: {}",
                e
            );
            (StatusCode::FORBIDDEN, msg.clone()).into_response()
        }
        _ => {
            tracing::warn!(
                repo_key = %repo_key,
                path = %diagnostic_path,
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

/// Byte-ceiling-bounded sibling of [`proxy_fetch`] (#1608 Phase 4b / #2181).
///
/// Identical to [`proxy_fetch`] except the buffered upstream *metadata* read is
/// capped at `max` bytes: a hostile or broken upstream that streams more than
/// `max` yields a 502 instead of an unbounded buffer that OOMs the pod, and no
/// truncated body is ever cached. Callers pass the per-format ceiling
/// ([`DEFAULT_METADATA_MAX_BYTES`] for most formats, [`LARGE_METADATA_MAX_BYTES`]
/// for formats with legitimately large metadata documents). This is the
/// buffered-metadata path only — large binaries must use [`proxy_fetch_streaming`].
pub async fn proxy_fetch_capped(
    proxy_service: &ProxyService,
    repo_id: Uuid,
    repo_key: &str,
    upstream_url: &str,
    path: &str,
    max: usize,
) -> Result<(Bytes, Option<String>), Response> {
    with_proxy_repo(repo_id, repo_key, upstream_url, path, |repo| async move {
        proxy_service.fetch_artifact_capped(&repo, path, max).await
    })
    .await
}

/// Byte-ceiling-bounded sibling of [`proxy_fetch_with_accept`] (#1608 Phase 4b /
/// #2181). See [`proxy_fetch_capped`] for the `max` semantics.
pub async fn proxy_fetch_capped_with_accept(
    proxy_service: &ProxyService,
    repo_id: Uuid,
    repo_key: &str,
    upstream_url: &str,
    path: &str,
    accept: Option<&str>,
    max: usize,
) -> Result<(Bytes, Option<String>), Response> {
    with_proxy_repo(repo_id, repo_key, upstream_url, path, |repo| async move {
        proxy_service
            .fetch_artifact_with_accept_capped(&repo, path, accept, max)
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

/// Streaming fetch of `path` from a virtual member, using the member's REAL
/// repository record so its `format` drives cache classification (#2069 bug 1)
/// instead of the synthesized `Generic` stand-in [`build_remote_repo`] would
/// produce. Builds a ready-to-serve [`Response`]; errors are mapped to a
/// [`Response`] exactly as [`proxy_fetch_streaming_with_disposition`] does, so
/// the streaming virtual-download path can detect a quarantine block via
/// [`is_quarantine_block_response`].
async fn proxy_fetch_streaming_member(
    proxy_service: &ProxyService,
    member: &Repository,
    path: &str,
    default_content_type: &str,
    content_disposition_filename: Option<&str>,
) -> Result<Response, Response> {
    let result = proxy_service
        .fetch_artifact_streaming(member, path)
        .await
        .map_err(|e| map_proxy_error(&member.key, path, e))?;
    build_streaming_response_with_disposition(
        result,
        default_content_type,
        content_disposition_filename,
    )
    .map_err(|e| {
        map_proxy_error(
            &member.key,
            path,
            crate::error::AppError::Internal(e.to_string()),
        )
    })
}

/// #1555 presigned-redirect fast path for a single virtual member: when the
/// member's proxy cache holds a FRESH copy of `path` and the cache storage
/// backend supports redirects, return a presigned redirect [`Response`] so the
/// backend never streams a large body itself (streaming holds a worker thread
/// for the whole transfer; under burst load that cascades into 502s). Returns
/// `None` when a redirect does not apply (presigned downloads disabled,
/// non-redirecting backend, or cache not fresh), in which case the caller falls
/// back to a streaming cache probe / upstream fetch.
///
/// #2075: a fresh entry still inside its Package Age Policy hold window is
/// NEVER presigned. The gate returns `None` so the member falls through to the
/// streaming cache probe, which classifies the held entry `NeedsUpstream`; the
/// Pass-2 re-resolve then re-detects the hold on the cached entry and surfaces
/// the 409/403 via `map_proxy_error` WITHOUT contacting upstream (see
/// [`classify_streaming_cache_probe`] / [`classify_stream_upstream`]).
async fn try_member_cache_redirect(
    state: &AppState,
    proxy: &ProxyService,
    member: &Repository,
    path: &str,
) -> Option<Response> {
    if !state.config.presigned_downloads_enabled {
        return None;
    }
    let storage = proxy.cache_storage_backend();
    let cache_key = ProxyService::cache_storage_key(&member.key, path).ok()?;
    if !(storage.supports_redirect() && proxy.is_cache_fresh(&member.key, path).await) {
        return None;
    }
    // #2075: gate the redirect on the hold window (mirrors the gate in
    // `proxy_fetch_or_redirect`). A held entry must not be handed out as a
    // 302; falling through routes it onto the quarantine-surfacing path.
    if proxy
        .cache_quarantine_gate(&member.key, path)
        .await
        .is_err()
    {
        return None;
    }
    let expiry = Duration::from_secs(state.config.presigned_download_expiry_secs);
    try_proxy_cache_redirect(
        storage.as_ref(),
        &cache_key,
        /* presigned_enabled = */ true,
        expiry,
        /* cache_is_fresh = */ true,
    )
    .await
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
            // #2075: a fresh cache entry may still be inside its Package Age
            // Policy hold window. The buffered/streaming fetch paths enforce
            // that hold via check_quarantine_until; the presigned-redirect fast
            // path must gate on it too, or a held object would be handed out as
            // a 302 on redirect-capable backends. Gate BEFORE signing; a hold
            // surfaces as the same 409/403 (no redirect, no upstream refetch).
            if let Err(e) = proxy_service.cache_quarantine_gate(repo_key, path).await {
                return Err(map_proxy_error(repo_key, path, e));
            }
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
    let hydration_lease_key = format!("artifact-repair:{}", storage_key);
    // #1609: single-flight the missing-file repair CLUSTER-WIDE (was per-process)
    // via the config-selected advisory-lock coordinator, so concurrent replicas
    // do not each re-download and write back the same object.
    HydrationCoordinator::from_env(db.clone())
        .coordinate(
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
    let hydration_lease_key = format!("artifact-read-retry:{}", storage_key);
    tracing::warn!(
        artifact_id = %artifact_id,
        storage_key = %storage_key,
        "storage miss on local artifact; coordinating re-read"
    );
    // #1609: coordinate the re-read CLUSTER-WIDE (was per-process) via the
    // config-selected advisory-lock coordinator.
    HydrationCoordinator::from_env(db.clone())
        .coordinate(
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

/// Variant of [`proxy_fetch_with_cache_key`] that also forwards an `Accept`
/// header to the upstream. The PyPI simple-index proxy uses this to request
/// the PEP 691 JSON representation while keying the cache on a format-qualified
/// `cache_path`, so the JSON and HTML forms of the same index never collide in
/// the proxy cache.
pub async fn proxy_fetch_with_cache_key_and_accept(
    proxy_service: &ProxyService,
    repo_id: Uuid,
    repo_key: &str,
    upstream_url: &str,
    fetch_path: &str,
    cache_path: &str,
    accept: Option<&str>,
) -> Result<(Bytes, Option<String>), Response> {
    with_proxy_repo(
        repo_id,
        repo_key,
        upstream_url,
        fetch_path,
        |repo| async move {
            proxy_service
                .fetch_artifact_with_cache_path_and_accept(&repo, fetch_path, cache_path, accept)
                .await
        },
    )
    .await
}

/// Byte-ceiling-bounded sibling of [`proxy_fetch_with_cache_key`] (#1608 Phase
/// 4b / #2181). See [`proxy_fetch_capped`] for the `max` semantics.
pub async fn proxy_fetch_capped_with_cache_key(
    proxy_service: &ProxyService,
    repo_id: Uuid,
    repo_key: &str,
    upstream_url: &str,
    fetch_path: &str,
    cache_path: &str,
    max: usize,
) -> Result<(Bytes, Option<String>), Response> {
    with_proxy_repo(
        repo_id,
        repo_key,
        upstream_url,
        fetch_path,
        |repo| async move {
            proxy_service
                .fetch_artifact_with_cache_path_capped(&repo, fetch_path, cache_path, max)
                .await
        },
    )
    .await
}

/// Byte-ceiling-bounded sibling of [`proxy_fetch_with_cache_key_and_accept`]
/// (#1608 Phase 4b / #2181). See [`proxy_fetch_capped`] for the `max` semantics.
#[allow(clippy::too_many_arguments)]
pub async fn proxy_fetch_capped_with_cache_key_and_accept(
    proxy_service: &ProxyService,
    repo_id: Uuid,
    repo_key: &str,
    upstream_url: &str,
    fetch_path: &str,
    cache_path: &str,
    accept: Option<&str>,
    max: usize,
) -> Result<(Bytes, Option<String>), Response> {
    with_proxy_repo(
        repo_id,
        repo_key,
        upstream_url,
        fetch_path,
        |repo| async move {
            proxy_service
                .fetch_artifact_with_cache_path_and_accept_capped(
                    &repo, fetch_path, cache_path, accept, max,
                )
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

/// Response-producing sibling of [`proxy_fetch_streaming_with_cache_key`]:
/// fetches with split fetch/cache paths and builds the outbound streaming
/// [`Response`] via [`stream_fetch_result`], the same way [`proxy_fetch_streaming`]
/// does for the common (single-path) case. Format handlers whose upstream
/// download URL cannot double as a safe proxy-cache path — e.g. Terraform/
/// OpenTofu network-mirror archive downloads, where the registry-provided
/// `download_url` is an absolute URL and `https://` trips the cache path's
/// empty-segment guard — use this instead of `proxy_fetch_streaming` (#1998).
pub async fn proxy_fetch_streaming_response_with_cache_key(
    proxy_service: &ProxyService,
    repo_id: Uuid,
    repo_key: &str,
    upstream_url: &str,
    fetch_path: &str,
    cache_path: &str,
    default_content_type: &str,
) -> Result<Response, Response> {
    let result = proxy_fetch_streaming_with_cache_key(
        proxy_service,
        repo_id,
        repo_key,
        upstream_url,
        fetch_path,
        cache_path,
    )
    .await?;

    stream_fetch_result(result, default_content_type, None)
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

/// Pass-1 cache classification of a single virtual member during a two-phase
/// resolve (#2069). Pass 1 inspects each member *without contacting upstream*
/// (a local DB lookup, or a cache-only proxy probe); Pass 2 then resolves only
/// the members that still need an upstream round-trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MemberCacheClass {
    /// The member can serve the artifact with no upstream contact — a positive
    /// proxy-cache hit or a local/staging artifact.
    DefiniteHit,
    /// The member definitely does not have the artifact, known without upstream
    /// contact: a local miss, a negative-cached 404 still inside its window, or
    /// a skipped (un-proxyable) member.
    DefiniteMiss,
    /// A proxy-cache miss that requires an upstream round-trip to resolve.
    NeedsUpstream,
}

/// Final outcome of resolving a single virtual member, after Pass 1 and (where
/// needed) Pass 2. Generic over the success payload `T` (a streaming result or
/// a built `Response`) and the quarantine carrier `E`.
#[derive(Debug)]
pub(crate) enum MemberResolveOutcome<T, E> {
    /// The member produced the artifact.
    Hit(T),
    /// The member returned a deliberate Package-Age-Policy quarantine block
    /// (409/403, #1770) that must surface rather than fall through.
    Quarantine(E),
    /// The member does not have the artifact; try the next by priority.
    Miss,
}

/// Indices of the members that must be resolved against upstream in Pass 2,
/// given each member's Pass-1 cache classification in **priority order**
/// (#2069).
///
/// Only members that could still outrank the best already-known
/// [`MemberCacheClass::DefiniteHit`] need an upstream round-trip: every
/// [`MemberCacheClass::NeedsUpstream`] member whose priority is higher than
/// (i.e. index below) the first definite hit. If no member is a definite hit,
/// every `NeedsUpstream` member is a candidate.
///
/// Members at or below the first definite hit are intentionally excluded — the
/// definite hit already wins over them by priority — so a warm cache hit on a
/// high-priority member never triggers upstream traffic on the members behind
/// it (the regression this two-phase split exists to avoid).
pub(crate) fn upstream_candidate_indices(classes: &[MemberCacheClass]) -> Vec<usize> {
    let cutoff = classes
        .iter()
        .position(|c| *c == MemberCacheClass::DefiniteHit)
        .unwrap_or(classes.len());
    classes
        .iter()
        .take(cutoff)
        .enumerate()
        .filter(|(_, c)| **c == MemberCacheClass::NeedsUpstream)
        .map(|(i, _)| i)
        .collect()
}

/// Upper bound on concurrent upstream fetches a virtual-repository
/// **metadata-merge** fan-out may have in flight at once (#2069) — i.e. the
/// "query every member and combine" paths ([`collect_virtual_metadata`] and the
/// Maven metadata-merge loops). Virtual repos typically aggregate a handful of
/// members, so this is generous; it caps the reqwest connection-pool / socket
/// pressure (and upstream load) a pathologically large virtual repo could
/// otherwise create by opening one upstream connection per member at once.
/// (A future enhancement could make this operator-configurable, cf. #1424 for
/// the OCI negative-cache knobs.)
///
/// The first-match resolvers do NOT use this: their fan-out is already bounded
/// to the candidates ranked above the first cache hit (see
/// [`resolve_members_two_phase`]).
pub(crate) const MAX_VIRTUAL_FANOUT: usize = 16;

/// Two-phase, priority-preserving virtual-member resolution (#2069).
///
/// Pass 1 calls `probe` on members in priority order, stopping at the first
/// [`MemberCacheClass::DefiniteHit`] (a cache hit or local artifact). `probe`
/// must NOT contact upstream — it returns the member's [`MemberCacheClass`]
/// together with the already-built success payload for a `DefiniteHit`.
/// Members ranked below the first hit are never probed: they can never win
/// (`upstream_candidate_indices` only considers members above the first hit),
/// so this preserves the old sequential loop's warm-path short-circuit —
/// probe cost is O(rank of first hit), not O(member count).
///
/// Pass 2 calls `upstream` — concurrently — for the members that are both
/// [`MemberCacheClass::NeedsUpstream`] AND could still outrank the
/// highest-priority Pass-1 hit (see [`upstream_candidate_indices`]). The winner
/// is the first member in priority order that produced a hit or a quarantine
/// block; `None` means every member missed. The caller maps that to its own
/// success/`NOT_FOUND` response.
///
/// Concurrency / fan-out semantics (the load-bearing tradeoff):
/// * The **warm path stays upstream-free**: when a high-priority member is a
///   Pass-1 cache hit, no member behind it is even a candidate, so Pass 2 makes
///   no upstream calls at all.
/// * **Confirm-top-first**: Pass 2 first resolves the *highest-priority*
///   candidate alone. If it is a non-miss it is the overall winner (nothing
///   outranks it) and we return WITHOUT launching any other upstream request.
///   So a cold first request for an artifact the top candidate holds — the
///   common cold-*positive* case — costs exactly ONE upstream request, not one
///   per member.
/// * Only when the top candidate **misses** are the remaining candidates driven
///   concurrently — the cold-*negative* (artifact missing everywhere) and
///   cold-positive-on-a-lower-member cases. Here every remaining candidate's
///   `upstream` future is launched at once, so a true negative still resolves in
///   roughly the slowest single miss rather than the sum. This fan-out does
///   initiate upstream requests to all remaining candidates (the losers are
///   cancelled once the winner is known, but their requests were dispatched) —
///   bounded request-initiation amplification, only on the cold path, and only
///   after the top candidate has already missed. Bodies of losing members are
///   never polled.
/// * The remaining-candidate result is finalized in **strict priority order with
///   early return**: as soon as the highest-priority remaining candidate that
///   resolves to a non-miss is known (all higher-priority ones having resolved
///   to a miss), that outcome wins and the in-flight losers are dropped
///   (cancelled). A fast high-priority hit is never delayed by a slow
///   low-priority member. The remaining-candidate fan-out is naturally bounded:
///   it only includes candidates ranked above the first Pass-1 cache hit, minus
///   the top one already confirmed.
pub(crate) async fn resolve_members_two_phase<'a, T, E, P, PFut, U, UFut>(
    members: &'a [Repository],
    probe: P,
    upstream: U,
) -> Option<MemberResolveOutcome<T, E>>
where
    P: Fn(&'a Repository) -> PFut,
    PFut: std::future::Future<Output = (MemberCacheClass, Option<T>)> + 'a,
    U: Fn(&'a Repository) -> UFut,
    UFut: std::future::Future<Output = MemberResolveOutcome<T, E>> + 'a,
{
    // Pass 1: classify members without contacting upstream, stopping at the
    // first DefiniteHit. Members below it can never win, and
    // `upstream_candidate_indices` only considers members above the first hit,
    // so probing the rest would be wasted work (and, for the streaming/metadata
    // resolvers, wasted storage round-trips / body reads on the warm path).
    let mut classes: Vec<MemberCacheClass> = Vec::with_capacity(members.len());
    let mut pass1_hits: Vec<Option<T>> = Vec::with_capacity(members.len());
    for member in members {
        let (class, hit) = probe(member).await;
        let is_definite_hit = class == MemberCacheClass::DefiniteHit;
        classes.push(class);
        pass1_hits.push(hit);
        if is_definite_hit {
            break;
        }
    }

    // The highest-priority Pass-1 cache hit is the fallback winner used when
    // every upstream candidate misses. By construction every candidate index is
    // higher priority than (below) the first DefiniteHit, so any candidate hit
    // outranks this fallback.
    let pass1_winner: Option<MemberResolveOutcome<T, E>> = pass1_hits
        .into_iter()
        .find_map(|hit| hit.map(MemberResolveOutcome::Hit));

    let candidates = upstream_candidate_indices(&classes);
    let Some((&first, rest)) = candidates.split_first() else {
        return pass1_winner;
    };

    let upstream = &upstream;

    // Pass 2, step 1 — confirm the HIGHEST-priority candidate on its own. If it
    // produces a non-miss it is the overall winner (nothing outranks it), so we
    // return WITHOUT launching any other upstream request. This eliminates the
    // cold-positive fan-out for the common "top member has it" case (#2069): a
    // first request for an artifact the top remote member holds costs exactly
    // one upstream request, not one per member.
    let first_outcome = upstream(&members[first]).await;
    if !matches!(first_outcome, MemberResolveOutcome::Miss) {
        return Some(first_outcome);
    }
    if rest.is_empty() {
        return pass1_winner;
    }

    // Pass 2, step 2 — the top candidate missed, so the remaining candidates are
    // driven concurrently (a cold negative/miss fans out here), finalizing in
    // strict priority order with early return + cancellation of losers.
    // `rest` is ascending by priority, so a candidate's position in `rest` is
    // its priority rank among the remaining candidates.
    // The remaining candidates run concurrently via `FuturesUnordered`,
    // yielding results as they complete, each tagged with its priority `rank`
    // for the ordered finalize below. The exposure here is naturally bounded:
    // `upstream_candidate_indices` only includes candidates ranked above the
    // first Pass-1 cache hit, and confirm-top-first has already peeled off the
    // top one — so `rest` is small in practice. (`FuturesUnordered` is used
    // rather than a lazy `buffer_unordered` stream because the latter's
    // borrowed-closure future is not provably `Send` for the generic `U`, which
    // would make every caller's handler future non-`Send`.)
    let mut running: futures::stream::FuturesUnordered<_> = rest
        .iter()
        .enumerate()
        .map(|(rank, &i)| {
            let member = &members[i];
            async move { (rank, upstream(member).await) }
        })
        .collect();

    let mut buffer: Vec<Option<MemberResolveOutcome<T, E>>> =
        (0..rest.len()).map(|_| None).collect();
    // `next` is the lowest-priority-rank candidate whose outcome is not yet
    // decided to be a miss; once `buffer[next]` is a known non-miss it wins.
    let mut next = 0usize;

    while let Some((rank, outcome)) = running.next().await {
        buffer[rank] = Some(outcome);
        // Advance over a contiguous run of already-resolved candidates.
        while next < buffer.len() {
            match buffer[next] {
                Some(MemberResolveOutcome::Miss) => next += 1,
                // A higher-priority candidate is still pending: must wait.
                None => break,
                // First non-miss in priority order wins; dropping `running`
                // cancels the remaining in-flight upstream futures.
                Some(_) => return buffer[next].take(),
            }
        }
    }

    // Every candidate resolved to a miss → fall back to the best Pass-1 hit.
    pass1_winner
}

/// Map a cache-only proxy probe (`streaming_cached_artifact_by_path`) to a
/// Pass-1 [`MemberCacheClass`] (#2069).
///
/// * `Ok(Some(_))` — a servable cache hit ([`MemberCacheClass::DefiniteHit`]).
/// * `Ok(None)` — a cache miss needing an upstream round-trip
///   ([`MemberCacheClass::NeedsUpstream`]).
/// * `Err(quarantine)` — a *fresh but held* cached entry surfaces from the probe
///   as a Package-Age-Policy block (#1770: `Conflict`/`Authorization`). It MUST
///   NOT be dropped (that would mask the 409/403 and serve a lower-priority
///   member or 404). It is classified [`MemberCacheClass::NeedsUpstream`] so
///   Pass 2 re-resolves it via `fetch_artifact_streaming` — which re-detects the
///   held cache entry and surfaces the block through `classify_stream_upstream`
///   WITHOUT contacting upstream (the held entry is a cache hit).
/// * `Err(other)` — a negative-cached 404 or an unusable cache key: a definite
///   miss we must NOT re-fetch.
///
/// (A transient sidecar read/parse error is mapped to `Ok(None)` upstream of
/// this in `read_cached_with_revalidation_streaming`, so it falls through to an
/// upstream fetch rather than being suppressed here.)
pub(crate) fn classify_cache_probe<T>(
    probe: Result<Option<T>, crate::error::AppError>,
) -> (MemberCacheClass, Option<T>) {
    match probe {
        Ok(Some(hit)) => (MemberCacheClass::DefiniteHit, Some(hit)),
        Ok(None) => (MemberCacheClass::NeedsUpstream, None),
        // A quarantine block must surface (#1770): re-resolve in Pass 2.
        Err(e) if is_quarantine_block(&e) => (MemberCacheClass::NeedsUpstream, None),
        Err(_) => (MemberCacheClass::DefiniteMiss, None),
    }
}

/// Map a Remote member's buffered/streaming upstream fetch result to its final
/// [`MemberResolveOutcome`] (#2069). A Package-Age-Policy quarantine block
/// (#1770) surfaces as [`MemberResolveOutcome::Quarantine`]; any other error is
/// an ordinary miss.
pub(crate) fn classify_stream_upstream(
    result: Result<StreamingFetchResult, crate::error::AppError>,
    member_key: &str,
    path: &str,
) -> MemberResolveOutcome<StreamingFetchResult, Response> {
    match result {
        Ok(result) => MemberResolveOutcome::Hit(result),
        Err(e) if is_quarantine_block(&e) => {
            MemberResolveOutcome::Quarantine(map_proxy_error(member_key, path, e))
        }
        Err(_) => MemberResolveOutcome::Miss,
    }
}

/// Streaming-path sibling of [`classify_cache_probe`] (#2069): build a
/// ready-to-serve [`Response`] from a cache hit so it can be returned without
/// touching upstream. A rare header-build failure degrades to
/// [`MemberCacheClass::NeedsUpstream`] rather than failing the whole virtual. A
/// quarantine block (#1770) from the probe is classified `NeedsUpstream` so
/// Pass 2 re-resolves and surfaces the 409/403 (see [`classify_cache_probe`]);
/// a negative-cached 404 / unusable key is a definite miss.
pub(crate) fn classify_streaming_cache_probe(
    probe: Result<Option<StreamingFetchResult>, crate::error::AppError>,
    default_content_type: &str,
    content_disposition_filename: Option<&str>,
) -> (MemberCacheClass, Option<Response>) {
    match probe {
        Ok(Some(result)) => match build_streaming_response_with_disposition(
            result,
            default_content_type,
            content_disposition_filename,
        ) {
            Ok(response) => (MemberCacheClass::DefiniteHit, Some(response)),
            Err(_) => (MemberCacheClass::NeedsUpstream, None),
        },
        Ok(None) => (MemberCacheClass::NeedsUpstream, None),
        // A quarantine block must surface (#1770): re-resolve in Pass 2.
        Err(e) if is_quarantine_block(&e) => (MemberCacheClass::NeedsUpstream, None),
        Err(_) => (MemberCacheClass::DefiniteMiss, None),
    }
}

/// Classify a Local/Staging member's buffered fetch for the streaming resolver
/// (#2069): build the streaming response on a hit (or serve a 500 if header
/// building fails — that member still "wins" with an error), else a miss.
pub(crate) fn classify_streaming_local(
    fetched: Result<StreamingFetchResult, Response>,
    default_content_type: &str,
    content_disposition_filename: Option<&str>,
) -> (MemberCacheClass, Option<Response>) {
    match fetched {
        Ok(result) => match build_streaming_response_with_disposition(
            result,
            default_content_type,
            content_disposition_filename,
        ) {
            Ok(response) => (MemberCacheClass::DefiniteHit, Some(response)),
            Err(e) => (
                MemberCacheClass::DefiniteHit,
                Some((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()),
            ),
        },
        Err(_) => (MemberCacheClass::DefiniteMiss, None),
    }
}

/// Map a Remote member's streaming upstream fetch (already mapped to a
/// [`Response`] by [`proxy_fetch_streaming_member`]) to its final outcome
/// (#2069). A quarantine 409/403 surfaces; any other error Response is a miss.
pub(crate) fn classify_streaming_upstream(
    result: Result<Response, Response>,
) -> MemberResolveOutcome<Response, Response> {
    match result {
        Ok(response) => MemberResolveOutcome::Hit(response),
        Err(resp) if is_quarantine_block_response(&resp) => MemberResolveOutcome::Quarantine(resp),
        Err(_) => MemberResolveOutcome::Miss,
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
///
/// Precondition (#2069): `path` must address an **immutable** artifact (a
/// versioned download), not a mutable index/metadata path. The Pass-1 cache
/// probe is upstream-free only for immutable content; a stale *mutable* entry
/// would conditionally revalidate against upstream, serializing per-member
/// round-trips in Pass 1 and defeating the concurrent fan-out. Mutable indexes
/// must instead go through [`resolve_virtual_metadata`] / the metadata-merge
/// helpers.
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

    // Two-phase, priority-preserving resolution (#2069). Pass 1 (the `probe`
    // closure) classifies each member: Local members hit the DB; Remote members
    // get a cache-only proxy probe (a versioned-artifact hit or a negative-cached
    // 404 lands here). `member` is passed to the proxy as-is so it carries its
    // REAL format (#2069 bug 1). NOTE on upstream contact: the probe is
    // upstream-free for IMMUTABLE content (which is what download callers route
    // here — versioned artifacts never revalidate). The probe (`streaming_cached_
    // artifact_by_path`) WOULD conditionally revalidate a *stale mutable* entry
    // against upstream; that is still correct but no longer upstream-free, so
    // routing a mutable path through this download resolver is not intended.
    // Pass 2 (the `upstream` closure) fans out — in parallel — over the members
    // that still need an upstream round-trip and could outrank a Pass-1 hit,
    // finalizing in strict priority order with early return. See
    // `resolve_members_two_phase` for the full fan-out / amplification tradeoff
    // (the fan-out also fires on a cold *positive*, not only the all-miss case).
    // Borrow `local_fetch` so the per-member `probe` closure copies the
    // reference instead of moving the `Fn` into each `async move` future.
    let local_fetch = &local_fetch;
    let outcome = resolve_members_two_phase::<StreamingFetchResult, Response, _, _, _, _>(
        &members,
        |member| async move {
            match virtual_member_fetch_strategy(
                &member.repo_type,
                proxy_service.is_some(),
                member.upstream_url.is_some(),
            ) {
                VirtualMemberFetchStrategy::Local => {
                    match local_fetch(member.id, member.storage_location()).await {
                        Ok(result) => (MemberCacheClass::DefiniteHit, Some(result)),
                        Err(_) => (MemberCacheClass::DefiniteMiss, None),
                    }
                }
                VirtualMemberFetchStrategy::Proxy => match proxy_service {
                    // The cache-only probe contacts no upstream; its result is
                    // classified by the pure `classify_cache_probe`.
                    Some(proxy) => classify_cache_probe(
                        proxy.streaming_cached_artifact_by_path(member, path).await,
                    ),
                    None => (MemberCacheClass::DefiniteMiss, None),
                },
                VirtualMemberFetchStrategy::Skip => (MemberCacheClass::DefiniteMiss, None),
            }
        },
        |member| async move {
            // Only reached for Remote members the strategy resolved as Proxy, so
            // a proxy service is guaranteed present.
            match proxy_service {
                Some(proxy) => classify_stream_upstream(
                    proxy.fetch_artifact_streaming(member, path).await,
                    &member.key,
                    path,
                ),
                None => MemberResolveOutcome::Miss,
            }
        },
    )
    .await;

    match outcome {
        Some(MemberResolveOutcome::Hit(result)) => Ok(result),
        Some(MemberResolveOutcome::Quarantine(response)) => Err(response),
        _ => Err((
            StatusCode::NOT_FOUND,
            "Artifact not found in any member repository",
        )
            .into_response()),
    }
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
///
/// Precondition (#2069): as with [`resolve_virtual_download_from_members`],
/// `path` must address an **immutable** artifact. The Pass-1 cache probe is
/// upstream-free only for immutable content; mutable indexes/metadata must go
/// through [`resolve_virtual_metadata`] / the metadata-merge helpers instead.
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

    // Two-phase, priority-preserving resolution (#2069), streaming sibling of
    // [`resolve_virtual_download_from_members`]. Pass 1 (`probe`) classifies
    // each member: Local members hit the DB; Remote members try the #1555
    // presigned-redirect fast path then a cache-only streaming probe. `member`
    // is used as-is so its REAL format drives cache classification (#2069
    // bug 1). Same upstream-contact note as the buffered sibling: the probe is
    // upstream-free for the IMMUTABLE artifact paths download callers route
    // here; a *stale mutable* entry would conditionally revalidate upstream
    // (correct, but not upstream-free), so routing a mutable path here is not
    // intended. Pass 2 (`upstream`) fans out — in parallel — only over members
    // that still need it, preserving #1215 OOM-avoidance (uncached bodies are
    // streamed, never buffered).
    // Borrow `local_fetch` so the per-member `probe` closure copies the
    // reference instead of moving the `Fn` into each `async move` future.
    let local_fetch = &local_fetch;
    let outcome = resolve_members_two_phase::<Response, Response, _, _, _, _>(
        &members,
        |member| async move {
            match virtual_member_fetch_strategy(
                &member.repo_type,
                proxy_service.is_some(),
                member.upstream_url.is_some(),
            ) {
                VirtualMemberFetchStrategy::Local => classify_streaming_local(
                    local_fetch(member.id, member.storage_location()).await,
                    default_content_type,
                    content_disposition_filename,
                ),
                VirtualMemberFetchStrategy::Proxy => match proxy_service {
                    Some(proxy) => {
                        // #1555: a fresh proxy-cache hit on a redirect-capable
                        // backend is served as a presigned redirect, never
                        // streamed through the backend.
                        if let Some(redirect) =
                            try_member_cache_redirect(state, proxy, member, path).await
                        {
                            (MemberCacheClass::DefiniteHit, Some(redirect))
                        } else {
                            classify_streaming_cache_probe(
                                proxy.streaming_cached_artifact_by_path(member, path).await,
                                default_content_type,
                                content_disposition_filename,
                            )
                        }
                    }
                    None => (MemberCacheClass::DefiniteMiss, None),
                },
                VirtualMemberFetchStrategy::Skip => (MemberCacheClass::DefiniteMiss, None),
            }
        },
        |member| async move {
            match proxy_service {
                Some(proxy) => classify_streaming_upstream(
                    proxy_fetch_streaming_member(
                        proxy,
                        member,
                        path,
                        default_content_type,
                        content_disposition_filename,
                    )
                    .await,
                ),
                None => MemberResolveOutcome::Miss,
            }
        },
    )
    .await;

    match outcome {
        Some(MemberResolveOutcome::Hit(response)) => Ok(response),
        Some(MemberResolveOutcome::Quarantine(response)) => Err(response),
        _ => Err((
            StatusCode::NOT_FOUND,
            "Artifact not found in any member repository",
        )
            .into_response()),
    }
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

    // Two-phase, priority-preserving first-match resolution (#2069). Metadata is
    // served only from Remote members. Bug 1 (member format passthrough) is a
    // no-op here: every metadata index (maven-metadata.xml, npm packument, the
    // PyPI simple index, ...) classifies as mutable regardless of format, so the
    // synthesized `build_remote_repo` format in `proxy_fetch` changes nothing.
    let transform = &transform;
    let outcome = resolve_members_two_phase::<Response, Response, _, _, _, _>(
        &members,
        |member| async move {
            if member.repo_type != RepositoryType::Remote {
                return (MemberCacheClass::DefiniteMiss, None);
            }
            let Some(proxy) = proxy_service else {
                return (MemberCacheClass::DefiniteMiss, None);
            };
            // Cache-only probe (no upstream) that honours the #1611 classifier
            // and the #1770 Package-Age-Policy gate, so a fresh hit is served
            // (warm path never fans out) while a held entry is skipped rather
            // than served raw. A fresh hit is transformed into the response.
            match proxy.cached_metadata_if_servable(member, path).await {
                Ok(Some((bytes, _ct))) => match transform(bytes, member.key.clone()).await {
                    Ok(response) => (MemberCacheClass::DefiniteHit, Some(response)),
                    // The cached bytes failed to transform (e.g. corrupt cached
                    // metadata). Don't treat the member as a definite miss —
                    // fall through to an upstream re-fetch in Pass 2 so a good
                    // upstream copy can still recover it (parity with the old
                    // `proxy_fetch`-then-transform path). Surface it for field
                    // debugging.
                    Err(_) => {
                        tracing::warn!(
                            member = %member.key,
                            path = %path,
                            "virtual metadata transform failed for cached member response; \
                             will re-fetch upstream"
                        );
                        (MemberCacheClass::NeedsUpstream, None)
                    }
                },
                // `Ok(None)` covers a cache miss AND a negative-cached 404
                // (both collapse to `None` here). Unlike the download resolvers
                // — which see the negative 404 as `Err` and classify it
                // `DefiniteMiss` — this metadata path re-checks it via Pass-2's
                // `proxy_fetch`, which re-honors the negative cache and returns
                // fast WITHOUT real upstream contact. The only cost of the
                // divergence is one extra (cheap) cache read for a negatively-
                // cached metadata member; correctness is identical.
                Ok(None) => (MemberCacheClass::NeedsUpstream, None),
                // A held (quarantined) or unusable-key entry: skip this member
                // (matches the old `proxy_fetch`-then-continue behaviour),
                // letting a lower-priority member serve if it can.
                Err(_) => (MemberCacheClass::DefiniteMiss, None),
            }
        },
        |member| async move {
            let (Some(proxy), Some(upstream_url)) = (proxy_service, member.upstream_url.as_deref())
            else {
                return MemberResolveOutcome::Miss;
            };
            match proxy_fetch(proxy, member.id, &member.key, upstream_url, path).await {
                Ok((bytes, _ct)) => match transform(bytes, member.key.clone()).await {
                    Ok(response) => MemberResolveOutcome::Hit(response),
                    Err(_) => {
                        tracing::warn!(
                            member = %member.key,
                            path = %path,
                            "virtual metadata transform failed for upstream member response"
                        );
                        MemberResolveOutcome::Miss
                    }
                },
                Err(_) => {
                    tracing::debug!(
                        member = %member.key,
                        path = %path,
                        "virtual metadata upstream fetch miss"
                    );
                    MemberResolveOutcome::Miss
                }
            }
        },
    )
    .await;

    match outcome {
        Some(MemberResolveOutcome::Hit(response)) => Ok(response),
        // The metadata probe/upstream closures never produce `Quarantine` today
        // (they map a held entry to a skipped member, matching the prior
        // `proxy_fetch`-then-continue behaviour). Handle it explicitly anyway so
        // that intent is enforced: if metadata quarantine surfacing is ever
        // added, the 409/403 propagates instead of silently collapsing to 404.
        Some(MemberResolveOutcome::Quarantine(response)) => Err(response),
        _ => Err((
            StatusCode::NOT_FOUND,
            "Metadata not found in any member repository",
        )
            .into_response()),
    }
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

    // Remote members are queried CONCURRENTLY (#2069) in priority-order batches
    // of at most [`MAX_VIRTUAL_FANOUT`], so a cold merge fan-out costs roughly
    // the slowest single upstream (per batch) rather than the sum, while never
    // opening more than the cap of upstream connections at once. Order is
    // preserved (batches are consumed in member/priority order and `join_all`
    // keeps within-batch order), which the caller's merge relies on.
    let extract = &extract;
    let remote_members: Vec<&Repository> = members
        .iter()
        .filter(|m| m.repo_type == RepositoryType::Remote)
        .collect();
    let mut results: Vec<(String, T)> = Vec::new();
    for chunk in remote_members.chunks(MAX_VIRTUAL_FANOUT) {
        let batch = futures::future::join_all(chunk.iter().copied().map(|member| async move {
            let (Some(proxy), Some(upstream_url)) = (proxy_service, member.upstream_url.as_deref())
            else {
                return None;
            };
            match proxy_fetch(proxy, member.id, &member.key, upstream_url, path).await {
                Ok((bytes, _ct)) => match extract(bytes, member.key.clone()).await {
                    Ok(data) => Some((member.key.clone(), data)),
                    Err(_) => {
                        tracing::warn!(
                            member = %member.key,
                            path = %path,
                            "virtual metadata extract failed for member response"
                        );
                        None
                    }
                },
                Err(_) => {
                    tracing::warn!(
                        member = %member.key,
                        path = %path,
                        "virtual metadata proxy fetch failed for member"
                    );
                    None
                }
            }
        }))
        .await;
        results.extend(batch.into_iter().flatten());
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
            r.age_gate_enabled, r.age_gate_min_age_days,
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
    // Route through map_db_err so pool saturation surfaces as 503 (capacity
    // shed) instead of 500, and to avoid leaking raw DB error text (#1437).
    .map_err(map_db_err)
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
        .map_err(|e| shadowing_guard_db_err(virtual_repo_id, "cross-format", e))?;
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
    .map_err(|e| shadowing_guard_db_err(virtual_repo_id, "cross-format", e))?;

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

fn shadowing_guard_db_err(virtual_repo_id: Uuid, format: &str, e: sqlx::Error) -> Response {
    let text = e.to_string();
    // Pool saturation is transient capacity, not a guard failure: shed to 503 +
    // Retry-After so clients back off, instead of failing closed to 500 (#1437).
    // Real query failures still fail closed to a non-leaking 500 below.
    if crate::error::is_pool_timeout(&text) {
        return map_db_err(text);
    }
    tracing::error!(
        event = "shadowing_guard_db_error",
        virtual_repo_id = %virtual_repo_id,
        format = format,
        error = %text,
        "shadowing-guard DB query failed; failing closed to 500",
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
    .map_err(|e| shadowing_guard_db_err(virtual_repo_id, "cross-format", e))?;

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
    .map_err(|e| shadowing_guard_db_err(virtual_repo_id, "cross-format", e))?;

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
    .map_err(|e| shadowing_guard_db_err(virtual_repo_id, "generic", e))?;

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
    .map_err(|e| shadowing_guard_db_err(virtual_repo_id, "maven", e))?;

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
#[allow(clippy::disallowed_methods)] // clippy allow is fn-scoped (assignment expr); the exempt call is marked inline below (#1608)
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
                // STREAMING-EXEMPT: upload handler buffers one bounded multipart field (capped by DefaultBodyLimit); tracked for incremental-hash put_stream conversion in a later #1608 phase
                (
                    StatusCode::BAD_REQUEST,
                    format!("Failed to read file: {}", e),
                )
                    .into_response()
            })?);
        } else if json_field_names.iter().any(|n| *n == field_name) {
            #[allow(clippy::disallowed_methods)]
            // STREAMING-EXEMPT: upload handler buffers one bounded multipart field (capped by DefaultBodyLimit); tracked for incremental-hash put_stream conversion in a later #1608 phase
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

// ---------------------------------------------------------------------------
// Streaming artifact uploads (#1608 Phase 2)
// ---------------------------------------------------------------------------
//
// Light-format upload handlers (chef, ansible, pub, ...) historically buffered
// the entire artifact body in memory via `Field::bytes()` before handing it to
// `put_artifact_bytes` -> `storage.put(Bytes)`. `stage_upload_field` +
// `put_artifact_stream` replace that with a memory-bounded path: the multipart
// field is spooled chunk-by-chunk to a scratch temp file (peak RAM =
// STREAM_STAGE_CHUNK), then streamed into the repo's `StorageBackend` through
// its native `put_stream` primitive (S3 multipart / GCS resumable / Azure
// block-blob / filesystem temp-and-rename), which computes the SHA-256
// incrementally as it copies. Mirrors the incus monolithic-upload pattern
// (`stream_body_to_file` + `open_temp_file_as_stream`). `put_artifact_bytes`
// is retained for the small metadata writers that still need the bytes in hand.
//
// This pair is the shared entry point later #1608 phases (helm/pypi/nuget)
// build on: `stage_upload_field` decouples the (borrowed, non-`'static`)
// multipart field lifetime from the `'static` stream `put_stream` requires,
// and lets a handler parse archive metadata off the staged file before the
// storage key is known.

/// Chunk size for reading a staged scratch file back into `put_stream`.
const STREAM_STAGE_CHUNK: usize = 256 * 1024;

/// A multipart upload body spooled to a bounded scratch file on local disk.
///
/// The scratch file is removed on drop (RAII), so every early return — a
/// mid-receive stream error, a `?`-propagated failure, or a storage failure in
/// [`put_artifact_stream`] — unlinks it instead of leaking an orphan (#1573).
/// The file is staged under the shared upload staging root, so the orphan
/// sweep reaps it as a backstop if the process dies mid-request.
pub struct StagedUpload {
    path: PathBuf,
    size_bytes: i64,
}

impl StagedUpload {
    /// On-disk path of the staged scratch file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Number of bytes spooled to disk (== the eventual artifact size).
    pub fn size_bytes(&self) -> i64 {
        self.size_bytes
    }

    /// Whether the spooled body is empty (no bytes received).
    pub fn is_empty(&self) -> bool {
        self.size_bytes == 0
    }
}

impl Drop for StagedUpload {
    fn drop(&mut self) {
        // Synchronous best-effort unlink: Drop can't await and the file is
        // local scratch, so a blocking unlink is negligible.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Spool one multipart field to a bounded scratch temp file, aborting with
/// `413 Payload Too Large` once `max_upload_size_bytes` is exceeded (a value of
/// 0 disables the limit, matching the `DefaultBodyLimit` config semantics).
///
/// Never buffers the whole field in memory: chunks are written straight to
/// disk. The returned [`StagedUpload`] owns the scratch file and removes it on
/// drop. Feed it to [`put_artifact_stream`] once the storage key is known.
#[allow(clippy::result_large_err)]
pub async fn stage_upload_field(
    state: &crate::api::SharedState,
    mut field: axum::extract::multipart::Field<'_>,
) -> Result<StagedUpload, Response> {
    use tokio::io::AsyncWriteExt;

    let path =
        crate::api::handlers::incus::temp_upload_path(&state.config.storage_path, &Uuid::new_v4());
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| internal_error("Staging directory", e))?;
    }

    // Arm the RAII cleanup before the first write so any early return below
    // unlinks the partial file rather than leaking it.
    let mut staged = StagedUpload {
        path: path.clone(),
        size_bytes: 0,
    };

    let mut file = tokio::fs::File::create(&path)
        .await
        .map_err(|e| internal_error("Staging file", e))?;

    let max = state.config.max_upload_size_bytes;
    let mut written: u64 = 0;
    while let Some(chunk) = field.chunk().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Failed to read upload body: {e}"),
        )
            .into_response()
    })? {
        written = written.saturating_add(chunk.len() as u64);
        if max != 0 && written > max {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("Upload exceeds the maximum allowed size of {max} bytes"),
            )
                .into_response());
        }
        file.write_all(&chunk)
            .await
            .map_err(|e| internal_error("Staging write", e))?;
    }

    file.flush()
        .await
        .map_err(|e| internal_error("Staging flush", e))?;
    file.sync_all()
        .await
        .map_err(|e| internal_error("Staging sync", e))?;

    staged.size_bytes = written as i64;
    Ok(staged)
}

/// Stream a [`StagedUpload`] scratch file into the repository's configured
/// `StorageBackend` via its native `put_stream`, computing the SHA-256
/// checksum incrementally as it copies (no separate hashing pass over a
/// buffered body). Returns the incremental checksum + byte count for building
/// the artifact row.
///
/// Consumes the `StagedUpload`: the scratch file is removed when this returns,
/// on success or on error.
#[allow(clippy::result_large_err)]
pub async fn put_artifact_stream(
    state: &crate::api::SharedState,
    repo: &RepoInfo,
    storage_key: &str,
    staged: StagedUpload,
) -> Result<crate::storage::PutStreamResult, Response> {
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;

    let stream = open_staged_stream(staged.path()).await?;
    let result = storage
        .put_stream(storage_key, stream)
        .await
        .map_err(|e| internal_error("Storage", e))?;
    Ok(result)
    // `staged` drops here -> scratch file removed.
}

/// Open a staged scratch file as a `'static` byte stream ready to feed
/// `StorageBackend::put_stream`. A buffered `ReaderStream` keeps the
/// disk->backend copy bounded to `STREAM_STAGE_CHUNK`.
#[allow(clippy::result_large_err)]
async fn open_staged_stream(
    path: &Path,
) -> Result<futures::stream::BoxStream<'static, crate::error::Result<Bytes>>, Response> {
    use tokio::io::BufReader;
    use tokio_util::io::ReaderStream;

    let file = tokio::fs::File::open(path)
        .await
        .map_err(|e| internal_error("Staging reopen", e))?;
    let reader = BufReader::with_capacity(STREAM_STAGE_CHUNK, file);
    let stream = ReaderStream::with_capacity(reader, STREAM_STAGE_CHUNK)
        .map(|r| r.map_err(|e| crate::error::AppError::Storage(format!("staged read: {e}"))));
    Ok(Box::pin(stream))
}

/// Spool an arbitrary byte stream to a bounded scratch temp file while computing
/// SHA-256, SHA-1, and MD5 incrementally. Aborts with `413 Payload Too Large`
/// once `max_upload_size_bytes` is exceeded (a value of 0 disables the limit,
/// matching `DefaultBodyLimit`). Never buffers the whole body in memory.
///
/// This is the shared content-addressed staging primitive: pypi feeds it an axum
/// multipart [`Field`](axum::extract::multipart::Field) (via
/// [`stage_upload_field_content_addressed`]); nuget feeds it a `multer` field
/// (streaming multipart) or the raw request-body data stream. Hand the returned
/// [`StagedUpload`] to [`open_staged_upload_stream`] and the
/// [`ContentDigests`](crate::services::artifact_service::ContentDigests) to
/// [`ArtifactService::upload_stream_with_sync_options`](crate::services::artifact_service::ArtifactService::upload_stream_with_sync_options).
#[allow(clippy::result_large_err)]
pub async fn stage_stream_content_addressed<S, E>(
    state: &crate::api::SharedState,
    stream: S,
) -> Result<
    (
        StagedUpload,
        crate::services::artifact_service::ContentDigests,
    ),
    Response,
>
where
    S: futures::Stream<Item = std::result::Result<Bytes, E>>,
    E: std::fmt::Display,
{
    use tokio::io::AsyncWriteExt;

    let path =
        crate::api::handlers::incus::temp_upload_path(&state.config.storage_path, &Uuid::new_v4());
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| internal_error("Staging directory", e))?;
    }

    // Arm the RAII cleanup before the first write so any early return below
    // unlinks the partial file rather than leaking it.
    let mut staged = StagedUpload {
        path: path.clone(),
        size_bytes: 0,
    };

    let mut file = tokio::fs::File::create(&path)
        .await
        .map_err(|e| internal_error("Staging file", e))?;

    let max = state.config.max_upload_size_bytes;
    let mut hasher = crate::services::artifact_service::MultiHasher::new();
    let mut written: u64 = 0;

    tokio::pin!(stream);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Failed to read upload body: {e}"),
            )
                .into_response()
        })?;
        written = written.saturating_add(chunk.len() as u64);
        if max != 0 && written > max {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("Upload exceeds the maximum allowed size of {max} bytes"),
            )
                .into_response());
        }
        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .map_err(|e| internal_error("Staging write", e))?;
    }

    file.flush()
        .await
        .map_err(|e| internal_error("Staging flush", e))?;
    file.sync_all()
        .await
        .map_err(|e| internal_error("Staging sync", e))?;

    staged.size_bytes = written as i64;
    Ok((staged, hasher.finalize()))
}

/// Content-addressed variant of [`stage_upload_field`]: spool one axum multipart
/// field to scratch while computing SHA-256 / SHA-1 / MD5. Thin wrapper over
/// [`stage_stream_content_addressed`] (axum's `Field` is itself a byte stream).
#[allow(clippy::result_large_err)]
pub async fn stage_upload_field_content_addressed(
    state: &crate::api::SharedState,
    field: axum::extract::multipart::Field<'_>,
) -> Result<
    (
        StagedUpload,
        crate::services::artifact_service::ContentDigests,
    ),
    Response,
> {
    stage_stream_content_addressed(state, field).await
}

/// Re-open a [`StagedUpload`] scratch file as a `'static` byte stream ready to
/// hand to
/// [`ArtifactService::upload_stream_with_sync_options`](crate::services::artifact_service::ArtifactService::upload_stream_with_sync_options).
///
/// The caller must keep the [`StagedUpload`] alive until the consumer finishes:
/// the returned stream holds an independent open file handle, and the scratch
/// file is only unlinked when the `StagedUpload` drops.
#[allow(clippy::result_large_err)]
pub async fn open_staged_upload_stream(
    staged: &StagedUpload,
) -> Result<futures::stream::BoxStream<'static, crate::error::Result<Bytes>>, Response> {
    open_staged_stream(staged.path()).await
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

    // Apply the upload-time quarantine hold at the shared chokepoint used by the
    // helper-based format handlers (helm, hex, cran, ansible, puppet, rubygems,
    // rpm, huggingface). Scoped to hosted repositories so proxy/remote cache
    // inserts — which carry their own sidecar quarantine state — are not
    // double-held. Best-effort: never fails the insert.
    crate::services::quarantine_service::apply_upload_hold_hosted(db, art.repository_id, id).await;

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

/// Build age-gate params from a resolved repository descriptor.
pub fn age_gate_params(info: &RepoInfo) -> crate::services::age_gate_service::AgeGateRepoParams {
    use crate::models::repository::{RepositoryFormat, RepositoryType};
    use crate::services::age_gate_service::AgeGateRepoParams;

    let repo_type = match info.repo_type.as_str() {
        "remote" => RepositoryType::Remote,
        "virtual" => RepositoryType::Virtual,
        "staging" => RepositoryType::Staging,
        _ => RepositoryType::Local,
    };
    let format = match info.format.to_lowercase().as_str() {
        "npm" => RepositoryFormat::Npm,
        "pypi" => RepositoryFormat::Pypi,
        other if other.starts_with("npm") || other == "yarn" || other == "pnpm" => {
            RepositoryFormat::Npm
        }
        other if other.starts_with("pypi") || other == "poetry" => RepositoryFormat::Pypi,
        _ => RepositoryFormat::Generic,
    };

    AgeGateRepoParams::from_parts(
        info.id,
        info.key.clone(),
        repo_type,
        format,
        info.age_gate_enabled,
        info.age_gate_min_age_days,
    )
}

/// HTTP 451 JSON body when a package version is blocked by the age gate with no LKG.
pub fn age_gate_blocked_body(
    review_id: uuid::Uuid,
    package: &str,
    version: &str,
    min_age_days: i32,
    requested_age_days: Option<i64>,
) -> serde_json::Value {
    serde_json::json!({
        "error": "age_gate_blocked",
        "review_id": review_id,
        "package": package,
        "version": version,
        "min_age_days": min_age_days,
        "requested_age_days": requested_age_days,
        "message": "Package version is younger than the configured age threshold and is pending review"
    })
}

/// HTTP 451 response when a package version is blocked by the age gate with no LKG.
pub fn age_gate_blocked_response(
    review_id: uuid::Uuid,
    package: &str,
    version: &str,
    min_age_days: i32,
    requested_age_days: Option<i64>,
) -> Response {
    let body = age_gate_blocked_body(
        review_id,
        package,
        version,
        min_age_days,
        requested_age_days,
    );
    (
        StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

/// Build a minimal `Repository` model for proxy operations.
///
/// Visible to other handler modules so they can construct a stand-in
/// `Repository` value for `ProxyService` calls that need more than just
/// the fields carried on the thin `RepoInfo` struct, e.g.
/// `ProxyService::fetch_dists_with_revalidation` in the Debian handler.
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
        age_gate_enabled: false,
        age_gate_min_age_days: 7,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[allow(clippy::disallowed_methods)]
// streaming-invariant: test module exempt — buffering response bodies in test assertions is not an artifact path (#1608)
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

    // ── Two-phase virtual fan-out: priority-preserving decision logic ──
    //
    // Cold negative resolution parallelizes the upstream fan-out (#2069) but
    // MUST preserve the sequential loop's strict-priority, first-non-miss
    // semantics. These cover the two pure helpers that encode that contract.

    #[test]
    fn upstream_candidates_are_all_needs_upstream_when_no_cache_hit() {
        use MemberCacheClass::*;
        // No member is a definite cache hit: every member that needs an
        // upstream round-trip must be probed.
        let classes = [NeedsUpstream, DefiniteMiss, NeedsUpstream];
        assert_eq!(upstream_candidate_indices(&classes), vec![0, 2]);
    }

    #[test]
    fn upstream_candidates_exclude_members_at_or_below_first_cache_hit() {
        use MemberCacheClass::*;
        // A definite cache hit at index 2 already wins over everything below
        // it by priority, so only the higher-priority NeedsUpstream member (0)
        // could still outrank it and needs an upstream probe. The NeedsUpstream
        // at index 3 (below the hit) is irrelevant and must NOT be probed —
        // this is what keeps the warm path upstream-free.
        let classes = [NeedsUpstream, DefiniteMiss, DefiniteHit, NeedsUpstream];
        assert_eq!(upstream_candidate_indices(&classes), vec![0]);
    }

    #[test]
    fn upstream_candidates_empty_when_top_priority_is_a_cache_hit() {
        use MemberCacheClass::*;
        // Highest-priority member is already a hit: nothing can outrank it, so
        // no upstream traffic at all.
        let classes = [DefiniteHit, NeedsUpstream, NeedsUpstream];
        assert!(upstream_candidate_indices(&classes).is_empty());
    }

    #[test]
    fn upstream_candidates_empty_when_all_definite_miss() {
        use MemberCacheClass::*;
        let classes = [DefiniteMiss, DefiniteMiss];
        assert!(upstream_candidate_indices(&classes).is_empty());
    }

    // ── Two-phase virtual fan-out: generic orchestrator (no proxy / no net) ──
    //
    // `resolve_members_two_phase` drives Pass 1 (cache-only probe, in priority
    // order) and Pass 2 (parallel upstream fan-out for members that could still
    // outrank a Pass-1 hit). These exercise the full control flow with canned
    // async closures, so they need no database, proxy, or upstream.

    fn two_members() -> Vec<Repository> {
        vec![test_local_member("m0"), test_local_member("m1")]
    }

    #[tokio::test]
    async fn two_phase_top_priority_cache_hit_skips_all_upstream() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let members = two_members();
        let out = resolve_members_two_phase::<String, String, _, _, _, _>(
            &members,
            |m| {
                let class = if m.key == "m0" {
                    (MemberCacheClass::DefiniteHit, Some("cache0".to_string()))
                } else {
                    (MemberCacheClass::NeedsUpstream, None)
                };
                async move { class }
            },
            |_m| {
                c.fetch_add(1, Ordering::SeqCst);
                async move { MemberResolveOutcome::Hit("upstream".to_string()) }
            },
        )
        .await;
        match out {
            Some(MemberResolveOutcome::Hit(v)) => assert_eq!(v, "cache0"),
            other => panic!("expected Hit(cache0), got {other:?}"),
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a dominating hit must not fan out"
        );
    }

    #[tokio::test]
    async fn two_phase_higher_priority_upstream_beats_lower_cache_hit() {
        let members = two_members();
        let out = resolve_members_two_phase::<String, String, _, _, _, _>(
            &members,
            |m| {
                let class = if m.key == "m0" {
                    (MemberCacheClass::NeedsUpstream, None)
                } else {
                    (MemberCacheClass::DefiniteHit, Some("cache1".to_string()))
                };
                async move { class }
            },
            |_m| async move { MemberResolveOutcome::Hit("upstream0".to_string()) },
        )
        .await;
        match out {
            Some(MemberResolveOutcome::Hit(v)) => assert_eq!(v, "upstream0"),
            other => panic!("expected Hit(upstream0), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn two_phase_falls_back_to_cache_hit_when_upstream_misses() {
        let members = two_members();
        let out = resolve_members_two_phase::<String, String, _, _, _, _>(
            &members,
            |m| {
                let class = if m.key == "m0" {
                    (MemberCacheClass::NeedsUpstream, None)
                } else {
                    (MemberCacheClass::DefiniteHit, Some("cache1".to_string()))
                };
                async move { class }
            },
            |_m| async move { MemberResolveOutcome::Miss },
        )
        .await;
        match out {
            Some(MemberResolveOutcome::Hit(v)) => assert_eq!(v, "cache1"),
            other => panic!("expected Hit(cache1), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn two_phase_all_miss_is_none_and_never_fans_out() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let members = two_members();
        let out = resolve_members_two_phase::<String, String, _, _, _, _>(
            &members,
            |_m| async move { (MemberCacheClass::DefiniteMiss, None) },
            |_m| {
                c.fetch_add(1, Ordering::SeqCst);
                async move { MemberResolveOutcome::Hit("x".to_string()) }
            },
        )
        .await;
        assert!(out.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn two_phase_quarantine_block_surfaces_from_upstream() {
        let members = two_members();
        let out = resolve_members_two_phase::<String, String, _, _, _, _>(
            &members,
            |_m| async move { (MemberCacheClass::NeedsUpstream, None) },
            |m| {
                let r = if m.key == "m0" {
                    MemberResolveOutcome::Quarantine("held".to_string())
                } else {
                    MemberResolveOutcome::Hit("hit1".to_string())
                };
                async move { r }
            },
        )
        .await;
        match out {
            Some(MemberResolveOutcome::Quarantine(e)) => assert_eq!(e, "held"),
            other => panic!("expected Quarantine(held), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn two_phase_returns_highest_priority_hit_even_if_lower_resolves_first() {
        // Both members need upstream and both would hit, but the LOWER-priority
        // member (m1) resolves immediately while the HIGHER-priority member (m0)
        // is slower. The ordered finalize MUST still return m0's hit — the
        // winner is decided by priority, never by which future resolves first.
        let members = two_members();
        let out = resolve_members_two_phase::<String, String, _, _, _, _>(
            &members,
            |_m| async move { (MemberCacheClass::NeedsUpstream, None) },
            |m| {
                let key = m.key.clone();
                async move {
                    if key == "m0" {
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        MemberResolveOutcome::Hit("hit0".to_string())
                    } else {
                        MemberResolveOutcome::Hit("hit1".to_string())
                    }
                }
            },
        )
        .await;
        match out {
            Some(MemberResolveOutcome::Hit(v)) => assert_eq!(
                v, "hit0",
                "highest-priority hit must win regardless of resolution order"
            ),
            other => panic!("expected Hit(hit0), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn two_phase_cancels_lower_priority_loser_once_winner_known() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        // m0 (highest priority) hits immediately; m1 would block for 10s. The
        // resolver must return m0 promptly and DROP (cancel) m1's in-flight
        // future rather than await it — so m1's completion flag stays false.
        let members = two_members();
        let lower_completed = Arc::new(AtomicBool::new(false));
        let lc = lower_completed.clone();
        let out = resolve_members_two_phase::<String, String, _, _, _, _>(
            &members,
            |_m| async move { (MemberCacheClass::NeedsUpstream, None) },
            move |m| {
                let key = m.key.clone();
                let lc = lc.clone();
                async move {
                    if key == "m0" {
                        MemberResolveOutcome::Hit("hit0".to_string())
                    } else {
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                        lc.store(true, Ordering::SeqCst);
                        MemberResolveOutcome::Hit("hit1".to_string())
                    }
                }
            },
        )
        .await;
        assert!(
            matches!(out, Some(MemberResolveOutcome::Hit(ref v)) if v == "hit0"),
            "highest-priority immediate hit must win"
        );
        assert!(
            !lower_completed.load(Ordering::SeqCst),
            "the lower-priority loser must be cancelled, not awaited to completion"
        );
    }

    #[tokio::test]
    async fn two_phase_stops_probing_after_first_definite_hit() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        // member 0 is a DefiniteHit; members 1 and 2 must NOT be probed (they
        // can never outrank it) — preserves the sequential loop's warm-path
        // short-circuit so probe cost is O(rank of first hit), not O(N).
        let members = vec![
            test_local_member("m0"),
            test_local_member("m1"),
            test_local_member("m2"),
        ];
        let probes = Arc::new(AtomicUsize::new(0));
        let p = probes.clone();
        let upstream_calls = Arc::new(AtomicUsize::new(0));
        let u = upstream_calls.clone();
        let out = resolve_members_two_phase::<String, String, _, _, _, _>(
            &members,
            move |_m| {
                p.fetch_add(1, Ordering::SeqCst);
                async move { (MemberCacheClass::DefiniteHit, Some("hit0".to_string())) }
            },
            move |_m| {
                u.fetch_add(1, Ordering::SeqCst);
                async move { MemberResolveOutcome::Hit("upstream".to_string()) }
            },
        )
        .await;
        assert!(matches!(out, Some(MemberResolveOutcome::Hit(ref v)) if v == "hit0"));
        assert_eq!(
            probes.load(Ordering::SeqCst),
            1,
            "Pass 1 must stop probing at the first DefiniteHit"
        );
        assert_eq!(
            upstream_calls.load(Ordering::SeqCst),
            0,
            "a top hit fans out to nothing"
        );
    }

    #[tokio::test]
    async fn two_phase_confirm_top_candidate_hit_skips_rest() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        // Cold (no Pass-1 hit): the highest-priority candidate hits. Confirm-top-
        // first (#2069) must return it WITHOUT launching the lower-priority
        // candidates' upstream fetches — exactly ONE upstream request, no
        // cold-positive fan-out.
        let members = vec![
            test_local_member("m0"),
            test_local_member("m1"),
            test_local_member("m2"),
        ];
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let out = resolve_members_two_phase::<String, String, _, _, _, _>(
            &members,
            |_m| async move { (MemberCacheClass::NeedsUpstream, None) },
            move |m| {
                c.fetch_add(1, Ordering::SeqCst);
                let key = m.key.clone();
                async move { MemberResolveOutcome::Hit(format!("hit-{key}")) }
            },
        )
        .await;
        match out {
            Some(MemberResolveOutcome::Hit(v)) => assert_eq!(v, "hit-m0"),
            other => panic!("expected Hit(hit-m0), got {other:?}"),
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "confirm-top-first must contact only the top candidate when it hits"
        );
    }

    #[tokio::test]
    async fn two_phase_top_candidate_miss_fans_out_rest_in_priority() {
        // Cold: the top candidate misses, so the rest are fanned out and the
        // highest-priority non-miss among them wins (strict priority).
        let members = vec![
            test_local_member("m0"),
            test_local_member("m1"),
            test_local_member("m2"),
        ];
        let out = resolve_members_two_phase::<String, String, _, _, _, _>(
            &members,
            |_m| async move { (MemberCacheClass::NeedsUpstream, None) },
            |m| {
                let key = m.key.clone();
                async move {
                    if key == "m0" {
                        MemberResolveOutcome::Miss
                    } else {
                        MemberResolveOutcome::Hit(format!("hit-{key}"))
                    }
                }
            },
        )
        .await;
        match out {
            Some(MemberResolveOutcome::Hit(v)) => assert_eq!(
                v, "hit-m1",
                "after the top candidate misses, the highest-priority remaining hit wins"
            ),
            other => panic!("expected Hit(hit-m1), got {other:?}"),
        }
    }

    // ── Two-phase virtual fan-out: probe / upstream classifiers (pure) ──

    #[test]
    fn classify_cache_probe_maps_hit_miss_negative() {
        use crate::error::AppError;
        let (class, hit) = classify_cache_probe::<i32>(Ok(Some(7)));
        assert_eq!(class, MemberCacheClass::DefiniteHit);
        assert_eq!(hit, Some(7));

        let (class, hit) = classify_cache_probe::<i32>(Ok(None));
        assert_eq!(class, MemberCacheClass::NeedsUpstream);
        assert!(hit.is_none());

        // A negative-cached 404 surfaces as Err -> definite miss (no re-fetch).
        let (class, hit) = classify_cache_probe::<i32>(Err(AppError::NotFound("neg".into())));
        assert_eq!(class, MemberCacheClass::DefiniteMiss);
        assert!(hit.is_none());

        // A quarantine block (#1770) from a *cached* held entry must NOT be
        // dropped: it is re-resolved in Pass 2 (which surfaces the 409/403),
        // so it classifies NeedsUpstream, not DefiniteMiss.
        let (class, _) = classify_cache_probe::<i32>(Err(AppError::Conflict("held".into())));
        assert_eq!(class, MemberCacheClass::NeedsUpstream);
        let (class, _) =
            classify_cache_probe::<i32>(Err(AppError::Authorization("rejected".into())));
        assert_eq!(class, MemberCacheClass::NeedsUpstream);
    }

    #[test]
    fn classify_stream_upstream_maps_hit_quarantine_miss() {
        use crate::error::AppError;
        match classify_stream_upstream(Ok(empty_stream_result()), "k", "p") {
            MemberResolveOutcome::Hit(_) => {}
            other => panic!("expected Hit, got {other:?}"),
        }
        // A quarantine block (409) must surface as Quarantine with a 409 status.
        match classify_stream_upstream(Err(AppError::Conflict("held".into())), "k", "p") {
            MemberResolveOutcome::Quarantine(resp) => {
                assert_eq!(resp.status(), StatusCode::CONFLICT)
            }
            other => panic!("expected Quarantine, got {other:?}"),
        }
        // An ordinary 404 is a miss, not a surfacing error.
        match classify_stream_upstream(Err(AppError::NotFound("gone".into())), "k", "p") {
            MemberResolveOutcome::Miss => {}
            other => panic!("expected Miss, got {other:?}"),
        }
    }

    #[test]
    fn classify_streaming_cache_probe_maps_hit_miss_negative() {
        use crate::error::AppError;
        let (class, resp) =
            classify_streaming_cache_probe(Ok(Some(empty_stream_result())), "text/xml", None);
        assert_eq!(class, MemberCacheClass::DefiniteHit);
        assert!(resp.is_some());

        let (class, resp) = classify_streaming_cache_probe(Ok(None), "text/xml", None);
        assert_eq!(class, MemberCacheClass::NeedsUpstream);
        assert!(resp.is_none());

        let (class, resp) =
            classify_streaming_cache_probe(Err(AppError::NotFound("neg".into())), "text/xml", None);
        assert_eq!(class, MemberCacheClass::DefiniteMiss);
        assert!(resp.is_none());

        // A quarantine block (#1770) re-resolves in Pass 2 → NeedsUpstream.
        let (class, _) = classify_streaming_cache_probe(
            Err(AppError::Conflict("held".into())),
            "text/xml",
            None,
        );
        assert_eq!(class, MemberCacheClass::NeedsUpstream);
    }

    #[test]
    fn classify_streaming_local_maps_hit_and_miss() {
        let (class, resp) =
            classify_streaming_local(Ok(empty_stream_result()), "application/json", Some("f.bin"));
        assert_eq!(class, MemberCacheClass::DefiniteHit);
        assert!(resp.is_some());

        let miss = Err((StatusCode::NOT_FOUND, "missing").into_response());
        let (class, resp) = classify_streaming_local(miss, "application/json", None);
        assert_eq!(class, MemberCacheClass::DefiniteMiss);
        assert!(resp.is_none());
    }

    #[test]
    fn classify_streaming_upstream_maps_hit_quarantine_miss() {
        let ok = Ok((StatusCode::OK, "body").into_response());
        match classify_streaming_upstream(ok) {
            MemberResolveOutcome::Hit(r) => assert_eq!(r.status(), StatusCode::OK),
            other => panic!("expected Hit, got {other:?}"),
        }
        // A 409/403 Response is a quarantine block that must surface.
        let held = Err((StatusCode::CONFLICT, "held").into_response());
        match classify_streaming_upstream(held) {
            MemberResolveOutcome::Quarantine(r) => assert_eq!(r.status(), StatusCode::CONFLICT),
            other => panic!("expected Quarantine, got {other:?}"),
        }
        // Any other error Response is a miss.
        let gone = Err((StatusCode::NOT_FOUND, "gone").into_response());
        match classify_streaming_upstream(gone) {
            MemberResolveOutcome::Miss => {}
            other => panic!("expected Miss, got {other:?}"),
        }
    }

    // ── Two-phase virtual fan-out: orchestration (no proxy / no network) ──
    //
    // These exercise `resolve_virtual_download_from_members` over Local and
    // un-proxyable members (proxy_service = None), so they need neither a
    // database nor an upstream. The Remote cache-probe / parallel upstream
    // branches require a live `ProxyService` and are covered by the virtual
    // resolution integration tests.

    fn empty_stream_result() -> StreamingFetchResult {
        StreamingFetchResult {
            body: Box::pin(futures::stream::empty()),
            content_type: None,
            content_length: Some(0),
        }
    }

    fn test_local_member(key: &str) -> Repository {
        let mut r = build_remote_repo(Uuid::new_v4(), key, "https://unused.example.com");
        r.repo_type = RepositoryType::Local;
        r.upstream_url = None;
        r
    }

    #[tokio::test]
    async fn resolve_from_members_empty_is_404() {
        let res = resolve_virtual_download_from_members(
            Vec::new(),
            None,
            "g/a/1.0/a-1.0.jar",
            |_id, _loc| async { Ok(empty_stream_result()) },
        )
        .await;
        assert_eq!(res.err().map(|r| r.status()), Some(StatusCode::NOT_FOUND));
    }

    #[tokio::test]
    async fn resolve_from_members_returns_local_hit() {
        let members = vec![test_local_member("maven-local")];
        let res = resolve_virtual_download_from_members(
            members,
            None,
            "g/a/1.0/a-1.0.jar",
            |_id, _loc| async { Ok(empty_stream_result()) },
        )
        .await;
        assert!(
            res.is_ok(),
            "a local member that has the artifact must serve it"
        );
    }

    #[tokio::test]
    async fn resolve_from_members_all_miss_is_404() {
        // One local member that misses + one remote member that cannot be
        // proxied (no proxy service) => skipped => overall 404.
        let members = vec![
            test_local_member("maven-local"),
            build_remote_repo(Uuid::new_v4(), "maven-remote", "https://repo1.example.com"),
        ];
        let res = resolve_virtual_download_from_members(
            members,
            None,
            "g/a/1.0/a-1.0.jar",
            |_id, _loc| async { Err((StatusCode::NOT_FOUND, "missing").into_response()) },
        )
        .await;
        assert_eq!(res.err().map(|r| r.status()), Some(StatusCode::NOT_FOUND));
    }

    #[tokio::test]
    async fn resolve_from_members_falls_through_to_lower_priority_local() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        // Highest-priority local misses; the next local has it. With no member
        // pending upstream, the lower-priority hit must win.
        let members = vec![
            test_local_member("maven-local-a"),
            test_local_member("maven-local-b"),
        ];
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = calls.clone();
        let res = resolve_virtual_download_from_members(
            members,
            None,
            "g/a/1.0/a-1.0.jar",
            move |_id, _loc| {
                let n = calls2.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n == 0 {
                        Err((StatusCode::NOT_FOUND, "miss").into_response())
                    } else {
                        Ok(empty_stream_result())
                    }
                }
            },
        )
        .await;
        assert!(res.is_ok(), "lower-priority local hit must be served");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "both locals are probed in order"
        );
    }

    #[test]
    fn test_redact_proxy_path_for_diagnostics_strips_signed_url_query() {
        let signed = "https://provider-bucket.s3.amazonaws.com/releases/pkg.zip\
                      ?X-Amz-Signature=deadbeef&X-Amz-Credential=AKIAEXAMPLE#frag";
        assert_eq!(
            redact_proxy_path_for_diagnostics(signed),
            "https://provider-bucket.s3.amazonaws.com/releases/pkg.zip"
        );
        assert_eq!(
            redact_proxy_path_for_diagnostics("packages/pkg.zip?token=secret#frag"),
            "packages/pkg.zip"
        );
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
            format: "generic".to_string(),
            upstream_url: None,
            promotion_only,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
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

    // ── promotion_only direct-delete gate ───────────────────────────

    #[test]
    fn test_promotion_only_blocks_non_admin_direct_delete() {
        // Non-admin (non-approver) + promotion_only repo => delete blocked.
        assert!(promotion_only_blocks_direct_delete(true, false));
    }

    #[test]
    fn test_promotion_only_admin_retains_delete_escape_hatch() {
        // Admins are the release-approvers and keep the retraction escape hatch,
        // unlike the upload gate: (promotion_only=true, is_admin=true) => allowed.
        assert!(!promotion_only_blocks_direct_delete(true, true));
    }

    #[test]
    fn test_promotion_only_delete_normal_repo_not_blocked() {
        // promotion_only = false => never blocked, for any caller (no regression
        // for normal repos).
        assert!(!promotion_only_blocks_direct_delete(false, false));
        assert!(!promotion_only_blocks_direct_delete(false, true));
    }

    #[test]
    fn test_reject_direct_delete_if_promotion_only_returns_403() {
        // Non-admin delete on a promotion_only repo is rejected 403 FORBIDDEN.
        let err = reject_direct_delete_if_promotion_only(true, false)
            .expect_err("non-admin direct delete on promotion_only repo must be rejected");
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_reject_direct_delete_if_promotion_only_admin_and_normal_ok() {
        // Admin delete on a promotion_only repo passes (retraction hatch); a
        // normal repo is a no-op for any caller.
        assert!(reject_direct_delete_if_promotion_only(true, true).is_ok());
        assert!(reject_direct_delete_if_promotion_only(false, false).is_ok());
        assert!(reject_direct_delete_if_promotion_only(false, true).is_ok());
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
    fn test_internal_error_pool_timeout_returns_503() {
        // Every local/virtual artifact-lookup helper funnels DB errors through
        // internal_error. A saturated pool must surface as 503 (capacity shed)
        // so clients back off, not a bare 500 (#1437). Reproduce the exact sqlx
        // Display string, which does not contain the "PoolTimedOut" variant name.
        let response = internal_error("Database", sqlx::Error::PoolTimedOut.to_string());
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn test_shadowing_guard_db_err_pool_timeout_returns_503() {
        // The shadowing guard fails closed to 500 on real DB errors, but a
        // saturated pool is transient capacity: it must shed to 503 so clients
        // back off instead of paging ops (#1437).
        let response =
            shadowing_guard_db_err(uuid::Uuid::new_v4(), "maven", sqlx::Error::PoolTimedOut);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn test_shadowing_guard_db_err_other_error_fails_closed_500() {
        // Non-timeout DB failures must still fail closed to 500 (no 503 shed)
        // and must not leak the raw error text in the body.
        let response =
            shadowing_guard_db_err(uuid::Uuid::new_v4(), "generic", sqlx::Error::RowNotFound);
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
            format: "generic".to_string(),
            promotion_only: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
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
        async fn put_stream(
            &self,
            key: &str,
            stream: futures::stream::BoxStream<'static, crate::error::Result<bytes::Bytes>>,
        ) -> crate::error::Result<crate::storage::PutStreamResult> {
            crate::storage::buffered_put_stream_fallback(self, key, stream).await
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
        async fn put_stream(
            &self,
            key: &str,
            stream: futures::stream::BoxStream<'static, crate::error::Result<bytes::Bytes>>,
        ) -> crate::error::Result<crate::storage::PutStreamResult> {
            crate::storage::buffered_put_stream_fallback(self, key, stream).await
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
                trivy_adapter_url: None,
                openscap_url: None,
                openscap_profile: "standard".into(),
                opensearch_url: None,
                opensearch_username: None,
                opensearch_password: None,
                opensearch_allow_invalid_certs: false,
                scan_workspace_path: "/tmp/scan".into(),
                demo_mode: false,
                guest_access_enabled: true,
                expose_detailed_health: false,
                grpc_reflection_enabled: false,
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
                blob_gc_sweep_grace_secs: 3600,
                lifecycle_check_interval_secs: 60,
                stuck_scan_threshold_secs: 1800,
                stuck_scan_check_interval_secs: 600,
                stuck_scan_reap_limit: 1000,
                allow_local_admin_login: false,
                sso_disable_admin_break_glass: false,
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
                rate_limit_trusted_proxy_cidrs: Vec::new(),
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
                proxy_singleflight_advisory_locks_enabled: false,
                proxy_singleflight_lock_poll_interval_ms: 200,
                proxy_singleflight_lock_wait_timeout_secs: 65,
                smtp_host: None,
                smtp_port: 587,
                smtp_username: None,
                smtp_password: None,
                smtp_from_address: "noreply@test.local".to_string(),
                smtp_tls_mode: "starttls".to_string(),
                npm_packument_cache_enabled: true,
                npm_packument_cache_fresh_ttl_secs: 300,
                npm_packument_cache_stale_max_secs: 86_400,
                npm_packument_cache_redis_url: None,
                scan_token_ttl_seconds: 300,
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
            format: "generic".to_string(),
            promotion_only: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
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

    // ── stage_upload_field + put_artifact_stream (#1608 Phase 2) ─────────

    /// Encode a single-field (`file`) multipart/form-data body.
    fn one_field_multipart(boundary: &str, payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            b"Content-Disposition: form-data; name=\"file\"; filename=\"f.tar.gz\"\r\n",
        );
        body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
        body.extend_from_slice(payload);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        body
    }

    /// Extract the first multipart field from an in-memory body.
    async fn first_field(body: Vec<u8>) -> axum::extract::Multipart {
        use axum::extract::FromRequest;
        let req = axum::http::Request::builder()
            .method("POST")
            .header("content-type", "multipart/form-data; boundary=BND")
            .body(axum::body::Body::from(body))
            .unwrap();
        axum::extract::Multipart::from_request(req, &())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_stage_and_put_artifact_stream_roundtrip() {
        let Some(pool) = db_helpers::try_pool().await else {
            return;
        };
        let (repo_id, repo_key, storage_dir) =
            db_helpers::create_repo(&pool, "local", "chef").await;
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

        let payload = b"streamed-artifact-body".repeat(64);
        let mut mp = first_field(one_field_multipart("BND", &payload)).await;
        let field = mp.next_field().await.unwrap().unwrap();

        let staged = stage_upload_field(&state, field).await.expect("stage");
        assert!(!staged.is_empty());
        assert_eq!(staged.size_bytes(), payload.len() as i64);
        // Field bytes really landed on disk (spooled, not buffered).
        assert_eq!(tokio::fs::read(staged.path()).await.unwrap(), payload);
        let scratch = staged.path().to_path_buf();

        let put = put_artifact_stream(&state, &repo, "chef/x/1.0/x.tar.gz", staged)
            .await
            .expect("put_stream");

        // Checksum computed incrementally by put_stream matches a direct hash.
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&payload);
        assert_eq!(put.checksum_sha256, format!("{:x}", hasher.finalize()));
        assert_eq!(put.bytes_written, payload.len() as u64);

        // Scratch file removed once the StagedUpload dropped.
        assert!(!scratch.exists());

        // Bytes are retrievable from the backend under the storage key.
        let storage = state.storage_for_repo(&repo.storage_location()).unwrap();
        let got = storage.get("chef/x/1.0/x.tar.gz").await.unwrap();
        assert_eq!(got.as_ref(), payload.as_slice());

        db_helpers::cleanup(&pool, repo_id, Uuid::nil()).await;
    }

    #[tokio::test]
    async fn test_stage_upload_field_reports_empty_body() {
        let Some(pool) = db_helpers::try_pool().await else {
            return;
        };
        let (repo_id, _repo_key, storage_dir) =
            db_helpers::create_repo(&pool, "local", "pub").await;
        let state = db_helpers::build_state(pool.clone(), storage_dir.to_str().unwrap());

        let mut mp = first_field(one_field_multipart("BND", b"")).await;
        let field = mp.next_field().await.unwrap().unwrap();

        let staged = stage_upload_field(&state, field).await.expect("stage");
        assert!(staged.is_empty());
        assert_eq!(staged.size_bytes(), 0);
        // Even an empty spool leaves a scratch file that is cleaned up on drop.
        let scratch = staged.path().to_path_buf();
        drop(staged);
        assert!(!scratch.exists());

        db_helpers::cleanup(&pool, repo_id, Uuid::nil()).await;
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
            format: "generic".to_string(),
            promotion_only: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
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
            format: "generic".to_string(),
            promotion_only: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
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
            format: "generic".to_string(),
            promotion_only: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
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
            format: "generic".to_string(),
            promotion_only: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
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

    /// End-to-end pin for [`proxy_fetch_streaming_response_with_cache_key`]
    /// (#1998): the upstream fetch and the proxy cache key must be allowed to
    /// diverge. This mirrors the Terraform/OpenTofu network-mirror archive
    /// download bug, where the registry-provided `download_url` is an
    /// absolute URL (fine as a fetch target) but unsafe as a cache path (its
    /// `https://` scheme's `//` trips `validate_cache_path`'s empty-segment
    /// guard). `fetch_path` here is deliberately an absolute URL while
    /// `cache_path` is a canonical, scheme-less path, so a regression that
    /// collapses the wrapper back to `fetch_path == cache_path` would fail
    /// cache-path validation rather than just silently caching under the
    /// wrong key.
    ///
    /// Skipped when `DATABASE_URL` is unset (CI always sets it).
    #[tokio::test]
    async fn test_proxy_fetch_streaming_response_with_cache_key_streams_split_paths_1998() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let server = MockServer::start().await;
        let archive_bytes = b"fake-provider-archive-bytes";
        Mock::given(method("GET"))
            .and(path("/terraform-provider-null_3.2.3_linux_arm64.zip"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(archive_bytes.as_ref()))
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("tf-mirror-cache-key-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp dir");
        let proxy = tdh::build_proxy_service_with_fs(pool, tmp.to_str().unwrap());

        // The absolute-URL fetch target, exactly as an upstream registry's
        // download document would provide it.
        let fetch_path = format!(
            "{}/terraform-provider-null_3.2.3_linux_arm64.zip",
            server.uri()
        );
        // The canonical, scheme-less cache path `mirror_archive_cache_path`
        // derives for this archive.
        let cache_path =
            "hashicorp/null/3.2.3/linux/arm64/terraform-provider-null_3.2.3_linux_arm64.zip";

        let response = proxy_fetch_streaming_response_with_cache_key(
            &proxy,
            Uuid::new_v4(),
            "tf-mirror",
            &server.uri(),
            &fetch_path,
            cache_path,
            "application/zip",
        )
        .await
        .expect("streaming response must succeed for a split fetch/cache path");

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        let _ = std::fs::remove_dir_all(&tmp);
        assert_eq!(&body[..], archive_bytes.as_ref());
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

    /// Source slice of one top-level item starting at `start`, bounded at the
    /// next column-0 `}` line (the item's own closing brace — body lines are all
    /// indented, so this matches only the top-level close). Keeps the
    /// #1215/#1555 source-guard pins robust to the function growing or being
    /// reordered, instead of relying on a fixed byte window.
    fn item_body(src: &str, start: usize) -> &str {
        let rel_end = src[start..]
            .find("\n}\n")
            .map(|e| e + 3)
            .unwrap_or(src.len() - start);
        &src[start..start + rel_end]
    }

    #[test]
    fn test_try_remote_or_virtual_download_remote_uses_streaming_helper_1215() {
        let src = include_str!("proxy_helpers.rs");
        let fn_start = src
            .find("pub async fn try_remote_or_virtual_download(")
            .expect("try_remote_or_virtual_download must exist");
        // Bound the window to just this function so a streaming token elsewhere
        // in the file cannot satisfy the assertion vacuously.
        let window = item_body(src, fn_start);
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
        let window = item_body(src, fn_start);
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
        // #1215: Remote members of a Virtual repo MUST stream, never buffer.
        // The two-phase resolver (#2069) drives each Remote member's upstream
        // fetch through `proxy_fetch_streaming_member(`, which in turn calls the
        // streaming `fetch_artifact_streaming(` (not the buffered `fetch_artifact`).
        let src = include_str!("proxy_helpers.rs");
        let fn_start = src
            .find("pub async fn resolve_virtual_download_streaming<")
            .expect("resolve_virtual_download_streaming must exist");
        let window = item_body(src, fn_start);
        assert!(
            window.contains("proxy_fetch_streaming_member("),
            "`resolve_virtual_download_streaming` MUST drive Remote members \
             through the streaming `proxy_fetch_streaming_member(` helper \
             (#1215/#2069). Buffering each Remote member's body before serving \
             it would defeat the whole point of having a streaming resolver."
        );

        // And that helper must itself stream, not buffer.
        let helper_start = src
            .find("async fn proxy_fetch_streaming_member(")
            .expect("proxy_fetch_streaming_member must exist");
        let helper_window = item_body(src, helper_start);
        assert!(
            helper_window.contains("fetch_artifact_streaming("),
            "`proxy_fetch_streaming_member` MUST use the streaming \
             `fetch_artifact_streaming(` (#1215), never a buffered fetch."
        );
    }

    #[test]
    fn test_resolve_virtual_download_streaming_redirects_before_streaming_1555() {
        // #1555: a fresh proxy-cache hit on an S3-backed member must be
        // served as a presigned redirect, NOT streamed through the
        // backend. Streaming holds a worker thread for the whole transfer
        // and saturates the dispatcher under burst load. The redirect
        // attempt (Pass 1, via `try_member_cache_redirect(`) must sit BEFORE
        // the streaming fallback (Pass 2, `proxy_fetch_streaming_member(`) so
        // cached bodies never get streamed through the backend.
        let src = include_str!("proxy_helpers.rs");
        let fn_start = src
            .find("pub async fn resolve_virtual_download_streaming<")
            .expect("resolve_virtual_download_streaming must exist");
        let window = item_body(src, fn_start);

        let redirect_pos = window.find("try_member_cache_redirect(").expect(
            "`resolve_virtual_download_streaming` MUST attempt the presigned \
             redirect fast path via `try_member_cache_redirect(` (#1555).",
        );
        let stream_pos = window
            .find("proxy_fetch_streaming_member(")
            .expect("streaming fallback must still exist (#1215)");
        assert!(
            redirect_pos < stream_pos,
            "the presigned redirect attempt (#1555) MUST come BEFORE the \
             streaming fallback (#1215); otherwise cached large artifacts \
             still stream through the backend.",
        );

        // The redirect helper itself must call `try_proxy_cache_redirect(` and
        // gate on a metadata-only `is_cache_fresh(` probe so it never pulls the
        // body just to decide whether to redirect (#1555).
        let helper_start = src
            .find("async fn try_member_cache_redirect(")
            .expect("try_member_cache_redirect must exist");
        let helper_window = item_body(src, helper_start);
        assert!(
            helper_window.contains("try_proxy_cache_redirect(")
                && helper_window.contains("is_cache_fresh("),
            "`try_member_cache_redirect` MUST attempt `try_proxy_cache_redirect(` \
             gated on a metadata-only `is_cache_fresh(` probe (#1555).",
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
            // The Virtual streaming resolver's presign moved into this helper
            // (#2069 two-phase refactor); it is where the no-prefix handle is used.
            "async fn try_member_cache_redirect(",
            "pub async fn local_fetch_or_redirect(",
        ] {
            let fn_start = src
                .find(fn_name)
                .unwrap_or_else(|| panic!("{fn_name} must exist"));
            let window = item_body(src, fn_start);

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
        let window = item_body(src, fn_start);
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

    /// Redirect-capable proxy-cache backend for the #2075 quarantine-gate
    /// tests. Serves a single fresh, positive cache entry whose sidecar carries
    /// the supplied Package Age Policy hold (`quarantine_until`), and records
    /// every presign attempt so a test can assert a HELD entry is never signed
    /// (and therefore never handed out as a 302). Mirrors `FreshProxyCacheStorage`
    /// but parameterizes the hold and counts `get_presigned_url` calls.
    struct QuarantineRedirectStorage {
        quarantine_until: Option<chrono::DateTime<Utc>>,
        presign_calls: StdArc<AtomicUsize>,
    }

    impl QuarantineRedirectStorage {
        fn new(quarantine_until: Option<chrono::DateTime<Utc>>) -> Self {
            Self {
                quarantine_until,
                presign_calls: StdArc::new(AtomicUsize::new(0)),
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::services::storage_service::StorageBackend for QuarantineRedirectStorage {
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
                    quarantine_until: self.quarantine_until,
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
        fn supports_redirect(&self) -> bool {
            true
        }
        async fn get_presigned_url(
            &self,
            key: &str,
            expires_in: std::time::Duration,
        ) -> crate::error::Result<Option<crate::storage::PresignedUrl>> {
            self.presign_calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some(crate::storage::PresignedUrl {
                url: format!("https://signed.example.com/{}", key),
                expires_in,
                source: crate::storage::PresignedUrlSource::S3,
            }))
        }
    }

    /// Build a `ProxyService` whose no-prefix cache backend is the supplied
    /// mock, over a lazy DB pool that is never dialed (the redirect fast path
    /// does not touch the database). Shared by the #2075 `proxy_fetch_or_redirect`
    /// tests.
    fn build_proxy_with_cache_backend(backend: StdArc<QuarantineRedirectStorage>) -> ProxyService {
        let pool = sqlx::PgPool::connect_lazy("postgres://fake:fake@localhost/fake")
            .expect("connect_lazy should not fail");
        ProxyService::new(
            pool,
            StdArc::new(crate::services::storage_service::StorageService::new(
                backend,
            )),
        )
    }

    /// #2075: a fresh proxy-cache entry that is still inside its Package Age
    /// Policy hold window MUST NOT be handed out as a presigned 302 on a
    /// redirect-capable backend. `proxy_fetch_or_redirect` must return the same
    /// 409 the buffered/streaming paths return, and MUST NOT sign the object.
    #[tokio::test]
    async fn test_proxy_fetch_or_redirect_blocks_held_entry_2075() {
        let held = StdArc::new(QuarantineRedirectStorage::new(Some(
            Utc::now() + chrono::Duration::minutes(30),
        )));
        let proxy = build_proxy_with_cache_backend(held.clone());
        // The registry-side backend is irrelevant to the fast path; presigned
        // downloads must be enabled on the state config.
        let registry_storage = StdArc::new(RecordingStorage::new(/* supports = */ true));
        let pool = sqlx::PgPool::connect_lazy("postgres://fake:fake@localhost/fake")
            .expect("connect_lazy should not fail");
        let state = db_helpers::build_state_presigned(pool, "s3-test", registry_storage.clone());

        let err = super::proxy_fetch_or_redirect(
            &proxy,
            &state,
            Uuid::nil(),
            "npm-proxy",
            "https://upstream.example.test",
            "lodash",
        )
        .await
        .expect_err("a held cache entry must not resolve to a redirect");

        assert_eq!(
            err.status(),
            StatusCode::CONFLICT,
            "a held entry must surface as 409, matching the buffered/streaming gate"
        );
        assert_eq!(
            held.presign_calls.load(Ordering::SeqCst),
            0,
            "a held entry must NEVER be presigned/redirected (#2075)"
        );
    }

    /// #2075 non-regression: a fresh proxy-cache entry with NO active hold must
    /// still take the presigned-redirect fast path (302), exactly as before the
    /// gate was added.
    #[tokio::test]
    async fn test_proxy_fetch_or_redirect_redirects_when_not_held_2075() {
        let fresh = StdArc::new(QuarantineRedirectStorage::new(/* quarantine = */ None));
        let proxy = build_proxy_with_cache_backend(fresh.clone());
        let registry_storage = StdArc::new(RecordingStorage::new(/* supports = */ true));
        let pool = sqlx::PgPool::connect_lazy("postgres://fake:fake@localhost/fake")
            .expect("connect_lazy should not fail");
        let state = db_helpers::build_state_presigned(pool, "s3-test", registry_storage.clone());

        let resp = super::proxy_fetch_or_redirect(
            &proxy,
            &state,
            Uuid::nil(),
            "npm-proxy",
            "https://upstream.example.test",
            "lodash",
        )
        .await
        .expect("a fresh, non-held entry must resolve to a redirect");

        assert_eq!(
            resp.status(),
            StatusCode::FOUND,
            "a fresh, non-held entry must still 302 to the presigned URL"
        );
        assert_eq!(
            fresh.presign_calls.load(Ordering::SeqCst),
            1,
            "the non-held fast path must sign exactly once"
        );
    }

    /// #2075: the virtual-member redirect fast path (`try_member_cache_redirect`
    /// inside the #2069 two-phase resolver) must apply the same hold gate as
    /// `proxy_fetch_or_redirect`. A held member entry on a redirect-capable
    /// backend must surface as 409 — routed through the resolver's quarantine
    /// channel (Pass-1 `NeedsUpstream` -> Pass-2 re-detect, no upstream
    /// contact) — never a 302 to the cached object, and must not sign.
    ///
    /// DB-gated like the sibling #1555 redirect test: skips without a live
    /// Postgres, runs in CI where one is provisioned.
    #[tokio::test]
    async fn test_resolve_virtual_download_streaming_blocks_held_entry_2075() {
        let Some(pool) = db_helpers::try_pool().await else {
            return;
        };

        let (virtual_id, _, _) = db_helpers::create_repo(&pool, "virtual", "pypi").await;
        let (member_id, _member_key, _) = db_helpers::create_repo(&pool, "remote", "pypi").await;
        db_helpers::link_member(&pool, virtual_id, member_id, 0).await;

        let registry_storage = StdArc::new(RecordingStorage::new(/* supports = */ true));
        let state =
            db_helpers::build_state_presigned(pool.clone(), "s3-test", registry_storage.clone());

        let held = StdArc::new(QuarantineRedirectStorage::new(Some(
            Utc::now() + chrono::Duration::minutes(30),
        )));
        let proxy = ProxyService::new(
            pool.clone(),
            StdArc::new(crate::services::storage_service::StorageService::new(
                held.clone(),
            )),
        );

        let err = resolve_virtual_download_streaming(
            &state,
            Some(&proxy),
            virtual_id,
            "pkg/pkg-1.0.0-py3-none-any.whl",
            "application/octet-stream",
            None,
            |_id, _loc| async {
                panic!("local_fetch must NOT run: the held entry must 409 before any fallback");
                #[allow(unreachable_code)]
                Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
            },
        )
        .await
        .expect_err("a held member cache entry must not resolve to a redirect");

        assert_eq!(
            err.status(),
            StatusCode::CONFLICT,
            "a held member entry must surface as 409 (#2075)"
        );
        assert_eq!(
            held.presign_calls.load(Ordering::SeqCst),
            0,
            "a held member entry must NEVER be presigned/redirected (#2075)"
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
            age_gate_enabled: false,
            age_gate_min_age_days: 0,
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
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: None,
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

    #[test]
    fn age_gate_params_maps_remote_npm_repo() {
        let info = RepoInfo {
            id: uuid::Uuid::new_v4(),
            key: "npm-remote".to_string(),
            storage_path: "/data".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "remote".to_string(),
            format: "npm".to_string(),
            upstream_url: Some("https://registry.npmjs.org".to_string()),
            promotion_only: false,
            age_gate_enabled: true,
            age_gate_min_age_days: 14,
        };
        let params = age_gate_params(&info);
        assert!(params.age_gate_enabled);
        assert_eq!(params.age_gate_min_age_days, 14);
        assert_eq!(params.key, "npm-remote");
    }

    #[test]
    fn age_gate_blocked_body_fields() {
        let id = uuid::Uuid::new_v4();
        let body = age_gate_blocked_body(id, "lodash", "4.0.0", 7, Some(2));
        assert_eq!(body["error"], "age_gate_blocked");
        assert_eq!(body["review_id"], id.to_string());
        assert_eq!(body["package"], "lodash");
        assert_eq!(body["min_age_days"], 7);
        assert_eq!(body["requested_age_days"], 2);
    }
}
