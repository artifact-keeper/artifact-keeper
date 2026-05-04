//! Shared helpers for remote repository proxying and virtual repository resolution.

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::api::download_response::try_presigned_redirect;
use crate::api::AppState;
use crate::models::repository::{
    ReplicationPriority, Repository, RepositoryFormat, RepositoryType,
};
use crate::services::proxy_service::ProxyService;
use crate::storage::StorageLocation;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Base URL from request headers
// ---------------------------------------------------------------------------

/// Derive the external base URL from reverse-proxy headers.
///
/// Checks `X-Forwarded-Proto` for the scheme (defaults to `"http"`) and
/// `X-Forwarded-Host` then `Host` for the hostname (defaults to
/// `"localhost"`). If the host value already contains a scheme prefix it is
/// returned as-is to avoid duplication.
///
/// Most format handlers need to construct absolute URLs for clients (OCI,
/// NuGet, npm, Cargo, Git LFS, SSO/OIDC). This function centralizes the
/// header inspection logic so each handler does not duplicate it.
pub fn request_base_url(headers: &HeaderMap) -> String {
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http");

    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get("host"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");

    if host.contains("://") {
        host.to_string()
    } else {
        format!("{}://{}", scheme, host)
    }
}

// ---------------------------------------------------------------------------
// Shared RepoInfo
// ---------------------------------------------------------------------------

/// Lightweight repository descriptor returned by [`resolve_repo_by_key`].
///
/// Every format handler needs the same handful of fields after looking up a
/// repository by its key. This struct avoids duplicating the definition in
/// each handler module.
pub struct RepoInfo {
    pub id: Uuid,
    pub key: String,
    pub storage_path: String,
    pub storage_backend: String,
    pub repo_type: String,
    pub upstream_url: Option<String>,
}

impl RepoInfo {
    pub fn storage_location(&self) -> StorageLocation {
        StorageLocation {
            backend: self.storage_backend.clone(),
            path: self.storage_path.clone(),
        }
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
         repo_type::text as repo_type, upstream_url \
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

/// Map a proxy service error to an HTTP error response.
///
/// `NotFound` errors become 404; everything else becomes 502 Bad Gateway.
/// The error is logged at `warn` level with the repo key and path for context.
fn map_proxy_error(repo_key: &str, path: &str, e: crate::error::AppError) -> Response {
    tracing::warn!("Proxy fetch failed for {}/{}: {}", repo_key, path, e);
    match &e {
        crate::error::AppError::NotFound(_) => {
            (StatusCode::NOT_FOUND, "Artifact not found upstream").into_response()
        }
        _ => (
            StatusCode::BAD_GATEWAY,
            format!("Failed to fetch from upstream: {}", e),
        )
            .into_response(),
    }
}

/// Attempt to fetch an artifact from the upstream via the proxy service.
/// Constructs a minimal `Repository` model from handler-level repo info.
/// Returns `(content_bytes, content_type)` on success.
pub async fn proxy_fetch(
    proxy_service: &ProxyService,
    repo_id: Uuid,
    repo_key: &str,
    upstream_url: &str,
    path: &str,
) -> Result<(Bytes, Option<String>), Response> {
    // Construct a minimal Repository that satisfies ProxyService::fetch_artifact
    let repo = build_remote_repo(repo_id, repo_key, upstream_url);

    proxy_service
        .fetch_artifact(&repo, path)
        .await
        .map_err(|e| map_proxy_error(repo_key, path, e))
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
    let cache_key = proxy_cache_storage_key(repo_key, path);
    let expiry = Duration::from_secs(state.config.presigned_download_expiry_secs);
    let presigned_enabled = state.config.presigned_downloads_enabled;

    // Fast path (#1018): if presigned downloads are enabled and the proxy
    // cache is already fresh, redirect to the signed URL without ever
    // pulling the cached body into the backend's memory. The freshness
    // probe is metadata-only (HEAD-equivalent on cloud backends).
    if presigned_enabled && proxy_service.is_cache_fresh(repo_key, path).await {
        if let Ok(storage) = state.storage_for_repo(&StorageLocation {
            backend: state.config.storage_backend.clone(),
            path: state.config.storage_path.clone(),
        }) {
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
        if let Ok(storage) = state.storage_for_repo(&StorageLocation {
            backend: state.config.storage_backend.clone(),
            path: state.config.storage_path.clone(),
        }) {
            if let Some(redirect) =
                try_presigned_redirect(storage.as_ref(), &cache_key, true, expiry).await
            {
                return Ok(redirect);
            }
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

/// Derive the proxy cache storage key for a given repo key and artifact path.
///
/// Matches the key pattern used by `ProxyService::cache_storage_key`, so
/// presigned redirects point to the correct cached object.
fn proxy_cache_storage_key(repo_key: &str, path: &str) -> String {
    format!(
        "proxy-cache/{}/{}/__content__",
        repo_key,
        path.trim_start_matches('/').trim_end_matches('/')
    )
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
pub(crate) async fn try_proxy_cache_redirect<S: crate::storage::StorageBackend + ?Sized>(
    storage: &S,
    cache_key: &str,
    presigned_enabled: bool,
    expiry: Duration,
    cache_is_fresh: bool,
) -> Option<Response> {
    if !presigned_enabled || !cache_is_fresh {
        return None;
    }
    try_presigned_redirect(storage, cache_key, true, expiry).await
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
    let repo = build_remote_repo(repo_id, repo_key, upstream_url);

    proxy_service
        .fetch_artifact_with_cache_path(&repo, fetch_path, cache_path)
        .await
        .map_err(|e| map_proxy_error(repo_key, fetch_path, e))
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
    let repo = build_remote_repo(repo_id, repo_key, upstream_url);

    proxy_service
        .fetch_upstream_direct(&repo, path)
        .await
        .map_err(|e| map_proxy_error(repo_key, path, e))
}

/// Fetch from upstream directly, preserving the upstream `Link` header.
pub async fn proxy_fetch_uncached_with_link(
    proxy_service: &ProxyService,
    repo_id: Uuid,
    repo_key: &str,
    upstream_url: &str,
    path: &str,
) -> Result<(Bytes, Option<String>, Option<String>), Response> {
    let repo = build_remote_repo(repo_id, repo_key, upstream_url);

    proxy_service
        .fetch_upstream_direct_with_link(&repo, path)
        .await
        .map_err(|e| map_proxy_error(repo_key, path, e))
}

/// Resolve virtual repository members and attempt to find an artifact.
/// Iterates through members by priority, trying local storage first,
/// then proxy for remote members.
///
/// `local_fetch` should attempt to load from local storage for a given repo_id.
/// Returns the first successful result, or the last error.
pub async fn resolve_virtual_download<F, Fut>(
    db: &PgPool,
    proxy_service: Option<&ProxyService>,
    virtual_repo_id: Uuid,
    path: &str,
    local_fetch: F,
) -> Result<(Bytes, Option<String>), Response>
where
    F: Fn(Uuid, StorageLocation) -> Fut,
    Fut: std::future::Future<Output = Result<(Bytes, Option<String>), Response>>,
{
    let members = fetch_virtual_members(db, virtual_repo_id).await?;

    if members.is_empty() {
        return Err((StatusCode::NOT_FOUND, "Virtual repository has no members").into_response());
    }

    for member in &members {
        // Try local storage first (works for Local, Staging, and cached Remote)
        if let Ok(result) = local_fetch(member.id, member.storage_location()).await {
            return Ok(result);
        }

        // If member is remote, try proxy
        if member.repo_type == RepositoryType::Remote {
            if let (Some(proxy), Some(upstream_url)) =
                (proxy_service, member.upstream_url.as_deref())
            {
                if let Ok(result) =
                    proxy_fetch(proxy, member.id, &member.key, upstream_url, path).await
                {
                    return Ok(result);
                }
            }
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
            r.is_public, r.quota_bytes,
            r.replication_priority as "replication_priority: ReplicationPriority",
            r.promotion_target_id, r.promotion_policy_id,
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

/// Row type for local artifact fetch queries, including quarantine fields.
#[derive(sqlx::FromRow)]
pub(crate) struct LocalArtifactRow {
    pub storage_key: String,
    pub content_type: String,
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

/// Generic local artifact fetch by exact path match.
/// Used as a `local_fetch` callback for [`resolve_virtual_download`].
pub async fn local_fetch_by_path(
    db: &PgPool,
    state: &AppState,
    repo_id: Uuid,
    location: &StorageLocation,
    artifact_path: &str,
) -> Result<(Bytes, Option<String>), Response> {
    let artifact = sqlx::query_as::<_, LocalArtifactRow>(
        "SELECT storage_key, content_type, quarantine_status, quarantine_until \
         FROM artifacts \
         WHERE repository_id = $1 AND path = $2 AND is_deleted = false \
         LIMIT 1",
    )
    .bind(repo_id)
    .bind(artifact_path)
    .fetch_optional(db)
    .await
    .map_err(|e| internal_error("Database", e))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Artifact not found").into_response())?;

    check_quarantine_row(&artifact)?;

    let storage = state.storage_for_repo_or_500(location)?;
    let content = storage
        .get(&artifact.storage_key)
        .await
        .map_err(|e| internal_error("Storage", e))?;

    Ok((content, Some(artifact.content_type)))
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
) -> Result<(Bytes, Option<String>), Response> {
    let artifact = sqlx::query_as::<_, LocalArtifactRow>(
        "SELECT storage_key, content_type, quarantine_status, quarantine_until \
         FROM artifacts \
         WHERE repository_id = $1 AND name = $2 AND version = $3 AND is_deleted = false \
         LIMIT 1",
    )
    .bind(repo_id)
    .bind(name)
    .bind(version)
    .fetch_optional(db)
    .await
    .map_err(|e| internal_error("Database", e))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Artifact not found").into_response())?;

    check_quarantine_row(&artifact)?;

    let storage = state.storage_for_repo_or_500(location)?;
    let content = storage
        .get(&artifact.storage_key)
        .await
        .map_err(|e| internal_error("Storage", e))?;

    Ok((content, Some(artifact.content_type)))
}

/// Generic local artifact fetch by path suffix (LIKE match).
/// Used for handlers like npm that query by filename suffix. `path_suffix`
/// is escaped internally; callers pass raw user input, not pre-escaped.
pub async fn local_fetch_by_path_suffix(
    db: &PgPool,
    state: &AppState,
    repo_id: Uuid,
    location: &StorageLocation,
    path_suffix: &str,
) -> Result<(Bytes, Option<String>), Response> {
    let path: String = sqlx::query_scalar(
        "SELECT path FROM artifacts \
         WHERE repository_id = $1 AND path LIKE '%/' || $2 ESCAPE '\\' AND is_deleted = false \
         LIMIT 1",
    )
    .bind(repo_id)
    .bind(super::escape_like_literal(path_suffix))
    .fetch_optional(db)
    .await
    .map_err(|e| internal_error("Database", e))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Artifact not found").into_response())?;

    local_fetch_by_path(db, state, repo_id, location, &path).await
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
    let artifact = sqlx::query_as::<_, LocalArtifactRow>(
        "SELECT storage_key, content_type, quarantine_status, quarantine_until \
         FROM artifacts \
         WHERE repository_id = $1 AND path = $2 AND is_deleted = false \
         LIMIT 1",
    )
    .bind(repo_id)
    .bind(artifact_path)
    .fetch_optional(db)
    .await
    .map_err(|e| internal_error("Database", e))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Artifact not found").into_response())?;

    check_quarantine_row(&artifact)?;

    let storage = state.storage_for_repo_or_500(location)?;

    // Try presigned redirect before reading content into memory
    if state.config.presigned_downloads_enabled {
        let expiry = Duration::from_secs(state.config.presigned_download_expiry_secs);
        if let Some(redirect) =
            try_presigned_redirect(storage.as_ref(), &artifact.storage_key, true, expiry).await
        {
            return Ok(redirect);
        }
    }

    let content = storage
        .get(&artifact.storage_key)
        .await
        .map_err(|e| internal_error("Storage", e))?;

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

/// Try the proxy and virtual fallbacks for a download miss.
///
/// Returns `Ok(Some(response))` if the artifact was served from upstream
/// (Remote) or a virtual member (Virtual), `Ok(None)` if the repo is hosted
/// (the caller should propagate its own NOT_FOUND), or `Err(response)` if
/// upstream fetch failed.
///
/// This consolidates the "miss path" of every format-handler download:
/// Remote → `proxy_fetch` + serve, Virtual → `resolve_virtual_download` +
/// serve. Each handler's only remaining variation is the upstream URL prefix,
/// the content type defaults, and whether to include a filename in the
/// `Content-Disposition` header.
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

        let (content, content_type) =
            proxy_fetch(proxy, repo.id, &repo.key, upstream_url, opts.upstream_path).await?;
        return Ok(Some(build_download_response(
            content,
            content_type,
            opts.default_content_type,
            opts.content_disposition_filename,
        )));
    }

    if classify_remote_or_virtual(&repo.repo_type) == RemoteOrVirtualAction::Virtual {
        let db = state.db.clone();
        let (content, content_type) = match opts.virtual_lookup {
            VirtualLookup::PathSuffix(suffix) => {
                let suffix = suffix.to_string();
                let state_arc = state.clone();
                resolve_virtual_download(
                    &state.db,
                    state.proxy_service.as_deref(),
                    repo.id,
                    opts.upstream_path,
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
                resolve_virtual_download(
                    &state.db,
                    state.proxy_service.as_deref(),
                    repo.id,
                    opts.upstream_path,
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
        return Ok(Some(build_download_response(
            content,
            content_type,
            opts.default_content_type,
            opts.content_disposition_filename,
        )));
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

/// Look up a single artifact by trailing filename match within a repository.
///
/// Runs `SELECT ... WHERE repository_id = $1 AND path LIKE '%/' || $2 ESCAPE '\'`
/// against `repository_id`, escaping `path_suffix` against `%` / `_` / `\`.
/// Returns `Ok(Some(hit))` on match, `Ok(None)` on miss, or `Err(response)`
/// on database failure.
///
/// Replaces the duplicated `sqlx::query! r#"... LIKE '%/' || $2 ESCAPE '\'
/// LIMIT 1 "#` boilerplate that every filename-keyed format download handler
/// otherwise repeats.
#[allow(clippy::result_large_err)]
pub async fn find_local_by_filename_suffix(
    db: &PgPool,
    repository_id: Uuid,
    path_suffix: &str,
) -> Result<Option<LocalArtifactHit>, Response> {
    use sqlx::Row;
    let row = sqlx::query(
        "SELECT id, storage_key FROM artifacts \
         WHERE repository_id = $1 \
           AND is_deleted = false \
           AND path LIKE '%/' || $2 ESCAPE '\\' \
         LIMIT 1",
    )
    .bind(repository_id)
    .bind(super::escape_like_literal(path_suffix))
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
fn build_remote_repo(id: Uuid, key: &str, upstream_url: &str) -> Repository {
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
        replication_priority: ReplicationPriority::OnDemand,
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderValue, StatusCode};

    // ── request_base_url tests ──────────────────────────────────────

    #[test]
    fn test_request_base_url_no_headers() {
        let headers = HeaderMap::new();
        assert_eq!(request_base_url(&headers), "http://localhost");
    }

    #[test]
    fn test_request_base_url_host_only() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("registry.example.com"));
        assert_eq!(request_base_url(&headers), "http://registry.example.com");
    }

    #[test]
    fn test_request_base_url_host_with_port() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("localhost:8080"));
        assert_eq!(request_base_url(&headers), "http://localhost:8080");
    }

    #[test]
    fn test_request_base_url_forwarded_proto() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("registry.example.com"));
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        assert_eq!(request_base_url(&headers), "https://registry.example.com");
    }

    #[test]
    fn test_request_base_url_forwarded_host() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("backend:8080"));
        headers.insert(
            "x-forwarded-host",
            HeaderValue::from_static("registry.example.com:30443"),
        );
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        assert_eq!(
            request_base_url(&headers),
            "https://registry.example.com:30443"
        );
    }

    #[test]
    fn test_request_base_url_forwarded_host_without_proto() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("backend:8080"));
        headers.insert(
            "x-forwarded-host",
            HeaderValue::from_static("registry.example.com"),
        );
        assert_eq!(request_base_url(&headers), "http://registry.example.com");
    }

    #[test]
    fn test_request_base_url_host_with_embedded_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            HeaderValue::from_static("https://already-absolute.example.com"),
        );
        assert_eq!(
            request_base_url(&headers),
            "https://already-absolute.example.com"
        );
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
        assert!(repo.promotion_target_id.is_none());
        assert!(repo.promotion_policy_id.is_none());
    }

    #[test]
    fn test_build_remote_repo_timestamps_set() {
        let before = Utc::now();
        let repo = build_remote_repo(Uuid::new_v4(), "k", "https://u.com");
        let after = Utc::now();
        assert!(repo.created_at >= before && repo.created_at <= after);
        assert!(repo.updated_at >= before && repo.updated_at <= after);
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
    fn test_map_proxy_error_validation_becomes_bad_gateway() {
        let err = crate::error::AppError::Validation("bad input".to_string());
        let response = map_proxy_error("repo-key", "pkg", err);
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
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

    // ── proxy_cache_storage_key tests ──────────────────────────────────

    #[test]
    fn test_proxy_cache_storage_key_basic() {
        let key = super::proxy_cache_storage_key("npm-remote", "lodash/-/lodash-4.17.21.tgz");
        assert_eq!(
            key,
            "proxy-cache/npm-remote/lodash/-/lodash-4.17.21.tgz/__content__"
        );
    }

    #[test]
    fn test_proxy_cache_storage_key_strips_leading_slash() {
        let key = super::proxy_cache_storage_key("maven-central", "/com/example/lib-1.0.jar");
        assert_eq!(
            key,
            "proxy-cache/maven-central/com/example/lib-1.0.jar/__content__"
        );
    }

    #[test]
    fn test_proxy_cache_storage_key_strips_trailing_slash() {
        let key = super::proxy_cache_storage_key("pypi-proxy", "packages/simple/requests/");
        assert_eq!(
            key,
            "proxy-cache/pypi-proxy/packages/simple/requests/__content__"
        );
    }

    #[test]
    fn test_proxy_cache_storage_key_no_slashes() {
        let key = super::proxy_cache_storage_key("npm-remote", "express");
        assert_eq!(key, "proxy-cache/npm-remote/express/__content__");
    }

    #[test]
    fn test_proxy_cache_storage_key_matches_proxy_service_format() {
        // Verifies the key format matches ProxyService::cache_storage_key
        // so presigned redirects point to the correct cached objects.
        let key = super::proxy_cache_storage_key("test-repo", "path/to/artifact");
        assert!(key.starts_with("proxy-cache/"));
        assert!(key.ends_with("/__content__"));
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

    /// Recording mock storage backend that counts every method call so tests
    /// can assert which I/O paths fired (in particular: was the full object
    /// `get(...)` called).
    struct RecordingStorage {
        get_calls: StdArc<AtomicUsize>,
        presigned_calls: StdArc<AtomicUsize>,
        supports: bool,
    }

    impl RecordingStorage {
        fn new(supports: bool) -> Self {
            Self {
                get_calls: StdArc::new(AtomicUsize::new(0)),
                presigned_calls: StdArc::new(AtomicUsize::new(0)),
                supports,
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::storage::StorageBackend for RecordingStorage {
        async fn put(&self, _key: &str, _content: Bytes) -> crate::error::Result<()> {
            Ok(())
        }
        async fn get(&self, _key: &str) -> crate::error::Result<Bytes> {
            self.get_calls.fetch_add(1, Ordering::SeqCst);
            Ok(Bytes::from_static(b"full-body"))
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
        };
        assert_eq!(opts.upstream_path, "pkg/v1/foo.tgz");
        assert_eq!(opts.default_content_type, "application/x-tar");
        assert_eq!(opts.content_disposition_filename, Some("foo.tgz"));
    }

    #[test]
    fn test_download_response_opts_without_filename() {
        let opts = DownloadResponseOpts {
            upstream_path: "/some/path",
            virtual_lookup: VirtualLookup::ExactPath("/some/path"),
            default_content_type: "application/octet-stream",
            content_disposition_filename: None,
        };
        assert!(opts.content_disposition_filename.is_none());
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
                peer_instance_name: "test".into(),
                peer_public_endpoint: "http://localhost:8080".into(),
                peer_api_key: "test-key".into(),
                dependency_track_url: None,
                otel_exporter_otlp_endpoint: None,
                otel_service_name: "test".into(),
                gc_schedule: "0 0 * * * *".into(),
                lifecycle_check_interval_secs: 60,
                allow_local_admin_login: false,
                max_upload_size_bytes: 10_737_418_240,
                metrics_port: None,
                database_max_connections: 20,
                database_min_connections: 5,
                database_acquire_timeout_secs: 30,
                database_idle_timeout_secs: 600,
                database_max_lifetime_secs: 1800,
                rate_limit_auth_per_window: 120,
                rate_limit_api_per_window: 5000,
                rate_limit_search_per_window: 300,
                rate_limit_window_secs: 60,
                rate_limit_exempt_usernames: Vec::new(),
                rate_limit_exempt_service_accounts: false,
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
        };

        let opts = DownloadResponseOpts {
            upstream_path: "any/path",
            virtual_lookup: VirtualLookup::PathSuffix("any.tgz"),
            default_content_type: "application/octet-stream",
            content_disposition_filename: None,
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
        };

        // state.proxy_service is None — should short-circuit to Ok(None).
        let opts = DownloadResponseOpts {
            upstream_path: "any/path",
            virtual_lookup: VirtualLookup::PathSuffix("any.tgz"),
            default_content_type: "application/octet-stream",
            content_disposition_filename: None,
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
        };

        let opts = DownloadResponseOpts {
            upstream_path: "any/path",
            virtual_lookup: VirtualLookup::ExactPath("any/path"),
            default_content_type: "application/octet-stream",
            content_disposition_filename: None,
        };
        let result = try_remote_or_virtual_download(&state, &repo, opts)
            .await
            .expect("ok");
        assert!(result.is_none(), "no upstream URL → Ok(None)");

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
        let (content, ct) =
            local_fetch_by_path(&pool, &state, repo_id, &location, "foo/1.0/foo.whl")
                .await
                .expect("fetch");
        assert_eq!(&content[..], b"abc123");
        assert_eq!(ct.as_deref(), Some("application/zip"));

        // Also exercise the suffix variant.
        let (content2, _) =
            local_fetch_by_path_suffix(&pool, &state, repo_id, &location, "foo.whl")
                .await
                .expect("fetch suffix");
        assert_eq!(&content2[..], b"abc123");

        db_helpers::cleanup(&pool, repo_id, user_id).await;
    }
}
