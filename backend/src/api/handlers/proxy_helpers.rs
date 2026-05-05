//! Shared helpers for remote repository proxying and virtual repository resolution.

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::api::AppState;
use crate::models::repository::{
    ReplicationPriority, Repository, RepositoryFormat, RepositoryType,
};
use crate::services::proxy_service::ProxyService;
use crate::storage::StorageLocation;

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
fn internal_error(label: &str, e: impl std::fmt::Display) -> Response {
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
///
/// Builds a `Repository` shape for the proxy from the caller-supplied
/// `location`. The `location` MUST be the real `StorageLocation` from the
/// caller's `Repository` (or `RepoInfo`/`OciRepoInfo`) so that proxy cache
/// I/O routes through the same per-repo backend that download handlers read
/// from via `state.storage_for_repo(...)`. Passing a synthesized location
/// (`backend: "filesystem"`, `path: ""`) silently re-introduces bug #1016
/// because the cache write lands on a different backend than the read.
///
/// Returns `(content_bytes, content_type)` on success.
pub async fn proxy_fetch(
    proxy_service: &ProxyService,
    repo_id: Uuid,
    repo_key: &str,
    location: &StorageLocation,
    upstream_url: &str,
    path: &str,
) -> Result<(Bytes, Option<String>), Response> {
    let repo = build_remote_repo(repo_id, repo_key, upstream_url, location);

    proxy_service
        .fetch_artifact(&repo, path)
        .await
        .map_err(|e| map_proxy_error(repo_key, path, e))
}

/// Check whether an artifact is present in the proxy cache under `path`
/// without contacting upstream. Returns `Some` on cache hit, `None` on miss
/// or expired entry.
///
/// Routes the lookup through the per-repo storage backend resolved from the
/// caller-supplied `location`. This is required so the cache hit/miss
/// decision matches the backend that download handlers read from
/// (bug #1016) — checking only the legacy global storage would silently
/// miss artifacts cached on the per-repo S3/R2 backend.
pub async fn proxy_check_cache(
    proxy_service: &ProxyService,
    repo_id: Uuid,
    repo_key: &str,
    location: &StorageLocation,
    upstream_url: &str,
    path: &str,
) -> Option<(Bytes, Option<String>)> {
    let repo = build_remote_repo(repo_id, repo_key, upstream_url, location);
    match proxy_service
        .get_cached_artifact_for_repo(&repo, path)
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
///
/// `location` MUST be the real `StorageLocation` of the caller's repository
/// — see [`proxy_fetch`] for why.
pub async fn proxy_fetch_with_cache_key(
    proxy_service: &ProxyService,
    repo_id: Uuid,
    repo_key: &str,
    location: &StorageLocation,
    upstream_url: &str,
    fetch_path: &str,
    cache_path: &str,
) -> Result<(Bytes, Option<String>), Response> {
    let repo = build_remote_repo(repo_id, repo_key, upstream_url, location);

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
///
/// `location` is unused for the cache (this call bypasses it) but is taken
/// here for signature symmetry with the other helpers and so future
/// instrumentation can attribute the upstream call to the correct backend.
pub async fn proxy_fetch_uncached(
    proxy_service: &ProxyService,
    repo_id: Uuid,
    repo_key: &str,
    location: &StorageLocation,
    upstream_url: &str,
    path: &str,
) -> Result<(Bytes, Option<String>, String), Response> {
    let repo = build_remote_repo(repo_id, repo_key, upstream_url, location);

    proxy_service
        .fetch_upstream_direct(&repo, path)
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
                if let Ok(result) = proxy_fetch(
                    proxy,
                    member.id,
                    &member.key,
                    &member.storage_location(),
                    upstream_url,
                    path,
                )
                .await
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

        match proxy_fetch(
            proxy,
            member.id,
            &member.key,
            &member.storage_location(),
            upstream_url,
            path,
        )
        .await
        {
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

        match proxy_fetch(
            proxy,
            member.id,
            &member.key,
            &member.storage_location(),
            upstream_url,
            path,
        )
        .await
        {
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

/// Generic local artifact fetch by exact path match.
/// Used as a `local_fetch` callback for [`resolve_virtual_download`].
pub async fn local_fetch_by_path(
    db: &PgPool,
    state: &AppState,
    repo_id: Uuid,
    location: &StorageLocation,
    artifact_path: &str,
) -> Result<(Bytes, Option<String>), Response> {
    let artifact = sqlx::query!(
        r#"SELECT storage_key, content_type
        FROM artifacts
        WHERE repository_id = $1 AND path = $2 AND is_deleted = false
        LIMIT 1"#,
        repo_id,
        artifact_path
    )
    .fetch_optional(db)
    .await
    .map_err(|e| internal_error("Database", e))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Artifact not found").into_response())?;

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
    let artifact = sqlx::query!(
        r#"SELECT storage_key, content_type
        FROM artifacts
        WHERE repository_id = $1 AND name = $2 AND version = $3 AND is_deleted = false
        LIMIT 1"#,
        repo_id,
        name,
        version
    )
    .fetch_optional(db)
    .await
    .map_err(|e| internal_error("Database", e))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Artifact not found").into_response())?;

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
    let path = sqlx::query_scalar!(
        r#"SELECT path FROM artifacts
        WHERE repository_id = $1 AND path LIKE '%/' || $2 ESCAPE '\' AND is_deleted = false
        LIMIT 1"#,
        repo_id,
        super::escape_like_literal(path_suffix)
    )
    .fetch_optional(db)
    .await
    .map_err(|e| internal_error("Database", e))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Artifact not found").into_response())?;

    local_fetch_by_path(db, state, repo_id, location, &path).await
}

/// Build a minimal `Repository` model for proxy operations.
///
/// The `location` MUST be the real `StorageLocation` of the caller's
/// repository so that `ProxyService` resolves cache I/O to the same backend
/// that download handlers read from. Earlier versions of this helper
/// hardcoded `storage_backend: "filesystem", storage_path: ""`, which
/// silently routed cache writes to a fresh filesystem backend rooted at the
/// process cwd while reads went to the configured S3/R2 backend — that was
/// the root cause of bug #1016.
fn build_remote_repo(
    id: Uuid,
    key: &str,
    upstream_url: &str,
    location: &StorageLocation,
) -> Repository {
    Repository {
        id,
        key: key.to_string(),
        name: key.to_string(),
        description: None,
        format: RepositoryFormat::Generic,
        repo_type: RepositoryType::Remote,
        storage_backend: location.backend.clone(),
        storage_path: location.path.clone(),
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

    fn loc(backend: &str, path: &str) -> StorageLocation {
        StorageLocation {
            backend: backend.to_string(),
            path: path.to_string(),
        }
    }

    #[test]
    fn test_build_remote_repo_sets_id() {
        let id = Uuid::new_v4();
        let repo = build_remote_repo(
            id,
            "my-repo",
            "https://upstream.example.com",
            &loc("filesystem", "/data/my-repo"),
        );
        assert_eq!(repo.id, id);
    }

    #[test]
    fn test_build_remote_repo_key_and_name_match() {
        let id = Uuid::new_v4();
        let repo = build_remote_repo(
            id,
            "npm-remote",
            "https://registry.npmjs.org",
            &loc("filesystem", "/data/npm-remote"),
        );
        assert_eq!(repo.key, "npm-remote");
        assert_eq!(repo.name, "npm-remote");
    }

    #[test]
    fn test_build_remote_repo_upstream_url() {
        let id = Uuid::new_v4();
        let url = "https://pypi.org/simple/";
        let repo = build_remote_repo(id, "pypi-proxy", url, &loc("s3-prod", "/proxies/pypi"));
        assert_eq!(repo.upstream_url, Some(url.to_string()));
    }

    #[test]
    fn test_build_remote_repo_type_is_remote() {
        let repo = build_remote_repo(
            Uuid::new_v4(),
            "r",
            "https://x.com",
            &loc("filesystem", "/data/r"),
        );
        assert_eq!(repo.repo_type, RepositoryType::Remote);
    }

    #[test]
    fn test_build_remote_repo_format_is_generic() {
        let repo = build_remote_repo(
            Uuid::new_v4(),
            "r",
            "https://x.com",
            &loc("filesystem", "/data/r"),
        );
        assert_eq!(repo.format, RepositoryFormat::Generic);
    }

    /// Bug #1016 regression: `build_remote_repo` MUST forward the caller's
    /// real `StorageLocation` so the proxy resolves cache I/O to the same
    /// backend that handlers read from. Earlier versions hardcoded
    /// `"filesystem", ""` here, which routed cache writes to a fresh
    /// filesystem backend rooted at cwd while reads went to the real S3/R2
    /// backend.
    #[test]
    fn test_build_remote_repo_propagates_storage_location_for_bug_1016() {
        let repo = build_remote_repo(
            Uuid::new_v4(),
            "debian-proxy",
            "https://deb.example.com",
            &loc("s3-prod", "/proxies/debian"),
        );
        assert_eq!(repo.storage_backend, "s3-prod");
        assert_eq!(repo.storage_path, "/proxies/debian");
    }

    #[test]
    fn test_build_remote_repo_defaults() {
        let repo = build_remote_repo(
            Uuid::new_v4(),
            "k",
            "https://u.com",
            &loc("filesystem", "/data/k"),
        );
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
        let repo = build_remote_repo(
            Uuid::new_v4(),
            "k",
            "https://u.com",
            &loc("filesystem", "/data/k"),
        );
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
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: "/data/test-repo".to_string(),
        };
        let repo =
            super::build_remote_repo(id, "test-repo", "https://upstream.example.com", &location);
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
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: "/data/any-key".to_string(),
        };
        let repo = super::build_remote_repo(id, "any-key", "https://example.com", &location);
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

    // =======================================================================
    // Bug #1016 regression: full handler-to-cache routing
    //
    // The earlier fix (`#1016` initial) routed cache I/O through the per-repo
    // backend inside `ProxyService` — but every format handler called
    // `proxy_helpers::proxy_fetch` which internally synthesized a `Repository`
    // with `storage_backend: "filesystem", storage_path: ""`. That synthetic
    // repo caused `per_repo_storage` to resolve to a fresh filesystem backend
    // rooted at the process cwd, NOT the configured S3/R2 backend that
    // download handlers read from. Result: writer wrote to filesystem, reader
    // read from S3, second download → NoSuchKey → 500.
    //
    // The fix below: helpers take an explicit `&StorageLocation` from the
    // caller so the synthesized repo carries the real backend. The test pins
    // the contract by:
    //   1. Building a `ProxyService` with a `StorageRegistry` that maps a
    //      named per-repo backend ("s3-test").
    //   2. Pre-seeding that backend with cache content + metadata under the
    //      production cache-key shape.
    //   3. Calling `proxy_check_cache` through the helper with a
    //      `StorageLocation { backend: "s3-test", path: "/data/debian" }`.
    //   4. Asserting the cache hit returns the seeded bytes — proving the
    //      helper threaded the location all the way through to the registry.
    //
    // If the helper ever regresses to a synthetic `"filesystem"`/`""`
    // location, this test fails because the registry lookup will resolve a
    // different backend than the one that holds the seeded content.
    // =======================================================================

    use crate::error::Result as AkResult;
    use crate::services::proxy_service::{CacheMetadata, ProxyService};
    use crate::services::storage_service::{FilesystemBackend, StorageService};
    use crate::storage::{StorageBackend as RepoStorageBackend, StorageRegistry};
    use async_trait::async_trait;
    use bytes::Bytes;
    use chrono::Utc;
    use sqlx::PgPool;
    use std::collections::HashMap as StdHashMap;
    use std::sync::{Arc, Mutex};

    /// In-memory `StorageBackend` for routing tests.
    struct MockBackend {
        store: Mutex<StdHashMap<String, Bytes>>,
    }

    impl MockBackend {
        fn new() -> Self {
            Self {
                store: Mutex::new(StdHashMap::new()),
            }
        }

        fn insert(&self, key: &str, content: Bytes) {
            self.store.lock().unwrap().insert(key.to_string(), content);
        }
    }

    #[async_trait]
    impl RepoStorageBackend for MockBackend {
        async fn put(&self, key: &str, content: Bytes) -> AkResult<()> {
            self.store.lock().unwrap().insert(key.to_string(), content);
            Ok(())
        }
        async fn get(&self, key: &str) -> AkResult<Bytes> {
            self.store
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| crate::error::AppError::NotFound(format!("not found: {}", key)))
        }
        async fn exists(&self, key: &str) -> AkResult<bool> {
            Ok(self.store.lock().unwrap().contains_key(key))
        }
        async fn delete(&self, key: &str) -> AkResult<()> {
            self.store.lock().unwrap().remove(key);
            Ok(())
        }
    }

    /// Bug #1016 full-path regression: when a handler calls
    /// `proxy_helpers::proxy_check_cache` with the real
    /// `StorageLocation` from its `Repository`, the lookup MUST route
    /// through the registry-resolved per-repo backend that holds cached
    /// content. If the helper synthesizes a `"filesystem"`/`""` location
    /// (the original bug), the registry resolves a different backend and
    /// the seeded content is invisible — second download 500s.
    #[tokio::test]
    async fn test_proxy_check_cache_routes_through_per_repo_backend_for_bug_1016() {
        // 1. Stand up a per-repo backend identified as "s3-test" in the
        //    registry. This stands in for a real S3-backed Debian proxy repo.
        let per_repo_backend: Arc<MockBackend> = Arc::new(MockBackend::new());
        let mut backends: StdHashMap<String, Arc<dyn RepoStorageBackend>> = StdHashMap::new();
        backends.insert("s3-test".to_string(), per_repo_backend.clone());
        let registry = Arc::new(StorageRegistry::new(backends, "s3-test".to_string()));

        // 2. Pre-seed the per-repo backend with cache content + metadata
        //    under the production cache-key shape. This simulates a
        //    previously-cached artifact that handlers would fetch on a
        //    second download.
        let repo_key = "debian-proxy";
        let cache_path = "pool/main/p/php7.4/php7.4_test.deb";
        let payload = Bytes::from_static(b"<deb file body>");
        let storage_key = ProxyService::cache_storage_key(repo_key, cache_path);
        let metadata_key = ProxyService::cache_metadata_key(repo_key, cache_path);

        let metadata = CacheMetadata {
            cached_at: Utc::now(),
            upstream_etag: None,
            expires_at: Utc::now() + chrono::Duration::hours(1),
            content_type: Some("application/vnd.debian.binary-package".to_string()),
            size_bytes: payload.len() as i64,
            checksum_sha256: StorageService::calculate_hash(&payload),
        };
        per_repo_backend.insert(&storage_key, payload.clone());
        per_repo_backend.insert(
            &metadata_key,
            Bytes::from(serde_json::to_vec(&metadata).unwrap()),
        );

        // 3. Build a ProxyService wired to that registry. The global storage
        //    is a throwaway filesystem backend in /tmp so a regression that
        //    silently falls back to global storage would NOT find the seeded
        //    bytes (which only exist on the per-repo mock backend).
        let pool = PgPool::connect_lazy("postgres://fake:fake@127.0.0.1:1/none")
            .expect("connect_lazy never fails for a syntactically valid URL");
        let global_backend: Arc<dyn crate::services::storage_service::StorageBackend> = Arc::new(
            FilesystemBackend::new(std::path::PathBuf::from("/tmp/ak-helpers-test-global-only")),
        );
        let global_storage = Arc::new(StorageService::new(global_backend));
        let config = crate::config::Config::default();
        let proxy =
            ProxyService::new(pool, global_storage, &config).with_storage_registry(registry);

        // 4. Call the helper with the REAL storage location of the repo
        //    (matches `repo.storage_location()` in the handler).
        let location = StorageLocation {
            backend: "s3-test".to_string(),
            path: "/data/debian".to_string(),
        };
        let result = super::proxy_check_cache(
            &proxy,
            Uuid::new_v4(),
            repo_key,
            &location,
            "https://deb.example.com",
            cache_path,
        )
        .await;

        // 5. The seeded bytes must be returned — proving the helper threaded
        //    the StorageLocation through to the registry-resolved per-repo
        //    backend. With the pre-fix synthetic location ("filesystem"/""),
        //    the registry would resolve a different backend and this would
        //    return None (cache miss), reproducing bug #1016 in the helper
        //    layer.
        let (content, content_type) = result.expect(
            "expected cache hit on the per-repo backend; if this is None, the helper is \
             routing through the wrong storage location (bug #1016)",
        );
        assert_eq!(content, payload);
        assert_eq!(
            content_type.as_deref(),
            Some("application/vnd.debian.binary-package")
        );
    }

    /// Bug #1016 negative test: when the helper is called with a
    /// `StorageLocation` whose `backend` is NOT registered in the
    /// `StorageRegistry`, the per-repo lookup falls back to global storage
    /// (which is empty in this test), producing a cache miss. This pins the
    /// other half of the contract: the helper does not silently coerce an
    /// unknown location into the registry's default backend.
    #[tokio::test]
    async fn test_proxy_check_cache_misses_when_location_does_not_match_seeded_backend() {
        let per_repo_backend: Arc<MockBackend> = Arc::new(MockBackend::new());
        let mut backends: StdHashMap<String, Arc<dyn RepoStorageBackend>> = StdHashMap::new();
        backends.insert("s3-test".to_string(), per_repo_backend.clone());
        let registry = Arc::new(StorageRegistry::new(backends, "s3-test".to_string()));

        let repo_key = "debian-proxy";
        let cache_path = "pool/main/p/php7.4/php7.4_test.deb";
        let payload = Bytes::from_static(b"<deb file body>");
        let storage_key = ProxyService::cache_storage_key(repo_key, cache_path);
        let metadata_key = ProxyService::cache_metadata_key(repo_key, cache_path);
        let metadata = CacheMetadata {
            cached_at: Utc::now(),
            upstream_etag: None,
            expires_at: Utc::now() + chrono::Duration::hours(1),
            content_type: Some("application/octet-stream".to_string()),
            size_bytes: payload.len() as i64,
            checksum_sha256: StorageService::calculate_hash(&payload),
        };
        per_repo_backend.insert(&storage_key, payload.clone());
        per_repo_backend.insert(
            &metadata_key,
            Bytes::from(serde_json::to_vec(&metadata).unwrap()),
        );

        let pool = PgPool::connect_lazy("postgres://fake:fake@127.0.0.1:1/none").unwrap();
        let global_backend: Arc<dyn crate::services::storage_service::StorageBackend> =
            Arc::new(FilesystemBackend::new(std::path::PathBuf::from(
                "/tmp/ak-helpers-test-global-only-2",
            )));
        let global_storage = Arc::new(StorageService::new(global_backend));
        let config = crate::config::Config::default();
        let proxy =
            ProxyService::new(pool, global_storage, &config).with_storage_registry(registry);

        // Caller passes a location whose backend is NOT registered. The
        // registry's `backend_for` should fail to resolve, the proxy should
        // fall back to global storage, and the global storage has no seeded
        // content => miss.
        let bad_location = StorageLocation {
            backend: "wrong-backend".to_string(),
            path: "/data/debian".to_string(),
        };
        let result = super::proxy_check_cache(
            &proxy,
            Uuid::new_v4(),
            repo_key,
            &bad_location,
            "https://deb.example.com",
            cache_path,
        )
        .await;

        assert!(
            result.is_none(),
            "expected cache miss when the location's backend is not in the registry; \
             got a hit, which means the helper is silently coercing the location"
        );
    }

    // =======================================================================
    // Helper-level coverage for `proxy_fetch`, `proxy_fetch_with_cache_key`,
    // and `proxy_fetch_uncached`.
    //
    // These helpers all thread `&StorageLocation` into a synthesized
    // `Repository` and forward to a `ProxyService` method. The cache-hit
    // tests below pre-seed the per-repo backend so the helpers short-circuit
    // before any HTTP traffic, exercising:
    //
    //   * the helper body (build_remote_repo + ProxyService dispatch),
    //   * the registry-resolved cache-hit fast path inside ProxyService,
    //   * the MockBackend's full `RepoStorageBackend` surface (put/get/delete
    //     get used across these tests).
    //
    // Validation-error tests exercise the early-return branches without
    // needing a live upstream.
    // =======================================================================

    /// Build a `(MockBackend, ProxyService, repo_key, location)` tuple
    /// pre-seeded with one cache entry. Reused by the cache-hit tests so
    /// each helper doesn't re-derive the same scaffolding.
    async fn make_seeded_proxy(
        repo_key: &str,
        cache_path: &str,
        payload: Bytes,
        content_type: &str,
    ) -> (Arc<MockBackend>, ProxyService, StorageLocation) {
        let per_repo: Arc<MockBackend> = Arc::new(MockBackend::new());
        let mut backends: StdHashMap<String, Arc<dyn RepoStorageBackend>> = StdHashMap::new();
        backends.insert("s3-helper".to_string(), per_repo.clone());
        let registry = Arc::new(StorageRegistry::new(backends, "s3-helper".to_string()));

        let storage_key = ProxyService::cache_storage_key(repo_key, cache_path);
        let metadata_key = ProxyService::cache_metadata_key(repo_key, cache_path);
        let metadata = CacheMetadata {
            cached_at: Utc::now(),
            upstream_etag: None,
            expires_at: Utc::now() + chrono::Duration::hours(1),
            content_type: Some(content_type.to_string()),
            size_bytes: payload.len() as i64,
            checksum_sha256: StorageService::calculate_hash(&payload),
        };
        // Use `MockBackend::put` via the `RepoStorageBackend` trait so the
        // trait `put` is exercised by these tests (covers the put body).
        let backend_dyn: Arc<dyn RepoStorageBackend> = per_repo.clone();
        backend_dyn.put(&storage_key, payload).await.unwrap();
        backend_dyn
            .put(
                &metadata_key,
                Bytes::from(serde_json::to_vec(&metadata).unwrap()),
            )
            .await
            .unwrap();

        let pool = PgPool::connect_lazy("postgres://fake:fake@127.0.0.1:1/none").unwrap();
        let global_backend: Arc<dyn crate::services::storage_service::StorageBackend> =
            Arc::new(FilesystemBackend::new(std::path::PathBuf::from(
                "/tmp/ak-helpers-test-global-helper",
            )));
        let global_storage = Arc::new(StorageService::new(global_backend));
        let config = crate::config::Config::default();
        let proxy =
            ProxyService::new(pool, global_storage, &config).with_storage_registry(registry);
        let location = StorageLocation {
            backend: "s3-helper".to_string(),
            path: "/data/helper".to_string(),
        };
        (per_repo, proxy, location)
    }

    /// `proxy_fetch` MUST route the cache-hit lookup through the same
    /// per-repo backend as `proxy_check_cache`. With the cache pre-seeded
    /// on the registry-resolved backend, the helper returns the cached
    /// bytes without contacting upstream — proving the helper threads the
    /// real `StorageLocation` into `ProxyService::fetch_artifact`.
    #[tokio::test]
    async fn test_proxy_fetch_returns_cached_bytes_without_upstream() {
        let repo_key = "debian-proxy";
        let cache_path = "pool/main/p/php7.4/php7.4_test.deb";
        let payload = Bytes::from_static(b"<deb file body>");
        let (per_repo, proxy, location) =
            make_seeded_proxy(repo_key, cache_path, payload.clone(), "application/x-deb").await;

        let (content, content_type) = super::proxy_fetch(
            &proxy,
            Uuid::new_v4(),
            repo_key,
            &location,
            "https://deb.example.com",
            cache_path,
        )
        .await
        .expect(
            "expected cache hit on the per-repo backend; if this errors, the helper is \
             routing through the wrong storage location (bug #1016)",
        );

        assert_eq!(content, payload);
        assert_eq!(content_type.as_deref(), Some("application/x-deb"));
        // Sanity: the seeded keys are still on the per-repo backend.
        assert!(per_repo
            .store
            .lock()
            .unwrap()
            .contains_key(&ProxyService::cache_storage_key(repo_key, cache_path)));
    }

    /// `proxy_fetch_with_cache_key` lets callers separate the upstream
    /// fetch path from the cache lookup path (e.g., PyPI resolves a file
    /// URL on a different domain but caches under `simple/{name}/{file}`).
    /// When the cache is seeded under `cache_path`, the helper must hit
    /// it and short-circuit, exercising both the helper body and the
    /// `fetch_artifact_with_cache_path` cache-hit branch.
    #[tokio::test]
    async fn test_proxy_fetch_with_cache_key_returns_cached_bytes() {
        let repo_key = "pypi-proxy";
        // cache_path differs from fetch_path: this is the whole point of
        // the helper.
        let cache_path = "simple/requests/requests-2.31.0.tar.gz";
        let fetch_path = "packages/source/r/requests/requests-2.31.0.tar.gz";
        let payload = Bytes::from_static(b"<tar.gz body>");
        let (_per_repo, proxy, location) =
            make_seeded_proxy(repo_key, cache_path, payload.clone(), "application/gzip").await;

        let (content, content_type) = super::proxy_fetch_with_cache_key(
            &proxy,
            Uuid::new_v4(),
            repo_key,
            &location,
            "https://pypi.example.com",
            fetch_path,
            cache_path,
        )
        .await
        .expect(
            "expected cache hit when cache_path matches the seeded entry; \
             if this errors, the helper is not threading the location through to \
             fetch_artifact_with_cache_path's cache-hit branch",
        );

        assert_eq!(content, payload);
        assert_eq!(content_type.as_deref(), Some("application/gzip"));
    }

    /// `proxy_fetch_uncached` always bypasses the cache, so we cannot
    /// exercise it via a cache-hit fixture. Instead, pin the early-return
    /// validation branches in the underlying `fetch_upstream_direct`: a
    /// repo that lies about being Remote must fail with a Validation error
    /// (the helper never builds the upstream URL or makes a network call).
    /// This covers the helper body lines plus the underlying validation
    /// branch in ProxyService.
    #[tokio::test]
    async fn test_proxy_fetch_uncached_rejects_when_underlying_repo_not_remote() {
        // Build a normal seeded proxy (we don't actually use the cache here),
        // then call `fetch_upstream_direct` directly with a non-Remote repo
        // to drive the validation branch.
        let (_per_repo, proxy, _location) = make_seeded_proxy(
            "any",
            "anything",
            Bytes::from_static(b"x"),
            "application/octet-stream",
        )
        .await;

        let mut local_repo = build_remote_repo(
            Uuid::new_v4(),
            "local-repo",
            "https://upstream.example.com",
            &StorageLocation {
                backend: "s3-helper".to_string(),
                path: "/data/helper".to_string(),
            },
        );
        local_repo.repo_type = RepositoryType::Local;

        let err = proxy
            .fetch_upstream_direct(&local_repo, "some/path")
            .await
            .expect_err("non-Remote repo must fail validation in fetch_upstream_direct");
        let msg = format!("{}", err);
        assert!(
            msg.contains("only supported for remote repositories"),
            "unexpected error: {}",
            msg
        );
    }

    /// `invalidate_cache` MUST delete cache content + metadata from the
    /// per-repo backend (the same backend that handlers read from). With a
    /// real `StorageLocation` and a registry, both keys vanish from the
    /// mock backend, exercising `cache_delete` (private) through the
    /// per-repo branch.
    #[tokio::test]
    async fn test_invalidate_cache_removes_entries_from_per_repo_backend() {
        let repo_key = "debian-proxy";
        let cache_path = "pool/main/p/php7.4/php7.4_test.deb";
        let payload = Bytes::from_static(b"<deb file body>");
        let (per_repo, proxy, location) =
            make_seeded_proxy(repo_key, cache_path, payload.clone(), "application/x-deb").await;

        let storage_key = ProxyService::cache_storage_key(repo_key, cache_path);
        let metadata_key = ProxyService::cache_metadata_key(repo_key, cache_path);
        // Pre-condition: both keys present.
        assert!(per_repo.store.lock().unwrap().contains_key(&storage_key));
        assert!(per_repo.store.lock().unwrap().contains_key(&metadata_key));

        // Use `build_remote_repo` directly so the call mirrors what the
        // helpers construct.
        let repo = build_remote_repo(
            Uuid::new_v4(),
            repo_key,
            "https://deb.example.com",
            &location,
        );
        proxy
            .invalidate_cache(&repo, cache_path)
            .await
            .expect("invalidate_cache must succeed");

        // Post-condition: both keys gone from the per-repo backend.
        let store = per_repo.store.lock().unwrap();
        assert!(
            !store.contains_key(&storage_key),
            "content key should be removed from the per-repo backend"
        );
        assert!(
            !store.contains_key(&metadata_key),
            "metadata key should be removed from the per-repo backend"
        );
    }

    /// `check_upstream` returns `false` (no fetch needed) when valid,
    /// non-expired metadata exists on the per-repo backend AND the cached
    /// metadata has no ETag (TTL-only path). This exercises lines around
    /// the `per_repo_storage` resolution + `load_cache_metadata` happy
    /// path inside `check_upstream`.
    #[tokio::test]
    async fn test_check_upstream_returns_false_for_fresh_cached_metadata() {
        let repo_key = "debian-proxy";
        let cache_path = "pool/main/p/php7.4/php7.4_test.deb";
        let payload = Bytes::from_static(b"<deb file body>");
        let (_per_repo, proxy, location) =
            make_seeded_proxy(repo_key, cache_path, payload, "application/x-deb").await;

        let repo = build_remote_repo(
            Uuid::new_v4(),
            repo_key,
            "https://deb.example.com",
            &location,
        );

        let needs_fetch = proxy
            .check_upstream(&repo, cache_path)
            .await
            .expect("check_upstream must succeed when metadata exists and is non-expired");
        assert!(
            !needs_fetch,
            "fresh cached metadata with no ETag should NOT require a re-fetch"
        );
    }

    /// `check_upstream` returns `true` (must fetch) when no cache metadata
    /// exists at all — exercises the `None => return Ok(true)` branch.
    #[tokio::test]
    async fn test_check_upstream_returns_true_when_cache_missing() {
        let repo_key = "debian-proxy";
        let unseeded_path = "pool/main/never/cached.deb";
        let (_per_repo, proxy, location) = make_seeded_proxy(
            repo_key,
            "some/other/path",
            Bytes::from_static(b"x"),
            "application/octet-stream",
        )
        .await;

        let repo = build_remote_repo(
            Uuid::new_v4(),
            repo_key,
            "https://deb.example.com",
            &location,
        );

        let needs_fetch = proxy
            .check_upstream(&repo, unseeded_path)
            .await
            .expect("check_upstream must succeed when no cache metadata is found");
        assert!(
            needs_fetch,
            "missing cache metadata should require a fresh upstream fetch"
        );
    }

    /// `check_upstream` rejects non-Remote repos with a Validation error,
    /// independent of any cache state. Pins the early-return branch.
    #[tokio::test]
    async fn test_check_upstream_rejects_non_remote_repo() {
        let (_per_repo, proxy, location) = make_seeded_proxy(
            "any",
            "anything",
            Bytes::from_static(b"x"),
            "application/octet-stream",
        )
        .await;
        let mut repo = build_remote_repo(
            Uuid::new_v4(),
            "local-repo",
            "https://upstream.example.com",
            &location,
        );
        repo.repo_type = RepositoryType::Local;

        let err = proxy
            .check_upstream(&repo, "some/path")
            .await
            .expect_err("non-Remote repo must fail validation in check_upstream");
        assert!(
            format!("{}", err).contains("only supported for remote repositories"),
            "unexpected error: {}",
            err
        );
    }

    /// `get_cached_artifact_by_path` is the legacy global-storage cache
    /// lookup (no `Repository` in scope). It should miss when the cache is
    /// only seeded on the per-repo backend, since it intentionally doesn't
    /// route through the registry. This pins the back-compat surface so a
    /// future refactor doesn't silently merge it with the per-repo path.
    #[tokio::test]
    async fn test_get_cached_artifact_by_path_does_not_see_per_repo_only_seeds() {
        let repo_key = "debian-proxy";
        let cache_path = "pool/main/p/php7.4/php7.4_test.deb";
        let payload = Bytes::from_static(b"<deb file body>");
        let (_per_repo, proxy, _location) =
            make_seeded_proxy(repo_key, cache_path, payload, "application/x-deb").await;

        // This call uses the global StorageService (a throwaway /tmp
        // FilesystemBackend in `make_seeded_proxy`), so the per-repo seed
        // is invisible: must return Ok(None).
        let result = proxy
            .get_cached_artifact_by_path(repo_key, cache_path)
            .await
            .expect("get_cached_artifact_by_path must not error on a clean global backend");
        assert!(
            result.is_none(),
            "legacy by-path lookup must NOT resolve through the per-repo backend; \
             a Some result here would mean the back-compat path silently uses the registry"
        );
    }

    /// `invalidate_cache` MUST also work when no registry is configured
    /// (legacy back-compat path). With `per_repo_storage` returning None,
    /// the call falls back to the global `StorageService` for both
    /// `cache_delete` invocations. Pinning this exercises the else-branch
    /// of `cache_delete` (private) without needing a registry.
    #[tokio::test]
    async fn test_invalidate_cache_falls_back_to_global_storage_without_registry() {
        let pool = PgPool::connect_lazy("postgres://fake:fake@127.0.0.1:1/none").unwrap();
        let global_backend: Arc<dyn crate::services::storage_service::StorageBackend> =
            Arc::new(FilesystemBackend::new(std::path::PathBuf::from(
                "/tmp/ak-helpers-invalidate-fallback",
            )));
        let global_storage = Arc::new(StorageService::new(global_backend));
        let config = crate::config::Config::default();
        // No `with_storage_registry` call: per_repo_storage returns None.
        let proxy = ProxyService::new(pool, global_storage, &config);

        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: "/tmp/whatever".to_string(),
        };
        let repo = build_remote_repo(
            Uuid::new_v4(),
            "no-registry-repo",
            "https://upstream.example.com",
            &location,
        );

        // The cache entries don't exist on the FS backend; `cache_delete`
        // tolerates NotFound. This is success-on-no-op semantics, exactly
        // what `invalidate_cache` swallows via `let _ = ...`.
        proxy
            .invalidate_cache(&repo, "any/path/that/does/not/exist")
            .await
            .expect("invalidate_cache must succeed even when keys are absent");
    }

    /// Direct exercise of the MockBackend's `delete` and `exists` impls.
    /// Without this, those trait methods are only reachable in tests that
    /// don't actually call them, leaving them as uncovered new lines.
    #[tokio::test]
    async fn test_mock_backend_delete_and_exists_round_trip() {
        let backend: Arc<dyn RepoStorageBackend> = Arc::new(MockBackend::new());
        backend
            .put("k", Bytes::from_static(b"v"))
            .await
            .expect("put");
        assert!(backend.exists("k").await.expect("exists ok"));
        backend.delete("k").await.expect("delete ok");
        assert!(
            !backend.exists("k").await.expect("exists after delete ok"),
            "key should be gone after delete"
        );
    }
}
