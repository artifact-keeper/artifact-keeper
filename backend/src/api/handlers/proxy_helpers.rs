//! Shared helpers for remote repository proxying and virtual repository resolution.

use axum::http::StatusCode;
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
pub async fn proxy_fetch_uncached(
    proxy_service: &ProxyService,
    repo_id: Uuid,
    repo_key: &str,
    upstream_url: &str,
    path: &str,
) -> Result<(Bytes, Option<String>), Response> {
    let repo = build_remote_repo(repo_id, repo_key, upstream_url);

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
/// Used for handlers like npm that query by filename suffix.
pub async fn local_fetch_by_path_suffix(
    db: &PgPool,
    state: &AppState,
    repo_id: Uuid,
    location: &StorageLocation,
    path_suffix: &str,
) -> Result<(Bytes, Option<String>), Response> {
    let artifact = sqlx::query!(
        r#"SELECT storage_key, content_type
        FROM artifacts
        WHERE repository_id = $1 AND path LIKE '%/' || $2 AND is_deleted = false
        LIMIT 1"#,
        repo_id,
        path_suffix
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
    use axum::http::StatusCode;

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
}
