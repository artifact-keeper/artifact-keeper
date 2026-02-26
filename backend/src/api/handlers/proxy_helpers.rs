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

/// Reject write operations (publish/upload) on remote and virtual repositories.
/// Returns 405 Method Not Allowed for remote repos, 400 for virtual repos.
#[allow(clippy::result_large_err)]
pub fn reject_write_if_not_hosted(repo_type: &str) -> Result<(), Response> {
    match repo_type {
        "remote" => Err((
            StatusCode::METHOD_NOT_ALLOWED,
            "Cannot publish to a remote (proxy) repository",
        )
            .into_response()),
        "virtual" => Err((
            StatusCode::BAD_REQUEST,
            "Cannot publish to a virtual repository",
        )
            .into_response()),
        _ => Ok(()),
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
        .map_err(|e| {
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
        })
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
    F: Fn(Uuid, String) -> Fut,
    Fut: std::future::Future<Output = Result<(Bytes, Option<String>), Response>>,
{
    let members = fetch_virtual_members(db, virtual_repo_id).await?;

    if members.is_empty() {
        return Err((StatusCode::NOT_FOUND, "Virtual repository has no members").into_response());
    }

    for member in &members {
        // Try local storage first (works for Local, Staging, and cached Remote)
        if let Ok(result) = local_fetch(member.id, member.storage_path.clone()).await {
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
    storage_path: &str,
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
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Artifact not found").into_response())?;

    let storage = state.storage_for_repo(storage_path);
    let content = storage.get(&artifact.storage_key).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    Ok((content, Some(artifact.content_type)))
}

/// Generic local artifact fetch by name and version.
/// Used as a `local_fetch` callback for [`resolve_virtual_download`].
pub async fn local_fetch_by_name_version(
    db: &PgPool,
    state: &AppState,
    repo_id: Uuid,
    storage_path: &str,
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
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Artifact not found").into_response())?;

    let storage = state.storage_for_repo(storage_path);
    let content = storage.get(&artifact.storage_key).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    Ok((content, Some(artifact.content_type)))
}

/// Generic local artifact fetch by path suffix (LIKE match).
/// Used for handlers like npm that query by filename suffix.
pub async fn local_fetch_by_path_suffix(
    db: &PgPool,
    state: &AppState,
    repo_id: Uuid,
    storage_path: &str,
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
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Artifact not found").into_response())?;

    let storage = state.storage_for_repo(storage_path);
    let content = storage.get(&artifact.storage_key).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

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
}
