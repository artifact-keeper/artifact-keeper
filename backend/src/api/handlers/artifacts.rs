//! Artifact handlers - standalone artifact operations.
//!
//! These handlers provide direct access to artifacts by ID, complementing
//! the repository-nested artifact routes in repositories.rs.

use axum::{
    extract::{Path, State},
    routing::get,
    Extension, Json, Router,
};
use serde::Serialize;
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::handlers::repositories::ArtifactResponse;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};

/// Check that the caller is allowed to see this artifact.
///
/// Unauthenticated requests are rejected for artifacts in private repos.
/// Authenticated requests with repository-scoped API tokens are rejected
/// if the artifact's repository is not in the token's allowed set.
pub(crate) async fn check_artifact_visibility(
    auth: &Option<AuthExtension>,
    artifact_id: Uuid,
    db: &sqlx::PgPool,
) -> Result<()> {
    // Always fetch repo info so we can check both visibility and token scope.
    let repo_info: Option<(Uuid, bool)> = sqlx::query_as(
        "SELECT r.id, r.is_public FROM repositories r \
         JOIN artifacts a ON a.repository_id = r.id WHERE a.id = $1",
    )
    .bind(artifact_id)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let Some((repo_id, is_public)) = repo_info else {
        // No matching repo means the artifact query upstream will 404.
        return Ok(());
    };

    match auth {
        Some(ext) => {
            // Enforce API token repository scope: if the token is restricted
            // to specific repos, the artifact's repo must be in that set.
            if !ext.can_access_repo(repo_id) {
                return Err(AppError::Authorization(
                    "Token does not have access to this repository".to_string(),
                ));
            }
            // Per-repo authorization for private repos: admins bypass; every
            // other caller must hold a role assignment scoped to the repo
            // (direct or global). NotFound (not Forbidden) avoids leaking the
            // existence of repositories the caller may not see.
            if !is_public && !ext.is_admin {
                let repo_service =
                    crate::services::repository_service::RepositoryService::new(db.clone());
                if !repo_service
                    .user_can_access_repo(repo_id, ext.user_id)
                    .await?
                {
                    return Err(AppError::NotFound("Artifact not found".to_string()));
                }
            }
            Ok(())
        }
        None => {
            if !is_public {
                return Err(AppError::NotFound("Artifact not found".to_string()));
            }
            Ok(())
        }
    }
}

/// Create artifact routes
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/:id", get(get_artifact))
        .route("/:id/metadata", get(get_artifact_metadata))
        .route("/:id/stats", get(get_artifact_stats))
        .merge(super::artifact_labels::artifact_labels_router())
}

/// Row shape for the by-id artifact lookup.
///
/// Runtime `query_as` (not the compile-time macro) so the query needs no
/// `.sqlx` offline entry; the columns mirror what
/// [`ArtifactResponse`] needs.
#[derive(Debug, sqlx::FromRow)]
struct ArtifactByIdRow {
    id: Uuid,
    repository_key: String,
    path: String,
    name: String,
    version: Option<String>,
    size_bytes: i64,
    checksum_sha256: String,
    content_type: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ArtifactMetadataResponse {
    pub artifact_id: Uuid,
    pub format: String,
    pub metadata: serde_json::Value,
    pub properties: serde_json::Value,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ArtifactStatsResponse {
    pub artifact_id: Uuid,
    pub download_count: i64,
    pub first_downloaded: Option<chrono::DateTime<chrono::Utc>>,
    pub last_downloaded: Option<chrono::DateTime<chrono::Utc>>,
}

/// Get artifact by ID
#[utoipa::path(
    get,
    path = "/{id}",
    context_path = "/api/v1/artifacts",
    tag = "artifacts",
    params(
        ("id" = Uuid, Path, description = "Artifact ID")
    ),
    responses(
        (status = 200, description = "Artifact details", body = ArtifactResponse),
        (status = 404, description = "Artifact not found", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn get_artifact(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ArtifactResponse>> {
    let artifact: ArtifactByIdRow = sqlx::query_as(
        "SELECT a.id, r.key AS repository_key, a.path, a.name, a.version, \
                a.size_bytes, a.checksum_sha256, a.content_type, a.created_at \
         FROM artifacts a \
         JOIN repositories r ON r.id = a.repository_id \
         WHERE a.id = $1 AND a.is_deleted = false",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Artifact not found".to_string()))?;

    check_artifact_visibility(&auth, id, &state.db).await?;

    let download_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM download_statistics WHERE artifact_id = $1")
            .bind(id)
            .fetch_one(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

    let metadata: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT metadata FROM artifact_metadata WHERE artifact_id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(ArtifactResponse {
        id: artifact.id,
        repository_key: artifact.repository_key,
        path: artifact.path,
        name: artifact.name,
        version: artifact.version,
        size_bytes: artifact.size_bytes,
        checksum_sha256: artifact.checksum_sha256,
        content_type: artifact.content_type,
        download_count,
        created_at: artifact.created_at,
        metadata,
        // This handler resolves a real `artifacts` row by id, so it is
        // always a hosted artifact (analyzable), matching the by-path
        // handler in repositories.rs.
        analyzable: true,
        // Proxy cache freshness is a Remote-repo, by-path concern; the
        // by-id surface does not resolve through the proxy cache.
        cache_cached_at: None,
        cache_expires_at: None,
        // Revision history is a by-path, versioned-repo concern (#2367);
        // the by-id surface leaves it unset.
        revision: None,
        version_label: None,
    }))
}

/// Get artifact metadata by artifact ID
#[utoipa::path(
    get,
    path = "/{id}/metadata",
    context_path = "/api/v1/artifacts",
    tag = "artifacts",
    params(
        ("id" = Uuid, Path, description = "Artifact ID")
    ),
    responses(
        (status = 200, description = "Artifact metadata", body = ArtifactMetadataResponse),
        (status = 404, description = "Artifact or metadata not found", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn get_artifact_metadata(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ArtifactMetadataResponse>> {
    let exists = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM artifacts WHERE id = $1 AND is_deleted = false)",
        id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if exists != Some(true) {
        return Err(AppError::NotFound("Artifact not found".to_string()));
    }

    check_artifact_visibility(&auth, id, &state.db).await?;

    let metadata = sqlx::query!(
        r#"
        SELECT artifact_id, format, metadata, properties
        FROM artifact_metadata
        WHERE artifact_id = $1
        "#,
        id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Artifact metadata not found".to_string()))?;

    Ok(Json(ArtifactMetadataResponse {
        artifact_id: metadata.artifact_id,
        format: metadata.format,
        metadata: metadata.metadata,
        properties: metadata.properties,
    }))
}

/// Get artifact download statistics
#[utoipa::path(
    get,
    path = "/{id}/stats",
    context_path = "/api/v1/artifacts",
    tag = "artifacts",
    params(
        ("id" = Uuid, Path, description = "Artifact ID")
    ),
    responses(
        (status = 200, description = "Artifact download statistics", body = ArtifactStatsResponse),
        (status = 404, description = "Artifact not found", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn get_artifact_stats(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ArtifactStatsResponse>> {
    let exists = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM artifacts WHERE id = $1 AND is_deleted = false)",
        id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if exists != Some(true) {
        return Err(AppError::NotFound("Artifact not found".to_string()));
    }

    check_artifact_visibility(&auth, id, &state.db).await?;

    let stats = sqlx::query!(
        r#"
        SELECT
            COUNT(*) as "download_count!",
            MIN(downloaded_at) as first_downloaded,
            MAX(downloaded_at) as last_downloaded
        FROM download_statistics
        WHERE artifact_id = $1
        "#,
        id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(ArtifactStatsResponse {
        artifact_id: id,
        download_count: stats.download_count,
        first_downloaded: stats.first_downloaded,
        last_downloaded: stats.last_downloaded,
    }))
}

#[derive(OpenApi)]
#[openapi(
    paths(get_artifact, get_artifact_metadata, get_artifact_stats,),
    // `ArtifactResponse` is intentionally NOT registered here: the canonical
    // schema lives in repositories.rs (RepositoriesApiDoc). Registering a
    // second struct under the same name used to shadow it (utoipa merge is
    // first-wins on schema names) and published a stale shape for
    // GET /api/v1/artifacts/{id}. See the schema-name-uniqueness regression
    // test in openapi.rs.
    components(schemas(ArtifactMetadataResponse, ArtifactStatsResponse,))
)]
pub struct ArtifactsApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    // ── ArtifactResponse serialization tests ────────────────────────
    //
    // The by-id endpoint now serves the canonical repositories.rs
    // ArtifactResponse (the shape the published OpenAPI spec has always
    // declared). These tests pin the on-the-wire contract of that shape as
    // served by GET /api/v1/artifacts/{id}.

    #[test]
    fn test_artifact_response_serialization_all_fields() {
        let now = Utc::now();
        let id = Uuid::new_v4();
        let resp = ArtifactResponse {
            revision: None,
            version_label: None,
            id,
            repository_key: "maven-releases".to_string(),
            path: "com/example/lib/1.0/lib-1.0.jar".to_string(),
            name: "lib".to_string(),
            version: Some("1.0".to_string()),
            size_bytes: 102400,
            checksum_sha256: "abc123".to_string(),
            content_type: "application/java-archive".to_string(),
            download_count: 42,
            created_at: now,
            metadata: Some(serde_json::json!({"groupId": "com.example"})),
            analyzable: true,
            cache_cached_at: None,
            cache_expires_at: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["id"], id.to_string());
        assert_eq!(json["repository_key"], "maven-releases");
        assert_eq!(json["path"], "com/example/lib/1.0/lib-1.0.jar");
        assert_eq!(json["name"], "lib");
        assert_eq!(json["version"], "1.0");
        assert_eq!(json["size_bytes"], 102400);
        assert_eq!(json["checksum_sha256"], "abc123");
        assert_eq!(json["content_type"], "application/java-archive");
        // Spec-required fields the by-id endpoint previously omitted (#98).
        assert_eq!(json["download_count"], 42);
        assert_eq!(json["analyzable"], true);
        assert_eq!(json["metadata"]["groupId"], "com.example");
    }

    #[test]
    fn test_artifact_response_no_undeclared_fields() {
        // The previous local ArtifactResponse leaked DB columns the spec
        // never declared. Pin their absence on the serialized output.
        let resp = ArtifactResponse {
            revision: None,
            version_label: None,
            id: Uuid::new_v4(),
            repository_key: "generic-local".to_string(),
            path: "file.tar.gz".to_string(),
            name: "file".to_string(),
            version: None,
            size_bytes: 0,
            checksum_sha256: "sha".to_string(),
            content_type: "application/octet-stream".to_string(),
            download_count: 0,
            created_at: Utc::now(),
            metadata: None,
            analyzable: true,
            cache_cached_at: None,
            cache_expires_at: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        let obj = json.as_object().unwrap();
        for undeclared in [
            "repository_id",
            "checksum_md5",
            "checksum_sha1",
            "updated_at",
        ] {
            assert!(
                !obj.contains_key(undeclared),
                "`{undeclared}` is not part of the published ArtifactResponse schema"
            );
        }
        // Cache freshness fields are skip_serializing_if = None.
        assert!(!obj.contains_key("cache_cached_at"));
        assert!(!obj.contains_key("cache_expires_at"));
        assert!(json["version"].is_null());
        assert!(json["metadata"].is_null());
    }

    #[test]
    fn test_artifact_response_zero_size() {
        let resp = ArtifactResponse {
            revision: None,
            version_label: None,
            id: Uuid::new_v4(),
            repository_key: "generic-local".to_string(),
            path: "empty".to_string(),
            name: "empty".to_string(),
            version: None,
            size_bytes: 0,
            checksum_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_string(),
            content_type: "application/octet-stream".to_string(),
            download_count: 0,
            created_at: Utc::now(),
            metadata: None,
            analyzable: false,
            cache_cached_at: None,
            cache_expires_at: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["size_bytes"], 0);
        assert_eq!(json["analyzable"], false);
    }

    // ── ArtifactMetadataResponse serialization tests ────────────────

    #[test]
    fn test_artifact_metadata_response_serialization() {
        let resp = ArtifactMetadataResponse {
            artifact_id: Uuid::new_v4(),
            format: "maven".to_string(),
            metadata: serde_json::json!({"groupId": "com.example", "artifactId": "lib"}),
            properties: serde_json::json!({"build.number": "42"}),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["format"], "maven");
        assert_eq!(json["metadata"]["groupId"], "com.example");
        assert_eq!(json["properties"]["build.number"], "42");
    }

    #[test]
    fn test_artifact_metadata_response_empty_metadata() {
        let resp = ArtifactMetadataResponse {
            artifact_id: Uuid::new_v4(),
            format: "generic".to_string(),
            metadata: serde_json::json!({}),
            properties: serde_json::json!({}),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["metadata"].as_object().unwrap().is_empty());
        assert!(json["properties"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_artifact_metadata_response_complex_metadata() {
        let resp = ArtifactMetadataResponse {
            artifact_id: Uuid::new_v4(),
            format: "npm".to_string(),
            metadata: serde_json::json!({
                "name": "@scope/pkg",
                "version": "2.0.0",
                "dependencies": {"lodash": "^4.0.0"},
                "keywords": ["test", "example"]
            }),
            properties: serde_json::json!(null),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["metadata"]["dependencies"]["lodash"], "^4.0.0");
        assert!(json["properties"].is_null());
    }

    // ── ArtifactStatsResponse serialization tests ───────────────────

    #[test]
    fn test_artifact_stats_response_with_downloads() {
        let now = Utc::now();
        let resp = ArtifactStatsResponse {
            artifact_id: Uuid::new_v4(),
            download_count: 1234,
            first_downloaded: Some(now - chrono::Duration::days(30)),
            last_downloaded: Some(now),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["download_count"], 1234);
        assert!(!json["first_downloaded"].is_null());
        assert!(!json["last_downloaded"].is_null());
    }

    #[test]
    fn test_artifact_stats_response_no_downloads() {
        let resp = ArtifactStatsResponse {
            artifact_id: Uuid::new_v4(),
            download_count: 0,
            first_downloaded: None,
            last_downloaded: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["download_count"], 0);
        assert!(json["first_downloaded"].is_null());
        assert!(json["last_downloaded"].is_null());
    }

    #[test]
    fn test_artifact_stats_response_large_download_count() {
        let resp = ArtifactStatsResponse {
            artifact_id: Uuid::new_v4(),
            download_count: i64::MAX,
            first_downloaded: None,
            last_downloaded: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["download_count"], i64::MAX);
    }

    // ── Struct field visibility / construction tests ─────────────────

    #[test]
    fn test_artifact_response_debug_impl() {
        let resp = ArtifactResponse {
            revision: None,
            version_label: None,
            id: Uuid::nil(),
            repository_key: "k".to_string(),
            path: "p".to_string(),
            name: "n".to_string(),
            version: None,
            size_bytes: 0,
            checksum_sha256: "s".to_string(),
            content_type: "t".to_string(),
            download_count: 0,
            created_at: Utc::now(),
            metadata: None,
            analyzable: true,
            cache_cached_at: None,
            cache_expires_at: None,
        };
        let debug_str = format!("{:?}", resp);
        assert!(debug_str.contains("ArtifactResponse"));
    }

    #[test]
    fn test_artifact_metadata_response_debug_impl() {
        let resp = ArtifactMetadataResponse {
            artifact_id: Uuid::nil(),
            format: "generic".to_string(),
            metadata: serde_json::json!(null),
            properties: serde_json::json!(null),
        };
        let debug_str = format!("{:?}", resp);
        assert!(debug_str.contains("ArtifactMetadataResponse"));
    }
}
