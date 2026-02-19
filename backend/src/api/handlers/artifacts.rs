//! Artifact handlers - standalone artifact operations.
//!
//! These handlers provide direct access to artifacts by ID, complementing
//! the repository-nested artifact routes in repositories.rs.

use axum::{
    extract::{Path, State},
    routing::get,
    Json, Router,
};
use serde::Serialize;
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::SharedState;
use crate::error::{AppError, Result};

/// Create artifact routes
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/:id", get(get_artifact))
        .route("/:id/metadata", get(get_artifact_metadata))
        .route("/:id/stats", get(get_artifact_stats))
        .merge(super::artifact_labels::artifact_labels_router())
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ArtifactResponse {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub repository_key: Option<String>,
    pub path: String,
    pub name: String,
    pub version: Option<String>,
    pub size_bytes: i64,
    pub checksum_sha256: String,
    pub checksum_md5: Option<String>,
    pub checksum_sha1: Option<String>,
    pub content_type: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
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
    Path(id): Path<Uuid>,
) -> Result<Json<ArtifactResponse>> {
    let artifact = sqlx::query!(
        r#"
        SELECT
            a.id, a.repository_id, a.path, a.name, a.version, a.size_bytes,
            a.checksum_sha256, a.checksum_md5, a.checksum_sha1,
            a.content_type, a.created_at, a.updated_at,
            r.key as repository_key
        FROM artifacts a
        JOIN repositories r ON r.id = a.repository_id
        WHERE a.id = $1 AND a.is_deleted = false
        "#,
        id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Artifact not found".to_string()))?;

    Ok(Json(ArtifactResponse {
        id: artifact.id,
        repository_id: artifact.repository_id,
        repository_key: Some(artifact.repository_key),
        path: artifact.path,
        name: artifact.name,
        version: artifact.version,
        size_bytes: artifact.size_bytes,
        checksum_sha256: artifact.checksum_sha256,
        checksum_md5: artifact.checksum_md5,
        checksum_sha1: artifact.checksum_sha1,
        content_type: artifact.content_type,
        created_at: artifact.created_at,
        updated_at: artifact.updated_at,
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
    components(schemas(ArtifactResponse, ArtifactMetadataResponse, ArtifactStatsResponse,))
)]
pub struct ArtifactsApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    // ── ArtifactResponse serialization tests ────────────────────────

    #[test]
    fn test_artifact_response_serialization_all_fields() {
        let now = Utc::now();
        let id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let resp = ArtifactResponse {
            id,
            repository_id: repo_id,
            repository_key: Some("maven-releases".to_string()),
            path: "com/example/lib/1.0/lib-1.0.jar".to_string(),
            name: "lib".to_string(),
            version: Some("1.0".to_string()),
            size_bytes: 102400,
            checksum_sha256: "abc123".to_string(),
            checksum_md5: Some("def456".to_string()),
            checksum_sha1: Some("ghi789".to_string()),
            content_type: "application/java-archive".to_string(),
            created_at: now,
            updated_at: now,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["id"], id.to_string());
        assert_eq!(json["repository_id"], repo_id.to_string());
        assert_eq!(json["repository_key"], "maven-releases");
        assert_eq!(json["path"], "com/example/lib/1.0/lib-1.0.jar");
        assert_eq!(json["name"], "lib");
        assert_eq!(json["version"], "1.0");
        assert_eq!(json["size_bytes"], 102400);
        assert_eq!(json["checksum_sha256"], "abc123");
        assert_eq!(json["checksum_md5"], "def456");
        assert_eq!(json["checksum_sha1"], "ghi789");
        assert_eq!(json["content_type"], "application/java-archive");
    }

    #[test]
    fn test_artifact_response_optional_fields_null() {
        let now = Utc::now();
        let resp = ArtifactResponse {
            id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            repository_key: None,
            path: "file.tar.gz".to_string(),
            name: "file".to_string(),
            version: None,
            size_bytes: 0,
            checksum_sha256: "sha".to_string(),
            checksum_md5: None,
            checksum_sha1: None,
            content_type: "application/octet-stream".to_string(),
            created_at: now,
            updated_at: now,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["repository_key"].is_null());
        assert!(json["version"].is_null());
        assert!(json["checksum_md5"].is_null());
        assert!(json["checksum_sha1"].is_null());
    }

    #[test]
    fn test_artifact_response_zero_size() {
        let now = Utc::now();
        let resp = ArtifactResponse {
            id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            repository_key: None,
            path: "empty".to_string(),
            name: "empty".to_string(),
            version: None,
            size_bytes: 0,
            checksum_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_string(),
            checksum_md5: None,
            checksum_sha1: None,
            content_type: "application/octet-stream".to_string(),
            created_at: now,
            updated_at: now,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["size_bytes"], 0);
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
            id: Uuid::nil(),
            repository_id: Uuid::nil(),
            repository_key: None,
            path: "p".to_string(),
            name: "n".to_string(),
            version: None,
            size_bytes: 0,
            checksum_sha256: "s".to_string(),
            checksum_md5: None,
            checksum_sha1: None,
            content_type: "t".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
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
