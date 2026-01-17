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
use uuid::Uuid;

use crate::api::SharedState;
use crate::error::{AppError, Result};

/// Create artifact routes
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/:id", get(get_artifact))
        .route("/:id/metadata", get(get_artifact_metadata))
        .route("/:id/stats", get(get_artifact_stats))
}

#[derive(Debug, Serialize)]
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

#[derive(Debug, Serialize)]
pub struct ArtifactMetadataResponse {
    pub artifact_id: Uuid,
    pub format: String,
    pub metadata: serde_json::Value,
    pub properties: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct ArtifactStatsResponse {
    pub artifact_id: Uuid,
    pub download_count: i64,
    pub first_downloaded: Option<chrono::DateTime<chrono::Utc>>,
    pub last_downloaded: Option<chrono::DateTime<chrono::Utc>>,
}

/// Get artifact by ID
pub async fn get_artifact(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ArtifactResponse>> {
    // Fetch artifact
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
pub async fn get_artifact_metadata(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ArtifactMetadataResponse>> {
    // Verify artifact exists
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

    // Fetch metadata
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
pub async fn get_artifact_stats(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ArtifactStatsResponse>> {
    // Verify artifact exists
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

    // Get download stats
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
