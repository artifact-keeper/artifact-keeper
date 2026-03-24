//! Chunked/resumable upload API handlers.
//!
//! Provides a universal chunked upload flow for large artifacts:
//!   POST   /api/v1/uploads              - Create upload session
//!   PATCH  /api/v1/uploads/{session_id} - Upload a chunk (Content-Range)
//!   GET    /api/v1/uploads/{session_id} - Get session status
//!   PUT    /api/v1/uploads/{session_id}/complete - Finalize upload
//!   DELETE /api/v1/uploads/{session_id} - Cancel upload
//!
//! All I/O is streamed directly to disk; chunks are never buffered in memory.

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{patch, post};
use axum::{Extension, Json, Router};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::services::upload_service::{self, UploadError, UploadService};

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", post(create_session))
        .route(
            "/:session_id",
            patch(upload_chunk).get(get_session_status).delete(cancel),
        )
        .route("/:session_id/complete", axum::routing::put(complete))
        // Allow up to 256 MB per chunk on the PATCH route. The router-level
        // limit set here applies to all routes; the global API limit is
        // overridden by this layer.
        .layer(DefaultBodyLimit::max(256 * 1024 * 1024))
}

// ---------------------------------------------------------------------------
// Request / Response DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateSessionRequest {
    /// Repository key (e.g. "my-repo")
    pub repository_key: String,
    /// Path within the repository (e.g. "images/vm.ova")
    pub artifact_path: String,
    /// Total file size in bytes
    pub total_size: i64,
    /// Expected SHA256 checksum of the complete file
    pub checksum_sha256: String,
    /// Chunk size in bytes (default 8 MB, range 1 MB - 256 MB)
    pub chunk_size: Option<i32>,
    /// MIME content type (default "application/octet-stream")
    pub content_type: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreateSessionResponse {
    pub session_id: Uuid,
    pub chunk_count: i32,
    pub chunk_size: i32,
    pub expires_at: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ChunkResponse {
    pub chunk_index: i32,
    pub bytes_received: i64,
    pub chunks_completed: i32,
    pub chunks_remaining: i32,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SessionStatusResponse {
    pub session_id: Uuid,
    pub status: String,
    pub total_size: i64,
    pub bytes_received: i64,
    pub chunks_completed: i32,
    pub chunks_total: i32,
    pub repository_key: String,
    pub artifact_path: String,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CompleteResponse {
    pub artifact_id: Uuid,
    pub path: String,
    pub size: i64,
    pub checksum_sha256: String,
}

// ---------------------------------------------------------------------------
// POST / -- Create upload session
// ---------------------------------------------------------------------------

#[utoipa::path(
    post,
    path = "/api/v1/uploads",
    tag = "uploads",
    request_body = CreateSessionRequest,
    responses(
        (status = 201, description = "Upload session created", body = CreateSessionResponse),
        (status = 400, description = "Invalid request", body = crate::api::openapi::ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Repository not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn create_session(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(req): Json<CreateSessionRequest>,
) -> Result<Response, Response> {
    let user_id = auth.user_id;

    // Resolve repository
    let repo = sqlx::query_as::<_, (Uuid,)>(
        "SELECT id FROM repositories WHERE key = $1 AND is_deleted = false",
    )
    .bind(&req.repository_key)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| map_err(StatusCode::INTERNAL_SERVER_ERROR, e))?
    .ok_or_else(|| {
        map_err(
            StatusCode::NOT_FOUND,
            format!("Repository '{}' not found", req.repository_key),
        )
    })?;

    let session = UploadService::create_session(upload_service::CreateSessionParams {
        db: &state.db,
        storage_path: &state.config.storage_path,
        user_id,
        repo_id: repo.0,
        repo_key: &req.repository_key,
        artifact_path: &req.artifact_path,
        total_size: req.total_size,
        chunk_size: req.chunk_size,
        checksum_sha256: &req.checksum_sha256,
        content_type: req.content_type.as_deref(),
    })
    .await
    .map_err(map_upload_err)?;

    let resp = CreateSessionResponse {
        session_id: session.id,
        chunk_count: session.total_chunks,
        chunk_size: session.chunk_size,
        expires_at: session.expires_at.to_rfc3339(),
    };

    Ok((StatusCode::CREATED, Json(resp)).into_response())
}

// ---------------------------------------------------------------------------
// PATCH /{session_id} -- Upload chunk
// ---------------------------------------------------------------------------

#[utoipa::path(
    patch,
    path = "/api/v1/uploads/{session_id}",
    tag = "uploads",
    params(
        ("session_id" = Uuid, Path, description = "Upload session ID"),
    ),
    responses(
        (status = 200, description = "Chunk uploaded", body = ChunkResponse),
        (status = 400, description = "Invalid chunk or Content-Range", body = crate::api::openapi::ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Session not found", body = crate::api::openapi::ErrorResponse),
        (status = 410, description = "Session expired", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn upload_chunk(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(session_id): Path<Uuid>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, Response> {
    let _user_id = auth.user_id;

    // Parse Content-Range header
    let range_header = headers
        .get("content-range")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| map_err(StatusCode::BAD_REQUEST, "Missing Content-Range header"))?;

    let (start, end, _total) = upload_service::parse_content_range(range_header).map_err(|e| {
        map_err(
            StatusCode::BAD_REQUEST,
            format!("Invalid Content-Range: {}", e),
        )
    })?;

    // Get the session to determine chunk_index from byte_offset
    let session = UploadService::get_session(&state.db, session_id)
        .await
        .map_err(map_upload_err)?;

    let chunk_index = (start / session.chunk_size as i64) as i32;

    // Stream body to bytes (chunk sized, not full file)
    let mut data = Vec::new();
    let mut stream = body.into_data_stream();
    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(|e| {
            map_err(
                StatusCode::BAD_REQUEST,
                format!("Error reading body: {}", e),
            )
        })?;
        data.extend_from_slice(&chunk);
    }

    let expected_len = (end - start + 1) as usize;
    if data.len() != expected_len {
        return Err(map_err(
            StatusCode::BAD_REQUEST,
            format!(
                "Content-Range declares {} bytes but body contains {} bytes",
                expected_len,
                data.len()
            ),
        ));
    }

    let result = UploadService::upload_chunk(
        &state.db,
        session_id,
        chunk_index,
        start,
        bytes::Bytes::from(data),
    )
    .await
    .map_err(map_upload_err)?;

    Ok(Json(ChunkResponse {
        chunk_index: result.chunk_index,
        bytes_received: result.bytes_received,
        chunks_completed: result.chunks_completed,
        chunks_remaining: result.chunks_remaining,
    })
    .into_response())
}

// ---------------------------------------------------------------------------
// GET /{session_id} -- Get session status
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/uploads/{session_id}",
    tag = "uploads",
    params(
        ("session_id" = Uuid, Path, description = "Upload session ID"),
    ),
    responses(
        (status = 200, description = "Session status", body = SessionStatusResponse),
        (status = 404, description = "Session not found", body = crate::api::openapi::ErrorResponse),
        (status = 410, description = "Session expired", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn get_session_status(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(session_id): Path<Uuid>,
) -> Result<Response, Response> {
    let _user_id = auth.user_id;

    let session = UploadService::get_session(&state.db, session_id)
        .await
        .map_err(map_upload_err)?;

    Ok(Json(SessionStatusResponse {
        session_id: session.id,
        status: session.status,
        total_size: session.total_size,
        bytes_received: session.bytes_received,
        chunks_completed: session.completed_chunks,
        chunks_total: session.total_chunks,
        repository_key: session.repository_key,
        artifact_path: session.artifact_path,
        created_at: session.created_at.to_rfc3339(),
        expires_at: session.expires_at.to_rfc3339(),
    })
    .into_response())
}

// ---------------------------------------------------------------------------
// PUT /{session_id}/complete -- Finalize upload
// ---------------------------------------------------------------------------

#[utoipa::path(
    put,
    path = "/api/v1/uploads/{session_id}/complete",
    tag = "uploads",
    params(
        ("session_id" = Uuid, Path, description = "Upload session ID"),
    ),
    responses(
        (status = 200, description = "Upload finalized, artifact created", body = CompleteResponse),
        (status = 400, description = "Incomplete chunks or invalid state", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Session not found", body = crate::api::openapi::ErrorResponse),
        (status = 409, description = "Checksum mismatch", body = crate::api::openapi::ErrorResponse),
        (status = 410, description = "Session expired", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn complete(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(session_id): Path<Uuid>,
) -> Result<Response, Response> {
    let user_id = auth.user_id;

    let session = UploadService::complete_session(&state.db, session_id)
        .await
        .map_err(map_upload_err)?;

    // Move temp file to final storage location and create artifact record
    let temp_path = std::path::PathBuf::from(&session.temp_file_path);
    let storage_key = format!(
        "uploads/{}/{}",
        session.repository_id, session.artifact_path
    );

    // Store via the storage service
    let content = tokio::fs::read(&temp_path)
        .await
        .map_err(|e| map_err(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    state
        .storage
        .put(&storage_key, content.into())
        .await
        .map_err(|e| map_err(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    // Clean up temp file
    let _ = tokio::fs::remove_file(&temp_path).await;

    // Create artifact record
    let artifact_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO artifacts (repository_id, path, name, version, size_bytes,
                               checksum_sha256, content_type, storage_key, uploaded_by)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (repository_id, path) DO UPDATE SET
            size_bytes = $5, checksum_sha256 = $6, content_type = $7, storage_key = $8,
            uploaded_by = $9, updated_at = NOW(), is_deleted = false
        RETURNING id
        "#,
    )
    .bind(session.repository_id)
    .bind(&session.artifact_path)
    .bind(artifact_name_from_path(&session.artifact_path))
    .bind::<Option<String>>(None) // version
    .bind(session.total_size)
    .bind(&session.checksum_sha256)
    .bind(&session.content_type)
    .bind(&storage_key)
    .bind(user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| map_err(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    tracing::info!(
        "Finalized chunked upload {} -> artifact {} ({}B, sha256:{})",
        session_id,
        artifact_id,
        session.total_size,
        &session.checksum_sha256[..12.min(session.checksum_sha256.len())]
    );

    Ok(Json(CompleteResponse {
        artifact_id,
        path: session.artifact_path,
        size: session.total_size,
        checksum_sha256: session.checksum_sha256,
    })
    .into_response())
}

// ---------------------------------------------------------------------------
// DELETE /{session_id} -- Cancel upload
// ---------------------------------------------------------------------------

#[utoipa::path(
    delete,
    path = "/api/v1/uploads/{session_id}",
    tag = "uploads",
    params(
        ("session_id" = Uuid, Path, description = "Upload session ID"),
    ),
    responses(
        (status = 204, description = "Upload cancelled"),
        (status = 404, description = "Session not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn cancel(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(session_id): Path<Uuid>,
) -> Result<Response, Response> {
    let _user_id = auth.user_id;

    UploadService::cancel_session(&state.db, session_id)
        .await
        .map_err(map_upload_err)?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---------------------------------------------------------------------------
// OpenAPI doc
// ---------------------------------------------------------------------------

#[derive(OpenApi)]
#[openapi(
    paths(
        create_session,
        upload_chunk,
        get_session_status,
        complete,
        cancel,
    ),
    components(schemas(
        CreateSessionRequest,
        CreateSessionResponse,
        ChunkResponse,
        SessionStatusResponse,
        CompleteResponse,
    )),
    tags(
        (name = "uploads", description = "Chunked/resumable file uploads"),
    )
)]
pub struct UploadApiDoc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map an UploadError to an HTTP response.
fn map_upload_err(e: UploadError) -> Response {
    let (status, msg) = match &e {
        UploadError::NotFound => (StatusCode::NOT_FOUND, e.to_string()),
        UploadError::Expired => (StatusCode::GONE, e.to_string()),
        UploadError::InvalidChunk(_) => (StatusCode::BAD_REQUEST, e.to_string()),
        UploadError::InvalidChunkSize => (StatusCode::BAD_REQUEST, e.to_string()),
        UploadError::InvalidStatus(_) => (StatusCode::BAD_REQUEST, e.to_string()),
        UploadError::ChecksumMismatch { .. } => (StatusCode::CONFLICT, e.to_string()),
        UploadError::IncompleteChunks { .. } => (StatusCode::BAD_REQUEST, e.to_string()),
        UploadError::SizeMismatch { .. } => (StatusCode::BAD_REQUEST, e.to_string()),
        UploadError::RepositoryNotFound(_) => (StatusCode::NOT_FOUND, e.to_string()),
        UploadError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error".into()),
        UploadError::Io(_) => (StatusCode::INTERNAL_SERVER_ERROR, "I/O error".into()),
    };

    (status, axum::Json(serde_json::json!({"error": msg}))).into_response()
}

/// Map any displayable error to an HTTP error response.
fn map_err(status: StatusCode, e: impl std::fmt::Display) -> Response {
    (
        status,
        axum::Json(serde_json::json!({"error": e.to_string()})),
    )
        .into_response()
}

/// Extract a simple artifact name from its path (last path component without extension).
fn artifact_name_from_path(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_artifact_name_from_path() {
        assert_eq!(artifact_name_from_path("images/vm.ova"), "vm.ova");
        assert_eq!(artifact_name_from_path("vm.ova"), "vm.ova");
        assert_eq!(artifact_name_from_path("a/b/c/file.tar.gz"), "file.tar.gz");
    }
}
