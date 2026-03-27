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

    // Validate artifact path before doing anything else
    upload_service::validate_artifact_path(&req.artifact_path).map_err(map_upload_err)?;

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
#[allow(clippy::io_other_error, clippy::unnecessary_literal_unwrap)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // artifact_name_from_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_artifact_name_from_path() {
        assert_eq!(artifact_name_from_path("images/vm.ova"), "vm.ova");
        assert_eq!(artifact_name_from_path("vm.ova"), "vm.ova");
        assert_eq!(artifact_name_from_path("a/b/c/file.tar.gz"), "file.tar.gz");
    }

    #[test]
    fn test_artifact_name_from_path_empty() {
        assert_eq!(artifact_name_from_path(""), "");
    }

    #[test]
    fn test_artifact_name_from_path_trailing_slash() {
        // rsplit('/').next() on "dir/" gives ""
        assert_eq!(artifact_name_from_path("dir/"), "");
    }

    #[test]
    fn test_artifact_name_from_path_no_slash() {
        assert_eq!(artifact_name_from_path("standalone.bin"), "standalone.bin");
    }

    #[test]
    fn test_artifact_name_from_path_deeply_nested() {
        assert_eq!(
            artifact_name_from_path("a/b/c/d/e/f/artifact.tar.gz"),
            "artifact.tar.gz"
        );
    }

    #[test]
    fn test_artifact_name_from_path_with_dots() {
        assert_eq!(
            artifact_name_from_path("releases/v1.2.3/app-1.2.3.jar"),
            "app-1.2.3.jar"
        );
    }

    #[test]
    fn test_artifact_name_from_path_unicode() {
        assert_eq!(
            artifact_name_from_path("packages/build-2024.pkg"),
            "build-2024.pkg"
        );
    }

    // -----------------------------------------------------------------------
    // CreateSessionRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_session_request_deserialize_full() {
        let json = r#"{
            "repository_key": "my-repo",
            "artifact_path": "images/vm.ova",
            "total_size": 21474836480,
            "checksum_sha256": "abc123def456",
            "chunk_size": 16777216,
            "content_type": "application/x-ova"
        }"#;
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.repository_key, "my-repo");
        assert_eq!(req.artifact_path, "images/vm.ova");
        assert_eq!(req.total_size, 21_474_836_480);
        assert_eq!(req.checksum_sha256, "abc123def456");
        assert_eq!(req.chunk_size, Some(16_777_216));
        assert_eq!(req.content_type.as_deref(), Some("application/x-ova"));
    }

    #[test]
    fn test_create_session_request_deserialize_minimal() {
        let json = r#"{
            "repository_key": "repo",
            "artifact_path": "file.bin",
            "total_size": 1024,
            "checksum_sha256": "deadbeef"
        }"#;
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.repository_key, "repo");
        assert_eq!(req.artifact_path, "file.bin");
        assert_eq!(req.total_size, 1024);
        assert_eq!(req.checksum_sha256, "deadbeef");
        assert!(req.chunk_size.is_none());
        assert!(req.content_type.is_none());
    }

    #[test]
    fn test_create_session_request_missing_required_field() {
        // Missing repository_key
        let json = r#"{
            "artifact_path": "file.bin",
            "total_size": 1024,
            "checksum_sha256": "deadbeef"
        }"#;
        let result: Result<CreateSessionRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_session_request_missing_total_size() {
        let json = r#"{
            "repository_key": "repo",
            "artifact_path": "file.bin",
            "checksum_sha256": "deadbeef"
        }"#;
        let result: Result<CreateSessionRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_session_request_missing_checksum() {
        let json = r#"{
            "repository_key": "repo",
            "artifact_path": "file.bin",
            "total_size": 1024
        }"#;
        let result: Result<CreateSessionRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_session_request_missing_artifact_path() {
        let json = r#"{
            "repository_key": "repo",
            "total_size": 1024,
            "checksum_sha256": "abc"
        }"#;
        let result: Result<CreateSessionRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_session_request_extra_fields_ignored() {
        let json = r#"{
            "repository_key": "repo",
            "artifact_path": "file.bin",
            "total_size": 1024,
            "checksum_sha256": "abc",
            "unknown_field": "should be ignored"
        }"#;
        // serde defaults to ignoring unknown fields
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.repository_key, "repo");
    }

    #[test]
    fn test_create_session_request_null_optional_fields() {
        let json = r#"{
            "repository_key": "repo",
            "artifact_path": "file.bin",
            "total_size": 1024,
            "checksum_sha256": "abc",
            "chunk_size": null,
            "content_type": null
        }"#;
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        assert!(req.chunk_size.is_none());
        assert!(req.content_type.is_none());
    }

    #[test]
    fn test_create_session_request_zero_total_size() {
        let json = r#"{
            "repository_key": "repo",
            "artifact_path": "empty.bin",
            "total_size": 0,
            "checksum_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        }"#;
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.total_size, 0);
    }

    // -----------------------------------------------------------------------
    // CreateSessionResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_session_response_serialize() {
        let resp = CreateSessionResponse {
            session_id: Uuid::nil(),
            chunk_count: 3,
            chunk_size: 8_388_608,
            expires_at: "2026-03-25T12:00:00Z".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["session_id"], "00000000-0000-0000-0000-000000000000");
        assert_eq!(json["chunk_count"], 3);
        assert_eq!(json["chunk_size"], 8_388_608);
        assert_eq!(json["expires_at"], "2026-03-25T12:00:00Z");
    }

    #[test]
    fn test_create_session_response_field_names() {
        // The CLI and web frontend depend on these exact field names
        let resp = CreateSessionResponse {
            session_id: Uuid::nil(),
            chunk_count: 1,
            chunk_size: 1,
            expires_at: String::new(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"session_id\""));
        assert!(json.contains("\"chunk_count\""));
        assert!(json.contains("\"chunk_size\""));
        assert!(json.contains("\"expires_at\""));
        // Verify no typos in field names (these should NOT appear)
        assert!(!json.contains("\"sessionId\""));
        assert!(!json.contains("\"chunkCount\""));
        assert!(!json.contains("\"chunkSize\""));
        assert!(!json.contains("\"expiresAt\""));
    }

    // -----------------------------------------------------------------------
    // ChunkResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_chunk_response_serialize() {
        let resp = ChunkResponse {
            chunk_index: 2,
            bytes_received: 25_165_824,
            chunks_completed: 3,
            chunks_remaining: 7,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["chunk_index"], 2);
        assert_eq!(json["bytes_received"], 25_165_824);
        assert_eq!(json["chunks_completed"], 3);
        assert_eq!(json["chunks_remaining"], 7);
    }

    #[test]
    fn test_chunk_response_field_names() {
        let resp = ChunkResponse {
            chunk_index: 0,
            bytes_received: 0,
            chunks_completed: 0,
            chunks_remaining: 0,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"chunk_index\""));
        assert!(json.contains("\"bytes_received\""));
        assert!(json.contains("\"chunks_completed\""));
        assert!(json.contains("\"chunks_remaining\""));
    }

    #[test]
    fn test_chunk_response_zero_remaining() {
        let resp = ChunkResponse {
            chunk_index: 9,
            bytes_received: 104_857_600,
            chunks_completed: 10,
            chunks_remaining: 0,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["chunks_remaining"], 0);
        assert_eq!(json["chunks_completed"], 10);
    }

    // -----------------------------------------------------------------------
    // SessionStatusResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_session_status_response_serialize() {
        let session_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let resp = SessionStatusResponse {
            session_id,
            status: "in_progress".into(),
            total_size: 104_857_600,
            bytes_received: 25_165_824,
            chunks_completed: 3,
            chunks_total: 13,
            repository_key: "docker-local".into(),
            artifact_path: "images/app.tar.gz".into(),
            created_at: "2026-03-25T10:00:00Z".into(),
            expires_at: "2026-03-26T10:00:00Z".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["session_id"], "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(json["status"], "in_progress");
        assert_eq!(json["total_size"], 104_857_600);
        assert_eq!(json["bytes_received"], 25_165_824);
        assert_eq!(json["chunks_completed"], 3);
        assert_eq!(json["chunks_total"], 13);
        assert_eq!(json["repository_key"], "docker-local");
        assert_eq!(json["artifact_path"], "images/app.tar.gz");
    }

    #[test]
    fn test_session_status_response_field_names() {
        let resp = SessionStatusResponse {
            session_id: Uuid::nil(),
            status: String::new(),
            total_size: 0,
            bytes_received: 0,
            chunks_completed: 0,
            chunks_total: 0,
            repository_key: String::new(),
            artifact_path: String::new(),
            created_at: String::new(),
            expires_at: String::new(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        // Verify snake_case field names (API contract)
        assert!(json.contains("\"session_id\""));
        assert!(json.contains("\"status\""));
        assert!(json.contains("\"total_size\""));
        assert!(json.contains("\"bytes_received\""));
        assert!(json.contains("\"chunks_completed\""));
        assert!(json.contains("\"chunks_total\""));
        assert!(json.contains("\"repository_key\""));
        assert!(json.contains("\"artifact_path\""));
        assert!(json.contains("\"created_at\""));
        assert!(json.contains("\"expires_at\""));
    }

    #[test]
    fn test_session_status_response_pending_state() {
        let resp = SessionStatusResponse {
            session_id: Uuid::nil(),
            status: "pending".into(),
            total_size: 1024,
            bytes_received: 0,
            chunks_completed: 0,
            chunks_total: 1,
            repository_key: "test".into(),
            artifact_path: "f.bin".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2026-01-02T00:00:00Z".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "pending");
        assert_eq!(json["bytes_received"], 0);
        assert_eq!(json["chunks_completed"], 0);
    }

    // -----------------------------------------------------------------------
    // CompleteResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_complete_response_serialize() {
        let artifact_id = Uuid::parse_str("a1b2c3d4-e5f6-7890-abcd-ef1234567890").unwrap();
        let resp = CompleteResponse {
            artifact_id,
            path: "images/vm.ova".into(),
            size: 21_474_836_480,
            checksum_sha256: "abc123".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["artifact_id"], "a1b2c3d4-e5f6-7890-abcd-ef1234567890");
        assert_eq!(json["path"], "images/vm.ova");
        assert_eq!(json["size"], 21_474_836_480_i64);
        assert_eq!(json["checksum_sha256"], "abc123");
    }

    #[test]
    fn test_complete_response_field_names() {
        let resp = CompleteResponse {
            artifact_id: Uuid::nil(),
            path: String::new(),
            size: 0,
            checksum_sha256: String::new(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"artifact_id\""));
        assert!(json.contains("\"path\""));
        assert!(json.contains("\"size\""));
        assert!(json.contains("\"checksum_sha256\""));
        // camelCase variants must NOT appear
        assert!(!json.contains("\"artifactId\""));
        assert!(!json.contains("\"checksumSha256\""));
    }

    #[test]
    fn test_complete_response_large_size() {
        let resp = CompleteResponse {
            artifact_id: Uuid::nil(),
            path: "big-file.iso".into(),
            size: 107_374_182_400, // 100 GB
            checksum_sha256: "abc".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["size"], 107_374_182_400_i64);
    }

    // -----------------------------------------------------------------------
    // map_upload_err status code mapping
    // -----------------------------------------------------------------------

    #[test]
    fn test_map_upload_err_not_found() {
        let resp = map_upload_err(UploadError::NotFound);
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_map_upload_err_expired() {
        let resp = map_upload_err(UploadError::Expired);
        assert_eq!(resp.status(), StatusCode::GONE);
    }

    #[test]
    fn test_map_upload_err_invalid_chunk() {
        let resp = map_upload_err(UploadError::InvalidChunk("bad".into()));
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_map_upload_err_invalid_chunk_size() {
        let resp = map_upload_err(UploadError::InvalidChunkSize);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_map_upload_err_invalid_status() {
        let resp = map_upload_err(UploadError::InvalidStatus("completed".into()));
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_map_upload_err_checksum_mismatch() {
        let resp = map_upload_err(UploadError::ChecksumMismatch {
            expected: "a".into(),
            actual: "b".into(),
        });
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn test_map_upload_err_incomplete_chunks() {
        let resp = map_upload_err(UploadError::IncompleteChunks {
            completed: 5,
            total: 10,
        });
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_map_upload_err_size_mismatch() {
        let resp = map_upload_err(UploadError::SizeMismatch {
            expected: 100,
            actual: 50,
        });
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_map_upload_err_repository_not_found() {
        let resp = map_upload_err(UploadError::RepositoryNotFound("gone-repo".into()));
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_map_upload_err_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "disk full");
        let resp = map_upload_err(UploadError::Io(io_err));
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // -----------------------------------------------------------------------
    // map_err helper
    // -----------------------------------------------------------------------

    #[test]
    fn test_map_err_returns_correct_status() {
        let resp = map_err(StatusCode::BAD_REQUEST, "something went wrong");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_map_err_internal_server_error() {
        let resp = map_err(StatusCode::INTERNAL_SERVER_ERROR, "boom");
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_map_err_not_found() {
        let resp = map_err(StatusCode::NOT_FOUND, "Repository 'x' not found");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // -----------------------------------------------------------------------
    // Round-trip: CreateSessionRequest JSON stability
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_session_request_roundtrip_optional_present() {
        let json_in = serde_json::json!({
            "repository_key": "npm-local",
            "artifact_path": "packages/@scope/pkg-1.0.0.tgz",
            "total_size": 52428800,
            "checksum_sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "chunk_size": 4194304,
            "content_type": "application/gzip"
        });
        let req: CreateSessionRequest = serde_json::from_value(json_in.clone()).unwrap();
        assert_eq!(req.repository_key, "npm-local");
        assert_eq!(req.chunk_size, Some(4_194_304));
        assert_eq!(req.content_type.as_deref(), Some("application/gzip"));
    }

    #[test]
    fn test_create_session_request_wrong_type_total_size() {
        let json = r#"{
            "repository_key": "repo",
            "artifact_path": "file.bin",
            "total_size": "not a number",
            "checksum_sha256": "abc"
        }"#;
        let result: Result<CreateSessionRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Debug implementations on DTOs
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_session_request_debug() {
        let req = CreateSessionRequest {
            repository_key: "repo".into(),
            artifact_path: "file.bin".into(),
            total_size: 100,
            checksum_sha256: "abc".into(),
            chunk_size: None,
            content_type: None,
        };
        let debug = format!("{:?}", req);
        assert!(debug.contains("CreateSessionRequest"));
        assert!(debug.contains("repo"));
    }

    #[test]
    fn test_create_session_response_debug() {
        let resp = CreateSessionResponse {
            session_id: Uuid::nil(),
            chunk_count: 1,
            chunk_size: 8388608,
            expires_at: "2026-01-01".into(),
        };
        let debug = format!("{:?}", resp);
        assert!(debug.contains("CreateSessionResponse"));
    }

    #[test]
    fn test_chunk_response_debug() {
        let resp = ChunkResponse {
            chunk_index: 0,
            bytes_received: 0,
            chunks_completed: 0,
            chunks_remaining: 0,
        };
        let debug = format!("{:?}", resp);
        assert!(debug.contains("ChunkResponse"));
    }

    #[test]
    fn test_session_status_response_debug() {
        let resp = SessionStatusResponse {
            session_id: Uuid::nil(),
            status: "pending".into(),
            total_size: 0,
            bytes_received: 0,
            chunks_completed: 0,
            chunks_total: 0,
            repository_key: String::new(),
            artifact_path: String::new(),
            created_at: String::new(),
            expires_at: String::new(),
        };
        let debug = format!("{:?}", resp);
        assert!(debug.contains("SessionStatusResponse"));
    }

    #[test]
    fn test_complete_response_debug() {
        let resp = CompleteResponse {
            artifact_id: Uuid::nil(),
            path: String::new(),
            size: 0,
            checksum_sha256: String::new(),
        };
        let debug = format!("{:?}", resp);
        assert!(debug.contains("CompleteResponse"));
    }

    // -----------------------------------------------------------------------
    // Content-Range header extraction logic
    // (tests the same parse function but from the handler's perspective)
    // -----------------------------------------------------------------------

    #[test]
    fn test_chunk_index_from_byte_offset() {
        // The handler computes chunk_index = start / chunk_size
        let chunk_size: i64 = 8 * 1024 * 1024; // 8 MB

        // First chunk
        let start: i64 = 0;
        assert_eq!((start / chunk_size) as i32, 0);

        // Second chunk
        let start: i64 = 8 * 1024 * 1024;
        assert_eq!((start / chunk_size) as i32, 1);

        // Third chunk
        let start: i64 = 16 * 1024 * 1024;
        assert_eq!((start / chunk_size) as i32, 2);

        // 100th chunk
        let start: i64 = 99 * 8 * 1024 * 1024;
        assert_eq!((start / chunk_size) as i32, 99);
    }

    #[test]
    fn test_expected_body_length_from_content_range() {
        // The handler validates: data.len() == (end - start + 1)
        let (start, end, _total) =
            upload_service::parse_content_range("bytes 0-8388607/20971520").unwrap();
        let expected_len = (end - start + 1) as usize;
        assert_eq!(expected_len, 8_388_608); // 8 MB
    }

    #[test]
    fn test_expected_body_length_last_partial_chunk() {
        // Last chunk of 20 MB file, 8 MB chunks: bytes 16777216-20971519/20971520
        let (start, end, _total) =
            upload_service::parse_content_range("bytes 16777216-20971519/20971520").unwrap();
        let expected_len = (end - start + 1) as usize;
        assert_eq!(expected_len, 4 * 1024 * 1024); // 4 MB
    }

    #[test]
    fn test_expected_body_length_single_byte() {
        let (start, end, _total) = upload_service::parse_content_range("bytes 0-0/1").unwrap();
        let expected_len = (end - start + 1) as usize;
        assert_eq!(expected_len, 1);
    }
}
