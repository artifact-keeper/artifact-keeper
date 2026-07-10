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

use crate::api::handlers::proxy_helpers;
use crate::api::handlers::repositories::require_repo_write_access;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::services::package_service::PackageService;
use crate::services::repository_service::RepositoryService;
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
    /// Artifact name to persist when the upload completes.
    ///
    /// Optional for regular client uploads. Peer replication sets this from
    /// the source artifact row so chunked replication preserves metadata.
    pub artifact_name: Option<String>,
    /// Artifact version to persist when the upload completes.
    ///
    /// Optional for regular client uploads. Peer replication sets this from
    /// the source artifact row so chunked replication preserves metadata.
    pub artifact_version: Option<String>,
    /// Source artifact metadata format for peer replication.
    pub artifact_metadata_format: Option<String>,
    /// Source artifact metadata for peer replication.
    pub artifact_metadata: Option<serde_json::Value>,
    /// Source artifact metadata properties for peer replication.
    pub artifact_metadata_properties: Option<serde_json::Value>,
    /// Source package description for peer replication.
    pub package_description: Option<String>,
    /// Source package catalog metadata for peer replication.
    pub package_metadata: Option<serde_json::Value>,
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

/// Pure write-authorization decision for creating a chunked-upload session.
///
/// Mirrors the semantics `repo_visibility_middleware` enforces on every other
/// repository write path, so the body-addressed `/uploads` flow is gated the
/// same way the URL-addressed legacy artifact PUT is:
///
/// * **Token repo-scope (#504):** an API token restricted to a set of repos
///   (`auth.can_access_repo`) may only target a repo in that set.
/// * **Admin bypass:** admins skip the fine-grained checks entirely.
/// * **No-rules fall-through:** a repo with no fine-grained permission rules
///   keeps working under the default access model (`has_rules == false`).
/// * **Fine-grained write (#817):** when rules exist, the caller must hold the
///   `write` (or `admin`) action on the repo.
///
/// The permission-service lookups that produce `has_rules`/`has_write`/
/// `has_admin` are done by the caller; keeping the decision pure makes it
/// unit-testable without a database.
fn session_write_authorized(
    auth: &AuthExtension,
    repo_id: Uuid,
    has_rules: bool,
    has_write: bool,
    has_admin: bool,
) -> bool {
    // #504: token repository scope.
    if !auth.can_access_repo(repo_id) {
        return false;
    }
    // Admins bypass fine-grained permission checks.
    if auth.is_admin {
        return true;
    }
    // No fine-grained rules: fall through to the default access model.
    if !has_rules {
        return true;
    }
    // Rules exist: the caller must hold write (or admin) on this repo.
    has_write || has_admin
}

#[utoipa::path(
    post,
    path = "/api/v1/uploads",
    tag = "uploads",
    request_body = CreateSessionRequest,
    responses(
        (status = 201, description = "Upload session created", body = CreateSessionResponse),
        (status = 400, description = "Invalid request", body = crate::api::openapi::ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Repository not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn create_session(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    headers: HeaderMap,
    Json(req): Json<CreateSessionRequest>,
) -> Result<Response, Response> {
    let user_id = auth.user_id;

    // Validate artifact path before doing anything else
    upload_service::validate_artifact_path(&req.artifact_path).map_err(map_upload_err)?;

    // Resolve repository. The `repositories` table has no `is_deleted` column
    // (the soft-delete pattern lives on `artifacts`); the previous
    // `AND is_deleted = false` predicate was a copy-paste from artifact
    // queries that crashed every session create (issue #1168).
    let repo = sqlx::query_as::<_, (Uuid, bool)>(
        "SELECT id, promotion_only FROM repositories WHERE key = $1",
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
    let repo_id = repo.0;
    let repo_promotion_only = repo.1;

    // Tenant write gate (xtenant-write-authz-systemic).
    //
    // The /uploads router runs under auth_middleware only (no
    // repo_visibility_middleware), and the target repo is named in the JSON body,
    // so the tenant-membership gate that protects the URL-addressed artifact PUT
    // never sees this request. The fine-grained RBAC checks below fall OPEN when
    // a repo has no permission rules (`has_rules == false`), so derive the tenant
    // boundary from `is_public` + role_assignments membership
    // (`require_repo_write_access`): a non-member, non-admin can never open a
    // session against another tenant's private repo regardless of whether any
    // permission rule exists. Admins, public-repo writers, same-org members and
    // write/admin-holding peer-replication identities all pass unchanged. Mirrors
    // `repositories::upload_artifact`.
    let repo_service = RepositoryService::new(state.db.clone());
    let repo_record = repo_service
        .get_by_key(&req.repository_key)
        .await
        .map_err(IntoResponse::into_response)?;
    require_repo_write_access(&auth, &repo_record, &repo_service)
        .await
        .map_err(IntoResponse::into_response)?;

    // Promotion-only gate (#817 parity with the direct upload path).
    //
    // A `promotion_only` repository accepts artifacts ONLY via the promotion
    // path (staging -> promotion -> approval). The direct artifact-write handler
    // (`repositories::upload_artifact`) already rejects non-admin direct uploads
    // to such repos; the chunked upload-session API is another direct-write entry
    // point and must enforce the SAME gate, otherwise a non-admin can sidestep
    // promotion/approval by opening a session against a release repo.
    //
    // This is enforced INDEPENDENTLY of the RBAC permission-rule check below: a
    // promotion_only repo with no explicit permission rules must still be blocked
    // for direct uploads. The promotion service writes through its own RAW SQL
    // INSERT path (handlers/promotion.rs), which does not pass through these HTTP
    // handlers, so promotions remain unaffected. All direct uploads (including
    // admins) are blocked, matching the direct path.
    if let Some(rejection) = reject_session_if_promotion_only(repo_promotion_only, auth.is_admin) {
        return Err(rejection);
    }

    // Repository write authorization (#817 parity).
    //
    // The chunked upload-session create path must enforce the same
    // fine-grained RBAC write gate that `repo_visibility_middleware` applies to
    // the rest of the artifact-write surface (see middleware/auth.rs): the
    // /api/v1/uploads router is layered only with `auth_middleware`
    // (authentication), so without this check any authenticated user could open
    // a session against a release/promotion-only repository.
    //
    // Admins bypass the check. For a non-admin, if any permission rule exists
    // for this repository the caller must hold the `write` action (or `admin`,
    // which implies all actions); a repository with no rules falls through
    // unchanged. A DB error on the rule lookup fails closed (503), mirroring the
    // middleware. Authorized peer-replication identities hold write/admin on the
    // target and continue to pass.
    let has_rules = if auth.is_admin {
        false
    } else {
        match state
            .permission_service
            .has_any_rules_for_target("repository", repo_id)
            .await
        {
            Ok(v) => v,
            Err(_) => {
                tracing::error!("permission check failed: database unreachable");
                return Err(map_err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "permission service temporarily unavailable",
                ));
            }
        }
    };
    let (has_write, has_admin) = if !auth.is_admin && has_rules {
        (
            state
                .permission_service
                .check_permission(user_id, "repository", repo_id, "write", false)
                .await
                .unwrap_or(false),
            state
                .permission_service
                .check_permission(user_id, "repository", repo_id, "admin", false)
                .await
                .unwrap_or(false),
        )
    } else {
        (false, false)
    };
    if !upload_write_decision(auth.is_admin, has_rules, has_write, has_admin) {
        return Err(map_err(
            StatusCode::FORBIDDEN,
            "You do not have permission to perform this action on this repository",
        ));
    }

    // Repository write authorization.
    //
    // The `/uploads` routes are nested under `auth_middleware` only, not
    // `repo_visibility_middleware`, and the target repo is named in the JSON
    // body rather than the URL path -- so the repo-scope (#504) and
    // fine-grained permission (#817) gates that protect every other write
    // path never see this request. Apply the same decision here, at the single
    // point where the cross-tenant write would originate, right after the repo
    // is resolved (the 404-for-unknown-repo behaviour above is unchanged).
    //
    // Only consult the permission service for a non-admin caller that is in
    // token scope for the repo; admins bypass and out-of-scope tokens are
    // denied without a DB round-trip. Fail closed (503) on a permission lookup
    // error, matching `repo_visibility_middleware`.
    let (has_rules, has_write, has_admin) = if auth.is_admin || !auth.can_access_repo(repo.0) {
        (false, false, false)
    } else {
        let has_rules = state
            .permission_service
            .has_any_rules_for_target("repository", repo.0)
            .await
            .map_err(|_| {
                tracing::error!("permission check failed: database unreachable");
                map_err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "permission service temporarily unavailable",
                )
            })?;
        if has_rules {
            let has_write = state
                .permission_service
                .check_permission(auth.user_id, "repository", repo.0, "write", false)
                .await
                .unwrap_or(false);
            let has_admin = state
                .permission_service
                .check_permission(auth.user_id, "repository", repo.0, "admin", false)
                .await
                .unwrap_or(false);
            (true, has_write, has_admin)
        } else {
            (false, false, false)
        }
    };

    if !session_write_authorized(&auth, repo.0, has_rules, has_write, has_admin) {
        return Err(map_err(
            StatusCode::FORBIDDEN,
            "You do not have permission to perform this action on this repository",
        ));
    }

    let is_replication = super::is_replication_request(&headers);
    let replication_metadata = replication_session_metadata_from_request(&headers, &req);

    if is_replication {
        cleanup_stale_replication_upload_sessions(&state.db, repo.0, &req.artifact_path).await;
    }

    // Repository storage-quota gate (parity with the direct artifact-write
    // path, `ArtifactService::store` -> `RepositoryService::check_quota`). The
    // chunked upload-session API is another direct-write entry point: without
    // this check an attacker-chosen `total_size` would both bypass the quota
    // and drive one DB row per chunk. Skipped for peer replication so artifacts
    // that legitimately predate a quota change can still replicate; the
    // `max_upload_size` cap inside `create_session` still applies in that case.
    if !is_replication {
        let within_quota = state
            .create_repository_service()
            .check_quota(repo_id, req.total_size)
            .await
            .map_err(|e| map_err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        if !within_quota {
            return Err(map_err(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Repository storage quota exceeded",
            ));
        }
    }

    let session = UploadService::create_session(upload_service::CreateSessionParams {
        db: &state.db,
        storage_path: &state.config.storage_path,
        user_id,
        repo_id,
        repo_key: &req.repository_key,
        artifact_path: &req.artifact_path,
        artifact_name: req.artifact_name.as_deref(),
        artifact_version: req.artifact_version.as_deref(),
        artifact_metadata_format: replication_metadata.artifact_metadata_format,
        artifact_metadata: replication_metadata.artifact_metadata,
        artifact_metadata_properties: replication_metadata.artifact_metadata_properties,
        package_description: replication_metadata.package_description,
        package_metadata: replication_metadata.package_metadata,
        is_replication,
        total_size: req.total_size,
        max_upload_size: state.config.max_upload_size_bytes,
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
    let user_id = auth.user_id;

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

    // C3: get_session now verifies user ownership
    let session = UploadService::get_session(&state.db, session_id, Some(user_id))
        .await
        .map_err(map_upload_err)?;

    let chunk_index = (start / session.chunk_size as i64) as i32;

    // C2: Stream body directly to a temp buffer with a size cap matching the
    // declared Content-Range length. This prevents unbounded memory growth.
    let expected_len = (end - start + 1) as usize;
    let mut data = Vec::with_capacity(expected_len.min(256 * 1024 * 1024));
    let mut stream = body.into_data_stream();
    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(|e| {
            map_err(
                StatusCode::BAD_REQUEST,
                format!("Error reading body: {}", e),
            )
        })?;
        data.extend_from_slice(&chunk);
        // Bail early if client sends more data than declared
        if data.len() > expected_len {
            return Err(map_err(
                StatusCode::BAD_REQUEST,
                format!(
                    "Body exceeds declared Content-Range length of {} bytes",
                    expected_len
                ),
            ));
        }
    }

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
        user_id,
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
    let user_id = auth.user_id;

    // C3: Verify user owns this session
    let session = UploadService::get_session(&state.db, session_id, Some(user_id))
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
    headers: HeaderMap,
    Path(session_id): Path<Uuid>,
) -> Result<Response, Response> {
    let user_id = auth.user_id;
    let is_replication_request = super::is_replication_request(&headers);

    // C3: Verify user owns this session
    let session = UploadService::complete_session(&state.db, session_id, user_id)
        .await
        .map_err(map_upload_err)?;

    // Resolve the *repo-scoped* storage backend and use a content-addressable
    // key, matching how non-chunked uploads work (issue #1168 part 3).
    //
    // Before this fix, the handler wrote via `state.storage` (the global
    // default backend, no repo path prefix) to `uploads/<repo_id>/<path>`,
    // while download_artifact resolves via `state.storage_for_repo(...)`
    // which prepends `<repo.storage_path>/`. The two paths never lined up,
    // so a 200 OK chunked upload produced a 404 on first download. Using
    // the content-addressable scheme (`<hash[:2]>/<hash[2:4]>/<full-hash>`)
    // also matches `ArtifactService::storage_key_from_checksum` so future
    // dedup, GC, and replication paths see the upload like any other write.
    let storage_key = crate::services::artifact_service::ArtifactService::storage_key_from_checksum(
        &session.checksum_sha256,
    );

    let repo = crate::services::repository_service::RepositoryService::new(state.db.clone())
        .get_by_id(session.repository_id)
        .await
        .map_err(|e| map_err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| map_err(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let temp_path = std::path::PathBuf::from(&session.temp_file_path);

    // C1: Use put_file to stream from disk instead of reading the entire file
    // into memory. The default implementation still reads into memory, but
    // backends can override for true streaming (S3 multipart, etc.).
    storage
        .put_file(&storage_key, &temp_path)
        .await
        .map_err(|e| map_err(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    // Clean up temp file
    let _ = tokio::fs::remove_file(&temp_path).await;

    // Create artifact record
    let artifact_name = completed_artifact_name(&session);
    // #1975 (stopgap for #1846): chunked uploads to FORMAT repositories must
    // carry a non-empty `version`, otherwise format index generators that key on
    // `version` silently drop the artifact (e.g. incus `streams_images` skips any
    // row with `version IS NULL`, so a chunked-uploaded image never appears in
    // `images.json`). Single-shot/format-native uploads always set a version; the
    // generic chunked path only set it from the optional create-session field.
    // For a format repo with no explicit version, derive one from the artifact
    // path so the artifact remains retrievable with correct coordinates. Generic
    // repositories keep their existing behaviour (version may be NULL).
    let derived_version = completed_format_artifact_version(&session, &repo.format);
    let artifact_version = derived_version.as_deref();
    let artifact_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO artifacts (repository_id, path, name, version, size_bytes,
                               checksum_sha256, content_type, storage_key, uploaded_by)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (repository_id, path) DO UPDATE SET
            name = $3, version = $4, size_bytes = $5, checksum_sha256 = $6,
            content_type = $7, storage_key = $8, uploaded_by = $9,
            updated_at = NOW(), is_deleted = false
        RETURNING id
        "#,
    )
    .bind(session.repository_id)
    .bind(&session.artifact_path)
    .bind(artifact_name)
    .bind(artifact_version)
    .bind(session.total_size)
    .bind(&session.checksum_sha256)
    .bind(&session.content_type)
    .bind(&storage_key)
    .bind(user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| map_err(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    if let (Some(format), Some(metadata)) = (
        session.artifact_metadata_format.as_deref(),
        session.artifact_metadata.clone(),
    ) {
        let properties = session
            .artifact_metadata_properties
            .clone()
            .unwrap_or_else(|| serde_json::json!({}));
        let artifact_service = state.create_artifact_service(storage.clone());
        artifact_service
            .set_metadata(artifact_id, format, metadata, properties)
            .await
            .map_err(|e| map_err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    }

    if let Some((package_name, package_version)) = completed_package_catalog_entry(&session) {
        PackageService::new(state.db.clone())
            .try_create_or_update_from_artifact(
                session.repository_id,
                &package_name,
                package_version,
                session.total_size,
                &session.checksum_sha256,
                completed_package_description(&session),
                completed_package_metadata(&session),
            )
            .await;
    }

    tracing::info!(
        "Finalized chunked upload {} -> artifact {} ({}B, sha256:{})",
        session_id,
        artifact_id,
        session.total_size,
        &session.checksum_sha256[..12.min(session.checksum_sha256.len())]
    );

    if is_replication_request || session.is_replication {
        cleanup_completed_upload_session(&state.db, session_id).await;
    }

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
    let user_id = auth.user_id;

    // C3: Verify user owns this session
    UploadService::cancel_session(&state.db, session_id, user_id)
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
        // A duplicate PATCH for a chunk another request is actively uploading:
        // a transient, retriable condition, not a client error (#2316).
        UploadError::ChunkInProgress(_) => (StatusCode::CONFLICT, e.to_string()),
        UploadError::InvalidChunkSize => (StatusCode::BAD_REQUEST, e.to_string()),
        UploadError::TooLarge { .. } => (StatusCode::PAYLOAD_TOO_LARGE, e.to_string()),
        UploadError::PathTooLong { .. } => (StatusCode::BAD_REQUEST, e.to_string()),
        UploadError::InvalidStatus(_) => (StatusCode::BAD_REQUEST, e.to_string()),
        UploadError::ChecksumMismatch { .. } => (StatusCode::CONFLICT, e.to_string()),
        UploadError::IncompleteChunks { .. } => (StatusCode::BAD_REQUEST, e.to_string()),
        UploadError::SizeMismatch { .. } => (StatusCode::BAD_REQUEST, e.to_string()),
        UploadError::RepositoryNotFound(_) => (StatusCode::NOT_FOUND, e.to_string()),
        UploadError::Database(msg) => (
            crate::api::handlers::db_status(msg),
            "Database error".into(),
        ),
        UploadError::Io(_) => (StatusCode::INTERNAL_SERVER_ERROR, "I/O error".into()),
    };

    super::with_retry_after_on_503(
        (status, axum::Json(serde_json::json!({"error": msg}))).into_response(),
    )
}

/// Map any displayable error to an HTTP error response.
fn map_err(status: StatusCode, e: impl std::fmt::Display) -> Response {
    (
        status,
        axum::Json(serde_json::json!({"error": e.to_string()})),
    )
        .into_response()
}

/// Pure authorization decision for chunked upload-session creation, mirroring
/// the non-admin RBAC write gate enforced by `repo_visibility_middleware`.
///
/// - Admins always pass (any rules state).
/// - Non-admins on a repository with no permission rules fall through (allowed).
/// - Non-admins on a rules-bearing repository must hold the `write` action or
///   the `admin` action (which implies all actions).
fn upload_write_decision(
    is_admin: bool,
    has_rules: bool,
    has_write: bool,
    has_admin: bool,
) -> bool {
    if is_admin {
        return true;
    }
    if !has_rules {
        return true;
    }
    has_write || has_admin
}

/// Build the rejection for a direct upload-session create against a
/// `promotion_only` repository, or `None` if the upload is permitted.
///
/// Mirrors the direct artifact-write path (`repositories::upload_artifact`):
/// direct uploads to a promotion-only repo are blocked (`403`) so the chunked
/// upload-session API cannot be used to sidestep promotion/approval. All direct
/// uploads (including admin tokens) are blocked; normal (non-promotion_only)
/// repositories are never blocked here. The promotion service writes through its
/// own raw-SQL path and does not pass through this handler, so promotions are
/// unaffected.
fn reject_session_if_promotion_only(promotion_only: bool, is_admin: bool) -> Option<Response> {
    if proxy_helpers::promotion_only_blocks_direct_upload(promotion_only, is_admin) {
        Some(map_err(
            StatusCode::FORBIDDEN,
            "Direct uploads are disabled for this repository; publish via promotion",
        ))
    } else {
        None
    }
}

/// Extract a simple artifact name from its path (last path component without extension).
fn artifact_name_from_path(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn completed_artifact_name(session: &upload_service::UploadSession) -> &str {
    session
        .artifact_name
        .as_deref()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| artifact_name_from_path(&session.artifact_path))
}

fn completed_artifact_version(session: &upload_service::UploadSession) -> Option<&str> {
    session
        .artifact_version
        .as_deref()
        .filter(|version| !version.is_empty())
}

/// Whether a repository format requires a non-empty artifact `version` for the
/// artifact to surface correctly through its format index/read paths.
///
/// Generic repositories serve artifacts by raw path and never key on `version`,
/// so they keep the legacy chunked-upload behaviour (version may be NULL). Every
/// other (format-native) repository runs a finalizer/index generator that keys
/// on `version`; a NULL there silently drops the artifact (#1975 / #1846).
fn format_repo_requires_version(format: &crate::models::repository::RepositoryFormat) -> bool {
    !matches!(format, crate::models::repository::RepositoryFormat::Generic)
}

/// Derive a version segment from an artifact path laid out as
/// `<product>/<version>/<filename>` (the shape the format-native paths build,
/// e.g. incus `build_artifact_path`). Returns the middle segment when the path
/// has at least three non-empty components, otherwise `None`.
fn version_from_artifact_path(path: &str) -> Option<&str> {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if segments.len() >= 3 {
        // second-to-last segment is the version in `<product>/<version>/<file>`
        segments.get(segments.len() - 2).copied()
    } else {
        None
    }
}

/// Resolve the `version` to persist for a completed chunked upload, accounting
/// for the target repository format (#1975, stopgap for #1846).
///
/// * Generic repositories keep the existing behaviour: the explicit
///   create-session `artifact_version` (or `None`).
/// * Format repositories must not persist a NULL/empty version (their index
///   generators drop such rows). Prefer the explicit create-session version;
///   otherwise derive it from the `<product>/<version>/<filename>` path layout;
///   as a last resort fall back to the upload checksum prefix so the artifact is
///   still retrievable with stable, non-null coordinates instead of being
///   silently dropped.
fn completed_format_artifact_version(
    session: &upload_service::UploadSession,
    format: &crate::models::repository::RepositoryFormat,
) -> Option<String> {
    if let Some(explicit) = completed_artifact_version(session) {
        return Some(explicit.to_string());
    }
    if !format_repo_requires_version(format) {
        return None;
    }
    if let Some(derived) = version_from_artifact_path(&session.artifact_path) {
        return Some(derived.to_string());
    }
    // Deterministic, non-empty fallback so the row is never dropped.
    let checksum = &session.checksum_sha256;
    let suffix = &checksum[..12.min(checksum.len())];
    Some(format!("sha256-{}", suffix))
}

fn replicated_maven_artifact_metadata(
    session: &upload_service::UploadSession,
) -> Option<&serde_json::Value> {
    match session.artifact_metadata_format.as_deref() {
        Some(format) if format.eq_ignore_ascii_case("maven") => session.artifact_metadata.as_ref(),
        _ => None,
    }
}

fn maven_package_name_from_metadata(metadata: &serde_json::Value) -> Option<String> {
    let group_id = metadata.get("groupId")?.as_str()?.trim();
    let artifact_id = metadata.get("artifactId")?.as_str()?.trim();
    if group_id.is_empty() || artifact_id.is_empty() {
        return None;
    }
    Some(format!("{group_id}:{artifact_id}"))
}

fn replicated_maven_artifact_is_pom(session: &upload_service::UploadSession) -> bool {
    let metadata_extension_is_pom = replicated_maven_artifact_metadata(session)
        .and_then(|metadata| metadata.get("extension"))
        .and_then(|extension| extension.as_str())
        .map(|extension| extension.eq_ignore_ascii_case("pom"))
        .unwrap_or(false);

    metadata_extension_is_pom || session.artifact_path.ends_with(".pom")
}

fn maven_package_metadata_from_artifact_metadata(
    session: &upload_service::UploadSession,
) -> Option<serde_json::Value> {
    if !replicated_maven_artifact_is_pom(session) {
        return None;
    }

    let metadata = replicated_maven_artifact_metadata(session)?;
    let group_id = metadata.get("groupId")?.as_str()?.trim();
    let artifact_id = metadata.get("artifactId")?.as_str()?.trim();
    if group_id.is_empty() || artifact_id.is_empty() {
        return None;
    }

    let mut catalog = serde_json::json!({
        "format": "maven",
        "groupId": group_id,
        "artifactId": artifact_id,
    });

    for key in ["name", "description", "url", "dependencies"] {
        if let Some(value) = metadata.get(key) {
            catalog[key] = value.clone();
        }
    }

    Some(catalog)
}

fn completed_package_catalog_entry(
    session: &upload_service::UploadSession,
) -> Option<(String, &str)> {
    let version = completed_artifact_version(session)?;
    let name = replicated_maven_artifact_metadata(session)
        .and_then(maven_package_name_from_metadata)
        .unwrap_or_else(|| completed_artifact_name(session).to_string());
    Some((name, version))
}

fn completed_package_description(session: &upload_service::UploadSession) -> Option<&str> {
    session.package_description.as_deref().or_else(|| {
        if !replicated_maven_artifact_is_pom(session) {
            return None;
        }
        replicated_maven_artifact_metadata(session)?
            .get("description")?
            .as_str()
    })
}

fn completed_package_metadata(
    session: &upload_service::UploadSession,
) -> Option<serde_json::Value> {
    session
        .package_metadata
        .clone()
        .or_else(|| maven_package_metadata_from_artifact_metadata(session))
}

async fn cleanup_completed_upload_session(db: &sqlx::PgPool, session_id: Uuid) {
    match sqlx::query("DELETE FROM upload_sessions WHERE id = $1 AND status = 'completed'")
        .bind(session_id)
        .execute(db)
        .await
    {
        Ok(result) if result.rows_affected() == 0 => {
            tracing::warn!(
                %session_id,
                "Completed upload session cleanup did not remove a row"
            );
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(
                %session_id,
                error = %e,
                "Failed to clean up completed upload session"
            );
        }
    }
}

async fn cleanup_stale_replication_upload_sessions(
    db: &sqlx::PgPool,
    repository_id: Uuid,
    artifact_path: &str,
) {
    let stale = match sqlx::query_as::<_, (Uuid, String)>(
        r#"
        DELETE FROM upload_sessions
        WHERE repository_id = $1
          AND artifact_path = $2
          AND is_replication = true
        RETURNING id, temp_file_path
        "#,
    )
    .bind(repository_id)
    .bind(artifact_path)
    .fetch_all(db)
    .await
    {
        Ok(stale) => stale,
        Err(e) => {
            tracing::warn!(
                %repository_id,
                artifact_path = %artifact_path,
                error = %e,
                "Failed to clean up stale replication upload sessions"
            );
            return;
        }
    };

    for (session_id, temp_file_path) in &stale {
        let _ = tokio::fs::remove_file(temp_file_path).await;
        tracing::info!(
            %session_id,
            %repository_id,
            artifact_path = %artifact_path,
            "Removed stale replication upload session before retry"
        );
    }
}

struct ReplicationSessionMetadata<'a> {
    artifact_metadata_format: Option<&'a str>,
    artifact_metadata: Option<&'a serde_json::Value>,
    artifact_metadata_properties: Option<&'a serde_json::Value>,
    package_description: Option<&'a str>,
    package_metadata: Option<&'a serde_json::Value>,
}

fn replication_session_metadata_from_request<'a>(
    headers: &HeaderMap,
    req: &'a CreateSessionRequest,
) -> ReplicationSessionMetadata<'a> {
    if !super::is_replication_request(headers) {
        return ReplicationSessionMetadata {
            artifact_metadata_format: None,
            artifact_metadata: None,
            artifact_metadata_properties: None,
            package_description: None,
            package_metadata: None,
        };
    }

    ReplicationSessionMetadata {
        artifact_metadata_format: req.artifact_metadata_format.as_deref(),
        artifact_metadata: req.artifact_metadata.as_ref(),
        artifact_metadata_properties: req.artifact_metadata_properties.as_ref(),
        package_description: req.package_description.as_deref(),
        package_metadata: req.package_metadata.as_ref(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
// streaming-invariant: test module exempt — buffering response bodies in test assertions is not an artifact path (#1608)
#[allow(clippy::io_other_error, clippy::unnecessary_literal_unwrap)]
mod tests {
    use super::*;

    /// Cross-tenant authz guard (xtenant-write-authz-systemic). `session_write_authorized`
    /// (and `upload_write_decision`) fall OPEN when the target repo has no
    /// fine-grained permission rules (`!has_rules`), so `create_session` must
    /// ALSO enforce the rule-independent tenant gate `require_repo_write_access`
    /// (is_public + role_assignments membership). String-grep because the handler
    /// needs a real DB to run.
    #[test]
    fn test_create_session_enforces_tenant_gate() {
        let source = include_str!("upload.rs");
        let start = source
            .find("async fn create_session(")
            .expect("create_session not found");
        let rest = &source[start..];
        let end = rest.find("\nasync fn ").unwrap_or(rest.len());
        assert!(
            rest[..end].contains("require_repo_write_access("),
            "create_session must call require_repo_write_access independent of \
             fine-grained rule existence (xtenant)"
        );
    }

    // -----------------------------------------------------------------------
    // session_write_authorized (pure write-authorization decision)
    // -----------------------------------------------------------------------

    /// Build an `AuthExtension` for the pure-helper tests. `allowed` is the
    /// token repo-scope (`None` = unrestricted, matching a JWT login).
    fn auth_for(is_admin: bool, allowed: Option<Vec<Uuid>>) -> AuthExtension {
        AuthExtension {
            user_id: Uuid::new_v4(),
            username: "tester".to_string(),
            email: "tester@example.test".to_string(),
            is_admin,
            is_api_token: allowed.is_some(),
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: crate::models::access_scope::AccessScope::from(allowed),
            iat_ms: None,
        }
    }

    #[test]
    fn session_write_authorized_denies_token_scoped_out() {
        let repo = Uuid::new_v4();
        let other = Uuid::new_v4();
        // Token restricted to a different repo: denied before any rule check.
        let auth = auth_for(false, Some(vec![other]));
        assert!(!session_write_authorized(&auth, repo, false, false, false));
        // Even an admin token is bound by its repo scope.
        let admin = auth_for(true, Some(vec![other]));
        assert!(!session_write_authorized(&admin, repo, false, false, false));
    }

    #[test]
    fn session_write_authorized_allows_admin() {
        let repo = Uuid::new_v4();
        let auth = auth_for(true, None);
        // Admin bypasses fine-grained rules even when the user holds nothing.
        assert!(session_write_authorized(&auth, repo, true, false, false));
    }

    #[test]
    fn session_write_authorized_allows_when_no_rules() {
        let repo = Uuid::new_v4();
        let auth = auth_for(false, None);
        // No fine-grained rules -> default access model (fall-through).
        assert!(session_write_authorized(&auth, repo, false, false, false));
    }

    #[test]
    fn session_write_authorized_allows_with_write_grant() {
        let repo = Uuid::new_v4();
        let auth = auth_for(false, None);
        assert!(session_write_authorized(&auth, repo, true, true, false));
    }

    #[test]
    fn session_write_authorized_allows_with_admin_action() {
        let repo = Uuid::new_v4();
        let auth = auth_for(false, None);
        assert!(session_write_authorized(&auth, repo, true, false, true));
    }

    #[test]
    fn session_write_authorized_denies_rules_without_grant() {
        let repo = Uuid::new_v4();
        let auth = auth_for(false, None);
        // Rules exist but the user holds neither write nor admin: denied.
        assert!(!session_write_authorized(&auth, repo, true, false, false));
    }

    // -----------------------------------------------------------------------
    // artifact_name_from_path
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // upload_write_decision (#817 parity with repo_visibility_middleware)
    // -----------------------------------------------------------------------

    #[test]
    fn test_upload_write_decision_admin_always_allowed() {
        // Admins bypass the check regardless of rules/actions.
        assert!(upload_write_decision(true, false, false, false));
        assert!(upload_write_decision(true, true, false, false));
        assert!(upload_write_decision(true, true, true, true));
    }

    #[test]
    fn test_upload_write_decision_non_admin_no_rules_allowed() {
        // A repository with no permission rules falls through unchanged.
        assert!(upload_write_decision(false, false, false, false));
    }

    #[test]
    fn test_upload_write_decision_non_admin_rules_with_write_allowed() {
        assert!(upload_write_decision(false, true, true, false));
    }

    #[test]
    fn test_upload_write_decision_non_admin_rules_with_admin_action_allowed() {
        // The `admin` action implies all actions (including write).
        assert!(upload_write_decision(false, true, false, true));
    }

    #[test]
    fn test_upload_write_decision_non_admin_rules_neither_denied() {
        // Release/promotion-only repo: rules exist but caller holds neither
        // write nor admin -> denied.
        assert!(!upload_write_decision(false, true, false, false));
    }

    // -----------------------------------------------------------------------
    // reject_session_if_promotion_only (#817 parity with direct upload path)
    // -----------------------------------------------------------------------

    #[test]
    fn test_promotion_only_session_blocks_non_admin() {
        // Non-admin opening a session against a promotion_only repo is rejected
        // with 403, mirroring the direct upload path. This is the re-attack:
        // a promotion_only release repo with NO permission rules must still be
        // blocked, independent of the RBAC permission-rule check.
        let rejection = reject_session_if_promotion_only(true, false)
            .expect("non-admin direct upload session to promotion_only repo must be rejected");
        assert_eq!(rejection.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_promotion_only_session_blocks_admin_too() {
        // Admins are no longer exempt: an upload-session create against a
        // promotion_only repo is rejected (403) regardless of admin status.
        let rejection = reject_session_if_promotion_only(true, true)
            .expect("admin direct upload session to promotion_only repo must be rejected");
        assert_eq!(rejection.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_promotion_only_session_normal_repo_allowed() {
        // A normal (non-promotion_only) repo is never blocked here -> no
        // regression for legitimate uploads by either non-admins or admins.
        assert!(reject_session_if_promotion_only(false, false).is_none());
        assert!(reject_session_if_promotion_only(false, true).is_none());
    }

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

    fn test_upload_session(
        path: &str,
        name: Option<&str>,
        version: Option<&str>,
    ) -> upload_service::UploadSession {
        upload_service::UploadSession {
            id: Uuid::nil(),
            user_id: Uuid::nil(),
            repository_id: Uuid::nil(),
            repository_key: "repo".to_string(),
            artifact_path: path.to_string(),
            artifact_name: name.map(str::to_string),
            artifact_version: version.map(str::to_string),
            artifact_metadata_format: None,
            artifact_metadata: None,
            artifact_metadata_properties: None,
            package_description: None,
            package_metadata: None,
            is_replication: false,
            content_type: "application/octet-stream".to_string(),
            total_size: 1,
            chunk_size: 1_048_576,
            total_chunks: 1,
            completed_chunks: 1,
            bytes_received: 1,
            checksum_sha256: "deadbeef".to_string(),
            temp_file_path: "/tmp/upload-session".to_string(),
            status: "completed".to_string(),
            error_message: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_completed_artifact_metadata_prefers_session_metadata() {
        let session = test_upload_session(
            "name-check/20260603T072902Z/large-160m.bin",
            Some("name-check"),
            Some("20260603T072902Z"),
        );

        assert_eq!(completed_artifact_name(&session), "name-check");
        assert_eq!(
            completed_artifact_version(&session),
            Some("20260603T072902Z")
        );
    }

    #[test]
    fn test_completed_artifact_metadata_falls_back_to_path_basename() {
        let session = test_upload_session("name-check/20260603T072902Z/large-160m.bin", None, None);

        assert_eq!(completed_artifact_name(&session), "large-160m.bin");
        assert_eq!(completed_artifact_version(&session), None);
    }

    #[test]
    fn test_completed_package_catalog_entry_uses_session_metadata() {
        let session = test_upload_session(
            "large-check/20260603T082854Z/large-160m.bin",
            Some("large-check"),
            Some("20260603T082854Z"),
        );

        assert_eq!(
            completed_package_catalog_entry(&session),
            Some(("large-check".to_string(), "20260603T082854Z"))
        );
    }

    #[test]
    fn test_completed_package_catalog_entry_uses_replicated_maven_metadata() {
        let mut session = test_upload_session(
            "org/example/ak/maven/ak-core/1.0.0/ak-core-1.0.0.pom",
            Some("ak-core"),
            Some("1.0.0"),
        );
        session.artifact_metadata_format = Some("maven".to_string());
        session.artifact_metadata = Some(serde_json::json!({
            "format": "maven",
            "groupId": "org.example.ak.maven",
            "artifactId": "ak-core",
            "version": "1.0.0",
            "extension": "pom",
            "description": "Replicated Maven package",
            "dependencies": [
                {"groupId": "com.example", "artifactId": "dep", "version": "2.0.0"}
            ]
        }));

        assert_eq!(
            completed_package_catalog_entry(&session),
            Some(("org.example.ak.maven:ak-core".to_string(), "1.0.0"))
        );
        assert_eq!(
            completed_package_description(&session),
            Some("Replicated Maven package")
        );
        let metadata = completed_package_metadata(&session).expect("maven package metadata");
        assert_eq!(metadata["format"], "maven");
        assert_eq!(metadata["groupId"], "org.example.ak.maven");
        assert_eq!(metadata["artifactId"], "ak-core");
        assert_eq!(metadata["description"], "Replicated Maven package");
        assert_eq!(metadata["dependencies"][0]["artifactId"], "dep");
    }

    #[test]
    fn test_completed_package_metadata_does_not_synthesize_for_replicated_maven_jar() {
        let mut session = test_upload_session(
            "org/example/ak/maven/ak-core/1.0.0/ak-core-1.0.0.jar",
            Some("ak-core"),
            Some("1.0.0"),
        );
        session.artifact_metadata_format = Some("maven".to_string());
        session.artifact_metadata = Some(serde_json::json!({
            "format": "maven",
            "groupId": "org.example.ak.maven",
            "artifactId": "ak-core",
            "version": "1.0.0",
            "extension": "jar"
        }));

        assert_eq!(
            completed_package_catalog_entry(&session),
            Some(("org.example.ak.maven:ak-core".to_string(), "1.0.0"))
        );
        assert_eq!(completed_package_description(&session), None);
        assert_eq!(completed_package_metadata(&session), None);
    }

    #[test]
    fn test_completed_package_catalog_entry_skips_unversioned_upload() {
        let session =
            test_upload_session("large-check/20260603T082854Z/large-160m.bin", None, None);

        assert_eq!(completed_package_catalog_entry(&session), None);
    }

    // -----------------------------------------------------------------------
    // completed_format_artifact_version (#1975 stopgap for #1846)
    // -----------------------------------------------------------------------

    use crate::models::repository::RepositoryFormat;

    #[test]
    fn test_version_from_artifact_path_three_segments() {
        assert_eq!(
            version_from_artifact_path("ubuntu/20240215/disk.qcow2"),
            Some("20240215")
        );
        assert_eq!(version_from_artifact_path("p/v/a/b/file.bin"), Some("b"));
    }

    #[test]
    fn test_version_from_artifact_path_too_short() {
        assert_eq!(version_from_artifact_path("file.bin"), None);
        assert_eq!(version_from_artifact_path("dir/file.bin"), None);
        assert_eq!(version_from_artifact_path(""), None);
    }

    #[test]
    fn test_format_repo_requires_version() {
        assert!(!format_repo_requires_version(&RepositoryFormat::Generic));
        assert!(format_repo_requires_version(&RepositoryFormat::Incus));
        assert!(format_repo_requires_version(&RepositoryFormat::Debian));
    }

    #[test]
    fn test_completed_format_version_generic_keeps_none() {
        // Generic repo: no derivation, version stays NULL (legacy behaviour).
        let session = test_upload_session("images/vm.ova", None, None);
        assert_eq!(
            completed_format_artifact_version(&session, &RepositoryFormat::Generic),
            None
        );
    }

    #[test]
    fn test_completed_format_version_prefers_explicit() {
        // An explicit create-session version wins for every format.
        let session = test_upload_session("ubuntu/20240215/disk.qcow2", None, Some("2026.06.03"));
        assert_eq!(
            completed_format_artifact_version(&session, &RepositoryFormat::Incus),
            Some("2026.06.03".to_string())
        );
        assert_eq!(
            completed_format_artifact_version(&session, &RepositoryFormat::Generic),
            Some("2026.06.03".to_string())
        );
    }

    #[test]
    fn test_completed_format_version_derives_from_path() {
        // Format repo, no explicit version: derive from <product>/<version>/<file>.
        let session = test_upload_session("ubuntu/20240215/disk.qcow2", None, None);
        assert_eq!(
            completed_format_artifact_version(&session, &RepositoryFormat::Incus),
            Some("20240215".to_string())
        );
    }

    #[test]
    fn test_completed_format_version_falls_back_to_checksum() {
        // Format repo, no explicit version and path too shallow to derive one:
        // fall back to a deterministic non-null version so the row is not dropped.
        let mut session = test_upload_session("flat.bin", None, None);
        session.checksum_sha256 = "abcdef0123456789".to_string();
        assert_eq!(
            completed_format_artifact_version(&session, &RepositoryFormat::Incus),
            Some("sha256-abcdef012345".to_string())
        );
    }

    fn request_with_replication_metadata() -> CreateSessionRequest {
        CreateSessionRequest {
            repository_key: "repo".to_string(),
            artifact_path: "pool/main/a/app/app_1_amd64.deb".to_string(),
            artifact_name: Some("app".to_string()),
            artifact_version: Some("1".to_string()),
            artifact_metadata_format: Some("debian".to_string()),
            artifact_metadata: Some(serde_json::json!({
                "format": "debian",
                "architecture": "amd64"
            })),
            artifact_metadata_properties: Some(serde_json::json!({"source": "peer"})),
            package_description: Some("replicated Debian package".to_string()),
            package_metadata: Some(serde_json::json!({
                "format": "debian",
                "component": "main"
            })),
            total_size: 1024,
            checksum_sha256: "deadbeef".to_string(),
            chunk_size: None,
            content_type: None,
        }
    }

    fn headers_with_replication(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-artifact-keeper-replication",
            axum::http::HeaderValue::from_str(value).unwrap(),
        );
        headers
    }

    #[test]
    fn test_replication_session_metadata_keeps_fields_for_peer_request() {
        let req = request_with_replication_metadata();
        let headers = headers_with_replication("true");

        let metadata = replication_session_metadata_from_request(&headers, &req);

        assert_eq!(metadata.artifact_metadata_format, Some("debian"));
        assert_eq!(
            metadata.artifact_metadata.unwrap()["architecture"],
            serde_json::json!("amd64")
        );
        assert_eq!(
            metadata.artifact_metadata_properties.unwrap()["source"],
            serde_json::json!("peer")
        );
        assert_eq!(
            metadata.package_description,
            Some("replicated Debian package")
        );
        assert_eq!(
            metadata.package_metadata.unwrap()["component"],
            serde_json::json!("main")
        );
    }

    #[test]
    fn test_replication_session_metadata_drops_fields_without_peer_marker() {
        let req = request_with_replication_metadata();
        let headers = HeaderMap::new();

        let metadata = replication_session_metadata_from_request(&headers, &req);

        assert!(metadata.artifact_metadata_format.is_none());
        assert!(metadata.artifact_metadata.is_none());
        assert!(metadata.artifact_metadata_properties.is_none());
        assert!(metadata.package_description.is_none());
        assert!(metadata.package_metadata.is_none());
    }

    // -----------------------------------------------------------------------
    // CreateSessionRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_session_request_deserialize_full() {
        let json = r#"{
            "repository_key": "my-repo",
            "artifact_path": "images/vm.ova",
            "artifact_name": "vm-image",
            "artifact_version": "2026.06.03",
            "artifact_metadata_format": "debian",
            "artifact_metadata": {"format": "debian", "architecture": "amd64"},
            "artifact_metadata_properties": {"source": "peer"},
            "package_description": "Debian package",
            "package_metadata": {"format": "debian", "component": "main"},
            "total_size": 21474836480,
            "checksum_sha256": "abc123def456",
            "chunk_size": 16777216,
            "content_type": "application/x-ova"
        }"#;
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.repository_key, "my-repo");
        assert_eq!(req.artifact_path, "images/vm.ova");
        assert_eq!(req.artifact_name.as_deref(), Some("vm-image"));
        assert_eq!(req.artifact_version.as_deref(), Some("2026.06.03"));
        assert_eq!(req.artifact_metadata_format.as_deref(), Some("debian"));
        assert_eq!(
            req.artifact_metadata.as_ref().unwrap()["architecture"],
            "amd64"
        );
        assert_eq!(
            req.artifact_metadata_properties.as_ref().unwrap()["source"],
            "peer"
        );
        assert_eq!(req.package_description.as_deref(), Some("Debian package"));
        assert_eq!(req.package_metadata.as_ref().unwrap()["component"], "main");
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
        assert_eq!(req.artifact_name, None);
        assert_eq!(req.artifact_version, None);
        assert_eq!(req.artifact_metadata_format, None);
        assert_eq!(req.artifact_metadata, None);
        assert_eq!(req.artifact_metadata_properties, None);
        assert_eq!(req.package_description, None);
        assert_eq!(req.package_metadata, None);
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
    fn test_map_upload_err_too_large() {
        let resp = map_upload_err(UploadError::TooLarge {
            size: 9_999_999_999_999,
            max: 10_737_418_240,
        });
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
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
            artifact_name: None,
            artifact_version: None,
            artifact_metadata_format: None,
            artifact_metadata: None,
            artifact_metadata_properties: None,
            package_description: None,
            package_metadata: None,
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

    // -----------------------------------------------------------------------
    // map_upload_err response body verification (new error branches)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_map_upload_err_database_hides_details() {
        // Database errors should NOT leak SQL details to the client
        let db_err = sqlx::Error::Configuration("secret connection string".into());
        let resp = map_upload_err(UploadError::Database(db_err));
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "Database error");
        // Must NOT contain the raw sqlx error
        assert!(!json["error"].as_str().unwrap().contains("secret"));
    }

    #[test]
    fn test_map_upload_err_database_pool_timeout_returns_503() {
        // A saturated pool during publish must shed to 503 (transient capacity),
        // not 500, so clients back off instead of retrying into it (#2083).
        let resp = map_upload_err(UploadError::Database(sqlx::Error::PoolTimedOut));
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_map_upload_err_io_hides_details() {
        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "/secret/path/file.tmp");
        let resp = map_upload_err(UploadError::Io(io_err));
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "I/O error");
        assert!(!json["error"].as_str().unwrap().contains("/secret"));
    }

    #[tokio::test]
    async fn test_map_upload_err_checksum_includes_details() {
        let resp = map_upload_err(UploadError::ChecksumMismatch {
            expected: "aaa".into(),
            actual: "bbb".into(),
        });
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let err_msg = json["error"].as_str().unwrap();
        assert!(err_msg.contains("aaa"));
        assert!(err_msg.contains("bbb"));
    }

    #[tokio::test]
    async fn test_map_upload_err_incomplete_includes_counts() {
        let resp = map_upload_err(UploadError::IncompleteChunks {
            completed: 7,
            total: 10,
        });
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let err_msg = json["error"].as_str().unwrap();
        assert!(err_msg.contains("7"));
        assert!(err_msg.contains("10"));
    }

    #[tokio::test]
    async fn test_map_upload_err_size_mismatch_includes_sizes() {
        let resp = map_upload_err(UploadError::SizeMismatch {
            expected: 1048576,
            actual: 1048575,
        });
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let err_msg = json["error"].as_str().unwrap();
        assert!(err_msg.contains("1048576"));
        assert!(err_msg.contains("1048575"));
    }

    #[tokio::test]
    async fn test_map_err_body_is_json() {
        let resp = map_err(StatusCode::BAD_REQUEST, "test error message");
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "test error message");
    }

    // -----------------------------------------------------------------------
    // C2: body size cap arithmetic
    // -----------------------------------------------------------------------

    #[test]
    fn test_body_cap_prevents_oversized_allocation() {
        // Vec::with_capacity should cap at 256 MB even if Content-Range
        // declares a larger range
        let expected_len: usize = 512 * 1024 * 1024; // 512 MB
        let capped = expected_len.min(256 * 1024 * 1024);
        assert_eq!(capped, 256 * 1024 * 1024);
    }

    #[test]
    fn test_body_cap_passthrough_for_small_chunks() {
        let expected_len: usize = 8 * 1024 * 1024; // 8 MB
        let capped = expected_len.min(256 * 1024 * 1024);
        assert_eq!(capped, expected_len);
    }

    // -----------------------------------------------------------------------
    // C5: total_size validation at the DTO level
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_session_request_negative_total_size() {
        let json = r#"{
            "repository_key": "repo",
            "artifact_path": "file.bin",
            "total_size": -1,
            "checksum_sha256": "abc"
        }"#;
        // The JSON deserializes fine (i64 accepts negatives), but
        // create_session will reject it. Verify deserialization works.
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.total_size, -1);
    }

    #[test]
    fn test_create_session_request_max_i64_total_size() {
        let json = format!(
            r#"{{
                "repository_key": "repo",
                "artifact_path": "huge.bin",
                "total_size": {},
                "checksum_sha256": "abc"
            }}"#,
            i64::MAX
        );
        let req: CreateSessionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.total_size, i64::MAX);
    }

    // -----------------------------------------------------------------------
    // C3: ownership check is exercised via the service layer
    // (these test the handler-level plumbing that now passes user_id)
    // -----------------------------------------------------------------------

    #[test]
    fn test_upload_error_not_found_is_used_for_auth_failure() {
        // When a user tries to access another user's session, the service
        // returns NotFound (not Unauthorized) to avoid leaking session existence.
        let err = UploadError::NotFound;
        let resp = map_upload_err(err);
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // -----------------------------------------------------------------------
    // C4: validate_artifact_path is called from handler (tested in service)
    // Verify the handler maps the error correctly
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_path_error_maps_to_bad_request() {
        let err = upload_service::validate_artifact_path("../../etc/passwd");
        assert!(err.is_err());
        let resp = map_upload_err(err.unwrap_err());
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_validate_path_null_byte_maps_to_bad_request() {
        let err = upload_service::validate_artifact_path("file\0.txt");
        assert!(err.is_err());
        let resp = map_upload_err(err.unwrap_err());
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_validate_path_encoded_traversal_maps_to_bad_request() {
        let err = upload_service::validate_artifact_path("a/%2e%2e/b");
        assert!(err.is_err());
        let resp = map_upload_err(err.unwrap_err());
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_validate_path_backslash_maps_to_bad_request() {
        let err = upload_service::validate_artifact_path("a\\b");
        assert!(err.is_err());
        let resp = map_upload_err(err.unwrap_err());
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // -----------------------------------------------------------------------
    // Regression: issue #1168 -- chunked upload uses content-addressable
    // storage key matching non-chunked uploads, so download can find it.
    // -----------------------------------------------------------------------

    #[test]
    fn complete_uses_content_addressable_storage_key() {
        // The chunked-upload finalize path must derive the same storage key
        // as ArtifactService::storage_key_from_checksum so the repo-scoped
        // download handler finds the bytes. Before #1168, finalize used
        // "uploads/<repo_id>/<path>" which broke downloads.
        let checksum = "deadbeef0123456789abcdef0123456789abcdef0123456789abcdef01234567";
        let expected =
            crate::services::artifact_service::ArtifactService::storage_key_from_checksum(checksum);
        assert_eq!(
            expected,
            "de/ad/deadbeef0123456789abcdef0123456789abcdef0123456789abcdef01234567"
        );
        // The leading two-char shards are what the download path expects.
        assert!(expected.starts_with("de/ad/"));
        assert!(!expected.starts_with("uploads/"));
    }

    // -----------------------------------------------------------------------
    // Regression: issue #1168 part 1 -- create_session must accept a valid
    // repository key. The pre-fix predicate `AND is_deleted = false` referred
    // to a column that does not exist on `repositories`, so every call to the
    // handler crashed with a database error. These DB-backed tests exercise
    // the rewritten repository lookup end-to-end through the axum router.
    //
    // No-ops without `DATABASE_URL` (matches the project-wide handler test
    // pattern); CI runs `cargo llvm-cov --workspace --lib` with Postgres up
    // and applied migrations so the coverage gate sees these instrumented.
    // -----------------------------------------------------------------------
    use crate::api::handlers::test_db_helpers as tdh;

    /// Build a JSON POST request for the create_session route.
    fn create_session_req(body: &serde_json::Value) -> axum::http::Request<axum::body::Body> {
        let payload = bytes::Bytes::from(serde_json::to_vec(body).unwrap());
        tdh::post("/".to_string(), "application/json", payload)
    }

    fn create_replication_session_req(
        body: &serde_json::Value,
    ) -> axum::http::Request<axum::body::Body> {
        let mut req = create_session_req(body);
        req.headers_mut().insert(
            "x-artifact-keeper-replication",
            axum::http::HeaderValue::from_static("true"),
        );
        req
    }

    /// Wrap the upload router with a bare `Extension(AuthExtension)` layer.
    ///
    /// `tdh::router_with_auth` inserts `Extension::<Option<AuthExtension>>`,
    /// but the upload handlers use the non-optional `Extension<AuthExtension>`
    /// extractor (the real middleware chain populates the bare type). The
    /// handlers expect the bare value so we mimic that here.
    fn upload_router_with_auth(state: crate::api::SharedState, auth: AuthExtension) -> Router {
        super::router()
            .with_state(state)
            .layer(Extension::<AuthExtension>(auth))
    }

    #[tokio::test]
    async fn create_session_returns_201_for_existing_repo() {
        // Verify the repo lookup at line 134 returns the row (previously
        // crashed with `column "is_deleted" does not exist`).
        let Some(f) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let auth = tdh::make_auth(f.user_id, &f.username);
        let app = upload_router_with_auth(f.state.clone(), auth);

        let req = create_session_req(&serde_json::json!({
            "repository_key": f.repo_key,
            "artifact_path": "images/test.bin",
            "total_size": 1024_i64,
            "checksum_sha256": "deadbeef0123456789abcdef0123456789abcdef0123456789abcdef01234567",
        }));
        let (status, body) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "create_session must succeed for an existing repo (issue #1168); body: {}",
            String::from_utf8_lossy(&body)
        );
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("session_id").is_some());
        assert!(json.get("chunk_count").is_some());
        assert!(json.get("chunk_size").is_some());
        assert!(json.get("expires_at").is_some());

        // Clean up any upload_sessions / upload_chunks rows seeded by the
        // handler before fixture teardown drops the repo. Fail-soft because
        // tables may use ON DELETE CASCADE in some environments.
        let session_id: Uuid =
            serde_json::from_value(json["session_id"].clone()).expect("session_id is a UUID");
        let _ = sqlx::query("DELETE FROM upload_chunks WHERE session_id = $1")
            .bind(session_id)
            .execute(&f.pool)
            .await;
        let _ = sqlx::query("DELETE FROM upload_sessions WHERE id = $1")
            .bind(session_id)
            .execute(&f.pool)
            .await;
        f.teardown().await;
    }

    #[tokio::test]
    async fn create_session_returns_404_for_unknown_repo() {
        // Drives the `ok_or_else(|| map_err(NOT_FOUND, ...))` branch at
        // lines 139-144. Before #1168 this branch was never reached because
        // the SQL itself errored on the phantom column.
        let Some(f) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let auth = tdh::make_auth(f.user_id, &f.username);
        let app = upload_router_with_auth(f.state.clone(), auth);

        let req = create_session_req(&serde_json::json!({
            "repository_key": "this-repo-does-not-exist-1168",
            "artifact_path": "x.bin",
            "total_size": 16_i64,
            "checksum_sha256": "abc",
        }));
        let (status, body) = tdh::send(app, req).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let err_msg = json["error"].as_str().unwrap_or_default();
        assert!(
            err_msg.contains("this-repo-does-not-exist-1168"),
            "error must echo the missing key, got: {}",
            err_msg
        );
        f.teardown().await;
    }

    /// Insert a fine-grained permission rule granting `principal_id` the given
    /// actions on the repository. Used to exercise the #817 write-authorization
    /// gate on the session-create path.
    async fn grant_repo_permission(
        pool: &sqlx::PgPool,
        repo_id: Uuid,
        principal_id: Uuid,
        actions: &[&str],
    ) {
        let actions: Vec<String> = actions.iter().map(|s| s.to_string()).collect();
        sqlx::query(
            "INSERT INTO permissions \
             (principal_type, principal_id, target_type, target_id, actions) \
             VALUES ('user', $1, 'repository', $2, $3)",
        )
        .bind(principal_id)
        .bind(repo_id)
        .bind(&actions)
        .execute(pool)
        .await
        .expect("insert permission rule");
    }

    async fn delete_repo_permissions(pool: &sqlx::PgPool, repo_id: Uuid) {
        let _ = sqlx::query("DELETE FROM permissions WHERE target_id = $1")
            .bind(repo_id)
            .execute(pool)
            .await;
    }

    /// Delete any `upload_sessions`/`upload_chunks` rows the handler created in
    /// response to a successful `create_session` call, parsing the session id
    /// out of the JSON response body. Fail-soft on every step.
    async fn cleanup_created_session(pool: &sqlx::PgPool, body: &[u8]) {
        let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) else {
            return;
        };
        let Some(session_id) = json
            .get("session_id")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<Uuid>().ok())
        else {
            return;
        };
        let _ = sqlx::query("DELETE FROM upload_chunks WHERE session_id = $1")
            .bind(session_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM upload_sessions WHERE id = $1")
            .bind(session_id)
            .execute(pool)
            .await;
    }

    async fn upload_session_row_counts(pool: &sqlx::PgPool, session_id: Uuid) -> (i64, i64) {
        let sessions =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM upload_sessions WHERE id = $1")
                .bind(session_id)
                .fetch_one(pool)
                .await
                .expect("count upload session rows");
        let chunks = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM upload_chunks WHERE session_id = $1",
        )
        .bind(session_id)
        .fetch_one(pool)
        .await
        .expect("count upload chunk rows");
        (sessions, chunks)
    }

    fn sha256_hex(payload: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(payload);
        hex::encode(hasher.finalize())
    }

    async fn complete_replication_upload(
        f: &tdh::Fixture,
        create_body: serde_json::Value,
        payload: &[u8],
    ) -> Uuid {
        let auth = tdh::make_auth(f.user_id, &f.username);
        let app = upload_router_with_auth(f.state.clone(), auth);
        let create_req = create_replication_session_req(&create_body);
        let (status, body) = tdh::send(app, create_req).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "create_session must preserve replication metadata; body: {}",
            String::from_utf8_lossy(&body)
        );
        let create_resp: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let session_id: Uuid =
            serde_json::from_value(create_resp["session_id"].clone()).expect("session_id");

        let auth = tdh::make_auth(f.user_id, &f.username);
        let app = upload_router_with_auth(f.state.clone(), auth);
        let req = axum::http::Request::builder()
            .method("PATCH")
            .uri(format!("/{}", session_id))
            .header(
                "content-range",
                format!("bytes 0-{}/{}", payload.len() - 1, payload.len()),
            )
            .header("content-type", "application/octet-stream")
            .body(axum::body::Body::from(payload.to_vec()))
            .unwrap();
        let (status, body) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "chunk PATCH must succeed; body: {}",
            String::from_utf8_lossy(&body)
        );

        let auth = tdh::make_auth(f.user_id, &f.username);
        let app = upload_router_with_auth(f.state.clone(), auth);
        let req = axum::http::Request::builder()
            .method("PUT")
            .uri(format!("/{}/complete", session_id))
            .header("x-artifact-keeper-replication", "true")
            .body(axum::body::Body::empty())
            .unwrap();
        let (status, body) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "complete must succeed; body: {}",
            String::from_utf8_lossy(&body)
        );

        session_id
    }

    #[tokio::test]
    async fn create_replication_session_removes_stale_replication_session_for_same_path() {
        let Some(f) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };

        let artifact_path = "torch/2.0.0/torch-2.0.0-cp311-cp311-win_amd64.whl";
        let stale_session_id = Uuid::new_v4();
        let stale_temp = f
            .storage_dir
            .join(".uploads")
            .join(stale_session_id.to_string());
        tokio::fs::create_dir_all(stale_temp.parent().expect("stale temp parent"))
            .await
            .expect("create stale temp dir");
        tokio::fs::write(&stale_temp, b"partial replication bytes")
            .await
            .expect("write stale temp file");

        sqlx::query(
            r#"
            INSERT INTO upload_sessions
                (id, user_id, repository_id, repository_key, artifact_path,
                 content_type, total_size, chunk_size, total_chunks,
                 completed_chunks, bytes_received, checksum_sha256, temp_file_path,
                 status, is_replication)
            VALUES ($1, $2, $3, $4, $5, 'application/zip', 172305868, 52428800, 4,
                    2, 104857600, $6, $7, 'in_progress', true)
            "#,
        )
        .bind(stale_session_id)
        .bind(f.user_id)
        .bind(f.repo_id)
        .bind(&f.repo_key)
        .bind(artifact_path)
        .bind("2802f84f021907deee7e9470ed10c0e78af7457ac9a08a6cd7d55adef835fede")
        .bind(stale_temp.to_string_lossy().as_ref())
        .execute(&f.pool)
        .await
        .expect("insert stale replication session");

        sqlx::query(
            "INSERT INTO upload_chunks (session_id, chunk_index, byte_offset, byte_length, status) \
             VALUES ($1, 0, 0, 52428800, 'completed')",
        )
        .bind(stale_session_id)
        .execute(&f.pool)
        .await
        .expect("insert stale chunk row");

        let auth = tdh::make_auth(f.user_id, &f.username);
        let app = upload_router_with_auth(f.state.clone(), auth);
        let req = create_replication_session_req(&serde_json::json!({
            "repository_key": f.repo_key,
            "artifact_path": artifact_path,
            "artifact_name": "torch",
            "artifact_version": "2.0.0",
            "artifact_metadata_format": "pypi",
            "artifact_metadata": {"format": "pypi", "filename": "torch-2.0.0-cp311-cp311-win_amd64.whl"},
            "package_metadata": {"format": "pypi", "filename": "torch-2.0.0-cp311-cp311-win_amd64.whl"},
            "total_size": 172305868_i64,
            "checksum_sha256": "2802f84f021907deee7e9470ed10c0e78af7457ac9a08a6cd7d55adef835fede",
            "chunk_size": 52428800_i64,
        }));
        let (status, body) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "retry create_session must succeed; body: {}",
            String::from_utf8_lossy(&body)
        );

        assert_eq!(
            upload_session_row_counts(&f.pool, stale_session_id).await,
            (0, 0),
            "retrying peer replication must remove stale upload session/chunk rows"
        );
        assert!(
            !stale_temp.exists(),
            "retry cleanup should remove the stale replication temp file"
        );

        let create_resp: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let new_session_id: Uuid =
            serde_json::from_value(create_resp["session_id"].clone()).expect("session_id");
        let is_replication: bool =
            sqlx::query_scalar("SELECT is_replication FROM upload_sessions WHERE id = $1")
                .bind(new_session_id)
                .fetch_one(&f.pool)
                .await
                .expect("query new upload session");
        assert!(
            is_replication,
            "new peer-created upload session must be marked as replication"
        );

        cleanup_created_session(&f.pool, &body).await;
        f.teardown().await;
    }

    #[tokio::test]
    async fn create_session_allows_non_admin_with_write_grant() {
        // (a) Non-admin holding a fine-grained `write` rule on the target repo
        // creates a session -> 201.
        let Some(f) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        grant_repo_permission(&f.pool, f.repo_id, f.user_id, &["read", "write"]).await;
        let auth = tdh::make_auth(f.user_id, &f.username);
        let app = upload_router_with_auth(f.state.clone(), auth);

        let req = create_session_req(&serde_json::json!({
            "repository_key": f.repo_key,
            "artifact_path": "grant/ok.bin",
            "total_size": 16_i64,
            "checksum_sha256": "deadbeef0123456789abcdef0123456789abcdef0123456789abcdef01234567",
        }));
        let (status, body) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "non-admin with write grant must be allowed; body: {}",
            String::from_utf8_lossy(&body)
        );

        cleanup_created_session(&f.pool, &body).await;
        delete_repo_permissions(&f.pool, f.repo_id).await;
        f.teardown().await;
    }

    #[tokio::test]
    async fn create_session_denies_non_admin_without_grant_when_rules_exist() {
        // (b) The exploit case: a non-admin whose target repo HAS fine-grained
        // rules, but holds no grant for that user, is denied -> 403. (Mirrors a
        // cross-tenant write attempt into a repo gated by permission rules.)
        let Some(f) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        // Rules exist for the repo, but they grant another principal, not the
        // caller.
        grant_repo_permission(&f.pool, f.repo_id, Uuid::new_v4(), &["read", "write"]).await;
        let auth = tdh::make_auth(f.user_id, &f.username);
        let app = upload_router_with_auth(f.state.clone(), auth);

        let req = create_session_req(&serde_json::json!({
            "repository_key": f.repo_key,
            "artifact_path": "xtenant/blocked.bin",
            "total_size": 16_i64,
            "checksum_sha256": "deadbeef0123456789abcdef0123456789abcdef0123456789abcdef01234567",
        }));
        let (status, _body) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "non-admin without a grant on a ruled repo must be denied"
        );
        // No session must have been created for this repo.
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM upload_sessions WHERE repository_id = $1")
                .bind(f.repo_id)
                .fetch_one(&f.pool)
                .await
                .unwrap_or(0);
        assert_eq!(count, 0, "denied request must not create a session");

        delete_repo_permissions(&f.pool, f.repo_id).await;
        f.teardown().await;
    }

    #[tokio::test]
    async fn create_session_allows_admin_on_ruled_repo() {
        // (c) An admin bypasses the fine-grained checks even when rules exist
        // and grant the admin nothing -> 201.
        let Some(f) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        grant_repo_permission(&f.pool, f.repo_id, Uuid::new_v4(), &["read", "write"]).await;
        let mut auth = tdh::make_auth(f.user_id, &f.username);
        auth.is_admin = true;
        let app = upload_router_with_auth(f.state.clone(), auth);

        let req = create_session_req(&serde_json::json!({
            "repository_key": f.repo_key,
            "artifact_path": "admin/ok.bin",
            "total_size": 16_i64,
            "checksum_sha256": "deadbeef0123456789abcdef0123456789abcdef0123456789abcdef01234567",
        }));
        let (status, body) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "admin must bypass fine-grained rules; body: {}",
            String::from_utf8_lossy(&body)
        );

        cleanup_created_session(&f.pool, &body).await;
        delete_repo_permissions(&f.pool, f.repo_id).await;
        f.teardown().await;
    }

    #[tokio::test]
    async fn complete_uses_repo_scoped_storage_and_writes_to_content_addressed_key() {
        // End-to-end: create session, upload one chunk equal to the full
        // file, complete. Drives `complete()` past `complete_session` and
        // through the new `storage_for_repo` + `storage_key_from_checksum`
        // path (lines 364-385). Asserts the bytes land at the hashed key
        // under the repo storage dir and that a subsequent download finds
        // them via the same backend.
        let Some(f) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };

        // Compute checksum of test payload up front -- complete_session
        // verifies the temp-file SHA256 matches.
        let payload: &[u8] = b"chunked-upload-test-bytes-for-1168";
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(payload);
        let checksum = hex::encode(hasher.finalize());

        // 1) Create session via the handler.
        let auth = tdh::make_auth(f.user_id, &f.username);
        let app = upload_router_with_auth(f.state.clone(), auth);
        let create_req = create_session_req(&serde_json::json!({
            "repository_key": f.repo_key,
            "artifact_path": "bundles/test.bin",
            "total_size": payload.len() as i64,
            "checksum_sha256": checksum,
            "chunk_size": 1024 * 1024_i64, // 1 MB, so total fits in one chunk
        }));
        let (status, body) = tdh::send(app, create_req).await;
        assert_eq!(status, StatusCode::CREATED, "create_session must succeed");
        let create_resp: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let session_id: Uuid =
            serde_json::from_value(create_resp["session_id"].clone()).expect("session_id");

        // 2) PATCH chunk index 0 with the full payload.
        let auth = tdh::make_auth(f.user_id, &f.username);
        let app = upload_router_with_auth(f.state.clone(), auth);
        let req = axum::http::Request::builder()
            .method("PATCH")
            .uri(format!("/{}", session_id))
            .header(
                "content-range",
                format!("bytes 0-{}/{}", payload.len() - 1, payload.len()),
            )
            .header("content-type", "application/octet-stream")
            .body(axum::body::Body::from(payload.to_vec()))
            .unwrap();
        let (status, body) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "chunk PATCH must succeed; body: {}",
            String::from_utf8_lossy(&body)
        );

        // 3) PUT /:session_id/complete -- runs the new code path.
        let auth = tdh::make_auth(f.user_id, &f.username);
        let app = upload_router_with_auth(f.state.clone(), auth);
        let req = axum::http::Request::builder()
            .method("PUT")
            .uri(format!("/{}/complete", session_id))
            .body(axum::body::Body::empty())
            .unwrap();
        let (status, body) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "complete must succeed; body: {}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(
            upload_session_row_counts(&f.pool, session_id).await,
            (1, 1),
            "regular completed upload sessions remain queryable for client status"
        );

        // 4) The new path uses content-addressable storage under the
        //    repo-scoped backend. Verify the bytes are there at the expected
        //    key (proves we no longer use the broken "uploads/<repo_id>/..."
        //    layout, regression for #1168 part 3).
        //
        // The storage key produced by `storage_key_from_checksum` is
        // hierarchical (`<hash[:2]>/<hash[2:4]>/<full-hash>`). For hierarchical
        // keys, `FilesystemStorage::key_to_path` does NOT prepend an extra
        // shard prefix (see #1073): keys containing `/` already distribute
        // themselves across directories, so the on-disk layout is simply
        // `<base>/<key>`. We assert the bytes land there with the right
        // content, and as a safety net, also verify the legacy "uploads/..."
        // path from before #1168 does NOT exist.
        let expected_key =
            crate::services::artifact_service::ArtifactService::storage_key_from_checksum(
                &checksum,
            );
        let on_disk_path = f.storage_dir.join(&expected_key);
        assert!(
            on_disk_path.exists(),
            "expected hashed bytes at {} (issue #1168 part 3)",
            on_disk_path.display()
        );
        let read_back = std::fs::read(&on_disk_path).expect("read back");
        assert_eq!(
            read_back, payload,
            "bytes round-trip through content-addressable storage"
        );
        // Regression guard: the old (broken) path scheme must NOT be in use.
        let legacy_path = f
            .storage_dir
            .join("uploads")
            .join(f.repo_id.to_string())
            .join("bundles/test.bin");
        assert!(
            !legacy_path.exists(),
            "legacy uploads/<repo_id>/<path> layout must not be used after #1168"
        );

        // Clean up everything we wrote.
        let _ = sqlx::query("DELETE FROM upload_chunks WHERE session_id = $1")
            .bind(session_id)
            .execute(&f.pool)
            .await;
        let _ = sqlx::query("DELETE FROM upload_sessions WHERE id = $1")
            .bind(session_id)
            .execute(&f.pool)
            .await;
        f.teardown().await;
    }

    #[tokio::test]
    async fn complete_materializes_replication_metadata() {
        let Some(f) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };

        let payload: &[u8] = b"replicated-debian-package-bytes";
        let checksum = sha256_hex(payload);

        let artifact_path = "pool/main/a/app/app_1_amd64.deb";
        let session_id = complete_replication_upload(
            &f,
            serde_json::json!({
                "repository_key": f.repo_key,
                "artifact_path": artifact_path,
                "artifact_name": "app",
                "artifact_version": "1",
                "artifact_metadata_format": "debian",
                "artifact_metadata": {
                    "format": "debian",
                    "architecture": "amd64",
                    "component": "main"
                },
                "artifact_metadata_properties": {"source": "lux"},
                "package_description": "replicated Debian package",
                "package_metadata": {
                    "format": "debian",
                    "component": "main"
                },
                "total_size": payload.len() as i64,
                "checksum_sha256": checksum,
                "chunk_size": 1024 * 1024_i64,
            }),
            payload,
        )
        .await;
        assert_eq!(
            upload_session_row_counts(&f.pool, session_id).await,
            (0, 0),
            "replication upload complete must not leave stale upload session/chunk rows"
        );

        let artifact_id: Uuid =
            sqlx::query_scalar("SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2")
                .bind(f.repo_id)
                .bind(artifact_path)
                .fetch_one(&f.pool)
                .await
                .expect("query replicated artifact");

        let metadata: (String, serde_json::Value, serde_json::Value) = sqlx::query_as(
            "SELECT format, metadata, properties FROM artifact_metadata WHERE artifact_id = $1",
        )
        .bind(artifact_id)
        .fetch_one(&f.pool)
        .await
        .expect("query replicated artifact metadata");
        assert_eq!(metadata.0, "debian");
        assert_eq!(metadata.1["architecture"], "amd64");
        assert_eq!(metadata.2["source"], "lux");

        let pkg: (String, Option<String>, Option<serde_json::Value>) = sqlx::query_as(
            "SELECT version, description, metadata FROM packages WHERE repository_id = $1 AND name = $2",
        )
        .bind(f.repo_id)
        .bind("app")
        .fetch_one(&f.pool)
        .await
        .expect("query replicated package catalog");
        assert_eq!(pkg.0, "1");
        assert_eq!(pkg.1.as_deref(), Some("replicated Debian package"));
        assert_eq!(pkg.2.expect("package metadata")["component"], "main");

        let _ = sqlx::query("DELETE FROM upload_chunks WHERE session_id = $1")
            .bind(session_id)
            .execute(&f.pool)
            .await;
        let _ = sqlx::query("DELETE FROM upload_sessions WHERE id = $1")
            .bind(session_id)
            .execute(&f.pool)
            .await;
        f.teardown().await;
    }

    #[tokio::test]
    async fn complete_materializes_maven_replication_package_catalog_from_metadata() {
        let Some(f) = tdh::Fixture::setup("local", "maven").await else {
            return;
        };

        let payload: &[u8] = br#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.example.ak.maven</groupId>
  <artifactId>ak-core</artifactId>
  <version>1.0.0</version>
  <description>Replicated Maven package</description>
</project>"#;
        let checksum = sha256_hex(payload);

        let artifact_path = "org/example/ak/maven/ak-core/1.0.0/ak-core-1.0.0.pom";
        let session_id = complete_replication_upload(
            &f,
            serde_json::json!({
                "repository_key": f.repo_key,
                "artifact_path": artifact_path,
                "artifact_name": "ak-core",
                "artifact_version": "1.0.0",
                "artifact_metadata_format": "maven",
                "artifact_metadata": {
                    "format": "maven",
                    "groupId": "org.example.ak.maven",
                    "artifactId": "ak-core",
                    "version": "1.0.0",
                    "extension": "pom",
                    "description": "Replicated Maven package"
                },
                "total_size": payload.len() as i64,
                "checksum_sha256": checksum,
                "chunk_size": 1024 * 1024_i64,
                "content_type": "text/xml",
            }),
            payload,
        )
        .await;

        let artifact: (String, String) = sqlx::query_as(
            "SELECT name, version FROM artifacts WHERE repository_id = $1 AND path = $2",
        )
        .bind(f.repo_id)
        .bind(artifact_path)
        .fetch_one(&f.pool)
        .await
        .expect("query replicated Maven artifact");
        assert_eq!(artifact.0, "ak-core");
        assert_eq!(artifact.1, "1.0.0");

        let package: (String, String, Option<String>, Option<serde_json::Value>) = sqlx::query_as(
            "SELECT name, version, description, metadata FROM packages WHERE repository_id = $1",
        )
        .bind(f.repo_id)
        .fetch_one(&f.pool)
        .await
        .expect("query replicated Maven package catalog");
        assert_eq!(package.0, "org.example.ak.maven:ak-core");
        assert_eq!(package.1, "1.0.0");
        assert_eq!(package.2.as_deref(), Some("Replicated Maven package"));
        let metadata = package.3.expect("Maven package metadata");
        assert_eq!(metadata["format"], "maven");
        assert_eq!(metadata["groupId"], "org.example.ak.maven");
        assert_eq!(metadata["artifactId"], "ak-core");

        let _ = sqlx::query("DELETE FROM upload_chunks WHERE session_id = $1")
            .bind(session_id)
            .execute(&f.pool)
            .await;
        let _ = sqlx::query("DELETE FROM upload_sessions WHERE id = $1")
            .bind(session_id)
            .execute(&f.pool)
            .await;
        f.teardown().await;
    }
}
