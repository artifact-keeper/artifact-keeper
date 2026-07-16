//! Git LFS API handlers.
//!
//! Implements the Git LFS Batch API and related endpoints for large file storage.
//!
//! Routes are mounted at `/lfs/{repo_key}/...`:
//!   POST /lfs/:repo_key/objects/batch        - Batch API (download/upload negotiation)
//!   PUT  /lfs/:repo_key/objects/:oid         - Upload object (raw binary)
//!   GET  /lfs/:repo_key/objects/:oid         - Download object
//!   POST /lfs/:repo_key/verify               - Verify upload
//!   POST /lfs/:repo_key/locks                - Create lock
//!   GET  /lfs/:repo_key/locks                - List locks
//!   POST /lfs/:repo_key/locks/verify         - Verify locks
//!   POST /lfs/:repo_key/locks/:id/unlock     - Delete lock

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{post, put};
use axum::Extension;
use axum::Router;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::extractors::RequestBaseUrl;
use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic, require_auth_basic_scope, AuthExtension};
use crate::api::SharedState;
use crate::models::repository::RepositoryType;

const LFS_CONTENT_TYPE: &str = "application/vnd.git-lfs+json";

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Batch API
        .route("/:repo_key/objects/batch", post(batch))
        // Object upload and download
        .route(
            "/:repo_key/objects/:oid",
            put(upload_object).get(download_object),
        )
        // Verify upload
        .route("/:repo_key/verify", post(verify_object))
        // Lock management
        .route("/:repo_key/locks", post(create_lock).get(list_locks))
        .route("/:repo_key/locks/verify", post(verify_locks))
        .route("/:repo_key/locks/:lock_id/unlock", post(delete_lock))
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024 * 1024)) // 2 GB
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct BatchRequest {
    operation: String,
    #[serde(default)]
    transfers: Vec<String>,
    objects: Vec<BatchObject>,
}

#[derive(Debug, Deserialize)]
struct BatchObject {
    oid: String,
    size: i64,
}

#[derive(Debug, Serialize)]
struct BatchResponse {
    transfer: String,
    objects: Vec<BatchResponseObject>,
}

#[derive(Debug, Serialize)]
struct BatchResponseObject {
    oid: String,
    size: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    authenticated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    actions: Option<BatchActions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<LfsError>,
}

#[derive(Debug, Serialize)]
struct BatchActions {
    #[serde(skip_serializing_if = "Option::is_none")]
    download: Option<BatchAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upload: Option<BatchAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verify: Option<BatchAction>,
}

#[derive(Debug, Serialize)]
struct BatchAction {
    href: String,
    header: serde_json::Value,
    expires_in: u64,
}

#[derive(Debug, Serialize)]
struct LfsError {
    code: u16,
    message: String,
}

#[derive(Debug, Deserialize)]
struct VerifyRequest {
    oid: String,
    size: i64,
}

#[derive(Debug, Deserialize)]
struct CreateLockRequest {
    path: String,
    #[serde(rename = "ref")]
    lock_ref: Option<LockRef>,
}

#[derive(Debug, Deserialize, Serialize)]
struct LockRef {
    name: String,
}

#[derive(Debug, Serialize)]
struct LockResponse {
    lock: LockInfo,
}

#[derive(Debug, Serialize)]
struct LockInfo {
    id: String,
    path: String,
    locked_at: String,
    owner: LockOwner,
}

#[derive(Debug, Serialize)]
struct LockOwner {
    name: String,
}

#[derive(Debug, Serialize)]
struct LockListResponse {
    locks: Vec<LockInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct VerifyLocksRequest {
    #[serde(rename = "ref")]
    lock_ref: Option<LockRef>,
}

#[derive(Debug, Serialize)]
struct VerifyLocksResponse {
    ours: Vec<LockInfo>,
    theirs: Vec<LockInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UnlockRequest {
    #[serde(default)]
    force: bool,
}

#[derive(Debug, Serialize)]
struct UnlockResponse {
    lock: LockInfo,
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_lfs_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    use sqlx::Row;
    let repo = sqlx::query(
        "SELECT id, key, storage_backend, storage_path, format::text as format, \
         repo_type::text as repo_type, upstream_url, promotion_only FROM repositories WHERE key = $1",
    )
    .bind(repo_key)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        lfs_error_response(
            crate::api::handlers::db_status(&e),
            &format!("Database error: {}", e),
        )
    })?
    .ok_or_else(|| lfs_error_response(StatusCode::NOT_FOUND, "Repository not found"))?;

    let fmt: String = repo.try_get("format").unwrap_or_default();
    let fmt = fmt.to_lowercase();
    if fmt != "gitlfs" {
        return Err(lfs_error_response(
            StatusCode::BAD_REQUEST,
            &format!(
                "Repository '{}' is not a Git LFS repository (format: {})",
                repo_key, fmt
            ),
        ));
    }

    Ok(RepoInfo {
        id: repo.try_get("id").unwrap_or_default(),
        key: repo.try_get("key").unwrap_or_default(),
        storage_path: repo.try_get("storage_path").unwrap_or_default(),
        storage_backend: repo.try_get("storage_backend").unwrap_or_default(),
        repo_type: repo.try_get("repo_type").unwrap_or_default(),
        upstream_url: repo.try_get("upstream_url").ok(),
        promotion_only: repo.try_get("promotion_only").unwrap_or(false),
        format: "generic".to_string(),
        age_gate_enabled: false,
        age_gate_min_age_days: 7,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[allow(clippy::result_large_err)]
fn validate_oid(oid: &str) -> Result<(), Response> {
    if oid.len() != 64 || !oid.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(lfs_error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "OID must be a 64-character SHA-256 hex string",
        ));
    }
    Ok(())
}

fn lfs_json_response(status: StatusCode, body: &impl Serialize) -> Response {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, LFS_CONTENT_TYPE)
        .body(Body::from(serde_json::to_string(body).unwrap()))
        .unwrap()
}

fn lfs_error_response(status: StatusCode, message: &str) -> Response {
    let body = serde_json::json!({
        "message": message,
        "request_id": uuid::Uuid::new_v4().to_string(),
    });
    super::with_retry_after_on_503(
        Response::builder()
            .status(status)
            .header(CONTENT_TYPE, LFS_CONTENT_TYPE)
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap(),
    )
}

// ---------------------------------------------------------------------------
// POST /lfs/:repo_key/objects/batch - Batch API
// ---------------------------------------------------------------------------

async fn batch(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    request_base_url: RequestBaseUrl,
    body: Bytes,
) -> Result<Response, Response> {
    let repo = resolve_lfs_repo(&state.db, &repo_key).await?;

    let request: BatchRequest = serde_json::from_slice(&body).map_err(|e| {
        lfs_error_response(StatusCode::BAD_REQUEST, &format!("Invalid JSON: {}", e))
    })?;

    if request.operation != "download" && request.operation != "upload" {
        return Err(lfs_error_response(
            StatusCode::BAD_REQUEST,
            &format!("Unsupported operation: {}", request.operation),
        ));
    }

    // Upload requires authentication
    let auth_header = if request.operation == "upload" {
        let _user_id = require_auth_basic(auth, "git-lfs")?.user_id;
        // Pass auth header through to action hrefs
        headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string())
    } else {
        None
    };

    let base_url = build_base_url(request_base_url.as_str(), &repo_key);
    let mut response_objects = Vec::with_capacity(request.objects.len());

    for obj in &request.objects {
        if let Err(e) = validate_oid(&obj.oid) {
            response_objects.push(BatchResponseObject {
                oid: obj.oid.clone(),
                size: obj.size,
                authenticated: None,
                actions: None,
                error: Some(LfsError {
                    code: StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
                    message: "Invalid OID format".to_string(),
                }),
            });
            let _ = e;
            continue;
        }

        let existing = sqlx::query!(
            r#"
            SELECT id, size_bytes
            FROM artifacts
            WHERE repository_id = $1
              AND is_deleted = false
              AND checksum_sha256 = $2
            LIMIT 1
            "#,
            repo.id,
            obj.oid
        )
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            lfs_error_response(
                crate::api::handlers::db_status(&e),
                &format!("Database error: {}", e),
            )
        })?;

        let action_header = match &auth_header {
            Some(auth) => serde_json::json!({ "Authorization": auth }),
            None => serde_json::json!({}),
        };

        let response_obj = match request.operation.as_str() {
            "download" => {
                if existing.is_some() {
                    BatchResponseObject {
                        oid: obj.oid.clone(),
                        size: obj.size,
                        authenticated: Some(true),
                        actions: Some(BatchActions {
                            download: Some(BatchAction {
                                href: format!("{}/objects/{}", base_url, obj.oid),
                                header: action_header,
                                expires_in: 3600,
                            }),
                            upload: None,
                            verify: None,
                        }),
                        error: None,
                    }
                } else {
                    BatchResponseObject {
                        oid: obj.oid.clone(),
                        size: obj.size,
                        authenticated: None,
                        actions: None,
                        error: Some(LfsError {
                            code: 404,
                            message: "Object not found".to_string(),
                        }),
                    }
                }
            }
            "upload" => {
                if existing.is_some() {
                    // Object already exists, no actions needed
                    BatchResponseObject {
                        oid: obj.oid.clone(),
                        size: obj.size,
                        authenticated: Some(true),
                        actions: None,
                        error: None,
                    }
                } else {
                    BatchResponseObject {
                        oid: obj.oid.clone(),
                        size: obj.size,
                        authenticated: Some(true),
                        actions: Some(BatchActions {
                            download: None,
                            upload: Some(BatchAction {
                                href: format!("{}/objects/{}", base_url, obj.oid),
                                header: action_header.clone(),
                                expires_in: 3600,
                            }),
                            verify: Some(BatchAction {
                                href: format!("{}/verify", base_url),
                                header: action_header,
                                expires_in: 3600,
                            }),
                        }),
                        error: None,
                    }
                }
            }
            _ => unreachable!(),
        };

        response_objects.push(response_obj);
    }

    let response = BatchResponse {
        transfer: "basic".to_string(),
        objects: response_objects,
    };

    Ok(lfs_json_response(StatusCode::OK, &response))
}

fn build_base_url(request_base_url: &str, repo_key: &str) -> String {
    format!("{}/lfs/{}", request_base_url, repo_key)
}

// ---------------------------------------------------------------------------
// PUT /lfs/:repo_key/objects/:oid - Upload object
// ---------------------------------------------------------------------------

async fn upload_object(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, oid)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "git-lfs", "write")?.user_id;
    let repo = resolve_lfs_repo(&state.db, &repo_key).await?;

    // Reject writes to remote/virtual repos
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    validate_oid(&oid)?;

    if body.is_empty() {
        return Err(lfs_error_response(StatusCode::BAD_REQUEST, "Empty body"));
    }

    // Verify SHA-256 matches the OID
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let computed_sha256 = format!("{:x}", hasher.finalize());

    if computed_sha256 != oid {
        return Err(lfs_error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!(
                "SHA-256 mismatch: expected {}, computed {}",
                oid, computed_sha256
            ),
        ));
    }

    // Check for duplicate
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND checksum_sha256 = $2 AND is_deleted = false",
        repo.id,
        oid
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        lfs_error_response(
            crate::api::handlers::db_status(&e),
            &format!("Database error: {}", e),
        )
    })?;

    if existing.is_some() {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap());
    }

    // Store the object
    let storage_key = format!("gitlfs/{}/{}", &oid[..2], oid);
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    storage.put(&storage_key, body.clone()).await.map_err(|e| {
        lfs_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Storage error: {}", e),
        )
    })?;

    let size_bytes = body.len() as i64;
    let artifact_path = format!("lfs/objects/{}/{}", &oid[..2], oid);

    super::cleanup_soft_deleted_artifact(&state.db, repo.id, &artifact_path).await;

    // Insert artifact record
    let artifact_id = sqlx::query_scalar!(
        r#"
        INSERT INTO artifacts (
            repository_id, path, name, version, size_bytes,
            checksum_sha256, content_type, storage_key, uploaded_by
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id
        "#,
        repo.id,
        artifact_path,
        oid,
        "sha256",
        size_bytes,
        oid,
        "application/octet-stream",
        storage_key,
        user_id,
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        lfs_error_response(
            crate::api::handlers::db_status(&e),
            &format!("Database error: {}", e),
        )
    })?;

    crate::services::quarantine_service::apply_upload_hold_hosted(&state.db, repo.id, artifact_id)
        .await;

    // Update repository timestamp
    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
    .await;

    info!(
        "Git LFS upload: {} ({} bytes) to repo {}",
        oid, size_bytes, repo_key
    );

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /lfs/:repo_key/objects/:oid - Download object
// ---------------------------------------------------------------------------

async fn download_object(
    State(state): State<SharedState>,
    Path((repo_key, oid)): Path<(String, String)>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let repo = resolve_lfs_repo(&state.db, &repo_key).await?;
    validate_oid(&oid)?;

    let artifact = sqlx::query!(
        r#"
        SELECT id, storage_key, size_bytes
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND checksum_sha256 = $2
        LIMIT 1
        "#,
        repo.id,
        oid
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        lfs_error_response(
            crate::api::handlers::db_status(&e),
            &format!("Database error: {}", e),
        )
    })?;

    let artifact = match artifact {
        Some(a) => a,
        None => {
            if repo.repo_type == RepositoryType::Remote {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let upstream_path = format!("objects/{}", oid);
                    // #895: stream large LFS blobs (the whole reason LFS
                    // exists). Default Content-Type matches the buffered
                    // handler's prior fallback.
                    return proxy_helpers::proxy_fetch_streaming(
                        proxy,
                        repo.id,
                        &repo_key,
                        upstream_url,
                        &upstream_path,
                        "application/octet-stream",
                    )
                    .await;
                }
            }

            // Virtual repo: try each member in priority order
            if repo.repo_type == RepositoryType::Virtual {
                let db = state.db.clone();
                let artifact_path = format!("lfs/objects/{}/{}", &oid[..2], oid);
                let path_clone = artifact_path.clone();
                let upstream_path = format!("objects/{}", oid);
                let result = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    state.proxy_service.as_deref(),
                    repo.id,
                    &upstream_path,
                    |member_id, location| {
                        let db = db.clone();
                        let state = state.clone();
                        let path = path_clone.clone();
                        async move {
                            proxy_helpers::local_fetch_by_path(
                                &db, &state, member_id, &location, &path,
                            )
                            .await
                        }
                    },
                )
                .await?;

                return proxy_helpers::stream_fetch_result(
                    result,
                    "application/octet-stream",
                    None,
                );
            }

            return Err(lfs_error_response(
                StatusCode::NOT_FOUND,
                "Object not found",
            ));
        }
    };

    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    // Check quarantine status before serving
    crate::services::quarantine_service::check_artifact_download(&state.db, artifact.id)
        .await
        .map_err(|e| e.into_response())?;

    let stream = storage
        .get_stream(&artifact.storage_key)
        .await
        .map_err(|e| {
            lfs_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Storage error: {}", e),
            )
        })?;

    // Record download
    crate::services::artifact_service::record_download(&state.db, artifact.id, &ctx).await;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(CONTENT_LENGTH, artifact.size_bytes.to_string())
        .body(Body::from_stream(stream))
        .unwrap())
}

// ---------------------------------------------------------------------------
// POST /lfs/:repo_key/verify - Verify upload
// ---------------------------------------------------------------------------

async fn verify_object(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    body: Bytes,
) -> Result<Response, Response> {
    let repo = resolve_lfs_repo(&state.db, &repo_key).await?;

    let request: VerifyRequest = serde_json::from_slice(&body).map_err(|e| {
        lfs_error_response(StatusCode::BAD_REQUEST, &format!("Invalid JSON: {}", e))
    })?;

    validate_oid(&request.oid)?;

    let artifact = sqlx::query!(
        r#"
        SELECT size_bytes
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND checksum_sha256 = $2
        LIMIT 1
        "#,
        repo.id,
        request.oid
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        lfs_error_response(
            crate::api::handlers::db_status(&e),
            &format!("Database error: {}", e),
        )
    })?
    .ok_or_else(|| lfs_error_response(StatusCode::NOT_FOUND, "Object not found"))?;

    if artifact.size_bytes != request.size {
        return Err(lfs_error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!(
                "Size mismatch: expected {}, stored {}",
                request.size, artifact.size_bytes
            ),
        ));
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap())
}

// ---------------------------------------------------------------------------
// POST /lfs/:repo_key/locks - Create lock
// ---------------------------------------------------------------------------

async fn create_lock(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    body: Bytes,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "git-lfs", "write")?.user_id;
    let repo = resolve_lfs_repo(&state.db, &repo_key).await?;

    let request: CreateLockRequest = serde_json::from_slice(&body).map_err(|e| {
        lfs_error_response(StatusCode::BAD_REQUEST, &format!("Invalid JSON: {}", e))
    })?;

    if request.path.is_empty() {
        return Err(lfs_error_response(
            StatusCode::BAD_REQUEST,
            "Lock path is required",
        ));
    }

    // Look up username for the lock owner record.
    let username = sqlx::query_scalar!("SELECT username FROM users WHERE id = $1", user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            lfs_error_response(
                crate::api::handlers::db_status(&e),
                &format!("Database error: {}", e),
            )
        })?;

    let ref_name = request.lock_ref.as_ref().map(|r| r.name.clone());

    // Insert the lock, relying on the (repository_id, path) UNIQUE constraint to
    // enforce single-ownership of a path. `ON CONFLICT DO NOTHING` returns no
    // row when the path is already locked, which we surface as the Git LFS 409
    // "already created" response (including the existing lock, per the spec).
    let inserted = sqlx::query!(
        r#"
        INSERT INTO lfs_locks (repository_id, path, ref_name, owner_id, owner_name)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (repository_id, path) DO NOTHING
        RETURNING id, locked_at
        "#,
        repo.id,
        request.path,
        ref_name,
        user_id,
        username,
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        lfs_error_response(
            crate::api::handlers::db_status(&e),
            &format!("Database error: {}", e),
        )
    })?;

    let Some(row) = inserted else {
        // Path already locked — return 409 with the existing lock so the client
        // can report who holds it (Git LFS locking spec, "lock already exists").
        let existing = sqlx::query!(
            r#"
            SELECT id, path, locked_at, owner_name
            FROM lfs_locks
            WHERE repository_id = $1 AND path = $2
            "#,
            repo.id,
            request.path,
        )
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            lfs_error_response(
                crate::api::handlers::db_status(&e),
                &format!("Database error: {}", e),
            )
        })?;

        let lock = existing.map(|r| LockInfo {
            id: r.id.to_string(),
            path: r.path,
            locked_at: r.locked_at.to_rfc3339(),
            owner: LockOwner { name: r.owner_name },
        });
        return Err(lock_conflict_response(lock));
    };

    let response = LockResponse {
        lock: LockInfo {
            id: row.id.to_string(),
            path: request.path,
            locked_at: row.locked_at.to_rfc3339(),
            owner: LockOwner { name: username },
        },
    };

    Ok(lfs_json_response(StatusCode::CREATED, &response))
}

/// Build the Git LFS 409 "lock already exists" response. The locking spec's
/// create endpoint returns `{ "lock": {...}, "message": "..." }` so the client
/// can surface the current holder.
fn lock_conflict_response(existing: Option<LockInfo>) -> Response {
    let body = serde_json::json!({
        "lock": existing,
        "message": "Lock already exists for this path",
    });
    lfs_json_response(StatusCode::CONFLICT, &body)
}

// ---------------------------------------------------------------------------
// GET /lfs/:repo_key/locks - List locks
// ---------------------------------------------------------------------------

async fn list_locks(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    // Per the Git LFS file-locking spec, GET /locks requires authentication
    // (https://github.com/git-lfs/git-lfs/blob/main/docs/api/locking.md).
    // Without it, anyone can enumerate file locks (paths, owners, timestamps)
    // for any LFS repo on this server. Match the auth pattern used by the
    // sibling lock handlers (create_lock, delete_lock, verify_locks).
    let _user_id = require_auth_basic(auth, "git-lfs")?.user_id;
    let repo = resolve_lfs_repo(&state.db, &repo_key).await?;

    let rows = sqlx::query!(
        r#"
        SELECT id, path, locked_at, owner_name
        FROM lfs_locks
        WHERE repository_id = $1
        ORDER BY locked_at DESC
        "#,
        repo.id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        lfs_error_response(
            crate::api::handlers::db_status(&e),
            &format!("Database error: {}", e),
        )
    })?;

    let locks: Vec<LockInfo> = rows
        .into_iter()
        .map(|row| LockInfo {
            id: row.id.to_string(),
            path: row.path,
            locked_at: row.locked_at.to_rfc3339(),
            owner: LockOwner {
                name: row.owner_name,
            },
        })
        .collect();

    let response = LockListResponse {
        locks,
        next_cursor: None,
    };

    Ok(lfs_json_response(StatusCode::OK, &response))
}

// ---------------------------------------------------------------------------
// POST /lfs/:repo_key/locks/verify - Verify locks
// ---------------------------------------------------------------------------

async fn verify_locks(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    body: Bytes,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "git-lfs", "write")?.user_id;
    let repo = resolve_lfs_repo(&state.db, &repo_key).await?;

    // Parse request body (optional, may be empty)
    let _request: Option<VerifyLocksRequest> = if body.is_empty() {
        None
    } else {
        Some(serde_json::from_slice(&body).map_err(|e| {
            lfs_error_response(StatusCode::BAD_REQUEST, &format!("Invalid JSON: {}", e))
        })?)
    };

    let username = sqlx::query_scalar!("SELECT username FROM users WHERE id = $1", user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            lfs_error_response(
                crate::api::handlers::db_status(&e),
                &format!("Database error: {}", e),
            )
        })?;

    let rows = sqlx::query!(
        r#"
        SELECT id, path, locked_at, owner_name
        FROM lfs_locks
        WHERE repository_id = $1
        ORDER BY locked_at DESC
        "#,
        repo.id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        lfs_error_response(
            crate::api::handlers::db_status(&e),
            &format!("Database error: {}", e),
        )
    })?;

    let mut ours = Vec::new();
    let mut theirs = Vec::new();

    for row in rows {
        let lock_info = LockInfo {
            id: row.id.to_string(),
            path: row.path,
            locked_at: row.locked_at.to_rfc3339(),
            owner: LockOwner {
                name: row.owner_name,
            },
        };

        if lock_info.owner.name == username {
            ours.push(lock_info);
        } else {
            theirs.push(lock_info);
        }
    }

    let response = VerifyLocksResponse {
        ours,
        theirs,
        next_cursor: None,
    };

    Ok(lfs_json_response(StatusCode::OK, &response))
}

// ---------------------------------------------------------------------------
// POST /lfs/:repo_key/locks/:id/unlock - Delete lock
// ---------------------------------------------------------------------------

async fn delete_lock(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, lock_id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "git-lfs", "delete")?.user_id;
    let repo = resolve_lfs_repo(&state.db, &repo_key).await?;

    let force = if body.is_empty() {
        false
    } else {
        serde_json::from_slice::<UnlockRequest>(&body)
            .map(|r| r.force)
            .unwrap_or(false)
    };

    // Look up the user
    let username = sqlx::query_scalar!("SELECT username FROM users WHERE id = $1", user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            lfs_error_response(
                crate::api::handlers::db_status(&e),
                &format!("Database error: {}", e),
            )
        })?;

    // The lock id is the `lfs_locks.id` UUID handed out by create_lock. An
    // unparseable id simply cannot match any row -> 404 (never a 500).
    let lock_uuid = uuid::Uuid::parse_str(&lock_id)
        .map_err(|_| lfs_error_response(StatusCode::NOT_FOUND, "Lock not found"))?;

    // Find the lock (scoped to this repository).
    let row = sqlx::query!(
        r#"
        SELECT id, path, locked_at, owner_name
        FROM lfs_locks
        WHERE repository_id = $1
          AND id = $2
        "#,
        repo.id,
        lock_uuid
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        lfs_error_response(
            crate::api::handlers::db_status(&e),
            &format!("Database error: {}", e),
        )
    })?
    .ok_or_else(|| lfs_error_response(StatusCode::NOT_FOUND, "Lock not found"))?;

    // Only the lock owner or a forced unlock can release it.
    if row.owner_name != username && !force {
        return Err(lfs_error_response(
            StatusCode::FORBIDDEN,
            "You do not own this lock",
        ));
    }

    let lock_info = LockInfo {
        id: lock_id.clone(),
        path: row.path,
        locked_at: row.locked_at.to_rfc3339(),
        owner: LockOwner {
            name: row.owner_name,
        },
    };

    // Delete the lock
    sqlx::query!("DELETE FROM lfs_locks WHERE id = $1", lock_uuid)
        .execute(&state.db)
        .await
        .map_err(|e| {
            lfs_error_response(
                crate::api::handlers::db_status(&e),
                &format!("Database error: {}", e),
            )
        })?;

    info!(
        "Git LFS unlock: {} by {} (force: {})",
        lock_id, username, force
    );

    let response = UnlockResponse { lock: lock_info };
    Ok(lfs_json_response(StatusCode::OK, &response))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // extract_credentials
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // validate_oid
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_oid_valid() {
        let oid = "a".repeat(64);
        assert!(validate_oid(&oid).is_ok());
    }

    #[test]
    fn test_validate_oid_valid_hex() {
        let oid = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        assert_eq!(oid.len(), 64);
        assert!(validate_oid(oid).is_ok());
    }

    #[test]
    fn test_validate_oid_too_short() {
        let oid = "abc123";
        assert!(validate_oid(oid).is_err());
    }

    #[test]
    fn test_validate_oid_too_long() {
        let oid = "a".repeat(65);
        assert!(validate_oid(&oid).is_err());
    }

    #[test]
    fn test_validate_oid_non_hex() {
        let oid = "g".repeat(64);
        assert!(validate_oid(&oid).is_err());
    }

    #[test]
    fn test_validate_oid_mixed_case_hex() {
        let oid = "ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789";
        assert_eq!(oid.len(), 64);
        assert!(validate_oid(oid).is_ok());
    }

    #[test]
    fn test_validate_oid_empty() {
        assert!(validate_oid("").is_err());
    }

    #[test]
    fn test_validate_oid_with_spaces() {
        let oid = format!("{} ", "a".repeat(63));
        assert!(validate_oid(&oid).is_err());
    }

    // -----------------------------------------------------------------------
    // LFS content type constant
    // -----------------------------------------------------------------------

    #[test]
    fn test_lfs_content_type() {
        assert_eq!(LFS_CONTENT_TYPE, "application/vnd.git-lfs+json");
    }

    // -----------------------------------------------------------------------
    // lfs_json_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_lfs_json_response() {
        let data = serde_json::json!({"key": "value"});
        let response = lfs_json_response(StatusCode::OK, &data);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            LFS_CONTENT_TYPE
        );
    }

    // -----------------------------------------------------------------------
    // lfs_error_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_lfs_error_response() {
        let response = lfs_error_response(StatusCode::NOT_FOUND, "Object not found");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            LFS_CONTENT_TYPE
        );
    }

    #[test]
    fn test_lfs_error_response_unauthorized() {
        let response = lfs_error_response(StatusCode::UNAUTHORIZED, "Auth required");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // -----------------------------------------------------------------------
    // BatchRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_batch_request_deserialization() {
        let json = r#"{
            "operation": "download",
            "transfers": ["basic"],
            "objects": [
                {"oid": "abc123", "size": 1024}
            ]
        }"#;
        let req: BatchRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.operation, "download");
        assert_eq!(req.transfers, vec!["basic"]);
        assert_eq!(req.objects.len(), 1);
        assert_eq!(req.objects[0].oid, "abc123");
        assert_eq!(req.objects[0].size, 1024);
    }

    #[test]
    fn test_batch_request_empty_transfers() {
        let json = r#"{
            "operation": "upload",
            "objects": [{"oid": "def456", "size": 512}]
        }"#;
        let req: BatchRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.operation, "upload");
        assert!(req.transfers.is_empty());
    }

    // -----------------------------------------------------------------------
    // BatchResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_batch_response_serialization() {
        let response = BatchResponse {
            transfer: "basic".to_string(),
            objects: vec![BatchResponseObject {
                oid: "abcdef".to_string(),
                size: 1024,
                authenticated: Some(true),
                actions: None,
                error: None,
            }],
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["transfer"], "basic");
        assert_eq!(json["objects"][0]["oid"], "abcdef");
        assert_eq!(json["objects"][0]["authenticated"], true);
        // actions and error should be skipped when None
        assert!(json["objects"][0].get("actions").is_none());
        assert!(json["objects"][0].get("error").is_none());
    }

    #[test]
    fn test_batch_response_with_actions() {
        let response = BatchResponseObject {
            oid: "test_oid".to_string(),
            size: 2048,
            authenticated: Some(true),
            actions: Some(BatchActions {
                download: Some(BatchAction {
                    href: "https://example.com/download".to_string(),
                    header: serde_json::json!({}),
                    expires_in: 3600,
                }),
                upload: None,
                verify: None,
            }),
            error: None,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(
            json["actions"]["download"]["href"],
            "https://example.com/download"
        );
        assert_eq!(json["actions"]["download"]["expires_in"], 3600);
        assert!(json["actions"].get("upload").is_none());
    }

    #[test]
    fn test_batch_response_with_error() {
        let response = BatchResponseObject {
            oid: "err_oid".to_string(),
            size: 0,
            authenticated: None,
            actions: None,
            error: Some(LfsError {
                code: 404,
                message: "Not found".to_string(),
            }),
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["error"]["code"], 404);
        assert_eq!(json["error"]["message"], "Not found");
    }

    // -----------------------------------------------------------------------
    // VerifyRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_verify_request_deserialization() {
        let json = r#"{"oid":"abc123","size":1024}"#;
        let req: VerifyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.oid, "abc123");
        assert_eq!(req.size, 1024);
    }

    // -----------------------------------------------------------------------
    // CreateLockRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_lock_request() {
        let json = r#"{"path":"models/big-model.bin","ref":{"name":"refs/heads/main"}}"#;
        let req: CreateLockRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.path, "models/big-model.bin");
        assert_eq!(req.lock_ref.unwrap().name, "refs/heads/main");
    }

    #[test]
    fn test_create_lock_request_no_ref() {
        let json = r#"{"path":"data/file.txt"}"#;
        let req: CreateLockRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.path, "data/file.txt");
        assert!(req.lock_ref.is_none());
    }

    // -----------------------------------------------------------------------
    // UnlockRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_unlock_request_force() {
        let json = r#"{"force":true}"#;
        let req: UnlockRequest = serde_json::from_str(json).unwrap();
        assert!(req.force);
    }

    #[test]
    fn test_unlock_request_default() {
        let json = r#"{}"#;
        let req: UnlockRequest = serde_json::from_str(json).unwrap();
        assert!(!req.force);
    }

    // -----------------------------------------------------------------------
    // LockInfo / LockResponse / LockListResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_lock_response_serialization() {
        let response = LockResponse {
            lock: LockInfo {
                id: "lock-1".to_string(),
                path: "images/large.bin".to_string(),
                locked_at: "2024-01-01T00:00:00Z".to_string(),
                owner: LockOwner {
                    name: "alice".to_string(),
                },
            },
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["lock"]["id"], "lock-1");
        assert_eq!(json["lock"]["path"], "images/large.bin");
        assert_eq!(json["lock"]["owner"]["name"], "alice");
    }

    #[test]
    fn test_lock_list_response_empty() {
        let response = LockListResponse {
            locks: vec![],
            next_cursor: None,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["locks"].as_array().unwrap().len(), 0);
        assert!(json.get("next_cursor").is_none());
    }

    #[test]
    fn test_verify_locks_response() {
        let response = VerifyLocksResponse {
            ours: vec![LockInfo {
                id: "1".to_string(),
                path: "a.bin".to_string(),
                locked_at: "2024-01-01T00:00:00Z".to_string(),
                owner: LockOwner {
                    name: "me".to_string(),
                },
            }],
            theirs: vec![],
            next_cursor: None,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["ours"].as_array().unwrap().len(), 1);
        assert_eq!(json["theirs"].as_array().unwrap().len(), 0);
    }

    // -----------------------------------------------------------------------
    // Storage key formatting
    // -----------------------------------------------------------------------

    #[test]
    fn test_lfs_storage_key_format() {
        let oid = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let storage_key = format!("gitlfs/{}/{}", &oid[..2], oid);
        assert_eq!(
            storage_key,
            "gitlfs/ab/abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        );
    }

    #[test]
    fn test_lfs_artifact_path_format() {
        let oid = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let artifact_path = format!("lfs/objects/{}/{}", &oid[..2], oid);
        assert!(artifact_path.starts_with("lfs/objects/ab/"));
    }

    // -----------------------------------------------------------------------
    // RepoInfo struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_info_construction() {
        let id = uuid::Uuid::new_v4();
        let info = RepoInfo {
            id,
            key: String::new(),
            storage_path: "/data/lfs".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: None,
            format: "generic".to_string(),
            promotion_only: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
        };
        assert_eq!(info.repo_type, "hosted");
        assert!(info.upstream_url.is_none());
    }

    // -----------------------------------------------------------------------
    // Auth-required lock endpoints (regression guard)
    //
    // Per the Git LFS file-locking spec, every locks endpoint requires
    // authentication. `require_auth_basic` is the seam every lock handler
    // (create_lock, delete_lock, verify_locks, list_locks) routes through.
    // If a refactor ever drops the auth call from a handler, this test still
    // proves the helper rejects unauthenticated callers — and the handler's
    // type signature (Extension<Option<AuthExtension>>) makes the bypass a
    // compile error rather than a silent regression.
    // -----------------------------------------------------------------------

    #[test]
    fn test_require_auth_basic_rejects_missing_auth() {
        // Calling the auth helper without any AuthExtension must produce an
        // error response — this is what every locks handler relies on to
        // enforce authentication.
        let result = require_auth_basic(None, "git-lfs");
        assert!(
            result.is_err(),
            "require_auth_basic(None, ...) must return Err to deny unauthenticated callers"
        );
    }

    // -----------------------------------------------------------------------
    // DB-backed Git LFS file-locking tests (#2627).
    //
    // These drive the four lock handlers this fix rewrote onto the dedicated
    // `lfs_locks` table (migration 165). Each handler is called directly with
    // hand-built extractors against a live database, so `cargo llvm-cov --lib`
    // — which is exactly what the CI coverage job runs — instruments them.
    //
    // The sibling HTTP-level suite in `backend/tests/gitlfs_locks_tests.rs` is
    // an integration (`--test`) target: it is a useful end-to-end guard over
    // the real router, but `--lib` never builds it, so it contributes no
    // coverage. These tests cover the handler bodies; that suite covers the
    // wiring.
    //
    // Runtime-skips when `DATABASE_URL` is unset (NOT `#[ignore]`, so the
    // coverage instrument sees these paths in CI, which stands up Postgres and
    // applies migrations before the coverage run). Mirrors the in-`src`
    // DB-test pattern used by the approval/migration handler suites.
    // -----------------------------------------------------------------------
    #[allow(clippy::disallowed_methods)]
    // streaming-invariant: test module exempt — buffering a small JSON lock
    // response body in an assertion is not an artifact path (#1608).
    mod locks_db {
        use super::*;
        use crate::api::handlers::test_db_helpers as tdh;
        use sqlx::PgPool;
        use uuid::Uuid;

        /// A live `gitlfs` repository, its owner, and a second principal used by
        /// the ownership / force-unlock paths.
        struct Fx {
            pool: PgPool,
            state: SharedState,
            repo_id: Uuid,
            repo_key: String,
            user_id: Uuid,
            username: String,
            other_id: Uuid,
            other_name: String,
        }

        impl Fx {
            /// Session-shaped auth for the lock owner. `scopes: None` grants
            /// every scope, so the scope-reject tests opt in via [`token_auth`].
            fn auth(&self) -> AuthExtension {
                tdh::make_auth(self.user_id, &self.username)
            }

            /// The owner presented as an API token carrying exactly `scopes` —
            /// the shape `require_auth_basic_scope` gates on.
            fn token_auth(&self, scopes: &[&str]) -> AuthExtension {
                let mut ext = self.auth();
                ext.is_api_token = true;
                ext.scopes = Some(scopes.iter().map(|s| s.to_string()).collect());
                ext
            }

            /// Insert a lock row directly, bypassing `create_lock`.
            async fn seed_lock(&self, path: &str, owner_id: Uuid, owner_name: &str) -> Uuid {
                sqlx::query_scalar::<_, Uuid>(
                    "INSERT INTO lfs_locks (repository_id, path, owner_id, owner_name) \
                     VALUES ($1, $2, $3, $4) RETURNING id",
                )
                .bind(self.repo_id)
                .bind(path)
                .bind(owner_id)
                .bind(owner_name)
                .fetch_one(&self.pool)
                .await
                .expect("seed lfs_locks row")
            }

            async fn lock_count(&self, path: &str) -> i64 {
                sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM lfs_locks WHERE repository_id = $1 AND path = $2",
                )
                .bind(self.repo_id)
                .bind(path)
                .fetch_one(&self.pool)
                .await
                .expect("count lfs_locks rows")
            }

            async fn cleanup(&self) {
                // `lfs_locks` cascades from both `repositories` and `users`.
                tdh::cleanup(&self.pool, self.repo_id, self.user_id).await;
                let _ = sqlx::query("DELETE FROM users WHERE id = $1")
                    .bind(self.other_id)
                    .execute(&self.pool)
                    .await;
            }
        }

        /// Build the fixture, or `None` when no database is reachable.
        async fn fx() -> Option<Fx> {
            let pool = tdh::try_pool().await?;
            let (repo_id, repo_key, storage_dir) = tdh::create_repo(&pool, "local", "gitlfs").await;
            let (user_id, username) = tdh::create_user(&pool).await;
            let (other_id, other_name) = tdh::create_user(&pool).await;
            let state = tdh::build_state(pool.clone(), storage_dir.to_string_lossy().as_ref());
            Some(Fx {
                pool,
                state,
                repo_id,
                repo_key,
                user_id,
                username,
                other_id,
                other_name,
            })
        }

        /// Collapse a handler's `Result<Response, Response>` into the status and
        /// body bytes both arms carry.
        async fn parts(out: Result<Response, Response>) -> (StatusCode, Bytes) {
            let response = match out {
                Ok(r) => r,
                Err(r) => r,
            };
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("read response body");
            (status, body)
        }

        fn as_json(body: &Bytes) -> serde_json::Value {
            serde_json::from_slice(body).expect("response body must be JSON")
        }

        /// `path` field of every lock in a response array, in response order.
        fn paths_of(value: &serde_json::Value) -> Vec<String> {
            value
                .as_array()
                .map(|locks| {
                    locks
                        .iter()
                        .map(|l| l["path"].as_str().unwrap_or_default().to_string())
                        .collect()
                })
                .unwrap_or_default()
        }

        // -------------------------------------------------------------------
        // create_lock
        // -------------------------------------------------------------------

        #[tokio::test]
        async fn create_lock_rejects_token_without_write_scope() {
            let Some(fx) = fx().await else {
                return;
            };
            let (status, body) = parts(
                create_lock(
                    State(fx.state.clone()),
                    Extension(Some(fx.token_auth(&["git-lfs:read"]))),
                    Path(fx.repo_key.clone()),
                    Bytes::from_static(br#"{"path":"a/b.bin"}"#),
                )
                .await,
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert!(
                String::from_utf8_lossy(&body).contains("required scope: write"),
                "expected a scope-denial body, got {:?}",
                String::from_utf8_lossy(&body)
            );
            assert_eq!(
                fx.lock_count("a/b.bin").await,
                0,
                "a scope-denied create must not take the lock"
            );
            fx.cleanup().await;
        }

        #[tokio::test]
        async fn create_lock_unknown_repository_is_404() {
            let Some(fx) = fx().await else {
                return;
            };
            let (status, body) = parts(
                create_lock(
                    State(fx.state.clone()),
                    Extension(Some(fx.auth())),
                    Path("lfs-no-such-repo-2627".to_string()),
                    Bytes::from_static(br#"{"path":"a.bin"}"#),
                )
                .await,
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            assert_eq!(as_json(&body)["message"], "Repository not found");
            fx.cleanup().await;
        }

        #[tokio::test]
        async fn create_lock_invalid_json_is_400() {
            let Some(fx) = fx().await else {
                return;
            };
            let (status, body) = parts(
                create_lock(
                    State(fx.state.clone()),
                    Extension(Some(fx.auth())),
                    Path(fx.repo_key.clone()),
                    Bytes::from_static(b"{not json"),
                )
                .await,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            let message = as_json(&body)["message"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            assert!(
                message.starts_with("Invalid JSON"),
                "expected an Invalid JSON message, got {message:?}"
            );
            fx.cleanup().await;
        }

        #[tokio::test]
        async fn create_lock_empty_path_is_400() {
            let Some(fx) = fx().await else {
                return;
            };
            let (status, body) = parts(
                create_lock(
                    State(fx.state.clone()),
                    Extension(Some(fx.auth())),
                    Path(fx.repo_key.clone()),
                    Bytes::from_static(br#"{"path":""}"#),
                )
                .await,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(as_json(&body)["message"], "Lock path is required");
            fx.cleanup().await;
        }

        /// The happy path: a lock is persisted to `lfs_locks` (the table
        /// migration 165 added) and reported in the LFS response shape.
        #[tokio::test]
        async fn create_lock_persists_the_lock_and_returns_201() {
            let Some(fx) = fx().await else {
                return;
            };
            let response = create_lock(
                State(fx.state.clone()),
                Extension(Some(fx.auth())),
                Path(fx.repo_key.clone()),
                Bytes::from_static(
                    br#"{"path":"data/model.bin","ref":{"name":"refs/heads/main"}}"#,
                ),
            )
            .await
            .expect("create_lock must succeed for an unlocked path");

            assert_eq!(response.status(), StatusCode::CREATED);
            assert_eq!(
                response
                    .headers()
                    .get(CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok()),
                Some(LFS_CONTENT_TYPE),
                "LFS clients require the git-lfs media type"
            );
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("read response body");

            let json = as_json(&body);
            let lock = &json["lock"];
            assert_eq!(lock["path"], "data/model.bin");
            assert_eq!(lock["owner"]["name"], fx.username.as_str());
            assert!(
                Uuid::parse_str(lock["id"].as_str().unwrap_or_default()).is_ok(),
                "the lock id must be the lfs_locks UUID, got {:?}",
                lock["id"]
            );
            assert!(
                chrono::DateTime::parse_from_rfc3339(
                    lock["locked_at"].as_str().unwrap_or_default()
                )
                .is_ok(),
                "locked_at must be RFC3339, got {:?}",
                lock["locked_at"]
            );

            // The row lands in the dedicated table with the ref and owner
            // recorded — the storage this fix introduced.
            let (ref_name, owner_id): (Option<String>, Uuid) = sqlx::query_as(
                "SELECT ref_name, owner_id FROM lfs_locks WHERE repository_id = $1 AND path = $2",
            )
            .bind(fx.repo_id)
            .bind("data/model.bin")
            .fetch_one(&fx.pool)
            .await
            .expect("the lock row must exist");
            assert_eq!(ref_name.as_deref(), Some("refs/heads/main"));
            assert_eq!(owner_id, fx.user_id);

            fx.cleanup().await;
        }

        #[tokio::test]
        async fn create_lock_on_a_locked_path_is_409_naming_the_holder() {
            let Some(fx) = fx().await else {
                return;
            };
            fx.seed_lock("shared/asset.psd", fx.other_id, &fx.other_name)
                .await;

            let (status, body) = parts(
                create_lock(
                    State(fx.state.clone()),
                    Extension(Some(fx.auth())),
                    Path(fx.repo_key.clone()),
                    Bytes::from_static(br#"{"path":"shared/asset.psd"}"#),
                )
                .await,
            )
            .await;

            assert_eq!(status, StatusCode::CONFLICT);
            let json = as_json(&body);
            assert_eq!(json["message"], "Lock already exists for this path");
            // Per the LFS locking spec the 409 carries the CURRENT holder so the
            // client can report who to ask.
            assert_eq!(json["lock"]["path"], "shared/asset.psd");
            assert_eq!(json["lock"]["owner"]["name"], fx.other_name.as_str());
            assert_eq!(
                fx.lock_count("shared/asset.psd").await,
                1,
                "the (repository_id, path) unique constraint must keep a single holder"
            );
            fx.cleanup().await;
        }

        /// The `existing == None` arm of the 409 builder. `create_lock` reaches
        /// it when the conflicting row is deleted between the
        /// `INSERT ... ON CONFLICT DO NOTHING` and the follow-up SELECT (a
        /// concurrent unlock). The response must still be a well-formed 409
        /// carrying a null lock rather than a 500. Needs no database.
        #[tokio::test]
        async fn lock_conflict_response_tolerates_a_vanished_holder() {
            let response = lock_conflict_response(None);
            assert_eq!(response.status(), StatusCode::CONFLICT);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("read response body");
            let json = as_json(&body);
            assert!(
                json["lock"].is_null(),
                "a holder that vanished mid-request must serialize as null"
            );
            assert_eq!(json["message"], "Lock already exists for this path");
        }

        // -------------------------------------------------------------------
        // list_locks
        // -------------------------------------------------------------------

        #[tokio::test]
        async fn list_locks_requires_authentication() {
            let Some(fx) = fx().await else {
                return;
            };
            let (status, body) = parts(
                list_locks(
                    State(fx.state.clone()),
                    Extension(None),
                    Path(fx.repo_key.clone()),
                )
                .await,
            )
            .await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "anonymous callers must not enumerate lock paths and holders"
            );
            assert_eq!(String::from_utf8_lossy(&body), "Authentication required");
            fx.cleanup().await;
        }

        #[tokio::test]
        async fn list_locks_returns_the_repository_locks() {
            let Some(fx) = fx().await else {
                return;
            };
            fx.seed_lock("mine.bin", fx.user_id, &fx.username).await;
            fx.seed_lock("theirs.bin", fx.other_id, &fx.other_name)
                .await;

            let (status, body) = parts(
                list_locks(
                    State(fx.state.clone()),
                    Extension(Some(fx.auth())),
                    Path(fx.repo_key.clone()),
                )
                .await,
            )
            .await;

            assert_eq!(status, StatusCode::OK);
            let json = as_json(&body);
            let mut paths = paths_of(&json["locks"]);
            paths.sort();
            assert_eq!(paths, vec!["mine.bin", "theirs.bin"]);
            // `next_cursor` is None -> omitted; a present cursor tells an LFS
            // client there is another page to fetch.
            assert!(
                json.get("next_cursor").is_none(),
                "next_cursor must be omitted when there is no next page"
            );
            fx.cleanup().await;
        }

        // -------------------------------------------------------------------
        // verify_locks
        // -------------------------------------------------------------------

        /// git-lfs sends no body when it has no ref to report, and the handler
        /// must treat that as "no ref filter" rather than a parse error.
        #[tokio::test]
        async fn verify_locks_accepts_an_empty_body_and_partitions_ours_from_theirs() {
            let Some(fx) = fx().await else {
                return;
            };
            fx.seed_lock("mine.bin", fx.user_id, &fx.username).await;
            fx.seed_lock("theirs.bin", fx.other_id, &fx.other_name)
                .await;

            let (status, body) = parts(
                verify_locks(
                    State(fx.state.clone()),
                    Extension(Some(fx.auth())),
                    Path(fx.repo_key.clone()),
                    Bytes::new(),
                )
                .await,
            )
            .await;

            assert_eq!(status, StatusCode::OK);
            let json = as_json(&body);
            assert_eq!(paths_of(&json["ours"]), vec!["mine.bin"]);
            assert_eq!(paths_of(&json["theirs"]), vec!["theirs.bin"]);
            assert!(json.get("next_cursor").is_none());
            fx.cleanup().await;
        }

        #[tokio::test]
        async fn verify_locks_accepts_a_ref_body() {
            let Some(fx) = fx().await else {
                return;
            };
            fx.seed_lock("mine.bin", fx.user_id, &fx.username).await;

            let (status, body) = parts(
                verify_locks(
                    State(fx.state.clone()),
                    Extension(Some(fx.auth())),
                    Path(fx.repo_key.clone()),
                    Bytes::from_static(br#"{"ref":{"name":"refs/heads/main"}}"#),
                )
                .await,
            )
            .await;

            assert_eq!(status, StatusCode::OK);
            let json = as_json(&body);
            assert_eq!(paths_of(&json["ours"]), vec!["mine.bin"]);
            assert!(paths_of(&json["theirs"]).is_empty());
            fx.cleanup().await;
        }

        #[tokio::test]
        async fn verify_locks_invalid_json_is_400() {
            let Some(fx) = fx().await else {
                return;
            };
            let (status, body) = parts(
                verify_locks(
                    State(fx.state.clone()),
                    Extension(Some(fx.auth())),
                    Path(fx.repo_key.clone()),
                    Bytes::from_static(b"{\"ref\":"),
                )
                .await,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            let message = as_json(&body)["message"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            assert!(
                message.starts_with("Invalid JSON"),
                "expected an Invalid JSON message, got {message:?}"
            );
            fx.cleanup().await;
        }

        #[tokio::test]
        async fn verify_locks_rejects_token_without_write_scope() {
            let Some(fx) = fx().await else {
                return;
            };
            let (status, _) = parts(
                verify_locks(
                    State(fx.state.clone()),
                    Extension(Some(fx.token_auth(&["git-lfs:read"]))),
                    Path(fx.repo_key.clone()),
                    Bytes::new(),
                )
                .await,
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            fx.cleanup().await;
        }

        // -------------------------------------------------------------------
        // delete_lock
        // -------------------------------------------------------------------

        /// The headline #2627 fix: the lock id is a `lfs_locks.id` UUID, and a
        /// client that sends anything else cannot match a row. That must be a
        /// 404, never a 500 from a failed UUID bind.
        #[tokio::test]
        async fn delete_lock_unparseable_id_is_404_not_500() {
            let Some(fx) = fx().await else {
                return;
            };
            let (status, body) = parts(
                delete_lock(
                    State(fx.state.clone()),
                    Extension(Some(fx.auth())),
                    Path((fx.repo_key.clone(), "not-a-uuid".to_string())),
                    Bytes::new(),
                )
                .await,
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            assert_eq!(as_json(&body)["message"], "Lock not found");
            fx.cleanup().await;
        }

        #[tokio::test]
        async fn delete_lock_unknown_id_is_404() {
            let Some(fx) = fx().await else {
                return;
            };
            let (status, body) = parts(
                delete_lock(
                    State(fx.state.clone()),
                    Extension(Some(fx.auth())),
                    Path((fx.repo_key.clone(), Uuid::new_v4().to_string())),
                    Bytes::new(),
                )
                .await,
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            assert_eq!(as_json(&body)["message"], "Lock not found");
            fx.cleanup().await;
        }

        #[tokio::test]
        async fn delete_lock_owner_releases_the_lock() {
            let Some(fx) = fx().await else {
                return;
            };
            let id = fx.seed_lock("mine.bin", fx.user_id, &fx.username).await;

            let (status, body) = parts(
                delete_lock(
                    State(fx.state.clone()),
                    Extension(Some(fx.auth())),
                    Path((fx.repo_key.clone(), id.to_string())),
                    Bytes::new(),
                )
                .await,
            )
            .await;

            assert_eq!(status, StatusCode::OK);
            let lock = &as_json(&body)["lock"];
            assert_eq!(lock["id"], id.to_string());
            assert_eq!(lock["path"], "mine.bin");
            assert_eq!(lock["owner"]["name"], fx.username.as_str());
            assert_eq!(
                fx.lock_count("mine.bin").await,
                0,
                "the lock row must be deleted"
            );
            fx.cleanup().await;
        }

        /// An empty unlock body means `force` defaults to false, so the
        /// ownership check still applies.
        #[tokio::test]
        async fn delete_lock_empty_body_does_not_force() {
            let Some(fx) = fx().await else {
                return;
            };
            let id = fx
                .seed_lock("theirs.bin", fx.other_id, &fx.other_name)
                .await;

            let (status, body) = parts(
                delete_lock(
                    State(fx.state.clone()),
                    Extension(Some(fx.auth())),
                    Path((fx.repo_key.clone(), id.to_string())),
                    Bytes::new(),
                )
                .await,
            )
            .await;

            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(as_json(&body)["message"], "You do not own this lock");
            assert_eq!(
                fx.lock_count("theirs.bin").await,
                1,
                "a refused unlock must leave the lock in place"
            );
            fx.cleanup().await;
        }

        /// A malformed unlock body must not be read as `force = true` — that
        /// would let any caller steal another user's lock. `unwrap_or(false)`
        /// keeps the ownership check in force.
        #[tokio::test]
        async fn delete_lock_malformed_body_is_not_a_force_unlock() {
            let Some(fx) = fx().await else {
                return;
            };
            let id = fx
                .seed_lock("theirs.bin", fx.other_id, &fx.other_name)
                .await;

            let (status, _) = parts(
                delete_lock(
                    State(fx.state.clone()),
                    Extension(Some(fx.auth())),
                    Path((fx.repo_key.clone(), id.to_string())),
                    Bytes::from_static(br#"{"force":"yes-please"}"#),
                )
                .await,
            )
            .await;

            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(
                fx.lock_count("theirs.bin").await,
                1,
                "an unparseable force flag must not release someone else's lock"
            );
            fx.cleanup().await;
        }

        #[tokio::test]
        async fn delete_lock_force_releases_another_users_lock() {
            let Some(fx) = fx().await else {
                return;
            };
            let id = fx
                .seed_lock("theirs.bin", fx.other_id, &fx.other_name)
                .await;

            let (status, body) = parts(
                delete_lock(
                    State(fx.state.clone()),
                    Extension(Some(fx.auth())),
                    Path((fx.repo_key.clone(), id.to_string())),
                    Bytes::from_static(br#"{"force":true}"#),
                )
                .await,
            )
            .await;

            assert_eq!(status, StatusCode::OK);
            // The response reports the ORIGINAL holder, not the forcing caller.
            assert_eq!(
                as_json(&body)["lock"]["owner"]["name"],
                fx.other_name.as_str()
            );
            assert_eq!(fx.lock_count("theirs.bin").await, 0);
            fx.cleanup().await;
        }

        #[tokio::test]
        async fn delete_lock_rejects_token_without_delete_scope() {
            let Some(fx) = fx().await else {
                return;
            };
            let id = fx.seed_lock("mine.bin", fx.user_id, &fx.username).await;

            let (status, _) = parts(
                delete_lock(
                    State(fx.state.clone()),
                    Extension(Some(fx.token_auth(&["git-lfs:write"]))),
                    Path((fx.repo_key.clone(), id.to_string())),
                    Bytes::new(),
                )
                .await,
            )
            .await;

            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "a write-scoped token must not be able to unlock"
            );
            assert_eq!(
                fx.lock_count("mine.bin").await,
                1,
                "a scope-denied unlock must not delete the row"
            );
            fx.cleanup().await;
        }
    }
}
