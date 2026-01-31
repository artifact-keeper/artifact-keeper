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

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{post, put};
use axum::Router;
use base64::Engine;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::SharedState;
use crate::services::auth_service::AuthService;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::StorageBackend;

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
// Auth helpers
// ---------------------------------------------------------------------------

fn extract_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    // Try Basic auth (standard for Git LFS)
    if let Some(creds) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic ").or(v.strip_prefix("basic ")))
        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|s| {
            let mut parts = s.splitn(2, ':');
            let user = parts.next()?.to_string();
            let pass = parts.next()?.to_string();
            Some((user, pass))
        })
    {
        return Some(creds);
    }

    // Try Bearer token
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or(v.strip_prefix("bearer ")))
        .map(|token| ("token".to_string(), token.to_string()))
}

async fn authenticate(
    db: &PgPool,
    config: &crate::config::Config,
    headers: &HeaderMap,
) -> Result<uuid::Uuid, Response> {
    let (username, password) = extract_credentials(headers).ok_or_else(|| {
        lfs_error_response(
            StatusCode::UNAUTHORIZED,
            "Authentication required",
        )
    })?;

    let auth_service = AuthService::new(db.clone(), Arc::new(config.clone()));
    let (user, _tokens) = auth_service
        .authenticate(&username, &password)
        .await
        .map_err(|_| {
            lfs_error_response(
                StatusCode::UNAUTHORIZED,
                "Invalid credentials",
            )
        })?;

    Ok(user.id)
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

struct RepoInfo {
    id: uuid::Uuid,
    storage_path: String,
}

async fn resolve_lfs_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    let repo = sqlx::query!(
        "SELECT id, storage_path, format::text as \"format!\" FROM repositories WHERE key = $1",
        repo_key
    )
    .fetch_optional(db)
    .await
    .map_err(|e| {
        lfs_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Database error: {}", e),
        )
    })?
    .ok_or_else(|| {
        lfs_error_response(StatusCode::NOT_FOUND, "Repository not found")
    })?;

    let fmt = repo.format.to_lowercase();
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
        id: repo.id,
        storage_path: repo.storage_path,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, LFS_CONTENT_TYPE)
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap()
}

// ---------------------------------------------------------------------------
// POST /lfs/:repo_key/objects/batch - Batch API
// ---------------------------------------------------------------------------

async fn batch(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let repo = resolve_lfs_repo(&state.db, &repo_key).await?;

    let request: BatchRequest = serde_json::from_slice(&body).map_err(|e| {
        lfs_error_response(
            StatusCode::BAD_REQUEST,
            &format!("Invalid JSON: {}", e),
        )
    })?;

    if request.operation != "download" && request.operation != "upload" {
        return Err(lfs_error_response(
            StatusCode::BAD_REQUEST,
            &format!("Unsupported operation: {}", request.operation),
        ));
    }

    // Upload requires authentication
    let auth_header = if request.operation == "upload" {
        let _user_id = authenticate(&state.db, &state.config, &headers).await?;
        // Pass auth header through to action hrefs
        headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string())
    } else {
        None
    };

    let base_url = build_base_url(&headers, &repo_key);
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
                StatusCode::INTERNAL_SERVER_ERROR,
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

fn build_base_url(headers: &HeaderMap, repo_key: &str) -> String {
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http");

    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");

    format!("{}://{}/lfs/{}", scheme, host, repo_key)
}

// ---------------------------------------------------------------------------
// PUT /lfs/:repo_key/objects/:oid - Upload object
// ---------------------------------------------------------------------------

async fn upload_object(
    State(state): State<SharedState>,
    Path((repo_key, oid)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_lfs_repo(&state.db, &repo_key).await?;
    validate_oid(&oid)?;

    if body.is_empty() {
        return Err(lfs_error_response(
            StatusCode::BAD_REQUEST,
            "Empty body",
        ));
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
            StatusCode::INTERNAL_SERVER_ERROR,
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
    let storage = FilesystemStorage::new(&repo.storage_path);
    storage.put(&storage_key, body.clone()).await.map_err(|e| {
        lfs_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Storage error: {}", e),
        )
    })?;

    let size_bytes = body.len() as i64;
    let artifact_path = format!("lfs/objects/{}/{}", &oid[..2], oid);

    // Insert artifact record
    sqlx::query!(
        r#"
        INSERT INTO artifacts (
            repository_id, path, name, version, size_bytes,
            checksum_sha256, content_type, storage_key, uploaded_by
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
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
    .execute(&state.db)
    .await
    .map_err(|e| {
        lfs_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Database error: {}", e),
        )
    })?;

    // Update repository timestamp
    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
    .await;

    info!("Git LFS upload: {} ({} bytes) to repo {}", oid, size_bytes, repo_key);

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
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Database error: {}", e),
        )
    })?
    .ok_or_else(|| lfs_error_response(StatusCode::NOT_FOUND, "Object not found"))?;

    let storage = FilesystemStorage::new(&repo.storage_path);
    let content = storage.get(&artifact.storage_key).await.map_err(|e| {
        lfs_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Storage error: {}", e),
        )
    })?;

    // Record download
    let _ = sqlx::query!(
        "INSERT INTO download_statistics (artifact_id, ip_address) VALUES ($1, '0.0.0.0')",
        artifact.id
    )
    .execute(&state.db)
    .await;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(CONTENT_LENGTH, content.len().to_string())
        .body(Body::from(content))
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
        lfs_error_response(
            StatusCode::BAD_REQUEST,
            &format!("Invalid JSON: {}", e),
        )
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
            StatusCode::INTERNAL_SERVER_ERROR,
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
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_lfs_repo(&state.db, &repo_key).await?;

    let request: CreateLockRequest = serde_json::from_slice(&body).map_err(|e| {
        lfs_error_response(
            StatusCode::BAD_REQUEST,
            &format!("Invalid JSON: {}", e),
        )
    })?;

    if request.path.is_empty() {
        return Err(lfs_error_response(
            StatusCode::BAD_REQUEST,
            "Lock path is required",
        ));
    }

    // Check for existing lock on this path
    let existing_lock = sqlx::query!(
        r#"
        SELECT id FROM artifact_metadata
        WHERE format = 'gitlfs_lock'
          AND artifact_id = $1
          AND metadata->>'path' = $2
        "#,
        repo.id,
        request.path
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        lfs_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Database error: {}", e),
        )
    })?;

    if existing_lock.is_some() {
        return Err(lfs_error_response(
            StatusCode::CONFLICT,
            "Lock already exists for this path",
        ));
    }

    // Look up username
    let username = sqlx::query_scalar!(
        "SELECT username FROM users WHERE id = $1",
        user_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        lfs_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Database error: {}", e),
        )
    })?;

    let lock_id = uuid::Uuid::new_v4();
    let locked_at = chrono::Utc::now();

    let lock_metadata = serde_json::json!({
        "lock_id": lock_id.to_string(),
        "path": request.path,
        "locked_at": locked_at.to_rfc3339(),
        "owner": username,
        "ref": request.lock_ref,
    });

    // Store lock as metadata entry (using repo.id as artifact_id for grouping)
    sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'gitlfs_lock', $2)
        "#,
        repo.id,
        lock_metadata,
    )
    .execute(&state.db)
    .await
    .map_err(|e| {
        lfs_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Database error: {}", e),
        )
    })?;

    let response = LockResponse {
        lock: LockInfo {
            id: lock_id.to_string(),
            path: request.path,
            locked_at: locked_at.to_rfc3339(),
            owner: LockOwner { name: username },
        },
    };

    Ok(lfs_json_response(StatusCode::CREATED, &response))
}

// ---------------------------------------------------------------------------
// GET /lfs/:repo_key/locks - List locks
// ---------------------------------------------------------------------------

async fn list_locks(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_lfs_repo(&state.db, &repo_key).await?;

    let rows = sqlx::query!(
        r#"
        SELECT metadata
        FROM artifact_metadata
        WHERE format = 'gitlfs_lock'
          AND artifact_id = $1
        ORDER BY metadata->>'locked_at' DESC
        "#,
        repo.id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        lfs_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Database error: {}", e),
        )
    })?;

    let locks: Vec<LockInfo> = rows
        .iter()
        .filter_map(|row| {
            let m = &row.metadata;
            Some(LockInfo {
                id: m.get("lock_id")?.as_str()?.to_string(),
                path: m.get("path")?.as_str()?.to_string(),
                locked_at: m.get("locked_at")?.as_str()?.to_string(),
                owner: LockOwner {
                    name: m.get("owner")?.as_str()?.to_string(),
                },
            })
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
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_lfs_repo(&state.db, &repo_key).await?;

    // Parse request body (optional, may be empty)
    let _request: Option<VerifyLocksRequest> = if body.is_empty() {
        None
    } else {
        Some(serde_json::from_slice(&body).map_err(|e| {
            lfs_error_response(
                StatusCode::BAD_REQUEST,
                &format!("Invalid JSON: {}", e),
            )
        })?)
    };

    let username = sqlx::query_scalar!(
        "SELECT username FROM users WHERE id = $1",
        user_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        lfs_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Database error: {}", e),
        )
    })?;

    let rows = sqlx::query!(
        r#"
        SELECT metadata
        FROM artifact_metadata
        WHERE format = 'gitlfs_lock'
          AND artifact_id = $1
        ORDER BY metadata->>'locked_at' DESC
        "#,
        repo.id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        lfs_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Database error: {}", e),
        )
    })?;

    let mut ours = Vec::new();
    let mut theirs = Vec::new();

    for row in &rows {
        let m = &row.metadata;
        let lock_info = match (
            m.get("lock_id").and_then(|v| v.as_str()),
            m.get("path").and_then(|v| v.as_str()),
            m.get("locked_at").and_then(|v| v.as_str()),
            m.get("owner").and_then(|v| v.as_str()),
        ) {
            (Some(id), Some(path), Some(locked_at), Some(owner)) => LockInfo {
                id: id.to_string(),
                path: path.to_string(),
                locked_at: locked_at.to_string(),
                owner: LockOwner {
                    name: owner.to_string(),
                },
            },
            _ => continue,
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
    Path((repo_key, lock_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_lfs_repo(&state.db, &repo_key).await?;

    let force = if body.is_empty() {
        false
    } else {
        serde_json::from_slice::<UnlockRequest>(&body)
            .map(|r| r.force)
            .unwrap_or(false)
    };

    // Look up the user
    let username = sqlx::query_scalar!(
        "SELECT username FROM users WHERE id = $1",
        user_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        lfs_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Database error: {}", e),
        )
    })?;

    // Find the lock
    let row = sqlx::query!(
        r#"
        SELECT id as "row_id!", metadata
        FROM artifact_metadata
        WHERE format = 'gitlfs_lock'
          AND artifact_id = $1
          AND metadata->>'lock_id' = $2
        "#,
        repo.id,
        lock_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        lfs_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Database error: {}", e),
        )
    })?
    .ok_or_else(|| lfs_error_response(StatusCode::NOT_FOUND, "Lock not found"))?;

    let m = &row.metadata;
    let lock_owner = m
        .get("owner")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Only the lock owner or force can unlock
    if lock_owner != username && !force {
        return Err(lfs_error_response(
            StatusCode::FORBIDDEN,
            "You do not own this lock",
        ));
    }

    let lock_info = LockInfo {
        id: lock_id.clone(),
        path: m.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        locked_at: m.get("locked_at").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        owner: LockOwner {
            name: lock_owner.to_string(),
        },
    };

    // Delete the lock
    sqlx::query!(
        "DELETE FROM artifact_metadata WHERE id = $1",
        row.row_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| {
        lfs_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Database error: {}", e),
        )
    })?;

    info!("Git LFS unlock: {} by {} (force: {})", lock_id, username, force);

    let response = UnlockResponse { lock: lock_info };
    Ok(lfs_json_response(StatusCode::OK, &response))
}
