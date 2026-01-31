//! Docker Registry V2 API (OCI Distribution Spec) handlers.
//!
//! Implements the minimum endpoints required for `docker login`, `docker push`,
//! and `docker pull` per the OCI Distribution Specification.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, LOCATION};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use base64::Engine;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

use crate::api::SharedState;
use crate::services::auth_service::AuthService;
use crate::storage::StorageBackend;

// ---------------------------------------------------------------------------
// OCI error helpers
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct OciErrorResponse {
    errors: Vec<OciErrorEntry>,
}

#[derive(Serialize)]
struct OciErrorEntry {
    code: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<serde_json::Value>,
}

fn oci_error(status: StatusCode, code: &str, message: &str) -> Response {
    let body = OciErrorResponse {
        errors: vec![OciErrorEntry {
            code: code.to_string(),
            message: message.to_string(),
            detail: None,
        }],
    };
    let json = serde_json::to_string(&body).unwrap_or_default();
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(json))
        .unwrap()
}

fn www_authenticate_header(host: &str) -> String {
    format!(
        "Bearer realm=\"{}/v2/token\",service=\"artifact-keeper\"",
        host
    )
}

fn unauthorized_challenge(host: &str) -> Response {
    let body = OciErrorResponse {
        errors: vec![OciErrorEntry {
            code: "UNAUTHORIZED".to_string(),
            message: "authentication required".to_string(),
            detail: None,
        }],
    };
    let json = serde_json::to_string(&body).unwrap_or_default();
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("WWW-Authenticate", www_authenticate_header(host))
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(json))
        .unwrap()
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or(v.strip_prefix("bearer ")))
        .map(|s| s.to_string())
}

fn extract_basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic ").or(v.strip_prefix("basic ")))
        .and_then(|b64| {
            base64::engine::general_purpose::STANDARD
                .decode(b64)
                .ok()
        })
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|s| {
            let mut parts = s.splitn(2, ':');
            let user = parts.next()?.to_string();
            let pass = parts.next()?.to_string();
            Some((user, pass))
        })
}

fn validate_token(
    db: &PgPool,
    config: &crate::config::Config,
    headers: &HeaderMap,
) -> Result<crate::services::auth_service::Claims, ()> {
    let token = extract_bearer_token(headers).ok_or(())?;
    let auth_service = AuthService::new(db.clone(), Arc::new(config.clone()));
    auth_service.validate_access_token(&token).map_err(|_| ())
}

fn request_host(headers: &HeaderMap) -> String {
    headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|h| {
            if h.contains("://") {
                h.to_string()
            } else {
                format!("http://{}", h)
            }
        })
        .unwrap_or_else(|| "http://localhost".to_string())
}

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

fn blob_storage_key(digest: &str) -> String {
    format!("oci-blobs/{}", digest)
}

fn manifest_storage_key(digest: &str) -> String {
    format!("oci-manifests/{}", digest)
}

fn upload_storage_key(uuid: &Uuid) -> String {
    format!("oci-uploads/{}", uuid)
}

fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("sha256:{:x}", hasher.finalize())
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

/// Resolve the first path segment as a repository key and the rest as the
/// image name within the repository.
async fn resolve_repo(
    db: &PgPool,
    image_name: &str,
) -> Result<(Uuid, String, String), Response> {
    // Split: "test/python" → repo_key="test", image="python"
    // Or:    "myrepo/org/image" → repo_key="myrepo", image="org/image"
    let (repo_key, image) = match image_name.find('/') {
        Some(idx) => (&image_name[..idx], &image_name[idx + 1..]),
        None => (image_name, image_name),
    };

    let repo = sqlx::query!(
        "SELECT id, storage_path FROM repositories WHERE key = $1",
        repo_key
    )
    .fetch_optional(db)
    .await
    .map_err(|e| oci_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", &e.to_string()))?
    .ok_or_else(|| oci_error(StatusCode::NOT_FOUND, "NAME_UNKNOWN", &format!("repository not found: {}", repo_key)))?;

    Ok((repo.id, repo.storage_path, image.to_string()))
}

// ---------------------------------------------------------------------------
// Token endpoint
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TokenQuery {
    #[allow(dead_code)]
    service: Option<String>,
    #[allow(dead_code)]
    scope: Option<String>,
    #[allow(dead_code)]
    account: Option<String>,
}

#[derive(Serialize)]
struct TokenResponse {
    token: String,
    access_token: String,
    expires_in: u64,
    issued_at: String,
}

async fn token(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(_query): Query<TokenQuery>,
) -> Response {
    let credentials = match extract_basic_credentials(&headers) {
        Some(c) => c,
        None => {
            // Also try Bearer token (docker may send existing token)
            if let Ok(claims) = validate_token(&state.db, &state.config, &headers) {
                let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
                let user = match sqlx::query_as!(
                    crate::models::user::User,
                    r#"SELECT id, username, email, password_hash, display_name,
                       auth_provider as "auth_provider: crate::models::user::AuthProvider",
                       external_id, is_admin, is_active, must_change_password,
                       last_login_at, created_at, updated_at
                       FROM users WHERE id = $1"#,
                    claims.sub
                )
                .fetch_optional(&state.db)
                .await
                {
                    Ok(Some(u)) => u,
                    _ => return oci_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "invalid credentials"),
                };

                let tokens = match auth_service.generate_tokens(&user) {
                    Ok(t) => t,
                    Err(_) => return oci_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "token generation failed"),
                };

                let resp = TokenResponse {
                    token: tokens.access_token.clone(),
                    access_token: tokens.access_token,
                    expires_in: tokens.expires_in,
                    issued_at: chrono::Utc::now().to_rfc3339(),
                };

                return Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_string(&resp).unwrap()))
                    .unwrap();
            }
            return oci_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "credentials required");
        }
    };

    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    let (_user, tokens) = match auth_service.authenticate(&credentials.0, &credentials.1).await {
        Ok(result) => result,
        Err(_) => {
            return oci_error(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "invalid username or password",
            )
        }
    };

    let resp = TokenResponse {
        token: tokens.access_token.clone(),
        access_token: tokens.access_token,
        expires_in: tokens.expires_in,
        issued_at: chrono::Utc::now().to_rfc3339(),
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&resp).unwrap()))
        .unwrap()
}

// ---------------------------------------------------------------------------
// Version check
// ---------------------------------------------------------------------------

async fn version_check(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    if validate_token(&state.db, &state.config, &headers).is_ok() {
        Response::builder()
            .status(StatusCode::OK)
            .header("Docker-Distribution-API-Version", "registry/2.0")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from("{}"))
            .unwrap()
    } else {
        let host = request_host(&headers);
        unauthorized_challenge(&host)
    }
}

// ---------------------------------------------------------------------------
// Catch-all dispatcher: parses /v2/<name>/blobs|manifests/... paths
// ---------------------------------------------------------------------------

/// Parse a catch-all path into (image_name, operation, extra).
/// The path comes without the /v2 prefix since Axum strips it.
/// Examples:
///   "test/python/blobs/sha256:abc" → ("test/python", "blobs", "sha256:abc")
///   "test/python/manifests/latest" → ("test/python", "manifests", "latest")
///   "test/python/blobs/uploads/"   → ("test/python", "uploads", None)
///   "test/python/blobs/uploads/uuid" → ("test/python", "uploads", "uuid")
fn parse_oci_path(path: &str) -> Option<(String, String, Option<String>)> {
    let path = path.trim_start_matches('/');
    let parts: Vec<&str> = path.split('/').collect();

    // Find "manifests" or "blobs" in the parts
    let op_idx = parts.iter().position(|&p| p == "manifests" || p == "blobs" || p == "tags")?;
    let name = parts[..op_idx].join("/");
    let operation = parts[op_idx];

    if operation == "blobs" && parts.get(op_idx + 1) == Some(&"uploads") {
        // Blob upload: either just "uploads/" or "uploads/<uuid>"
        let uuid = parts.get(op_idx + 2).map(|s| s.to_string());
        return Some((name, "uploads".to_string(), uuid));
    }

    let reference = parts.get(op_idx + 1).map(|s| s.to_string());
    Some((name, operation.to_string(), reference))
}

// ---------------------------------------------------------------------------
// Blob handlers
// ---------------------------------------------------------------------------

async fn handle_head_blob(
    state: &SharedState,
    headers: &HeaderMap,
    image_name: &str,
    digest: &str,
) -> Response {
    let host = request_host(headers);
    let claims = match validate_token(&state.db, &state.config, headers) {
        Ok(c) => c,
        Err(_) => return unauthorized_challenge(&host),
    };
    let _ = claims;

    let (repo_id, storage_path, _image) = match resolve_repo(&state.db, image_name).await {
        Ok(r) => r,
        Err(e) => return e,
    };

    // Check oci_blobs table
    let blob = sqlx::query!(
        "SELECT size_bytes, storage_key FROM oci_blobs WHERE repository_id = $1 AND digest = $2",
        repo_id,
        digest
    )
    .fetch_optional(&state.db)
    .await;

    match blob {
        Ok(Some(b)) => {
            let storage = crate::storage::filesystem::FilesystemStorage::new(&storage_path);
            if storage.exists(&b.storage_key).await.unwrap_or(false) {
                return Response::builder()
                    .status(StatusCode::OK)
                    .header("Docker-Content-Digest", digest)
                    .header(CONTENT_LENGTH, b.size_bytes.to_string())
                    .header(CONTENT_TYPE, "application/octet-stream")
                    .body(Body::empty())
                    .unwrap();
            }
        }
        Ok(None) => {}
        Err(e) => {
            warn!("DB error checking blob: {}", e);
        }
    }

    oci_error(StatusCode::NOT_FOUND, "BLOB_UNKNOWN", "blob not found")
}

async fn handle_get_blob(
    state: &SharedState,
    headers: &HeaderMap,
    image_name: &str,
    digest: &str,
) -> Response {
    let host = request_host(headers);
    let claims = match validate_token(&state.db, &state.config, headers) {
        Ok(c) => c,
        Err(_) => return unauthorized_challenge(&host),
    };
    let _ = claims;

    let (repo_id, storage_path, _image) = match resolve_repo(&state.db, image_name).await {
        Ok(r) => r,
        Err(e) => return e,
    };

    let blob = sqlx::query!(
        "SELECT size_bytes, storage_key FROM oci_blobs WHERE repository_id = $1 AND digest = $2",
        repo_id,
        digest
    )
    .fetch_optional(&state.db)
    .await;

    match blob {
        Ok(Some(b)) => {
            let storage = crate::storage::filesystem::FilesystemStorage::new(&storage_path);
            match storage.get(&b.storage_key).await {
                Ok(data) => {
                    return Response::builder()
                        .status(StatusCode::OK)
                        .header("Docker-Content-Digest", digest)
                        .header(CONTENT_LENGTH, data.len().to_string())
                        .header(CONTENT_TYPE, "application/octet-stream")
                        .body(Body::from(data))
                        .unwrap();
                }
                Err(e) => {
                    warn!("Storage error reading blob {}: {}", digest, e);
                }
            }
        }
        Ok(None) => {}
        Err(e) => {
            warn!("DB error reading blob: {}", e);
        }
    }

    oci_error(StatusCode::NOT_FOUND, "BLOB_UNKNOWN", "blob not found")
}

async fn handle_start_upload(
    state: &SharedState,
    headers: &HeaderMap,
    image_name: &str,
    query_digest: Option<&str>,
    body: Bytes,
) -> Response {
    let host = request_host(headers);
    let claims = match validate_token(&state.db, &state.config, headers) {
        Ok(c) => c,
        Err(_) => return unauthorized_challenge(&host),
    };

    let (repo_id, storage_path, _image) = match resolve_repo(&state.db, image_name).await {
        Ok(r) => r,
        Err(e) => return e,
    };

    // Monolithic upload: if digest is provided and body is non-empty
    if let Some(digest) = query_digest {
        if !body.is_empty() {
            let computed = compute_sha256(&body);
            if computed != digest {
                return oci_error(
                    StatusCode::BAD_REQUEST,
                    "DIGEST_INVALID",
                    &format!("digest mismatch: computed {} != provided {}", computed, digest),
                );
            }

            let storage = crate::storage::filesystem::FilesystemStorage::new(&storage_path);
            let key = blob_storage_key(digest);
            if let Err(e) = storage.put(&key, body.clone()).await {
                return oci_error(StatusCode::INTERNAL_SERVER_ERROR, "BLOB_UPLOAD_UNKNOWN", &e.to_string());
            }

            // Record in oci_blobs
            let _ = sqlx::query!(
                "INSERT INTO oci_blobs (repository_id, digest, size_bytes, storage_key) VALUES ($1, $2, $3, $4) ON CONFLICT (repository_id, digest) DO NOTHING",
                repo_id, digest, body.len() as i64, key
            )
            .execute(&state.db)
            .await;

            return Response::builder()
                .status(StatusCode::CREATED)
                .header(LOCATION, format!("/v2/{}/blobs/{}", image_name, digest))
                .header("Docker-Content-Digest", digest)
                .header(CONTENT_LENGTH, "0")
                .body(Body::empty())
                .unwrap();
        }
    }

    // Create upload session
    let session_id = Uuid::new_v4();
    let temp_key = upload_storage_key(&session_id);

    // If body is non-empty, store it as initial chunk
    if !body.is_empty() {
        let storage = crate::storage::filesystem::FilesystemStorage::new(&storage_path);
        if let Err(e) = storage.put(&temp_key, body.clone()).await {
            return oci_error(StatusCode::INTERNAL_SERVER_ERROR, "BLOB_UPLOAD_UNKNOWN", &e.to_string());
        }
    }

    let bytes_received = body.len() as i64;

    if let Err(e) = sqlx::query!(
        "INSERT INTO oci_upload_sessions (id, repository_id, user_id, bytes_received, storage_temp_key) VALUES ($1, $2, $3, $4, $5)",
        session_id, repo_id, claims.sub, bytes_received, temp_key
    )
    .execute(&state.db)
    .await
    {
        return oci_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", &e.to_string());
    }

    info!("Started blob upload session {} for {}", session_id, image_name);

    Response::builder()
        .status(StatusCode::ACCEPTED)
        .header(LOCATION, format!("/v2/{}/blobs/uploads/{}", image_name, session_id))
        .header("Docker-Upload-UUID", session_id.to_string())
        .header("Range", format!("0-{}", bytes_received.max(0)))
        .header(CONTENT_LENGTH, "0")
        .body(Body::empty())
        .unwrap()
}

async fn handle_patch_upload(
    state: &SharedState,
    headers: &HeaderMap,
    image_name: &str,
    uuid_str: &str,
    body: Bytes,
) -> Response {
    let host = request_host(headers);
    let claims = match validate_token(&state.db, &state.config, headers) {
        Ok(c) => c,
        Err(_) => return unauthorized_challenge(&host),
    };
    let _ = claims;

    let session_id: Uuid = match uuid_str.parse() {
        Ok(id) => id,
        Err(_) => return oci_error(StatusCode::NOT_FOUND, "BLOB_UPLOAD_UNKNOWN", "invalid upload UUID"),
    };

    // Look up session
    let session = match sqlx::query!(
        "SELECT repository_id, bytes_received, storage_temp_key FROM oci_upload_sessions WHERE id = $1",
        session_id
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(s)) => s,
        Ok(None) => return oci_error(StatusCode::NOT_FOUND, "BLOB_UPLOAD_UNKNOWN", "upload session not found"),
        Err(e) => return oci_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", &e.to_string()),
    };

    let (_repo_id, storage_path, _image) = match resolve_repo(&state.db, image_name).await {
        Ok(r) => r,
        Err(e) => return e,
    };

    let storage = crate::storage::filesystem::FilesystemStorage::new(&storage_path);

    // Read existing data and append
    let mut existing = match storage.get(&session.storage_temp_key).await {
        Ok(data) => data.to_vec(),
        Err(_) => Vec::new(),
    };
    existing.extend_from_slice(&body);

    let new_bytes = existing.len() as i64;
    if let Err(e) = storage.put(&session.storage_temp_key, Bytes::from(existing)).await {
        return oci_error(StatusCode::INTERNAL_SERVER_ERROR, "BLOB_UPLOAD_UNKNOWN", &e.to_string());
    }

    // Update session
    let _ = sqlx::query!(
        "UPDATE oci_upload_sessions SET bytes_received = $2, updated_at = NOW() WHERE id = $1",
        session_id, new_bytes
    )
    .execute(&state.db)
    .await;

    Response::builder()
        .status(StatusCode::ACCEPTED)
        .header(LOCATION, format!("/v2/{}/blobs/uploads/{}", image_name, session_id))
        .header("Docker-Upload-UUID", session_id.to_string())
        .header("Range", format!("0-{}", new_bytes))
        .header(CONTENT_LENGTH, "0")
        .body(Body::empty())
        .unwrap()
}

async fn handle_complete_upload(
    state: &SharedState,
    headers: &HeaderMap,
    image_name: &str,
    uuid_str: &str,
    digest_query: Option<&str>,
    body: Bytes,
) -> Response {
    let host = request_host(headers);
    let claims = match validate_token(&state.db, &state.config, headers) {
        Ok(c) => c,
        Err(_) => return unauthorized_challenge(&host),
    };
    let _ = claims;

    let digest = match digest_query {
        Some(d) => d.to_string(),
        None => return oci_error(StatusCode::BAD_REQUEST, "DIGEST_INVALID", "digest query parameter required"),
    };

    let session_id: Uuid = match uuid_str.parse() {
        Ok(id) => id,
        Err(_) => return oci_error(StatusCode::NOT_FOUND, "BLOB_UPLOAD_UNKNOWN", "invalid upload UUID"),
    };

    let session = match sqlx::query!(
        "SELECT repository_id, storage_temp_key FROM oci_upload_sessions WHERE id = $1",
        session_id
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(s)) => s,
        Ok(None) => return oci_error(StatusCode::NOT_FOUND, "BLOB_UPLOAD_UNKNOWN", "upload session not found"),
        Err(e) => return oci_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", &e.to_string()),
    };

    let (_repo_id, storage_path, _image) = match resolve_repo(&state.db, image_name).await {
        Ok(r) => r,
        Err(e) => return e,
    };

    let storage = crate::storage::filesystem::FilesystemStorage::new(&storage_path);

    // Read accumulated data and append final chunk
    let mut data = match storage.get(&session.storage_temp_key).await {
        Ok(d) => d.to_vec(),
        Err(_) => Vec::new(),
    };
    if !body.is_empty() {
        data.extend_from_slice(&body);
    }

    // Verify digest
    let computed = compute_sha256(&data);
    if computed != digest {
        return oci_error(
            StatusCode::BAD_REQUEST,
            "DIGEST_INVALID",
            &format!("digest mismatch: computed {} != provided {}", computed, digest),
        );
    }

    // Store blob permanently
    let blob_key = blob_storage_key(&digest);
    let size_bytes = data.len() as i64;
    if let Err(e) = storage.put(&blob_key, Bytes::from(data)).await {
        return oci_error(StatusCode::INTERNAL_SERVER_ERROR, "BLOB_UPLOAD_UNKNOWN", &e.to_string());
    }

    // Record in oci_blobs
    let _ = sqlx::query!(
        "INSERT INTO oci_blobs (repository_id, digest, size_bytes, storage_key) VALUES ($1, $2, $3, $4) ON CONFLICT (repository_id, digest) DO NOTHING",
        session.repository_id, digest, size_bytes, blob_key
    )
    .execute(&state.db)
    .await;

    // Cleanup: delete temp data and session
    let _ = storage.delete(&session.storage_temp_key).await;
    let _ = sqlx::query!("DELETE FROM oci_upload_sessions WHERE id = $1", session_id)
        .execute(&state.db)
        .await;

    info!("Completed blob upload {}: {} ({} bytes)", session_id, digest, size_bytes);

    Response::builder()
        .status(StatusCode::CREATED)
        .header(LOCATION, format!("/v2/{}/blobs/{}", image_name, digest))
        .header("Docker-Content-Digest", &digest)
        .header(CONTENT_LENGTH, "0")
        .body(Body::empty())
        .unwrap()
}

// ---------------------------------------------------------------------------
// Manifest handlers
// ---------------------------------------------------------------------------

async fn handle_head_manifest(
    state: &SharedState,
    headers: &HeaderMap,
    image_name: &str,
    reference: &str,
) -> Response {
    let host = request_host(headers);
    let claims = match validate_token(&state.db, &state.config, headers) {
        Ok(c) => c,
        Err(_) => return unauthorized_challenge(&host),
    };
    let _ = claims;

    let (repo_id, storage_path, image) = match resolve_repo(&state.db, image_name).await {
        Ok(r) => r,
        Err(e) => return e,
    };

    // Reference can be a tag or a digest
    let (manifest_digest, content_type) = if reference.starts_with("sha256:") {
        // Look up by digest directly
        match sqlx::query!(
            "SELECT manifest_digest, manifest_content_type FROM oci_tags WHERE repository_id = $1 AND manifest_digest = $2 LIMIT 1",
            repo_id, reference
        )
        .fetch_optional(&state.db)
        .await
        {
            Ok(Some(t)) => (t.manifest_digest, t.manifest_content_type),
            _ => return oci_error(StatusCode::NOT_FOUND, "MANIFEST_UNKNOWN", "manifest not found"),
        }
    } else {
        // Look up by tag
        match sqlx::query!(
            "SELECT manifest_digest, manifest_content_type FROM oci_tags WHERE repository_id = $1 AND name = $2 AND tag = $3",
            repo_id, image, reference
        )
        .fetch_optional(&state.db)
        .await
        {
            Ok(Some(t)) => (t.manifest_digest, t.manifest_content_type),
            _ => return oci_error(StatusCode::NOT_FOUND, "MANIFEST_UNKNOWN", "manifest not found"),
        }
    };

    let storage = crate::storage::filesystem::FilesystemStorage::new(&storage_path);
    let manifest_key = manifest_storage_key(&manifest_digest);

    match storage.get(&manifest_key).await {
        Ok(data) => Response::builder()
            .status(StatusCode::OK)
            .header("Docker-Content-Digest", &manifest_digest)
            .header(CONTENT_LENGTH, data.len().to_string())
            .header(CONTENT_TYPE, &content_type)
            .body(Body::empty())
            .unwrap(),
        Err(_) => oci_error(StatusCode::NOT_FOUND, "MANIFEST_UNKNOWN", "manifest not found"),
    }
}

async fn handle_get_manifest(
    state: &SharedState,
    headers: &HeaderMap,
    image_name: &str,
    reference: &str,
) -> Response {
    let host = request_host(headers);
    let claims = match validate_token(&state.db, &state.config, headers) {
        Ok(c) => c,
        Err(_) => return unauthorized_challenge(&host),
    };
    let _ = claims;

    let (repo_id, storage_path, image) = match resolve_repo(&state.db, image_name).await {
        Ok(r) => r,
        Err(e) => return e,
    };

    let (manifest_digest, content_type) = if reference.starts_with("sha256:") {
        match sqlx::query!(
            "SELECT manifest_digest, manifest_content_type FROM oci_tags WHERE repository_id = $1 AND manifest_digest = $2 LIMIT 1",
            repo_id, reference
        )
        .fetch_optional(&state.db)
        .await
        {
            Ok(Some(t)) => (t.manifest_digest, t.manifest_content_type),
            _ => return oci_error(StatusCode::NOT_FOUND, "MANIFEST_UNKNOWN", "manifest not found"),
        }
    } else {
        match sqlx::query!(
            "SELECT manifest_digest, manifest_content_type FROM oci_tags WHERE repository_id = $1 AND name = $2 AND tag = $3",
            repo_id, image, reference
        )
        .fetch_optional(&state.db)
        .await
        {
            Ok(Some(t)) => (t.manifest_digest, t.manifest_content_type),
            _ => return oci_error(StatusCode::NOT_FOUND, "MANIFEST_UNKNOWN", "manifest not found"),
        }
    };

    let storage = crate::storage::filesystem::FilesystemStorage::new(&storage_path);
    let manifest_key = manifest_storage_key(&manifest_digest);

    match storage.get(&manifest_key).await {
        Ok(data) => Response::builder()
            .status(StatusCode::OK)
            .header("Docker-Content-Digest", &manifest_digest)
            .header(CONTENT_LENGTH, data.len().to_string())
            .header(CONTENT_TYPE, &content_type)
            .body(Body::from(data))
            .unwrap(),
        Err(_) => oci_error(StatusCode::NOT_FOUND, "MANIFEST_UNKNOWN", "manifest data not found"),
    }
}

async fn handle_put_manifest(
    state: &SharedState,
    headers: &HeaderMap,
    image_name: &str,
    reference: &str,
    body: Bytes,
) -> Response {
    let host = request_host(headers);
    let claims = match validate_token(&state.db, &state.config, headers) {
        Ok(c) => c,
        Err(_) => return unauthorized_challenge(&host),
    };

    let (repo_id, storage_path, image) = match resolve_repo(&state.db, image_name).await {
        Ok(r) => r,
        Err(e) => return e,
    };

    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/vnd.oci.image.manifest.v1+json")
        .to_string();

    // Compute digest
    let digest = compute_sha256(&body);
    let manifest_key = manifest_storage_key(&digest);

    // Store manifest
    let storage = crate::storage::filesystem::FilesystemStorage::new(&storage_path);
    if let Err(e) = storage.put(&manifest_key, body.clone()).await {
        return oci_error(StatusCode::INTERNAL_SERVER_ERROR, "MANIFEST_INVALID", &e.to_string());
    }

    // Upsert tag mapping
    if let Err(e) = sqlx::query!(
        r#"INSERT INTO oci_tags (repository_id, name, tag, manifest_digest, manifest_content_type)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (repository_id, name, tag) DO UPDATE SET
             manifest_digest = EXCLUDED.manifest_digest,
             manifest_content_type = EXCLUDED.manifest_content_type,
             updated_at = NOW()"#,
        repo_id, image, reference, digest, content_type
    )
    .execute(&state.db)
    .await
    {
        return oci_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", &e.to_string());
    }

    // Calculate total image size from manifest (config + layers)
    let total_size: i64 = if let Ok(manifest_json) = serde_json::from_slice::<serde_json::Value>(&body) {
        let config_size = manifest_json.get("config")
            .and_then(|c| c.get("size"))
            .and_then(|s| s.as_i64())
            .unwrap_or(0);
        let layers_size: i64 = manifest_json.get("layers")
            .and_then(|l| l.as_array())
            .map(|layers| layers.iter()
                .filter_map(|l| l.get("size").and_then(|s| s.as_i64()))
                .sum())
            .unwrap_or(0);
        config_size + layers_size
    } else {
        body.len() as i64
    };

    // Also create an artifact record so it appears in the UI
    let artifact_path = format!("v2/{}/manifests/{}", image, reference);
    let artifact_name = format!("{}:{}", image, reference);
    let checksum = digest.strip_prefix("sha256:").unwrap_or(&digest);

    let _ = sqlx::query!(
        r#"INSERT INTO artifacts (repository_id, path, name, version, size_bytes, checksum_sha256, content_type, storage_key, uploaded_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
           ON CONFLICT (repository_id, path) DO UPDATE SET
             version = EXCLUDED.version,
             size_bytes = EXCLUDED.size_bytes,
             checksum_sha256 = EXCLUDED.checksum_sha256,
             content_type = EXCLUDED.content_type,
             storage_key = EXCLUDED.storage_key,
             uploaded_by = EXCLUDED.uploaded_by,
             updated_at = NOW()"#,
        repo_id,
        artifact_path,
        artifact_name,
        Some(reference),
        total_size,
        checksum,
        content_type,
        manifest_key,
        Some(claims.sub),
    )
    .execute(&state.db)
    .await;

    info!(
        "Manifest pushed: {}/{}:{} ({})",
        image_name, image, reference, digest
    );

    Response::builder()
        .status(StatusCode::CREATED)
        .header(LOCATION, format!("/v2/{}/manifests/{}", image_name, digest))
        .header("Docker-Content-Digest", &digest)
        .header(CONTENT_LENGTH, "0")
        .body(Body::empty())
        .unwrap()
}

// ---------------------------------------------------------------------------
// Catch-all handlers
// ---------------------------------------------------------------------------

async fn catch_all(
    State(state): State<SharedState>,
    method: Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    query: Query<std::collections::HashMap<String, String>>,
    body: Bytes,
) -> Response {
    // Extract path from URI — the nest strips /v2 prefix already
    let path = uri.path().to_string();
    let parsed = match parse_oci_path(&path) {
        Some(p) => p,
        None => return oci_error(StatusCode::NOT_FOUND, "NAME_UNKNOWN", "invalid path"),
    };

    let (image_name, operation, reference) = parsed;

    match (method.as_str(), operation.as_str()) {
        // Blob operations
        ("HEAD", "blobs") => {
            let digest = match reference {
                Some(d) => d,
                None => return oci_error(StatusCode::BAD_REQUEST, "DIGEST_INVALID", "digest required"),
            };
            handle_head_blob(&state, &headers, &image_name, &digest).await
        }
        ("GET", "blobs") => {
            let digest = match reference {
                Some(d) => d,
                None => return oci_error(StatusCode::BAD_REQUEST, "DIGEST_INVALID", "digest required"),
            };
            handle_get_blob(&state, &headers, &image_name, &digest).await
        }

        // Upload operations
        ("POST", "uploads") => {
            let digest = query.get("digest").map(|s| s.as_str());
            handle_start_upload(&state, &headers, &image_name, digest, body).await
        }
        ("PATCH", "uploads") => {
            let uuid = match reference {
                Some(u) => u,
                None => return oci_error(StatusCode::NOT_FOUND, "BLOB_UPLOAD_UNKNOWN", "upload UUID required"),
            };
            handle_patch_upload(&state, &headers, &image_name, &uuid, body).await
        }
        ("PUT", "uploads") => {
            let uuid = match reference {
                Some(u) => u,
                None => return oci_error(StatusCode::NOT_FOUND, "BLOB_UPLOAD_UNKNOWN", "upload UUID required"),
            };
            let digest = query.get("digest").map(|s| s.as_str());
            handle_complete_upload(&state, &headers, &image_name, &uuid, digest, body).await
        }

        // Manifest operations
        ("HEAD", "manifests") => {
            let reference = match reference {
                Some(r) => r,
                None => return oci_error(StatusCode::BAD_REQUEST, "NAME_INVALID", "reference required"),
            };
            handle_head_manifest(&state, &headers, &image_name, &reference).await
        }
        ("GET", "manifests") => {
            let reference = match reference {
                Some(r) => r,
                None => return oci_error(StatusCode::BAD_REQUEST, "NAME_INVALID", "reference required"),
            };
            handle_get_manifest(&state, &headers, &image_name, &reference).await
        }
        ("PUT", "manifests") => {
            let reference = match reference {
                Some(r) => r,
                None => return oci_error(StatusCode::BAD_REQUEST, "NAME_INVALID", "reference required"),
            };
            handle_put_manifest(&state, &headers, &image_name, &reference, body).await
        }

        _ => oci_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "UNSUPPORTED",
            &format!("method {} not supported for {}", method, operation),
        ),
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(version_check))
        .route("/token", get(token).post(token))
        .fallback(catch_all)
        .layer(DefaultBodyLimit::disable())
}

/// Standalone version check handler for /v2/ (trailing slash).
/// Axum nest("/v2") + route("/") only matches /v2, not /v2/.
/// We add a top-level route for /v2/ to handle Docker's canonical check.
pub fn version_check_handler() -> axum::routing::MethodRouter<SharedState> {
    get(version_check)
}
