//! Docker Registry V2 API (OCI Distribution Spec) handlers.
//!
//! Implements the minimum endpoints required for `docker login`, `docker push`,
//! and `docker pull` per the OCI Distribution Specification.
//!
// TODO(#553): OCI errors use a spec-mandated JSON envelope (oci_error fn) and
// cannot be converted to AppError without breaking Docker/OCI client compat.
// Consider wrapping oci_error to also log via tracing for consistency.

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

use crate::api::handlers::proxy_helpers;
use crate::api::SharedState;
use crate::models::repository::RepositoryType;
use crate::services::auth_service::AuthService;

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
        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
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
    proxy_helpers::request_base_url(headers)
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

/// Resolved OCI repository descriptor.
struct OciRepoInfo {
    id: Uuid,
    key: String,
    location: crate::storage::StorageLocation,
    repo_type: String,
    upstream_url: Option<String>,
    image: String,
}

/// Resolve the first path segment as a repository key and the rest as the
/// image name within the repository.
async fn resolve_repo(db: &PgPool, image_name: &str) -> Result<OciRepoInfo, Response> {
    use sqlx::Row;
    // Split: "test/python" → repo_key="test", image="python"
    // Or:    "myrepo/org/image" → repo_key="myrepo", image="org/image"
    let (repo_key, image) = match image_name.find('/') {
        Some(idx) => (&image_name[..idx], &image_name[idx + 1..]),
        None => (image_name, image_name),
    };

    let repo = sqlx::query(
        "SELECT id, key, storage_backend, storage_path, repo_type::text as repo_type, \
         upstream_url FROM repositories WHERE key = $1",
    )
    .bind(repo_key)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            &e.to_string(),
        )
    })?
    .ok_or_else(|| {
        oci_error(
            StatusCode::NOT_FOUND,
            "NAME_UNKNOWN",
            &format!("repository not found: {}", repo_key),
        )
    })?;

    let location = crate::storage::StorageLocation {
        backend: repo.try_get("storage_backend").unwrap_or_default(),
        path: repo.try_get("storage_path").unwrap_or_default(),
    };

    Ok(OciRepoInfo {
        id: repo.try_get("id").unwrap_or_default(),
        key: repo.try_get("key").unwrap_or_default(),
        location,
        repo_type: repo.try_get("repo_type").unwrap_or_default(),
        upstream_url: repo.try_get("upstream_url").ok(),
        image: image.to_string(),
    })
}

/// Check whether an upstream URL points to Docker Hub.
fn is_docker_hub(upstream_url: &str) -> bool {
    let host = upstream_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("");
    host == "docker.io" || host.ends_with(".docker.io")
}

/// For Docker Hub upstreams, official images (single name, no slash) live under
/// the `library/` namespace. This function prepends it when needed.
fn normalize_docker_image(image: &str, upstream_url: &str) -> String {
    if !image.contains('/') && is_docker_hub(upstream_url) {
        format!("library/{}", image)
    } else {
        image.to_string()
    }
}

/// Try to fetch an OCI resource from the upstream registry for a remote repo.
/// Returns `None` if the repo is not remote, has no upstream configured, or the
/// fetch fails.
async fn try_upstream_fetch(
    repo: &OciRepoInfo,
    state: &SharedState,
    path_suffix: &str,
) -> Option<(Bytes, Option<String>)> {
    if repo.repo_type != RepositoryType::Remote {
        return None;
    }
    let upstream_url = repo.upstream_url.as_ref()?;
    let proxy = state.proxy_service.as_ref()?;
    let image = normalize_docker_image(&repo.image, upstream_url);
    let upstream_path = format!("v2/{}/{}", image, path_suffix);
    proxy_helpers::proxy_fetch(proxy, repo.id, &repo.key, upstream_url, &upstream_path)
        .await
        .ok()
}

/// Build an OCI registry response from proxied upstream content.
///
/// Used by both blob and manifest proxy handlers to avoid duplicating the
/// response-building logic across HEAD and GET variants.
fn build_oci_proxy_response(
    content: &Bytes,
    content_type: Option<String>,
    digest: &str,
    default_ct: &str,
    include_body: bool,
) -> Response {
    let ct = content_type.unwrap_or_else(|| default_ct.to_string());
    let body = if include_body {
        Body::from(content.clone())
    } else {
        Body::empty()
    };
    Response::builder()
        .status(StatusCode::OK)
        .header("Docker-Content-Digest", digest)
        .header(CONTENT_LENGTH, content.len().to_string())
        .header(CONTENT_TYPE, ct)
        .body(body)
        .unwrap()
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
                let auth_service =
                    AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
                let user = match sqlx::query_as!(
                    crate::models::user::User,
                    r#"SELECT id, username, email, password_hash, display_name,
                       auth_provider as "auth_provider: crate::models::user::AuthProvider",
                       external_id, is_admin, is_active, is_service_account, must_change_password,
                       totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
                       last_login_at, created_at, updated_at
                       FROM users WHERE id = $1"#,
                    claims.sub
                )
                .fetch_optional(&state.db)
                .await
                {
                    Ok(Some(u)) => u,
                    _ => {
                        return oci_error(
                            StatusCode::UNAUTHORIZED,
                            "UNAUTHORIZED",
                            "invalid credentials",
                        )
                    }
                };

                let tokens = match auth_service.generate_tokens(&user) {
                    Ok(t) => t,
                    Err(_) => {
                        return oci_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "INTERNAL_ERROR",
                            "token generation failed",
                        )
                    }
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
            return oci_error(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "credentials required",
            );
        }
    };

    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    let (user, tokens, authenticated_via_api_token) = match auth_service
        .authenticate(&credentials.0, &credentials.1)
        .await
    {
        Ok((user, tokens)) => (user, tokens, false),
        Err(_) => {
            // Fall back to API token in the password field (for service accounts
            // and CI/CD pipelines that use `docker login -p <api-token>`)
            match auth_service.validate_api_token(&credentials.1).await {
                Ok(validation) => {
                    // TODO: Enforce token scopes and allowed_repo_ids for OCI
                    // token exchange. Currently the generated JWT inherits full
                    // user privileges regardless of token restrictions.
                    if !validation.scopes.is_empty()
                        && !validation.scopes.contains(&"*".to_string())
                    {
                        warn!(
                            user = %validation.user.username,
                            scopes = ?validation.scopes,
                            allowed_repo_ids = ?validation.allowed_repo_ids,
                            "API token has scope/repo restrictions that are not \
                             enforced during OCI token exchange"
                        );
                    }
                    let user = validation.user;
                    let tokens = match auth_service.generate_tokens(&user) {
                        Ok(t) => t,
                        Err(_) => {
                            return oci_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "INTERNAL_ERROR",
                                "failed to generate tokens",
                            )
                        }
                    };
                    (user, tokens, true)
                }
                Err(_) => {
                    return oci_error(
                        StatusCode::UNAUTHORIZED,
                        "UNAUTHORIZED",
                        "invalid username or password",
                    )
                }
            }
        }
    };

    // Block password-based OCI token requests when the user has TOTP 2FA
    // enabled. Docker CLI cannot perform a TOTP challenge, so the user
    // must create an API token (which bypasses TOTP) instead. API tokens
    // are the intended bypass mechanism for non-interactive flows, so skip
    // the TOTP guard when the user authenticated via one.
    if user.totp_enabled && !authenticated_via_api_token {
        return oci_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "TOTP 2FA is enabled on this account. \
             Create a personal access token and use it as your Docker password instead.",
        );
    }

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

fn version_check_ok() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header("Docker-Distribution-API-Version", "registry/2.0")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap()
}

async fn version_check(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    // Accept Bearer token (standard Docker client flow)
    if validate_token(&state.db, &state.config, &headers).is_ok() {
        return version_check_ok();
    }

    // Accept Basic Auth directly (curl -u user:pass, HTTP clients)
    if let Some((username, password)) = extract_basic_credentials(&headers) {
        let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
        if auth_service
            .authenticate(&username, &password)
            .await
            .is_ok()
        {
            return version_check_ok();
        }

        // Fall back to API token in the password field
        if auth_service.validate_api_token(&password).await.is_ok() {
            return version_check_ok();
        }
    }

    let host = request_host(&headers);
    unauthorized_challenge(&host)
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
    let op_idx = parts
        .iter()
        .position(|&p| p == "manifests" || p == "blobs" || p == "tags")?;
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

    let repo = match resolve_repo(&state.db, image_name).await {
        Ok(r) => r,
        Err(e) => return e,
    };

    // Check oci_blobs table
    let blob = sqlx::query!(
        "SELECT size_bytes, storage_key FROM oci_blobs WHERE repository_id = $1 AND digest = $2",
        repo.id,
        digest
    )
    .fetch_optional(&state.db)
    .await;

    match blob {
        Ok(Some(b)) => {
            let storage = match state.storage_for_repo(&repo.location) {
                Ok(s) => s,
                Err(e) => {
                    return oci_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "INTERNAL_ERROR",
                        &e.to_string(),
                    )
                }
            };
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

    // For remote repos, try fetching blob from upstream
    if let Some((content, ct)) =
        try_upstream_fetch(&repo, state, &format!("blobs/{}", digest)).await
    {
        return build_oci_proxy_response(&content, ct, digest, "application/octet-stream", false);
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

    let repo = match resolve_repo(&state.db, image_name).await {
        Ok(r) => r,
        Err(e) => return e,
    };

    let blob = sqlx::query!(
        "SELECT size_bytes, storage_key FROM oci_blobs WHERE repository_id = $1 AND digest = $2",
        repo.id,
        digest
    )
    .fetch_optional(&state.db)
    .await;

    match blob {
        Ok(Some(b)) => {
            let storage = match state.storage_for_repo(&repo.location) {
                Ok(s) => s,
                Err(e) => {
                    return oci_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "INTERNAL_ERROR",
                        &e.to_string(),
                    )
                }
            };
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

    // For remote repos, try fetching blob from upstream
    if let Some((content, ct)) =
        try_upstream_fetch(&repo, state, &format!("blobs/{}", digest)).await
    {
        return build_oci_proxy_response(&content, ct, digest, "application/octet-stream", true);
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

    let repo = match resolve_repo(&state.db, image_name).await {
        Ok(r) => r,
        Err(e) => return e,
    };
    let repo_id = repo.id;
    let location = repo.location;

    // Monolithic upload: if digest is provided and body is non-empty
    if let Some(digest) = query_digest {
        if !body.is_empty() {
            let computed = compute_sha256(&body);
            if computed != digest {
                return oci_error(
                    StatusCode::BAD_REQUEST,
                    "DIGEST_INVALID",
                    &format!(
                        "digest mismatch: computed {} != provided {}",
                        computed, digest
                    ),
                );
            }

            let storage = match state.storage_for_repo(&location) {
                Ok(s) => s,
                Err(e) => {
                    return oci_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "INTERNAL_ERROR",
                        &e.to_string(),
                    )
                }
            };
            let key = blob_storage_key(digest);
            if let Err(e) = storage.put(&key, body.clone()).await {
                return oci_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "BLOB_UPLOAD_UNKNOWN",
                    &e.to_string(),
                );
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
        let storage = match state.storage_for_repo(&location) {
            Ok(s) => s,
            Err(e) => {
                return oci_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    &e.to_string(),
                )
            }
        };
        if let Err(e) = storage.put(&temp_key, body.clone()).await {
            return oci_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "BLOB_UPLOAD_UNKNOWN",
                &e.to_string(),
            );
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

    info!(
        "Started blob upload session {} for {}",
        session_id, image_name
    );

    Response::builder()
        .status(StatusCode::ACCEPTED)
        .header(
            LOCATION,
            format!("/v2/{}/blobs/uploads/{}", image_name, session_id),
        )
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
        Err(_) => {
            return oci_error(
                StatusCode::NOT_FOUND,
                "BLOB_UPLOAD_UNKNOWN",
                "invalid upload UUID",
            )
        }
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

    let repo = match resolve_repo(&state.db, image_name).await {
        Ok(r) => r,
        Err(e) => return e,
    };

    let storage = match state.storage_for_repo(&repo.location) {
        Ok(s) => s,
        Err(e) => {
            return oci_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                &e.to_string(),
            )
        }
    };

    // Read existing data and append
    let mut existing = match storage.get(&session.storage_temp_key).await {
        Ok(data) => data.to_vec(),
        Err(_) => Vec::new(),
    };
    existing.extend_from_slice(&body);

    let new_bytes = existing.len() as i64;
    if let Err(e) = storage
        .put(&session.storage_temp_key, Bytes::from(existing))
        .await
    {
        return oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "BLOB_UPLOAD_UNKNOWN",
            &e.to_string(),
        );
    }

    // Update session
    let _ = sqlx::query!(
        "UPDATE oci_upload_sessions SET bytes_received = $2, updated_at = NOW() WHERE id = $1",
        session_id,
        new_bytes
    )
    .execute(&state.db)
    .await;

    Response::builder()
        .status(StatusCode::ACCEPTED)
        .header(
            LOCATION,
            format!("/v2/{}/blobs/uploads/{}", image_name, session_id),
        )
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
        None => {
            return oci_error(
                StatusCode::BAD_REQUEST,
                "DIGEST_INVALID",
                "digest query parameter required",
            )
        }
    };

    let session_id: Uuid = match uuid_str.parse() {
        Ok(id) => id,
        Err(_) => {
            return oci_error(
                StatusCode::NOT_FOUND,
                "BLOB_UPLOAD_UNKNOWN",
                "invalid upload UUID",
            )
        }
    };

    let session = match sqlx::query!(
        "SELECT repository_id, storage_temp_key FROM oci_upload_sessions WHERE id = $1",
        session_id
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            return oci_error(
                StatusCode::NOT_FOUND,
                "BLOB_UPLOAD_UNKNOWN",
                "upload session not found",
            )
        }
        Err(e) => {
            return oci_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                &e.to_string(),
            )
        }
    };

    let repo = match resolve_repo(&state.db, image_name).await {
        Ok(r) => r,
        Err(e) => return e,
    };

    let storage = match state.storage_for_repo(&repo.location) {
        Ok(s) => s,
        Err(e) => {
            return oci_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                &e.to_string(),
            )
        }
    };

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
            &format!(
                "digest mismatch: computed {} != provided {}",
                computed, digest
            ),
        );
    }

    // Store blob permanently
    let blob_key = blob_storage_key(&digest);
    let size_bytes = data.len() as i64;
    if let Err(e) = storage.put(&blob_key, Bytes::from(data)).await {
        return oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "BLOB_UPLOAD_UNKNOWN",
            &e.to_string(),
        );
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

    info!(
        "Completed blob upload {}: {} ({} bytes)",
        session_id, digest, size_bytes
    );

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

    let repo = match resolve_repo(&state.db, image_name).await {
        Ok(r) => r,
        Err(e) => return e,
    };

    // Reference can be a tag or a digest. Look up locally first.
    let local_result: Option<(String, String)> = if reference.starts_with("sha256:") {
        sqlx::query!(
            "SELECT manifest_digest, manifest_content_type FROM oci_tags WHERE repository_id = $1 AND manifest_digest = $2 LIMIT 1",
            repo.id, reference
        )
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .map(|t| (t.manifest_digest, t.manifest_content_type))
    } else {
        sqlx::query!(
            "SELECT manifest_digest, manifest_content_type FROM oci_tags WHERE repository_id = $1 AND name = $2 AND tag = $3",
            repo.id, repo.image, reference
        )
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .map(|t| (t.manifest_digest, t.manifest_content_type))
    };

    if let Some((manifest_digest, content_type)) = local_result {
        let storage = match state.storage_for_repo(&repo.location) {
            Ok(s) => s,
            Err(e) => {
                return oci_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    &e.to_string(),
                )
            }
        };
        let manifest_key = manifest_storage_key(&manifest_digest);

        if let Ok(data) = storage.get(&manifest_key).await {
            return Response::builder()
                .status(StatusCode::OK)
                .header("Docker-Content-Digest", &manifest_digest)
                .header(CONTENT_LENGTH, data.len().to_string())
                .header(CONTENT_TYPE, &content_type)
                .body(Body::empty())
                .unwrap();
        }
    }

    // For remote repos, try fetching manifest from upstream
    if let Some((content, ct)) =
        try_upstream_fetch(&repo, state, &format!("manifests/{}", reference)).await
    {
        let digest = compute_sha256(&content);
        return build_oci_proxy_response(
            &content,
            ct,
            &digest,
            "application/vnd.oci.image.manifest.v1+json",
            false,
        );
    }

    oci_error(
        StatusCode::NOT_FOUND,
        "MANIFEST_UNKNOWN",
        "manifest not found",
    )
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

    let repo = match resolve_repo(&state.db, image_name).await {
        Ok(r) => r,
        Err(e) => return e,
    };

    let local_result: Option<(String, String)> = if reference.starts_with("sha256:") {
        sqlx::query!(
            "SELECT manifest_digest, manifest_content_type FROM oci_tags WHERE repository_id = $1 AND manifest_digest = $2 LIMIT 1",
            repo.id, reference
        )
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .map(|t| (t.manifest_digest, t.manifest_content_type))
    } else {
        sqlx::query!(
            "SELECT manifest_digest, manifest_content_type FROM oci_tags WHERE repository_id = $1 AND name = $2 AND tag = $3",
            repo.id, repo.image, reference
        )
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .map(|t| (t.manifest_digest, t.manifest_content_type))
    };

    if let Some((manifest_digest, content_type)) = local_result {
        let storage = match state.storage_for_repo(&repo.location) {
            Ok(s) => s,
            Err(e) => {
                return oci_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    &e.to_string(),
                )
            }
        };
        let manifest_key = manifest_storage_key(&manifest_digest);

        if let Ok(data) = storage.get(&manifest_key).await {
            return Response::builder()
                .status(StatusCode::OK)
                .header("Docker-Content-Digest", &manifest_digest)
                .header(CONTENT_LENGTH, data.len().to_string())
                .header(CONTENT_TYPE, &content_type)
                .body(Body::from(data))
                .unwrap();
        }
    }

    // For remote repos, try fetching manifest from upstream
    if let Some((content, ct)) =
        try_upstream_fetch(&repo, state, &format!("manifests/{}", reference)).await
    {
        let digest = compute_sha256(&content);
        return build_oci_proxy_response(
            &content,
            ct,
            &digest,
            "application/vnd.oci.image.manifest.v1+json",
            true,
        );
    }

    oci_error(
        StatusCode::NOT_FOUND,
        "MANIFEST_UNKNOWN",
        "manifest not found",
    )
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

    let repo = match resolve_repo(&state.db, image_name).await {
        Ok(r) => r,
        Err(e) => return e,
    };
    let repo_id = repo.id;
    let image = repo.image;

    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/vnd.oci.image.manifest.v1+json")
        .to_string();

    // Compute digest
    let digest = compute_sha256(&body);
    let manifest_key = manifest_storage_key(&digest);

    // Store manifest
    let storage = match state.storage_for_repo(&repo.location) {
        Ok(s) => s,
        Err(e) => {
            return oci_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                &e.to_string(),
            )
        }
    };
    if let Err(e) = storage.put(&manifest_key, body.clone()).await {
        return oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "MANIFEST_INVALID",
            &e.to_string(),
        );
    }

    // Upsert tag mapping
    if let Err(e) = sqlx::query!(
        r#"INSERT INTO oci_tags (repository_id, name, tag, manifest_digest, manifest_content_type)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (repository_id, name, tag) DO UPDATE SET
             manifest_digest = EXCLUDED.manifest_digest,
             manifest_content_type = EXCLUDED.manifest_content_type,
             updated_at = NOW()"#,
        repo_id,
        image,
        reference,
        digest,
        content_type
    )
    .execute(&state.db)
    .await
    {
        return oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            &e.to_string(),
        );
    }

    // Calculate total image size from manifest (config + layers)
    let total_size: i64 =
        if let Ok(manifest_json) = serde_json::from_slice::<serde_json::Value>(&body) {
            let config_size = manifest_json
                .get("config")
                .and_then(|c| c.get("size"))
                .and_then(|s| s.as_i64())
                .unwrap_or(0);
            let layers_size: i64 = manifest_json
                .get("layers")
                .and_then(|l| l.as_array())
                .map(|layers| {
                    layers
                        .iter()
                        .filter_map(|l| l.get("size").and_then(|s| s.as_i64()))
                        .sum()
                })
                .unwrap_or(0);
            config_size + layers_size
        } else {
            body.len() as i64
        };

    // Also create an artifact record so it appears in the UI
    let artifact_path = format!("v2/{}/manifests/{}", image, reference);
    let artifact_name = format!("{}:{}", image, reference);
    let checksum = digest.strip_prefix("sha256:").unwrap_or(&digest);

    if let Err(e) = sqlx::query!(
        r#"INSERT INTO artifacts (repository_id, path, name, version, size_bytes, checksum_sha256, content_type, storage_key, uploaded_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
           ON CONFLICT (repository_id, path) DO UPDATE SET
             version = EXCLUDED.version,
             size_bytes = EXCLUDED.size_bytes,
             checksum_sha256 = EXCLUDED.checksum_sha256,
             content_type = EXCLUDED.content_type,
             storage_key = EXCLUDED.storage_key,
             uploaded_by = EXCLUDED.uploaded_by,
             is_deleted = false,
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
    .await
    {
        tracing::error!("Failed to upsert artifact record for {}: {}", artifact_path, e);
    }

    info!("Manifest pushed: {}:{} ({})", image_name, reference, digest);

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
                None => {
                    return oci_error(StatusCode::BAD_REQUEST, "DIGEST_INVALID", "digest required")
                }
            };
            handle_head_blob(&state, &headers, &image_name, &digest).await
        }
        ("GET", "blobs") => {
            let digest = match reference {
                Some(d) => d,
                None => {
                    return oci_error(StatusCode::BAD_REQUEST, "DIGEST_INVALID", "digest required")
                }
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
                None => {
                    return oci_error(
                        StatusCode::NOT_FOUND,
                        "BLOB_UPLOAD_UNKNOWN",
                        "upload UUID required",
                    )
                }
            };
            handle_patch_upload(&state, &headers, &image_name, &uuid, body).await
        }
        ("PUT", "uploads") => {
            let uuid = match reference {
                Some(u) => u,
                None => {
                    return oci_error(
                        StatusCode::NOT_FOUND,
                        "BLOB_UPLOAD_UNKNOWN",
                        "upload UUID required",
                    )
                }
            };
            let digest = query.get("digest").map(|s| s.as_str());
            handle_complete_upload(&state, &headers, &image_name, &uuid, digest, body).await
        }

        // Manifest operations
        ("HEAD", "manifests") => {
            let reference = match reference {
                Some(r) => r,
                None => {
                    return oci_error(
                        StatusCode::BAD_REQUEST,
                        "NAME_INVALID",
                        "reference required",
                    )
                }
            };
            handle_head_manifest(&state, &headers, &image_name, &reference).await
        }
        ("GET", "manifests") => {
            let reference = match reference {
                Some(r) => r,
                None => {
                    return oci_error(
                        StatusCode::BAD_REQUEST,
                        "NAME_INVALID",
                        "reference required",
                    )
                }
            };
            handle_get_manifest(&state, &headers, &image_name, &reference).await
        }
        ("PUT", "manifests") => {
            let reference = match reference {
                Some(r) => r,
                None => {
                    return oci_error(
                        StatusCode::BAD_REQUEST,
                        "NAME_INVALID",
                        "reference required",
                    )
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    // -----------------------------------------------------------------------
    // oci_error
    // -----------------------------------------------------------------------

    #[test]
    fn test_oci_error_status() {
        let resp = oci_error(StatusCode::NOT_FOUND, "BLOB_UNKNOWN", "blob not found");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_oci_error_bad_request() {
        let resp = oci_error(StatusCode::BAD_REQUEST, "DIGEST_INVALID", "bad digest");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_oci_error_internal() {
        let resp = oci_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "oops");
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // -----------------------------------------------------------------------
    // build_oci_proxy_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_oci_proxy_response_head() {
        let content = Bytes::from("hello");
        let resp = build_oci_proxy_response(
            &content,
            None,
            "sha256:abc",
            "application/octet-stream",
            false,
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("Docker-Content-Digest").unwrap(),
            "sha256:abc"
        );
        assert_eq!(resp.headers().get(CONTENT_LENGTH).unwrap(), "5");
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap(),
            "application/octet-stream"
        );
    }

    #[test]
    fn test_build_oci_proxy_response_get_with_custom_ct() {
        let content = Bytes::from("{\"schemaVersion\":2}");
        let resp = build_oci_proxy_response(
            &content,
            Some("application/vnd.docker.distribution.manifest.v2+json".to_string()),
            "sha256:def",
            "application/vnd.oci.image.manifest.v1+json",
            true,
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap(),
            "application/vnd.docker.distribution.manifest.v2+json"
        );
        assert_eq!(
            resp.headers().get(CONTENT_LENGTH).unwrap(),
            content.len().to_string().as_str()
        );
    }

    #[test]
    fn test_build_oci_proxy_response_uses_default_ct_when_none() {
        let content = Bytes::from("data");
        let resp = build_oci_proxy_response(
            &content,
            None,
            "sha256:000",
            "application/vnd.oci.image.manifest.v1+json",
            true,
        );
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap(),
            "application/vnd.oci.image.manifest.v1+json"
        );
    }

    // -----------------------------------------------------------------------
    // OciErrorResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_oci_error_response_serialization() {
        let resp = OciErrorResponse {
            errors: vec![OciErrorEntry {
                code: "BLOB_UNKNOWN".to_string(),
                message: "blob not found".to_string(),
                detail: None,
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"code\":\"BLOB_UNKNOWN\""));
        assert!(json.contains("\"message\":\"blob not found\""));
        // detail should not be present when None
        assert!(!json.contains("\"detail\""));
    }

    #[test]
    fn test_oci_error_response_with_detail() {
        let resp = OciErrorResponse {
            errors: vec![OciErrorEntry {
                code: "MANIFEST_INVALID".to_string(),
                message: "invalid manifest".to_string(),
                detail: Some(serde_json::json!({"reason": "bad json"})),
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"detail\""));
        assert!(json.contains("bad json"));
    }

    // -----------------------------------------------------------------------
    // www_authenticate_header
    // -----------------------------------------------------------------------

    #[test]
    fn test_www_authenticate_header_with_scheme() {
        let header = www_authenticate_header("http://localhost:8080");
        assert!(header.contains("realm=\"http://localhost:8080/v2/token\""));
        assert!(header.contains("service=\"artifact-keeper\""));
    }

    #[test]
    fn test_www_authenticate_header_https() {
        let header = www_authenticate_header("https://registry.example.com");
        assert!(header.contains("https://registry.example.com/v2/token"));
    }

    // -----------------------------------------------------------------------
    // unauthorized_challenge
    // -----------------------------------------------------------------------

    #[test]
    fn test_unauthorized_challenge_status() {
        let resp = unauthorized_challenge("http://localhost");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_unauthorized_challenge_has_www_authenticate_header() {
        let resp = unauthorized_challenge("http://localhost");
        assert!(resp.headers().get("WWW-Authenticate").is_some());
    }

    // -----------------------------------------------------------------------
    // extract_bearer_token
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_bearer_token_valid() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer my-token-123"),
        );
        assert_eq!(
            extract_bearer_token(&headers),
            Some("my-token-123".to_string())
        );
    }

    #[test]
    fn test_extract_bearer_token_lowercase() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("bearer my-token"));
        assert_eq!(extract_bearer_token(&headers), Some("my-token".to_string()));
    }

    #[test]
    fn test_extract_bearer_token_no_header() {
        let headers = HeaderMap::new();
        assert!(extract_bearer_token(&headers).is_none());
    }

    #[test]
    fn test_extract_bearer_token_basic_auth_returns_none() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        assert!(extract_bearer_token(&headers).is_none());
    }

    // -----------------------------------------------------------------------
    // extract_basic_credentials
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_basic_credentials_valid() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        let result = extract_basic_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "pass".to_string())));
    }

    #[test]
    fn test_extract_basic_credentials_lowercase() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("basic dXNlcjpwYXNz"),
        );
        let result = extract_basic_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "pass".to_string())));
    }

    #[test]
    fn test_extract_basic_credentials_no_header() {
        let headers = HeaderMap::new();
        assert!(extract_basic_credentials(&headers).is_none());
    }

    #[test]
    fn test_extract_basic_credentials_invalid_base64() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Basic !!!invalid"));
        assert!(extract_basic_credentials(&headers).is_none());
    }

    #[test]
    fn test_extract_basic_credentials_no_colon() {
        let mut headers = HeaderMap::new();
        // "useronly" in base64 = "dXNlcm9ubHk="
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcm9ubHk="),
        );
        assert!(extract_basic_credentials(&headers).is_none());
    }

    #[test]
    fn test_extract_basic_credentials_password_with_colon() {
        let mut headers = HeaderMap::new();
        // "user:pa:ss" in base64 = "dXNlcjpwYTpzcw=="
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYTpzcw=="),
        );
        let result = extract_basic_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "pa:ss".to_string())));
    }

    // -----------------------------------------------------------------------
    // request_host
    // -----------------------------------------------------------------------

    #[test]
    fn test_request_host_with_host_header() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("registry.example.com"));
        assert_eq!(request_host(&headers), "http://registry.example.com");
    }

    #[test]
    fn test_request_host_with_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            HeaderValue::from_static("https://registry.example.com"),
        );
        assert_eq!(request_host(&headers), "https://registry.example.com");
    }

    #[test]
    fn test_request_host_no_header() {
        let headers = HeaderMap::new();
        assert_eq!(request_host(&headers), "http://localhost");
    }

    #[test]
    fn test_request_host_with_port() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("localhost:8080"));
        assert_eq!(request_host(&headers), "http://localhost:8080");
    }

    #[test]
    fn test_request_host_uses_x_forwarded_proto() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("registry.example.com"));
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        assert_eq!(request_host(&headers), "https://registry.example.com");
    }

    #[test]
    fn test_request_host_uses_x_forwarded_host() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("backend:8080"));
        headers.insert(
            "x-forwarded-host",
            HeaderValue::from_static("registry.example.com:30443"),
        );
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        assert_eq!(request_host(&headers), "https://registry.example.com:30443");
    }

    #[test]
    fn test_request_host_forwarded_host_without_proto() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("backend:8080"));
        headers.insert(
            "x-forwarded-host",
            HeaderValue::from_static("registry.example.com"),
        );
        assert_eq!(request_host(&headers), "http://registry.example.com");
    }

    // -----------------------------------------------------------------------
    // Storage key helpers
    // -----------------------------------------------------------------------

    #[test]
    fn test_blob_storage_key() {
        assert_eq!(blob_storage_key("sha256:abc123"), "oci-blobs/sha256:abc123");
    }

    #[test]
    fn test_manifest_storage_key() {
        assert_eq!(
            manifest_storage_key("sha256:def456"),
            "oci-manifests/sha256:def456"
        );
    }

    #[test]
    fn test_upload_storage_key() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(
            upload_storage_key(&uuid),
            "oci-uploads/550e8400-e29b-41d4-a716-446655440000"
        );
    }

    // -----------------------------------------------------------------------
    // compute_sha256
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_sha256_empty() {
        let hash = compute_sha256(b"");
        assert!(hash.starts_with("sha256:"));
        // SHA256 of empty string is a well-known value
        assert_eq!(
            hash,
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_compute_sha256_hello_world() {
        let hash = compute_sha256(b"hello world");
        assert!(hash.starts_with("sha256:"));
        assert_eq!(
            hash,
            "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_compute_sha256_deterministic() {
        let h1 = compute_sha256(b"test data");
        let h2 = compute_sha256(b"test data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_compute_sha256_different_data() {
        let h1 = compute_sha256(b"data1");
        let h2 = compute_sha256(b"data2");
        assert_ne!(h1, h2);
    }

    // -----------------------------------------------------------------------
    // parse_oci_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_oci_path_blobs() {
        let result = parse_oci_path("/test/python/blobs/sha256:abc");
        let (name, op, reference) = result.unwrap();
        assert_eq!(name, "test/python");
        assert_eq!(op, "blobs");
        assert_eq!(reference, Some("sha256:abc".to_string()));
    }

    #[test]
    fn test_parse_oci_path_manifests() {
        let result = parse_oci_path("/test/python/manifests/latest");
        let (name, op, reference) = result.unwrap();
        assert_eq!(name, "test/python");
        assert_eq!(op, "manifests");
        assert_eq!(reference, Some("latest".to_string()));
    }

    #[test]
    fn test_parse_oci_path_uploads_no_uuid() {
        let result = parse_oci_path("/test/python/blobs/uploads/");
        let (name, op, reference) = result.unwrap();
        assert_eq!(name, "test/python");
        assert_eq!(op, "uploads");
        // Empty string from splitting trailing slash
        assert_eq!(reference, Some("".to_string()));
    }

    #[test]
    fn test_parse_oci_path_uploads_with_uuid() {
        let result = parse_oci_path("/test/python/blobs/uploads/some-uuid");
        let (name, op, reference) = result.unwrap();
        assert_eq!(name, "test/python");
        assert_eq!(op, "uploads");
        assert_eq!(reference, Some("some-uuid".to_string()));
    }

    #[test]
    fn test_parse_oci_path_no_leading_slash() {
        let result = parse_oci_path("test/python/manifests/v1.0");
        let (name, op, reference) = result.unwrap();
        assert_eq!(name, "test/python");
        assert_eq!(op, "manifests");
        assert_eq!(reference, Some("v1.0".to_string()));
    }

    #[test]
    fn test_parse_oci_path_deep_name() {
        let result = parse_oci_path("myrepo/org/image/manifests/latest");
        let (name, op, reference) = result.unwrap();
        assert_eq!(name, "myrepo/org/image");
        assert_eq!(op, "manifests");
        assert_eq!(reference, Some("latest".to_string()));
    }

    #[test]
    fn test_parse_oci_path_no_operation() {
        let result = parse_oci_path("just/a/name");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_oci_path_tags_operation() {
        let result = parse_oci_path("test/image/tags/list");
        let (name, op, reference) = result.unwrap();
        assert_eq!(name, "test/image");
        assert_eq!(op, "tags");
        assert_eq!(reference, Some("list".to_string()));
    }

    #[test]
    fn test_parse_oci_path_blobs_no_digest() {
        let result = parse_oci_path("test/image/blobs");
        let (name, op, reference) = result.unwrap();
        assert_eq!(name, "test/image");
        assert_eq!(op, "blobs");
        assert!(reference.is_none());
    }

    #[test]
    fn test_parse_oci_path_manifests_sha256_reference() {
        let result = parse_oci_path("test/image/manifests/sha256:abc123");
        let (name, op, reference) = result.unwrap();
        assert_eq!(name, "test/image");
        assert_eq!(op, "manifests");
        assert_eq!(reference, Some("sha256:abc123".to_string()));
    }

    // -----------------------------------------------------------------------
    // version_check_ok
    // -----------------------------------------------------------------------

    #[test]
    fn test_version_check_ok_status() {
        let resp = version_check_ok();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn test_version_check_ok_has_distribution_header() {
        let resp = version_check_ok();
        assert_eq!(
            resp.headers()
                .get("Docker-Distribution-API-Version")
                .unwrap(),
            "registry/2.0"
        );
    }

    #[test]
    fn test_version_check_ok_content_type() {
        let resp = version_check_ok();
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }

    // -----------------------------------------------------------------------
    // Auth dispatch: verify Basic vs Bearer extraction is mutually exclusive
    // (validate_token depends on extract_bearer_token, which these prove)
    // -----------------------------------------------------------------------

    #[test]
    fn test_basic_auth_not_extracted_as_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        // Bearer extraction returns None for Basic Auth
        assert!(extract_bearer_token(&headers).is_none());
        // Basic extraction returns the credentials
        assert!(extract_basic_credentials(&headers).is_some());
    }

    #[test]
    fn test_bearer_not_extracted_as_basic() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer some-jwt-token"),
        );
        // Basic extraction returns None for Bearer
        assert!(extract_basic_credentials(&headers).is_none());
        // Bearer extraction returns the token
        assert!(extract_bearer_token(&headers).is_some());
    }

    #[test]
    fn test_no_auth_header_returns_none_for_both() {
        let headers = HeaderMap::new();
        assert!(extract_bearer_token(&headers).is_none());
        assert!(extract_basic_credentials(&headers).is_none());
    }

    // -----------------------------------------------------------------------
    // extract_basic_credentials edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_basic_credentials_empty_password() {
        let mut headers = HeaderMap::new();
        // "user:" in base64 = "dXNlcjo="
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Basic dXNlcjo="));
        let result = extract_basic_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "".to_string())));
    }

    #[test]
    fn test_extract_basic_credentials_bearer_returns_none() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer some-token"));
        assert!(extract_basic_credentials(&headers).is_none());
    }

    // -----------------------------------------------------------------------
    // extract_bearer_token edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_bearer_token_empty_value() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer "));
        assert_eq!(extract_bearer_token(&headers), Some("".to_string()));
    }

    #[test]
    fn test_extract_bearer_token_with_spaces_in_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer token with spaces"),
        );
        assert_eq!(
            extract_bearer_token(&headers),
            Some("token with spaces".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // unauthorized_challenge body content
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_unauthorized_challenge_body_contains_error() {
        let resp = unauthorized_challenge("http://localhost:8080");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let www_auth = resp
            .headers()
            .get("WWW-Authenticate")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(www_auth.contains("realm=\"http://localhost:8080/v2/token\""));
        assert!(www_auth.contains("service=\"artifact-keeper\""));

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["errors"][0]["code"], "UNAUTHORIZED");
        assert_eq!(json["errors"][0]["message"], "authentication required");
    }

    // -----------------------------------------------------------------------
    // TokenResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_token_response_serialization() {
        let resp = TokenResponse {
            token: "tok1".to_string(),
            access_token: "tok1".to_string(),
            expires_in: 3600,
            issued_at: "2024-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"token\":\"tok1\""));
        assert!(json.contains("\"access_token\":\"tok1\""));
        assert!(json.contains("\"expires_in\":3600"));
        assert!(json.contains("\"issued_at\""));
    }

    // -----------------------------------------------------------------------
    // OciRepoInfo
    // -----------------------------------------------------------------------

    fn make_repo_info(
        key: &str,
        repo_type: &str,
        upstream_url: Option<&str>,
        image: &str,
    ) -> OciRepoInfo {
        OciRepoInfo {
            id: Uuid::new_v4(),
            key: key.to_string(),
            location: crate::storage::StorageLocation {
                backend: "filesystem".to_string(),
                path: "/data/docker".to_string(),
            },
            repo_type: repo_type.to_string(),
            upstream_url: upstream_url.map(String::from),
            image: image.to_string(),
        }
    }

    #[test]
    fn test_oci_repo_info_remote_type() {
        let info = make_repo_info(
            "docker-hub",
            "remote",
            Some("https://registry-1.docker.io"),
            "library/nginx",
        );
        assert_eq!(info.repo_type, RepositoryType::Remote);
        assert_eq!(
            info.upstream_url.as_deref(),
            Some("https://registry-1.docker.io")
        );
        assert_eq!(info.image, "library/nginx");
    }

    #[test]
    fn test_oci_repo_info_local_type() {
        let info = make_repo_info("docker-local", "local", None, "myapp");
        assert_ne!(info.repo_type, RepositoryType::Remote);
        assert!(info.upstream_url.is_none());
    }

    // --- Docker Hub library/ prefix tests ---

    #[test]
    fn test_is_docker_hub_registry1() {
        assert!(super::is_docker_hub("https://registry-1.docker.io"));
    }

    #[test]
    fn test_is_docker_hub_plain() {
        assert!(super::is_docker_hub("https://docker.io"));
    }

    #[test]
    fn test_is_docker_hub_index() {
        assert!(super::is_docker_hub("https://index.docker.io"));
    }

    #[test]
    fn test_is_docker_hub_with_path() {
        assert!(super::is_docker_hub("https://registry-1.docker.io/v2"));
    }

    #[test]
    fn test_is_not_docker_hub_ghcr() {
        assert!(!super::is_docker_hub("https://ghcr.io"));
    }

    #[test]
    fn test_is_not_docker_hub_false_positive() {
        assert!(!super::is_docker_hub("https://not-docker.io.example.com"));
    }

    #[test]
    fn test_normalize_official_image_on_docker_hub() {
        assert_eq!(
            super::normalize_docker_image("alpine", "https://registry-1.docker.io"),
            "library/alpine"
        );
    }

    #[test]
    fn test_normalize_namespaced_image_on_docker_hub() {
        assert_eq!(
            super::normalize_docker_image("myorg/myimage", "https://registry-1.docker.io"),
            "myorg/myimage"
        );
    }

    #[test]
    fn test_normalize_multi_level_namespace_on_docker_hub() {
        assert_eq!(
            super::normalize_docker_image("myorg/subteam/myimage", "https://registry-1.docker.io"),
            "myorg/subteam/myimage"
        );
    }

    #[test]
    fn test_normalize_already_prefixed_library() {
        assert_eq!(
            super::normalize_docker_image("library/alpine", "https://registry-1.docker.io"),
            "library/alpine"
        );
    }

    #[test]
    fn test_normalize_official_image_on_non_docker_hub() {
        assert_eq!(
            super::normalize_docker_image("alpine", "https://ghcr.io"),
            "alpine"
        );
    }

    #[test]
    fn test_normalize_on_plain_docker_io() {
        assert_eq!(
            super::normalize_docker_image("nginx", "https://docker.io"),
            "library/nginx"
        );
    }
}
