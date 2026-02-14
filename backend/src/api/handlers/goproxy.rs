//! GOPROXY protocol handler.
//!
//! Implements the endpoints required for `go get` via GOPROXY protocol.
//!
//! Routes are mounted at `/go/{repo_key}/...`:
//!   GET  /go/{repo_key}/*module/@v/list             - List versions
//!   GET  /go/{repo_key}/*module/@v/{version}.info    - Version info (JSON)
//!   GET  /go/{repo_key}/*module/@v/{version}.mod     - Get go.mod
//!   GET  /go/{repo_key}/*module/@v/{version}.zip     - Download module zip
//!   GET  /go/{repo_key}/*module/@latest              - Latest version info
//!   PUT  /go/{repo_key}/*module/@v/{version}.zip     - Upload module zip
//!   PUT  /go/{repo_key}/*module/@v/{version}.mod     - Upload go.mod

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use base64::Engine;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::proxy_helpers;
use crate::api::SharedState;
use crate::services::auth_service::AuthService;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::StorageBackend;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/:repo_key/*path", get(handle_get).put(handle_put))
        .layer(DefaultBodyLimit::max(512 * 1024 * 1024)) // 512 MB
}

// ---------------------------------------------------------------------------
// Module path encoding/decoding
// ---------------------------------------------------------------------------

/// Decode a GOPROXY-encoded module path.
/// Capital letters are encoded as `!` followed by the lowercase letter.
/// E.g., `github.com/!azure/go-sdk` → `github.com/Azure/go-sdk`
fn decode_module_path(encoded: &str) -> String {
    let mut result = String::with_capacity(encoded.len());
    let mut chars = encoded.chars();
    while let Some(c) = chars.next() {
        if c == '!' {
            if let Some(next) = chars.next() {
                result.push(next.to_ascii_uppercase());
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Encode a module path for GOPROXY.
/// Capital letters become `!` + lowercase.
fn encode_module_path(path: &str) -> String {
    let mut result = String::with_capacity(path.len());
    for c in path.chars() {
        if c.is_ascii_uppercase() {
            result.push('!');
            result.push(c.to_ascii_lowercase());
        } else {
            result.push(c);
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Path parsing
// ---------------------------------------------------------------------------

/// Parsed GOPROXY request.
enum GoProxyRequest {
    /// `/@v/list` — list all versions
    List { module: String },
    /// `/@v/{version}.info` — version metadata JSON
    Info { module: String, version: String },
    /// `/@v/{version}.mod` — go.mod file
    Mod { module: String, version: String },
    /// `/@v/{version}.zip` — module zip
    Zip { module: String, version: String },
    /// `/@latest` — latest version info
    Latest { module: String },
}

/// Parse the wildcard path segment into a GoProxyRequest.
///
/// The path comes in as everything after `/:repo_key/`, e.g.:
///   `github.com/!azure/go-sdk/@v/list`
///   `github.com/!azure/go-sdk/@v/v1.0.0.info`
///   `github.com/!azure/go-sdk/@latest`
#[allow(clippy::result_large_err)]
fn parse_path(raw_path: &str) -> Result<GoProxyRequest, Response> {
    // Strip leading slash if present (axum wildcard may include it)
    let path = raw_path.strip_prefix('/').unwrap_or(raw_path);

    // Check for /@latest suffix
    if let Some(module_encoded) = path.strip_suffix("/@latest") {
        let module = decode_module_path(module_encoded);
        return Ok(GoProxyRequest::Latest { module });
    }

    // Look for /@v/ separator
    let av_pos = path.find("/@v/").ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid GOPROXY path: missing /@v/ or /@latest",
        )
            .into_response()
    })?;

    let module_encoded = &path[..av_pos];
    let operation = &path[av_pos + 4..]; // skip "/@v/"
    let module = decode_module_path(module_encoded);

    if operation == "list" {
        return Ok(GoProxyRequest::List { module });
    }

    if let Some(version) = operation.strip_suffix(".info") {
        return Ok(GoProxyRequest::Info {
            module,
            version: version.to_string(),
        });
    }

    if let Some(version) = operation.strip_suffix(".mod") {
        return Ok(GoProxyRequest::Mod {
            module,
            version: version.to_string(),
        });
    }

    if let Some(version) = operation.strip_suffix(".zip") {
        return Ok(GoProxyRequest::Zip {
            module,
            version: version.to_string(),
        });
    }

    Err((
        StatusCode::BAD_REQUEST,
        format!("Unknown GOPROXY operation: {}", operation),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

fn extract_basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    headers
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
}

/// Authenticate via Basic auth, returning user_id on success.
async fn authenticate(
    db: &PgPool,
    config: &crate::config::Config,
    headers: &HeaderMap,
) -> Result<uuid::Uuid, Response> {
    let (username, password) = extract_basic_credentials(headers).ok_or_else(|| {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Basic realm=\"go\"")
            .body(Body::from("Authentication required"))
            .unwrap()
    })?;

    let auth_service = AuthService::new(db.clone(), Arc::new(config.clone()));
    let (user, _tokens) = auth_service
        .authenticate(&username, &password)
        .await
        .map_err(|_| {
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("WWW-Authenticate", "Basic realm=\"go\"")
                .body(Body::from("Invalid credentials"))
                .unwrap()
        })?;

    Ok(user.id)
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

struct RepoInfo {
    id: uuid::Uuid,
    key: String,
    storage_path: String,
    repo_type: String,
    upstream_url: Option<String>,
}

async fn resolve_go_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    let repo = sqlx::query!(
        "SELECT id, key, storage_path, format::text as \"format!\", repo_type::text as \"repo_type!\", upstream_url FROM repositories WHERE key = $1",
        repo_key
    )
    .fetch_optional(db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Repository not found").into_response())?;

    let fmt = repo.format.to_lowercase();
    if fmt != "go" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not a Go repository (format: {})",
                repo_key, fmt
            ),
        )
            .into_response());
    }

    Ok(RepoInfo {
        id: repo.id,
        key: repo.key,
        storage_path: repo.storage_path,
        repo_type: repo.repo_type,
        upstream_url: repo.upstream_url,
    })
}

// ---------------------------------------------------------------------------
// GET handler — dispatches based on parsed path
// ---------------------------------------------------------------------------

async fn handle_get(
    State(state): State<SharedState>,
    Path((repo_key, path)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_go_repo(&state.db, &repo_key).await?;
    let request = parse_path(&path)?;

    match request {
        GoProxyRequest::List { module } => list_versions(&state, &repo, &module).await,
        GoProxyRequest::Info { module, version } => {
            version_info(&state, &repo, &module, &version).await
        }
        GoProxyRequest::Mod { module, version } => {
            get_mod_file(&state, &repo, &module, &version).await
        }
        GoProxyRequest::Zip { module, version } => {
            download_zip(&state, &repo, &module, &version).await
        }
        GoProxyRequest::Latest { module } => latest_version(&state, &repo, &module).await,
    }
}

// ---------------------------------------------------------------------------
// PUT handler — dispatches based on parsed path
// ---------------------------------------------------------------------------

async fn handle_put(
    State(state): State<SharedState>,
    Path((repo_key, path)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_go_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    let request = parse_path(&path)?;

    match request {
        GoProxyRequest::Zip { module, version } => {
            upload_zip(&state, &repo, &module, &version, user_id, body).await
        }
        GoProxyRequest::Mod { module, version } => {
            upload_mod(&state, &repo, &module, &version, user_id, body).await
        }
        _ => Err((
            StatusCode::METHOD_NOT_ALLOWED,
            "PUT is only supported for .zip and .mod files",
        )
            .into_response()),
    }
}

// ---------------------------------------------------------------------------
// GET /@v/list — List versions
// ---------------------------------------------------------------------------

async fn list_versions(
    state: &SharedState,
    repo: &RepoInfo,
    module: &str,
) -> Result<Response, Response> {
    let versions: Vec<Option<String>> = sqlx::query_scalar!(
        r#"
        SELECT DISTINCT version
        FROM artifacts
        WHERE repository_id = $1
          AND name = $2
          AND is_deleted = false
          AND version IS NOT NULL
        ORDER BY version
        "#,
        repo.id,
        module
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    let body = versions
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("\n");

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(body))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /@v/{version}.info — Version info
// ---------------------------------------------------------------------------

async fn version_info(
    state: &SharedState,
    repo: &RepoInfo,
    module: &str,
    version: &str,
) -> Result<Response, Response> {
    let artifact = sqlx::query!(
        r#"
        SELECT a.created_at
        FROM artifacts a
        WHERE a.repository_id = $1
          AND a.name = $2
          AND a.version = $3
          AND a.is_deleted = false
        ORDER BY a.created_at ASC
        LIMIT 1
        "#,
        repo.id,
        module,
        version
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("Version {} not found for module {}", version, module),
        )
            .into_response()
    })?;

    let time_str = artifact.created_at.format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let info = serde_json::json!({
        "Version": version,
        "Time": time_str,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&info).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /@v/{version}.mod — Get go.mod
// ---------------------------------------------------------------------------

async fn get_mod_file(
    state: &SharedState,
    repo: &RepoInfo,
    module: &str,
    version: &str,
) -> Result<Response, Response> {
    let artifact = sqlx::query!(
        r#"
        SELECT id, storage_key, size_bytes
        FROM artifacts
        WHERE repository_id = $1
          AND name = $2
          AND version = $3
          AND path LIKE '%.mod'
          AND is_deleted = false
        LIMIT 1
        "#,
        repo.id,
        module,
        version
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("go.mod not found for {}@{}", module, version),
        )
            .into_response()
    });

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == "remote" {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let encoded = encode_module_path(module);
                    let upstream_path = format!("{}/@v/{}.mod", encoded, version);
                    let (content, content_type) = proxy_helpers::proxy_fetch(
                        proxy,
                        repo.id,
                        &repo.key,
                        upstream_url,
                        &upstream_path,
                    )
                    .await?;
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(
                            "Content-Type",
                            content_type.unwrap_or_else(|| "text/plain; charset=utf-8".to_string()),
                        )
                        .body(Body::from(content))
                        .unwrap());
                }
            }

            // Virtual repo: try each member in priority order
            if repo.repo_type == "virtual" {
                let db = state.db.clone();
                let encoded = encode_module_path(module);
                let upstream_path = format!("{}/@v/{}.mod", encoded, version);
                let module_clone = module.to_string();
                let version_clone = version.to_string();
                let (content, content_type) = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    state.proxy_service.as_deref(),
                    repo.id,
                    &upstream_path,
                    |member_id, storage_path| {
                        let db = db.clone();
                        let name = module_clone.clone();
                        let ver = version_clone.clone();
                        async move {
                            proxy_helpers::local_fetch_by_name_version(
                                &db,
                                member_id,
                                &storage_path,
                                &name,
                                &ver,
                            )
                            .await
                        }
                    },
                )
                .await?;

                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(
                        "Content-Type",
                        content_type.unwrap_or_else(|| "text/plain; charset=utf-8".to_string()),
                    )
                    .header(CONTENT_LENGTH, content.len().to_string())
                    .body(Body::from(content))
                    .unwrap());
            }

            return Err(not_found);
        }
    };

    let storage = FilesystemStorage::new(&repo.storage_path);
    let content = storage.get(&artifact.storage_key).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
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
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(CONTENT_LENGTH, content.len().to_string())
        .body(Body::from(content))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /@v/{version}.zip — Download module zip
// ---------------------------------------------------------------------------

async fn download_zip(
    state: &SharedState,
    repo: &RepoInfo,
    module: &str,
    version: &str,
) -> Result<Response, Response> {
    let artifact = sqlx::query!(
        r#"
        SELECT id, storage_key, size_bytes, checksum_sha256
        FROM artifacts
        WHERE repository_id = $1
          AND name = $2
          AND version = $3
          AND path LIKE '%.zip'
          AND is_deleted = false
        LIMIT 1
        "#,
        repo.id,
        module,
        version
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("Module zip not found for {}@{}", module, version),
        )
            .into_response()
    });

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == "remote" {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let encoded = encode_module_path(module);
                    let upstream_path = format!("{}/@v/{}.zip", encoded, version);
                    let (content, content_type) = proxy_helpers::proxy_fetch(
                        proxy,
                        repo.id,
                        &repo.key,
                        upstream_url,
                        &upstream_path,
                    )
                    .await?;
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(
                            "Content-Type",
                            content_type.unwrap_or_else(|| "application/zip".to_string()),
                        )
                        .body(Body::from(content))
                        .unwrap());
                }
            }

            // Virtual repo: try each member in priority order
            if repo.repo_type == "virtual" {
                let db = state.db.clone();
                let encoded = encode_module_path(module);
                let upstream_path = format!("{}/@v/{}.zip", encoded, version);
                let module_clone = module.to_string();
                let version_clone = version.to_string();
                let (content, content_type) = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    state.proxy_service.as_deref(),
                    repo.id,
                    &upstream_path,
                    |member_id, storage_path| {
                        let db = db.clone();
                        let name = module_clone.clone();
                        let ver = version_clone.clone();
                        async move {
                            proxy_helpers::local_fetch_by_name_version(
                                &db,
                                member_id,
                                &storage_path,
                                &name,
                                &ver,
                            )
                            .await
                        }
                    },
                )
                .await?;

                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(
                        "Content-Type",
                        content_type.unwrap_or_else(|| "application/zip".to_string()),
                    )
                    .header(CONTENT_LENGTH, content.len().to_string())
                    .body(Body::from(content))
                    .unwrap());
            }

            return Err(not_found);
        }
    };

    let storage = FilesystemStorage::new(&repo.storage_path);
    let content = storage.get(&artifact.storage_key).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
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
        .header(CONTENT_TYPE, "application/zip")
        .header(CONTENT_LENGTH, content.len().to_string())
        .header(
            "Content-Disposition",
            format!(
                "attachment; filename=\"{}@{}.zip\"",
                encode_module_path(module),
                version
            ),
        )
        .body(Body::from(content))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /@latest — Latest version info
// ---------------------------------------------------------------------------

async fn latest_version(
    state: &SharedState,
    repo: &RepoInfo,
    module: &str,
) -> Result<Response, Response> {
    let artifact = sqlx::query!(
        r#"
        SELECT version, created_at
        FROM artifacts
        WHERE repository_id = $1
          AND name = $2
          AND is_deleted = false
          AND version IS NOT NULL
        ORDER BY created_at DESC
        LIMIT 1
        "#,
        repo.id,
        module
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("No versions found for module {}", module),
        )
            .into_response()
    })?;

    let version = artifact.version.unwrap_or_default();
    let time_str = artifact.created_at.format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let info = serde_json::json!({
        "Version": version,
        "Time": time_str,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&info).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// PUT /@v/{version}.zip — Upload module zip
// ---------------------------------------------------------------------------

async fn upload_zip(
    state: &SharedState,
    repo: &RepoInfo,
    module: &str,
    version: &str,
    user_id: uuid::Uuid,
    body: Bytes,
) -> Result<Response, Response> {
    let encoded_module = encode_module_path(module);
    let artifact_path = format!("{}/{}/{}.zip", encoded_module, version, version);

    // Check for duplicate
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND name = $2 AND version = $3 AND path LIKE '%.zip' AND is_deleted = false",
        repo.id,
        module,
        version
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    if existing.is_some() {
        return Err((
            StatusCode::CONFLICT,
            format!("Module zip {}@{} already exists", module, version),
        )
            .into_response());
    }

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let checksum = format!("{:x}", hasher.finalize());

    let size_bytes = body.len() as i64;
    let storage_key = format!("go/{}/{}/{}.zip", encoded_module, version, version);

    // Store the file
    let storage = FilesystemStorage::new(&repo.storage_path);
    storage.put(&storage_key, body).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

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
        module,
        version,
        size_bytes,
        checksum,
        "application/zip",
        storage_key,
        user_id,
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    // Store metadata
    let metadata = serde_json::json!({
        "module": module,
        "version": version,
        "type": "zip",
    });

    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'go', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        metadata,
    )
    .execute(&state.db)
    .await;

    // Update repository timestamp
    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
    .await;

    info!("Go module upload: {}@{} (zip)", module, version);

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .body(Body::from("Created"))
        .unwrap())
}

// ---------------------------------------------------------------------------
// PUT /@v/{version}.mod — Upload go.mod
// ---------------------------------------------------------------------------

async fn upload_mod(
    state: &SharedState,
    repo: &RepoInfo,
    module: &str,
    version: &str,
    user_id: uuid::Uuid,
    body: Bytes,
) -> Result<Response, Response> {
    let encoded_module = encode_module_path(module);
    let artifact_path = format!("{}/{}/go.mod", encoded_module, version);

    // Check for duplicate
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND name = $2 AND version = $3 AND path LIKE '%.mod' AND is_deleted = false",
        repo.id,
        module,
        version
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    if existing.is_some() {
        return Err((
            StatusCode::CONFLICT,
            format!("go.mod for {}@{} already exists", module, version),
        )
            .into_response());
    }

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let checksum = format!("{:x}", hasher.finalize());

    let size_bytes = body.len() as i64;
    let storage_key = format!("go/{}/{}/go.mod", encoded_module, version);

    // Store the file
    let storage = FilesystemStorage::new(&repo.storage_path);
    storage.put(&storage_key, body).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

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
        module,
        version,
        size_bytes,
        checksum,
        "text/plain",
        storage_key,
        user_id,
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    // Store metadata
    let metadata = serde_json::json!({
        "module": module,
        "version": version,
        "type": "mod",
    });

    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'go', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        metadata,
    )
    .execute(&state.db)
    .await;

    // Update repository timestamp
    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
    .await;

    info!("Go module upload: {}@{} (go.mod)", module, version);

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .body(Body::from("Created"))
        .unwrap())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Extracted pure functions for testability
// ---------------------------------------------------------------------------

/// Build a version info JSON string (used by .info and @latest endpoints).
pub(crate) fn build_version_info_json(version: &str, time_str: &str) -> String {
    serde_json::json!({
        "Version": version,
        "Time": time_str,
    })
    .to_string()
}

/// Format a chrono DateTime into Go-compatible timestamp string.
pub(crate) fn format_go_timestamp(dt: &chrono::DateTime<chrono::Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Build a newline-separated version list from a vec of optional version strings.
pub(crate) fn build_version_list(versions: &[Option<String>]) -> String {
    versions
        .iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>()
        .join("\n")
}

/// Build the artifact path for a Go module zip.
pub(crate) fn build_go_zip_artifact_path(module: &str, version: &str) -> String {
    let encoded_module = encode_module_path(module);
    format!("{}/{}/{}.zip", encoded_module, version, version)
}

/// Build the storage key for a Go module zip.
pub(crate) fn build_go_zip_storage_key(module: &str, version: &str) -> String {
    let encoded_module = encode_module_path(module);
    format!("go/{}/{}/{}.zip", encoded_module, version, version)
}

/// Build the artifact path for a Go go.mod file.
pub(crate) fn build_go_mod_artifact_path(module: &str, version: &str) -> String {
    let encoded_module = encode_module_path(module);
    format!("{}/{}/go.mod", encoded_module, version)
}

/// Build the storage key for a Go go.mod file.
pub(crate) fn build_go_mod_storage_key(module: &str, version: &str) -> String {
    let encoded_module = encode_module_path(module);
    format!("go/{}/{}/go.mod", encoded_module, version)
}

/// Build Go module metadata JSON for storage.
pub(crate) fn build_go_artifact_metadata(
    module: &str,
    version: &str,
    file_type: &str,
) -> serde_json::Value {
    serde_json::json!({
        "module": module,
        "version": version,
        "type": file_type,
    })
}

/// Build Content-Disposition header for Go zip downloads.
pub(crate) fn build_go_zip_content_disposition(module: &str, version: &str) -> String {
    format!(
        "attachment; filename=\"{}@{}.zip\"",
        encode_module_path(module),
        version
    )
}

/// Build the upstream path for a Go module request (used by remote/virtual repos).
pub(crate) fn build_go_upstream_path(module: &str, version: &str, ext: &str) -> String {
    let encoded = encode_module_path(module);
    format!("{}/@v/{}.{}", encoded, version, ext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_module_path() {
        assert_eq!(
            decode_module_path("github.com/!azure/go-sdk"),
            "github.com/Azure/go-sdk"
        );
        assert_eq!(
            decode_module_path("github.com/user/repo"),
            "github.com/user/repo"
        );
        assert_eq!(
            decode_module_path("github.com/!big!corp/!my!lib"),
            "github.com/BigCorp/MyLib"
        );
    }

    #[test]
    fn test_encode_module_path() {
        assert_eq!(
            encode_module_path("github.com/Azure/go-sdk"),
            "github.com/!azure/go-sdk"
        );
        assert_eq!(
            encode_module_path("github.com/user/repo"),
            "github.com/user/repo"
        );
    }

    #[test]
    fn test_parse_path_list() {
        let req = parse_path("github.com/user/repo/@v/list").unwrap();
        match req {
            GoProxyRequest::List { module } => {
                assert_eq!(module, "github.com/user/repo");
            }
            _ => panic!("Expected List"),
        }
    }

    #[test]
    fn test_parse_path_info() {
        let req = parse_path("github.com/user/repo/@v/v1.0.0.info").unwrap();
        match req {
            GoProxyRequest::Info { module, version } => {
                assert_eq!(module, "github.com/user/repo");
                assert_eq!(version, "v1.0.0");
            }
            _ => panic!("Expected Info"),
        }
    }

    #[test]
    fn test_parse_path_mod() {
        let req = parse_path("github.com/user/repo/@v/v1.0.0.mod").unwrap();
        match req {
            GoProxyRequest::Mod { module, version } => {
                assert_eq!(module, "github.com/user/repo");
                assert_eq!(version, "v1.0.0");
            }
            _ => panic!("Expected Mod"),
        }
    }

    #[test]
    fn test_parse_path_zip() {
        let req = parse_path("github.com/user/repo/@v/v1.0.0.zip").unwrap();
        match req {
            GoProxyRequest::Zip { module, version } => {
                assert_eq!(module, "github.com/user/repo");
                assert_eq!(version, "v1.0.0");
            }
            _ => panic!("Expected Zip"),
        }
    }

    #[test]
    fn test_parse_path_latest() {
        let req = parse_path("github.com/user/repo/@latest").unwrap();
        match req {
            GoProxyRequest::Latest { module } => {
                assert_eq!(module, "github.com/user/repo");
            }
            _ => panic!("Expected Latest"),
        }
    }

    #[test]
    fn test_parse_path_with_leading_slash() {
        let req = parse_path("/github.com/user/repo/@v/list").unwrap();
        match req {
            GoProxyRequest::List { module } => {
                assert_eq!(module, "github.com/user/repo");
            }
            _ => panic!("Expected List"),
        }
    }

    #[test]
    fn test_parse_path_encoded_module() {
        let req = parse_path("github.com/!azure/go-sdk/@v/v2.0.0.info").unwrap();
        match req {
            GoProxyRequest::Info { module, version } => {
                assert_eq!(module, "github.com/Azure/go-sdk");
                assert_eq!(version, "v2.0.0");
            }
            _ => panic!("Expected Info"),
        }
    }

    #[test]
    fn test_parse_path_invalid() {
        assert!(parse_path("github.com/user/repo/invalid").is_err());
    }

    // -----------------------------------------------------------------------
    // build_version_info_json
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_version_info_json_basic() {
        let json = build_version_info_json("v1.2.3", "2024-01-15T10:30:00Z");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["Version"], "v1.2.3");
        assert_eq!(parsed["Time"], "2024-01-15T10:30:00Z");
    }

    #[test]
    fn test_build_version_info_json_prerelease() {
        let json = build_version_info_json("v0.1.0-alpha.1", "2024-06-01T00:00:00Z");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["Version"], "v0.1.0-alpha.1");
    }

    #[test]
    fn test_build_version_info_json_valid_json() {
        let json = build_version_info_json("v2.0.0", "2025-12-25T12:00:00Z");
        assert!(serde_json::from_str::<serde_json::Value>(&json).is_ok());
    }

    // -----------------------------------------------------------------------
    // format_go_timestamp
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_go_timestamp() {
        use chrono::TimeZone;
        let dt = chrono::Utc.with_ymd_and_hms(2024, 3, 15, 9, 30, 0).unwrap();
        assert_eq!(format_go_timestamp(&dt), "2024-03-15T09:30:00Z");
    }

    #[test]
    fn test_format_go_timestamp_midnight() {
        use chrono::TimeZone;
        let dt = chrono::Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        assert_eq!(format_go_timestamp(&dt), "2025-01-01T00:00:00Z");
    }

    // -----------------------------------------------------------------------
    // build_version_list
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_version_list_basic() {
        let versions = vec![
            Some("v1.0.0".to_string()),
            Some("v1.1.0".to_string()),
            Some("v2.0.0".to_string()),
        ];
        assert_eq!(build_version_list(&versions), "v1.0.0\nv1.1.0\nv2.0.0");
    }

    #[test]
    fn test_build_version_list_with_nones() {
        let versions = vec![
            Some("v1.0.0".to_string()),
            None,
            Some("v2.0.0".to_string()),
            None,
        ];
        assert_eq!(build_version_list(&versions), "v1.0.0\nv2.0.0");
    }

    #[test]
    fn test_build_version_list_empty() {
        let versions: Vec<Option<String>> = vec![];
        assert_eq!(build_version_list(&versions), "");
    }

    #[test]
    fn test_build_version_list_all_none() {
        let versions: Vec<Option<String>> = vec![None, None, None];
        assert_eq!(build_version_list(&versions), "");
    }

    // -----------------------------------------------------------------------
    // build_go_zip_artifact_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_go_zip_artifact_path_simple() {
        assert_eq!(
            build_go_zip_artifact_path("github.com/user/repo", "v1.0.0"),
            "github.com/user/repo/v1.0.0/v1.0.0.zip"
        );
    }

    #[test]
    fn test_build_go_zip_artifact_path_uppercase() {
        assert_eq!(
            build_go_zip_artifact_path("github.com/Azure/go-sdk", "v2.0.0"),
            "github.com/!azure/go-sdk/v2.0.0/v2.0.0.zip"
        );
    }

    // -----------------------------------------------------------------------
    // build_go_zip_storage_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_go_zip_storage_key_simple() {
        assert_eq!(
            build_go_zip_storage_key("github.com/user/repo", "v1.0.0"),
            "go/github.com/user/repo/v1.0.0/v1.0.0.zip"
        );
    }

    #[test]
    fn test_build_go_zip_storage_key_encoded() {
        assert_eq!(
            build_go_zip_storage_key("github.com/Azure/SDK", "v3.0.0"),
            "go/github.com/!azure/!s!d!k/v3.0.0/v3.0.0.zip"
        );
    }

    // -----------------------------------------------------------------------
    // build_go_mod_artifact_path / storage_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_go_mod_artifact_path() {
        assert_eq!(
            build_go_mod_artifact_path("github.com/user/repo", "v1.0.0"),
            "github.com/user/repo/v1.0.0/go.mod"
        );
    }

    #[test]
    fn test_build_go_mod_storage_key() {
        assert_eq!(
            build_go_mod_storage_key("github.com/user/repo", "v1.0.0"),
            "go/github.com/user/repo/v1.0.0/go.mod"
        );
    }

    // -----------------------------------------------------------------------
    // build_go_artifact_metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_go_artifact_metadata_zip() {
        let meta = build_go_artifact_metadata("github.com/user/repo", "v1.0.0", "zip");
        assert_eq!(meta["module"], "github.com/user/repo");
        assert_eq!(meta["version"], "v1.0.0");
        assert_eq!(meta["type"], "zip");
    }

    #[test]
    fn test_build_go_artifact_metadata_mod() {
        let meta = build_go_artifact_metadata("github.com/user/repo", "v2.0.0", "mod");
        assert_eq!(meta["type"], "mod");
    }

    // -----------------------------------------------------------------------
    // build_go_zip_content_disposition
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_go_zip_content_disposition_simple() {
        assert_eq!(
            build_go_zip_content_disposition("github.com/user/repo", "v1.0.0"),
            "attachment; filename=\"github.com/user/repo@v1.0.0.zip\""
        );
    }

    #[test]
    fn test_build_go_zip_content_disposition_encoded() {
        assert_eq!(
            build_go_zip_content_disposition("github.com/Azure/go-sdk", "v2.0.0"),
            "attachment; filename=\"github.com/!azure/go-sdk@v2.0.0.zip\""
        );
    }

    // -----------------------------------------------------------------------
    // build_go_upstream_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_go_upstream_path_zip() {
        assert_eq!(
            build_go_upstream_path("github.com/user/repo", "v1.0.0", "zip"),
            "github.com/user/repo/@v/v1.0.0.zip"
        );
    }

    #[test]
    fn test_build_go_upstream_path_mod() {
        assert_eq!(
            build_go_upstream_path("github.com/user/repo", "v1.0.0", "mod"),
            "github.com/user/repo/@v/v1.0.0.mod"
        );
    }

    #[test]
    fn test_build_go_upstream_path_info() {
        assert_eq!(
            build_go_upstream_path("github.com/user/repo", "v1.0.0", "info"),
            "github.com/user/repo/@v/v1.0.0.info"
        );
    }

    #[test]
    fn test_build_go_upstream_path_encoded() {
        assert_eq!(
            build_go_upstream_path("github.com/Azure/go-sdk", "v2.0.0", "zip"),
            "github.com/!azure/go-sdk/@v/v2.0.0.zip"
        );
    }

    // -----------------------------------------------------------------------
    // encode_module_path round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn test_encode_decode_roundtrip() {
        let original = "github.com/Azure/Go-SDK";
        let encoded = encode_module_path(original);
        let decoded = decode_module_path(&encoded);
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_encode_decode_roundtrip_no_uppercase() {
        let original = "github.com/user/repo";
        let encoded = encode_module_path(original);
        assert_eq!(encoded, original); // no change
        assert_eq!(decode_module_path(&encoded), original);
    }

    #[test]
    fn test_decode_multiple_consecutive_bangs() {
        // Two consecutive capital letters: AB -> !a!b
        assert_eq!(
            decode_module_path("github.com/!a!b/pkg"),
            "github.com/AB/pkg"
        );
    }

    // -----------------------------------------------------------------------
    // extract_basic_credentials
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_basic_credentials_valid() {
        use axum::http::HeaderValue;
        let encoded =
            base64::engine::general_purpose::STANDARD.encode("gouser:gopass");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", encoded)).unwrap(),
        );
        let result = extract_basic_credentials(&headers);
        assert_eq!(
            result,
            Some(("gouser".to_string(), "gopass".to_string()))
        );
    }

    #[test]
    fn test_extract_basic_credentials_missing() {
        assert!(extract_basic_credentials(&HeaderMap::new()).is_none());
    }

    #[test]
    fn test_extract_basic_credentials_bearer_ignored() {
        use axum::http::HeaderValue;
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer some-token"),
        );
        assert!(extract_basic_credentials(&headers).is_none());
    }

    #[test]
    fn test_extract_basic_credentials_colon_in_password() {
        use axum::http::HeaderValue;
        let encoded =
            base64::engine::general_purpose::STANDARD.encode("user:p:a:s:s");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", encoded)).unwrap(),
        );
        let result = extract_basic_credentials(&headers);
        assert_eq!(
            result,
            Some(("user".to_string(), "p:a:s:s".to_string()))
        );
    }
}
