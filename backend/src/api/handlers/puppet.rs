//! Puppet Forge API handlers.
//!
//! Implements the endpoints required for Puppet module management.
//!
//! Routes are mounted at `/puppet/{repo_key}/...`:
//!   GET  /puppet/{repo_key}/v3/modules/{owner}-{name}                  - Module info
//!   GET  /puppet/{repo_key}/v3/modules/{owner}-{name}/releases         - Release list
//!   GET  /puppet/{repo_key}/v3/releases/{owner}-{name}-{version}       - Release info
//!   GET  /puppet/{repo_key}/v3/files/{owner}-{name}-{version}.tar.gz   - Download
//!   POST /puppet/{repo_key}/v3/releases                                - Publish module

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Multipart, Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use base64::Engine;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::SharedState;
use crate::formats::puppet::PuppetHandler;
use crate::services::auth_service::AuthService;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::StorageBackend;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/:repo_key/v3/modules/:owner_name", get(module_info))
        .route(
            "/:repo_key/v3/modules/:owner_name/releases",
            get(release_list),
        )
        .route(
            "/:repo_key/v3/releases/:owner_name_version",
            get(release_info),
        )
        .route("/:repo_key/v3/files/*file_path", get(download_module))
        .route("/:repo_key/v3/releases", post(publish_module))
        .layer(DefaultBodyLimit::max(512 * 1024 * 1024)) // 512 MB
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

fn extract_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    if let Some(bearer) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or(v.strip_prefix("bearer ")))
    {
        return Some(("token".to_string(), bearer.to_string()));
    }

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

async fn authenticate(
    db: &PgPool,
    config: &crate::config::Config,
    headers: &HeaderMap,
) -> Result<uuid::Uuid, Response> {
    let (username, password) = extract_credentials(headers).ok_or_else(|| {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Basic realm=\"puppet\"")
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
                .header("WWW-Authenticate", "Basic realm=\"puppet\"")
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
    storage_path: String,
}

async fn resolve_puppet_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    let repo = sqlx::query!(
        "SELECT id, storage_path, format::text as \"format!\" FROM repositories WHERE key = $1",
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
    if fmt != "puppet" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not a Puppet repository (format: {})",
                repo_key, fmt
            ),
        )
            .into_response());
    }

    Ok(RepoInfo {
        id: repo.id,
        storage_path: repo.storage_path,
    })
}

/// Parse an "owner-name" string into (owner, name) by splitting on the first hyphen.
#[allow(clippy::result_large_err)]
fn parse_owner_name(s: &str) -> Result<(String, String), Response> {
    let first_hyphen = s.find('-').ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid module identifier '{}': expected owner-name", s),
        )
            .into_response()
    })?;

    let owner = s[..first_hyphen].to_string();
    let name = s[first_hyphen + 1..].to_string();

    if owner.is_empty() || name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Owner and name must not be empty").into_response());
    }

    Ok((owner, name))
}

/// Parse an "owner-name-version" string into (owner, name, version).
#[allow(clippy::result_large_err)]
fn parse_owner_name_version(s: &str) -> Result<(String, String, String), Response> {
    let first_hyphen = s.find('-').ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!(
                "Invalid release identifier '{}': expected owner-name-version",
                s
            ),
        )
            .into_response()
    })?;

    let owner = s[..first_hyphen].to_string();
    let remainder = &s[first_hyphen + 1..];

    let last_hyphen = remainder.rfind('-').ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!(
                "Invalid release identifier '{}': expected owner-name-version",
                s
            ),
        )
            .into_response()
    })?;

    let name = remainder[..last_hyphen].to_string();
    let version = remainder[last_hyphen + 1..].to_string();

    if owner.is_empty() || name.is_empty() || version.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Owner, name, and version must not be empty",
        )
            .into_response());
    }

    Ok((owner, name, version))
}

// ---------------------------------------------------------------------------
// GET /puppet/{repo_key}/v3/modules/{owner}-{name} — Module info
// ---------------------------------------------------------------------------

async fn module_info(
    State(state): State<SharedState>,
    Path((repo_key, owner_name)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_puppet_repo(&state.db, &repo_key).await?;
    let (owner, name) = parse_owner_name(&owner_name)?;

    // Validate via format handler
    let validate_path = format!("v3/modules/{}-{}", owner, name);
    let _ = PuppetHandler::parse_path(&validate_path)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid path: {}", e)).into_response())?;

    let artifact = sqlx::query!(
        r#"
        SELECT a.id, a.name, a.version, a.size_bytes, a.checksum_sha256,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND LOWER(a.name) = LOWER($2)
        ORDER BY a.created_at DESC
        LIMIT 1
        "#,
        repo.id,
        format!("{}-{}", owner, name)
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Module not found").into_response())?;

    let current_version = artifact.version.clone().unwrap_or_default();

    let json = serde_json::json!({
        "slug": format!("{}-{}", owner, name),
        "name": name,
        "owner": { "slug": owner, "username": owner },
        "current_release": {
            "version": current_version,
            "slug": format!("{}-{}-{}", owner, name, current_version),
            "file_uri": format!(
                "/puppet/{}/v3/files/{}-{}-{}.tar.gz",
                repo_key, owner, name, current_version
            ),
        },
        "releases": [],
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /puppet/{repo_key}/v3/modules/{owner}-{name}/releases — Release list
// ---------------------------------------------------------------------------

async fn release_list(
    State(state): State<SharedState>,
    Path((repo_key, owner_name)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_puppet_repo(&state.db, &repo_key).await?;
    let (owner, name) = parse_owner_name(&owner_name)?;

    let artifacts = sqlx::query!(
        r#"
        SELECT a.id, a.name, a.version, a.size_bytes, a.checksum_sha256,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND LOWER(a.name) = LOWER($2)
        ORDER BY a.created_at DESC
        "#,
        repo.id,
        format!("{}-{}", owner, name)
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

    let releases: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            let version = a.version.clone().unwrap_or_default();
            serde_json::json!({
                "slug": format!("{}-{}-{}", owner, name, version),
                "version": version,
                "file_uri": format!(
                    "/puppet/{}/v3/files/{}-{}-{}.tar.gz",
                    repo_key, owner, name, version
                ),
                "file_size": a.size_bytes,
                "file_sha256": a.checksum_sha256,
                "metadata": a.metadata.clone().unwrap_or(serde_json::json!({})),
            })
        })
        .collect();

    let json = serde_json::json!({
        "pagination": {
            "limit": 20,
            "offset": 0,
            "total": releases.len(),
        },
        "results": releases,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /puppet/{repo_key}/v3/releases/{owner}-{name}-{version} — Release info
// ---------------------------------------------------------------------------

async fn release_info(
    State(state): State<SharedState>,
    Path((repo_key, owner_name_version)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_puppet_repo(&state.db, &repo_key).await?;
    let (owner, name, version) = parse_owner_name_version(&owner_name_version)?;

    // Validate via format handler
    let validate_path = format!("v3/releases/{}-{}-{}", owner, name, version);
    let _ = PuppetHandler::parse_path(&validate_path)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid path: {}", e)).into_response())?;

    let module_name = format!("{}-{}", owner, name);
    let artifact = sqlx::query!(
        r#"
        SELECT a.id, a.name, a.version, a.size_bytes, a.checksum_sha256,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND LOWER(a.name) = LOWER($2)
          AND a.version = $3
        LIMIT 1
        "#,
        repo.id,
        module_name,
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Release not found").into_response())?;

    let download_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM download_statistics WHERE artifact_id = $1",
        artifact.id
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(Some(0))
    .unwrap_or(0);

    let json = serde_json::json!({
        "slug": format!("{}-{}-{}", owner, name, version),
        "version": version,
        "module": {
            "slug": format!("{}-{}", owner, name),
            "name": name,
            "owner": { "slug": owner, "username": owner },
        },
        "file_uri": format!(
            "/puppet/{}/v3/files/{}-{}-{}.tar.gz",
            repo_key, owner, name, version
        ),
        "file_size": artifact.size_bytes,
        "file_sha256": artifact.checksum_sha256,
        "downloads": download_count,
        "metadata": artifact.metadata.unwrap_or(serde_json::json!({})),
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /puppet/{repo_key}/v3/files/{owner}-{name}-{version}.tar.gz — Download
// ---------------------------------------------------------------------------

async fn download_module(
    State(state): State<SharedState>,
    Path((repo_key, file_path)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_puppet_repo(&state.db, &repo_key).await?;

    let filename = file_path.trim_start_matches('/');

    let artifact = sqlx::query!(
        r#"
        SELECT id, path, name, version, size_bytes, checksum_sha256, storage_key
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND path LIKE '%/' || $2
        LIMIT 1
        "#,
        repo.id,
        filename
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Module file not found").into_response())?;

    let storage = FilesystemStorage::new(&repo.storage_path);
    let content = storage.get(&artifact.storage_key).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    let _ = sqlx::query!(
        "INSERT INTO download_statistics (artifact_id, ip_address) VALUES ($1, '0.0.0.0')",
        artifact.id
    )
    .execute(&state.db)
    .await;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/gzip")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, content.len().to_string())
        .body(Body::from(content))
        .unwrap())
}

// ---------------------------------------------------------------------------
// POST /puppet/{repo_key}/v3/releases — Publish module (multipart)
// ---------------------------------------------------------------------------

async fn publish_module(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_puppet_repo(&state.db, &repo_key).await?;

    let mut tarball: Option<bytes::Bytes> = None;
    let mut module_json: Option<serde_json::Value> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Multipart error: {}", e)).into_response())?
    {
        let field_name = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
            "file" => {
                tarball = Some(field.bytes().await.map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Failed to read file: {}", e),
                    )
                        .into_response()
                })?);
            }
            "module" => {
                let data = field.bytes().await.map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Failed to read module JSON: {}", e),
                    )
                        .into_response()
                })?;
                module_json = Some(serde_json::from_slice(&data).map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Invalid module JSON: {}", e),
                    )
                        .into_response()
                })?);
            }
            _ => {}
        }
    }

    let tarball =
        tarball.ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing file field").into_response())?;

    if tarball.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty tarball").into_response());
    }

    let (owner, module_name, module_version) = if let Some(ref json) = module_json {
        let owner = json
            .get("owner")
            .or_else(|| json.get("author"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let name = json
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let version = json
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        (owner, name, version)
    } else {
        return Err((StatusCode::BAD_REQUEST, "Missing module metadata JSON").into_response());
    };

    if owner.is_empty() || module_name.is_empty() || module_version.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Owner, name, and version are required",
        )
            .into_response());
    }

    // Validate via format handler
    let validate_path = format!("v3/releases/{}-{}-{}", owner, module_name, module_version);
    let _ = PuppetHandler::parse_path(&validate_path)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid module: {}", e)).into_response())?;

    let full_name = format!("{}-{}", owner, module_name);
    let filename = format!("{}-{}-{}.tar.gz", owner, module_name, module_version);

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&tarball);
    let computed_sha256 = format!("{:x}", hasher.finalize());

    let artifact_path = format!("{}/{}/{}", full_name, module_version, filename);

    // Check for duplicate
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        repo.id,
        artifact_path
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
        return Err((StatusCode::CONFLICT, "Module version already exists").into_response());
    }

    // Store the file
    let storage_key = format!("puppet/{}/{}/{}", full_name, module_version, filename);
    let storage = FilesystemStorage::new(&repo.storage_path);
    storage
        .put(&storage_key, tarball.clone())
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Storage error: {}", e),
            )
                .into_response()
        })?;

    let puppet_metadata = serde_json::json!({
        "owner": owner,
        "module_name": module_name,
        "version": module_version,
        "filename": filename,
        "module_json": module_json,
    });

    let size_bytes = tarball.len() as i64;

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
        full_name,
        module_version,
        size_bytes,
        computed_sha256,
        "application/gzip",
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

    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'puppet', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        puppet_metadata,
    )
    .execute(&state.db)
    .await;

    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
    .await;

    info!(
        "Puppet publish: {}-{} {} ({}) to repo {}",
        owner, module_name, module_version, filename, repo_key
    );

    let response_json = serde_json::json!({
        "slug": format!("{}-{}-{}", owner, module_name, module_version),
        "file_uri": format!(
            "/puppet/{}/v3/files/{}",
            repo_key, filename
        ),
    });

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response_json).unwrap()))
        .unwrap())
}
