//! Chef Supermarket API handlers.
//!
//! Implements the endpoints required for Chef cookbook management.
//!
//! Routes are mounted at `/chef/{repo_key}/...`:
//!   GET  /chef/{repo_key}/api/v1/cookbooks                                  - List cookbooks
//!   GET  /chef/{repo_key}/api/v1/cookbooks/{name}                           - Cookbook info
//!   GET  /chef/{repo_key}/api/v1/cookbooks/{name}/versions/{version}        - Version info
//!   GET  /chef/{repo_key}/api/v1/cookbooks/{name}/versions/{version}/download - Download tarball
//!   POST /chef/{repo_key}/api/v1/cookbooks                                  - Upload cookbook

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Multipart, Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use base64::Engine;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::SharedState;
use crate::formats::chef::ChefHandler;
use crate::services::auth_service::AuthService;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::StorageBackend;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        .route(
            "/:repo_key/api/v1/cookbooks",
            get(list_cookbooks).post(upload_cookbook),
        )
        .route("/:repo_key/api/v1/cookbooks/:name", get(cookbook_info))
        .route(
            "/:repo_key/api/v1/cookbooks/:name/versions/:version",
            get(version_info),
        )
        .route(
            "/:repo_key/api/v1/cookbooks/:name/versions/:version/download",
            get(download_cookbook),
        )
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
            .header("WWW-Authenticate", "Basic realm=\"chef\"")
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
                .header("WWW-Authenticate", "Basic realm=\"chef\"")
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

async fn resolve_chef_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
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
    if fmt != "chef" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not a Chef repository (format: {})",
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

// ---------------------------------------------------------------------------
// GET /chef/{repo_key}/api/v1/cookbooks — List cookbooks
// ---------------------------------------------------------------------------

async fn list_cookbooks(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_chef_repo(&state.db, &repo_key).await?;

    let artifacts = sqlx::query!(
        r#"
        SELECT DISTINCT ON (LOWER(name)) name, version
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
        ORDER BY LOWER(name), created_at DESC
        "#,
        repo.id
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

    let items: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            let name = a.name.clone();
            let version = a.version.clone().unwrap_or_default();
            serde_json::json!({
                "cookbook_name": name,
                "cookbook_maintainer": "",
                "cookbook_description": "",
                "cookbook": format!("/chef/{}/api/v1/cookbooks/{}", repo_key, name),
                "latest_version": version,
            })
        })
        .collect();

    let json = serde_json::json!({
        "start": 0,
        "total": items.len(),
        "items": items,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /chef/{repo_key}/api/v1/cookbooks/{name} — Cookbook info
// ---------------------------------------------------------------------------

async fn cookbook_info(
    State(state): State<SharedState>,
    Path((repo_key, name)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_chef_repo(&state.db, &repo_key).await?;

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
        name
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

    if artifacts.is_empty() {
        return Err((StatusCode::NOT_FOUND, "Cookbook not found").into_response());
    }

    let versions: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            let version = a.version.clone().unwrap_or_default();
            serde_json::json!({
                "version": version,
                "url": format!(
                    "/chef/{}/api/v1/cookbooks/{}/versions/{}",
                    repo_key, name, version
                ),
            })
        })
        .collect();

    let latest_version = artifacts[0].version.clone().unwrap_or_default();
    let description = artifacts[0]
        .metadata
        .as_ref()
        .and_then(|m| m.get("description"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let json = serde_json::json!({
        "name": name,
        "maintainer": "",
        "description": description,
        "latest_version": latest_version,
        "versions": versions,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /chef/{repo_key}/api/v1/cookbooks/{name}/versions/{version} — Version info
// ---------------------------------------------------------------------------

async fn version_info(
    State(state): State<SharedState>,
    Path((repo_key, name, version)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_chef_repo(&state.db, &repo_key).await?;

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
        name,
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Cookbook version not found").into_response())?;

    let download_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM download_statistics WHERE artifact_id = $1",
        artifact.id
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(Some(0))
    .unwrap_or(0);

    let json = serde_json::json!({
        "cookbook": name,
        "version": version,
        "file": format!(
            "/chef/{}/api/v1/cookbooks/{}/versions/{}/download",
            repo_key, name, version
        ),
        "tarball_file_size": artifact.size_bytes,
        "sha256": artifact.checksum_sha256,
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
// GET /chef/{repo_key}/api/v1/cookbooks/{name}/versions/{version}/download
// ---------------------------------------------------------------------------

async fn download_cookbook(
    State(state): State<SharedState>,
    Path((repo_key, name, version)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_chef_repo(&state.db, &repo_key).await?;

    let artifact = sqlx::query!(
        r#"
        SELECT id, storage_key, name, version, size_bytes
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND LOWER(name) = LOWER($2)
          AND version = $3
        LIMIT 1
        "#,
        repo.id,
        name,
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Cookbook version not found").into_response())?;

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

    let filename = format!("{}-{}.tar.gz", name, version);

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
// POST /chef/{repo_key}/api/v1/cookbooks — Upload cookbook (multipart)
// ---------------------------------------------------------------------------

async fn upload_cookbook(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_chef_repo(&state.db, &repo_key).await?;

    let mut tarball: Option<bytes::Bytes> = None;
    let mut cookbook_json: Option<serde_json::Value> = None;

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Multipart error: {}", e),
        )
            .into_response()
    })? {
        let field_name = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
            "tarball" => {
                tarball = Some(field.bytes().await.map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Failed to read tarball: {}", e),
                    )
                        .into_response()
                })?);
            }
            "cookbook" => {
                let data = field.bytes().await.map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Failed to read cookbook JSON: {}", e),
                    )
                        .into_response()
                })?;
                cookbook_json = Some(serde_json::from_slice(&data).map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Invalid cookbook JSON: {}", e),
                    )
                        .into_response()
                })?);
            }
            _ => {}
        }
    }

    let tarball = tarball.ok_or_else(|| {
        (StatusCode::BAD_REQUEST, "Missing tarball field").into_response()
    })?;

    if tarball.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty tarball").into_response());
    }

    // Extract name and version from cookbook JSON or validate the tarball
    let (cookbook_name, cookbook_version) = if let Some(ref json) = cookbook_json {
        let name = json
            .get("cookbook_name")
            .or_else(|| json.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let version = json
            .get("cookbook_version")
            .or_else(|| json.get("version"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        (name, version)
    } else {
        // Validate via format handler as fallback
        let path = "api/v1/cookbooks/unknown/versions/0.0.0";
        let _ = ChefHandler::parse_path(path);
        return Err(
            (StatusCode::BAD_REQUEST, "Missing cookbook metadata JSON").into_response()
        );
    };

    if cookbook_name.is_empty() || cookbook_version.is_empty() {
        return Err(
            (StatusCode::BAD_REQUEST, "Cookbook name and version are required").into_response(),
        );
    }

    // Validate via format handler
    let validate_path = format!(
        "api/v1/cookbooks/{}/versions/{}",
        cookbook_name, cookbook_version
    );
    let _ = ChefHandler::parse_path(&validate_path).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid cookbook: {}", e),
        )
            .into_response()
    })?;

    let filename = format!("{}-{}.tar.gz", cookbook_name, cookbook_version);

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&tarball);
    let computed_sha256 = format!("{:x}", hasher.finalize());

    let artifact_path = format!("{}/{}/{}", cookbook_name, cookbook_version, filename);

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
        return Err(
            (StatusCode::CONFLICT, "Cookbook version already exists").into_response()
        );
    }

    // Store the file
    let storage_key = format!(
        "chef/{}/{}/{}",
        cookbook_name, cookbook_version, filename
    );
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

    let chef_metadata = serde_json::json!({
        "cookbook_name": cookbook_name,
        "cookbook_version": cookbook_version,
        "filename": filename,
        "cookbook_json": cookbook_json,
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
        cookbook_name,
        cookbook_version,
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
        VALUES ($1, 'chef', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        chef_metadata,
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
        "Chef upload: {} {} ({}) to repo {}",
        cookbook_name, cookbook_version, filename, repo_key
    );

    let response_json = serde_json::json!({
        "uri": format!(
            "/chef/{}/api/v1/cookbooks/{}/versions/{}",
            repo_key, cookbook_name, cookbook_version
        ),
    });

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response_json).unwrap()))
        .unwrap())
}
