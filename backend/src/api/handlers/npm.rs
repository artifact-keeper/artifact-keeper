//! npm Registry API handlers.
//!
//! Implements the endpoints required for `npm publish` and `npm install`.
//!
//! Routes are mounted at `/npm/{repo_key}/...`:
//!   GET  /npm/{repo_key}/{package}                    - Get package metadata
//!   GET  /npm/{repo_key}/{@scope}/{package}           - Get scoped package metadata
//!   GET  /npm/{repo_key}/{package}/-/{filename}       - Download tarball
//!   GET  /npm/{repo_key}/{@scope}/{package}/-/{filename} - Download scoped tarball
//!   PUT  /npm/{repo_key}/{package}                    - Publish package
//!   PUT  /npm/{repo_key}/{@scope}/{package}           - Publish scoped package

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

use crate::api::SharedState;
use crate::services::auth_service::AuthService;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::StorageBackend;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Scoped package tarball: GET /npm/{repo_key}/@{scope}/{package}/-/{filename}
        .route(
            "/:repo_key/@:scope/:package/-/:filename",
            get(download_scoped_tarball),
        )
        // Scoped package metadata / publish: GET/PUT /npm/{repo_key}/@{scope}/{package}
        .route(
            "/:repo_key/@:scope/:package",
            get(get_scoped_metadata).put(publish_scoped),
        )
        // Unscoped package tarball: GET /npm/{repo_key}/{package}/-/{filename}
        .route("/:repo_key/:package/-/:filename", get(download_tarball))
        // Unscoped package metadata / publish: GET/PUT /npm/{repo_key}/{package}
        .route("/:repo_key/:package", get(get_metadata).put(publish))
        .layer(DefaultBodyLimit::max(512 * 1024 * 1024)) // 512 MB
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

/// Extract credentials from Bearer token (npm sends base64-encoded user:pass as token).
fn extract_bearer_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or(v.strip_prefix("bearer ")))
        .and_then(|token| {
            base64::engine::general_purpose::STANDARD
                .decode(token)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .and_then(|s| {
                    let mut parts = s.splitn(2, ':');
                    let user = parts.next()?.to_string();
                    let pass = parts.next()?.to_string();
                    Some((user, pass))
                })
        })
}

/// Authenticate via Basic auth or Bearer token, returning user_id on success.
async fn authenticate(
    db: &PgPool,
    config: &crate::config::Config,
    headers: &HeaderMap,
) -> Result<uuid::Uuid, Response> {
    let (username, password) = extract_basic_credentials(headers)
        .or_else(|| extract_bearer_credentials(headers))
        .ok_or_else(|| {
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("WWW-Authenticate", "Basic realm=\"npm\"")
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
                .header("WWW-Authenticate", "Basic realm=\"npm\"")
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

async fn resolve_npm_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
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
    if fmt != "npm" && fmt != "yarn" && fmt != "pnpm" && fmt != "bower" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not an npm repository (format: {})",
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
// GET metadata handlers
// ---------------------------------------------------------------------------

async fn get_metadata(
    State(state): State<SharedState>,
    Path((repo_key, package)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    get_package_metadata(&state, &repo_key, &package, &headers).await
}

async fn get_scoped_metadata(
    State(state): State<SharedState>,
    Path((repo_key, scope, package)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let full_name = format!("@{}/{}", scope, package);
    get_package_metadata(&state, &repo_key, &full_name, &headers).await
}

/// Build and return the npm package metadata JSON for all versions.
async fn get_package_metadata(
    state: &SharedState,
    repo_key: &str,
    package_name: &str,
    headers: &HeaderMap,
) -> Result<Response, Response> {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http");
    let base_url = format!("{}://{}", scheme, host);

    let repo = resolve_npm_repo(&state.db, repo_key).await?;

    // Find all artifacts for this package name
    let artifacts = sqlx::query!(
        r#"
        SELECT a.id, a.path, a.name, a.version, a.size_bytes, a.checksum_sha256,
               a.storage_key, a.created_at,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND a.name = $2
        ORDER BY a.created_at ASC
        "#,
        repo.id,
        package_name
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
        return Err((StatusCode::NOT_FOUND, "Package not found").into_response());
    }

    // Build versions map and track the latest version
    let mut versions = serde_json::Map::new();
    let mut latest_version: Option<String> = None;

    for artifact in &artifacts {
        let version = match &artifact.version {
            Some(v) => v.clone(),
            None => continue,
        };

        // Extract the filename from the path
        let filename = artifact.path.rsplit('/').next().unwrap_or(&artifact.path);

        // Build the tarball URL
        let tarball_url = format!(
            "{}/npm/{}/{}/-/{}",
            base_url, repo_key, package_name, filename
        );

        // Get version-specific metadata from artifact_metadata if available
        let version_metadata = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("version_data").cloned())
            .unwrap_or_else(|| serde_json::json!({}));

        let mut version_obj = if version_metadata.is_object() {
            version_metadata
        } else {
            serde_json::json!({})
        };

        // Ensure required fields are set
        let obj = version_obj.as_object_mut().unwrap();
        obj.entry("name".to_string())
            .or_insert_with(|| serde_json::Value::String(package_name.to_string()));
        obj.entry("version".to_string())
            .or_insert_with(|| serde_json::Value::String(version.clone()));
        // npm expects shasum (SHA-1) or integrity (subresource integrity hash).
        // We only store SHA-256, so provide it via the integrity field.
        use base64::Engine;
        let hex = &artifact.checksum_sha256;
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
            .collect();
        let integrity = format!(
            "sha256-{}",
            base64::engine::general_purpose::STANDARD.encode(&bytes)
        );
        obj.insert(
            "dist".to_string(),
            serde_json::json!({
                "tarball": tarball_url,
                "integrity": integrity,
            }),
        );

        versions.insert(version.clone(), version_obj);
        latest_version = Some(version);
    }

    let dist_tags = serde_json::json!({
        "latest": latest_version.unwrap_or_default()
    });

    let response = serde_json::json!({
        "name": package_name,
        "versions": versions,
        "dist-tags": dist_tags,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET tarball download handlers
// ---------------------------------------------------------------------------

async fn download_tarball(
    State(state): State<SharedState>,
    Path((repo_key, _package, filename)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    serve_tarball(&state, &repo_key, &filename).await
}

async fn download_scoped_tarball(
    State(state): State<SharedState>,
    Path((repo_key, _scope, _package, filename)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    serve_tarball(&state, &repo_key, &filename).await
}

async fn serve_tarball(
    state: &SharedState,
    repo_key: &str,
    filename: &str,
) -> Result<Response, Response> {
    let repo = resolve_npm_repo(&state.db, repo_key).await?;

    // Find artifact by filename
    let artifact = sqlx::query!(
        r#"
        SELECT id, path, name, size_bytes, checksum_sha256, storage_key
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Tarball not found").into_response())?;

    // Read from storage
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
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, content.len().to_string())
        .body(Body::from(content))
        .unwrap())
}

// ---------------------------------------------------------------------------
// PUT publish handlers
// ---------------------------------------------------------------------------

async fn publish(
    State(state): State<SharedState>,
    Path((repo_key, package)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    publish_package(&state, &repo_key, &package, &headers, body).await
}

async fn publish_scoped(
    State(state): State<SharedState>,
    Path((repo_key, scope, package)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let full_name = format!("@{}/{}", scope, package);
    publish_package(&state, &repo_key, &full_name, &headers, body).await
}

/// Handle npm publish. The request body is JSON with versions and base64-encoded attachments.
async fn publish_package(
    state: &SharedState,
    repo_key: &str,
    package_name: &str,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    // Authenticate
    let user_id = authenticate(&state.db, &state.config, headers).await?;
    let repo = resolve_npm_repo(&state.db, repo_key).await?;

    // Parse the npm publish payload
    let payload: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid JSON payload: {}", e),
        )
            .into_response()
    })?;

    let name = payload
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(package_name);

    // Validate name matches the URL
    if name != package_name {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Package name mismatch: URL says '{}' but payload says '{}'",
                package_name, name
            ),
        )
            .into_response());
    }

    let versions_obj = payload
        .get("versions")
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            (StatusCode::BAD_REQUEST, "Missing 'versions' in payload").into_response()
        })?;

    let attachments_obj = payload
        .get("_attachments")
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            (StatusCode::BAD_REQUEST, "Missing '_attachments' in payload").into_response()
        })?;

    // Process each version
    for (version, version_data) in versions_obj {
        // Determine the expected tarball filename
        let tarball_filename = if package_name.starts_with('@') {
            // Scoped: @scope/pkg -> pkg-1.0.0.tgz
            let short_name = package_name.rsplit('/').next().unwrap_or(package_name);
            format!("{}-{}.tgz", short_name, version)
        } else {
            format!("{}-{}.tgz", package_name, version)
        };

        // Find the attachment — try the exact filename first, then any available
        let attachment_data = attachments_obj
            .get(&tarball_filename)
            .or_else(|| {
                // npm may use the full scoped name in the attachment key
                attachments_obj.values().next()
            })
            .ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("No attachment found for version {}", version),
                )
                    .into_response()
            })?;

        let base64_data = attachment_data
            .get("data")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                (StatusCode::BAD_REQUEST, "Missing 'data' in attachment").into_response()
            })?;

        // Decode the base64 tarball
        let tarball_bytes = base64::engine::general_purpose::STANDARD
            .decode(base64_data)
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Invalid base64 data: {}", e),
                )
                    .into_response()
            })?;

        // Compute SHA256
        let mut hasher = Sha256::new();
        hasher.update(&tarball_bytes);
        let sha256 = format!("{:x}", hasher.finalize());

        // Build artifact path
        let artifact_path = format!("{}/{}/{}", package_name, version, tarball_filename);

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
            return Err((
                StatusCode::CONFLICT,
                format!("Version {} of {} already exists", version, package_name),
            )
                .into_response());
        }

        // Store the tarball
        let storage_key = format!("npm/{}/{}/{}", package_name, version, tarball_filename);
        let storage = FilesystemStorage::new(&repo.storage_path);
        storage
            .put(&storage_key, Bytes::from(tarball_bytes.clone()))
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Storage error: {}", e),
                )
                    .into_response()
            })?;

        let size_bytes = tarball_bytes.len() as i64;

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
            package_name,
            version.clone(),
            size_bytes,
            sha256,
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

        // Store metadata (version_data from the publish payload)
        let npm_metadata = serde_json::json!({
            "name": package_name,
            "version": version,
            "version_data": version_data,
        });

        let _ = sqlx::query!(
            r#"
            INSERT INTO artifact_metadata (artifact_id, format, metadata)
            VALUES ($1, 'npm', $2)
            ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
            "#,
            artifact_id,
            npm_metadata,
        )
        .execute(&state.db)
        .await;

        // Populate packages / package_versions tables (best-effort)
        {
            let pkg_svc =
                crate::services::package_service::PackageService::new(state.db.clone());
            let description = version_data
                .get("description")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            pkg_svc
                .try_create_or_update_from_artifact(
                    repo.id,
                    package_name,
                    version,
                    size_bytes,
                    &sha256,
                    description.as_deref(),
                    Some(serde_json::json!({ "format": "npm" })),
                )
                .await;
        }

        info!(
            "npm publish: {} {} ({}) to repo {}",
            package_name, version, tarball_filename, repo_key
        );
    }

    // Update repository timestamp
    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
    .await;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({"ok": true})).unwrap(),
        ))
        .unwrap())
}
