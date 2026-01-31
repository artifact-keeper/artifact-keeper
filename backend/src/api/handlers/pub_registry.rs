//! Pub (Dart/Flutter) API handlers.
//!
//! Implements the Pub Repository Spec v2 endpoints for `dart pub publish`
//! and `dart pub get`.
//!
//! Routes are mounted at `/pub/{repo_key}/...`:
//!   GET  /pub/{repo_key}/api/packages/{name}                       - Package info
//!   GET  /pub/{repo_key}/api/packages/{name}/versions/{version}    - Version info
//!   GET  /pub/{repo_key}/packages/{name}/versions/{version}.tar.gz - Download archive
//!   POST /pub/{repo_key}/api/packages/versions/new                 - Get upload URL
//!   POST /pub/{repo_key}/api/packages/versions/newUpload           - Upload package
//!   GET  /pub/{repo_key}/api/packages/versions/newUploadFinish     - Finalize upload

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
use crate::services::auth_service::AuthService;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::StorageBackend;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Upload flow (must be registered before the parameterized routes
        // so that literal segments match before `:name` captures them)
        .route(
            "/:repo_key/api/packages/versions/new",
            post(new_upload_url),
        )
        .route(
            "/:repo_key/api/packages/versions/newUpload",
            post(upload_package),
        )
        .route(
            "/:repo_key/api/packages/versions/newUploadFinish",
            get(finalize_upload),
        )
        // Package info
        .route("/:repo_key/api/packages/:name", get(package_info))
        // Version info
        .route(
            "/:repo_key/api/packages/:name/versions/:version",
            get(version_info),
        )
        // Download archive - wildcard to capture name/versions/version.tar.gz
        .route("/:repo_key/packages/*archive_path", get(download_archive))
        .layer(DefaultBodyLimit::max(512 * 1024 * 1024)) // 512 MB
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

fn extract_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    // Try Bearer token first (used by `dart pub publish`)
    if let Some(bearer) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or(v.strip_prefix("bearer ")))
    {
        return Some(("token".to_string(), bearer.to_string()));
    }

    // Try Basic auth
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

/// Authenticate via Bearer token or Basic auth, returning user_id on success.
async fn authenticate(
    db: &PgPool,
    config: &crate::config::Config,
    headers: &HeaderMap,
) -> Result<uuid::Uuid, Response> {
    let (username, password) = extract_credentials(headers).ok_or_else(|| {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Bearer realm=\"pub\"")
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
                .header("WWW-Authenticate", "Bearer realm=\"pub\"")
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

async fn resolve_pub_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
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
    if fmt != "pub" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not a Pub repository (format: {})",
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
// GET /pub/{repo_key}/api/packages/{name} -- Package info
// ---------------------------------------------------------------------------

async fn package_info(
    State(state): State<SharedState>,
    Path((repo_key, name)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_pub_repo(&state.db, &repo_key).await?;

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
        return Err((StatusCode::NOT_FOUND, "Package not found").into_response());
    }

    let versions: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            let version = a.version.clone().unwrap_or_default();
            let archive_url = format!(
                "/pub/{}/packages/{}/versions/{}.tar.gz",
                repo_key, name, version
            );

            let pubspec = a
                .metadata
                .as_ref()
                .and_then(|m| m.get("pubspec"))
                .cloned()
                .unwrap_or_else(|| {
                    serde_json::json!({
                        "name": name,
                        "version": version,
                    })
                });

            serde_json::json!({
                "version": version,
                "archive_url": archive_url,
                "pubspec": pubspec,
            })
        })
        .collect();

    let latest = versions.first().cloned().unwrap_or(serde_json::json!(null));

    let json = serde_json::json!({
        "name": name,
        "latest": latest,
        "versions": versions,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/vnd.pub.v2+json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /pub/{repo_key}/api/packages/{name}/versions/{version} -- Version info
// ---------------------------------------------------------------------------

async fn version_info(
    State(state): State<SharedState>,
    Path((repo_key, name, version)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_pub_repo(&state.db, &repo_key).await?;

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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Version not found").into_response())?;

    let ver = artifact.version.clone().unwrap_or_default();
    let archive_url = format!(
        "/pub/{}/packages/{}/versions/{}.tar.gz",
        repo_key, name, ver
    );

    let pubspec = artifact
        .metadata
        .as_ref()
        .and_then(|m| m.get("pubspec"))
        .cloned()
        .unwrap_or_else(|| {
            serde_json::json!({
                "name": name,
                "version": ver,
            })
        });

    let json = serde_json::json!({
        "version": ver,
        "archive_url": archive_url,
        "archive_sha256": artifact.checksum_sha256,
        "pubspec": pubspec,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/vnd.pub.v2+json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /pub/{repo_key}/packages/{name}/versions/{version}.tar.gz -- Download
// ---------------------------------------------------------------------------

async fn download_archive(
    State(state): State<SharedState>,
    Path((repo_key, archive_path)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_pub_repo(&state.db, &repo_key).await?;

    let archive_path = archive_path.trim_start_matches('/');

    // Parse: {name}/versions/{version}.tar.gz
    let parts: Vec<&str> = archive_path.splitn(3, '/').collect();
    if parts.len() < 3 || parts[1] != "versions" {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid archive path: expected packages/{name}/versions/{version}.tar.gz",
        )
            .into_response());
    }

    let pkg_name = parts[0];
    let version_file = parts[2];

    let version = version_file.strip_suffix(".tar.gz").ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid archive path: expected .tar.gz extension",
        )
            .into_response()
    })?;

    let artifact = sqlx::query!(
        r#"
        SELECT id, storage_key, size_bytes
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND LOWER(name) = LOWER($2)
          AND version = $3
        LIMIT 1
        "#,
        repo.id,
        pkg_name,
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Package archive not found").into_response())?;

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

    let filename = format!("{}-{}.tar.gz", pkg_name, version);

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
// POST /pub/{repo_key}/api/packages/versions/new -- Get upload URL
// ---------------------------------------------------------------------------

async fn new_upload_url(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let _user_id = authenticate(&state.db, &state.config, &headers).await?;
    let _repo = resolve_pub_repo(&state.db, &repo_key).await?;

    let upload_url = format!("/pub/{}/api/packages/versions/newUpload", repo_key);
    let json = serde_json::json!({
        "url": upload_url,
        "fields": {},
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/vnd.pub.v2+json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// POST /pub/{repo_key}/api/packages/versions/newUpload -- Upload package
// ---------------------------------------------------------------------------

async fn upload_package(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_pub_repo(&state.db, &repo_key).await?;

    // Extract the tar.gz file from multipart form data
    let mut file_bytes: Option<bytes::Bytes> = None;
    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid multipart: {}", e),
        )
            .into_response()
    })? {
        let field_name = field.name().unwrap_or("").to_string();
        if field_name == "file" {
            file_bytes = Some(field.bytes().await.map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Failed to read upload: {}", e),
                )
                    .into_response()
            })?);
            break;
        }
    }

    let body = file_bytes
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing 'file' field in upload").into_response())?;

    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty package archive").into_response());
    }

    // Extract pubspec.yaml from the tar.gz archive
    let pubspec = extract_pubspec_from_archive(&body).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid Pub package: {}", e),
        )
            .into_response()
    })?;

    let pkg_name = &pubspec.name;
    let pkg_version = &pubspec.version;

    if pkg_name.is_empty() || pkg_version.is_empty() {
        return Err(
            (StatusCode::BAD_REQUEST, "Package name and version are required").into_response(),
        );
    }

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let computed_sha256 = format!("{:x}", hasher.finalize());

    let filename = format!("{}-{}.tar.gz", pkg_name, pkg_version);
    let artifact_path = format!("{}/{}/{}", pkg_name, pkg_version, filename);

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
        return Err((StatusCode::CONFLICT, "Package version already exists").into_response());
    }

    // Store the file
    let storage_key = format!("pub/{}/{}/{}", pkg_name, pkg_version, filename);
    let storage = FilesystemStorage::new(&repo.storage_path);
    storage.put(&storage_key, body.clone()).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    // Build metadata JSON
    let pub_metadata = serde_json::json!({
        "pubspec": serde_json::to_value(&pubspec).unwrap_or_default(),
        "filename": filename,
    });

    let size_bytes = body.len() as i64;

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
        pkg_name,
        pkg_version.to_string(),
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

    // Store metadata
    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'pub', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        pub_metadata,
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

    info!(
        "Pub upload: {} {} ({}) to repo {}",
        pkg_name, pkg_version, filename, repo_key
    );

    // Redirect to finalize endpoint per the Pub spec
    let finish_url = format!(
        "/pub/{}/api/packages/versions/newUploadFinish",
        repo_key
    );

    Ok(Response::builder()
        .status(StatusCode::FOUND)
        .header("Location", finish_url)
        .body(Body::empty())
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /pub/{repo_key}/api/packages/versions/newUploadFinish -- Finalize
// ---------------------------------------------------------------------------

async fn finalize_upload(
    State(_state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let json = serde_json::json!({
        "success": {
            "message": format!("Successfully uploaded package to repository '{}'.", repo_key),
        },
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/vnd.pub.v2+json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract pubspec.yaml from a Pub package tar.gz archive.
fn extract_pubspec_from_archive(
    data: &[u8],
) -> Result<crate::formats::r#pub::PubSpec, String> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    use tar::Archive;

    let decoder = GzDecoder::new(data);
    let mut archive = Archive::new(decoder);

    let entries = archive.entries().map_err(|e| format!("Failed to read archive: {}", e))?;

    for entry in entries {
        let mut entry = entry.map_err(|e| format!("Failed to read archive entry: {}", e))?;
        let path = entry
            .path()
            .map_err(|e| format!("Failed to read entry path: {}", e))?
            .to_string_lossy()
            .to_string();

        if path == "pubspec.yaml" || path.ends_with("/pubspec.yaml") {
            let mut contents = String::new();
            entry
                .read_to_string(&mut contents)
                .map_err(|e| format!("Failed to read pubspec.yaml: {}", e))?;

            let pubspec: crate::formats::r#pub::PubSpec = serde_yaml::from_str(&contents)
                .map_err(|e| format!("Failed to parse pubspec.yaml: {}", e))?;

            return Ok(pubspec);
        }
    }

    Err("pubspec.yaml not found in archive".to_string())
}
