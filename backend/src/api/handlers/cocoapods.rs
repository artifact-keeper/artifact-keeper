//! CocoaPods Spec Repo API handlers.
//!
//! Implements the endpoints required for CocoaPods pod install and pod push.
//!
//! Routes are mounted at `/cocoapods/{repo_key}/...`:
//!   GET  /cocoapods/{repo_key}/Specs/{name}/{version}/{name}.podspec.json - Get podspec
//!   GET  /cocoapods/{repo_key}/pods/{name}-{version}.tar.gz              - Download pod archive
//!   POST /cocoapods/{repo_key}/pods                                      - Push pod (auth required)
//!   GET  /cocoapods/{repo_key}/all_specs                                 - List all specs

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use base64::Engine;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::SharedState;
use crate::formats::cocoapods::CocoaPodsHandler;
use crate::services::auth_service::AuthService;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::StorageBackend;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Push pod
        .route("/:repo_key/pods", post(push_pod))
        // List all specs
        .route("/:repo_key/all_specs", get(all_specs))
        // Get podspec
        .route(
            "/:repo_key/Specs/:name/:version/*podspec_file",
            get(get_podspec),
        )
        // Download pod archive
        .route("/:repo_key/pods/*pod_file", get(download_pod))
        .layer(DefaultBodyLimit::max(512 * 1024 * 1024)) // 512 MB
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

fn extract_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    // Try Bearer token first
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

/// Authenticate via Basic auth or Bearer token, returning user_id on success.
async fn authenticate(
    db: &PgPool,
    config: &crate::config::Config,
    headers: &HeaderMap,
) -> Result<uuid::Uuid, Response> {
    let (username, password) = extract_credentials(headers).ok_or_else(|| {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Basic realm=\"cocoapods\"")
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
                .header("WWW-Authenticate", "Basic realm=\"cocoapods\"")
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

async fn resolve_cocoapods_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
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
    if fmt != "cocoapods" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not a CocoaPods repository (format: {})",
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
// GET /cocoapods/{repo_key}/Specs/{name}/{version}/{name}.podspec.json
// ---------------------------------------------------------------------------

async fn get_podspec(
    State(state): State<SharedState>,
    Path((repo_key, name, version, podspec_file)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_cocoapods_repo(&state.db, &repo_key).await?;

    let podspec_file = podspec_file.trim_start_matches('/');

    // Validate via the format handler
    let full_path = format!("Specs/{}/{}/{}", name, version, podspec_file);
    let path_info = CocoaPodsHandler::parse_path(&full_path)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid path: {}", e)).into_response())?;

    // Find the artifact
    let artifact = sqlx::query!(
        r#"
        SELECT a.id, a.storage_key, am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND LOWER(a.name) = LOWER($2)
          AND a.version = $3
        LIMIT 1
        "#,
        repo.id,
        path_info.name,
        path_info.version
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Podspec not found").into_response())?;

    // Return the podspec from metadata if available, otherwise read from storage
    let podspec_from_meta: Option<String> = artifact
        .metadata
        .as_ref()
        .and_then(|m| m.get("podspec"))
        .map(|v| serde_json::to_string(v).unwrap_or_default());

    if let Some(podspec_json) = podspec_from_meta {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(podspec_json))
            .unwrap());
    }

    // Fall back to reading the podspec file from storage
    let podspec_key = format!(
        "cocoapods/{}/{}/{}.podspec.json",
        path_info.name, path_info.version, path_info.name
    );
    let storage = FilesystemStorage::new(&repo.storage_path);
    let content = storage.get(&podspec_key).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .header(CONTENT_LENGTH, content.len().to_string())
        .body(Body::from(content))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /cocoapods/{repo_key}/pods/{name}-{version}.tar.gz — Download pod archive
// ---------------------------------------------------------------------------

async fn download_pod(
    State(state): State<SharedState>,
    Path((repo_key, pod_file)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_cocoapods_repo(&state.db, &repo_key).await?;

    let filename = pod_file.trim_start_matches('/');

    // Parse the pod path to extract name and version
    let full_path = format!("pods/{}", filename);
    let path_info = CocoaPodsHandler::parse_path(&full_path)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid path: {}", e)).into_response())?;

    // Find artifact by name and version
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
        path_info.name,
        path_info.version
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Pod not found").into_response())?;

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
// POST /cocoapods/{repo_key}/pods — Push pod (body is tar.gz with podspec)
// ---------------------------------------------------------------------------

async fn push_pod(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_cocoapods_repo(&state.db, &repo_key).await?;

    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty pod archive").into_response());
    }

    // Try to extract podspec from the archive body.
    // The body should contain a tar.gz with a podspec.json inside.
    let podspec = extract_podspec_from_archive(&body).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid pod archive: {}", e),
        )
            .into_response()
    })?;

    let pod_name = &podspec.name;
    let pod_version = &podspec.version;

    if pod_name.is_empty() || pod_version.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Pod name and version are required").into_response());
    }

    let filename = format!("{}-{}.tar.gz", pod_name, pod_version);
    let artifact_path = format!("{}/{}/{}", pod_name, pod_version, filename);

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let computed_sha256 = format!("{:x}", hasher.finalize());

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
        return Err((StatusCode::CONFLICT, "Pod version already exists").into_response());
    }

    // Store the pod archive
    let storage_key = format!("cocoapods/{}/{}/{}", pod_name, pod_version, filename);
    let storage = FilesystemStorage::new(&repo.storage_path);
    storage.put(&storage_key, body.clone()).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    // Also store the podspec JSON separately for direct retrieval
    let podspec_key = format!(
        "cocoapods/{}/{}/{}.podspec.json",
        pod_name, pod_version, pod_name
    );
    let podspec_json = serde_json::to_vec(&podspec).unwrap_or_default();
    storage
        .put(&podspec_key, Bytes::from(podspec_json))
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Storage error: {}", e),
            )
                .into_response()
        })?;

    // Build metadata JSON
    let pod_metadata = serde_json::json!({
        "podspec": serde_json::to_value(&podspec).unwrap_or_default(),
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
        pod_name,
        pod_version.to_string(),
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
        VALUES ($1, 'cocoapods', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        pod_metadata,
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
        "CocoaPods push: {} {} ({}) to repo {}",
        pod_name, pod_version, filename, repo_key
    );

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::from("Successfully registered pod"))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /cocoapods/{repo_key}/all_specs — List all specs (JSON)
// ---------------------------------------------------------------------------

async fn all_specs(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_cocoapods_repo(&state.db, &repo_key).await?;

    let artifacts = sqlx::query!(
        r#"
        SELECT a.name, a.version, am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
        ORDER BY a.name, a.created_at DESC
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

    // Group versions by pod name
    let mut specs: std::collections::HashMap<String, Vec<serde_json::Value>> =
        std::collections::HashMap::new();

    for a in &artifacts {
        let name = a.name.clone();
        let version = a.version.clone().unwrap_or_default();

        let summary = a
            .metadata
            .as_ref()
            .and_then(|m| m.get("podspec"))
            .and_then(|ps| ps.get("summary"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let version_info = serde_json::json!({
            "version": version,
            "summary": summary,
        });

        specs.entry(name).or_default().push(version_info);
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&specs).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

use crate::formats::cocoapods::PodSpec;

/// Extract a podspec.json from a tar.gz archive.
///
/// Scans the archive entries for any file ending in `.podspec.json` and
/// deserializes it into a PodSpec.
fn extract_podspec_from_archive(data: &[u8]) -> Result<PodSpec, String> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    use tar::Archive;

    let gz = GzDecoder::new(data);
    let mut archive = Archive::new(gz);

    let entries = archive
        .entries()
        .map_err(|e| format!("Failed to read archive: {}", e))?;

    for entry in entries {
        let mut entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;

        let path = entry
            .path()
            .map_err(|e| format!("Failed to read path: {}", e))?
            .to_string_lossy()
            .to_string();

        if path.ends_with(".podspec.json") {
            let mut contents = Vec::new();
            entry
                .read_to_end(&mut contents)
                .map_err(|e| format!("Failed to read podspec: {}", e))?;

            let podspec: PodSpec = serde_json::from_slice(&contents)
                .map_err(|e| format!("Invalid podspec JSON: {}", e))?;

            return Ok(podspec);
        }
    }

    Err("No .podspec.json found in archive".to_string())
}
