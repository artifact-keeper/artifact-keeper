//! Conan v2 Repository API handlers.
//!
//! Implements the Conan v2 REST API for C/C++ package management.
//!
//! Routes are mounted at `/conan/{repo_key}/...`:
//!   GET  /conan/{repo_key}/v2/ping                                                                         - Ping / capability check
//!   POST /conan/{repo_key}/v2/users/authenticate                                                           - Authenticate and get token
//!   GET  /conan/{repo_key}/v2/users/check_credentials                                                      - Check credentials
//!   GET  /conan/{repo_key}/v2/conans/search                                                                - Search packages
//!   GET  /conan/{repo_key}/v2/conans/{name}/{version}/{user}/{channel}/latest                               - Latest recipe revision
//!   GET  /conan/{repo_key}/v2/conans/{name}/{version}/{user}/{channel}/revisions                            - List recipe revisions
//!   GET  /conan/{repo_key}/v2/conans/{name}/{version}/{user}/{channel}/revisions/{rev}/files/{path}         - Download recipe file
//!   PUT  /conan/{repo_key}/v2/conans/{name}/{version}/{user}/{channel}/revisions/{rev}/files/{path}         - Upload recipe file
//!   GET  /conan/{repo_key}/v2/conans/{name}/{version}/{user}/{channel}/revisions/{rev}/packages/{pkg_id}/latest           - Latest package revision
//!   GET  /conan/{repo_key}/v2/conans/{name}/{version}/{user}/{channel}/revisions/{rev}/packages/{pkg_id}/revisions        - List package revisions
//!   GET  /conan/{repo_key}/v2/conans/{name}/{version}/{user}/{channel}/revisions/{rev}/packages/{pkg_id}/revisions/{pkg_rev}/files/{path} - Download package file
//!   PUT  /conan/{repo_key}/v2/conans/{name}/{version}/{user}/{channel}/revisions/{rev}/packages/{pkg_id}/revisions/{pkg_rev}/files/{path} - Upload package file

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
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
        // Ping
        .route("/:repo_key/v2/ping", get(ping))
        // Authentication
        .route(
            "/:repo_key/v2/users/authenticate",
            get(users_authenticate).post(users_authenticate),
        )
        .route(
            "/:repo_key/v2/users/check_credentials",
            get(check_credentials),
        )
        // Search
        .route("/:repo_key/v2/conans/search", get(search))
        // Recipe latest revision
        .route(
            "/:repo_key/v2/conans/:name/:version/:user/:channel/latest",
            get(recipe_latest),
        )
        // Recipe revisions list
        .route(
            "/:repo_key/v2/conans/:name/:version/:user/:channel/revisions",
            get(recipe_revisions),
        )
        // Recipe file download / upload
        .route(
            "/:repo_key/v2/conans/:name/:version/:user/:channel/revisions/:revision/files/*file_path",
            get(recipe_file_download).put(recipe_file_upload),
        )
        // Package latest revision
        .route(
            "/:repo_key/v2/conans/:name/:version/:user/:channel/revisions/:revision/packages/:package_id/latest",
            get(package_latest),
        )
        // Package revisions list
        .route(
            "/:repo_key/v2/conans/:name/:version/:user/:channel/revisions/:revision/packages/:package_id/revisions",
            get(package_revisions),
        )
        // Package file download / upload
        .route(
            "/:repo_key/v2/conans/:name/:version/:user/:channel/revisions/:revision/packages/:package_id/revisions/:pkg_revision/files/*file_path",
            get(package_file_download).put(package_file_upload),
        )
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

/// Authenticate via Basic auth, returning user_id on success.
async fn authenticate(
    db: &PgPool,
    config: &crate::config::Config,
    headers: &HeaderMap,
) -> Result<uuid::Uuid, Response> {
    let (username, password) = extract_basic_credentials(headers).ok_or_else(|| {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Basic realm=\"conan\"")
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
                .header("WWW-Authenticate", "Basic realm=\"conan\"")
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

async fn resolve_conan_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
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
    if fmt != "conan" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not a Conan repository (format: {})",
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
// Helpers
// ---------------------------------------------------------------------------

/// Normalize user/channel: Conan uses "_" as the default placeholder.
fn normalize_user(user: &str) -> &str {
    if user == "_" {
        "_"
    } else {
        user
    }
}

fn normalize_channel(channel: &str) -> &str {
    if channel == "_" {
        "_"
    } else {
        channel
    }
}

/// Build a storage key for a recipe file.
fn recipe_storage_key(
    name: &str,
    version: &str,
    user: &str,
    channel: &str,
    revision: &str,
    file_path: &str,
) -> String {
    format!(
        "conan/{}/{}/{}/{}/recipe/{}/{}",
        name,
        version,
        normalize_user(user),
        normalize_channel(channel),
        revision,
        file_path.trim_start_matches('/')
    )
}

/// Build a storage key for a package file.
fn package_storage_key(
    name: &str,
    version: &str,
    user: &str,
    channel: &str,
    revision: &str,
    package_id: &str,
    pkg_revision: &str,
    file_path: &str,
) -> String {
    format!(
        "conan/{}/{}/{}/{}/package/{}/{}/{}/{}",
        name,
        version,
        normalize_user(user),
        normalize_channel(channel),
        revision,
        package_id,
        pkg_revision,
        file_path.trim_start_matches('/')
    )
}

/// Build the artifact path (stored in the `artifacts.path` column) for a recipe file.
fn recipe_artifact_path(
    name: &str,
    version: &str,
    user: &str,
    channel: &str,
    revision: &str,
    file_path: &str,
) -> String {
    format!(
        "{}/{}/{}/{}/revisions/{}/files/{}",
        name,
        version,
        normalize_user(user),
        normalize_channel(channel),
        revision,
        file_path.trim_start_matches('/')
    )
}

/// Build the artifact path for a package file.
fn package_artifact_path(
    name: &str,
    version: &str,
    user: &str,
    channel: &str,
    revision: &str,
    package_id: &str,
    pkg_revision: &str,
    file_path: &str,
) -> String {
    format!(
        "{}/{}/{}/{}/revisions/{}/packages/{}/revisions/{}/files/{}",
        name,
        version,
        normalize_user(user),
        normalize_channel(channel),
        revision,
        package_id,
        pkg_revision,
        file_path.trim_start_matches('/')
    )
}

fn content_type_for_conan_file(path: &str) -> &'static str {
    if path.ends_with(".py") || path.ends_with(".txt") {
        "text/plain"
    } else if path.ends_with(".tgz") || path.ends_with(".tar.gz") {
        "application/gzip"
    } else {
        "application/octet-stream"
    }
}

// ---------------------------------------------------------------------------
// GET /conan/{repo_key}/v2/ping
// ---------------------------------------------------------------------------

async fn ping() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header("X-Conan-Server-Capabilities", "revisions")
        .body(Body::empty())
        .unwrap()
}

// ---------------------------------------------------------------------------
// POST /conan/{repo_key}/v2/users/authenticate
// ---------------------------------------------------------------------------

async fn users_authenticate(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    // Validate repo exists and is conan format
    let _repo = resolve_conan_repo(&state.db, &repo_key).await?;

    // Authenticate user via Basic auth
    let _user_id = authenticate(&state.db, &state.config, &headers).await?;

    // Return a simple token (the Conan client expects a token string in the body).
    // In a production system this would be a proper JWT; for now we echo back the
    // Basic auth value so the client can keep using it.
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic ").or(v.strip_prefix("basic ")))
        .unwrap_or("")
        .to_string();

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain")
        .body(Body::from(token))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /conan/{repo_key}/v2/users/check_credentials
// ---------------------------------------------------------------------------

async fn check_credentials(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let _repo = resolve_conan_repo(&state.db, &repo_key).await?;
    let _user_id = authenticate(&state.db, &state.config, &headers).await?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /conan/{repo_key}/v2/conans/search?q=pattern
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct SearchQuery {
    q: Option<String>,
}

async fn search(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    Query(query): Query<SearchQuery>,
) -> Result<Response, Response> {
    let repo = resolve_conan_repo(&state.db, &repo_key).await?;

    let pattern = query.q.unwrap_or_else(|| "*".to_string());

    // Convert glob-like pattern to SQL LIKE pattern
    let like_pattern = pattern.replace('*', "%");

    let rows = sqlx::query!(
        r#"
        SELECT DISTINCT a.name, a.version as "version?"
        FROM artifacts a
        JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND am.format = 'conan'
          AND a.name LIKE $2
        ORDER BY a.name, a.version
        "#,
        repo.id,
        like_pattern,
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

    // Build search results in Conan v2 format
    let results: Vec<String> = rows
        .iter()
        .map(|r| {
            let version = r.version.as_deref().unwrap_or("0.0.0");
            let user = "_";
            let channel = "_";
            format!("{}/{}@{}/{}", r.name, version, user, channel)
        })
        .collect();

    let json = serde_json::json!({
        "results": results
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /conan/{repo_key}/v2/conans/{name}/{version}/{user}/{channel}/latest
// ---------------------------------------------------------------------------

async fn recipe_latest(
    State(state): State<SharedState>,
    Path((repo_key, name, version, _user, _channel)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, Response> {
    let repo = resolve_conan_repo(&state.db, &repo_key).await?;

    // Find the latest recipe revision by looking at the most recently created artifact
    // with a revision in its metadata.
    let row = sqlx::query!(
        r#"
        SELECT am.metadata->>'revision' as "revision?"
        FROM artifacts a
        JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND am.format = 'conan'
          AND a.name = $2
          AND a.version = $3
          AND am.metadata->>'revision' IS NOT NULL
        ORDER BY a.created_at DESC
        LIMIT 1
        "#,
        repo.id,
        name,
        version,
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "No revisions found").into_response())?;

    let revision = row
        .revision
        .ok_or_else(|| (StatusCode::NOT_FOUND, "No revisions found").into_response())?;

    let json = serde_json::json!({
        "revision": revision,
        "time": chrono::Utc::now().to_rfc3339()
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /conan/{repo_key}/v2/conans/{name}/{version}/{user}/{channel}/revisions
// ---------------------------------------------------------------------------

async fn recipe_revisions(
    State(state): State<SharedState>,
    Path((repo_key, name, version, _user, _channel)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, Response> {
    let repo = resolve_conan_repo(&state.db, &repo_key).await?;

    let rows = sqlx::query!(
        r#"
        SELECT DISTINCT am.metadata->>'revision' as "revision?", a.created_at
        FROM artifacts a
        JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND am.format = 'conan'
          AND a.name = $2
          AND a.version = $3
          AND am.metadata->>'revision' IS NOT NULL
        ORDER BY a.created_at DESC
        "#,
        repo.id,
        name,
        version,
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

    let revisions: Vec<serde_json::Value> = rows
        .into_iter()
        .filter_map(|r| {
            r.revision.map(|rev| {
                serde_json::json!({
                    "revision": rev,
                    "time": r.created_at.to_rfc3339()
                })
            })
        })
        .collect();

    let json = serde_json::json!({
        "revisions": revisions
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET  .../revisions/{rev}/files/{path} — Download recipe file
// ---------------------------------------------------------------------------

async fn recipe_file_download(
    State(state): State<SharedState>,
    Path((repo_key, name, version, user, channel, revision, file_path)): Path<(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, Response> {
    let repo = resolve_conan_repo(&state.db, &repo_key).await?;

    let artifact_path =
        recipe_artifact_path(&name, &version, &user, &channel, &revision, &file_path);
    let _storage_key = recipe_storage_key(&name, &version, &user, &channel, &revision, &file_path);

    // Look up artifact
    let artifact = sqlx::query!(
        r#"
        SELECT id, size_bytes, checksum_sha256, storage_key
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND path = $2
        LIMIT 1
        "#,
        repo.id,
        artifact_path,
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "File not found").into_response())?;

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

    let ct = content_type_for_conan_file(&file_path);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, ct)
        .header(CONTENT_LENGTH, content.len().to_string())
        .header("X-Checksum-SHA256", &artifact.checksum_sha256)
        .body(Body::from(content))
        .unwrap())
}

// ---------------------------------------------------------------------------
// PUT  .../revisions/{rev}/files/{path} — Upload recipe file
// ---------------------------------------------------------------------------

async fn recipe_file_upload(
    State(state): State<SharedState>,
    Path((repo_key, name, version, user, channel, revision, file_path)): Path<(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    )>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_conan_repo(&state.db, &repo_key).await?;

    let artifact_path =
        recipe_artifact_path(&name, &version, &user, &channel, &revision, &file_path);
    let storage_key = recipe_storage_key(&name, &version, &user, &channel, &revision, &file_path);

    // Compute SHA-256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let checksum_sha256 = format!("{:x}", hasher.finalize());

    let size_bytes = body.len() as i64;
    let ct = content_type_for_conan_file(&file_path);

    // Check for duplicate — allow overwrite for the same revision
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        repo.id,
        artifact_path,
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

    if let Some(existing_id) = existing {
        // Soft-delete the old version to allow re-upload within same revision
        let _ = sqlx::query!(
            "UPDATE artifacts SET is_deleted = true WHERE id = $1",
            existing_id,
        )
        .execute(&state.db)
        .await;
    }

    // Store the file
    let storage = FilesystemStorage::new(&repo.storage_path);
    storage.put(&storage_key, body.clone()).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    // Build metadata JSON
    let metadata = serde_json::json!({
        "name": name,
        "version": version,
        "user": normalize_user(&user),
        "channel": normalize_channel(&channel),
        "revision": revision,
        "type": "recipe",
        "file": file_path.trim_start_matches('/'),
    });

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
        name,
        version,
        size_bytes,
        checksum_sha256,
        ct,
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
        VALUES ($1, 'conan', $2)
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

    info!(
        "Conan recipe upload: {}/{} rev={} file={} to repo {}",
        name,
        version,
        revision,
        file_path.trim_start_matches('/'),
        repo_key
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .body(Body::from("Created"))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET .../packages/{package_id}/latest — Latest package revision
// ---------------------------------------------------------------------------

async fn package_latest(
    State(state): State<SharedState>,
    Path((repo_key, name, version, _user, _channel, revision, package_id)): Path<(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, Response> {
    let repo = resolve_conan_repo(&state.db, &repo_key).await?;

    let row = sqlx::query!(
        r#"
        SELECT am.metadata->>'packageRevision' as "pkg_revision?"
        FROM artifacts a
        JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND am.format = 'conan'
          AND a.name = $2
          AND a.version = $3
          AND am.metadata->>'revision' = $4
          AND am.metadata->>'packageId' = $5
          AND am.metadata->>'type' = 'package'
          AND am.metadata->>'packageRevision' IS NOT NULL
        ORDER BY a.created_at DESC
        LIMIT 1
        "#,
        repo.id,
        name,
        version,
        revision,
        package_id,
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "No package revisions found").into_response())?;

    let pkg_revision = row
        .pkg_revision
        .ok_or_else(|| (StatusCode::NOT_FOUND, "No package revisions found").into_response())?;

    let json = serde_json::json!({
        "revision": pkg_revision,
        "time": chrono::Utc::now().to_rfc3339()
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET .../packages/{package_id}/revisions — List package revisions
// ---------------------------------------------------------------------------

async fn package_revisions(
    State(state): State<SharedState>,
    Path((repo_key, name, version, _user, _channel, revision, package_id)): Path<(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, Response> {
    let repo = resolve_conan_repo(&state.db, &repo_key).await?;

    let rows = sqlx::query!(
        r#"
        SELECT DISTINCT am.metadata->>'packageRevision' as "pkg_revision?", a.created_at
        FROM artifacts a
        JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND am.format = 'conan'
          AND a.name = $2
          AND a.version = $3
          AND am.metadata->>'revision' = $4
          AND am.metadata->>'packageId' = $5
          AND am.metadata->>'type' = 'package'
          AND am.metadata->>'packageRevision' IS NOT NULL
        ORDER BY a.created_at DESC
        "#,
        repo.id,
        name,
        version,
        revision,
        package_id,
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

    let revisions: Vec<serde_json::Value> = rows
        .into_iter()
        .filter_map(|r| {
            r.pkg_revision.map(|rev| {
                serde_json::json!({
                    "revision": rev,
                    "time": r.created_at.to_rfc3339()
                })
            })
        })
        .collect();

    let json = serde_json::json!({
        "revisions": revisions
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET  .../packages/{pkg_id}/revisions/{pkg_rev}/files/{path} — Download package file
// ---------------------------------------------------------------------------

async fn package_file_download(
    State(state): State<SharedState>,
    Path((repo_key, name, version, user, channel, revision, package_id, pkg_revision, file_path)): Path<(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, Response> {
    let repo = resolve_conan_repo(&state.db, &repo_key).await?;

    let artifact_path = package_artifact_path(
        &name,
        &version,
        &user,
        &channel,
        &revision,
        &package_id,
        &pkg_revision,
        &file_path,
    );

    // Look up artifact
    let artifact = sqlx::query!(
        r#"
        SELECT id, size_bytes, checksum_sha256, storage_key
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND path = $2
        LIMIT 1
        "#,
        repo.id,
        artifact_path,
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "File not found").into_response())?;

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

    let ct = content_type_for_conan_file(&file_path);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, ct)
        .header(CONTENT_LENGTH, content.len().to_string())
        .header("X-Checksum-SHA256", &artifact.checksum_sha256)
        .body(Body::from(content))
        .unwrap())
}

// ---------------------------------------------------------------------------
// PUT  .../packages/{pkg_id}/revisions/{pkg_rev}/files/{path} — Upload package file
// ---------------------------------------------------------------------------

async fn package_file_upload(
    State(state): State<SharedState>,
    Path((repo_key, name, version, user, channel, revision, package_id, pkg_revision, file_path)): Path<(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    )>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_conan_repo(&state.db, &repo_key).await?;

    let artifact_path = package_artifact_path(
        &name,
        &version,
        &user,
        &channel,
        &revision,
        &package_id,
        &pkg_revision,
        &file_path,
    );
    let storage_key = package_storage_key(
        &name,
        &version,
        &user,
        &channel,
        &revision,
        &package_id,
        &pkg_revision,
        &file_path,
    );

    // Compute SHA-256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let checksum_sha256 = format!("{:x}", hasher.finalize());

    let size_bytes = body.len() as i64;
    let ct = content_type_for_conan_file(&file_path);

    // Check for duplicate — allow overwrite within same revision
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        repo.id,
        artifact_path,
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

    if let Some(existing_id) = existing {
        let _ = sqlx::query!(
            "UPDATE artifacts SET is_deleted = true WHERE id = $1",
            existing_id,
        )
        .execute(&state.db)
        .await;
    }

    // Store the file
    let storage = FilesystemStorage::new(&repo.storage_path);
    storage.put(&storage_key, body.clone()).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    // Build metadata JSON
    let metadata = serde_json::json!({
        "name": name,
        "version": version,
        "user": normalize_user(&user),
        "channel": normalize_channel(&channel),
        "revision": revision,
        "packageId": package_id,
        "packageRevision": pkg_revision,
        "type": "package",
        "file": file_path.trim_start_matches('/'),
    });

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
        name,
        version,
        size_bytes,
        checksum_sha256,
        ct,
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
        VALUES ($1, 'conan', $2)
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

    info!(
        "Conan package upload: {}/{} rev={} pkg={} pkg_rev={} file={} to repo {}",
        name,
        version,
        revision,
        package_id,
        pkg_revision,
        file_path.trim_start_matches('/'),
        repo_key
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .body(Body::from("Created"))
        .unwrap())
}
