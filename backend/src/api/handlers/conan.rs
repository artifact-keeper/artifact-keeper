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
//!   GET  /conan/{repo_key}/v2/conans/{name}/{version}/{user}/{channel}/revisions/{rev}/files                - List recipe files
//!   GET  /conan/{repo_key}/v2/conans/{name}/{version}/{user}/{channel}/revisions/{rev}/files/{path}         - Download recipe file
//!   PUT  /conan/{repo_key}/v2/conans/{name}/{version}/{user}/{channel}/revisions/{rev}/files/{path}         - Upload recipe file
//!   GET  /conan/{repo_key}/v2/conans/{name}/{version}/{user}/{channel}/revisions/{rev}/packages/{pkg_id}/latest           - Latest package revision
//!   GET  /conan/{repo_key}/v2/conans/{name}/{version}/{user}/{channel}/revisions/{rev}/packages/{pkg_id}/revisions        - List package revisions
//!   GET  /conan/{repo_key}/v2/conans/{name}/{version}/{user}/{channel}/revisions/{rev}/packages/{pkg_id}/revisions/{pkg_rev}/files                - List package files
//!   GET  /conan/{repo_key}/v2/conans/{name}/{version}/{user}/{channel}/revisions/{rev}/packages/{pkg_id}/revisions/{pkg_rev}/files/{path} - Download package file
//!   PUT  /conan/{repo_key}/v2/conans/{name}/{version}/{user}/{channel}/revisions/{rev}/packages/{pkg_id}/revisions/{pkg_rev}/files/{path} - Upload package file

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Extension;
use axum::Router;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic, AuthExtension};
use crate::api::SharedState;
use crate::models::repository::RepositoryType;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Ping. Conan 2 clients probe `/v1/ping` for server capabilities
        // (the `x-conan-server-capabilities` header) even when using the v2
        // protocol — see `conan/internal/rest/rest_client.py::_get_api`. Both
        // routes return the same response.
        .route("/:repo_key/v1/ping", get(ping))
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
        // Recipe files list (must precede the wildcard route below so axum
        // matches exact `/files` requests here rather than treating them as
        // a wildcard with an empty path segment).
        .route(
            "/:repo_key/v2/conans/:name/:version/:user/:channel/revisions/:revision/files",
            get(recipe_files_list),
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
        // Package files list (precedes the wildcard route, same reason as
        // the recipe files-list route above).
        .route(
            "/:repo_key/v2/conans/:name/:version/:user/:channel/revisions/:revision/packages/:package_id/revisions/:pkg_revision/files",
            get(package_files_list),
        )
        // Package file download / upload
        .route(
            "/:repo_key/v2/conans/:name/:version/:user/:channel/revisions/:revision/packages/:package_id/revisions/:pkg_revision/files/*file_path",
            get(package_file_download).put(package_file_upload),
        )
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_conan_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["conan"], "a Conan").await
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
#[allow(clippy::too_many_arguments)]
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
#[allow(clippy::too_many_arguments)]
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
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    // Validate repo exists and is conan format
    let _repo = resolve_conan_repo(&state.db, &repo_key).await?;

    // Authenticate user via Basic auth
    let _user_id = require_auth_basic(auth, "conan")?.user_id;

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
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let _repo = resolve_conan_repo(&state.db, &repo_key).await?;
    let _user_id = require_auth_basic(auth, "conan")?.user_id;

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
        SELECT DISTINCT
            a.name,
            a.version as "version?",
            am.metadata->>'version' as "meta_version?",
            am.metadata->>'user' as "meta_user?",
            am.metadata->>'channel' as "meta_channel?"
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

    // Build search results in Conan v2 format.
    //
    // Prefer the per-recipe values stored in `artifact_metadata.metadata`
    // (`version`, `user`, `channel`) so the response matches what the Conan
    // client uploaded. Fall back to the artifact column / spec defaults when
    // the JSON field is absent (preserves Conan v2 protocol: `_` is the
    // sentinel for "no user / no channel", `0.0.0` is the fallback version).
    let results: Vec<String> = rows
        .iter()
        .map(|r| {
            let version = r
                .meta_version
                .as_deref()
                .or(r.version.as_deref())
                .unwrap_or("0.0.0");
            let user = r.meta_user.as_deref().unwrap_or("_");
            let channel = r.meta_channel.as_deref().unwrap_or("_");
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
// GET  .../revisions/{rev}/files — List recipe files
// ---------------------------------------------------------------------------

async fn recipe_files_list(
    State(state): State<SharedState>,
    Path((repo_key, name, version, user, channel, revision)): Path<(
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
        SELECT am.metadata->>'file' as "file?"
        FROM artifacts a
        JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND am.format = 'conan'
          AND am.metadata->>'type' = 'recipe'
          AND a.name = $2
          AND a.version = $3
          AND am.metadata->>'user' = $4
          AND am.metadata->>'channel' = $5
          AND am.metadata->>'revision' = $6
        "#,
        repo.id,
        name,
        version,
        normalize_user(&user),
        normalize_channel(&channel),
        revision,
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

    let filenames: Vec<String> = rows.into_iter().filter_map(|r| r.file).collect();
    Ok(files_listing_response(filenames))
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "File not found").into_response());

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == RepositoryType::Remote {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let upstream_path = format!(
                        "v2/conans/{}/{}/{}/{}/revisions/{}/files/{}",
                        name,
                        version,
                        user,
                        channel,
                        revision,
                        file_path.trim_start_matches('/')
                    );
                    let (content, content_type) = proxy_helpers::proxy_fetch(
                        proxy,
                        repo.id,
                        &repo_key,
                        upstream_url,
                        &upstream_path,
                    )
                    .await?;
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(
                            "Content-Type",
                            content_type.unwrap_or_else(|| "application/octet-stream".to_string()),
                        )
                        .body(Body::from(content))
                        .unwrap());
                }
            }
            // Virtual repo: try each member in priority order
            if repo.repo_type == RepositoryType::Virtual {
                let db = state.db.clone();
                let upstream_path = format!(
                    "v2/conans/{}/{}/{}/{}/revisions/{}/files/{}",
                    name,
                    version,
                    user,
                    channel,
                    revision,
                    file_path.trim_start_matches('/')
                );
                let vpath = artifact_path.clone();
                let (content, content_type) = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    state.proxy_service.as_deref(),
                    repo.id,
                    &upstream_path,
                    |member_id, location| {
                        let db = db.clone();
                        let state = state.clone();
                        let vpath = vpath.clone();
                        async move {
                            proxy_helpers::local_fetch_by_path(
                                &db, &state, member_id, &location, &vpath,
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
                        content_type.unwrap_or_else(|| "application/octet-stream".to_string()),
                    )
                    .header(CONTENT_LENGTH, content.len().to_string())
                    .body(Body::from(content))
                    .unwrap());
            }
            return Err(not_found);
        }
    };

    // Read from storage
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    // Check quarantine status before serving
    crate::services::quarantine_service::check_artifact_download(&state.db, artifact.id)
        .await
        .map_err(|e| e.into_response())?;

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
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, name, version, user, channel, revision, file_path)): Path<(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    )>,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = require_auth_basic(auth, "conan")?.user_id;
    let repo = resolve_conan_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

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

    // Clean up soft-deleted rows (including the one just soft-deleted above)
    // so the UNIQUE(repository_id, path) constraint won't block the INSERT.
    super::cleanup_soft_deleted_artifact(&state.db, repo.id, &artifact_path).await;

    // Store the file
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
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
// GET  .../packages/{pkg_id}/revisions/{pkg_rev}/files — List package files
// ---------------------------------------------------------------------------

#[allow(clippy::type_complexity)]
async fn package_files_list(
    State(state): State<SharedState>,
    Path((repo_key, name, version, user, channel, revision, package_id, pkg_revision)): Path<(
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

    let rows = sqlx::query!(
        r#"
        SELECT am.metadata->>'file' as "file?"
        FROM artifacts a
        JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND am.format = 'conan'
          AND am.metadata->>'type' = 'package'
          AND a.name = $2
          AND a.version = $3
          AND am.metadata->>'user' = $4
          AND am.metadata->>'channel' = $5
          AND am.metadata->>'revision' = $6
          AND am.metadata->>'packageId' = $7
          AND am.metadata->>'packageRevision' = $8
        "#,
        repo.id,
        name,
        version,
        normalize_user(&user),
        normalize_channel(&channel),
        revision,
        package_id,
        pkg_revision,
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

    let filenames: Vec<String> = rows.into_iter().filter_map(|r| r.file).collect();
    Ok(files_listing_response(filenames))
}

/// Build the Conan v2 files-listing JSON body. The protocol shape is
/// `{"files": {"filename.ext": {}, ...}}` — see
/// `conan/internal/rest/rest_client_v2.py::_get_file_list_json`. Returns an
/// empty `files` object when no artifacts match, matching what Conan expects
/// for a recipe/package revision that has zero files.
fn build_files_listing_json(filenames: Vec<String>) -> serde_json::Value {
    let mut files = serde_json::Map::new();
    for name in filenames {
        files.insert(name, serde_json::json!({}));
    }
    serde_json::json!({ "files": files })
}

fn files_listing_response(filenames: Vec<String>) -> Response {
    let body = build_files_listing_json(filenames);
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap()
}

// ---------------------------------------------------------------------------
// GET  .../packages/{pkg_id}/revisions/{pkg_rev}/files/{path} — Download package file
// ---------------------------------------------------------------------------

#[allow(clippy::type_complexity)]
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "File not found").into_response());

    let artifact =
        match artifact {
            Ok(a) => a,
            Err(not_found) => {
                if repo.repo_type == RepositoryType::Remote {
                    if let (Some(ref upstream_url), Some(ref proxy)) =
                        (&repo.upstream_url, &state.proxy_service)
                    {
                        let upstream_path =
                            format!(
                        "v2/conans/{}/{}/{}/{}/revisions/{}/packages/{}/revisions/{}/files/{}",
                        name, version, user, channel, revision, package_id, pkg_revision,
                        file_path.trim_start_matches('/')
                    );
                        let (content, content_type) = proxy_helpers::proxy_fetch(
                            proxy,
                            repo.id,
                            &repo_key,
                            upstream_url,
                            &upstream_path,
                        )
                        .await?;
                        return Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header(
                                "Content-Type",
                                content_type
                                    .unwrap_or_else(|| "application/octet-stream".to_string()),
                            )
                            .body(Body::from(content))
                            .unwrap());
                    }
                }
                // Virtual repo: try each member in priority order
                if repo.repo_type == RepositoryType::Virtual {
                    let db = state.db.clone();
                    let upstream_path = format!(
                        "v2/conans/{}/{}/{}/{}/revisions/{}/packages/{}/revisions/{}/files/{}",
                        name,
                        version,
                        user,
                        channel,
                        revision,
                        package_id,
                        pkg_revision,
                        file_path.trim_start_matches('/')
                    );
                    let vpath = artifact_path.clone();
                    let (content, content_type) = proxy_helpers::resolve_virtual_download(
                        &state.db,
                        state.proxy_service.as_deref(),
                        repo.id,
                        &upstream_path,
                        |member_id, location| {
                            let db = db.clone();
                            let state = state.clone();
                            let vpath = vpath.clone();
                            async move {
                                proxy_helpers::local_fetch_by_path(
                                    &db, &state, member_id, &location, &vpath,
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
                            content_type.unwrap_or_else(|| "application/octet-stream".to_string()),
                        )
                        .header(CONTENT_LENGTH, content.len().to_string())
                        .body(Body::from(content))
                        .unwrap());
                }
                return Err(not_found);
            }
        };

    // Read from storage
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    // Check quarantine status before serving
    crate::services::quarantine_service::check_artifact_download(&state.db, artifact.id)
        .await
        .map_err(|e| e.into_response())?;

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

#[allow(clippy::type_complexity)]
async fn package_file_upload(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
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
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = require_auth_basic(auth, "conan")?.user_id;
    let repo = resolve_conan_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

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

    // Clean up soft-deleted rows (including the one just soft-deleted above)
    // so the UNIQUE(repository_id, path) constraint won't block the INSERT.
    super::cleanup_soft_deleted_artifact(&state.db, repo.id, &artifact_path).await;

    // Store the file
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ping_returns_revisions_capability() {
        let response = ping().await;
        assert_eq!(response.status(), StatusCode::OK);
        let capabilities = response
            .headers()
            .get("x-conan-server-capabilities")
            .expect("x-conan-server-capabilities header must be present")
            .to_str()
            .expect("header value must be ASCII");
        assert!(
            capabilities.contains("revisions"),
            "capability header must advertise 'revisions', got: {capabilities}"
        );
    }

    #[test]
    fn build_files_listing_json_empty() {
        let json = build_files_listing_json(Vec::new());
        assert_eq!(json, serde_json::json!({ "files": {} }));
    }

    #[test]
    fn build_files_listing_json_with_filenames() {
        let json = build_files_listing_json(vec![
            "conanfile.py".to_string(),
            "conanmanifest.txt".to_string(),
            "conan_export.tgz".to_string(),
        ]);
        let files = json
            .get("files")
            .and_then(|v| v.as_object())
            .expect("response must have a 'files' object");
        assert_eq!(files.len(), 3);
        for name in ["conanfile.py", "conanmanifest.txt", "conan_export.tgz"] {
            assert_eq!(
                files.get(name),
                Some(&serde_json::json!({})),
                "missing or wrong value for {name}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Extracted pure functions (moved into test module)
    // -----------------------------------------------------------------------

    /// Convert a Conan glob pattern to a SQL LIKE pattern.
    fn conan_glob_to_like(pattern: &str) -> String {
        pattern.replace('*', "%")
    }

    /// Build a Conan reference string: "name/version@user/channel".
    fn build_conan_reference(name: &str, version: &str) -> String {
        format!("{}/{}@_/_", name, version)
    }

    /// Build recipe metadata JSON.
    fn build_recipe_metadata(
        name: &str,
        version: &str,
        user: &str,
        channel: &str,
        revision: &str,
        file_path: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "version": version,
            "user": normalize_user(user),
            "channel": normalize_channel(channel),
            "revision": revision,
            "type": "recipe",
            "file": file_path.trim_start_matches('/'),
        })
    }

    /// Build package metadata JSON.
    #[allow(clippy::too_many_arguments)]
    fn build_package_metadata(
        name: &str,
        version: &str,
        user: &str,
        channel: &str,
        revision: &str,
        package_id: &str,
        pkg_revision: &str,
        file_path: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "version": version,
            "user": normalize_user(user),
            "channel": normalize_channel(channel),
            "revision": revision,
            "packageId": package_id,
            "packageRevision": pkg_revision,
            "type": "package",
            "file": file_path.trim_start_matches('/'),
        })
    }

    /// Build the upstream path for proxying a recipe file.
    fn build_recipe_upstream_path(
        name: &str,
        version: &str,
        user: &str,
        channel: &str,
        revision: &str,
        file_path: &str,
    ) -> String {
        format!(
            "v2/conans/{}/{}/{}/{}/revisions/{}/files/{}",
            name,
            version,
            user,
            channel,
            revision,
            file_path.trim_start_matches('/')
        )
    }

    /// Build the upstream path for proxying a package file.
    #[allow(clippy::too_many_arguments)]
    fn build_package_upstream_path(
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
            "v2/conans/{}/{}/{}/{}/revisions/{}/packages/{}/revisions/{}/files/{}",
            name,
            version,
            user,
            channel,
            revision,
            package_id,
            pkg_revision,
            file_path.trim_start_matches('/')
        )
    }

    // -----------------------------------------------------------------------
    // normalize_user
    // -----------------------------------------------------------------------

    #[test]
    fn test_normalize_user_underscore() {
        assert_eq!(normalize_user("_"), "_");
    }

    #[test]
    fn test_normalize_user_custom() {
        assert_eq!(normalize_user("myuser"), "myuser");
    }

    #[test]
    fn test_normalize_user_empty() {
        assert_eq!(normalize_user(""), "");
    }

    // -----------------------------------------------------------------------
    // normalize_channel
    // -----------------------------------------------------------------------

    #[test]
    fn test_normalize_channel_underscore() {
        assert_eq!(normalize_channel("_"), "_");
    }

    #[test]
    fn test_normalize_channel_custom() {
        assert_eq!(normalize_channel("stable"), "stable");
    }

    #[test]
    fn test_normalize_channel_empty() {
        assert_eq!(normalize_channel(""), "");
    }

    // -----------------------------------------------------------------------
    // recipe_storage_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_recipe_storage_key_basic() {
        let key = recipe_storage_key("zlib", "1.2.13", "_", "_", "abc123", "conanfile.py");
        assert_eq!(key, "conan/zlib/1.2.13/_/_/recipe/abc123/conanfile.py");
    }

    #[test]
    fn test_recipe_storage_key_with_user_and_channel() {
        let key = recipe_storage_key(
            "boost",
            "1.80.0",
            "myuser",
            "stable",
            "def456",
            "conanmanifest.txt",
        );
        assert_eq!(
            key,
            "conan/boost/1.80.0/myuser/stable/recipe/def456/conanmanifest.txt"
        );
    }

    #[test]
    fn test_recipe_storage_key_leading_slash_in_path() {
        let key = recipe_storage_key("zlib", "1.0", "_", "_", "rev1", "/conanfile.py");
        assert_eq!(key, "conan/zlib/1.0/_/_/recipe/rev1/conanfile.py");
    }

    // -----------------------------------------------------------------------
    // package_storage_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_package_storage_key_basic() {
        let key = package_storage_key(
            "zlib",
            "1.2.13",
            "_",
            "_",
            "abc123",
            "pkg-id-1",
            "pkg-rev-1",
            "conan_package.tgz",
        );
        assert_eq!(
            key,
            "conan/zlib/1.2.13/_/_/package/abc123/pkg-id-1/pkg-rev-1/conan_package.tgz"
        );
    }

    #[test]
    fn test_package_storage_key_leading_slash() {
        let key = package_storage_key(
            "zlib",
            "1.0",
            "_",
            "_",
            "rev1",
            "pkgid",
            "pkgrev",
            "/conan_package.tgz",
        );
        assert_eq!(
            key,
            "conan/zlib/1.0/_/_/package/rev1/pkgid/pkgrev/conan_package.tgz"
        );
    }

    // -----------------------------------------------------------------------
    // recipe_artifact_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_recipe_artifact_path_basic() {
        let path = recipe_artifact_path("zlib", "1.2.13", "_", "_", "abc123", "conanfile.py");
        assert_eq!(path, "zlib/1.2.13/_/_/revisions/abc123/files/conanfile.py");
    }

    #[test]
    fn test_recipe_artifact_path_with_user() {
        let path =
            recipe_artifact_path("boost", "1.80", "myuser", "stable", "rev1", "conanfile.py");
        assert_eq!(
            path,
            "boost/1.80/myuser/stable/revisions/rev1/files/conanfile.py"
        );
    }

    #[test]
    fn test_recipe_artifact_path_strips_leading_slash() {
        let path = recipe_artifact_path("zlib", "1.0", "_", "_", "rev1", "/conanfile.py");
        assert_eq!(path, "zlib/1.0/_/_/revisions/rev1/files/conanfile.py");
    }

    // -----------------------------------------------------------------------
    // package_artifact_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_package_artifact_path_basic() {
        let path = package_artifact_path(
            "zlib",
            "1.2.13",
            "_",
            "_",
            "rev1",
            "pkgid",
            "pkgrev",
            "conan_package.tgz",
        );
        assert_eq!(
            path,
            "zlib/1.2.13/_/_/revisions/rev1/packages/pkgid/revisions/pkgrev/files/conan_package.tgz"
        );
    }

    #[test]
    fn test_package_artifact_path_strips_leading_slash() {
        let path = package_artifact_path(
            "zlib",
            "1.0",
            "_",
            "_",
            "rev1",
            "pkgid",
            "pkgrev",
            "/file.tgz",
        );
        assert_eq!(
            path,
            "zlib/1.0/_/_/revisions/rev1/packages/pkgid/revisions/pkgrev/files/file.tgz"
        );
    }

    // -----------------------------------------------------------------------
    // content_type_for_conan_file
    // -----------------------------------------------------------------------

    #[test]
    fn test_content_type_for_conan_file_python() {
        assert_eq!(content_type_for_conan_file("conanfile.py"), "text/plain");
    }

    #[test]
    fn test_content_type_for_conan_file_txt() {
        assert_eq!(
            content_type_for_conan_file("conanmanifest.txt"),
            "text/plain"
        );
    }

    #[test]
    fn test_content_type_for_conan_file_tgz() {
        assert_eq!(
            content_type_for_conan_file("conan_package.tgz"),
            "application/gzip"
        );
    }

    #[test]
    fn test_content_type_for_conan_file_tar_gz() {
        assert_eq!(
            content_type_for_conan_file("conan_sources.tar.gz"),
            "application/gzip"
        );
    }

    #[test]
    fn test_content_type_for_conan_file_other() {
        assert_eq!(
            content_type_for_conan_file("conaninfo"),
            "application/octet-stream"
        );
    }

    #[test]
    fn test_content_type_for_conan_file_no_extension() {
        assert_eq!(
            content_type_for_conan_file("somefile"),
            "application/octet-stream"
        );
    }

    // -----------------------------------------------------------------------
    // SearchQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_query_with_q() {
        let json = r#"{"q": "zlib*"}"#;
        let q: SearchQuery = serde_json::from_str(json).unwrap();
        assert_eq!(q.q, Some("zlib*".to_string()));
    }

    #[test]
    fn test_search_query_empty() {
        let json = r#"{}"#;
        let q: SearchQuery = serde_json::from_str(json).unwrap();
        assert!(q.q.is_none());
    }

    // -----------------------------------------------------------------------
    // conan_glob_to_like
    // -----------------------------------------------------------------------

    #[test]
    fn test_conan_glob_to_like_wildcard() {
        assert_eq!(conan_glob_to_like("zlib*"), "zlib%");
    }

    #[test]
    fn test_conan_glob_to_like_all() {
        assert_eq!(conan_glob_to_like("*"), "%");
    }

    #[test]
    fn test_conan_glob_to_like_no_wildcard() {
        assert_eq!(conan_glob_to_like("exact"), "exact");
    }

    #[test]
    fn test_conan_glob_to_like_multiple_wildcards() {
        assert_eq!(conan_glob_to_like("*lib*"), "%lib%");
    }

    #[test]
    fn test_conan_glob_to_like_empty() {
        assert_eq!(conan_glob_to_like(""), "");
    }

    // -----------------------------------------------------------------------
    // build_conan_reference
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_conan_reference_basic() {
        assert_eq!(build_conan_reference("zlib", "1.2.13"), "zlib/1.2.13@_/_");
    }

    #[test]
    fn test_build_conan_reference_boost() {
        assert_eq!(build_conan_reference("boost", "1.80.0"), "boost/1.80.0@_/_");
    }

    #[test]
    fn test_build_conan_reference_empty_version() {
        assert_eq!(build_conan_reference("pkg", ""), "pkg/@_/_");
    }

    // -----------------------------------------------------------------------
    // build_recipe_metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_recipe_metadata_basic() {
        let meta = build_recipe_metadata("zlib", "1.2.13", "_", "_", "rev1", "conanfile.py");
        assert_eq!(meta["name"], "zlib");
        assert_eq!(meta["version"], "1.2.13");
        assert_eq!(meta["user"], "_");
        assert_eq!(meta["channel"], "_");
        assert_eq!(meta["revision"], "rev1");
        assert_eq!(meta["type"], "recipe");
        assert_eq!(meta["file"], "conanfile.py");
    }

    #[test]
    fn test_build_recipe_metadata_strips_slash() {
        let meta = build_recipe_metadata("zlib", "1.0", "_", "_", "r", "/conanfile.py");
        assert_eq!(meta["file"], "conanfile.py");
    }

    #[test]
    fn test_build_recipe_metadata_custom_user_channel() {
        let meta = build_recipe_metadata("boost", "1.80", "myuser", "stable", "r1", "file.txt");
        assert_eq!(meta["user"], "myuser");
        assert_eq!(meta["channel"], "stable");
    }

    // -----------------------------------------------------------------------
    // build_package_metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_package_metadata_basic() {
        let meta = build_package_metadata(
            "zlib",
            "1.2.13",
            "_",
            "_",
            "rev1",
            "pkgid",
            "pkgrev",
            "conan_package.tgz",
        );
        assert_eq!(meta["name"], "zlib");
        assert_eq!(meta["type"], "package");
        assert_eq!(meta["packageId"], "pkgid");
        assert_eq!(meta["packageRevision"], "pkgrev");
        assert_eq!(meta["file"], "conan_package.tgz");
    }

    #[test]
    fn test_build_package_metadata_strips_slash() {
        let meta = build_package_metadata("z", "1.0", "_", "_", "r", "p", "pr", "/file.tgz");
        assert_eq!(meta["file"], "file.tgz");
    }

    #[test]
    fn test_build_package_metadata_all_fields_present() {
        let meta = build_package_metadata("n", "v", "u", "c", "r", "pi", "pr", "f");
        assert!(meta.get("name").is_some());
        assert!(meta.get("version").is_some());
        assert!(meta.get("user").is_some());
        assert!(meta.get("channel").is_some());
        assert!(meta.get("revision").is_some());
        assert!(meta.get("packageId").is_some());
        assert!(meta.get("packageRevision").is_some());
        assert!(meta.get("type").is_some());
        assert!(meta.get("file").is_some());
    }

    // -----------------------------------------------------------------------
    // build_recipe_upstream_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_recipe_upstream_path_basic() {
        let path = build_recipe_upstream_path("zlib", "1.2.13", "_", "_", "rev1", "conanfile.py");
        assert_eq!(
            path,
            "v2/conans/zlib/1.2.13/_/_/revisions/rev1/files/conanfile.py"
        );
    }

    #[test]
    fn test_build_recipe_upstream_path_strips_slash() {
        let path = build_recipe_upstream_path("z", "1.0", "_", "_", "r", "/file.py");
        assert_eq!(path, "v2/conans/z/1.0/_/_/revisions/r/files/file.py");
    }

    #[test]
    fn test_build_recipe_upstream_path_custom_user() {
        let path =
            build_recipe_upstream_path("boost", "1.80", "user", "stable", "r1", "manifest.txt");
        assert_eq!(
            path,
            "v2/conans/boost/1.80/user/stable/revisions/r1/files/manifest.txt"
        );
    }

    // -----------------------------------------------------------------------
    // build_package_upstream_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_package_upstream_path_basic() {
        let path = build_package_upstream_path(
            "zlib",
            "1.2.13",
            "_",
            "_",
            "rev1",
            "pkgid",
            "pkgrev",
            "conan_package.tgz",
        );
        assert_eq!(
            path,
            "v2/conans/zlib/1.2.13/_/_/revisions/rev1/packages/pkgid/revisions/pkgrev/files/conan_package.tgz"
        );
    }

    #[test]
    fn test_build_package_upstream_path_strips_slash() {
        let path = build_package_upstream_path("z", "1.0", "_", "_", "r", "p", "pr", "/f.tgz");
        assert!(path.ends_with("/f.tgz"));
        assert!(!path.ends_with("//f.tgz"));
    }

    #[test]
    fn test_build_package_upstream_path_custom_user_channel() {
        let path = build_package_upstream_path(
            "boost", "1.80", "myuser", "stable", "r1", "pid", "prev", "file",
        );
        assert!(path.contains("/myuser/stable/"));
    }

    // -----------------------------------------------------------------------
    // test_helpers — shared scaffolding for DB-backed handler tests.
    //
    // Phase 1 agents build on this: they add `mod agent{N}_<area>` submodules
    // inside `mod tests` and call `super::test_helpers::*` from them. All
    // DB-backed tests must start with
    //
    //     let Some(pool) = test_helpers::try_pool().await else { return; };
    //
    // so they skip cleanly when `DATABASE_URL` is unset or unreachable.
    //
    // AuthExtension injection (resolved R2):
    //   Handlers extract `Extension<Option<AuthExtension>>`. In axum 0.7
    //   `Extension<T>` looks up exactly `T` in request extensions, so we
    //   insert `Option<AuthExtension>` (wrapped in `Some`) via
    //   `.layer(Extension(Some(auth)))`. See `router_with_auth` below.
    // -----------------------------------------------------------------------

    #[allow(dead_code)]
    pub(super) mod test_helpers {
        use std::path::PathBuf;
        use std::sync::Arc;

        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use axum::{Extension, Router};
        use bytes::Bytes;
        use sqlx::PgPool;
        use tower::ServiceExt;
        use uuid::Uuid;

        use crate::api::middleware::auth::AuthExtension;
        use crate::api::{AppState, SharedState};
        use crate::config::Config;

        // ------------------------------------------------------------------
        // Pool acquisition
        // ------------------------------------------------------------------

        /// Connect to the test database. Returns `None` if `DATABASE_URL` is
        /// unset or the pool cannot be established (e.g. Postgres is not
        /// running). All DB-backed tests start with
        /// `let Some(pool) = try_pool().await else { return; };` so the suite
        /// is a no-op in environments without Postgres.
        pub async fn try_pool() -> Option<PgPool> {
            let url = std::env::var("DATABASE_URL").ok()?;
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(5)
                .acquire_timeout(std::time::Duration::from_secs(3))
                .connect(&url)
                .await
                .ok()
        }

        // ------------------------------------------------------------------
        // Config + SharedState construction
        // ------------------------------------------------------------------

        fn test_config(storage_path: &str) -> Config {
            Config {
                database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
                bind_address: "127.0.0.1:0".into(),
                log_level: "error".into(),
                storage_backend: "filesystem".into(),
                storage_path: storage_path.into(),
                s3_bucket: None,
                gcs_bucket: None,
                s3_region: None,
                s3_endpoint: None,
                jwt_secret: "test-secret-at-least-32-bytes-long-for-testing".into(),
                jwt_expiration_secs: 86400,
                jwt_access_token_expiry_minutes: 30,
                jwt_refresh_token_expiry_days: 7,
                oidc_issuer: None,
                oidc_client_id: None,
                oidc_client_secret: None,
                ldap_url: None,
                ldap_base_dn: None,
                trivy_url: None,
                openscap_url: None,
                openscap_profile: "standard".into(),
                meilisearch_url: None,
                meilisearch_api_key: None,
                scan_workspace_path: "/tmp/scan".into(),
                demo_mode: false,
                peer_instance_name: "test".into(),
                peer_public_endpoint: "http://localhost:8080".into(),
                peer_api_key: "test-key".into(),
                dependency_track_url: None,
                otel_exporter_otlp_endpoint: None,
                otel_service_name: "test".into(),
                gc_schedule: "0 0 * * * *".into(),
                lifecycle_check_interval_secs: 60,
                allow_local_admin_login: false,
                max_upload_size_bytes: 10_737_418_240,
                metrics_port: None,
                database_max_connections: 20,
                database_min_connections: 5,
                database_acquire_timeout_secs: 30,
                database_idle_timeout_secs: 600,
                database_max_lifetime_secs: 1800,
                rate_limit_auth_per_window: 120,
                rate_limit_api_per_window: 5000,
                rate_limit_window_secs: 60,
                rate_limit_exempt_usernames: Vec::new(),
                rate_limit_exempt_service_accounts: false,
                account_lockout_threshold: 5,
                account_lockout_duration_minutes: 30,
                quarantine_enabled: false,
                quarantine_duration_minutes: 60,
                password_history_count: 0,
                password_expiry_days: 0,
                password_expiry_warning_days: vec![14, 7, 1],
                password_expiry_check_interval_secs: 3600,
                password_min_length: 8,
                password_max_length: 128,
                password_require_uppercase: false,
                password_require_lowercase: false,
                password_require_digit: false,
                password_require_special: false,
                password_min_strength: 0,
                presigned_downloads_enabled: false,
                presigned_download_expiry_secs: 300,
                smtp_host: None,
                smtp_port: 587,
                smtp_username: None,
                smtp_password: None,
                smtp_from_address: "noreply@artifact-keeper.local".to_string(),
                smtp_tls_mode: "starttls".to_string(),
            }
        }

        /// Build a `SharedState` backed by `FilesystemStorage` rooted at
        /// `storage_path`. Pattern mirrored from
        /// `backend/tests/incus_upload_tests.rs::build_state`.
        pub fn build_state(pool: PgPool, storage_path: &str) -> SharedState {
            let storage: Arc<dyn crate::storage::StorageBackend> = Arc::new(
                crate::storage::filesystem::FilesystemStorage::new(storage_path),
            );
            let registry = Arc::new(crate::storage::StorageRegistry::new(
                std::collections::HashMap::new(),
                "filesystem".to_string(),
            ));
            Arc::new(AppState::new(
                test_config(storage_path),
                pool,
                storage,
                registry,
            ))
        }

        // ------------------------------------------------------------------
        // DB fixture helpers
        // ------------------------------------------------------------------

        /// Insert a test user with a bcrypt-hashed password (cost=4 for speed).
        /// Returns `(user_id, username, password)`. Username is UUID-suffixed
        /// so parallel tests on the same DB do not collide.
        pub async fn create_user(pool: &PgPool) -> (Uuid, String, String) {
            let id = Uuid::new_v4();
            let username = format!("conan-test-u-{}", id);
            let password = "conan-test-pw".to_string();
            let hash = bcrypt::hash(&password, 4).expect("bcrypt hash failed");
            sqlx::query(
                r#"
                INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, is_active)
                VALUES ($1, $2, $3, $4, 'local', false, true)
                "#,
            )
            .bind(id)
            .bind(&username)
            .bind(format!("{}@test.local", username))
            .bind(&hash)
            .execute(pool)
            .await
            .expect("failed to create test user");
            (id, username, password)
        }

        /// Insert a test Conan repository. Returns `(repo_id, repo_key, storage_dir)`.
        /// `repo_type` is `"local"` | `"remote"` | `"virtual"`. The repo key is
        /// UUID-suffixed so parallel tests on the same DB do not collide.
        pub async fn create_conan_repo(pool: &PgPool, repo_type: &str) -> (Uuid, String, PathBuf) {
            let id = Uuid::new_v4();
            let key = format!("conan-test-{}", id);
            let storage_dir = std::env::temp_dir().join(format!("conan-test-{}", id));
            std::fs::create_dir_all(&storage_dir).expect("create storage dir");

            // Remote repos require a non-null upstream_url (check constraint).
            let upstream_url: Option<&str> = if repo_type == "remote" {
                Some("https://center.conan.io")
            } else {
                None
            };

            let sql = format!(
                "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, upstream_url) \
                 VALUES ($1, $2, $3, $4, '{}'::repository_type, 'conan'::repository_format, $5)",
                repo_type
            );
            sqlx::query(&sql)
                .bind(id)
                .bind(&key)
                .bind(format!("conan-test-{}", id))
                .bind(storage_dir.to_string_lossy().as_ref())
                .bind(upstream_url)
                .execute(pool)
                .await
                .expect("failed to create test conan repo");

            (id, key, storage_dir)
        }

        // ------------------------------------------------------------------
        // AuthExtension + Router construction
        // ------------------------------------------------------------------

        /// Construct a non-admin, non-API-token `AuthExtension` suitable for
        /// injection via a bare `Extension` layer. See the module-level R2
        /// note on injection semantics.
        pub fn make_auth(user_id: Uuid, username: &str) -> AuthExtension {
            AuthExtension {
                user_id,
                username: username.to_string(),
                email: format!("{}@test.local", username),
                is_admin: false,
                is_api_token: false,
                is_service_account: false,
                scopes: None,
                allowed_repo_ids: None,
            }
        }

        /// Build the conan router + state with an `Option<AuthExtension>`
        /// pre-injected, bypassing real Basic auth middleware.
        ///
        /// Winning injection pattern (axum 0.7): `Extension<Option<T>>` looks
        /// up exactly `Option<T>` in request extensions, so we insert
        /// `Some(auth)` here — not a bare `AuthExtension`. Inserting the bare
        /// value would leave the handler's `Option<AuthExtension>` lookup
        /// empty and `require_auth_basic` would return 401.
        pub fn router_with_auth(state: SharedState, auth: AuthExtension) -> Router {
            super::router()
                .with_state(state)
                .layer(Extension::<Option<AuthExtension>>(Some(auth)))
        }

        /// Build the conan router + state with NO auth injected. Used for
        /// 401 negative-path tests where we want the handler's
        /// `require_auth_basic(None, ...)` to fire.
        pub fn router_anon(state: SharedState) -> Router {
            // Insert an explicit `Option<AuthExtension>::None` so the handler's
            // `Extension<Option<AuthExtension>>` extractor succeeds with `None`
            // rather than failing the extraction entirely.
            super::router()
                .with_state(state)
                .layer(Extension::<Option<AuthExtension>>(None))
        }

        // ------------------------------------------------------------------
        // HTTP sugar
        // ------------------------------------------------------------------

        /// Build a `"Basic <base64(user:pass)>"` header value.
        pub fn basic_auth(user: &str, pass: &str) -> String {
            use base64::Engine;
            let encoded =
                base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", user, pass));
            format!("Basic {}", encoded)
        }

        /// Dispatch a request through the router and collect the full body.
        pub async fn send(app: Router, req: Request<Body>) -> (StatusCode, Bytes) {
            let resp = app.oneshot(req).await.expect("router oneshot failed");
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 16 * 1024 * 1024)
                .await
                .expect("collect body");
            (status, body)
        }

        // ------------------------------------------------------------------
        // Composite upload helpers (used 3+ times across Phase 1 agents)
        // ------------------------------------------------------------------

        /// PUT a recipe file through the router and return the status code.
        #[allow(clippy::too_many_arguments)]
        pub async fn upload_recipe_file(
            state: &SharedState,
            auth: &AuthExtension,
            repo_key: &str,
            name: &str,
            version: &str,
            user: &str,
            channel: &str,
            revision: &str,
            file_name: &str,
            body: &[u8],
        ) -> StatusCode {
            let app = router_with_auth(state.clone(), auth.clone());
            let uri = format!(
                "/{}/v2/conans/{}/{}/{}/{}/revisions/{}/files/{}",
                repo_key, name, version, user, channel, revision, file_name
            );
            let req = Request::builder()
                .method("PUT")
                .uri(uri)
                .header("Authorization", basic_auth(&auth.username, "irrelevant"))
                .body(Body::from(body.to_vec()))
                .expect("build request");
            let (status, _body) = send(app, req).await;
            status
        }

        /// PUT a package file through the router and return the status code.
        #[allow(clippy::too_many_arguments)]
        pub async fn upload_package_file(
            state: &SharedState,
            auth: &AuthExtension,
            repo_key: &str,
            name: &str,
            version: &str,
            user: &str,
            channel: &str,
            revision: &str,
            package_id: &str,
            pkg_revision: &str,
            file_name: &str,
            body: &[u8],
        ) -> StatusCode {
            let app = router_with_auth(state.clone(), auth.clone());
            let uri = format!(
                "/{}/v2/conans/{}/{}/{}/{}/revisions/{}/packages/{}/revisions/{}/files/{}",
                repo_key,
                name,
                version,
                user,
                channel,
                revision,
                package_id,
                pkg_revision,
                file_name,
            );
            let req = Request::builder()
                .method("PUT")
                .uri(uri)
                .header("Authorization", basic_auth(&auth.username, "irrelevant"))
                .body(Body::from(body.to_vec()))
                .expect("build request");
            let (status, _body) = send(app, req).await;
            status
        }

        // ------------------------------------------------------------------
        // Direct DB seed helpers (bypass the upload handler)
        //
        // Used by tests that exercise read handlers without also exercising
        // the upload path. Mirrors the metadata JSON shape written by
        // `recipe_file_upload` and `package_file_upload`.
        // ------------------------------------------------------------------

        #[allow(clippy::too_many_arguments)]
        pub async fn seed_recipe_row(
            pool: &PgPool,
            repo_id: Uuid,
            name: &str,
            version: &str,
            user: &str,
            channel: &str,
            revision: &str,
            file_name: &str,
        ) -> Uuid {
            let artifact_id = Uuid::new_v4();
            let path = format!(
                "{}/{}/{}/{}/revisions/{}/files/{}",
                name,
                version,
                user,
                channel,
                revision,
                file_name.trim_start_matches('/'),
            );
            let storage_key = format!(
                "conan/{}/{}/{}/{}/recipe/{}/{}",
                name,
                version,
                user,
                channel,
                revision,
                file_name.trim_start_matches('/'),
            );
            // Distinct checksum per row so UNIQUE(repo_id, path) collisions
            // don't silently mask test errors.
            let checksum = format!("{:0>64}", artifact_id.simple().to_string());

            sqlx::query(
                r#"
                INSERT INTO artifacts (
                    id, repository_id, path, name, version, size_bytes,
                    checksum_sha256, content_type, storage_key
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                "#,
            )
            .bind(artifact_id)
            .bind(repo_id)
            .bind(&path)
            .bind(name)
            .bind(version)
            .bind(0i64)
            .bind(&checksum)
            .bind("text/plain")
            .bind(&storage_key)
            .execute(pool)
            .await
            .expect("seed artifact row");

            let metadata = serde_json::json!({
                "name": name,
                "version": version,
                "user": user,
                "channel": channel,
                "revision": revision,
                "type": "recipe",
                "file": file_name.trim_start_matches('/'),
            });

            sqlx::query(
                r#"
                INSERT INTO artifact_metadata (artifact_id, format, metadata)
                VALUES ($1, 'conan', $2)
                "#,
            )
            .bind(artifact_id)
            .bind(&metadata)
            .execute(pool)
            .await
            .expect("seed artifact metadata");

            artifact_id
        }

        #[allow(clippy::too_many_arguments)]
        pub async fn seed_package_row(
            pool: &PgPool,
            repo_id: Uuid,
            name: &str,
            version: &str,
            user: &str,
            channel: &str,
            revision: &str,
            package_id: &str,
            pkg_revision: &str,
            file_name: &str,
        ) -> Uuid {
            let artifact_id = Uuid::new_v4();
            let path = format!(
                "{}/{}/{}/{}/revisions/{}/packages/{}/revisions/{}/files/{}",
                name,
                version,
                user,
                channel,
                revision,
                package_id,
                pkg_revision,
                file_name.trim_start_matches('/'),
            );
            let storage_key = format!(
                "conan/{}/{}/{}/{}/package/{}/{}/{}/{}",
                name,
                version,
                user,
                channel,
                revision,
                package_id,
                pkg_revision,
                file_name.trim_start_matches('/'),
            );
            let checksum = format!("{:0>64}", artifact_id.simple().to_string());

            sqlx::query(
                r#"
                INSERT INTO artifacts (
                    id, repository_id, path, name, version, size_bytes,
                    checksum_sha256, content_type, storage_key
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                "#,
            )
            .bind(artifact_id)
            .bind(repo_id)
            .bind(&path)
            .bind(name)
            .bind(version)
            .bind(0i64)
            .bind(&checksum)
            .bind("application/gzip")
            .bind(&storage_key)
            .execute(pool)
            .await
            .expect("seed artifact row");

            let metadata = serde_json::json!({
                "name": name,
                "version": version,
                "user": user,
                "channel": channel,
                "revision": revision,
                "type": "package",
                "packageId": package_id,
                "packageRevision": pkg_revision,
                "file": file_name.trim_start_matches('/'),
            });

            sqlx::query(
                r#"
                INSERT INTO artifact_metadata (artifact_id, format, metadata)
                VALUES ($1, 'conan', $2)
                "#,
            )
            .bind(artifact_id)
            .bind(&metadata)
            .execute(pool)
            .await
            .expect("seed artifact metadata");

            artifact_id
        }

        // ------------------------------------------------------------------
        // Sample byte helpers (content is arbitrary; only SHA256 distinctness
        // matters for handler-level tests).
        // ------------------------------------------------------------------

        pub fn sample_conanfile_py() -> &'static [u8] {
            b"from conan import ConanFile\nclass T(ConanFile):\n    name='t'\n"
        }

        pub fn sample_conanmanifest_txt() -> &'static [u8] {
            b"1700000000\nconanfile.py: abcd\n"
        }

        pub fn sample_conaninfo_txt() -> &'static [u8] {
            b"[settings]\nos=Linux\narch=x86_64\n"
        }

        pub fn sample_conan_package_tgz() -> Vec<u8> {
            // Gzip magic + a handful of deterministic bytes. Content is
            // never decompressed by the handlers, so validity is irrelevant.
            let mut v = vec![0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
            v.extend_from_slice(b"conan-test-package-bytes");
            v
        }

        // ------------------------------------------------------------------
        // Cleanup
        // ------------------------------------------------------------------

        /// Delete all test rows in FK-order: artifact_metadata → artifacts →
        /// repositories → users.
        pub async fn cleanup(pool: &PgPool, repo_id: Uuid, user_id: Uuid) {
            let _ = sqlx::query(
                "DELETE FROM artifact_metadata WHERE artifact_id IN \
                 (SELECT id FROM artifacts WHERE repository_id = $1)",
            )
            .bind(repo_id)
            .execute(pool)
            .await;
            let _ = sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
                .bind(repo_id)
                .execute(pool)
                .await;
            let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
                .bind(repo_id)
                .execute(pool)
                .await;
            let _ = sqlx::query("DELETE FROM users WHERE id = $1")
                .bind(user_id)
                .execute(pool)
                .await;
        }
    }

    // -----------------------------------------------------------------------
    // Smoke test — proves the scaffolding works end-to-end.
    //
    // Seeds two recipe revisions at different created_at timestamps, calls
    // GET /<repo>/v2/conans/<name>/<ver>/_/_/revisions through the
    // router_with_auth + send pipeline, and asserts the JSON response
    // contains both revisions in DESC-by-created_at order.
    //
    // If this passes, Phase 1 agents can rely on the test_helpers module.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn smoke_scaffolding_works() {
        let Some(pool) = test_helpers::try_pool().await else {
            return;
        };

        let (user_id, username, _pw) = test_helpers::create_user(&pool).await;
        let (repo_id, repo_key, storage_dir) =
            test_helpers::create_conan_repo(&pool, "local").await;
        let state = test_helpers::build_state(pool.clone(), storage_dir.to_str().unwrap());
        let auth = test_helpers::make_auth(user_id, &username);

        // Seed rev_old first, then rev_new — DESC ordering must return
        // rev_new before rev_old.
        let _a1 = test_helpers::seed_recipe_row(
            &pool,
            repo_id,
            "smokelib",
            "1.0",
            "_",
            "_",
            "rev_old",
            "conanfile.py",
        )
        .await;
        // Ensure the second row lands with a strictly greater created_at.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let _a2 = test_helpers::seed_recipe_row(
            &pool,
            repo_id,
            "smokelib",
            "1.0",
            "_",
            "_",
            "rev_new",
            "conanfile.py",
        )
        .await;

        let app = test_helpers::router_with_auth(state.clone(), auth.clone());
        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/{}/v2/conans/smokelib/1.0/_/_/revisions",
                repo_key
            ))
            .header(
                "Authorization",
                test_helpers::basic_auth(&username, "irrelevant"),
            )
            .body(axum::body::Body::empty())
            .expect("build request");

        let (status, body) = test_helpers::send(app, req).await;
        let body_str = String::from_utf8_lossy(&body).to_string();
        assert_eq!(
            status,
            StatusCode::OK,
            "smoke test expected 200, got {}: {}",
            status,
            body_str,
        );

        let json: serde_json::Value = serde_json::from_slice(&body).expect("response must be JSON");
        let revisions = json
            .get("revisions")
            .and_then(|v| v.as_array())
            .expect("response must contain a 'revisions' array");
        assert_eq!(
            revisions.len(),
            2,
            "expected 2 revisions, got {}: {}",
            revisions.len(),
            body_str
        );
        assert_eq!(
            revisions[0].get("revision").and_then(|v| v.as_str()),
            Some("rev_new"),
            "expected DESC ordering (rev_new first), got: {}",
            body_str
        );
        assert_eq!(
            revisions[1].get("revision").and_then(|v| v.as_str()),
            Some("rev_old"),
            "expected DESC ordering (rev_old last), got: {}",
            body_str
        );

        // Cleanup
        test_helpers::cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);
    }
}
