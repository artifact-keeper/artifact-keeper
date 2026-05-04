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

use crate::api::handlers::error_helpers::{map_db_err, map_storage_err};
use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic, AuthExtension};
use crate::api::SharedState;
use crate::models::repository::RepositoryType;

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

/// Maximum byte length for any single Conan reference path segment
/// (`name`, `version`, `user`, `channel`, `revision`, `package_id`,
/// `pkg_revision`, `file_path`). This matches the typical filesystem
/// `NAME_MAX` limit (255) and keeps storage-backend operations from
/// surfacing low-level filesystem errors as 5xx responses.
const CONAN_MAX_SEGMENT_LEN: usize = 255;

/// Validate the byte length of every user-supplied Conan path segment.
///
/// Returns a 414 (URI Too Long) plain-text error response when any segment
/// exceeds [`CONAN_MAX_SEGMENT_LEN`]. The first offending segment is named
/// in the response body so abuse / fuzzing payloads do not look like server
/// faults in monitoring (issue #990).
#[allow(clippy::result_large_err)]
fn validate_conan_segments(segments: &[(&str, &str)]) -> Result<(), Response> {
    for (label, value) in segments {
        if value.len() > CONAN_MAX_SEGMENT_LEN {
            return Err((
                StatusCode::URI_TOO_LONG,
                format!(
                    "Conan path segment '{}' exceeds {} bytes (got {})",
                    label,
                    CONAN_MAX_SEGMENT_LEN,
                    value.len()
                ),
            )
                .into_response());
        }
    }
    Ok(())
}

/// Flatten the optional auth extension that the upload handlers receive.
///
/// Upload handlers accept `Option<Extension<Option<AuthExtension>>>` so that
/// requests routed to a non-existent repo (where the repo-visibility
/// middleware skips inserting the extension) still reach the handler — the
/// handler can then return 404 instead of a 500. See `recipe_file_upload`
/// for the full rationale (issue #990).
fn flatten_auth_extension(auth: Option<Extension<Option<AuthExtension>>>) -> Option<AuthExtension> {
    auth.and_then(|Extension(a)| a)
}

// ---------------------------------------------------------------------------
// GET /conan/{repo_key}/v2/ping
// ---------------------------------------------------------------------------

/// Ping / capability probe.
///
/// Validates the repository exists before returning the static capability
/// banner so Conan clients can distinguish a configured-but-broken remote
/// from a typo (issue #990). Returns 404 when the repository does not
/// exist or is not Conan-format.
async fn ping(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let _repo = resolve_conan_repo(&state.db, &repo_key).await?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("X-Conan-Server-Capabilities", "revisions")
        .body(Body::empty())
        .unwrap())
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
    .map_err(map_db_err)?;

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
        ORDER BY a.created_at DESC, a.id DESC
        LIMIT 1
        "#,
        repo.id,
        name,
        version,
    )
    .fetch_optional(&state.db)
    .await
    .map_err(map_db_err)?
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
        SELECT am.metadata->>'revision' as "revision?",
               MAX(a.created_at) as "created_at!"
        FROM artifacts a
        JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND am.format = 'conan'
          AND a.name = $2
          AND a.version = $3
          AND am.metadata->>'revision' IS NOT NULL
        GROUP BY am.metadata->>'revision'
        ORDER BY "created_at!" DESC
        "#,
        repo.id,
        name,
        version,
    )
    .fetch_all(&state.db)
    .await
    .map_err(map_db_err)?;

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
// GET  .../revisions/{rev}/files - List recipe files
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
    .map_err(map_db_err)?;

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
    .map_err(map_db_err)?
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
    let content = storage
        .get(&artifact.storage_key)
        .await
        .map_err(map_storage_err)?;

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
    auth: Option<Extension<Option<AuthExtension>>>,
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
    // Reject path segments that exceed the filesystem NAME_MAX before any
    // DB, auth, or storage-backend call, so deeply-nested or fuzzing-style
    // payloads surface as a 414 instead of a low-level 500 (issue #990).
    // Path-shape is independent of authn/authz so it is safe (and useful for
    // monitoring) to fail it first.
    validate_conan_segments(&[
        ("name", &name),
        ("version", &version),
        ("user", &user),
        ("channel", &channel),
        ("revision", &revision),
        ("file_path", &file_path),
    ])?;

    // Validate the repo BEFORE checking auth, so an upload to a non-existent
    // repo returns 404 instead of 500 (issue #990). See
    // `flatten_auth_extension` for why the extension is optional here.
    let repo = resolve_conan_repo(&state.db, &repo_key).await?;
    let user_id = require_auth_basic(flatten_auth_extension(auth), "conan")?.user_id;
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
    .map_err(map_db_err)?;

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
    storage
        .put(&storage_key, body.clone())
        .await
        .map_err(map_storage_err)?;

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
    .map_err(map_db_err)?;

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
        ORDER BY a.created_at DESC, a.id DESC
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
    .map_err(map_db_err)?
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
        SELECT am.metadata->>'packageRevision' as "pkg_revision?",
               MAX(a.created_at) as "created_at!"
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
        GROUP BY am.metadata->>'packageRevision'
        ORDER BY "created_at!" DESC
        "#,
        repo.id,
        name,
        version,
        revision,
        package_id,
    )
    .fetch_all(&state.db)
    .await
    .map_err(map_db_err)?;

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
// GET  .../packages/{pkg_id}/revisions/{pkg_rev}/files - List package files
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
    .map_err(map_db_err)?;

    let filenames: Vec<String> = rows.into_iter().filter_map(|r| r.file).collect();
    Ok(files_listing_response(filenames))
}

/// Build the Conan v2 files-listing JSON body. The protocol shape is
/// `{"files": {"filename.ext": {}, ...}}` -- see
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
    .map_err(map_db_err)?
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
    let content = storage
        .get(&artifact.storage_key)
        .await
        .map_err(map_storage_err)?;

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
    auth: Option<Extension<Option<AuthExtension>>>,
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
    // Reject excessively long path segments up front (before any DB, auth,
    // or storage-backend call) so the storage backend and DB never see paths
    // that would surface as opaque 5xx errors (issue #990).
    validate_conan_segments(&[
        ("name", &name),
        ("version", &version),
        ("user", &user),
        ("channel", &channel),
        ("revision", &revision),
        ("package_id", &package_id),
        ("pkg_revision", &pkg_revision),
        ("file_path", &file_path),
    ])?;

    // Resolve repo BEFORE auth so unknown repo keys surface as 404, not 500.
    // See `recipe_file_upload` for the full rationale (issue #990).
    let repo = resolve_conan_repo(&state.db, &repo_key).await?;
    let user_id = require_auth_basic(flatten_auth_extension(auth), "conan")?.user_id;
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

    // Check for duplicate -- allow overwrite within same revision
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        repo.id,
        artifact_path,
    )
    .fetch_optional(&state.db)
    .await
    .map_err(map_db_err)?;

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
    storage
        .put(&storage_key, body.clone())
        .await
        .map_err(map_storage_err)?;

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
    .map_err(map_db_err)?;

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
    // files_listing_response / build_files_listing_json
    // -----------------------------------------------------------------------

    #[test]
    fn files_listing_response_returns_200_json() {
        let resp = files_listing_response(vec!["conanfile.py".to_string()]);
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(ct, "application/json");
    }

    #[test]
    fn files_listing_response_empty_returns_200() {
        let resp = files_listing_response(Vec::new());
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn build_files_listing_json_preserves_order_independent_keys() {
        // Verify that duplicate filenames collapse to one entry (last wins
        // with serde_json::Map insert semantics).
        let json =
            build_files_listing_json(vec!["conanfile.py".to_string(), "conanfile.py".to_string()]);
        let files = json
            .get("files")
            .and_then(|v| v.as_object())
            .expect("files object");
        assert_eq!(
            files.len(),
            1,
            "duplicate filenames should collapse to one key"
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
    // validate_conan_segments — issue #990 long-path guard
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_conan_segments_accepts_normal_segments() {
        let segments = [
            ("name", "zlib"),
            ("version", "1.3.1"),
            ("user", "_"),
            ("channel", "_"),
            ("revision", "deadbeefcafebabedeadbeefcafebabe"),
            ("file_path", "conanfile.py"),
        ];
        assert!(validate_conan_segments(&segments).is_ok());
    }

    #[test]
    fn test_validate_conan_segments_accepts_segment_at_max() {
        let max_segment: String = "a".repeat(CONAN_MAX_SEGMENT_LEN);
        let segments = [("name", max_segment.as_str())];
        assert!(
            validate_conan_segments(&segments).is_ok(),
            "exactly {} bytes must be accepted",
            CONAN_MAX_SEGMENT_LEN
        );
    }

    #[test]
    fn test_validate_conan_segments_rejects_overlong_name() {
        // Mirrors test-conan-errors.sh #15: a 300-char package name.
        let long_name: String = "a".repeat(300);
        let segments = [
            ("name", long_name.as_str()),
            ("version", "1.0.0"),
            ("user", "_"),
            ("channel", "_"),
            ("revision", "rev"),
            ("file_path", "conanfile.py"),
        ];
        let resp = validate_conan_segments(&segments).expect_err("must reject 300-char name");
        assert_eq!(resp.status(), StatusCode::URI_TOO_LONG);
    }

    #[test]
    fn test_validate_conan_segments_rejects_overlong_version() {
        let long_version: String = "1.".repeat(200); // 400 chars
        let segments = [("name", "zlib"), ("version", long_version.as_str())];
        let resp = validate_conan_segments(&segments).expect_err("must reject 400-char version");
        assert_eq!(resp.status(), StatusCode::URI_TOO_LONG);
    }

    #[test]
    fn test_validate_conan_segments_rejects_overlong_file_path() {
        let long_path: String = "x".repeat(CONAN_MAX_SEGMENT_LEN + 1);
        let segments = [("file_path", long_path.as_str())];
        let resp = validate_conan_segments(&segments).expect_err("must reject overlong file_path");
        assert_eq!(resp.status(), StatusCode::URI_TOO_LONG);
    }

    // -----------------------------------------------------------------------
    // flatten_auth_extension — issue #990 Option-extension flattening
    // -----------------------------------------------------------------------

    fn make_auth_ext() -> AuthExtension {
        AuthExtension {
            user_id: uuid::Uuid::nil(),
            username: "tester".into(),
            email: "tester@test.local".into(),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: None,
        }
    }

    #[test]
    fn test_flatten_auth_extension_none_outer() {
        // No Extension at all — repo-visibility middleware did not run because
        // the repo does not exist. Must flatten to None so the upload handler
        // can return a 4xx (issue #990).
        assert!(flatten_auth_extension(None).is_none());
    }

    #[test]
    fn test_flatten_auth_extension_some_outer_none_inner() {
        // Extension was inserted but the request was unauthenticated.
        let inner: Option<AuthExtension> = None;
        assert!(flatten_auth_extension(Some(Extension(inner))).is_none());
    }

    #[test]
    fn test_flatten_auth_extension_some_outer_some_inner() {
        // Extension was inserted with an authenticated user.
        let ext = make_auth_ext();
        let username = ext.username.clone();
        let flat = flatten_auth_extension(Some(Extension(Some(ext))))
            .expect("Some(Extension(Some(_))) must flatten to Some");
        assert_eq!(flat.username, username);
    }

    // -----------------------------------------------------------------------
    // ping / *_file_upload — exercise non-DB code paths through the router so
    // that the new lines (validate-segments call sites, signature lines,
    // auth-flattening) are covered in --lib coverage runs (issue #990).
    //
    // These tests use `PgPool::connect_lazy` (the same pattern used by
    // events.rs / users.rs / auth_service.rs unit tests) so no PostgreSQL is
    // required. Requests that hit a DB query short-circuit with a 5xx, but
    // requests that fail the path-segment guard return 414 *before* any DB
    // call — exactly the shape we want to verify.
    // -----------------------------------------------------------------------

    fn unit_test_state() -> SharedState {
        use crate::api::AppState;
        use crate::config::Config;
        use crate::storage::filesystem::FilesystemStorage;
        use std::sync::Arc;

        let pool = sqlx::PgPool::connect_lazy("postgres://invalid:invalid@127.0.0.1:1/none")
            .expect("connect_lazy never fails for a syntactically valid URL");
        let storage: Arc<dyn crate::storage::StorageBackend> =
            Arc::new(FilesystemStorage::new("/tmp/conan-unit-test"));
        let registry = Arc::new(crate::storage::StorageRegistry::new(
            std::collections::HashMap::new(),
            "filesystem".to_string(),
        ));
        let config = Config {
            database_url: String::new(),
            bind_address: "127.0.0.1:0".into(),
            log_level: "error".into(),
            storage_backend: "filesystem".into(),
            storage_path: "/tmp/conan-unit-test".into(),
            s3_bucket: None,
            gcs_bucket: None,
            s3_region: None,
            s3_endpoint: None,
            jwt_secret: "test-secret-at-least-32-bytes-long-for-testing".into(),
            jwt_expiration_secs: 3600,
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
            proxy_max_concurrent_fetches: 20,
            proxy_max_artifact_size_bytes: 2_147_483_648,
            proxy_queue_timeout_secs: 30,
            metrics_port: None,
            rate_limit_exempt_usernames: Vec::new(),
            rate_limit_exempt_service_accounts: false,
        };
        Arc::new(AppState::new(config, pool, storage, registry))
    }

    #[tokio::test]
    async fn test_recipe_file_upload_returns_414_for_overlong_segment() {
        // PUT with a 300-char `name` segment must surface as a 4xx (414)
        // before any DB call. This exercises the validate_conan_segments
        // call site in `recipe_file_upload` (issue #990 sub-test #15).
        use tower::ServiceExt;

        let state = unit_test_state();
        let app = router().with_state(state);

        let long_name: String = "a".repeat(300);
        let uri = format!(
            "/some-repo/v2/conans/{}/1.0.0/_/_/revisions/rev/files/conanfile.py",
            long_name
        );
        let req = axum::http::Request::builder()
            .method("PUT")
            .uri(uri)
            .body(Body::from("dummy".as_bytes().to_vec()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::URI_TOO_LONG,
            "300-char recipe path segment must return 414 before any DB call"
        );
    }

    #[tokio::test]
    async fn test_package_file_upload_returns_414_for_overlong_segment() {
        // PUT to the package-file route with a 300-char `package_id` must
        // also short-circuit with a 414. Exercises the validate_conan_segments
        // call site in `package_file_upload` (issue #990).
        use tower::ServiceExt;

        let state = unit_test_state();
        let app = router().with_state(state);

        let long_pkg_id: String = "p".repeat(300);
        let uri = format!(
            "/some-repo/v2/conans/zlib/1.3.1/_/_/revisions/rev/packages/{}/revisions/prev/files/conanfile.py",
            long_pkg_id
        );
        let req = axum::http::Request::builder()
            .method("PUT")
            .uri(uri)
            .body(Body::from("dummy".as_bytes().to_vec()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::URI_TOO_LONG,
            "300-char package path segment must return 414 before any DB call"
        );
    }

    #[tokio::test]
    async fn test_ping_handler_propagates_repo_resolution_error() {
        // GET /v2/ping must call `resolve_conan_repo` before returning the
        // capability banner (issue #990 sub-test #12). With a lazy pool that
        // cannot connect to PostgreSQL, the resolve call fails and the
        // handler must propagate that as a 5xx — NOT a 200. This exercises
        // the handler signature, the `?` propagation, and proves the
        // capability banner is gated on repo resolution.
        use tower::ServiceExt;

        let state = unit_test_state();
        let app = router().with_state(state);

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/some-repo/v2/ping")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        // The exact status depends on how `map_db_err` shapes the response,
        // but the contract that issue #990 requires is: ping does NOT return
        // 200 when the repo cannot be resolved.
        assert_ne!(
            resp.status(),
            StatusCode::OK,
            "ping must not return 200 when repo resolution fails"
        );
        assert!(
            resp.headers().get("X-Conan-Server-Capabilities").is_none(),
            "capability banner must be gated on successful repo resolution"
        );
    }
}
