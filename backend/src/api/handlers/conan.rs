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
use axum::http::StatusCode;
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
use crate::api::middleware::auth::{require_auth_basic, require_auth_basic_scope, AuthExtension};
use crate::api::SharedState;
use crate::models::repository::RepositoryType;
use crate::services::auth_service::AuthService;

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
        // Package search for a recipe revision (#2058). Conan 2's `download`
        // enumerates a recipe revision's package IDs via this endpoint; without
        // it the client 404s after `/latest` and the download fails. For remote
        // repos the query is forwarded to the (authenticated) upstream.
        .route(
            "/:repo_key/v2/conans/:name/:version/:user/:channel/revisions/:revision/search",
            get(recipe_package_search),
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

/// Push items from `incoming` onto `sink`, skipping any whose key (per
/// `key_fn`) has already been recorded in `seen`. Used by the virtual-repo
/// fan-out paths in `search`, `recipe_revisions`, `package_revisions`,
/// `recipe_files_list`, and `package_files_list` to dedupe metadata rows
/// across hosted members while preserving member priority order.
fn merge_unique_by<V, K, F>(
    incoming: Vec<V>,
    seen: &mut std::collections::HashSet<K>,
    sink: &mut Vec<V>,
    key_fn: F,
) where
    K: Eq + std::hash::Hash,
    F: Fn(&V) -> K,
{
    for v in incoming {
        if seen.insert(key_fn(&v)) {
            sink.push(v);
        }
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

// ---------------------------------------------------------------------------
// GET /conan/{repo_key}/v2/ping
// ---------------------------------------------------------------------------

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
) -> Result<Response, Response> {
    // Validate repo exists and is conan format
    let _repo = resolve_conan_repo(&state.db, &repo_key).await?;

    // Authenticate user via Basic auth (middleware has already resolved the
    // credential into an AuthExtension).
    let user_id = require_auth_basic(auth, "conan")?.user_id;

    // Issue a real JWT access token. The Conan client stores the body of this
    // response and sends it back as `Authorization: Bearer <token>` on later
    // requests (e.g. check_credentials, uploads). Echoing the base64 Basic
    // value here (issue #1433) produced a string the Bearer/JWT validator in
    // the auth middleware rejected, so every privileged action returned 401.
    // A signed JWT is accepted by `validate_access_token_async`, which is the
    // first thing the Bearer path tries.
    let user = sqlx::query_as!(
        crate::models::user::User,
        r#"SELECT id, username, email, password_hash, display_name,
           auth_provider as "auth_provider: crate::models::user::AuthProvider",
           external_id, is_admin, is_active, is_service_account, must_change_password,
           totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
           failed_login_attempts, locked_until, last_failed_login_at,
           password_changed_at, last_login_at, created_at, updated_at
           FROM users WHERE id = $1 AND is_active = true"#,
        user_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(map_db_err)?
    .ok_or_else(|| {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Basic realm=\"conan\"")
            .body(Body::from("Authentication required"))
            .unwrap()
    })?;

    let auth_service =
        AuthService::new(state.db.clone(), std::sync::Arc::new(state.config.clone()));
    let tokens = auth_service.generate_tokens(&user).map_err(|_| {
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from("token generation failed"))
            .unwrap()
    })?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain")
        .body(Body::from(tokens.access_token))
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

/// Pure helper extracted from [`search`] so the per-repo query can be reused
/// for both the non-virtual fast path and for virtual fan-out across hosted
/// member repositories. Returns the list of recipe references
/// (`name/version@user/channel`) for one repository matching `like_pattern`.
async fn search_recipes_for_repo(
    db: &PgPool,
    repository_id: uuid::Uuid,
    like_pattern: &str,
) -> Result<Vec<String>, sqlx::Error> {
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
        repository_id,
        like_pattern,
    )
    .fetch_all(db)
    .await?;

    // Build search results in Conan v2 format.
    //
    // Prefer the per-recipe values stored in `artifact_metadata.metadata`
    // (`version`, `user`, `channel`) so the response matches what the Conan
    // client uploaded. Fall back to the artifact column / spec defaults when
    // the JSON field is absent (preserves Conan v2 protocol: `_` is the
    // sentinel for "no user / no channel", `0.0.0` is the fallback version).
    Ok(rows
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
        .collect())
}

/// Forward a Conan v2 search query to a remote upstream and parse the JSON
/// `results: [...]` array. Returns `Ok(Vec::new())` on any non-200 response
/// or parse error — search is a best-effort, additive operation, so a remote
/// failure must not block locally-uploaded recipes from being returned. The
/// caller is responsible for merging the result with local hits.
async fn search_recipes_from_remote(
    proxy: &crate::services::proxy_service::ProxyService,
    repo_id: uuid::Uuid,
    repo_key: &str,
    upstream_url: &str,
    pattern: &str,
) -> Vec<String> {
    let encoded = urlencoding::encode(pattern);
    let upstream_path = format!("v2/conans/search?q={}", encoded);
    match proxy_helpers::proxy_fetch_capped(
        proxy,
        repo_id,
        repo_key,
        upstream_url,
        &upstream_path,
        proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
    )
    .await
    {
        Ok((bytes, _ct)) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(v) => v
                .get("results")
                .and_then(|r| r.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|item| item.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default(),
            Err(e) => {
                tracing::warn!(
                    "conan search: failed to parse upstream JSON for member '{}': {}",
                    repo_key,
                    e
                );
                Vec::new()
            }
        },
        Err(_e) => {
            tracing::debug!(
                "conan search: upstream fetch failed or returned non-2xx for member '{}'",
                repo_key
            );
            Vec::new()
        }
    }
}

/// Parse an upstream Conan v2 revisions response body into `RecipeRevisionRow`s.
///
/// The upstream shape is identical to what these handlers emit:
/// `{"revisions":[{"revision":"...","time":"..."}]}`. The `time` field is
/// parsed as RFC3339 so merged rows can be re-sorted newest-first; an absent or
/// unparseable `time` falls back to "now" (the row is still returned). Returns
/// an empty `Vec` on any parse failure so a malformed upstream degrades to
/// local-only rather than erroring.
fn parse_recipe_revisions_json(bytes: &[u8]) -> Vec<RecipeRevisionRow> {
    let value: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                "conan recipe_revisions: failed to parse upstream JSON: {}",
                e
            );
            return Vec::new();
        }
    };
    parse_revisions_value(&value)
        .into_iter()
        .map(|(revision, created_at)| RecipeRevisionRow {
            revision,
            created_at,
        })
        .collect()
}

/// Parse an upstream Conan v2 package-revisions response body into
/// `PackageRevisionRow`s. Same shape and degradation rules as
/// [`parse_recipe_revisions_json`].
fn parse_package_revisions_json(bytes: &[u8]) -> Vec<PackageRevisionRow> {
    let value: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                "conan package_revisions: failed to parse upstream JSON: {}",
                e
            );
            return Vec::new();
        }
    };
    parse_revisions_value(&value)
        .into_iter()
        .map(|(revision, created_at)| PackageRevisionRow {
            revision,
            created_at,
        })
        .collect()
}

/// Parse an upstream Conan v2 package-search response body (`#2058`).
///
/// The endpoint returns a JSON object keyed by package ID, each value being
/// that package's configuration (settings/options/requires). We keep the shape
/// verbatim so a forwarded upstream response is passed through unchanged.
/// Anything that is not a JSON object (malformed body, empty upstream) degrades
/// to an empty map so the handler still returns `200 {}` rather than `500`.
fn parse_package_search_json(bytes: &[u8]) -> serde_json::Map<String, serde_json::Value> {
    match serde_json::from_slice::<serde_json::Value>(bytes) {
        Ok(serde_json::Value::Object(map)) => map,
        Ok(_) => serde_json::Map::new(),
        Err(e) => {
            tracing::warn!("conan package_search: failed to parse upstream JSON: {}", e);
            serde_json::Map::new()
        }
    }
}

/// Parse an upstream Conan `time` string. Conan Center emits times with a
/// numeric `+0000` offset (e.g. `2025-12-09T12:51:39.337+0000`) which is NOT
/// strict RFC3339 (RFC3339 requires `Z` or `+00:00`), so try RFC3339 first and
/// fall back to the `%z` form. On any failure return `Utc::now()` so the row is
/// still surfaced (only its sort key is approximate).
fn parse_conan_time(t: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(t)
        .or_else(|_| chrono::DateTime::parse_from_str(t, "%Y-%m-%dT%H:%M:%S%.f%z"))
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now())
}

/// Shared extraction of the `revisions: [{revision, time}]` array, returning
/// `(revision, created_at)` pairs. An entry without a string `revision` is
/// skipped; an absent/unparseable `time` falls back to `Utc::now()`.
fn parse_revisions_value(
    value: &serde_json::Value,
) -> Vec<(String, chrono::DateTime<chrono::Utc>)> {
    value
        .get("revisions")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| {
                    let revision = item.get("revision").and_then(|v| v.as_str())?;
                    let created_at = item
                        .get("time")
                        .and_then(|v| v.as_str())
                        .map(parse_conan_time)
                        .unwrap_or_else(chrono::Utc::now);
                    Some((revision.to_string(), created_at))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Parse an upstream Conan v2 `.../latest` response body into the single
/// revision id. Shape: `{"revision":"...","time":"..."}`. Returns `None` on a
/// missing/unparseable body so a Remote `/latest` falls through to 404 only
/// when the upstream genuinely has nothing.
fn parse_latest_revision_json(bytes: &[u8]) -> Option<String> {
    let value: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("conan latest: failed to parse upstream JSON: {}", e);
            return None;
        }
    };
    value
        .get("revision")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Forward a recipe-revisions list query to a remote upstream and parse the
/// `revisions` array. Returns `Vec::new()` on any non-2xx response or parse
/// error (mirrors [`search_recipes_from_remote`]) so a flaky/offline upstream
/// degrades to local-only instead of erroring. The caller merges the result
/// with local cache rows.
#[allow(clippy::too_many_arguments)]
async fn recipe_revisions_from_remote(
    proxy: &crate::services::proxy_service::ProxyService,
    repo_id: uuid::Uuid,
    repo_key: &str,
    upstream_url: &str,
    name: &str,
    version: &str,
    user: &str,
    channel: &str,
) -> Vec<RecipeRevisionRow> {
    let upstream_path = format!(
        "v2/conans/{}/{}/{}/{}/revisions",
        name, version, user, channel
    );
    match proxy_helpers::proxy_fetch_capped(
        proxy,
        repo_id,
        repo_key,
        upstream_url,
        &upstream_path,
        proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
    )
    .await
    {
        Ok((bytes, _ct)) => parse_recipe_revisions_json(&bytes),
        Err(_e) => {
            tracing::debug!(
                "conan recipe_revisions: upstream fetch failed or non-2xx for '{}'",
                repo_key
            );
            Vec::new()
        }
    }
}

/// Forward a package-search query for a recipe revision to a remote upstream
/// and parse the returned package map (#2058). Applies the repository's
/// configured upstream credentials via [`proxy_helpers::proxy_fetch`] (which
/// loads them by `repo_id`), so an authenticated upstream registry is queried
/// with the stored basic/bearer auth. Returns an empty map on any non-2xx
/// response or parse error so a flaky/offline upstream degrades to local-only.
#[allow(clippy::too_many_arguments)]
async fn package_search_from_remote(
    proxy: &crate::services::proxy_service::ProxyService,
    repo_id: uuid::Uuid,
    repo_key: &str,
    upstream_url: &str,
    name: &str,
    version: &str,
    user: &str,
    channel: &str,
    revision: &str,
) -> serde_json::Map<String, serde_json::Value> {
    let upstream_path = format!(
        "v2/conans/{}/{}/{}/{}/revisions/{}/search",
        name, version, user, channel, revision
    );
    match proxy_helpers::proxy_fetch_capped(
        proxy,
        repo_id,
        repo_key,
        upstream_url,
        &upstream_path,
        proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
    )
    .await
    {
        Ok((bytes, _ct)) => parse_package_search_json(&bytes),
        Err(_e) => {
            tracing::debug!(
                "conan package_search: upstream fetch failed or non-2xx for '{}'",
                repo_key
            );
            serde_json::Map::new()
        }
    }
}

/// Forward a recipe `/latest` query to a remote upstream. Returns `None` on any
/// non-2xx response or parse error so the caller can fall through to a 404 only
/// when the upstream truly has no revision. Mirrors the file-download Remote arm.
#[allow(clippy::too_many_arguments)]
async fn recipe_latest_from_remote(
    proxy: &crate::services::proxy_service::ProxyService,
    repo_id: uuid::Uuid,
    repo_key: &str,
    upstream_url: &str,
    name: &str,
    version: &str,
    user: &str,
    channel: &str,
) -> Option<String> {
    let upstream_path = format!("v2/conans/{}/{}/{}/{}/latest", name, version, user, channel);
    match proxy_helpers::proxy_fetch_capped(
        proxy,
        repo_id,
        repo_key,
        upstream_url,
        &upstream_path,
        proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
    )
    .await
    {
        Ok((bytes, _ct)) => parse_latest_revision_json(&bytes),
        Err(_e) => {
            tracing::debug!(
                "conan recipe_latest: upstream fetch failed or non-2xx for '{}'",
                repo_key
            );
            None
        }
    }
}

/// Forward a package-revisions list query to a remote upstream and parse the
/// `revisions` array. Same degradation rules as [`recipe_revisions_from_remote`].
#[allow(clippy::too_many_arguments)]
async fn package_revisions_from_remote(
    proxy: &crate::services::proxy_service::ProxyService,
    repo_id: uuid::Uuid,
    repo_key: &str,
    upstream_url: &str,
    name: &str,
    version: &str,
    user: &str,
    channel: &str,
    revision: &str,
    package_id: &str,
) -> Vec<PackageRevisionRow> {
    let upstream_path = format!(
        "v2/conans/{}/{}/{}/{}/revisions/{}/packages/{}/revisions",
        name, version, user, channel, revision, package_id
    );
    match proxy_helpers::proxy_fetch_capped(
        proxy,
        repo_id,
        repo_key,
        upstream_url,
        &upstream_path,
        proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
    )
    .await
    {
        Ok((bytes, _ct)) => parse_package_revisions_json(&bytes),
        Err(_e) => {
            tracing::debug!(
                "conan package_revisions: upstream fetch failed or non-2xx for '{}'",
                repo_key
            );
            Vec::new()
        }
    }
}

/// Forward a package `/latest` query to a remote upstream. Same degradation
/// rules as [`recipe_latest_from_remote`].
#[allow(clippy::too_many_arguments)]
async fn package_latest_from_remote(
    proxy: &crate::services::proxy_service::ProxyService,
    repo_id: uuid::Uuid,
    repo_key: &str,
    upstream_url: &str,
    name: &str,
    version: &str,
    user: &str,
    channel: &str,
    revision: &str,
    package_id: &str,
) -> Option<String> {
    let upstream_path = format!(
        "v2/conans/{}/{}/{}/{}/revisions/{}/packages/{}/latest",
        name, version, user, channel, revision, package_id
    );
    match proxy_helpers::proxy_fetch_capped(
        proxy,
        repo_id,
        repo_key,
        upstream_url,
        &upstream_path,
        proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
    )
    .await
    {
        Ok((bytes, _ct)) => parse_latest_revision_json(&bytes),
        Err(_e) => {
            tracing::debug!(
                "conan package_latest: upstream fetch failed or non-2xx for '{}'",
                repo_key
            );
            None
        }
    }
}

async fn search(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    Query(query): Query<SearchQuery>,
) -> Result<Response, Response> {
    let repo = resolve_conan_repo(&state.db, &repo_key).await?;

    let pattern = query.q.unwrap_or_else(|| "*".to_string());

    // Convert glob-like pattern to SQL LIKE pattern.
    let like_pattern = pattern.replace('*', "%");

    // Aggregate using a deduped Vec so order is preserved across members.
    let mut seen = std::collections::HashSet::<String>::new();
    let mut results: Vec<String> = Vec::new();
    let push = |refs: Vec<String>, seen: &mut _, sink: &mut Vec<String>| {
        merge_unique_by(refs, seen, sink, |r| r.clone());
    };

    if repo.repo_type == RepositoryType::Virtual {
        // Walk virtual members in priority order. Hosted members are queried
        // directly; remote members are forwarded to their upstream. Each
        // member's results are merged and deduped.
        let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
        for member in &members {
            if member.repo_type.is_hosted() {
                let local = search_recipes_for_repo(&state.db, member.id, &like_pattern)
                    .await
                    .map_err(map_db_err)?;
                push(local, &mut seen, &mut results);
            } else if member.repo_type == RepositoryType::Remote {
                if let (Some(upstream_url), Some(proxy)) = (
                    member.upstream_url.as_deref(),
                    state.proxy_service.as_deref(),
                ) {
                    let remote = search_recipes_from_remote(
                        proxy,
                        member.id,
                        &member.key,
                        upstream_url,
                        &pattern,
                    )
                    .await;
                    push(remote, &mut seen, &mut results);
                }
            }
        }
    } else if repo.repo_type == RepositoryType::Remote {
        // Local cache first, then forward upstream and merge any remote hits.
        let local = search_recipes_for_repo(&state.db, repo.id, &like_pattern)
            .await
            .map_err(map_db_err)?;
        push(local, &mut seen, &mut results);
        if let (Some(upstream_url), Some(proxy)) =
            (repo.upstream_url.as_deref(), state.proxy_service.as_deref())
        {
            let remote =
                search_recipes_from_remote(proxy, repo.id, &repo_key, upstream_url, &pattern).await;
            push(remote, &mut seen, &mut results);
        }
    } else {
        let local = search_recipes_for_repo(&state.db, repo.id, &like_pattern)
            .await
            .map_err(map_db_err)?;
        push(local, &mut seen, &mut results);
    }

    let json = serde_json::json!({ "results": results });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /conan/{repo_key}/v2/conans/{name}/{version}/{user}/{channel}/latest
// ---------------------------------------------------------------------------

/// Look up the latest recipe revision for a single repository.
///
/// Pure helper extracted from [`recipe_latest`] so the per-repo query can be
/// reused both for the non-virtual fast path and for virtual fan-out across
/// member repositories. Returns `Ok(None)` when the repository has no
/// matching recipe rows.
async fn latest_recipe_revision_for_repo(
    db: &PgPool,
    repository_id: uuid::Uuid,
    name: &str,
    version: &str,
    user: &str,
    channel: &str,
) -> Result<Option<String>, sqlx::Error> {
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
          AND am.metadata->>'user' = $4
          AND am.metadata->>'channel' = $5
          AND am.metadata->>'revision' IS NOT NULL
        ORDER BY a.created_at DESC, a.id DESC
        LIMIT 1
        "#,
        repository_id,
        name,
        version,
        normalize_user(user),
        normalize_channel(channel),
    )
    .fetch_optional(db)
    .await?;

    Ok(row.and_then(|r| r.revision))
}

async fn recipe_latest(
    State(state): State<SharedState>,
    Path((repo_key, name, version, user, channel)): Path<(String, String, String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_conan_repo(&state.db, &repo_key).await?;

    // Find the latest recipe revision by looking at the most recently created
    // artifact with a revision in its metadata. Must filter by user/channel so
    // revisions uploaded under one namespace (e.g. myuser/stable) do not leak
    // into the latest response for another (e.g. _/_).
    //
    // For virtual repos, fan out to each member in priority order and return
    // the first member that has a matching revision. This mirrors the pattern
    // used by `recipe_file_download`. Remote member aggregation is deferred to
    // a follow-up; only hosted (Local/Staging) members are consulted here.
    let revision = if repo.repo_type == RepositoryType::Virtual {
        let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
        let mut found: Option<String> = None;
        for member in &members {
            if !member.repo_type.is_hosted() {
                continue;
            }
            match latest_recipe_revision_for_repo(
                &state.db, member.id, &name, &version, &user, &channel,
            )
            .await
            .map_err(map_db_err)?
            {
                Some(rev) => {
                    found = Some(rev);
                    break;
                }
                None => continue,
            }
        }
        found.ok_or_else(|| (StatusCode::NOT_FOUND, "No revisions found").into_response())?
    } else if repo.repo_type == RepositoryType::Remote {
        // Local cache first; on a miss forward to the upstream `/latest`. Only
        // 404 when both local cache and upstream have nothing. Mirrors the
        // file-download Remote arm.
        match latest_recipe_revision_for_repo(&state.db, repo.id, &name, &version, &user, &channel)
            .await
            .map_err(map_db_err)?
        {
            Some(rev) => rev,
            None => {
                let remote = match (repo.upstream_url.as_deref(), state.proxy_service.as_deref()) {
                    (Some(upstream_url), Some(proxy)) => {
                        recipe_latest_from_remote(
                            proxy,
                            repo.id,
                            &repo_key,
                            upstream_url,
                            &name,
                            &version,
                            &user,
                            &channel,
                        )
                        .await
                    }
                    _ => None,
                };
                remote
                    .ok_or_else(|| (StatusCode::NOT_FOUND, "No revisions found").into_response())?
            }
        }
    } else {
        latest_recipe_revision_for_repo(&state.db, repo.id, &name, &version, &user, &channel)
            .await
            .map_err(map_db_err)?
            .ok_or_else(|| (StatusCode::NOT_FOUND, "No revisions found").into_response())?
    };

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

/// Row shape for the revisions query, factored so the per-repo helper can be
/// reused for both the non-virtual fast path and virtual fan-out.
struct RecipeRevisionRow {
    revision: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

async fn recipe_revisions_for_repo(
    db: &PgPool,
    repository_id: uuid::Uuid,
    name: &str,
    version: &str,
    user: &str,
    channel: &str,
) -> Result<Vec<RecipeRevisionRow>, sqlx::Error> {
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
          AND am.metadata->>'user' = $4
          AND am.metadata->>'channel' = $5
          AND am.metadata->>'revision' IS NOT NULL
        GROUP BY am.metadata->>'revision'
        ORDER BY "created_at!" DESC
        "#,
        repository_id,
        name,
        version,
        normalize_user(user),
        normalize_channel(channel),
    )
    .fetch_all(db)
    .await?;

    Ok(rows
        .into_iter()
        .filter_map(|r| {
            r.revision.map(|rev| RecipeRevisionRow {
                revision: rev,
                created_at: r.created_at,
            })
        })
        .collect())
}

async fn recipe_revisions(
    State(state): State<SharedState>,
    Path((repo_key, name, version, user, channel)): Path<(String, String, String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_conan_repo(&state.db, &repo_key).await?;

    // Must filter by user/channel so revisions uploaded under one namespace
    // (e.g. myuser/stable) do not appear in the revisions list for a different
    // namespace (e.g. _/_).
    //
    // For virtual repos, walk hosted members in priority order and merge the
    // union of revisions, deduped by revision id, ordered by newest first.
    // Remote-member aggregation is deferred (matches recipe_latest semantics).
    let rows = if repo.repo_type == RepositoryType::Virtual {
        let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
        let mut seen = std::collections::HashSet::<String>::new();
        let mut merged: Vec<RecipeRevisionRow> = Vec::new();
        for member in &members {
            if !member.repo_type.is_hosted() {
                continue;
            }
            let member_rows =
                recipe_revisions_for_repo(&state.db, member.id, &name, &version, &user, &channel)
                    .await
                    .map_err(map_db_err)?;
            merge_unique_by(member_rows, &mut seen, &mut merged, |r| r.revision.clone());
        }
        merged.sort_by_key(|r| std::cmp::Reverse(r.created_at));
        merged
    } else if repo.repo_type == RepositoryType::Remote {
        // Local cache first, then forward upstream and merge any remote
        // revisions, deduped by revision id and re-sorted newest-first. Mirrors
        // the search Remote arm.
        let mut seen = std::collections::HashSet::<String>::new();
        let mut merged: Vec<RecipeRevisionRow> = Vec::new();
        let local = recipe_revisions_for_repo(&state.db, repo.id, &name, &version, &user, &channel)
            .await
            .map_err(map_db_err)?;
        merge_unique_by(local, &mut seen, &mut merged, |r| r.revision.clone());
        if let (Some(upstream_url), Some(proxy)) =
            (repo.upstream_url.as_deref(), state.proxy_service.as_deref())
        {
            let remote = recipe_revisions_from_remote(
                proxy,
                repo.id,
                &repo_key,
                upstream_url,
                &name,
                &version,
                &user,
                &channel,
            )
            .await;
            merge_unique_by(remote, &mut seen, &mut merged, |r| r.revision.clone());
        }
        merged.sort_by_key(|r| std::cmp::Reverse(r.created_at));
        merged
    } else {
        recipe_revisions_for_repo(&state.db, repo.id, &name, &version, &user, &channel)
            .await
            .map_err(map_db_err)?
    };

    let revisions: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "revision": r.revision,
                "time": r.created_at.to_rfc3339()
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
// GET .../revisions/{rev}/search — Package search for a recipe revision (#2058)
// ---------------------------------------------------------------------------

/// Distinct package IDs stored locally for a given recipe revision.
///
/// Backs the hosted arm of [`recipe_package_search`]: Conan 2's `download`
/// enumerates a recipe revision's packages through the `/search` endpoint, so
/// we surface every `packageId` we hold for the (name, version, user, channel,
/// recipe-revision) tuple.
async fn package_ids_for_recipe_revision(
    db: &PgPool,
    repository_id: uuid::Uuid,
    name: &str,
    version: &str,
    user: &str,
    channel: &str,
    revision: &str,
) -> Result<Vec<String>, sqlx::Error> {
    let rows = sqlx::query!(
        r#"
        SELECT DISTINCT am.metadata->>'packageId' as "package_id?"
        FROM artifacts a
        JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND am.format = 'conan'
          AND a.name = $2
          AND a.version = $3
          AND am.metadata->>'user' = $4
          AND am.metadata->>'channel' = $5
          AND am.metadata->>'revision' = $6
          AND am.metadata->>'type' = 'package'
          AND am.metadata->>'packageId' IS NOT NULL
        "#,
        repository_id,
        name,
        version,
        normalize_user(user),
        normalize_channel(channel),
        revision,
    )
    .fetch_all(db)
    .await?;

    Ok(rows.into_iter().filter_map(|r| r.package_id).collect())
}

async fn recipe_package_search(
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

    // Package ID -> configuration map. Hosted rows contribute an empty object
    // (the ID is what `download` needs); a remote upstream contributes the full
    // configuration and takes precedence for shared IDs.
    let mut packages = serde_json::Map::new();
    let add_local = |packages: &mut serde_json::Map<String, serde_json::Value>,
                     ids: Vec<String>| {
        for id in ids {
            packages
                .entry(id)
                .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        }
    };

    if repo.repo_type == RepositoryType::Virtual {
        let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
        for member in &members {
            if member.repo_type.is_hosted() {
                let ids = package_ids_for_recipe_revision(
                    &state.db, member.id, &name, &version, &user, &channel, &revision,
                )
                .await
                .map_err(map_db_err)?;
                add_local(&mut packages, ids);
            } else if member.repo_type == RepositoryType::Remote {
                if let (Some(upstream_url), Some(proxy)) = (
                    member.upstream_url.as_deref(),
                    state.proxy_service.as_deref(),
                ) {
                    let remote = package_search_from_remote(
                        proxy,
                        member.id,
                        &member.key,
                        upstream_url,
                        &name,
                        &version,
                        &user,
                        &channel,
                        &revision,
                    )
                    .await;
                    packages.extend(remote);
                }
            }
        }
    } else if repo.repo_type == RepositoryType::Remote {
        let ids = package_ids_for_recipe_revision(
            &state.db, repo.id, &name, &version, &user, &channel, &revision,
        )
        .await
        .map_err(map_db_err)?;
        add_local(&mut packages, ids);
        if let (Some(upstream_url), Some(proxy)) =
            (repo.upstream_url.as_deref(), state.proxy_service.as_deref())
        {
            let remote = package_search_from_remote(
                proxy,
                repo.id,
                &repo_key,
                upstream_url,
                &name,
                &version,
                &user,
                &channel,
                &revision,
            )
            .await;
            packages.extend(remote);
        }
    } else {
        let ids = package_ids_for_recipe_revision(
            &state.db, repo.id, &name, &version, &user, &channel, &revision,
        )
        .await
        .map_err(map_db_err)?;
        add_local(&mut packages, ids);
    }

    let json = serde_json::Value::Object(packages);
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET  .../revisions/{rev}/files — List recipe files
// ---------------------------------------------------------------------------

async fn recipe_files_list_for_repo(
    db: &PgPool,
    repository_id: uuid::Uuid,
    name: &str,
    version: &str,
    user: &str,
    channel: &str,
    revision: &str,
) -> Result<Vec<String>, sqlx::Error> {
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
        repository_id,
        name,
        version,
        normalize_user(user),
        normalize_channel(channel),
        revision,
    )
    .fetch_all(db)
    .await?;

    Ok(rows.into_iter().filter_map(|r| r.file).collect())
}

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

    // For virtual repos, walk hosted members in priority order and merge the
    // union of file names, deduped. Order matches recipe_revisions semantics.
    let filenames: Vec<String> = if repo.repo_type == RepositoryType::Virtual {
        let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
        let mut seen = std::collections::HashSet::<String>::new();
        let mut merged: Vec<String> = Vec::new();
        for member in &members {
            if !member.repo_type.is_hosted() {
                continue;
            }
            let member_files = recipe_files_list_for_repo(
                &state.db, member.id, &name, &version, &user, &channel, &revision,
            )
            .await
            .map_err(map_db_err)?;
            merge_unique_by(member_files, &mut seen, &mut merged, |f| f.clone());
        }
        merged
    } else {
        recipe_files_list_for_repo(
            &state.db, repo.id, &name, &version, &user, &channel, &revision,
        )
        .await
        .map_err(map_db_err)?
    };

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
    .map_err(crate::api::handlers::db_err)?
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
                    // #1608 Phase 4: stream the recipe file body (may be a
                    // large conan_export.tgz / conan_sources.tgz) straight to
                    // the client while teeing to the proxy cache, instead of
                    // buffering the whole artifact in memory. Tees via the
                    // merged coordinator so concurrent cold-misses collapse to
                    // a single upstream fetch (#1609). octet-stream default
                    // matches the buffered handler's prior fallback.
                    return proxy_helpers::proxy_fetch_streaming(
                        proxy,
                        repo.id,
                        &repo_key,
                        upstream_url,
                        &upstream_path,
                        "application/octet-stream",
                    )
                    .await;
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
                let result = proxy_helpers::resolve_virtual_download(
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

                return proxy_helpers::stream_fetch_result(
                    result,
                    "application/octet-stream",
                    None,
                );
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
    // Path-shape is independent of authn/authz so it is safe (and useful
    // for monitoring) to fail it first.
    validate_conan_segments(&[
        ("name", &name),
        ("version", &version),
        ("user", &user),
        ("channel", &channel),
        ("revision", &revision),
        ("file_path", &file_path),
    ])?;

    // Validate the repo BEFORE checking auth, so an upload to a non-existent
    // repo returns 404 instead of 500 (issue #990). The repo-visibility
    // middleware skips the auth-extension insertion when the repo key is
    // unknown, so a strict `Extension<Option<AuthExtension>>` extractor
    // would surface a 500 here. Accepting the extension as `Option<...>`
    // lets us run the resolve-then-auth-then-validate sequence cleanly.
    let repo = resolve_conan_repo(&state.db, &repo_key).await?;
    let auth_ext = auth.and_then(|Extension(a)| a);
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth_ext, "conan", "write")?.user_id;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

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
    // The checked variant additionally rejects a release-immutability swap on
    // any coordinate the classifier marks immutable (Conan paths are mutable
    // today, so this is a no-op for them and preserves same-revision overwrite).
    super::cleanup_soft_deleted_artifact_checked(
        &state.db,
        &crate::models::repository::RepositoryFormat::Conan,
        repo.id,
        &artifact_path,
        &checksum_sha256,
    )
    .await
    .map_err(|e| e.into_response())?;

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

    crate::services::quarantine_service::apply_upload_hold_hosted(&state.db, repo.id, artifact_id)
        .await;

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

/// Per-repo helper: latest package revision (newest by created_at) for a
/// given (name, version, recipe revision, package_id). Returns `Ok(None)` when
/// the repository has no matching rows. Mirrors [`latest_recipe_revision_for_repo`].
async fn latest_package_revision_for_repo(
    db: &PgPool,
    repository_id: uuid::Uuid,
    name: &str,
    version: &str,
    revision: &str,
    package_id: &str,
) -> Result<Option<String>, sqlx::Error> {
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
        repository_id,
        name,
        version,
        revision,
        package_id,
    )
    .fetch_optional(db)
    .await?;

    Ok(row.and_then(|r| r.pkg_revision))
}

async fn package_latest(
    State(state): State<SharedState>,
    Path((repo_key, name, version, user, channel, revision, package_id)): Path<(
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

    // For virtual repos, fan out to each hosted member in priority order and
    // return the first member that has a matching package revision. Matches
    // recipe_latest semantics. Remote-member aggregation is deferred.
    let pkg_revision = if repo.repo_type == RepositoryType::Virtual {
        let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
        let mut found: Option<String> = None;
        for member in &members {
            if !member.repo_type.is_hosted() {
                continue;
            }
            match latest_package_revision_for_repo(
                &state.db,
                member.id,
                &name,
                &version,
                &revision,
                &package_id,
            )
            .await
            .map_err(map_db_err)?
            {
                Some(rev) => {
                    found = Some(rev);
                    break;
                }
                None => continue,
            }
        }
        found
            .ok_or_else(|| (StatusCode::NOT_FOUND, "No package revisions found").into_response())?
    } else if repo.repo_type == RepositoryType::Remote {
        // Local cache first; on a miss forward to the upstream package `/latest`.
        // Only 404 when both local and upstream have nothing.
        match latest_package_revision_for_repo(
            &state.db,
            repo.id,
            &name,
            &version,
            &revision,
            &package_id,
        )
        .await
        .map_err(map_db_err)?
        {
            Some(rev) => rev,
            None => {
                let remote = match (repo.upstream_url.as_deref(), state.proxy_service.as_deref()) {
                    (Some(upstream_url), Some(proxy)) => {
                        package_latest_from_remote(
                            proxy,
                            repo.id,
                            &repo_key,
                            upstream_url,
                            &name,
                            &version,
                            &user,
                            &channel,
                            &revision,
                            &package_id,
                        )
                        .await
                    }
                    _ => None,
                };
                remote.ok_or_else(|| {
                    (StatusCode::NOT_FOUND, "No package revisions found").into_response()
                })?
            }
        }
    } else {
        latest_package_revision_for_repo(
            &state.db,
            repo.id,
            &name,
            &version,
            &revision,
            &package_id,
        )
        .await
        .map_err(map_db_err)?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "No package revisions found").into_response())?
    };

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

/// Row shape for the package-revisions query. Mirrors [`RecipeRevisionRow`].
struct PackageRevisionRow {
    revision: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

async fn package_revisions_for_repo(
    db: &PgPool,
    repository_id: uuid::Uuid,
    name: &str,
    version: &str,
    revision: &str,
    package_id: &str,
) -> Result<Vec<PackageRevisionRow>, sqlx::Error> {
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
        repository_id,
        name,
        version,
        revision,
        package_id,
    )
    .fetch_all(db)
    .await?;

    Ok(rows
        .into_iter()
        .filter_map(|r| {
            r.pkg_revision.map(|rev| PackageRevisionRow {
                revision: rev,
                created_at: r.created_at,
            })
        })
        .collect())
}

async fn package_revisions(
    State(state): State<SharedState>,
    Path((repo_key, name, version, user, channel, revision, package_id)): Path<(
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

    // Virtual fan-out: union of package revisions across hosted members,
    // deduped by revision id and re-sorted by newest first.
    let rows = if repo.repo_type == RepositoryType::Virtual {
        let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
        let mut seen = std::collections::HashSet::<String>::new();
        let mut merged: Vec<PackageRevisionRow> = Vec::new();
        for member in &members {
            if !member.repo_type.is_hosted() {
                continue;
            }
            let member_rows = package_revisions_for_repo(
                &state.db,
                member.id,
                &name,
                &version,
                &revision,
                &package_id,
            )
            .await
            .map_err(map_db_err)?;
            merge_unique_by(member_rows, &mut seen, &mut merged, |r| r.revision.clone());
        }
        merged.sort_by_key(|r| std::cmp::Reverse(r.created_at));
        merged
    } else if repo.repo_type == RepositoryType::Remote {
        // Local cache first, then forward upstream and merge any remote package
        // revisions, deduped by revision id and re-sorted newest-first.
        let mut seen = std::collections::HashSet::<String>::new();
        let mut merged: Vec<PackageRevisionRow> = Vec::new();
        let local =
            package_revisions_for_repo(&state.db, repo.id, &name, &version, &revision, &package_id)
                .await
                .map_err(map_db_err)?;
        merge_unique_by(local, &mut seen, &mut merged, |r| r.revision.clone());
        if let (Some(upstream_url), Some(proxy)) =
            (repo.upstream_url.as_deref(), state.proxy_service.as_deref())
        {
            let remote = package_revisions_from_remote(
                proxy,
                repo.id,
                &repo_key,
                upstream_url,
                &name,
                &version,
                &user,
                &channel,
                &revision,
                &package_id,
            )
            .await;
            merge_unique_by(remote, &mut seen, &mut merged, |r| r.revision.clone());
        }
        merged.sort_by_key(|r| std::cmp::Reverse(r.created_at));
        merged
    } else {
        package_revisions_for_repo(&state.db, repo.id, &name, &version, &revision, &package_id)
            .await
            .map_err(map_db_err)?
    };

    let revisions: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "revision": r.revision,
                "time": r.created_at.to_rfc3339()
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

#[allow(clippy::too_many_arguments)]
async fn package_files_list_for_repo(
    db: &PgPool,
    repository_id: uuid::Uuid,
    name: &str,
    version: &str,
    user: &str,
    channel: &str,
    revision: &str,
    package_id: &str,
    pkg_revision: &str,
) -> Result<Vec<String>, sqlx::Error> {
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
        repository_id,
        name,
        version,
        normalize_user(user),
        normalize_channel(channel),
        revision,
        package_id,
        pkg_revision,
    )
    .fetch_all(db)
    .await?;

    Ok(rows.into_iter().filter_map(|r| r.file).collect())
}

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

    // Virtual fan-out: union of package file names across hosted members,
    // deduped by file name.
    let filenames: Vec<String> = if repo.repo_type == RepositoryType::Virtual {
        let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
        let mut seen = std::collections::HashSet::<String>::new();
        let mut merged: Vec<String> = Vec::new();
        for member in &members {
            if !member.repo_type.is_hosted() {
                continue;
            }
            let member_files = package_files_list_for_repo(
                &state.db,
                member.id,
                &name,
                &version,
                &user,
                &channel,
                &revision,
                &package_id,
                &pkg_revision,
            )
            .await
            .map_err(map_db_err)?;
            merge_unique_by(member_files, &mut seen, &mut merged, |f| f.clone());
        }
        merged
    } else {
        package_files_list_for_repo(
            &state.db,
            repo.id,
            &name,
            &version,
            &user,
            &channel,
            &revision,
            &package_id,
            &pkg_revision,
        )
        .await
        .map_err(map_db_err)?
    };

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
    .map_err(crate::api::handlers::db_err)?
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
                        // #1608 Phase 4: stream the package file body (the
                        // conan_package.tgz binary can be very large) to the
                        // client while teeing to the proxy cache, instead of
                        // buffering it in memory. Single-flight via the merged
                        // coordinator (#1609). octet-stream default matches the
                        // buffered handler's prior fallback.
                        return proxy_helpers::proxy_fetch_streaming(
                            proxy,
                            repo.id,
                            &repo_key,
                            upstream_url,
                            &upstream_path,
                            "application/octet-stream",
                        )
                        .await;
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
                    let result = proxy_helpers::resolve_virtual_download(
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

                    return proxy_helpers::stream_fetch_result(
                        result,
                        "application/octet-stream",
                        None,
                    );
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
    let auth_ext = auth.and_then(|Extension(a)| a);
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth_ext, "conan", "write")?.user_id;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

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
    // The checked variant additionally rejects a release-immutability swap on
    // any coordinate the classifier marks immutable (Conan paths are mutable
    // today, so this is a no-op for them and preserves same-revision overwrite).
    super::cleanup_soft_deleted_artifact_checked(
        &state.db,
        &crate::models::repository::RepositoryFormat::Conan,
        repo.id,
        &artifact_path,
        &checksum_sha256,
    )
    .await
    .map_err(|e| e.into_response())?;

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

    crate::services::quarantine_service::apply_upload_hold_hosted(&state.db, repo.id, artifact_id)
        .await;

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

#[allow(clippy::disallowed_methods)]
// streaming-invariant: test module exempt — buffering response bodies in test assertions is not an artifact path (#1608)
#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn test_remote_recipe_file_download_streams_upstream_blob_1608() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "conan").await else {
            return;
        };
        let server = MockServer::start().await;
        let blob: &[u8] = b"\x00\x01\x02 #1608 phase4 streamed proxy blob \x03\x04\x05";
        Mock::given(method("GET"))
            .and(path(
                "/v2/conans/zlib/1.3/_/_/revisions/rev1/files/conan_sources.tgz",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(blob))
            .mount(&server)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&fx, &server.uri()).await;
        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{key}/v2/conans/zlib/1.3/_/_/revisions/rev1/files/conan_sources.tgz",
                key = fx.repo_key
            )),
        )
        .await;

        let teardown = || async { fx.teardown().await };
        if status != axum::http::StatusCode::OK {
            teardown().await;
            panic!("expected 200 from streamed remote download, got {status}");
        }
        assert_eq!(&body[..], blob, "streamed body must equal upstream bytes");
        teardown().await;
    }

    #[tokio::test]
    async fn test_remote_package_file_download_streams_upstream_blob_1608() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "conan").await else {
            return;
        };
        let server = MockServer::start().await;
        let blob: &[u8] = b"\x00\x01\x02 #1608 phase4 streamed proxy blob \x03\x04\x05";
        Mock::given(method("GET"))
            .and(path("/v2/conans/zlib/1.3/_/_/revisions/rev1/packages/pkgid123/revisions/prev1/files/conan_package.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(blob))
            .mount(&server)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&fx, &server.uri()).await;
        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(app, tdh::get(format!("/{key}/v2/conans/zlib/1.3/_/_/revisions/rev1/packages/pkgid123/revisions/prev1/files/conan_package.tgz", key = fx.repo_key))).await;

        let teardown = || async { fx.teardown().await };
        if status != axum::http::StatusCode::OK {
            teardown().await;
            panic!("expected 200 from streamed remote download, got {status}");
        }
        assert_eq!(&body[..], blob, "streamed body must equal upstream bytes");
        teardown().await;
    }
    use super::*;

    #[tokio::test]
    async fn ping_returns_revisions_capability() {
        let Some(f) = test_helpers::TestFixture::setup("local").await else {
            return;
        };

        let app = f.router();
        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!("/{}/v2/ping", f.repo_key))
            .body(Body::empty())
            .expect("build request");
        let resp = tower::ServiceExt::oneshot(app, req).await.expect("oneshot");

        assert_eq!(resp.status(), StatusCode::OK);
        let capabilities = resp
            .headers()
            .get("x-conan-server-capabilities")
            .expect("x-conan-server-capabilities header must be present")
            .to_str()
            .expect("header value must be ASCII")
            .to_string();
        assert!(
            capabilities.contains("revisions"),
            "capability header must advertise 'revisions', got: {capabilities}"
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn ping_returns_404_when_repo_missing() {
        let Some(f) = test_helpers::TestFixture::setup("local").await else {
            return;
        };

        let bogus_key = format!("nonexistent-{}", uuid::Uuid::new_v4());
        let app = f.router();
        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!("/{}/v2/ping", bogus_key))
            .body(Body::empty())
            .expect("build request");
        let resp = tower::ServiceExt::oneshot(app, req).await.expect("oneshot");

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        f.teardown().await;
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
                trivy_adapter_url: None,
                openscap_url: None,
                openscap_profile: "standard".into(),
                opensearch_url: None,
                opensearch_username: None,
                opensearch_password: None,
                opensearch_allow_invalid_certs: false,
                scan_workspace_path: "/tmp/scan".into(),
                demo_mode: false,
                guest_access_enabled: true,
                plugins_require_signed: true,
                plugins_trusted_pubkey: None,
                peer_instance_name: "test".into(),
                peer_public_endpoint: "http://localhost:8080".into(),
                peer_api_key: "test-key".into(),
                dependency_track_url: None,
                dependency_track_enabled: false,
                otel_exporter_otlp_endpoint: None,
                otel_service_name: "test".into(),
                gc_schedule: "0 0 * * * *".into(),
                blob_gc_enabled: false,
                blob_gc_sweep_grace_secs: 3600,
                lifecycle_check_interval_secs: 60,
                stuck_scan_threshold_secs: 1800,
                stuck_scan_check_interval_secs: 600,
                stuck_scan_reap_limit: 1000,
                allow_local_admin_login: false,
                sso_disable_admin_break_glass: false,
                max_upload_size_bytes: 10_737_418_240,
                metrics_port: None,
                database_max_connections: 20,
                database_min_connections: 5,
                database_acquire_timeout_secs: 30,
                database_idle_timeout_secs: 600,
                database_max_lifetime_secs: 1800,
                auth_max_concurrency: 8,
                global_max_concurrency: 512,
                global_request_timeout_secs: 120,
                rate_limit_enabled: true,
                rate_limit_auth_per_window: 120,
                rate_limit_api_per_window: 5000,
                rate_limit_search_per_window: 300,
                rate_limit_presign_per_window: 30,

                rate_limit_login_global_per_window: 8192,
                rate_limit_password_change_per_window: 5,
                rate_limit_password_change_window_secs: 900,
                rate_limit_window_secs: 60,
                rate_limit_exempt_usernames: Vec::new(),
                rate_limit_exempt_service_accounts: false,
                rate_limit_trusted_cidrs: Vec::new(),
                rate_limit_trusted_proxy_cidrs: Vec::new(),
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
                proxy_singleflight_advisory_locks_enabled: false,
                proxy_singleflight_lock_poll_interval_ms: 200,
                proxy_singleflight_lock_wait_timeout_secs: 65,
                smtp_host: None,
                smtp_port: 587,
                smtp_username: None,
                smtp_password: None,
                smtp_from_address: "noreply@artifact-keeper.local".to_string(),
                smtp_tls_mode: "starttls".to_string(),
                npm_packument_cache_enabled: true,
                npm_packument_cache_fresh_ttl_secs: 300,
                npm_packument_cache_stale_max_secs: 86_400,
                npm_packument_cache_redis_url: None,
                scan_token_ttl_seconds: 300,
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

        // ------------------------------------------------------------------
        // TestFixture: eliminates the 5-line setup + 2-line teardown
        // boilerplate that was duplicated across every DB-backed test.
        // ------------------------------------------------------------------

        /// Bundles a database pool, user, repository, state, and auth extension
        /// so each test body can focus on the actual assertions. Call
        /// `TestFixture::setup("local")` at the start and
        /// `fixture.teardown().await` at the end.
        pub struct TestFixture {
            pub pool: PgPool,
            pub user_id: Uuid,
            pub username: String,
            pub repo_id: Uuid,
            pub repo_key: String,
            pub storage_dir: PathBuf,
            pub state: SharedState,
            pub auth: AuthExtension,
        }

        impl TestFixture {
            /// Create a full test environment: pool, user, repo, state, auth.
            /// Returns `None` when `DATABASE_URL` is absent (the test skips).
            pub async fn setup(repo_type: &str) -> Option<Self> {
                let pool = try_pool().await?;
                let (user_id, username, _pw) = create_user(&pool).await;
                let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, repo_type).await;
                let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
                let auth = make_auth(user_id, &username);
                Some(Self {
                    pool,
                    user_id,
                    username,
                    repo_id,
                    repo_key,
                    storage_dir,
                    state,
                    auth,
                })
            }

            /// Clean up all test data and remove the storage directory.
            pub async fn teardown(&self) {
                cleanup(&self.pool, self.repo_id, self.user_id).await;
                let _ = std::fs::remove_dir_all(&self.storage_dir);
            }

            /// Shorthand: build a router with auth pre-injected.
            pub fn router(&self) -> Router {
                router_with_auth(self.state.clone(), self.auth.clone())
            }

            /// Shorthand: GET request with basic auth, returns (status, body).
            pub async fn get(&self, uri: String) -> (StatusCode, Bytes) {
                let app = self.router();
                let req = Request::builder()
                    .method("GET")
                    .uri(uri)
                    .header("Authorization", basic_auth(&self.username, "irrelevant"))
                    .body(Body::empty())
                    .expect("build request");
                send(app, req).await
            }
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
        let Some(f) = test_helpers::TestFixture::setup("local").await else {
            return;
        };

        // Seed rev_old first, then rev_new. DESC ordering must return
        // rev_new before rev_old.
        let _a1 = test_helpers::seed_recipe_row(
            &f.pool,
            f.repo_id,
            "smokelib",
            "1.0",
            "_",
            "_",
            "rev_old",
            "conanfile.py",
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let _a2 = test_helpers::seed_recipe_row(
            &f.pool,
            f.repo_id,
            "smokelib",
            "1.0",
            "_",
            "_",
            "rev_new",
            "conanfile.py",
        )
        .await;

        let (status, body) = f
            .get(format!(
                "/{}/v2/conans/smokelib/1.0/_/_/revisions",
                f.repo_key
            ))
            .await;
        let body_str = String::from_utf8_lossy(&body).to_string();
        assert_eq!(status, StatusCode::OK, "smoke: {}", body_str);

        let json: serde_json::Value = serde_json::from_slice(&body).expect("response must be JSON");
        let revisions = json
            .get("revisions")
            .and_then(|v| v.as_array())
            .expect("response must contain a 'revisions' array");
        assert_eq!(revisions.len(), 2, "got: {}", body_str);
        assert_eq!(
            revisions[0].get("revision").and_then(|v| v.as_str()),
            Some("rev_new"),
        );
        assert_eq!(
            revisions[1].get("revision").and_then(|v| v.as_str()),
            Some("rev_old"),
        );

        f.teardown().await;
    }

    // -----------------------------------------------------------------------
    // recipe_latest / recipe_revisions: user/channel scoping regression tests.
    //
    // Bug: previously, recipe_latest and recipe_revisions ignored the
    // {user}/{channel} path segments. Uploads under one namespace
    // (e.g. myuser/stable) leaked into responses for another (e.g. _/_).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn recipe_latest_scopes_to_default_user_channel() {
        let Some(f) = test_helpers::TestFixture::setup("local").await else {
            return;
        };

        // Upload one revision under _/_ and an unrelated revision under
        // myuser/stable for the same name+version. recipe_latest for _/_
        // must only see the _/_ revision.
        let _ = test_helpers::seed_recipe_row(
            &f.pool,
            f.repo_id,
            "scopelib",
            "1.0",
            "_",
            "_",
            "rev_default",
            "conanfile.py",
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        // Seeded later so its created_at is newer; if scoping is broken,
        // the buggy query would return rev_user_stable here.
        let _ = test_helpers::seed_recipe_row(
            &f.pool,
            f.repo_id,
            "scopelib",
            "1.0",
            "myuser",
            "stable",
            "rev_user_stable",
            "conanfile.py",
        )
        .await;

        let (status, body) = f
            .get(format!("/{}/v2/conans/scopelib/1.0/_/_/latest", f.repo_key))
            .await;
        let body_str = String::from_utf8_lossy(&body).to_string();
        assert_eq!(status, StatusCode::OK, "body: {}", body_str);

        let json: serde_json::Value = serde_json::from_slice(&body).expect("JSON");
        assert_eq!(
            json.get("revision").and_then(|v| v.as_str()),
            Some("rev_default"),
            "latest for _/_ must NOT leak revision uploaded under myuser/stable; got: {}",
            body_str,
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn recipe_latest_scopes_to_custom_user_channel() {
        let Some(f) = test_helpers::TestFixture::setup("local").await else {
            return;
        };

        // Inverse direction: querying myuser/stable must not return _/_ revisions.
        let _ = test_helpers::seed_recipe_row(
            &f.pool,
            f.repo_id,
            "scopelib",
            "1.0",
            "_",
            "_",
            "rev_default",
            "conanfile.py",
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let _ = test_helpers::seed_recipe_row(
            &f.pool,
            f.repo_id,
            "scopelib",
            "1.0",
            "myuser",
            "stable",
            "rev_user_stable",
            "conanfile.py",
        )
        .await;

        let (status, body) = f
            .get(format!(
                "/{}/v2/conans/scopelib/1.0/myuser/stable/latest",
                f.repo_key
            ))
            .await;
        let body_str = String::from_utf8_lossy(&body).to_string();
        assert_eq!(status, StatusCode::OK, "body: {}", body_str);

        let json: serde_json::Value = serde_json::from_slice(&body).expect("JSON");
        assert_eq!(
            json.get("revision").and_then(|v| v.as_str()),
            Some("rev_user_stable"),
            "latest for myuser/stable must NOT return _/_ revision; got: {}",
            body_str,
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn recipe_latest_404_when_namespace_empty() {
        let Some(f) = test_helpers::TestFixture::setup("local").await else {
            return;
        };

        // Upload only under myuser/stable. _/_ should 404.
        let _ = test_helpers::seed_recipe_row(
            &f.pool,
            f.repo_id,
            "scopelib",
            "1.0",
            "myuser",
            "stable",
            "rev_only",
            "conanfile.py",
        )
        .await;

        let (status, _body) = f
            .get(format!("/{}/v2/conans/scopelib/1.0/_/_/latest", f.repo_key))
            .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "_/_ namespace has no revisions; must 404",
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn recipe_revisions_scopes_to_default_user_channel() {
        let Some(f) = test_helpers::TestFixture::setup("local").await else {
            return;
        };

        // Two revisions under _/_, two under myuser/stable. The _/_ query
        // must return only the two _/_ revisions.
        for rev in ["rev_a", "rev_b"] {
            let _ = test_helpers::seed_recipe_row(
                &f.pool,
                f.repo_id,
                "scopelib",
                "1.0",
                "_",
                "_",
                rev,
                "conanfile.py",
            )
            .await;
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        for rev in ["rev_x", "rev_y"] {
            let _ = test_helpers::seed_recipe_row(
                &f.pool,
                f.repo_id,
                "scopelib",
                "1.0",
                "myuser",
                "stable",
                rev,
                "conanfile.py",
            )
            .await;
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        let (status, body) = f
            .get(format!(
                "/{}/v2/conans/scopelib/1.0/_/_/revisions",
                f.repo_key
            ))
            .await;
        let body_str = String::from_utf8_lossy(&body).to_string();
        assert_eq!(status, StatusCode::OK, "body: {}", body_str);

        let json: serde_json::Value = serde_json::from_slice(&body).expect("JSON");
        let revisions = json
            .get("revisions")
            .and_then(|v| v.as_array())
            .expect("revisions array");
        let names: Vec<&str> = revisions
            .iter()
            .filter_map(|r| r.get("revision").and_then(|v| v.as_str()))
            .collect();
        assert_eq!(
            names.len(),
            2,
            "_/_ revisions must not include myuser/stable rows; got: {:?}",
            names,
        );
        assert!(names.contains(&"rev_a"));
        assert!(names.contains(&"rev_b"));
        assert!(
            !names.contains(&"rev_x") && !names.contains(&"rev_y"),
            "myuser/stable revisions leaked into _/_ response: {:?}",
            names,
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn recipe_revisions_scopes_to_custom_user_channel() {
        let Some(f) = test_helpers::TestFixture::setup("local").await else {
            return;
        };

        let _ = test_helpers::seed_recipe_row(
            &f.pool,
            f.repo_id,
            "scopelib",
            "1.0",
            "_",
            "_",
            "rev_default",
            "conanfile.py",
        )
        .await;
        let _ = test_helpers::seed_recipe_row(
            &f.pool,
            f.repo_id,
            "scopelib",
            "1.0",
            "myuser",
            "stable",
            "rev_user_stable",
            "conanfile.py",
        )
        .await;

        let (status, body) = f
            .get(format!(
                "/{}/v2/conans/scopelib/1.0/myuser/stable/revisions",
                f.repo_key
            ))
            .await;
        let body_str = String::from_utf8_lossy(&body).to_string();
        assert_eq!(status, StatusCode::OK, "body: {}", body_str);

        let json: serde_json::Value = serde_json::from_slice(&body).expect("JSON");
        let revisions = json
            .get("revisions")
            .and_then(|v| v.as_array())
            .expect("revisions array");
        let names: Vec<&str> = revisions
            .iter()
            .filter_map(|r| r.get("revision").and_then(|v| v.as_str()))
            .collect();
        assert_eq!(names, vec!["rev_user_stable"], "got: {}", body_str);

        f.teardown().await;
    }

    // -----------------------------------------------------------------------
    // Agent 1 — users_authenticate, check_credentials, search handlers.
    //
    // All tests are DB-backed and no-op when `DATABASE_URL` is unreachable.
    // -----------------------------------------------------------------------
    #[allow(clippy::disallowed_methods)]
    // streaming-invariant: test module exempt — buffering response bodies in test assertions is not an artifact path (#1608)
    #[cfg(test)]
    mod agent1_auth_search {
        use super::test_helpers::*;
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;
        use uuid::Uuid;

        // ---------------- users_authenticate ----------------

        /// Regression for issue #1433. The authenticate endpoint used to echo
        /// back the base64 Basic credential as the "token". Conan then sent
        /// that string as `Authorization: Bearer <token>`, which the Bearer
        /// validator rejected (it is not a JWT or API token), so every
        /// privileged action returned 401.
        ///
        /// This test proves the body is now a signed JWT access token that the
        /// same AuthService used by the middleware validates back to the
        /// authenticating user, so it works as a Bearer credential.
        #[tokio::test]
        async fn users_authenticate_returns_jwt_valid_for_bearer() {
            use crate::services::auth_service::AuthService;
            use std::sync::Arc;

            let Some(f) = TestFixture::setup("local").await else {
                return;
            };

            let app = f.router();
            let basic = basic_auth(&f.username, "irrelevant");
            let basic_payload = basic.strip_prefix("Basic ").unwrap().to_string();
            let req = Request::builder()
                .method("POST")
                .uri(format!("/{}/v2/users/authenticate", f.repo_key))
                .header("Authorization", &basic)
                .body(Body::empty())
                .expect("build request");

            let (status, body) = send(app, req).await;
            assert_eq!(status, StatusCode::OK, "body={:?}", body);

            let token = String::from_utf8_lossy(&body).to_string();
            assert!(
                !token.is_empty(),
                "authenticate must return a non-empty token"
            );
            assert_ne!(
                token, basic_payload,
                "authenticate must not echo the base64 Basic credential back (issue #1433)",
            );

            // The returned token must validate as a JWT access token through the
            // exact path the Bearer auth middleware uses, and resolve to the
            // authenticating user.
            let auth_service = AuthService::new(f.pool.clone(), Arc::new(f.state.config.clone()));
            let claims = auth_service
                .validate_access_token_async(&token)
                .await
                .expect("authenticate token must validate as a Bearer JWT");
            assert_eq!(
                claims.sub, f.user_id,
                "JWT subject must be the authenticating user",
            );

            f.teardown().await;
        }

        #[tokio::test]
        async fn users_authenticate_404_when_repo_missing() {
            let Some(f) = TestFixture::setup("local").await else {
                return;
            };

            let bogus_key = format!("nonexistent-{}", Uuid::new_v4());
            let app = f.router();
            let req = Request::builder()
                .method("POST")
                .uri(format!("/{}/v2/users/authenticate", bogus_key))
                .header("Authorization", basic_auth(&f.username, "irrelevant"))
                .body(Body::empty())
                .expect("build request");

            let (status, _body) = send(app, req).await;
            assert_eq!(status, StatusCode::NOT_FOUND);

            f.teardown().await;
        }

        /// Coverage for the post-`require_auth_basic` user lookup in
        /// `users_authenticate`. The PR #1488 fix loads the user row from the
        /// database to mint a JWT; if `AuthExtension.user_id` does not resolve
        /// to an active row (account deleted between request arrival and the
        /// handler running, or deactivated), the handler must return 401 with
        /// `WWW-Authenticate: Basic realm="conan"` rather than mint a token
        /// for a phantom user.
        ///
        /// Exercises the `ok_or_else` UNAUTHORIZED branch of the
        /// `fetch_optional` result, which the happy-path test
        /// `users_authenticate_returns_jwt_valid_for_bearer` does not reach.
        /// Covered for both the user-id-does-not-exist case and the
        /// is_active=false case (both filtered by the same SQL `WHERE`).
        #[tokio::test]
        async fn users_authenticate_401_when_user_row_missing_or_inactive() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (real_user_id, real_username, _pw) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());

            // Case 1: AuthExtension carries a user_id that does not exist in
            // the `users` table at all (e.g. row deleted after auth middleware
            // resolved the credential). The SQL `fetch_optional` returns None
            // and the handler must 401 via the `ok_or_else` closure.
            let phantom_user_id = Uuid::new_v4();
            let phantom_auth = make_auth(phantom_user_id, "phantom-user");
            let app = router_with_auth(state.clone(), phantom_auth);
            let req = Request::builder()
                .method("POST")
                .uri(format!("/{}/v2/users/authenticate", repo_key))
                .header("Authorization", basic_auth("phantom-user", "irrelevant"))
                .body(Body::empty())
                .expect("build request");
            let resp = app.oneshot(req).await.expect("oneshot");
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "phantom user_id must not mint a JWT",
            );
            let www = resp
                .headers()
                .get("WWW-Authenticate")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            assert!(
                www.contains("Basic") && www.contains("conan"),
                "phantom-user 401 must advertise Basic realm=\"conan\", got: {}",
                www,
            );
            let body = to_bytes(resp.into_body(), 4096)
                .await
                .expect("collect body");
            assert_eq!(
                &body[..],
                b"Authentication required",
                "phantom-user 401 body must be the handler's literal, not a JWT",
            );

            // Case 2: AuthExtension carries the real user_id but the row was
            // flipped to is_active=false. The same SQL filter (`AND is_active
            // = true`) excludes it, and the handler must 401 the same way.
            // This proves the inactive-user branch is also defended.
            sqlx::query("UPDATE users SET is_active = false WHERE id = $1")
                .bind(real_user_id)
                .execute(&pool)
                .await
                .expect("deactivate user");

            let real_auth = make_auth(real_user_id, &real_username);
            let app2 = router_with_auth(state, real_auth);
            let req2 = Request::builder()
                .method("POST")
                .uri(format!("/{}/v2/users/authenticate", repo_key))
                .header("Authorization", basic_auth(&real_username, "irrelevant"))
                .body(Body::empty())
                .expect("build request");
            let (status2, body2) = send(app2, req2).await;
            assert_eq!(
                status2,
                StatusCode::UNAUTHORIZED,
                "deactivated user must not mint a JWT, body={:?}",
                body2,
            );
            assert_eq!(
                &body2[..],
                b"Authentication required",
                "deactivated-user 401 body must be the handler's literal",
            );

            cleanup(&pool, repo_id, real_user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }

        #[tokio::test]
        async fn users_authenticate_400_when_repo_wrong_format() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, username, _pw) = create_user(&pool).await;
            // Seed a non-conan (maven) repository directly so
            // resolve_conan_repo rejects it with a 400 "not a Conan repo" body.
            let repo_id = Uuid::new_v4();
            let repo_key = format!("mvn-test-{}", repo_id);
            let storage_dir = std::env::temp_dir().join(format!("mvn-test-{}", repo_id));
            std::fs::create_dir_all(&storage_dir).expect("create storage dir");
            sqlx::query(
                "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
                 VALUES ($1, $2, $3, $4, 'local'::repository_type, 'maven'::repository_format)",
            )
            .bind(repo_id)
            .bind(&repo_key)
            .bind(format!("mvn-test-{}", repo_id))
            .bind(storage_dir.to_string_lossy().as_ref())
            .execute(&pool)
            .await
            .expect("seed maven repo");

            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
            let auth = make_auth(user_id, &username);
            let app = router_with_auth(state, auth);
            let req = Request::builder()
                .method("POST")
                .uri(format!("/{}/v2/users/authenticate", repo_key))
                .header("Authorization", basic_auth(&username, "irrelevant"))
                .body(Body::empty())
                .expect("build request");

            let (status, _body) = send(app, req).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "wrong-format repo should fail resolve_conan_repo with 400",
            );

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }

        #[tokio::test]
        async fn users_authenticate_401_when_anon() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, _username, _pw) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());

            let app = router_anon(state);
            let req = Request::builder()
                .method("POST")
                .uri(format!("/{}/v2/users/authenticate", repo_key))
                .body(Body::empty())
                .expect("build request");

            let resp = app.oneshot(req).await.expect("oneshot");
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            let www = resp
                .headers()
                .get("WWW-Authenticate")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            assert!(
                www.contains("Basic") && www.contains("conan"),
                "WWW-Authenticate header must advertise Basic realm=\"conan\", got: {}",
                www,
            );

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }

        // ---------------- check_credentials ----------------

        #[tokio::test]
        async fn check_credentials_200_empty_body() {
            let Some(f) = TestFixture::setup("local").await else {
                return;
            };

            let (status, body) = f
                .get(format!("/{}/v2/users/check_credentials", f.repo_key))
                .await;
            assert_eq!(status, StatusCode::OK);
            assert!(
                body.is_empty(),
                "check_credentials should return an empty body on success, got {} bytes",
                body.len(),
            );

            f.teardown().await;
        }

        #[tokio::test]
        async fn check_credentials_404_when_repo_missing() {
            let Some(f) = TestFixture::setup("local").await else {
                return;
            };

            let bogus_key = format!("nonexistent-{}", Uuid::new_v4());
            let (status, _body) = f
                .get(format!("/{}/v2/users/check_credentials", bogus_key))
                .await;
            assert_eq!(status, StatusCode::NOT_FOUND);

            f.teardown().await;
        }

        #[tokio::test]
        async fn check_credentials_401_when_anon() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, _username, _pw) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());

            let app = router_anon(state);
            let req = Request::builder()
                .method("GET")
                .uri(format!("/{}/v2/users/check_credentials", repo_key))
                .body(Body::empty())
                .expect("build request");

            let (status, _body) = send(app, req).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }

        // ---------------- search ----------------

        async fn parse_search_results(body: &bytes::Bytes) -> Vec<String> {
            let json: serde_json::Value = serde_json::from_slice(body).expect("body is JSON");
            json.get("results")
                .and_then(|v| v.as_array())
                .expect("results array")
                .iter()
                .map(|v| v.as_str().expect("result is string").to_string())
                .collect()
        }

        #[tokio::test]
        async fn search_empty_repo_returns_empty_results() {
            let Some(f) = TestFixture::setup("local").await else {
                return;
            };

            let (status, body) = f.get(format!("/{}/v2/conans/search", f.repo_key)).await;
            assert_eq!(status, StatusCode::OK);
            let results = parse_search_results(&body).await;
            assert!(results.is_empty(), "expected no results, got {:?}", results);

            f.teardown().await;
        }

        #[tokio::test]
        async fn search_single_recipe_returns_one_reference() {
            let Some(f) = TestFixture::setup("local").await else {
                return;
            };

            let _ = seed_recipe_row(
                &f.pool,
                f.repo_id,
                "zlib",
                "1.3",
                "_",
                "_",
                "rev1",
                "conanfile.py",
            )
            .await;

            let (status, body) = f.get(format!("/{}/v2/conans/search", f.repo_key)).await;
            assert_eq!(status, StatusCode::OK);
            let results = parse_search_results(&body).await;
            assert_eq!(results, vec!["zlib/1.3@_/_".to_string()]);

            f.teardown().await;
        }

        #[tokio::test]
        async fn search_deduplicates_across_revisions_and_files() {
            let Some(f) = TestFixture::setup("local").await else {
                return;
            };

            // Three rows but only two distinct (name, version) pairs.
            for (n, v, rev, file) in [
                ("fmt", "9.1", "rev1", "conanfile.py"),
                ("fmt", "9.1", "rev2", "conanmanifest.txt"),
                ("boost", "1.82", "rev1", "conanfile.py"),
            ] {
                let _ = seed_recipe_row(&f.pool, f.repo_id, n, v, "_", "_", rev, file).await;
            }

            let (_status, body) = f.get(format!("/{}/v2/conans/search", f.repo_key)).await;
            let results = parse_search_results(&body).await;
            assert_eq!(
                results,
                vec!["boost/1.82@_/_".to_string(), "fmt/9.1@_/_".to_string()],
                "expected de-duplicated, name-ASC-ordered results",
            );

            f.teardown().await;
        }

        #[tokio::test]
        async fn search_glob_wildcard_filters_by_prefix() {
            let Some(f) = TestFixture::setup("local").await else {
                return;
            };

            for (n, v) in [("zlib", "1.3"), ("zstd", "1.5.5"), ("boost", "1.82")] {
                let _ = seed_recipe_row(&f.pool, f.repo_id, n, v, "_", "_", "rev1", "conanfile.py")
                    .await;
            }

            let (status, body) = f
                .get(format!("/{}/v2/conans/search?q=z*", f.repo_key))
                .await;
            assert_eq!(status, StatusCode::OK);
            let results = parse_search_results(&body).await;
            assert_eq!(
                results,
                vec!["zlib/1.3@_/_".to_string(), "zstd/1.5.5@_/_".to_string()],
                "glob z* must match zlib + zstd but exclude boost",
            );

            f.teardown().await;
        }

        #[tokio::test]
        async fn search_missing_q_defaults_to_match_all() {
            let Some(f) = TestFixture::setup("local").await else {
                return;
            };

            let _ = seed_recipe_row(
                &f.pool,
                f.repo_id,
                "libcurl",
                "8.5",
                "_",
                "_",
                "rev1",
                "conanfile.py",
            )
            .await;

            let (status, body) = f.get(format!("/{}/v2/conans/search", f.repo_key)).await;
            assert_eq!(status, StatusCode::OK);
            let results = parse_search_results(&body).await;
            assert_eq!(results, vec!["libcurl/8.5@_/_".to_string()]);

            f.teardown().await;
        }

        #[tokio::test]
        async fn search_excludes_soft_deleted_artifacts() {
            let Some(f) = TestFixture::setup("local").await else {
                return;
            };

            let visible = seed_recipe_row(
                &f.pool,
                f.repo_id,
                "openssl",
                "3.2",
                "_",
                "_",
                "rev1",
                "conanfile.py",
            )
            .await;
            let hidden = seed_recipe_row(
                &f.pool,
                f.repo_id,
                "sqlite3",
                "3.45",
                "_",
                "_",
                "rev1",
                "conanfile.py",
            )
            .await;
            sqlx::query("UPDATE artifacts SET is_deleted = true WHERE id = $1")
                .bind(hidden)
                .execute(&f.pool)
                .await
                .expect("soft-delete artifact");

            let (_status, body) = f.get(format!("/{}/v2/conans/search", f.repo_key)).await;
            let results = parse_search_results(&body).await;
            assert_eq!(
                results,
                vec!["openssl/3.2@_/_".to_string()],
                "soft-deleted sqlite3 must not appear in search output",
            );
            assert_ne!(visible, hidden);

            f.teardown().await;
        }

        #[tokio::test]
        async fn search_returns_real_user_channel_and_version_from_metadata() {
            let Some(f) = TestFixture::setup("local").await else {
                return;
            };

            let _ = seed_recipe_row(
                &f.pool,
                f.repo_id,
                "mylib",
                "2.5.1",
                "myorg",
                "stable",
                "rev1",
                "conanfile.py",
            )
            .await;

            let (status, body) = f.get(format!("/{}/v2/conans/search", f.repo_key)).await;
            assert_eq!(status, StatusCode::OK);
            let results = parse_search_results(&body).await;
            assert_eq!(
                results,
                vec!["mylib/2.5.1@myorg/stable".to_string()],
                "search response must use real user/channel/version from metadata",
            );

            f.teardown().await;
        }
    }

    // ========================================================================
    // Agent 3 — recipe_file_upload + package-side read handlers.
    // ========================================================================
    #[cfg(test)]
    mod agent3_mixed {
        use super::test_helpers::*;
        use axum::body::Body;
        use axum::http::{Request, StatusCode};

        // Short helper to make GET requests (used by tests that haven't been
        // migrated to TestFixture yet).
        async fn get_json(
            app: axum::Router,
            uri: String,
            username: &str,
        ) -> (StatusCode, bytes::Bytes) {
            let req = Request::builder()
                .method("GET")
                .uri(uri)
                .header("Authorization", basic_auth(username, "irrelevant"))
                .body(Body::empty())
                .expect("build request");
            send(app, req).await
        }

        // ================================================================
        // recipe_file_upload
        // ================================================================

        #[tokio::test]
        async fn recipe_file_upload_fresh_created_201_and_persists() {
            let Some(f) = TestFixture::setup("local").await else {
                return;
            };

            let body_bytes = sample_conanfile_py();
            let status = upload_recipe_file(
                &f.state,
                &f.auth,
                &f.repo_key,
                "uplib",
                "1.0",
                "_",
                "_",
                "rev1",
                "conanfile.py",
                body_bytes,
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);

            // Verify the artifact row + metadata landed.
            let art_path = "uplib/1.0/_/_/revisions/rev1/files/conanfile.py".to_string();
            let checksum: String = sqlx::query_scalar(
                "SELECT checksum_sha256 FROM artifacts \
                 WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
            )
            .bind(f.repo_id)
            .bind(&art_path)
            .fetch_one(&f.pool)
            .await
            .expect("artifact row must exist");

            let meta_type: String = sqlx::query_scalar(
                "SELECT am.metadata->>'type' FROM artifact_metadata am \
                 JOIN artifacts a ON a.id = am.artifact_id \
                 WHERE a.repository_id = $1 AND a.path = $2 AND a.is_deleted = false",
            )
            .bind(f.repo_id)
            .bind(&art_path)
            .fetch_one(&f.pool)
            .await
            .expect("metadata row must exist");
            assert_eq!(meta_type, "recipe");

            let meta_format: String = sqlx::query_scalar(
                "SELECT am.format::text FROM artifact_metadata am \
                 JOIN artifacts a ON a.id = am.artifact_id \
                 WHERE a.repository_id = $1 AND a.path = $2 AND a.is_deleted = false",
            )
            .bind(f.repo_id)
            .bind(&art_path)
            .fetch_one(&f.pool)
            .await
            .expect("format");
            assert_eq!(meta_format, "conan");

            use sha2::{Digest, Sha256};
            let expected = format!("{:x}", Sha256::digest(body_bytes));
            assert_eq!(checksum, expected);

            f.teardown().await;
        }

        #[tokio::test]
        async fn recipe_file_upload_reupload_soft_deletes_prior() {
            let Some(f) = TestFixture::setup("local").await else {
                return;
            };

            // First upload.
            let s1 = upload_recipe_file(
                &f.state,
                &f.auth,
                &f.repo_key,
                "relib",
                "1.0",
                "_",
                "_",
                "rev1",
                "conanfile.py",
                b"first-bytes-v1",
            )
            .await;
            assert_eq!(s1, StatusCode::CREATED);

            // Second upload with different bytes at the same path.
            let new_body: &[u8] = b"second-bytes-v2-different";
            let s2 = upload_recipe_file(
                &f.state,
                &f.auth,
                &f.repo_key,
                "relib",
                "1.0",
                "_",
                "_",
                "rev1",
                "conanfile.py",
                new_body,
            )
            .await;
            assert_eq!(s2, StatusCode::CREATED);

            // Exactly one non-deleted row at that path.
            let art_path = "relib/1.0/_/_/revisions/rev1/files/conanfile.py".to_string();
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
            )
            .bind(f.repo_id)
            .bind(&art_path)
            .fetch_one(&f.pool)
            .await
            .expect("count query");
            assert_eq!(count, 1, "re-upload must leave exactly one live row");

            use sha2::{Digest, Sha256};
            let want = format!("{:x}", Sha256::digest(new_body));
            let got: String = sqlx::query_scalar(
                "SELECT checksum_sha256 FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
            )
            .bind(f.repo_id)
            .bind(&art_path)
            .fetch_one(&f.pool)
            .await
            .expect("checksum");
            assert_eq!(got, want);

            f.teardown().await;
        }

        #[tokio::test]
        async fn recipe_file_upload_401_when_anonymous() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, _username, _pw) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());

            let app = router_anon(state.clone());
            let uri = format!(
                "/{}/v2/conans/anonlib/1.0/_/_/revisions/rev1/files/conanfile.py",
                repo_key
            );
            let req = Request::builder()
                .method("PUT")
                .uri(uri)
                .body(Body::from(sample_conanfile_py().to_vec()))
                .expect("build req");
            let (status, _body) = send(app, req).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }

        #[tokio::test]
        async fn recipe_file_upload_405_on_remote_repo() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, username, _pw) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "remote").await;
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
            let auth = make_auth(user_id, &username);

            let status = upload_recipe_file(
                &state,
                &auth,
                &repo_key,
                "rl",
                "1.0",
                "_",
                "_",
                "rev1",
                "conanfile.py",
                sample_conanfile_py(),
            )
            .await;
            assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }

        #[tokio::test]
        async fn recipe_file_upload_400_on_virtual_repo() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, username, _pw) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "virtual").await;
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
            let auth = make_auth(user_id, &username);

            let status = upload_recipe_file(
                &state,
                &auth,
                &repo_key,
                "vl",
                "1.0",
                "_",
                "_",
                "rev1",
                "conanfile.py",
                sample_conanfile_py(),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }

        #[tokio::test]
        async fn recipe_file_upload_bumps_repository_updated_at() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, username, _pw) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
            let auth = make_auth(user_id, &username);

            let before: chrono::DateTime<chrono::Utc> =
                sqlx::query_scalar("SELECT updated_at FROM repositories WHERE id = $1")
                    .bind(repo_id)
                    .fetch_one(&pool)
                    .await
                    .expect("before updated_at");

            tokio::time::sleep(std::time::Duration::from_millis(20)).await;

            let status = upload_recipe_file(
                &state,
                &auth,
                &repo_key,
                "stamp",
                "1.0",
                "_",
                "_",
                "rev1",
                "conanfile.py",
                sample_conanfile_py(),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);

            let after: chrono::DateTime<chrono::Utc> =
                sqlx::query_scalar("SELECT updated_at FROM repositories WHERE id = $1")
                    .bind(repo_id)
                    .fetch_one(&pool)
                    .await
                    .expect("after updated_at");
            assert!(
                after > before,
                "updated_at must advance after upload (before={before}, after={after})"
            );

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }

        // ================================================================
        // package_latest
        // ================================================================

        #[tokio::test]
        async fn package_latest_returns_newer_revision() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, username, _pw) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
            let auth = make_auth(user_id, &username);

            let _ = seed_package_row(
                &pool,
                repo_id,
                "plib",
                "1.0",
                "_",
                "_",
                "rrev",
                "pid",
                "pkg_old",
                "conan_package.tgz",
            )
            .await;
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            let _ = seed_package_row(
                &pool,
                repo_id,
                "plib",
                "1.0",
                "_",
                "_",
                "rrev",
                "pid",
                "pkg_new",
                "conaninfo.txt",
            )
            .await;

            let app = router_with_auth(state.clone(), auth.clone());
            let uri = format!(
                "/{}/v2/conans/plib/1.0/_/_/revisions/rrev/packages/pid/latest",
                repo_key
            );
            let (status, body) = get_json(app, uri, &username).await;
            assert_eq!(status, StatusCode::OK);
            let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
            assert_eq!(json["revision"], "pkg_new");

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }

        #[tokio::test]
        async fn package_latest_404_when_no_rows_match() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, username, _pw) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
            let auth = make_auth(user_id, &username);

            let app = router_with_auth(state.clone(), auth.clone());
            let uri = format!(
                "/{}/v2/conans/nothing/1.0/_/_/revisions/r/packages/pid/latest",
                repo_key
            );
            let (status, _body) = get_json(app, uri, &username).await;
            assert_eq!(status, StatusCode::NOT_FOUND);

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }

        #[tokio::test]
        async fn package_latest_404_when_package_id_mismatches_existing_recipe_rev() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, username, _pw) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
            let auth = make_auth(user_id, &username);

            // Recipe revision exists, but packageId 'pid-other' will not.
            let _ = seed_package_row(
                &pool,
                repo_id,
                "lib",
                "1.0",
                "_",
                "_",
                "rrev",
                "pid-here",
                "pkgrev",
                "conan_package.tgz",
            )
            .await;

            let app = router_with_auth(state.clone(), auth.clone());
            let uri = format!(
                "/{}/v2/conans/lib/1.0/_/_/revisions/rrev/packages/pid-other/latest",
                repo_key
            );
            let (status, _body) = get_json(app, uri, &username).await;
            assert_eq!(status, StatusCode::NOT_FOUND);

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }

        /// Tiebreaker test: two package rows with identical created_at values
        /// must still yield a deterministic winner. Paired with the fix
        /// `fix(conan): stable tiebreaker for package_latest ordering` —
        /// before that fix, ORDER BY created_at DESC alone picks an
        /// indeterminate row when timestamps collide.
        #[tokio::test]
        async fn package_latest_tiebreaker_is_deterministic() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, username, _pw) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
            let auth = make_auth(user_id, &username);

            let a1 = seed_package_row(
                &pool,
                repo_id,
                "tblib",
                "1.0",
                "_",
                "_",
                "rrev",
                "pid",
                "pkg_A",
                "conan_package.tgz",
            )
            .await;
            let a2 = seed_package_row(
                &pool,
                repo_id,
                "tblib",
                "1.0",
                "_",
                "_",
                "rrev",
                "pid",
                "pkg_B",
                "conaninfo.txt",
            )
            .await;

            // Force identical created_at on both rows.
            sqlx::query("UPDATE artifacts SET created_at = NOW() WHERE id = ANY($1::uuid[])")
                .bind(vec![a1, a2])
                .execute(&pool)
                .await
                .expect("normalize created_at");

            // Expected winner under `ORDER BY created_at DESC, id DESC`: max(id).
            let (winner_id, winner_label) = if a1 > a2 {
                (a1, "pkg_A")
            } else {
                (a2, "pkg_B")
            };
            let _ = winner_id;

            let app = router_with_auth(state.clone(), auth.clone());
            let uri = format!(
                "/{}/v2/conans/tblib/1.0/_/_/revisions/rrev/packages/pid/latest",
                repo_key
            );
            let (status, body) = get_json(app, uri, &username).await;
            assert_eq!(status, StatusCode::OK);
            let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
            assert_eq!(
                json["revision"], winner_label,
                "tiebreaker must pick the row with the lexicographically greater UUID"
            );

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }

        // ================================================================
        // package_revisions
        // ================================================================

        #[tokio::test]
        async fn package_revisions_empty_returns_empty_array() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, username, _pw) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
            let auth = make_auth(user_id, &username);

            let app = router_with_auth(state.clone(), auth.clone());
            let uri = format!(
                "/{}/v2/conans/nolib/1.0/_/_/revisions/r/packages/pid/revisions",
                repo_key
            );
            let (status, body) = get_json(app, uri, &username).await;
            assert_eq!(status, StatusCode::OK);
            let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
            let arr = json
                .get("revisions")
                .and_then(|v| v.as_array())
                .expect("revisions array");
            assert!(arr.is_empty(), "expected empty revisions");

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }

        #[tokio::test]
        async fn package_revisions_multiple_in_desc_order() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, username, _pw) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
            let auth = make_auth(user_id, &username);

            let _ = seed_package_row(
                &pool,
                repo_id,
                "rlib",
                "1.0",
                "_",
                "_",
                "rrev",
                "pid",
                "pkg_old",
                "conan_package.tgz",
            )
            .await;
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            let _ = seed_package_row(
                &pool,
                repo_id,
                "rlib",
                "1.0",
                "_",
                "_",
                "rrev",
                "pid",
                "pkg_new",
                "conaninfo.txt",
            )
            .await;

            let app = router_with_auth(state.clone(), auth.clone());
            let uri = format!(
                "/{}/v2/conans/rlib/1.0/_/_/revisions/rrev/packages/pid/revisions",
                repo_key
            );
            let (status, body) = get_json(app, uri, &username).await;
            assert_eq!(status, StatusCode::OK);
            let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
            let arr = json["revisions"].as_array().expect("revisions array");
            assert_eq!(arr.len(), 2);
            assert_eq!(arr[0]["revision"], "pkg_new");
            assert_eq!(arr[1]["revision"], "pkg_old");

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }

        #[tokio::test]
        async fn package_revisions_filters_soft_deleted() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, username, _pw) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
            let auth = make_auth(user_id, &username);

            let deleted_id = seed_package_row(
                &pool,
                repo_id,
                "slib",
                "1.0",
                "_",
                "_",
                "rrev",
                "pid",
                "pkg_deleted",
                "conan_package.tgz",
            )
            .await;
            let _live = seed_package_row(
                &pool,
                repo_id,
                "slib",
                "1.0",
                "_",
                "_",
                "rrev",
                "pid",
                "pkg_alive",
                "conaninfo.txt",
            )
            .await;

            sqlx::query("UPDATE artifacts SET is_deleted = true WHERE id = $1")
                .bind(deleted_id)
                .execute(&pool)
                .await
                .expect("soft-delete");

            let app = router_with_auth(state.clone(), auth.clone());
            let uri = format!(
                "/{}/v2/conans/slib/1.0/_/_/revisions/rrev/packages/pid/revisions",
                repo_key
            );
            let (status, body) = get_json(app, uri, &username).await;
            assert_eq!(status, StatusCode::OK);
            let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
            let arr = json["revisions"].as_array().expect("array");
            assert_eq!(arr.len(), 1, "soft-deleted rows must be filtered");
            assert_eq!(arr[0]["revision"], "pkg_alive");

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }

        // ================================================================
        // package_files_list
        // ================================================================

        #[tokio::test]
        async fn package_files_list_empty_revision_returns_empty_files() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, username, _pw) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
            let auth = make_auth(user_id, &username);

            let app = router_with_auth(state.clone(), auth.clone());
            let uri = format!(
                "/{}/v2/conans/elib/1.0/_/_/revisions/r/packages/pid/revisions/pr/files",
                repo_key
            );
            let (status, body) = get_json(app, uri, &username).await;
            assert_eq!(status, StatusCode::OK);
            let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
            let files = json["files"].as_object().expect("files object");
            assert!(files.is_empty(), "expected empty files object");

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }

        #[tokio::test]
        async fn package_files_list_includes_all_filenames() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, username, _pw) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
            let auth = make_auth(user_id, &username);

            for fname in ["conan_package.tgz", "conaninfo.txt", "conanmanifest.txt"] {
                let _ = seed_package_row(
                    &pool, repo_id, "mlib", "1.0", "_", "_", "rrev", "pid", "pkgrev", fname,
                )
                .await;
            }

            let app = router_with_auth(state.clone(), auth.clone());
            let uri = format!(
                "/{}/v2/conans/mlib/1.0/_/_/revisions/rrev/packages/pid/revisions/pkgrev/files",
                repo_key
            );
            let (status, body) = get_json(app, uri, &username).await;
            assert_eq!(status, StatusCode::OK);
            let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
            let files = json["files"].as_object().expect("files object");
            for fname in ["conan_package.tgz", "conaninfo.txt", "conanmanifest.txt"] {
                assert!(files.contains_key(fname), "missing file: {}", fname);
            }

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }

        #[tokio::test]
        async fn package_files_list_scoped_by_package_revision() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, username, _pw) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
            let auth = make_auth(user_id, &username);

            // Two pkg revisions with overlapping file names. Scope query to
            // pr_A and assert pr_B's files are absent.
            let _ = seed_package_row(
                &pool,
                repo_id,
                "slib",
                "1.0",
                "_",
                "_",
                "rrev",
                "pid",
                "pr_A",
                "only_in_A.tgz",
            )
            .await;
            let _ = seed_package_row(
                &pool,
                repo_id,
                "slib",
                "1.0",
                "_",
                "_",
                "rrev",
                "pid",
                "pr_A",
                "conaninfo.txt",
            )
            .await;
            let _ = seed_package_row(
                &pool,
                repo_id,
                "slib",
                "1.0",
                "_",
                "_",
                "rrev",
                "pid",
                "pr_B",
                "only_in_B.tgz",
            )
            .await;
            let _ = seed_package_row(
                &pool,
                repo_id,
                "slib",
                "1.0",
                "_",
                "_",
                "rrev",
                "pid",
                "pr_B",
                "conaninfo.txt",
            )
            .await;

            let app = router_with_auth(state.clone(), auth.clone());
            let uri = format!(
                "/{}/v2/conans/slib/1.0/_/_/revisions/rrev/packages/pid/revisions/pr_A/files",
                repo_key
            );
            let (status, body) = get_json(app, uri, &username).await;
            assert_eq!(status, StatusCode::OK);
            let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
            let files = json["files"].as_object().expect("files object");
            assert!(files.contains_key("only_in_A.tgz"));
            assert!(files.contains_key("conaninfo.txt"));
            assert!(
                !files.contains_key("only_in_B.tgz"),
                "pr_A query must NOT see pr_B's unique file"
            );

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }

        // ================================================================
        // package_file_download
        // ================================================================

        #[tokio::test]
        async fn package_file_download_hosted_happy_path() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, username, _pw) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
            let auth = make_auth(user_id, &username);

            // Upload via handler so bytes actually land on disk with matching
            // storage_key + checksum. Seeded rows use a synthetic checksum.
            let pkg_bytes = sample_conan_package_tgz();
            let s = upload_package_file(
                &state,
                &auth,
                &repo_key,
                "dlib",
                "1.0",
                "_",
                "_",
                "rrev",
                "pid",
                "pkgrev",
                "conan_package.tgz",
                &pkg_bytes,
            )
            .await;
            assert_eq!(s, StatusCode::CREATED);

            let app = router_with_auth(state.clone(), auth.clone());
            let uri = format!(
                "/{}/v2/conans/dlib/1.0/_/_/revisions/rrev/packages/pid/revisions/pkgrev/files/conan_package.tgz",
                repo_key
            );
            let req = Request::builder()
                .method("GET")
                .uri(uri)
                .header("Authorization", basic_auth(&username, "irrelevant"))
                .body(Body::empty())
                .expect("build req");
            let (status, body) = send(app, req).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body.as_ref(), pkg_bytes.as_slice());

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }

        #[tokio::test]
        async fn package_file_download_hosted_missing_file_404() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, username, _pw) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
            let auth = make_auth(user_id, &username);

            let app = router_with_auth(state.clone(), auth.clone());
            let uri = format!(
                "/{}/v2/conans/miss/1.0/_/_/revisions/r/packages/pid/revisions/pr/files/nope.tgz",
                repo_key
            );
            let (status, _body) = get_json(app, uri, &username).await;
            assert_eq!(status, StatusCode::NOT_FOUND);

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }

        #[tokio::test]
        async fn package_file_download_remote_without_proxy_404() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, username, _pw) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "remote").await;
            // `build_state` wires no proxy_service, so remote-type repos
            // hit the not-found branch guard (state.proxy_service = None).
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
            let auth = make_auth(user_id, &username);

            let app = router_with_auth(state.clone(), auth.clone());
            let uri = format!(
                "/{}/v2/conans/remotelib/1.0/_/_/revisions/r/packages/pid/revisions/pr/files/x.tgz",
                repo_key
            );
            let (status, _body) = get_json(app, uri, &username).await;
            assert_eq!(status, StatusCode::NOT_FOUND);

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }

        #[tokio::test]
        async fn package_file_download_soft_deleted_returns_404() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, username, _pw) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
            let auth = make_auth(user_id, &username);

            let s = upload_package_file(
                &state,
                &auth,
                &repo_key,
                "sdlib",
                "1.0",
                "_",
                "_",
                "rrev",
                "pid",
                "pkgrev",
                "conan_package.tgz",
                &sample_conan_package_tgz(),
            )
            .await;
            assert_eq!(s, StatusCode::CREATED);

            sqlx::query("UPDATE artifacts SET is_deleted = true WHERE repository_id = $1")
                .bind(repo_id)
                .execute(&pool)
                .await
                .expect("soft-delete");

            let app = router_with_auth(state.clone(), auth.clone());
            let uri = format!(
                "/{}/v2/conans/sdlib/1.0/_/_/revisions/rrev/packages/pid/revisions/pkgrev/files/conan_package.tgz",
                repo_key
            );
            let (status, _body) = get_json(app, uri, &username).await;
            assert_eq!(status, StatusCode::NOT_FOUND);

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }
    }

    // ========================================================================
    // Agent 4 — package_file_upload happy paths + HIGH cleanup-bug regression
    // + cross-cutting write-path guards (remote/virtual 405/400, anon 401).
    // ========================================================================
    #[cfg(test)]
    mod agent4_package_writes {
        use super::test_helpers::*;
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use sha2::{Digest, Sha256};

        // ------------------------------------------------------------------
        // package_file_upload: fresh upload → 201 + artifact row + metadata
        // ------------------------------------------------------------------
        #[tokio::test]
        async fn package_file_upload_fresh_write_persists_artifact_and_metadata() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, username, _pw) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
            let auth = make_auth(user_id, &username);

            let body = sample_conan_package_tgz();
            let status = upload_package_file(
                &state,
                &auth,
                &repo_key,
                "zlib",
                "1.2.13",
                "_",
                "_",
                "recrev1",
                "pkgid1",
                "pkgrev1",
                "conan_package.tgz",
                &body,
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);

            let expected_path =
                "zlib/1.2.13/_/_/revisions/recrev1/packages/pkgid1/revisions/pkgrev1/files/conan_package.tgz";
            let expected_sha = format!("{:x}", Sha256::digest(&body));

            let row: (String, i64, String) = sqlx::query_as(
                "SELECT path, size_bytes, checksum_sha256 FROM artifacts \
                 WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
            )
            .bind(repo_id)
            .bind(expected_path)
            .fetch_one(&pool)
            .await
            .expect("artifact row must exist");
            assert_eq!(row.0, expected_path);
            assert_eq!(row.1, body.len() as i64);
            assert_eq!(row.2, expected_sha);

            let meta: (String, serde_json::Value) = sqlx::query_as(
                "SELECT am.format, am.metadata FROM artifact_metadata am \
                 JOIN artifacts a ON a.id = am.artifact_id \
                 WHERE a.repository_id = $1 AND a.path = $2",
            )
            .bind(repo_id)
            .bind(expected_path)
            .fetch_one(&pool)
            .await
            .expect("artifact_metadata row must exist");
            assert_eq!(meta.0, "conan");
            assert_eq!(meta.1["type"], "package");
            assert_eq!(meta.1["packageId"], "pkgid1");
            assert_eq!(meta.1["packageRevision"], "pkgrev1");
            assert_eq!(meta.1["revision"], "recrev1");
            assert_eq!(meta.1["file"], "conan_package.tgz");

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }

        // ------------------------------------------------------------------
        // package_file_upload: uploading three files under the same
        // (packageId, pkgRevision) → package_files_list returns all three.
        // ------------------------------------------------------------------
        #[tokio::test]
        async fn package_file_upload_multiple_files_list_returns_all() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, username, _pw) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
            let auth = make_auth(user_id, &username);

            for (file, bytes) in [
                ("conanmanifest.txt", sample_conanmanifest_txt().to_vec()),
                ("conaninfo.txt", sample_conaninfo_txt().to_vec()),
                ("conan_package.tgz", sample_conan_package_tgz()),
            ] {
                let status = upload_package_file(
                    &state, &auth, &repo_key, "boost", "1.80", "_", "_", "rec1", "pid", "prev",
                    file, &bytes,
                )
                .await;
                assert_eq!(status, StatusCode::CREATED, "upload of {} failed", file);
            }

            // Call the package_files_list handler via the router to prove the
            // files are queryable end-to-end.
            let app = router_with_auth(state.clone(), auth.clone());
            let uri = format!(
                "/{}/v2/conans/{}/{}/{}/{}/revisions/{}/packages/{}/revisions/{}/files",
                repo_key, "boost", "1.80", "_", "_", "rec1", "pid", "prev",
            );
            let req = Request::builder()
                .method("GET")
                .uri(uri)
                .header("Authorization", basic_auth(&username, "irrelevant"))
                .body(Body::empty())
                .expect("build request");
            let (status, body) = send(app, req).await;
            assert_eq!(status, StatusCode::OK);
            let json: serde_json::Value =
                serde_json::from_slice(&body).expect("files-list must be JSON");
            let files = json
                .get("files")
                .and_then(|v| v.as_object())
                .expect("files-list must contain a 'files' object");
            assert_eq!(files.len(), 3, "expected 3 files, got: {}", json);
            for name in ["conanmanifest.txt", "conaninfo.txt", "conan_package.tgz"] {
                assert!(
                    files.contains_key(name),
                    "missing file {} in {}",
                    name,
                    json
                );
            }

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }

        // ------------------------------------------------------------------
        // package_file_upload: the repository.updated_at is bumped forward.
        // ------------------------------------------------------------------
        #[tokio::test]
        async fn package_file_upload_bumps_repository_updated_at() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, username, _pw) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
            let auth = make_auth(user_id, &username);

            let before: chrono::DateTime<chrono::Utc> =
                sqlx::query_scalar("SELECT updated_at FROM repositories WHERE id = $1")
                    .bind(repo_id)
                    .fetch_one(&pool)
                    .await
                    .expect("read before-updated_at");

            // Sleep briefly so NOW() strictly exceeds `before`.
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;

            let status = upload_package_file(
                &state,
                &auth,
                &repo_key,
                "pkg",
                "1.0",
                "_",
                "_",
                "rec",
                "pid",
                "prev",
                "conan_package.tgz",
                &sample_conan_package_tgz(),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);

            let after: chrono::DateTime<chrono::Utc> =
                sqlx::query_scalar("SELECT updated_at FROM repositories WHERE id = $1")
                    .bind(repo_id)
                    .fetch_one(&pool)
                    .await
                    .expect("read after-updated_at");
            assert!(
                after > before,
                "updated_at must advance: before={} after={}",
                before,
                after,
            );

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }

        // ------------------------------------------------------------------
        // HIGH-bug regression (commit c4fc666): uploading to the same
        // (repo, path) twice must succeed. Before c4fc666, the second upload
        // collided with the soft-deleted row on UNIQUE(repository_id, path)
        // and returned 500 because cleanup_soft_deleted_artifact was not
        // called between the UPDATE (soft-delete) and the INSERT.
        // ------------------------------------------------------------------
        #[tokio::test]
        async fn package_file_upload_reupload_same_path_succeeds() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, username, _pw) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
            let auth = make_auth(user_id, &username);

            // First upload (v1 bytes)
            let body_v1 = sample_conan_package_tgz();
            let status1 = upload_package_file(
                &state,
                &auth,
                &repo_key,
                "fmt",
                "9.1.0",
                "_",
                "_",
                "rec",
                "pid",
                "prev",
                "conan_package.tgz",
                &body_v1,
            )
            .await;
            assert_eq!(status1, StatusCode::CREATED);

            // Second upload (DIFFERENT bytes) to the same path. Before the
            // fix in c4fc666 this returned 500 because the INSERT hit
            // UNIQUE(repository_id, path) against the row just soft-deleted.
            let mut body_v2 = sample_conan_package_tgz();
            body_v2.extend_from_slice(b"-v2-bytes-different");
            assert_ne!(body_v1, body_v2, "test bodies must differ");
            let status2 = upload_package_file(
                &state,
                &auth,
                &repo_key,
                "fmt",
                "9.1.0",
                "_",
                "_",
                "rec",
                "pid",
                "prev",
                "conan_package.tgz",
                &body_v2,
            )
            .await;
            assert_eq!(
                status2,
                StatusCode::CREATED,
                "re-upload to same path must return 201, not 500 (HIGH bug fixed in c4fc666)",
            );

            // Exactly one non-deleted artifacts row must remain at that path.
            let expected_path =
                "fmt/9.1.0/_/_/revisions/rec/packages/pid/revisions/prev/files/conan_package.tgz";
            let live_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM artifacts \
                 WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
            )
            .bind(repo_id)
            .bind(expected_path)
            .fetch_one(&pool)
            .await
            .expect("count live artifacts");
            assert_eq!(
                live_count, 1,
                "expected exactly one live row after re-upload"
            );

            // And the stored checksum must match the second upload's bytes.
            let expected_sha = format!("{:x}", Sha256::digest(&body_v2));
            let stored_sha: String = sqlx::query_scalar(
                "SELECT checksum_sha256 FROM artifacts \
                 WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
            )
            .bind(repo_id)
            .bind(expected_path)
            .fetch_one(&pool)
            .await
            .expect("read live checksum");
            assert_eq!(
                stored_sha, expected_sha,
                "stored checksum must match v2 bytes"
            );

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }

        // ------------------------------------------------------------------
        // Cross-cutting: reject_write_if_not_hosted on recipe uploads.
        // Remote repo → 405 METHOD_NOT_ALLOWED.
        // ------------------------------------------------------------------
        #[tokio::test]
        async fn recipe_file_upload_against_remote_repo_returns_405() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, username, _pw) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "remote").await;
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
            let auth = make_auth(user_id, &username);

            let status = upload_recipe_file(
                &state,
                &auth,
                &repo_key,
                "zlib",
                "1.2.13",
                "_",
                "_",
                "rec",
                "conanfile.py",
                sample_conanfile_py(),
            )
            .await;
            assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }

        // ------------------------------------------------------------------
        // Cross-cutting: reject_write_if_not_hosted on recipe uploads.
        // Virtual repo → 400 BAD_REQUEST.
        // ------------------------------------------------------------------
        #[tokio::test]
        async fn recipe_file_upload_against_virtual_repo_returns_400() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, username, _pw) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "virtual").await;
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
            let auth = make_auth(user_id, &username);

            let status = upload_recipe_file(
                &state,
                &auth,
                &repo_key,
                "zlib",
                "1.2.13",
                "_",
                "_",
                "rec",
                "conanfile.py",
                sample_conanfile_py(),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }

        // ------------------------------------------------------------------
        // Cross-cutting: reject_write_if_not_hosted on package uploads.
        // Remote repo → 405.
        // ------------------------------------------------------------------
        #[tokio::test]
        async fn package_file_upload_against_remote_repo_returns_405() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, username, _pw) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "remote").await;
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
            let auth = make_auth(user_id, &username);

            let status = upload_package_file(
                &state,
                &auth,
                &repo_key,
                "zlib",
                "1.2.13",
                "_",
                "_",
                "rec",
                "pid",
                "prev",
                "conan_package.tgz",
                &sample_conan_package_tgz(),
            )
            .await;
            assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }

        // ------------------------------------------------------------------
        // Cross-cutting: reject_write_if_not_hosted on package uploads.
        // Virtual repo → 400.
        // ------------------------------------------------------------------
        #[tokio::test]
        async fn package_file_upload_against_virtual_repo_returns_400() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, username, _pw) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "virtual").await;
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
            let auth = make_auth(user_id, &username);

            let status = upload_package_file(
                &state,
                &auth,
                &repo_key,
                "zlib",
                "1.2.13",
                "_",
                "_",
                "rec",
                "pid",
                "prev",
                "conan_package.tgz",
                &sample_conan_package_tgz(),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }

        // ------------------------------------------------------------------
        // Cross-cutting: anonymous recipe upload → 401 + WWW-Authenticate.
        // ------------------------------------------------------------------
        #[tokio::test]
        async fn recipe_file_upload_anonymous_returns_401() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, _u, _p) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());

            let app = router_anon(state.clone());
            let uri = format!(
                "/{}/v2/conans/{}/{}/{}/{}/revisions/{}/files/{}",
                repo_key, "zlib", "1.2.13", "_", "_", "rec", "conanfile.py",
            );
            let req = Request::builder()
                .method("PUT")
                .uri(uri)
                .body(Body::from(sample_conanfile_py().to_vec()))
                .expect("build request");
            let resp = tower::ServiceExt::oneshot(app, req)
                .await
                .expect("router oneshot failed");
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            let www = resp
                .headers()
                .get("WWW-Authenticate")
                .expect("WWW-Authenticate header must be present")
                .to_str()
                .expect("ASCII header");
            assert!(
                www.contains("Basic") && www.contains("realm=\"conan\""),
                "unexpected WWW-Authenticate value: {}",
                www,
            );

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }

        // ------------------------------------------------------------------
        // Cross-cutting: anonymous package upload → 401 + WWW-Authenticate.
        // ------------------------------------------------------------------
        #[tokio::test]
        async fn package_file_upload_anonymous_returns_401() {
            let Some(pool) = try_pool().await else {
                return;
            };
            let (user_id, _u, _p) = create_user(&pool).await;
            let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
            let state = build_state(pool.clone(), storage_dir.to_str().unwrap());

            let app = router_anon(state.clone());
            let uri = format!(
                "/{}/v2/conans/{}/{}/{}/{}/revisions/{}/packages/{}/revisions/{}/files/{}",
                repo_key, "zlib", "1.2.13", "_", "_", "rec", "pid", "prev", "conan_package.tgz",
            );
            let req = Request::builder()
                .method("PUT")
                .uri(uri)
                .body(Body::from(sample_conan_package_tgz()))
                .expect("build request");
            let resp = tower::ServiceExt::oneshot(app, req)
                .await
                .expect("router oneshot failed");
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            let www = resp
                .headers()
                .get("WWW-Authenticate")
                .expect("WWW-Authenticate header must be present")
                .to_str()
                .expect("ASCII header");
            assert!(
                www.contains("Basic") && www.contains("realm=\"conan\""),
                "unexpected WWW-Authenticate value: {}",
                www,
            );

            cleanup(&pool, repo_id, user_id).await;
            let _ = std::fs::remove_dir_all(&storage_dir);
        }
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
}

// ===========================================================================
// Agent 2 — recipe-side read handlers:
//   recipe_latest, recipe_revisions, recipe_files_list, recipe_file_download
// ===========================================================================

#[cfg(test)]
mod agent2_recipe_reads {
    use super::tests::test_helpers::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use uuid::Uuid;

    /// Build an anonymous request for a recipe read endpoint (these handlers
    /// do not call `require_auth_basic`).
    fn get(uri: String) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .expect("build request")
    }

    // -----------------------------------------------------------------------
    // recipe_latest
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn recipe_latest_returns_newest_revision() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (user_id, _username, _pw) = create_user(&pool).await;
        let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
        let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
        let auth = make_auth(user_id, "dummy");

        let _ = seed_recipe_row(
            &pool,
            repo_id,
            "boost",
            "1.83.0",
            "_",
            "_",
            "rev_old_hash",
            "conanfile.py",
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let _ = seed_recipe_row(
            &pool,
            repo_id,
            "boost",
            "1.83.0",
            "_",
            "_",
            "rev_new_hash",
            "conanfile.py",
        )
        .await;

        let app = router_with_auth(state, auth);
        let (status, body) = send(
            app,
            get(format!("/{}/v2/conans/boost/1.83.0/_/_/latest", repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body={:?}", body);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(
            json.get("revision").and_then(|v| v.as_str()),
            Some("rev_new_hash"),
            "expected newest revision; body={}",
            String::from_utf8_lossy(&body)
        );
        // RFC 3339 time string present and parseable.
        let time = json
            .get("time")
            .and_then(|v| v.as_str())
            .expect("time present");
        chrono::DateTime::parse_from_rfc3339(time).expect("valid rfc3339");

        cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);
    }

    #[tokio::test]
    async fn recipe_latest_404_when_no_rows() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (user_id, _username, _pw) = create_user(&pool).await;
        let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
        let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
        let auth = make_auth(user_id, "dummy");

        let app = router_with_auth(state, auth);
        let (status, _body) = send(
            app,
            get(format!("/{}/v2/conans/nope/0.0.1/_/_/latest", repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);
    }

    #[tokio::test]
    async fn recipe_latest_404_when_other_ref_exists_but_query_ref_missing() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (user_id, _username, _pw) = create_user(&pool).await;
        let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
        let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
        let auth = make_auth(user_id, "dummy");

        // Seed a row for foo/1.0 — we then query bar/1.0 and expect 404.
        let _ = seed_recipe_row(
            &pool,
            repo_id,
            "foo",
            "1.0",
            "_",
            "_",
            "revX",
            "conanfile.py",
        )
        .await;

        let app = router_with_auth(state, auth);
        let (status, _body) = send(
            app,
            get(format!("/{}/v2/conans/bar/1.0/_/_/latest", repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);
    }

    /// Tiebreaker bug: when two recipe rows share the same `created_at`, the
    /// handler must return a deterministic result. The fix adds `a.id DESC`
    /// to `ORDER BY`, so the row with the larger UUID wins.
    #[tokio::test]
    async fn recipe_latest_tiebreaker_is_deterministic_on_identical_created_at() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (user_id, _username, _pw) = create_user(&pool).await;
        let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
        let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
        let auth = make_auth(user_id, "dummy");

        // Two artifacts with EXACTLY the same explicit created_at. The
        // tiebreaker on `a.id DESC` should pick the larger UUID. We use
        // fresh UUIDs here (not hardcoded) so parallel/repeated test runs
        // on the same database don't collide on the primary key.
        let ts = chrono::Utc::now();
        let u_a = Uuid::new_v4();
        let u_b = Uuid::new_v4();
        let (id_lo, id_hi) = if u_a < u_b { (u_a, u_b) } else { (u_b, u_a) };

        for (aid, rev) in [(id_lo, "rev_low_id"), (id_hi, "rev_high_id")] {
            let path = format!("tbreak/1.0/_/_/revisions/{}/files/conanfile.py", rev);
            let storage_key = format!("conan/tbreak/1.0/_/_/recipe/{}/conanfile.py", rev);
            let checksum = format!("{:0>64}", aid.simple().to_string());
            sqlx::query(
                r#"
                INSERT INTO artifacts (
                    id, repository_id, path, name, version, size_bytes,
                    checksum_sha256, content_type, storage_key, created_at
                )
                VALUES ($1, $2, $3, 'tbreak', '1.0', 0, $4, 'text/plain', $5, $6)
                "#,
            )
            .bind(aid)
            .bind(repo_id)
            .bind(&path)
            .bind(&checksum)
            .bind(&storage_key)
            .bind(ts)
            .execute(&pool)
            .await
            .expect("seed artifact");
            let md = serde_json::json!({
                "name": "tbreak",
                "version": "1.0",
                "user": "_",
                "channel": "_",
                "revision": rev,
                "type": "recipe",
                "file": "conanfile.py",
            });
            sqlx::query(
                r#"
                INSERT INTO artifact_metadata (artifact_id, format, metadata)
                VALUES ($1, 'conan', $2)
                "#,
            )
            .bind(aid)
            .bind(md)
            .execute(&pool)
            .await
            .expect("seed metadata");
        }

        // The fix (`ORDER BY created_at DESC, id DESC`) picks the row with
        // the larger UUID, i.e. rev_high_id. Repeat the request several
        // times to make sure we always get the same answer (the pre-fix
        // code could return either, depending on storage order).
        let mut seen = std::collections::HashSet::new();
        for _ in 0..5 {
            let app = router_with_auth(state.clone(), auth.clone());
            let (status, body) = send(
                app,
                get(format!("/{}/v2/conans/tbreak/1.0/_/_/latest", repo_key)),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
            seen.insert(
                json.get("revision")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            );
        }
        assert_eq!(
            seen.len(),
            1,
            "recipe_latest must be deterministic across calls; saw: {:?}",
            seen
        );
        let chosen = seen.into_iter().next().unwrap();
        assert_eq!(
            chosen, "rev_high_id",
            "tiebreaker must pick the larger UUID (id DESC); got {}",
            chosen
        );

        cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);
    }

    /// Virtual fan-out regression: a virtual repo whose only member is a
    /// local repo with revisions for the requested name/version must return
    /// 200 with the member's latest revision. Before the fix, `recipe_latest`
    /// queried `repository_id = virtual_repo.id` directly and returned 404
    /// because virtual repos never own artifact rows themselves.
    ///
    /// Surfaced by `tests/formats/test-conan-remote.sh` assertion
    /// "Fetch locallib latest through virtual repo matches local"
    /// in release-gate run 24938542187.
    #[tokio::test]
    async fn recipe_latest_aggregates_across_virtual_members() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (user_id, _username, _pw) = create_user(&pool).await;
        let (local_repo_id, _local_key, local_storage_dir) =
            create_conan_repo(&pool, "local").await;
        let (virtual_repo_id, virtual_key, virtual_storage_dir) =
            create_conan_repo(&pool, "virtual").await;
        let state = build_state(pool.clone(), virtual_storage_dir.to_str().unwrap());
        let auth = make_auth(user_id, "dummy");

        // Link the local repo as a member of the virtual repo.
        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, 0)",
        )
        .bind(virtual_repo_id)
        .bind(local_repo_id)
        .execute(&pool)
        .await
        .expect("link virtual member");

        // Seed two revisions in the local member; the newer one should win.
        let _ = seed_recipe_row(
            &pool,
            local_repo_id,
            "locallib",
            "1.0.0",
            "_",
            "_",
            "rev_old_v",
            "conanfile.py",
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let _ = seed_recipe_row(
            &pool,
            local_repo_id,
            "locallib",
            "1.0.0",
            "_",
            "_",
            "rev_new_v",
            "conanfile.py",
        )
        .await;

        let app = router_with_auth(state, auth);
        let (status, body) = send(
            app,
            get(format!(
                "/{}/v2/conans/locallib/1.0.0/_/_/latest",
                virtual_key
            )),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "virtual repo should aggregate to local member; body={}",
            String::from_utf8_lossy(&body)
        );
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(
            json.get("revision").and_then(|v| v.as_str()),
            Some("rev_new_v"),
            "expected newest revision from local member; body={}",
            String::from_utf8_lossy(&body)
        );

        // Cleanup: drop the membership row first, then the artifacts/repos.
        let _ = sqlx::query("DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1")
            .bind(virtual_repo_id)
            .execute(&pool)
            .await;
        cleanup(&pool, local_repo_id, user_id).await;
        // Virtual repo has no artifacts; just drop the row.
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(virtual_repo_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&local_storage_dir);
        let _ = std::fs::remove_dir_all(&virtual_storage_dir);
    }

    // -----------------------------------------------------------------------
    // recipe_revisions
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn recipe_revisions_empty_returns_empty_array() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (user_id, _username, _pw) = create_user(&pool).await;
        let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
        let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
        let auth = make_auth(user_id, "dummy");

        let app = router_with_auth(state, auth);
        let (status, body) = send(
            app,
            get(format!("/{}/v2/conans/ghost/0.0.0/_/_/revisions", repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let revs = json
            .get("revisions")
            .and_then(|v| v.as_array())
            .expect("array");
        assert!(revs.is_empty(), "expected [], got {:?}", revs);

        cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);
    }

    #[tokio::test]
    async fn recipe_revisions_single_entry() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (user_id, _username, _pw) = create_user(&pool).await;
        let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
        let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
        let auth = make_auth(user_id, "dummy");

        let _ = seed_recipe_row(
            &pool,
            repo_id,
            "openssl",
            "3.0.0",
            "_",
            "_",
            "rev_only",
            "conanfile.py",
        )
        .await;

        let app = router_with_auth(state, auth);
        let (status, body) = send(
            app,
            get(format!(
                "/{}/v2/conans/openssl/3.0.0/_/_/revisions",
                repo_key
            )),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let revs = json
            .get("revisions")
            .and_then(|v| v.as_array())
            .expect("array");
        assert_eq!(revs.len(), 1);
        assert_eq!(
            revs[0].get("revision").and_then(|v| v.as_str()),
            Some("rev_only")
        );
        let time = revs[0]
            .get("time")
            .and_then(|v| v.as_str())
            .expect("time str");
        chrono::DateTime::parse_from_rfc3339(time).expect("rfc3339");

        cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);
    }

    #[tokio::test]
    async fn recipe_revisions_multiple_ordered_desc_by_created_at() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (user_id, _username, _pw) = create_user(&pool).await;
        let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
        let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
        let auth = make_auth(user_id, "dummy");

        let _ = seed_recipe_row(
            &pool,
            repo_id,
            "zlib",
            "1.2.13",
            "_",
            "_",
            "rev_a",
            "conanfile.py",
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let _ = seed_recipe_row(
            &pool,
            repo_id,
            "zlib",
            "1.2.13",
            "_",
            "_",
            "rev_b",
            "conanfile.py",
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let _ = seed_recipe_row(
            &pool,
            repo_id,
            "zlib",
            "1.2.13",
            "_",
            "_",
            "rev_c",
            "conanfile.py",
        )
        .await;

        let app = router_with_auth(state, auth);
        let (status, body) = send(
            app,
            get(format!("/{}/v2/conans/zlib/1.2.13/_/_/revisions", repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let revs = json
            .get("revisions")
            .and_then(|v| v.as_array())
            .expect("array");
        let labels: Vec<&str> = revs
            .iter()
            .filter_map(|v| v.get("revision").and_then(|r| r.as_str()))
            .collect();
        assert_eq!(labels, vec!["rev_c", "rev_b", "rev_a"]);

        cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);
    }

    #[tokio::test]
    async fn recipe_revisions_filters_soft_deleted_rows() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (user_id, _username, _pw) = create_user(&pool).await;
        let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
        let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
        let auth = make_auth(user_id, "dummy");

        let a_del = seed_recipe_row(
            &pool,
            repo_id,
            "fmt",
            "10.0",
            "_",
            "_",
            "rev_gone",
            "conanfile.py",
        )
        .await;
        let _a_live = seed_recipe_row(
            &pool,
            repo_id,
            "fmt",
            "10.0",
            "_",
            "_",
            "rev_live",
            "conanfile.py",
        )
        .await;
        // Soft-delete a_del.
        sqlx::query("UPDATE artifacts SET is_deleted = true WHERE id = $1")
            .bind(a_del)
            .execute(&pool)
            .await
            .expect("soft delete");

        let app = router_with_auth(state, auth);
        let (status, body) = send(
            app,
            get(format!("/{}/v2/conans/fmt/10.0/_/_/revisions", repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let revs = json
            .get("revisions")
            .and_then(|v| v.as_array())
            .expect("array");
        let labels: Vec<&str> = revs
            .iter()
            .filter_map(|v| v.get("revision").and_then(|r| r.as_str()))
            .collect();
        assert_eq!(labels, vec!["rev_live"]);

        cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);
    }

    // -----------------------------------------------------------------------
    // recipe_files_list
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn recipe_files_list_empty_returns_empty_map() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (user_id, _username, _pw) = create_user(&pool).await;
        let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
        let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
        let auth = make_auth(user_id, "dummy");

        let app = router_with_auth(state, auth);
        let (status, body) = send(
            app,
            get(format!(
                "/{}/v2/conans/nothing/1.0/_/_/revisions/revNone/files",
                repo_key
            )),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json, serde_json::json!({"files": {}}));

        cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);
    }

    #[tokio::test]
    async fn recipe_files_list_single_file() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (user_id, _username, _pw) = create_user(&pool).await;
        let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
        let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
        let auth = make_auth(user_id, "dummy");

        let _ = seed_recipe_row(
            &pool,
            repo_id,
            "cat",
            "2.0",
            "_",
            "_",
            "rev_one",
            "conanfile.py",
        )
        .await;

        let app = router_with_auth(state, auth);
        let (status, body) = send(
            app,
            get(format!(
                "/{}/v2/conans/cat/2.0/_/_/revisions/rev_one/files",
                repo_key
            )),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let files = json.get("files").and_then(|v| v.as_object()).expect("map");
        assert_eq!(files.len(), 1);
        assert_eq!(files.get("conanfile.py"), Some(&serde_json::json!({})));

        cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);
    }

    #[tokio::test]
    async fn recipe_files_list_multiple_files_for_revision() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (user_id, _username, _pw) = create_user(&pool).await;
        let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
        let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
        let auth = make_auth(user_id, "dummy");

        for fname in ["conanfile.py", "conanmanifest.txt", "conan_export.tgz"] {
            let _ = seed_recipe_row(&pool, repo_id, "multi", "1.0", "_", "_", "rev_m", fname).await;
        }
        // And seed one row for an unrelated revision — must NOT appear.
        let _ = seed_recipe_row(
            &pool,
            repo_id,
            "multi",
            "1.0",
            "_",
            "_",
            "rev_other",
            "conanfile.py",
        )
        .await;

        let app = router_with_auth(state, auth);
        let (status, body) = send(
            app,
            get(format!(
                "/{}/v2/conans/multi/1.0/_/_/revisions/rev_m/files",
                repo_key
            )),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let files = json.get("files").and_then(|v| v.as_object()).expect("map");
        assert_eq!(files.len(), 3, "files={:?}", files);
        for name in ["conanfile.py", "conanmanifest.txt", "conan_export.tgz"] {
            assert!(files.contains_key(name), "missing {}", name);
        }

        cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);
    }

    #[tokio::test]
    async fn recipe_files_list_user_channel_placeholder_underscore() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (user_id, _username, _pw) = create_user(&pool).await;
        let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
        let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
        let auth = make_auth(user_id, "dummy");

        // Seed with "_"/"_" as user/channel and a non-placeholder neighbor
        // — only the placeholder rows should come back.
        let _ = seed_recipe_row(
            &pool,
            repo_id,
            "plib",
            "1.0",
            "_",
            "_",
            "rev_u",
            "conanfile.py",
        )
        .await;
        let _ = seed_recipe_row(
            &pool,
            repo_id,
            "plib",
            "1.0",
            "acme",
            "stable",
            "rev_u",
            "conanfile.py",
        )
        .await;

        let app = router_with_auth(state, auth);
        let (status, body) = send(
            app,
            get(format!(
                "/{}/v2/conans/plib/1.0/_/_/revisions/rev_u/files",
                repo_key
            )),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let files = json.get("files").and_then(|v| v.as_object()).expect("map");
        assert_eq!(files.len(), 1);
        assert!(files.contains_key("conanfile.py"));

        cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);
    }

    // -----------------------------------------------------------------------
    // recipe_file_download
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn recipe_file_download_hosted_roundtrip() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (user_id, username, _pw) = create_user(&pool).await;
        let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
        let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
        let auth = make_auth(user_id, &username);

        let body = b"from conan import ConanFile\nclass T(ConanFile): pass\n";
        let put_status = upload_recipe_file(
            &state,
            &auth,
            &repo_key,
            "rt",
            "1.0",
            "_",
            "_",
            "rev_rt",
            "conanfile.py",
            body,
        )
        .await;
        assert!(put_status.is_success(), "upload failed: {}", put_status);

        let app = router_with_auth(state, auth);
        let (status, got) = send(
            app,
            get(format!(
                "/{}/v2/conans/rt/1.0/_/_/revisions/rev_rt/files/conanfile.py",
                repo_key
            )),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(got.as_ref(), body);

        cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);
    }

    #[tokio::test]
    async fn recipe_file_download_404_when_missing_in_hosted_repo() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (user_id, _username, _pw) = create_user(&pool).await;
        let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
        let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
        let auth = make_auth(user_id, "dummy");

        let app = router_with_auth(state, auth);
        let (status, _body) = send(
            app,
            get(format!(
                "/{}/v2/conans/zz/1.0/_/_/revisions/rev_zz/files/conanfile.py",
                repo_key
            )),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);
    }

    #[tokio::test]
    async fn recipe_file_download_remote_without_proxy_returns_404() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (user_id, _username, _pw) = create_user(&pool).await;
        let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "remote").await;
        let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
        // state.proxy_service is None in build_state — this branch returns
        // the original NOT_FOUND from the artifact lookup.
        let auth = make_auth(user_id, "dummy");

        let app = router_with_auth(state, auth);
        let (status, _body) = send(
            app,
            get(format!(
                "/{}/v2/conans/xx/9.9/_/_/revisions/revX/files/conanfile.py",
                repo_key
            )),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);
    }

    #[tokio::test]
    async fn recipe_file_download_virtual_with_no_member_returns_error() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (user_id, _username, _pw) = create_user(&pool).await;
        let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "virtual").await;
        let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
        let auth = make_auth(user_id, "dummy");

        let app = router_with_auth(state, auth);
        let (status, _body) = send(
            app,
            get(format!(
                "/{}/v2/conans/missing/1.0/_/_/revisions/revV/files/conanfile.py",
                repo_key
            )),
        )
        .await;
        // No members resolved; `resolve_virtual_download` returns a 404 or
        // similar non-success status. The exact status depends on
        // proxy_helpers; assert it's a client/server error and not 200.
        assert!(
            !status.is_success(),
            "virtual repo with no members should not return 200, got {}",
            status
        );

        cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);
    }

    #[tokio::test]
    async fn recipe_file_download_soft_deleted_artifact_returns_404() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (user_id, username, _pw) = create_user(&pool).await;
        let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
        let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
        let auth = make_auth(user_id, &username);

        let body = b"payload";
        let put_status = upload_recipe_file(
            &state,
            &auth,
            &repo_key,
            "soft",
            "1.0",
            "_",
            "_",
            "rev_sd",
            "conanfile.py",
            body,
        )
        .await;
        assert!(put_status.is_success(), "upload failed: {}", put_status);

        // Soft-delete the artifact row.
        sqlx::query(
            "UPDATE artifacts SET is_deleted = true \
             WHERE repository_id = $1 AND name = 'soft'",
        )
        .bind(repo_id)
        .execute(&pool)
        .await
        .expect("soft delete");

        let app = router_with_auth(state, auth);
        let (status, _body) = send(
            app,
            get(format!(
                "/{}/v2/conans/soft/1.0/_/_/revisions/rev_sd/files/conanfile.py",
                repo_key
            )),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);
    }

    // -----------------------------------------------------------------------
    // Virtual fan-out for remaining metadata endpoints (#876)
    //
    // recipe_latest already aggregates across hosted virtual-repo members
    // (covered by `recipe_latest_aggregates_across_virtual_members` in the
    // `tests` module). The same pattern is required for recipe_revisions,
    // recipe_files_list, package_latest, package_revisions, and
    // package_files_list. The tests below seed a hosted member of a virtual
    // repo and exercise each handler through the virtual key.
    // -----------------------------------------------------------------------

    /// Helper: build a virtual repo with one hosted member already linked.
    /// Returns `(virtual_repo_id, virtual_key, member_repo_id, virtual_storage_dir,
    /// member_storage_dir, user_id, state, auth)`. Tests should cleanup all
    /// returned resources at the end.
    #[allow(clippy::type_complexity)]
    async fn setup_virtual_with_member(
        pool: &sqlx::PgPool,
    ) -> (
        Uuid,
        String,
        Uuid,
        std::path::PathBuf,
        std::path::PathBuf,
        Uuid,
        crate::api::SharedState,
        crate::api::middleware::auth::AuthExtension,
    ) {
        let (user_id, _u, _p) = create_user(pool).await;
        let (member_id, _member_key, member_dir) = create_conan_repo(pool, "local").await;
        let (virtual_id, virtual_key, virtual_dir) = create_conan_repo(pool, "virtual").await;
        let state = build_state(pool.clone(), virtual_dir.to_str().unwrap());
        let auth = make_auth(user_id, "dummy");
        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, 0)",
        )
        .bind(virtual_id)
        .bind(member_id)
        .execute(pool)
        .await
        .expect("link virtual member");
        (
            virtual_id,
            virtual_key,
            member_id,
            virtual_dir,
            member_dir,
            user_id,
            state,
            auth,
        )
    }

    async fn cleanup_virtual_pair(
        pool: &sqlx::PgPool,
        virtual_id: Uuid,
        member_id: Uuid,
        virtual_dir: &std::path::Path,
        member_dir: &std::path::Path,
        user_id: Uuid,
    ) {
        let _ = sqlx::query("DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1")
            .bind(virtual_id)
            .execute(pool)
            .await;
        cleanup(pool, member_id, user_id).await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(virtual_id)
            .execute(pool)
            .await;
        let _ = std::fs::remove_dir_all(virtual_dir);
        let _ = std::fs::remove_dir_all(member_dir);
    }

    #[tokio::test]
    async fn recipe_revisions_aggregates_across_virtual_members() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (virtual_id, virtual_key, member_id, virtual_dir, member_dir, user_id, state, auth) =
            setup_virtual_with_member(&pool).await;

        let _ = seed_recipe_row(
            &pool,
            member_id,
            "vlib",
            "1.0",
            "_",
            "_",
            "rev_alpha",
            "conanfile.py",
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let _ = seed_recipe_row(
            &pool,
            member_id,
            "vlib",
            "1.0",
            "_",
            "_",
            "rev_beta",
            "conanfile.py",
        )
        .await;

        let app = router_with_auth(state, auth);
        let (status, body) = send(
            app,
            get(format!("/{}/v2/conans/vlib/1.0/_/_/revisions", virtual_key)),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "body={}",
            String::from_utf8_lossy(&body)
        );
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let revs = json
            .get("revisions")
            .and_then(|v| v.as_array())
            .expect("array");
        let ids: Vec<&str> = revs
            .iter()
            .filter_map(|r| r.get("revision").and_then(|v| v.as_str()))
            .collect();
        assert_eq!(
            ids,
            vec!["rev_beta", "rev_alpha"],
            "virtual recipe_revisions must aggregate hosted member rows, newest first"
        );

        cleanup_virtual_pair(
            &pool,
            virtual_id,
            member_id,
            &virtual_dir,
            &member_dir,
            user_id,
        )
        .await;
    }

    #[tokio::test]
    async fn recipe_files_list_aggregates_across_virtual_members() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (virtual_id, virtual_key, member_id, virtual_dir, member_dir, user_id, state, auth) =
            setup_virtual_with_member(&pool).await;

        let _ = seed_recipe_row(
            &pool,
            member_id,
            "flib",
            "1.0",
            "_",
            "_",
            "rev_files",
            "conanfile.py",
        )
        .await;
        let _ = seed_recipe_row(
            &pool,
            member_id,
            "flib",
            "1.0",
            "_",
            "_",
            "rev_files",
            "conanmanifest.txt",
        )
        .await;

        let app = router_with_auth(state, auth);
        let (status, body) = send(
            app,
            get(format!(
                "/{}/v2/conans/flib/1.0/_/_/revisions/rev_files/files",
                virtual_key
            )),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "body={}",
            String::from_utf8_lossy(&body)
        );
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let files = json
            .get("files")
            .and_then(|v| v.as_object())
            .expect("object");
        assert!(
            files.contains_key("conanfile.py") && files.contains_key("conanmanifest.txt"),
            "virtual recipe_files_list must surface both seeded files, got {:?}",
            files.keys().collect::<Vec<_>>()
        );

        cleanup_virtual_pair(
            &pool,
            virtual_id,
            member_id,
            &virtual_dir,
            &member_dir,
            user_id,
        )
        .await;
    }

    #[tokio::test]
    async fn package_latest_aggregates_across_virtual_members() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (virtual_id, virtual_key, member_id, virtual_dir, member_dir, user_id, state, auth) =
            setup_virtual_with_member(&pool).await;

        let _ = seed_package_row(
            &pool,
            member_id,
            "plib",
            "1.0",
            "_",
            "_",
            "recipe_rev_x",
            "pkgid1",
            "pkg_rev_old",
            "conan_package.tgz",
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let _ = seed_package_row(
            &pool,
            member_id,
            "plib",
            "1.0",
            "_",
            "_",
            "recipe_rev_x",
            "pkgid1",
            "pkg_rev_new",
            "conan_package.tgz",
        )
        .await;

        let app = router_with_auth(state, auth);
        let (status, body) = send(
            app,
            get(format!(
                "/{}/v2/conans/plib/1.0/_/_/revisions/recipe_rev_x/packages/pkgid1/latest",
                virtual_key
            )),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "body={}",
            String::from_utf8_lossy(&body)
        );
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(
            json.get("revision").and_then(|v| v.as_str()),
            Some("pkg_rev_new"),
            "virtual package_latest must return newest member revision"
        );

        cleanup_virtual_pair(
            &pool,
            virtual_id,
            member_id,
            &virtual_dir,
            &member_dir,
            user_id,
        )
        .await;
    }

    #[tokio::test]
    async fn package_revisions_aggregates_across_virtual_members() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (virtual_id, virtual_key, member_id, virtual_dir, member_dir, user_id, state, auth) =
            setup_virtual_with_member(&pool).await;

        let _ = seed_package_row(
            &pool,
            member_id,
            "prlib",
            "1.0",
            "_",
            "_",
            "rrev_a",
            "pkgid2",
            "pkg_rev_one",
            "conan_package.tgz",
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let _ = seed_package_row(
            &pool,
            member_id,
            "prlib",
            "1.0",
            "_",
            "_",
            "rrev_a",
            "pkgid2",
            "pkg_rev_two",
            "conan_package.tgz",
        )
        .await;

        let app = router_with_auth(state, auth);
        let (status, body) = send(
            app,
            get(format!(
                "/{}/v2/conans/prlib/1.0/_/_/revisions/rrev_a/packages/pkgid2/revisions",
                virtual_key
            )),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "body={}",
            String::from_utf8_lossy(&body)
        );
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let revs = json
            .get("revisions")
            .and_then(|v| v.as_array())
            .expect("array");
        let ids: Vec<&str> = revs
            .iter()
            .filter_map(|r| r.get("revision").and_then(|v| v.as_str()))
            .collect();
        assert_eq!(
            ids,
            vec!["pkg_rev_two", "pkg_rev_one"],
            "virtual package_revisions must aggregate hosted member rows, newest first"
        );

        cleanup_virtual_pair(
            &pool,
            virtual_id,
            member_id,
            &virtual_dir,
            &member_dir,
            user_id,
        )
        .await;
    }

    #[tokio::test]
    async fn package_files_list_aggregates_across_virtual_members() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (virtual_id, virtual_key, member_id, virtual_dir, member_dir, user_id, state, auth) =
            setup_virtual_with_member(&pool).await;

        let _ = seed_package_row(
            &pool,
            member_id,
            "pflib",
            "1.0",
            "_",
            "_",
            "rrev_pf",
            "pkgid3",
            "pkgrev_pf",
            "conan_package.tgz",
        )
        .await;
        let _ = seed_package_row(
            &pool,
            member_id,
            "pflib",
            "1.0",
            "_",
            "_",
            "rrev_pf",
            "pkgid3",
            "pkgrev_pf",
            "conaninfo.txt",
        )
        .await;

        let app = router_with_auth(state, auth);
        let (status, body) = send(
            app,
            get(format!(
                "/{}/v2/conans/pflib/1.0/_/_/revisions/rrev_pf/packages/pkgid3/revisions/pkgrev_pf/files",
                virtual_key
            )),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "body={}",
            String::from_utf8_lossy(&body)
        );
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let files = json
            .get("files")
            .and_then(|v| v.as_object())
            .expect("object");
        assert!(
            files.contains_key("conan_package.tgz") && files.contains_key("conaninfo.txt"),
            "virtual package_files_list must surface both seeded files, got {:?}",
            files.keys().collect::<Vec<_>>()
        );

        cleanup_virtual_pair(
            &pool,
            virtual_id,
            member_id,
            &virtual_dir,
            &member_dir,
            user_id,
        )
        .await;
    }

    #[tokio::test]
    async fn search_aggregates_across_virtual_members() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (virtual_id, virtual_key, member_id, virtual_dir, member_dir, user_id, state, auth) =
            setup_virtual_with_member(&pool).await;

        let _ = seed_recipe_row(
            &pool,
            member_id,
            "searchlib",
            "1.2.3",
            "myuser",
            "stable",
            "rev_s",
            "conanfile.py",
        )
        .await;

        let app = router_with_auth(state, auth);
        let (status, body) = send(
            app,
            get(format!("/{}/v2/conans/search?q=searchlib*", virtual_key)),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "body={}",
            String::from_utf8_lossy(&body)
        );
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let results = json
            .get("results")
            .and_then(|v| v.as_array())
            .expect("array");
        let refs: Vec<&str> = results.iter().filter_map(|v| v.as_str()).collect();
        assert!(
            refs.iter()
                .any(|r| r.starts_with("searchlib/1.2.3@myuser/stable")),
            "virtual search must aggregate from hosted member, got {:?}",
            refs
        );

        cleanup_virtual_pair(
            &pool,
            virtual_id,
            member_id,
            &virtual_dir,
            &member_dir,
            user_id,
        )
        .await;
    }

    // -----------------------------------------------------------------------
    // recipe_package_search (#2058): /revisions/{rrev}/search
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn recipe_package_search_lists_hosted_package_ids() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (user_id, _username, _pw) = create_user(&pool).await;
        let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "local").await;
        let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
        let auth = make_auth(user_id, "dummy");

        // Two distinct package IDs under the same recipe revision.
        let _ = seed_package_row(
            &pool,
            repo_id,
            "pslib",
            "1.0",
            "_",
            "_",
            "rrev_ps",
            "pkgid_a",
            "prev1",
            "conaninfo.txt",
        )
        .await;
        let _ = seed_package_row(
            &pool,
            repo_id,
            "pslib",
            "1.0",
            "_",
            "_",
            "rrev_ps",
            "pkgid_b",
            "prev1",
            "conaninfo.txt",
        )
        .await;
        // A package under a DIFFERENT recipe revision must NOT appear.
        let _ = seed_package_row(
            &pool,
            repo_id,
            "pslib",
            "1.0",
            "_",
            "_",
            "rrev_other",
            "pkgid_c",
            "prev1",
            "conaninfo.txt",
        )
        .await;

        let app = router_with_auth(state, auth);
        let (status, body) = send(
            app,
            get(format!(
                "/{}/v2/conans/pslib/1.0/_/_/revisions/rrev_ps/search",
                repo_key
            )),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "body={}",
            String::from_utf8_lossy(&body)
        );
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let map = json
            .as_object()
            .expect("search response must be a JSON object");
        assert!(
            map.contains_key("pkgid_a") && map.contains_key("pkgid_b"),
            "hosted package search must list both package IDs for the revision, got {:?}",
            map.keys().collect::<Vec<_>>()
        );
        assert!(
            !map.contains_key("pkgid_c"),
            "packages from other recipe revisions must not leak, got {:?}",
            map.keys().collect::<Vec<_>>()
        );

        cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);
    }

    #[tokio::test]
    async fn recipe_package_search_aggregates_across_virtual_members() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (virtual_id, virtual_key, member_id, virtual_dir, member_dir, user_id, state, auth) =
            setup_virtual_with_member(&pool).await;

        let _ = seed_package_row(
            &pool,
            member_id,
            "vpslib",
            "1.0",
            "_",
            "_",
            "rrev_v",
            "pkgid_v",
            "prev1",
            "conaninfo.txt",
        )
        .await;

        let app = router_with_auth(state, auth);
        let (status, body) = send(
            app,
            get(format!(
                "/{}/v2/conans/vpslib/1.0/_/_/revisions/rrev_v/search",
                virtual_key
            )),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "body={}",
            String::from_utf8_lossy(&body)
        );
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let map = json.as_object().expect("object");
        assert!(
            map.contains_key("pkgid_v"),
            "virtual package search must aggregate hosted member package IDs, got {:?}",
            map.keys().collect::<Vec<_>>()
        );

        cleanup_virtual_pair(
            &pool,
            virtual_id,
            member_id,
            &virtual_dir,
            &member_dir,
            user_id,
        )
        .await;
    }

    #[tokio::test]
    async fn recipe_package_search_remote_without_proxy_returns_local_only() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (user_id, _username, _pw) = create_user(&pool).await;
        // `build_state` leaves `proxy_service` as None, so the Remote arm must
        // skip the upstream forward and return only locally-cached package IDs.
        let (repo_id, repo_key, storage_dir) = create_conan_repo(&pool, "remote").await;
        let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
        let auth = make_auth(user_id, "dummy");

        let _ = seed_package_row(
            &pool,
            repo_id,
            "rpslib",
            "2.0",
            "_",
            "_",
            "rrev_r",
            "pkgid_r",
            "prev1",
            "conaninfo.txt",
        )
        .await;

        let app = router_with_auth(state, auth);
        let (status, body) = send(
            app,
            get(format!(
                "/{}/v2/conans/rpslib/2.0/_/_/revisions/rrev_r/search",
                repo_key
            )),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "body={}",
            String::from_utf8_lossy(&body)
        );
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let map = json.as_object().expect("object");
        assert!(
            map.contains_key("pkgid_r"),
            "remote-without-proxy search must still return the local package ID, got {:?}",
            map.keys().collect::<Vec<_>>()
        );

        cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);
    }

    #[test]
    fn test_parse_package_search_json_happy() {
        let body = br#"{"pkgid_a":{"settings":{"os":"Linux"}},"pkgid_b":{}}"#;
        let map = super::parse_package_search_json(body);
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("pkgid_a"));
        assert_eq!(
            map.get("pkgid_a").and_then(|v| v.get("settings")),
            Some(&serde_json::json!({"os": "Linux"}))
        );
    }

    #[test]
    fn test_parse_package_search_json_non_object_is_empty() {
        // Upstream that returns a non-object (e.g. an array or a string) must
        // degrade to an empty map, not error.
        assert!(super::parse_package_search_json(br#"["a","b"]"#).is_empty());
        assert!(super::parse_package_search_json(br#""nope""#).is_empty());
    }

    #[test]
    fn test_parse_package_search_json_malformed_is_empty() {
        assert!(super::parse_package_search_json(b"not json {").is_empty());
        assert!(super::parse_package_search_json(b"").is_empty());
    }

    // -----------------------------------------------------------------------
    // Upstream-revisions JSON parsing (Remote pull-through resolution).
    //
    // These cover the pure parse+row-mapping logic used by the new
    // `*_from_remote` helpers without requiring a live upstream: a happy-path
    // parse must yield the upstream revisions (merge-ready), and a malformed /
    // shapeless body must degrade to an empty Vec / None so the handler
    // returns 200 / 404 instead of 500.
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_recipe_revisions_json_happy() {
        let body = br#"{"revisions":[
            {"revision":"rev-a","time":"2026-01-02T00:00:00Z"},
            {"revision":"rev-b","time":"2026-01-01T00:00:00Z"}
        ]}"#;
        let rows = super::parse_recipe_revisions_json(body);
        assert_eq!(rows.len(), 2);
        let revs: Vec<&str> = rows.iter().map(|r| r.revision.as_str()).collect();
        assert!(revs.contains(&"rev-a"));
        assert!(revs.contains(&"rev-b"));
        // RFC3339 time is parsed into created_at so the caller can re-sort.
        let a = rows.iter().find(|r| r.revision == "rev-a").unwrap();
        let b = rows.iter().find(|r| r.revision == "rev-b").unwrap();
        assert!(a.created_at > b.created_at);
    }

    #[test]
    fn test_parse_recipe_revisions_json_missing_time_falls_back() {
        // No `time` field: row is still returned (created_at defaults to now).
        let body = br#"{"revisions":[{"revision":"only"}]}"#;
        let rows = super::parse_recipe_revisions_json(body);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].revision, "only");
    }

    #[test]
    fn test_parse_recipe_revisions_json_unparsable_is_empty() {
        // Garbage body -> empty Vec (degrade to local-only, no 500).
        assert!(super::parse_recipe_revisions_json(b"not json").is_empty());
    }

    #[test]
    fn test_parse_recipe_revisions_json_no_revisions_key_is_empty() {
        // Valid JSON but wrong shape -> empty Vec.
        assert!(super::parse_recipe_revisions_json(br#"{"other":1}"#).is_empty());
    }

    #[test]
    fn test_parse_recipe_revisions_json_skips_non_string_revision() {
        let body = br#"{"revisions":[{"revision":42},{"revision":"good"}]}"#;
        let rows = super::parse_recipe_revisions_json(body);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].revision, "good");
    }

    #[test]
    fn test_parse_package_revisions_json_happy() {
        let body = br#"{"revisions":[{"revision":"prev-1","time":"2026-03-04T05:06:07Z"}]}"#;
        let rows = super::parse_package_revisions_json(body);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].revision, "prev-1");
    }

    #[test]
    fn test_parse_package_revisions_json_unparsable_is_empty() {
        assert!(super::parse_package_revisions_json(b"<html>oops</html>").is_empty());
    }

    #[test]
    fn test_parse_latest_revision_json_happy() {
        let body = br#"{"revision":"latest-rev","time":"2026-01-01T00:00:00Z"}"#;
        assert_eq!(
            super::parse_latest_revision_json(body),
            Some("latest-rev".to_string())
        );
    }

    #[test]
    fn test_parse_latest_revision_json_missing_revision_is_none() {
        assert_eq!(super::parse_latest_revision_json(br#"{"time":"x"}"#), None);
    }

    #[test]
    fn test_parse_latest_revision_json_unparsable_is_none() {
        assert_eq!(super::parse_latest_revision_json(b"502 Bad Gateway"), None);
    }

    #[test]
    fn test_parse_revisions_value_empty_array() {
        let v = serde_json::json!({"revisions": []});
        assert!(super::parse_revisions_value(&v).is_empty());
    }

    #[test]
    fn test_parse_conan_time_rfc3339() {
        let dt = super::parse_conan_time("2025-12-09T12:51:39.337Z");
        assert_eq!(dt.format("%Y-%m-%d").to_string(), "2025-12-09");
    }

    #[test]
    fn test_parse_conan_time_numeric_offset() {
        // Conan Center's actual format: numeric +0000 offset (not RFC3339).
        let dt = super::parse_conan_time("2025-12-09T12:51:39.337+0000");
        assert_eq!(
            dt.format("%Y-%m-%dT%H:%M:%S").to_string(),
            "2025-12-09T12:51:39"
        );
    }

    #[test]
    fn test_parse_revisions_value_preserves_numeric_offset_ordering() {
        // With real Conan-Center-shaped times, rows keep their true timestamps so
        // the caller's newest-first sort is correct (not collapsed to "now").
        let body = br#"{"revisions":[
            {"revision":"newer","time":"2025-12-09T12:51:39.337+0000"},
            {"revision":"older","time":"2024-01-23T08:39:53.687+0000"}
        ]}"#;
        let rows = super::parse_recipe_revisions_json(body);
        let newer = rows.iter().find(|r| r.revision == "newer").unwrap();
        let older = rows.iter().find(|r| r.revision == "older").unwrap();
        assert!(newer.created_at > older.created_at);
    }
}
