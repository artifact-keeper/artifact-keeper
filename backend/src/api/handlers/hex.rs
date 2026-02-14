//! Hex.pm API handlers.
//!
//! Implements the endpoints required for `mix hex.publish` and `mix hex.package`.
//!
//! Routes are mounted at `/hex/{repo_key}/...`:
//!   GET  /hex/{repo_key}/packages/{name}              - Package info (JSON with releases)
//!   GET  /hex/{repo_key}/tarballs/{name}-{version}.tar - Download package tarball
//!   POST /hex/{repo_key}/publish                       - Publish package (auth required)
//!   GET  /hex/{repo_key}/names                         - List all package names
//!   GET  /hex/{repo_key}/versions                      - List all packages with versions

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

use crate::api::handlers::proxy_helpers;
use crate::api::SharedState;
use crate::formats::hex::HexHandler;
use crate::services::auth_service::AuthService;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::StorageBackend;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Publish package
        .route("/:repo_key/publish", post(publish_package))
        // Package info
        .route("/:repo_key/packages/:name", get(package_info))
        // List all package names
        .route("/:repo_key/names", get(list_names))
        // List all packages with versions
        .route("/:repo_key/versions", get(list_versions))
        // Download tarball - use a wildcard to capture name-version.tar
        .route("/:repo_key/tarballs/*tarball_file", get(download_tarball))
        .layer(DefaultBodyLimit::max(512 * 1024 * 1024)) // 512 MB
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

fn extract_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    // Try Bearer token first (used by mix hex.publish with API key)
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
            .header("WWW-Authenticate", "Basic realm=\"hex\"")
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
                .header("WWW-Authenticate", "Basic realm=\"hex\"")
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
    repo_type: String,
    upstream_url: Option<String>,
}

async fn resolve_hex_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    let repo = sqlx::query!(
        r#"SELECT id, storage_path, format::text as "format!", repo_type::text as "repo_type!", upstream_url
        FROM repositories WHERE key = $1"#,
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
    if fmt != "hex" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not a Hex repository (format: {})",
                repo_key, fmt
            ),
        )
            .into_response());
    }

    Ok(RepoInfo {
        id: repo.id,
        storage_path: repo.storage_path,
        repo_type: repo.repo_type,
        upstream_url: repo.upstream_url,
    })
}

// ---------------------------------------------------------------------------
// GET /hex/{repo_key}/packages/{name} -- Package info (JSON with releases)
// ---------------------------------------------------------------------------

async fn package_info(
    State(state): State<SharedState>,
    Path((repo_key, name)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_hex_repo(&state.db, &repo_key).await?;

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

    let releases: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            let version = a.version.clone().unwrap_or_default();
            let tarball_url = format!("/hex/{}/tarballs/{}-{}.tar", repo_key, name, version);

            serde_json::json!({
                "version": version,
                "url": tarball_url,
                "checksum": a.checksum_sha256,
            })
        })
        .collect();

    // Get download count across all versions
    let artifact_ids: Vec<uuid::Uuid> = artifacts.iter().map(|a| a.id).collect();
    let download_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM download_statistics WHERE artifact_id = ANY($1)",
        &artifact_ids
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(Some(0))
    .unwrap_or(0);

    let json = serde_json::json!({
        "name": name,
        "releases": releases,
        "downloads": download_count,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /hex/{repo_key}/tarballs/{name}-{version}.tar -- Download tarball
// ---------------------------------------------------------------------------

async fn download_tarball(
    State(state): State<SharedState>,
    Path((repo_key, tarball_file)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_hex_repo(&state.db, &repo_key).await?;

    let filename = tarball_file.trim_start_matches('/');

    // Find artifact by matching the path ending
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Tarball not found").into_response());

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == "remote" {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let upstream_path = format!("tarballs/{}", filename);
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
            if repo.repo_type == "virtual" {
                let db = state.db.clone();
                let upstream_path = format!("tarballs/{}", filename);
                let filename_clone = filename.to_string();
                let (content, content_type) = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    state.proxy_service.as_deref(),
                    repo.id,
                    &upstream_path,
                    |member_id, storage_path| {
                        let db = db.clone();
                        let suffix = filename_clone.clone();
                        async move {
                            proxy_helpers::local_fetch_by_path_suffix(
                                &db,
                                member_id,
                                &storage_path,
                                &suffix,
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
                    .header(
                        "Content-Disposition",
                        format!("attachment; filename=\"{}\"", filename),
                    )
                    .header(CONTENT_LENGTH, content.len().to_string())
                    .body(Body::from(content))
                    .unwrap());
            }

            return Err(not_found);
        }
    };

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
// POST /hex/{repo_key}/publish -- Publish package (raw tarball body)
// ---------------------------------------------------------------------------

async fn publish_package(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_hex_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty tarball").into_response());
    }

    // Validate the tarball path using the HexHandler
    let tarball_path = "tarballs/package-0.0.0.tar".to_string();
    HexHandler::parse_path(&tarball_path).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid hex package: {}", e),
        )
            .into_response()
    })?;

    // Extract package name and version from the tarball metadata.
    // Hex tarballs contain a metadata.config file at the top level.
    // For now, we require name and version as query params or from the tarball contents.
    // The Hex spec includes metadata inside the tarball as an outer tar containing:
    //   - VERSION (text file with "3")
    //   - metadata.config (Erlang term format)
    //   - contents.tar.gz (the actual package files)
    //   - CHECKSUM (SHA-256 of the above)
    let (pkg_name, pkg_version) = extract_name_version_from_tarball(&body).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid hex tarball: {}", e),
        )
            .into_response()
    })?;

    if pkg_name.is_empty() || pkg_version.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Package name and version are required",
        )
            .into_response());
    }

    let filename = format!("{}-{}.tar", pkg_name, pkg_version);

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let computed_sha256 = format!("{:x}", hasher.finalize());

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
    let storage_key = format!("hex/{}/{}/{}", pkg_name, pkg_version, filename);
    let storage = FilesystemStorage::new(&repo.storage_path);
    storage.put(&storage_key, body.clone()).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    let hex_metadata = serde_json::json!({
        "format": "hex",
        "name": pkg_name,
        "version": pkg_version,
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
        pkg_version,
        size_bytes,
        computed_sha256,
        "application/octet-stream",
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
        VALUES ($1, 'hex', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        hex_metadata,
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
        "Hex publish: {} {} ({}) to repo {}",
        pkg_name, pkg_version, filename, repo_key
    );

    let response_json = serde_json::json!({
        "name": pkg_name,
        "version": pkg_version,
        "url": format!("/hex/{}/tarballs/{}", repo_key, filename),
    });

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response_json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /hex/{repo_key}/names -- List all package names
// ---------------------------------------------------------------------------

async fn list_names(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_hex_repo(&state.db, &repo_key).await?;

    let names = sqlx::query_scalar!(
        r#"
        SELECT DISTINCT name
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
        ORDER BY name
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

    let json = serde_json::json!(names);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /hex/{repo_key}/versions -- List all packages with versions
// ---------------------------------------------------------------------------

async fn list_versions(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_hex_repo(&state.db, &repo_key).await?;

    let artifacts = sqlx::query!(
        r#"
        SELECT name, version
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
        ORDER BY name, created_at DESC
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

    // Group versions by package name
    let mut packages: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();

    for artifact in &artifacts {
        let name = artifact.name.clone();
        let version = artifact.version.clone().unwrap_or_default();
        packages.entry(name).or_default().push(version);
    }

    let result: Vec<serde_json::Value> = packages
        .into_iter()
        .map(|(name, versions)| {
            serde_json::json!({
                "name": name,
                "versions": versions,
            })
        })
        .collect();

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&result).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract package name and version from a Hex tarball.
///
/// Hex tarballs are outer tar archives containing:
///   - VERSION (text: "3")
///   - metadata.config (Erlang term format with package name/version)
///   - contents.tar.gz
///   - CHECKSUM
///
/// We parse the metadata.config to extract the name and version fields.
fn extract_name_version_from_tarball(data: &[u8]) -> Result<(String, String), String> {
    let mut archive = tar::Archive::new(data);

    let entries = archive
        .entries()
        .map_err(|e| format!("Failed to read tarball entries: {}", e))?;

    for entry_result in entries {
        let mut entry = entry_result.map_err(|e| format!("Failed to read tar entry: {}", e))?;
        let path = entry
            .path()
            .map_err(|e| format!("Failed to read entry path: {}", e))?
            .to_string_lossy()
            .to_string();

        if path == "metadata.config" {
            let mut content = String::new();
            std::io::Read::read_to_string(&mut entry, &mut content)
                .map_err(|e| format!("Failed to read metadata.config: {}", e))?;

            let name = extract_erlang_term_value(&content, "name")
                .ok_or_else(|| "Missing 'name' in metadata.config".to_string())?;
            let version = extract_erlang_term_value(&content, "version")
                .ok_or_else(|| "Missing 'version' in metadata.config".to_string())?;

            return Ok((name, version));
        }
    }

    Err("metadata.config not found in tarball".to_string())
}

/// Extract a string value from Erlang term format metadata.
///
/// Hex metadata.config uses Erlang term format like:
///   {<<"name">>, <<"phoenix">>}.
///   {<<"version">>, <<"1.7.0">>}.
///
/// This is a simple parser that extracts binary string values for known keys.
fn extract_erlang_term_value(content: &str, key: &str) -> Option<String> {
    let search_pattern = format!("<<\"{}\">>", key);

    for line in content.lines() {
        let trimmed = line.trim();
        if !trimmed.contains(&search_pattern) {
            continue;
        }

        // Find the value part: the second <<"...">> in the line
        let after_key = &trimmed[trimmed.find(&search_pattern)? + search_pattern.len()..];
        let value_start = after_key.find("<<\"")?;
        let value_content = &after_key[value_start + 3..];
        let value_end = value_content.find("\">>").unwrap_or(value_content.len());
        return Some(value_content[..value_end].to_string());
    }

    None
}

// ---------------------------------------------------------------------------
// Extracted pure helpers (testable without DB)
// ---------------------------------------------------------------------------

/// Build the standard hex tarball filename: `{name}-{version}.tar`
pub(crate) fn build_hex_filename(name: &str, version: &str) -> String {
    format!("{}-{}.tar", name, version)
}

/// Build the artifact storage path: `{name}/{version}/{name}-{version}.tar`
pub(crate) fn build_hex_artifact_path(name: &str, version: &str) -> String {
    let filename = build_hex_filename(name, version);
    format!("{}/{}/{}", name, version, filename)
}

/// Build the storage key: `hex/{name}/{version}/{name}-{version}.tar`
pub(crate) fn build_hex_storage_key(name: &str, version: &str) -> String {
    let filename = build_hex_filename(name, version);
    format!("hex/{}/{}/{}", name, version, filename)
}

/// Build a tarball download URL: `/hex/{repo_key}/tarballs/{name}-{version}.tar`
pub(crate) fn build_hex_tarball_url(repo_key: &str, name: &str, version: &str) -> String {
    let filename = build_hex_filename(name, version);
    format!("/hex/{}/tarballs/{}", repo_key, filename)
}

/// Build hex metadata JSON for a package.
pub(crate) fn build_hex_metadata(name: &str, version: &str) -> serde_json::Value {
    let filename = build_hex_filename(name, version);
    serde_json::json!({
        "format": "hex",
        "name": name,
        "version": version,
        "filename": filename,
    })
}

/// Build the JSON publish response.
pub(crate) fn build_hex_publish_response(
    repo_key: &str,
    name: &str,
    version: &str,
) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "version": version,
        "url": build_hex_tarball_url(repo_key, name, version),
    })
}

/// Build a release entry for the package info endpoint.
pub(crate) fn build_hex_release_entry(
    repo_key: &str,
    name: &str,
    version: &str,
    checksum: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "version": version,
        "url": build_hex_tarball_url(repo_key, name, version),
        "checksum": checksum,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    // -----------------------------------------------------------------------
    // extract_credentials
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_credentials_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer hex-api-key"),
        );
        let result = extract_credentials(&headers);
        assert_eq!(
            result,
            Some(("token".to_string(), "hex-api-key".to_string()))
        );
    }

    #[test]
    fn test_extract_credentials_bearer_lowercase() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("bearer my-hex-token"),
        );
        let result = extract_credentials(&headers);
        assert_eq!(
            result,
            Some(("token".to_string(), "my-hex-token".to_string()))
        );
    }

    #[test]
    fn test_extract_credentials_basic() {
        let mut headers = HeaderMap::new();
        let encoded = base64::engine::general_purpose::STANDARD.encode("alice:hex-pass");
        let value = format!("Basic {}", encoded);
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&value).unwrap(),
        );
        let result = extract_credentials(&headers);
        assert_eq!(
            result,
            Some(("alice".to_string(), "hex-pass".to_string()))
        );
    }

    #[test]
    fn test_extract_credentials_no_header() {
        let headers = HeaderMap::new();
        assert_eq!(extract_credentials(&headers), None);
    }

    #[test]
    fn test_extract_credentials_invalid_base64() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic !!!invalid"),
        );
        assert_eq!(extract_credentials(&headers), None);
    }

    #[test]
    fn test_extract_credentials_basic_no_colon() {
        let mut headers = HeaderMap::new();
        let encoded = base64::engine::general_purpose::STANDARD.encode("justuser");
        let value = format!("Basic {}", encoded);
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&value).unwrap(),
        );
        assert_eq!(extract_credentials(&headers), None);
    }

    // -----------------------------------------------------------------------
    // extract_erlang_term_value
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_erlang_term_name() {
        let content = r#"{<<"name">>, <<"phoenix">>}.
{<<"version">>, <<"1.7.0">>}.
"#;
        let result = extract_erlang_term_value(content, "name");
        assert_eq!(result, Some("phoenix".to_string()));
    }

    #[test]
    fn test_extract_erlang_term_version() {
        let content = r#"{<<"name">>, <<"phoenix">>}.
{<<"version">>, <<"1.7.0">>}.
"#;
        let result = extract_erlang_term_value(content, "version");
        assert_eq!(result, Some("1.7.0".to_string()));
    }

    #[test]
    fn test_extract_erlang_term_missing_key() {
        let content = r#"{<<"name">>, <<"phoenix">>}.
{<<"version">>, <<"1.7.0">>}.
"#;
        let result = extract_erlang_term_value(content, "description");
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_erlang_term_empty_content() {
        let result = extract_erlang_term_value("", "name");
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_erlang_term_with_hyphens_in_name() {
        let content = r#"{<<"name">>, <<"my-elixir-lib">>}.
{<<"version">>, <<"0.1.0">>}.
"#;
        let result = extract_erlang_term_value(content, "name");
        assert_eq!(result, Some("my-elixir-lib".to_string()));
    }

    #[test]
    fn test_extract_erlang_term_app_key() {
        let content = r#"{<<"app">>, <<"myapp">>}.
{<<"name">>, <<"myapp">>}.
{<<"version">>, <<"2.0.0">>}.
"#;
        let result = extract_erlang_term_value(content, "app");
        assert_eq!(result, Some("myapp".to_string()));
    }

    #[test]
    fn test_extract_erlang_term_with_extra_whitespace() {
        let content = "  {<<\"name\">>, <<\"ecto\">>}.  \n";
        let result = extract_erlang_term_value(content, "name");
        assert_eq!(result, Some("ecto".to_string()));
    }

    // -----------------------------------------------------------------------
    // extract_name_version_from_tarball
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_name_version_from_tarball_empty() {
        let result = extract_name_version_from_tarball(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_name_version_from_tarball_invalid() {
        let result = extract_name_version_from_tarball(b"not a tarball");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_name_version_from_tarball_no_metadata() {
        // Create a valid tar with no metadata.config file
        let mut builder = tar::Builder::new(Vec::new());
        let data = b"3";
        let mut header = tar::Header::new_gnu();
        header.set_path("VERSION").unwrap();
        header.set_size(data.len() as u64);
        header.set_cksum();
        builder.append(&header, &data[..]).unwrap();
        let tar_data = builder.into_inner().unwrap();

        let result = extract_name_version_from_tarball(&tar_data);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("metadata.config not found"));
    }

    #[test]
    fn test_extract_name_version_from_tarball_valid() {
        // Create a valid tar with metadata.config
        let mut builder = tar::Builder::new(Vec::new());

        let metadata = r#"{<<"name">>, <<"phoenix">>}.
{<<"version">>, <<"1.7.0">>}.
"#;
        let data = metadata.as_bytes();
        let mut header = tar::Header::new_gnu();
        header.set_path("metadata.config").unwrap();
        header.set_size(data.len() as u64);
        header.set_cksum();
        builder.append(&header, data).unwrap();
        let tar_data = builder.into_inner().unwrap();

        let result = extract_name_version_from_tarball(&tar_data);
        assert!(result.is_ok());
        let (name, version) = result.unwrap();
        assert_eq!(name, "phoenix");
        assert_eq!(version, "1.7.0");
    }

    // -----------------------------------------------------------------------
    // build_hex_filename
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_hex_filename() {
        assert_eq!(build_hex_filename("plug", "1.15.0"), "plug-1.15.0.tar");
    }

    #[test]
    fn test_build_hex_filename_hyphenated_name() {
        assert_eq!(
            build_hex_filename("my-elixir-lib", "0.1.0"),
            "my-elixir-lib-0.1.0.tar"
        );
    }

    #[test]
    fn test_build_hex_filename_underscore_name() {
        assert_eq!(
            build_hex_filename("ecto_sql", "3.11.0"),
            "ecto_sql-3.11.0.tar"
        );
    }

    // -----------------------------------------------------------------------
    // build_hex_artifact_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_hex_artifact_path() {
        assert_eq!(
            build_hex_artifact_path("ecto", "3.11.0"),
            "ecto/3.11.0/ecto-3.11.0.tar"
        );
    }

    #[test]
    fn test_build_hex_artifact_path_prerelease() {
        assert_eq!(
            build_hex_artifact_path("phoenix", "1.8.0-rc.1"),
            "phoenix/1.8.0-rc.1/phoenix-1.8.0-rc.1.tar"
        );
    }

    #[test]
    fn test_build_hex_artifact_path_simple() {
        assert_eq!(
            build_hex_artifact_path("jason", "1.4.0"),
            "jason/1.4.0/jason-1.4.0.tar"
        );
    }

    // -----------------------------------------------------------------------
    // build_hex_storage_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_hex_storage_key() {
        assert_eq!(
            build_hex_storage_key("jason", "1.4.0"),
            "hex/jason/1.4.0/jason-1.4.0.tar"
        );
    }

    #[test]
    fn test_build_hex_storage_key_starts_with_hex() {
        let key = build_hex_storage_key("plug", "2.0.0");
        assert!(key.starts_with("hex/"));
    }

    #[test]
    fn test_build_hex_storage_key_contains_filename() {
        let key = build_hex_storage_key("ecto", "3.11.0");
        assert!(key.ends_with("ecto-3.11.0.tar"));
    }

    // -----------------------------------------------------------------------
    // build_hex_tarball_url
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_hex_tarball_url() {
        assert_eq!(
            build_hex_tarball_url("hex-local", "plug", "1.15.0"),
            "/hex/hex-local/tarballs/plug-1.15.0.tar"
        );
    }

    #[test]
    fn test_build_hex_tarball_url_starts_with_hex() {
        let url = build_hex_tarball_url("my-repo", "phoenix", "1.7.0");
        assert!(url.starts_with("/hex/"));
    }

    #[test]
    fn test_build_hex_tarball_url_contains_tarballs() {
        let url = build_hex_tarball_url("repo", "ecto", "3.0.0");
        assert!(url.contains("/tarballs/"));
    }

    // -----------------------------------------------------------------------
    // build_hex_metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_hex_metadata() {
        let meta = build_hex_metadata("phoenix", "1.7.0");
        assert_eq!(meta["format"], "hex");
        assert_eq!(meta["name"], "phoenix");
        assert_eq!(meta["version"], "1.7.0");
        assert_eq!(meta["filename"], "phoenix-1.7.0.tar");
    }

    #[test]
    fn test_build_hex_metadata_has_all_keys() {
        let meta = build_hex_metadata("ecto", "3.11.0");
        let obj = meta.as_object().unwrap();
        assert!(obj.contains_key("format"));
        assert!(obj.contains_key("name"));
        assert!(obj.contains_key("version"));
        assert!(obj.contains_key("filename"));
    }

    #[test]
    fn test_build_hex_metadata_four_keys() {
        let meta = build_hex_metadata("plug", "1.0.0");
        assert_eq!(meta.as_object().unwrap().len(), 4);
    }

    // -----------------------------------------------------------------------
    // build_hex_publish_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_hex_publish_response() {
        let resp = build_hex_publish_response("hex-local", "phoenix", "1.7.0");
        assert_eq!(resp["name"], "phoenix");
        assert_eq!(resp["version"], "1.7.0");
        assert_eq!(resp["url"], "/hex/hex-local/tarballs/phoenix-1.7.0.tar");
    }

    #[test]
    fn test_build_hex_publish_response_has_url() {
        let resp = build_hex_publish_response("repo", "ecto", "3.0.0");
        let url = resp["url"].as_str().unwrap();
        assert!(url.starts_with("/hex/"));
        assert!(url.contains("ecto-3.0.0.tar"));
    }

    #[test]
    fn test_build_hex_publish_response_three_keys() {
        let resp = build_hex_publish_response("r", "p", "1.0.0");
        assert_eq!(resp.as_object().unwrap().len(), 3);
    }

    // -----------------------------------------------------------------------
    // build_hex_release_entry
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_hex_release_entry() {
        let entry = build_hex_release_entry("hex-local", "plug", "1.15.0", Some("abc123"));
        assert_eq!(entry["version"], "1.15.0");
        assert_eq!(entry["checksum"], "abc123");
        assert!(entry["url"].as_str().unwrap().contains("plug-1.15.0.tar"));
    }

    #[test]
    fn test_build_hex_release_entry_no_checksum() {
        let entry = build_hex_release_entry("repo", "ecto", "3.11.0", None);
        assert_eq!(entry["version"], "3.11.0");
        assert!(entry["checksum"].is_null());
    }

    #[test]
    fn test_build_hex_release_entry_url_format() {
        let entry = build_hex_release_entry("my-repo", "phoenix", "1.7.0", None);
        assert_eq!(entry["url"], "/hex/my-repo/tarballs/phoenix-1.7.0.tar");
    }

    // -----------------------------------------------------------------------
    // SHA256 computation
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256_computation() {
        let mut hasher = Sha256::new();
        hasher.update(b"hex package data");
        let result = format!("{:x}", hasher.finalize());
        assert_eq!(result.len(), 64);
    }

    // -----------------------------------------------------------------------
    // RepoInfo struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_info_hosted() {
        let id = uuid::Uuid::new_v4();
        let repo = RepoInfo {
            id,
            storage_path: "/data/hex".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: None,
        };
        assert_eq!(repo.repo_type, "hosted");
        assert!(repo.upstream_url.is_none());
    }

    #[test]
    fn test_repo_info_remote() {
        let repo = RepoInfo {
            id: uuid::Uuid::new_v4(),
            storage_path: "/cache".to_string(),
            repo_type: "remote".to_string(),
            upstream_url: Some("https://repo.hex.pm".to_string()),
        };
        assert_eq!(
            repo.upstream_url.as_deref(),
            Some("https://repo.hex.pm")
        );
    }
}
