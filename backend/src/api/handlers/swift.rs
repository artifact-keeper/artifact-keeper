//! Swift Package Registry API handlers (SE-0292).
//!
//! Implements the endpoints required by the Swift Package Manager registry protocol.
//!
//! Routes are mounted at `/swift/{repo_key}/...`:
//!   GET  /swift/:repo_key/:scope/:name                 - List package releases
//!   GET  /swift/:repo_key/:scope/:name/:version         - Get release metadata
//!   GET  /swift/:repo_key/:scope/:name/:version.zip     - Download source archive
//!   GET  /swift/:repo_key/:scope/:name/:version/Package.swift - Fetch manifest
//!   PUT  /swift/:repo_key/:scope/:name/:version         - Publish release (auth required)
//!   GET  /swift/:repo_key/identifiers?url={package_url} - Lookup package identifiers

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

use crate::api::handlers::proxy_helpers;
use crate::api::SharedState;
use crate::formats::swift::SwiftHandler;
use crate::services::auth_service::AuthService;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::StorageBackend;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Lookup package identifiers by URL
        .route("/:repo_key/identifiers", get(lookup_identifiers))
        // List package releases
        .route("/:repo_key/:scope/:name", get(list_releases))
        // Version path: GET dispatches to metadata/archive/manifest, PUT publishes
        .route(
            "/:repo_key/:scope/:name/*version_path",
            get(version_path_handler).put(publish_release_from_wildcard),
        )
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
            .header("WWW-Authenticate", "Basic realm=\"swift\"")
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
                .header("WWW-Authenticate", "Basic realm=\"swift\"")
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

async fn resolve_swift_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
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
    if fmt != "swift" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not a Swift repository (format: {})",
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
// Response helpers
// ---------------------------------------------------------------------------

/// Build a JSON response with the required Content-Version: 1 header.
fn swift_json_response(status: StatusCode, body: serde_json::Value) -> Response {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .header("Content-Version", "1")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap()
}

/// Build an error response with the Content-Version: 1 header.
fn swift_error_response(status: StatusCode, detail: &str) -> Response {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/problem+json")
        .header("Content-Version", "1")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "detail": detail,
            }))
            .unwrap(),
        ))
        .unwrap()
}

// ---------------------------------------------------------------------------
// GET /swift/:repo_key/:scope/:name -- List package releases
// ---------------------------------------------------------------------------

async fn list_releases(
    State(state): State<SharedState>,
    Path((repo_key, scope, name)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    // Validate the path via SwiftHandler
    let _info = SwiftHandler::parse_path(&format!("{}/{}", scope, name))
        .map_err(|e| swift_error_response(StatusCode::BAD_REQUEST, &e.to_string()))?;

    let repo = resolve_swift_repo(&state.db, &repo_key).await?;

    let package_id = format!("{}.{}", scope, name);

    let artifacts = sqlx::query!(
        r#"
        SELECT a.version, a.checksum_sha256
        FROM artifacts a
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND LOWER(a.name) = LOWER($2)
        ORDER BY a.created_at DESC
        "#,
        repo.id,
        package_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        swift_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Database error: {}", e),
        )
    })?;

    // Build releases object: version -> { url }
    let mut releases = serde_json::Map::new();
    for artifact in &artifacts {
        let version = artifact.version.clone().unwrap_or_default();
        let url = format!("/swift/{}/{}/{}/{}", repo_key, scope, name, version);
        releases.insert(
            version,
            serde_json::json!({
                "url": url,
            }),
        );
    }

    let body = serde_json::json!({
        "releases": releases,
    });

    Ok(swift_json_response(StatusCode::OK, body))
}

// ---------------------------------------------------------------------------
// Version path handler -- dispatches to version info, archive, or manifest
// ---------------------------------------------------------------------------

async fn version_path_handler(
    State(state): State<SharedState>,
    Path((repo_key, scope, name, version_path)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let version_path = version_path.trim_start_matches('/');

    if version_path.ends_with(".zip") {
        // Download source archive: /:scope/:name/:version.zip
        let version = version_path.trim_end_matches(".zip");
        return download_archive(state, &repo_key, &scope, &name, version).await;
    }

    if version_path.ends_with("/Package.swift") || version_path.contains("/Package.swift") {
        // Fetch manifest: /:scope/:name/:version/Package.swift
        let version = version_path.trim_end_matches("/Package.swift");
        return fetch_manifest(state, &repo_key, &scope, &name, version).await;
    }

    // Release metadata: /:scope/:name/:version
    get_release_metadata(state, &repo_key, &scope, &name, version_path).await
}

// ---------------------------------------------------------------------------
// GET /swift/:repo_key/:scope/:name/:version -- Get release metadata
// ---------------------------------------------------------------------------

async fn get_release_metadata(
    state: SharedState,
    repo_key: &str,
    scope: &str,
    name: &str,
    version: &str,
) -> Result<Response, Response> {
    let repo = resolve_swift_repo(&state.db, repo_key).await?;
    let package_id = format!("{}.{}", scope, name);

    let artifact = sqlx::query!(
        r#"
        SELECT a.id, a.version, a.size_bytes, a.checksum_sha256,
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
        package_id,
        version
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        swift_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Database error: {}", e),
        )
    })?
    .ok_or_else(|| swift_error_response(StatusCode::NOT_FOUND, "Release not found"))?;

    let archive_url = format!("/swift/{}/{}/{}/{}.zip", repo_key, scope, name, version);

    let mut resources = vec![serde_json::json!({
        "name": "source-archive",
        "type": "application/zip",
        "checksum": artifact.checksum_sha256.clone(),
    })];

    // Check if a manifest exists in metadata
    let has_manifest = artifact
        .metadata
        .as_ref()
        .and_then(|m| m.get("manifest"))
        .is_some();

    if has_manifest {
        resources.push(serde_json::json!({
            "name": "Package.swift",
            "type": "text/x-swift",
        }));
    }

    let body = serde_json::json!({
        "id": format!("{}.{}", scope, name),
        "version": version,
        "resources": resources,
        "metadata": artifact.metadata.clone().and_then(|m| m.get("swift_metadata").cloned()).unwrap_or(serde_json::json!({})),
    });

    let mut response = swift_json_response(StatusCode::OK, body);
    response.headers_mut().insert(
        "Link",
        format!("<{}>; rel=\"latest-version\"", archive_url)
            .parse()
            .unwrap(),
    );

    Ok(response)
}

// ---------------------------------------------------------------------------
// GET /swift/:repo_key/:scope/:name/:version.zip -- Download source archive
// ---------------------------------------------------------------------------

async fn download_archive(
    state: SharedState,
    repo_key: &str,
    scope: &str,
    name: &str,
    version: &str,
) -> Result<Response, Response> {
    let repo = resolve_swift_repo(&state.db, repo_key).await?;
    let package_id = format!("{}.{}", scope, name);

    let artifact = sqlx::query!(
        r#"
        SELECT id, storage_key, size_bytes, checksum_sha256
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND LOWER(name) = LOWER($2)
          AND version = $3
        LIMIT 1
        "#,
        repo.id,
        package_id,
        version
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        swift_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Database error: {}", e),
        )
    })?;

    let artifact = match artifact {
        Some(a) => a,
        None => {
            if repo.repo_type == "remote" {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let upstream_path = format!("{}/{}/{}.zip", scope, name, version);
                    let (content, content_type) = proxy_helpers::proxy_fetch(
                        proxy,
                        repo.id,
                        repo_key,
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
                let name_clone = package_id.clone();
                let version_clone = version.to_string();
                let upstream_path = format!("{}/{}/{}.zip", scope, name, version);
                let (content, content_type) = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    state.proxy_service.as_deref(),
                    repo.id,
                    &upstream_path,
                    |member_id, storage_path| {
                        let db = db.clone();
                        let name = name_clone.clone();
                        let version = version_clone.clone();
                        async move {
                            proxy_helpers::local_fetch_by_name_version(
                                &db,
                                member_id,
                                &storage_path,
                                &name,
                                &version,
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
                        content_type.unwrap_or_else(|| "application/zip".to_string()),
                    )
                    .header(CONTENT_LENGTH, content.len().to_string())
                    .body(Body::from(content))
                    .unwrap());
            }

            return Err(swift_error_response(
                StatusCode::NOT_FOUND,
                "Source archive not found",
            ));
        }
    };

    let storage = FilesystemStorage::new(&repo.storage_path);
    let content = storage.get(&artifact.storage_key).await.map_err(|e| {
        swift_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Storage error: {}", e),
        )
    })?;

    // Record download
    let _ = sqlx::query!(
        "INSERT INTO download_statistics (artifact_id, ip_address) VALUES ($1, '0.0.0.0')",
        artifact.id
    )
    .execute(&state.db)
    .await;

    let checksum = artifact.checksum_sha256.clone();
    let filename = format!("{}-{}-{}.zip", scope, name, version);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/zip")
        .header("Content-Version", "1")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, content.len().to_string())
        .header("Digest", format!("sha-256={}", checksum))
        .body(Body::from(content))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /swift/:repo_key/:scope/:name/:version/Package.swift -- Fetch manifest
// ---------------------------------------------------------------------------

async fn fetch_manifest(
    state: SharedState,
    repo_key: &str,
    scope: &str,
    name: &str,
    version: &str,
) -> Result<Response, Response> {
    let repo = resolve_swift_repo(&state.db, repo_key).await?;
    let package_id = format!("{}.{}", scope, name);

    let artifact = sqlx::query!(
        r#"
        SELECT am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND LOWER(a.name) = LOWER($2)
          AND a.version = $3
        LIMIT 1
        "#,
        repo.id,
        package_id,
        version
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        swift_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Database error: {}", e),
        )
    })?
    .ok_or_else(|| swift_error_response(StatusCode::NOT_FOUND, "Release not found"))?;

    let manifest = artifact
        .metadata
        .as_ref()
        .and_then(|m| m.get("manifest"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            swift_error_response(StatusCode::NOT_FOUND, "Manifest not found for this release")
        })?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/x-swift")
        .header("Content-Version", "1")
        .body(Body::from(manifest.to_string()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// PUT /swift/:repo_key/:scope/:name/*version_path -- Publish release (wildcard wrapper)
// ---------------------------------------------------------------------------

async fn publish_release_from_wildcard(
    State(state): State<SharedState>,
    Path((repo_key, scope, name, version_path)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let version = version_path.trim_start_matches('/').to_string();
    publish_release(state, repo_key, scope, name, version, headers, body).await
}

// ---------------------------------------------------------------------------
// Publish release implementation
// ---------------------------------------------------------------------------

async fn publish_release(
    state: SharedState,
    repo_key: String,
    scope: String,
    name: String,
    version: String,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    // Authenticate
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_swift_repo(&state.db, &repo_key).await?;

    // Reject writes to remote/virtual repos
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    // Validate path
    let _info = SwiftHandler::parse_path(&format!("{}/{}/{}", scope, name, version))
        .map_err(|e| swift_error_response(StatusCode::BAD_REQUEST, &e.to_string()))?;

    if body.is_empty() {
        return Err(swift_error_response(
            StatusCode::BAD_REQUEST,
            "Empty request body",
        ));
    }

    let package_id = format!("{}.{}", scope, name);
    let artifact_path = format!("{}/{}/{}/{}.zip", scope, name, version, name);

    // Check for duplicate
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND LOWER(name) = LOWER($2) AND version = $3 AND is_deleted = false",
        repo.id,
        package_id,
        version
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        swift_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Database error: {}", e),
        )
    })?;

    if existing.is_some() {
        return Err(swift_error_response(
            StatusCode::CONFLICT,
            "A release with this version already exists",
        ));
    }

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let computed_sha256 = format!("{:x}", hasher.finalize());

    // Store the file
    let storage_key = format!("swift/{}/{}/{}/{}.zip", scope, name, version, name);
    let storage = FilesystemStorage::new(&repo.storage_path);
    storage.put(&storage_key, body.clone()).await.map_err(|e| {
        swift_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Storage error: {}", e),
        )
    })?;

    // Extract manifest from multipart body if present, or store the raw archive.
    // For simplicity, we treat the body as the source archive. Metadata can be
    // supplied via the swift_metadata field in a JSON content-type header.
    let manifest = headers
        .get("X-Swift-Package-Manifest")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let swift_metadata = serde_json::json!({
        "scope": scope,
        "name": name,
        "version": version,
        "package_id": package_id,
        "manifest": manifest,
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
        package_id,
        version,
        size_bytes,
        computed_sha256,
        "application/zip",
        storage_key,
        user_id,
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        swift_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Database error: {}", e),
        )
    })?;

    // Store metadata
    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'swift', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        swift_metadata,
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
        "Swift publish: {}.{} {} to repo {}",
        scope, name, version, repo_key
    );

    Ok(swift_json_response(
        StatusCode::CREATED,
        serde_json::json!({}),
    ))
}

// ---------------------------------------------------------------------------
// GET /swift/:repo_key/identifiers?url={package_url} -- Lookup identifiers
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize, Debug)]
struct IdentifierQuery {
    url: Option<String>,
}

async fn lookup_identifiers(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    Query(query): Query<IdentifierQuery>,
) -> Result<Response, Response> {
    let repo = resolve_swift_repo(&state.db, &repo_key).await?;

    let package_url = query.url.as_deref().unwrap_or("");
    if package_url.is_empty() {
        return Err(swift_error_response(
            StatusCode::BAD_REQUEST,
            "Missing required 'url' query parameter",
        ));
    }

    // Look up packages that have a matching repository URL in their metadata
    let artifacts = sqlx::query!(
        r#"
        SELECT DISTINCT a.name
        FROM artifacts a
        JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND am.metadata->>'repository_url' = $2
        "#,
        repo.id,
        package_url
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        swift_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Database error: {}", e),
        )
    })?;

    let identifiers: Vec<&str> = artifacts.iter().map(|a| a.name.as_str()).collect();

    let body = serde_json::json!({
        "identifiers": identifiers,
    });

    Ok(swift_json_response(StatusCode::OK, body))
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
            HeaderValue::from_static("Bearer my-swift-token"),
        );
        let result = extract_credentials(&headers);
        assert_eq!(
            result,
            Some(("token".to_string(), "my-swift-token".to_string()))
        );
    }

    #[test]
    fn test_extract_credentials_bearer_lowercase() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("bearer my-token"),
        );
        let result = extract_credentials(&headers);
        assert_eq!(result, Some(("token".to_string(), "my-token".to_string())));
    }

    #[test]
    fn test_extract_credentials_basic() {
        let mut headers = HeaderMap::new();
        let encoded = base64::engine::general_purpose::STANDARD.encode("alice:p@ssword");
        let value = format!("Basic {}", encoded);
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&value).unwrap(),
        );
        let result = extract_credentials(&headers);
        assert_eq!(result, Some(("alice".to_string(), "p@ssword".to_string())));
    }

    #[test]
    fn test_extract_credentials_basic_lowercase() {
        let mut headers = HeaderMap::new();
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:pass");
        let value = format!("basic {}", encoded);
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&value).unwrap(),
        );
        let result = extract_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "pass".to_string())));
    }

    #[test]
    fn test_extract_credentials_basic_with_colon_in_password() {
        let mut headers = HeaderMap::new();
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:pass:with:colons");
        let value = format!("Basic {}", encoded);
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&value).unwrap(),
        );
        let result = extract_credentials(&headers);
        assert_eq!(
            result,
            Some(("user".to_string(), "pass:with:colons".to_string()))
        );
    }

    #[test]
    fn test_extract_credentials_no_header() {
        let headers = HeaderMap::new();
        assert_eq!(extract_credentials(&headers), None);
    }

    #[test]
    fn test_extract_credentials_invalid_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Digest abc123"),
        );
        assert_eq!(extract_credentials(&headers), None);
    }

    #[test]
    fn test_extract_credentials_invalid_base64() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic !!!not-base64!!!"),
        );
        assert_eq!(extract_credentials(&headers), None);
    }

    #[test]
    fn test_extract_credentials_basic_no_colon() {
        let mut headers = HeaderMap::new();
        let encoded = base64::engine::general_purpose::STANDARD.encode("usernocolon");
        let value = format!("Basic {}", encoded);
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&value).unwrap(),
        );
        assert_eq!(extract_credentials(&headers), None);
    }

    // -----------------------------------------------------------------------
    // swift_json_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_swift_json_response_status_and_headers() {
        let body = serde_json::json!({"releases": {}});
        let response = swift_json_response(StatusCode::OK, body.clone());

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(response.headers().get("Content-Version").unwrap(), "1");
    }

    #[test]
    fn test_swift_json_response_created() {
        let body = serde_json::json!({});
        let response = swift_json_response(StatusCode::CREATED, body);
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers().get("Content-Version").unwrap(), "1");
    }

    // -----------------------------------------------------------------------
    // swift_error_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_swift_error_response_status_and_content_type() {
        let response = swift_error_response(StatusCode::NOT_FOUND, "Release not found");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/problem+json"
        );
        assert_eq!(response.headers().get("Content-Version").unwrap(), "1");
    }

    #[test]
    fn test_swift_error_response_bad_request() {
        let response = swift_error_response(StatusCode::BAD_REQUEST, "Invalid path");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // -----------------------------------------------------------------------
    // IdentifierQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_identifier_query_with_url() {
        let query: IdentifierQuery =
            serde_json::from_str(r#"{"url": "https://github.com/example/repo"}"#).unwrap();
        assert_eq!(
            query.url,
            Some("https://github.com/example/repo".to_string())
        );
    }

    #[test]
    fn test_identifier_query_without_url() {
        let query: IdentifierQuery = serde_json::from_str(r#"{}"#).unwrap();
        assert_eq!(query.url, None);
    }

    // -----------------------------------------------------------------------
    // Format-specific logic: package_id, artifact_path, storage_key, filename
    // -----------------------------------------------------------------------

    #[test]
    fn test_package_id_format() {
        let scope = "apple";
        let name = "swift-log";
        let package_id = format!("{}.{}", scope, name);
        assert_eq!(package_id, "apple.swift-log");
    }

    #[test]
    fn test_artifact_path_format() {
        let scope = "vapor";
        let name = "async-kit";
        let version = "1.2.0";
        let artifact_path = format!("{}/{}/{}/{}.zip", scope, name, version, name);
        assert_eq!(artifact_path, "vapor/async-kit/1.2.0/async-kit.zip");
    }

    #[test]
    fn test_storage_key_format() {
        let scope = "grpc";
        let name = "grpc-swift";
        let version = "2.0.0";
        let storage_key = format!("swift/{}/{}/{}/{}.zip", scope, name, version, name);
        assert_eq!(storage_key, "swift/grpc/grpc-swift/2.0.0/grpc-swift.zip");
    }

    #[test]
    fn test_download_filename_format() {
        let scope = "apple";
        let name = "swift-nio";
        let version = "2.40.0";
        let filename = format!("{}-{}-{}.zip", scope, name, version);
        assert_eq!(filename, "apple-swift-nio-2.40.0.zip");
    }

    #[test]
    fn test_sha256_computation() {
        let mut hasher = Sha256::new();
        hasher.update(b"test data");
        let result = format!("{:x}", hasher.finalize());
        assert_eq!(result.len(), 64);
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // -----------------------------------------------------------------------
    // Version path dispatching logic
    // -----------------------------------------------------------------------

    #[test]
    fn test_version_path_zip_detection() {
        let path = "1.2.0.zip";
        assert!(path.ends_with(".zip"));
        let version = path.trim_end_matches(".zip");
        assert_eq!(version, "1.2.0");
    }

    #[test]
    fn test_version_path_manifest_detection() {
        let path = "1.2.0/Package.swift";
        assert!(path.ends_with("/Package.swift") || path.contains("/Package.swift"));
        let version = path.trim_end_matches("/Package.swift");
        assert_eq!(version, "1.2.0");
    }

    #[test]
    fn test_version_path_metadata_no_suffix() {
        let path = "1.2.0";
        assert!(!path.ends_with(".zip"));
        assert!(!path.ends_with("/Package.swift"));
        // Falls through to get_release_metadata
    }

    // -----------------------------------------------------------------------
    // RepoInfo struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_info_construction() {
        let id = uuid::Uuid::new_v4();
        let repo = RepoInfo {
            id,
            storage_path: "/data/swift-repo".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: None,
        };
        assert_eq!(repo.id, id);
        assert_eq!(repo.storage_path, "/data/swift-repo");
        assert_eq!(repo.repo_type, "hosted");
        assert!(repo.upstream_url.is_none());
    }

    #[test]
    fn test_repo_info_remote() {
        let repo = RepoInfo {
            id: uuid::Uuid::new_v4(),
            storage_path: "/data/cache".to_string(),
            repo_type: "remote".to_string(),
            upstream_url: Some("https://swift-packages.example.com".to_string()),
        };
        assert_eq!(repo.repo_type, "remote");
        assert_eq!(
            repo.upstream_url.as_deref(),
            Some("https://swift-packages.example.com")
        );
    }
}
