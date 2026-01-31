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
use axum::routing::{get, put};
use axum::Router;
use base64::Engine;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

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
        // Download source archive (must come before /:version to match .zip suffix)
        .route("/:repo_key/:scope/:name/*version_path", get(version_path_handler))
        // Publish release
        .route("/:repo_key/:scope/:name/:version", put(publish_release))
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
}

async fn resolve_swift_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
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
    let _info = SwiftHandler::parse_path(&format!("{}/{}", scope, name)).map_err(|e| {
        swift_error_response(StatusCode::BAD_REQUEST, &e.to_string())
    })?;

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
        let url = format!(
            "/swift/{}/{}/{}/{}",
            repo_key, scope, name, version
        );
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

    let archive_url = format!(
        "/swift/{}/{}/{}/{}.zip",
        repo_key, scope, name, version
    );

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
    })?
    .ok_or_else(|| swift_error_response(StatusCode::NOT_FOUND, "Source archive not found"))?;

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
// PUT /swift/:repo_key/:scope/:name/:version -- Publish release
// ---------------------------------------------------------------------------

async fn publish_release(
    State(state): State<SharedState>,
    Path((repo_key, scope, name, version)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    // Authenticate
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_swift_repo(&state.db, &repo_key).await?;

    // Validate path
    let _info = SwiftHandler::parse_path(&format!("{}/{}/{}", scope, name, version)).map_err(
        |e| swift_error_response(StatusCode::BAD_REQUEST, &e.to_string()),
    )?;

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

    Ok(swift_json_response(StatusCode::CREATED, serde_json::json!({})))
}

// ---------------------------------------------------------------------------
// GET /swift/:repo_key/identifiers?url={package_url} -- Lookup identifiers
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
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

    let identifiers: Vec<&str> = artifacts
        .iter()
        .map(|a| a.name.as_str())
        .collect();

    let body = serde_json::json!({
        "identifiers": identifiers,
    });

    Ok(swift_json_response(StatusCode::OK, body))
}
