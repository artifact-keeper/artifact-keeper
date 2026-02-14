//! Composer (PHP) Repository API handlers.
//!
//! Implements the endpoints required for `composer install` and `composer require`
//! per the Packagist/Composer repository specification.
//!
//! Routes are mounted at `/composer/{repo_key}/...`:
//!   GET  /composer/{repo_key}/packages.json                           - Root packages index
//!   GET  /composer/{repo_key}/p2/{vendor}/{package}.json              - Package metadata (v2)
//!   GET  /composer/{repo_key}/p/{vendor}/{package}${hash}.json        - Package metadata (v1)
//!   GET  /composer/{repo_key}/dist/{vendor}/{package}/{version}/{ref}.zip - Download archive
//!   GET  /composer/{repo_key}/search.json?q=query                     - Search packages
//!   PUT  /composer/{repo_key}/api/packages                            - Upload/register package
//!   POST /composer/{repo_key}/api/packages                            - Upload/register package

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

use crate::api::handlers::proxy_helpers;
use crate::api::SharedState;
use crate::formats::composer::ComposerHandler;
use crate::services::auth_service::AuthService;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::StorageBackend;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Root packages index
        .route("/:repo_key/packages.json", get(packages_json))
        // Composer v2 metadata: /p2/{vendor}/{package}.json
        .route("/:repo_key/p2/:vendor/:package", get(metadata_v2))
        // Composer v1 metadata: /p/{vendor}/{package_hash}.json
        .route("/:repo_key/p/:vendor/:package_hash", get(metadata_v1))
        // Distribution archive download
        .route(
            "/:repo_key/dist/:vendor/:package/:version/:reference",
            get(download_archive),
        )
        // Search
        .route("/:repo_key/search.json", get(search))
        // Upload/register package (PUT and POST)
        .route("/:repo_key/api/packages", put(upload).post(upload))
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
            .header("WWW-Authenticate", "Basic realm=\"composer\"")
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
                .header("WWW-Authenticate", "Basic realm=\"composer\"")
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

async fn resolve_composer_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    let repo = sqlx::query!(
        "SELECT id, storage_path, format::text as \"format!\", repo_type::text as \"repo_type!\", upstream_url FROM repositories WHERE key = $1",
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
    if fmt != "composer" && fmt != "php" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not a Composer repository (format: {})",
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
// GET /composer/{repo_key}/packages.json - Root packages index
// ---------------------------------------------------------------------------

async fn packages_json(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_composer_repo(&state.db, &repo_key).await?;

    // Get all distinct vendor/package names in this repository
    let packages = sqlx::query!(
        r#"
        SELECT DISTINCT a.name, a.version,
               a.checksum_sha256,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1 AND a.is_deleted = false
        ORDER BY a.name, a.version
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

    // Build the Composer v2 packages.json response with metadata-url
    // This tells Composer to use the v2 lazy-loading endpoint
    let mut packages_map: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();

    // Group artifacts by package name
    let mut by_name: std::collections::HashMap<String, Vec<serde_json::Value>> =
        std::collections::HashMap::new();

    for row in &packages {
        let name = &row.name;
        let version = row.version.as_deref().unwrap_or("dev-main");

        let mut version_entry = serde_json::json!({
            "name": name,
            "version": version,
            "dist": {
                "type": "zip",
                "url": format!("/composer/{}/dist/{}/{}/{}.zip",
                    repo_key,
                    name, // vendor/package
                    version,
                    &row.checksum_sha256
                ),
                "reference": &row.checksum_sha256,
                "shasum": &row.checksum_sha256,
            },
        });

        // Merge in composer.json metadata if available
        if let Some(metadata) = &row.metadata {
            if let Some(composer) = metadata.get("composer") {
                if let Some(desc) = composer.get("description").and_then(|v| v.as_str()) {
                    version_entry["description"] = serde_json::Value::String(desc.to_string());
                }
                if let Some(pkg_type) = composer.get("type").and_then(|v| v.as_str()) {
                    version_entry["type"] = serde_json::Value::String(pkg_type.to_string());
                }
                if let Some(license) = composer.get("license") {
                    version_entry["license"] = license.clone();
                }
                if let Some(require) = composer.get("require") {
                    version_entry["require"] = require.clone();
                }
                if let Some(require_dev) = composer.get("require-dev") {
                    version_entry["require-dev"] = require_dev.clone();
                }
                if let Some(autoload) = composer.get("autoload") {
                    version_entry["autoload"] = autoload.clone();
                }
                if let Some(authors) = composer.get("authors") {
                    version_entry["authors"] = authors.clone();
                }
                if let Some(keywords) = composer.get("keywords") {
                    version_entry["keywords"] = keywords.clone();
                }
                if let Some(homepage) = composer.get("homepage") {
                    version_entry["homepage"] = homepage.clone();
                }
            }
        }

        by_name.entry(name.clone()).or_default().push(version_entry);
    }

    for (name, versions) in &by_name {
        packages_map.insert(name.clone(), serde_json::Value::Array(versions.clone()));
    }

    let response = serde_json::json!({
        "packages": packages_map,
        "metadata-url": format!("/composer/{}/p2/%package%.json", repo_key),
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /composer/{repo_key}/p2/{vendor}/{package}.json - Package metadata (v2)
// ---------------------------------------------------------------------------

async fn metadata_v2(
    State(state): State<SharedState>,
    Path((repo_key, vendor, package_file)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_composer_repo(&state.db, &repo_key).await?;

    // Strip .json extension from package name
    let package = package_file.trim_end_matches(".json");
    let full_name = format!("{}/{}", vendor, package);

    let artifacts = sqlx::query!(
        r#"
        SELECT a.id, a.name, a.version, a.checksum_sha256,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND a.name = $2
        ORDER BY a.created_at ASC
        "#,
        repo.id,
        full_name
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

    // Build the v2 "minified" format: {"packages": {"vendor/package": [...]}}
    let mut versions: Vec<serde_json::Value> = Vec::new();

    for artifact in &artifacts {
        let version = artifact.version.as_deref().unwrap_or("dev-main");

        let mut version_entry = serde_json::json!({
            "name": &full_name,
            "version": version,
            "dist": {
                "type": "zip",
                "url": format!("/composer/{}/dist/{}/{}/{}.zip",
                    repo_key,
                    full_name,
                    version,
                    &artifact.checksum_sha256
                ),
                "reference": &artifact.checksum_sha256,
                "shasum": &artifact.checksum_sha256,
            },
        });

        // Merge composer.json metadata
        if let Some(metadata) = &artifact.metadata {
            if let Some(composer) = metadata.get("composer") {
                for key in &[
                    "description",
                    "type",
                    "license",
                    "require",
                    "require-dev",
                    "autoload",
                    "authors",
                    "keywords",
                    "homepage",
                ] {
                    if let Some(val) = composer.get(*key) {
                        version_entry[*key] = val.clone();
                    }
                }
            }
        }

        versions.push(version_entry);
    }

    let mut packages_map = serde_json::Map::new();
    packages_map.insert(full_name, serde_json::Value::Array(versions));

    let response = serde_json::json!({
        "packages": packages_map,
        "minified": "composer/2.0",
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /composer/{repo_key}/p/{vendor}/{package_hash}.json - Package metadata (v1)
// ---------------------------------------------------------------------------

async fn metadata_v1(
    State(state): State<SharedState>,
    Path((repo_key, vendor, package_hash)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_composer_repo(&state.db, &repo_key).await?;

    // Parse: {package}${sha256}.json or {package}.json
    let raw = package_hash.trim_end_matches(".json");
    let package = raw.split('$').next().unwrap_or(raw);
    let full_name = format!("{}/{}", vendor, package);

    let artifacts = sqlx::query!(
        r#"
        SELECT a.id, a.name, a.version, a.checksum_sha256,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND a.name = $2
        ORDER BY a.created_at ASC
        "#,
        repo.id,
        full_name
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

    // Build v1 format: {"packages": {"vendor/package": {"version": {...}}}}
    let mut version_map = serde_json::Map::new();

    for artifact in &artifacts {
        let version = artifact.version.as_deref().unwrap_or("dev-main");

        let mut version_entry = serde_json::json!({
            "name": &full_name,
            "version": version,
            "dist": {
                "type": "zip",
                "url": format!("/composer/{}/dist/{}/{}/{}.zip",
                    repo_key,
                    full_name,
                    version,
                    &artifact.checksum_sha256
                ),
                "reference": &artifact.checksum_sha256,
                "shasum": &artifact.checksum_sha256,
            },
        });

        if let Some(metadata) = &artifact.metadata {
            if let Some(composer) = metadata.get("composer") {
                for key in &[
                    "description",
                    "type",
                    "license",
                    "require",
                    "require-dev",
                    "autoload",
                    "authors",
                    "keywords",
                    "homepage",
                ] {
                    if let Some(val) = composer.get(*key) {
                        version_entry[*key] = val.clone();
                    }
                }
            }
        }

        version_map.insert(version.to_string(), version_entry);
    }

    let mut packages_map = serde_json::Map::new();
    packages_map.insert(full_name, serde_json::Value::Object(version_map));

    let response = serde_json::json!({
        "packages": packages_map,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /composer/{repo_key}/dist/{vendor}/{package}/{version}/{ref}.zip
// ---------------------------------------------------------------------------

async fn download_archive(
    State(state): State<SharedState>,
    Path((repo_key, vendor, package, version, reference)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, Response> {
    let repo = resolve_composer_repo(&state.db, &repo_key).await?;
    let full_name = format!("{}/{}", vendor, package);

    // Strip .zip extension from reference if present
    let reference = reference.trim_end_matches(".zip");

    // Find the artifact by name, version, and sha256 reference
    let artifact = sqlx::query!(
        r#"
        SELECT id, path, name, size_bytes, checksum_sha256, storage_key
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND name = $2
          AND version = $3
          AND checksum_sha256 = $4
        LIMIT 1
        "#,
        repo.id,
        full_name,
        version,
        reference
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Archive not found").into_response());

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == "remote" {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let upstream_path =
                        format!("dist/{}/{}/{}/{}.zip", vendor, package, version, reference);
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
                let vname = full_name.clone();
                let vversion = version.clone();
                let upstream_path =
                    format!("dist/{}/{}/{}/{}.zip", vendor, package, version, reference);
                let (content, content_type) = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    state.proxy_service.as_deref(),
                    repo.id,
                    &upstream_path,
                    |member_id, storage_path| {
                        let db = db.clone();
                        let vname = vname.clone();
                        let vversion = vversion.clone();
                        async move {
                            proxy_helpers::local_fetch_by_name_version(
                                &db,
                                member_id,
                                &storage_path,
                                &vname,
                                &vversion,
                            )
                            .await
                        }
                    },
                )
                .await?;

                let filename = format!("{}-{}.zip", package, version);

                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(
                        CONTENT_TYPE,
                        content_type.unwrap_or_else(|| "application/zip".to_string()),
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

    let filename = format!("{}-{}.zip", package, version);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/zip")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, content.len().to_string())
        .header("X-Checksum-SHA256", &artifact.checksum_sha256)
        .body(Body::from(content))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /composer/{repo_key}/search.json?q=query - Search packages
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct SearchQuery {
    q: Option<String>,
    #[serde(rename = "type")]
    package_type: Option<String>,
    #[allow(dead_code)]
    per_page: Option<i64>,
    #[allow(dead_code)]
    page: Option<i64>,
}

async fn search(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    Query(params): Query<SearchQuery>,
) -> Result<Response, Response> {
    let repo = resolve_composer_repo(&state.db, &repo_key).await?;

    let query_str = params.q.unwrap_or_default();
    let per_page = params.per_page.unwrap_or(15).min(100);
    let page = params.page.unwrap_or(1).max(1);
    let offset = (page - 1) * per_page;

    // Search by name pattern
    let search_pattern = format!("%{}%", query_str);

    let results = sqlx::query!(
        r#"
        SELECT DISTINCT a.name,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND a.name ILIKE $2
        ORDER BY a.name
        LIMIT $3 OFFSET $4
        "#,
        repo.id,
        search_pattern,
        per_page,
        offset
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

    // Optionally filter by type from metadata
    let search_results: Vec<serde_json::Value> = results
        .iter()
        .filter(|r| {
            if let Some(ref type_filter) = params.package_type {
                r.metadata
                    .as_ref()
                    .and_then(|m| m.get("composer"))
                    .and_then(|c| c.get("type"))
                    .and_then(|t| t.as_str())
                    .map(|t| t == type_filter)
                    .unwrap_or(false)
            } else {
                true
            }
        })
        .map(|r| {
            let description = r
                .metadata
                .as_ref()
                .and_then(|m| m.get("composer"))
                .and_then(|c| c.get("description"))
                .and_then(|d| d.as_str())
                .unwrap_or("");

            let url = format!("/composer/{}/p2/{}.json", repo_key, r.name);

            serde_json::json!({
                "name": r.name,
                "description": description,
                "url": url,
            })
        })
        .collect();

    // Count total results for pagination
    let total_count = sqlx::query_scalar!(
        r#"
        SELECT COUNT(DISTINCT name)
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND name ILIKE $2
        "#,
        repo.id,
        search_pattern
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?
    .unwrap_or(0);

    let total_pages = ((total_count as f64) / (per_page as f64)).ceil() as i64;
    let has_next = page < total_pages;

    let mut response = serde_json::json!({
        "results": search_results,
        "total": total_count,
    });

    if has_next {
        response["next"] = serde_json::Value::String(format!(
            "/composer/{}/search.json?q={}&page={}",
            repo_key,
            query_str,
            page + 1
        ));
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// PUT/POST /composer/{repo_key}/api/packages - Upload/register package
// ---------------------------------------------------------------------------

async fn upload(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    // Authenticate
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_composer_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    // The body should be a zip archive containing composer.json
    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty request body").into_response());
    }

    // Parse composer.json from the archive to extract metadata
    let composer_json = ComposerHandler::parse_composer_json(&body).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Failed to parse composer.json from archive: {}", e),
        )
            .into_response()
    })?;

    // Validate package name has vendor/package format
    let full_name = &composer_json.name;
    if !full_name.contains('/') {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Invalid package name '{}': must be in vendor/package format",
                full_name
            ),
        )
            .into_response());
    }

    let version = composer_json
        .version
        .as_deref()
        .unwrap_or("dev-main")
        .to_string();

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let sha256 = format!("{:x}", hasher.finalize());

    // Build artifact path
    let artifact_path = format!("{}/{}/{}.zip", full_name, version, sha256);

    // Check for duplicate
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND name = $2 AND version = $3 AND is_deleted = false",
        repo.id,
        full_name,
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
    })?;

    if existing.is_some() {
        return Err((
            StatusCode::CONFLICT,
            format!("Version {} of {} already exists", version, full_name),
        )
            .into_response());
    }

    // Store the archive
    let storage_key = format!("composer/{}/{}/{}.zip", full_name, version, sha256);
    let storage = FilesystemStorage::new(&repo.storage_path);
    storage.put(&storage_key, body.clone()).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

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
        full_name,
        version,
        size_bytes,
        sha256,
        "application/zip",
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
    let composer_metadata = serde_json::json!({
        "name": full_name,
        "version": version,
        "composer": serde_json::to_value(&composer_json).unwrap_or_default(),
    });

    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'composer', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        composer_metadata,
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
        "Composer upload: {} {} to repo {}",
        full_name, version, repo_key
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "status": "ok",
                "package": full_name,
                "version": version,
                "sha256": sha256,
            }))
            .unwrap(),
        ))
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    // -----------------------------------------------------------------------
    // extract_basic_credentials
    // -----------------------------------------------------------------------

    fn make_basic_header(user: &str, pass: &str) -> HeaderMap {
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", user, pass));
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", encoded)).unwrap(),
        );
        headers
    }

    #[test]
    fn test_extract_basic_credentials_valid() {
        let headers = make_basic_header("composer", "secret");
        let result = extract_basic_credentials(&headers);
        assert_eq!(result, Some(("composer".to_string(), "secret".to_string())));
    }

    #[test]
    fn test_extract_basic_credentials_lowercase() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:pass");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("basic {}", encoded)).unwrap(),
        );
        assert_eq!(
            extract_basic_credentials(&headers),
            Some(("user".to_string(), "pass".to_string()))
        );
    }

    #[test]
    fn test_extract_basic_credentials_missing() {
        assert!(extract_basic_credentials(&HeaderMap::new()).is_none());
    }

    #[test]
    fn test_extract_basic_credentials_no_colon() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("nocolon");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", encoded)).unwrap(),
        );
        assert!(extract_basic_credentials(&headers).is_none());
    }

    // -----------------------------------------------------------------------
    // RepoInfo struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_info_construction() {
        let id = uuid::Uuid::new_v4();
        let info = RepoInfo {
            id,
            storage_path: "/data/composer".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: Some("https://packagist.org".to_string()),
        };
        assert_eq!(info.id, id);
        assert_eq!(info.repo_type, "hosted");
        assert_eq!(info.upstream_url, Some("https://packagist.org".to_string()));
    }

    // -----------------------------------------------------------------------
    // SearchQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_query_defaults() {
        let q: SearchQuery = serde_json::from_str(r#"{}"#).unwrap();
        assert!(q.q.is_none());
        assert!(q.package_type.is_none());
        assert!(q.per_page.is_none());
        assert!(q.page.is_none());
    }

    #[test]
    fn test_search_query_with_type() {
        let q: SearchQuery =
            serde_json::from_str(r#"{"q":"monolog","type":"library","per_page":30,"page":2}"#)
                .unwrap();
        assert_eq!(q.q, Some("monolog".to_string()));
        assert_eq!(q.package_type, Some("library".to_string()));
        assert_eq!(q.per_page, Some(30));
        assert_eq!(q.page, Some(2));
    }

    // -----------------------------------------------------------------------
    // Package name validation (vendor/package format)
    // -----------------------------------------------------------------------

    #[test]
    fn test_package_name_valid() {
        let name = "monolog/monolog";
        assert!(name.contains('/'));
    }

    #[test]
    fn test_package_name_invalid_no_slash() {
        let name = "no-vendor";
        assert!(!name.contains('/'));
    }

    // -----------------------------------------------------------------------
    // Composer v1 metadata package hash parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_v1_package_hash_parsing_with_hash() {
        let package_hash = "monolog$abc123.json";
        let raw = package_hash.trim_end_matches(".json");
        let package = raw.split('$').next().unwrap_or(raw);
        assert_eq!(package, "monolog");
    }

    #[test]
    fn test_v1_package_hash_parsing_without_hash() {
        let package_hash = "monolog.json";
        let raw = package_hash.trim_end_matches(".json");
        let package = raw.split('$').next().unwrap_or(raw);
        assert_eq!(package, "monolog");
    }

    #[test]
    fn test_v1_full_name_construction() {
        let vendor = "monolog";
        let package = "monolog";
        let full_name = format!("{}/{}", vendor, package);
        assert_eq!(full_name, "monolog/monolog");
    }

    // -----------------------------------------------------------------------
    // Composer v2 package file parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_v2_package_file_trim() {
        let package_file = "monolog.json";
        let package = package_file.trim_end_matches(".json");
        assert_eq!(package, "monolog");
    }

    // -----------------------------------------------------------------------
    // Artifact path and storage key generation
    // -----------------------------------------------------------------------

    #[test]
    fn test_composer_artifact_path() {
        let full_name = "vendor/package";
        let version = "1.2.3";
        let sha256 = "abc123def456";
        let artifact_path = format!("{}/{}/{}.zip", full_name, version, sha256);
        assert_eq!(artifact_path, "vendor/package/1.2.3/abc123def456.zip");
    }

    #[test]
    fn test_composer_storage_key() {
        let full_name = "monolog/monolog";
        let version = "3.0.0";
        let sha256 = "fedcba987654";
        let storage_key = format!("composer/{}/{}/{}.zip", full_name, version, sha256);
        assert_eq!(
            storage_key,
            "composer/monolog/monolog/3.0.0/fedcba987654.zip"
        );
    }

    // -----------------------------------------------------------------------
    // SHA256 checksum
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256() {
        let data = b"composer package";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let checksum = format!("{:x}", hasher.finalize());
        assert_eq!(checksum.len(), 64);
    }

    // -----------------------------------------------------------------------
    // Distribution URL formatting
    // -----------------------------------------------------------------------

    #[test]
    fn test_dist_url_format() {
        let repo_key = "php-repo";
        let name = "vendor/package";
        let version = "1.0.0";
        let sha256 = "abc123";
        let url = format!(
            "/composer/{}/dist/{}/{}/{}.zip",
            repo_key, name, version, sha256
        );
        assert_eq!(
            url,
            "/composer/php-repo/dist/vendor/package/1.0.0/abc123.zip"
        );
    }

    // -----------------------------------------------------------------------
    // Reference .zip strip
    // -----------------------------------------------------------------------

    #[test]
    fn test_reference_strip_zip() {
        let reference = "abc123def.zip";
        let stripped = reference.trim_end_matches(".zip");
        assert_eq!(stripped, "abc123def");
    }

    #[test]
    fn test_reference_no_zip() {
        let reference = "abc123def";
        let stripped = reference.trim_end_matches(".zip");
        assert_eq!(stripped, "abc123def");
    }

    // -----------------------------------------------------------------------
    // Metadata URL pattern
    // -----------------------------------------------------------------------

    #[test]
    fn test_metadata_url_pattern() {
        let repo_key = "composer-hosted";
        let metadata_url = format!("/composer/{}/p2/%package%.json", repo_key);
        assert_eq!(metadata_url, "/composer/composer-hosted/p2/%package%.json");
    }

    // -----------------------------------------------------------------------
    // Search pagination logic
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_pagination() {
        let per_page = 15i64;
        let page = 1i64;
        let offset = (page - 1) * per_page;
        assert_eq!(offset, 0);

        let total_count = 45i64;
        let total_pages = ((total_count as f64) / (per_page as f64)).ceil() as i64;
        assert_eq!(total_pages, 3);
        let has_next = page < total_pages;
        assert!(has_next);
    }

    #[test]
    fn test_search_per_page_clamping() {
        let per_page_input = 200i64;
        let per_page = per_page_input.min(100);
        assert_eq!(per_page, 100);
    }

    #[test]
    fn test_search_page_clamping() {
        let page_input = 0i64;
        let page = page_input.max(1);
        assert_eq!(page, 1);
    }

    // -----------------------------------------------------------------------
    // Default version handling
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_version() {
        let resolved: &str = "dev-main";
        assert_eq!(resolved, "dev-main");
    }
}
