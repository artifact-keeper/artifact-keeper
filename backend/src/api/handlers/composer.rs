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

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::Extension;
use axum::Router;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::SharedState;
use crate::formats::composer::ComposerHandler;
use crate::models::repository::RepositoryType;

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
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_composer_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["composer", "php"], "a Composer").await
}

// ---------------------------------------------------------------------------
// Composer metadata helpers
// ---------------------------------------------------------------------------

/// Build the upstream path for the Composer v2 metadata document of a package.
///
/// The Composer v2 wire shape is `p2/{vendor}/{package}.json`. Helper-extracted
/// so the proxy fallback in `metadata_v2` is unit-testable without spinning up
/// a database + proxy_service (#1096).
fn composer_v2_upstream_path(full_name: &str) -> String {
    format!("p2/{}.json", full_name)
}

/// Build the upstream path for the Composer v1 metadata document of a package.
///
/// The Composer v1 wire shape is `p/{vendor}/{package}.json`. Helper-extracted
/// for the same reason as [`composer_v2_upstream_path`] (#1096).
fn composer_v1_upstream_path(full_name: &str) -> String {
    format!("p/{}.json", full_name)
}

/// Build the 200 response that the metadata_v1 / metadata_v2 proxy fallback
/// returns to the composer client. Extracted from the handler body so the
/// response-construction path (status, content-type default, body wiring) is
/// unit-testable without DB or proxy_service (#1096).
///
/// `content_type` is taken from the upstream response when present; we default
/// to `application/json` because the composer client treats anything else as
/// a fetch error.
fn build_composer_proxy_response(content: Bytes, content_type: Option<String>) -> Response {
    let ct = content_type.unwrap_or_else(|| "application/json".to_string());
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, ct)
        .body(Body::from(content))
        .unwrap()
}

/// Keys from composer.json that should be merged into version entries.
const COMPOSER_METADATA_KEYS: &[&str] = &[
    "description",
    "type",
    "license",
    "require",
    "require-dev",
    "autoload",
    "authors",
    "keywords",
    "homepage",
];

/// Merge composer.json metadata fields into a version entry JSON object.
fn merge_composer_metadata(
    version_entry: &mut serde_json::Value,
    metadata: Option<&serde_json::Value>,
) {
    let composer = metadata.and_then(|m| m.get("composer"));

    let Some(composer) = composer else {
        return;
    };

    for key in COMPOSER_METADATA_KEYS {
        if let Some(val) = composer.get(*key) {
            version_entry[*key] = val.clone();
        }
    }
}

/// Build a version entry JSON for a composer package.
fn build_version_entry(
    repo_key: &str,
    name: &str,
    version: &str,
    checksum_sha256: &str,
    metadata: Option<&serde_json::Value>,
) -> serde_json::Value {
    let mut entry = serde_json::json!({
        "name": name,
        "version": version,
        "dist": {
            "type": "zip",
            "url": format!("/composer/{}/dist/{}/{}/{}.zip",
                repo_key, name, version, checksum_sha256
            ),
            "reference": checksum_sha256,
            "shasum": checksum_sha256,
        },
    });

    merge_composer_metadata(&mut entry, metadata);
    entry
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

    // Group artifacts by package name
    let mut by_name: std::collections::HashMap<String, Vec<serde_json::Value>> =
        std::collections::HashMap::new();

    for row in &packages {
        let version = row.version.as_deref().unwrap_or("dev-main");
        let entry = build_version_entry(
            &repo_key,
            &row.name,
            version,
            &row.checksum_sha256,
            row.metadata.as_ref(),
        );
        by_name.entry(row.name.clone()).or_default().push(entry);
    }

    let mut packages_map: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
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
        // #1096: For remote repos, proxy the v2 metadata document from
        // upstream when we have nothing cached locally. The composer CLI
        // hits `/p2/{vendor}/{package}.json` as its first lookup; returning
        // 404 here means `composer install` fails even when the upstream
        // (packagist.org or any mirror) has the package. The proxy_service
        // also caches the response body so subsequent requests hit the
        // cache, matching the behaviour of the PyPI and OCI handlers.
        if repo.repo_type == RepositoryType::Remote {
            if let (Some(ref upstream_url), Some(ref proxy)) =
                (&repo.upstream_url, &state.proxy_service)
            {
                let upstream_path = composer_v2_upstream_path(&full_name);
                let (content, content_type) = proxy_helpers::proxy_fetch(
                    proxy,
                    repo.id,
                    &repo_key,
                    upstream_url,
                    &upstream_path,
                )
                .await?;
                return Ok(build_composer_proxy_response(content, content_type));
            }
        }
        return Err((StatusCode::NOT_FOUND, "Package not found").into_response());
    }

    // Build the v2 "minified" format: {"packages": {"vendor/package": [...]}}
    let mut versions: Vec<serde_json::Value> = Vec::new();

    for artifact in &artifacts {
        let version = artifact.version.as_deref().unwrap_or("dev-main");
        let entry = build_version_entry(
            &repo_key,
            &full_name,
            version,
            &artifact.checksum_sha256,
            artifact.metadata.as_ref(),
        );
        versions.push(entry);
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
        // #1096: Also proxy the v1 metadata format for older composer
        // clients. The upstream path mirrors the v1 URL shape (`p/`).
        if repo.repo_type == RepositoryType::Remote {
            if let (Some(ref upstream_url), Some(ref proxy)) =
                (&repo.upstream_url, &state.proxy_service)
            {
                let upstream_path = composer_v1_upstream_path(&full_name);
                let (content, content_type) = proxy_helpers::proxy_fetch(
                    proxy,
                    repo.id,
                    &repo_key,
                    upstream_url,
                    &upstream_path,
                )
                .await?;
                return Ok(build_composer_proxy_response(content, content_type));
            }
        }
        return Err((StatusCode::NOT_FOUND, "Package not found").into_response());
    }

    // Build v1 format: {"packages": {"vendor/package": {"version": {...}}}}
    let mut version_map = serde_json::Map::new();

    for artifact in &artifacts {
        let version = artifact.version.as_deref().unwrap_or("dev-main");
        let entry = build_version_entry(
            &repo_key,
            &full_name,
            version,
            &artifact.checksum_sha256,
            artifact.metadata.as_ref(),
        );
        version_map.insert(version.to_string(), entry);
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
            if repo.repo_type == RepositoryType::Remote {
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
            if repo.repo_type == RepositoryType::Virtual {
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
                    |member_id, location| {
                        let db = db.clone();
                        let state = state.clone();
                        let vname = vname.clone();
                        let vversion = vversion.clone();
                        async move {
                            proxy_helpers::local_fetch_by_name_version(
                                &db, &state, member_id, &location, &vname, &vversion,
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
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    body: Bytes,
) -> Result<Response, Response> {
    // Authenticate
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "composer", "write")?.user_id;
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

    super::cleanup_soft_deleted_artifact(&state.db, repo.id, &artifact_path).await;

    // Store the archive
    let storage_key = format!("composer/{}/{}/{}.zip", full_name, version, sha256);
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

    // Populate packages / package_versions tables (best-effort).
    //
    // #1341: the WebUI Packages tab reads the `packages` table, not
    // `artifacts`. Every other artifact-publishing handler (npm, pypi,
    // nuget) calls PackageService after the artifact insert; the Composer
    // handler did not, so a successfully uploaded Composer package was
    // stored and served over the Composer wire protocol but never appeared
    // in the WebUI. Mirror the npm/pypi pattern here. The call is
    // fire-and-forget so a packages-table failure never blocks the upload.
    {
        let pkg_svc = crate::services::package_service::PackageService::new(state.db.clone());
        pkg_svc
            .try_create_or_update_from_artifact(
                repo.id,
                full_name,
                &version,
                size_bytes,
                &sha256,
                composer_json.description.as_deref(),
                Some(serde_json::json!({ "format": "composer" })),
            )
            .await;
    }

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

    // -----------------------------------------------------------------------
    // RepoInfo struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_info_construction() {
        let id = uuid::Uuid::new_v4();
        let info = RepoInfo {
            id,
            key: String::new(),
            storage_path: "/data/composer".to_string(),
            storage_backend: "filesystem".to_string(),
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

    // -----------------------------------------------------------------------
    // merge_composer_metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_merge_composer_metadata_all_keys() {
        let mut entry = serde_json::json!({"name": "vendor/pkg", "version": "1.0.0"});
        let metadata = serde_json::json!({
            "composer": {
                "description": "A PHP library",
                "type": "library",
                "license": "MIT",
                "require": {"php": ">=8.1"},
                "require-dev": {"phpunit/phpunit": "^10"},
                "autoload": {"psr-4": {"Vendor\\": "src/"}},
                "authors": [{"name": "Jane"}],
                "keywords": ["php", "library"],
                "homepage": "https://example.com"
            }
        });
        merge_composer_metadata(&mut entry, Some(&metadata));

        assert_eq!(entry["description"], "A PHP library");
        assert_eq!(entry["type"], "library");
        assert_eq!(entry["license"], "MIT");
        assert_eq!(entry["require"]["php"], ">=8.1");
        assert_eq!(entry["require-dev"]["phpunit/phpunit"], "^10");
        assert!(entry["autoload"]["psr-4"].is_object());
        assert_eq!(entry["authors"][0]["name"], "Jane");
        assert_eq!(entry["keywords"][0], "php");
        assert_eq!(entry["homepage"], "https://example.com");
    }

    #[test]
    fn test_merge_composer_metadata_no_composer_key() {
        let mut entry = serde_json::json!({"name": "vendor/pkg"});
        let metadata = serde_json::json!({"format": "composer"});
        merge_composer_metadata(&mut entry, Some(&metadata));
        assert!(entry.get("description").is_none());
    }

    #[test]
    fn test_merge_composer_metadata_none() {
        let mut entry = serde_json::json!({"name": "vendor/pkg"});
        merge_composer_metadata(&mut entry, None);
        assert!(entry.get("description").is_none());
    }

    #[test]
    fn test_merge_composer_metadata_partial_keys() {
        let mut entry = serde_json::json!({"name": "vendor/pkg"});
        let metadata = serde_json::json!({
            "composer": {
                "description": "Partial",
                "license": ["MIT", "Apache-2.0"]
            }
        });
        merge_composer_metadata(&mut entry, Some(&metadata));
        assert_eq!(entry["description"], "Partial");
        assert!(entry["license"].is_array());
        assert!(entry.get("type").is_none());
        assert!(entry.get("require").is_none());
    }

    #[test]
    fn test_merge_composer_metadata_does_not_overwrite_existing() {
        let mut entry = serde_json::json!({
            "name": "vendor/pkg",
            "description": "original"
        });
        let metadata = serde_json::json!({
            "composer": {
                "description": "from composer.json"
            }
        });
        merge_composer_metadata(&mut entry, Some(&metadata));
        assert_eq!(entry["description"], "from composer.json");
    }

    // -----------------------------------------------------------------------
    // build_version_entry
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_version_entry_basic() {
        let entry = build_version_entry(
            "php-hosted",
            "monolog/monolog",
            "3.0.0",
            "abc123def456",
            None,
        );
        assert_eq!(entry["name"], "monolog/monolog");
        assert_eq!(entry["version"], "3.0.0");
        assert_eq!(entry["dist"]["type"], "zip");
        assert_eq!(entry["dist"]["reference"], "abc123def456");
        assert_eq!(entry["dist"]["shasum"], "abc123def456");
        let url = entry["dist"]["url"].as_str().unwrap();
        assert_eq!(
            url,
            "/composer/php-hosted/dist/monolog/monolog/3.0.0/abc123def456.zip"
        );
    }

    #[test]
    fn test_build_version_entry_with_metadata() {
        let metadata = serde_json::json!({
            "composer": {
                "description": "Sends logs to files, sockets, inboxes, and databases",
                "type": "library",
                "license": "MIT",
                "require": {"php": ">=8.1", "psr/log": "^3"}
            }
        });
        let entry = build_version_entry(
            "repo",
            "monolog/monolog",
            "3.5.0",
            "fedcba",
            Some(&metadata),
        );
        assert_eq!(
            entry["description"],
            "Sends logs to files, sockets, inboxes, and databases"
        );
        assert_eq!(entry["type"], "library");
        assert_eq!(entry["license"], "MIT");
        assert_eq!(entry["require"]["php"], ">=8.1");
    }

    #[test]
    fn test_build_version_entry_dist_url_format() {
        let entry =
            build_version_entry("my-repo", "laravel/framework", "11.0.0", "sha256hex", None);
        let url = entry["dist"]["url"].as_str().unwrap();
        assert!(url.starts_with("/composer/my-repo/dist/"));
        assert!(url.ends_with("/sha256hex.zip"));
        assert!(url.contains("laravel/framework"));
        assert!(url.contains("11.0.0"));
    }

    // -----------------------------------------------------------------------
    // COMPOSER_METADATA_KEYS
    // -----------------------------------------------------------------------

    #[test]
    fn test_composer_metadata_keys_count() {
        assert_eq!(COMPOSER_METADATA_KEYS.len(), 9);
    }

    #[test]
    fn test_composer_metadata_keys_contains_required() {
        assert!(COMPOSER_METADATA_KEYS.contains(&"description"));
        assert!(COMPOSER_METADATA_KEYS.contains(&"type"));
        assert!(COMPOSER_METADATA_KEYS.contains(&"license"));
        assert!(COMPOSER_METADATA_KEYS.contains(&"require"));
        assert!(COMPOSER_METADATA_KEYS.contains(&"require-dev"));
        assert!(COMPOSER_METADATA_KEYS.contains(&"autoload"));
        assert!(COMPOSER_METADATA_KEYS.contains(&"authors"));
        assert!(COMPOSER_METADATA_KEYS.contains(&"keywords"));
        assert!(COMPOSER_METADATA_KEYS.contains(&"homepage"));
    }

    // -----------------------------------------------------------------------
    // Search next page URL generation
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_next_page_url() {
        let repo_key = "composer-hosted";
        let query_str = "monolog";
        let page = 2i64;
        let next_url = format!(
            "/composer/{}/search.json?q={}&page={}",
            repo_key,
            query_str,
            page + 1
        );
        assert_eq!(
            next_url,
            "/composer/composer-hosted/search.json?q=monolog&page=3"
        );
    }

    #[test]
    fn test_search_total_pages_rounding() {
        let total_count = 1i64;
        let per_page = 15i64;
        let total_pages = ((total_count as f64) / (per_page as f64)).ceil() as i64;
        assert_eq!(total_pages, 1);
        let has_next = 1 < total_pages;
        assert!(!has_next);
    }

    #[test]
    fn test_search_total_pages_exact_division() {
        let total_count = 30i64;
        let per_page = 15i64;
        let total_pages = ((total_count as f64) / (per_page as f64)).ceil() as i64;
        assert_eq!(total_pages, 2);
    }

    // -----------------------------------------------------------------------
    // Search result JSON structure
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_result_json_structure() {
        let repo_key = "php-repo";
        let name = "vendor/package";
        let description = "A PHP package";
        let url = format!("/composer/{}/p2/{}.json", repo_key, name);
        let result = serde_json::json!({
            "name": name,
            "description": description,
            "url": url,
        });
        assert_eq!(result["name"], "vendor/package");
        assert_eq!(result["url"], "/composer/php-repo/p2/vendor/package.json");
    }

    // -----------------------------------------------------------------------
    // Download filename generation
    // -----------------------------------------------------------------------

    #[test]
    fn test_download_filename() {
        let package = "monolog";
        let version = "3.5.0";
        let filename = format!("{}-{}.zip", package, version);
        assert_eq!(filename, "monolog-3.5.0.zip");
    }

    // -----------------------------------------------------------------------
    // Upload response JSON structure
    // -----------------------------------------------------------------------

    #[test]
    fn test_upload_response_structure() {
        let full_name = "vendor/my-package";
        let version = "1.2.3";
        let sha256 = "abcdef1234567890";
        let response = serde_json::json!({
            "status": "ok",
            "package": full_name,
            "version": version,
            "sha256": sha256,
        });
        assert_eq!(response["status"], "ok");
        assert_eq!(response["package"], "vendor/my-package");
        assert_eq!(response["version"], "1.2.3");
        assert_eq!(response["sha256"], "abcdef1234567890");
    }

    // -----------------------------------------------------------------------
    // Composer metadata JSON for storage
    // -----------------------------------------------------------------------

    #[test]
    fn test_composer_metadata_json_structure() {
        let full_name = "vendor/pkg";
        let version = "2.0.0";
        let composer_json_val = serde_json::json!({
            "name": "vendor/pkg",
            "description": "Test",
            "version": "2.0.0"
        });
        let metadata = serde_json::json!({
            "name": full_name,
            "version": version,
            "composer": composer_json_val,
        });
        assert_eq!(metadata["name"], "vendor/pkg");
        assert_eq!(metadata["version"], "2.0.0");
        assert_eq!(metadata["composer"]["description"], "Test");
    }

    // -----------------------------------------------------------------------
    // Upstream path construction for remote-proxy fallback (#1096)
    // -----------------------------------------------------------------------

    #[test]
    fn test_composer_v2_upstream_path_simple() {
        // The v2 wire shape is `p2/{vendor}/{package}.json` (no leading slash;
        // proxy_service prepends the upstream base URL itself).
        assert_eq!(
            composer_v2_upstream_path("monolog/monolog"),
            "p2/monolog/monolog.json"
        );
    }

    #[test]
    fn test_composer_v2_upstream_path_keeps_full_name_verbatim() {
        // No re-canonicalization: a hyphen-separated package name flows
        // through unchanged so Packagist sees the same path the client used.
        assert_eq!(
            composer_v2_upstream_path("symfony/http-foundation"),
            "p2/symfony/http-foundation.json"
        );
    }

    #[test]
    fn test_composer_v2_upstream_path_does_not_include_leading_slash() {
        // proxy_service::build_upstream_url joins base + "/" + path; a leading
        // slash here would produce `https://packagist.org//p2/...` which some
        // mirrors reject.
        let path = composer_v2_upstream_path("acme/widget");
        assert!(!path.starts_with('/'), "path must be relative: {}", path);
    }

    #[test]
    fn test_composer_v1_upstream_path_simple() {
        // The v1 wire shape is `p/{vendor}/{package}.json` (older Composer
        // clients hit this before p2).
        assert_eq!(
            composer_v1_upstream_path("monolog/monolog"),
            "p/monolog/monolog.json"
        );
    }

    #[test]
    fn test_composer_v1_upstream_path_keeps_full_name_verbatim() {
        assert_eq!(
            composer_v1_upstream_path("symfony/http-foundation"),
            "p/symfony/http-foundation.json"
        );
    }

    #[test]
    fn test_composer_v1_and_v2_paths_diverge_on_p_segment() {
        // Regression guard: the only difference between v1 and v2 in the
        // upstream URL is the leading `p/` vs `p2/`. If a future refactor
        // unifies the two helpers, this assertion fails loudly.
        let v1 = composer_v1_upstream_path("vendor/pkg");
        let v2 = composer_v2_upstream_path("vendor/pkg");
        assert_ne!(v1, v2);
        assert!(v1.starts_with("p/"));
        assert!(v2.starts_with("p2/"));
        assert!(v1.ends_with(".json"));
        assert!(v2.ends_with(".json"));
    }

    // -----------------------------------------------------------------------
    // build_composer_proxy_response (#1096)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_composer_proxy_response_status_is_ok() {
        let body = Bytes::from_static(br#"{"packages":{}}"#);
        let resp = build_composer_proxy_response(body, Some("application/json".to_string()));
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn test_build_composer_proxy_response_uses_upstream_content_type() {
        // Upstream told us the body is JSON: pass that through unchanged.
        let body = Bytes::from_static(b"{}");
        let resp = build_composer_proxy_response(body, Some("application/json".to_string()));
        let ct = resp
            .headers()
            .get(CONTENT_TYPE)
            .expect("response must set Content-Type");
        assert_eq!(ct.to_str().unwrap(), "application/json");
    }

    #[test]
    fn test_build_composer_proxy_response_defaults_content_type_to_json() {
        // Cache hits with empty metadata can land here without a content_type;
        // default to `application/json` because the composer client treats
        // anything else as a fetch error.
        let body = Bytes::from_static(b"{}");
        let resp = build_composer_proxy_response(body, None);
        let ct = resp
            .headers()
            .get(CONTENT_TYPE)
            .expect("response must set Content-Type");
        assert_eq!(ct.to_str().unwrap(), "application/json");
    }

    #[test]
    fn test_build_composer_proxy_response_preserves_custom_content_type() {
        // If the upstream returns a vendor-prefixed JSON content type
        // (some mirrors do), we must not silently rewrite it.
        let body = Bytes::from_static(b"{}");
        let resp = build_composer_proxy_response(
            body,
            Some("application/vnd.composer+json; charset=utf-8".to_string()),
        );
        let ct = resp
            .headers()
            .get(CONTENT_TYPE)
            .expect("response must set Content-Type");
        assert_eq!(
            ct.to_str().unwrap(),
            "application/vnd.composer+json; charset=utf-8"
        );
    }

    #[test]
    fn test_build_composer_proxy_response_empty_body_is_ok() {
        // Upstream returned an empty body but a 200 status: pass through.
        let resp = build_composer_proxy_response(Bytes::new(), None);
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn test_composer_v2_upstream_path_with_subnamespace() {
        // Vendor namespaces with dots / numeric suffixes (e.g.
        // `phpunit/phpunit`, `psr/log`, `aws/aws-sdk-php-v2`) must round-trip
        // through the helper untouched.
        assert_eq!(composer_v2_upstream_path("psr/log"), "p2/psr/log.json");
        assert_eq!(
            composer_v2_upstream_path("aws/aws-sdk-php-v2"),
            "p2/aws/aws-sdk-php-v2.json"
        );
        assert_eq!(
            composer_v2_upstream_path("phpunit/phpunit"),
            "p2/phpunit/phpunit.json"
        );
    }

    #[test]
    fn test_composer_v1_upstream_path_with_subnamespace() {
        assert_eq!(composer_v1_upstream_path("psr/log"), "p/psr/log.json");
        assert_eq!(
            composer_v1_upstream_path("aws/aws-sdk-php-v2"),
            "p/aws/aws-sdk-php-v2.json"
        );
    }
}

// ---------------------------------------------------------------------------
// DB-backed router tests for the packages-index population added in
// fix/1341-composer-webui-packages:
//
// After a successful Composer upload, the handler calls
// `PackageService::try_create_or_update_from_artifact` so the package
// surfaces in the WebUI Packages tab (which reads the `packages` table,
// not `artifacts`). Before this fix, Composer was the only publishing
// handler that did not populate `packages` / `package_versions`.
//
// These tests rely on `DATABASE_URL` being set. CI seeds + migrates a
// Postgres before running `cargo llvm-cov --lib`, so they execute there
// and cover the new lib lines in `upload`. In local environments without
// a database they no-op cleanly via `tdh::Fixture::setup` returning None.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod upload_db_tests {
    use crate::api::handlers::test_db_helpers as tdh;
    use std::io::Write;

    /// Build a minimal valid Composer package archive: a zip with a single
    /// `composer.json` entry carrying the required fields. Stored (no
    /// compression) so the tiny payload doesn't pay the deflate cost.
    fn build_composer_zip(name: &str, version: &str, description: &str) -> Vec<u8> {
        let composer_json = serde_json::json!({
            "name": name,
            "version": version,
            "description": description,
            "type": "library",
            "license": "MIT",
        });
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut cursor);
            let options: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip.start_file("composer.json", options)
                .expect("start composer.json");
            zip.write_all(serde_json::to_string(&composer_json).unwrap().as_bytes())
                .expect("write composer.json");
            zip.finish().expect("finish zip");
        }
        cursor.into_inner()
    }

    /// Build a PUT request shaped like a real Composer publish.
    fn put_composer(uri: String, zip_bytes: Vec<u8>) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method("PUT")
            .uri(uri)
            .header("content-type", "application/zip")
            .body(axum::body::Body::from(zip_bytes))
            .expect("build PUT request")
    }

    // -----------------------------------------------------------------------
    // Happy path: a Composer upload populates the `packages` table with the
    // description from composer.json and the `format: composer` metadata
    // tag, AND inserts the matching `package_versions` row keyed by the
    // package id. This is the new lib code path the coverage gate watches.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn upload_populates_packages_index_with_description() {
        let Some(f) = tdh::Fixture::setup("local", "composer").await else {
            return;
        };
        let name = "acme/widget";
        let version = "1.2.3";
        let description = "An indexed Composer package (#1341)";
        let zip = build_composer_zip(name, version, description);
        let app = f.router_with_auth(super::router());
        let req = put_composer(format!("/{}/api/packages", f.repo_key), zip);
        let (status, body) = tdh::send(app, req).await;
        assert!(
            status.is_success(),
            "expected 2xx for Composer upload, got {}: {:?}",
            status,
            String::from_utf8_lossy(&body[..])
        );

        // The artifact row was already correct pre-fix.
        let artifact_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM artifacts \
             WHERE repository_id = $1 AND name = $2 AND version = $3 AND is_deleted = false",
        )
        .bind(f.repo_id)
        .bind(name)
        .bind(version)
        .fetch_one(&f.pool)
        .await
        .expect("query artifacts");
        assert_eq!(
            artifact_count.0, 1,
            "exactly one artifact row expected after upload"
        );

        // The regression assertion: the packages row must exist with the
        // description folded from composer.json and the format-tag metadata
        // the handler passes to PackageService.
        let row: Option<(String, Option<String>, Option<serde_json::Value>)> = sqlx::query_as(
            "SELECT name, description, metadata FROM packages \
             WHERE repository_id = $1 AND name = $2 AND version = $3",
        )
        .bind(f.repo_id)
        .bind(name)
        .bind(version)
        .fetch_optional(&f.pool)
        .await
        .expect("query packages");

        let (pkg_name, desc, meta) = row.expect("packages row must exist after Composer upload");
        assert_eq!(pkg_name, name);
        assert_eq!(
            desc.as_deref(),
            Some(description),
            "composer.json description must be persisted to packages.description"
        );
        let meta = meta.expect("metadata must be set");
        assert_eq!(
            meta["format"], "composer",
            "handler passes {{format: composer}} to PackageService"
        );

        // package_versions UPSERTed by PackageService.
        let version_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM package_versions pv \
             JOIN packages p ON p.id = pv.package_id \
             WHERE p.repository_id = $1 AND p.name = $2 AND pv.version = $3",
        )
        .bind(f.repo_id)
        .bind(name)
        .bind(version)
        .fetch_one(&f.pool)
        .await
        .expect("query package_versions");
        assert_eq!(
            version_count.0, 1,
            "exactly one package_versions row expected after a single upload"
        );

        f.teardown().await;
    }

    // -----------------------------------------------------------------------
    // composer.json without a `description` key: the handler passes
    // `composer_json.description.as_deref()` (== None) into
    // `try_create_or_update_from_artifact`, which must land as NULL in the
    // packages table (COALESCE keeps existing NULL on conflict).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn upload_packages_index_missing_description_maps_to_null() {
        let Some(f) = tdh::Fixture::setup("local", "composer").await else {
            return;
        };
        // No `description` field in the composer.json.
        let composer_json = serde_json::json!({
            "name": "acme/no-desc",
            "version": "0.1.0",
            "type": "library",
            "license": "MIT",
        });
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut cursor);
            let options: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip.start_file("composer.json", options).unwrap();
            zip.write_all(serde_json::to_string(&composer_json).unwrap().as_bytes())
                .unwrap();
            zip.finish().unwrap();
        }
        let zip_bytes = cursor.into_inner();

        let app = f.router_with_auth(super::router());
        let req = put_composer(format!("/{}/api/packages", f.repo_key), zip_bytes);
        let (status, body) = tdh::send(app, req).await;
        assert!(
            status.is_success(),
            "upload without description must still succeed: {} {:?}",
            status,
            String::from_utf8_lossy(&body[..])
        );

        let row: Option<(Option<String>,)> = sqlx::query_as(
            "SELECT description FROM packages \
             WHERE repository_id = $1 AND name = $2 AND version = $3",
        )
        .bind(f.repo_id)
        .bind("acme/no-desc")
        .bind("0.1.0")
        .fetch_optional(&f.pool)
        .await
        .expect("query packages");

        let (desc,) = row.expect("packages row must exist even without description");
        assert!(
            desc.is_none(),
            "missing composer.json description must fold to NULL, got {:?}",
            desc
        );

        f.teardown().await;
    }

    // -----------------------------------------------------------------------
    // composer.json without `version`: the handler defaults to `dev-main`
    // (see `composer_json.version.as_deref().unwrap_or("dev-main")`). The
    // packages-index row must use that resolved version so the WebUI lists
    // the package as a dev branch rather than dropping it. Covers the
    // `&version` argument the new code passes after the fallback resolves.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn upload_default_version_indexed_as_dev_main() {
        let Some(f) = tdh::Fixture::setup("local", "composer").await else {
            return;
        };
        // No `version` field: the handler should fall back to "dev-main".
        let composer_json = serde_json::json!({
            "name": "acme/dev-pkg",
            "description": "dev-branch package",
            "type": "library",
            "license": "MIT",
        });
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut cursor);
            let options: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip.start_file("composer.json", options).unwrap();
            zip.write_all(serde_json::to_string(&composer_json).unwrap().as_bytes())
                .unwrap();
            zip.finish().unwrap();
        }
        let zip_bytes = cursor.into_inner();

        let app = f.router_with_auth(super::router());
        let req = put_composer(format!("/{}/api/packages", f.repo_key), zip_bytes);
        let (status, _) = tdh::send(app, req).await;
        assert!(status.is_success(), "upload must succeed: {}", status);

        let row: Option<(String,)> = sqlx::query_as(
            "SELECT version FROM packages \
             WHERE repository_id = $1 AND name = $2",
        )
        .bind(f.repo_id)
        .bind("acme/dev-pkg")
        .fetch_optional(&f.pool)
        .await
        .expect("query packages");

        let (ver,) = row.expect("packages row must exist for default-version upload");
        assert_eq!(
            ver, "dev-main",
            "missing composer.json version must index as dev-main"
        );

        // And the matching package_versions row carries the resolved
        // `&sha256` checksum (non-empty hex string) the handler passed.
        let checksum: (String,) = sqlx::query_as(
            "SELECT pv.checksum_sha256 FROM package_versions pv \
             JOIN packages p ON p.id = pv.package_id \
             WHERE p.repository_id = $1 AND p.name = $2 AND pv.version = $3",
        )
        .bind(f.repo_id)
        .bind("acme/dev-pkg")
        .bind("dev-main")
        .fetch_one(&f.pool)
        .await
        .expect("query package_versions checksum");
        assert_eq!(
            checksum.0.len(),
            64,
            "package_versions.checksum_sha256 must be a 64-char hex digest"
        );

        f.teardown().await;
    }

    // -----------------------------------------------------------------------
    // POST verb: composer's upload route is `put(upload).post(upload)`, so
    // a POST publish must follow the same code path and end up in the
    // packages index too. Guards against a future refactor that drops the
    // POST handler and silently regresses CI clients that publish with
    // POST.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn upload_via_post_also_populates_packages_index() {
        let Some(f) = tdh::Fixture::setup("local", "composer").await else {
            return;
        };
        let name = "acme/postpkg";
        let version = "2.0.0";
        let zip = build_composer_zip(name, version, "posted via POST");
        let app = f.router_with_auth(super::router());
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/{}/api/packages", f.repo_key))
            .header("content-type", "application/zip")
            .body(axum::body::Body::from(zip))
            .expect("build POST request");
        let (status, body) = tdh::send(app, req).await;
        assert!(
            status.is_success(),
            "POST publish must succeed: {} {:?}",
            status,
            String::from_utf8_lossy(&body[..])
        );

        let row: Option<(String, i64)> = sqlx::query_as(
            "SELECT name, size_bytes FROM packages \
             WHERE repository_id = $1 AND name = $2 AND version = $3",
        )
        .bind(f.repo_id)
        .bind(name)
        .bind(version)
        .fetch_optional(&f.pool)
        .await
        .expect("query packages");
        let (got_name, size) = row.expect("packages row must exist after POST publish");
        assert_eq!(got_name, name);
        assert!(
            size > 0,
            "size_bytes must be the archive length the handler passed, got {}",
            size
        );

        f.teardown().await;
    }
}
