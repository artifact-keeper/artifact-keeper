//! npm Registry API handlers.
//!
//! Implements the endpoints required for `npm publish` and `npm install`.
//!
//! Routes are mounted at `/npm/{repo_key}/...`:
//!   GET  /npm/{repo_key}/{package}                    - Get package metadata
//!   GET  /npm/{repo_key}/{@scope}/{package}           - Get scoped package metadata
//!   GET  /npm/{repo_key}/{package}/-/{filename}       - Download tarball
//!   GET  /npm/{repo_key}/{@scope}/{package}/-/{filename} - Download scoped tarball
//!   PUT  /npm/{repo_key}/{package}                    - Publish package
//!   PUT  /npm/{repo_key}/{@scope}/{package}           - Publish scoped package

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Extension;
use axum::Router;
use base64::Engine;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::proxy_helpers;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Scoped package tarball: GET /npm/{repo_key}/@{scope}/{package}/-/{filename}
        .route(
            "/:repo_key/@:scope/:package/-/:filename",
            get(download_scoped_tarball),
        )
        // Scoped package metadata / publish: GET/PUT /npm/{repo_key}/@{scope}/{package}
        .route(
            "/:repo_key/@:scope/:package",
            get(get_scoped_metadata).put(publish_scoped),
        )
        // Unscoped package tarball: GET /npm/{repo_key}/{package}/-/{filename}
        .route("/:repo_key/:package/-/:filename", get(download_tarball))
        // Unscoped package metadata / publish: GET/PUT /npm/{repo_key}/{package}
        .route("/:repo_key/:package", get(get_metadata).put(publish))
        .layer(DefaultBodyLimit::max(512 * 1024 * 1024)) // 512 MB
}

use crate::api::middleware::auth::require_auth_with_bearer_fallback;

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

struct RepoInfo {
    id: uuid::Uuid,
    storage_path: String,
    repo_type: String,
    upstream_url: Option<String>,
}

async fn resolve_npm_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
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
    if fmt != "npm" && fmt != "yarn" && fmt != "pnpm" && fmt != "bower" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not an npm repository (format: {})",
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
// GET metadata handlers
// ---------------------------------------------------------------------------

async fn get_metadata(
    State(state): State<SharedState>,
    Path((repo_key, package)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    get_package_metadata(&state, &repo_key, &package, &headers).await
}

async fn get_scoped_metadata(
    State(state): State<SharedState>,
    Path((repo_key, scope, package)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let full_name = format!("@{}/{}", scope, package);
    get_package_metadata(&state, &repo_key, &full_name, &headers).await
}

/// Build and return the npm package metadata JSON for all versions.
async fn get_package_metadata(
    state: &SharedState,
    repo_key: &str,
    package_name: &str,
    headers: &HeaderMap,
) -> Result<Response, Response> {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http");
    let base_url = format!("{}://{}", scheme, host);

    let repo = resolve_npm_repo(&state.db, repo_key).await?;

    // Find all artifacts for this package name
    let artifacts = sqlx::query!(
        r#"
        SELECT a.id, a.path, a.name, a.version, a.size_bytes, a.checksum_sha256,
               a.storage_key, a.created_at,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND a.name = $2
        ORDER BY a.created_at ASC
        "#,
        repo.id,
        package_name
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
        // For remote repos, proxy the metadata from upstream
        if repo.repo_type == "remote" {
            if let Some(ref upstream_url) = repo.upstream_url {
                if let Some(ref proxy) = state.proxy_service {
                    let (content, content_type) = proxy_helpers::proxy_fetch(
                        proxy,
                        repo.id,
                        repo_key,
                        upstream_url,
                        package_name,
                    )
                    .await?;

                    // Rewrite tarball URLs in the upstream metadata to point to our local instance
                    if let Ok(mut json) = serde_json::from_slice::<serde_json::Value>(&content) {
                        rewrite_npm_tarball_urls(&mut json, &base_url, repo_key);
                        let rewritten = serde_json::to_string(&json).unwrap_or_default();
                        return Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/json")
                            .body(Body::from(rewritten))
                            .unwrap());
                    }

                    // If not valid JSON, return raw upstream response
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(
                            CONTENT_TYPE,
                            content_type.unwrap_or_else(|| "application/json".to_string()),
                        )
                        .body(Body::from(content))
                        .unwrap());
                }
            }
        }
        // For virtual repos, iterate through members and try proxy for remote members
        if repo.repo_type == "virtual" {
            if let Some(ref proxy) = state.proxy_service {
                let members = sqlx::query!(
                    r#"SELECT r.id, r.key, r.repo_type::text as "repo_type!", r.upstream_url
                    FROM repositories r
                    INNER JOIN virtual_repo_members vrm ON r.id = vrm.member_repo_id
                    WHERE vrm.virtual_repo_id = $1
                    ORDER BY vrm.priority"#,
                    repo.id
                )
                .fetch_all(&state.db)
                .await
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to resolve virtual members: {}", e),
                    )
                        .into_response()
                })?;

                for member in &members {
                    // Try local artifacts first
                    let local_count: i64 = sqlx::query_scalar!(
                        "SELECT COUNT(*) as \"count!\" FROM artifacts WHERE repository_id = $1 AND name = $2 AND is_deleted = false",
                        member.id,
                        package_name
                    )
                    .fetch_one(&state.db)
                    .await
                    .unwrap_or(0);

                    if local_count > 0 {
                        // Has local artifacts in this member, skip for now
                        // (would need to build metadata from local artifacts — complex)
                        continue;
                    }

                    // Try proxy for remote members
                    if member.repo_type == "remote" {
                        if let Some(ref upstream_url) = member.upstream_url {
                            if let Ok((content, _ct)) = proxy_helpers::proxy_fetch(
                                proxy,
                                member.id,
                                &member.key,
                                upstream_url,
                                package_name,
                            )
                            .await
                            {
                                if let Ok(mut json) =
                                    serde_json::from_slice::<serde_json::Value>(&content)
                                {
                                    rewrite_npm_tarball_urls(&mut json, &base_url, repo_key);
                                    let rewritten =
                                        serde_json::to_string(&json).unwrap_or_default();
                                    return Ok(Response::builder()
                                        .status(StatusCode::OK)
                                        .header(CONTENT_TYPE, "application/json")
                                        .body(Body::from(rewritten))
                                        .unwrap());
                                }

                                return Ok(Response::builder()
                                    .status(StatusCode::OK)
                                    .header(CONTENT_TYPE, "application/json")
                                    .body(Body::from(content))
                                    .unwrap());
                            }
                        }
                    }
                }
            }
        }

        return Err((StatusCode::NOT_FOUND, "Package not found").into_response());
    }

    // Build versions map and track the latest version
    let mut versions = serde_json::Map::new();
    let mut latest_version: Option<String> = None;

    for artifact in &artifacts {
        let version = match &artifact.version {
            Some(v) => v.clone(),
            None => continue,
        };

        // Extract the filename from the path
        let filename = artifact.path.rsplit('/').next().unwrap_or(&artifact.path);

        // Build the tarball URL
        let tarball_url = format!(
            "{}/npm/{}/{}/-/{}",
            base_url, repo_key, package_name, filename
        );

        // Get version-specific metadata from artifact_metadata if available
        let version_metadata = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("version_data").cloned())
            .unwrap_or_else(|| serde_json::json!({}));

        let mut version_obj = if version_metadata.is_object() {
            version_metadata
        } else {
            serde_json::json!({})
        };

        // Ensure required fields are set
        let obj = version_obj.as_object_mut().unwrap();
        obj.entry("name".to_string())
            .or_insert_with(|| serde_json::Value::String(package_name.to_string()));
        obj.entry("version".to_string())
            .or_insert_with(|| serde_json::Value::String(version.clone()));
        // npm expects shasum (SHA-1) or integrity (subresource integrity hash).
        // We only store SHA-256, so provide it via the integrity field.
        use base64::Engine;
        let hex = &artifact.checksum_sha256;
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
            .collect();
        let integrity = format!(
            "sha256-{}",
            base64::engine::general_purpose::STANDARD.encode(&bytes)
        );
        obj.insert(
            "dist".to_string(),
            serde_json::json!({
                "tarball": tarball_url,
                "integrity": integrity,
            }),
        );

        versions.insert(version.clone(), version_obj);
        latest_version = Some(version);
    }

    let dist_tags = serde_json::json!({
        "latest": latest_version.unwrap_or_default()
    });

    let response = serde_json::json!({
        "name": package_name,
        "versions": versions,
        "dist-tags": dist_tags,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET tarball download handlers
// ---------------------------------------------------------------------------

async fn download_tarball(
    State(state): State<SharedState>,
    Path((repo_key, package, filename)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    serve_tarball(&state, &repo_key, &package, &filename).await
}

async fn download_scoped_tarball(
    State(state): State<SharedState>,
    Path((repo_key, scope, package, filename)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let full_name = format!("@{}/{}", scope, package);
    serve_tarball(&state, &repo_key, &full_name, &filename).await
}

async fn serve_tarball(
    state: &SharedState,
    repo_key: &str,
    package_name: &str,
    filename: &str,
) -> Result<Response, Response> {
    let repo = resolve_npm_repo(&state.db, repo_key).await?;

    // Find artifact by filename
    let artifact = sqlx::query!(
        r#"
        SELECT id, path, name, size_bytes, checksum_sha256, storage_key
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
    })?;

    // If artifact not found locally, try proxy for remote repos
    let artifact = match artifact {
        Some(a) => a,
        None => {
            if repo.repo_type == "remote" {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    // Upstream path: {package_name}/-/{filename}
                    let upstream_path = format!("{}/-/{}", package_name, filename);
                    let (content, _content_type) = proxy_helpers::proxy_fetch(
                        proxy,
                        repo.id,
                        repo_key,
                        upstream_url,
                        &upstream_path,
                    )
                    .await?;

                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, "application/octet-stream")
                        .header(
                            "Content-Disposition",
                            format!("attachment; filename=\"{}\"", filename),
                        )
                        .header(CONTENT_LENGTH, content.len().to_string())
                        .body(Body::from(content))
                        .unwrap());
                }
            }
            // Virtual repo: try each member in priority order
            if repo.repo_type == "virtual" {
                let db = state.db.clone();
                let fname = filename.to_string();
                let upstream_path = format!("{}/-/{}", package_name, filename);
                let (content, content_type) = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    state.proxy_service.as_deref(),
                    repo.id,
                    &upstream_path,
                    |member_id, storage_path| {
                        let db = db.clone();
                        let state = state.clone();
                        let fname = fname.clone();
                        async move {
                            proxy_helpers::local_fetch_by_path_suffix(
                                &db,
                                &state,
                                member_id,
                                &storage_path,
                                &fname,
                            )
                            .await
                        }
                    },
                )
                .await?;

                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(
                        CONTENT_TYPE,
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
            return Err((StatusCode::NOT_FOUND, "Tarball not found").into_response());
        }
    };

    // Read from storage
    let storage = state.storage_for_repo(&repo.storage_path);
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
// PUT publish handlers
// ---------------------------------------------------------------------------

async fn publish(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, package)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    publish_package(&state, auth, &repo_key, &package, &headers, body).await
}

async fn publish_scoped(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, scope, package)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let full_name = format!("@{}/{}", scope, package);
    publish_package(&state, auth, &repo_key, &full_name, &headers, body).await
}

/// Parsed and validated npm publish payload ready for storage.
struct ParsedNpmPublish {
    versions: Vec<NpmVersionToPublish>,
}

/// A single version extracted from the npm publish payload.
struct NpmVersionToPublish {
    version: String,
    version_data: serde_json::Value,
    tarball_filename: String,
    tarball_bytes: Vec<u8>,
    sha256: String,
}

/// Parse and validate the raw npm publish JSON body into structured data.
/// Returns an error response if the payload is malformed.
#[allow(clippy::result_large_err)]
fn parse_npm_publish_payload(
    body: &Bytes,
    package_name: &str,
) -> Result<ParsedNpmPublish, Response> {
    let payload: serde_json::Value = serde_json::from_slice(body).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid JSON payload: {}", e),
        )
            .into_response()
    })?;

    let name = payload
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(package_name);

    if name != package_name {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Package name mismatch: URL says '{}' but payload says '{}'",
                package_name, name
            ),
        )
            .into_response());
    }

    let versions_obj = payload
        .get("versions")
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            (StatusCode::BAD_REQUEST, "Missing 'versions' in payload").into_response()
        })?;

    let attachments_obj = payload
        .get("_attachments")
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            (StatusCode::BAD_REQUEST, "Missing '_attachments' in payload").into_response()
        })?;

    let mut versions = Vec::new();
    for (version, version_data) in versions_obj {
        let parsed =
            extract_version_tarball(package_name, version, version_data.clone(), attachments_obj)?;
        versions.push(parsed);
    }

    Ok(ParsedNpmPublish { versions })
}

/// Extract and decode the tarball for a single version from the attachments map.
#[allow(clippy::result_large_err)]
fn extract_version_tarball(
    package_name: &str,
    version: &str,
    version_data: serde_json::Value,
    attachments_obj: &serde_json::Map<String, serde_json::Value>,
) -> Result<NpmVersionToPublish, Response> {
    let tarball_filename = if package_name.starts_with('@') {
        let short_name = package_name.rsplit('/').next().unwrap_or(package_name);
        format!("{}-{}.tgz", short_name, version)
    } else {
        format!("{}-{}.tgz", package_name, version)
    };

    let attachment_data = attachments_obj
        .get(&tarball_filename)
        .or_else(|| attachments_obj.values().next())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                format!("No attachment found for version {}", version),
            )
                .into_response()
        })?;

    let base64_data = attachment_data
        .get("data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing 'data' in attachment").into_response())?;

    let tarball_bytes = base64::engine::general_purpose::STANDARD
        .decode(base64_data)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Invalid base64 data: {}", e),
            )
                .into_response()
        })?;

    let mut hasher = Sha256::new();
    hasher.update(&tarball_bytes);
    let sha256 = format!("{:x}", hasher.finalize());

    Ok(NpmVersionToPublish {
        version: version.to_string(),
        version_data,
        tarball_filename,
        tarball_bytes,
        sha256,
    })
}

/// Store a single npm version: check duplicates, write to storage, insert DB
/// records, and update the package_versions table.
#[allow(clippy::too_many_arguments)]
async fn store_npm_version(
    state: &SharedState,
    repo_id: uuid::Uuid,
    repo_key: &str,
    storage_path: &str,
    package_name: &str,
    user_id: uuid::Uuid,
    ver: &NpmVersionToPublish,
) -> Result<(), Response> {
    let artifact_path = format!("{}/{}/{}", package_name, ver.version, ver.tarball_filename);

    // Check for duplicate
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        repo_id,
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
        return Err((
            StatusCode::CONFLICT,
            format!("Version {} of {} already exists", ver.version, package_name),
        )
            .into_response());
    }

    // Store the tarball
    let storage_key = format!(
        "npm/{}/{}/{}",
        package_name, ver.version, ver.tarball_filename
    );
    let storage = state.storage_for_repo(storage_path);
    storage
        .put(&storage_key, Bytes::from(ver.tarball_bytes.clone()))
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Storage error: {}", e),
            )
                .into_response()
        })?;

    let size_bytes = ver.tarball_bytes.len() as i64;

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
        repo_id,
        artifact_path,
        package_name,
        ver.version,
        size_bytes,
        ver.sha256,
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
    let npm_metadata = serde_json::json!({
        "name": package_name,
        "version": ver.version,
        "version_data": ver.version_data,
    });

    let _ = sqlx::query(
        "INSERT INTO artifact_metadata (artifact_id, format, metadata) \
         VALUES ($1, 'npm', $2) \
         ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2",
    )
    .bind(artifact_id)
    .bind(&npm_metadata)
    .execute(&state.db)
    .await;

    // Populate packages / package_versions tables (best-effort)
    let pkg_svc = crate::services::package_service::PackageService::new(state.db.clone());
    let description = ver
        .version_data
        .get("description")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    pkg_svc
        .try_create_or_update_from_artifact(
            repo_id,
            package_name,
            &ver.version,
            size_bytes,
            &ver.sha256,
            description.as_deref(),
            Some(serde_json::json!({ "format": "npm" })),
        )
        .await;

    info!(
        "npm publish: {} {} ({}) to repo {}",
        package_name, ver.version, ver.tarball_filename, repo_key
    );

    Ok(())
}

/// Handle npm publish. The request body is JSON with versions and base64-encoded attachments.
async fn publish_package(
    state: &SharedState,
    auth: Option<AuthExtension>,
    repo_key: &str,
    package_name: &str,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id =
        require_auth_with_bearer_fallback(auth, headers, &state.db, &state.config, "npm").await?;
    let repo = resolve_npm_repo(&state.db, repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    let parsed = parse_npm_publish_payload(&body, package_name)?;

    for ver in &parsed.versions {
        store_npm_version(
            state,
            repo.id,
            repo_key,
            &repo.storage_path,
            package_name,
            user_id,
            ver,
        )
        .await?;
    }

    // Update repository timestamp
    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
    .await;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({"ok": true})).unwrap(),
        ))
        .unwrap())
}

// ---------------------------------------------------------------------------
// Proxy helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Extracted pure functions for testability
// ---------------------------------------------------------------------------

/// Rewrite tarball URLs in npm metadata JSON to point to our local instance.
/// npm metadata contains `versions.{ver}.dist.tarball` pointing to the upstream registry.
/// We rewrite those to point to `{base_url}/npm/{repo_key}/{package}/-/{filename}`.
fn rewrite_npm_tarball_urls(json: &mut serde_json::Value, base_url: &str, repo_key: &str) {
    let versions = match json.get_mut("versions").and_then(|v| v.as_object_mut()) {
        Some(v) => v,
        None => return,
    };

    for (_version, version_data) in versions.iter_mut() {
        // Extract package name before taking mutable borrow on dist
        let pkg_name = version_data
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("_unknown")
            .to_string();

        if let Some(dist) = version_data.get_mut("dist") {
            // Extract the current tarball URL and compute the new one
            let new_url = dist
                .get("tarball")
                .and_then(|t| t.as_str())
                .and_then(|tarball| {
                    // e.g., https://registry.npmjs.org/express/-/express-4.18.2.tgz
                    tarball.rsplit_once("/-/").map(|(_, filename)| {
                        format!("{}/npm/{}/{}/-/{}", base_url, repo_key, pkg_name, filename)
                    })
                });

            if let Some(url) = new_url {
                if let Some(d) = dist.as_object_mut() {
                    d.insert("tarball".to_string(), serde_json::Value::String(url));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Extracted pure functions (test-only)
    // -----------------------------------------------------------------------

    /// Compute npm integrity field from a SHA256 hex digest.
    fn compute_npm_integrity(sha256_hex: &str) -> String {
        let bytes: Vec<u8> = (0..sha256_hex.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&sha256_hex[i..i + 2], 16).ok())
            .collect();
        format!(
            "sha256-{}",
            base64::engine::general_purpose::STANDARD.encode(&bytes)
        )
    }

    /// Build the tarball filename for an npm package.
    fn build_npm_tarball_filename(package_name: &str, version: &str) -> String {
        if package_name.starts_with('@') {
            let short_name = package_name.rsplit('/').next().unwrap_or(package_name);
            format!("{}-{}.tgz", short_name, version)
        } else {
            format!("{}-{}.tgz", package_name, version)
        }
    }

    /// Build the artifact path for an npm tarball.
    fn build_npm_artifact_path(
        package_name: &str,
        version: &str,
        tarball_filename: &str,
    ) -> String {
        format!("{}/{}/{}", package_name, version, tarball_filename)
    }

    /// Build the storage key for an npm tarball.
    fn build_npm_storage_key(package_name: &str, version: &str, tarball_filename: &str) -> String {
        format!("npm/{}/{}/{}", package_name, version, tarball_filename)
    }

    /// Build a scoped package name from scope and package.
    fn build_scoped_package_name(scope: &str, package: &str) -> String {
        format!("@{}/{}", scope, package)
    }

    /// Validate an npm package name (basic checks).
    fn validate_npm_package_name(name: &str) -> std::result::Result<(), String> {
        if name.is_empty() {
            return Err("Package name cannot be empty".to_string());
        }
        if name.len() > 214 {
            return Err("Package name cannot exceed 214 characters".to_string());
        }
        if name.starts_with('.') || name.starts_with('_') {
            return Err("Package name cannot start with '.' or '_'".to_string());
        }
        if name != name.to_lowercase() && !name.starts_with('@') {
            return Err("Package name must be lowercase (unless scoped)".to_string());
        }
        Ok(())
    }

    /// Build the npm tarball URL for metadata responses.
    fn build_npm_tarball_url(
        base_url: &str,
        repo_key: &str,
        package_name: &str,
        filename: &str,
    ) -> String {
        format!(
            "{}/npm/{}/{}/-/{}",
            base_url, repo_key, package_name, filename
        )
    }

    /// Info struct for building npm version metadata.
    #[allow(dead_code)]
    struct NpmArtifactInfo {
        version: String,
        filename: String,
        checksum_sha256: String,
        tarball_url: String,
        version_metadata: Option<serde_json::Value>,
        package_name: String,
    }

    /// Build a single npm version entry for the metadata response.
    fn build_npm_version_entry(info: &NpmArtifactInfo) -> serde_json::Value {
        let integrity = compute_npm_integrity(&info.checksum_sha256);

        let mut version_obj = info
            .version_metadata
            .as_ref()
            .filter(|v| v.is_object())
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));

        let obj = version_obj.as_object_mut().unwrap();
        obj.entry("name".to_string())
            .or_insert_with(|| serde_json::Value::String(info.package_name.clone()));
        obj.entry("version".to_string())
            .or_insert_with(|| serde_json::Value::String(info.version.clone()));
        obj.insert(
            "dist".to_string(),
            serde_json::json!({
                "tarball": info.tarball_url,
                "integrity": integrity,
            }),
        );

        version_obj
    }

    // -----------------------------------------------------------------------
    // rewrite_npm_tarball_urls
    // -----------------------------------------------------------------------

    #[test]
    fn test_rewrite_npm_tarball_urls_basic() {
        let mut json = serde_json::json!({
            "name": "express",
            "versions": {
                "4.18.2": {
                    "name": "express",
                    "version": "4.18.2",
                    "dist": {
                        "tarball": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
                        "integrity": "sha512-abc"
                    }
                }
            }
        });

        rewrite_npm_tarball_urls(&mut json, "http://localhost:8080", "npm-remote");

        let tarball = json["versions"]["4.18.2"]["dist"]["tarball"]
            .as_str()
            .unwrap();
        assert_eq!(
            tarball,
            "http://localhost:8080/npm/npm-remote/express/-/express-4.18.2.tgz"
        );
    }

    #[test]
    fn test_rewrite_npm_tarball_urls_scoped_package() {
        let mut json = serde_json::json!({
            "name": "@angular/core",
            "versions": {
                "17.0.0": {
                    "name": "@angular/core",
                    "version": "17.0.0",
                    "dist": {
                        "tarball": "https://registry.npmjs.org/@angular/core/-/core-17.0.0.tgz"
                    }
                }
            }
        });

        rewrite_npm_tarball_urls(&mut json, "https://my.registry.com", "npm-main");

        let tarball = json["versions"]["17.0.0"]["dist"]["tarball"]
            .as_str()
            .unwrap();
        assert_eq!(
            tarball,
            "https://my.registry.com/npm/npm-main/@angular/core/-/core-17.0.0.tgz"
        );
    }

    #[test]
    fn test_rewrite_npm_tarball_urls_no_versions() {
        let mut json = serde_json::json!({
            "name": "empty-pkg"
        });
        // Should not panic
        rewrite_npm_tarball_urls(&mut json, "http://localhost", "repo");
        // JSON unchanged
        assert!(json.get("versions").is_none());
    }

    #[test]
    fn test_rewrite_npm_tarball_urls_no_dist() {
        let mut json = serde_json::json!({
            "versions": {
                "1.0.0": {
                    "name": "no-dist",
                    "version": "1.0.0"
                }
            }
        });
        // Should not panic
        rewrite_npm_tarball_urls(&mut json, "http://localhost", "repo");
    }

    #[test]
    fn test_rewrite_npm_tarball_urls_no_tarball_field() {
        let mut json = serde_json::json!({
            "versions": {
                "1.0.0": {
                    "name": "no-tarball",
                    "version": "1.0.0",
                    "dist": {
                        "integrity": "sha512-abc"
                    }
                }
            }
        });
        // Should not panic or modify anything
        rewrite_npm_tarball_urls(&mut json, "http://localhost", "repo");
    }

    #[test]
    fn test_rewrite_npm_tarball_urls_multiple_versions() {
        let mut json = serde_json::json!({
            "name": "lodash",
            "versions": {
                "4.17.20": {
                    "name": "lodash",
                    "dist": {
                        "tarball": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
                    }
                },
                "4.17.21": {
                    "name": "lodash",
                    "dist": {
                        "tarball": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
                    }
                }
            }
        });

        rewrite_npm_tarball_urls(&mut json, "http://local:8080", "npm");

        let t1 = json["versions"]["4.17.20"]["dist"]["tarball"]
            .as_str()
            .unwrap();
        let t2 = json["versions"]["4.17.21"]["dist"]["tarball"]
            .as_str()
            .unwrap();
        assert!(t1.starts_with("http://local:8080/npm/npm/lodash/-/"));
        assert!(t2.starts_with("http://local:8080/npm/npm/lodash/-/"));
    }

    // -----------------------------------------------------------------------
    // RepoInfo struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_info_construction() {
        let info = RepoInfo {
            id: uuid::Uuid::new_v4(),
            storage_path: "/data/npm".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: None,
        };
        assert_eq!(info.repo_type, "hosted");
        assert!(info.upstream_url.is_none());
    }

    // -----------------------------------------------------------------------
    // Tarball filename generation
    // -----------------------------------------------------------------------

    #[test]
    fn test_tarball_filename_unscoped() {
        let package_name = "express";
        let version = "4.18.2";
        let filename = format!("{}-{}.tgz", package_name, version);
        assert_eq!(filename, "express-4.18.2.tgz");
    }

    #[test]
    fn test_tarball_filename_scoped() {
        let package_name = "@angular/core";
        let version = "17.0.0";
        let tarball_filename = if package_name.starts_with('@') {
            let short_name = package_name.rsplit('/').next().unwrap_or(package_name);
            format!("{}-{}.tgz", short_name, version)
        } else {
            format!("{}-{}.tgz", package_name, version)
        };
        assert_eq!(tarball_filename, "core-17.0.0.tgz");
    }

    #[test]
    fn test_tarball_filename_scoped_no_slash() {
        let package_name = "@oddpackage";
        let version = "1.0.0";
        let tarball_filename = if package_name.starts_with('@') {
            let short_name = package_name.rsplit('/').next().unwrap_or(package_name);
            format!("{}-{}.tgz", short_name, version)
        } else {
            format!("{}-{}.tgz", package_name, version)
        };
        // rsplit('/') returns the entire string when no '/' is found
        assert_eq!(tarball_filename, "@oddpackage-1.0.0.tgz");
    }

    // -----------------------------------------------------------------------
    // Scoped package name construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_scoped_package_name() {
        let scope = "babel";
        let package = "core";
        let full_name = format!("@{}/{}", scope, package);
        assert_eq!(full_name, "@babel/core");
    }

    // -----------------------------------------------------------------------
    // Path/storage key
    // -----------------------------------------------------------------------

    #[test]
    fn test_npm_artifact_path() {
        let package_name = "express";
        let version = "4.18.2";
        let tarball_filename = format!("{}-{}.tgz", package_name, version);
        let artifact_path = format!("{}/{}/{}", package_name, version, tarball_filename);
        assert_eq!(artifact_path, "express/4.18.2/express-4.18.2.tgz");
    }

    #[test]
    fn test_npm_storage_key() {
        let package_name = "@vue/compiler-core";
        let version = "3.4.0";
        let tarball_filename = "compiler-core-3.4.0.tgz";
        let storage_key = format!("npm/{}/{}/{}", package_name, version, tarball_filename);
        assert_eq!(
            storage_key,
            "npm/@vue/compiler-core/3.4.0/compiler-core-3.4.0.tgz"
        );
    }

    // -----------------------------------------------------------------------
    // SHA256
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256_deterministic() {
        let data = b"npm package tarball data";
        let mut h1 = Sha256::new();
        h1.update(data);
        let c1 = format!("{:x}", h1.finalize());

        let mut h2 = Sha256::new();
        h2.update(data);
        let c2 = format!("{:x}", h2.finalize());

        assert_eq!(c1, c2);
        assert_eq!(c1.len(), 64);
    }

    // -----------------------------------------------------------------------
    // Hex to bytes conversion (used for integrity field)
    // -----------------------------------------------------------------------

    #[test]
    fn test_hex_to_bytes_and_integrity() {
        let hex = "abcdef0123456789";
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
            .collect();
        assert_eq!(bytes, vec![0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89]);

        let integrity = format!(
            "sha256-{}",
            base64::engine::general_purpose::STANDARD.encode(&bytes)
        );
        assert!(integrity.starts_with("sha256-"));
    }

    // -----------------------------------------------------------------------
    // Tarball URL building
    // -----------------------------------------------------------------------

    #[test]
    fn test_tarball_url() {
        let base_url = "http://localhost:8080";
        let repo_key = "npm-hosted";
        let package_name = "express";
        let filename = "express-4.18.2.tgz";
        let url = format!(
            "{}/npm/{}/{}/-/{}",
            base_url, repo_key, package_name, filename
        );
        assert_eq!(
            url,
            "http://localhost:8080/npm/npm-hosted/express/-/express-4.18.2.tgz"
        );
    }

    // -----------------------------------------------------------------------
    // compute_npm_integrity
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_npm_integrity_basic() {
        let hex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let result = compute_npm_integrity(hex);
        assert!(result.starts_with("sha256-"));
        assert!(result.len() > 7);
    }

    #[test]
    fn test_compute_npm_integrity_zeros() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = compute_npm_integrity(hex);
        assert!(result.starts_with("sha256-"));
        // All zeros base64-encoded
        assert_eq!(
            result,
            "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
    }

    #[test]
    fn test_compute_npm_integrity_deterministic() {
        let hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let r1 = compute_npm_integrity(hex);
        let r2 = compute_npm_integrity(hex);
        assert_eq!(r1, r2);
    }

    // -----------------------------------------------------------------------
    // build_npm_tarball_filename
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_npm_tarball_filename_unscoped() {
        assert_eq!(
            build_npm_tarball_filename("express", "4.18.2"),
            "express-4.18.2.tgz"
        );
    }

    #[test]
    fn test_build_npm_tarball_filename_scoped() {
        assert_eq!(
            build_npm_tarball_filename("@angular/core", "17.0.0"),
            "core-17.0.0.tgz"
        );
    }

    #[test]
    fn test_build_npm_tarball_filename_scoped_deep() {
        assert_eq!(
            build_npm_tarball_filename("@babel/preset-env", "7.24.0"),
            "preset-env-7.24.0.tgz"
        );
    }

    #[test]
    fn test_build_npm_tarball_filename_scoped_no_slash() {
        // Edge case: scoped package without a slash
        assert_eq!(
            build_npm_tarball_filename("@oddpackage", "1.0.0"),
            "@oddpackage-1.0.0.tgz"
        );
    }

    // -----------------------------------------------------------------------
    // build_npm_artifact_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_npm_artifact_path_unscoped() {
        assert_eq!(
            build_npm_artifact_path("lodash", "4.17.21", "lodash-4.17.21.tgz"),
            "lodash/4.17.21/lodash-4.17.21.tgz"
        );
    }

    #[test]
    fn test_build_npm_artifact_path_scoped() {
        assert_eq!(
            build_npm_artifact_path("@vue/compiler-core", "3.4.0", "compiler-core-3.4.0.tgz"),
            "@vue/compiler-core/3.4.0/compiler-core-3.4.0.tgz"
        );
    }

    // -----------------------------------------------------------------------
    // build_npm_storage_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_npm_storage_key_unscoped() {
        assert_eq!(
            build_npm_storage_key("express", "4.18.2", "express-4.18.2.tgz"),
            "npm/express/4.18.2/express-4.18.2.tgz"
        );
    }

    #[test]
    fn test_build_npm_storage_key_scoped() {
        assert_eq!(
            build_npm_storage_key("@vue/compiler-core", "3.4.0", "compiler-core-3.4.0.tgz"),
            "npm/@vue/compiler-core/3.4.0/compiler-core-3.4.0.tgz"
        );
    }

    // -----------------------------------------------------------------------
    // build_scoped_package_name
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_scoped_package_name_basic() {
        assert_eq!(build_scoped_package_name("babel", "core"), "@babel/core");
    }

    #[test]
    fn test_build_scoped_package_name_vue() {
        assert_eq!(
            build_scoped_package_name("vue", "compiler-core"),
            "@vue/compiler-core"
        );
    }

    // -----------------------------------------------------------------------
    // validate_npm_package_name
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_npm_package_name_valid() {
        assert!(validate_npm_package_name("express").is_ok());
    }

    #[test]
    fn test_validate_npm_package_name_empty() {
        assert!(validate_npm_package_name("").is_err());
    }

    #[test]
    fn test_validate_npm_package_name_too_long() {
        let long_name = "a".repeat(215);
        assert!(validate_npm_package_name(&long_name).is_err());
    }

    #[test]
    fn test_validate_npm_package_name_starts_with_dot() {
        assert!(validate_npm_package_name(".hidden").is_err());
    }

    #[test]
    fn test_validate_npm_package_name_starts_with_underscore() {
        assert!(validate_npm_package_name("_private").is_err());
    }

    #[test]
    fn test_validate_npm_package_name_uppercase_rejected() {
        assert!(validate_npm_package_name("MyPackage").is_err());
    }

    #[test]
    fn test_validate_npm_package_name_scoped_uppercase_ok() {
        assert!(validate_npm_package_name("@Scope/Package").is_ok());
    }

    #[test]
    fn test_validate_npm_package_name_max_length() {
        let name = "a".repeat(214);
        assert!(validate_npm_package_name(&name).is_ok());
    }

    // -----------------------------------------------------------------------
    // build_npm_tarball_url
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_npm_tarball_url_basic() {
        assert_eq!(
            build_npm_tarball_url(
                "http://localhost:8080",
                "npm-hosted",
                "express",
                "express-4.18.2.tgz"
            ),
            "http://localhost:8080/npm/npm-hosted/express/-/express-4.18.2.tgz"
        );
    }

    #[test]
    fn test_build_npm_tarball_url_scoped() {
        assert_eq!(
            build_npm_tarball_url(
                "https://registry.example.com",
                "main",
                "@angular/core",
                "core-17.0.0.tgz"
            ),
            "https://registry.example.com/npm/main/@angular/core/-/core-17.0.0.tgz"
        );
    }

    // -----------------------------------------------------------------------
    // build_npm_version_entry
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_npm_version_entry_basic() {
        let info = NpmArtifactInfo {
            version: "1.0.0".to_string(),
            filename: "mylib-1.0.0.tgz".to_string(),
            checksum_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_string(),
            tarball_url: "http://localhost:8080/npm/repo/mylib/-/mylib-1.0.0.tgz".to_string(),
            version_metadata: None,
            package_name: "mylib".to_string(),
        };
        let entry = build_npm_version_entry(&info);
        assert_eq!(entry["name"], "mylib");
        assert_eq!(entry["version"], "1.0.0");
        assert!(entry["dist"]["tarball"]
            .as_str()
            .unwrap()
            .contains("mylib-1.0.0.tgz"));
        assert!(entry["dist"]["integrity"]
            .as_str()
            .unwrap()
            .starts_with("sha256-"));
    }

    #[test]
    fn test_build_npm_version_entry_with_metadata() {
        let meta = serde_json::json!({
            "description": "A great library",
            "license": "MIT"
        });
        let info = NpmArtifactInfo {
            version: "2.0.0".to_string(),
            filename: "pkg-2.0.0.tgz".to_string(),
            checksum_sha256: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            tarball_url: "http://localhost/npm/r/pkg/-/pkg-2.0.0.tgz".to_string(),
            version_metadata: Some(meta),
            package_name: "pkg".to_string(),
        };
        let entry = build_npm_version_entry(&info);
        assert_eq!(entry["name"], "pkg");
        assert_eq!(entry["version"], "2.0.0");
        assert_eq!(entry["description"], "A great library");
        assert_eq!(entry["license"], "MIT");
    }

    #[test]
    fn test_build_npm_version_entry_metadata_preserves_name_if_set() {
        let meta = serde_json::json!({
            "name": "custom-name",
            "version": "0.9.0"
        });
        let info = NpmArtifactInfo {
            version: "1.0.0".to_string(),
            filename: "pkg-1.0.0.tgz".to_string(),
            checksum_sha256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                .to_string(),
            tarball_url: "http://localhost/npm/r/pkg/-/pkg-1.0.0.tgz".to_string(),
            version_metadata: Some(meta),
            package_name: "pkg".to_string(),
        };
        let entry = build_npm_version_entry(&info);
        // name and version from metadata should be preserved (or_insert_with doesn't overwrite)
        assert_eq!(entry["name"], "custom-name");
        assert_eq!(entry["version"], "0.9.0");
    }

    // -----------------------------------------------------------------------
    // parse_npm_publish_payload
    // -----------------------------------------------------------------------

    fn make_valid_publish_body(package_name: &str, version: &str) -> Bytes {
        let tarball_data = b"fake tarball content";
        let b64 = base64::engine::general_purpose::STANDARD.encode(tarball_data);
        let tarball_filename = build_npm_tarball_filename(package_name, version);

        let payload = serde_json::json!({
            "name": package_name,
            "versions": {
                version: {
                    "name": package_name,
                    "version": version,
                    "description": "A test package"
                }
            },
            "_attachments": {
                tarball_filename: {
                    "content_type": "application/octet-stream",
                    "data": b64,
                    "length": tarball_data.len()
                }
            }
        });
        Bytes::from(serde_json::to_vec(&payload).unwrap())
    }

    #[test]
    fn test_parse_npm_publish_payload_valid() {
        let body = make_valid_publish_body("express", "4.18.2");
        let result = parse_npm_publish_payload(&body, "express");
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.versions.len(), 1);
        assert_eq!(parsed.versions[0].version, "4.18.2");
        assert_eq!(parsed.versions[0].tarball_filename, "express-4.18.2.tgz");
        assert!(!parsed.versions[0].tarball_bytes.is_empty());
        assert_eq!(parsed.versions[0].sha256.len(), 64);
    }

    #[test]
    fn test_parse_npm_publish_payload_scoped() {
        let body = make_valid_publish_body("@babel/core", "7.24.0");
        let result = parse_npm_publish_payload(&body, "@babel/core");
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.versions[0].version, "7.24.0");
        assert_eq!(parsed.versions[0].tarball_filename, "core-7.24.0.tgz");
    }

    #[test]
    fn test_parse_npm_publish_payload_invalid_json() {
        let body = Bytes::from(b"not json at all".to_vec());
        let result = parse_npm_publish_payload(&body, "pkg");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_npm_publish_payload_name_mismatch() {
        let payload = serde_json::json!({
            "name": "wrong-name",
            "versions": { "1.0.0": {} },
            "_attachments": { "wrong-name-1.0.0.tgz": { "data": "dGVzdA==" } }
        });
        let body = Bytes::from(serde_json::to_vec(&payload).unwrap());
        let result = parse_npm_publish_payload(&body, "correct-name");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_npm_publish_payload_missing_versions() {
        let payload = serde_json::json!({
            "name": "pkg",
            "_attachments": {}
        });
        let body = Bytes::from(serde_json::to_vec(&payload).unwrap());
        let result = parse_npm_publish_payload(&body, "pkg");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_npm_publish_payload_missing_attachments() {
        let payload = serde_json::json!({
            "name": "pkg",
            "versions": { "1.0.0": {} }
        });
        let body = Bytes::from(serde_json::to_vec(&payload).unwrap());
        let result = parse_npm_publish_payload(&body, "pkg");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_npm_publish_payload_no_name_field_uses_url_name() {
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"data");
        let payload = serde_json::json!({
            "versions": {
                "1.0.0": { "version": "1.0.0" }
            },
            "_attachments": {
                "pkg-1.0.0.tgz": { "data": b64 }
            }
        });
        let body = Bytes::from(serde_json::to_vec(&payload).unwrap());
        let result = parse_npm_publish_payload(&body, "pkg");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_npm_publish_preserves_version_data() {
        let body = make_valid_publish_body("mylib", "2.0.0");
        let parsed = parse_npm_publish_payload(&body, "mylib").unwrap();
        let vd = &parsed.versions[0].version_data;
        assert_eq!(vd["description"], "A test package");
    }

    // -----------------------------------------------------------------------
    // extract_version_tarball
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_version_tarball_unscoped() {
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"tarball bytes");
        let mut attachments = serde_json::Map::new();
        attachments.insert(
            "mylib-1.0.0.tgz".to_string(),
            serde_json::json!({ "data": b64 }),
        );

        let result = extract_version_tarball(
            "mylib",
            "1.0.0",
            serde_json::json!({"version": "1.0.0"}),
            &attachments,
        );
        assert!(result.is_ok());
        let ver = result.unwrap();
        assert_eq!(ver.version, "1.0.0");
        assert_eq!(ver.tarball_filename, "mylib-1.0.0.tgz");
        assert_eq!(ver.tarball_bytes, b"tarball bytes");
        assert_eq!(ver.sha256.len(), 64);
    }

    #[test]
    fn test_extract_version_tarball_scoped() {
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"scoped data");
        let mut attachments = serde_json::Map::new();
        attachments.insert(
            "core-7.0.0.tgz".to_string(),
            serde_json::json!({ "data": b64 }),
        );

        let result =
            extract_version_tarball("@babel/core", "7.0.0", serde_json::json!({}), &attachments);
        assert!(result.is_ok());
        let ver = result.unwrap();
        assert_eq!(ver.tarball_filename, "core-7.0.0.tgz");
    }

    #[test]
    fn test_extract_version_tarball_falls_back_to_first_attachment() {
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"fallback data");
        let mut attachments = serde_json::Map::new();
        attachments.insert(
            "different-name.tgz".to_string(),
            serde_json::json!({ "data": b64 }),
        );

        let result = extract_version_tarball("mylib", "1.0.0", serde_json::json!({}), &attachments);
        assert!(result.is_ok());
    }

    #[test]
    fn test_extract_version_tarball_empty_attachments() {
        let attachments = serde_json::Map::new();
        let result = extract_version_tarball("mylib", "1.0.0", serde_json::json!({}), &attachments);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_version_tarball_missing_data_field() {
        let mut attachments = serde_json::Map::new();
        attachments.insert(
            "mylib-1.0.0.tgz".to_string(),
            serde_json::json!({ "content_type": "application/octet-stream" }),
        );

        let result = extract_version_tarball("mylib", "1.0.0", serde_json::json!({}), &attachments);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_version_tarball_invalid_base64() {
        let mut attachments = serde_json::Map::new();
        attachments.insert(
            "mylib-1.0.0.tgz".to_string(),
            serde_json::json!({ "data": "!!!not-base64!!!" }),
        );

        let result = extract_version_tarball("mylib", "1.0.0", serde_json::json!({}), &attachments);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_version_tarball_sha256_matches_content() {
        let content = b"deterministic content";
        let b64 = base64::engine::general_purpose::STANDARD.encode(content);
        let mut attachments = serde_json::Map::new();
        attachments.insert(
            "pkg-1.0.0.tgz".to_string(),
            serde_json::json!({ "data": b64 }),
        );

        let ver =
            extract_version_tarball("pkg", "1.0.0", serde_json::json!({}), &attachments).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(content);
        let expected_sha256 = format!("{:x}", hasher.finalize());
        assert_eq!(ver.sha256, expected_sha256);
    }

    // -----------------------------------------------------------------------
    // ParsedNpmPublish / NpmVersionToPublish structs
    // -----------------------------------------------------------------------

    #[test]
    fn test_npm_version_to_publish_fields() {
        let ver = NpmVersionToPublish {
            version: "3.0.0".to_string(),
            version_data: serde_json::json!({"description": "test"}),
            tarball_filename: "pkg-3.0.0.tgz".to_string(),
            tarball_bytes: vec![1, 2, 3],
            sha256: "abc".to_string(),
        };
        assert_eq!(ver.version, "3.0.0");
        assert_eq!(ver.tarball_bytes.len(), 3);
        assert_eq!(ver.version_data["description"], "test");
    }

    #[test]
    fn test_parsed_npm_publish_multiple_versions() {
        let b64_a = base64::engine::general_purpose::STANDARD.encode(b"version a");
        let b64_b = base64::engine::general_purpose::STANDARD.encode(b"version b");

        let payload = serde_json::json!({
            "name": "multi",
            "versions": {
                "1.0.0": { "version": "1.0.0" },
                "2.0.0": { "version": "2.0.0" }
            },
            "_attachments": {
                "multi-1.0.0.tgz": { "data": b64_a },
                "multi-2.0.0.tgz": { "data": b64_b }
            }
        });
        let body = Bytes::from(serde_json::to_vec(&payload).unwrap());
        let parsed = parse_npm_publish_payload(&body, "multi").unwrap();
        assert_eq!(parsed.versions.len(), 2);

        let version_names: Vec<&str> = parsed.versions.iter().map(|v| v.version.as_str()).collect();
        assert!(version_names.contains(&"1.0.0"));
        assert!(version_names.contains(&"2.0.0"));
    }
}
