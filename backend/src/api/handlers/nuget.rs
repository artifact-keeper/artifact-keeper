//! NuGet v3 Server API handlers.
//!
//! Implements the endpoints required for `dotnet nuget push` and
//! `dotnet add package` against a NuGet v3 feed.
//!
//! Routes are mounted at `/nuget/{repo_key}/...`:
//!   GET  /nuget/{repo_key}/v3/index.json                                      — Service index
//!   GET  /nuget/{repo_key}/v3/search                                          — Search packages
//!   GET  /nuget/{repo_key}/v3/registration/{id}/index.json                    — Package registration
//!   GET  /nuget/{repo_key}/v3/flatcontainer/{id}/index.json                   — Version list
//!   GET  /nuget/{repo_key}/v3/flatcontainer/{id}/{version}/{id}.{version}.nupkg — Download
//!   PUT  /nuget/{repo_key}/api/v2/package                                     — Push package

use std::io::Read;
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
use crate::services::auth_service::AuthService;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::StorageBackend;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Service index (NuGet discovery document)
        .route("/:repo_key/v3/index.json", get(service_index))
        // Search
        .route("/:repo_key/v3/search", get(search_packages))
        // Package registration
        .route(
            "/:repo_key/v3/registration/:id/index.json",
            get(registration_index),
        )
        // Flat container — version list
        .route(
            "/:repo_key/v3/flatcontainer/:id/index.json",
            get(flatcontainer_versions),
        )
        // Flat container — download .nupkg
        .route(
            "/:repo_key/v3/flatcontainer/:id/:version/:filename",
            get(flatcontainer_download),
        )
        // Push package (dotnet nuget push)
        .route("/:repo_key/api/v2/package", put(push_package))
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

/// Authenticate via X-NuGet-ApiKey header (preferred) or Basic auth.
/// Returns user_id on success.
async fn authenticate(
    db: &PgPool,
    config: &crate::config::Config,
    headers: &HeaderMap,
) -> Result<uuid::Uuid, Response> {
    // Try X-NuGet-ApiKey first
    if let Some(api_key) = headers.get("X-NuGet-ApiKey").and_then(|v| v.to_str().ok()) {
        // The API key may be in "user:password" format or just a token.
        // Try splitting on ':' first for user:password style keys.
        let (username, password) = if let Some((u, p)) = api_key.split_once(':') {
            (u.to_string(), p.to_string())
        } else {
            ("apikey".to_string(), api_key.to_string())
        };

        let auth_service = AuthService::new(db.clone(), Arc::new(config.clone()));
        let (user, _tokens) = auth_service
            .authenticate(&username, &password)
            .await
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid API key").into_response())?;

        return Ok(user.id);
    }

    // Fall back to Basic auth
    let (username, password) = extract_basic_credentials(headers).ok_or_else(|| {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Basic realm=\"nuget\"")
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
                .header("WWW-Authenticate", "Basic realm=\"nuget\"")
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

async fn resolve_nuget_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
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
    if fmt != "nuget" && fmt != "chocolatey" && fmt != "powershell" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not a NuGet repository (format: {})",
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
// GET /nuget/{repo_key}/v3/index.json — Service index
// ---------------------------------------------------------------------------

async fn service_index(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let _repo = resolve_nuget_repo(&state.db, &repo_key).await?;

    // Determine the base URL from the Host header or fall back to config.
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");

    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http");

    let base = format!("{}://{}/nuget/{}", scheme, host, repo_key);

    let index = serde_json::json!({
        "version": "3.0.0",
        "resources": [
            {
                "@id": format!("{}/v3/search", base),
                "@type": "SearchQueryService",
                "comment": "Search packages"
            },
            {
                "@id": format!("{}/v3/search", base),
                "@type": "SearchQueryService/3.0.0-beta",
                "comment": "Search packages"
            },
            {
                "@id": format!("{}/v3/search", base),
                "@type": "SearchQueryService/3.0.0-rc",
                "comment": "Search packages"
            },
            {
                "@id": format!("{}/v3/registration/", base),
                "@type": "RegistrationsBaseUrl",
                "comment": "Package registrations"
            },
            {
                "@id": format!("{}/v3/registration/", base),
                "@type": "RegistrationsBaseUrl/3.0.0-beta",
                "comment": "Package registrations"
            },
            {
                "@id": format!("{}/v3/registration/", base),
                "@type": "RegistrationsBaseUrl/3.0.0-rc",
                "comment": "Package registrations"
            },
            {
                "@id": format!("{}/v3/flatcontainer/", base),
                "@type": "PackageBaseAddress/3.0.0",
                "comment": "Package content"
            },
            {
                "@id": format!("{}/api/v2/package", base),
                "@type": "PackagePublish/2.0.0",
                "comment": "Push packages"
            }
        ]
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string_pretty(&index).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /nuget/{repo_key}/v3/search — Search packages
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize, Default)]
struct SearchQuery {
    q: Option<String>,
    skip: Option<i64>,
    take: Option<i64>,
    #[serde(rename = "prerelease")]
    prerelease: Option<bool>,
}

async fn search_packages(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    Query(params): Query<SearchQuery>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let repo = resolve_nuget_repo(&state.db, &repo_key).await?;

    let query_term = params.q.unwrap_or_default();
    let skip = params.skip.unwrap_or(0);
    let take = params.take.unwrap_or(20).min(100);
    let _prerelease = params.prerelease.unwrap_or(false);

    // Determine base URL for building resource links.
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http");
    let base = format!("{}://{}/nuget/{}", scheme, host, repo_key);

    // Search distinct package names matching the query term.
    let search_pattern = format!("%{}%", query_term.to_lowercase());

    let packages = sqlx::query!(
        r#"
        SELECT LOWER(name) as "name!", MAX(version) as "latest_version?",
               COUNT(DISTINCT version)::bigint as "version_count!",
               SUM(size_bytes)::bigint as "total_size?"
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND LOWER(name) LIKE $2
        GROUP BY LOWER(name)
        ORDER BY LOWER(name)
        LIMIT $3 OFFSET $4
        "#,
        repo.id,
        search_pattern,
        take,
        skip
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

    // Get total count for pagination.
    let total_count = sqlx::query_scalar!(
        r#"
        SELECT COUNT(DISTINCT LOWER(name))::bigint as "count!"
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND LOWER(name) LIKE $2
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
    })?;

    let data: Vec<serde_json::Value> = packages
        .iter()
        .map(|p| {
            let id = &p.name;
            let latest = p.latest_version.as_deref().unwrap_or("0.0.0");

            // Build version list entry for the latest version.
            let versions = vec![serde_json::json!({
                "version": latest,
                "@id": format!("{}/v3/registration/{}/{}.json", base, id, latest),
            })];

            serde_json::json!({
                "@id": format!("{}/v3/registration/{}/index.json", base, id),
                "@type": "Package",
                "registration": format!("{}/v3/registration/{}/index.json", base, id),
                "id": id,
                "version": latest,
                "description": "",
                "totalDownloads": 0,
                "versions": versions
            })
        })
        .collect();

    let response = serde_json::json!({
        "totalHits": total_count,
        "data": data
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /nuget/{repo_key}/v3/registration/{id}/index.json — Registration index
// ---------------------------------------------------------------------------

async fn registration_index(
    State(state): State<SharedState>,
    Path((repo_key, package_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let repo = resolve_nuget_repo(&state.db, &repo_key).await?;
    let package_id_lower = package_id.to_lowercase();

    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http");
    let base = format!("{}://{}/nuget/{}", scheme, host, repo_key);

    // Fetch all versions of this package.
    let artifacts = sqlx::query!(
        r#"
        SELECT a.id, a.version as "version?", a.path, a.size_bytes,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND LOWER(a.name) = $2
        ORDER BY a.created_at ASC
        "#,
        repo.id,
        package_id_lower
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

    let items: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            let version = a.version.as_deref().unwrap_or("0.0.0");
            let description = a
                .metadata
                .as_ref()
                .and_then(|m| m.get("description"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let authors = a
                .metadata
                .as_ref()
                .and_then(|m| m.get("authors"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            serde_json::json!({
                "@id": format!("{}/v3/registration/{}/{}.json", base, package_id_lower, version),
                "catalogEntry": {
                    "@id": format!("{}/v3/registration/{}/{}.json", base, package_id_lower, version),
                    "id": package_id_lower,
                    "version": version,
                    "description": description,
                    "authors": authors,
                    "packageContent": format!(
                        "{}/v3/flatcontainer/{}/{}/{}.{}.nupkg",
                        base, package_id_lower, version, package_id_lower, version
                    ),
                    "listed": true,
                },
                "packageContent": format!(
                    "{}/v3/flatcontainer/{}/{}/{}.{}.nupkg",
                    base, package_id_lower, version, package_id_lower, version
                ),
            })
        })
        .collect();

    let lower_version = artifacts
        .first()
        .and_then(|a| a.version.as_deref())
        .unwrap_or("0.0.0");
    let upper_version = artifacts
        .last()
        .and_then(|a| a.version.as_deref())
        .unwrap_or("0.0.0");

    let response = serde_json::json!({
        "@id": format!("{}/v3/registration/{}/index.json", base, package_id_lower),
        "count": 1,
        "items": [
            {
                "@id": format!("{}/v3/registration/{}/index.json#page/0", base, package_id_lower),
                "count": items.len(),
                "lower": lower_version,
                "upper": upper_version,
                "items": items,
            }
        ]
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /nuget/{repo_key}/v3/flatcontainer/{id}/index.json — Version list
// ---------------------------------------------------------------------------

async fn flatcontainer_versions(
    State(state): State<SharedState>,
    Path((repo_key, package_id)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_nuget_repo(&state.db, &repo_key).await?;
    let package_id_lower = package_id.to_lowercase();

    let versions: Vec<String> = sqlx::query_scalar!(
        r#"
        SELECT DISTINCT version as "version!"
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND LOWER(name) = $2
          AND version IS NOT NULL
        ORDER BY version
        "#,
        repo.id,
        package_id_lower
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

    if versions.is_empty() {
        return Err((StatusCode::NOT_FOUND, "Package not found").into_response());
    }

    let response = serde_json::json!({
        "versions": versions
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /nuget/{repo_key}/v3/flatcontainer/{id}/{version}/{filename} — Download
// ---------------------------------------------------------------------------

async fn flatcontainer_download(
    State(state): State<SharedState>,
    Path((repo_key, package_id, version, filename)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_nuget_repo(&state.db, &repo_key).await?;
    let package_id_lower = package_id.to_lowercase();

    // Find the artifact matching this package/version.
    let artifact = sqlx::query!(
        r#"
        SELECT id, storage_key, size_bytes, checksum_sha256, content_type
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND LOWER(name) = $2
          AND version = $3
        LIMIT 1
        "#,
        repo.id,
        package_id_lower,
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
    })?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Package version not found").into_response())?;

    // Read from storage.
    let storage = FilesystemStorage::new(&repo.storage_path);
    let content = storage.get(&artifact.storage_key).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    // Record download.
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
// PUT /nuget/{repo_key}/api/v2/package — Push package
// ---------------------------------------------------------------------------

async fn push_package(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    // Authenticate.
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_nuget_repo(&state.db, &repo_key).await?;

    // The body may be multipart/form-data or raw binary .nupkg.
    let nupkg_bytes = extract_nupkg_bytes(&headers, body)?;

    if nupkg_bytes.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty package body").into_response());
    }

    // Parse .nuspec from the .nupkg (ZIP archive).
    let nuspec = parse_nuspec_from_nupkg(&nupkg_bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Failed to read .nuspec from package: {}", e),
        )
            .into_response()
    })?;

    let package_id = nuspec.id.to_lowercase();
    let version = nuspec.version.clone();

    if package_id.is_empty() || version.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Package ID and version are required in .nuspec",
        )
            .into_response());
    }

    // Check for duplicate.
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND LOWER(name) = $2 AND version = $3 AND is_deleted = false",
        repo.id,
        package_id,
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
            format!("Package {}.{} already exists", package_id, version),
        )
            .into_response());
    }

    // Compute SHA256.
    let mut hasher = Sha256::new();
    hasher.update(&nupkg_bytes);
    let checksum = format!("{:x}", hasher.finalize());

    let size_bytes = nupkg_bytes.len() as i64;
    let filename = format!("{}.{}.nupkg", package_id, version);
    let artifact_path = format!("{}/{}/{}", package_id, version, filename);
    let storage_key = format!("nuget/{}/{}/{}", package_id, version, filename);

    // Store the file.
    let storage = FilesystemStorage::new(&repo.storage_path);
    storage.put(&storage_key, nupkg_bytes).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    // Build metadata JSON.
    let metadata = serde_json::json!({
        "id": nuspec.id,
        "version": nuspec.version,
        "description": nuspec.description,
        "authors": nuspec.authors,
        "filename": filename,
    });

    // Insert artifact record.
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
        checksum,
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

    // Store metadata.
    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'nuget', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        metadata,
    )
    .execute(&state.db)
    .await;

    // Update repository timestamp.
    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
    .await;

    info!(
        "NuGet push: {} {} ({}) to repo {}",
        nuspec.id, version, filename, repo_key
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .body(Body::empty())
        .unwrap())
}

// ---------------------------------------------------------------------------
// .nupkg / .nuspec helpers
// ---------------------------------------------------------------------------

/// Extract the .nupkg bytes from the request body.
/// Handles both raw binary upload and multipart/form-data.
#[allow(clippy::result_large_err)]
fn extract_nupkg_bytes(headers: &HeaderMap, body: Bytes) -> Result<Bytes, Response> {
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if content_type.contains("multipart/form-data") {
        // For multipart, we need to find the boundary and extract the file part.
        // The `dotnet nuget push` client sends multipart/form-data with the
        // .nupkg as the file field. We do a simple boundary-based extraction.
        extract_nupkg_from_multipart(content_type, &body)
    } else {
        // Raw binary body — the entire body is the .nupkg.
        Ok(body)
    }
}

/// Simple multipart extraction: find the file content between boundaries.
#[allow(clippy::result_large_err)]
fn extract_nupkg_from_multipart(content_type: &str, body: &[u8]) -> Result<Bytes, Response> {
    // Extract boundary from content-type header.
    let boundary = content_type
        .split(';')
        .find_map(|part| {
            let trimmed = part.trim();
            trimmed
                .strip_prefix("boundary=")
                .map(|b| b.trim_matches('"').to_string())
        })
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing multipart boundary").into_response())?;

    let boundary_marker = format!("--{}", boundary);
    let boundary_bytes = boundary_marker.as_bytes();

    // Find first boundary.
    let start = find_subsequence(body, boundary_bytes)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid multipart body").into_response())?;

    // Skip past the boundary line to the part headers.
    let after_boundary = start + boundary_bytes.len();

    // Find the blank line (\r\n\r\n) that separates headers from content.
    let header_end = find_subsequence(&body[after_boundary..], b"\r\n\r\n").ok_or_else(|| {
        (StatusCode::BAD_REQUEST, "Invalid multipart part headers").into_response()
    })?;

    let content_start = after_boundary + header_end + 4; // skip \r\n\r\n

    // Find the next boundary.
    let content_end = find_subsequence(&body[content_start..], boundary_bytes)
        .map(|pos| content_start + pos)
        .unwrap_or(body.len());

    // Strip trailing \r\n before the boundary.
    let end =
        if content_end >= 2 && body[content_end - 2] == b'\r' && body[content_end - 1] == b'\n' {
            content_end - 2
        } else {
            content_end
        };

    Ok(Bytes::copy_from_slice(&body[content_start..end]))
}

/// Find the position of a subsequence within a byte slice.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Metadata extracted from a .nuspec file.
struct NuspecInfo {
    id: String,
    version: String,
    description: String,
    authors: String,
}

/// Parse the .nuspec XML from inside a .nupkg (ZIP) archive.
/// Uses simple string matching rather than a full XML parser.
fn parse_nuspec_from_nupkg(nupkg: &[u8]) -> Result<NuspecInfo, String> {
    let cursor = std::io::Cursor::new(nupkg);
    let mut archive =
        zip::ZipArchive::new(cursor).map_err(|e| format!("Invalid ZIP archive: {}", e))?;

    // Find the .nuspec file inside the archive.
    let mut nuspec_xml = String::new();
    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| format!("Cannot read ZIP entry: {}", e))?;
        if file.name().ends_with(".nuspec") {
            file.read_to_string(&mut nuspec_xml)
                .map_err(|e| format!("Cannot read .nuspec: {}", e))?;
            break;
        }
    }

    if nuspec_xml.is_empty() {
        return Err("No .nuspec file found in package".to_string());
    }

    // Simple tag extraction.
    let id = extract_xml_tag(&nuspec_xml, "id").unwrap_or_default();
    let version = extract_xml_tag(&nuspec_xml, "version").unwrap_or_default();
    let description = extract_xml_tag(&nuspec_xml, "description").unwrap_or_default();
    let authors = extract_xml_tag(&nuspec_xml, "authors").unwrap_or_default();

    Ok(NuspecInfo {
        id,
        version,
        description,
        authors,
    })
}

/// Extract the text content of a simple XML tag (no attributes, no nesting).
/// e.g. `<id>Foo</id>` returns `Some("Foo")`.
fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}", tag);
    let close = format!("</{}>", tag);

    let start_pos = xml.find(&open)?;
    // Skip past the opening tag (handle possible attributes or xmlns).
    let after_open = &xml[start_pos + open.len()..];
    let content_start = after_open.find('>')? + 1;
    let content = &after_open[content_start..];
    let end_pos = content.find(&close)?;
    Some(content[..end_pos].trim().to_string())
}
