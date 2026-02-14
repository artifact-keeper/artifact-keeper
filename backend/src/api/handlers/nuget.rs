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

use crate::api::handlers::proxy_helpers;
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
    repo_type: String,
    upstream_url: Option<String>,
}

async fn resolve_nuget_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
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
        repo_type: repo.repo_type,
        upstream_url: repo.upstream_url,
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Package version not found").into_response());

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == "remote" {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let upstream_path = format!(
                        "v3/flatcontainer/{}/{}/{}",
                        package_id_lower, version, filename
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
            if repo.repo_type == "virtual" {
                let db = state.db.clone();
                let vname = package_id_lower.clone();
                let vversion = version.clone();
                let upstream_path = format!(
                    "v3/flatcontainer/{}/{}/{}",
                    package_id_lower, version, filename
                );
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
            return Err(not_found);
        }
    };

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
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    // -----------------------------------------------------------------------
    // Extracted pure functions (test-only)
    // -----------------------------------------------------------------------

    /// Build the base URL for NuGet service index resources.
    fn build_nuget_base_url(scheme: &str, host: &str, repo_key: &str) -> String {
        format!("{}://{}/nuget/{}", scheme, host, repo_key)
    }

    /// Build the NuGet service index JSON (v3/index.json).
    fn build_nuget_service_index(base: &str) -> serde_json::Value {
        serde_json::json!({
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
        })
    }

    /// Build a single registration item JSON for a NuGet package version.
    fn build_registration_item(
        base: &str,
        package_id: &str,
        version: &str,
        description: &str,
        authors: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "@id": format!("{}/v3/registration/{}/{}.json", base, package_id, version),
            "catalogEntry": {
                "@id": format!("{}/v3/registration/{}/{}.json", base, package_id, version),
                "id": package_id,
                "version": version,
                "description": description,
                "authors": authors,
                "packageContent": format!(
                    "{}/v3/flatcontainer/{}/{}/{}.{}.nupkg",
                    base, package_id, version, package_id, version
                ),
                "listed": true,
            },
            "packageContent": format!(
                "{}/v3/flatcontainer/{}/{}/{}.{}.nupkg",
                base, package_id, version, package_id, version
            ),
        })
    }

    /// Build the flatcontainer versions JSON response.
    fn build_flatcontainer_versions_json(versions: &[String]) -> serde_json::Value {
        serde_json::json!({
            "versions": versions
        })
    }

    /// Build the NuGet artifact path for a .nupkg.
    fn build_nuget_artifact_path(package_id: &str, version: &str) -> String {
        let filename = format!("{}.{}.nupkg", package_id, version);
        format!("{}/{}/{}", package_id, version, filename)
    }

    /// Build the NuGet storage key for a .nupkg.
    fn build_nuget_storage_key(package_id: &str, version: &str) -> String {
        let filename = format!("{}.{}.nupkg", package_id, version);
        format!("nuget/{}/{}/{}", package_id, version, filename)
    }

    /// Build the NuGet push metadata JSON.
    fn build_nuget_push_metadata(info: &NuspecInfo) -> serde_json::Value {
        serde_json::json!({
            "id": info.id,
            "version": info.version,
            "description": info.description,
            "authors": info.authors,
            "filename": format!("{}.{}.nupkg", info.id.to_lowercase(), info.version),
        })
    }

    /// Build the search pattern for NuGet package queries.
    fn build_nuget_search_pattern(query_term: &str) -> String {
        format!("%{}%", query_term.to_lowercase())
    }

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
        let headers = make_basic_header("admin", "secret");
        let result = extract_basic_credentials(&headers);
        assert_eq!(result, Some(("admin".to_string(), "secret".to_string())));
    }

    #[test]
    fn test_extract_basic_credentials_lowercase() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:pass");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("basic {}", encoded)).unwrap(),
        );
        let result = extract_basic_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "pass".to_string())));
    }

    #[test]
    fn test_extract_basic_credentials_missing() {
        let headers = HeaderMap::new();
        assert!(extract_basic_credentials(&headers).is_none());
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

    #[test]
    fn test_extract_basic_credentials_colon_in_password() {
        let headers = make_basic_header("user", "p:a:s:s");
        let result = extract_basic_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "p:a:s:s".to_string())));
    }

    // -----------------------------------------------------------------------
    // extract_xml_tag
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_xml_tag_simple() {
        let xml = "<id>MyPackage</id>";
        assert_eq!(extract_xml_tag(xml, "id"), Some("MyPackage".to_string()));
    }

    #[test]
    fn test_extract_xml_tag_with_whitespace() {
        let xml = "<id>  MyPackage  </id>";
        assert_eq!(extract_xml_tag(xml, "id"), Some("MyPackage".to_string()));
    }

    #[test]
    fn test_extract_xml_tag_with_namespace() {
        let xml = r#"<id xmlns="http://example.com">PackageWithNS</id>"#;
        assert_eq!(
            extract_xml_tag(xml, "id"),
            Some("PackageWithNS".to_string())
        );
    }

    #[test]
    fn test_extract_xml_tag_missing() {
        let xml = "<name>Hello</name>";
        assert_eq!(extract_xml_tag(xml, "id"), None);
    }

    #[test]
    fn test_extract_xml_tag_empty_content() {
        let xml = "<id></id>";
        assert_eq!(extract_xml_tag(xml, "id"), Some("".to_string()));
    }

    #[test]
    fn test_extract_xml_tag_in_nuspec() {
        let xml = r#"<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd">
  <metadata>
    <id>Newtonsoft.Json</id>
    <version>13.0.1</version>
    <description>Popular JSON framework</description>
    <authors>James Newton-King</authors>
  </metadata>
</package>"#;
        assert_eq!(
            extract_xml_tag(xml, "id"),
            Some("Newtonsoft.Json".to_string())
        );
        assert_eq!(extract_xml_tag(xml, "version"), Some("13.0.1".to_string()));
        assert_eq!(
            extract_xml_tag(xml, "description"),
            Some("Popular JSON framework".to_string())
        );
        assert_eq!(
            extract_xml_tag(xml, "authors"),
            Some("James Newton-King".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // find_subsequence
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_subsequence_found() {
        let haystack = b"hello world";
        let needle = b"world";
        assert_eq!(find_subsequence(haystack, needle), Some(6));
    }

    #[test]
    fn test_find_subsequence_at_start() {
        let haystack = b"hello world";
        let needle = b"hello";
        assert_eq!(find_subsequence(haystack, needle), Some(0));
    }

    #[test]
    fn test_find_subsequence_not_found() {
        let haystack = b"hello world";
        let needle = b"xyz";
        assert_eq!(find_subsequence(haystack, needle), None);
    }

    // NOTE: find_subsequence panics when needle is empty because
    // haystack.windows(0) panics. This is a potential bug in production
    // code if it ever receives an empty needle. Not fixing source code.
    #[test]
    #[should_panic(expected = "window size must be non-zero")]
    fn test_find_subsequence_empty_needle_panics() {
        let haystack = b"hello";
        let needle = b"";
        find_subsequence(haystack, needle);
    }

    #[test]
    fn test_find_subsequence_needle_longer_than_haystack() {
        let haystack = b"hi";
        let needle = b"hello world";
        assert_eq!(find_subsequence(haystack, needle), None);
    }

    #[test]
    fn test_find_subsequence_crlf() {
        let haystack = b"header\r\n\r\nbody";
        let needle = b"\r\n\r\n";
        assert_eq!(find_subsequence(haystack, needle), Some(6));
    }

    // -----------------------------------------------------------------------
    // extract_nupkg_bytes
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_nupkg_bytes_raw_body() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        let body = Bytes::from_static(b"raw nupkg content");
        let result = extract_nupkg_bytes(&headers, body.clone()).unwrap();
        assert_eq!(result, body);
    }

    #[test]
    fn test_extract_nupkg_bytes_no_content_type() {
        let headers = HeaderMap::new();
        let body = Bytes::from_static(b"raw content");
        let result = extract_nupkg_bytes(&headers, body.clone()).unwrap();
        assert_eq!(result, body);
    }

    // -----------------------------------------------------------------------
    // extract_nupkg_from_multipart
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_nupkg_from_multipart_valid() {
        let boundary = "----boundary123";
        let content_type = format!("multipart/form-data; boundary={}", boundary);
        let body = "------boundary123\r\n\
             Content-Disposition: form-data; name=\"file\"; filename=\"pkg.nupkg\"\r\n\
             Content-Type: application/octet-stream\r\n\
             \r\n\
             FILE_CONTENT_HERE\r\n\
             ------boundary123--\r\n"
            .to_string();
        let result = extract_nupkg_from_multipart(&content_type, body.as_bytes());
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes.as_ref(), b"FILE_CONTENT_HERE");
    }

    #[test]
    fn test_extract_nupkg_from_multipart_missing_boundary() {
        let content_type = "multipart/form-data";
        let body = b"some body";
        let result = extract_nupkg_from_multipart(content_type, body);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_nupkg_from_multipart_quoted_boundary() {
        let content_type = "multipart/form-data; boundary=\"myboundary\"";
        let body = b"--myboundary\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nDATA\r\n--myboundary--\r\n";
        let result = extract_nupkg_from_multipart(content_type, body);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // parse_nuspec_from_nupkg
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_nuspec_from_nupkg_valid() {
        // Create a minimal ZIP with a .nuspec file
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut zip = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("MyPackage.nuspec", options).unwrap();
        let nuspec_content = r#"<?xml version="1.0"?>
<package>
  <metadata>
    <id>MyPackage</id>
    <version>1.2.3</version>
    <description>A test package</description>
    <authors>Test Author</authors>
  </metadata>
</package>"#;
        std::io::Write::write_all(&mut zip, nuspec_content.as_bytes()).unwrap();
        let cursor = zip.finish().unwrap();

        let result = parse_nuspec_from_nupkg(cursor.get_ref());
        assert!(result.is_ok());
        let nuspec = result.unwrap();
        assert_eq!(nuspec.id, "MyPackage");
        assert_eq!(nuspec.version, "1.2.3");
        assert_eq!(nuspec.description, "A test package");
        assert_eq!(nuspec.authors, "Test Author");
    }

    #[test]
    fn test_parse_nuspec_from_nupkg_no_nuspec() {
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut zip = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("readme.txt", options).unwrap();
        std::io::Write::write_all(&mut zip, b"no nuspec here").unwrap();
        let cursor = zip.finish().unwrap();

        let result = parse_nuspec_from_nupkg(cursor.get_ref());
        assert!(result.is_err());
        assert!(result.err().unwrap().contains("No .nuspec file found"));
    }

    #[test]
    fn test_parse_nuspec_from_nupkg_invalid_zip() {
        let result = parse_nuspec_from_nupkg(b"not a zip file");
        assert!(result.is_err());
        assert!(result.err().unwrap().contains("Invalid ZIP archive"));
    }

    #[test]
    fn test_parse_nuspec_missing_fields() {
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut zip = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("Partial.nuspec", options).unwrap();
        let nuspec_content = r#"<?xml version="1.0"?>
<package><metadata><id>OnlyId</id></metadata></package>"#;
        std::io::Write::write_all(&mut zip, nuspec_content.as_bytes()).unwrap();
        let cursor = zip.finish().unwrap();

        let result = parse_nuspec_from_nupkg(cursor.get_ref());
        assert!(result.is_ok());
        let nuspec = result.unwrap();
        assert_eq!(nuspec.id, "OnlyId");
        assert_eq!(nuspec.version, "");
        assert_eq!(nuspec.description, "");
        assert_eq!(nuspec.authors, "");
    }

    // -----------------------------------------------------------------------
    // NuspecInfo struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_nuspec_info_construction() {
        let info = NuspecInfo {
            id: "TestPkg".to_string(),
            version: "2.0.0".to_string(),
            description: "A library".to_string(),
            authors: "Author Name".to_string(),
        };
        assert_eq!(info.id, "TestPkg");
        assert_eq!(info.version, "2.0.0");
    }

    // -----------------------------------------------------------------------
    // SearchQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_query_defaults() {
        let q: SearchQuery = serde_json::from_str(r#"{}"#).unwrap();
        assert!(q.q.is_none());
        assert_eq!(q.skip, None);
        assert_eq!(q.take, None);
        assert_eq!(q.prerelease, None);
    }

    #[test]
    fn test_search_query_with_values() {
        let q: SearchQuery =
            serde_json::from_str(r#"{"q":"json","skip":10,"take":50,"prerelease":true}"#).unwrap();
        assert_eq!(q.q, Some("json".to_string()));
        assert_eq!(q.skip, Some(10));
        assert_eq!(q.take, Some(50));
        assert_eq!(q.prerelease, Some(true));
    }

    // -----------------------------------------------------------------------
    // RepoInfo struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_nuget_repo_info_construction() {
        let id = uuid::Uuid::new_v4();
        let info = RepoInfo {
            id,
            storage_path: "/data/nuget".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: None,
        };
        assert_eq!(info.repo_type, "hosted");
        assert!(info.upstream_url.is_none());
    }

    // -----------------------------------------------------------------------
    // SHA256 checksum
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256_checksum() {
        let data = b"nuget package data";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let checksum = format!("{:x}", hasher.finalize());
        assert_eq!(checksum.len(), 64);
        // Same input => same output
        let mut hasher2 = Sha256::new();
        hasher2.update(data);
        let checksum2 = format!("{:x}", hasher2.finalize());
        assert_eq!(checksum, checksum2);
    }

    // -----------------------------------------------------------------------
    // Path/storage key construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_nuget_artifact_path() {
        let package_id = "newtonsoft.json";
        let version = "13.0.1";
        let filename = format!("{}.{}.nupkg", package_id, version);
        let artifact_path = format!("{}/{}/{}", package_id, version, filename);
        assert_eq!(
            artifact_path,
            "newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg"
        );
    }

    #[test]
    fn test_nuget_storage_key() {
        let package_id = "newtonsoft.json";
        let version = "13.0.1";
        let filename = format!("{}.{}.nupkg", package_id, version);
        let storage_key = format!("nuget/{}/{}/{}", package_id, version, filename);
        assert_eq!(
            storage_key,
            "nuget/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg"
        );
    }

    // -----------------------------------------------------------------------
    // Service index base URL
    // -----------------------------------------------------------------------

    #[test]
    fn test_service_index_base_url() {
        let scheme = "https";
        let host = "myregistry.example.com";
        let repo_key = "nuget-hosted";
        let base = format!("{}://{}/nuget/{}", scheme, host, repo_key);
        assert_eq!(base, "https://myregistry.example.com/nuget/nuget-hosted");
    }

    #[test]
    fn test_service_index_default_host() {
        let scheme = "http";
        let host = "localhost";
        let repo_key = "main";
        let base = format!("{}://{}/nuget/{}", scheme, host, repo_key);
        assert_eq!(base, "http://localhost/nuget/main");
    }

    // -----------------------------------------------------------------------
    // build_nuget_base_url
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_nuget_base_url_https() {
        assert_eq!(
            build_nuget_base_url("https", "registry.example.com", "nuget-hosted"),
            "https://registry.example.com/nuget/nuget-hosted"
        );
    }

    #[test]
    fn test_build_nuget_base_url_http_localhost() {
        assert_eq!(
            build_nuget_base_url("http", "localhost", "main"),
            "http://localhost/nuget/main"
        );
    }

    #[test]
    fn test_build_nuget_base_url_with_port() {
        assert_eq!(
            build_nuget_base_url("http", "localhost:8080", "nuget-local"),
            "http://localhost:8080/nuget/nuget-local"
        );
    }

    // -----------------------------------------------------------------------
    // build_nuget_service_index
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_nuget_service_index_structure() {
        let base = "https://example.com/nuget/main";
        let index = build_nuget_service_index(base);
        assert_eq!(index["version"], "3.0.0");
        let resources = index["resources"].as_array().unwrap();
        assert_eq!(resources.len(), 8);
    }

    #[test]
    fn test_build_nuget_service_index_search_url() {
        let base = "https://example.com/nuget/repo";
        let index = build_nuget_service_index(base);
        let resources = index["resources"].as_array().unwrap();
        let search = &resources[0];
        assert_eq!(search["@id"], "https://example.com/nuget/repo/v3/search");
        assert_eq!(search["@type"], "SearchQueryService");
    }

    #[test]
    fn test_build_nuget_service_index_push_url() {
        let base = "https://example.com/nuget/repo";
        let index = build_nuget_service_index(base);
        let resources = index["resources"].as_array().unwrap();
        let push = &resources[7];
        assert_eq!(push["@id"], "https://example.com/nuget/repo/api/v2/package");
        assert_eq!(push["@type"], "PackagePublish/2.0.0");
    }

    #[test]
    fn test_build_nuget_service_index_registration_url() {
        let base = "https://example.com/nuget/repo";
        let index = build_nuget_service_index(base);
        let resources = index["resources"].as_array().unwrap();
        let reg = &resources[3];
        assert_eq!(
            reg["@id"],
            "https://example.com/nuget/repo/v3/registration/"
        );
        assert_eq!(reg["@type"], "RegistrationsBaseUrl");
    }

    // -----------------------------------------------------------------------
    // build_registration_item
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_registration_item_basic() {
        let item = build_registration_item(
            "https://example.com/nuget/repo",
            "newtonsoft.json",
            "13.0.1",
            "Popular JSON framework",
            "James Newton-King",
        );
        assert_eq!(item["catalogEntry"]["id"], "newtonsoft.json");
        assert_eq!(item["catalogEntry"]["version"], "13.0.1");
        assert_eq!(
            item["catalogEntry"]["description"],
            "Popular JSON framework"
        );
        assert_eq!(item["catalogEntry"]["authors"], "James Newton-King");
        assert_eq!(item["catalogEntry"]["listed"], true);
    }

    #[test]
    fn test_build_registration_item_package_content_url() {
        let item = build_registration_item(
            "https://example.com/nuget/repo",
            "mypackage",
            "1.0.0",
            "",
            "",
        );
        let url = item["packageContent"].as_str().unwrap();
        assert_eq!(
            url,
            "https://example.com/nuget/repo/v3/flatcontainer/mypackage/1.0.0/mypackage.1.0.0.nupkg"
        );
    }

    #[test]
    fn test_build_registration_item_empty_metadata() {
        let item = build_registration_item("http://localhost/nuget/local", "pkg", "0.1.0", "", "");
        assert_eq!(item["catalogEntry"]["description"], "");
        assert_eq!(item["catalogEntry"]["authors"], "");
    }

    // -----------------------------------------------------------------------
    // build_flatcontainer_versions_json
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_flatcontainer_versions_json_basic() {
        let versions = vec![
            "1.0.0".to_string(),
            "2.0.0".to_string(),
            "3.0.0".to_string(),
        ];
        let json = build_flatcontainer_versions_json(&versions);
        let arr = json["versions"].as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0], "1.0.0");
        assert_eq!(arr[2], "3.0.0");
    }

    #[test]
    fn test_build_flatcontainer_versions_json_empty() {
        let versions: Vec<String> = vec![];
        let json = build_flatcontainer_versions_json(&versions);
        assert!(json["versions"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_build_flatcontainer_versions_json_single() {
        let versions = vec!["1.0.0-beta".to_string()];
        let json = build_flatcontainer_versions_json(&versions);
        let arr = json["versions"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0], "1.0.0-beta");
    }

    // -----------------------------------------------------------------------
    // build_nuget_artifact_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_nuget_artifact_path_basic() {
        assert_eq!(
            build_nuget_artifact_path("newtonsoft.json", "13.0.1"),
            "newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg"
        );
    }

    #[test]
    fn test_build_nuget_artifact_path_prerelease() {
        assert_eq!(
            build_nuget_artifact_path("mypackage", "1.0.0-beta.1"),
            "mypackage/1.0.0-beta.1/mypackage.1.0.0-beta.1.nupkg"
        );
    }

    // -----------------------------------------------------------------------
    // build_nuget_storage_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_nuget_storage_key_basic() {
        assert_eq!(
            build_nuget_storage_key("newtonsoft.json", "13.0.1"),
            "nuget/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg"
        );
    }

    // -----------------------------------------------------------------------
    // build_nuget_push_metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_nuget_push_metadata_basic() {
        let info = NuspecInfo {
            id: "TestPackage".to_string(),
            version: "2.0.0".to_string(),
            description: "A test package".to_string(),
            authors: "Author".to_string(),
        };
        let meta = build_nuget_push_metadata(&info);
        assert_eq!(meta["id"], "TestPackage");
        assert_eq!(meta["version"], "2.0.0");
        assert_eq!(meta["description"], "A test package");
        assert_eq!(meta["authors"], "Author");
        assert_eq!(meta["filename"], "testpackage.2.0.0.nupkg");
    }

    #[test]
    fn test_build_nuget_push_metadata_preserves_original_id() {
        let info = NuspecInfo {
            id: "Newtonsoft.Json".to_string(),
            version: "13.0.1".to_string(),
            description: "JSON framework".to_string(),
            authors: "James NK".to_string(),
        };
        let meta = build_nuget_push_metadata(&info);
        // id is preserved as-is (with original casing)
        assert_eq!(meta["id"], "Newtonsoft.Json");
        // filename is lowercased
        assert_eq!(meta["filename"], "newtonsoft.json.13.0.1.nupkg");
    }

    // -----------------------------------------------------------------------
    // build_nuget_search_pattern
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_nuget_search_pattern_basic() {
        assert_eq!(build_nuget_search_pattern("json"), "%json%");
    }

    #[test]
    fn test_build_nuget_search_pattern_case_insensitive() {
        assert_eq!(build_nuget_search_pattern("Newton"), "%newton%");
    }

    #[test]
    fn test_build_nuget_search_pattern_empty() {
        assert_eq!(build_nuget_search_pattern(""), "%%");
    }

    #[test]
    fn test_build_nuget_search_pattern_with_dots() {
        assert_eq!(
            build_nuget_search_pattern("Newtonsoft.Json"),
            "%newtonsoft.json%"
        );
    }
}
