//! RubyGems API handlers.
//!
//! Implements the endpoints required for `gem push` and `gem install`.
//!
//! Routes are mounted at `/gems/{repo_key}/...`:
//!   GET  /gems/{repo_key}/api/v1/gems/{name}.json           - Gem info
//!   GET  /gems/{repo_key}/api/v1/versions/{name}.json       - All versions
//!   GET  /gems/{repo_key}/gems/{name}-{version}.gem         - Download gem
//!   POST /gems/{repo_key}/api/v1/gems                       - Push gem
//!   GET  /gems/{repo_key}/specs.4.8.gz                      - Full spec index
//!   GET  /gems/{repo_key}/latest_specs.4.8.gz               - Latest spec index
//!   GET  /gems/{repo_key}/api/v1/dependencies?gems={names}  - Dependency info

use std::io::Write as IoWrite;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use base64::Engine;
use bytes::Bytes;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::proxy_helpers;
use crate::api::SharedState;
use crate::formats::rubygems::RubygemsHandler;
use crate::services::auth_service::AuthService;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::StorageBackend;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Gem push
        .route("/:repo_key/api/v1/gems", post(push_gem))
        // Gem info
        .route("/:repo_key/api/v1/gems/:name", get(gem_info))
        // Gem versions
        .route("/:repo_key/api/v1/versions/:name", get(gem_versions))
        // Dependencies
        .route("/:repo_key/api/v1/dependencies", get(dependencies))
        // Specs indices
        .route("/:repo_key/specs.4.8.gz", get(specs_index))
        .route("/:repo_key/latest_specs.4.8.gz", get(latest_specs_index))
        // Download gem - use a wildcard to capture name-version.gem
        .route("/:repo_key/gems/*gem_file", get(download_gem))
        .layer(DefaultBodyLimit::max(512 * 1024 * 1024)) // 512 MB
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

fn extract_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    // Try Bearer token first (used by gem push with API key)
    if let Some(bearer) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or(v.strip_prefix("bearer ")))
    {
        // For Bearer tokens, use the token as both username and password
        // (the auth service will validate it)
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
            .header("WWW-Authenticate", "Basic realm=\"rubygems\"")
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
                .header("WWW-Authenticate", "Basic realm=\"rubygems\"")
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

async fn resolve_rubygems_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
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
    if fmt != "rubygems" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not a RubyGems repository (format: {})",
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
// GET /gems/{repo_key}/api/v1/gems/{name}.json — Gem info
// ---------------------------------------------------------------------------

async fn gem_info(
    State(state): State<SharedState>,
    Path((repo_key, name)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_rubygems_repo(&state.db, &repo_key).await?;

    // Strip .json suffix if present
    let gem_name = name.strip_suffix(".json").unwrap_or(&name);

    // Find the latest version of this gem
    let artifact = sqlx::query!(
        r#"
        SELECT a.id, a.name, a.version, a.size_bytes, a.checksum_sha256,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND LOWER(a.name) = LOWER($2)
        ORDER BY a.created_at DESC
        LIMIT 1
        "#,
        repo.id,
        gem_name
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Gem not found").into_response())?;

    // Get download count
    let download_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM download_statistics WHERE artifact_id = $1",
        artifact.id
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(Some(0))
    .unwrap_or(0);

    let version = artifact.version.unwrap_or_default();
    let description = artifact
        .metadata
        .as_ref()
        .and_then(|m| m.get("gemspec"))
        .and_then(|gs| gs.get("summary"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let gem_filename = format!("{}-{}.gem", gem_name, version);
    let gem_uri = format!("/gems/{}/gems/{}", repo_key, gem_filename);

    let json = serde_json::json!({
        "name": gem_name,
        "version": version,
        "info": description,
        "gem_uri": gem_uri,
        "sha": artifact.checksum_sha256,
        "downloads": download_count,
        "version_downloads": download_count,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /gems/{repo_key}/api/v1/versions/{name}.json — All versions
// ---------------------------------------------------------------------------

async fn gem_versions(
    State(state): State<SharedState>,
    Path((repo_key, name)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_rubygems_repo(&state.db, &repo_key).await?;

    let gem_name = name.strip_suffix(".json").unwrap_or(&name);

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
        gem_name
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
        return Err((StatusCode::NOT_FOUND, "Gem not found").into_response());
    }

    let versions: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            let version = a.version.clone().unwrap_or_default();
            let description = a
                .metadata
                .as_ref()
                .and_then(|m| m.get("gemspec"))
                .and_then(|gs| gs.get("summary"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let gem_filename = format!("{}-{}.gem", gem_name, version);

            serde_json::json!({
                "number": version,
                "summary": description,
                "platform": "ruby",
                "sha": a.checksum_sha256,
                "gem_uri": format!("/gems/{}/gems/{}", repo_key, gem_filename),
                "downloads_count": 0,
            })
        })
        .collect();

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&versions).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /gems/{repo_key}/gems/{name}-{version}.gem — Download gem
// ---------------------------------------------------------------------------

async fn download_gem(
    State(state): State<SharedState>,
    Path((repo_key, gem_file)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_rubygems_repo(&state.db, &repo_key).await?;

    let filename = gem_file.trim_start_matches('/');

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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Gem file not found").into_response());

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == "remote" {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let upstream_path = format!("gems/{}", filename);
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
                let fname = filename.to_string();
                let upstream_path = format!("gems/{}", filename);
                let (content, content_type) = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    state.proxy_service.as_deref(),
                    repo.id,
                    &upstream_path,
                    |member_id, storage_path| {
                        let db = db.clone();
                        let fname = fname.clone();
                        async move {
                            proxy_helpers::local_fetch_by_path_suffix(
                                &db,
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
// POST /gems/{repo_key}/api/v1/gems — Push gem (raw body)
// ---------------------------------------------------------------------------

async fn push_gem(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    // Authenticate
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_rubygems_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty gem file").into_response());
    }

    // Extract gemspec from the .gem file
    let gemspec = RubygemsHandler::extract_gemspec(&body).map_err(|e| {
        (StatusCode::BAD_REQUEST, format!("Invalid gem file: {}", e)).into_response()
    })?;

    let gem_name = &gemspec.name;
    let gem_version = &gemspec.version;

    if gem_name.is_empty() || gem_version.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Gem name and version are required").into_response());
    }

    // Build filename
    let filename = if let Some(ref platform) = gemspec.platform {
        format!("{}-{}-{}.gem", gem_name, gem_version, platform)
    } else {
        format!("{}-{}.gem", gem_name, gem_version)
    };

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let computed_sha256 = format!("{:x}", hasher.finalize());

    // Artifact path
    let artifact_path = format!("{}/{}/{}", gem_name, gem_version, filename);

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
        return Err((StatusCode::CONFLICT, "Gem version already exists").into_response());
    }

    // Store the file
    let storage_key = format!("rubygems/{}/{}/{}", gem_name, gem_version, filename);
    let storage = FilesystemStorage::new(&repo.storage_path);
    storage.put(&storage_key, body.clone()).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    // Build metadata JSON
    let gem_metadata = serde_json::json!({
        "gemspec": serde_json::to_value(&gemspec).unwrap_or_default(),
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
        gem_name,
        gem_version.to_string(),
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
        VALUES ($1, 'rubygems', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        gem_metadata,
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
        "RubyGems push: {} {} ({}) to repo {}",
        gem_name, gem_version, filename, repo_key
    );

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::from("Successfully registered gem"))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /gems/{repo_key}/specs.4.8.gz — Full spec index (gzipped JSON)
// ---------------------------------------------------------------------------

async fn specs_index(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_rubygems_repo(&state.db, &repo_key).await?;

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

    let specs: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| serde_json::json!([a.name, a.version.clone().unwrap_or_default(), "ruby"]))
        .collect();

    let json_bytes = serde_json::to_vec(&specs).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Serialization error: {}", e),
        )
            .into_response()
    })?;

    let compressed = gzip_compress(&json_bytes).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Compression error: {}", e),
        )
            .into_response()
    })?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/gzip")
        .header(CONTENT_LENGTH, compressed.len().to_string())
        .body(Body::from(compressed))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /gems/{repo_key}/latest_specs.4.8.gz — Latest spec index
// ---------------------------------------------------------------------------

async fn latest_specs_index(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_rubygems_repo(&state.db, &repo_key).await?;

    // Get latest version of each gem using DISTINCT ON
    let artifacts = sqlx::query!(
        r#"
        SELECT DISTINCT ON (LOWER(name)) name, version
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
        ORDER BY LOWER(name), created_at DESC
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

    let specs: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| serde_json::json!([a.name, a.version.clone().unwrap_or_default(), "ruby"]))
        .collect();

    let json_bytes = serde_json::to_vec(&specs).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Serialization error: {}", e),
        )
            .into_response()
    })?;

    let compressed = gzip_compress(&json_bytes).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Compression error: {}", e),
        )
            .into_response()
    })?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/gzip")
        .header(CONTENT_LENGTH, compressed.len().to_string())
        .body(Body::from(compressed))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /gems/{repo_key}/api/v1/dependencies?gems={names} — Dependency info
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct DependencyQuery {
    gems: Option<String>,
}

async fn dependencies(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    Query(query): Query<DependencyQuery>,
) -> Result<Response, Response> {
    let repo = resolve_rubygems_repo(&state.db, &repo_key).await?;

    let gem_names: Vec<&str> = query
        .gems
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    if gem_names.is_empty() {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from("[]"))
            .unwrap());
    }

    let mut result: Vec<serde_json::Value> = Vec::new();

    for gem_name in &gem_names {
        let artifacts = sqlx::query!(
            r#"
            SELECT a.name, a.version, am.metadata as "metadata?"
            FROM artifacts a
            LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
            WHERE a.repository_id = $1
              AND a.is_deleted = false
              AND LOWER(a.name) = LOWER($2)
            ORDER BY a.created_at DESC
            "#,
            repo.id,
            gem_name.to_string()
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

        for a in &artifacts {
            let deps = a
                .metadata
                .as_ref()
                .and_then(|m| m.get("gemspec"))
                .and_then(|gs| gs.get("dependencies"))
                .and_then(|d| d.as_array())
                .map(|arr| {
                    arr.iter()
                        .map(|dep| {
                            serde_json::json!([
                                dep.get("name").and_then(|n| n.as_str()).unwrap_or(""),
                                dep.get("requirements")
                                    .and_then(|r| r.as_str())
                                    .unwrap_or(">= 0"),
                            ])
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            result.push(serde_json::json!({
                "name": a.name,
                "number": a.version.clone().unwrap_or_default(),
                "platform": "ruby",
                "dependencies": deps,
            }));
        }
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&result).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn gzip_compress(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    encoder.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    // -----------------------------------------------------------------------
    // extract_credentials
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
    fn test_extract_credentials_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer my-rubygems-token"),
        );
        let result = extract_credentials(&headers);
        assert_eq!(
            result,
            Some(("token".to_string(), "my-rubygems-token".to_string()))
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
        let headers = make_basic_header("gem-user", "gem-pass");
        let result = extract_credentials(&headers);
        assert_eq!(
            result,
            Some(("gem-user".to_string(), "gem-pass".to_string()))
        );
    }

    #[test]
    fn test_extract_credentials_basic_lowercase() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:pass");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("basic {}", encoded)).unwrap(),
        );
        assert_eq!(
            extract_credentials(&headers),
            Some(("user".to_string(), "pass".to_string()))
        );
    }

    #[test]
    fn test_extract_credentials_none() {
        assert!(extract_credentials(&HeaderMap::new()).is_none());
    }

    #[test]
    fn test_extract_credentials_bearer_priority() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer my-api-key"),
        );
        // Bearer should be tried first
        let result = extract_credentials(&headers);
        assert_eq!(result.unwrap().0, "token");
    }

    #[test]
    fn test_extract_credentials_basic_no_colon() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("nocolon");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", encoded)).unwrap(),
        );
        assert!(extract_credentials(&headers).is_none());
    }

    // -----------------------------------------------------------------------
    // gzip_compress
    // -----------------------------------------------------------------------

    #[test]
    fn test_gzip_compress_empty() {
        let result = gzip_compress(b"");
        assert!(result.is_ok());
        assert!(!result.unwrap().is_empty()); // gzip header exists even for empty
    }

    #[test]
    fn test_gzip_compress_data() {
        let data = b"hello world, this is some test data for gzip compression";
        let result = gzip_compress(data);
        assert!(result.is_ok());
        let compressed = result.unwrap();
        // Compressed data should start with gzip magic bytes
        assert!(compressed.len() >= 2);
        assert_eq!(compressed[0], 0x1f);
        assert_eq!(compressed[1], 0x8b);
    }

    #[test]
    fn test_gzip_compress_roundtrip() {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let original = b"RubyGems spec data [\"rails\", \"7.0.0\", \"ruby\"]";
        let compressed = gzip_compress(original).unwrap();

        let mut decoder = GzDecoder::new(&compressed[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();
        assert_eq!(decompressed, original);
    }

    // -----------------------------------------------------------------------
    // DependencyQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_dependency_query_empty() {
        let q: DependencyQuery = serde_json::from_str(r#"{}"#).unwrap();
        assert!(q.gems.is_none());
    }

    #[test]
    fn test_dependency_query_with_gems() {
        let q: DependencyQuery = serde_json::from_str(r#"{"gems":"rails,sinatra,rack"}"#).unwrap();
        assert_eq!(q.gems, Some("rails,sinatra,rack".to_string()));
    }

    // -----------------------------------------------------------------------
    // Gem name parsing (strip .json suffix)
    // -----------------------------------------------------------------------

    #[test]
    fn test_gem_name_strip_json() {
        let name = "rails.json";
        let gem_name = name.strip_suffix(".json").unwrap_or(name);
        assert_eq!(gem_name, "rails");
    }

    #[test]
    fn test_gem_name_no_json() {
        let name = "rails";
        let gem_name = name.strip_suffix(".json").unwrap_or(name);
        assert_eq!(gem_name, "rails");
    }

    // -----------------------------------------------------------------------
    // Gem filename construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_gem_filename_no_platform() {
        let gem_name = "rails";
        let gem_version = "7.0.0";
        let platform: Option<String> = None;
        let filename = if let Some(ref p) = platform {
            format!("{}-{}-{}.gem", gem_name, gem_version, p)
        } else {
            format!("{}-{}.gem", gem_name, gem_version)
        };
        assert_eq!(filename, "rails-7.0.0.gem");
    }

    #[test]
    fn test_gem_filename_with_platform() {
        let gem_name = "nokogiri";
        let gem_version = "1.16.0";
        let platform = Some("x86_64-linux".to_string());
        let filename = if let Some(ref p) = platform {
            format!("{}-{}-{}.gem", gem_name, gem_version, p)
        } else {
            format!("{}-{}.gem", gem_name, gem_version)
        };
        assert_eq!(filename, "nokogiri-1.16.0-x86_64-linux.gem");
    }

    // -----------------------------------------------------------------------
    // Artifact path and storage key
    // -----------------------------------------------------------------------

    #[test]
    fn test_rubygems_artifact_path() {
        let gem_name = "sinatra";
        let gem_version = "3.0.0";
        let filename = format!("{}-{}.gem", gem_name, gem_version);
        let artifact_path = format!("{}/{}/{}", gem_name, gem_version, filename);
        assert_eq!(artifact_path, "sinatra/3.0.0/sinatra-3.0.0.gem");
    }

    #[test]
    fn test_rubygems_storage_key() {
        let gem_name = "sinatra";
        let gem_version = "3.0.0";
        let filename = format!("{}-{}.gem", gem_name, gem_version);
        let storage_key = format!("rubygems/{}/{}/{}", gem_name, gem_version, filename);
        assert_eq!(storage_key, "rubygems/sinatra/3.0.0/sinatra-3.0.0.gem");
    }

    // -----------------------------------------------------------------------
    // RepoInfo struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_info_construction() {
        let id = uuid::Uuid::new_v4();
        let info = RepoInfo {
            id,
            storage_path: "/data/rubygems".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: Some("https://rubygems.org".to_string()),
        };
        assert_eq!(info.id, id);
        assert_eq!(info.repo_type, "hosted");
        assert_eq!(info.upstream_url, Some("https://rubygems.org".to_string()));
    }

    // -----------------------------------------------------------------------
    // SHA256
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256() {
        let data = b"gem file content";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let checksum = format!("{:x}", hasher.finalize());
        assert_eq!(checksum.len(), 64);
    }

    // -----------------------------------------------------------------------
    // Gem URI format
    // -----------------------------------------------------------------------

    #[test]
    fn test_gem_uri() {
        let repo_key = "gems-hosted";
        let gem_filename = "rails-7.0.0.gem";
        let gem_uri = format!("/gems/{}/gems/{}", repo_key, gem_filename);
        assert_eq!(gem_uri, "/gems/gems-hosted/gems/rails-7.0.0.gem");
    }

    // -----------------------------------------------------------------------
    // Dependency parsing logic
    // -----------------------------------------------------------------------

    #[test]
    fn test_dependency_gem_names_parsing() {
        let gems_str = "rails,sinatra,rack";
        let gem_names: Vec<&str> = gems_str
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        assert_eq!(gem_names, vec!["rails", "sinatra", "rack"]);
    }

    #[test]
    fn test_dependency_gem_names_empty() {
        let gems_str = "";
        let gem_names: Vec<&str> = gems_str
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        assert!(gem_names.is_empty());
    }

    #[test]
    fn test_dependency_gem_names_with_spaces() {
        let gems_str = " rails , sinatra , rack ";
        let gem_names: Vec<&str> = gems_str
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        assert_eq!(gem_names, vec!["rails", "sinatra", "rack"]);
    }

    // -----------------------------------------------------------------------
    // Filename trimming (download_gem path)
    // -----------------------------------------------------------------------

    #[test]
    fn test_filename_trim_leading_slash() {
        let gem_file = "/rails-7.0.0.gem";
        let filename = gem_file.trim_start_matches('/');
        assert_eq!(filename, "rails-7.0.0.gem");
    }

    #[test]
    fn test_filename_no_leading_slash() {
        let gem_file = "rails-7.0.0.gem";
        let filename = gem_file.trim_start_matches('/');
        assert_eq!(filename, "rails-7.0.0.gem");
    }

    // -----------------------------------------------------------------------
    // Specs format
    // -----------------------------------------------------------------------

    #[test]
    fn test_specs_json_format() {
        let specs: Vec<serde_json::Value> = vec![
            serde_json::json!(["rails", "7.0.0", "ruby"]),
            serde_json::json!(["sinatra", "3.0.0", "ruby"]),
        ];
        let json_bytes = serde_json::to_vec(&specs).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0][0], "rails");
        assert_eq!(parsed[0][1], "7.0.0");
        assert_eq!(parsed[0][2], "ruby");
    }
}
