//! Cargo sparse registry protocol handlers.
//!
//! Implements the endpoints required for `cargo publish` and `cargo install`
//! via the sparse registry protocol (RFC 2789).
//!
//! Routes are mounted at `/cargo/{repo_key}/...`:
//!   GET  /cargo/{repo_key}/config.json                              - Registry config
//!   GET  /cargo/{repo_key}/api/v1/crates                           - Search crates
//!   PUT  /cargo/{repo_key}/api/v1/crates/new                       - Publish crate
//!   GET  /cargo/{repo_key}/api/v1/crates/{name}/{version}/download - Download crate
//!   GET  /cargo/{repo_key}/index/*path                             - Sparse index lookup

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, State};
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
        // Registry config
        .route("/:repo_key/config.json", get(config_json))
        // Search
        .route("/:repo_key/api/v1/crates", get(search_crates))
        // Publish
        .route("/:repo_key/api/v1/crates/new", put(publish))
        // Download
        .route(
            "/:repo_key/api/v1/crates/:name/:version/download",
            get(download),
        )
        // Sparse index — various path layouts
        .route("/:repo_key/index/1/:name", get(sparse_index_1))
        .route("/:repo_key/index/2/:name", get(sparse_index_2))
        .route("/:repo_key/index/3/:prefix/:name", get(sparse_index_3))
        .route(
            "/:repo_key/index/:prefix1/:prefix2/:name",
            get(sparse_index_4plus),
        )
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

/// Also support Bearer token auth (cargo uses token-based auth).
fn extract_token(headers: &HeaderMap) -> Option<(String, String)> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or(v.strip_prefix("bearer ")))
        .map(|token| {
            // Cargo sends the token directly; treat it as password with "cargo" username
            ("cargo".to_string(), token.to_string())
        })
}

/// Authenticate via Basic auth or Bearer token, returning user_id on success.
async fn authenticate(
    db: &PgPool,
    config: &crate::config::Config,
    headers: &HeaderMap,
) -> Result<uuid::Uuid, Response> {
    let (username, password) = extract_basic_credentials(headers)
        .or_else(|| extract_token(headers))
        .ok_or_else(|| {
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("WWW-Authenticate", "Basic realm=\"cargo\"")
                .body(Body::from(
                    serde_json::json!({"errors": [{"detail": "Authentication required"}]})
                        .to_string(),
                ))
                .unwrap()
        })?;

    let auth_service = AuthService::new(db.clone(), Arc::new(config.clone()));
    let (user, _tokens) = auth_service
        .authenticate(&username, &password)
        .await
        .map_err(|_| {
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("WWW-Authenticate", "Basic realm=\"cargo\"")
                .body(Body::from(
                    serde_json::json!({"errors": [{"detail": "Invalid credentials"}]}).to_string(),
                ))
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

async fn resolve_cargo_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
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
    if fmt != "cargo" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not a Cargo repository (format: {})",
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
// GET /cargo/{repo_key}/config.json — Registry configuration
// ---------------------------------------------------------------------------

async fn config_json(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let _repo = resolve_cargo_repo(&state.db, &repo_key).await?;

    // Determine the host from the request headers or fall back to config
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");

    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http");

    let base_url = format!("{}://{}", scheme, host);

    let config = serde_json::json!({
        "dl": format!("{}/cargo/{}/api/v1/crates", base_url, repo_key),
        "api": format!("{}/cargo/{}", base_url, repo_key),
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .header("cache-control", "max-age=300")
        .body(Body::from(serde_json::to_string_pretty(&config).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /cargo/{repo_key}/api/v1/crates — Search crates
// ---------------------------------------------------------------------------

async fn search_crates(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Result<Response, Response> {
    let repo = resolve_cargo_repo(&state.db, &repo_key).await?;

    let query = params.get("q").cloned().unwrap_or_default();
    let per_page: i64 = params
        .get("per_page")
        .and_then(|v| v.parse().ok())
        .unwrap_or(10)
        .min(100);

    // Search for crates matching the query
    let crates = sqlx::query!(
        r#"
        SELECT DISTINCT a.name,
               MAX(a.version) as "max_version?",
               MAX(am.metadata::text) as "metadata_text?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND ($2 = '' OR a.name ILIKE '%' || $2 || '%')
        GROUP BY a.name
        ORDER BY a.name
        LIMIT $3
        "#,
        repo.id,
        query,
        per_page,
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

    let crate_list: Vec<serde_json::Value> = crates
        .iter()
        .map(|c| {
            let description = c
                .metadata_text
                .as_ref()
                .and_then(|t| serde_json::from_str::<serde_json::Value>(t).ok())
                .and_then(|m| {
                    m.get("description")
                        .and_then(|v| v.as_str())
                        .map(String::from)
                })
                .unwrap_or_default();

            serde_json::json!({
                "name": c.name,
                "max_version": c.max_version,
                "description": description,
            })
        })
        .collect();

    let response = serde_json::json!({
        "crates": crate_list,
        "meta": {
            "total": crate_list.len(),
        }
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// PUT /cargo/{repo_key}/api/v1/crates/new — Publish crate
// ---------------------------------------------------------------------------

/// Cargo publish binary protocol:
///   - 4 bytes: JSON metadata length (LE u32)
///   - N bytes: JSON metadata
///   - 4 bytes: .crate file length (LE u32)
///   - Remaining: .crate file bytes (gzipped tar)
async fn publish(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    // Authenticate
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_cargo_repo(&state.db, &repo_key).await?;

    // Reject writes to remote/virtual repos
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    // Parse the binary publish payload
    if body.len() < 4 {
        return Err((StatusCode::BAD_REQUEST, "Payload too short").into_response());
    }

    // Read JSON metadata length
    let json_len = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as usize;
    if body.len() < 4 + json_len + 4 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Payload too short for metadata + crate length",
        )
            .into_response());
    }

    // Parse JSON metadata
    let json_bytes = &body[4..4 + json_len];
    let metadata: serde_json::Value = serde_json::from_slice(json_bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid JSON metadata: {}", e),
        )
            .into_response()
    })?;

    let crate_name = metadata["name"]
        .as_str()
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing 'name' in metadata").into_response())?
        .to_string();

    let crate_version = metadata["vers"]
        .as_str()
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing 'vers' in metadata").into_response())?
        .to_string();

    // Read crate file length
    let crate_len_offset = 4 + json_len;
    let crate_len = u32::from_le_bytes([
        body[crate_len_offset],
        body[crate_len_offset + 1],
        body[crate_len_offset + 2],
        body[crate_len_offset + 3],
    ]) as usize;

    let crate_data_offset = crate_len_offset + 4;
    if body.len() < crate_data_offset + crate_len {
        return Err((StatusCode::BAD_REQUEST, "Payload too short for .crate data").into_response());
    }

    let crate_bytes =
        Bytes::copy_from_slice(&body[crate_data_offset..crate_data_offset + crate_len]);

    // Compute SHA256 of the .crate file
    let mut hasher = Sha256::new();
    hasher.update(&crate_bytes);
    let checksum = format!("{:x}", hasher.finalize());

    let name_lower = crate_name.to_lowercase();

    // Check for duplicate
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND name = $2 AND version = $3 AND is_deleted = false",
        repo.id,
        name_lower,
        crate_version,
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
        return Err(Response::builder()
            .status(StatusCode::CONFLICT)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({"errors": [{"detail": format!(
                    "crate version `{}@{}` already exists",
                    name_lower, crate_version
                )}]})
                .to_string(),
            ))
            .unwrap());
    }

    // Store the .crate file
    let filename = format!("{}-{}.crate", name_lower, crate_version);
    let storage_key = format!("cargo/{}/{}/{}", name_lower, crate_version, filename);
    let storage = FilesystemStorage::new(&repo.storage_path);
    storage
        .put(&storage_key, crate_bytes.clone())
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Storage error: {}", e),
            )
                .into_response()
        })?;

    let artifact_path = format!("{}/{}/{}", name_lower, crate_version, filename);
    let size_bytes = crate_bytes.len() as i64;

    // Build metadata for artifact_metadata table
    let deps = metadata
        .get("deps")
        .cloned()
        .unwrap_or(serde_json::json!([]));
    let features = metadata
        .get("features")
        .cloned()
        .unwrap_or(serde_json::json!({}));
    let description = metadata
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let license = metadata
        .get("license")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let keywords = metadata
        .get("keywords")
        .cloned()
        .unwrap_or(serde_json::json!([]));
    let categories = metadata
        .get("categories")
        .cloned()
        .unwrap_or(serde_json::json!([]));
    let links = metadata.get("links").cloned();
    let rust_version = metadata
        .get("rust_version")
        .and_then(|v| v.as_str())
        .map(String::from);

    let cargo_metadata = serde_json::json!({
        "name": name_lower,
        "vers": crate_version,
        "deps": deps,
        "features": features,
        "description": description,
        "license": license,
        "keywords": keywords,
        "categories": categories,
        "links": links,
        "rust_version": rust_version,
        "cksum": checksum,
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
        name_lower,
        crate_version,
        size_bytes,
        checksum,
        "application/x-tar",
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
        VALUES ($1, 'cargo', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        cargo_metadata,
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
        "Cargo publish: {} {} ({} bytes) to repo {}",
        name_lower, crate_version, size_bytes, repo_key
    );

    // Cargo expects a JSON response with warnings
    let response = serde_json::json!({
        "warnings": {
            "invalid_categories": [],
            "invalid_badges": [],
            "other": []
        }
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /cargo/{repo_key}/api/v1/crates/{name}/{version}/download — Download
// ---------------------------------------------------------------------------

async fn download(
    State(state): State<SharedState>,
    Path((repo_key, name, version)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_cargo_repo(&state.db, &repo_key).await?;
    let name_lower = name.to_lowercase();

    let artifact = sqlx::query!(
        r#"
        SELECT id, storage_key, size_bytes, checksum_sha256
        FROM artifacts
        WHERE repository_id = $1
          AND name = $2
          AND version = $3
          AND is_deleted = false
        LIMIT 1
        "#,
        repo.id,
        name_lower,
        version,
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

    // If crate not found locally, try proxy for remote repos
    let artifact = match artifact {
        Some(a) => a,
        None => {
            if repo.repo_type == "remote" {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let upstream_path =
                        format!("api/v1/crates/{}/{}/download", name_lower, version);
                    let (content, _content_type) = proxy_helpers::proxy_fetch(
                        proxy,
                        repo.id,
                        &repo_key,
                        upstream_url,
                        &upstream_path,
                    )
                    .await?;

                    let filename = format!("{}-{}.crate", name_lower, version);

                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, "application/x-tar")
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
                let vname = name_lower.clone();
                let vversion = version.clone();
                let upstream_path = format!("api/v1/crates/{}/{}/download", name_lower, version);
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

                let filename = format!("{}-{}.crate", name_lower, version);

                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(
                        CONTENT_TYPE,
                        content_type.unwrap_or_else(|| "application/x-tar".to_string()),
                    )
                    .header(
                        "Content-Disposition",
                        format!("attachment; filename=\"{}\"", filename),
                    )
                    .header(CONTENT_LENGTH, content.len().to_string())
                    .body(Body::from(content))
                    .unwrap());
            }
            return Err((StatusCode::NOT_FOUND, "Crate not found").into_response());
        }
    };

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

    let filename = format!("{}-{}.crate", name_lower, version);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/x-tar")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, content.len().to_string())
        .body(Body::from(content))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /cargo/{repo_key}/index/... — Sparse index endpoints
// ---------------------------------------------------------------------------

/// Index for 1-character crate names: /index/1/{name}
async fn sparse_index_1(
    State(state): State<SharedState>,
    Path((repo_key, name)): Path<(String, String)>,
) -> Result<Response, Response> {
    serve_index(&state, &repo_key, &name).await
}

/// Index for 2-character crate names: /index/2/{name}
async fn sparse_index_2(
    State(state): State<SharedState>,
    Path((repo_key, name)): Path<(String, String)>,
) -> Result<Response, Response> {
    serve_index(&state, &repo_key, &name).await
}

/// Index for 3-character crate names: /index/3/{first_char}/{name}
async fn sparse_index_3(
    State(state): State<SharedState>,
    Path((repo_key, _prefix, name)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    serve_index(&state, &repo_key, &name).await
}

/// Index for 4+ character crate names: /index/{first2}/{next2}/{name}
async fn sparse_index_4plus(
    State(state): State<SharedState>,
    Path((repo_key, _prefix1, _prefix2, name)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    serve_index(&state, &repo_key, &name).await
}

/// Serve the sparse index file for a crate (one JSON object per version, per line).
async fn serve_index(
    state: &SharedState,
    repo_key: &str,
    crate_name: &str,
) -> Result<Response, Response> {
    let repo = resolve_cargo_repo(&state.db, repo_key).await?;
    let name_lower = crate_name.to_lowercase();

    // Fetch all versions of this crate with their metadata
    let versions = sqlx::query!(
        r#"
        SELECT a.name, a.version as "version?", a.checksum_sha256,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.name = $2
          AND a.is_deleted = false
        ORDER BY a.created_at ASC
        "#,
        repo.id,
        name_lower,
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
        // For remote repos, proxy the sparse index from upstream
        if repo.repo_type == "remote" {
            if let (Some(ref upstream_url), Some(ref proxy)) =
                (&repo.upstream_url, &state.proxy_service)
            {
                // Cargo sparse index path layout depends on crate name length
                let index_path = cargo_sparse_index_path(&name_lower);
                let (content, content_type) =
                    proxy_helpers::proxy_fetch(proxy, repo.id, repo_key, upstream_url, &index_path)
                        .await?;

                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(
                        CONTENT_TYPE,
                        content_type.unwrap_or_else(|| "application/json".to_string()),
                    )
                    .header("cache-control", "max-age=60")
                    .body(Body::from(content))
                    .unwrap());
            }
        }
        // Virtual repo: try each member in priority order for index
        if repo.repo_type == "virtual" {
            let index_path = cargo_sparse_index_path(&name_lower);
            let db = state.db.clone();
            let vname = name_lower.clone();
            let (content, content_type) = proxy_helpers::resolve_virtual_download(
                &state.db,
                state.proxy_service.as_deref(),
                repo.id,
                &index_path,
                |member_id, _storage_path| {
                    let db = db.clone();
                    let vname = vname.clone();
                    async move {
                        // For the index, we just need to check if the crate exists in this member.
                        // We query by name and return the index content if found.
                        // Using non-macro query to avoid offline cache requirements.
                        use sqlx::Row;
                        let rows = sqlx::query(
                            r#"
                            SELECT a.name, a.version, a.checksum_sha256,
                                   am.metadata
                            FROM artifacts a
                            LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
                            WHERE a.repository_id = $1
                              AND a.name = $2
                              AND a.is_deleted = false
                            ORDER BY a.created_at ASC
                            "#,
                        )
                        .bind(member_id)
                        .bind(&vname)
                        .fetch_all(&db)
                        .await
                        .map_err(|e| {
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                format!("Database error: {}", e),
                            )
                                .into_response()
                        })?;

                        if rows.is_empty() {
                            return Err((StatusCode::NOT_FOUND, "Crate not found").into_response());
                        }

                        let mut lines = Vec::new();
                        for row in &rows {
                            let vers: Option<String> = row.get("version");
                            let vers = vers.as_deref().unwrap_or("0.0.0");
                            let cksum: String = row.get("checksum_sha256");
                            let meta: Option<serde_json::Value> = row.get("metadata");

                            let (deps, features, links, rust_version) = if let Some(ref meta) = meta
                            {
                                (
                                    meta.get("deps").cloned().unwrap_or(serde_json::json!([])),
                                    meta.get("features")
                                        .cloned()
                                        .unwrap_or(serde_json::json!({})),
                                    meta.get("links")
                                        .cloned()
                                        .unwrap_or(serde_json::Value::Null),
                                    meta.get("rust_version")
                                        .cloned()
                                        .unwrap_or(serde_json::Value::Null),
                                )
                            } else {
                                (
                                    serde_json::json!([]),
                                    serde_json::json!({}),
                                    serde_json::Value::Null,
                                    serde_json::Value::Null,
                                )
                            };

                            let mut entry = serde_json::json!({
                                "name": vname,
                                "vers": vers,
                                "deps": deps,
                                "cksum": cksum,
                                "features": features,
                                "yanked": false,
                            });

                            if !links.is_null() {
                                entry["links"] = links;
                            }
                            if !rust_version.is_null() {
                                entry["rust-version"] = rust_version;
                            }

                            lines.push(serde_json::to_string(&entry).unwrap());
                        }

                        let body = lines.join("\n");
                        Ok((
                            bytes::Bytes::from(body),
                            Some("application/json".to_string()),
                        ))
                    }
                },
            )
            .await?;

            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(
                    CONTENT_TYPE,
                    content_type.unwrap_or_else(|| "application/json".to_string()),
                )
                .header("cache-control", "max-age=60")
                .body(Body::from(content))
                .unwrap());
        }
        return Err((StatusCode::NOT_FOUND, "Crate not found in index").into_response());
    }

    // Build index file: one JSON object per line
    let mut lines = Vec::new();

    for v in &versions {
        let vers = v.version.as_deref().unwrap_or("0.0.0");
        let cksum = &v.checksum_sha256;

        // Extract deps and features from stored metadata
        let (deps, features, links, rust_version) = if let Some(ref meta) = v.metadata {
            let deps = meta.get("deps").cloned().unwrap_or(serde_json::json!([]));
            let features = meta
                .get("features")
                .cloned()
                .unwrap_or(serde_json::json!({}));
            let links = meta
                .get("links")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let rust_version = meta
                .get("rust_version")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            (deps, features, links, rust_version)
        } else {
            (
                serde_json::json!([]),
                serde_json::json!({}),
                serde_json::Value::Null,
                serde_json::Value::Null,
            )
        };

        let mut entry = serde_json::json!({
            "name": name_lower,
            "vers": vers,
            "deps": deps,
            "cksum": cksum,
            "features": features,
            "yanked": false,
        });

        if !links.is_null() {
            entry["links"] = links;
        }
        if !rust_version.is_null() {
            entry["rust-version"] = rust_version;
        }

        lines.push(serde_json::to_string(&entry).unwrap());
    }

    let body = lines.join("\n");

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .header("cache-control", "max-age=60")
        .body(Body::from(body))
        .unwrap())
}

/// Build the sparse index path for a crate name following the Cargo registry layout.
fn cargo_sparse_index_path(name: &str) -> String {
    match name.len() {
        1 => format!("index/1/{}", name),
        2 => format!("index/2/{}", name),
        3 => format!("index/3/{}/{}", &name[..1], name),
        _ => format!("index/{}/{}/{}", &name[..2], &name[2..4], name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    // -----------------------------------------------------------------------
    // cargo_sparse_index_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_cargo_sparse_index_path_1_char() {
        assert_eq!(cargo_sparse_index_path("a"), "index/1/a");
    }

    #[test]
    fn test_cargo_sparse_index_path_2_char() {
        assert_eq!(cargo_sparse_index_path("ab"), "index/2/ab");
    }

    #[test]
    fn test_cargo_sparse_index_path_3_char() {
        assert_eq!(cargo_sparse_index_path("abc"), "index/3/a/abc");
    }

    #[test]
    fn test_cargo_sparse_index_path_4_char() {
        assert_eq!(cargo_sparse_index_path("abcd"), "index/ab/cd/abcd");
    }

    #[test]
    fn test_cargo_sparse_index_path_long_name() {
        assert_eq!(
            cargo_sparse_index_path("serde_json"),
            "index/se/rd/serde_json"
        );
    }

    #[test]
    fn test_cargo_sparse_index_path_5_char() {
        assert_eq!(cargo_sparse_index_path("tokio"), "index/to/ki/tokio");
    }

    #[test]
    fn test_cargo_sparse_index_path_exact_4() {
        assert_eq!(cargo_sparse_index_path("rand"), "index/ra/nd/rand");
    }

    // -----------------------------------------------------------------------
    // extract_basic_credentials
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_basic_credentials_valid() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        let result = extract_basic_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "pass".to_string())));
    }

    #[test]
    fn test_extract_basic_credentials_lowercase() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("basic dXNlcjpwYXNz"),
        );
        assert!(extract_basic_credentials(&headers).is_some());
    }

    #[test]
    fn test_extract_basic_credentials_no_header() {
        let headers = HeaderMap::new();
        assert!(extract_basic_credentials(&headers).is_none());
    }

    #[test]
    fn test_extract_basic_credentials_invalid_base64() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic !!!invalid!!!"),
        );
        assert!(extract_basic_credentials(&headers).is_none());
    }

    #[test]
    fn test_extract_basic_credentials_no_colon() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic bm9jb2xvbg=="),
        );
        assert!(extract_basic_credentials(&headers).is_none());
    }

    #[test]
    fn test_extract_basic_credentials_password_with_colon() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYTpzcw=="),
        );
        let result = extract_basic_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "pa:ss".to_string())));
    }

    // -----------------------------------------------------------------------
    // extract_token (Bearer auth)
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_token_valid_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer my-api-token"),
        );
        let result = extract_token(&headers);
        assert_eq!(
            result,
            Some(("cargo".to_string(), "my-api-token".to_string()))
        );
    }

    #[test]
    fn test_extract_token_lowercase_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("bearer my-token"),
        );
        let result = extract_token(&headers);
        assert_eq!(result, Some(("cargo".to_string(), "my-token".to_string())));
    }

    #[test]
    fn test_extract_token_no_header() {
        let headers = HeaderMap::new();
        assert!(extract_token(&headers).is_none());
    }

    #[test]
    fn test_extract_token_basic_auth_returns_none() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        assert!(extract_token(&headers).is_none());
    }

    #[test]
    fn test_extract_token_empty_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer "),
        );
        let result = extract_token(&headers);
        assert_eq!(result, Some(("cargo".to_string(), "".to_string())));
    }

    // -----------------------------------------------------------------------
    // Publish binary protocol parsing (standalone logic)
    // -----------------------------------------------------------------------

    #[test]
    fn test_publish_payload_parsing_too_short() {
        let body = Bytes::from_static(&[0, 0, 0]);
        assert!(body.len() < 4);
    }

    #[test]
    fn test_publish_payload_json_len_parsing() {
        let json_data = b"{\"a\":1}";
        let json_len = json_data.len() as u32;
        let mut payload = Vec::new();
        payload.extend_from_slice(&json_len.to_le_bytes());
        payload.extend_from_slice(json_data);

        let crate_data = b"crate_content";
        let crate_len = crate_data.len() as u32;
        payload.extend_from_slice(&crate_len.to_le_bytes());
        payload.extend_from_slice(crate_data);

        let body = Bytes::from(payload);

        let json_len_parsed = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as usize;
        assert_eq!(json_len_parsed, 7);

        let json_bytes = &body[4..4 + json_len_parsed];
        let metadata: serde_json::Value = serde_json::from_slice(json_bytes).unwrap();
        assert_eq!(metadata["a"], 1);

        let crate_len_offset = 4 + json_len_parsed;
        let crate_len_parsed = u32::from_le_bytes([
            body[crate_len_offset],
            body[crate_len_offset + 1],
            body[crate_len_offset + 2],
            body[crate_len_offset + 3],
        ]) as usize;
        assert_eq!(crate_len_parsed, 13);

        let crate_data_offset = crate_len_offset + 4;
        let parsed_crate = &body[crate_data_offset..crate_data_offset + crate_len_parsed];
        assert_eq!(parsed_crate, b"crate_content");
    }

    #[test]
    fn test_publish_payload_with_real_metadata() {
        let metadata = serde_json::json!({
            "name": "my-crate",
            "vers": "0.1.0",
            "deps": [],
            "features": {},
            "description": "A test crate",
            "license": "MIT"
        });
        let json_bytes = serde_json::to_vec(&metadata).unwrap();
        let json_len = json_bytes.len() as u32;

        let crate_data = b"fake crate tarball bytes";
        let crate_len = crate_data.len() as u32;

        let mut payload = Vec::new();
        payload.extend_from_slice(&json_len.to_le_bytes());
        payload.extend_from_slice(&json_bytes);
        payload.extend_from_slice(&crate_len.to_le_bytes());
        payload.extend_from_slice(crate_data);

        let body = Bytes::from(payload);

        assert!(body.len() >= 4);
        let jl = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as usize;
        assert!(body.len() >= 4 + jl + 4);

        let parsed: serde_json::Value = serde_json::from_slice(&body[4..4 + jl]).unwrap();
        assert_eq!(parsed["name"], "my-crate");
        assert_eq!(parsed["vers"], "0.1.0");

        let cl_offset = 4 + jl;
        let cl = u32::from_le_bytes([
            body[cl_offset],
            body[cl_offset + 1],
            body[cl_offset + 2],
            body[cl_offset + 3],
        ]) as usize;
        assert_eq!(cl, crate_data.len());
    }

    // -----------------------------------------------------------------------
    // SHA256 computation (same logic used in publish)
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256_computation() {
        let data = b"test crate data";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let checksum = format!("{:x}", hasher.finalize());
        assert_eq!(checksum.len(), 64);
        let mut hasher2 = Sha256::new();
        hasher2.update(data);
        let checksum2 = format!("{:x}", hasher2.finalize());
        assert_eq!(checksum, checksum2);
    }

    #[test]
    fn test_sha256_different_data() {
        let mut h1 = Sha256::new();
        h1.update(b"data1");
        let c1 = format!("{:x}", h1.finalize());

        let mut h2 = Sha256::new();
        h2.update(b"data2");
        let c2 = format!("{:x}", h2.finalize());

        assert_ne!(c1, c2);
    }
}
