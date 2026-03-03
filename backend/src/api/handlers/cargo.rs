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

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::Extension;
use axum::Router;
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
        // Sparse index — index/ prefixed paths (legacy / internal)
        .route("/:repo_key/index/1/:name", get(sparse_index_1))
        .route("/:repo_key/index/2/:name", get(sparse_index_2))
        .route("/:repo_key/index/3/:prefix/:name", get(sparse_index_3))
        .route(
            "/:repo_key/index/:prefix1/:prefix2/:name",
            get(sparse_index_4plus),
        )
        // Sparse index — root-level paths (Cargo sparse registry protocol)
        // Cargo clients expect index files at the registry root, not under index/.
        // Axum prioritises static segments first so api/v1/crates etc. still win.
        .route("/:repo_key/1/:name", get(sparse_index_1))
        .route("/:repo_key/2/:name", get(sparse_index_2))
        .route("/:repo_key/3/:prefix/:name", get(sparse_index_3))
        .route(
            "/:repo_key/:prefix1/:prefix2/:name",
            get(sparse_index_4plus),
        )
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
    /// Separate index host for registries like crates.io that split index
    /// (`https://index.crates.io`) and download (`https://crates.io`) across
    /// two hosts. Loaded from the `repository_config` table on the key
    /// `index_upstream_url`. Falls back to `upstream_url` when absent.
    index_upstream_url: Option<String>,
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

    let index_upstream_url: Option<String> = sqlx::query_as::<_, (Option<String>,)>(
        "SELECT value FROM repository_config WHERE repository_id = $1 AND key = 'index_upstream_url'"
    )
    .bind(repo.id)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?
    .and_then(|(v,)| v);

    Ok(RepoInfo {
        id: repo.id,
        storage_path: repo.storage_path,
        repo_type: repo.repo_type,
        upstream_url: repo.upstream_url,
        index_upstream_url,
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

/// Result of parsing the Cargo publish binary protocol payload.
struct ParsedPublishPayload {
    metadata: serde_json::Value,
    crate_name: String,
    crate_version: String,
    crate_bytes: Bytes,
}

/// Parse the Cargo publish binary protocol:
///   - 4 bytes: JSON metadata length (LE u32)
///   - N bytes: JSON metadata
///   - 4 bytes: .crate file length (LE u32)
///   - Remaining: .crate file bytes (gzipped tar)
#[allow(clippy::result_large_err)]
fn parse_publish_payload(body: &Bytes) -> Result<ParsedPublishPayload, Response> {
    if body.len() < 4 {
        return Err((StatusCode::BAD_REQUEST, "Payload too short").into_response());
    }

    let json_len = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as usize;
    if body.len() < 4 + json_len + 4 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Payload too short for metadata + crate length",
        )
            .into_response());
    }

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

    Ok(ParsedPublishPayload {
        metadata,
        crate_name,
        crate_version,
        crate_bytes,
    })
}

/// Build the cargo metadata JSON from the publish request metadata, suitable
/// for storing in the artifact_metadata table.
fn build_cargo_metadata(
    metadata: &serde_json::Value,
    name_lower: &str,
    crate_version: &str,
    checksum: &str,
) -> serde_json::Value {
    let get_or = |key: &str, default: serde_json::Value| -> serde_json::Value {
        metadata.get(key).cloned().unwrap_or(default)
    };

    serde_json::json!({
        "name": name_lower,
        "vers": crate_version,
        "deps": get_or("deps", serde_json::json!([])),
        "features": get_or("features", serde_json::json!({})),
        "description": metadata.get("description").and_then(|v| v.as_str()).unwrap_or(""),
        "license": metadata.get("license").and_then(|v| v.as_str()).unwrap_or(""),
        "keywords": get_or("keywords", serde_json::json!([])),
        "categories": get_or("categories", serde_json::json!([])),
        "links": metadata.get("links").cloned(),
        "rust_version": metadata.get("rust_version").and_then(|v| v.as_str()),
        "cksum": checksum,
    })
}

/// Check whether a crate version already exists and return a CONFLICT error if so.
async fn check_duplicate_crate(
    db: &PgPool,
    repo_id: uuid::Uuid,
    name: &str,
    version: &str,
) -> Result<(), Response> {
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND name = $2 AND version = $3 AND is_deleted = false",
        repo_id,
        name,
        version,
    )
    .fetch_optional(db)
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
                    name, version
                )}]})
                .to_string(),
            ))
            .unwrap());
    }

    Ok(())
}

/// Store the .crate file and insert artifact + metadata records into the database.
#[allow(clippy::too_many_arguments)]
async fn store_crate_artifact(
    state: &SharedState,
    repo: &RepoInfo,
    name_lower: &str,
    crate_version: &str,
    crate_bytes: Bytes,
    checksum: &str,
    cargo_metadata: serde_json::Value,
    user_id: uuid::Uuid,
) -> Result<(), Response> {
    let filename = format!("{}-{}.crate", name_lower, crate_version);
    let storage_key = format!("cargo/{}/{}/{}", name_lower, crate_version, filename);
    let storage = state.storage_for_repo(&repo.storage_path);
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

    super::cleanup_soft_deleted_artifact(&state.db, repo.id, &artifact_path).await;

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

    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
    .await;

    Ok(())
}

async fn publish(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id =
        require_auth_with_bearer_fallback(auth, &headers, &state.db, &state.config, "cargo")
            .await?;
    let repo = resolve_cargo_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    let parsed = parse_publish_payload(&body)?;
    let name_lower = parsed.crate_name.to_lowercase();

    check_duplicate_crate(&state.db, repo.id, &name_lower, &parsed.crate_version).await?;

    // Compute SHA256 of the .crate file
    let mut hasher = Sha256::new();
    hasher.update(&parsed.crate_bytes);
    let checksum = format!("{:x}", hasher.finalize());

    let cargo_metadata = build_cargo_metadata(
        &parsed.metadata,
        &name_lower,
        &parsed.crate_version,
        &checksum,
    );

    let size_bytes = parsed.crate_bytes.len() as i64;

    store_crate_artifact(
        &state,
        &repo,
        &name_lower,
        &parsed.crate_version,
        parsed.crate_bytes,
        &checksum,
        cargo_metadata,
        user_id,
    )
    .await?;

    info!(
        "Cargo publish: {} {} ({} bytes) to repo {}",
        name_lower, parsed.crate_version, size_bytes, repo_key
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
                        let state = state.clone();
                        let vname = vname.clone();
                        let vversion = vversion.clone();
                        async move {
                            proxy_helpers::local_fetch_by_name_version(
                                &db,
                                &state,
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

/// Build a single sparse-index JSON entry from crate metadata.
fn build_index_entry(
    crate_name: &str,
    version: &str,
    checksum: &str,
    metadata: Option<&serde_json::Value>,
) -> String {
    let (deps, features, links, rust_version) = extract_index_fields(metadata);

    let mut entry = serde_json::json!({
        "name": crate_name,
        "vers": version,
        "deps": deps,
        "cksum": checksum,
        "features": features,
        "yanked": false,
    });

    if !links.is_null() {
        entry["links"] = links;
    }
    if !rust_version.is_null() {
        entry["rust-version"] = rust_version;
    }

    serde_json::to_string(&entry).unwrap()
}

/// Extract deps, features, links, and rust_version from stored metadata,
/// returning defaults when metadata is absent.
fn extract_index_fields(
    metadata: Option<&serde_json::Value>,
) -> (
    serde_json::Value,
    serde_json::Value,
    serde_json::Value,
    serde_json::Value,
) {
    let Some(meta) = metadata else {
        return (
            serde_json::json!([]),
            serde_json::json!({}),
            serde_json::Value::Null,
            serde_json::Value::Null,
        );
    };

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
}

/// Build a JSON response with cache-control for index responses.
fn index_response(content: impl Into<Body>, content_type: Option<String>) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(
            CONTENT_TYPE,
            content_type.unwrap_or_else(|| "application/json".to_string()),
        )
        .header("cache-control", "max-age=60")
        .body(content.into())
        .unwrap()
}

/// Try to resolve a crate index from a remote upstream proxy.
async fn try_remote_index(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
    name_lower: &str,
) -> Option<Result<Response, Response>> {
    if repo.repo_type != "remote" {
        return None;
    }

    let (upstream_url, proxy) = match (&repo.upstream_url, &state.proxy_service) {
        (Some(u), Some(p)) => (u, p),
        _ => return None,
    };

    let base_url = repo.index_upstream_url.as_deref().unwrap_or(upstream_url);
    let index_path = cargo_sparse_index_path_upstream(name_lower);
    let result =
        proxy_helpers::proxy_fetch(proxy, repo.id, repo_key, base_url, &index_path).await;

    Some(result.map(|(content, content_type)| index_response(content, content_type)))
}

/// Try to resolve a crate index from a virtual repo's member repositories.
///
/// Iterates members in priority order: local index entries first, then upstream
/// proxy for remote members. Honours each member's `index_upstream_url` from
/// `repository_config` (falls back to `upstream_url` when absent).
async fn try_virtual_index(
    state: &SharedState,
    repo: &RepoInfo,
    name_lower: &str,
) -> Option<Result<Response, Response>> {
    use crate::models::repository::RepositoryType;
    use sqlx::Row;

    if repo.repo_type != "virtual" {
        return None;
    }

    let members = match proxy_helpers::fetch_virtual_members(&state.db, repo.id).await {
        Ok(m) => m,
        Err(e) => return Some(Err(e)),
    };

    if members.is_empty() {
        return Some(Err(
            (StatusCode::NOT_FOUND, "Virtual repository has no members").into_response()
        ));
    }

    let index_path = cargo_sparse_index_path_upstream(name_lower);

    for member in &members {
        // Try building the index from local artifacts first.
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
        .bind(member.id)
        .bind(name_lower)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

        if !rows.is_empty() {
            let lines: Vec<String> = rows
                .iter()
                .map(|row| {
                    let vers: Option<String> = row.get("version");
                    let vers = vers.as_deref().unwrap_or("0.0.0");
                    let cksum: String = row.get("checksum_sha256");
                    let meta: Option<serde_json::Value> = row.get("metadata");
                    build_index_entry(name_lower, vers, &cksum, meta.as_ref())
                })
                .collect();
            let body = lines.join("\n");
            return Some(Ok(index_response(
                bytes::Bytes::from(body),
                Some("application/json".to_string()),
            )));
        }

        // For remote members, try the upstream proxy.
        if member.repo_type == RepositoryType::Remote {
            if let (Some(proxy), Some(upstream_url)) =
                (&state.proxy_service, &member.upstream_url)
            {
                // Check for a per-member index_upstream_url override.
                let base_url = sqlx::query_as::<_, (Option<String>,)>(
                    "SELECT value FROM repository_config \
                     WHERE repository_id = $1 AND key = 'index_upstream_url'",
                )
                .bind(member.id)
                .fetch_optional(&state.db)
                .await
                .ok()
                .flatten()
                .and_then(|(v,)| v)
                .unwrap_or_else(|| upstream_url.clone());

                if let Ok((content, content_type)) = proxy_helpers::proxy_fetch(
                    proxy,
                    member.id,
                    &member.key,
                    &base_url,
                    &index_path,
                )
                .await
                {
                    return Some(Ok(index_response(content, content_type)));
                }
            }
        }
    }

    Some(Err((
        StatusCode::NOT_FOUND,
        "Artifact not found in any member repository",
    )
    .into_response()))
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
        if let Some(result) = try_remote_index(state, &repo, repo_key, &name_lower).await {
            return result;
        }
        if let Some(result) = try_virtual_index(state, &repo, &name_lower).await {
            return result;
        }
        return Err((StatusCode::NOT_FOUND, "Crate not found in index").into_response());
    }

    // Build index file: one JSON object per line
    let lines: Vec<String> = versions
        .iter()
        .map(|v| {
            let vers = v.version.as_deref().unwrap_or("0.0.0");
            build_index_entry(&name_lower, vers, &v.checksum_sha256, v.metadata.as_ref())
        })
        .collect();

    let body = lines.join("\n");

    Ok(index_response(body, Some("application/json".to_string())))
}

/// Build the sparse index path for a crate name following the Cargo registry layout.
/// Includes the `index/` prefix used by artifact-keeper's own routing.
/// Kept for reference and test coverage — upstream proxy calls use
/// [`cargo_sparse_index_path_upstream`] instead.
#[cfg_attr(not(test), allow(dead_code))]
fn cargo_sparse_index_path(name: &str) -> String {
    match name.len() {
        1 => format!("index/1/{}", name),
        2 => format!("index/2/{}", name),
        3 => format!("index/3/{}/{}", &name[..1], name),
        _ => format!("index/{}/{}/{}", &name[..2], &name[2..4], name),
    }
}

/// Build the upstream sparse index path for proxying to an external registry.
///
/// The Cargo sparse registry protocol stores index files at the path root
/// (e.g. `https://index.crates.io/se/rd/serde`), so no `index/` prefix is
/// used when constructing the proxy request path.
fn cargo_sparse_index_path_upstream(name: &str) -> String {
    match name.len() {
        1 => format!("1/{}", name),
        2 => format!("2/{}", name),
        3 => format!("3/{}/{}", &name[..1], name),
        _ => format!("{}/{}/{}", &name[..2], &name[2..4], name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    fn make_publish_payload(metadata: &serde_json::Value, crate_data: &[u8]) -> Bytes {
        let json_bytes = serde_json::to_vec(metadata).unwrap();
        let json_len = json_bytes.len() as u32;
        let crate_len = crate_data.len() as u32;

        let mut payload = Vec::new();
        payload.extend_from_slice(&json_len.to_le_bytes());
        payload.extend_from_slice(&json_bytes);
        payload.extend_from_slice(&crate_len.to_le_bytes());
        payload.extend_from_slice(crate_data);
        Bytes::from(payload)
    }

    fn sample_metadata() -> serde_json::Value {
        serde_json::json!({
            "name": "my-crate",
            "vers": "0.1.0",
            "deps": [{"name": "serde", "req": "^1.0", "features": [], "optional": false, "default_features": true, "target": null, "kind": "normal"}],
            "features": {"default": ["serde"]},
            "description": "A test crate",
            "license": "MIT",
            "keywords": ["test", "example"],
            "categories": ["development-tools"],
            "links": null,
            "rust_version": "1.70.0"
        })
    }

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

    #[test]
    fn test_cargo_sparse_index_path_hyphenated() {
        assert_eq!(cargo_sparse_index_path("my-crate"), "index/my/-c/my-crate");
    }

    #[test]
    fn test_cargo_sparse_index_path_underscore() {
        assert_eq!(
            cargo_sparse_index_path("tokio_util"),
            "index/to/ki/tokio_util"
        );
    }

    // -----------------------------------------------------------------------
    // cargo_sparse_index_path_upstream
    // -----------------------------------------------------------------------

    #[test]
    fn test_cargo_sparse_index_path_upstream_1char() {
        assert_eq!(cargo_sparse_index_path_upstream("a"), "1/a");
    }

    #[test]
    fn test_cargo_sparse_index_path_upstream_2char() {
        assert_eq!(cargo_sparse_index_path_upstream("ab"), "2/ab");
    }

    #[test]
    fn test_cargo_sparse_index_path_upstream_3char() {
        assert_eq!(cargo_sparse_index_path_upstream("abc"), "3/a/abc");
    }

    #[test]
    fn test_cargo_sparse_index_path_upstream_serde() {
        assert_eq!(cargo_sparse_index_path_upstream("serde"), "se/rd/serde");
    }

    // -----------------------------------------------------------------------
    // Root-level sparse index route path construction
    // -----------------------------------------------------------------------

    /// Verify that the root-level route path for a 4+ char crate matches what
    /// a standard Cargo client would request: `/{repo}/se/rd/serde` (no index/ prefix).
    #[test]
    fn test_sparse_index_root_route_4plus() {
        let path = cargo_sparse_index_path_upstream("serde");
        let parts: Vec<&str> = path.splitn(3, '/').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "se");
        assert_eq!(parts[1], "rd");
        assert_eq!(parts[2], "serde");
    }

    // -----------------------------------------------------------------------
    // parse_publish_payload
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_publish_payload_too_short() {
        let body = Bytes::from_static(&[0, 0, 0]);
        assert!(parse_publish_payload(&body).is_err());
    }

    #[test]
    fn test_parse_publish_payload_exactly_4_bytes_no_json() {
        let body = Bytes::from_static(&[10, 0, 0, 0]);
        assert!(parse_publish_payload(&body).is_err());
    }

    #[test]
    fn test_parse_publish_payload_json_but_no_crate_length() {
        let metadata = serde_json::json!({"name": "x", "vers": "1.0.0"});
        let json_bytes = serde_json::to_vec(&metadata).unwrap();
        let json_len = json_bytes.len() as u32;

        let mut payload = Vec::new();
        payload.extend_from_slice(&json_len.to_le_bytes());
        payload.extend_from_slice(&json_bytes);
        // Missing 4-byte crate length
        let body = Bytes::from(payload);
        assert!(parse_publish_payload(&body).is_err());
    }

    #[test]
    fn test_parse_publish_payload_invalid_json() {
        let bad_json = b"not json{{{";
        let json_len = bad_json.len() as u32;
        let crate_data = b"data";
        let crate_len = crate_data.len() as u32;

        let mut payload = Vec::new();
        payload.extend_from_slice(&json_len.to_le_bytes());
        payload.extend_from_slice(bad_json);
        payload.extend_from_slice(&crate_len.to_le_bytes());
        payload.extend_from_slice(crate_data);
        let body = Bytes::from(payload);
        assert!(parse_publish_payload(&body).is_err());
    }

    #[test]
    fn test_parse_publish_payload_missing_name() {
        let metadata = serde_json::json!({"vers": "1.0.0"});
        let body = make_publish_payload(&metadata, b"crate-bytes");
        assert!(parse_publish_payload(&body).is_err());
    }

    #[test]
    fn test_parse_publish_payload_missing_vers() {
        let metadata = serde_json::json!({"name": "my-crate"});
        let body = make_publish_payload(&metadata, b"crate-bytes");
        assert!(parse_publish_payload(&body).is_err());
    }

    #[test]
    fn test_parse_publish_payload_crate_data_truncated() {
        let metadata = serde_json::json!({"name": "my-crate", "vers": "1.0.0"});
        let json_bytes = serde_json::to_vec(&metadata).unwrap();
        let json_len = json_bytes.len() as u32;
        let declared_crate_len: u32 = 100;

        let mut payload = Vec::new();
        payload.extend_from_slice(&json_len.to_le_bytes());
        payload.extend_from_slice(&json_bytes);
        payload.extend_from_slice(&declared_crate_len.to_le_bytes());
        payload.extend_from_slice(b"short"); // only 5 bytes, declared 100
        let body = Bytes::from(payload);
        assert!(parse_publish_payload(&body).is_err());
    }

    #[test]
    fn test_parse_publish_payload_valid_minimal() {
        let metadata = serde_json::json!({"name": "my-crate", "vers": "1.0.0"});
        let crate_data = b"fake-tarball-data";
        let body = make_publish_payload(&metadata, crate_data);

        let parsed = parse_publish_payload(&body).unwrap();
        assert_eq!(parsed.crate_name, "my-crate");
        assert_eq!(parsed.crate_version, "1.0.0");
        assert_eq!(parsed.crate_bytes.as_ref(), crate_data);
        assert_eq!(parsed.metadata["name"], "my-crate");
        assert_eq!(parsed.metadata["vers"], "1.0.0");
    }

    #[test]
    fn test_parse_publish_payload_valid_full_metadata() {
        let metadata = sample_metadata();
        let crate_data = b"compressed-tarball-bytes-here";
        let body = make_publish_payload(&metadata, crate_data);

        let parsed = parse_publish_payload(&body).unwrap();
        assert_eq!(parsed.crate_name, "my-crate");
        assert_eq!(parsed.crate_version, "0.1.0");
        assert_eq!(parsed.crate_bytes.len(), crate_data.len());
        assert_eq!(parsed.metadata["description"], "A test crate");
        assert_eq!(parsed.metadata["license"], "MIT");
    }

    #[test]
    fn test_parse_publish_payload_empty_crate_data() {
        let metadata = serde_json::json!({"name": "empty", "vers": "0.0.1"});
        let body = make_publish_payload(&metadata, b"");

        let parsed = parse_publish_payload(&body).unwrap();
        assert_eq!(parsed.crate_name, "empty");
        assert_eq!(parsed.crate_version, "0.0.1");
        assert!(parsed.crate_bytes.is_empty());
    }

    #[test]
    fn test_parse_publish_payload_preserves_all_metadata_fields() {
        let metadata = serde_json::json!({
            "name": "full-crate",
            "vers": "2.0.0",
            "deps": [{"name": "tokio", "req": "^1"}],
            "features": {"async": ["tokio"]},
            "description": "Full featured crate",
            "license": "Apache-2.0",
            "keywords": ["async", "runtime"],
            "categories": ["asynchronous"],
            "links": "native-lib",
            "rust_version": "1.75.0"
        });
        let body = make_publish_payload(&metadata, b"data");

        let parsed = parse_publish_payload(&body).unwrap();
        assert_eq!(parsed.metadata["deps"][0]["name"], "tokio");
        assert_eq!(parsed.metadata["features"]["async"][0], "tokio");
        assert_eq!(parsed.metadata["keywords"][0], "async");
        assert_eq!(parsed.metadata["links"], "native-lib");
        assert_eq!(parsed.metadata["rust_version"], "1.75.0");
    }

    // -----------------------------------------------------------------------
    // build_cargo_metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_cargo_metadata_minimal() {
        let input = serde_json::json!({"name": "my-crate", "vers": "1.0.0"});
        let result = build_cargo_metadata(&input, "my-crate", "1.0.0", "abc123");

        assert_eq!(result["name"], "my-crate");
        assert_eq!(result["vers"], "1.0.0");
        assert_eq!(result["cksum"], "abc123");
        assert_eq!(result["deps"], serde_json::json!([]));
        assert_eq!(result["features"], serde_json::json!({}));
        assert_eq!(result["description"], "");
        assert_eq!(result["license"], "");
        assert_eq!(result["keywords"], serde_json::json!([]));
        assert_eq!(result["categories"], serde_json::json!([]));
    }

    #[test]
    fn test_build_cargo_metadata_full() {
        let input = sample_metadata();
        let result = build_cargo_metadata(&input, "my-crate", "0.1.0", "deadbeef");

        assert_eq!(result["name"], "my-crate");
        assert_eq!(result["vers"], "0.1.0");
        assert_eq!(result["cksum"], "deadbeef");
        assert_eq!(result["description"], "A test crate");
        assert_eq!(result["license"], "MIT");
        assert_eq!(result["rust_version"], "1.70.0");
        assert_eq!(result["keywords"], serde_json::json!(["test", "example"]));
        assert_eq!(
            result["categories"],
            serde_json::json!(["development-tools"])
        );
        assert!(result["links"].is_null());

        let deps = result["deps"].as_array().unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0]["name"], "serde");
    }

    #[test]
    fn test_build_cargo_metadata_uses_name_lower_not_original() {
        let input = serde_json::json!({"name": "My-Crate", "vers": "1.0.0"});
        let result = build_cargo_metadata(&input, "my-crate", "1.0.0", "checksum");
        assert_eq!(result["name"], "my-crate");
    }

    #[test]
    fn test_build_cargo_metadata_with_links() {
        let input = serde_json::json!({
            "name": "openssl-sys",
            "vers": "0.9.0",
            "links": "openssl"
        });
        let result = build_cargo_metadata(&input, "openssl-sys", "0.9.0", "sum");
        assert_eq!(result["links"], "openssl");
    }

    #[test]
    fn test_build_cargo_metadata_deps_preserved() {
        let deps = serde_json::json!([
            {"name": "serde", "req": "^1.0", "features": ["derive"], "optional": false, "default_features": true, "target": null, "kind": "normal"},
            {"name": "tokio", "req": "^1", "features": ["full"], "optional": false, "default_features": true, "target": null, "kind": "normal"}
        ]);
        let input = serde_json::json!({"name": "x", "vers": "1.0.0", "deps": deps});
        let result = build_cargo_metadata(&input, "x", "1.0.0", "sum");
        assert_eq!(result["deps"].as_array().unwrap().len(), 2);
        assert_eq!(result["deps"][1]["name"], "tokio");
    }

    #[test]
    fn test_build_cargo_metadata_features_preserved() {
        let input = serde_json::json!({
            "name": "x",
            "vers": "1.0.0",
            "features": {
                "default": ["std"],
                "std": [],
                "serde": ["dep:serde"]
            }
        });
        let result = build_cargo_metadata(&input, "x", "1.0.0", "sum");
        let features = result["features"].as_object().unwrap();
        assert_eq!(features.len(), 3);
        assert_eq!(features["default"], serde_json::json!(["std"]));
        assert_eq!(features["serde"], serde_json::json!(["dep:serde"]));
    }

    // -----------------------------------------------------------------------
    // extract_index_fields
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_index_fields_none() {
        let (deps, features, links, rust_version) = extract_index_fields(None);
        assert_eq!(deps, serde_json::json!([]));
        assert_eq!(features, serde_json::json!({}));
        assert!(links.is_null());
        assert!(rust_version.is_null());
    }

    #[test]
    fn test_extract_index_fields_empty_object() {
        let meta = serde_json::json!({});
        let (deps, features, links, rust_version) = extract_index_fields(Some(&meta));
        assert_eq!(deps, serde_json::json!([]));
        assert_eq!(features, serde_json::json!({}));
        assert!(links.is_null());
        assert!(rust_version.is_null());
    }

    #[test]
    fn test_extract_index_fields_with_all_fields() {
        let meta = serde_json::json!({
            "deps": [{"name": "serde", "req": "^1"}],
            "features": {"default": ["std"]},
            "links": "native-lib",
            "rust_version": "1.70.0"
        });
        let (deps, features, links, rust_version) = extract_index_fields(Some(&meta));
        assert_eq!(deps, serde_json::json!([{"name": "serde", "req": "^1"}]));
        assert_eq!(features, serde_json::json!({"default": ["std"]}));
        assert_eq!(links, "native-lib");
        assert_eq!(rust_version, "1.70.0");
    }

    #[test]
    fn test_extract_index_fields_partial() {
        let meta = serde_json::json!({
            "deps": [{"name": "log"}],
            "rust_version": "1.56.0"
        });
        let (deps, features, links, rust_version) = extract_index_fields(Some(&meta));
        assert_eq!(deps.as_array().unwrap().len(), 1);
        assert_eq!(features, serde_json::json!({}));
        assert!(links.is_null());
        assert_eq!(rust_version, "1.56.0");
    }

    // -----------------------------------------------------------------------
    // build_index_entry
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_index_entry_no_metadata() {
        let entry_str = build_index_entry("my-crate", "1.0.0", "abcdef1234", None);
        let entry: serde_json::Value = serde_json::from_str(&entry_str).unwrap();

        assert_eq!(entry["name"], "my-crate");
        assert_eq!(entry["vers"], "1.0.0");
        assert_eq!(entry["cksum"], "abcdef1234");
        assert_eq!(entry["deps"], serde_json::json!([]));
        assert_eq!(entry["features"], serde_json::json!({}));
        assert_eq!(entry["yanked"], false);
        assert!(entry.get("links").is_none());
        assert!(entry.get("rust-version").is_none());
    }

    #[test]
    fn test_build_index_entry_with_metadata() {
        let meta = serde_json::json!({
            "deps": [{"name": "serde", "req": "^1.0", "features": [], "optional": false, "default_features": true, "target": null, "kind": "normal"}],
            "features": {"derive": ["serde/derive"]},
            "links": "openssl",
            "rust_version": "1.75.0"
        });
        let entry_str = build_index_entry("openssl-sys", "0.9.102", "deadbeef", Some(&meta));
        let entry: serde_json::Value = serde_json::from_str(&entry_str).unwrap();

        assert_eq!(entry["name"], "openssl-sys");
        assert_eq!(entry["vers"], "0.9.102");
        assert_eq!(entry["cksum"], "deadbeef");
        assert_eq!(entry["yanked"], false);
        assert_eq!(entry["deps"][0]["name"], "serde");
        assert_eq!(entry["features"]["derive"][0], "serde/derive");
        assert_eq!(entry["links"], "openssl");
        assert_eq!(entry["rust-version"], "1.75.0");
    }

    #[test]
    fn test_build_index_entry_without_links_or_rust_version() {
        let meta = serde_json::json!({
            "deps": [],
            "features": {}
        });
        let entry_str = build_index_entry("simple", "0.1.0", "aaa", Some(&meta));
        let entry: serde_json::Value = serde_json::from_str(&entry_str).unwrap();

        assert!(entry.get("links").is_none());
        assert!(entry.get("rust-version").is_none());
    }

    #[test]
    fn test_build_index_entry_is_valid_json() {
        let entry_str = build_index_entry("test", "0.0.1", "checksum", None);
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&entry_str);
        assert!(parsed.is_ok());
    }

    #[test]
    fn test_build_index_entry_yanked_is_always_false() {
        let meta = serde_json::json!({"deps": [], "features": {}});
        let entry_str = build_index_entry("crate", "1.0.0", "cksum", Some(&meta));
        let entry: serde_json::Value = serde_json::from_str(&entry_str).unwrap();
        assert_eq!(entry["yanked"], false);
    }

    // -----------------------------------------------------------------------
    // index_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_index_response_default_content_type() {
        let resp = index_response("test body", None);
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(resp.headers().get("cache-control").unwrap(), "max-age=60");
    }

    #[test]
    fn test_index_response_custom_content_type() {
        let resp = index_response("body", Some("text/plain".to_string()));
        assert_eq!(resp.headers().get(CONTENT_TYPE).unwrap(), "text/plain");
    }

    #[test]
    fn test_index_response_status_is_ok() {
        let resp = index_response("", None);
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn test_index_response_cache_control() {
        let resp = index_response("data", None);
        let cache = resp
            .headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cache, "max-age=60");
    }

    // -----------------------------------------------------------------------
    // SHA256 computation (same logic used in publish)
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256_computation_deterministic() {
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

    #[test]
    fn test_sha256_empty_input() {
        let mut hasher = Sha256::new();
        hasher.update(b"");
        let checksum = format!("{:x}", hasher.finalize());
        assert_eq!(checksum.len(), 64);
        assert_eq!(
            checksum,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_known_value() {
        let mut hasher = Sha256::new();
        hasher.update(b"hello");
        let checksum = format!("{:x}", hasher.finalize());
        assert_eq!(
            checksum,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    // -----------------------------------------------------------------------
    // Storage path and key construction (patterns from store_crate_artifact)
    // -----------------------------------------------------------------------

    fn build_crate_filename(name: &str, version: &str) -> String {
        format!("{}-{}.crate", name, version)
    }

    fn build_crate_storage_key(name: &str, version: &str, filename: &str) -> String {
        format!("cargo/{}/{}/{}", name, version, filename)
    }

    fn build_crate_artifact_path(name: &str, version: &str, filename: &str) -> String {
        format!("{}/{}/{}", name, version, filename)
    }

    #[test]
    fn test_crate_filename() {
        assert_eq!(build_crate_filename("serde", "1.0.0"), "serde-1.0.0.crate");
        assert_eq!(
            build_crate_filename("my-crate", "0.1.0"),
            "my-crate-0.1.0.crate"
        );
        assert_eq!(
            build_crate_filename("tokio", "1.35.1"),
            "tokio-1.35.1.crate"
        );
    }

    #[test]
    fn test_crate_storage_key() {
        let filename = build_crate_filename("serde", "1.0.0");
        let key = build_crate_storage_key("serde", "1.0.0", &filename);
        assert_eq!(key, "cargo/serde/1.0.0/serde-1.0.0.crate");
    }

    #[test]
    fn test_crate_artifact_path() {
        let filename = build_crate_filename("tokio", "1.35.1");
        let path = build_crate_artifact_path("tokio", "1.35.1", &filename);
        assert_eq!(path, "tokio/1.35.1/tokio-1.35.1.crate");
    }

    #[test]
    fn test_crate_storage_key_hyphenated_name() {
        let filename = build_crate_filename("my-cool-crate", "2.0.0-rc.1");
        let key = build_crate_storage_key("my-cool-crate", "2.0.0-rc.1", &filename);
        assert_eq!(
            key,
            "cargo/my-cool-crate/2.0.0-rc.1/my-cool-crate-2.0.0-rc.1.crate"
        );
    }

    // -----------------------------------------------------------------------
    // RepoInfo struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_info_hosted() {
        let info = RepoInfo {
            id: uuid::Uuid::new_v4(),
            storage_path: "/data/cargo".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: None,
            index_upstream_url: None,
        };
        assert_eq!(info.repo_type, "hosted");
        assert!(info.upstream_url.is_none());
    }

    #[test]
    fn test_repo_info_remote() {
        let info = RepoInfo {
            id: uuid::Uuid::new_v4(),
            storage_path: "/data/cargo-remote".to_string(),
            repo_type: "remote".to_string(),
            upstream_url: Some("https://crates.io".to_string()),
            index_upstream_url: None,
        };
        assert_eq!(info.repo_type, "remote");
        assert_eq!(info.upstream_url.as_deref(), Some("https://crates.io"));
    }

    #[test]
    fn test_repo_info_remote_with_index_upstream_url() {
        let info = RepoInfo {
            id: uuid::Uuid::new_v4(),
            storage_path: "/data/cargo-remote".to_string(),
            repo_type: "remote".to_string(),
            upstream_url: Some("https://crates.io".to_string()),
            index_upstream_url: Some("https://index.crates.io".to_string()),
        };
        assert_eq!(info.upstream_url.as_deref(), Some("https://crates.io"));
        assert_eq!(
            info.index_upstream_url.as_deref(),
            Some("https://index.crates.io")
        );
    }

    #[test]
    fn test_repo_info_virtual() {
        let info = RepoInfo {
            id: uuid::Uuid::new_v4(),
            storage_path: "/data/cargo-virtual".to_string(),
            repo_type: "virtual".to_string(),
            upstream_url: None,
            index_upstream_url: None,
        };
        assert_eq!(info.repo_type, "virtual");
    }

    // -----------------------------------------------------------------------
    // Config JSON URL construction
    // -----------------------------------------------------------------------

    fn build_config_json(base_url: &str, repo_key: &str) -> serde_json::Value {
        serde_json::json!({
            "dl": format!("{}/cargo/{}/api/v1/crates", base_url, repo_key),
            "api": format!("{}/cargo/{}", base_url, repo_key),
        })
    }

    #[test]
    fn test_config_json_url_construction() {
        let config = build_config_json("http://localhost:8080", "cargo-hosted");
        assert_eq!(
            config["dl"],
            "http://localhost:8080/cargo/cargo-hosted/api/v1/crates"
        );
        assert_eq!(config["api"], "http://localhost:8080/cargo/cargo-hosted");
    }

    #[test]
    fn test_config_json_url_https() {
        let config = build_config_json("https://registry.example.com", "main");
        assert_eq!(
            config["dl"],
            "https://registry.example.com/cargo/main/api/v1/crates"
        );
        assert_eq!(config["api"], "https://registry.example.com/cargo/main");
    }

    #[test]
    fn test_config_json_base_url_construction() {
        let scheme = "https";
        let host = "my.registry.com";
        let base_url = format!("{}://{}", scheme, host);
        assert_eq!(base_url, "https://my.registry.com");
    }

    #[test]
    fn test_config_json_base_url_with_port() {
        let scheme = "http";
        let host = "localhost:8080";
        let base_url = format!("{}://{}", scheme, host);
        assert_eq!(base_url, "http://localhost:8080");
    }

    // -----------------------------------------------------------------------
    // Publish response format
    // -----------------------------------------------------------------------

    #[test]
    fn test_publish_response_format() {
        let response = serde_json::json!({
            "warnings": {
                "invalid_categories": [],
                "invalid_badges": [],
                "other": []
            }
        });
        assert!(response["warnings"]["invalid_categories"].is_array());
        assert!(response["warnings"]["invalid_badges"].is_array());
        assert!(response["warnings"]["other"].is_array());
        assert_eq!(
            response["warnings"]["invalid_categories"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
    }

    // -----------------------------------------------------------------------
    // Download content-disposition header format
    // -----------------------------------------------------------------------

    #[test]
    fn test_download_content_disposition() {
        let name_lower = "serde_json";
        let version = "1.0.120";
        let filename = format!("{}-{}.crate", name_lower, version);
        let header = format!("attachment; filename=\"{}\"", filename);
        assert_eq!(header, "attachment; filename=\"serde_json-1.0.120.crate\"");
    }

    #[test]
    fn test_download_content_disposition_hyphenated() {
        let filename = format!("{}-{}.crate", "my-cool-crate", "0.1.0-alpha.1");
        let header = format!("attachment; filename=\"{}\"", filename);
        assert_eq!(
            header,
            "attachment; filename=\"my-cool-crate-0.1.0-alpha.1.crate\""
        );
    }

    // -----------------------------------------------------------------------
    // Search response construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_response_structure() {
        let crate_list: Vec<serde_json::Value> = vec![
            serde_json::json!({"name": "serde", "max_version": "1.0.0", "description": "Serialization"}),
            serde_json::json!({"name": "serde_json", "max_version": "1.0.120", "description": "JSON"}),
        ];
        let response = serde_json::json!({
            "crates": crate_list,
            "meta": {
                "total": crate_list.len(),
            }
        });
        assert_eq!(response["crates"].as_array().unwrap().len(), 2);
        assert_eq!(response["meta"]["total"], 2);
        assert_eq!(response["crates"][0]["name"], "serde");
    }

    #[test]
    fn test_search_response_empty() {
        let crate_list: Vec<serde_json::Value> = vec![];
        let response = serde_json::json!({
            "crates": crate_list,
            "meta": {
                "total": crate_list.len(),
            }
        });
        assert_eq!(response["crates"].as_array().unwrap().len(), 0);
        assert_eq!(response["meta"]["total"], 0);
    }

    #[test]
    fn test_search_description_extraction_from_metadata() {
        let metadata_text = r#"{"description": "A fast JSON library", "license": "MIT"}"#;
        let description = serde_json::from_str::<serde_json::Value>(metadata_text)
            .ok()
            .and_then(|m| {
                m.get("description")
                    .and_then(|v| v.as_str())
                    .map(String::from)
            })
            .unwrap_or_default();
        assert_eq!(description, "A fast JSON library");
    }

    #[test]
    fn test_search_description_extraction_missing() {
        let metadata_text = r#"{"license": "MIT"}"#;
        let description = serde_json::from_str::<serde_json::Value>(metadata_text)
            .ok()
            .and_then(|m| {
                m.get("description")
                    .and_then(|v| v.as_str())
                    .map(String::from)
            })
            .unwrap_or_default();
        assert_eq!(description, "");
    }

    #[test]
    fn test_search_description_extraction_invalid_json() {
        let metadata_text = "not json at all";
        let description = serde_json::from_str::<serde_json::Value>(metadata_text)
            .ok()
            .and_then(|m| {
                m.get("description")
                    .and_then(|v| v.as_str())
                    .map(String::from)
            })
            .unwrap_or_default();
        assert_eq!(description, "");
    }

    // -----------------------------------------------------------------------
    // per_page clamping (same logic as search_crates)
    // -----------------------------------------------------------------------

    #[test]
    fn test_per_page_default() {
        let params: HashMap<String, String> = HashMap::new();
        let per_page: i64 = params
            .get("per_page")
            .and_then(|v| v.parse().ok())
            .unwrap_or(10)
            .min(100);
        assert_eq!(per_page, 10);
    }

    #[test]
    fn test_per_page_custom_value() {
        let mut params = HashMap::new();
        params.insert("per_page".to_string(), "50".to_string());
        let per_page: i64 = params
            .get("per_page")
            .and_then(|v| v.parse().ok())
            .unwrap_or(10)
            .min(100);
        assert_eq!(per_page, 50);
    }

    #[test]
    fn test_per_page_clamped_to_100() {
        let mut params = HashMap::new();
        params.insert("per_page".to_string(), "500".to_string());
        let per_page: i64 = params
            .get("per_page")
            .and_then(|v| v.parse().ok())
            .unwrap_or(10)
            .min(100);
        assert_eq!(per_page, 100);
    }

    #[test]
    fn test_per_page_invalid_string() {
        let mut params = HashMap::new();
        params.insert("per_page".to_string(), "not_a_number".to_string());
        let per_page: i64 = params
            .get("per_page")
            .and_then(|v| v.parse().ok())
            .unwrap_or(10)
            .min(100);
        assert_eq!(per_page, 10);
    }

    // -----------------------------------------------------------------------
    // Sparse index multiline output (one JSON per line)
    // -----------------------------------------------------------------------

    #[test]
    fn test_index_multiline_output() {
        let lines: Vec<String> = vec![
            build_index_entry("mycrate", "0.1.0", "aaa", None),
            build_index_entry("mycrate", "0.2.0", "bbb", None),
            build_index_entry("mycrate", "1.0.0", "ccc", None),
        ];
        let body = lines.join("\n");

        let parsed_lines: Vec<&str> = body.split('\n').collect();
        assert_eq!(parsed_lines.len(), 3);

        for line in &parsed_lines {
            let entry: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(entry["name"], "mycrate");
            assert_eq!(entry["yanked"], false);
        }

        let first: serde_json::Value = serde_json::from_str(parsed_lines[0]).unwrap();
        assert_eq!(first["vers"], "0.1.0");
        assert_eq!(first["cksum"], "aaa");

        let last: serde_json::Value = serde_json::from_str(parsed_lines[2]).unwrap();
        assert_eq!(last["vers"], "1.0.0");
        assert_eq!(last["cksum"], "ccc");
    }

    #[test]
    fn test_index_single_version() {
        let lines: Vec<String> = vec![build_index_entry("single", "1.0.0", "checksum", None)];
        let body = lines.join("\n");
        assert!(!body.contains('\n'));

        let entry: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(entry["name"], "single");
    }

    // -----------------------------------------------------------------------
    // Name lowercasing (used throughout handlers)
    // -----------------------------------------------------------------------

    #[test]
    fn test_crate_name_lowercasing() {
        assert_eq!("My-Crate".to_lowercase(), "my-crate");
        assert_eq!("SERDE".to_lowercase(), "serde");
        assert_eq!("already-lower".to_lowercase(), "already-lower");
        assert_eq!("Tokio_Util".to_lowercase(), "tokio_util");
    }

    // -----------------------------------------------------------------------
    // Conflict error JSON format
    // -----------------------------------------------------------------------

    #[test]
    fn test_conflict_error_json_format() {
        let name = "my-crate";
        let version = "1.0.0";
        let error_json = serde_json::json!({"errors": [{"detail": format!(
            "crate version `{}@{}` already exists",
            name, version
        )}]});
        assert_eq!(
            error_json["errors"][0]["detail"],
            "crate version `my-crate@1.0.0` already exists"
        );
    }

    // -----------------------------------------------------------------------
    // Auth error JSON format
    // -----------------------------------------------------------------------

    #[test]
    fn test_auth_required_error_json() {
        let error = serde_json::json!({"errors": [{"detail": "Authentication required"}]});
        assert_eq!(error["errors"][0]["detail"], "Authentication required");
    }

    #[test]
    fn test_invalid_credentials_error_json() {
        let error = serde_json::json!({"errors": [{"detail": "Invalid credentials"}]});
        assert_eq!(error["errors"][0]["detail"], "Invalid credentials");
    }
}
