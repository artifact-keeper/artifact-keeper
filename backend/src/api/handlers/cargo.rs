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
use std::time::Instant;

use axum::body::Body;
use axum::extract::{Path, State};
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

use crate::api::handlers::error_helpers::{map_db_err, map_storage_err};
use crate::api::handlers::proxy_helpers;
use crate::api::middleware::auth::{require_auth_with_bearer_fallback, AuthExtension};
use crate::api::validation::validate_outbound_url;
use crate::api::SharedState;
use crate::api::{CachedRepo, IndexCache, RepoCache, REPO_CACHE_TTL_SECS};
use crate::error::AppError;
use crate::models::repository::RepositoryType;

// ---------------------------------------------------------------------------
// In-process caches
// ---------------------------------------------------------------------------

const INDEX_CACHE_TTL_SECS: u64 = 300;

/// TTL for cached upstream `config.json` data (the `dl` download URL).
/// Upstream registries change their config.json very rarely, so 1 hour
/// is a reasonable balance between freshness and upstream request volume.
const CONFIG_CACHE_TTL_SECS: u64 = 3600;

/// Thread-safe cache for upstream registry `config.json` download URL (`dl` field).
/// Key: upstream base URL. Value: resolved `dl` URL + insertion time.
type ConfigCache = std::sync::Arc<std::sync::RwLock<HashMap<String, (String, Instant)>>>;

/// Module-level cache for upstream `config.json` download URLs.
static UPSTREAM_CONFIG_CACHE: once_cell::sync::Lazy<ConfigCache> =
    once_cell::sync::Lazy::new(|| std::sync::Arc::new(std::sync::RwLock::new(HashMap::new())));

fn index_cache_get(cache: &IndexCache, key: &str) -> Option<Bytes> {
    let c = cache.read().ok()?;
    let (bytes, at) = c.get(key)?;
    if at.elapsed().as_secs() < INDEX_CACHE_TTL_SECS {
        Some(bytes.clone())
    } else {
        None
    }
}

fn index_cache_set(cache: &IndexCache, key: String, bytes: Bytes) {
    if let Ok(mut c) = cache.write() {
        c.retain(|_, (_, at)| at.elapsed().as_secs() < INDEX_CACHE_TTL_SECS);
        c.insert(key, (bytes, Instant::now()));
    }
}

fn index_cache_invalidate(cache: &IndexCache, key: &str) {
    if let Ok(mut c) = cache.write() {
        c.remove(key);
    }
}

// ---------------------------------------------------------------------------
// Upstream config.json resolution
// ---------------------------------------------------------------------------

/// Look up the cached `dl` URL for an upstream registry base URL.
fn config_cache_get(base_url: &str) -> Option<String> {
    let c = UPSTREAM_CONFIG_CACHE.read().ok()?;
    let (dl_url, at) = c.get(base_url)?;
    if at.elapsed().as_secs() < CONFIG_CACHE_TTL_SECS {
        Some(dl_url.clone())
    } else {
        None
    }
}

/// Store a resolved `dl` URL for an upstream base URL.
fn config_cache_set(base_url: String, dl_url: String) {
    if let Ok(mut c) = UPSTREAM_CONFIG_CACHE.write() {
        c.retain(|_, (_, at)| at.elapsed().as_secs() < CONFIG_CACHE_TTL_SECS);
        c.insert(base_url, (dl_url, Instant::now()));
    }
}

/// Fetch the upstream registry's `config.json` and extract the `dl` field.
///
/// Cargo registries serve a `config.json` at their root that contains a `dl`
/// field indicating the download URL template. For registries like crates.io,
/// the index (`https://index.crates.io`) and the download host
/// (`https://crates.io`) are on different domains, so the `dl` field is the
/// authoritative source for where to fetch .crate files.
///
/// Returns `Some(dl_url)` on success, `None` if the config could not be fetched
/// or parsed. Results are cached for `CONFIG_CACHE_TTL_SECS`.
async fn resolve_upstream_dl_url(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
) -> Option<String> {
    // Determine which base URL to fetch config.json from. Prefer the index URL
    // because that is where Cargo registries serve their config.json.
    let base_url = repo
        .index_upstream_url
        .as_deref()
        .or(repo.upstream_url.as_deref())?;

    // Check the cache first.
    if let Some(cached) = config_cache_get(base_url) {
        return Some(cached);
    }

    // Fetch config.json from upstream.
    let proxy = state.proxy_service.as_ref()?;
    let config_bytes =
        proxy_helpers::proxy_fetch(proxy, repo.id, repo_key, base_url, "config.json")
            .await
            .ok()?;

    let config: serde_json::Value = serde_json::from_slice(&config_bytes.0).ok()?;
    let dl_url = config.get("dl")?.as_str()?.to_string();

    // Cache the resolved dl URL.
    config_cache_set(base_url.to_string(), dl_url.clone());

    Some(dl_url)
}

/// Build the full download URL for a crate, using the upstream `dl` template
/// when available. Falls back to `{upstream_url}/api/v1/crates/{name}/{version}/download`.
///
/// The `dl` field from `config.json` can be either a plain base URL
/// (e.g. `https://crates.io/api/v1/crates`) to which `/{name}/{version}/download`
/// is appended, or a template with `{crate}` / `{version}` markers. This
/// function handles both forms.
fn build_download_url(dl_url: &str, name: &str, version: &str) -> String {
    if dl_url.contains("{crate}") || dl_url.contains("{version}") {
        dl_url
            .replace("{crate}", name)
            .replace("{version}", version)
    } else {
        let base = dl_url.trim_end_matches('/');
        format!("{}/{}/{}/download", base, name, version)
    }
}

/// Split a fully-qualified URL into `(origin, path)`.
///
/// Given `https://crates.io/api/v1/crates/serde/1.0.0/download`, returns
/// `("https://crates.io", "api/v1/crates/serde/1.0.0/download")`.
///
/// Returns `None` when the URL has no scheme or no path component after the host.
fn split_url(url: &str) -> Option<(String, String)> {
    let scheme_end = url.find("://")?;
    let after_scheme = &url[scheme_end + 3..];
    let slash = after_scheme.find('/')?;
    let origin = &url[..scheme_end + 3 + slash];
    let path = &url[scheme_end + 3 + slash + 1..];
    Some((origin.to_string(), path.to_string()))
}

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
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

struct RepoInfo {
    id: uuid::Uuid,
    storage_path: String,
    storage_backend: String,
    repo_type: String,
    upstream_url: Option<String>,
    /// Separate index host for registries like crates.io that split index
    /// (`https://index.crates.io`) and download (`https://crates.io`) across
    /// two hosts. Loaded from the `repository_config` table on the key
    /// `index_upstream_url`. Falls back to `upstream_url` when absent.
    index_upstream_url: Option<String>,
}

impl RepoInfo {
    fn storage_location(&self) -> crate::storage::StorageLocation {
        crate::storage::StorageLocation {
            backend: self.storage_backend.clone(),
            path: self.storage_path.clone(),
        }
    }
}

async fn resolve_cargo_repo(
    db: &PgPool,
    repo_key: &str,
    repo_cache: &RepoCache,
) -> Result<RepoInfo, Response> {
    // Check the shared repo cache first.  The repo_visibility_middleware
    // populates this cache before handlers run, so on most requests this
    // returns immediately with 0 DB queries.
    if let Ok(cache) = repo_cache.read() {
        if let Some((entry, at)) = cache.get(repo_key) {
            if at.elapsed().as_secs() < REPO_CACHE_TTL_SECS {
                let fmt = entry.format.to_lowercase();
                if fmt != "cargo" {
                    return Err(AppError::Validation(format!(
                        "Repository '{}' is not a Cargo repository (format: {})",
                        repo_key, fmt
                    ))
                    .into_response());
                }
                return Ok(RepoInfo {
                    id: entry.id,
                    storage_path: entry.storage_path.clone(),
                    storage_backend: entry.storage_backend.clone(),
                    repo_type: entry.repo_type.clone(),
                    upstream_url: entry.upstream_url.clone(),
                    index_upstream_url: entry.index_upstream_url.clone(),
                });
            }
        }
    }

    // Cache miss (e.g. direct access bypassing the middleware): fall back to
    // a DB lookup and populate the cache for next time.  Uses sqlx::query()
    // (not the macro) so no offline-cache update is needed.
    use sqlx::Row;
    let repo = sqlx::query(
        "SELECT id, storage_backend, storage_path, format::text as format, repo_type::text as repo_type, \
         upstream_url, is_public, \
         (SELECT value FROM repository_config \
          WHERE repository_id = repositories.id \
          AND key = 'index_upstream_url') AS index_upstream_url \
         FROM repositories WHERE key = $1",
    )
    .bind(repo_key)
    .fetch_optional(db)
    .await
    .map_err(map_db_err)?
    .ok_or_else(|| AppError::NotFound("Repository not found".to_string()).into_response())?;

    let fmt: String = repo.get("format");
    let fmt = fmt.to_lowercase();
    if fmt != "cargo" {
        return Err(AppError::Validation(format!(
            "Repository '{}' is not a Cargo repository (format: {})",
            repo_key, fmt
        ))
        .into_response());
    }

    let id: uuid::Uuid = repo.get("id");
    let storage_backend: String = repo.get("storage_backend");
    let storage_path: String = repo.get("storage_path");
    let repo_type: String = repo.get("repo_type");
    let upstream_url: Option<String> = repo.get("upstream_url");
    let is_public: bool = repo.get("is_public");
    let index_upstream_url: Option<String> = repo.get("index_upstream_url");

    // Populate cache so subsequent requests from this handler path are fast.
    if let Ok(mut cache) = repo_cache.write() {
        cache.retain(|_, (_, at)| at.elapsed().as_secs() < REPO_CACHE_TTL_SECS);
        cache.insert(
            repo_key.to_string(),
            (
                CachedRepo {
                    id,
                    format: fmt.clone(),
                    repo_type: repo_type.clone(),
                    upstream_url: upstream_url.clone(),
                    storage_path: storage_path.clone(),
                    storage_backend: storage_backend.clone(),
                    is_public,
                    index_upstream_url: index_upstream_url.clone(),
                },
                Instant::now(),
            ),
        );
    }

    Ok(RepoInfo {
        id,
        storage_path,
        storage_backend,
        repo_type,
        upstream_url,
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
    let _repo = resolve_cargo_repo(&state.db, &repo_key, &state.repo_cache).await?;

    // Check repo visibility from the cache (populated by resolve_cargo_repo).
    let is_private = !state
        .repo_cache
        .read()
        .ok()
        .and_then(|c| c.get(&repo_key).map(|(r, _)| r.is_public))
        .unwrap_or(true);

    // Determine the base URL from reverse-proxy / Host headers.
    let base_url = proxy_helpers::request_base_url(&headers);

    let config = serde_json::json!({
        "dl": format!("{}/cargo/{}/api/v1/crates", base_url, repo_key),
        "api": format!("{}/cargo/{}", base_url, repo_key),
        // For private repos, tell cargo to send credentials on all requests
        // (index fetches included).  Without this flag cargo only sends auth
        // after a 401 challenge, but it does not retry 401s on index entries.
        // Public repos must NOT set this, otherwise anonymous users need a
        // credential provider configured even though the server allows access.
        "auth-required": is_private,
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
    let repo = resolve_cargo_repo(&state.db, &repo_key, &state.repo_cache).await?;

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
    .map_err(map_db_err)?;

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
        return Err(AppError::Validation("Payload too short".to_string()).into_response());
    }

    let json_len = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as usize;
    if body.len() < 4 + json_len + 4 {
        return Err(AppError::Validation(
            "Payload too short for metadata + crate length".to_string(),
        )
        .into_response());
    }

    let json_bytes = &body[4..4 + json_len];
    let metadata: serde_json::Value = serde_json::from_slice(json_bytes).map_err(|e| {
        AppError::Validation(format!("Invalid JSON metadata: {}", e)).into_response()
    })?;

    let crate_name = metadata["name"]
        .as_str()
        .ok_or_else(|| {
            AppError::Validation("Missing 'name' in metadata".to_string()).into_response()
        })?
        .to_string();

    let crate_version = metadata["vers"]
        .as_str()
        .ok_or_else(|| {
            AppError::Validation("Missing 'vers' in metadata".to_string()).into_response()
        })?
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
        return Err(
            AppError::Validation("Payload too short for .crate data".to_string()).into_response(),
        );
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
    .map_err(map_db_err)?;

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
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    storage
        .put(&storage_key, crate_bytes.clone())
        .await
        .map_err(map_storage_err)?;

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
    .map_err(map_db_err)?;

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
    let repo = resolve_cargo_repo(&state.db, &repo_key, &state.repo_cache).await?;
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

    // Invalidate the index cache for this crate so the next fetch sees the new version.
    index_cache_invalidate(&state.index_cache, &format!("{}:{}", repo_key, name_lower));

    // Also invalidate any virtual repos that include this hosted repo.
    let virtual_keys: Vec<String> = sqlx::query_scalar(
        "SELECT r.key FROM repositories r \
         INNER JOIN virtual_repo_members vrm ON r.id = vrm.virtual_repo_id \
         WHERE vrm.member_repo_id = $1",
    )
    .bind(repo.id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    for vkey in &virtual_keys {
        index_cache_invalidate(&state.index_cache, &format!("{}:{}", vkey, name_lower));
    }

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
    let repo = resolve_cargo_repo(&state.db, &repo_key, &state.repo_cache).await?;
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
    .map_err(map_db_err)?;

    // If crate not found locally, try proxy for remote repos
    let artifact = match artifact {
        Some(a) => a,
        None => {
            if repo.repo_type == RepositoryType::Remote {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    // Resolve the download base URL from the upstream config.json.
                    // This handles split-host registries like crates.io where
                    // the index lives at index.crates.io but downloads come
                    // from crates.io/api/v1/crates.
                    let fallback_path =
                        format!("api/v1/crates/{}/{}/download", name_lower, version);
                    let (dl_base, dl_path) = match resolve_upstream_dl_url(&state, &repo, &repo_key)
                        .await
                    {
                        Some(dl_url) => {
                            let full = build_download_url(&dl_url, &name_lower, &version);
                            // Validate the resolved download URL against SSRF.
                            // A malicious upstream config.json could set `dl` to
                            // a cloud metadata endpoint or internal service URL.
                            validate_outbound_url(&full, "Cargo upstream download URL")
                                .map_err(|e| e.into_response())?;
                            split_url(&full)
                                .unwrap_or_else(|| (upstream_url.clone(), fallback_path.clone()))
                        }
                        None => (upstream_url.clone(), fallback_path.clone()),
                    };

                    // Use the canonical local cache path regardless of which
                    // upstream URL was resolved so that subsequent requests hit
                    // the proxy cache even after a config.json TTL change.
                    let cache_path = format!("api/v1/crates/{}/{}/download", name_lower, version);
                    let (content, _content_type) = proxy_helpers::proxy_fetch_with_cache_key(
                        proxy,
                        repo.id,
                        &repo_key,
                        &dl_base,
                        &dl_path,
                        &cache_path,
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
                        .header("cache-control", "public, max-age=31536000, immutable")
                        .body(Body::from(content))
                        .unwrap());
                }
            }
            // Virtual repo: try each member in priority order
            if repo.repo_type == RepositoryType::Virtual {
                let db = state.db.clone();
                let vname = name_lower.clone();
                let vversion = version.clone();
                let upstream_path = format!("api/v1/crates/{}/{}/download", name_lower, version);
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
                    .header("cache-control", "public, max-age=31536000, immutable")
                    .body(Body::from(content))
                    .unwrap());
            }
            return Err(AppError::NotFound("Crate not found".to_string()).into_response());
        }
    };

    // Check quarantine status before serving
    crate::services::quarantine_service::check_artifact_download(&state.db, artifact.id)
        .await
        .map_err(|e| e.into_response())?;

    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    let content = storage
        .get(&artifact.storage_key)
        .await
        .map_err(map_storage_err)?;

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
        // .crate files are content-addressed and immutable: same name+version
        // always has the same bytes.  Cargo can cache them indefinitely.
        .header("cache-control", "public, max-age=31536000, immutable")
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

    // Cargo publish API sends "version_req" but the sparse index format
    // requires "req".  Rename on the fly so clients can parse the index.
    // See https://doc.rust-lang.org/cargo/reference/registry-index.html
    let deps = match meta.get("deps").cloned().unwrap_or(serde_json::json!([])) {
        serde_json::Value::Array(arr) => serde_json::Value::Array(
            arr.into_iter()
                .map(|mut dep| {
                    if let serde_json::Value::Object(ref mut map) = dep {
                        if let Some(vr) = map.remove("version_req") {
                            map.entry("req").or_insert(vr);
                        }
                    }
                    dep
                })
                .collect(),
        ),
        other => other,
    };

    (
        deps,
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
        .header("cache-control", "max-age=300")
        .body(content.into())
        .unwrap()
}

/// Try to resolve a crate index from a remote upstream proxy.
async fn try_remote_index(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
    name_lower: &str,
    index_cache: &IndexCache,
    cache_key: &str,
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
    let result = proxy_helpers::proxy_fetch(proxy, repo.id, repo_key, base_url, &index_path).await;

    Some(result.map(|(content, content_type)| {
        index_cache_set(index_cache, cache_key.to_string(), content.clone());
        index_response(content, content_type)
    }))
}

/// Try to resolve a crate index from a virtual repo's member repositories.
///
/// Iterates members in priority order: local index entries first, then upstream
/// proxy for remote members. Honours each member's `index_upstream_url` from
/// `repository_config` (falls back to `upstream_url` when absent).
///
/// NOTE: This does not use `resolve_virtual_metadata` because cargo index
/// resolution interleaves local DB queries with remote proxy fallback per
/// member, and uses `index_upstream_url` config overrides for the proxy URL.
/// The shared helper only handles remote members in isolation.
async fn try_virtual_index(
    state: &SharedState,
    repo: &RepoInfo,
    name_lower: &str,
    index_cache: &IndexCache,
    cache_key: &str,
) -> Option<Result<Response, Response>> {
    use sqlx::Row;

    if repo.repo_type != "virtual" {
        return None;
    }

    let members = match proxy_helpers::fetch_virtual_members(&state.db, repo.id).await {
        Ok(m) => m,
        Err(e) => return Some(Err(e)),
    };

    if members.is_empty() {
        return Some(Err(AppError::NotFound(
            "Virtual repository has no members".to_string(),
        )
        .into_response()));
    }

    // Batch-fetch index_upstream_url overrides for all members in one query.
    let member_ids: Vec<uuid::Uuid> = members.iter().map(|m| m.id).collect();
    let index_url_overrides: HashMap<uuid::Uuid, String> =
        sqlx::query_as::<_, (uuid::Uuid, String)>(
            "SELECT repository_id, value FROM repository_config \
             WHERE repository_id = ANY($1) AND key = 'index_upstream_url' AND value IS NOT NULL",
        )
        .bind(&member_ids)
        .fetch_all(&state.db)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("Failed to fetch index_upstream_url overrides: {}", e);
            Vec::new()
        })
        .into_iter()
        .collect();

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
        .unwrap_or_else(|e| {
            tracing::warn!("Failed to query artifacts for member {}: {}", member.id, e);
            Vec::new()
        });

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
            let body = bytes::Bytes::from(lines.join("\n"));
            index_cache_set(index_cache, cache_key.to_string(), body.clone());
            return Some(Ok(index_response(
                body,
                Some("application/json".to_string()),
            )));
        }

        // For remote members, try the upstream proxy.
        if member.repo_type == RepositoryType::Remote {
            if let (Some(proxy), Some(upstream_url)) = (&state.proxy_service, &member.upstream_url)
            {
                let base_url = index_url_overrides
                    .get(&member.id)
                    .cloned()
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
                    index_cache_set(index_cache, cache_key.to_string(), content.clone());
                    return Some(Ok(index_response(content, content_type)));
                }
            }
        }
    }

    Some(Err(AppError::NotFound(
        "Artifact not found in any member repository".to_string(),
    )
    .into_response()))
}

/// Serve the sparse index file for a crate (one JSON object per version, per line).
async fn serve_index(
    state: &SharedState,
    repo_key: &str,
    crate_name: &str,
) -> Result<Response, Response> {
    let repo = resolve_cargo_repo(&state.db, repo_key, &state.repo_cache).await?;
    let name_lower = crate_name.to_lowercase();

    let cache_key = format!("{}:{}", repo_key, name_lower);

    // Fast path: serve from in-process index cache (no storage I/O, no SHA-256).
    if let Some(cached) = index_cache_get(&state.index_cache, &cache_key) {
        return Ok(index_response(cached, Some("application/json".to_string())));
    }

    // Remote and virtual repos never have directly-published artifacts — publishes
    // are rejected by reject_write_if_not_hosted.  Skip the artifacts DB query and
    // go straight to the appropriate upstream/member lookup.
    if repo.repo_type == "remote" {
        return match try_remote_index(
            state,
            &repo,
            repo_key,
            &name_lower,
            &state.index_cache,
            &cache_key,
        )
        .await
        {
            Some(result) => result,
            None => Err(AppError::NotFound("Crate not found in index".to_string()).into_response()),
        };
    }
    if repo.repo_type == "virtual" {
        return match try_virtual_index(state, &repo, &name_lower, &state.index_cache, &cache_key)
            .await
        {
            Some(result) => result,
            None => Err(AppError::NotFound("Crate not found in index".to_string()).into_response()),
        };
    }

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
    .map_err(map_db_err)?;

    if versions.is_empty() {
        if let Some(result) = try_remote_index(
            state,
            &repo,
            repo_key,
            &name_lower,
            &state.index_cache,
            &cache_key,
        )
        .await
        {
            return result;
        }
        if let Some(result) =
            try_virtual_index(state, &repo, &name_lower, &state.index_cache, &cache_key).await
        {
            return result;
        }
        return Err(AppError::NotFound("Crate not found in index".to_string()).into_response());
    }

    // Build index file: one JSON object per line
    let lines: Vec<String> = versions
        .iter()
        .map(|v| {
            let vers = v.version.as_deref().unwrap_or("0.0.0");
            build_index_entry(&name_lower, vers, &v.checksum_sha256, v.metadata.as_ref())
        })
        .collect();

    let body = bytes::Bytes::from(lines.join("\n"));
    index_cache_set(&state.index_cache, cache_key, body.clone());
    Ok(index_response(body, Some("application/json".to_string())))
}

/// Build the sparse index path for a crate name following the Cargo registry layout.
/// Includes the `index/` prefix used by artifact-keeper's own routing.
#[cfg_attr(not(test), allow(dead_code))]
fn cargo_sparse_index_path(name: &str) -> String {
    format!("index/{}", cargo_sparse_index_path_upstream(name))
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

    #[test]
    fn test_build_index_entry_normalises_dep_version_req_field() {
        // Cargo publish sends "version_req" but the sparse index requires "req".
        // If metadata already uses "req" (e.g. proxied index), it passes through.
        // See https://doc.rust-lang.org/cargo/reference/registry-index.html
        let cases: &[(&str, &str)] = &[("version_req", "^1.0"), ("req", "^0.4")];
        for &(field, ver) in cases {
            let meta = serde_json::json!({
                "deps": [{ "name": "dep", field: ver, "kind": "normal" }],
                "features": {}
            });
            let entry_str = build_index_entry("test-crate", "0.1.0", "aaa", Some(&meta));
            let entry: serde_json::Value = serde_json::from_str(&entry_str).unwrap();
            let dep = &entry["deps"][0];
            assert_eq!(dep["req"], ver, "field '{field}' should produce req={ver}");
            assert!(
                dep.get("version_req").is_none(),
                "version_req must be absent for '{field}'"
            );
        }
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
        assert_eq!(resp.headers().get("cache-control").unwrap(), "max-age=300");
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
        assert_eq!(cache, "max-age=300");
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
            storage_backend: "filesystem".to_string(),
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
            storage_backend: "filesystem".to_string(),
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
            storage_backend: "filesystem".to_string(),
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
            storage_backend: "filesystem".to_string(),
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

    // -----------------------------------------------------------------------
    // index_cache_get / index_cache_set / index_cache_invalidate
    // -----------------------------------------------------------------------

    fn make_index_cache() -> IndexCache {
        use std::sync::{Arc, RwLock};
        Arc::new(RwLock::new(HashMap::new()))
    }

    #[test]
    fn test_index_cache_get_empty_cache_returns_none() {
        let cache = make_index_cache();
        assert!(index_cache_get(&cache, "myrepo:serde").is_none());
    }

    #[test]
    fn test_index_cache_get_unknown_key_returns_none() {
        let cache = make_index_cache();
        let data = Bytes::from_static(b"some index data");
        index_cache_set(&cache, "myrepo:tokio".to_string(), data);
        assert!(index_cache_get(&cache, "myrepo:serde").is_none());
    }

    #[test]
    fn test_index_cache_set_and_get_roundtrip() {
        let cache = make_index_cache();
        let data = Bytes::from_static(b"{\"name\":\"serde\",\"vers\":\"1.0.0\"}");
        index_cache_set(&cache, "myrepo:serde".to_string(), data.clone());
        let result = index_cache_get(&cache, "myrepo:serde").expect("should be in cache");
        assert_eq!(result, data);
    }

    #[test]
    fn test_index_cache_set_overwrites_existing_entry() {
        let cache = make_index_cache();
        let v1 = Bytes::from_static(b"version 1 data");
        let v2 = Bytes::from_static(b"version 2 data");
        index_cache_set(&cache, "repo:crate".to_string(), v1);
        index_cache_set(&cache, "repo:crate".to_string(), v2.clone());
        let result = index_cache_get(&cache, "repo:crate").expect("should be in cache");
        assert_eq!(result, v2);
    }

    #[test]
    fn test_index_cache_invalidate_removes_key() {
        let cache = make_index_cache();
        let data = Bytes::from_static(b"data");
        index_cache_set(&cache, "repo:serde".to_string(), data);
        assert!(index_cache_get(&cache, "repo:serde").is_some());
        index_cache_invalidate(&cache, "repo:serde");
        assert!(index_cache_get(&cache, "repo:serde").is_none());
    }

    #[test]
    fn test_index_cache_invalidate_missing_key_is_noop() {
        let cache = make_index_cache();
        // Should not panic on a cache miss.
        index_cache_invalidate(&cache, "repo:nonexistent");
        assert!(index_cache_get(&cache, "repo:nonexistent").is_none());
    }

    #[test]
    fn test_index_cache_invalidate_leaves_other_keys_intact() {
        let cache = make_index_cache();
        index_cache_set(
            &cache,
            "repo:serde".to_string(),
            Bytes::from_static(b"serde"),
        );
        index_cache_set(
            &cache,
            "repo:tokio".to_string(),
            Bytes::from_static(b"tokio"),
        );
        index_cache_invalidate(&cache, "repo:serde");
        assert!(index_cache_get(&cache, "repo:serde").is_none());
        assert!(index_cache_get(&cache, "repo:tokio").is_some());
    }

    #[test]
    fn test_index_cache_key_format() {
        // The key is "{repo_key}:{crate_name_lowercase}".
        let repo_key = "cargo-proxy";
        let crate_name = "serde_json";
        let key = format!("{}:{}", repo_key, crate_name.to_lowercase());
        assert_eq!(key, "cargo-proxy:serde_json");
    }

    #[test]
    fn test_index_cache_key_uses_lowercase_crate_name() {
        // Verify that upper-case input is folded before building the key,
        // matching what serve_index does with `crate_name.to_lowercase()`.
        let cache = make_index_cache();
        let data = Bytes::from_static(b"data");
        let lower_key = "repo:serde".to_string();
        index_cache_set(&cache, lower_key, data.clone());
        // A lookup with the pre-lowercased key must hit.
        assert!(index_cache_get(&cache, "repo:serde").is_some());
        // A lookup with a mixed-case key does NOT hit (the caller is responsible
        // for lowercasing before building the key).
        assert!(index_cache_get(&cache, "repo:Serde").is_none());
    }

    #[test]
    fn test_index_cache_set_lazy_eviction_preserves_fresh_entries() {
        // After a set+get cycle the entry must still be retrievable: the
        // lazy eviction in index_cache_set only removes *expired* entries,
        // never fresh ones.
        let cache = make_index_cache();
        let data = Bytes::from_static(b"fresh");
        index_cache_set(&cache, "repo:crate-a".to_string(), data.clone());
        // Trigger eviction pass by setting another entry.
        index_cache_set(&cache, "repo:crate-b".to_string(), Bytes::from_static(b"b"));
        // The first entry must still be present.
        assert_eq!(
            index_cache_get(&cache, "repo:crate-a").expect("should still be cached"),
            data
        );
    }

    #[test]
    fn test_index_cache_multiple_repos_isolated() {
        // Entries for different repo keys must not collide.
        let cache = make_index_cache();
        let data_a = Bytes::from_static(b"repo-a data");
        let data_b = Bytes::from_static(b"repo-b data");
        index_cache_set(&cache, "repo-a:serde".to_string(), data_a.clone());
        index_cache_set(&cache, "repo-b:serde".to_string(), data_b.clone());
        assert_eq!(index_cache_get(&cache, "repo-a:serde").unwrap(), data_a);
        assert_eq!(index_cache_get(&cache, "repo-b:serde").unwrap(), data_b);
        index_cache_invalidate(&cache, "repo-a:serde");
        assert!(index_cache_get(&cache, "repo-a:serde").is_none());
        assert!(index_cache_get(&cache, "repo-b:serde").is_some());
    }

    #[test]
    fn test_index_cache_ttl_matches_http_max_age() {
        // INDEX_CACHE_TTL_SECS must equal the numeric value in the HTTP
        // Cache-Control header that index_response() sets.  If someone changes
        // one without the other, cargo clients will either hold stale data
        // longer than the in-process cache, or re-request before the in-process
        // cache has expired.
        assert_eq!(INDEX_CACHE_TTL_SECS, 300);
        let resp = index_response("", None);
        let cache_control = resp
            .headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cache_control, &format!("max-age={}", INDEX_CACHE_TTL_SECS));
    }

    #[test]
    fn test_index_cache_concurrent_access() {
        // Arc<RwLock<HashMap>> must allow concurrent reads and writes from
        // multiple threads without panicking or losing data.
        use std::thread;
        let cache = make_index_cache();
        let threads: Vec<_> = (0..8)
            .map(|i| {
                let c = cache.clone();
                thread::spawn(move || {
                    let key = format!("repo:crate-{}", i);
                    let data = Bytes::from(format!("data-{}", i).into_bytes());
                    index_cache_set(&c, key.clone(), data.clone());
                    let result = index_cache_get(&c, &key);
                    assert!(result.is_some());
                    assert_eq!(result.unwrap(), data);
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
    }

    #[test]
    fn test_virtual_repo_invalidation_pattern() {
        // Simulates the multi-key invalidation that publish performs:
        // invalidate the hosted repo's entry AND each virtual repo that
        // aggregates it.
        let cache = make_index_cache();
        let crate_name = "serde";
        let hosted_key = "hosted-repo";
        let virtual_keys = ["virtual-a", "virtual-b"];

        // Populate all keys (as if serve_index has warmed them).
        index_cache_set(
            &cache,
            format!("{}:{}", hosted_key, crate_name),
            Bytes::from_static(b"hosted-index"),
        );
        for vk in &virtual_keys {
            index_cache_set(
                &cache,
                format!("{}:{}", vk, crate_name),
                Bytes::from_static(b"virtual-index"),
            );
        }

        // Invalidate (mirrors the publish handler).
        index_cache_invalidate(&cache, &format!("{}:{}", hosted_key, crate_name));
        for vk in &virtual_keys {
            index_cache_invalidate(&cache, &format!("{}:{}", vk, crate_name));
        }

        // All three entries must be gone.
        assert!(index_cache_get(&cache, &format!("{}:{}", hosted_key, crate_name)).is_none());
        for vk in &virtual_keys {
            assert!(index_cache_get(&cache, &format!("{}:{}", vk, crate_name)).is_none());
        }
    }

    #[test]
    fn test_index_cache_binary_content_round_trip() {
        // The cache stores raw Bytes; arbitrary byte sequences (not just UTF-8
        // JSON) must be returned unchanged.
        let cache = make_index_cache();
        let binary_data = Bytes::from(vec![0u8, 1, 2, 127, 128, 255, b'"', b'\n']);
        index_cache_set(&cache, "repo:binary-crate".to_string(), binary_data.clone());
        let result = index_cache_get(&cache, "repo:binary-crate").unwrap();
        assert_eq!(result, binary_data);
    }

    // -----------------------------------------------------------------------
    // build_download_url (upstream config.json dl field)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_download_url_plain_base() {
        // Standard crates.io style: dl is a plain URL, we append /{name}/{version}/download.
        let dl = "https://crates.io/api/v1/crates";
        let url = build_download_url(dl, "serde", "1.0.200");
        assert_eq!(
            url,
            "https://crates.io/api/v1/crates/serde/1.0.200/download"
        );
    }

    #[test]
    fn test_build_download_url_plain_base_trailing_slash() {
        let dl = "https://crates.io/api/v1/crates/";
        let url = build_download_url(dl, "tokio", "1.38.0");
        assert_eq!(url, "https://crates.io/api/v1/crates/tokio/1.38.0/download");
    }

    #[test]
    fn test_build_download_url_template_with_markers() {
        // Some registries use template markers in the dl field.
        let dl = "https://dl.example.com/crates/{crate}/{version}/download";
        let url = build_download_url(dl, "rand", "0.8.5");
        assert_eq!(url, "https://dl.example.com/crates/rand/0.8.5/download");
    }

    #[test]
    fn test_build_download_url_template_only_crate_marker() {
        let dl = "https://cdn.example.com/{crate}/files/{version}.tgz";
        let url = build_download_url(dl, "regex", "1.10.0");
        assert_eq!(url, "https://cdn.example.com/regex/files/1.10.0.tgz");
    }

    #[test]
    fn test_build_download_url_prerelease_version() {
        let dl = "https://crates.io/api/v1/crates";
        let url = build_download_url(dl, "my-crate", "0.1.0-alpha.1");
        assert_eq!(
            url,
            "https://crates.io/api/v1/crates/my-crate/0.1.0-alpha.1/download"
        );
    }

    #[test]
    fn test_build_download_url_single_char_crate() {
        let dl = "https://crates.io/api/v1/crates";
        let url = build_download_url(dl, "a", "0.0.1");
        assert_eq!(url, "https://crates.io/api/v1/crates/a/0.0.1/download");
    }

    // -----------------------------------------------------------------------
    // split_url
    // -----------------------------------------------------------------------

    #[test]
    fn test_split_url_standard() {
        let (origin, path) =
            split_url("https://crates.io/api/v1/crates/serde/1.0.0/download").unwrap();
        assert_eq!(origin, "https://crates.io");
        assert_eq!(path, "api/v1/crates/serde/1.0.0/download");
    }

    #[test]
    fn test_split_url_with_port() {
        let (origin, path) =
            split_url("http://localhost:8080/api/v1/crates/tokio/1.0.0/download").unwrap();
        assert_eq!(origin, "http://localhost:8080");
        assert_eq!(path, "api/v1/crates/tokio/1.0.0/download");
    }

    #[test]
    fn test_split_url_no_path() {
        // A URL with no path after the host returns None.
        assert!(split_url("https://crates.io").is_none());
    }

    #[test]
    fn test_split_url_no_scheme() {
        assert!(split_url("crates.io/api/v1/crates").is_none());
    }

    #[test]
    fn test_split_url_root_path() {
        let (origin, path) = split_url("https://example.com/download").unwrap();
        assert_eq!(origin, "https://example.com");
        assert_eq!(path, "download");
    }

    #[test]
    fn test_split_url_deep_path() {
        let (origin, path) = split_url("https://cdn.example.com/a/b/c/d/e").unwrap();
        assert_eq!(origin, "https://cdn.example.com");
        assert_eq!(path, "a/b/c/d/e");
    }

    // -----------------------------------------------------------------------
    // config_cache_get / config_cache_set
    // -----------------------------------------------------------------------

    #[test]
    fn test_config_cache_miss_returns_none() {
        assert!(config_cache_get("https://nonexistent.example.com").is_none());
    }

    #[test]
    fn test_config_cache_set_and_get_roundtrip() {
        let base = format!(
            "https://test-roundtrip-{}.example.com",
            uuid::Uuid::new_v4()
        );
        let dl = "https://dl.example.com/api/v1/crates".to_string();
        config_cache_set(base.clone(), dl.clone());
        let result = config_cache_get(&base).expect("should be in cache");
        assert_eq!(result, dl);
    }

    #[test]
    fn test_config_cache_overwrites_previous_value() {
        let base = format!(
            "https://test-overwrite-{}.example.com",
            uuid::Uuid::new_v4()
        );
        config_cache_set(base.clone(), "https://old.example.com/dl".to_string());
        config_cache_set(base.clone(), "https://new.example.com/dl".to_string());
        let result = config_cache_get(&base).unwrap();
        assert_eq!(result, "https://new.example.com/dl");
    }

    // -----------------------------------------------------------------------
    // End-to-end download URL resolution scenario tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_crates_io_dl_url_produces_correct_download() {
        // Simulates the crates.io scenario:
        // config.json at index.crates.io has dl = "https://crates.io/api/v1/crates"
        let dl = "https://crates.io/api/v1/crates";
        let full_url = build_download_url(dl, "serde_json", "1.0.120");
        assert_eq!(
            full_url,
            "https://crates.io/api/v1/crates/serde_json/1.0.120/download"
        );

        // The split must yield the correct origin for proxy_fetch.
        let (origin, path) = split_url(&full_url).unwrap();
        assert_eq!(origin, "https://crates.io");
        assert_eq!(path, "api/v1/crates/serde_json/1.0.120/download");
    }

    #[test]
    fn test_self_hosted_registry_same_host_dl() {
        // A self-hosted registry where index and downloads share the same host.
        // config.json has dl = "https://registry.company.com/api/v1/crates"
        let dl = "https://registry.company.com/api/v1/crates";
        let full_url = build_download_url(dl, "internal-lib", "2.0.0");
        let (origin, path) = split_url(&full_url).unwrap();
        assert_eq!(origin, "https://registry.company.com");
        assert_eq!(path, "api/v1/crates/internal-lib/2.0.0/download");
    }

    #[test]
    fn test_fallback_when_no_dl_url() {
        // When resolve_upstream_dl_url returns None, the download handler
        // falls back to upstream_url + the standard path.
        let upstream_url = "https://index.crates.io";
        let name = "serde";
        let version = "1.0.0";
        let fallback_path = format!("api/v1/crates/{}/{}/download", name, version);
        assert_eq!(fallback_path, "api/v1/crates/serde/1.0.0/download");

        // This would produce the wrong URL for crates.io (index.crates.io
        // does not serve downloads), but it is the correct fallback for
        // registries where index and downloads share the same host.
        let full_fallback = format!("{}/{}", upstream_url, fallback_path);
        assert_eq!(
            full_fallback,
            "https://index.crates.io/api/v1/crates/serde/1.0.0/download"
        );
    }

    #[test]
    fn test_build_download_url_rejects_internal_addresses() {
        use crate::api::validation::validate_outbound_url;

        // Cloud metadata endpoint (AWS IMDSv1)
        let dl = "http://169.254.169.254/latest/meta-data/";
        let url = build_download_url(dl, "evil", "1.0.0");
        assert!(
            validate_outbound_url(&url, "Cargo upstream download URL").is_err(),
            "cloud metadata URL should be rejected"
        );

        // Localhost
        let dl = "http://localhost:8080/evil";
        let url = build_download_url(dl, "crate", "0.1.0");
        assert!(
            validate_outbound_url(&url, "Cargo upstream download URL").is_err(),
            "localhost URL should be rejected"
        );

        // Private network (10.x)
        let dl = "http://10.0.0.1/packages";
        let url = build_download_url(dl, "crate", "0.1.0");
        assert!(
            validate_outbound_url(&url, "Cargo upstream download URL").is_err(),
            "private network URL should be rejected"
        );

        // Docker-internal service name
        let dl = "http://backend:8080/internal";
        let url = build_download_url(dl, "crate", "0.1.0");
        assert!(
            validate_outbound_url(&url, "Cargo upstream download URL").is_err(),
            "Docker-internal service URL should be rejected"
        );

        // Legitimate external URL should pass
        let dl = "https://crates.io/api/v1/crates";
        let url = build_download_url(dl, "serde", "1.0.0");
        assert!(
            validate_outbound_url(&url, "Cargo upstream download URL").is_ok(),
            "legitimate external URL should be accepted"
        );
    }
}
