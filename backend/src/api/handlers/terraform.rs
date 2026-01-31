//! Terraform Registry Protocol API handlers.
//!
//! Implements the Terraform Registry Protocol for modules and providers,
//! compatible with both Terraform CLI and OpenTofu.
//!
//! Routes are mounted at `/terraform/{repo_key}/...`:
//!
//! Service Discovery:
//!   GET  /terraform/{repo_key}/.well-known/terraform.json
//!
//! Module Registry:
//!   GET  /terraform/{repo_key}/v1/modules/{namespace}/{name}/{provider}/versions
//!   GET  /terraform/{repo_key}/v1/modules/{namespace}/{name}/{provider}/{version}/download
//!   GET  /terraform/{repo_key}/v1/modules/{namespace}/{name}/{provider}
//!   GET  /terraform/{repo_key}/v1/modules/search?q=query
//!   PUT  /terraform/{repo_key}/v1/modules/{namespace}/{name}/{provider}/{version}
//!
//! Provider Registry:
//!   GET  /terraform/{repo_key}/v1/providers/{namespace}/{type}/versions
//!   GET  /terraform/{repo_key}/v1/providers/{namespace}/{type}/{version}/download/{os}/{arch}
//!   PUT  /terraform/{repo_key}/v1/providers/{namespace}/{type}/{version}/{os}/{arch}

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::header::CONTENT_TYPE;
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
        // Service discovery
        .route(
            "/:repo_key/.well-known/terraform.json",
            get(service_discovery),
        )
        // Module registry - search
        .route("/:repo_key/v1/modules/search", get(search_modules))
        // Module registry - list versions
        .route(
            "/:repo_key/v1/modules/:namespace/:name/:provider/versions",
            get(list_module_versions),
        )
        // Module registry - download (must be before latest to avoid clash)
        .route(
            "/:repo_key/v1/modules/:namespace/:name/:provider/:version/download",
            get(download_module),
        )
        // Module registry - latest version
        .route(
            "/:repo_key/v1/modules/:namespace/:name/:provider",
            get(latest_module_version),
        )
        // Module upload
        .route(
            "/:repo_key/v1/modules/:namespace/:name/:provider/:version",
            put(upload_module),
        )
        // Provider registry - list versions
        .route(
            "/:repo_key/v1/providers/:namespace/:type_name/versions",
            get(list_provider_versions),
        )
        // Provider registry - download
        .route(
            "/:repo_key/v1/providers/:namespace/:type_name/:version/download/:os/:arch",
            get(download_provider),
        )
        // Provider upload
        .route(
            "/:repo_key/v1/providers/:namespace/:type_name/:version/:os/:arch",
            put(upload_provider),
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

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or(v.strip_prefix("bearer ")))
        .map(|t| t.to_string())
}

/// Authenticate via Bearer token or Basic auth, returning user_id on success.
async fn authenticate(
    db: &PgPool,
    config: &crate::config::Config,
    headers: &HeaderMap,
) -> Result<uuid::Uuid, Response> {
    // Try Bearer token first (Terraform's preferred method)
    if let Some(token) = extract_bearer_token(headers) {
        let auth_service = AuthService::new(db.clone(), Arc::new(config.clone()));
        // Use token as password with a placeholder username
        let (user, _tokens) = auth_service
            .authenticate("token", &token)
            .await
            .map_err(|_| {
                Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header("WWW-Authenticate", "Bearer realm=\"terraform\"")
                    .body(Body::from("Invalid token"))
                    .unwrap()
            })?;
        return Ok(user.id);
    }

    // Fall back to Basic auth
    let (username, password) = extract_basic_credentials(headers).ok_or_else(|| {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Basic realm=\"terraform\"")
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
                .header("WWW-Authenticate", "Basic realm=\"terraform\"")
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

async fn resolve_terraform_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
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
    if fmt != "terraform" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not a Terraform repository (format: {})",
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
// GET /{repo_key}/.well-known/terraform.json — Service Discovery
// ---------------------------------------------------------------------------

async fn service_discovery(Path(repo_key): Path<String>) -> Result<Response, Response> {
    let json = serde_json::json!({
        "modules.v1": format!("/terraform/{}/v1/modules/", repo_key),
        "providers.v1": format!("/terraform/{}/v1/providers/", repo_key),
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /v1/modules/{namespace}/{name}/{provider}/versions
// ---------------------------------------------------------------------------

async fn list_module_versions(
    State(state): State<SharedState>,
    Path((repo_key, namespace, name, provider)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_terraform_repo(&state.db, &repo_key).await?;
    let module_name = format!("{}/{}/{}", namespace, name, provider);

    let versions: Vec<Option<String>> = sqlx::query_scalar!(
        r#"
        SELECT DISTINCT version
        FROM artifacts
        WHERE repository_id = $1
          AND name = $2
          AND is_deleted = false
          AND version IS NOT NULL
        ORDER BY version
        "#,
        repo.id,
        module_name
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

    let version_list: Vec<serde_json::Value> = versions
        .into_iter()
        .flatten()
        .map(|v| serde_json::json!({ "version": v }))
        .collect();

    let json = serde_json::json!({
        "modules": [{
            "versions": version_list,
        }]
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /v1/modules/{namespace}/{name}/{provider}/{version}/download
// ---------------------------------------------------------------------------

async fn download_module(
    State(state): State<SharedState>,
    Path((repo_key, namespace, name, provider, version)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, Response> {
    let repo = resolve_terraform_repo(&state.db, &repo_key).await?;
    let module_name = format!("{}/{}/{}", namespace, name, provider);

    let artifact = sqlx::query!(
        r#"
        SELECT id, storage_key
        FROM artifacts
        WHERE repository_id = $1
          AND name = $2
          AND version = $3
          AND is_deleted = false
        LIMIT 1
        "#,
        repo.id,
        module_name,
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
    })?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!(
                "Module {}/{}/{} version {} not found",
                namespace, name, provider, version
            ),
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

    // Return 204 with X-Terraform-Get header pointing to the archive download URL
    let download_url = format!(
        "/terraform/{}/v1/modules/{}/{}/{}/{}/archive",
        repo_key, namespace, name, provider, version
    );

    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("X-Terraform-Get", download_url)
        .body(Body::empty())
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /v1/modules/{namespace}/{name}/{provider} — Latest version
// ---------------------------------------------------------------------------

async fn latest_module_version(
    State(state): State<SharedState>,
    Path((repo_key, namespace, name, provider)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_terraform_repo(&state.db, &repo_key).await?;
    let module_name = format!("{}/{}/{}", namespace, name, provider);

    let artifact = sqlx::query!(
        r#"
        SELECT version, created_at
        FROM artifacts
        WHERE repository_id = $1
          AND name = $2
          AND is_deleted = false
          AND version IS NOT NULL
        ORDER BY created_at DESC
        LIMIT 1
        "#,
        repo.id,
        module_name
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
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("No versions found for module {}", module_name),
        )
            .into_response()
    })?;

    let version = artifact.version.unwrap_or_default();

    let json = serde_json::json!({
        "id": format!("{}/{}/{}/{}", namespace, name, provider, version),
        "owner": "",
        "namespace": namespace,
        "name": name,
        "version": version,
        "provider": provider,
        "description": "",
        "source": "",
        "published_at": artifact.created_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        "downloads": 0,
        "verified": false,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /v1/modules/search?q=query — Search modules
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct SearchQuery {
    q: Option<String>,
    #[serde(default = "default_offset")]
    offset: i64,
    #[serde(default = "default_limit")]
    limit: i64,
}

fn default_offset() -> i64 {
    0
}

fn default_limit() -> i64 {
    10
}

async fn search_modules(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    Query(params): Query<SearchQuery>,
) -> Result<Response, Response> {
    let repo = resolve_terraform_repo(&state.db, &repo_key).await?;
    let query = params.q.unwrap_or_default();
    let search_pattern = format!("%{}%", query);

    let modules = sqlx::query!(
        r#"
        SELECT DISTINCT name, version, created_at
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND name ILIKE $2
          AND version IS NOT NULL
        ORDER BY created_at DESC
        LIMIT $3 OFFSET $4
        "#,
        repo.id,
        search_pattern,
        params.limit,
        params.offset,
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

    let module_list: Vec<serde_json::Value> = modules
        .iter()
        .map(|m| {
            let parts: Vec<&str> = m.name.splitn(3, '/').collect();
            let (namespace, name, provider) = match parts.as_slice() {
                [ns, n, p] => (ns.to_string(), n.to_string(), p.to_string()),
                _ => (m.name.clone(), String::new(), String::new()),
            };
            let version = m.version.clone().unwrap_or_default();
            serde_json::json!({
                "id": format!("{}/{}", m.name, version),
                "namespace": namespace,
                "name": name,
                "provider": provider,
                "version": version,
                "description": "",
                "published_at": m.created_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            })
        })
        .collect();

    let json = serde_json::json!({
        "meta": {
            "limit": params.limit,
            "current_offset": params.offset,
        },
        "modules": module_list,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// PUT /v1/modules/{namespace}/{name}/{provider}/{version} — Upload module
// ---------------------------------------------------------------------------

async fn upload_module(
    State(state): State<SharedState>,
    Path((repo_key, namespace, name, provider, version)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_terraform_repo(&state.db, &repo_key).await?;
    let module_name = format!("{}/{}/{}", namespace, name, provider);

    // Check for duplicate
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND name = $2 AND version = $3 AND is_deleted = false",
        repo.id,
        module_name,
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
            format!("Module {} version {} already exists", module_name, version),
        )
            .into_response());
    }

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let checksum = format!("{:x}", hasher.finalize());

    let size_bytes = body.len() as i64;
    let artifact_path = format!("{}/{}/{}/{}", namespace, name, provider, version);
    let storage_key = format!(
        "terraform/modules/{}/{}/{}/{}.tar.gz",
        namespace, name, provider, version
    );

    // Store the file
    let storage = FilesystemStorage::new(&repo.storage_path);
    storage.put(&storage_key, body).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

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
        module_name,
        version,
        size_bytes,
        checksum,
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
    let metadata = serde_json::json!({
        "kind": "module",
        "namespace": namespace,
        "name": name,
        "provider": provider,
        "version": version,
    });

    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'terraform', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        metadata,
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
        "Terraform module upload: {}/{}/{} v{} to repo {}",
        namespace, name, provider, version, repo_key
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "id": format!("{}/{}/{}/{}", namespace, name, provider, version),
                "namespace": namespace,
                "name": name,
                "provider": provider,
                "version": version,
                "checksum": checksum,
            }))
            .unwrap(),
        ))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /v1/providers/{namespace}/{type}/versions
// ---------------------------------------------------------------------------

async fn list_provider_versions(
    State(state): State<SharedState>,
    Path((repo_key, namespace, type_name)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_terraform_repo(&state.db, &repo_key).await?;
    let provider_name = format!("{}/{}", namespace, type_name);

    // Get all versions with their platform info from metadata
    let artifacts = sqlx::query!(
        r#"
        SELECT DISTINCT a.version, am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.name = $2
          AND a.is_deleted = false
          AND a.version IS NOT NULL
        ORDER BY a.version
        "#,
        repo.id,
        provider_name,
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

    // Group by version and collect platforms
    let mut version_map: std::collections::BTreeMap<String, Vec<serde_json::Value>> =
        std::collections::BTreeMap::new();

    for artifact in &artifacts {
        let version = match &artifact.version {
            Some(v) => v.clone(),
            None => continue,
        };

        let platforms = version_map.entry(version).or_default();

        if let Some(metadata) = &artifact.metadata {
            let os = metadata
                .get("os")
                .and_then(|v| v.as_str())
                .unwrap_or("linux");
            let arch = metadata
                .get("arch")
                .and_then(|v| v.as_str())
                .unwrap_or("amd64");

            let platform = serde_json::json!({ "os": os, "arch": arch });
            if !platforms.contains(&platform) {
                platforms.push(platform);
            }
        }
    }

    let versions: Vec<serde_json::Value> = version_map
        .into_iter()
        .map(|(version, platforms)| {
            serde_json::json!({
                "version": version,
                "protocols": ["5.0"],
                "platforms": if platforms.is_empty() {
                    vec![serde_json::json!({"os": "linux", "arch": "amd64"})]
                } else {
                    platforms
                },
            })
        })
        .collect();

    let json = serde_json::json!({
        "versions": versions,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /v1/providers/{namespace}/{type}/{version}/download/{os}/{arch}
// ---------------------------------------------------------------------------

async fn download_provider(
    State(state): State<SharedState>,
    Path((repo_key, namespace, type_name, version, os, arch)): Path<(
        String,
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, Response> {
    let repo = resolve_terraform_repo(&state.db, &repo_key).await?;
    let provider_name = format!("{}/{}", namespace, type_name);
    let platform_path = format!("{}_{}", os, arch);

    let artifact = sqlx::query!(
        r#"
        SELECT id, storage_key, size_bytes, checksum_sha256, path
        FROM artifacts
        WHERE repository_id = $1
          AND name = $2
          AND version = $3
          AND path LIKE '%' || $4 || '%'
          AND is_deleted = false
        LIMIT 1
        "#,
        repo.id,
        provider_name,
        version,
        platform_path,
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
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!(
                "Provider {}/{} version {} for {}/{} not found",
                namespace, type_name, version, os, arch
            ),
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

    let filename = format!(
        "terraform-provider-{}_{}_{}.zip",
        type_name, version, platform_path
    );

    // The provider download endpoint returns JSON with download information
    let download_url = format!(
        "/terraform/{}/v1/providers/{}/{}/{}/binary/{}/{}",
        repo_key, namespace, type_name, version, os, arch
    );

    let json = serde_json::json!({
        "protocols": ["5.0"],
        "os": os,
        "arch": arch,
        "filename": filename,
        "download_url": download_url,
        "shasum": artifact.checksum_sha256,
        "shasums_url": "",
        "shasums_signature_url": "",
        "signing_keys": {
            "gpg_public_keys": []
        },
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// PUT /v1/modules/{namespace}/{name}/{provider}/{version} — Upload module
// (handled above)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// PUT /v1/providers/{namespace}/{type}/{version}/{os}/{arch} — Upload provider
// ---------------------------------------------------------------------------

async fn upload_provider(
    State(state): State<SharedState>,
    Path((repo_key, namespace, type_name, version, os, arch)): Path<(
        String,
        String,
        String,
        String,
        String,
        String,
    )>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_terraform_repo(&state.db, &repo_key).await?;
    let provider_name = format!("{}/{}", namespace, type_name);
    let platform = format!("{}_{}", os, arch);

    let artifact_path = format!("{}/{}/{}/{}", namespace, type_name, version, platform);

    // Check for duplicate
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND name = $2 AND version = $3 AND path = $4 AND is_deleted = false",
        repo.id,
        provider_name,
        version,
        artifact_path,
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
            format!(
                "Provider {} version {} for {} already exists",
                provider_name, version, platform
            ),
        )
            .into_response());
    }

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let checksum = format!("{:x}", hasher.finalize());

    let size_bytes = body.len() as i64;
    let storage_key = format!(
        "terraform/providers/{}/{}/{}/terraform-provider-{}_{}.zip",
        namespace, type_name, version, type_name, platform
    );

    // Store the file
    let storage = FilesystemStorage::new(&repo.storage_path);
    storage.put(&storage_key, body).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

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
        provider_name,
        version,
        size_bytes,
        checksum,
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
    let metadata = serde_json::json!({
        "kind": "provider",
        "namespace": namespace,
        "type": type_name,
        "version": version,
        "os": os,
        "arch": arch,
    });

    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'terraform', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        metadata,
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
        "Terraform provider upload: {}/{} v{} ({}) to repo {}",
        namespace, type_name, version, platform, repo_key
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "namespace": namespace,
                "type": type_name,
                "version": version,
                "os": os,
                "arch": arch,
                "checksum": checksum,
            }))
            .unwrap(),
        ))
        .unwrap())
}
