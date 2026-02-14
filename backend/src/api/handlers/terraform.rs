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
    repo_type: String,
    upstream_url: Option<String>,
}

async fn resolve_terraform_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
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
        repo_type: repo.repo_type,
        upstream_url: repo.upstream_url,
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
    });

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == "remote" {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let upstream_path = format!(
                        "v1/modules/{}/{}/{}/{}/download",
                        namespace, name, provider, version
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
                let upstream_path = format!(
                    "v1/modules/{}/{}/{}/{}/download",
                    namespace, name, provider, version
                );
                let vname = module_name.clone();
                let vversion = version.clone();
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
                        "Content-Type",
                        content_type.unwrap_or_else(|| "application/octet-stream".to_string()),
                    )
                    .header(CONTENT_LENGTH, content.len().to_string())
                    .body(Body::from(content))
                    .unwrap());
            }
            return Err(not_found);
        }
    };

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
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
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
    });

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == "remote" {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let upstream_path = format!(
                        "v1/providers/{}/{}/{}/download/{}/{}",
                        namespace, type_name, version, os, arch
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
                let upstream_path = format!(
                    "v1/providers/{}/{}/{}/download/{}/{}",
                    namespace, type_name, version, os, arch
                );
                let vname = provider_name.clone();
                let vversion = version.clone();
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
                        "Content-Type",
                        content_type.unwrap_or_else(|| "application/octet-stream".to_string()),
                    )
                    .header(CONTENT_LENGTH, content.len().to_string())
                    .body(Body::from(content))
                    .unwrap());
            }
            return Err(not_found);
        }
    };

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
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
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

// ---------------------------------------------------------------------------
// PUT /v1/modules/{namespace}/{name}/{provider}/{version} — Upload module
// (handled above)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// PUT /v1/providers/{namespace}/{type}/{version}/{os}/{arch} — Upload provider
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    /// Build the service discovery JSON for a Terraform registry.
    fn build_service_discovery_json(repo_key: &str) -> serde_json::Value {
        serde_json::json!({
            "modules.v1": format!("/terraform/{}/v1/modules/", repo_key),
            "providers.v1": format!("/terraform/{}/v1/providers/", repo_key),
        })
    }

    // -----------------------------------------------------------------------
    // Extracted pure functions (moved into test module)
    // -----------------------------------------------------------------------

    /// Build a fully-qualified module name.
    fn build_module_name(namespace: &str, name: &str, provider: &str) -> String {
        format!("{}/{}/{}", namespace, name, provider)
    }

    /// Build a fully-qualified provider name.
    fn build_provider_name(namespace: &str, type_name: &str) -> String {
        format!("{}/{}", namespace, type_name)
    }

    /// Build the download URL for a module.
    fn build_module_download_url(
        repo_key: &str,
        namespace: &str,
        name: &str,
        provider: &str,
        version: &str,
    ) -> String {
        format!(
            "/terraform/{}/v1/modules/{}/{}/{}/{}/archive",
            repo_key, namespace, name, provider, version
        )
    }

    /// Build the download URL for a provider binary.
    fn build_provider_download_url(
        repo_key: &str,
        namespace: &str,
        type_name: &str,
        version: &str,
        os: &str,
        arch: &str,
    ) -> String {
        format!(
            "/terraform/{}/v1/providers/{}/{}/{}/binary/{}/{}",
            repo_key, namespace, type_name, version, os, arch
        )
    }

    /// Build the provider binary filename.
    fn build_provider_filename(type_name: &str, version: &str, platform_path: &str) -> String {
        format!(
            "terraform-provider-{}_{}_{}.zip",
            type_name, version, platform_path
        )
    }

    /// Build the platform path string (os_arch).
    fn build_platform_path(os: &str, arch: &str) -> String {
        format!("{}_{}", os, arch)
    }

    /// Build the storage key for a Terraform module.
    fn build_module_storage_key(
        namespace: &str,
        name: &str,
        provider: &str,
        version: &str,
    ) -> String {
        format!(
            "terraform/modules/{}/{}/{}/{}.tar.gz",
            namespace, name, provider, version
        )
    }

    /// Build the storage key for a Terraform provider.
    fn build_provider_storage_key(
        namespace: &str,
        type_name: &str,
        version: &str,
        platform: &str,
    ) -> String {
        format!(
            "terraform/providers/{}/{}/{}/terraform-provider-{}_{}.zip",
            namespace, type_name, version, type_name, platform
        )
    }

    /// Build the artifact path for a module.
    fn build_module_artifact_path(
        namespace: &str,
        name: &str,
        provider: &str,
        version: &str,
    ) -> String {
        format!("{}/{}/{}/{}", namespace, name, provider, version)
    }

    /// Build the artifact path for a provider.
    fn build_provider_artifact_path(
        namespace: &str,
        type_name: &str,
        version: &str,
        platform: &str,
    ) -> String {
        format!("{}/{}/{}/{}", namespace, type_name, version, platform)
    }

    /// Build module metadata JSON.
    fn build_module_metadata(
        namespace: &str,
        name: &str,
        provider: &str,
        version: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "kind": "module",
            "namespace": namespace,
            "name": name,
            "provider": provider,
            "version": version,
        })
    }

    /// Build provider metadata JSON.
    fn build_provider_metadata(
        namespace: &str,
        type_name: &str,
        version: &str,
        os: &str,
        arch: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "kind": "provider",
            "namespace": namespace,
            "type": type_name,
            "version": version,
            "os": os,
            "arch": arch,
        })
    }

    /// Build the version list JSON for a module.
    fn build_version_list_json(versions: &[String]) -> serde_json::Value {
        let version_list: Vec<serde_json::Value> = versions
            .iter()
            .map(|v| serde_json::json!({ "version": v }))
            .collect();
        serde_json::json!({
            "modules": [{
                "versions": version_list,
            }]
        })
    }

    /// Build the provider download JSON response.
    fn build_provider_download_json(
        os: &str,
        arch: &str,
        filename: &str,
        download_url: &str,
        shasum: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "protocols": ["5.0"],
            "os": os,
            "arch": arch,
            "filename": filename,
            "download_url": download_url,
            "shasum": shasum,
            "shasums_url": "",
            "shasums_signature_url": "",
            "signing_keys": {
                "gpg_public_keys": []
            },
        })
    }

    /// Parse a module name into (namespace, name, provider).
    fn parse_module_name(full_name: &str) -> (String, String, String) {
        let parts: Vec<&str> = full_name.splitn(3, '/').collect();
        match parts.as_slice() {
            [ns, n, p] => (ns.to_string(), n.to_string(), p.to_string()),
            _ => (full_name.to_string(), String::new(), String::new()),
        }
    }

    /// Build a SQL LIKE search pattern from a query string.
    fn build_search_pattern(query: &str) -> String {
        format!("%{}%", query)
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
    fn test_extract_basic_credentials_lowercase_prefix() {
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
    fn test_extract_basic_credentials_missing_header() {
        let headers = HeaderMap::new();
        let result = extract_basic_credentials(&headers);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_basic_credentials_no_colon() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("nocolon");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", encoded)).unwrap(),
        );
        let result = extract_basic_credentials(&headers);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_basic_credentials_colon_in_password() {
        let headers = make_basic_header("admin", "pass:with:colons");
        let result = extract_basic_credentials(&headers);
        assert_eq!(
            result,
            Some(("admin".to_string(), "pass:with:colons".to_string()))
        );
    }

    #[test]
    fn test_extract_basic_credentials_empty_password() {
        let headers = make_basic_header("admin", "");
        let result = extract_basic_credentials(&headers);
        assert_eq!(result, Some(("admin".to_string(), "".to_string())));
    }

    #[test]
    fn test_extract_basic_credentials_bearer_not_accepted() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer some-token"),
        );
        let result = extract_basic_credentials(&headers);
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // extract_bearer_token
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_bearer_token_valid() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer my-terraform-token"),
        );
        let result = extract_bearer_token(&headers);
        assert_eq!(result, Some("my-terraform-token".to_string()));
    }

    #[test]
    fn test_extract_bearer_token_lowercase() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("bearer my-token"),
        );
        let result = extract_bearer_token(&headers);
        assert_eq!(result, Some("my-token".to_string()));
    }

    #[test]
    fn test_extract_bearer_token_missing() {
        let headers = HeaderMap::new();
        let result = extract_bearer_token(&headers);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_bearer_token_basic_not_accepted() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:pass");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", encoded)).unwrap(),
        );
        let result = extract_bearer_token(&headers);
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // default_offset / default_limit
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_offset() {
        assert_eq!(default_offset(), 0);
    }

    #[test]
    fn test_default_limit() {
        assert_eq!(default_limit(), 10);
    }

    // -----------------------------------------------------------------------
    // SearchQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_query_defaults() {
        let q: SearchQuery = serde_json::from_str(r#"{}"#).unwrap();
        assert!(q.q.is_none());
        assert_eq!(q.offset, 0);
        assert_eq!(q.limit, 10);
    }

    #[test]
    fn test_search_query_with_values() {
        let q: SearchQuery =
            serde_json::from_str(r#"{"q":"my-module","offset":5,"limit":20}"#).unwrap();
        assert_eq!(q.q, Some("my-module".to_string()));
        assert_eq!(q.offset, 5);
        assert_eq!(q.limit, 20);
    }

    // -----------------------------------------------------------------------
    // RepoInfo struct construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_info_construction() {
        let id = uuid::Uuid::new_v4();
        let info = RepoInfo {
            id,
            storage_path: "/data/terraform".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: Some("https://registry.terraform.io".to_string()),
        };
        assert_eq!(info.id, id);
        assert_eq!(info.storage_path, "/data/terraform");
        assert_eq!(info.repo_type, "hosted");
        assert_eq!(
            info.upstream_url,
            Some("https://registry.terraform.io".to_string())
        );
    }

    #[test]
    fn test_repo_info_no_upstream() {
        let info = RepoInfo {
            id: uuid::Uuid::new_v4(),
            storage_path: "/data/tf".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: None,
        };
        assert!(info.upstream_url.is_none());
    }

    // -----------------------------------------------------------------------
    // Module name formatting
    // -----------------------------------------------------------------------

    #[test]
    fn test_module_name_format() {
        let namespace = "hashicorp";
        let name = "consul";
        let provider = "aws";
        let module_name = format!("{}/{}/{}", namespace, name, provider);
        assert_eq!(module_name, "hashicorp/consul/aws");
    }

    #[test]
    fn test_provider_name_format() {
        let namespace = "hashicorp";
        let type_name = "aws";
        let provider_name = format!("{}/{}", namespace, type_name);
        assert_eq!(provider_name, "hashicorp/aws");
    }

    // -----------------------------------------------------------------------
    // Storage key formatting
    // -----------------------------------------------------------------------

    #[test]
    fn test_module_storage_key_format() {
        let namespace = "hashicorp";
        let name = "consul";
        let provider = "aws";
        let version = "0.1.0";
        let storage_key = format!(
            "terraform/modules/{}/{}/{}/{}.tar.gz",
            namespace, name, provider, version
        );
        assert_eq!(
            storage_key,
            "terraform/modules/hashicorp/consul/aws/0.1.0.tar.gz"
        );
    }

    #[test]
    fn test_provider_storage_key_format() {
        let namespace = "hashicorp";
        let type_name = "aws";
        let version = "5.0.0";
        let platform = "linux_amd64";
        let storage_key = format!(
            "terraform/providers/{}/{}/{}/terraform-provider-{}_{}.zip",
            namespace, type_name, version, type_name, platform
        );
        assert_eq!(
            storage_key,
            "terraform/providers/hashicorp/aws/5.0.0/terraform-provider-aws_linux_amd64.zip"
        );
    }

    // -----------------------------------------------------------------------
    // SHA-256 checksum computation
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256_computation() {
        let data = b"terraform module content";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let checksum = format!("{:x}", hasher.finalize());
        assert_eq!(checksum.len(), 64);
        assert!(checksum.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // -----------------------------------------------------------------------
    // Platform path formatting
    // -----------------------------------------------------------------------

    #[test]
    fn test_platform_path() {
        let os = "linux";
        let arch = "amd64";
        let platform_path = format!("{}_{}", os, arch);
        assert_eq!(platform_path, "linux_amd64");
    }

    #[test]
    fn test_provider_filename_format() {
        let type_name = "aws";
        let version = "5.0.0";
        let platform_path = "linux_amd64";
        let filename = format!(
            "terraform-provider-{}_{}_{}.zip",
            type_name, version, platform_path
        );
        assert_eq!(filename, "terraform-provider-aws_5.0.0_linux_amd64.zip");
    }

    // -----------------------------------------------------------------------
    // Download URL formatting
    // -----------------------------------------------------------------------

    #[test]
    fn test_module_download_url_format() {
        let repo_key = "my-terraform";
        let namespace = "hashicorp";
        let name = "consul";
        let provider = "aws";
        let version = "0.1.0";
        let download_url = format!(
            "/terraform/{}/v1/modules/{}/{}/{}/{}/archive",
            repo_key, namespace, name, provider, version
        );
        assert_eq!(
            download_url,
            "/terraform/my-terraform/v1/modules/hashicorp/consul/aws/0.1.0/archive"
        );
    }

    #[test]
    fn test_provider_download_url_format() {
        let repo_key = "my-terraform";
        let namespace = "hashicorp";
        let type_name = "aws";
        let version = "5.0.0";
        let os = "linux";
        let arch = "amd64";
        let download_url = format!(
            "/terraform/{}/v1/providers/{}/{}/{}/binary/{}/{}",
            repo_key, namespace, type_name, version, os, arch
        );
        assert_eq!(
            download_url,
            "/terraform/my-terraform/v1/providers/hashicorp/aws/5.0.0/binary/linux/amd64"
        );
    }

    // -----------------------------------------------------------------------
    // Service discovery JSON structure
    // -----------------------------------------------------------------------

    #[test]
    fn test_service_discovery_json() {
        let repo_key = "my-tf-repo";
        let json = serde_json::json!({
            "modules.v1": format!("/terraform/{}/v1/modules/", repo_key),
            "providers.v1": format!("/terraform/{}/v1/providers/", repo_key),
        });
        assert_eq!(json["modules.v1"], "/terraform/my-tf-repo/v1/modules/");
        assert_eq!(json["providers.v1"], "/terraform/my-tf-repo/v1/providers/");
    }

    // -----------------------------------------------------------------------
    // Metadata JSON structure
    // -----------------------------------------------------------------------

    #[test]
    fn test_module_metadata_json() {
        let namespace = "hashicorp";
        let name = "consul";
        let provider = "aws";
        let version = "0.1.0";
        let metadata = serde_json::json!({
            "kind": "module",
            "namespace": namespace,
            "name": name,
            "provider": provider,
            "version": version,
        });
        assert_eq!(metadata["kind"], "module");
        assert_eq!(metadata["namespace"], "hashicorp");
    }

    #[test]
    fn test_provider_metadata_json() {
        let metadata = serde_json::json!({
            "kind": "provider",
            "namespace": "hashicorp",
            "type": "aws",
            "version": "5.0.0",
            "os": "linux",
            "arch": "amd64",
        });
        assert_eq!(metadata["kind"], "provider");
        assert_eq!(metadata["os"], "linux");
        assert_eq!(metadata["arch"], "amd64");
    }

    // -----------------------------------------------------------------------
    // Search results module name parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_module_name_parsing_three_parts() {
        let name = "hashicorp/consul/aws";
        let parts: Vec<&str> = name.splitn(3, '/').collect();
        let (ns, n, p) = match parts.as_slice() {
            [ns, n, p] => (ns.to_string(), n.to_string(), p.to_string()),
            _ => (name.to_string(), String::new(), String::new()),
        };
        assert_eq!(ns, "hashicorp");
        assert_eq!(n, "consul");
        assert_eq!(p, "aws");
    }

    #[test]
    fn test_module_name_parsing_one_part() {
        let name = "single-name";
        let parts: Vec<&str> = name.splitn(3, '/').collect();
        let (ns, n, p) = match parts.as_slice() {
            [ns, n, p] => (ns.to_string(), n.to_string(), p.to_string()),
            _ => (name.to_string(), String::new(), String::new()),
        };
        assert_eq!(ns, "single-name");
        assert_eq!(n, "");
        assert_eq!(p, "");
    }

    #[test]
    fn test_module_name_parsing_two_parts() {
        let name = "vendor/module";
        let parts: Vec<&str> = name.splitn(3, '/').collect();
        let (ns, n, p) = match parts.as_slice() {
            [ns, n, p] => (ns.to_string(), n.to_string(), p.to_string()),
            _ => (name.to_string(), String::new(), String::new()),
        };
        // With only 2 parts, we fall through to the default case
        assert_eq!(ns, "vendor/module");
        assert_eq!(n, "");
        assert_eq!(p, "");
    }

    // -----------------------------------------------------------------------
    // Version list response structure
    // -----------------------------------------------------------------------

    #[test]
    fn test_version_list_json_structure() {
        let versions = vec!["0.1.0", "0.2.0", "1.0.0"];
        let version_list: Vec<serde_json::Value> = versions
            .into_iter()
            .map(|v| serde_json::json!({ "version": v }))
            .collect();
        let json = serde_json::json!({
            "modules": [{
                "versions": version_list,
            }]
        });
        let modules = json["modules"].as_array().unwrap();
        assert_eq!(modules.len(), 1);
        let inner_versions = modules[0]["versions"].as_array().unwrap();
        assert_eq!(inner_versions.len(), 3);
        assert_eq!(inner_versions[0]["version"], "0.1.0");
    }

    // -----------------------------------------------------------------------
    // Provider version grouping logic
    // -----------------------------------------------------------------------

    #[test]
    fn test_provider_version_platform_grouping() {
        let mut version_map: std::collections::BTreeMap<String, Vec<serde_json::Value>> =
            std::collections::BTreeMap::new();

        let platforms = version_map.entry("1.0.0".to_string()).or_default();
        let p1 = serde_json::json!({"os": "linux", "arch": "amd64"});
        let p2 = serde_json::json!({"os": "darwin", "arch": "arm64"});
        platforms.push(p1.clone());
        platforms.push(p2.clone());

        // Verify dedup check
        assert!(platforms.contains(&p1));
        assert!(platforms.contains(&p2));
        assert_eq!(platforms.len(), 2);
    }

    #[test]
    fn test_provider_empty_platforms_default() {
        let platforms: Vec<serde_json::Value> = vec![];
        let result = if platforms.is_empty() {
            vec![serde_json::json!({"os": "linux", "arch": "amd64"})]
        } else {
            platforms
        };
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["os"], "linux");
        assert_eq!(result[0]["arch"], "amd64");
    }

    // -----------------------------------------------------------------------
    // build_service_discovery_json
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_service_discovery_json_basic() {
        let json = build_service_discovery_json("my-tf-repo");
        assert_eq!(json["modules.v1"], "/terraform/my-tf-repo/v1/modules/");
        assert_eq!(json["providers.v1"], "/terraform/my-tf-repo/v1/providers/");
    }

    #[test]
    fn test_build_service_discovery_json_different_key() {
        let json = build_service_discovery_json("prod-registry");
        assert!(json["modules.v1"]
            .as_str()
            .unwrap()
            .contains("prod-registry"));
    }

    // -----------------------------------------------------------------------
    // build_module_name / build_provider_name
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_module_name() {
        assert_eq!(
            build_module_name("hashicorp", "consul", "aws"),
            "hashicorp/consul/aws"
        );
    }

    #[test]
    fn test_build_provider_name() {
        assert_eq!(build_provider_name("hashicorp", "aws"), "hashicorp/aws");
    }

    // -----------------------------------------------------------------------
    // build_module_download_url / build_provider_download_url
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_module_download_url() {
        let url = build_module_download_url("repo", "ns", "name", "prov", "1.0.0");
        assert_eq!(url, "/terraform/repo/v1/modules/ns/name/prov/1.0.0/archive");
    }

    #[test]
    fn test_build_provider_download_url() {
        let url = build_provider_download_url("repo", "ns", "aws", "5.0.0", "linux", "amd64");
        assert_eq!(
            url,
            "/terraform/repo/v1/providers/ns/aws/5.0.0/binary/linux/amd64"
        );
    }

    // -----------------------------------------------------------------------
    // build_provider_filename / build_platform_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_provider_filename() {
        assert_eq!(
            build_provider_filename("aws", "5.0.0", "linux_amd64"),
            "terraform-provider-aws_5.0.0_linux_amd64.zip"
        );
    }

    #[test]
    fn test_build_platform_path() {
        assert_eq!(build_platform_path("linux", "amd64"), "linux_amd64");
        assert_eq!(build_platform_path("darwin", "arm64"), "darwin_arm64");
    }

    // -----------------------------------------------------------------------
    // build_module_storage_key / build_provider_storage_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_module_storage_key() {
        assert_eq!(
            build_module_storage_key("hashicorp", "consul", "aws", "0.1.0"),
            "terraform/modules/hashicorp/consul/aws/0.1.0.tar.gz"
        );
    }

    #[test]
    fn test_build_provider_storage_key() {
        assert_eq!(
            build_provider_storage_key("hashicorp", "aws", "5.0.0", "linux_amd64"),
            "terraform/providers/hashicorp/aws/5.0.0/terraform-provider-aws_linux_amd64.zip"
        );
    }

    // -----------------------------------------------------------------------
    // build_module_artifact_path / build_provider_artifact_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_module_artifact_path() {
        assert_eq!(
            build_module_artifact_path("hashicorp", "consul", "aws", "0.1.0"),
            "hashicorp/consul/aws/0.1.0"
        );
    }

    #[test]
    fn test_build_provider_artifact_path() {
        assert_eq!(
            build_provider_artifact_path("hashicorp", "aws", "5.0.0", "linux_amd64"),
            "hashicorp/aws/5.0.0/linux_amd64"
        );
    }

    // -----------------------------------------------------------------------
    // build_module_metadata / build_provider_metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_module_metadata() {
        let meta = build_module_metadata("hashicorp", "consul", "aws", "0.1.0");
        assert_eq!(meta["kind"], "module");
        assert_eq!(meta["namespace"], "hashicorp");
        assert_eq!(meta["name"], "consul");
        assert_eq!(meta["provider"], "aws");
        assert_eq!(meta["version"], "0.1.0");
    }

    #[test]
    fn test_build_provider_metadata() {
        let meta = build_provider_metadata("hashicorp", "aws", "5.0.0", "linux", "amd64");
        assert_eq!(meta["kind"], "provider");
        assert_eq!(meta["namespace"], "hashicorp");
        assert_eq!(meta["type"], "aws");
        assert_eq!(meta["os"], "linux");
        assert_eq!(meta["arch"], "amd64");
    }

    // -----------------------------------------------------------------------
    // build_version_list_json
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_version_list_json_basic() {
        let versions = vec![
            "0.1.0".to_string(),
            "0.2.0".to_string(),
            "1.0.0".to_string(),
        ];
        let json = build_version_list_json(&versions);
        let modules = json["modules"].as_array().unwrap();
        assert_eq!(modules.len(), 1);
        let inner = modules[0]["versions"].as_array().unwrap();
        assert_eq!(inner.len(), 3);
        assert_eq!(inner[0]["version"], "0.1.0");
    }

    #[test]
    fn test_build_version_list_json_empty() {
        let json = build_version_list_json(&[]);
        let inner = json["modules"][0]["versions"].as_array().unwrap();
        assert!(inner.is_empty());
    }

    // -----------------------------------------------------------------------
    // build_provider_download_json
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_provider_download_json_basic() {
        let json = build_provider_download_json(
            "linux",
            "amd64",
            "terraform-provider-aws_5.0.0_linux_amd64.zip",
            "/download/url",
            "sha256hash",
        );
        assert_eq!(json["os"], "linux");
        assert_eq!(json["arch"], "amd64");
        assert_eq!(json["shasum"], "sha256hash");
        assert!(json["protocols"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("5.0")));
        assert!(json["signing_keys"]["gpg_public_keys"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn test_build_provider_download_json_darwin() {
        let json = build_provider_download_json("darwin", "arm64", "file.zip", "/url", "hash");
        assert_eq!(json["os"], "darwin");
        assert_eq!(json["arch"], "arm64");
    }

    // -----------------------------------------------------------------------
    // parse_module_name
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_module_name_three_parts() {
        let (ns, n, p) = parse_module_name("hashicorp/consul/aws");
        assert_eq!(ns, "hashicorp");
        assert_eq!(n, "consul");
        assert_eq!(p, "aws");
    }

    #[test]
    fn test_parse_module_name_one_part() {
        let (ns, n, p) = parse_module_name("single");
        assert_eq!(ns, "single");
        assert_eq!(n, "");
        assert_eq!(p, "");
    }

    #[test]
    fn test_parse_module_name_two_parts() {
        let (ns, n, p) = parse_module_name("vendor/module");
        assert_eq!(ns, "vendor/module");
        assert_eq!(n, "");
        assert_eq!(p, "");
    }

    // -----------------------------------------------------------------------
    // build_search_pattern
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_search_pattern_basic() {
        assert_eq!(build_search_pattern("consul"), "%consul%");
    }

    #[test]
    fn test_build_search_pattern_empty() {
        assert_eq!(build_search_pattern(""), "%%");
    }

    #[test]
    fn test_build_search_pattern_special_chars() {
        assert_eq!(build_search_pattern("my-module"), "%my-module%");
    }
}
