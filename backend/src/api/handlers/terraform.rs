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

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::header::CONTENT_TYPE;
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
use crate::api::validation::validate_outbound_url;
use crate::api::SharedState;
use crate::models::repository::RepositoryType;

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
        // Provider Network Mirror Protocol (#1566).
        //
        // Configured by the client via `.terraformrc`/`.tofurc`:
        //   provider_installation {
        //     network_mirror { url = "https://host/terraform/<repo_key>/" }
        //   }
        // Terraform/OpenTofu then appends `<hostname>/<namespace>/<type>/...`
        // to that base, which lands on the routes below.
        //
        // List available versions of a provider.
        .route(
            "/:repo_key/:hostname/:namespace/:type_name/index.json",
            get(mirror_index),
        )
        // List the installation packages for one version (e.g. `2.0.0.json`).
        .route(
            "/:repo_key/:hostname/:namespace/:type_name/:version_file",
            get(mirror_version),
        )
        // Stream the actual provider archive for a platform (referenced by the
        // `url` field that `mirror_version` emits).
        .route(
            "/:repo_key/:hostname/:namespace/:type_name/:version/download/:os/:arch",
            get(mirror_download),
        )
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_terraform_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["terraform"], "a Terraform").await
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

    if version_list.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            format!("Module {} not found", module_name),
        )
            .into_response());
    }

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
            if repo.repo_type == RepositoryType::Remote {
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
            if repo.repo_type == RepositoryType::Virtual {
                let db = state.db.clone();
                let upstream_path = format!(
                    "v1/modules/{}/{}/{}/{}/download",
                    namespace, name, provider, version
                );
                let vname = module_name.clone();
                let vversion = version.clone();
                let result = proxy_helpers::resolve_virtual_download(
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

                return proxy_helpers::stream_fetch_result(
                    result,
                    "application/octet-stream",
                    None,
                );
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
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, namespace, name, provider, version)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
    body: Bytes,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "terraform", "write")?.user_id;
    let repo = resolve_terraform_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;
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

    super::cleanup_soft_deleted_artifact(&state.db, repo.id, &artifact_path).await;

    // Store the file
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
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

    if versions.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            format!("Provider {} not found", provider_name),
        )
            .into_response());
    }

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
    let platform_path = super::escape_like_literal(&format!("{}_{}", os, arch));

    let artifact = sqlx::query!(
        r#"
        SELECT id, storage_key, size_bytes, checksum_sha256, path
        FROM artifacts
        WHERE repository_id = $1
          AND name = $2
          AND version = $3
          AND path LIKE '%' || $4 || '%' ESCAPE '\'
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
            if repo.repo_type == RepositoryType::Remote {
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
            if repo.repo_type == RepositoryType::Virtual {
                let db = state.db.clone();
                let upstream_path = format!(
                    "v1/providers/{}/{}/{}/download/{}/{}",
                    namespace, type_name, version, os, arch
                );
                let vname = provider_name.clone();
                let vversion = version.clone();
                let result = proxy_helpers::resolve_virtual_download(
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

                return proxy_helpers::stream_fetch_result(
                    result,
                    "application/octet-stream",
                    None,
                );
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
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, namespace, type_name, version, os, arch)): Path<(
        String,
        String,
        String,
        String,
        String,
        String,
    )>,
    body: Bytes,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "terraform", "write")?.user_id;
    let repo = resolve_terraform_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;
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

    super::cleanup_soft_deleted_artifact(&state.db, repo.id, &artifact_path).await;

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
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
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
// Provider Network Mirror Protocol (#1566)
//
// Terraform/OpenTofu can be pointed at a "network mirror" via
// `provider_installation { network_mirror { url = "…" } }`. The mirror
// protocol is distinct from the registry protocol the registry handlers
// above implement: it has its own endpoints and JSON shapes.
//
//   GET <base>/:hostname/:namespace/:type/index.json
//       -> { "versions": { "<version>": {}, … } }
//   GET <base>/:hostname/:namespace/:type/<version>.json
//       -> { "archives": { "<os>_<arch>": { "url": "…", "hashes": [...] } } }
//
// The AK UI documents configuring a remote Terraform repository as a network
// mirror, so for a remote repo we translate these mirror requests into
// registry-protocol calls against the configured upstream (e.g.
// registry.opentofu.org) and rewrite the package URLs to flow the actual
// archive download back through AK (so it is cached/auth-gated like any other
// proxied artifact).
// ---------------------------------------------------------------------------

/// Strip the trailing `.json` from a mirror version filename (`2.0.0.json` ->
/// `2.0.0`). Returns `None` when the segment is not a `.json` document.
fn parse_mirror_version_file(version_file: &str) -> Option<&str> {
    version_file.strip_suffix(".json")
}

/// Build the upstream registry path that lists available versions of a
/// provider (Provider Registry Protocol).
fn build_registry_versions_path(namespace: &str, type_name: &str) -> String {
    format!("v1/providers/{}/{}/versions", namespace, type_name)
}

/// Build the upstream registry path that returns the download metadata for one
/// provider package (Provider Registry Protocol).
fn build_registry_download_path(
    namespace: &str,
    type_name: &str,
    version: &str,
    os: &str,
    arch: &str,
) -> String {
    format!(
        "v1/providers/{}/{}/{}/download/{}/{}",
        namespace, type_name, version, os, arch
    )
}

/// Build the AK-local mirror download URL emitted in `<version>.json` so the
/// archive is fetched back through this server (relative to the mirror base,
/// per the network-mirror spec).
fn build_mirror_archive_url(version: &str, os: &str, arch: &str) -> String {
    // The mirror base the client configured already ends at
    // `<base>/:hostname/:namespace/:type/`, so a relative URL keeps the path
    // anchored there. Terraform resolves it against the request URL.
    format!("{}/download/{}/{}", version, os, arch)
}

/// Transform a registry-protocol `versions` document into a mirror-protocol
/// `index.json` document.
///
/// Registry shape: `{ "versions": [ { "version": "2.0.0", … }, … ] }`
/// Mirror shape:   `{ "versions": { "2.0.0": {}, … } }`
fn registry_versions_to_mirror_index(registry: &serde_json::Value) -> serde_json::Value {
    let mut versions = serde_json::Map::new();
    if let Some(arr) = registry.get("versions").and_then(|v| v.as_array()) {
        for entry in arr {
            if let Some(v) = entry.get("version").and_then(|v| v.as_str()) {
                versions.insert(v.to_string(), serde_json::json!({}));
            }
        }
    }
    serde_json::json!({ "versions": serde_json::Value::Object(versions) })
}

/// Collect the `(os, arch)` platform pairs advertised for a specific version
/// from a registry-protocol `versions` document.
fn platforms_for_version(registry: &serde_json::Value, version: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(arr) = registry.get("versions").and_then(|v| v.as_array()) {
        for entry in arr {
            if entry.get("version").and_then(|v| v.as_str()) != Some(version) {
                continue;
            }
            if let Some(platforms) = entry.get("platforms").and_then(|v| v.as_array()) {
                for p in platforms {
                    let os = p.get("os").and_then(|v| v.as_str());
                    let arch = p.get("arch").and_then(|v| v.as_str());
                    if let (Some(os), Some(arch)) = (os, arch) {
                        out.push((os.to_string(), arch.to_string()));
                    }
                }
            }
        }
    }
    out
}

/// Convert a registry-protocol download document's `shasum` (hex SHA-256) into
/// the `zh:` hash form Terraform expects in a mirror archive entry. Returns
/// `None` when no usable shasum is present.
fn registry_shasum_to_mirror_hash(download: &serde_json::Value) -> Option<String> {
    download
        .get("shasum")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| format!("zh:{}", s))
}

/// Build one mirror archive entry from the AK-local archive URL plus an
/// optional hash list.
fn build_mirror_archive_entry(url: &str, hashes: Vec<String>) -> serde_json::Value {
    if hashes.is_empty() {
        serde_json::json!({ "url": url })
    } else {
        serde_json::json!({ "url": url, "hashes": hashes })
    }
}

/// Outcome of validating a repo for the network-mirror protocol. Kept as a
/// pure enum so the (otherwise async) guard's branching is unit-testable.
#[derive(Debug, PartialEq, Eq)]
enum MirrorGuard {
    Ok,
    /// Repo exists but is not a remote/proxy repo.
    NotRemote,
    /// Remote repo missing an upstream URL or with proxying disabled.
    NotProxyable,
}

/// Decide whether a resolved repo can serve network-mirror requests, given its
/// type and whether an upstream URL and a proxy service are available.
fn classify_mirror_repo(is_remote: bool, has_upstream: bool, has_proxy: bool) -> MirrorGuard {
    if !is_remote {
        MirrorGuard::NotRemote
    } else if has_upstream && has_proxy {
        MirrorGuard::Ok
    } else {
        MirrorGuard::NotProxyable
    }
}

/// Map a non-`Ok` [`MirrorGuard`] to the client-facing error response.
fn mirror_guard_error(guard: MirrorGuard) -> Response {
    let msg = match guard {
        MirrorGuard::NotRemote => {
            "Provider network mirror is only available on remote Terraform repositories"
        }
        MirrorGuard::NotProxyable => "Remote repository is not configured for proxying",
        MirrorGuard::Ok => "", // unreachable; callers only map error variants
    };
    (StatusCode::NOT_FOUND, msg.to_string()).into_response()
}

/// Assemble the mirror `<version>.json` `archives` object from the discovered
/// platforms and a (possibly partial) per-platform shasum lookup. Pure so the
/// archive shaping is exercised without any network I/O.
fn assemble_mirror_archives(
    version: &str,
    platforms: &[(String, String)],
    shasums: &std::collections::HashMap<(String, String), String>,
) -> serde_json::Value {
    let mut archives = serde_json::Map::new();
    for (os, arch) in platforms {
        let url = build_mirror_archive_url(version, os, arch);
        let hashes = shasums
            .get(&(os.clone(), arch.clone()))
            .cloned()
            .map(|h| vec![h])
            .unwrap_or_default();
        archives.insert(
            format!("{}_{}", os, arch),
            build_mirror_archive_entry(&url, hashes),
        );
    }
    serde_json::json!({ "archives": serde_json::Value::Object(archives) })
}

/// Extract the upstream `download_url` from a registry download document.
fn extract_download_url(download: &serde_json::Value) -> Option<&str> {
    download
        .get("download_url")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
}

/// 404 response for an unknown provider/version on the mirror.
fn mirror_not_found(namespace: &str, type_name: &str, version: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        format!("Provider {}/{} {} not found", namespace, type_name, version),
    )
        .into_response()
}

/// Parse the version from a mirror `<version>.json` filename, returning the
/// `404` error response when the document name is not recognized.
#[allow(clippy::result_large_err)] // Response-as-error matches the handler convention in this module.
fn version_from_mirror_file(version_file: &str) -> Result<&str, Response> {
    parse_mirror_version_file(version_file).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("Unrecognized mirror document: {}", version_file),
        )
            .into_response()
    })
}

/// Resolve the upstream archive URL from a registry download document, mapping
/// a missing/empty `download_url` to the appropriate `502` response.
#[allow(clippy::result_large_err)] // Response-as-error matches the handler convention in this module.
fn resolve_archive_url(download: &serde_json::Value) -> Result<&str, Response> {
    extract_download_url(download).ok_or_else(|| {
        (
            StatusCode::BAD_GATEWAY,
            "Upstream registry did not provide a download_url".to_string(),
        )
            .into_response()
    })
}

/// Derive a scheme-less proxy-cache path for a network-mirror archive
/// download from the registry-provided (frequently absolute) `download_url`.
///
/// `archive_url` is used directly as the upstream fetch target (absolute
/// `http(s)://` URLs pass through `ProxyService::build_upstream_url`
/// unchanged), but it cannot double as the proxy-cache path: the `https://`
/// scheme's `//` trips `ProxyService::validate_cache_path`'s empty-segment
/// guard. This instead derives a canonical
/// `<namespace>/<type>/<version>/<os>/<arch>/<filename>` path from the
/// archive URL's own filename, keeping cache keys stable regardless of which
/// host or path shape the upstream registry serves archives from (#1998).
///
/// Parses `archive_url` instead of splitting the raw string so that a signed
/// URL's query string (e.g. `?X-Amz-Signature=...`) or fragment is dropped
/// along with everything else outside the path: query material must never
/// end up embedded in a proxy-cache object key.
fn mirror_archive_cache_path(
    namespace: &str,
    type_name: &str,
    version: &str,
    os: &str,
    arch: &str,
    archive_url: &str,
) -> String {
    let filename = reqwest::Url::parse(archive_url)
        .ok()
        .and_then(|url| url.path_segments()?.next_back().map(str::to_string))
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "provider.zip".to_string());

    format!("{namespace}/{type_name}/{version}/{os}/{arch}/{filename}")
}

/// Validated context for serving a network-mirror request against a remote
/// Terraform repository: the resolved repo plus its upstream registry URL.
struct MirrorRemote<'a> {
    repo: RepoInfo,
    upstream_url: String,
    proxy: &'a crate::services::proxy_service::ProxyService,
}

/// Resolve a Terraform repo for the network-mirror protocol, asserting it is a
/// remote repo configured for proxying. Centralizes the guard shared by all
/// three mirror handlers so the logic exists once (#1566).
async fn resolve_mirror_remote<'a>(
    state: &'a SharedState,
    repo_key: &str,
) -> Result<MirrorRemote<'a>, Response> {
    let repo = resolve_terraform_repo(&state.db, repo_key).await?;

    let guard = classify_mirror_repo(
        repo.repo_type == RepositoryType::Remote,
        repo.upstream_url.is_some(),
        state.proxy_service.is_some(),
    );
    if guard != MirrorGuard::Ok {
        return Err(mirror_guard_error(guard));
    }

    // Both unwraps are guaranteed by the guard above.
    let upstream_url = repo.upstream_url.clone().unwrap();
    let proxy = state.proxy_service.as_ref().unwrap();
    Ok(MirrorRemote {
        repo,
        upstream_url,
        proxy,
    })
}

/// Fetch a registry-protocol document from the upstream and parse it as JSON,
/// mapping any failure to the appropriate client response.
async fn fetch_upstream_json(
    remote: &MirrorRemote<'_>,
    repo_key: &str,
    path: &str,
) -> Result<serde_json::Value, Response> {
    let (content, _ct) = proxy_helpers::proxy_fetch(
        remote.proxy,
        remote.repo.id,
        repo_key,
        &remote.upstream_url,
        path,
    )
    .await?;
    serde_json::from_slice(&content).map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("Invalid upstream registry response: {}", e),
        )
            .into_response()
    })
}

/// Wrap a serialized JSON value in a 200 `application/json` response.
fn json_ok_response(value: &serde_json::Value) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(value).unwrap()))
        .unwrap()
}

/// GET /:repo_key/:hostname/:namespace/:type/index.json — mirror version list.
async fn mirror_index(
    State(state): State<SharedState>,
    Path((repo_key, _hostname, namespace, type_name)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let remote = resolve_mirror_remote(&state, &repo_key).await?;
    let path = build_registry_versions_path(&namespace, &type_name);
    let registry = fetch_upstream_json(&remote, &repo_key, &path).await?;
    Ok(json_ok_response(&registry_versions_to_mirror_index(
        &registry,
    )))
}

/// GET /:repo_key/:hostname/:namespace/:type/<version>.json — mirror packages.
async fn mirror_version(
    State(state): State<SharedState>,
    Path((repo_key, _hostname, namespace, type_name, version_file)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, Response> {
    let version = version_from_mirror_file(&version_file)?;
    let remote = resolve_mirror_remote(&state, &repo_key).await?;

    // Discover the platforms this version ships for via the registry's
    // `versions` document.
    let versions_path = build_registry_versions_path(&namespace, &type_name);
    let registry = fetch_upstream_json(&remote, &repo_key, &versions_path).await?;

    let platforms = platforms_for_version(&registry, version);
    if platforms.is_empty() {
        return Err(mirror_not_found(&namespace, &type_name, version));
    }

    // Best-effort: pull each per-platform download doc to obtain the shasum.
    // A failed/absent shasum just omits the hash (Terraform downloads without
    // pinning) rather than failing the whole request.
    let mut shasums = std::collections::HashMap::new();
    for (os, arch) in &platforms {
        let dl_path = build_registry_download_path(&namespace, &type_name, version, os, arch);
        if let Some(hash) = fetch_upstream_json(&remote, &repo_key, &dl_path)
            .await
            .ok()
            .as_ref()
            .and_then(registry_shasum_to_mirror_hash)
        {
            shasums.insert((os.clone(), arch.clone()), hash);
        }
    }

    Ok(json_ok_response(&assemble_mirror_archives(
        version, &platforms, &shasums,
    )))
}

/// GET /:repo_key/:hostname/:namespace/:type/:version/download/:os/:arch —
/// stream the provider archive for a platform (referenced by `mirror_version`).
async fn mirror_download(
    State(state): State<SharedState>,
    Path((repo_key, _hostname, namespace, type_name, version, os, arch)): Path<(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, Response> {
    let remote = resolve_mirror_remote(&state, &repo_key).await?;

    // Resolve the upstream registry download document to learn the real
    // archive URL, then stream that archive back through the proxy (cached).
    let dl_path = build_registry_download_path(&namespace, &type_name, &version, &os, &arch);
    let download = fetch_upstream_json(&remote, &repo_key, &dl_path).await?;

    let archive_url = resolve_archive_url(&download)?;

    // A malicious/compromised upstream registry could return an internal
    // address (e.g. the cloud metadata endpoint) as `download_url`. Validate
    // it against the same anti-SSRF policy used for other registries'
    // registry-discovered download URLs (see cargo.rs's `download` handler
    // and pypi.rs's `find_upstream_url_for_file` path) before fetching it.
    validate_outbound_url(archive_url, "Terraform upstream archive URL").map_err(|e| {
        // Deliberately omit `archive_url` from this log line: it is
        // registry-controlled and frequently a signed URL (e.g.
        // `?X-Amz-Signature=...`), so logging it verbatim would leak
        // credential-bearing query material. `e` already names the
        // specific blocked host/IP without echoing the query string.
        tracing::warn!(
            "SSRF check rejected upstream download_url for {}/{} {} {}/{}: {}",
            namespace,
            type_name,
            version,
            os,
            arch,
            e
        );
        (
            StatusCode::BAD_GATEWAY,
            format!("Upstream registry returned a disallowed download_url: {e}"),
        )
            .into_response()
    })?;

    // `archive_url` is frequently an absolute `https://` URL (#1998): fine as
    // the upstream fetch target (absolute URLs pass through unchanged), but
    // not as the proxy-cache path (its `https://` scheme trips the
    // empty-segment guard). Fetch from `archive_url` but cache under a
    // derived, scheme-less canonical path instead.
    let cache_path =
        mirror_archive_cache_path(&namespace, &type_name, &version, &os, &arch, archive_url);

    proxy_helpers::proxy_fetch_streaming_response_with_cache_key(
        remote.proxy,
        remote.repo.id,
        &repo_key,
        &remote.upstream_url,
        archive_url,
        &cache_path,
        "application/zip",
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

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
            key: String::new(),
            storage_path: "/data/terraform".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: Some("https://registry.terraform.io".to_string()),
            promotion_only: false,
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
            key: String::new(),
            storage_path: "/data/tf".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: None,
            promotion_only: false,
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

    // -----------------------------------------------------------------------
    // Provider Network Mirror Protocol (#1566)
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_mirror_version_file_valid() {
        assert_eq!(parse_mirror_version_file("2.0.0.json"), Some("2.0.0"));
        assert_eq!(
            parse_mirror_version_file("1.2.3-rc.1.json"),
            Some("1.2.3-rc.1")
        );
    }

    #[test]
    fn test_parse_mirror_version_file_invalid() {
        assert_eq!(parse_mirror_version_file("index.json"), Some("index"));
        assert_eq!(parse_mirror_version_file("2.0.0"), None);
        assert_eq!(parse_mirror_version_file("foo.txt"), None);
    }

    #[test]
    fn test_build_registry_versions_path() {
        assert_eq!(
            build_registry_versions_path("carlpett", "sops"),
            "v1/providers/carlpett/sops/versions"
        );
    }

    #[test]
    fn test_build_registry_download_path() {
        assert_eq!(
            build_registry_download_path("carlpett", "sops", "1.0.0", "linux", "amd64"),
            "v1/providers/carlpett/sops/1.0.0/download/linux/amd64"
        );
    }

    #[test]
    fn test_build_mirror_archive_url() {
        assert_eq!(
            build_mirror_archive_url("1.0.0", "linux", "amd64"),
            "1.0.0/download/linux/amd64"
        );
    }

    #[test]
    fn test_registry_versions_to_mirror_index() {
        let registry = serde_json::json!({
            "versions": [
                { "version": "0.7.2", "protocols": ["5.0"], "platforms": [] },
                { "version": "1.0.0", "protocols": ["5.0"], "platforms": [] },
            ]
        });
        let mirror = registry_versions_to_mirror_index(&registry);
        let versions = mirror["versions"].as_object().unwrap();
        assert_eq!(versions.len(), 2);
        assert!(versions.contains_key("0.7.2"));
        assert!(versions.contains_key("1.0.0"));
        // Each value must be an (empty) object per the mirror spec.
        assert!(versions["1.0.0"].is_object());
    }

    #[test]
    fn test_registry_versions_to_mirror_index_empty() {
        let mirror = registry_versions_to_mirror_index(&serde_json::json!({}));
        assert!(mirror["versions"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_platforms_for_version() {
        let registry = serde_json::json!({
            "versions": [
                {
                    "version": "1.0.0",
                    "platforms": [
                        { "os": "linux", "arch": "amd64" },
                        { "os": "darwin", "arch": "arm64" }
                    ]
                },
                {
                    "version": "2.0.0",
                    "platforms": [ { "os": "windows", "arch": "amd64" } ]
                }
            ]
        });
        let p = platforms_for_version(&registry, "1.0.0");
        assert_eq!(
            p,
            vec![
                ("linux".to_string(), "amd64".to_string()),
                ("darwin".to_string(), "arm64".to_string()),
            ]
        );
        let p2 = platforms_for_version(&registry, "2.0.0");
        assert_eq!(p2, vec![("windows".to_string(), "amd64".to_string())]);
        assert!(platforms_for_version(&registry, "9.9.9").is_empty());
    }

    #[test]
    fn test_platforms_for_version_edge_branches() {
        // Version entry without a `platforms` key, malformed entries, and a
        // platform missing `arch` are all skipped without panicking.
        let registry = serde_json::json!({
            "versions": [
                { "version": "1.0.0" },
                { "version": "1.0.0", "platforms": "not-an-array" },
                { "version": "1.0.0", "platforms": [
                    { "os": "linux" },
                    { "arch": "amd64" },
                    { "os": "linux", "arch": "amd64" }
                ] }
            ]
        });
        assert_eq!(
            platforms_for_version(&registry, "1.0.0"),
            vec![("linux".to_string(), "amd64".to_string())]
        );
        // No `versions` array at all.
        assert!(platforms_for_version(&serde_json::json!({}), "1.0.0").is_empty());
    }

    #[test]
    fn test_registry_shasum_to_mirror_hash() {
        let dl = serde_json::json!({ "shasum": "abc123" });
        assert_eq!(
            registry_shasum_to_mirror_hash(&dl),
            Some("zh:abc123".to_string())
        );
        assert_eq!(
            registry_shasum_to_mirror_hash(&serde_json::json!({ "shasum": "" })),
            None
        );
        assert_eq!(registry_shasum_to_mirror_hash(&serde_json::json!({})), None);
    }

    #[test]
    fn test_build_mirror_archive_entry() {
        let with_hash =
            build_mirror_archive_entry("1.0.0/download/linux/amd64", vec!["zh:abc".to_string()]);
        assert_eq!(with_hash["url"], "1.0.0/download/linux/amd64");
        assert_eq!(with_hash["hashes"][0], "zh:abc");

        let no_hash = build_mirror_archive_entry("u", vec![]);
        assert_eq!(no_hash["url"], "u");
        assert!(no_hash.get("hashes").is_none());
    }

    #[test]
    fn test_classify_mirror_repo() {
        assert_eq!(classify_mirror_repo(true, true, true), MirrorGuard::Ok);
        assert_eq!(
            classify_mirror_repo(false, true, true),
            MirrorGuard::NotRemote
        );
        // Type guard takes precedence over proxyability.
        assert_eq!(
            classify_mirror_repo(false, false, false),
            MirrorGuard::NotRemote
        );
        assert_eq!(
            classify_mirror_repo(true, false, true),
            MirrorGuard::NotProxyable
        );
        assert_eq!(
            classify_mirror_repo(true, true, false),
            MirrorGuard::NotProxyable
        );
    }

    #[test]
    fn test_mirror_guard_error_status() {
        use axum::http::StatusCode;
        assert_eq!(
            mirror_guard_error(MirrorGuard::NotRemote).status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            mirror_guard_error(MirrorGuard::NotProxyable).status(),
            StatusCode::NOT_FOUND
        );
        // Ok variant maps to a (degenerate) 404 too; callers never hit it.
        assert_eq!(
            mirror_guard_error(MirrorGuard::Ok).status(),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn test_extract_download_url() {
        let dl = serde_json::json!({ "download_url": "https://example/p.zip" });
        assert_eq!(extract_download_url(&dl), Some("https://example/p.zip"));
        assert_eq!(
            extract_download_url(&serde_json::json!({ "download_url": "" })),
            None
        );
        assert_eq!(extract_download_url(&serde_json::json!({})), None);
        assert_eq!(
            extract_download_url(&serde_json::json!({ "download_url": 5 })),
            None
        );
    }

    #[test]
    fn test_mirror_not_found_status() {
        use axum::http::StatusCode;
        let resp = mirror_not_found("carlpett", "sops", "1.0.0");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_version_from_mirror_file() {
        assert_eq!(version_from_mirror_file("2.0.0.json").unwrap(), "2.0.0");
        let err = version_from_mirror_file("nope").unwrap_err();
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_resolve_archive_url() {
        let ok = serde_json::json!({ "download_url": "https://x/p.zip" });
        assert_eq!(resolve_archive_url(&ok).unwrap(), "https://x/p.zip");

        let err = resolve_archive_url(&serde_json::json!({})).unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_GATEWAY);

        let err2 = resolve_archive_url(&serde_json::json!({ "download_url": "" })).unwrap_err();
        assert_eq!(err2.status(), StatusCode::BAD_GATEWAY);
    }

    /// Regression guard for the SSRF gap found in review of #1998: a
    /// malicious/compromised upstream Terraform registry must not be able to
    /// redirect `mirror_download` at an internal address via `download_url`.
    /// Mirrors `test_build_download_url_rejects_internal_addresses` in
    /// cargo.rs — one realistic bypass case pins the integration; the full
    /// bypass matrix lives in `api::validation::tests`.
    #[test]
    fn test_resolve_archive_url_rejects_ssrf_targets() {
        let metadata =
            serde_json::json!({ "download_url": "http://169.254.169.254/latest/meta-data/" });
        let archive_url = resolve_archive_url(&metadata).unwrap();
        let err = validate_outbound_url(archive_url, "Terraform upstream archive URL")
            .expect_err("cloud metadata download_url must be rejected");
        assert!(
            err.to_string().contains("private/internal network")
                || err.to_string().contains("not allowed"),
            "expected SSRF rejection reason in error message, got: {err}"
        );

        let legit = serde_json::json!({
            "download_url": "https://releases.hashicorp.com/terraform-provider-null/3.2.3/terraform-provider-null_3.2.3_linux_arm64.zip"
        });
        let archive_url = resolve_archive_url(&legit).unwrap();
        assert!(
            validate_outbound_url(archive_url, "Terraform upstream archive URL").is_ok(),
            "legitimate external archive URL should be accepted"
        );
    }

    #[test]
    fn test_mirror_archive_cache_path_strips_signed_url_query_string() {
        // A signed archive URL (e.g. an S3 presigned link) must not leak its
        // query-string credentials into the derived cache path / storage
        // object key.
        let cache_path = mirror_archive_cache_path(
            "hashicorp",
            "null",
            "3.2.3",
            "linux",
            "arm64",
            "https://provider-bucket.s3.amazonaws.com/terraform-provider-null_3.2.3_linux_arm64.zip\
             ?X-Amz-Signature=deadbeef&X-Amz-Credential=AKIAEXAMPLE%2F20260630%2Fus-east-1",
        );
        assert_eq!(
            cache_path,
            "hashicorp/null/3.2.3/linux/arm64/terraform-provider-null_3.2.3_linux_arm64.zip"
        );
        assert!(
            !cache_path.contains("X-Amz"),
            "cache path must not contain signed-URL query material, got: {cache_path}"
        );
    }

    #[test]
    fn test_mirror_archive_cache_path_hashicorp_release_url() {
        // Reproduces the exact #1998 repro: an absolute releases.hashicorp.com
        // archive URL must derive a clean, scheme-less canonical cache path.
        let cache_path = mirror_archive_cache_path(
            "hashicorp",
            "null",
            "3.2.3",
            "linux",
            "arm64",
            "https://releases.hashicorp.com/terraform-provider-null/3.2.3/terraform-provider-null_3.2.3_linux_arm64.zip",
        );
        assert_eq!(
            cache_path,
            "hashicorp/null/3.2.3/linux/arm64/terraform-provider-null_3.2.3_linux_arm64.zip"
        );
    }

    #[test]
    fn test_mirror_archive_cache_path_third_party_host() {
        // OpenTofu-style / third-party mirrors (e.g. a provider hosted on
        // GitHub Releases) serve from a different host and path shape; only
        // the archive's filename should influence the derived cache path.
        let cache_path = mirror_archive_cache_path(
            "carlpett",
            "sops",
            "1.0.0",
            "darwin",
            "arm64",
            "https://github.com/carlpett/terraform-provider-sops/releases/download/v1.0.0/terraform-provider-sops_1.0.0_darwin_arm64.zip",
        );
        assert_eq!(
            cache_path,
            "carlpett/sops/1.0.0/darwin/arm64/terraform-provider-sops_1.0.0_darwin_arm64.zip"
        );
    }

    #[test]
    fn test_mirror_archive_cache_path_trailing_slash_falls_back_to_default_filename() {
        // A URL ending in `/` has no filename segment; falling back to a
        // fixed name avoids producing an empty final path segment.
        let cache_path = mirror_archive_cache_path(
            "hashicorp",
            "null",
            "3.2.3",
            "linux",
            "arm64",
            "https://example.com/download/",
        );
        assert_eq!(cache_path, "hashicorp/null/3.2.3/linux/arm64/provider.zip");
    }

    #[test]
    fn test_mirror_archive_cache_path_accepted_by_cache_storage_key_1998() {
        // Regression guard for #1998: the raw absolute archive URL must NOT
        // be usable as a proxy-cache path (its `https://` scheme's `//`
        // trips the empty-segment guard), but the derived cache path must be.
        use crate::services::proxy_service::ProxyService;

        let archive_url = "https://releases.hashicorp.com/terraform-provider-null/3.2.3/terraform-provider-null_3.2.3_linux_arm64.zip";

        let raw_err = ProxyService::cache_storage_key("tf-mirror", archive_url).unwrap_err();
        assert!(
            raw_err.to_string().contains("empty segments"),
            "raw absolute archive URL must be rejected as a cache path, got: {}",
            raw_err
        );

        let cache_path =
            mirror_archive_cache_path("hashicorp", "null", "3.2.3", "linux", "arm64", archive_url);
        ProxyService::cache_storage_key("tf-mirror", &cache_path)
            .expect("derived cache path must be a valid proxy-cache path");
    }

    #[test]
    fn test_json_ok_response_status_and_type() {
        let resp = json_ok_response(&serde_json::json!({ "a": 1 }));
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }

    #[test]
    fn test_assemble_mirror_archives_with_and_without_hashes() {
        let platforms = vec![
            ("linux".to_string(), "amd64".to_string()),
            ("darwin".to_string(), "arm64".to_string()),
        ];
        let mut shasums = std::collections::HashMap::new();
        shasums.insert(
            ("linux".to_string(), "amd64".to_string()),
            "zh:abc".to_string(),
        );
        // darwin/arm64 intentionally has no shasum.
        let out = assemble_mirror_archives("1.0.0", &platforms, &shasums);
        let archives = out["archives"].as_object().unwrap();
        assert_eq!(archives.len(), 2);

        let lin = &archives["linux_amd64"];
        assert_eq!(lin["url"], "1.0.0/download/linux/amd64");
        assert_eq!(lin["hashes"][0], "zh:abc");

        let dar = &archives["darwin_arm64"];
        assert_eq!(dar["url"], "1.0.0/download/darwin/arm64");
        assert!(dar.get("hashes").is_none());
    }

    #[test]
    fn test_assemble_mirror_archives_empty() {
        let out = assemble_mirror_archives("1.0.0", &[], &std::collections::HashMap::new());
        assert!(out["archives"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_full_mirror_version_assembly_for_sops() {
        // Mirrors the carlpett/sops flow from #1566 end to end (pure parts):
        // registry versions -> platforms -> archives doc.
        let registry = serde_json::json!({
            "versions": [
                { "version": "1.0.0", "protocols": ["5.0"],
                  "platforms": [ { "os": "linux", "arch": "amd64" } ] }
            ]
        });
        let platforms = platforms_for_version(&registry, "1.0.0");
        assert_eq!(platforms, vec![("linux".to_string(), "amd64".to_string())]);

        let download = serde_json::json!({
            "download_url": "https://github.com/carlpett/terraform-provider-sops/.../sops_1.0.0_linux_amd64.zip",
            "shasum": "deadbeef"
        });
        let mut shasums = std::collections::HashMap::new();
        if let Some(h) = registry_shasum_to_mirror_hash(&download) {
            shasums.insert(("linux".to_string(), "amd64".to_string()), h);
        }
        let archives = assemble_mirror_archives("1.0.0", &platforms, &shasums);
        assert_eq!(
            archives["archives"]["linux_amd64"]["url"],
            "1.0.0/download/linux/amd64"
        );
        assert_eq!(
            archives["archives"]["linux_amd64"]["hashes"][0],
            "zh:deadbeef"
        );
        assert_eq!(
            extract_download_url(&download),
            Some("https://github.com/carlpett/terraform-provider-sops/.../sops_1.0.0_linux_amd64.zip")
        );
    }

    #[test]
    fn test_router_builds_without_route_conflicts() {
        // axum panics at construction time on overlapping routes. Building the
        // router proves the network-mirror routes (#1566) coexist with the
        // existing registry routes.
        let _router: Router<SharedState> = router();
    }

    #[test]
    fn test_full_mirror_index_translation_roundtrip() {
        // End-to-end shape check mirroring what the upstream registry returns
        // for carlpett/sops (the provider from issue #1566).
        let registry = serde_json::json!({
            "versions": [
                { "version": "0.7.2", "protocols": ["5.0"],
                  "platforms": [ { "os": "linux", "arch": "amd64" } ] }
            ]
        });
        let index = registry_versions_to_mirror_index(&registry);
        assert_eq!(
            serde_json::to_value(&index).unwrap(),
            serde_json::json!({ "versions": { "0.7.2": {} } })
        );
    }
}
