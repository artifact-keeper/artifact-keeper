//! Chef Supermarket API handlers.
//!
//! Implements the endpoints required for Chef cookbook management.
//!
//! Routes are mounted at `/chef/{repo_key}/...`:
//!   GET  /chef/{repo_key}/api/v1/cookbooks                                  - List cookbooks
//!   GET  /chef/{repo_key}/api/v1/cookbooks/{name}                           - Cookbook info
//!   GET  /chef/{repo_key}/api/v1/cookbooks/{name}/versions/{version}        - Version info
//!   GET  /chef/{repo_key}/api/v1/cookbooks/{name}/versions/{version}/download - Download tarball
//!   POST /chef/{repo_key}/api/v1/cookbooks                                  - Upload cookbook

use axum::body::Body;
use axum::extract::{Multipart, Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Extension;
use axum::Router;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic, AuthExtension};
use crate::api::SharedState;
use crate::formats::chef::ChefHandler;
use crate::models::repository::RepositoryType;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        .route(
            "/:repo_key/api/v1/cookbooks",
            get(list_cookbooks).post(upload_cookbook),
        )
        .route("/:repo_key/api/v1/cookbooks/:name", get(cookbook_info))
        .route(
            "/:repo_key/api/v1/cookbooks/:name/versions/:version",
            get(version_info),
        )
        .route(
            "/:repo_key/api/v1/cookbooks/:name/versions/:version/download",
            get(download_cookbook),
        )
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_chef_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["chef"], "a Chef").await
}

// ---------------------------------------------------------------------------
// GET /chef/{repo_key}/api/v1/cookbooks — List cookbooks
// ---------------------------------------------------------------------------

async fn list_cookbooks(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_chef_repo(&state.db, &repo_key).await?;

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

    let items: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            let name = a.name.clone();
            let version = a.version.clone().unwrap_or_default();
            serde_json::json!({
                "cookbook_name": name,
                "cookbook_maintainer": "",
                "cookbook_description": "",
                "cookbook": format!("/chef/{}/api/v1/cookbooks/{}", repo_key, name),
                "latest_version": version,
            })
        })
        .collect();

    let json = serde_json::json!({
        "start": 0,
        "total": items.len(),
        "items": items,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /chef/{repo_key}/api/v1/cookbooks/{name} — Cookbook info
// ---------------------------------------------------------------------------

async fn cookbook_info(
    State(state): State<SharedState>,
    Path((repo_key, name)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_chef_repo(&state.db, &repo_key).await?;

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
        name
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
        return Err((StatusCode::NOT_FOUND, "Cookbook not found").into_response());
    }

    let versions: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            let version = a.version.clone().unwrap_or_default();
            serde_json::json!({
                "version": version,
                "url": format!(
                    "/chef/{}/api/v1/cookbooks/{}/versions/{}",
                    repo_key, name, version
                ),
            })
        })
        .collect();

    let latest_version = artifacts[0].version.clone().unwrap_or_default();
    let description = artifacts[0]
        .metadata
        .as_ref()
        .and_then(|m| m.get("description"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let json = serde_json::json!({
        "name": name,
        "maintainer": "",
        "description": description,
        "latest_version": latest_version,
        "versions": versions,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /chef/{repo_key}/api/v1/cookbooks/{name}/versions/{version} — Version info
// ---------------------------------------------------------------------------

async fn version_info(
    State(state): State<SharedState>,
    Path((repo_key, name, version)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_chef_repo(&state.db, &repo_key).await?;

    let artifact = sqlx::query!(
        r#"
        SELECT a.id, a.name, a.version, a.size_bytes, a.checksum_sha256,
               am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND LOWER(a.name) = LOWER($2)
          AND a.version = $3
        LIMIT 1
        "#,
        repo.id,
        name,
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Cookbook version not found").into_response())?;

    let download_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM download_statistics WHERE artifact_id = $1",
        artifact.id
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(Some(0))
    .unwrap_or(0);

    let json = serde_json::json!({
        "cookbook": name,
        "version": version,
        "file": format!(
            "/chef/{}/api/v1/cookbooks/{}/versions/{}/download",
            repo_key, name, version
        ),
        "tarball_file_size": artifact.size_bytes,
        "sha256": artifact.checksum_sha256,
        "downloads": download_count,
        "metadata": artifact.metadata.unwrap_or(serde_json::json!({})),
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /chef/{repo_key}/api/v1/cookbooks/{name}/versions/{version}/download
// ---------------------------------------------------------------------------

async fn download_cookbook(
    State(state): State<SharedState>,
    Path((repo_key, name, version)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_chef_repo(&state.db, &repo_key).await?;

    let artifact = sqlx::query!(
        r#"
        SELECT id, storage_key, name, version, size_bytes
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND LOWER(name) = LOWER($2)
          AND version = $3
        LIMIT 1
        "#,
        repo.id,
        name,
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Cookbook version not found").into_response());

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == RepositoryType::Remote {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let upstream_path =
                        format!("api/v1/cookbooks/{}/versions/{}/download", name, version);
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
                let upstream_path =
                    format!("api/v1/cookbooks/{}/versions/{}/download", name, version);
                let name_clone = name.clone();
                let version_clone = version.clone();
                let (content, content_type) = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    state.proxy_service.as_deref(),
                    repo.id,
                    &upstream_path,
                    |member_id, location| {
                        let db = db.clone();
                        let state = state.clone();
                        let n = name_clone.clone();
                        let v = version_clone.clone();
                        async move {
                            proxy_helpers::local_fetch_by_name_version(
                                &db, &state, member_id, &location, &n, &v,
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
                        content_type.unwrap_or_else(|| "application/gzip".to_string()),
                    )
                    .header(CONTENT_LENGTH, content.len().to_string())
                    .body(Body::from(content))
                    .unwrap());
            }

            return Err(not_found);
        }
    };

    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    // Check quarantine status before serving
    crate::services::quarantine_service::check_artifact_download(&state.db, artifact.id)
        .await
        .map_err(|e| e.into_response())?;

    let content = storage.get(&artifact.storage_key).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    let _ = sqlx::query!(
        "INSERT INTO download_statistics (artifact_id, ip_address) VALUES ($1, '0.0.0.0')",
        artifact.id
    )
    .execute(&state.db)
    .await;

    let filename = format!("{}-{}.tar.gz", name, version);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/gzip")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, content.len().to_string())
        .body(Body::from(content))
        .unwrap())
}

// ---------------------------------------------------------------------------
// POST /chef/{repo_key}/api/v1/cookbooks — Upload cookbook (multipart)
// ---------------------------------------------------------------------------

async fn upload_cookbook(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    mut multipart: Multipart,
) -> Result<Response, Response> {
    let user_id = require_auth_basic(auth, "chef")?.user_id;
    let repo = resolve_chef_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    let mut tarball: Option<bytes::Bytes> = None;
    let mut cookbook_json: Option<serde_json::Value> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Multipart error: {}", e)).into_response())?
    {
        let field_name = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
            "tarball" => {
                tarball = Some(field.bytes().await.map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Failed to read tarball: {}", e),
                    )
                        .into_response()
                })?);
            }
            "cookbook" => {
                let data = field.bytes().await.map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Failed to read cookbook JSON: {}", e),
                    )
                        .into_response()
                })?;
                cookbook_json = Some(serde_json::from_slice(&data).map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Invalid cookbook JSON: {}", e),
                    )
                        .into_response()
                })?);
            }
            _ => {}
        }
    }

    let tarball = tarball
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing tarball field").into_response())?;

    if tarball.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty tarball").into_response());
    }

    // Extract name and version from cookbook JSON or validate the tarball
    let (cookbook_name, cookbook_version) = if let Some(ref json) = cookbook_json {
        let name = json
            .get("cookbook_name")
            .or_else(|| json.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let version = json
            .get("cookbook_version")
            .or_else(|| json.get("version"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        (name, version)
    } else {
        // Validate via format handler as fallback
        let path = "api/v1/cookbooks/unknown/versions/0.0.0";
        let _ = ChefHandler::parse_path(path);
        return Err((StatusCode::BAD_REQUEST, "Missing cookbook metadata JSON").into_response());
    };

    if cookbook_name.is_empty() || cookbook_version.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Cookbook name and version are required",
        )
            .into_response());
    }

    // Validate via format handler
    let validate_path = format!(
        "api/v1/cookbooks/{}/versions/{}",
        cookbook_name, cookbook_version
    );
    let _ = ChefHandler::parse_path(&validate_path).map_err(|e| {
        (StatusCode::BAD_REQUEST, format!("Invalid cookbook: {}", e)).into_response()
    })?;

    let filename = format!("{}-{}.tar.gz", cookbook_name, cookbook_version);

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&tarball);
    let computed_sha256 = format!("{:x}", hasher.finalize());

    let artifact_path = format!("{}/{}/{}", cookbook_name, cookbook_version, filename);

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
        return Err((StatusCode::CONFLICT, "Cookbook version already exists").into_response());
    }

    super::cleanup_soft_deleted_artifact(&state.db, repo.id, &artifact_path).await;

    // Store the file
    let storage_key = format!("chef/{}/{}/{}", cookbook_name, cookbook_version, filename);
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    storage
        .put(&storage_key, tarball.clone())
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Storage error: {}", e),
            )
                .into_response()
        })?;

    let chef_metadata = serde_json::json!({
        "cookbook_name": cookbook_name,
        "cookbook_version": cookbook_version,
        "filename": filename,
        "cookbook_json": cookbook_json,
    });

    let size_bytes = tarball.len() as i64;

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
        cookbook_name,
        cookbook_version,
        size_bytes,
        computed_sha256,
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

    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'chef', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        chef_metadata,
    )
    .execute(&state.db)
    .await;

    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
    .await;

    info!(
        "Chef upload: {} {} ({}) to repo {}",
        cookbook_name, cookbook_version, filename, repo_key
    );

    let response_json = serde_json::json!({
        "uri": format!(
            "/chef/{}/api/v1/cookbooks/{}/versions/{}",
            repo_key, cookbook_name, cookbook_version
        ),
    });

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response_json).unwrap()))
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // extract_credentials
    // -----------------------------------------------------------------------
    // -----------------------------------------------------------------------
    // Format-specific logic: filename, artifact_path, storage_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_cookbook_filename_format() {
        let name = "apache2";
        let version = "8.0.0";
        let filename = format!("{}-{}.tar.gz", name, version);
        assert_eq!(filename, "apache2-8.0.0.tar.gz");
    }

    #[test]
    fn test_cookbook_artifact_path_format() {
        let name = "nginx";
        let version = "12.0.0";
        let filename = format!("{}-{}.tar.gz", name, version);
        let artifact_path = format!("{}/{}/{}", name, version, filename);
        assert_eq!(artifact_path, "nginx/12.0.0/nginx-12.0.0.tar.gz");
    }

    #[test]
    fn test_cookbook_storage_key_format() {
        let name = "mysql";
        let version = "5.0.0";
        let filename = format!("{}-{}.tar.gz", name, version);
        let storage_key = format!("chef/{}/{}/{}", name, version, filename);
        assert_eq!(storage_key, "chef/mysql/5.0.0/mysql-5.0.0.tar.gz");
    }

    #[test]
    fn test_sha256_computation() {
        let mut hasher = Sha256::new();
        hasher.update(b"cookbook content");
        let result = format!("{:x}", hasher.finalize());
        assert_eq!(result.len(), 64);
    }

    // -----------------------------------------------------------------------
    // RepoInfo struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_info_hosted() {
        let id = uuid::Uuid::new_v4();
        let repo = RepoInfo {
            id,
            key: String::new(),
            storage_path: "/data/chef".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: None,
        };
        assert_eq!(repo.repo_type, "hosted");
        assert!(repo.upstream_url.is_none());
    }

    #[test]
    fn test_repo_info_remote() {
        let repo = RepoInfo {
            id: uuid::Uuid::new_v4(),
            key: String::new(),
            storage_path: "/cache/chef".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "remote".to_string(),
            upstream_url: Some("https://supermarket.chef.io".to_string()),
        };
        assert_eq!(repo.repo_type, "remote");
        assert_eq!(
            repo.upstream_url.as_deref(),
            Some("https://supermarket.chef.io")
        );
    }

    // -----------------------------------------------------------------------
    // Chef metadata JSON construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_chef_metadata_json() {
        let cookbook_name = "apache2";
        let cookbook_version = "8.0.0";
        let filename = format!("{}-{}.tar.gz", cookbook_name, cookbook_version);
        let cookbook_json: Option<serde_json::Value> = Some(serde_json::json!({
            "cookbook_name": cookbook_name,
            "version": cookbook_version,
        }));

        let meta = serde_json::json!({
            "cookbook_name": cookbook_name,
            "cookbook_version": cookbook_version,
            "filename": filename,
            "cookbook_json": cookbook_json,
        });

        assert_eq!(meta["cookbook_name"], "apache2");
        assert_eq!(meta["cookbook_version"], "8.0.0");
        assert_eq!(meta["filename"], "apache2-8.0.0.tar.gz");
        assert!(meta["cookbook_json"].is_object());
    }

    // -----------------------------------------------------------------------
    // Chef API URL format
    // -----------------------------------------------------------------------

    #[test]
    fn test_version_info_url() {
        let repo_key = "chef-local";
        let name = "nginx";
        let version = "12.0.0";
        let url = format!(
            "/chef/{}/api/v1/cookbooks/{}/versions/{}",
            repo_key, name, version
        );
        assert_eq!(
            url,
            "/chef/chef-local/api/v1/cookbooks/nginx/versions/12.0.0"
        );
    }

    #[test]
    fn test_download_url() {
        let repo_key = "chef-local";
        let name = "nginx";
        let version = "12.0.0";
        let url = format!(
            "/chef/{}/api/v1/cookbooks/{}/versions/{}/download",
            repo_key, name, version
        );
        assert_eq!(
            url,
            "/chef/chef-local/api/v1/cookbooks/nginx/versions/12.0.0/download"
        );
    }
}
