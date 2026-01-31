//! Ansible Galaxy API handlers.
//!
//! Implements the endpoints required for Ansible collection management.
//!
//! Routes are mounted at `/ansible/{repo_key}/...`:
//!   GET  /ansible/{repo_key}/api/v3/collections/                                      - List collections
//!   GET  /ansible/{repo_key}/api/v3/collections/{namespace}/{name}/                   - Collection info
//!   GET  /ansible/{repo_key}/api/v3/collections/{namespace}/{name}/versions/           - Version list
//!   GET  /ansible/{repo_key}/api/v3/collections/{namespace}/{name}/versions/{version}/ - Version info
//!   GET  /ansible/{repo_key}/download/{namespace}-{name}-{version}.tar.gz              - Download
//!   POST /ansible/{repo_key}/api/v3/artifacts/collections/                             - Upload collection

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Multipart, Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use base64::Engine;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::SharedState;
use crate::formats::ansible::AnsibleHandler;
use crate::services::auth_service::AuthService;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::StorageBackend;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        .route(
            "/:repo_key/api/v3/collections/",
            get(list_collections),
        )
        .route(
            "/:repo_key/api/v3/collections/:namespace/:name/",
            get(collection_info),
        )
        .route(
            "/:repo_key/api/v3/collections/:namespace/:name/versions/",
            get(version_list),
        )
        .route(
            "/:repo_key/api/v3/collections/:namespace/:name/versions/:version/",
            get(version_info),
        )
        .route(
            "/:repo_key/download/*file_path",
            get(download_collection),
        )
        .route(
            "/:repo_key/api/v3/artifacts/collections/",
            post(upload_collection),
        )
        .layer(DefaultBodyLimit::max(512 * 1024 * 1024)) // 512 MB
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

fn extract_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    if let Some(bearer) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or(v.strip_prefix("bearer ")))
    {
        return Some(("token".to_string(), bearer.to_string()));
    }

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

async fn authenticate(
    db: &PgPool,
    config: &crate::config::Config,
    headers: &HeaderMap,
) -> Result<uuid::Uuid, Response> {
    let (username, password) = extract_credentials(headers).ok_or_else(|| {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Basic realm=\"ansible\"")
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
                .header("WWW-Authenticate", "Basic realm=\"ansible\"")
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

async fn resolve_ansible_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
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
    if fmt != "ansible" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not an Ansible repository (format: {})",
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
// GET /ansible/{repo_key}/api/v3/collections/ — List collections (paginated)
// ---------------------------------------------------------------------------

async fn list_collections(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_ansible_repo(&state.db, &repo_key).await?;

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

    let data: Vec<serde_json::Value> = artifacts
        .iter()
        .filter_map(|a| {
            let name = a.name.clone();
            // Artifact name is stored as "namespace-collection_name"
            let first_hyphen = name.find('-')?;
            let namespace = name[..first_hyphen].to_string();
            let coll_name = name[first_hyphen + 1..].to_string();
            let latest_version = a.version.clone().unwrap_or_default();

            Some(serde_json::json!({
                "namespace": namespace,
                "name": coll_name,
                "href": format!(
                    "/ansible/{}/api/v3/collections/{}/{}/",
                    repo_key, namespace, coll_name
                ),
                "highest_version": {
                    "version": latest_version,
                    "href": format!(
                        "/ansible/{}/api/v3/collections/{}/{}/versions/{}/",
                        repo_key, namespace, coll_name, latest_version
                    ),
                },
            }))
        })
        .collect();

    let json = serde_json::json!({
        "meta": {
            "count": data.len(),
        },
        "links": {
            "first": null,
            "previous": null,
            "next": null,
            "last": null,
        },
        "data": data,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /ansible/{repo_key}/api/v3/collections/{namespace}/{name}/ — Collection info
// ---------------------------------------------------------------------------

async fn collection_info(
    State(state): State<SharedState>,
    Path((repo_key, namespace, name)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_ansible_repo(&state.db, &repo_key).await?;

    // Validate via format handler
    let validate_path = format!("api/v3/collections/{}/{}", namespace, name);
    let _ = AnsibleHandler::parse_path(&validate_path).map_err(|e| {
        (StatusCode::BAD_REQUEST, format!("Invalid path: {}", e)).into_response()
    })?;

    let collection_name = format!("{}-{}", namespace, name);
    let artifact = sqlx::query!(
        r#"
        SELECT a.id, a.name, a.version, a.size_bytes,
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
        collection_name
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Collection not found").into_response())?;

    let latest_version = artifact.version.clone().unwrap_or_default();
    let description = artifact
        .metadata
        .as_ref()
        .and_then(|m| m.get("description"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let json = serde_json::json!({
        "namespace": namespace,
        "name": name,
        "description": description,
        "highest_version": {
            "version": latest_version,
            "href": format!(
                "/ansible/{}/api/v3/collections/{}/{}/versions/{}/",
                repo_key, namespace, name, latest_version
            ),
        },
        "versions_url": format!(
            "/ansible/{}/api/v3/collections/{}/{}/versions/",
            repo_key, namespace, name
        ),
        "download_url": format!(
            "/ansible/{}/download/{}-{}-{}.tar.gz",
            repo_key, namespace, name, latest_version
        ),
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /ansible/{repo_key}/api/v3/collections/{namespace}/{name}/versions/ — Version list
// ---------------------------------------------------------------------------

async fn version_list(
    State(state): State<SharedState>,
    Path((repo_key, namespace, name)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_ansible_repo(&state.db, &repo_key).await?;

    let collection_name = format!("{}-{}", namespace, name);
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
        collection_name
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

    let versions: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            let version = a.version.clone().unwrap_or_default();
            serde_json::json!({
                "version": version,
                "href": format!(
                    "/ansible/{}/api/v3/collections/{}/{}/versions/{}/",
                    repo_key, namespace, name, version
                ),
            })
        })
        .collect();

    let json = serde_json::json!({
        "meta": {
            "count": versions.len(),
        },
        "links": {
            "first": null,
            "previous": null,
            "next": null,
            "last": null,
        },
        "data": versions,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /ansible/{repo_key}/api/v3/collections/{namespace}/{name}/versions/{version}/ — Version info
// ---------------------------------------------------------------------------

async fn version_info(
    State(state): State<SharedState>,
    Path((repo_key, namespace, name, version)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_ansible_repo(&state.db, &repo_key).await?;

    // Validate via format handler
    let validate_path = format!(
        "api/v3/collections/{}/{}/versions/{}",
        namespace, name, version
    );
    let _ = AnsibleHandler::parse_path(&validate_path).map_err(|e| {
        (StatusCode::BAD_REQUEST, format!("Invalid path: {}", e)).into_response()
    })?;

    let collection_name = format!("{}-{}", namespace, name);
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
        collection_name,
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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Collection version not found").into_response())?;

    let download_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM download_statistics WHERE artifact_id = $1",
        artifact.id
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(Some(0))
    .unwrap_or(0);

    let json = serde_json::json!({
        "namespace": namespace,
        "name": name,
        "version": version,
        "download_url": format!(
            "/ansible/{}/download/{}-{}-{}.tar.gz",
            repo_key, namespace, name, version
        ),
        "artifact": {
            "filename": format!("{}-{}-{}.tar.gz", namespace, name, version),
            "size": artifact.size_bytes,
            "sha256": artifact.checksum_sha256,
        },
        "collection": {
            "href": format!(
                "/ansible/{}/api/v3/collections/{}/{}/",
                repo_key, namespace, name
            ),
        },
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
// GET /ansible/{repo_key}/download/{namespace}-{name}-{version}.tar.gz — Download
// ---------------------------------------------------------------------------

async fn download_collection(
    State(state): State<SharedState>,
    Path((repo_key, file_path)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_ansible_repo(&state.db, &repo_key).await?;

    let filename = file_path.trim_start_matches('/');

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
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Collection file not found").into_response())?;

    let storage = FilesystemStorage::new(&repo.storage_path);
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
// POST /ansible/{repo_key}/api/v3/artifacts/collections/ — Upload collection (multipart)
// ---------------------------------------------------------------------------

async fn upload_collection(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_ansible_repo(&state.db, &repo_key).await?;

    let mut tarball: Option<bytes::Bytes> = None;
    let mut collection_json: Option<serde_json::Value> = None;

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Multipart error: {}", e),
        )
            .into_response()
    })? {
        let field_name = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
            "file" => {
                tarball = Some(field.bytes().await.map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Failed to read file: {}", e),
                    )
                        .into_response()
                })?);
            }
            "collection" | "metadata" => {
                let data = field.bytes().await.map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Failed to read collection JSON: {}", e),
                    )
                        .into_response()
                })?;
                collection_json = Some(serde_json::from_slice(&data).map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Invalid collection JSON: {}", e),
                    )
                        .into_response()
                })?);
            }
            _ => {}
        }
    }

    let tarball = tarball.ok_or_else(|| {
        (StatusCode::BAD_REQUEST, "Missing file field").into_response()
    })?;

    if tarball.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty tarball").into_response());
    }

    let (namespace, collection_name, collection_version) = if let Some(ref json) = collection_json {
        let namespace = json
            .get("namespace")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let name = json
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let version = json
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        (namespace, name, version)
    } else {
        return Err(
            (StatusCode::BAD_REQUEST, "Missing collection metadata JSON").into_response(),
        );
    };

    if namespace.is_empty() || collection_name.is_empty() || collection_version.is_empty() {
        return Err(
            (StatusCode::BAD_REQUEST, "Namespace, name, and version are required").into_response(),
        );
    }

    // Validate via format handler
    let validate_path = format!(
        "api/v3/collections/{}/{}/versions/{}",
        namespace, collection_name, collection_version
    );
    let _ = AnsibleHandler::parse_path(&validate_path).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid collection: {}", e),
        )
            .into_response()
    })?;

    let full_name = format!("{}-{}", namespace, collection_name);
    let filename = format!(
        "{}-{}-{}.tar.gz",
        namespace, collection_name, collection_version
    );

    // Compute SHA256
    let mut hasher = Sha256::new();
    hasher.update(&tarball);
    let computed_sha256 = format!("{:x}", hasher.finalize());

    let artifact_path = format!("{}/{}/{}", full_name, collection_version, filename);

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
        return Err(
            (StatusCode::CONFLICT, "Collection version already exists").into_response(),
        );
    }

    // Store the file
    let storage_key = format!(
        "ansible/{}/{}/{}",
        full_name, collection_version, filename
    );
    let storage = FilesystemStorage::new(&repo.storage_path);
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

    let ansible_metadata = serde_json::json!({
        "namespace": namespace,
        "collection_name": collection_name,
        "version": collection_version,
        "filename": filename,
        "collection_json": collection_json,
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
        full_name,
        collection_version,
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
        VALUES ($1, 'ansible', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        ansible_metadata,
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
        "Ansible upload: {}-{} {} ({}) to repo {}",
        namespace, collection_name, collection_version, filename, repo_key
    );

    let response_json = serde_json::json!({
        "namespace": namespace,
        "name": collection_name,
        "version": collection_version,
        "href": format!(
            "/ansible/{}/api/v3/collections/{}/{}/versions/{}/",
            repo_key, namespace, collection_name, collection_version
        ),
        "download_url": format!(
            "/ansible/{}/download/{}",
            repo_key, filename
        ),
    });

    Ok(Response::builder()
        .status(StatusCode::ACCEPTED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response_json).unwrap()))
        .unwrap())
}
