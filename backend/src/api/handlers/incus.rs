//! Incus/LXC Container Image API handlers.
//!
//! Implements endpoints for uploading, downloading, and discovering Incus
//! container and VM images via the SimpleStreams protocol.
//!
//! Routes are mounted at `/incus/{repo_key}/...`:
//!   GET    /incus/{repo_key}/streams/v1/index.json              - SimpleStreams index
//!   GET    /incus/{repo_key}/streams/v1/images.json             - SimpleStreams product catalog
//!   GET    /incus/{repo_key}/images/{product}/{version}/{file}  - Download image file
//!   PUT    /incus/{repo_key}/images/{product}/{version}/{file}  - Upload image file
//!   DELETE /incus/{repo_key}/images/{product}/{version}/{file}  - Delete image file

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use base64::Engine;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};

use crate::api::handlers::proxy_helpers;
use crate::api::SharedState;
use crate::formats::incus::IncusHandler;
use crate::formats::FormatHandler;
use crate::services::auth_service::AuthService;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::StorageBackend;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // SimpleStreams discovery endpoints
        .route("/:repo_key/streams/v1/index.json", get(streams_index))
        .route("/:repo_key/streams/v1/images.json", get(streams_images))
        // Image file operations
        .route(
            "/:repo_key/images/:product/:version/:filename",
            get(download_image).put(upload_image).delete(delete_image),
        )
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024 * 1024)) // 4 GB for container images
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

async fn authenticate(
    db: &PgPool,
    config: &crate::config::Config,
    headers: &HeaderMap,
) -> Result<uuid::Uuid, Response> {
    let (username, password) = extract_basic_credentials(headers).ok_or_else(|| {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Basic realm=\"incus\"")
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
                .header("WWW-Authenticate", "Basic realm=\"incus\"")
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
    #[allow(dead_code)]
    upstream_url: Option<String>,
}

async fn resolve_incus_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    let repo = sqlx::query(
        r#"SELECT id, storage_path, format::text as format, repo_type::text as repo_type, upstream_url
        FROM repositories WHERE key = $1"#,
    )
    .bind(repo_key)
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

    let fmt: String = repo.get("format");
    let fmt = fmt.to_lowercase();
    if fmt != "incus" && fmt != "lxc" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not an Incus/LXC repository (format: {})",
                repo_key, fmt
            ),
        )
            .into_response());
    }

    Ok(RepoInfo {
        id: repo.get("id"),
        storage_path: repo.get("storage_path"),
        repo_type: repo.get("repo_type"),
        upstream_url: repo.get("upstream_url"),
    })
}

// ---------------------------------------------------------------------------
// GET /incus/{repo_key}/streams/v1/index.json -- SimpleStreams index
// ---------------------------------------------------------------------------

async fn streams_index(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    // Verify repo exists and is incus format
    let _repo = resolve_incus_repo(&state.db, &repo_key).await?;

    // Collect product names from artifacts
    let rows = sqlx::query(
        r#"
        SELECT DISTINCT a.name
        FROM artifacts a
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND a.name IS NOT NULL
        ORDER BY a.name ASC
        "#,
    )
    .bind(_repo.id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    let products: Vec<String> = rows.iter().map(|r| r.get::<String, _>("name")).collect();

    let index = serde_json::json!({
        "format": "index:1.0",
        "index": {
            "images": {
                "datatype": "image-downloads",
                "format": "products:1.0",
                "path": format!("streams/v1/images.json"),
                "products": products
            }
        }
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json; charset=utf-8")
        .body(Body::from(serde_json::to_string_pretty(&index).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /incus/{repo_key}/streams/v1/images.json -- SimpleStreams product catalog
// ---------------------------------------------------------------------------

async fn streams_images(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_incus_repo(&state.db, &repo_key).await?;

    // Query all non-deleted artifacts with metadata
    let rows = sqlx::query(
        r#"
        SELECT a.id, a.name, a.version, a.path, a.size_bytes, a.checksum_sha256,
               am.metadata
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND a.name IS NOT NULL
        ORDER BY a.name ASC, a.version ASC
        "#,
    )
    .bind(repo.id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    // Group artifacts by product name, then by version
    let mut products: HashMap<String, serde_json::Value> = HashMap::new();

    for row in &rows {
        let name: String = row.get("name");
        let version: Option<String> = row.get("version");
        let path: String = row.get("path");
        let size_bytes: i64 = row.get("size_bytes");
        let checksum: String = row.get("checksum_sha256");
        let metadata: Option<serde_json::Value> = row.get("metadata");

        let version = match version {
            Some(v) => v,
            None => continue,
        };

        // Extract architecture and other info from metadata
        let arch = metadata
            .as_ref()
            .and_then(|m| m.get("image_metadata"))
            .and_then(|im| im.get("architecture"))
            .and_then(|v| v.as_str())
            .unwrap_or("amd64");

        let os = metadata
            .as_ref()
            .and_then(|m| m.get("image_metadata"))
            .and_then(|im| im.get("os"))
            .and_then(|v| v.as_str());

        let release = metadata
            .as_ref()
            .and_then(|m| m.get("image_metadata"))
            .and_then(|im| im.get("release"))
            .and_then(|v| v.as_str());

        // Determine the ftype from path
        let filename = path.rsplit('/').next().unwrap_or(&path);
        let ftype = if filename.ends_with(".squashfs") {
            "squashfs"
        } else if filename.ends_with(".img") || filename.ends_with(".qcow2") {
            "disk-kvm.img"
        } else if filename.ends_with(".tar.xz") {
            "incus.tar.xz"
        } else if filename.ends_with(".tar.gz") {
            "incus.tar.gz"
        } else {
            filename
        };

        let download_url = format!(
            "/incus/{}/images/{}/{}/{}",
            repo_key, name, version, filename
        );

        let item = serde_json::json!({
            "ftype": ftype,
            "sha256": checksum,
            "path": download_url,
            "size": size_bytes,
        });

        // Build the product entry
        let product = products.entry(name.clone()).or_insert_with(|| {
            let mut p = serde_json::json!({
                "arch": arch,
                "versions": {},
            });
            if let Some(os_val) = os {
                p["os"] = serde_json::Value::String(os_val.to_string());
            }
            if let Some(release_val) = release {
                p["release"] = serde_json::Value::String(release_val.to_string());
            }
            p
        });

        // Add item under the version
        let versions = product
            .get_mut("versions")
            .and_then(|v| v.as_object_mut())
            .unwrap();

        let version_entry = versions
            .entry(version.clone())
            .or_insert_with(|| serde_json::json!({"items": {}}));

        if let Some(items) = version_entry
            .get_mut("items")
            .and_then(|i| i.as_object_mut())
        {
            // Use a key that identifies the file type
            let item_key = if ftype.contains("tar") {
                "incus.tar.xz".to_string()
            } else {
                "rootfs".to_string()
            };
            items.insert(item_key, item);
        }
    }

    let catalog = serde_json::json!({
        "format": "products:1.0",
        "products": products
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json; charset=utf-8")
        .body(Body::from(serde_json::to_string_pretty(&catalog).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /incus/{repo_key}/images/{product}/{version}/{filename} -- Download
// ---------------------------------------------------------------------------

async fn download_image(
    State(state): State<SharedState>,
    Path((repo_key, product, version, filename)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_incus_repo(&state.db, &repo_key).await?;

    let artifact_path = format!("{}/{}/{}", product, version, filename);

    let artifact = sqlx::query(
        r#"
        SELECT id, path, size_bytes, checksum_sha256, storage_key
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND path = $2
        LIMIT 1
        "#,
    )
    .bind(repo.id)
    .bind(&artifact_path)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Image file not found").into_response())?;

    let storage_key: String = artifact.get("storage_key");
    let size_bytes: i64 = artifact.get("size_bytes");
    let checksum: String = artifact.get("checksum_sha256");

    let storage = FilesystemStorage::new(&repo.storage_path);
    let content = storage.get(&storage_key).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    let content_type = if filename.ends_with(".tar.xz") {
        "application/x-xz"
    } else if filename.ends_with(".tar.gz") {
        "application/gzip"
    } else if filename.ends_with(".json") {
        "application/json"
    } else {
        "application/octet-stream"
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .header(CONTENT_LENGTH, size_bytes.to_string())
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header("X-Checksum-Sha256", checksum)
        .body(Body::from(content))
        .unwrap())
}

// ---------------------------------------------------------------------------
// PUT /incus/{repo_key}/images/{product}/{version}/{filename} -- Upload
// ---------------------------------------------------------------------------

async fn upload_image(
    State(state): State<SharedState>,
    Path((repo_key, product, version, filename)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_incus_repo(&state.db, &repo_key).await?;

    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    // Validate path through format handler
    let artifact_path = format!("{}/{}/{}", product, version, filename);
    IncusHandler::parse_path(&artifact_path).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid image path: {}", e),
        )
            .into_response()
    })?;

    // Compute checksum
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let checksum = format!("{:x}", hasher.finalize());

    let size_bytes = body.len() as i64;
    let storage_key = format!("incus/{}/{}", repo.id, artifact_path);

    // Store the file
    let storage = FilesystemStorage::new(&repo.storage_path);
    storage.put(&storage_key, body.clone()).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    // Parse metadata from the upload
    let handler = IncusHandler::new();
    let metadata = handler
        .parse_metadata(&artifact_path, &body)
        .await
        .unwrap_or(serde_json::json!({}));

    // Insert artifact record
    let artifact = sqlx::query(
        r#"
        INSERT INTO artifacts (repository_id, path, name, version, size_bytes, checksum_sha256, storage_key, uploaded_by)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (repository_id, path) DO UPDATE SET
            size_bytes = $5, checksum_sha256 = $6, storage_key = $7,
            uploaded_by = $8, updated_at = NOW(), is_deleted = false
        RETURNING id
        "#,
    )
    .bind(repo.id)
    .bind(&artifact_path)
    .bind(&product)
    .bind(&version)
    .bind(size_bytes)
    .bind(&checksum)
    .bind(&storage_key)
    .bind(user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    let artifact_id: uuid::Uuid = artifact.get("id");

    // Store metadata
    sqlx::query(
        r#"
        INSERT INTO artifact_metadata (artifact_id, metadata)
        VALUES ($1, $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
    )
    .bind(artifact_id)
    .bind(&metadata)
    .execute(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to store metadata: {}", e),
        )
            .into_response()
    })?;

    tracing::info!(
        "Uploaded Incus image: {}/{}/{} ({}B, sha256:{})",
        product,
        version,
        filename,
        size_bytes,
        &checksum[..12]
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "id": artifact_id,
                "product": product,
                "version": version,
                "file": filename,
                "size": size_bytes,
                "sha256": checksum,
            })
            .to_string(),
        ))
        .unwrap())
}

// ---------------------------------------------------------------------------
// DELETE /incus/{repo_key}/images/{product}/{version}/{filename} -- Delete
// ---------------------------------------------------------------------------

async fn delete_image(
    State(state): State<SharedState>,
    Path((repo_key, product, version, filename)): Path<(String, String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let _user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_incus_repo(&state.db, &repo_key).await?;

    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    let artifact_path = format!("{}/{}/{}", product, version, filename);

    let result = sqlx::query(
        r#"
        UPDATE artifacts SET is_deleted = true, updated_at = NOW()
        WHERE repository_id = $1 AND path = $2 AND is_deleted = false
        "#,
    )
    .bind(repo.id)
    .bind(&artifact_path)
    .execute(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "Image file not found").into_response());
    }

    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_basic_credentials_valid() {
        let mut headers = HeaderMap::new();
        // "admin:password" base64 = "YWRtaW46cGFzc3dvcmQ="
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Basic YWRtaW46cGFzc3dvcmQ=".parse().unwrap(),
        );
        let creds = extract_basic_credentials(&headers);
        assert!(creds.is_some());
        let (user, pass) = creds.unwrap();
        assert_eq!(user, "admin");
        assert_eq!(pass, "password");
    }

    #[test]
    fn test_extract_basic_credentials_missing() {
        let headers = HeaderMap::new();
        assert!(extract_basic_credentials(&headers).is_none());
    }
}
