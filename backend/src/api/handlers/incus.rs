//! Incus/LXC Container Image API handlers.
//!
//! Implements endpoints for uploading, downloading, and discovering Incus
//! container and VM images via the SimpleStreams protocol.
//!
//! Uploads use **streaming I/O** — the request body is written to disk
//! frame-by-frame, so memory stays flat regardless of image size.
//! Both monolithic (single PUT) and chunked/resumable uploads are supported.
//!
//! Routes mounted at `/incus/{repo_key}/...`:
//!   GET    /streams/v1/index.json              - SimpleStreams index
//!   GET    /streams/v1/images.json             - SimpleStreams product catalog
//!   GET    /images/{product}/{version}/{file}  - Download image file
//!   PUT    /images/{product}/{version}/{file}  - Monolithic upload (streaming)
//!   DELETE /images/{product}/{version}/{file}  - Delete image file
//!   POST   /images/{product}/{version}/{filename}/uploads - Start chunked upload
//!   PATCH  /uploads/{uuid}                     - Upload chunk
//!   PUT    /uploads/{uuid}                     - Complete chunked upload
//!   DELETE /uploads/{uuid}                     - Cancel chunked upload
//!   GET    /uploads/{uuid}                     - Check upload progress

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path as AxumPath, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::Router;
use base64::Engine;
use futures::StreamExt;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::api::handlers::proxy_helpers;
use crate::api::SharedState;
use crate::formats::incus::IncusHandler;
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
        // Chunked / resumable upload endpoints (more-specific routes first)
        .route(
            "/:repo_key/images/:product/:version/:filename/uploads",
            post(start_chunked_upload),
        )
        .route(
            "/:repo_key/uploads/:uuid",
            patch(upload_chunk)
                .put(complete_chunked_upload)
                .delete(cancel_chunked_upload)
                .get(get_upload_progress),
        )
        // Image file operations (monolithic upload via PUT)
        .route(
            "/:repo_key/images/:product/:version/:filename",
            get(download_image).put(upload_image).delete(delete_image),
        )
        .layer(DefaultBodyLimit::disable()) // No size limit — container images can be very large
}

// ---------------------------------------------------------------------------
// Streaming helpers — never load full file into memory
// ---------------------------------------------------------------------------

/// Stream a request body to a new file, computing SHA256 incrementally.
/// Returns `(total_bytes, sha256_hex)`.
async fn stream_body_to_file(body: Body, path: &Path) -> Result<(i64, String), Response> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to create directory: {}", e),
            )
                .into_response()
        })?;
    }

    let mut file = tokio::fs::File::create(path).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create temp file: {}", e),
        )
            .into_response()
    })?;

    let mut hasher = Sha256::new();
    let mut size: i64 = 0;

    let mut stream = body.into_data_stream();
    while let Some(chunk_result) = stream.next().await {
        let chunk: bytes::Bytes = chunk_result.map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Error reading request body: {}", e),
            )
                .into_response()
        })?;
        hasher.update(&chunk);
        file.write_all(&chunk).await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to write to disk: {}", e),
            )
                .into_response()
        })?;
        size += chunk.len() as i64;
    }

    file.sync_all().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to sync file: {}", e),
        )
            .into_response()
    })?;

    Ok((size, format!("{:x}", hasher.finalize())))
}

/// Append a request body to an existing file. Returns bytes written.
async fn append_body_to_file(body: Body, path: &Path) -> Result<i64, Response> {
    let mut file = tokio::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to open temp file for append: {}", e),
            )
                .into_response()
        })?;

    let mut bytes_written: i64 = 0;

    let mut stream = body.into_data_stream();
    while let Some(chunk_result) = stream.next().await {
        let chunk: bytes::Bytes = chunk_result.map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Error reading request body: {}", e),
            )
                .into_response()
        })?;
        file.write_all(&chunk).await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to write chunk to disk: {}", e),
            )
                .into_response()
        })?;
        bytes_written += chunk.len() as i64;
    }

    file.sync_all().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to sync file: {}", e),
        )
            .into_response()
    })?;

    Ok(bytes_written)
}

/// Compute SHA256 of a file by streaming through it in 64 KB blocks.
async fn compute_sha256_from_file(path: &Path) -> Result<String, Response> {
    use tokio::io::AsyncReadExt;

    let mut file = tokio::fs::File::open(path).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to open file for checksum: {}", e),
        )
            .into_response()
    })?;

    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to read file for checksum: {}", e),
            )
                .into_response()
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

/// Compute the on-disk path for a storage key (mirrors FilesystemStorage::key_to_path).
fn storage_path_for_key(storage_base: &str, key: &str) -> PathBuf {
    let prefix = &key[..2.min(key.len())];
    PathBuf::from(storage_base).join(prefix).join(key)
}

/// Temp file path for an upload session.
fn temp_upload_path(storage_base: &str, session_id: &Uuid) -> PathBuf {
    let key = format!("incus-uploads/{}", session_id);
    storage_path_for_key(storage_base, &key)
}

/// Parameters for creating or updating an artifact record.
struct UpsertArtifactParams<'a> {
    db: &'a PgPool,
    repo_id: Uuid,
    artifact_path: &'a str,
    product: &'a str,
    version: &'a str,
    size_bytes: i64,
    checksum: &'a str,
    storage_key: &'a str,
    user_id: Uuid,
    metadata: &'a serde_json::Value,
}

/// Insert or update the artifact record and store metadata. Shared by
/// monolithic and chunked upload finalization.
async fn upsert_artifact(p: UpsertArtifactParams<'_>) -> Result<Uuid, Response> {
    let UpsertArtifactParams {
        db,
        repo_id,
        artifact_path,
        product,
        version,
        size_bytes,
        checksum,
        storage_key,
        user_id,
        metadata,
    } = p;
    let content_type = if artifact_path.ends_with(".tar.xz") {
        "application/x-xz"
    } else if artifact_path.ends_with(".tar.gz") {
        "application/gzip"
    } else {
        "application/octet-stream"
    };

    let artifact = sqlx::query(
        r#"
        INSERT INTO artifacts (repository_id, path, name, version, size_bytes,
                               checksum_sha256, content_type, storage_key, uploaded_by)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (repository_id, path) DO UPDATE SET
            size_bytes = $5, checksum_sha256 = $6, content_type = $7, storage_key = $8,
            uploaded_by = $9, updated_at = NOW(), is_deleted = false
        RETURNING id
        "#,
    )
    .bind(repo_id)
    .bind(artifact_path)
    .bind(product)
    .bind(version)
    .bind(size_bytes)
    .bind(checksum)
    .bind(content_type)
    .bind(storage_key)
    .bind(user_id)
    .fetch_one(db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    let artifact_id: Uuid = artifact.get("id");

    sqlx::query(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'incus', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
    )
    .bind(artifact_id)
    .bind(metadata)
    .execute(db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to store metadata: {}", e),
        )
            .into_response()
    })?;

    Ok(artifact_id)
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
) -> Result<Uuid, Response> {
    let (username, password) = extract_basic_credentials(headers).ok_or_else(|| {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Basic realm=\"incus\"")
            .body(Body::from("Authentication required"))
            .unwrap()
    })?;

    let auth_service =
        crate::services::auth_service::AuthService::new(db.clone(), Arc::new(config.clone()));
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
    id: Uuid,
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
// GET /streams/v1/index.json -- SimpleStreams index
// ---------------------------------------------------------------------------

async fn streams_index(
    State(state): State<SharedState>,
    AxumPath(repo_key): AxumPath<String>,
) -> Result<Response, Response> {
    let _repo = resolve_incus_repo(&state.db, &repo_key).await?;

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
                "path": "streams/v1/images.json",
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
// GET /streams/v1/images.json -- SimpleStreams product catalog
// ---------------------------------------------------------------------------

async fn streams_images(
    State(state): State<SharedState>,
    AxumPath(repo_key): AxumPath<String>,
) -> Result<Response, Response> {
    let repo = resolve_incus_repo(&state.db, &repo_key).await?;

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
// GET /images/{product}/{version}/{filename} -- Download
// ---------------------------------------------------------------------------

async fn download_image(
    State(state): State<SharedState>,
    AxumPath((repo_key, product, version, filename)): AxumPath<(String, String, String, String)>,
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
// PUT /images/{product}/{version}/{filename} -- Monolithic streaming upload
// ---------------------------------------------------------------------------

async fn upload_image(
    State(state): State<SharedState>,
    AxumPath((repo_key, product, version, filename)): AxumPath<(String, String, String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_incus_repo(&state.db, &repo_key).await?;

    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    let artifact_path = format!("{}/{}/{}", product, version, filename);
    IncusHandler::parse_path(&artifact_path).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid image path: {}", e),
        )
            .into_response()
    })?;

    // Stream body to temp file (never buffers entire image in RAM)
    let temp_id = Uuid::new_v4();
    let temp_path = temp_upload_path(&repo.storage_path, &temp_id);
    let (size_bytes, checksum) = stream_body_to_file(body, &temp_path).await?;

    // Extract metadata from the file on disk
    let metadata = IncusHandler::parse_metadata_from_file(&artifact_path, &temp_path)
        .unwrap_or_else(|_| serde_json::json!({"file_type": "unknown"}));

    // Move temp file to final storage location (atomic rename, same filesystem)
    let storage_key = format!("incus/{}/{}", repo.id, artifact_path);
    let final_path = storage_path_for_key(&repo.storage_path, &storage_key);
    if let Some(parent) = final_path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to create directory: {}", e),
            )
                .into_response()
        })?;
    }
    tokio::fs::rename(&temp_path, &final_path)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to finalize upload: {}", e),
            )
                .into_response()
        })?;

    let artifact_id = upsert_artifact(UpsertArtifactParams {
        db: &state.db,
        repo_id: repo.id,
        artifact_path: &artifact_path,
        product: &product,
        version: &version,
        size_bytes,
        checksum: &checksum,
        storage_key: &storage_key,
        user_id,
        metadata: &metadata,
    })
    .await?;

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
// DELETE /images/{product}/{version}/{filename} -- Delete image
// ---------------------------------------------------------------------------

async fn delete_image(
    State(state): State<SharedState>,
    AxumPath((repo_key, product, version, filename)): AxumPath<(String, String, String, String)>,
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

// ===========================================================================
// Chunked / resumable upload endpoints
// ===========================================================================

/// Look up an upload session by UUID.
async fn get_session(db: &PgPool, session_id: Uuid) -> Result<UploadSession, Response> {
    sqlx::query_as::<_, UploadSession>(
        r#"
        SELECT id, repository_id, user_id, artifact_path, product, version,
               filename, bytes_received, storage_temp_path
        FROM incus_upload_sessions
        WHERE id = $1
        "#,
    )
    .bind(session_id)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Upload session not found").into_response())
}

#[derive(sqlx::FromRow)]
struct UploadSession {
    id: Uuid,
    repository_id: Uuid,
    user_id: Uuid,
    artifact_path: String,
    product: String,
    version: String,
    filename: String,
    bytes_received: i64,
    storage_temp_path: String,
}

// ---------------------------------------------------------------------------
// POST /images/{product}/{version}/{filename}/uploads -- Start chunked upload
// ---------------------------------------------------------------------------

async fn start_chunked_upload(
    State(state): State<SharedState>,
    AxumPath((repo_key, product, version, filename)): AxumPath<(String, String, String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_incus_repo(&state.db, &repo_key).await?;

    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    let artifact_path = format!("{}/{}/{}", product, version, filename);
    IncusHandler::parse_path(&artifact_path).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid image path: {}", e),
        )
            .into_response()
    })?;

    let session_id = Uuid::new_v4();
    let temp_path = temp_upload_path(&repo.storage_path, &session_id);

    // Stream initial body (may be empty) to temp file
    let (initial_bytes, _checksum) = stream_body_to_file(body, &temp_path).await?;

    // Record session
    sqlx::query(
        r#"
        INSERT INTO incus_upload_sessions
            (id, repository_id, user_id, artifact_path, product, version,
             filename, bytes_received, storage_temp_path)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
    )
    .bind(session_id)
    .bind(repo.id)
    .bind(user_id)
    .bind(&artifact_path)
    .bind(&product)
    .bind(&version)
    .bind(&filename)
    .bind(initial_bytes)
    .bind(temp_path.to_string_lossy().as_ref())
    .execute(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    tracing::info!(
        "Started chunked upload session {} for {}/{}/{} ({} initial bytes)",
        session_id,
        product,
        version,
        filename,
        initial_bytes
    );

    Ok(Response::builder()
        .status(StatusCode::ACCEPTED)
        .header(
            "Location",
            format!("/incus/{}/uploads/{}", repo_key, session_id),
        )
        .header("Upload-UUID", session_id.to_string())
        .header("Range", format!("0-{}", initial_bytes))
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "session_id": session_id,
                "bytes_received": initial_bytes,
            })
            .to_string(),
        ))
        .unwrap())
}

// ---------------------------------------------------------------------------
// PATCH /uploads/{uuid} -- Upload a chunk
// ---------------------------------------------------------------------------

async fn upload_chunk(
    State(state): State<SharedState>,
    AxumPath((repo_key, session_id)): AxumPath<(String, Uuid)>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, Response> {
    let _user_id = authenticate(&state.db, &state.config, &headers).await?;
    let session = get_session(&state.db, session_id).await?;
    let temp_path = PathBuf::from(&session.storage_temp_path);

    // Append body to temp file (no read-back of existing data)
    let bytes_written = append_body_to_file(body, &temp_path).await?;
    let new_total = session.bytes_received + bytes_written;

    // Update session
    sqlx::query(
        "UPDATE incus_upload_sessions SET bytes_received = $2, updated_at = NOW() WHERE id = $1",
    )
    .bind(session_id)
    .bind(new_total)
    .execute(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    tracing::debug!(
        "Chunk uploaded for session {}: +{} bytes (total: {})",
        session_id,
        bytes_written,
        new_total
    );

    Ok(Response::builder()
        .status(StatusCode::ACCEPTED)
        .header(
            "Location",
            format!("/incus/{}/uploads/{}", repo_key, session_id),
        )
        .header("Upload-UUID", session_id.to_string())
        .header("Range", format!("0-{}", new_total))
        .body(Body::empty())
        .unwrap())
}

// ---------------------------------------------------------------------------
// PUT /uploads/{uuid} -- Complete chunked upload
// ---------------------------------------------------------------------------

async fn complete_chunked_upload(
    State(state): State<SharedState>,
    AxumPath((repo_key, session_id)): AxumPath<(String, Uuid)>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, Response> {
    let _user_id = authenticate(&state.db, &state.config, &headers).await?;
    let session = get_session(&state.db, session_id).await?;
    let repo = resolve_incus_repo(&state.db, &repo_key).await?;
    let temp_path = PathBuf::from(&session.storage_temp_path);

    // Append any final body data
    let final_bytes = append_body_to_file(body, &temp_path).await?;
    let total_bytes = session.bytes_received + final_bytes;

    // Compute SHA256 by streaming through the file
    let checksum = compute_sha256_from_file(&temp_path).await?;

    // Verify client-provided checksum if present
    if let Some(expected) = headers.get("X-Checksum-Sha256") {
        let expected = expected.to_str().unwrap_or("");
        if expected != checksum {
            // Checksum mismatch — clean up
            let _ = tokio::fs::remove_file(&temp_path).await;
            let _ = sqlx::query("DELETE FROM incus_upload_sessions WHERE id = $1")
                .bind(session_id)
                .execute(&state.db)
                .await;
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "Checksum mismatch: expected {}, computed {}",
                    expected, checksum
                ),
            )
                .into_response());
        }
    }

    // Extract metadata from the file on disk
    let metadata = IncusHandler::parse_metadata_from_file(&session.artifact_path, &temp_path)
        .unwrap_or_else(|_| serde_json::json!({"file_type": "unknown"}));

    // Move temp file to final storage location
    let storage_key = format!("incus/{}/{}", session.repository_id, session.artifact_path);
    let final_path = storage_path_for_key(&repo.storage_path, &storage_key);
    if let Some(parent) = final_path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to create directory: {}", e),
            )
                .into_response()
        })?;
    }
    tokio::fs::rename(&temp_path, &final_path)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to finalize upload: {}", e),
            )
                .into_response()
        })?;

    // Create artifact record
    let artifact_id = upsert_artifact(UpsertArtifactParams {
        db: &state.db,
        repo_id: session.repository_id,
        artifact_path: &session.artifact_path,
        product: &session.product,
        version: &session.version,
        size_bytes: total_bytes,
        checksum: &checksum,
        storage_key: &storage_key,
        user_id: session.user_id,
        metadata: &metadata,
    })
    .await?;

    // Clean up session
    let _ = sqlx::query("DELETE FROM incus_upload_sessions WHERE id = $1")
        .bind(session_id)
        .execute(&state.db)
        .await;

    tracing::info!(
        "Completed chunked upload {}: {}/{}/{} ({}B, sha256:{})",
        session_id,
        session.product,
        session.version,
        session.filename,
        total_bytes,
        &checksum[..12]
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "id": artifact_id,
                "product": session.product,
                "version": session.version,
                "file": session.filename,
                "size": total_bytes,
                "sha256": checksum,
            })
            .to_string(),
        ))
        .unwrap())
}

// ---------------------------------------------------------------------------
// DELETE /uploads/{uuid} -- Cancel chunked upload
// ---------------------------------------------------------------------------

async fn cancel_chunked_upload(
    State(state): State<SharedState>,
    AxumPath((_repo_key, session_id)): AxumPath<(String, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let _user_id = authenticate(&state.db, &state.config, &headers).await?;
    let session = get_session(&state.db, session_id).await?;

    // Delete temp file
    let _ = tokio::fs::remove_file(&session.storage_temp_path).await;

    // Delete session
    sqlx::query("DELETE FROM incus_upload_sessions WHERE id = $1")
        .bind(session_id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
                .into_response()
        })?;

    tracing::info!("Cancelled chunked upload session {}", session_id);

    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /uploads/{uuid} -- Check upload progress
// ---------------------------------------------------------------------------

async fn get_upload_progress(
    State(state): State<SharedState>,
    AxumPath((_repo_key, session_id)): AxumPath<(String, Uuid)>,
) -> Result<Response, Response> {
    let session = get_session(&state.db, session_id).await?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .header("Range", format!("0-{}", session.bytes_received))
        .body(Body::from(
            serde_json::json!({
                "session_id": session.id,
                "artifact_path": session.artifact_path,
                "bytes_received": session.bytes_received,
            })
            .to_string(),
        ))
        .unwrap())
}

// ===========================================================================
// Stale upload cleanup
// ===========================================================================

/// Delete upload sessions that haven't been updated in `max_age_hours`.
/// Returns the number of sessions cleaned up.
pub async fn cleanup_stale_sessions(db: &PgPool, max_age_hours: i64) -> Result<i64, String> {
    let stale = sqlx::query_as::<_, (Uuid, String)>(
        r#"
        SELECT id, storage_temp_path
        FROM incus_upload_sessions
        WHERE updated_at < NOW() - make_interval(hours => $1::int)
        "#,
    )
    .bind(max_age_hours as i32)
    .fetch_all(db)
    .await
    .map_err(|e| format!("Failed to query stale sessions: {}", e))?;

    let count = stale.len() as i64;

    for (id, temp_path) in &stale {
        let _ = tokio::fs::remove_file(temp_path).await;
        let _ = sqlx::query("DELETE FROM incus_upload_sessions WHERE id = $1")
            .bind(id)
            .execute(db)
            .await;
        tracing::info!("Cleaned up stale upload session {}", id);
    }

    Ok(count)
}

// ===========================================================================
// Tests
// ===========================================================================

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

    #[test]
    fn test_storage_path_for_key() {
        let path = storage_path_for_key("/data", "incus/abc/file.tar.xz");
        assert_eq!(path, PathBuf::from("/data/in/incus/abc/file.tar.xz"));
    }

    #[test]
    fn test_temp_upload_path() {
        let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let path = temp_upload_path("/data", &id);
        assert_eq!(
            path,
            PathBuf::from("/data/in/incus-uploads/550e8400-e29b-41d4-a716-446655440000")
        );
    }
}
