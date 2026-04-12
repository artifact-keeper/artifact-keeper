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

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path as AxumPath, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::Extension;
use axum::Router;
use futures::StreamExt;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use std::fmt::Display;
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic, AuthExtension};
use crate::api::SharedState;
use crate::formats::incus::IncusHandler;

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
    ensure_parent_dirs(path).await?;

    let mut file = tokio::fs::File::create(path)
        .await
        .map_err(|e| fs_err("create temp file", e))?;

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
        file.write_all(&chunk)
            .await
            .map_err(|e| fs_err("write to disk", e))?;
        size += chunk.len() as i64;
    }

    file.sync_all().await.map_err(|e| fs_err("sync file", e))?;

    Ok((size, format!("{:x}", hasher.finalize())))
}

/// Append a request body to an existing file. Returns bytes written.
async fn append_body_to_file(body: Body, path: &Path) -> Result<i64, Response> {
    let mut file = tokio::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .await
        .map_err(|e| fs_err("open temp file for append", e))?;

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
        file.write_all(&chunk)
            .await
            .map_err(|e| fs_err("write chunk to disk", e))?;
        bytes_written += chunk.len() as i64;
    }

    file.sync_all().await.map_err(|e| fs_err("sync file", e))?;

    Ok(bytes_written)
}

/// Compute SHA256 of a file by streaming through it in 64 KB blocks.
async fn compute_sha256_from_file(path: &Path) -> Result<String, Response> {
    use tokio::io::AsyncReadExt;

    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| fs_err("open file for checksum", e))?;

    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .await
            .map_err(|e| fs_err("read file for checksum", e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

/// Compute the on-disk path for a storage key (mirrors FilesystemStorage::key_to_path).
pub(crate) fn storage_path_for_key(storage_base: &str, key: &str) -> PathBuf {
    let prefix = &key[..2.min(key.len())];
    PathBuf::from(storage_base).join(prefix).join(key)
}

/// Temp file path for an upload session.
pub(crate) fn temp_upload_path(storage_base: &str, session_id: &Uuid) -> PathBuf {
    let key = format!("incus-uploads/{}", session_id);
    storage_path_for_key(storage_base, &key)
}

/// Determine the content type for an Incus artifact based on its path.
pub(crate) fn content_type_for_artifact(artifact_path: &str) -> &'static str {
    if artifact_path.ends_with(".tar.xz") {
        "application/x-xz"
    } else if artifact_path.ends_with(".tar.gz") {
        "application/gzip"
    } else {
        "application/octet-stream"
    }
}

/// Determine the content type for downloading an Incus image file.
pub(crate) fn content_type_for_download(filename: &str) -> &'static str {
    if filename.ends_with(".tar.xz") {
        "application/x-xz"
    } else if filename.ends_with(".tar.gz") {
        "application/gzip"
    } else if filename.ends_with(".json") {
        "application/json"
    } else {
        "application/octet-stream"
    }
}

/// Classify a filename into a SimpleStreams file type string.
pub(crate) fn simplestreams_ftype(filename: &str) -> &str {
    if filename.ends_with(".squashfs") {
        "squashfs"
    } else if filename.ends_with(".img") || filename.ends_with(".qcow2") {
        "disk-kvm.img"
    } else if filename.ends_with(".tar.xz") {
        "incus.tar.xz"
    } else if filename.ends_with(".tar.gz") {
        "incus.tar.gz"
    } else {
        filename
    }
}

/// Determine the item key used in a SimpleStreams version entry.
pub(crate) fn simplestreams_item_key(ftype: &str) -> &str {
    if ftype.contains("tar") {
        "incus.tar.xz"
    } else {
        "rootfs"
    }
}

/// Build the download URL for an image in the SimpleStreams catalog.
pub(crate) fn build_download_url(
    repo_key: &str,
    product: &str,
    version: &str,
    filename: &str,
) -> String {
    format!(
        "/incus/{}/images/{}/{}/{}",
        repo_key, product, version, filename
    )
}

/// Build the artifact path from product, version, and filename.
pub(crate) fn build_artifact_path(product: &str, version: &str, filename: &str) -> String {
    format!("{}/{}/{}", product, version, filename)
}

/// Build the storage key for an Incus artifact.
pub(crate) fn build_storage_key(repo_id: &Uuid, artifact_path: &str) -> String {
    format!("incus/{}/{}", repo_id, artifact_path)
}

/// Extract the architecture from Incus image metadata JSON.
pub(crate) fn extract_arch_from_metadata(metadata: Option<&serde_json::Value>) -> &str {
    metadata
        .and_then(|m| m.get("image_metadata"))
        .and_then(|im| im.get("architecture"))
        .and_then(|v| v.as_str())
        .unwrap_or("amd64")
}

/// Extract the OS from Incus image metadata JSON.
pub(crate) fn extract_os_from_metadata(metadata: Option<&serde_json::Value>) -> Option<&str> {
    metadata
        .and_then(|m| m.get("image_metadata"))
        .and_then(|im| im.get("os"))
        .and_then(|v| v.as_str())
}

/// Extract the release from Incus image metadata JSON.
pub(crate) fn extract_release_from_metadata(metadata: Option<&serde_json::Value>) -> Option<&str> {
    metadata
        .and_then(|m| m.get("image_metadata"))
        .and_then(|im| im.get("release"))
        .and_then(|v| v.as_str())
}

/// Extract the filename portion from an artifact path.
pub(crate) fn filename_from_path(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Build the Location header for chunked upload responses.
pub(crate) fn build_upload_location(repo_key: &str, session_id: &Uuid) -> String {
    format!("/incus/{}/uploads/{}", repo_key, session_id)
}

/// Build the SimpleStreams index JSON structure.
pub(crate) fn build_streams_index_json(products: &[String]) -> serde_json::Value {
    serde_json::json!({
        "format": "index:1.0",
        "index": {
            "images": {
                "datatype": "image-downloads",
                "format": "products:1.0",
                "path": "streams/v1/images.json",
                "products": products
            }
        }
    })
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
    let content_type = content_type_for_artifact(artifact_path);

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
    .map_err(db_err)?;

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
    .map_err(|e| fs_err("store metadata", e))?;

    Ok(artifact_id)
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_incus_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    use sqlx::Row;
    let repo = sqlx::query(
        r#"SELECT id, key, storage_backend, storage_path, format::text as format, repo_type::text as repo_type, upstream_url
        FROM repositories WHERE key = $1"#,
    )
    .bind(repo_key)
    .fetch_optional(db)
    .await
    .map_err(db_err)?
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
        key: repo.get("key"),
        storage_path: repo.get("storage_path"),
        storage_backend: repo.get("storage_backend"),
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
    .map_err(db_err)?;

    let products: Vec<String> = rows.iter().map(|r| r.get::<String, _>("name")).collect();

    let index = build_streams_index_json(&products);

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
    .map_err(db_err)?;

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

        let arch = extract_arch_from_metadata(metadata.as_ref());
        let os = extract_os_from_metadata(metadata.as_ref());
        let release = extract_release_from_metadata(metadata.as_ref());

        let filename = filename_from_path(&path);
        let ftype = simplestreams_ftype(filename);
        let download_url = build_download_url(&repo_key, &name, &version, filename);

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
            items.insert(simplestreams_item_key(ftype).to_string(), item);
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

    let artifact_path = build_artifact_path(&product, &version, &filename);

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
    .map_err(db_err)?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Image file not found").into_response())?;

    let artifact_id: uuid::Uuid = artifact.get("id");
    let storage_key: String = artifact.get("storage_key");
    let size_bytes: i64 = artifact.get("size_bytes");
    let checksum: String = artifact.get("checksum_sha256");

    // Check quarantine status before serving
    crate::services::quarantine_service::check_artifact_download(&state.db, artifact_id)
        .await
        .map_err(|e| e.into_response())?;

    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    let content = storage.get(&storage_key).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Storage error: {}", e),
        )
            .into_response()
    })?;

    let content_type = content_type_for_download(&filename);

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
    Extension(auth): Extension<Option<AuthExtension>>,
    AxumPath((repo_key, product, version, filename)): AxumPath<(String, String, String, String)>,
    body: Body,
) -> Result<Response, Response> {
    let user_id = require_auth_basic(auth, "incus")?.user_id;
    let repo = resolve_incus_repo(&state.db, &repo_key).await?;

    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    let artifact_path = build_artifact_path(&product, &version, &filename);
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
    let storage_key = build_storage_key(&repo.id, &artifact_path);
    let final_path = storage_path_for_key(&repo.storage_path, &storage_key);
    finalize_temp_file(&temp_path, &final_path).await?;

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
    Extension(auth): Extension<Option<AuthExtension>>,
    AxumPath((repo_key, product, version, filename)): AxumPath<(String, String, String, String)>,
) -> Result<Response, Response> {
    let _user_id = require_auth_basic(auth, "incus")?.user_id;
    let repo = resolve_incus_repo(&state.db, &repo_key).await?;

    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    let artifact_path = build_artifact_path(&product, &version, &filename);

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
    .map_err(db_err)?;

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
    .map_err(db_err)?
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
    Extension(auth): Extension<Option<AuthExtension>>,
    AxumPath((repo_key, product, version, filename)): AxumPath<(String, String, String, String)>,
    body: Body,
) -> Result<Response, Response> {
    let user_id = require_auth_basic(auth, "incus")?.user_id;
    let repo = resolve_incus_repo(&state.db, &repo_key).await?;

    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    let artifact_path = build_artifact_path(&product, &version, &filename);
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
    .map_err(db_err)?;

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
        .header("Location", build_upload_location(&repo_key, &session_id))
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
    Extension(auth): Extension<Option<AuthExtension>>,
    AxumPath((repo_key, session_id)): AxumPath<(String, Uuid)>,
    body: Body,
) -> Result<Response, Response> {
    let _user_id = require_auth_basic(auth, "incus")?.user_id;
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
    .map_err(db_err)?;

    tracing::debug!(
        "Chunk uploaded for session {}: +{} bytes (total: {})",
        session_id,
        bytes_written,
        new_total
    );

    Ok(Response::builder()
        .status(StatusCode::ACCEPTED)
        .header("Location", build_upload_location(&repo_key, &session_id))
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
    Extension(auth): Extension<Option<AuthExtension>>,
    AxumPath((repo_key, session_id)): AxumPath<(String, Uuid)>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, Response> {
    let _user_id = require_auth_basic(auth, "incus")?.user_id;
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
    let storage_key = build_storage_key(&session.repository_id, &session.artifact_path);
    let final_path = storage_path_for_key(&repo.storage_path, &storage_key);
    finalize_temp_file(&temp_path, &final_path).await?;

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
    Extension(auth): Extension<Option<AuthExtension>>,
    AxumPath((_repo_key, session_id)): AxumPath<(String, Uuid)>,
) -> Result<Response, Response> {
    let _user_id = require_auth_basic(auth, "incus")?.user_id;
    let session = get_session(&state.db, session_id).await?;

    // Delete temp file
    let _ = tokio::fs::remove_file(&session.storage_temp_path).await;

    // Delete session
    sqlx::query("DELETE FROM incus_upload_sessions WHERE id = $1")
        .bind(session_id)
        .execute(&state.db)
        .await
        .map_err(db_err)?;

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

// ---------------------------------------------------------------------------
// Private error helpers — reduce duplicated .map_err() patterns
// ---------------------------------------------------------------------------

/// Build an `INTERNAL_SERVER_ERROR` response for database errors.
fn db_err(e: impl Display) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Database error: {}", e),
    )
        .into_response()
}

/// Build an `INTERNAL_SERVER_ERROR` response for filesystem/IO errors.
fn fs_err(operation: &str, e: impl Display) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Failed to {}: {}", operation, e),
    )
        .into_response()
}

/// Ensure all parent directories exist for the given path.
async fn ensure_parent_dirs(path: &Path) -> Result<(), Response> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| fs_err("create directory", e))?;
    }
    Ok(())
}

/// Move a temp file to its final storage location, creating parent dirs as needed.
async fn finalize_temp_file(temp_path: &Path, final_path: &Path) -> Result<(), Response> {
    ensure_parent_dirs(final_path).await?;
    tokio::fs::rename(temp_path, final_path)
        .await
        .map_err(|e| fs_err("finalize upload", e))?;
    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // storage_path_for_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_storage_path_for_key() {
        let path = storage_path_for_key("/data", "incus/abc/file.tar.xz");
        assert_eq!(path, PathBuf::from("/data/in/incus/abc/file.tar.xz"));
    }

    #[test]
    fn test_storage_path_for_key_short_key() {
        let path = storage_path_for_key("/data", "a");
        assert_eq!(path, PathBuf::from("/data/a/a"));
    }

    #[test]
    fn test_storage_path_for_key_two_char_key() {
        let path = storage_path_for_key("/data", "ab");
        assert_eq!(path, PathBuf::from("/data/ab/ab"));
    }

    #[test]
    fn test_storage_path_for_key_nested_base() {
        let path = storage_path_for_key("/mnt/storage/repos", "incus/repo-id/img.tar.xz");
        assert_eq!(
            path,
            PathBuf::from("/mnt/storage/repos/in/incus/repo-id/img.tar.xz")
        );
    }

    // -----------------------------------------------------------------------
    // temp_upload_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_temp_upload_path() {
        let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let path = temp_upload_path("/data", &id);
        assert_eq!(
            path,
            PathBuf::from("/data/in/incus-uploads/550e8400-e29b-41d4-a716-446655440000")
        );
    }

    #[test]
    fn test_temp_upload_path_different_base() {
        let id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let path = temp_upload_path("/mnt/artifacts", &id);
        assert_eq!(
            path,
            PathBuf::from("/mnt/artifacts/in/incus-uploads/00000000-0000-0000-0000-000000000001")
        );
    }

    // -----------------------------------------------------------------------
    // content_type_for_artifact
    // -----------------------------------------------------------------------

    #[test]
    fn test_content_type_for_artifact_tar_xz() {
        assert_eq!(
            content_type_for_artifact("ubuntu/20240215/incus.tar.xz"),
            "application/x-xz"
        );
    }

    #[test]
    fn test_content_type_for_artifact_tar_gz() {
        assert_eq!(
            content_type_for_artifact("ubuntu/20240215/incus.tar.gz"),
            "application/gzip"
        );
    }

    #[test]
    fn test_content_type_for_artifact_squashfs() {
        assert_eq!(
            content_type_for_artifact("ubuntu/20240215/rootfs.squashfs"),
            "application/octet-stream"
        );
    }

    #[test]
    fn test_content_type_for_artifact_qcow2() {
        assert_eq!(
            content_type_for_artifact("ubuntu/20240215/rootfs.qcow2"),
            "application/octet-stream"
        );
    }

    #[test]
    fn test_content_type_for_artifact_img() {
        assert_eq!(
            content_type_for_artifact("ubuntu/20240215/rootfs.img"),
            "application/octet-stream"
        );
    }

    // -----------------------------------------------------------------------
    // content_type_for_download
    // -----------------------------------------------------------------------

    #[test]
    fn test_content_type_for_download_tar_xz() {
        assert_eq!(
            content_type_for_download("incus.tar.xz"),
            "application/x-xz"
        );
    }

    #[test]
    fn test_content_type_for_download_tar_gz() {
        assert_eq!(
            content_type_for_download("incus.tar.gz"),
            "application/gzip"
        );
    }

    #[test]
    fn test_content_type_for_download_json() {
        assert_eq!(
            content_type_for_download("metadata.json"),
            "application/json"
        );
    }

    #[test]
    fn test_content_type_for_download_squashfs() {
        assert_eq!(
            content_type_for_download("rootfs.squashfs"),
            "application/octet-stream"
        );
    }

    #[test]
    fn test_content_type_for_download_qcow2() {
        assert_eq!(
            content_type_for_download("rootfs.qcow2"),
            "application/octet-stream"
        );
    }

    #[test]
    fn test_content_type_for_download_img() {
        assert_eq!(
            content_type_for_download("rootfs.img"),
            "application/octet-stream"
        );
    }

    // -----------------------------------------------------------------------
    // simplestreams_ftype
    // -----------------------------------------------------------------------

    #[test]
    fn test_simplestreams_ftype_squashfs() {
        assert_eq!(simplestreams_ftype("rootfs.squashfs"), "squashfs");
    }

    #[test]
    fn test_simplestreams_ftype_img() {
        assert_eq!(simplestreams_ftype("rootfs.img"), "disk-kvm.img");
    }

    #[test]
    fn test_simplestreams_ftype_qcow2() {
        assert_eq!(simplestreams_ftype("rootfs.qcow2"), "disk-kvm.img");
    }

    #[test]
    fn test_simplestreams_ftype_tar_xz() {
        assert_eq!(simplestreams_ftype("incus.tar.xz"), "incus.tar.xz");
    }

    #[test]
    fn test_simplestreams_ftype_tar_gz() {
        assert_eq!(simplestreams_ftype("incus.tar.gz"), "incus.tar.gz");
    }

    #[test]
    fn test_simplestreams_ftype_unknown_fallback() {
        assert_eq!(simplestreams_ftype("custom-file.bin"), "custom-file.bin");
    }

    #[test]
    fn test_simplestreams_ftype_metadata_tar_xz() {
        assert_eq!(simplestreams_ftype("metadata.tar.xz"), "incus.tar.xz");
    }

    #[test]
    fn test_simplestreams_ftype_custom_squashfs() {
        assert_eq!(simplestreams_ftype("custom-rootfs.squashfs"), "squashfs");
    }

    // -----------------------------------------------------------------------
    // simplestreams_item_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_simplestreams_item_key_tarball() {
        assert_eq!(simplestreams_item_key("incus.tar.xz"), "incus.tar.xz");
    }

    #[test]
    fn test_simplestreams_item_key_tar_gz() {
        assert_eq!(simplestreams_item_key("incus.tar.gz"), "incus.tar.xz");
    }

    #[test]
    fn test_simplestreams_item_key_squashfs() {
        assert_eq!(simplestreams_item_key("squashfs"), "rootfs");
    }

    #[test]
    fn test_simplestreams_item_key_disk_kvm() {
        assert_eq!(simplestreams_item_key("disk-kvm.img"), "rootfs");
    }

    #[test]
    fn test_simplestreams_item_key_unknown() {
        assert_eq!(simplestreams_item_key("something-else"), "rootfs");
    }

    // -----------------------------------------------------------------------
    // build_download_url
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_download_url() {
        assert_eq!(
            build_download_url("my-repo", "ubuntu-noble", "20240215", "incus.tar.xz"),
            "/incus/my-repo/images/ubuntu-noble/20240215/incus.tar.xz"
        );
    }

    #[test]
    fn test_build_download_url_with_squashfs() {
        assert_eq!(
            build_download_url("repo", "alpine", "v3.19", "rootfs.squashfs"),
            "/incus/repo/images/alpine/v3.19/rootfs.squashfs"
        );
    }

    // -----------------------------------------------------------------------
    // build_artifact_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_artifact_path() {
        assert_eq!(
            build_artifact_path("ubuntu-noble", "20240215", "incus.tar.xz"),
            "ubuntu-noble/20240215/incus.tar.xz"
        );
    }

    #[test]
    fn test_build_artifact_path_squashfs() {
        assert_eq!(
            build_artifact_path("alpine", "v3.19", "rootfs.squashfs"),
            "alpine/v3.19/rootfs.squashfs"
        );
    }

    // -----------------------------------------------------------------------
    // build_storage_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_storage_key() {
        let repo_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(
            build_storage_key(&repo_id, "ubuntu/20240215/incus.tar.xz"),
            "incus/550e8400-e29b-41d4-a716-446655440000/ubuntu/20240215/incus.tar.xz"
        );
    }

    // -----------------------------------------------------------------------
    // extract_arch_from_metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_arch_from_metadata_present() {
        let metadata = serde_json::json!({
            "image_metadata": {
                "architecture": "arm64"
            }
        });
        assert_eq!(extract_arch_from_metadata(Some(&metadata)), "arm64");
    }

    #[test]
    fn test_extract_arch_from_metadata_missing() {
        let metadata = serde_json::json!({
            "image_metadata": {}
        });
        assert_eq!(extract_arch_from_metadata(Some(&metadata)), "amd64");
    }

    #[test]
    fn test_extract_arch_from_metadata_none() {
        assert_eq!(extract_arch_from_metadata(None), "amd64");
    }

    #[test]
    fn test_extract_arch_from_metadata_no_image_metadata_key() {
        let metadata = serde_json::json!({"file_type": "unified_tarball"});
        assert_eq!(extract_arch_from_metadata(Some(&metadata)), "amd64");
    }

    // -----------------------------------------------------------------------
    // extract_os_from_metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_os_from_metadata_present() {
        let metadata = serde_json::json!({
            "image_metadata": {
                "os": "Ubuntu"
            }
        });
        assert_eq!(extract_os_from_metadata(Some(&metadata)), Some("Ubuntu"));
    }

    #[test]
    fn test_extract_os_from_metadata_missing() {
        let metadata = serde_json::json!({
            "image_metadata": {}
        });
        assert_eq!(extract_os_from_metadata(Some(&metadata)), None);
    }

    #[test]
    fn test_extract_os_from_metadata_none() {
        assert_eq!(extract_os_from_metadata(None), None);
    }

    // -----------------------------------------------------------------------
    // extract_release_from_metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_release_from_metadata_present() {
        let metadata = serde_json::json!({
            "image_metadata": {
                "release": "noble"
            }
        });
        assert_eq!(
            extract_release_from_metadata(Some(&metadata)),
            Some("noble")
        );
    }

    #[test]
    fn test_extract_release_from_metadata_missing() {
        assert_eq!(extract_release_from_metadata(None), None);
    }

    #[test]
    fn test_extract_release_from_metadata_no_release_field() {
        let metadata = serde_json::json!({
            "image_metadata": {
                "os": "Ubuntu",
                "architecture": "amd64"
            }
        });
        assert_eq!(extract_release_from_metadata(Some(&metadata)), None);
    }

    // -----------------------------------------------------------------------
    // filename_from_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_filename_from_path_nested() {
        assert_eq!(
            filename_from_path("ubuntu/20240215/incus.tar.xz"),
            "incus.tar.xz"
        );
    }

    #[test]
    fn test_filename_from_path_no_slash() {
        assert_eq!(filename_from_path("incus.tar.xz"), "incus.tar.xz");
    }

    #[test]
    fn test_filename_from_path_deep() {
        assert_eq!(
            filename_from_path("a/b/c/d/rootfs.squashfs"),
            "rootfs.squashfs"
        );
    }

    // -----------------------------------------------------------------------
    // build_upload_location
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_upload_location() {
        let session_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(
            build_upload_location("my-repo", &session_id),
            "/incus/my-repo/uploads/550e8400-e29b-41d4-a716-446655440000"
        );
    }

    // -----------------------------------------------------------------------
    // build_streams_index_json
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_streams_index_json_empty() {
        let index = build_streams_index_json(&[]);
        assert_eq!(index["format"], "index:1.0");
        assert_eq!(index["index"]["images"]["datatype"], "image-downloads");
        assert_eq!(index["index"]["images"]["format"], "products:1.0");
        assert_eq!(index["index"]["images"]["path"], "streams/v1/images.json");
        let products = index["index"]["images"]["products"].as_array().unwrap();
        assert!(products.is_empty());
    }

    #[test]
    fn test_build_streams_index_json_with_products() {
        let products = vec!["alpine-edge".to_string(), "ubuntu-noble".to_string()];
        let index = build_streams_index_json(&products);
        let product_list = index["index"]["images"]["products"].as_array().unwrap();
        assert_eq!(product_list.len(), 2);
        assert_eq!(product_list[0], "alpine-edge");
        assert_eq!(product_list[1], "ubuntu-noble");
    }

    // -----------------------------------------------------------------------
    // RepoInfo struct construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_info_construction_hosted() {
        let info = RepoInfo {
            id: Uuid::new_v4(),
            key: String::new(),
            storage_path: "/data/incus".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: None,
        };
        assert_eq!(info.repo_type, "hosted");
        assert_eq!(info.storage_path, "/data/incus");
        assert!(info.upstream_url.is_none());
    }

    #[test]
    fn test_repo_info_construction_remote() {
        let info = RepoInfo {
            id: Uuid::new_v4(),
            key: String::new(),
            storage_path: "/data/incus-remote".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "remote".to_string(),
            upstream_url: Some("https://images.linuxcontainers.org".to_string()),
        };
        assert_eq!(info.repo_type, "remote");
        assert_eq!(
            info.upstream_url,
            Some("https://images.linuxcontainers.org".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // SHA256 hashing (used in streaming upload)
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256_deterministic() {
        let data = b"incus container image data";
        let mut h1 = Sha256::new();
        h1.update(data);
        let c1 = format!("{:x}", h1.finalize());

        let mut h2 = Sha256::new();
        h2.update(data);
        let c2 = format!("{:x}", h2.finalize());

        assert_eq!(c1, c2);
        assert_eq!(c1.len(), 64);
    }

    #[test]
    fn test_sha256_incremental_matches_whole() {
        let data = b"hello world from incus";

        let mut whole = Sha256::new();
        whole.update(data);
        let whole_hash = format!("{:x}", whole.finalize());

        let mut incremental = Sha256::new();
        incremental.update(&data[..5]);
        incremental.update(&data[5..11]);
        incremental.update(&data[11..]);
        let inc_hash = format!("{:x}", incremental.finalize());

        assert_eq!(whole_hash, inc_hash);
    }

    #[test]
    fn test_sha256_empty_input() {
        let mut hasher = Sha256::new();
        hasher.update(b"");
        let hash = format!("{:x}", hasher.finalize());
        assert_eq!(hash.len(), 64);
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    // -----------------------------------------------------------------------
    // Error helpers
    // -----------------------------------------------------------------------

    #[test]
    fn test_db_err_produces_500() {
        let resp = db_err("connection refused");
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_fs_err_produces_500() {
        let resp = fs_err("write to disk", "permission denied");
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // -----------------------------------------------------------------------
    // Content-Disposition header value construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_content_disposition_format() {
        let filename = "incus.tar.xz";
        let header = format!("attachment; filename=\"{}\"", filename);
        assert_eq!(header, "attachment; filename=\"incus.tar.xz\"");
    }

    #[test]
    fn test_content_disposition_squashfs() {
        let filename = "rootfs.squashfs";
        let header = format!("attachment; filename=\"{}\"", filename);
        assert_eq!(header, "attachment; filename=\"rootfs.squashfs\"");
    }

    // -----------------------------------------------------------------------
    // Range header value construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_range_header_zero_bytes() {
        let range = format!("0-{}", 0i64);
        assert_eq!(range, "0-0");
    }

    #[test]
    fn test_range_header_large_value() {
        let range = format!("0-{}", 1_073_741_824i64);
        assert_eq!(range, "0-1073741824");
    }

    // -----------------------------------------------------------------------
    // Upload response JSON structure
    // -----------------------------------------------------------------------

    #[test]
    fn test_upload_response_json_structure() {
        let artifact_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let response_json = serde_json::json!({
            "id": artifact_id,
            "product": "ubuntu-noble",
            "version": "20240215",
            "file": "incus.tar.xz",
            "size": 524288000i64,
            "sha256": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        });

        assert_eq!(response_json["product"], "ubuntu-noble");
        assert_eq!(response_json["version"], "20240215");
        assert_eq!(response_json["file"], "incus.tar.xz");
        assert_eq!(response_json["size"], 524288000);
        assert_eq!(response_json["id"], "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn test_chunked_upload_start_response_json() {
        let session_id = Uuid::new_v4();
        let initial_bytes = 4096i64;
        let response_json = serde_json::json!({
            "session_id": session_id,
            "bytes_received": initial_bytes,
        });

        assert_eq!(response_json["bytes_received"], 4096);
        assert!(response_json["session_id"].is_string());
    }

    #[test]
    fn test_upload_progress_response_json() {
        let session_id = Uuid::new_v4();
        let response_json = serde_json::json!({
            "session_id": session_id,
            "artifact_path": "ubuntu-noble/20240215/incus.tar.xz",
            "bytes_received": 1048576i64,
        });

        assert_eq!(
            response_json["artifact_path"],
            "ubuntu-noble/20240215/incus.tar.xz"
        );
        assert_eq!(response_json["bytes_received"], 1048576);
    }

    // -----------------------------------------------------------------------
    // SimpleStreams catalog product entry construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_simplestreams_product_entry_with_all_metadata() {
        let arch = "amd64";
        let os = Some("Ubuntu");
        let release = Some("noble");

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

        assert_eq!(p["arch"], "amd64");
        assert_eq!(p["os"], "Ubuntu");
        assert_eq!(p["release"], "noble");
        assert!(p["versions"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_simplestreams_product_entry_without_os_release() {
        let arch = "arm64";
        let os: Option<&str> = None;
        let release: Option<&str> = None;

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

        assert_eq!(p["arch"], "arm64");
        assert!(p.get("os").is_none());
        assert!(p.get("release").is_none());
    }

    #[test]
    fn test_simplestreams_item_json() {
        let ftype = "squashfs";
        let checksum = "abc123";
        let download_url = "/incus/repo/images/ubuntu/v1/rootfs.squashfs";
        let size_bytes = 256_000_000i64;

        let item = serde_json::json!({
            "ftype": ftype,
            "sha256": checksum,
            "path": download_url,
            "size": size_bytes,
        });

        assert_eq!(item["ftype"], "squashfs");
        assert_eq!(item["sha256"], "abc123");
        assert_eq!(item["path"], "/incus/repo/images/ubuntu/v1/rootfs.squashfs");
        assert_eq!(item["size"], 256_000_000);
    }

    #[test]
    fn test_simplestreams_catalog_format() {
        let products: HashMap<String, serde_json::Value> = HashMap::new();
        let catalog = serde_json::json!({
            "format": "products:1.0",
            "products": products
        });

        assert_eq!(catalog["format"], "products:1.0");
        assert!(catalog["products"].as_object().unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // Version entry construction in catalog
    // -----------------------------------------------------------------------

    #[test]
    fn test_version_entry_items_insertion() {
        let mut version_entry = serde_json::json!({"items": {}});
        let item = serde_json::json!({
            "ftype": "squashfs",
            "sha256": "abc",
            "path": "/incus/repo/images/p/v/rootfs.squashfs",
            "size": 100,
        });

        let ftype = "squashfs";
        let item_key = simplestreams_item_key(ftype);

        if let Some(items) = version_entry
            .get_mut("items")
            .and_then(|i| i.as_object_mut())
        {
            items.insert(item_key.to_string(), item.clone());
        }

        assert_eq!(version_entry["items"]["rootfs"]["ftype"], "squashfs");
    }

    #[test]
    fn test_version_entry_tarball_insertion() {
        let mut version_entry = serde_json::json!({"items": {}});
        let item = serde_json::json!({
            "ftype": "incus.tar.xz",
            "sha256": "def",
            "path": "/incus/repo/images/p/v/incus.tar.xz",
            "size": 200,
        });

        let ftype = "incus.tar.xz";
        let item_key = simplestreams_item_key(ftype);

        if let Some(items) = version_entry
            .get_mut("items")
            .and_then(|i| i.as_object_mut())
        {
            items.insert(item_key.to_string(), item.clone());
        }

        assert_eq!(
            version_entry["items"]["incus.tar.xz"]["ftype"],
            "incus.tar.xz"
        );
    }

    // -----------------------------------------------------------------------
    // Full metadata extraction pipeline (pure parts)
    // -----------------------------------------------------------------------

    #[test]
    fn test_full_metadata_extraction_pipeline() {
        let metadata = serde_json::json!({
            "image_metadata": {
                "architecture": "arm64",
                "os": "Alpine",
                "release": "3.19"
            }
        });

        let arch = extract_arch_from_metadata(Some(&metadata));
        let os = extract_os_from_metadata(Some(&metadata));
        let release = extract_release_from_metadata(Some(&metadata));

        assert_eq!(arch, "arm64");
        assert_eq!(os, Some("Alpine"));
        assert_eq!(release, Some("3.19"));
    }

    #[test]
    fn test_metadata_extraction_with_null_fields() {
        let metadata = serde_json::json!({
            "image_metadata": {
                "architecture": "amd64",
                "os": null,
                "release": null
            }
        });

        let arch = extract_arch_from_metadata(Some(&metadata));
        let os = extract_os_from_metadata(Some(&metadata));
        let release = extract_release_from_metadata(Some(&metadata));

        assert_eq!(arch, "amd64");
        assert_eq!(os, None);
        assert_eq!(release, None);
    }

    // -----------------------------------------------------------------------
    // End-to-end path/URL consistency
    // -----------------------------------------------------------------------

    #[test]
    fn test_artifact_path_used_in_download_url() {
        let product = "ubuntu-noble";
        let version = "20240215";
        let filename = "incus.tar.xz";
        let artifact_path = build_artifact_path(product, version, filename);
        let download_url = build_download_url("my-repo", product, version, filename);

        assert_eq!(artifact_path, "ubuntu-noble/20240215/incus.tar.xz");
        assert!(download_url.ends_with(&artifact_path));
    }

    #[test]
    fn test_storage_key_contains_artifact_path() {
        let repo_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let artifact_path = build_artifact_path("alpine", "v3.19", "rootfs.squashfs");
        let storage_key = build_storage_key(&repo_id, &artifact_path);

        assert!(storage_key.starts_with("incus/"));
        assert!(storage_key.ends_with(&artifact_path));
        assert!(storage_key.contains(&repo_id.to_string()));
    }

    #[test]
    fn test_content_type_consistent_between_upload_and_download() {
        let path = "ubuntu/20240215/incus.tar.xz";
        let filename = filename_from_path(path);
        assert_eq!(
            content_type_for_artifact(path),
            content_type_for_download(filename)
        );
    }

    #[test]
    fn test_content_type_tar_gz_consistent() {
        let path = "ubuntu/20240215/incus.tar.gz";
        let filename = filename_from_path(path);
        assert_eq!(
            content_type_for_artifact(path),
            content_type_for_download(filename)
        );
    }
}
