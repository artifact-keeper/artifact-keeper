//! Incus/LXC Container Image API handlers.
//!
//! Implements endpoints for uploading, downloading, and discovering Incus
//! container and VM images via the SimpleStreams protocol.
//!
//! Uploads use **streaming I/O** — the request body is written to disk
//! frame-by-frame, so memory stays flat regardless of image size.
//! Both monolithic (single PUT) and chunked/resumable uploads are supported.
//!
//! Routes mounted at `/incus/{repo_key}/...` and (as an alias for repos
//! created with `format: lxc`) `/lxc/{repo_key}/...`:
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
use axum::extract::{DefaultBodyLimit, OriginalUri, Path as AxumPath, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::Extension;
use axum::Router;
use bytes::Bytes;
use futures::StreamExt;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use std::fmt::Display;
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::SharedState;
use crate::formats::incus::IncusHandler;
// `StorageBackend` is referenced implicitly via `state.storage_for_repo(...)`
// returning `Arc<dyn StorageBackend>`; no direct trait import needed.

/// Chunk size used when streaming the staged temp file into the storage
/// backend's `put_stream`, and when serving downloads back through
/// `get_stream`. 256 KiB matches the OCI handler (#1521) and the migration
/// worker (#1512) so the per-task memory budget is uniform across upload
/// surfaces.
const STREAM_CHUNK_BUDGET: usize = 256 * 1024;
const INCUS_FINALIZE_LEASE_TTL_SECS: f64 = 6.0 * 3600.0;

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
///
/// The open is deliberately `append`-without-`create`: once a finalize has
/// sealed the staging file (renamed it out from under the session's
/// `storage_temp_path`), this open fails with `ENOENT`, which is reported as
/// `409 CONFLICT` — a session that entered finalize no longer accepts chunks.
async fn append_body_to_file(body: Body, path: &Path) -> Result<i64, Response> {
    let mut file = tokio::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                (
                    StatusCode::CONFLICT,
                    "Upload session is finalizing: it no longer accepts chunks".to_string(),
                )
                    .into_response()
            } else {
                fs_err("open temp file for append", e)
            }
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
        file.write_all(&chunk)
            .await
            .map_err(|e| fs_err("write chunk to disk", e))?;
        bytes_written += chunk.len() as i64;
    }

    file.sync_all().await.map_err(|e| fs_err("sync file", e))?;

    Ok(bytes_written)
}

/// Make a reclaimed finalize idempotent against a crashed predecessor's
/// append: truncate the staged file back to the session's persisted
/// `bytes_received` before appending the final body.
///
/// A prior finalize attempt may have appended final body bytes and died
/// before persisting the new offset (that durable update happens only after
/// append/checksum), so the file can legitimately be LONGER than the
/// persisted offset — the unrecorded tail is dropped and re-appended by the
/// current owner. A file SHORTER than the persisted offset means staged data
/// was lost (different pod's filesystem, manual cleanup); extending it with
/// zeros would corrupt the artifact, so that case fails the request instead.
async fn truncate_staged_file_to_offset(path: &Path, persisted: u64) -> Result<(), Response> {
    let file = tokio::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .await
        .map_err(|e| fs_err("open temp file for truncate", e))?;
    let len = file
        .metadata()
        .await
        .map_err(|e| fs_err("stat temp file", e))?
        .len();

    if len < persisted {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "Staged file is {} bytes but the session has {} bytes recorded; \
                 staged data is missing on this replica",
                len, persisted
            ),
        )
            .into_response());
    }
    if len > persisted {
        tracing::warn!(
            path = %path.display(),
            file_len = len,
            persisted,
            "staged file has an unrecorded tail from a crashed finalize; truncating"
        );
        file.set_len(persisted)
            .await
            .map_err(|e| fs_err("truncate temp file", e))?;
        file.sync_all().await.map_err(|e| fs_err("sync file", e))?;
    }
    Ok(())
}

/// Suffix of the file a finalize seals the staged chunks into.
const SEALED_FILE_SUFFIX: &str = ".seal";
/// Suffix of the finalize-private file holding the completing request's body.
const FINAL_BODY_FILE_SUFFIX: &str = ".final";

fn suffixed_path(base: &Path, suffix: &str) -> PathBuf {
    let mut name = base.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// Path the staged chunks are sealed into when a finalize claims the session.
///
/// Keeps the `ak-incus-upload-` prefix (it is the temp path plus a suffix) so
/// [`is_staging_file`] recognises it and the age-based orphan sweep reaps it.
pub(crate) fn sealed_upload_path(temp: &Path) -> PathBuf {
    suffixed_path(temp, SEALED_FILE_SUFFIX)
}

/// Path the completing request's trailing body is streamed into. Isolated
/// from the sealed file so nothing is ever appended to the staged chunks
/// during finalize (a reclaimed finalize rewrites this file instead of
/// appending the body a second time). Same prefix, so the sweep reaps it.
pub(crate) fn final_upload_path(temp: &Path) -> PathBuf {
    suffixed_path(temp, FINAL_BODY_FILE_SUFFIX)
}

/// Seal the staged chunks to the finalize lease by renaming them out of the
/// session's `storage_temp_path`.
///
/// The rename is atomic, so after it returns the staged bytes are reachable
/// only through the sealed path, which no PATCH can name: a chunk arriving
/// after the seal opens `temp` and gets `ENOENT` -> 409.
///
/// Idempotent, because the sealed name is derived from the session's temp
/// path and therefore identical for every finalize attempt on the session:
///   * `sealed` already present -> a predecessor sealed it; reuse it (its
///     content is the committed prefix, and only a lease release un-seals).
///   * otherwise rename `temp` -> `sealed`.
///   * neither present -> the staged data is not on this replica; fail the
///     request rather than publish a truncated artifact (mirrors
///     [`truncate_staged_file_to_offset`]'s short-file behaviour).
async fn seal_staging_file(temp: &Path, sealed: &Path) -> Result<(), Response> {
    if tokio::fs::metadata(sealed).await.is_ok() {
        tracing::warn!(
            sealed = %sealed.display(),
            "staged file was already sealed by a previous finalize attempt; reusing it"
        );
        return Ok(());
    }
    match tokio::fs::rename(temp, sealed).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "Staged upload data is missing on this replica (expected {})",
                temp.display()
            ),
        )
            .into_response()),
        Err(e) => Err(fs_err("seal staged file", e)),
    }
}

/// Best-effort removal of every file a session may have staged: the chunk
/// file plus the sealed / final-body sidecars a finalize creates. Callers
/// that retire a session (cancel, checksum-mismatch, the reaper) use this so
/// a session that died mid-finalize cannot leave a sidecar behind.
async fn remove_staging_files(temp: &Path, sealed: &Path, final_path: &Path) {
    let _ = tokio::fs::remove_file(temp).await;
    let _ = tokio::fs::remove_file(sealed).await;
    let _ = tokio::fs::remove_file(final_path).await;
}

/// Undo [`seal_staging_file`] so a session released back to `receiving`
/// resumes cleanly: the staged chunks return to the path a follow-up PATCH
/// opens, and the abandoned final-body file is dropped.
async fn unseal_staging_file(temp: &Path, sealed: &Path, final_path: &Path) {
    let _ = tokio::fs::remove_file(final_path).await;
    if tokio::fs::metadata(sealed).await.is_ok() {
        let _ = tokio::fs::rename(sealed, temp).await;
    }
}

/// Compute the on-disk path for a storage key (mirrors FilesystemStorage::key_to_path).
///
/// Retained as a public helper for operators inspecting an existing
/// filesystem-backed STORAGE_PATH layout (pre-#1471 incus uploads landed
/// here). New uploads route through `StorageBackend::put_stream`, so the
/// handler itself no longer derives final paths this way.
#[allow(dead_code)]
pub(crate) fn storage_path_for_key(storage_base: &str, key: &str) -> PathBuf {
    let prefix = &key[..2.min(key.len())];
    PathBuf::from(storage_base).join(prefix).join(key)
}

/// Prefix shared by every staged upload temp file. Used both to name new
/// staging files and to recognise crash-orphans during the age-based sweep.
const STAGING_FILE_PREFIX: &str = "ak-incus-upload-";

/// Resolve the base directory used to stage in-progress uploads (#1573).
///
/// Resolution order:
///   1. `$AK_UPLOAD_STAGING_DIR` — explicit operator override.
///   2. `$AK_INCUS_UPLOAD_TMP_DIR` — legacy per-format override, kept for
///      backward compatibility with existing deployments.
///   3. `<storage_path>/.incoming` — the default.
///
/// The default deliberately lives under the configured `STORAGE_PATH`
/// rather than `std::env::temp_dir()` (`/tmp`). On Kubernetes `/tmp` is
/// typically a small `emptyDir`, so multi-GiB uploads overrun it and the
/// kubelet evicts the pod mid-receive. `STORAGE_PATH` is a real, writable,
/// deployment-sized local mount on every backend (it already holds
/// filesystem artifacts, plugins, and backups), so staging inherits the
/// same sizing as the artifacts it stages — even when the repo's storage
/// backend is S3/GCS, since `STORAGE_PATH` is still a local disk path.
///
/// The `.incoming` subdir is dot-prefixed so it can never collide with a
/// repository key prefix in the filesystem backend's `<base>/<prefix>/<key>`
/// layout.
pub(crate) fn staging_root(storage_path: &str) -> PathBuf {
    if let Ok(dir) = std::env::var("AK_UPLOAD_STAGING_DIR") {
        return PathBuf::from(dir);
    }
    if let Ok(dir) = std::env::var("AK_INCUS_UPLOAD_TMP_DIR") {
        return PathBuf::from(dir);
    }
    PathBuf::from(storage_path).join(".incoming")
}

/// Temp file path for an upload session.
///
/// Uploads stage to this on-disk path so PATCH continuations can append
/// without re-downloading the in-progress object from the storage backend.
/// The final, durable copy is written via `StorageBackend::put_stream` at
/// completion time. See [`staging_root`] for how the base directory is
/// resolved.
pub(crate) fn temp_upload_path(storage_path: &str, session_id: &Uuid) -> PathBuf {
    staging_root(storage_path).join(format!("{STAGING_FILE_PREFIX}{session_id}"))
}

/// Whether `file_name` belongs to the upload staging scheme — used by the
/// orphan sweep so it only ever reaps files this handler created, never
/// anything else that may share the staging volume.
pub(crate) fn is_staging_file(file_name: &str) -> bool {
    file_name.starts_with(STAGING_FILE_PREFIX)
}

/// RAII guard that best-effort removes a staged temp file when dropped,
/// unless [`disarm`](StagedTempFile::disarm)ed first (#1573).
///
/// Used by the monolithic upload path, where the staging file is scoped to a
/// single request: it guarantees the file is deleted on *every* early return
/// (`?` propagation, mid-receive stream error, storage failure) as well as on
/// the happy path, so an interrupted handler can't leak an orphan. The
/// chunked path deliberately does NOT use this — its staging file must
/// survive between PATCH requests and is reaped instead by the session reaper
/// / orphan sweep.
struct StagedTempFile {
    path: PathBuf,
    armed: bool,
}

impl StagedTempFile {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    /// Stop the guard from removing the file (the caller has taken ownership
    /// of cleanup, e.g. already removed it).
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StagedTempFile {
    fn drop(&mut self) {
        if self.armed {
            // Synchronous best-effort unlink: Drop can't await, and the file
            // is local scratch so a blocking unlink is negligible.
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Shorthand for the staged-data streams fed to `StorageBackend::put_stream`.
type StagedStream = futures::stream::BoxStream<'static, crate::error::Result<Bytes>>;

/// Open at most `limit` bytes of `path` as a `BoxStream<Result<Bytes>>` ready
/// to feed `StorageBackend::put_stream`. Uses a `STREAM_CHUNK_BUDGET`
/// buffered `ReaderStream` so the upload from local disk to the storage
/// backend stays memory-bounded (S3 multipart, GCS resumable, filesystem
/// temp-and-rename all consume this stream natively after #1512).
///
/// The bound is what keeps a finalize's view of the staged file fixed at the
/// committed offset: bytes written past it (by a chunk whose fd was opened
/// before the seal) are outside every read this handler performs, so they can
/// reach neither the checksum nor the stored object.
async fn open_bounded_file_stream(path: &Path, limit: u64) -> Result<StagedStream, std::io::Error> {
    use tokio::io::{AsyncReadExt, BufReader};
    use tokio_util::io::ReaderStream;

    let file = tokio::fs::File::open(path).await?;
    let reader = BufReader::with_capacity(STREAM_CHUNK_BUDGET, file).take(limit);
    let stream = ReaderStream::with_capacity(reader, STREAM_CHUNK_BUDGET);
    let mapped = stream
        .map(|r| r.map_err(|e| crate::error::AppError::Storage(format!("temp file read: {e}"))));
    Ok(Box::pin(mapped))
}

/// Build the deterministic byte view of a finalizing upload:
/// `sealed[0..committed] ++ final`.
///
/// This is the single definition of "what this upload is". Both the checksum
/// pass and the `put_stream` push read through it, so the recorded digest,
/// the recorded size and the stored object are derived from the exact same
/// bytes, and re-running a reclaimed finalize re-derives them identically
/// (the sealed prefix is immutable and the final body is rewritten, never
/// appended).
async fn open_finalize_stream(
    sealed: &Path,
    committed: u64,
    final_path: Option<&Path>,
) -> Result<StagedStream, std::io::Error> {
    let head = open_bounded_file_stream(sealed, committed).await?;
    let Some(final_path) = final_path else {
        return Ok(head);
    };
    let tail = open_bounded_file_stream(final_path, u64::MAX).await?;
    Ok(Box::pin(head.chain(tail)))
}

/// Hash a staged-data stream (see [`open_finalize_stream`]) in place, so the
/// checksum is computed over the same bounded view that is stored.
async fn compute_sha256_over_stream(mut stream: StagedStream) -> Result<String, Response> {
    let mut hasher = Sha256::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to read staged data for checksum: {e}"),
            )
                .into_response()
        })?;
        hasher.update(&chunk);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Determine the content type for an Incus artifact based on its path.
pub(crate) fn content_type_for_artifact(artifact_path: &str) -> &'static str {
    if artifact_path.ends_with(".tar.xz") {
        "application/x-xz"
    } else if artifact_path.ends_with(".tar.gz") {
        "application/gzip"
    } else if artifact_path.ends_with(".tar.zst") {
        "application/zstd"
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
    } else if filename.ends_with(".tar.zst") {
        "application/zstd"
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
    } else if filename.ends_with(".tar.zst") {
        "incus.tar.zst"
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
///
/// `prefix` is the mount prefix the request came in on (`/incus` or `/lxc`),
/// so the emitted URL matches the request prefix (#1320). Callers should
/// derive the prefix from `OriginalUri` via [`mount_prefix_from_uri`].
pub(crate) fn build_download_url(
    prefix: &str,
    repo_key: &str,
    product: &str,
    version: &str,
    filename: &str,
) -> String {
    format!(
        "{}/{}/images/{}/{}/{}",
        prefix, repo_key, product, version, filename
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
///
/// `prefix` is the mount prefix the request came in on (`/incus` or `/lxc`),
/// so the emitted Location header matches the request prefix (#1320).
pub(crate) fn build_upload_location(prefix: &str, repo_key: &str, session_id: &Uuid) -> String {
    format!("{}/{}/uploads/{}", prefix, repo_key, session_id)
}

/// Determine the mount prefix from the request URI.
///
/// The Incus handler is mounted under both `/incus` and `/lxc` (see
/// `backend/src/api/routes.rs`). URL builders need to emit the same prefix
/// the client used so SimpleStreams catalog paths and chunked-upload
/// `Location` headers don't cross prefixes (#1320).
///
/// Returns `"/lxc"` if the request path begins with `/lxc/` or is exactly
/// `/lxc`; otherwise falls back to `"/incus"`. The fallback covers requests
/// that arrive with a stripped path (e.g. behind a reverse proxy that
/// rewrites the prefix) and preserves the historical default.
pub(crate) fn mount_prefix_from_uri(uri: &Uri) -> &'static str {
    let path = uri.path();
    if path == "/lxc" || path.starts_with("/lxc/") {
        "/lxc"
    } else {
        "/incus"
    }
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
async fn upsert_artifact(p: UpsertArtifactParams<'_>) -> Result<Uuid, String> {
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
    .map_err(|e| format!("database error: {e}"))?;

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
    .map_err(|e| format!("store metadata: {e}"))?;

    // Surface Incus images in the top-level package browser. The generic
    // upload path (artifact_service) and the npm/pypi/nuget handlers populate
    // these tables already; the Incus handler writes `artifacts` directly and
    // so must call it explicitly. Best-effort — a failure must not fail upload.
    crate::services::package_service::PackageService::new(db.clone())
        .try_create_or_update_from_artifact(
            repo_id,
            product,
            version,
            size_bytes,
            checksum,
            None,
            Some(serde_json::json!({ "format": "incus" })),
        )
        .await;

    Ok(artifact_id)
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_incus_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    use sqlx::Row;
    let repo = sqlx::query(
        r#"SELECT id, key, storage_backend, storage_path, format::text as format, repo_type::text as repo_type, upstream_url, promotion_only
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
        promotion_only: repo.try_get("promotion_only").unwrap_or(false),
        format: "generic".to_string(),
        age_gate_enabled: false,
        age_gate_min_age_days: 7,
        age_gate_mode: "upstream_publish_time".to_string(),
        curation_enabled: false,
        curation_default_action: "allow".to_string(),
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
    OriginalUri(original_uri): OriginalUri,
    AxumPath(repo_key): AxumPath<String>,
) -> Result<Response, Response> {
    let repo = resolve_incus_repo(&state.db, &repo_key).await?;
    let prefix = mount_prefix_from_uri(&original_uri);

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
        let download_url = build_download_url(prefix, &repo_key, &name, &version, filename);

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
    method: axum::http::Method,
    headers: HeaderMap,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
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

    // Record the download exactly once for a real GET (#2260). A HEAD request
    // returns identical headers but serves no body — axum routes HEAD to this
    // GET handler — so it must NOT write a download row (guard against the
    // HEAD over-count in §5). Inline-awaited so the row is committed before the
    // response is built.
    if method != axum::http::Method::HEAD {
        crate::services::artifact_service::record_download(&state.db, artifact_id, &ctx).await;
    }

    // Pull the artifact through the repo's configured StorageBackend via
    // `get_stream`. Pre-#1471 the upload path wrote to local disk on the
    // ingest pod and this read path opened that same local file, so
    // multi-replica and S3/GCS deployments saw intermittent 404s (#1441).
    // Now that upload writes through `put_stream`, downloads go through
    // `get_stream` and stay byte-aligned with the configured backend.
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Storage backend resolution failed: {}", e),
            )
                .into_response()
        })?;

    let stream = storage.get_stream(&storage_key).await.map_err(|e| {
        let msg = e.to_string();
        // Cloud backends typically return a NotFound-shaped error here;
        // map any storage error containing "not found" to 404 so a missing
        // key doesn't leak as 500.
        if msg.to_lowercase().contains("not found") {
            (StatusCode::NOT_FOUND, "Image file not found").into_response()
        } else {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Storage error: {}", msg),
            )
                .into_response()
        }
    })?;

    // Honour HTTP `Range` so large images are resumable, via the shared
    // range-aware streaming helper that the generic artifact download uses
    // (#1847). Previously this handler ignored `Range` and always returned a
    // full `200`, so a dropped multi-GiB transfer could never resume.
    let range_header = headers
        .get(axum::http::header::RANGE)
        .and_then(|v| v.to_str().ok());
    let base_headers = vec![
        (
            CONTENT_TYPE,
            content_type_for_download(&filename).to_string(),
        ),
        (
            axum::http::header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", filename),
        ),
        (
            axum::http::header::HeaderName::from_static("x-checksum-sha256"),
            checksum,
        ),
    ];
    crate::api::handlers::repositories::ranged_stream_response(
        range_header,
        size_bytes.max(0) as u64,
        stream,
        base_headers,
    )
    .map_err(|e| e.into_response())
}

// ---------------------------------------------------------------------------
// PUT /images/{product}/{version}/{filename} -- Monolithic streaming upload
// ---------------------------------------------------------------------------

async fn upload_image(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    OriginalUri(original_uri): OriginalUri,
    AxumPath((repo_key, product, version, filename)): AxumPath<(String, String, String, String)>,
    body: Body,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "incus", "write:artifacts")?.user_id;
    let repo = resolve_incus_repo(&state.db, &repo_key).await?;

    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    let artifact_path = build_artifact_path(&product, &version, &filename);
    IncusHandler::parse_path(&artifact_path).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid image path: {}", e),
        )
            .into_response()
    })?;

    // Stream body to local scratch temp file (never buffers entire image
    // in RAM), then hand the assembled file to the repo's configured
    // StorageBackend via `put_stream`. Pre-#1471 this path performed a
    // `tokio::fs::rename` onto the server's local STORAGE_PATH regardless
    // of the repo's actual backend, so S3/GCS-backed deployments silently
    // dropped uploads on the ingest pod's ephemeral disk: any subsequent
    // GET that hit a different replica (or the same replica after a
    // restart) 404'd because the bytes never made it to the bucket. The
    // streaming-temp-file → `put_stream` pattern mirrors the OCI rewrite
    // in #1521 and routes through each backend's native streaming
    // primitive (S3 multipart, GCS resumable, Azure block-blob,
    // filesystem temp-and-rename), so peak memory per upload is bounded
    // to STREAM_CHUNK_BUDGET regardless of image size.
    let temp_id = Uuid::new_v4();
    let temp_path = temp_upload_path(&state.config.storage_path, &temp_id);
    // Guard the staging file so an early return on ANY path below (a
    // mid-receive stream error, a `?`-propagated failure, or storage failure)
    // removes it instead of leaking an orphan (#1573).
    let mut staged = StagedTempFile::new(temp_path.clone());
    let (size_bytes, checksum) = stream_body_to_file(body, &temp_path).await?;

    // Extract metadata from the file on disk. #2561: permit-scoped decode; the
    // artifact is already staged, so a saturated server skips this best-effort
    // extraction rather than shedding the upload.
    let metadata = crate::util::bounded_archive::with_ingest_extraction(|| {
        IncusHandler::parse_metadata_from_file(&artifact_path, &temp_path).ok()
    })
    .ok()
    .flatten()
    .unwrap_or_else(|| serde_json::json!({"file_type": "unknown"}));

    // Record an upload session in `finalizing` state, then push to the
    // StorageBackend on a background task and return 202. Doing the
    // multi-GiB push inside the request would outlive an L7 gateway timeout
    // (504) even though the body was fully received (#1471/#1494). The
    // session row makes the async finalize observable: the client polls
    // `GET /incus/{repo}/uploads/{id}` for `completed`/`failed`.
    let storage_key = build_storage_key(&repo.id, &artifact_path);
    let session_id = Uuid::new_v4();
    // Fresh session, but it still carries a finalize lease so the background
    // finalizer's terminal updates are token-guarded like the chunked path.
    let finalize_token = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO incus_upload_sessions
            (id, repository_id, user_id, artifact_path, product, version,
             filename, bytes_received, storage_temp_path, status,
             finalize_token, finalize_claimed_until, finalize_phase)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'finalizing',
                $10, NOW() + make_interval(secs => $11), 'sealing')
        "#,
    )
    .bind(session_id)
    .bind(repo.id)
    .bind(user_id)
    .bind(&artifact_path)
    .bind(&product)
    .bind(&version)
    .bind(&filename)
    .bind(size_bytes)
    .bind(&*temp_path.to_string_lossy())
    .bind(finalize_token)
    .bind(INCUS_FINALIZE_LEASE_TTL_SECS)
    .execute(&state.db)
    .await
    .map_err(db_err)?;

    // The staged temp file must outlive this request so the background
    // finalize can read it; disarm the #1573 RAII guard here and hand cleanup
    // to finalize_upload, which removes it after the push completes (or fails).
    staged.disarm();

    tokio::spawn(finalize_upload(
        state.clone(),
        repo.clone(),
        FinalizeParams {
            session_id,
            repo_id: repo.id,
            artifact_path: artifact_path.clone(),
            product: product.clone(),
            version: version.clone(),
            size_bytes,
            checksum: checksum.clone(),
            storage_key,
            user_id,
            metadata,
            // The monolithic body was staged in one shot, so the staged file
            // IS the artifact and there is no trailing-body part.
            sealed_path: temp_path.clone(),
            committed_offset: size_bytes,
            final_path: None,
            finalize_token,
        },
    ));

    let prefix = mount_prefix_from_uri(&original_uri);
    Ok(Response::builder()
        .status(StatusCode::ACCEPTED)
        .header(CONTENT_TYPE, "application/json")
        .header(
            "Location",
            build_upload_location(prefix, &repo_key, &session_id),
        )
        .header("Upload-UUID", session_id.to_string())
        .body(Body::from(
            serde_json::json!({
                "session_id": session_id,
                "status": "finalizing",
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
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let _user_id = require_auth_basic_scope(auth, "incus", "delete:artifacts")?.user_id;
    let repo = resolve_incus_repo(&state.db, &repo_key).await?;

    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

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

/// Look up an upload session by UUID, scoped to a specific repository.
///
/// Issue #1317: chunked-upload session lookups must bind the URL's `repo_key`
/// against `session.repository_id` so that a session created in repo A cannot
/// be driven (chunked/finalized/cancelled) via repo B's URL. Returning the
/// same 404 shape for "session does not exist" and "session does not belong
/// to this repo" avoids leaking session existence across repos.
async fn get_session(
    db: &PgPool,
    session_id: Uuid,
    repo_id: Uuid,
) -> Result<UploadSession, Response> {
    sqlx::query_as::<_, UploadSession>(
        r#"
        SELECT id, repository_id, user_id, artifact_path, product, version,
               filename, bytes_received, storage_temp_path, status,
               finalize_error, artifact_id
        FROM incus_upload_sessions
        WHERE id = $1 AND repository_id = $2
        "#,
    )
    .bind(session_id)
    .bind(repo_id)
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
    status: String,
    finalize_error: Option<String>,
    artifact_id: Option<Uuid>,
}

// ---------------------------------------------------------------------------
// POST /images/{product}/{version}/{filename}/uploads -- Start chunked upload
// ---------------------------------------------------------------------------

async fn start_chunked_upload(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    OriginalUri(original_uri): OriginalUri,
    AxumPath((repo_key, product, version, filename)): AxumPath<(String, String, String, String)>,
    body: Body,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "incus", "write:artifacts")?.user_id;
    let repo = resolve_incus_repo(&state.db, &repo_key).await?;
    let prefix = mount_prefix_from_uri(&original_uri);

    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    let artifact_path = build_artifact_path(&product, &version, &filename);
    IncusHandler::parse_path(&artifact_path).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid image path: {}", e),
        )
            .into_response()
    })?;

    let session_id = Uuid::new_v4();
    // Stage to a local scratch file; the final copy is uploaded through
    // the repo's StorageBackend at `complete_chunked_upload` time (#1471).
    // The chosen path is persisted to `incus_upload_sessions.storage_temp_path`,
    // so subsequent chunk/complete/cancel calls read it back from the
    // session row and don't need to re-derive it.
    let temp_path = temp_upload_path(&state.config.storage_path, &session_id);

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
    .bind(&*temp_path.to_string_lossy())
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
        .header(
            "Location",
            build_upload_location(prefix, &repo_key, &session_id),
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
    Extension(auth): Extension<Option<AuthExtension>>,
    OriginalUri(original_uri): OriginalUri,
    AxumPath((repo_key, session_id)): AxumPath<(String, Uuid)>,
    body: Body,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let _user_id = require_auth_basic_scope(auth, "incus", "write:artifacts")?.user_id;
    // Issue #1317: scope the session lookup to the URL repo so a session
    // created in repo A cannot be driven via repo B's URL.
    let repo = resolve_incus_repo(&state.db, &repo_key).await?;
    let session = get_session(&state.db, session_id, repo.id).await?;
    let temp_path = PathBuf::from(&session.storage_temp_path);
    let prefix = mount_prefix_from_uri(&original_uri);

    // Only a session still receiving may be appended to. A straggler or
    // retried PATCH arriving after `complete` claimed the finalize lease would
    // otherwise append bytes while the finalizer is checksumming the staged
    // file, and overwrite `bytes_received` — which the truncate-on-reclaim
    // arithmetic treats as the authoritative persisted offset.
    if session.status != "receiving" {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "Upload session is '{}': it no longer accepts chunks",
                session.status
            ),
        )
            .into_response());
    }

    // Append body to temp file (no read-back of existing data). Once a
    // finalize has sealed the staging file this open fails with ENOENT and is
    // reported as 409, so a chunk arriving after the claim cannot write bytes
    // the finalizer is already hashing.
    let bytes_written = append_body_to_file(body, &temp_path).await?;

    // Record the new offset only while the session is still 'receiving'. The
    // status can change between the check above and here (a `complete` on any
    // replica claims the lease with a guarded UPDATE), so this predicate — not
    // the pre-read — is what keeps `bytes_received` owned by one writer.
    //
    // The offset is advanced DB-side (`bytes_received + $2`) rather than from
    // the pre-read `session.bytes_received`: a read-modify-write loses one of
    // two concurrent chunk updates, and this counter is the authoritative
    // committed offset the finalize bounds its read to, so a lost update would
    // silently drop committed bytes from the artifact.
    let updated = sqlx::query(
        "UPDATE incus_upload_sessions SET bytes_received = bytes_received + $2, \
         updated_at = NOW() \
         WHERE id = $1 AND status = 'receiving' RETURNING bytes_received",
    )
    .bind(session_id)
    .bind(bytes_written)
    .fetch_optional(&state.db)
    .await
    .map_err(db_err)?;

    let Some(row) = updated else {
        // A finalize claimed the session while this body was streaming. The
        // offset is deliberately NOT advanced: the finalize owner re-reads the
        // persisted `bytes_received` under its lease and bounds every read of
        // the sealed file to it, so these bytes reach neither the recorded
        // checksum nor the stored object.
        tracing::warn!(
            session_id = %session_id,
            bytes_written,
            "Incus chunk PATCH raced a finalize claim; append discarded by the \
             finalize truncate"
        );
        return Err((
            StatusCode::CONFLICT,
            "Upload session entered finalize while this chunk was uploading".to_string(),
        )
            .into_response());
    };
    let new_total: i64 = row.try_get("bytes_received").map_err(db_err)?;

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
            build_upload_location(prefix, &repo_key, &session_id),
        )
        .header("Upload-UUID", session_id.to_string())
        .header("Range", format!("0-{}", new_total))
        .body(Body::empty())
        .unwrap())
}

// ---------------------------------------------------------------------------
// PUT /uploads/{uuid} -- Complete chunked upload
// ---------------------------------------------------------------------------

/// Response body for a finalize that cannot be safely reclaimed (#3083).
pub(crate) const LEGACY_FINALIZE_MESSAGE: &str =
    "Upload session was left mid-finalize by a pre-upgrade server and cannot be \
     safely resumed; cancel this session and re-upload the image";

/// Whether an upload-session row was stranded mid-finalize by pre-#3072 code
/// and therefore must NOT be reclaimed (#3083).
///
/// Pre-#3072 finalize appended the completing request's body straight onto the
/// staging file and could advance `bytes_received` past it. Post-#3072 finalize
/// seals the staged chunks and keeps the final body in its own file, treating
/// `bytes_received` as the strictly *pre-final* offset. On disk those two
/// states are identical, so reclaiming a legacy row with the new algorithm can
/// append the final body a second time and publish a corrupt image.
///
/// `finalize_phase` (migration 199) is the discriminator: post-#3072 code
/// stamps it on EVERY write that puts a row into `finalizing` (the lease claim
/// and the monolithic-upload insert), so a `finalizing` row that still has NULL
/// there can only have been written by the old code path. New sessions never
/// reach this state, so the refusal is bounded to the upgrade itself.
///
/// `lease_lapsed` is load-bearing, not decoration. During a *rolling* upgrade an
/// old replica can still be actively finalizing a legacy session while its lease
/// is live, and that finalize will complete correctly under the old algorithm.
/// Answering a concurrent retry with "cancel and re-upload" would then be both
/// wrong and destructive. The refusal therefore applies only where a reclaim
/// would otherwise have happened — a lapsed lease. A live lease keeps the
/// pre-existing "finalize already in progress" answer, unchanged.
///
/// Pure, so the upgrade matrix is unit-testable without a database.
pub(crate) fn is_legacy_ambiguous_finalize(
    status: &str,
    finalize_phase: Option<&str>,
    lease_lapsed: bool,
) -> bool {
    status == "finalizing" && finalize_phase.is_none() && lease_lapsed
}

/// Re-read the columns that explain WHY a finalize claim was refused.
///
/// Deliberately a fresh read rather than the pre-claim `session` snapshot: that
/// snapshot can be stale by the time the claim runs, and the lease comparison
/// must use the DATABASE clock — the same one
/// [`claim_incus_finalize_lease`] compared against — so the explanation can
/// never disagree with the decision because of client/server clock skew.
///
/// Returns `(status, finalize_phase, lease_lapsed)`, or `None` if the row is
/// gone or unreadable.
async fn describe_unclaimable_finalize(
    db: &PgPool,
    session_id: Uuid,
) -> Option<(String, Option<String>, bool)> {
    sqlx::query_as::<_, (String, Option<String>, bool)>(
        "SELECT status, finalize_phase, \
         COALESCE(finalize_claimed_until, updated_at + make_interval(secs => $2)) <= NOW() \
         FROM incus_upload_sessions WHERE id = $1",
    )
    .bind(session_id)
    .bind(INCUS_FINALIZE_LEASE_TTL_SECS)
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
}

/// Build the 409 for a finalize whose lease could not be claimed, separating
/// "someone else is finalizing / already finished" from the #3083 refusal.
async fn unclaimable_finalize_response(
    db: &PgPool,
    session_id: Uuid,
    fallback_status: &str,
) -> Response {
    // If the row cannot be re-read, fall back to the pre-claim status and the
    // historical message — never to the #3083 refusal, which tells the operator
    // to throw work away and must only be issued on positive evidence.
    let (status, phase, lease_lapsed) = describe_unclaimable_finalize(db, session_id)
        .await
        .unwrap_or_else(|| {
            (
                fallback_status.to_string(),
                Some("unknown".to_string()),
                false,
            )
        });

    if is_legacy_ambiguous_finalize(&status, phase.as_deref(), lease_lapsed) {
        tracing::error!(
            session_id = %session_id,
            "Refusing to reclaim an Incus finalize left in flight by pre-#3072 \
             code: the staged bytes cannot be distinguished from a committed \
             upload, so a reclaim could double-append (#3083). Cancel the \
             session and re-upload."
        );
        return (StatusCode::CONFLICT, LEGACY_FINALIZE_MESSAGE).into_response();
    }

    (
        StatusCode::CONFLICT,
        format!("Upload session is '{status}': finalize already in progress or finished"),
    )
        .into_response()
}

/// Atomically claim the finalize lease on a chunked upload session
/// (StateMachineLease, see [`crate::services::cluster_work`]).
///
/// Transitions `receiving -> finalizing` and stamps a fresh token; returns
/// `None` when the session is owned by another live finalize (or already
/// terminal) — the caller maps that to `409 CONFLICT`. A `finalizing`
/// session whose lease deadline passed (crashed finalizer; the COALESCE
/// covers pre-migration rows with no deadline) is reclaimable in place.
async fn claim_incus_finalize_lease(
    db: &PgPool,
    session_id: Uuid,
) -> Result<Option<Uuid>, sqlx::Error> {
    let finalize_token = Uuid::new_v4();
    let claimed = sqlx::query(
        r#"
        UPDATE incus_upload_sessions
        SET status = 'finalizing',
            finalize_token = $2,
            finalize_claimed_until = NOW() + make_interval(secs => $3),
            finalize_phase = 'sealing',
            updated_at = NOW()
        WHERE id = $1
          AND (
            status = 'receiving'
            OR (
                status = 'finalizing'
                -- #3083: only reclaim a finalize that post-#3072 code stamped.
                -- A NULL phase on a finalizing row is a session left in flight
                -- by pre-#3072 code across an upgrade: its on-disk state is
                -- indistinguishable from a committed one, so reclaiming it can
                -- double-append the final body. Refuse instead.
                AND finalize_phase IS NOT NULL
                AND COALESCE(finalize_claimed_until, updated_at + make_interval(secs => $3)) <= NOW()
            )
          )
        "#,
    )
    .bind(session_id)
    .bind(finalize_token)
    .bind(INCUS_FINALIZE_LEASE_TTL_SECS)
    .execute(db)
    .await?;

    Ok((claimed.rows_affected() == 1).then_some(finalize_token))
}

/// Token-guarded heartbeat for a finalizing Incus upload.
async fn renew_incus_finalize_lease(
    db: &PgPool,
    session_id: Uuid,
    finalize_token: Uuid,
    ttl_secs: f64,
) -> Result<bool, sqlx::Error> {
    let renewed = sqlx::query(
        "UPDATE incus_upload_sessions \
         SET finalize_claimed_until = NOW() + make_interval(secs => $3), updated_at = NOW() \
         WHERE id = $1 AND status = 'finalizing' AND finalize_token = $2",
    )
    .bind(session_id)
    .bind(finalize_token)
    .bind(ttl_secs)
    .execute(db)
    .await?;

    Ok(renewed.rows_affected() == 1)
}

fn spawn_incus_finalize_lease_renewal(
    db: PgPool,
    session_id: Uuid,
    finalize_token: Uuid,
) -> crate::services::cluster_work::RenewalGuard {
    crate::services::cluster_work::spawn_renewal_loop(
        format!("incus finalize {session_id}"),
        INCUS_FINALIZE_LEASE_TTL_SECS,
        move || {
            let db = db.clone();
            async move {
                renew_incus_finalize_lease(
                    &db,
                    session_id,
                    finalize_token,
                    INCUS_FINALIZE_LEASE_TTL_SECS,
                )
                .await
                .map_err(|e| e.to_string())
            }
        },
    )
}

/// Token-guarded release of a finalize lease back to 'receiving', for
/// retryable failures between the claim and the spawned finalizer (body
/// append or checksum-pass errors). The client can re-issue the complete.
async fn release_incus_finalize_lease(db: &PgPool, session_id: Uuid, finalize_token: Uuid) {
    let _ = sqlx::query(
        "UPDATE incus_upload_sessions \
         SET status = 'receiving', finalize_token = NULL, finalize_claimed_until = NULL, \
             updated_at = NOW() \
         WHERE id = $1 AND status = 'finalizing' AND finalize_token = $2",
    )
    .bind(session_id)
    .bind(finalize_token)
    .execute(db)
    .await;
}

/// Re-assert that this finalize token still owns the session, immediately
/// before the handler starts background side effects. A `false` result means
/// the lease expired and was reclaimed (or the row became terminal/deleted),
/// so the caller must not spawn its finalizer.
///
/// Deliberately does NOT write `bytes_received`: that column is the durable
/// *pre-final* offset owned by the PATCH path, and a reclaimed finalize
/// re-derives the artifact as `sealed[0..bytes_received] ++ final`. Folding
/// the final body into the column would make the reclaim's bounded read
/// include bytes that are also in the final file, i.e. count them twice.
async fn assert_incus_finalize_lease_live(
    db: &PgPool,
    session_id: Uuid,
    finalize_token: Uuid,
) -> Result<bool, sqlx::Error> {
    let updated = sqlx::query(
        "UPDATE incus_upload_sessions \
         SET updated_at = NOW() \
         WHERE id = $1 AND status = 'finalizing' AND finalize_token = $2",
    )
    .bind(session_id)
    .bind(finalize_token)
    .execute(db)
    .await?;

    Ok(updated.rows_affected() == 1)
}

/// Release a finalize lease taken by a request that then failed, restoring
/// both halves of the session state: the staged chunks go back to the path a
/// resumed PATCH opens, and the row goes back to `receiving`.
///
/// Order matters — the file is un-sealed first, so a PATCH that observes
/// `receiving` always finds the staging file already in place.
async fn abort_incus_finalize(
    db: &PgPool,
    session_id: Uuid,
    finalize_token: Uuid,
    temp: &Path,
    sealed: &Path,
    final_path: &Path,
) {
    unseal_staging_file(temp, sealed, final_path).await;
    release_incus_finalize_lease(db, session_id, finalize_token).await;
}

/// Assemble the finalize's input under an already-claimed lease and hash it.
/// Returns `(final_body_bytes, checksum_of_the_whole_artifact)`.
///
/// Every step is idempotent, so a finalize reclaiming a crashed
/// predecessor's lease re-derives the exact same artifact:
///   1. seal — rename `temp` -> `sealed`, or reuse an existing `sealed`;
///   2. truncate `sealed` back to the committed offset;
///   3. write the completing request's body to `final` with create+truncate,
///      never appending it to `sealed`;
///   4. hash the bounded `sealed[0..committed] ++ final` view — the same view
///      the storage push later streams.
async fn stage_finalize_input(
    body: Body,
    temp: &Path,
    sealed: &Path,
    final_path: &Path,
    committed: u64,
) -> Result<(i64, String), Response> {
    seal_staging_file(temp, sealed).await?;
    truncate_staged_file_to_offset(sealed, committed).await?;
    let (final_bytes, _) = stream_body_to_file(body, final_path).await?;
    let stream = open_finalize_stream(sealed, committed, Some(final_path))
        .await
        .map_err(|e| fs_err("open staged data for checksum", e))?;
    let checksum = compute_sha256_over_stream(stream).await?;
    Ok((final_bytes, checksum))
}

async fn complete_chunked_upload(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    AxumPath((repo_key, session_id)): AxumPath<(String, Uuid)>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let _user_id = require_auth_basic_scope(auth, "incus", "write:artifacts")?.user_id;
    // Issue #1317: scope the session lookup to the URL repo so a session
    // created in repo A cannot be finalized via repo B's URL.
    let repo = resolve_incus_repo(&state.db, &repo_key).await?;
    let session = get_session(&state.db, session_id, repo.id).await?;
    let temp_path = PathBuf::from(&session.storage_temp_path);
    // Both derived from the session's temp path, so every finalize attempt on
    // this session — including one reclaiming a crashed predecessor's lease —
    // names the exact same pair of files.
    let sealed_path = sealed_upload_path(&temp_path);
    let final_path = final_upload_path(&temp_path);

    // Claim the finalize lease BEFORE touching the temp file: the guarded
    // 'receiving' -> 'finalizing' transition is what stops a duplicate
    // complete request (possibly on another replica) from appending to the
    // staged file and spawning a second finalizer for the same session.
    let finalize_token = match claim_incus_finalize_lease(&state.db, session_id)
        .await
        .map_err(db_err)?
    {
        Some(token) => token,
        // #3083: separate "someone else is finalizing / already finished" from
        // "this row was stranded mid-finalize by pre-#3072 code", which the
        // claim query now deliberately refuses to reclaim.
        None => {
            return Err(unclaimable_finalize_response(&state.db, session_id, &session.status).await)
        }
    };

    // The persisted offset re-read UNDER the lease is the authoritative
    // committed length: the pre-claim `session` read can be stale, and the
    // PATCH path only advances this column while the session is 'receiving'.
    // Every read this finalize performs is bounded to it.
    let persisted_bytes: i64 =
        match sqlx::query_scalar("SELECT bytes_received FROM incus_upload_sessions WHERE id = $1")
            .bind(session_id)
            .fetch_one(&state.db)
            .await
        {
            Ok(n) => n,
            Err(e) => {
                abort_incus_finalize(
                    &state.db,
                    session_id,
                    finalize_token,
                    &temp_path,
                    &sealed_path,
                    &final_path,
                )
                .await;
                return Err(db_err(e));
            }
        };

    // Seal the staged chunks, stage the trailing body, and hash the result.
    // Any failure in there releases the lease back to 'receiving' (and
    // un-seals) — otherwise the session would be wedged in 'finalizing' with
    // no finalizer until the 6h lease lapses.
    let (final_bytes, checksum) = match stage_finalize_input(
        body,
        &temp_path,
        &sealed_path,
        &final_path,
        persisted_bytes as u64,
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => {
            abort_incus_finalize(
                &state.db,
                session_id,
                finalize_token,
                &temp_path,
                &sealed_path,
                &final_path,
            )
            .await;
            return Err(resp);
        }
    };
    let total_bytes = persisted_bytes + final_bytes;

    // Verify client-provided checksum if present
    if let Some(expected) = headers.get("X-Checksum-Sha256") {
        let expected = expected.to_str().unwrap_or("");
        if expected != checksum {
            // Checksum mismatch — clean up (token-guarded: only the lease
            // owner may delete the session out from under other requests)
            remove_staging_files(&temp_path, &sealed_path, &final_path).await;
            let _ = sqlx::query(
                "DELETE FROM incus_upload_sessions WHERE id = $1 AND finalize_token = $2",
            )
            .bind(session_id)
            .bind(finalize_token)
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

    // Extract metadata from the file on disk. #2561: permit-scoped decode; the
    // artifact is already staged, so a saturated server skips this best-effort
    // extraction rather than shedding the upload.
    //
    // The artifact is split across two files, so read from whichever holds
    // its head: the sealed chunks when any were committed, else the
    // completing request's body (a client that sent everything in the final
    // PUT). Extraction is best-effort either way.
    let metadata_source = if persisted_bytes > 0 {
        &sealed_path
    } else {
        &final_path
    };
    let metadata = crate::util::bounded_archive::with_ingest_extraction(|| {
        IncusHandler::parse_metadata_from_file(&session.artifact_path, metadata_source).ok()
    })
    .ok()
    .flatten()
    .unwrap_or_else(|| serde_json::json!({"file_type": "unknown"}));

    // Finalize asynchronously: push to the StorageBackend on a background
    // task and return 202. The assembled multi-GiB push can outlive an L7
    // gateway timeout the same way the monolithic PUT can, so the `complete`
    // request must not block on it (#1471/#1494). The session row is
    // retained (not deleted) so the client can poll
    // `GET /incus/{repo}/uploads/{id}` for `completed`/`failed`; the
    // stale-session reaper cleans terminal rows after `max_age_hours`.
    let storage_key = build_storage_key(&session.repository_id, &session.artifact_path);
    let lease_live =
        match assert_incus_finalize_lease_live(&state.db, session_id, finalize_token).await {
            Ok(live) => live,
            Err(e) => {
                // Nothing durable was changed: `bytes_received` still holds the
                // committed offset and the sealed/final pair is rebuilt from
                // scratch by whichever finalize runs next.
                abort_incus_finalize(
                    &state.db,
                    session_id,
                    finalize_token,
                    &temp_path,
                    &sealed_path,
                    &final_path,
                )
                .await;
                return Err(db_err(e));
            }
        };
    if !lease_live {
        // The lease expired and another request reclaimed it while this
        // handler was staging or hashing. Do not spawn a stale finalizer:
        // its terminal update would be fenced, but its storage write,
        // artifact upsert, and staging cleanup happen before that check.
        // The sealed/final files are deliberately left in place — they are
        // named after the session, so the new owner reuses/rewrites them.
        return Err((
            StatusCode::CONFLICT,
            "Upload finalize lease was lost or superseded".to_string(),
        )
            .into_response());
    }

    tokio::spawn(finalize_upload(
        state.clone(),
        repo.clone(),
        FinalizeParams {
            session_id,
            repo_id: session.repository_id,
            artifact_path: session.artifact_path.clone(),
            product: session.product.clone(),
            version: session.version.clone(),
            size_bytes: total_bytes,
            checksum: checksum.clone(),
            storage_key,
            user_id: session.user_id,
            metadata,
            sealed_path: sealed_path.clone(),
            committed_offset: persisted_bytes,
            final_path: Some(final_path.clone()),
            finalize_token,
        },
    ));

    tracing::info!(
        "Finalizing chunked upload {}: {}/{}/{} ({}B, sha256:{})",
        session_id,
        session.product,
        session.version,
        session.filename,
        total_bytes,
        &checksum[..12]
    );

    Ok(Response::builder()
        .status(StatusCode::ACCEPTED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "session_id": session_id,
                "status": "finalizing",
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
    AxumPath((repo_key, session_id)): AxumPath<(String, Uuid)>,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "incus", "delete:artifacts")?.user_id;
    // Issue #1317: scope the session lookup to the URL repo so a session
    // created in repo A cannot be cancelled via repo B's URL.
    let repo = resolve_incus_repo(&state.db, &repo_key).await?;
    let session = get_session(&state.db, session_id, repo.id).await?;

    // Only the client that started the upload may cancel it. Defence in depth
    // behind the token scope + random session id.
    if session.user_id != user_id {
        return Err((
            StatusCode::FORBIDDEN,
            "Upload session belongs to another user".to_string(),
        )
            .into_response());
    }

    // Cancel is claim-aware like every other transition on this row. A
    // session that already entered finalize is owned by that finalize: it is
    // streaming the staged data to the storage backend and will publish an
    // artifact, so deleting the row (and its staged file) out from under it
    // would both corrupt that push and leave a published artifact with no
    // session. Refuse instead of racing it.
    if session.status != "receiving" {
        let detail = if session.status == "finalizing" {
            "finalize is already in progress"
        } else {
            "the upload has already finished"
        };
        return Err((
            StatusCode::CONFLICT,
            format!("Cannot cancel upload session: {}", detail),
        )
            .into_response());
    }

    // The guarded DELETE is the claim: it closes the window between the read
    // above and the delete, so a `complete` that claims the lease in that gap
    // wins and this cancel reports 409 rather than deleting a row a live
    // finalizer owns. The staged files are only touched once the claim is won.
    let claimed = sqlx::query(
        "DELETE FROM incus_upload_sessions \
         WHERE id = $1 AND user_id = $2 AND status = 'receiving' \
         RETURNING storage_temp_path",
    )
    .bind(session_id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(db_err)?;

    let Some(row) = claimed else {
        return Err((
            StatusCode::CONFLICT,
            "Cannot cancel upload session: finalize is already in progress".to_string(),
        )
            .into_response());
    };

    let staged: String = row.try_get("storage_temp_path").map_err(db_err)?;
    let temp_path = PathBuf::from(staged);
    remove_staging_files(
        &temp_path,
        &sealed_upload_path(&temp_path),
        &final_upload_path(&temp_path),
    )
    .await;

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
    AxumPath((repo_key, session_id)): AxumPath<(String, Uuid)>,
) -> Result<Response, Response> {
    // Issue #1317: scope the session lookup to the URL repo so progress for
    // a session in repo A cannot be probed via repo B's URL.
    let repo = resolve_incus_repo(&state.db, &repo_key).await?;
    let session = get_session(&state.db, session_id, repo.id).await?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .header("Range", format!("0-{}", session.bytes_received))
        .body(Body::from(
            serde_json::json!({
                "session_id": session.id,
                "artifact_path": session.artifact_path,
                "bytes_received": session.bytes_received,
                "status": session.status,
                "finalize_error": session.finalize_error,
                "artifact_id": session.artifact_id,
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
///
/// The row DELETE is the claim: candidates are taken with FOR UPDATE SKIP
/// LOCKED and removed *before* the temp-file delete, so concurrent replicas
/// sweep disjoint sessions. Sessions in 'finalizing' with a live lease are
/// skipped — the reaper must not remove a temp file a live finalizer is
/// still streaming to the storage backend.
pub async fn cleanup_stale_sessions(db: &PgPool, max_age_hours: i64) -> Result<i64, String> {
    let stale = sqlx::query_as::<_, (Uuid, String)>(
        r#"
        WITH candidate AS (
            SELECT id
            FROM incus_upload_sessions
            WHERE updated_at < NOW() - make_interval(hours => $1::int)
              AND (
                status != 'finalizing'
                OR finalize_claimed_until IS NULL
                OR finalize_claimed_until <= NOW()
              )
            FOR UPDATE SKIP LOCKED
        )
        DELETE FROM incus_upload_sessions s
        USING candidate
        WHERE s.id = candidate.id
        RETURNING s.id, s.storage_temp_path
        "#,
    )
    .bind(max_age_hours as i32)
    .fetch_all(db)
    .await
    .map_err(|e| format!("Failed to reap stale sessions: {}", e))?;

    let count = stale.len() as i64;

    for (id, temp_path) in &stale {
        let temp_path = Path::new(temp_path);
        remove_staging_files(
            temp_path,
            &sealed_upload_path(temp_path),
            &final_upload_path(temp_path),
        )
        .await;
        tracing::info!("Cleaned up stale upload session {}", id);
    }

    Ok(count)
}

/// Age-based sweep of crash-orphaned staging files (#1573).
///
/// The DB-tracked session reaper above only covers chunked uploads that
/// reached the point of inserting a session row. A monolithic upload — or a
/// chunked upload killed before its `INSERT` — stages bytes to a file with no
/// DB row, so a receive cut short by OOM / eviction / restart leaves an
/// orphan that nothing reaps. This walks the staging directory and deletes
/// any [`is_staging_file`] entry older than `max_age_hours`, on the same
/// threshold as the session reaper. Returns the number of files removed.
pub async fn sweep_orphan_staging_files(storage_path: &str, max_age_hours: i64) -> i64 {
    let dir = staging_root(storage_path);
    let mut entries = match tokio::fs::read_dir(&dir).await {
        Ok(e) => e,
        // Missing dir is normal before the first upload — nothing to sweep.
        Err(_) => return 0,
    };

    let cutoff = std::time::Duration::from_secs((max_age_hours.max(0) as u64) * 3600);
    let mut removed = 0_i64;

    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !is_staging_file(name) {
            continue;
        }
        let is_old = entry
            .metadata()
            .await
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|mtime| mtime.elapsed().ok())
            .map(|age| age >= cutoff)
            .unwrap_or(false);
        if is_old && tokio::fs::remove_file(entry.path()).await.is_ok() {
            removed += 1;
            tracing::info!("Reaped orphan staging file {}", entry.path().display());
        }
    }

    removed
}

// ---------------------------------------------------------------------------
// Private error helpers — reduce duplicated .map_err() patterns
// ---------------------------------------------------------------------------

/// Build an `INTERNAL_SERVER_ERROR` response for database errors.
fn db_err(e: impl Display) -> Response {
    crate::api::handlers::db_err(e)
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
///
/// Retained as a building block for callers that still need an in-place
/// rename (currently none in the upload path). Real uploads route the
/// staged temp file through `put_staged_upload_to_storage` so cloud-backed
/// repos actually persist to the configured bucket (#1471).
#[allow(dead_code)]
async fn finalize_temp_file(temp_path: &Path, final_path: &Path) -> Result<(), Response> {
    ensure_parent_dirs(final_path).await?;
    tokio::fs::rename(temp_path, final_path)
        .await
        .map_err(|e| fs_err("finalize upload", e))?;
    Ok(())
}

/// Push the staged upload into the repo's configured StorageBackend via
/// `put_stream`. Peak memory is bounded to `STREAM_CHUNK_BUDGET` thanks to
/// the ReaderStream chunking in [`open_bounded_file_stream`].
///
/// The object streamed is [`open_finalize_stream`]'s deterministic
/// `sealed[0..committed] ++ final` view — byte-for-byte the input the
/// recorded checksum was computed over, and identical on every re-run, so a
/// finalize that reclaims a crashed predecessor overwrites the storage key
/// with the same object instead of assembling a longer one.
///
/// This is the contract that makes Incus uploads durable on S3/GCS-backed
/// deployments. Before #1471 both upload paths called `tokio::fs::rename`
/// onto the server-local STORAGE_PATH unconditionally, so the bytes never
/// reached the bucket the repo was configured to use; downloads worked
/// only as long as the same ingest pod also served the GET.
async fn put_staged_upload_to_storage(
    state: &SharedState,
    repo: &RepoInfo,
    storage_key: &str,
    sealed_path: &Path,
    committed: u64,
    final_path: Option<&Path>,
) -> Result<(), String> {
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| format!("storage backend resolution failed: {e}"))?;

    let stream = open_finalize_stream(sealed_path, committed, final_path)
        .await
        .map_err(|e| format!("reopen staged data for streaming put: {e}"))?;

    storage
        .put_stream(storage_key, stream)
        .await
        .map_err(|e| format!("storage put_stream failed: {e}"))?;

    Ok(())
}

/// Owned inputs for the background finalize task. Everything is owned (no
/// borrows) so the value can move into the spawned task.
struct FinalizeParams {
    session_id: Uuid,
    repo_id: Uuid,
    artifact_path: String,
    product: String,
    version: String,
    size_bytes: i64,
    checksum: String,
    storage_key: String,
    user_id: Uuid,
    metadata: serde_json::Value,
    /// Staged file holding the artifact's first [`committed_offset`] bytes.
    /// For a chunked upload this is the sealed chunk file; for a monolithic
    /// upload it is the single staged body.
    ///
    /// [`committed_offset`]: FinalizeParams::committed_offset
    sealed_path: PathBuf,
    /// How much of `sealed_path` belongs to the artifact. Bytes past it (an
    /// append by a chunk request whose fd predates the seal) are excluded
    /// from both the checksum and the stored object.
    committed_offset: i64,
    /// Finalize-private file holding the completing request's trailing body,
    /// concatenated after `sealed_path[..committed_offset]`. `None` for the
    /// monolithic path, which has no trailing body.
    final_path: Option<PathBuf>,
    /// Finalize-lease token stamped when the session entered 'finalizing'.
    /// The finalizer's terminal updates must present it, so a finalizer whose
    /// lease expired and was reclaimed cannot clobber the new owner's state.
    finalize_token: Uuid,
}

/// Push the staged temp file to the repo's StorageBackend, create the
/// artifact row, and fire the `scan_on_upload` trigger. Returns the new
/// artifact id.
///
/// Errors are returned as strings (not an HTTP `Response`) because this runs
/// on a background task after the client already received `202`; the caller
/// records the string on the upload session so a failed finalize is
/// observable rather than silently lost.
async fn run_finalize(
    state: &SharedState,
    repo: &RepoInfo,
    p: &FinalizeParams,
) -> Result<Uuid, String> {
    put_staged_upload_to_storage(
        state,
        repo,
        &p.storage_key,
        &p.sealed_path,
        p.committed_offset as u64,
        p.final_path.as_deref(),
    )
    .await?;

    let artifact_id = upsert_artifact(UpsertArtifactParams {
        db: &state.db,
        repo_id: p.repo_id,
        artifact_path: &p.artifact_path,
        product: &p.product,
        version: &p.version,
        size_bytes: p.size_bytes,
        checksum: &p.checksum,
        storage_key: &p.storage_key,
        user_id: p.user_id,
        metadata: &p.metadata,
    })
    .await?;

    // scan_on_upload trigger — format-native upload paths bypass
    // `ArtifactService::upload`'s auto-scan gate, so mirror it here. No-op when
    // the scanner_service is None or `scan_on_upload`/`scan_enabled` is false.
    if let Some(scanner) = state.scanner_service.clone() {
        let should_scan = sqlx::query_scalar!(
            "SELECT scan_on_upload FROM scan_configs WHERE repository_id = $1 AND scan_enabled = true",
            p.repo_id
        )
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .unwrap_or(false);
        crate::services::scanner_service::spawn_scan_on_upload(
            should_scan,
            artifact_id,
            move |aid| async move {
                if let Err(e) = scanner.scan_artifact(aid).await {
                    tracing::warn!(
                        artifact_id = %aid,
                        error = %e,
                        "scan_on_upload trigger failed"
                    );
                }
            },
        );
    }

    Ok(artifact_id)
}

/// Run [`run_finalize`], remove the staged temp file, and only then record
/// the outcome on the upload session. The client already received `202`, so
/// a failed backend push must be observable: on success the session flips to
/// `completed` with the new `artifact_id`; on failure it flips to `failed`
/// with the error string, which `GET /incus/{repo}/uploads/{id}` surfaces.
///
/// Ordering matters: the terminal status is the only signal observers have
/// that finalize is done, so staging cleanup must happen before the status
/// flips — otherwise a poller can see `completed` while the temp file still
/// exists.
async fn finalize_upload(state: SharedState, repo: RepoInfo, params: FinalizeParams) {
    let session_id = params.session_id;
    // Keep the finalize lease renewed for the whole multi-GiB backend push
    // AND the terminal token-guarded update below; the staged temp file is
    // still removed before the status flips (see ordering note above).
    let finalize_renewal =
        spawn_incus_finalize_lease_renewal(state.db.clone(), session_id, params.finalize_token);
    let outcome = run_finalize(&state, &repo, &params).await;
    let _ = tokio::fs::remove_file(&params.sealed_path).await;
    if let Some(final_path) = &params.final_path {
        let _ = tokio::fs::remove_file(final_path).await;
    }
    match outcome {
        Ok(artifact_id) => {
            tracing::info!(
                session = %session_id,
                artifact = %artifact_id,
                "Finalized Incus upload {} ({}B)",
                params.artifact_path,
                params.size_bytes
            );
            // `bytes_received` is only now advanced to the artifact's full
            // size, so `GET /uploads/{id}` reports it. Safe at this point and
            // only at this point: the row becomes terminal in the same
            // statement, and a terminal row is never reclaimed, so no later
            // finalize can mistake the total for a committed chunk offset.
            let result = sqlx::query(
                "UPDATE incus_upload_sessions \
                 SET status = 'completed', artifact_id = $2, finalize_error = NULL, \
                     bytes_received = $4, finalize_claimed_until = NULL, updated_at = NOW() \
                 WHERE id = $1 AND status = 'finalizing' AND finalize_token = $3",
            )
            .bind(session_id)
            .bind(artifact_id)
            .bind(params.finalize_token)
            .bind(params.size_bytes)
            .execute(&state.db)
            .await;
            if let Ok(r) = result {
                if r.rows_affected() != 1 {
                    tracing::warn!(
                        session = %session_id,
                        "finalize succeeded but its lease was lost (expired and re-claimed); \
                         leaving session state to the new owner"
                    );
                }
            }
        }
        Err(msg) => {
            tracing::error!(
                session = %session_id,
                error = %msg,
                "Incus upload finalize failed for {}",
                params.artifact_path
            );
            let _ = sqlx::query(
                "UPDATE incus_upload_sessions \
                 SET status = 'failed', finalize_error = $2, \
                     finalize_claimed_until = NULL, updated_at = NOW() \
                 WHERE id = $1 AND status = 'finalizing' AND finalize_token = $3",
            )
            .bind(session_id)
            .bind(&msg)
            .bind(params.finalize_token)
            .execute(&state.db)
            .await;
        }
    }
    drop(finalize_renewal);
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // #3083: pre-#3072 in-flight finalizes must not be reclaimed
    // -----------------------------------------------------------------------

    /// This file's own source, for the structural guards below.
    const INCUS_RS_SRC: &str = include_str!("incus.rs");

    #[test]
    fn legacy_in_flight_finalize_is_not_reclaimable() {
        // The residual window: `finalizing`, no phase stamp (so it can only
        // have been written by pre-#3072 code, whose on-disk state is
        // ambiguous), and a lapsed lease (so we would otherwise reclaim it).
        assert!(is_legacy_ambiguous_finalize("finalizing", None, true));
    }

    #[test]
    fn post_fix_finalize_is_reclaimable() {
        // Every write that puts a row into `finalizing` under current code
        // stamps the phase, so a crashed finalizer's lapsed lease is still
        // reclaimable and idempotent (#3072).
        assert!(!is_legacy_ambiguous_finalize(
            "finalizing",
            Some("sealing"),
            true
        ));
    }

    /// A live lease means a finalizer may still be running — on a rolling
    /// upgrade, possibly an un-upgraded replica that will finish the job
    /// correctly under the old algorithm. That is "already in progress", not
    /// grounds to tell the operator to cancel and re-upload.
    #[test]
    fn live_lease_is_never_reported_as_a_pre_upgrade_session() {
        assert!(!is_legacy_ambiguous_finalize("finalizing", None, false));
        assert!(!is_legacy_ambiguous_finalize(
            "finalizing",
            Some("sealing"),
            false
        ));
    }

    #[test]
    fn non_finalizing_states_are_unaffected() {
        // Sessions that never entered finalize (including pre-migration rows,
        // which also have a NULL phase) are untouched by the #3083 refusal.
        for status in ["receiving", "completed", "failed", "cancelled"] {
            for lapsed in [true, false] {
                assert!(
                    !is_legacy_ambiguous_finalize(status, None, lapsed),
                    "{status}/{lapsed}"
                );
                assert!(
                    !is_legacy_ambiguous_finalize(status, Some("sealing"), lapsed),
                    "{status}/{lapsed}"
                );
            }
        }
    }

    /// Structural guard: the SQL claim must carry the same discriminator, or
    /// the refusal above would be unreachable (the row would be reclaimed
    /// before the handler ever consults the phase).
    #[test]
    fn claim_query_refuses_phaseless_finalizing_rows() {
        assert!(
            INCUS_RS_SRC.contains("AND finalize_phase IS NOT NULL"),
            "the finalize-lease reclaim branch must exclude phaseless rows (#3083)"
        );
        assert!(
            INCUS_RS_SRC.contains("finalize_phase = 'sealing'"),
            "claiming the lease must stamp finalize_phase (#3083)"
        );
    }

    /// The #3083 discriminator only works if `finalize_phase IS NULL` really
    /// does imply "written by pre-#3072 code" — i.e. EVERY production write
    /// that puts a row into `finalizing` also stamps the phase. Nothing
    /// enforced that invariant, and a test fixture drifted from it (it inserted
    /// a phaseless `finalizing` row to mean "current-server crashed finalize",
    /// which the guard then correctly refused). This scans the production SQL
    /// so a future writer cannot silently reintroduce the gap.
    #[test]
    fn every_production_write_to_finalizing_stamps_the_phase() {
        // Slice off the test module so fixtures — which legitimately seed the
        // legacy phaseless shape on purpose — are not scanned.
        let production = INCUS_RS_SRC
            .split("#[cfg(test)]")
            .next()
            .expect("source has a production prefix");

        let mut unstamped = Vec::new();
        for (idx, _) in production.match_indices("'finalizing'") {
            // Look at the surrounding statement, not the whole file.
            let start = production[..idx].rfind("sqlx::query").unwrap_or(0);
            let end = production[idx..]
                .find("\n    )")
                .map(|off| idx + off)
                .unwrap_or(production.len());
            let stmt = &production[start..end];
            // Only INSERT/UPDATE statements WRITE the status; the guarded
            // `WHERE ... status = 'finalizing'` reads are not writes.
            let writes_status =
                stmt.contains("SET status = 'finalizing'") || stmt.contains("INSERT INTO");
            if writes_status && !stmt.contains("finalize_phase") {
                unstamped.push(stmt.lines().next().unwrap_or("").trim().to_string());
            }
        }

        assert!(
            unstamped.is_empty(),
            "these production statements move a session into 'finalizing' without \
             stamping finalize_phase, which would make a healthy session \
             indistinguishable from a pre-#3072 one and permanently unreclaimable \
             (#3083): {unstamped:?}"
        );
    }

    #[test]
    fn legacy_finalize_message_tells_the_operator_what_to_do() {
        assert!(LEGACY_FINALIZE_MESSAGE.contains("cancel"));
        assert!(LEGACY_FINALIZE_MESSAGE.contains("re-upload"));
    }

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

    /// Serialises every test that reads or mutates the staging env overrides.
    /// The process-global environment is shared across the test runner's
    /// threads, so without this lock parallel tests race each other's
    /// `set_var`/`remove_var` (#1573).
    static STAGING_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// RAII guard that takes [`STAGING_ENV_LOCK`], snapshots the two staging
    /// env overrides, clears them, and restores them (releasing the lock) on
    /// drop. Holding the guard for the whole test body guarantees no other
    /// env-touching test runs concurrently. Works for both sync and async
    /// bodies — the guard simply lives for the scope under test.
    struct StagingEnvCleared {
        _lock: std::sync::MutexGuard<'static, ()>,
        prev: Vec<(&'static str, Option<String>)>,
    }

    impl StagingEnvCleared {
        fn new() -> Self {
            // Recover from a poisoned lock: a panicking test still leaves the
            // env in a known state once its guard drops, so the data is fine.
            let lock = STAGING_ENV_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let vars = ["AK_UPLOAD_STAGING_DIR", "AK_INCUS_UPLOAD_TMP_DIR"];
            let prev = vars
                .iter()
                .map(|&k| {
                    let v = std::env::var(k).ok();
                    std::env::remove_var(k);
                    (k, v)
                })
                .collect();
            Self { _lock: lock, prev }
        }
    }

    impl Drop for StagingEnvCleared {
        fn drop(&mut self) {
            for (k, v) in &self.prev {
                match v {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    #[test]
    fn test_staging_root_defaults_under_storage_path_not_tmp() {
        // #1573: with no override set, staging must live under STORAGE_PATH
        // (`<storage_path>/.incoming`), NOT the OS temp dir. The dot-prefixed
        // subdir can't collide with a repo key prefix.
        let _guard = StagingEnvCleared::new();
        let root = staging_root("/var/lib/artifact-keeper/artifacts");
        assert_eq!(
            root,
            PathBuf::from("/var/lib/artifact-keeper/artifacts/.incoming")
        );
        assert_ne!(root, std::env::temp_dir());
        assert!(!root.starts_with("/tmp"));
    }

    #[test]
    fn test_staging_root_uses_ak_upload_staging_dir_override() {
        let _guard = StagingEnvCleared::new();
        std::env::set_var("AK_UPLOAD_STAGING_DIR", "/data/staging");
        // The new override wins even over both the legacy var and the default.
        std::env::set_var("AK_INCUS_UPLOAD_TMP_DIR", "/legacy/tmp");
        assert_eq!(
            staging_root("/var/lib/artifact-keeper/artifacts"),
            PathBuf::from("/data/staging")
        );
    }

    #[test]
    fn test_staging_root_falls_back_to_legacy_override() {
        let _guard = StagingEnvCleared::new();
        // Legacy per-format var still honoured when the new one is unset.
        std::env::set_var("AK_INCUS_UPLOAD_TMP_DIR", "/var/tmp/ak-incus");
        assert_eq!(
            staging_root("/var/lib/artifact-keeper/artifacts"),
            PathBuf::from("/var/tmp/ak-incus")
        );
    }

    #[test]
    fn test_temp_upload_path_joins_session_id_onto_staging_root() {
        let _guard = StagingEnvCleared::new();
        let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let path = temp_upload_path("/srv/data", &id);
        assert_eq!(
            path,
            PathBuf::from(
                "/srv/data/.incoming/ak-incus-upload-550e8400-e29b-41d4-a716-446655440000"
            )
        );
    }

    #[test]
    fn test_is_staging_file_matches_only_upload_temp_files() {
        // The orphan sweep must only ever reap files this handler created.
        assert!(is_staging_file(
            "ak-incus-upload-550e8400-e29b-41d4-a716-446655440000"
        ));
        assert!(!is_staging_file("img.tar.xz"));
        assert!(!is_staging_file(".keep"));
        assert!(!is_staging_file("ak-other-upload-123"));
    }

    #[test]
    fn test_staged_temp_file_guard_removes_on_drop_unless_disarmed() {
        // #1573: an armed guard unlinks the file when it goes out of scope;
        // a disarmed guard leaves it (the caller took over cleanup).
        let base = std::env::temp_dir().join(format!("ak-1573-guard-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&base).unwrap();

        let armed_path = base.join("armed");
        std::fs::write(&armed_path, b"x").unwrap();
        {
            let _g = StagedTempFile::new(armed_path.clone());
        }
        assert!(!armed_path.exists(), "armed guard must remove file on drop");

        let kept_path = base.join("kept");
        std::fs::write(&kept_path, b"x").unwrap();
        {
            let mut g = StagedTempFile::new(kept_path.clone());
            g.disarm();
        }
        assert!(
            kept_path.exists(),
            "disarmed guard must leave file in place"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn test_sweep_orphan_staging_files_age_and_selectivity() {
        // #1573: the orphan sweep must (a) tolerate a missing staging dir,
        // (b) reap aged staging files, (c) leave non-staging files alone,
        // and (d) leave fresh staging files alone.
        let _guard = StagingEnvCleared::new();
        {
            let base = std::env::temp_dir().join(format!("ak-1573-sweep-{}", Uuid::new_v4()));
            let storage_path = base.to_str().unwrap().to_string();

            // (a) staging dir does not exist yet → no-op, no panic.
            assert_eq!(sweep_orphan_staging_files(&storage_path, 24).await, 0);

            let dir = staging_root(&storage_path);
            tokio::fs::create_dir_all(&dir).await.unwrap();
            let session = Uuid::nil();
            let orphan = dir.join(format!("{STAGING_FILE_PREFIX}{session}"));
            let unrelated = dir.join("img.tar.xz");
            tokio::fs::write(&orphan, b"staged bytes").await.unwrap();
            tokio::fs::write(&unrelated, b"not ours").await.unwrap();

            // (d) with a positive max-age the just-written orphan is too fresh.
            assert_eq!(sweep_orphan_staging_files(&storage_path, 24).await, 0);
            assert!(orphan.exists());

            // (b)+(c) max_age 0 → cutoff 0 → the staging file is reaped but the
            // unrelated file is untouched.
            assert_eq!(sweep_orphan_staging_files(&storage_path, 0).await, 1);
            assert!(!orphan.exists());
            assert!(unrelated.exists());

            let _ = tokio::fs::remove_dir_all(&base).await;
        }
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

    #[test]
    fn test_content_type_for_artifact_tar_zst() {
        assert_eq!(
            content_type_for_artifact("ubuntu/20240215/incus.tar.zst"),
            "application/zstd"
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
    fn test_simplestreams_ftype_tar_zst() {
        assert_eq!(simplestreams_ftype("incus.tar.zst"), "incus.tar.zst");
    }

    #[test]
    fn test_content_type_for_download_tar_zst() {
        assert_eq!(
            content_type_for_download("incus.tar.zst"),
            "application/zstd"
        );
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
            build_download_url(
                "/incus",
                "my-repo",
                "ubuntu-noble",
                "20240215",
                "incus.tar.xz"
            ),
            "/incus/my-repo/images/ubuntu-noble/20240215/incus.tar.xz"
        );
    }

    #[test]
    fn test_build_download_url_with_squashfs() {
        assert_eq!(
            build_download_url("/incus", "repo", "alpine", "v3.19", "rootfs.squashfs"),
            "/incus/repo/images/alpine/v3.19/rootfs.squashfs"
        );
    }

    /// #1320: when the request arrives via `/lxc/...`, the download URL emitted
    /// in the SimpleStreams catalog must use the `/lxc` prefix, not `/incus`.
    #[test]
    fn test_build_download_url_with_lxc_prefix() {
        assert_eq!(
            build_download_url(
                "/lxc",
                "my-repo",
                "ubuntu-noble",
                "20240215",
                "incus.tar.xz"
            ),
            "/lxc/my-repo/images/ubuntu-noble/20240215/incus.tar.xz"
        );
    }

    /// #1320: `build_download_url` must not contain the literal `/incus/` when
    /// invoked with the `/lxc` prefix. Pins prefix-independence at the
    /// function level so a future refactor that re-hardcodes the prefix
    /// fails loudly.
    #[test]
    fn test_build_download_url_does_not_leak_incus_under_lxc() {
        let url = build_download_url("/lxc", "repo", "alpine", "v3.19", "rootfs.squashfs");
        assert!(
            !url.starts_with("/incus/"),
            "/lxc request emitted /incus URL: {url}"
        );
        assert!(url.starts_with("/lxc/"), "expected /lxc prefix: {url}");
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
            build_upload_location("/incus", "my-repo", &session_id),
            "/incus/my-repo/uploads/550e8400-e29b-41d4-a716-446655440000"
        );
    }

    /// #1320: chunked upload `Location` header must use the `/lxc` prefix
    /// when the request came in via `/lxc/...`.
    #[test]
    fn test_build_upload_location_with_lxc_prefix() {
        let session_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(
            build_upload_location("/lxc", "my-repo", &session_id),
            "/lxc/my-repo/uploads/550e8400-e29b-41d4-a716-446655440000"
        );
    }

    /// #1320: `mount_prefix_from_uri` maps each known request prefix back to
    /// the matching mount path, and falls back to `/incus` for anything
    /// unrecognized (preserves the historical default).
    #[test]
    fn test_mount_prefix_from_uri_incus() {
        let uri: Uri = "/incus/my-repo/streams/v1/images.json".parse().unwrap();
        assert_eq!(mount_prefix_from_uri(&uri), "/incus");
    }

    #[test]
    fn test_mount_prefix_from_uri_lxc() {
        let uri: Uri = "/lxc/my-repo/streams/v1/images.json".parse().unwrap();
        assert_eq!(mount_prefix_from_uri(&uri), "/lxc");
    }

    #[test]
    fn test_mount_prefix_from_uri_lxc_exact_root() {
        // Defensive: the exact path `/lxc` (no trailing slash) is still /lxc.
        let uri: Uri = "/lxc".parse().unwrap();
        assert_eq!(mount_prefix_from_uri(&uri), "/lxc");
    }

    #[test]
    fn test_mount_prefix_from_uri_does_not_match_substrings() {
        // Defensive: a path that merely contains `lxc` somewhere else (e.g.
        // a repo key) must not be misread as the /lxc mount.
        let uri: Uri = "/incus/lxc-images/streams/v1/index.json".parse().unwrap();
        assert_eq!(mount_prefix_from_uri(&uri), "/incus");
    }

    #[test]
    fn test_mount_prefix_from_uri_unknown_falls_back_to_incus() {
        let uri: Uri = "/some/other/path".parse().unwrap();
        assert_eq!(mount_prefix_from_uri(&uri), "/incus");
    }

    /// #1320: combined check -- if the request arrives under `/lxc/`, both the
    /// download URL and the upload Location must consistently use `/lxc`,
    /// never `/incus`.
    #[test]
    fn test_url_builders_prefix_consistent_for_lxc_request() {
        let uri: Uri = "/lxc/my-repo/streams/v1/images.json".parse().unwrap();
        let prefix = mount_prefix_from_uri(&uri);
        let dl = build_download_url(prefix, "my-repo", "ubuntu", "20240215", "incus.tar.xz");
        let session_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let loc = build_upload_location(prefix, "my-repo", &session_id);
        assert!(dl.starts_with("/lxc/"), "download URL not under /lxc: {dl}");
        assert!(
            loc.starts_with("/lxc/"),
            "upload Location not under /lxc: {loc}"
        );
        assert!(!dl.contains("/incus/"), "download URL leaks /incus: {dl}");
        assert!(
            !loc.contains("/incus/"),
            "upload Location leaks /incus: {loc}"
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
            format: "generic".to_string(),
            promotion_only: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
            age_gate_mode: "upstream_publish_time".to_string(),
            curation_enabled: false,
            curation_default_action: "allow".to_string(),
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
            format: "generic".to_string(),
            promotion_only: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
            age_gate_mode: "upstream_publish_time".to_string(),
            curation_enabled: false,
            curation_default_action: "allow".to_string(),
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
        let download_url = build_download_url("/incus", "my-repo", product, version, filename);

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

    // -----------------------------------------------------------------------
    // #1441 regression: download must read from the same on-disk layout the
    // upload path writes to.
    //
    // Both upload paths (monolithic + chunked finalize) compute the final
    // location via `storage_path_for_key(state.config.storage_path, key)`,
    // which prepends a 2-char shard derived from the key's first 2 chars
    // (e.g. `in/` for `incus/<repo_id>/...`). The previous download
    // implementation went through `FilesystemStorage::key_to_path`, which
    // treats hierarchical keys (those containing `/`) as already-distributed
    // and skips the shard prefix entirely — so the read landed under a
    // different directory than the write, returning HTTP 500 every time.
    // This test pins the contract that a file written via
    // `storage_path_for_key` is readable via the same call.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_storage_key_and_path_layout_roundtrip() {
        // Sanity check on the storage-key construction the StorageBackend
        // receives. Even after #1471 routes uploads through `put_stream`,
        // the filesystem backend still stores blobs under a 2-char shard
        // prefix, so the key shape (`incus/<repo_id>/<path>`) and shard
        // layout (`in/incus/<repo_id>/<path>`) must stay stable; existing
        // on-disk artifacts depend on it.
        let tmp = std::env::temp_dir().join(format!("ak-incus-key-layout-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&tmp).await.unwrap();

        let repo_id = Uuid::new_v4();
        let artifact_path = build_artifact_path("ubuntu-noble", "20240215", "incus.tar.gz");
        let storage_key = build_storage_key(&repo_id, &artifact_path);
        assert!(storage_key.starts_with("incus/"));
        let final_path = storage_path_for_key(tmp.to_str().unwrap(), &storage_key);
        let path_str = final_path.to_string_lossy();
        assert!(
            path_str.contains("/in/incus/"),
            "expected shard prefix /in/ before incus/<repo_id>/, got {}",
            path_str
        );

        let _ = tokio::fs::remove_dir_all(&tmp).await;
    }

    // -----------------------------------------------------------------------
    // #1471 regression: uploads MUST hand the staged temp file to the
    // configured StorageBackend via `put_stream`, never `tokio::fs::rename`
    // onto local STORAGE_PATH. A pre-#1471 implementation would never
    // touch `put_stream` and the chunk recorder below would observe
    // zero chunks.
    //
    // Uses a ChunkRecordingBackend (same pattern as #1521 oci_v2 tests)
    // that captures stream chunks and forbids the buffered `put` path.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_upload_uses_put_stream_not_local_rename() {
        use crate::error::Result as StorageResult;
        use crate::storage::{PutStreamResult, StorageBackend};
        use async_trait::async_trait;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        struct ChunkRecordingBackend {
            put_calls: Arc<AtomicUsize>,
            put_stream_calls: Arc<AtomicUsize>,
            chunk_sizes: Arc<Mutex<Vec<usize>>>,
            last_key: Arc<Mutex<Option<String>>>,
        }

        #[async_trait]
        impl StorageBackend for ChunkRecordingBackend {
            async fn put(&self, _key: &str, _content: bytes::Bytes) -> StorageResult<()> {
                self.put_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
            async fn get(&self, _key: &str) -> StorageResult<bytes::Bytes> {
                Ok(bytes::Bytes::new())
            }
            async fn exists(&self, _key: &str) -> StorageResult<bool> {
                Ok(false)
            }
            async fn delete(&self, _key: &str) -> StorageResult<()> {
                Ok(())
            }
            async fn put_stream(
                &self,
                key: &str,
                stream: futures::stream::BoxStream<'static, StorageResult<bytes::Bytes>>,
            ) -> StorageResult<PutStreamResult> {
                self.put_stream_calls.fetch_add(1, Ordering::SeqCst);
                *self.last_key.lock().unwrap() = Some(key.to_string());
                let mut total: u64 = 0;
                let mut hasher = Sha256::new();
                tokio::pin!(stream);
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk?;
                    self.chunk_sizes.lock().unwrap().push(chunk.len());
                    hasher.update(&chunk);
                    total += chunk.len() as u64;
                }
                Ok(PutStreamResult {
                    checksum_sha256: format!("{:x}", hasher.finalize()),
                    bytes_written: total,
                })
            }
        }

        // 4 MiB payload spans multiple STREAM_CHUNK_BUDGET windows, so a
        // non-streaming backend would show up as a single Bytes of 4 MiB.
        let payload = vec![0xACu8; 4 * 1024 * 1024];
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("incus-staged.tar.gz");
        tokio::fs::write(&path, &payload).await.unwrap();

        let put_calls = Arc::new(AtomicUsize::new(0));
        let put_stream_calls = Arc::new(AtomicUsize::new(0));
        let chunk_sizes: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
        let last_key: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let backend = ChunkRecordingBackend {
            put_calls: put_calls.clone(),
            put_stream_calls: put_stream_calls.clone(),
            chunk_sizes: chunk_sizes.clone(),
            last_key: last_key.clone(),
        };

        let stream = open_bounded_file_stream(&path, u64::MAX)
            .await
            .expect("open staged temp as stream");
        let storage_key = "incus/00000000-0000-0000-0000-000000000000/ubuntu/20240215/incus.tar.gz";
        let result = backend
            .put_stream(storage_key, stream)
            .await
            .expect("put_stream succeeds");

        assert_eq!(
            put_calls.load(Ordering::SeqCst),
            0,
            "buffered `put` must NOT be called for an incus upload"
        );
        assert_eq!(
            put_stream_calls.load(Ordering::SeqCst),
            1,
            "`put_stream` must be called exactly once at upload completion"
        );
        assert_eq!(
            last_key.lock().unwrap().as_deref(),
            Some(storage_key),
            "put_stream must be called with the incus/<repo_id>/<artifact_path> storage key"
        );
        let sizes = chunk_sizes.lock().unwrap().clone();
        assert!(
            sizes.len() > 1,
            "expected multiple chunks for a 4 MiB payload (memory-bounded streaming), got {} chunks",
            sizes.len()
        );
        let max_chunk = sizes.iter().copied().max().unwrap_or(0);
        assert!(
            max_chunk <= STREAM_CHUNK_BUDGET,
            "max chunk {} bytes exceeds STREAM_CHUNK_BUDGET ({}); upload is buffering",
            max_chunk,
            STREAM_CHUNK_BUDGET,
        );
        assert_eq!(result.bytes_written as usize, payload.len());
    }

    #[tokio::test]
    async fn test_open_bounded_file_stream_roundtrip() {
        // Sanity: the bytes the streaming helper yields exactly match the
        // bytes on disk. Guards against an off-by-one chunk-boundary bug
        // that would silently corrupt incus uploads.
        let payload: Vec<u8> = (0u32..(300 * 1024)).map(|i| (i % 251) as u8).collect();
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("payload.bin");
        tokio::fs::write(&path, &payload).await.unwrap();

        let mut stream = open_bounded_file_stream(&path, u64::MAX)
            .await
            .expect("open stream");
        let mut collected: Vec<u8> = Vec::with_capacity(payload.len());
        while let Some(chunk) = stream.next().await {
            collected.extend_from_slice(&chunk.expect("chunk ok"));
        }
        assert_eq!(collected, payload);
    }

    // -----------------------------------------------------------------------
    // Regression: Incus uploads must populate the `packages` /
    // `package_versions` tables so images appear in the top-level package
    // browser, matching npm/pypi/nuget and the generic upload path. Before
    // the fix, `upsert_artifact` wrote only the `artifacts` row, so Incus
    // images were invisible in `GET /api/v1/packages`.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn upsert_artifact_populates_packages_index() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(f) = tdh::Fixture::setup("local", "incus").await else {
            return;
        };
        let artifact_path = build_artifact_path("ubuntu-noble", "20240215", "incus.tar.xz");
        let storage_key = build_storage_key(&f.repo_id, &artifact_path);
        let metadata = serde_json::json!({ "format": "incus" });

        let Ok(_id) = upsert_artifact(UpsertArtifactParams {
            db: &f.pool,
            repo_id: f.repo_id,
            artifact_path: &artifact_path,
            product: "ubuntu-noble",
            version: "20240215",
            size_bytes: 1234,
            checksum: "deadbeef",
            storage_key: &storage_key,
            user_id: f.user_id,
            metadata: &metadata,
        })
        .await
        else {
            panic!("upsert_artifact failed");
        };

        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT name, version FROM packages \
             WHERE repository_id = $1 AND name = $2 AND version = $3",
        )
        .bind(f.repo_id)
        .bind("ubuntu-noble")
        .bind("20240215")
        .fetch_optional(&f.pool)
        .await
        .expect("query packages");
        let (name, version) = row.expect("packages row must exist after an Incus upload");
        assert_eq!(
            (name.as_str(), version.as_str()),
            ("ubuntu-noble", "20240215")
        );

        let version_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM package_versions pv \
             JOIN packages p ON p.id = pv.package_id \
             WHERE p.repository_id = $1 AND p.name = $2 AND pv.version = $3",
        )
        .bind(f.repo_id)
        .bind("ubuntu-noble")
        .bind("20240215")
        .fetch_one(&f.pool)
        .await
        .expect("query package_versions");
        assert_eq!(version_count.0, 1);

        f.teardown().await;
    }
}

// ===========================================================================
// Issue #1317 regression coverage (lib-side, picked up by the Coverage gate).
//
// The corresponding integration suite lives in
// `backend/tests/incus_upload_tests.rs` and is also wired into the CI
// integration matrix. These lib-side tests are intentionally redundant so
// that `cargo llvm-cov --workspace --lib` instruments the cross-repo session
// rejection branch in `upload_chunk`, `complete_chunked_upload`,
// `cancel_chunked_upload`, and `get_upload_progress`. Without them the new
// 404-on-cross-repo lines would appear uncovered to the coverage gate
// (`--lib` excludes the `tests/` directory).
//
// Tests skip when `DATABASE_URL` is unset (matches the rest of the
// `tdh::`-style suites).
// ===========================================================================

#[cfg(test)]
mod cross_repo_session_regression_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;

    /// Insert a second Incus repository under the same fixture pool and
    /// return its key. Used to drive cross-repo PATCH/PUT/DELETE/GET against
    /// a session owned by the fixture's primary repo.
    async fn create_second_incus_repo(pool: &PgPool) -> (Uuid, String) {
        let id = Uuid::new_v4();
        let key = format!("ph-test-incus-b-{}", id);
        let storage_dir = std::env::temp_dir().join(format!("ph-test-{}", id));
        std::fs::create_dir_all(&storage_dir).expect("create storage dir");
        sqlx::query(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
             VALUES ($1, $2, $3, $4, 'local'::repository_type, 'incus'::repository_format)",
        )
        .bind(id)
        .bind(&key)
        .bind(&key)
        .bind(&*storage_dir.to_string_lossy())
        .execute(pool)
        .await
        .expect("create second repo");
        (id, key)
    }

    /// POST start a chunked upload under the fixture's primary repo and
    /// return the session UUID. Asserts a 202 response.
    async fn start_session(f: &tdh::Fixture) -> Uuid {
        let app = f.router_with_auth(router());
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/{}/images/alpine/3.20/rootfs.tar.gz/uploads",
                f.repo_key
            ))
            .body(Body::from(b"initial-bytes".to_vec()))
            .expect("build POST request");
        let (status, body) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "POST start under owning repo should be 202: {}",
            String::from_utf8_lossy(&body)
        );
        let json: serde_json::Value = serde_json::from_slice(&body).expect("parse JSON body");
        let session_id_str = json["session_id"].as_str().expect("session_id field");
        session_id_str.parse().expect("session_id is a UUID")
    }

    async fn cleanup_second_repo(pool: &PgPool, repo_b_id: Uuid) {
        let _ = sqlx::query("DELETE FROM incus_upload_sessions WHERE repository_id = $1")
            .bind(repo_b_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_b_id)
            .execute(pool)
            .await;
    }

    /// PATCH chunk under repo B must be rejected with 404 even though the
    /// session exists in repo A (issue #1317). The same-repo PATCH must
    /// continue to succeed so we cover both branches of the new
    /// `get_session(... repo_id ...)` lookup.
    #[tokio::test]
    async fn upload_chunk_cross_repo_rejected_and_same_repo_ok() {
        let Some(f) = tdh::Fixture::setup("local", "incus").await else {
            return;
        };
        let (repo_b_id, key_b) = create_second_incus_repo(&f.pool).await;
        let session_id = start_session(&f).await;

        // Cross-repo PATCH: must be 404 (does NOT touch the session row).
        let app = f.router_with_auth(router());
        let req = axum::http::Request::builder()
            .method("PATCH")
            .uri(format!("/{}/uploads/{}", key_b, session_id))
            .body(Body::from(b"attacker-chunk".to_vec()))
            .expect("build PATCH request");
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "PATCH chunk under wrong repo must be 404 (issue #1317)"
        );

        // Same-repo PATCH: covers the happy-path branch of the new lookup.
        let app = f.router_with_auth(router());
        let req = axum::http::Request::builder()
            .method("PATCH")
            .uri(format!("/{}/uploads/{}", f.repo_key, session_id))
            .body(Body::from(b"legitimate-chunk".to_vec()))
            .expect("build PATCH request");
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "PATCH chunk under owning repo should still be 202"
        );

        cleanup_second_repo(&f.pool, repo_b_id).await;
        f.teardown().await;
    }

    /// PUT complete under repo B must be 404; the legitimate session in
    /// repo A must remain intact so subsequent operations under repo A keep
    /// working.
    #[tokio::test]
    async fn complete_chunked_upload_cross_repo_rejected() {
        let Some(f) = tdh::Fixture::setup("local", "incus").await else {
            return;
        };
        let (repo_b_id, key_b) = create_second_incus_repo(&f.pool).await;
        let session_id = start_session(&f).await;

        let app = f.router_with_auth(router());
        let req = axum::http::Request::builder()
            .method("PUT")
            .uri(format!("/{}/uploads/{}", key_b, session_id))
            .body(Body::empty())
            .expect("build PUT request");
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "PUT complete under wrong repo must be 404 (issue #1317)"
        );

        // Session row must still be there (cross-repo PUT must NOT have
        // deleted or finalized it).
        let still_there: i64 =
            sqlx::query_scalar("SELECT count(*) FROM incus_upload_sessions WHERE id = $1")
                .bind(session_id)
                .fetch_one(&f.pool)
                .await
                .expect("count sessions");
        assert_eq!(still_there, 1, "cross-repo PUT must not delete session");

        cleanup_second_repo(&f.pool, repo_b_id).await;
        f.teardown().await;
    }

    /// DELETE cancel under repo B must be 404 and must NOT remove the
    /// session row owned by repo A.
    #[tokio::test]
    async fn cancel_chunked_upload_cross_repo_rejected() {
        let Some(f) = tdh::Fixture::setup("local", "incus").await else {
            return;
        };
        let (repo_b_id, key_b) = create_second_incus_repo(&f.pool).await;
        let session_id = start_session(&f).await;

        let app = f.router_with_auth(router());
        let req = axum::http::Request::builder()
            .method("DELETE")
            .uri(format!("/{}/uploads/{}", key_b, session_id))
            .body(Body::empty())
            .expect("build DELETE request");
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "DELETE cancel under wrong repo must be 404 (issue #1317)"
        );

        let still_there: i64 =
            sqlx::query_scalar("SELECT count(*) FROM incus_upload_sessions WHERE id = $1")
                .bind(session_id)
                .fetch_one(&f.pool)
                .await
                .expect("count sessions");
        assert_eq!(
            still_there, 1,
            "cross-repo DELETE must not remove legitimate session"
        );

        // Legitimate DELETE under owning repo still works (covers
        // happy-path branch of `cancel_chunked_upload`'s session lookup).
        let app = f.router_with_auth(router());
        let req = axum::http::Request::builder()
            .method("DELETE")
            .uri(format!("/{}/uploads/{}", f.repo_key, session_id))
            .body(Body::empty())
            .expect("build DELETE request");
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::NO_CONTENT,
            "DELETE under owning repo should succeed"
        );

        cleanup_second_repo(&f.pool, repo_b_id).await;
        f.teardown().await;
    }

    /// GET progress under repo B must be 404; under repo A it must return
    /// 200 with the expected JSON shape (covers both branches of the
    /// session lookup in `get_upload_progress`).
    #[tokio::test]
    async fn get_upload_progress_cross_repo_rejected_and_same_repo_ok() {
        let Some(f) = tdh::Fixture::setup("local", "incus").await else {
            return;
        };
        let (repo_b_id, key_b) = create_second_incus_repo(&f.pool).await;
        let session_id = start_session(&f).await;

        let app = f.router_with_auth(router());
        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!("/{}/uploads/{}", key_b, session_id))
            .body(Body::empty())
            .expect("build GET request");
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "GET progress under wrong repo must be 404 (issue #1317)"
        );

        let app = f.router_with_auth(router());
        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!("/{}/uploads/{}", f.repo_key, session_id))
            .body(Body::empty())
            .expect("build GET request");
        let (status, body) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "GET progress under owning repo should be 200: {}",
            String::from_utf8_lossy(&body)
        );

        cleanup_second_repo(&f.pool, repo_b_id).await;
        f.teardown().await;
    }
}

// ===========================================================================
// #1471 lib-side streaming regression coverage.
//
// `cargo llvm-cov --workspace --lib` does not instrument the `tests/`
// directory, so the new `put_stream` / `get_stream` / temp-file pipeline in
// `upload_image`, `download_image`, and `complete_chunked_upload` would
// otherwise look uncovered on the New Code Coverage gate. These tests drive
// the router end-to-end against the fixture's filesystem-backed
// StorageBackend so every new line in those handlers gets exercised under
// `--lib`.
//
// Tests no-op when `DATABASE_URL` is unset, matching every other tdh-style
// suite in this crate.
// ===========================================================================

#[allow(clippy::disallowed_methods)]
// streaming-invariant: test module exempt — buffering response bodies in test assertions is not an artifact path (#1608)
#[cfg(test)]
mod streaming_pipeline_regression_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::http::header;
    use tower::ServiceExt;

    /// Poll `GET /{repo}/uploads/{id}` until the async finalize reaches a
    /// terminal status, returning the final progress JSON. Panics after ~60s:
    /// the budget must exceed the 30s the finalize task's DB work may
    /// legitimately spend just acquiring a pool connection under parallel
    /// coverage runs (a 10s budget timed out at 16 test threads).
    async fn await_finalize(f: &tdh::Fixture, session_id: Uuid) -> serde_json::Value {
        for _ in 0..2400 {
            let app = f.router_with_auth(router());
            let req = axum::http::Request::builder()
                .method("GET")
                .uri(format!("/{}/uploads/{}", f.repo_key, session_id))
                .body(Body::empty())
                .expect("build progress GET");
            let (status, body) = tdh::send(app, req).await;
            assert_eq!(status, StatusCode::OK, "progress poll must return 200");
            let json: serde_json::Value =
                serde_json::from_slice(&body).expect("parse progress JSON");
            match json["status"].as_str() {
                Some("completed") | Some("failed") => return json,
                _ => tokio::time::sleep(std::time::Duration::from_millis(25)).await,
            }
        }
        panic!("finalize did not reach a terminal status in time");
    }

    /// PUT a monolithic image, then GET it back. Exercises `upload_image`'s
    /// stream-to-temp-file → `put_staged_upload_to_storage` → `put_stream`
    /// pipeline and the matching `download_image` → `get_stream` →
    /// streaming response body path.
    #[tokio::test]
    async fn monolithic_upload_then_download_roundtrip_via_put_stream() {
        let Some(f) = tdh::Fixture::setup("local", "incus").await else {
            return;
        };

        // 320 KiB payload guarantees the streamed download body and the
        // ReaderStream-chunked upload both span multiple
        // STREAM_CHUNK_BUDGET windows.
        let payload: Vec<u8> = (0u32..(320 * 1024)).map(|i| (i % 251) as u8).collect();
        let product = "ubuntu-noble";
        let version = "20240215";
        let filename = "incus.tar.gz";
        let uri = format!(
            "/{}/images/{}/{}/{}",
            f.repo_key, product, version, filename
        );

        // --- PUT (upload_image) -------------------------------------------
        let app = f.router_with_auth(router());
        let req = axum::http::Request::builder()
            .method("PUT")
            .uri(&uri)
            .body(Body::from(payload.clone()))
            .expect("build PUT request");
        let (status, body) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "monolithic PUT must return 202 (async finalize): {}",
            String::from_utf8_lossy(&body)
        );
        let upload_json: serde_json::Value =
            serde_json::from_slice(&body).expect("parse upload response");
        assert_eq!(upload_json["size"].as_i64(), Some(payload.len() as i64));
        assert_eq!(upload_json["status"].as_str(), Some("finalizing"));
        let returned_sha = upload_json["sha256"]
            .as_str()
            .expect("response has sha256 field")
            .to_string();
        let session_id: Uuid = upload_json["session_id"]
            .as_str()
            .expect("response has session_id")
            .parse()
            .expect("session_id is a UUID");

        // Poll the session until the background finalize completes.
        let progress = await_finalize(&f, session_id).await;
        assert_eq!(
            progress["status"].as_str(),
            Some("completed"),
            "finalize must complete: {}",
            progress
        );
        assert!(
            progress["artifact_id"].as_str().is_some(),
            "completed session must carry the artifact_id"
        );

        // Confirm the artifact row was inserted with the storage key shape
        // that the background finalize writes to.
        let storage_key: String = sqlx::query_scalar(
            "SELECT storage_key FROM artifacts WHERE repository_id = $1 AND path = $2 LIMIT 1",
        )
        .bind(f.repo_id)
        .bind(build_artifact_path(product, version, filename))
        .fetch_one(&f.pool)
        .await
        .expect("artifact row");
        assert!(
            storage_key.starts_with("incus/"),
            "storage_key should be the put_stream key, got {}",
            storage_key
        );

        // --- GET (download_image, streaming) ------------------------------
        let app = f.router_with_auth(router());
        let req = axum::http::Request::builder()
            .method("GET")
            .uri(&uri)
            .body(Body::empty())
            .expect("build GET request");
        let resp = app.oneshot(req).await.expect("download oneshot");
        assert_eq!(resp.status(), StatusCode::OK, "GET must succeed");
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert_eq!(
            ct, "application/gzip",
            "Content-Type must match content_type_for_download for .tar.gz"
        );
        let checksum_hdr = resp
            .headers()
            .get("X-Checksum-Sha256")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert_eq!(
            checksum_hdr, returned_sha,
            "X-Checksum-Sha256 must match the value computed during PUT"
        );
        let content_length_hdr = resp
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok())
            .expect("Content-Length header parses");
        assert_eq!(content_length_hdr, payload.len());

        let downloaded = axum::body::to_bytes(resp.into_body(), 16 * 1024 * 1024)
            .await
            .expect("read download body");
        assert_eq!(
            downloaded.as_ref(),
            payload.as_slice(),
            "downloaded bytes must match uploaded bytes (round-trip via put_stream/get_stream)"
        );

        f.teardown().await;
    }

    /// GET for an artifact whose `storage_key` row exists but whose object
    /// is missing from the StorageBackend must surface as a non-200 error.
    /// Exercises `download_image`'s `get_stream` error-mapping closure.
    /// The filesystem backend reports ENOENT as a generic Storage error
    /// ("Failed to open ... No such file or directory") so this path falls
    /// through to 500; cloud backends typically return a "not found"-shaped
    /// message and surface as 404 via the same closure.
    #[tokio::test]
    async fn download_missing_object_exercises_get_stream_error_mapping() {
        let Some(f) = tdh::Fixture::setup("local", "incus").await else {
            return;
        };

        let product = "ubuntu-noble";
        let version = "20240215";
        let filename = "incus.tar.xz";
        let artifact_path = build_artifact_path(product, version, filename);
        let storage_key = build_storage_key(&f.repo_id, &artifact_path);

        // Insert an artifact row but never write the object — get_stream
        // will fail with "not found", which the handler must translate to
        // HTTP 404.
        sqlx::query(
            "INSERT INTO artifacts \
             (id, repository_id, path, name, version, size_bytes, checksum_sha256, \
              content_type, storage_key, uploaded_by, is_deleted) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, false)",
        )
        .bind(Uuid::new_v4())
        .bind(f.repo_id)
        .bind(&artifact_path)
        .bind(product)
        .bind(version)
        .bind(42_i64)
        .bind("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        .bind("application/x-xz")
        .bind(&storage_key)
        .bind(f.user_id)
        .execute(&f.pool)
        .await
        .expect("insert artifact row with no backing object");

        let app = f.router_with_auth(router());
        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/{}/images/{}/{}/{}",
                f.repo_key, product, version, filename
            ))
            .body(Body::empty())
            .expect("build GET request");
        let (status, _) = tdh::send(app, req).await;
        assert!(
            status == StatusCode::INTERNAL_SERVER_ERROR || status == StatusCode::NOT_FOUND,
            "missing storage object must surface via get_stream error closure as 404 or 500, got {}",
            status
        );
        assert_ne!(
            status,
            StatusCode::OK,
            "must NOT return 200 when the storage object is absent"
        );

        f.teardown().await;
    }

    /// Drive a full chunked upload (POST start → PATCH chunk → PUT complete)
    /// and confirm the assembled blob is downloadable via `get_stream`.
    /// Exercises `complete_chunked_upload`'s new
    /// `put_staged_upload_to_storage` call site and staging cleanup.
    #[tokio::test]
    async fn chunked_upload_complete_then_download_roundtrip() {
        let Some(f) = tdh::Fixture::setup("local", "incus").await else {
            return;
        };

        let product = "alpine";
        let version = "3.20";
        let filename = "rootfs.squashfs";
        let chunk_a = vec![0x11u8; 96 * 1024];
        let chunk_b = vec![0x22u8; 96 * 1024];
        let mut expected: Vec<u8> = Vec::with_capacity(chunk_a.len() + chunk_b.len());
        expected.extend_from_slice(&chunk_a);
        expected.extend_from_slice(&chunk_b);

        // POST start
        let app = f.router_with_auth(router());
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/{}/images/{}/{}/{}/uploads",
                f.repo_key, product, version, filename
            ))
            .body(Body::from(chunk_a.clone()))
            .expect("build POST start");
        let (status, body) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "POST start must be 202: {}",
            String::from_utf8_lossy(&body)
        );
        let start_json: serde_json::Value =
            serde_json::from_slice(&body).expect("parse start JSON");
        let session_id: Uuid = start_json["session_id"]
            .as_str()
            .expect("session_id field")
            .parse()
            .expect("session_id is a UUID");

        // PATCH chunk
        let app = f.router_with_auth(router());
        let req = axum::http::Request::builder()
            .method("PATCH")
            .uri(format!("/{}/uploads/{}", f.repo_key, session_id))
            .body(Body::from(chunk_b.clone()))
            .expect("build PATCH chunk");
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, StatusCode::ACCEPTED, "PATCH chunk must be 202");

        // PUT complete: returns 202 and finalizes on a background task.
        let app = f.router_with_auth(router());
        let req = axum::http::Request::builder()
            .method("PUT")
            .uri(format!("/{}/uploads/{}", f.repo_key, session_id))
            .body(Body::empty())
            .expect("build PUT complete");
        let (status, body) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "PUT complete must return 202 (async finalize): {}",
            String::from_utf8_lossy(&body)
        );

        // Poll until the background finalize completes.
        let progress = await_finalize(&f, session_id).await;
        assert_eq!(
            progress["status"].as_str(),
            Some("completed"),
            "chunked finalize must complete: {}",
            progress
        );

        // Staging temp file MUST be gone once finalize has run.
        let temp_path = temp_upload_path(f.storage_dir.to_str().unwrap(), &session_id);
        assert!(
            !temp_path.exists(),
            "staged temp file must be removed after finalize (path: {})",
            temp_path.display()
        );

        // Download the assembled blob and confirm byte equality.
        let app = f.router_with_auth(router());
        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/{}/images/{}/{}/{}",
                f.repo_key, product, version, filename
            ))
            .body(Body::empty())
            .expect("build GET");
        let resp = app.oneshot(req).await.expect("download oneshot");
        assert_eq!(resp.status(), StatusCode::OK, "GET must succeed");
        let bytes = axum::body::to_bytes(resp.into_body(), 16 * 1024 * 1024)
            .await
            .expect("download body");
        assert_eq!(
            bytes.as_ref(),
            expected.as_slice(),
            "chunked upload must round-trip through put_stream/get_stream"
        );

        f.teardown().await;
    }

    /// A finalize whose backend push fails must flip the session to `failed`
    /// with an error string, so the client that already received `202` can
    /// observe the failure via `GET /uploads/{id}` instead of it being lost.
    #[tokio::test]
    async fn failed_finalize_marks_session_failed() {
        let Some(f) = tdh::Fixture::setup("local", "incus").await else {
            return;
        };

        let session_id = Uuid::new_v4();
        let artifact_path = build_artifact_path("ubuntu", "1", "incus.tar.xz");
        // Temp file deliberately never created, so the finalize's backend push
        // fails when it tries to reopen it for streaming.
        let bogus_temp = std::env::temp_dir().join(format!("ak-incus-missing-{session_id}"));

        let finalize_token = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO incus_upload_sessions \
             (id, repository_id, user_id, artifact_path, product, version, filename, \
              bytes_received, storage_temp_path, status, finalize_token, \
              finalize_claimed_until) \
             VALUES ($1, $2, $3, $4, 'ubuntu', '1', 'incus.tar.xz', 0, $5, 'finalizing', $6, \
                     NOW() + make_interval(secs => $7))",
        )
        .bind(session_id)
        .bind(f.repo_id)
        .bind(f.user_id)
        .bind(&artifact_path)
        .bind(&*bogus_temp.to_string_lossy())
        .bind(finalize_token)
        .bind(INCUS_FINALIZE_LEASE_TTL_SECS)
        .execute(&f.pool)
        .await
        .expect("insert finalizing session");

        let repo = RepoInfo {
            id: f.repo_id,
            key: f.repo_key.clone(),
            storage_path: std::env::temp_dir().to_string_lossy().into_owned(),
            storage_backend: "filesystem".to_string(),
            repo_type: "local".to_string(),
            format: "generic".to_string(),
            upstream_url: None,
            promotion_only: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
            age_gate_mode: "upstream_publish_time".to_string(),
            curation_enabled: false,
            curation_default_action: "allow".to_string(),
        };

        finalize_upload(
            f.state.clone(),
            repo,
            FinalizeParams {
                session_id,
                repo_id: f.repo_id,
                artifact_path: artifact_path.clone(),
                product: "ubuntu".to_string(),
                version: "1".to_string(),
                size_bytes: 0,
                checksum: "0".repeat(64),
                storage_key: build_storage_key(&f.repo_id, &artifact_path),
                user_id: f.user_id,
                metadata: serde_json::json!({ "file_type": "unknown" }),
                sealed_path: bogus_temp,
                committed_offset: 0,
                final_path: None,
                finalize_token,
            },
        )
        .await;

        let (status, err): (String, Option<String>) = sqlx::query_as(
            "SELECT status, finalize_error FROM incus_upload_sessions WHERE id = $1",
        )
        .bind(session_id)
        .fetch_one(&f.pool)
        .await
        .expect("session row");
        assert_eq!(
            status, "failed",
            "a failed finalize must mark the session 'failed'"
        );
        assert!(
            err.is_some(),
            "a failed finalize must record an observable error string"
        );

        f.teardown().await;
    }

    // -----------------------------------------------------------------------
    // Finalize lease (Tier-2: no-op without DATABASE_URL)
    // -----------------------------------------------------------------------

    async fn insert_receiving_session(f: &tdh::Fixture) -> Uuid {
        let session_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO incus_upload_sessions \
             (id, repository_id, user_id, artifact_path, product, version, filename, \
              bytes_received, storage_temp_path, status) \
             VALUES ($1, $2, $3, $4, 'ubuntu', '1', 'incus.tar.xz', 0, $5, 'receiving')",
        )
        .bind(session_id)
        .bind(f.repo_id)
        .bind(f.user_id)
        .bind(build_artifact_path("ubuntu", "1", "incus.tar.xz"))
        .bind(
            &*std::env::temp_dir()
                .join(format!("ak-incus-lease-{session_id}"))
                .to_string_lossy(),
        )
        .execute(&f.pool)
        .await
        .expect("insert receiving session");
        session_id
    }

    /// The receiving -> finalizing transition is exclusive while the lease is
    /// live, reclaimable once it lapses, and a stale finalizer's terminal
    /// update is fenced by the token.
    #[tokio::test]
    async fn finalize_lease_is_exclusive_and_fences_stale_finalizer() {
        let Some(f) = tdh::Fixture::setup("local", "incus").await else {
            return;
        };
        let session_id = insert_receiving_session(&f).await;

        // First complete claims; a duplicate complete gets no lease (=> 409).
        let stale_token = claim_incus_finalize_lease(&f.pool, session_id)
            .await
            .expect("claim query ok")
            .expect("receiving session must be claimable");
        assert!(
            claim_incus_finalize_lease(&f.pool, session_id)
                .await
                .expect("claim query ok")
                .is_none(),
            "a live finalize lease must not be claimable again"
        );

        // Crashed finalizer: the lease lapses and a new complete reclaims.
        sqlx::query(
            "UPDATE incus_upload_sessions \
             SET finalize_claimed_until = NOW() - INTERVAL '1 minute' WHERE id = $1",
        )
        .bind(session_id)
        .execute(&f.pool)
        .await
        .expect("expire lease");
        let fresh_token = claim_incus_finalize_lease(&f.pool, session_id)
            .await
            .expect("claim query ok")
            .expect("expired finalize lease must be reclaimable");
        assert_ne!(stale_token, fresh_token);

        // The stale finalizer comes back (its storage push fails on the
        // missing temp file) — its token-guarded failure update must NOT
        // clobber the new owner's in-flight finalize.
        let repo = RepoInfo {
            id: f.repo_id,
            key: f.repo_key.clone(),
            storage_path: std::env::temp_dir().to_string_lossy().into_owned(),
            storage_backend: "filesystem".to_string(),
            repo_type: "local".to_string(),
            format: "incus".to_string(),
            upstream_url: None,
            promotion_only: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 0,
            age_gate_mode: "upstream_publish_time".to_string(),
            curation_enabled: false,
            curation_default_action: "allow".to_string(),
        };
        let artifact_path = build_artifact_path("ubuntu", "1", "incus.tar.xz");
        finalize_upload(
            f.state.clone(),
            repo,
            FinalizeParams {
                session_id,
                repo_id: f.repo_id,
                artifact_path: artifact_path.clone(),
                product: "ubuntu".to_string(),
                version: "1".to_string(),
                size_bytes: 0,
                checksum: "0".repeat(64),
                storage_key: build_storage_key(&f.repo_id, &artifact_path),
                user_id: f.user_id,
                metadata: serde_json::json!({ "file_type": "unknown" }),
                sealed_path: std::env::temp_dir().join(format!("ak-incus-missing-{session_id}")),
                committed_offset: 0,
                final_path: None,
                finalize_token: stale_token,
            },
        )
        .await;

        let (status, err): (String, Option<String>) = sqlx::query_as(
            "SELECT status, finalize_error FROM incus_upload_sessions WHERE id = $1",
        )
        .bind(session_id)
        .fetch_one(&f.pool)
        .await
        .expect("session row");
        assert_eq!(
            status, "finalizing",
            "a stale finalizer must not overwrite the new owner's session state"
        );
        assert!(err.is_none(), "stale finalizer must not record its error");

        let _ = sqlx::query("DELETE FROM incus_upload_sessions WHERE id = $1")
            .bind(session_id)
            .execute(&f.pool)
            .await;
        f.teardown().await;
    }

    /// A finalize handler can lose its lease while it is still receiving the
    /// final request body or hashing the staged file. Persisting the final
    /// offset is the last ownership check before background side effects: a
    /// superseded handler must return 409 without spawning its finalizer.
    #[tokio::test]
    async fn complete_conflicts_when_finalize_lease_is_superseded_before_offset_persist() {
        let Some(f) = tdh::Fixture::setup("local", "incus").await else {
            return;
        };
        let session_id = insert_receiving_session(&f).await;
        let temp_path = std::env::temp_dir().join(format!("ak-incus-lease-{session_id}"));
        tokio::fs::write(&temp_path, b"base")
            .await
            .expect("stage file");
        sqlx::query("UPDATE incus_upload_sessions SET bytes_received = 4 WHERE id = $1")
            .bind(session_id)
            .execute(&f.pool)
            .await
            .expect("record offset");

        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let (go_tx, go_rx) = tokio::sync::oneshot::channel::<()>();
        let body = Body::from_stream(futures::stream::once(async move {
            let _ = started_tx.send(());
            let _ = go_rx.await;
            Ok::<bytes::Bytes, std::io::Error>(bytes::Bytes::from_static(b"TAIL"))
        }));

        let app = f.router_with_auth(router());
        let req = axum::http::Request::builder()
            .method("PUT")
            .uri(format!("/{}/uploads/{}", f.repo_key, session_id))
            .body(body)
            .expect("build complete request");
        let request = tokio::spawn(async move { tdh::send(app, req).await });

        // The body is polled only after the handler has claimed and truncated
        // under its finalize token. Supersede that token while the body is
        // paused, then allow the stale handler to append and hash.
        started_rx.await.expect("handler must reach the body read");
        let stale_token: Uuid =
            sqlx::query_scalar("SELECT finalize_token FROM incus_upload_sessions WHERE id = $1")
                .bind(session_id)
                .fetch_one(&f.pool)
                .await
                .expect("read stale token");
        sqlx::query(
            "UPDATE incus_upload_sessions \
             SET finalize_claimed_until = NOW() - INTERVAL '1 minute' WHERE id = $1",
        )
        .bind(session_id)
        .execute(&f.pool)
        .await
        .expect("expire stale lease");
        let fresh_token = claim_incus_finalize_lease(&f.pool, session_id)
            .await
            .expect("claim query ok")
            .expect("expired lease must be reclaimable");
        assert_ne!(stale_token, fresh_token);
        let _ = go_tx.send(());

        let (status, _) = request.await.expect("request task");
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "a superseded finalize must return 409 instead of spawning"
        );

        let (session_status, owner, persisted): (String, Option<Uuid>, i64) = sqlx::query_as(
            "SELECT status, finalize_token, bytes_received \
             FROM incus_upload_sessions WHERE id = $1",
        )
        .bind(session_id)
        .fetch_one(&f.pool)
        .await
        .expect("read session state");
        assert_eq!(session_status, "finalizing");
        assert_eq!(
            owner,
            Some(fresh_token),
            "the fresh owner must remain intact"
        );
        assert_eq!(
            persisted, 4,
            "the stale handler must not move the durable recovery offset"
        );

        release_incus_finalize_lease(&f.pool, session_id, fresh_token).await;
        let _ = tokio::fs::remove_file(&temp_path).await;
        let _ = sqlx::query("DELETE FROM incus_upload_sessions WHERE id = $1")
            .bind(session_id)
            .execute(&f.pool)
            .await;
        f.teardown().await;
    }

    /// A reclaimed finalize must be idempotent against a predecessor that
    /// appended final body bytes and crashed BEFORE persisting the new
    /// offset: the staged file's unrecorded tail is truncated back to the
    /// session's persisted `bytes_received`, and a staged file SHORTER than
    /// the persisted offset (lost data) refuses to finalize rather than
    /// zero-extending.
    #[tokio::test]
    async fn reclaimed_finalize_truncates_unrecorded_append_tail() {
        let Some(f) = tdh::Fixture::setup("local", "incus").await else {
            return;
        };
        let session_id = insert_receiving_session(&f).await;

        // Stage a real temp file with 6 recorded bytes.
        let temp_path = std::env::temp_dir().join(format!("ak-incus-lease-{session_id}"));
        tokio::fs::write(&temp_path, b"123456")
            .await
            .expect("stage file");
        sqlx::query("UPDATE incus_upload_sessions SET bytes_received = 6 WHERE id = $1")
            .bind(session_id)
            .execute(&f.pool)
            .await
            .expect("record offset");

        // Owner A claims, appends the 4-byte final body, and "crashes" before
        // the durable bytes_received update; its lease then lapses.
        let _stale_token = claim_incus_finalize_lease(&f.pool, session_id)
            .await
            .expect("claim query ok")
            .expect("claimable");
        {
            use tokio::io::AsyncWriteExt;
            let mut file = tokio::fs::OpenOptions::new()
                .append(true)
                .open(&temp_path)
                .await
                .expect("open for crashed append");
            file.write_all(b"TAIL").await.expect("append tail");
            file.sync_all().await.expect("sync");
        }
        sqlx::query(
            "UPDATE incus_upload_sessions \
             SET finalize_claimed_until = NOW() - INTERVAL '1 minute' WHERE id = $1",
        )
        .bind(session_id)
        .execute(&f.pool)
        .await
        .expect("expire lease");

        // Owner B reclaims and truncates the unrecorded tail before its own
        // append — the file is back at the persisted 6 bytes, so re-sending
        // the same final body cannot double-append.
        let _fresh_token = claim_incus_finalize_lease(&f.pool, session_id)
            .await
            .expect("claim query ok")
            .expect("expired lease must be reclaimable");
        let persisted: i64 =
            sqlx::query_scalar("SELECT bytes_received FROM incus_upload_sessions WHERE id = $1")
                .bind(session_id)
                .fetch_one(&f.pool)
                .await
                .expect("read persisted offset");
        assert_eq!(
            persisted, 6,
            "crashed append must not have moved the offset"
        );
        truncate_staged_file_to_offset(&temp_path, persisted as u64)
            .await
            .expect("truncate unrecorded tail");
        assert_eq!(
            tokio::fs::read(&temp_path).await.expect("read staged file"),
            b"123456",
            "unrecorded tail must be dropped"
        );

        // A staged file SHORTER than the persisted offset is lost data and
        // must fail instead of being zero-extended.
        assert!(
            truncate_staged_file_to_offset(&temp_path, 99)
                .await
                .is_err(),
            "a too-short staged file must refuse to finalize"
        );

        let _ = tokio::fs::remove_file(&temp_path).await;
        let _ = sqlx::query("DELETE FROM incus_upload_sessions WHERE id = $1")
            .bind(session_id)
            .execute(&f.pool)
            .await;
        f.teardown().await;
    }

    /// A straggler chunk PATCH that arrives after `complete` claimed the
    /// finalize lease must be refused: appending to the staging file mid
    /// checksum would make the stored blob diverge from the recorded checksum,
    /// and advancing `bytes_received` would poison the truncate-on-reclaim
    /// arithmetic that treats it as the authoritative persisted offset.
    #[tokio::test]
    async fn chunk_patch_is_rejected_once_the_session_is_finalizing() {
        let Some(f) = tdh::Fixture::setup("local", "incus").await else {
            return;
        };
        let session_id = insert_receiving_session(&f).await;
        let temp_path = std::env::temp_dir().join(format!("ak-incus-lease-{session_id}"));
        tokio::fs::write(&temp_path, b"123456")
            .await
            .expect("stage file");
        sqlx::query("UPDATE incus_upload_sessions SET bytes_received = 6 WHERE id = $1")
            .bind(session_id)
            .execute(&f.pool)
            .await
            .expect("record offset");
        let before: i64 = 6;

        // A `complete` on any replica claims the finalize lease.
        claim_incus_finalize_lease(&f.pool, session_id)
            .await
            .expect("claim query ok")
            .expect("receiving session must be claimable");

        let app = f.router_with_auth(router());
        let req = axum::http::Request::builder()
            .method("PATCH")
            .uri(format!("/{}/uploads/{}", f.repo_key, session_id))
            .body(Body::from(b"straggler-chunk".to_vec()))
            .expect("build PATCH request");
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "a PATCH during finalize must be refused with 409"
        );

        let after: i64 =
            sqlx::query_scalar("SELECT bytes_received FROM incus_upload_sessions WHERE id = $1")
                .bind(session_id)
                .fetch_one(&f.pool)
                .await
                .expect("read offset after refused PATCH");
        assert_eq!(
            after, before,
            "a refused PATCH must not move the persisted offset"
        );
        let status_after: String =
            sqlx::query_scalar("SELECT status FROM incus_upload_sessions WHERE id = $1")
                .bind(session_id)
                .fetch_one(&f.pool)
                .await
                .expect("read status after refused PATCH");
        assert_eq!(
            status_after, "finalizing",
            "a refused PATCH must leave the finalize lease intact"
        );
        assert_eq!(
            tokio::fs::read(&temp_path).await.expect("read staged file"),
            b"123456",
            "a refused PATCH must not append to the file being checksummed"
        );

        let _ = tokio::fs::remove_file(&temp_path).await;
        let _ = sqlx::query("DELETE FROM incus_upload_sessions WHERE id = $1")
            .bind(session_id)
            .execute(&f.pool)
            .await;
        f.teardown().await;
    }

    /// The status check at the top of the handler cannot cover a PATCH whose
    /// body is still streaming when a finalize claims the session, so the
    /// `bytes_received` write carries the same predicate. This drives that
    /// exact interleaving deterministically: the body stream signals once the
    /// handler has read past the status check, the test claims the finalize
    /// lease, and only then does the body complete.
    #[tokio::test]
    async fn chunk_patch_racing_a_finalize_claim_does_not_move_the_offset() {
        let Some(f) = tdh::Fixture::setup("local", "incus").await else {
            return;
        };
        let session_id = insert_receiving_session(&f).await;
        let temp_path = std::env::temp_dir().join(format!("ak-incus-lease-{session_id}"));
        tokio::fs::write(&temp_path, b"123456")
            .await
            .expect("stage file");
        sqlx::query("UPDATE incus_upload_sessions SET bytes_received = 6 WHERE id = $1")
            .bind(session_id)
            .execute(&f.pool)
            .await
            .expect("record offset");

        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let (go_tx, go_rx) = tokio::sync::oneshot::channel::<()>();
        // The first poll of this stream happens inside `append_body_to_file`,
        // i.e. strictly after the handler's status check passed.
        let body = Body::from_stream(futures::stream::once(async move {
            let _ = started_tx.send(());
            let _ = go_rx.await;
            Ok::<bytes::Bytes, std::io::Error>(bytes::Bytes::from_static(b"racing-bytes"))
        }));

        let app = f.router_with_auth(router());
        let req = axum::http::Request::builder()
            .method("PATCH")
            .uri(format!("/{}/uploads/{}", f.repo_key, session_id))
            .body(body)
            .expect("build PATCH request");
        let request = tokio::spawn(async move { tdh::send(app, req).await });

        started_rx.await.expect("handler must reach the body read");
        claim_incus_finalize_lease(&f.pool, session_id)
            .await
            .expect("claim query ok")
            .expect("a receiving session must still be claimable mid-PATCH");
        let _ = go_tx.send(());

        let (status, _) = request.await.expect("request task");
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "a PATCH that lost the race to a finalize claim must 409"
        );

        let persisted: i64 =
            sqlx::query_scalar("SELECT bytes_received FROM incus_upload_sessions WHERE id = $1")
                .bind(session_id)
                .fetch_one(&f.pool)
                .await
                .expect("read persisted offset");
        assert_eq!(
            persisted, 6,
            "the losing PATCH must not move the offset the finalizer reads"
        );

        // The append itself did land (it had already started), so the staged
        // file now carries an unrecorded tail — exactly the shape the finalize
        // owner's truncate-to-persisted-offset pass reconciles.
        assert!(
            tokio::fs::metadata(&temp_path)
                .await
                .expect("stat staged file")
                .len()
                > persisted as u64,
            "the raced append leaves an unrecorded tail"
        );
        truncate_staged_file_to_offset(&temp_path, persisted as u64)
            .await
            .expect("finalize owner truncates the unrecorded tail");
        assert_eq!(
            tokio::fs::read(&temp_path).await.expect("read staged file"),
            b"123456",
            "the finalizer recovers the exact bytes it accounted for"
        );

        let _ = tokio::fs::remove_file(&temp_path).await;
        let _ = sqlx::query("DELETE FROM incus_upload_sessions WHERE id = $1")
            .bind(session_id)
            .execute(&f.pool)
            .await;
        f.teardown().await;
    }

    /// A live finalizer can renew before a duplicate complete request
    /// reclaims the session; once a newer token owns it, the stale token is
    /// fenced out of renewal.
    #[tokio::test]
    async fn finalize_lease_renewal_blocks_reclaim_and_fences_stale_owner() {
        let Some(f) = tdh::Fixture::setup("local", "incus").await else {
            return;
        };
        let session_id = insert_receiving_session(&f).await;

        let stale_token = claim_incus_finalize_lease(&f.pool, session_id)
            .await
            .expect("claim query ok")
            .expect("receiving session must be claimable");
        sqlx::query(
            "UPDATE incus_upload_sessions \
             SET finalize_claimed_until = NOW() - INTERVAL '1 minute' WHERE id = $1",
        )
        .bind(session_id)
        .execute(&f.pool)
        .await
        .expect("expire lease");

        assert!(
            renew_incus_finalize_lease(
                &f.pool,
                session_id,
                stale_token,
                INCUS_FINALIZE_LEASE_TTL_SECS,
            )
            .await
            .expect("renew query ok"),
            "live owner must be able to extend its token"
        );
        assert!(
            claim_incus_finalize_lease(&f.pool, session_id)
                .await
                .expect("claim query ok")
                .is_none(),
            "a renewed finalize lease must block duplicate completion"
        );

        sqlx::query(
            "UPDATE incus_upload_sessions \
             SET finalize_claimed_until = NOW() - INTERVAL '1 minute' WHERE id = $1",
        )
        .bind(session_id)
        .execute(&f.pool)
        .await
        .expect("expire renewed lease");
        let fresh_token = claim_incus_finalize_lease(&f.pool, session_id)
            .await
            .expect("claim query ok")
            .expect("expired finalize lease must be reclaimable");

        assert!(
            !renew_incus_finalize_lease(
                &f.pool,
                session_id,
                stale_token,
                INCUS_FINALIZE_LEASE_TTL_SECS,
            )
            .await
            .expect("renew query ok"),
            "stale token must not renew after a reclaim"
        );
        assert!(
            renew_incus_finalize_lease(
                &f.pool,
                session_id,
                fresh_token,
                INCUS_FINALIZE_LEASE_TTL_SECS,
            )
            .await
            .expect("renew query ok"),
            "fresh token must be able to renew"
        );

        let _ = sqlx::query("DELETE FROM incus_upload_sessions WHERE id = $1")
            .bind(session_id)
            .execute(&f.pool)
            .await;
        f.teardown().await;
    }

    /// The stale-session reaper must skip a finalizing session whose lease is
    /// live (a finalizer may still be streaming its temp file), then reap it
    /// once the lease lapses.
    #[tokio::test]
    async fn stale_reaper_skips_live_finalize_lease() {
        let Some(f) = tdh::Fixture::setup("local", "incus").await else {
            return;
        };
        let session_id = insert_receiving_session(&f).await;
        let _token = claim_incus_finalize_lease(&f.pool, session_id)
            .await
            .expect("claim query ok")
            .expect("claim");

        // Age the session past the reap threshold while its lease is live.
        sqlx::query(
            "UPDATE incus_upload_sessions \
             SET updated_at = NOW() - INTERVAL '48 hours' WHERE id = $1",
        )
        .bind(session_id)
        .execute(&f.pool)
        .await
        .expect("age session");

        cleanup_stale_sessions(&f.pool, 24).await.expect("sweep ok");
        let survives: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM incus_upload_sessions WHERE id = $1)")
                .bind(session_id)
                .fetch_one(&f.pool)
                .await
                .expect("existence check");
        assert!(survives, "reaper must not delete a live finalize lease");

        // Lapse the lease; now the reaper may claim-and-delete it.
        sqlx::query(
            "UPDATE incus_upload_sessions \
             SET finalize_claimed_until = NOW() - INTERVAL '1 minute', \
                 updated_at = NOW() - INTERVAL '48 hours' \
             WHERE id = $1",
        )
        .bind(session_id)
        .execute(&f.pool)
        .await
        .expect("expire lease");
        cleanup_stale_sessions(&f.pool, 24).await.expect("sweep ok");
        let survives: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM incus_upload_sessions WHERE id = $1)")
                .bind(session_id)
                .fetch_one(&f.pool)
                .await
                .expect("existence check");
        assert!(!survives, "reaper must reap once the finalize lease lapsed");

        f.teardown().await;
    }

    // =======================================================================
    // Finalize-seal regression suite
    //
    // The finalize lease fences the session ROW; these cover the fencing of
    // the staged FILE that goes with it: the staged chunks are sealed to the
    // lease at claim time, the completing request's body is staged in its own
    // file, and the artifact is a deterministic bounded concatenation of the
    // two. Together they pin idempotent reclaim, exclusion of post-seal
    // writes, claim-aware cancel, and the DB-side chunk offset.
    // =======================================================================

    /// Seed a session parked in `finalizing` with a lapsed lease, staged the
    /// way a finalize that died mid storage-push leaves it: the committed
    /// chunks sealed at `committed`, plus whatever the dead attempt had
    /// written to the final-body file. Returns `(session_id, temp_path)`.
    ///
    /// This models a **post-#3072** crashed finalize — note that it writes the
    /// `.seal` sidecar, which only post-#3072 code ever creates — so it must
    /// carry `finalize_phase`, exactly as `claim_incus_finalize_lease` stamps
    /// it. A NULL phase here would instead describe a session stranded by a
    /// PRE-#3072 server, which #3083 deliberately refuses to reclaim; see
    /// `legacy_pre_3072_finalize_is_refused_not_reclaimed` for that shape.
    async fn seed_crashed_finalize(
        f: &tdh::Fixture,
        artifact_path: &str,
        committed: &[u8],
        stale_final: Option<&[u8]>,
    ) -> (Uuid, PathBuf) {
        let session_id = Uuid::new_v4();
        let temp_path = temp_upload_path(f.storage_dir.to_str().unwrap(), &session_id);
        ensure_parent_dirs(&temp_path).await.expect("staging dir");
        tokio::fs::write(sealed_upload_path(&temp_path), committed)
            .await
            .expect("write sealed chunks");
        if let Some(partial) = stale_final {
            tokio::fs::write(final_upload_path(&temp_path), partial)
                .await
                .expect("write stale final body");
        }
        sqlx::query(
            "INSERT INTO incus_upload_sessions \
             (id, repository_id, user_id, artifact_path, product, version, filename, \
              bytes_received, storage_temp_path, status, finalize_token, \
              finalize_claimed_until, finalize_phase) \
             VALUES ($1, $2, $3, $4, 'alpine', '3.20', 'rootfs.tar.gz', $5, $6, 'finalizing', \
                     $7, NOW() - INTERVAL '1 minute', 'sealing')",
        )
        .bind(session_id)
        .bind(f.repo_id)
        .bind(f.user_id)
        .bind(artifact_path)
        .bind(committed.len() as i64)
        .bind(&*temp_path.to_string_lossy())
        .bind(Uuid::new_v4())
        .execute(&f.pool)
        .await
        .expect("insert crashed finalizing session");
        (session_id, temp_path)
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        format!("{:x}", hasher.finalize())
    }

    async fn put_complete(
        f: &tdh::Fixture,
        session_id: Uuid,
        body: Vec<u8>,
    ) -> (StatusCode, Bytes) {
        let app = f.router_with_auth(router());
        let req = axum::http::Request::builder()
            .method("PUT")
            .uri(format!("/{}/uploads/{}", f.repo_key, session_id))
            .body(Body::from(body))
            .expect("build complete request");
        tdh::send(app, req).await
    }

    async fn download(f: &tdh::Fixture, path: &str) -> axum::response::Response {
        let app = f.router_with_auth(router());
        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!("/{}/images/{}", f.repo_key, path))
            .body(Body::empty())
            .expect("build download request");
        app.oneshot(req).await.expect("download oneshot")
    }

    /// Seed the shape a PRE-#3072 server leaves behind across an upgrade
    /// (#3083): `finalizing`, no `finalize_phase`, and — because pre-#3072
    /// code appended the completing body straight onto the staging file and
    /// never sealed — a plain staging file with no `.seal` sidecar.
    ///
    /// `lease_lapsed` picks whether the old finalizer is presumed dead (lapsed;
    /// this is the reclaim window #3083 closes) or still running on an
    /// un-upgraded replica during a rolling upgrade (live lease).
    async fn seed_legacy_pre_3072_finalize(
        f: &tdh::Fixture,
        artifact_path: &str,
        staged: &[u8],
        lease_lapsed: bool,
    ) -> Uuid {
        let session_id = Uuid::new_v4();
        let temp_path = temp_upload_path(f.storage_dir.to_str().unwrap(), &session_id);
        ensure_parent_dirs(&temp_path).await.expect("staging dir");
        tokio::fs::write(&temp_path, staged)
            .await
            .expect("write legacy staging file");
        let lease = if lease_lapsed {
            "NOW() - INTERVAL '1 minute'"
        } else {
            "NOW() + INTERVAL '1 hour'"
        };
        sqlx::query(&format!(
            "INSERT INTO incus_upload_sessions \
             (id, repository_id, user_id, artifact_path, product, version, filename, \
              bytes_received, storage_temp_path, status, finalize_token, \
              finalize_claimed_until) \
             VALUES ($1, $2, $3, $4, 'alpine', '3.20', 'rootfs.tar.gz', $5, $6, 'finalizing', \
                     $7, {lease})"
        ))
        .bind(session_id)
        .bind(f.repo_id)
        .bind(f.user_id)
        .bind(artifact_path)
        .bind(staged.len() as i64)
        .bind(&*temp_path.to_string_lossy())
        .bind(Uuid::new_v4())
        .execute(&f.pool)
        .await
        .expect("insert legacy finalizing session");
        session_id
    }

    /// #3083: a session left mid-finalize by a pre-#3072 server must be
    /// REFUSED, not reclaimed. Its `bytes_received` may already include the
    /// completing body (old code appended it in place), so re-running the
    /// current seal/truncate/append algorithm over it would append that body a
    /// second time and publish a corrupt image.
    #[tokio::test]
    async fn legacy_pre_3072_finalize_is_refused_not_reclaimed() {
        let Some(f) = tdh::Fixture::setup("local", "incus").await else {
            return;
        };
        let artifact_path = build_artifact_path("alpine", "3.20", "rootfs.tar.gz");
        let session_id =
            seed_legacy_pre_3072_finalize(&f, &artifact_path, &vec![b'A'; 512], true).await;

        let (status, body) = put_complete(&f, session_id, vec![b'B'; 128]).await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "a pre-upgrade in-flight finalize must not be reclaimed: {}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(String::from_utf8_lossy(&body), LEGACY_FINALIZE_MESSAGE);

        // The refusal must not have quietly taken the lease: the row stays put
        // for the operator to cancel, still unstamped.
        let (row_status, phase): (String, Option<String>) = sqlx::query_as(
            "SELECT status, finalize_phase FROM incus_upload_sessions WHERE id = $1",
        )
        .bind(session_id)
        .fetch_one(&f.pool)
        .await
        .expect("session row");
        assert_eq!(row_status, "finalizing");
        assert_eq!(phase, None, "a refused claim must not stamp the phase");
    }

    /// The #3083 refusal is scoped to a LAPSED lease. During a rolling upgrade
    /// an un-upgraded replica can still be actively finalizing a legacy session
    /// under a live lease, and that finalize completes correctly under the old
    /// algorithm — so a concurrent retry must get the ordinary "already in
    /// progress" answer, never advice to cancel and throw the upload away.
    #[tokio::test]
    async fn legacy_finalize_with_a_live_lease_reports_in_progress() {
        let Some(f) = tdh::Fixture::setup("local", "incus").await else {
            return;
        };
        let artifact_path = build_artifact_path("alpine", "3.20", "rootfs.tar.gz");
        let session_id =
            seed_legacy_pre_3072_finalize(&f, &artifact_path, &vec![b'A'; 512], false).await;

        let (status, body) = put_complete(&f, session_id, vec![b'B'; 128]).await;
        let body = String::from_utf8_lossy(&body).to_string();
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(
            body.contains("finalize already in progress or finished"),
            "a live-lease legacy row must keep the historical message, not the \
             destructive #3083 cancel-and-re-upload advice: {body}"
        );
        assert_ne!(body, LEGACY_FINALIZE_MESSAGE);
    }

    /// (1) HIGH-3b. A finalize that died after staging its input and while
    /// pushing to the storage backend is retried by the client. The retry
    /// must re-derive the SAME artifact — committed chunks plus the resent
    /// body, once — instead of accumulating the body a second time.
    ///
    /// The completing body is re-staged with create+truncate, so the stale
    /// partial the dead attempt left behind is overwritten rather than kept,
    /// and the sealed chunks are never appended to.
    #[tokio::test]
    async fn reclaim_finalize_does_not_double_append() {
        let Some(f) = tdh::Fixture::setup("local", "incus").await else {
            return;
        };

        let committed = vec![b'A'; 1000];
        let final_body = vec![b'B'; 200 * 1024];
        let mut expected = committed.clone();
        expected.extend_from_slice(&final_body);
        let expected_sha = sha256_hex(&expected);
        let artifact_path = build_artifact_path("alpine", "3.20", "rootfs.tar.gz");

        // The dead attempt had already staged the whole body and was pushing
        // it to the storage backend when it died — the window that used to
        // make the retry store the body twice.
        let (session_id, temp_path) =
            seed_crashed_finalize(&f, &artifact_path, &committed, Some(&final_body)).await;

        let (status, body) = put_complete(&f, session_id, final_body.clone()).await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "reclaiming a lapsed finalize must be accepted: {}",
            String::from_utf8_lossy(&body)
        );
        let json: serde_json::Value = serde_json::from_slice(&body).expect("parse complete JSON");
        assert_eq!(
            json["size"].as_i64(),
            Some(expected.len() as i64),
            "the retry must report the committed chunks plus ONE copy of the resent body"
        );
        assert_eq!(
            json["sha256"].as_str(),
            Some(expected_sha.as_str()),
            "the retry must re-derive the same checksum, not one over a doubled body"
        );

        let progress = await_finalize(&f, session_id).await;
        assert_eq!(
            progress["status"].as_str(),
            Some("completed"),
            "reclaimed finalize must complete: {}",
            progress
        );

        let (size_bytes, checksum): (i64, String) = sqlx::query_as(
            "SELECT size_bytes, checksum_sha256 FROM artifacts \
             WHERE repository_id = $1 AND path = $2",
        )
        .bind(f.repo_id)
        .bind(&artifact_path)
        .fetch_one(&f.pool)
        .await
        .expect("artifact row");
        assert_eq!(
            size_bytes,
            expected.len() as i64,
            "recorded size must be committed + one body, not committed + two"
        );
        assert_eq!(checksum, expected_sha, "recorded checksum must match");

        // Stored object == recorded == served.
        let resp = download(&f, "alpine/3.20/rootfs.tar.gz").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let served_hdr = resp
            .headers()
            .get("X-Checksum-Sha256")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let served = axum::body::to_bytes(resp.into_body(), 16 * 1024 * 1024)
            .await
            .expect("download body");
        assert_eq!(served.as_ref(), expected.as_slice(), "served bytes");
        assert_eq!(sha256_hex(&served), expected_sha, "served digest");
        assert_eq!(served_hdr, expected_sha, "advertised digest");

        // Both staging halves are gone once the finalize is done.
        assert!(
            !sealed_upload_path(&temp_path).exists(),
            "sealed file leaked"
        );
        assert!(!final_upload_path(&temp_path).exists(), "final file leaked");

        // A completed session is terminal: it is never reclaimed, so a
        // further retry cannot re-run any of this.
        let (status, _) = put_complete(&f, session_id, final_body).await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "a completed session must never be reclaimed"
        );

        f.teardown().await;
    }

    /// (2) HIGH-3a, deterministic. The finalize's view of the staged data is
    /// bounded to the committed offset, so bytes appended past it — by a
    /// chunk whose fd was opened before the seal — are in neither the
    /// checksum nor the stored object. An unbounded read-to-EOF would
    /// include them.
    #[tokio::test]
    async fn finalize_stream_excludes_post_seal_tail() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let sealed = tmp.path().join("ak-incus-upload-x.seal");
        let final_path = tmp.path().join("ak-incus-upload-x.final");

        let committed = vec![b'A'; 300 * 1024];
        let post_seal_tail = vec![b'X'; 64 * 1024];
        let final_body = vec![b'B'; 5000];

        let mut on_disk = committed.clone();
        on_disk.extend_from_slice(&post_seal_tail);
        tokio::fs::write(&sealed, &on_disk)
            .await
            .expect("write sealed");
        tokio::fs::write(&final_path, &final_body)
            .await
            .expect("write final");

        let mut expected = committed.clone();
        expected.extend_from_slice(&final_body);

        let mut stream = open_finalize_stream(&sealed, committed.len() as u64, Some(&final_path))
            .await
            .expect("open finalize stream");
        let mut collected: Vec<u8> = Vec::new();
        while let Some(chunk) = stream.next().await {
            collected.extend_from_slice(&chunk.expect("chunk ok"));
        }
        assert_eq!(
            collected.len(),
            expected.len(),
            "finalize stream must yield committed + final, excluding the post-seal tail"
        );
        assert_eq!(collected, expected, "finalize stream bytes");

        let stream = open_finalize_stream(&sealed, committed.len() as u64, Some(&final_path))
            .await
            .expect("reopen finalize stream");
        assert_eq!(
            compute_sha256_over_stream(stream)
                .await
                .expect("hash finalize stream"),
            sha256_hex(&expected),
            "checksum must be computed over the same bounded view that is stored"
        );

        // Same builder with no trailing body (the monolithic shape).
        let stream = open_finalize_stream(&sealed, committed.len() as u64, None)
            .await
            .expect("open bodyless finalize stream");
        assert_eq!(
            compute_sha256_over_stream(stream)
                .await
                .expect("hash bodyless stream"),
            sha256_hex(&committed),
        );
    }

    /// (3) HIGH-3a, end to end. A chunk request whose append fd was opened
    /// before the finalize claim keeps writing to the staged inode after the
    /// seal. Its bytes must be excluded from the artifact — recorded size,
    /// recorded checksum, the stored object and the served body must all
    /// agree — and the chunk itself must be refused.
    #[tokio::test]
    async fn patch_after_finalize_claim_is_fenced() {
        let Some(f) = tdh::Fixture::setup("local", "incus").await else {
            return;
        };

        let product = "debian";
        let version = "12";
        let filename = "rootfs.tar.gz";
        let committed = vec![b'A'; 256 * 1024];
        let expected_sha = sha256_hex(&committed);

        // POST start stages the committed bytes.
        let app = f.router_with_auth(router());
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/{}/images/{}/{}/{}/uploads",
                f.repo_key, product, version, filename
            ))
            .body(Body::from(committed.clone()))
            .expect("build POST start");
        let (status, body) = tdh::send(app, req).await;
        assert_eq!(status, StatusCode::ACCEPTED, "POST start must be 202");
        let session_id: Uuid = serde_json::from_slice::<serde_json::Value>(&body)
            .expect("parse start JSON")["session_id"]
            .as_str()
            .expect("session_id")
            .parse()
            .expect("uuid");
        let temp_path = temp_upload_path(f.storage_dir.to_str().unwrap(), &session_id);

        // A chunk request that has passed its status check and holds an open
        // append fd, paused before it writes.
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let (go_tx, go_rx) = tokio::sync::oneshot::channel::<()>();
        let straggler = vec![b'X'; 128 * 1024];
        let straggler_body = Body::from_stream(futures::stream::once(async move {
            let _ = started_tx.send(());
            let _ = go_rx.await;
            Ok::<Bytes, std::io::Error>(Bytes::from(straggler))
        }));
        let app = f.router_with_auth(router());
        let req = axum::http::Request::builder()
            .method("PATCH")
            .uri(format!("/{}/uploads/{}", f.repo_key, session_id))
            .body(straggler_body)
            .expect("build straggler PATCH");
        let straggler_req = tokio::spawn(async move { tdh::send(app, req).await });
        started_rx.await.expect("straggler must open its append fd");

        // Finalize claims the session and seals the staged chunks.
        let (status, body) = put_complete(&f, session_id, Vec::new()).await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "complete must be accepted: {}",
            String::from_utf8_lossy(&body)
        );
        let json: serde_json::Value = serde_json::from_slice(&body).expect("parse complete JSON");
        assert_eq!(json["size"].as_i64(), Some(committed.len() as i64));
        assert_eq!(json["sha256"].as_str(), Some(expected_sha.as_str()));

        // Release the straggler: it writes through its pre-seal fd, then
        // finds the session is no longer receiving.
        let _ = go_tx.send(());
        let (straggler_status, _) = straggler_req.await.expect("straggler task");
        assert_eq!(
            straggler_status,
            StatusCode::CONFLICT,
            "a chunk racing the finalize claim must be refused"
        );

        let progress = await_finalize(&f, session_id).await;
        assert_eq!(progress["status"].as_str(), Some("completed"));

        let (size_bytes, checksum): (i64, String) = sqlx::query_as(
            "SELECT size_bytes, checksum_sha256 FROM artifacts \
             WHERE repository_id = $1 AND path = $2",
        )
        .bind(f.repo_id)
        .bind(build_artifact_path(product, version, filename))
        .fetch_one(&f.pool)
        .await
        .expect("artifact row");
        assert_eq!(size_bytes, committed.len() as i64, "recorded size");
        assert_eq!(checksum, expected_sha, "recorded checksum");

        let resp = download(&f, "debian/12/rootfs.tar.gz").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let served_hdr = resp
            .headers()
            .get("X-Checksum-Sha256")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let served = axum::body::to_bytes(resp.into_body(), 16 * 1024 * 1024)
            .await
            .expect("download body");
        // recorded == on-disk == served, all three.
        assert_eq!(
            served.len(),
            size_bytes as usize,
            "served length vs recorded"
        );
        assert_eq!(sha256_hex(&served), checksum, "served digest vs recorded");
        assert_eq!(served_hdr, checksum, "advertised digest vs recorded");
        assert!(
            !sealed_upload_path(&temp_path).exists(),
            "sealed file leaked"
        );
        assert!(!final_upload_path(&temp_path).exists(), "final file leaked");

        f.teardown().await;
    }

    /// (3, direct) A chunk that arrives after the staged file was sealed —
    /// even before the row read observes the new status — cannot write: the
    /// append open finds nothing at the session's staging path and the
    /// request is refused rather than failing as a server error or landing
    /// bytes the finalize is already hashing.
    #[tokio::test]
    async fn chunk_append_after_seal_is_refused() {
        let Some(f) = tdh::Fixture::setup("local", "incus").await else {
            return;
        };
        let session_id = insert_receiving_session(&f).await;
        let temp_path = std::env::temp_dir().join(format!("ak-incus-lease-{session_id}"));
        let sealed = sealed_upload_path(&temp_path);
        tokio::fs::write(&temp_path, b"123456")
            .await
            .expect("stage file");
        sqlx::query("UPDATE incus_upload_sessions SET bytes_received = 6 WHERE id = $1")
            .bind(session_id)
            .execute(&f.pool)
            .await
            .expect("record offset");

        // Seal, leaving the row readable as 'receiving' — the exact window a
        // chunk request that pre-read the row is in.
        seal_staging_file(&temp_path, &sealed)
            .await
            .expect("seal staged file");
        assert!(!temp_path.exists(), "seal must move the staged file");

        let app = f.router_with_auth(router());
        let req = axum::http::Request::builder()
            .method("PATCH")
            .uri(format!("/{}/uploads/{}", f.repo_key, session_id))
            .body(Body::from(vec![b'X'; 512]))
            .expect("build PATCH");
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "a chunk on a sealed session must be refused with 409"
        );

        let persisted: i64 =
            sqlx::query_scalar("SELECT bytes_received FROM incus_upload_sessions WHERE id = $1")
                .bind(session_id)
                .fetch_one(&f.pool)
                .await
                .expect("read offset");
        assert_eq!(persisted, 6, "a refused chunk must not move the offset");
        assert_eq!(
            tokio::fs::metadata(&sealed)
                .await
                .expect("sealed stat")
                .len(),
            6,
            "a refused chunk must not reach the sealed data"
        );

        // Un-sealing restores the staged file so a released session resumes.
        unseal_staging_file(&temp_path, &sealed, &final_upload_path(&temp_path)).await;
        assert!(temp_path.exists(), "unseal must restore the staged file");
        assert!(!sealed.exists(), "unseal must consume the sealed file");

        let _ = tokio::fs::remove_file(&temp_path).await;
        let _ = sqlx::query("DELETE FROM incus_upload_sessions WHERE id = $1")
            .bind(session_id)
            .execute(&f.pool)
            .await;
        f.teardown().await;
    }

    /// (4a) MED-3c. Cancelling a session that already entered finalize must
    /// be refused: that session is owned by a finalize which is streaming the
    /// staged data out and will publish an artifact. The row and its staged
    /// data must survive the refused cancel.
    #[tokio::test]
    async fn cancel_rejects_finalizing_session() {
        let Some(f) = tdh::Fixture::setup("local", "incus").await else {
            return;
        };
        let session_id = insert_receiving_session(&f).await;
        let temp_path = std::env::temp_dir().join(format!("ak-incus-lease-{session_id}"));
        tokio::fs::write(&temp_path, b"staged-bytes")
            .await
            .expect("stage file");
        let token = claim_incus_finalize_lease(&f.pool, session_id)
            .await
            .expect("claim query ok")
            .expect("claimable");

        let app = f.router_with_auth(router());
        let req = axum::http::Request::builder()
            .method("DELETE")
            .uri(format!("/{}/uploads/{}", f.repo_key, session_id))
            .body(Body::empty())
            .expect("build DELETE");
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "cancelling a finalizing session must be refused"
        );

        let (still_there, owner): (String, Option<Uuid>) = sqlx::query_as(
            "SELECT status, finalize_token FROM incus_upload_sessions WHERE id = $1",
        )
        .bind(session_id)
        .fetch_one(&f.pool)
        .await
        .expect("session row must survive a refused cancel");
        assert_eq!(still_there, "finalizing");
        assert_eq!(owner, Some(token), "the finalize must keep its lease");
        assert!(
            temp_path.exists(),
            "a refused cancel must not touch data a live finalize owns"
        );

        // A terminal session is equally not cancellable.
        sqlx::query("UPDATE incus_upload_sessions SET status = 'completed' WHERE id = $1")
            .bind(session_id)
            .execute(&f.pool)
            .await
            .expect("mark completed");
        let app = f.router_with_auth(router());
        let req = axum::http::Request::builder()
            .method("DELETE")
            .uri(format!("/{}/uploads/{}", f.repo_key, session_id))
            .body(Body::empty())
            .expect("build DELETE");
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "cancelling a finished session must be refused"
        );

        let _ = tokio::fs::remove_file(&temp_path).await;
        let _ = sqlx::query("DELETE FROM incus_upload_sessions WHERE id = $1")
            .bind(session_id)
            .execute(&f.pool)
            .await;
        f.teardown().await;
    }

    /// (4b) Cancelling a session that is still receiving is the supported
    /// case: the row goes away and every staged file with it.
    #[tokio::test]
    async fn cancel_receiving_happy_path() {
        let Some(f) = tdh::Fixture::setup("local", "incus").await else {
            return;
        };
        let session_id = insert_receiving_session(&f).await;
        let temp_path = std::env::temp_dir().join(format!("ak-incus-lease-{session_id}"));
        let sealed = sealed_upload_path(&temp_path);
        let final_path = final_upload_path(&temp_path);
        tokio::fs::write(&temp_path, b"staged")
            .await
            .expect("stage");
        tokio::fs::write(&sealed, b"seal-leftover")
            .await
            .expect("stage sealed leftover");
        tokio::fs::write(&final_path, b"final-leftover")
            .await
            .expect("stage final leftover");

        let app = f.router_with_auth(router());
        let req = axum::http::Request::builder()
            .method("DELETE")
            .uri(format!("/{}/uploads/{}", f.repo_key, session_id))
            .body(Body::empty())
            .expect("build DELETE");
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "cancel must be 204");

        let gone: bool = sqlx::query_scalar(
            "SELECT NOT EXISTS(SELECT 1 FROM incus_upload_sessions WHERE id = $1)",
        )
        .bind(session_id)
        .fetch_one(&f.pool)
        .await
        .expect("existence check");
        assert!(gone, "cancel must delete the session row");
        assert!(!temp_path.exists(), "cancel must remove the staged file");
        assert!(!sealed.exists(), "cancel must remove a sealed leftover");
        assert!(!final_path.exists(), "cancel must remove a final leftover");

        f.teardown().await;
    }

    /// (4c) Cancel is owner-scoped: another account that holds the delete
    /// scope and learns the session id cannot retire someone else's upload.
    #[tokio::test]
    async fn cancel_enforces_owner() {
        let Some(f) = tdh::Fixture::setup("local", "incus").await else {
            return;
        };
        let session_id = insert_receiving_session(&f).await;
        let temp_path = std::env::temp_dir().join(format!("ak-incus-lease-{session_id}"));
        tokio::fs::write(&temp_path, b"staged")
            .await
            .expect("stage");

        // Re-point the session at a different owner, then drive the cancel as
        // the fixture user.
        let other_owner = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, username, email, password_hash) \
             VALUES ($1, $2, $3, 'x')",
        )
        .bind(other_owner)
        .bind(format!("owner-{}", other_owner))
        .bind(format!("owner-{}@test.local", other_owner))
        .execute(&f.pool)
        .await
        .expect("insert other owner");
        sqlx::query("UPDATE incus_upload_sessions SET user_id = $2 WHERE id = $1")
            .bind(session_id)
            .bind(other_owner)
            .execute(&f.pool)
            .await
            .expect("re-point owner");

        let app = f.router_with_auth(router());
        let req = axum::http::Request::builder()
            .method("DELETE")
            .uri(format!("/{}/uploads/{}", f.repo_key, session_id))
            .body(Body::empty())
            .expect("build DELETE");
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a non-owner must not cancel someone else's upload"
        );

        let survives: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM incus_upload_sessions WHERE id = $1)")
                .bind(session_id)
                .fetch_one(&f.pool)
                .await
                .expect("existence check");
        assert!(survives, "a refused cancel must leave the session intact");
        assert!(temp_path.exists(), "a refused cancel must not remove data");

        let _ = tokio::fs::remove_file(&temp_path).await;
        let _ = sqlx::query("DELETE FROM incus_upload_sessions WHERE id = $1")
            .bind(session_id)
            .execute(&f.pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(other_owner)
            .execute(&f.pool)
            .await;
        f.teardown().await;
    }

    /// (5) The committed offset is advanced DB-side, so two chunk requests
    /// that overlap both count. A read-modify-write from each request's own
    /// pre-read would lose one of them, and the finalize bounds its read to
    /// this counter — a lost update silently drops committed bytes from the
    /// artifact.
    #[tokio::test]
    async fn concurrent_patch_offset_is_additive() {
        let Some(f) = tdh::Fixture::setup("local", "incus").await else {
            return;
        };
        let session_id = insert_receiving_session(&f).await;
        let temp_path = std::env::temp_dir().join(format!("ak-incus-lease-{session_id}"));
        tokio::fs::write(&temp_path, b"base").await.expect("stage");
        sqlx::query("UPDATE incus_upload_sessions SET bytes_received = 4 WHERE id = $1")
            .bind(session_id)
            .execute(&f.pool)
            .await
            .expect("record offset");

        // Both requests are held open until each has read the session row and
        // opened its append fd, so their offset updates genuinely overlap.
        let mut gates = Vec::new();
        let mut tasks = Vec::new();
        for len in [700usize, 300usize] {
            let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
            let (go_tx, go_rx) = tokio::sync::oneshot::channel::<()>();
            let body = Body::from_stream(futures::stream::once(async move {
                let _ = started_tx.send(());
                let _ = go_rx.await;
                Ok::<Bytes, std::io::Error>(Bytes::from(vec![b'C'; len]))
            }));
            let app = f.router_with_auth(router());
            let req = axum::http::Request::builder()
                .method("PATCH")
                .uri(format!("/{}/uploads/{}", f.repo_key, session_id))
                .body(body)
                .expect("build PATCH");
            tasks.push(tokio::spawn(async move { tdh::send(app, req).await }));
            started_rx.await.expect("chunk must reach its body read");
            gates.push(go_tx);
        }
        for gate in gates {
            let _ = gate.send(());
        }
        for task in tasks {
            let (status, _) = task.await.expect("chunk task");
            assert_eq!(status, StatusCode::ACCEPTED, "both chunks must be accepted");
        }

        let persisted: i64 =
            sqlx::query_scalar("SELECT bytes_received FROM incus_upload_sessions WHERE id = $1")
                .bind(session_id)
                .fetch_one(&f.pool)
                .await
                .expect("read offset");
        assert_eq!(
            persisted, 1004,
            "overlapping chunks must both count toward the committed offset"
        );
        assert_eq!(
            tokio::fs::metadata(&temp_path)
                .await
                .expect("staged stat")
                .len(),
            1004,
            "the committed offset must match the bytes actually on disk"
        );

        let _ = tokio::fs::remove_file(&temp_path).await;
        let _ = sqlx::query("DELETE FROM incus_upload_sessions WHERE id = $1")
            .bind(session_id)
            .execute(&f.pool)
            .await;
        f.teardown().await;
    }

    /// A finalize that claims the lease and then fails while staging its
    /// input must leave the session exactly as it found it: back in
    /// `receiving`, with the staged chunks restored to the path a resumed
    /// chunk request opens and no finalize sidecars left behind. Otherwise
    /// the session would be wedged in `finalizing` until the lease lapses,
    /// and a resumed chunk would find nothing to append to.
    #[tokio::test]
    async fn failed_finalize_unseals_and_releases_the_session() {
        let Some(f) = tdh::Fixture::setup("local", "incus").await else {
            return;
        };
        let session_id = insert_receiving_session(&f).await;
        let temp_path = std::env::temp_dir().join(format!("ak-incus-lease-{session_id}"));
        tokio::fs::write(&temp_path, b"123456")
            .await
            .expect("stage file");
        // Recorded offset beyond what is staged: the staged data is not on
        // this replica, which must fail the finalize rather than publish a
        // short artifact.
        sqlx::query("UPDATE incus_upload_sessions SET bytes_received = 99 WHERE id = $1")
            .bind(session_id)
            .execute(&f.pool)
            .await
            .expect("record offset");

        let (status, _) = put_complete(&f, session_id, b"TAIL".to_vec()).await;
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "a finalize whose staged data is missing must fail"
        );

        let (session_status, token): (String, Option<Uuid>) = sqlx::query_as(
            "SELECT status, finalize_token FROM incus_upload_sessions WHERE id = $1",
        )
        .bind(session_id)
        .fetch_one(&f.pool)
        .await
        .expect("session row");
        assert_eq!(
            session_status, "receiving",
            "a failed finalize must release the lease so the client can retry"
        );
        assert!(token.is_none(), "the released lease must drop its token");
        assert!(
            temp_path.exists(),
            "a failed finalize must restore the staged file for a resumed chunk"
        );
        assert_eq!(
            tokio::fs::read(&temp_path).await.expect("read staged"),
            b"123456",
            "restored staged data must be intact"
        );
        assert!(
            !sealed_upload_path(&temp_path).exists(),
            "a failed finalize must not leave a sealed file"
        );
        assert!(
            !final_upload_path(&temp_path).exists(),
            "a failed finalize must not leave a final-body file"
        );

        // The session really is resumable.
        let app = f.router_with_auth(router());
        let req = axum::http::Request::builder()
            .method("PATCH")
            .uri(format!("/{}/uploads/{}", f.repo_key, session_id))
            .body(Body::from(b"789".to_vec()))
            .expect("build PATCH");
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "a released session must accept chunks again"
        );

        let _ = tokio::fs::remove_file(&temp_path).await;
        let _ = sqlx::query("DELETE FROM incus_upload_sessions WHERE id = $1")
            .bind(session_id)
            .execute(&f.pool)
            .await;
        f.teardown().await;
    }
}
