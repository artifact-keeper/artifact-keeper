//! Referenced-content walker for Docker/OCI migration imports (#2457).
//!
//! A Docker/OCI source registry (Nexus, a conformant `/v2/` registry)
//! enumerates only the *tag* manifests of a repository. The bytes those
//! manifests reference — the image `config` blob, every `layers[]` blob, and
//! (for a multi-arch image index) the per-arch child manifests plus *their*
//! config/layer blobs — are addressed by digest and are NEVER returned by the
//! source's artifact listing. Before this module the migration worker
//! registered the tag manifests (`oci_tags` + index→child edges) but fetched
//! none of the referenced content, so a migrated image was HOLLOW: every
//! `/v2/.../blobs/<config>` and `/v2/.../manifests/<child>` returned 404 and
//! `docker pull` failed even though the job reported success.
//!
//! [`walk_and_register_referenced_content`] closes that gap. Given a manifest
//! that the worker has just fetched, classified, and registered, it:
//!   * for an IMAGE manifest, fetches the `config` blob and every layer blob
//!     by digest and registers real bytes into `oci_blobs`;
//!   * for an image INDEX, recurses each child: fetches the child manifest by
//!     digest, stores it at its digest-addressed key, registers it via
//!     [`persist_tag_and_refs_in_tx`] (so it resolves by digest exactly as a
//!     live `docker push` would record it), then walks the child's own
//!     config/layer blobs.
//!
//! Design guarantees:
//!   * **Fail-closed.** Any referenced blob or child manifest that cannot be
//!     transferred (source 404, transport error, digest mismatch, malformed
//!     child) returns `Err`. The caller runs the walk inside the item's
//!     transaction, so a failure rolls the tag back and marks the item FAILED
//!     — a migrated tag is never acked while its content is incomplete.
//!   * **Streaming.** Every blob is spilled through a `NamedTempFile` and
//!     `put_stream`, so peak memory is O(chunk) regardless of layer size
//!     (#1422/#1512). Only manifests (bounded by [`MAX_INDEX_MANIFEST_BYTES`])
//!     are buffered, matching the worker's manifest path.
//!   * **Dedup / no-op.** Content already present in `oci_blobs` /
//!     `oci_tags` (e.g. blobs the Artifactory source enumerates as their own
//!     items) is skipped without a fetch, so the walker is a no-op there and
//!     cannot regress the Artifactory path.
//!   * **DoS-bounded.** A visited-digest set guards against cycles and
//!     re-fetching shared layers; recursion depth, per-index fan-out, and
//!     total blob/manifest counts are all capped.

use std::collections::{HashSet, VecDeque};
use std::path::Path;
use std::sync::Arc;

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::api::handlers::oci_v2::{
    blob_storage_key, classify_manifest, extract_blob_refs, extract_child_digests,
    manifest_storage_key, persist_tag_and_refs_in_tx, resolve_manifest_content_type,
    stored_media_type_for, ManifestClass,
};
use crate::services::migration_service::MigrationError;
use crate::services::oci_manifest_refs_backfill::MAX_INDEX_MANIFEST_BYTES;
use crate::services::source_registry::{OciContentKind, SourceRegistry};
use crate::storage::StorageBackend;

/// Bounds on a single referenced-content walk. Every limit fails the item
/// (fail-closed) rather than truncating silently, so a pathological source
/// image cannot exhaust memory, storage, or the DB connection.
#[derive(Debug, Clone, Copy)]
pub struct WalkCaps {
    /// Maximum index-of-index recursion depth. A normal multi-arch image is
    /// depth 1 (index → child image manifests); deeper nesting is unusual and
    /// capped to bound recursion.
    pub max_depth: usize,
    /// Maximum number of children a single image index may declare. Bounds the
    /// fan-out of one `manifests[]` array.
    pub max_index_fanout: usize,
    /// Maximum total blobs fetched across the whole image (all arches).
    pub max_blobs_total: usize,
    /// Maximum total child manifests fetched across the whole image.
    pub max_manifests_total: usize,
}

impl Default for WalkCaps {
    fn default() -> Self {
        Self {
            max_depth: 4,
            max_index_fanout: 1024,
            max_blobs_total: 4096,
            max_manifests_total: 1024,
        }
    }
}

/// Counters returned by a walk, for tracing and tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WalkStats {
    /// Blob rows registered into `oci_blobs` (excludes deduped skips).
    pub blobs_registered: usize,
    /// Child manifests fetched + registered (excludes deduped skips).
    pub children_registered: usize,
    /// Referenced digests skipped because they were already present.
    pub deduped: usize,
}

/// Walk and register the content an already-registered manifest references.
///
/// `root_class` / `root_body` are the manifest the worker has just fetched and
/// registered for `image`; the walk registers the blobs/children it pulls in.
/// All DB writes run on `tx` (the item transaction) so a failure rolls back
/// the tag together with any partial registration.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn walk_and_register_referenced_content(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    storage: &Arc<dyn StorageBackend>,
    client: &Arc<dyn SourceRegistry>,
    staging_dir: &Path,
    repo_id: Uuid,
    repo_key: &str,
    image: &str,
    root_class: &ManifestClass,
    root_body: &[u8],
    caps: &WalkCaps,
) -> Result<WalkStats, MigrationError> {
    let mut stats = WalkStats::default();
    let mut visited: HashSet<String> = HashSet::new();
    // Child manifests still to fetch + expand: (digest, depth).
    let mut manifest_queue: VecDeque<(String, usize)> = VecDeque::new();

    // Seed the walk from the already-fetched root manifest.
    match root_class {
        ManifestClass::Image => {
            for blob in extract_blob_refs(root_body) {
                ensure_blob(
                    tx,
                    storage,
                    client,
                    staging_dir,
                    repo_id,
                    repo_key,
                    image,
                    &blob.digest,
                    caps,
                    &mut visited,
                    &mut stats,
                )
                .await?;
            }
        }
        ManifestClass::Index => {
            enqueue_children(root_body, 1, caps, &visited, &mut manifest_queue)?;
        }
        // The caller only invokes the walk for a non-malformed manifest.
        ManifestClass::Malformed => {}
    }

    // Expand child manifests breadth-first. A child image manifest contributes
    // its own config/layer blobs; a child index (index-of-index) enqueues its
    // grandchildren one level deeper, up to the depth cap.
    while let Some((digest, depth)) = manifest_queue.pop_front() {
        if !visited.insert(digest.clone()) {
            stats.deduped += 1;
            continue;
        }
        if depth > caps.max_depth {
            return Err(MigrationError::Other(format!(
                "referenced-content walk for image '{image}' exceeded the max index depth ({})",
                caps.max_depth
            )));
        }
        stats.children_registered += 1;
        if stats.children_registered > caps.max_manifests_total {
            return Err(MigrationError::Other(format!(
                "referenced-content walk for image '{image}' exceeded the max child-manifest count ({})",
                caps.max_manifests_total
            )));
        }

        // Resolve the child manifest body. If its bytes are already present in
        // storage (a separate migration item registered it — Artifactory — or
        // it is a digest shared with an already-walked image, e.g. a
        // single-arch tag that is also a multi-arch child), read them back
        // instead of re-fetching from the source. Either way the child is then
        // registered under THIS image name below: registration is idempotent
        // and must NOT be skipped just because the digest exists under another
        // tag, or the child would 404 the moment that other tag is deleted
        // (exactly what a native `docker push` avoids — every child gets its
        // own by-digest tag under the image it belongs to). Only the FETCH is
        // deduped; the registration is always applied.
        let body =
            load_or_fetch_child_manifest(storage, client, staging_dir, repo_key, image, &digest)
                .await?;

        let class = classify_manifest(&body);
        if matches!(class, ManifestClass::Malformed) {
            return Err(MigrationError::Other(format!(
                "referenced child manifest '{digest}' of image '{image}' is neither an image nor an index"
            )));
        }
        let content_type =
            stored_media_type_for(&class, &resolve_manifest_content_type(None, &body));
        // Register the child so it resolves by digest, exactly as the live
        // push path records a manifest pushed by digest (reference == digest).
        persist_tag_and_refs_in_tx(
            tx,
            repo_id,
            image,
            &digest,
            &digest,
            &content_type,
            &class,
            &body,
        )
        .await?;

        match class {
            ManifestClass::Image => {
                for blob in extract_blob_refs(&body) {
                    ensure_blob(
                        tx,
                        storage,
                        client,
                        staging_dir,
                        repo_id,
                        repo_key,
                        image,
                        &blob.digest,
                        caps,
                        &mut visited,
                        &mut stats,
                    )
                    .await?;
                }
            }
            ManifestClass::Index => {
                enqueue_children(&body, depth + 1, caps, &visited, &mut manifest_queue)?;
            }
            ManifestClass::Malformed => unreachable!("rejected above"),
        }
    }

    Ok(stats)
}

/// Enqueue the children of an index body at `depth`, enforcing the fan-out cap.
fn enqueue_children(
    index_body: &[u8],
    depth: usize,
    caps: &WalkCaps,
    visited: &HashSet<String>,
    queue: &mut VecDeque<(String, usize)>,
) -> Result<(), MigrationError> {
    let children = extract_child_digests(index_body);
    if children.len() > caps.max_index_fanout {
        return Err(MigrationError::Other(format!(
            "image index declares {} children, exceeding the fan-out cap ({})",
            children.len(),
            caps.max_index_fanout
        )));
    }
    for child in children {
        if !visited.contains(&child) {
            queue.push_back((child, depth));
        }
    }
    Ok(())
}

/// Fetch, verify, store, and register one referenced blob unless it is already
/// present (deduped). No-op on a repeat digest within the same walk.
#[allow(clippy::too_many_arguments)]
async fn ensure_blob(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    storage: &Arc<dyn StorageBackend>,
    client: &Arc<dyn SourceRegistry>,
    staging_dir: &Path,
    repo_id: Uuid,
    repo_key: &str,
    image: &str,
    digest: &str,
    caps: &WalkCaps,
    visited: &mut HashSet<String>,
    stats: &mut WalkStats,
) -> Result<(), MigrationError> {
    if !visited.insert(digest.to_string()) {
        stats.deduped += 1;
        return Ok(());
    }
    // Already enumerated as its own migration item (Artifactory) or registered
    // by an earlier walk: skip the fetch entirely.
    if blob_already_registered(tx, repo_id, digest).await? {
        stats.deduped += 1;
        return Ok(());
    }
    if stats.blobs_registered >= caps.max_blobs_total {
        return Err(MigrationError::Other(format!(
            "referenced-content walk for image '{image}' exceeded the max blob count ({})",
            caps.max_blobs_total
        )));
    }

    let (storage_key, size) =
        fetch_verify_store_blob(storage, client, staging_dir, repo_key, image, digest).await?;

    // Mirror the monolithic-upload / migration blob insert: resurrect a
    // GC-marked blob on conflict.
    sqlx::query(
        "INSERT INTO oci_blobs (repository_id, digest, size_bytes, storage_key) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (repository_id, digest) DO UPDATE SET pending_delete_at = NULL",
    )
    .bind(repo_id)
    .bind(digest)
    .bind(size)
    .bind(&storage_key)
    .execute(&mut **tx)
    .await?;
    stats.blobs_registered += 1;
    Ok(())
}

async fn blob_already_registered(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    repo_id: Uuid,
    digest: &str,
) -> Result<bool, MigrationError> {
    let row: Option<(i32,)> =
        sqlx::query_as("SELECT 1 FROM oci_blobs WHERE repository_id = $1 AND digest = $2 LIMIT 1")
            .bind(repo_id)
            .bind(digest)
            .fetch_optional(&mut **tx)
            .await?;
    Ok(row.is_some())
}

/// Resolve a child manifest body, preferring bytes already in storage over a
/// source fetch. When present locally (a separate migration item stored it, or
/// the digest is shared with an already-walked image), the stored bytes are
/// read back and digest-verified; otherwise the manifest is fetched from the
/// source, verified, and stored. The caller registers it under the current
/// image name regardless, so a shared digest is never left dependent on
/// another tag's existence.
async fn load_or_fetch_child_manifest(
    storage: &Arc<dyn StorageBackend>,
    client: &Arc<dyn SourceRegistry>,
    staging_dir: &Path,
    repo_key: &str,
    image: &str,
    digest: &str,
) -> Result<bytes::Bytes, MigrationError> {
    let key = manifest_storage_key(digest);
    if storage.exists(&key).await.unwrap_or(false) {
        let body = storage
            .get(&key)
            .await
            .map_err(|e| MigrationError::StorageError(e.to_string()))?;
        if body.len() > MAX_INDEX_MANIFEST_BYTES {
            return Err(MigrationError::Other(format!(
                "stored child manifest '{digest}' of image '{image}' exceeds the {} byte manifest cap",
                MAX_INDEX_MANIFEST_BYTES
            )));
        }
        let computed = {
            let mut h = Sha256::new();
            h.update(&body);
            format!("sha256:{}", hex::encode(h.finalize()))
        };
        if computed == digest {
            return Ok(body);
        }
        // Stored bytes do not match the referenced digest (corruption / key
        // reuse): fall through and re-fetch the authoritative content.
    }
    fetch_verify_store_manifest(storage, client, staging_dir, repo_key, image, digest).await
}

/// Stream a referenced blob to a temp file, verify it hashes to `digest`, and
/// commit its bytes to storage under the digest-addressed key. Returns the
/// storage key and size. Never buffers the whole blob (O(chunk) memory).
async fn fetch_verify_store_blob(
    storage: &Arc<dyn StorageBackend>,
    client: &Arc<dyn SourceRegistry>,
    staging_dir: &Path,
    repo_key: &str,
    image: &str,
    digest: &str,
) -> Result<(String, i64), MigrationError> {
    // Blobs are not size-capped here (config/layer sizes are legitimate and
    // large); count caps + fail-closed transfer bound the walk.
    let (temp, computed, size) = stream_to_temp(
        client,
        staging_dir,
        repo_key,
        image,
        digest,
        OciContentKind::Blob,
        None,
    )
    .await?;
    if computed != digest {
        return Err(MigrationError::ChecksumMismatch {
            path: format!("{image}/blobs/{digest}"),
            expected: digest.to_string(),
            actual: computed,
        });
    }
    let storage_key = blob_storage_key(digest);
    put_temp_to_storage(storage, temp.path(), &storage_key).await?;
    Ok((storage_key, size))
}

/// Fetch a referenced child manifest, verify it hashes to `digest`, store its
/// bytes at the digest-addressed manifest key, and return the body (bounded by
/// [`MAX_INDEX_MANIFEST_BYTES`], so buffering it is safe).
async fn fetch_verify_store_manifest(
    storage: &Arc<dyn StorageBackend>,
    client: &Arc<dyn SourceRegistry>,
    staging_dir: &Path,
    repo_key: &str,
    image: &str,
    digest: &str,
) -> Result<bytes::Bytes, MigrationError> {
    // The manifest cap is enforced MID-STREAM inside `stream_to_temp` (a
    // hostile source must not spill a multi-GB body to disk behind a manifest
    // URL), so anything returned here is already within the cap.
    let (temp, computed, _size) = stream_to_temp(
        client,
        staging_dir,
        repo_key,
        image,
        digest,
        OciContentKind::Manifest,
        Some(MAX_INDEX_MANIFEST_BYTES),
    )
    .await?;
    if computed != digest {
        return Err(MigrationError::ChecksumMismatch {
            path: format!("{image}/manifests/{digest}"),
            expected: digest.to_string(),
            actual: computed,
        });
    }
    let body = tokio::fs::read(temp.path())
        .await
        .map_err(|e| MigrationError::StorageError(format!("read child manifest temp file: {e}")))?;
    let storage_key = manifest_storage_key(digest);
    if !storage.exists(&storage_key).await.unwrap_or(false) {
        storage
            .put(&storage_key, bytes::Bytes::from(body.clone()))
            .await
            .map_err(|e| MigrationError::StorageError(e.to_string()))?;
    }
    Ok(bytes::Bytes::from(body))
}

/// Stream digest-addressed content from the source into a `NamedTempFile`
/// rooted in the migration staging dir, computing its sha256 as it lands.
/// Returns the temp file (kept alive by the caller), the computed
/// `sha256:<hex>` digest, and the byte count.
async fn stream_to_temp(
    client: &Arc<dyn SourceRegistry>,
    staging_dir: &Path,
    repo_key: &str,
    image: &str,
    digest: &str,
    kind: OciContentKind,
    max_bytes: Option<usize>,
) -> Result<(tempfile::NamedTempFile, String, i64), MigrationError> {
    use futures::StreamExt;
    use tokio::io::AsyncWriteExt;

    let mut stream = client
        .download_oci_content_stream(repo_key, image, digest, kind)
        .await?;

    let temp = tempfile::NamedTempFile::new_in(staging_dir).map_err(|e| {
        MigrationError::StorageError(format!(
            "create temp file in {}: {e}",
            staging_dir.display()
        ))
    })?;
    let temp_path = temp.path().to_path_buf();
    let mut writer = tokio::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&temp_path)
        .await
        .map_err(|e| MigrationError::StorageError(format!("open temp file for write: {e}")))?;

    let mut hasher = Sha256::new();
    let mut size: i64 = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(MigrationError::from)?;
        // Enforce the size cap MID-STREAM (manifest fetches): reject before the
        // overflowing chunk is written, so a hostile source cannot spill a
        // multi-GB body to the staging temp file behind a manifest URL before
        // rejection. Blob fetches pass `None` and stay uncapped here.
        let next_size = size + chunk.len() as i64;
        if let Some(cap) = max_bytes {
            if next_size as usize > cap {
                return Err(MigrationError::Other(format!(
                    "OCI manifest '{image}/{}/{digest}' exceeds the {cap} byte cap mid-stream; aborting fetch",
                    kind.path_segment()
                )));
            }
        }
        hasher.update(&chunk);
        size = next_size;
        writer
            .write_all(&chunk)
            .await
            .map_err(|e| MigrationError::StorageError(format!("write chunk to temp: {e}")))?;
        drop(chunk);
    }
    drop(stream);
    writer
        .flush()
        .await
        .map_err(|e| MigrationError::StorageError(format!("flush temp file: {e}")))?;
    writer
        .sync_all()
        .await
        .map_err(|e| MigrationError::StorageError(format!("sync temp file: {e}")))?;
    drop(writer);

    let computed = format!("sha256:{}", hex::encode(hasher.finalize()));
    Ok((temp, computed, size))
}

/// Commit a temp file's bytes to storage under `storage_key` via `put_stream`
/// (never buffering the whole file), skipping the write when the content is
/// already present (dedup on the CAS-like digest key).
async fn put_temp_to_storage(
    storage: &Arc<dyn StorageBackend>,
    temp_path: &Path,
    storage_key: &str,
) -> Result<(), MigrationError> {
    if storage.exists(storage_key).await.unwrap_or(false) {
        return Ok(());
    }
    use tokio::io::BufReader;
    use tokio_util::io::ReaderStream;

    let file = tokio::fs::File::open(temp_path)
        .await
        .map_err(|e| MigrationError::StorageError(format!("reopen temp file for upload: {e}")))?;
    let reader = BufReader::with_capacity(256 * 1024, file);
    let stream = ReaderStream::with_capacity(reader, 256 * 1024);
    let mapped = futures::StreamExt::map(stream, |r| {
        r.map_err(|e| {
            crate::error::AppError::Storage(format!("temp read error during upload: {e}"))
        })
    });
    storage
        .put_stream(storage_key, Box::pin(mapped))
        .await
        .map_err(|e| MigrationError::StorageError(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::artifactory_client::{
        AqlResponse, ArtifactoryError, PropertiesResponse, RepositoryListItem,
        SystemVersionResponse,
    };
    use crate::services::source_registry::ArtifactByteStream;
    use std::collections::HashMap;
    use std::sync::Mutex;

    fn sha256_digest(data: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(data);
        format!("sha256:{}", hex::encode(h.finalize()))
    }

    /// Source that serves digest-addressed content and records every fetch so
    /// tests can assert the walker deduped shared layers. Serves ONLY by
    /// digest (`download_oci_content_stream`) — the enumeration path is not
    /// used by the walker, mirroring a real registry that lists just tags.
    struct DigestSource {
        blobs: HashMap<String, bytes::Bytes>,
        manifests: HashMap<String, bytes::Bytes>,
        fetches: Arc<Mutex<Vec<String>>>,
    }

    impl DigestSource {
        fn new() -> Self {
            Self {
                blobs: HashMap::new(),
                manifests: HashMap::new(),
                fetches: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    #[async_trait::async_trait]
    impl SourceRegistry for DigestSource {
        async fn ping(&self) -> Result<bool, ArtifactoryError> {
            Ok(true)
        }
        async fn get_version(&self) -> Result<SystemVersionResponse, ArtifactoryError> {
            unimplemented!()
        }
        async fn list_repositories(&self) -> Result<Vec<RepositoryListItem>, ArtifactoryError> {
            Ok(vec![])
        }
        async fn list_artifacts(
            &self,
            _repo_key: &str,
            _offset: i64,
            _limit: i64,
        ) -> Result<AqlResponse, ArtifactoryError> {
            unimplemented!()
        }
        async fn download_artifact(
            &self,
            _repo_key: &str,
            _path: &str,
        ) -> Result<bytes::Bytes, ArtifactoryError> {
            unimplemented!()
        }
        async fn download_oci_content_stream(
            &self,
            _repo_key: &str,
            _image: &str,
            digest: &str,
            kind: OciContentKind,
        ) -> Result<ArtifactByteStream, ArtifactoryError> {
            self.fetches.lock().unwrap().push(digest.to_string());
            let map = match kind {
                OciContentKind::Blob => &self.blobs,
                OciContentKind::Manifest => &self.manifests,
            };
            let bytes = map
                .get(digest)
                .cloned()
                .ok_or_else(|| ArtifactoryError::NotFound(format!("digest not found: {digest}")))?;
            Ok(Box::pin(futures::stream::once(async move { Ok(bytes) })))
        }
        async fn get_properties(
            &self,
            _repo_key: &str,
            _path: &str,
        ) -> Result<PropertiesResponse, ArtifactoryError> {
            Ok(PropertiesResponse {
                properties: None,
                uri: None,
            })
        }
        fn source_type(&self) -> &'static str {
            "digest-mock"
        }
    }

    async fn setup(pool: &sqlx::PgPool) -> (Arc<dyn StorageBackend>, tempfile::TempDir, Uuid) {
        let tmp = tempfile::tempdir().unwrap();
        let repo_id = Uuid::new_v4();
        let key = format!("refwalk-{}", &repo_id.to_string()[..8]);
        sqlx::query(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, is_public) \
             VALUES ($1, $2, $2, $3, 'local', 'docker'::repository_format, true)",
        )
        .bind(repo_id)
        .bind(&key)
        .bind(tmp.path().to_str().unwrap())
        .execute(pool)
        .await
        .unwrap();
        let storage: Arc<dyn StorageBackend> = Arc::new(
            crate::storage::filesystem::FilesystemStorage::new(tmp.path().to_str().unwrap()),
        );
        (storage, tmp, repo_id)
    }

    fn image_manifest(config: &[u8], layers: &[&[u8]]) -> bytes::Bytes {
        let layer_json: Vec<String> = layers
            .iter()
            .map(|l| {
                format!(
                    "{{\"size\":{},\"digest\":\"{}\"}}",
                    l.len(),
                    sha256_digest(l)
                )
            })
            .collect();
        bytes::Bytes::from(format!(
            "{{\"schemaVersion\":2,\
              \"mediaType\":\"application/vnd.docker.distribution.manifest.v2+json\",\
              \"config\":{{\"size\":{},\"digest\":\"{}\"}},\
              \"layers\":[{}]}}",
            config.len(),
            sha256_digest(config),
            layer_json.join(",")
        ))
    }

    fn index_manifest(children: &[&bytes::Bytes]) -> bytes::Bytes {
        let entries: Vec<String> = children
            .iter()
            .map(|c| {
                format!(
                    "{{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\
                      \"size\":{},\"digest\":\"{}\",\
                      \"platform\":{{\"architecture\":\"amd64\",\"os\":\"linux\"}}}}",
                    c.len(),
                    sha256_digest(c)
                )
            })
            .collect();
        bytes::Bytes::from(format!(
            "{{\"schemaVersion\":2,\
              \"mediaType\":\"application/vnd.oci.image.index.v1+json\",\
              \"manifests\":[{}]}}",
            entries.join(",")
        ))
    }

    /// Image manifest: the walker fetches the config + every layer and
    /// registers each into `oci_blobs`.
    #[tokio::test]
    async fn walker_fetches_config_and_all_layers_for_image() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (storage, tmp, repo_id) = setup(&pool).await;

        let config = bytes::Bytes::from_static(b"{\"os\":\"linux\"}");
        let layer_a = bytes::Bytes::from_static(b"layer-a-bytes");
        let layer_b = bytes::Bytes::from_static(b"layer-b-bytes");
        let manifest = image_manifest(&config, &[&layer_a, &layer_b]);

        let mut src = DigestSource::new();
        for b in [&config, &layer_a, &layer_b] {
            src.blobs.insert(sha256_digest(b), b.clone());
        }
        let client: Arc<dyn SourceRegistry> = Arc::new(src);

        let mut tx = pool.begin().await.unwrap();
        let stats = walk_and_register_referenced_content(
            &mut tx,
            &storage,
            &client,
            tmp.path(),
            repo_id,
            "app",
            "app",
            &ManifestClass::Image,
            &manifest,
            &WalkCaps::default(),
        )
        .await
        .expect("image walk");
        tx.commit().await.unwrap();

        assert_eq!(stats.blobs_registered, 3, "config + 2 layers");
        for b in [&config, &layer_a, &layer_b] {
            let d = sha256_digest(b);
            let row: Option<(String,)> = sqlx::query_as(
                "SELECT storage_key FROM oci_blobs WHERE repository_id = $1 AND digest = $2",
            )
            .bind(repo_id)
            .bind(&d)
            .fetch_optional(&pool)
            .await
            .unwrap();
            let (key,) = row.expect("blob registered");
            assert!(storage.exists(&key).await.unwrap());
        }
        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// Image index: the walker recurses each child manifest, registers it by
    /// digest, then fetches the child's own config/layers.
    #[tokio::test]
    async fn walker_recurses_children_then_their_blobs_for_index() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (storage, tmp, repo_id) = setup(&pool).await;

        let cfg_a = bytes::Bytes::from_static(b"{\"arch\":\"amd64\"}");
        let cfg_b = bytes::Bytes::from_static(b"{\"arch\":\"arm64\"}");
        let layer = bytes::Bytes::from_static(b"shared-layer");
        let child_a = image_manifest(&cfg_a, &[&layer]);
        let child_b = image_manifest(&cfg_b, &[&layer]);
        let index = index_manifest(&[&child_a, &child_b]);

        let mut src = DigestSource::new();
        for b in [&cfg_a, &cfg_b, &layer] {
            src.blobs.insert(sha256_digest(b), b.clone());
        }
        for m in [&child_a, &child_b] {
            src.manifests.insert(sha256_digest(m), m.clone());
        }
        let fetches = src.fetches.clone();
        let client: Arc<dyn SourceRegistry> = Arc::new(src);

        let mut tx = pool.begin().await.unwrap();
        let stats = walk_and_register_referenced_content(
            &mut tx,
            &storage,
            &client,
            tmp.path(),
            repo_id,
            "app",
            "app",
            &ManifestClass::Index,
            &index,
            &WalkCaps::default(),
        )
        .await
        .expect("index walk");
        tx.commit().await.unwrap();

        assert_eq!(stats.children_registered, 2, "two arch children");
        assert_eq!(
            stats.blobs_registered, 3,
            "two configs + one shared layer (deduped)"
        );

        // Shared layer fetched exactly once (visited-set dedup).
        let layer_digest = sha256_digest(&layer);
        let layer_fetches = fetches
            .lock()
            .unwrap()
            .iter()
            .filter(|d| **d == layer_digest)
            .count();
        assert_eq!(layer_fetches, 1, "shared layer must be fetched once");

        // Children resolve by digest.
        for m in [&child_a, &child_b] {
            let d = sha256_digest(m);
            let row: Option<(String,)> = sqlx::query_as(
                "SELECT manifest_digest FROM oci_tags WHERE repository_id = $1 AND manifest_digest = $2 LIMIT 1",
            )
            .bind(repo_id)
            .bind(&d)
            .fetch_optional(&pool)
            .await
            .unwrap();
            assert!(row.is_some(), "child {d} registered");
            assert!(storage.exists(&manifest_storage_key(&d)).await.unwrap());
        }
        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// Shared-digest regression: a child manifest whose digest is already
    /// registered under a DIFFERENT image (e.g. a single-arch tag that is also
    /// a multi-arch child) must still be registered under the current image
    /// name — never skipped — so it survives the other tag's deletion. Its
    /// bytes are read back from storage rather than re-fetched.
    #[tokio::test]
    async fn walker_registers_shared_child_under_current_image() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (storage, tmp, repo_id) = setup(&pool).await;

        let cfg = bytes::Bytes::from_static(b"{\"os\":\"linux\"}");
        let child = image_manifest(&cfg, &[]);
        let child_digest = sha256_digest(&child);
        let index = index_manifest(&[&child]);

        // Pre-register the child under a DIFFERENT image ("single") + store its
        // bytes, mimicking a single-arch tag that shares the multi-arch child
        // digest. The source has the config only (walker reads the child from
        // storage, so it must NOT need to fetch the child manifest).
        storage
            .put(&manifest_storage_key(&child_digest), child.clone())
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO oci_tags (repository_id, name, tag, manifest_digest, manifest_content_type) \
             VALUES ($1, 'single', 'latest', $2, 'application/vnd.oci.image.manifest.v1+json')",
        )
        .bind(repo_id)
        .bind(&child_digest)
        .execute(&pool)
        .await
        .unwrap();

        let mut src = DigestSource::new();
        src.blobs.insert(sha256_digest(&cfg), cfg.clone());
        // deliberately DO NOT put the child manifest in the source: it must be
        // read from storage.
        let fetches = src.fetches.clone();
        let client: Arc<dyn SourceRegistry> = Arc::new(src);

        let mut tx = pool.begin().await.unwrap();
        walk_and_register_referenced_content(
            &mut tx,
            &storage,
            &client,
            tmp.path(),
            repo_id,
            "app",
            "multi",
            &ManifestClass::Index,
            &index,
            &WalkCaps::default(),
        )
        .await
        .expect("index walk");
        tx.commit().await.unwrap();

        // The child must now be registered under the CURRENT image name
        // ("multi"), independent of the pre-existing "single" tag.
        let under_multi: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM oci_tags WHERE repository_id=$1 AND name='multi' AND manifest_digest=$2",
        )
        .bind(repo_id)
        .bind(&child_digest)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            under_multi.0, 1,
            "shared child must be registered under the current image name"
        );

        // Deleting the OTHER tag must not orphan the child — it still resolves.
        sqlx::query("DELETE FROM oci_tags WHERE repository_id=$1 AND name='single'")
            .bind(repo_id)
            .execute(&pool)
            .await
            .unwrap();
        let resolves: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM oci_tags WHERE repository_id=$1 AND manifest_digest=$2",
        )
        .bind(repo_id)
        .bind(&child_digest)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            resolves.0, 1,
            "child still resolves after the other tag is deleted"
        );

        // The child manifest was read from storage, never fetched from source.
        assert!(
            !fetches.lock().unwrap().contains(&child_digest),
            "present child manifest must be read from storage, not re-fetched"
        );

        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// An unfetchable layer (source 404) fails the walk (fail-closed).
    #[tokio::test]
    async fn walker_errors_when_a_referenced_blob_is_unfetchable() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (storage, tmp, repo_id) = setup(&pool).await;

        let config = bytes::Bytes::from_static(b"{\"os\":\"linux\"}");
        let layer = bytes::Bytes::from_static(b"missing-layer");
        let manifest = image_manifest(&config, &[&layer]);

        let mut src = DigestSource::new();
        // config present, layer intentionally absent -> 404 on fetch.
        src.blobs.insert(sha256_digest(&config), config.clone());
        let client: Arc<dyn SourceRegistry> = Arc::new(src);

        let mut tx = pool.begin().await.unwrap();
        let res = walk_and_register_referenced_content(
            &mut tx,
            &storage,
            &client,
            tmp.path(),
            repo_id,
            "app",
            "app",
            &ManifestClass::Image,
            &manifest,
            &WalkCaps::default(),
        )
        .await;
        assert!(res.is_err(), "an unfetchable layer must fail the walk");
        drop(tx);

        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// A pathological index whose fan-out exceeds the cap fails the walk (DoS
    /// guard), before any fetch.
    #[tokio::test]
    async fn walker_rejects_index_exceeding_fanout_cap() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (storage, tmp, repo_id) = setup(&pool).await;

        // Build an index declaring more children than a tiny cap allows.
        let children: Vec<bytes::Bytes> = (0..5)
            .map(|i| image_manifest(format!("cfg{i}").as_bytes(), &[]))
            .collect();
        let refs: Vec<&bytes::Bytes> = children.iter().collect();
        let index = index_manifest(&refs);

        let client: Arc<dyn SourceRegistry> = Arc::new(DigestSource::new());
        let caps = WalkCaps {
            max_index_fanout: 2,
            ..WalkCaps::default()
        };
        let mut tx = pool.begin().await.unwrap();
        let res = walk_and_register_referenced_content(
            &mut tx,
            &storage,
            &client,
            tmp.path(),
            repo_id,
            "app",
            "app",
            &ManifestClass::Index,
            &index,
            &caps,
        )
        .await;
        assert!(res.is_err(), "fan-out beyond the cap must fail the walk");
        drop(tx);

        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// The manifest fetch aborts mid-stream once the body exceeds the cap,
    /// before the whole body is spilled to the staging temp file (DoS DiD).
    #[tokio::test]
    async fn stream_to_temp_aborts_manifest_over_cap() {
        let tmp = tempfile::tempdir().unwrap();
        let big = bytes::Bytes::from(vec![b'x'; 4096]);
        let digest = sha256_digest(&big);
        let mut src = DigestSource::new();
        // Same body served on both the manifest and blob routes so the capped
        // (manifest) and uncapped (blob) fetches exercise the identical bytes.
        src.manifests.insert(digest.clone(), big.clone());
        src.blobs.insert(digest.clone(), big.clone());
        let client: Arc<dyn SourceRegistry> = Arc::new(src);

        // Cap far below the body size: the fetch must error, not buffer it.
        let capped = stream_to_temp(
            &client,
            tmp.path(),
            "repo",
            "app",
            &digest,
            OciContentKind::Manifest,
            Some(64),
        )
        .await;
        assert!(
            capped.is_err(),
            "manifest fetch must abort once it exceeds the cap"
        );

        // Same body with no cap (blob path) streams fine.
        let uncapped = stream_to_temp(
            &client,
            tmp.path(),
            "repo",
            "app",
            &digest,
            OciContentKind::Blob,
            None,
        )
        .await;
        assert!(uncapped.is_ok(), "uncapped (blob) fetch must succeed");
        let (_t, computed, size) = uncapped.unwrap();
        assert_eq!(computed, digest);
        assert_eq!(size, 4096);
    }

    #[test]
    fn walk_caps_default_is_bounded() {
        let c = WalkCaps::default();
        assert!(c.max_depth >= 1);
        assert!(c.max_index_fanout >= 1);
        assert!(c.max_blobs_total >= c.max_index_fanout);
        assert!(c.max_manifests_total >= 1);
    }
}
