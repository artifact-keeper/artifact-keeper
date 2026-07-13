//! One-shot repair for Docker/OCI artifacts imported by earlier migration
//! runs (#2457).
//!
//! Before #2457 the migration worker stored Docker/OCI manifest and blob
//! bytes under generic CAS keys and inserted only `artifacts` rows — it
//! never registered anything in the OCI index (`oci_tags`, `oci_blobs`,
//! `oci_manifest_refs`, `manifest_blob_refs`). The V2 pull path resolves
//! exclusively through that index, so every migrated tag returned
//! `MANIFEST_UNKNOWN` even though the migration job reported success and
//! the UI/download API showed the artifacts.
//!
//! This module walks docker/oci `artifacts` rows whose paths look like
//! manifests but that have no matching `oci_tags` row, re-derives the
//! image/reference from the preserved source path, copies the manifest
//! bytes to the digest-addressed `oci-manifests/<digest>` key, registers
//! referenced blobs into `oci_blobs` (reusing each blob's existing CAS
//! `storage_key` — the blob-serve path honors arbitrary keys), and calls
//! the same `persist_tag_and_refs` the live push path uses.
//!
//! Additive-only: nothing is deleted or rewritten. Idempotent: after the
//! first successful pass the candidate query returns zero rows (each
//! repaired manifest now has its `oci_tags` row). Best-effort: a single
//! unreadable/malformed candidate is logged at WARN and skipped, never
//! failing startup. Spawned in the background from `main.rs` (next to the
//! `manifest_blob_refs` backfill) so it cannot delay the HTTP listener.

use std::sync::Arc;

use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::services::migration_worker::{classify_oci_source_artifact, OciRole};
use crate::services::oci_manifest_refs_backfill::MAX_INDEX_MANIFEST_BYTES;
use crate::storage::{StorageLocation, StorageRegistry};

/// Result of a repair pass. Returned for tracing and tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct RepairStats {
    /// Candidate `artifacts` rows examined (docker/oci, manifest-shaped
    /// path, no matching `oci_tags` row).
    pub candidates_scanned: usize,
    /// Manifests registered into the OCI index (tag row + refs written).
    pub manifests_registered: usize,
    /// Blob rows inserted (or resurrected) into `oci_blobs`.
    pub blobs_registered: usize,
    /// Candidates whose path did not classify as a manifest after prefix
    /// stripping. Left untouched; not an error.
    pub candidates_skipped: usize,
    /// Candidates that could not be processed (bytes missing from storage,
    /// digest mismatch, malformed JSON, DB write failure). Logged at WARN;
    /// retried on the next restart.
    pub candidates_failed: usize,
}

/// Run the one-shot repair. Never errors at the function boundary — all
/// per-candidate failures are logged and counted so server startup is
/// never blocked by a single corrupt row.
pub async fn run_repair(db: &PgPool, registry: Arc<StorageRegistry>) -> RepairStats {
    let candidates = match select_unregistered_manifests(db).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "OCI migration reindex: failed to scan candidates; skipping"
            );
            return RepairStats::default();
        }
    };

    let mut stats = RepairStats {
        candidates_scanned: candidates.len(),
        ..RepairStats::default()
    };

    if candidates.is_empty() {
        return stats;
    }

    tracing::info!(
        candidate_count = candidates.len(),
        "OCI migration reindex: registering migrated Docker/OCI manifests"
    );

    for candidate in candidates {
        match process_candidate(db, &registry, &candidate).await {
            Ok(Some(blobs)) => {
                stats.manifests_registered += 1;
                stats.blobs_registered += blobs;
            }
            Ok(None) => stats.candidates_skipped += 1,
            Err(e) => {
                tracing::warn!(
                    repository_id = %candidate.repository_id,
                    path = %candidate.path,
                    error = %e,
                    "OCI migration reindex: skipped candidate"
                );
                stats.candidates_failed += 1;
            }
        }
    }

    tracing::info!(
        candidates_scanned = stats.candidates_scanned,
        manifests_registered = stats.manifests_registered,
        blobs_registered = stats.blobs_registered,
        candidates_skipped = stats.candidates_skipped,
        candidates_failed = stats.candidates_failed,
        "OCI migration reindex: complete"
    );
    stats
}

#[derive(Debug)]
struct RepairCandidate {
    repository_id: Uuid,
    repo_key: String,
    path: String,
    size_bytes: i64,
    storage_key: String,
    storage_backend: String,
    storage_path: String,
}

/// Select docker/oci `artifacts` rows whose paths look like source-layout
/// manifests and that have no `oci_tags` row for their content digest in
/// the same repository. The migration stored the source-relative path
/// under a `<repo_key>/` prefix (docker falls into the version-less path
/// fallback), and `artifacts.checksum_sha256` is the digest of the stored
/// bytes, so `'sha256:' || checksum_sha256` matches `manifest_digest`
/// exactly once registration has happened — making re-runs a no-op.
async fn select_unregistered_manifests(db: &PgPool) -> sqlx::Result<Vec<RepairCandidate>> {
    let rows = sqlx::query(
        r#"
        SELECT a.repository_id AS repository_id,
               r.key AS repo_key,
               a.path AS path,
               a.size_bytes AS size_bytes,
               a.storage_key AS storage_key,
               r.storage_backend AS storage_backend,
               r.storage_path AS storage_path
        FROM artifacts a
        JOIN repositories r ON r.id = a.repository_id
        WHERE lower(r.format::text) IN ('docker', 'oci')
          AND a.is_deleted = false
          AND (a.path LIKE '%/manifest.json'
               OR a.path LIKE '%/list.manifest.json'
               OR a.path LIKE '%/manifests/%')
          AND NOT EXISTS (
                SELECT 1 FROM oci_tags ot
                WHERE ot.repository_id = a.repository_id
                  AND ot.manifest_digest = 'sha256:' || a.checksum_sha256
          )
        "#,
    )
    .fetch_all(db)
    .await?;

    let candidates = rows
        .into_iter()
        .map(|r| RepairCandidate {
            repository_id: r.try_get("repository_id").unwrap_or_default(),
            repo_key: r.try_get("repo_key").unwrap_or_default(),
            path: r.try_get("path").unwrap_or_default(),
            size_bytes: r.try_get("size_bytes").unwrap_or_default(),
            storage_key: r.try_get("storage_key").unwrap_or_default(),
            storage_backend: r.try_get("storage_backend").unwrap_or_default(),
            storage_path: r.try_get("storage_path").unwrap_or_default(),
        })
        .collect();
    Ok(candidates)
}

/// Strip the `<repo_key>/` prefix the migration writes onto docker
/// `artifacts.path` values, recovering the original source-relative path
/// that [`classify_oci_source_artifact`] understands. Paths without the
/// prefix (unexpected, but possible for hand-inserted rows) are returned
/// unchanged.
pub(crate) fn strip_repo_prefix<'a>(path: &'a str, repo_key: &str) -> &'a str {
    path.strip_prefix(repo_key)
        .and_then(|rest| rest.strip_prefix('/'))
        .unwrap_or(path)
}

/// Repair a single candidate. Returns `Ok(Some(blob_rows))` when the
/// manifest was registered, `Ok(None)` when the path did not classify as
/// a manifest (skipped), and `Err` for real failures.
async fn process_candidate(
    db: &PgPool,
    registry: &StorageRegistry,
    candidate: &RepairCandidate,
) -> Result<Option<usize>, String> {
    let source_path = strip_repo_prefix(&candidate.path, &candidate.repo_key);
    let (image, reference) = match classify_oci_source_artifact(source_path) {
        OciRole::Manifest { image, reference } => (image, reference),
        _ => return Ok(None),
    };

    if candidate.size_bytes > MAX_INDEX_MANIFEST_BYTES as i64 {
        return Err(format!(
            "manifest body exceeds {} bytes (got {}); refusing to buffer",
            MAX_INDEX_MANIFEST_BYTES, candidate.size_bytes
        ));
    }

    let location = StorageLocation {
        backend: candidate.storage_backend.clone(),
        path: candidate.storage_path.clone(),
    };
    let storage = registry
        .backend_for(&location)
        .map_err(|e| format!("resolve storage backend: {}", e))?;

    let body = storage
        .get(&candidate.storage_key)
        .await
        .map_err(|e| format!("read manifest bytes from storage: {}", e))?;
    if body.len() > MAX_INDEX_MANIFEST_BYTES {
        return Err(format!(
            "manifest body exceeds {} bytes (got {}); refusing to parse",
            MAX_INDEX_MANIFEST_BYTES,
            body.len()
        ));
    }

    let digest = crate::api::handlers::oci_v2::compute_sha256(&body);
    // A digest-shaped reference asserts content-addressed identity; refuse
    // to register bytes that do not hash to it.
    if reference.starts_with("sha256:") && reference != digest {
        return Err(format!(
            "content digest {} does not match path-derived reference {}",
            digest, reference
        ));
    }

    let class = crate::api::handlers::oci_v2::classify_manifest(&body);
    if matches!(
        class,
        crate::api::handlers::oci_v2::ManifestClass::Malformed
    ) {
        return Err("body is neither an image manifest nor an image index".to_string());
    }

    // Copy the bytes to the digest-addressed key the V2 pull path reads.
    // The CAS copy is left in place (the `artifacts` row still points at
    // it); manifests are tiny so the duplication is negligible.
    let manifest_key = crate::api::handlers::oci_v2::manifest_storage_key(&digest);
    let already_stored = storage.exists(&manifest_key).await.unwrap_or(false);
    if !already_stored {
        storage
            .put(&manifest_key, body.clone())
            .await
            .map_err(|e| format!("write manifest to {}: {}", manifest_key, e))?;
    }

    // Register the blobs an image manifest references, reusing each blob's
    // existing CAS storage_key (blob-serve honors arbitrary keys). A blob
    // whose artifacts row is missing is logged but does not fail the
    // manifest registration — the tag resolving is strictly better than
    // MANIFEST_UNKNOWN, and the gap is visible in the logs.
    let mut blobs_registered = 0usize;
    for blob_ref in crate::api::handlers::oci_v2::extract_blob_refs(&body) {
        let Some(hex) = blob_ref.digest.strip_prefix("sha256:") else {
            continue;
        };
        let blob_row: Option<(String, i64)> = sqlx::query_as(
            "SELECT storage_key, size_bytes FROM artifacts \
             WHERE repository_id = $1 AND checksum_sha256 = $2 AND is_deleted = false \
             LIMIT 1",
        )
        .bind(candidate.repository_id)
        .bind(hex)
        .fetch_optional(db)
        .await
        .map_err(|e| format!("look up blob artifact row: {}", e))?;

        match blob_row {
            Some((blob_storage_key, blob_size)) => {
                sqlx::query(
                    "INSERT INTO oci_blobs (repository_id, digest, size_bytes, storage_key) \
                     VALUES ($1, $2, $3, $4) \
                     ON CONFLICT (repository_id, digest) DO UPDATE SET pending_delete_at = NULL",
                )
                .bind(candidate.repository_id)
                .bind(&blob_ref.digest)
                .bind(blob_size)
                .bind(&blob_storage_key)
                .execute(db)
                .await
                .map_err(|e| format!("insert oci_blobs row: {}", e))?;
                blobs_registered += 1;
            }
            None => {
                tracing::warn!(
                    repository_id = %candidate.repository_id,
                    manifest_path = %candidate.path,
                    blob_digest = %blob_ref.digest,
                    "OCI migration reindex: referenced blob has no artifacts row; \
                     layer will 404 until re-migrated"
                );
            }
        }
    }

    // Media type from the BODY's own `mediaType` (no client header exists
    // here); a Docker schema2 body stored under the OCI media type makes
    // `docker pull` reject the manifest as a mediaType mismatch.
    let content_type = crate::api::handlers::oci_v2::stored_media_type_for(
        &class,
        &crate::api::handlers::oci_v2::resolve_manifest_content_type(None, &body),
    );
    crate::api::handlers::oci_v2::persist_tag_and_refs(
        db,
        candidate.repository_id,
        &image,
        &reference,
        &digest,
        &content_type,
        &class,
        &body,
    )
    .await
    .map_err(|e| format!("persist tag and refs: {}", e))?;

    Ok(Some(blobs_registered))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repair_stats_default_is_zero() {
        let s = RepairStats::default();
        assert_eq!(s.candidates_scanned, 0);
        assert_eq!(s.manifests_registered, 0);
        assert_eq!(s.blobs_registered, 0);
        assert_eq!(s.candidates_skipped, 0);
        assert_eq!(s.candidates_failed, 0);
    }

    #[test]
    fn strip_repo_prefix_removes_key_and_slash() {
        assert_eq!(
            strip_repo_prefix("docker-local/hello/latest/manifest.json", "docker-local"),
            "hello/latest/manifest.json"
        );
    }

    #[test]
    fn strip_repo_prefix_leaves_unprefixed_paths_alone() {
        assert_eq!(
            strip_repo_prefix("hello/latest/manifest.json", "docker-local"),
            "hello/latest/manifest.json"
        );
    }

    #[test]
    fn strip_repo_prefix_requires_full_segment_match() {
        // "docker-localextra/..." must NOT be treated as prefixed by
        // "docker-local" (no separating slash).
        assert_eq!(
            strip_repo_prefix("docker-localextra/hello/manifest.json", "docker-local"),
            "docker-localextra/hello/manifest.json"
        );
    }

    fn sha256_hex_of(data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    async fn insert_prefix_artifact(
        pool: &PgPool,
        repo_id: Uuid,
        path: &str,
        checksum: &str,
        storage_key: &str,
        size: i64,
    ) {
        sqlx::query(
            "INSERT INTO artifacts (repository_id, path, name, size_bytes, checksum_sha256, storage_key, content_type) \
             VALUES ($1, $2, $3, $4, $5, $6, 'application/octet-stream')",
        )
        .bind(repo_id)
        .bind(path)
        .bind(path.rsplit('/').next().unwrap_or(path))
        .bind(size)
        .bind(checksum)
        .bind(storage_key)
        .execute(pool)
        .await
        .expect("insert pre-fix artifact row");
    }

    /// End-to-end repair: a pre-#2457 migrated image (bytes at CAS keys,
    /// `artifacts` rows only, zero OCI index rows) becomes resolvable after
    /// `run_repair` — and a second run is a no-op.
    #[tokio::test]
    async fn test_run_repair_registers_pre_fix_migrated_image() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::artifact_service::ArtifactService;
        use crate::storage::StorageBackend;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let tmp = tempfile::tempdir().expect("tempdir");
        let repo_id = Uuid::new_v4();
        let repo_key = format!("reidx2457-{}", &repo_id.to_string()[..8]);
        sqlx::query(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, is_public) \
             VALUES ($1, $2, $2, $3, 'local', 'docker'::repository_format, true)",
        )
        .bind(repo_id)
        .bind(&repo_key)
        .bind(tmp.path().to_str().unwrap())
        .execute(&pool)
        .await
        .expect("insert docker repo");

        let storage =
            crate::storage::filesystem::FilesystemStorage::new(tmp.path().to_str().unwrap());

        // Pre-fix state: config blob + layer blob + manifest, all under CAS
        // keys with only artifacts rows.
        let config_bytes = bytes::Bytes::from_static(b"{\"os\":\"linux\"}");
        let layer_bytes = bytes::Bytes::from_static(b"layer-bytes-reindex");
        let config_hex = sha256_hex_of(&config_bytes);
        let layer_hex = sha256_hex_of(&layer_bytes);
        let manifest = format!(
            "{{\"schemaVersion\":2,\
              \"config\":{{\"size\":{},\"digest\":\"sha256:{}\"}},\
              \"layers\":[{{\"size\":{},\"digest\":\"sha256:{}\"}}]}}",
            config_bytes.len(),
            config_hex,
            layer_bytes.len(),
            layer_hex
        );
        let manifest_bytes = bytes::Bytes::from(manifest);
        let manifest_hex = sha256_hex_of(&manifest_bytes);

        for (bytes, hex, rel_path) in [
            (
                &config_bytes,
                &config_hex,
                format!("hello/latest/sha256__{config_hex}"),
            ),
            (
                &layer_bytes,
                &layer_hex,
                format!("hello/latest/sha256__{layer_hex}"),
            ),
            (
                &manifest_bytes,
                &manifest_hex,
                "hello/latest/manifest.json".to_string(),
            ),
        ] {
            let cas_key = ArtifactService::storage_key_from_checksum(hex);
            storage
                .put(&cas_key, bytes.clone())
                .await
                .expect("seed CAS bytes");
            insert_prefix_artifact(
                &pool,
                repo_id,
                &format!("{repo_key}/{rel_path}"),
                hex,
                &cas_key,
                bytes.len() as i64,
            )
            .await;
        }

        let registry = Arc::new(StorageRegistry::new(
            std::collections::HashMap::new(),
            "filesystem".to_string(),
        ));

        let stats = run_repair(&pool, registry.clone()).await;
        assert!(
            stats.manifests_registered >= 1,
            "repair must register the seeded manifest, stats: {stats:?}"
        );
        assert!(
            stats.blobs_registered >= 2,
            "repair must register config + layer blobs, stats: {stats:?}"
        );

        // Tag resolves; manifest bytes at the digest-addressed key; blobs
        // registered reusing their existing CAS storage keys.
        let tag: Option<(String,)> = sqlx::query_as(
            "SELECT manifest_digest FROM oci_tags \
             WHERE repository_id = $1 AND name = 'hello' AND tag = 'latest'",
        )
        .bind(repo_id)
        .fetch_optional(&pool)
        .await
        .expect("query oci_tags");
        assert_eq!(
            tag.expect("repaired tag row").0,
            format!("sha256:{manifest_hex}")
        );
        assert!(
            storage
                .exists(&format!("oci-manifests/sha256:{manifest_hex}"))
                .await
                .unwrap(),
            "manifest bytes copied to the digest-addressed key"
        );
        for hex in [&config_hex, &layer_hex] {
            let blob: Option<(String,)> = sqlx::query_as(
                "SELECT storage_key FROM oci_blobs WHERE repository_id = $1 AND digest = $2",
            )
            .bind(repo_id)
            .bind(format!("sha256:{hex}"))
            .fetch_optional(&pool)
            .await
            .expect("query oci_blobs");
            assert_eq!(
                blob.expect("repaired blob row").0,
                ArtifactService::storage_key_from_checksum(hex),
                "blob row must reuse the existing CAS storage key"
            );
        }

        // Second run must be a no-op for this repo (its manifest now has an
        // oci_tags row, so the candidate query no longer matches it). Assert
        // repo-scoped state rather than global stats: the shared test DB may
        // hold unrelated candidates from concurrently running tests.
        let tags_after_first: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM oci_tags WHERE repository_id = $1")
                .bind(repo_id)
                .fetch_one(&pool)
                .await
                .expect("count oci_tags after first run");
        let _ = run_repair(&pool, registry).await;
        let tags_after_second: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM oci_tags WHERE repository_id = $1")
                .bind(repo_id)
                .fetch_one(&pool)
                .await
                .expect("count oci_tags after second run");
        assert_eq!(
            tags_after_first, tags_after_second,
            "re-run must not change this repo's registrations"
        );

        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .expect("cleanup repo");
    }
}
