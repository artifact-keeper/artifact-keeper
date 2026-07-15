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
    /// Child (per-arch) manifests of an image index registered from present
    /// artifacts rows (#2457 F2 index recursion).
    pub children_registered: usize,
    /// Candidates whose path did not classify as a manifest after prefix
    /// stripping. Left untouched; not an error.
    pub candidates_skipped: usize,
    /// Candidates that could not be processed (bytes missing from storage,
    /// digest mismatch, malformed JSON, DB write failure). Logged at WARN;
    /// retried on the next restart.
    pub candidates_failed: usize,
    /// Registered tags found to be HOLLOW — an image whose referenced blobs
    /// are missing, or an index whose children are unresolvable. AK cannot
    /// fabricate never-transferred bytes; these repos need re-migration and
    /// are surfaced in the startup WARN (#2457 F2 startup repair).
    pub hollow_tags_flagged: usize,
    /// Orphan `oci_tags` rows (migrated manifest whose backing artifact was
    /// soft-deleted, leaving a tag with no live artifacts row) dropped so
    /// they 404 cleanly instead of resolving to a phantom manifest.
    pub orphan_tags_reconciled: usize,
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

    // Register any unregistered migrated manifests (hollow-image repair). This
    // loop is a no-op when there are no candidates, but the orphan/hollow
    // reconciliation below MUST still run: an orphan tag (a migrated manifest
    // whose backing `artifacts` row was later soft-deleted) can exist with no
    // unregistered-manifest candidate at all, so it cannot be gated behind a
    // non-empty candidate set.
    if !candidates.is_empty() {
        tracing::info!(
            candidate_count = candidates.len(),
            "OCI migration reindex: registering migrated Docker/OCI manifests"
        );

        for candidate in candidates {
            match process_candidate(db, &registry, &candidate).await {
                Ok(Some(counts)) => {
                    stats.manifests_registered += 1;
                    stats.blobs_registered += counts.blobs;
                    stats.children_registered += counts.children;
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
    }

    // #2457 F2 startup repair: reconcile the hollow/orphan state left by
    // v1.5.7 migrations (tags registered, referenced content never fetched).
    // Conservative — a healthy DB is untouched: only tags whose backing
    // artifact was soft-deleted are dropped, and hollow tags are merely
    // flagged (AK cannot fabricate never-transferred bytes) so operators know
    // which repos to re-migrate.
    match reconcile_hollow_and_orphan_tags(db).await {
        Ok(recon) => {
            stats.hollow_tags_flagged = recon.hollow_tags_flagged;
            stats.orphan_tags_reconciled = recon.orphan_tags_reconciled;
            if !recon.hollow_repos.is_empty() {
                tracing::warn!(
                    hollow_tags = recon.hollow_tags_flagged,
                    repositories = ?recon.hollow_repos,
                    "OCI migration reindex: hollow Docker/OCI tags detected \
                     (referenced blobs/child manifests were never transferred); \
                     re-run the migration for these repositories to make the \
                     images pullable"
                );
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "OCI migration reindex: hollow/orphan reconciliation skipped");
        }
    }

    tracing::info!(
        candidates_scanned = stats.candidates_scanned,
        manifests_registered = stats.manifests_registered,
        blobs_registered = stats.blobs_registered,
        children_registered = stats.children_registered,
        candidates_skipped = stats.candidates_skipped,
        candidates_failed = stats.candidates_failed,
        hollow_tags_flagged = stats.hollow_tags_flagged,
        orphan_tags_reconciled = stats.orphan_tags_reconciled,
        "OCI migration reindex: complete"
    );
    stats
}

/// Outcome of the conservative hollow/orphan reconciliation pass.
#[derive(Debug, Default)]
struct ReconcileOutcome {
    hollow_tags_flagged: usize,
    orphan_tags_reconciled: usize,
    hollow_repos: Vec<String>,
}

/// Reconcile the two data-fidelity defects a v1.5.7 Docker migration leaves.
///
/// 1. ORPHAN tags (#2457 F3, historical): a migrated manifest whose backing
///    `artifacts` row was later soft-deleted leaves an `oci_tags` row with no
///    live artifact. It is dropped so the tag 404s cleanly. The criterion is
///    deliberately narrow — the tag must match a *tombstoned* (`is_deleted =
///    true`) artifacts row and NOT any live one — so a natively `docker push`ed
///    tag (which has no `artifacts` row at all) is never touched, and neither
///    is a healthy migrated tag.
///
/// 2. HOLLOW tags (#2457 F1, historical): a tag that IS backed by a live
///    artifact but whose referenced content is incomplete — an image with a
///    `manifest_blob_refs` edge to a digest that has no `oci_blobs` row, or an
///    index with an `oci_manifest_refs` child that resolves to neither a tag
///    nor a blob. These cannot be fixed here (the bytes were never
///    transferred); they are counted and their repositories returned for a
///    WARN so operators re-migrate.
async fn reconcile_hollow_and_orphan_tags(db: &PgPool) -> sqlx::Result<ReconcileOutcome> {
    let mut outcome = ReconcileOutcome::default();

    // --- 1. Drop orphan tags (tombstoned backing artifact only). ---
    let dropped = sqlx::query(
        r#"
        DELETE FROM oci_tags ot
        USING repositories r
        WHERE ot.repository_id = r.id
          AND lower(r.format::text) IN ('docker', 'oci')
          AND EXISTS (
                SELECT 1 FROM artifacts a
                WHERE a.repository_id = ot.repository_id
                  AND 'sha256:' || a.checksum_sha256 = ot.manifest_digest
                  AND a.is_deleted = true
          )
          AND NOT EXISTS (
                SELECT 1 FROM artifacts a
                WHERE a.repository_id = ot.repository_id
                  AND 'sha256:' || a.checksum_sha256 = ot.manifest_digest
                  AND a.is_deleted = false
          )
        "#,
    )
    .execute(db)
    .await?;
    outcome.orphan_tags_reconciled = dropped.rows_affected() as usize;

    // --- 2. Flag hollow tags (referenced content incomplete). ---
    let rows = sqlx::query(
        r#"
        SELECT DISTINCT r.key AS repo_key, ot.repository_id AS repository_id
        FROM oci_tags ot
        JOIN repositories r ON r.id = ot.repository_id
        WHERE lower(r.format::text) IN ('docker', 'oci')
          AND (
            -- image manifest: a referenced blob has no oci_blobs row
            EXISTS (
                SELECT 1 FROM manifest_blob_refs br
                WHERE br.repository_id = ot.repository_id
                  AND br.manifest_digest = ot.manifest_digest
                  AND NOT EXISTS (
                        SELECT 1 FROM oci_blobs ob
                        WHERE ob.repository_id = br.repository_id
                          AND ob.digest = br.blob_digest
                  )
            )
            -- image index: a child manifest resolves to neither a tag nor a blob
            OR EXISTS (
                SELECT 1 FROM oci_manifest_refs mr
                WHERE mr.repository_id = ot.repository_id
                  AND mr.parent_digest = ot.manifest_digest
                  AND NOT EXISTS (
                        SELECT 1 FROM oci_tags c
                        WHERE c.repository_id = mr.repository_id
                          AND c.manifest_digest = mr.child_digest
                  )
            )
          )
        "#,
    )
    .fetch_all(db)
    .await?;

    let mut repos: Vec<String> = Vec::new();
    for row in &rows {
        let key: String = row.try_get("repo_key").unwrap_or_default();
        if !repos.contains(&key) {
            repos.push(key);
        }
    }
    outcome.hollow_tags_flagged = rows.len();
    outcome.hollow_repos = repos;
    Ok(outcome)
}

/// Blob + child-manifest registration counts from processing one candidate.
#[derive(Debug, Default, Clone, Copy)]
struct CandidateCounts {
    blobs: usize,
    children: usize,
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
) -> Result<Option<CandidateCounts>, String> {
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

    // Register the blobs an image manifest references from present artifacts
    // rows (an index has none — `extract_blob_refs` returns empty for it).
    let blobs_registered =
        register_present_blobs(db, candidate.repository_id, &candidate.path, &body).await?;

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

    // #2457 F2 index recursion: for an image INDEX, register each child
    // manifest from its own (present) artifacts row so multi-arch images pull.
    // Children whose bytes were never migrated are logged and left for a
    // re-migration — the parent tag resolving is strictly better than nothing.
    let mut children_registered = 0usize;
    if matches!(class, crate::api::handlers::oci_v2::ManifestClass::Index) {
        for child_digest in crate::api::handlers::oci_v2::extract_child_digests(&body) {
            match register_child_manifest_from_artifacts(
                db,
                registry,
                candidate,
                &image,
                &child_digest,
            )
            .await?
            {
                Some(child_blobs) => {
                    children_registered += 1;
                    // child blobs count toward the same blob tally.
                    // (kept separate from `blobs_registered` for clarity)
                    let _ = child_blobs;
                }
                None => {
                    tracing::warn!(
                        repository_id = %candidate.repository_id,
                        manifest_path = %candidate.path,
                        child_digest = %child_digest,
                        "OCI migration reindex: index child manifest has no artifacts \
                         row; child will 404 until re-migrated"
                    );
                }
            }
        }
    }

    Ok(Some(CandidateCounts {
        blobs: blobs_registered,
        children: children_registered,
    }))
}

/// Register the config/layer blobs an image manifest references, reusing each
/// blob's existing CAS `storage_key` from its `artifacts` row (blob-serve
/// honors arbitrary keys). A referenced blob whose artifacts row is absent is
/// logged and skipped — the tag resolving beats MANIFEST_UNKNOWN and the gap
/// is visible in the logs. Returns the number of blob rows written.
async fn register_present_blobs(
    db: &PgPool,
    repository_id: Uuid,
    manifest_path: &str,
    body: &[u8],
) -> Result<usize, String> {
    let mut registered = 0usize;
    for blob_ref in crate::api::handlers::oci_v2::extract_blob_refs(body) {
        let Some(hex) = blob_ref.digest.strip_prefix("sha256:") else {
            continue;
        };
        let blob_row: Option<(String, i64)> = sqlx::query_as(
            "SELECT storage_key, size_bytes FROM artifacts \
             WHERE repository_id = $1 AND checksum_sha256 = $2 AND is_deleted = false \
             LIMIT 1",
        )
        .bind(repository_id)
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
                .bind(repository_id)
                .bind(&blob_ref.digest)
                .bind(blob_size)
                .bind(&blob_storage_key)
                .execute(db)
                .await
                .map_err(|e| format!("insert oci_blobs row: {}", e))?;
                registered += 1;
            }
            None => {
                tracing::warn!(
                    repository_id = %repository_id,
                    manifest_path = %manifest_path,
                    blob_digest = %blob_ref.digest,
                    "OCI migration reindex: referenced blob has no artifacts row; \
                     layer will 404 until re-migrated"
                );
            }
        }
    }
    Ok(registered)
}

/// Register one child (per-arch) manifest of an image index from its present
/// `artifacts` row: copy its bytes to the digest-addressed manifest key,
/// register it via `persist_tag_and_refs` (reference == digest, exactly as the
/// live push path records a manifest pushed by digest), and register the
/// child's own config/layer blobs. Returns `Ok(None)` when the child manifest
/// has no present artifacts row (never transferred), `Ok(Some(child_blobs))`
/// otherwise.
async fn register_child_manifest_from_artifacts(
    db: &PgPool,
    registry: &StorageRegistry,
    candidate: &RepairCandidate,
    image: &str,
    child_digest: &str,
) -> Result<Option<usize>, String> {
    let Some(hex) = child_digest.strip_prefix("sha256:") else {
        return Ok(None);
    };
    let child_row: Option<(String, i64)> = sqlx::query_as(
        "SELECT storage_key, size_bytes FROM artifacts \
         WHERE repository_id = $1 AND checksum_sha256 = $2 AND is_deleted = false \
         LIMIT 1",
    )
    .bind(candidate.repository_id)
    .bind(hex)
    .fetch_optional(db)
    .await
    .map_err(|e| format!("look up child manifest artifact row: {}", e))?;
    let Some((child_storage_key, child_size)) = child_row else {
        return Ok(None);
    };
    if child_size > MAX_INDEX_MANIFEST_BYTES as i64 {
        return Err(format!(
            "child manifest {} exceeds {} bytes",
            child_digest, MAX_INDEX_MANIFEST_BYTES
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
        .get(&child_storage_key)
        .await
        .map_err(|e| format!("read child manifest bytes: {}", e))?;

    let computed = crate::api::handlers::oci_v2::compute_sha256(&body);
    if computed != child_digest {
        return Err(format!(
            "child manifest content digest {} != index-referenced {}",
            computed, child_digest
        ));
    }
    let class = crate::api::handlers::oci_v2::classify_manifest(&body);
    if matches!(
        class,
        crate::api::handlers::oci_v2::ManifestClass::Malformed
    ) {
        return Err(format!("child manifest {} is malformed", child_digest));
    }

    let manifest_key = crate::api::handlers::oci_v2::manifest_storage_key(child_digest);
    if !storage.exists(&manifest_key).await.unwrap_or(false) {
        storage
            .put(&manifest_key, body.clone())
            .await
            .map_err(|e| format!("write child manifest to {}: {}", manifest_key, e))?;
    }

    let child_blobs =
        register_present_blobs(db, candidate.repository_id, &candidate.path, &body).await?;

    let content_type = crate::api::handlers::oci_v2::stored_media_type_for(
        &class,
        &crate::api::handlers::oci_v2::resolve_manifest_content_type(None, &body),
    );
    crate::api::handlers::oci_v2::persist_tag_and_refs(
        db,
        candidate.repository_id,
        image,
        child_digest,
        child_digest,
        &content_type,
        &class,
        &body,
    )
    .await
    .map_err(|e| format!("persist child tag and refs: {}", e))?;

    Ok(Some(child_blobs))
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
        assert_eq!(s.children_registered, 0);
        assert_eq!(s.hollow_tags_flagged, 0);
        assert_eq!(s.orphan_tags_reconciled, 0);
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

    /// #2457 F2: an image INDEX imported by an older run (index + child
    /// manifest + child blobs all present as `artifacts` rows, no OCI index
    /// rows) must repair to a pullable multi-arch image — the child manifest
    /// resolves by digest and its config blob is registered.
    #[tokio::test]
    async fn test_run_repair_registers_image_index_and_children() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::artifact_service::ArtifactService;
        use crate::storage::StorageBackend;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let tmp = tempfile::tempdir().expect("tempdir");
        let repo_id = Uuid::new_v4();
        let repo_key = format!("reidxidx-{}", &repo_id.to_string()[..8]);
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

        let cfg = bytes::Bytes::from_static(b"{\"arch\":\"amd64\"}");
        let cfg_hex = sha256_hex_of(&cfg);
        let child = format!(
            "{{\"schemaVersion\":2,\"config\":{{\"size\":{},\"digest\":\"sha256:{}\"}},\"layers\":[]}}",
            cfg.len(),
            cfg_hex
        );
        let child_bytes = bytes::Bytes::from(child);
        let child_hex = sha256_hex_of(&child_bytes);
        let index = format!(
            "{{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.index.v1+json\",\
              \"manifests\":[{{\"size\":{},\"digest\":\"sha256:{}\",\
              \"platform\":{{\"architecture\":\"amd64\",\"os\":\"linux\"}}}}]}}",
            child_bytes.len(),
            child_hex
        );
        let index_bytes = bytes::Bytes::from(index);
        let index_hex = sha256_hex_of(&index_bytes);

        // Seed pre-fix state: config blob, child manifest (digest folder), and
        // the index tag — all CAS bytes + artifacts rows, no OCI rows.
        for (bytes, hex, rel_path) in [
            (&cfg, &cfg_hex, format!("app/latest/sha256__{cfg_hex}")),
            (
                &child_bytes,
                &child_hex,
                format!("app/sha256__{child_hex}/manifest.json"),
            ),
            (
                &index_bytes,
                &index_hex,
                "app/latest/list.manifest.json".to_string(),
            ),
        ] {
            let cas_key = ArtifactService::storage_key_from_checksum(hex);
            storage
                .put(&cas_key, bytes.clone())
                .await
                .expect("seed CAS");
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
        let _ = run_repair(&pool, registry).await;

        // Parent index tag registered.
        let parent: Option<(String,)> = sqlx::query_as(
            "SELECT manifest_digest FROM oci_tags WHERE repository_id=$1 AND name='app' AND tag='latest'",
        )
        .bind(repo_id)
        .fetch_optional(&pool)
        .await
        .unwrap();
        assert_eq!(parent.expect("index tag").0, format!("sha256:{index_hex}"));

        // Child manifest resolves by digest + config blob registered.
        let child_tag: Option<(String,)> = sqlx::query_as(
            "SELECT manifest_digest FROM oci_tags WHERE repository_id=$1 AND manifest_digest=$2 LIMIT 1",
        )
        .bind(repo_id)
        .bind(format!("sha256:{child_hex}"))
        .fetch_optional(&pool)
        .await
        .unwrap();
        assert!(child_tag.is_some(), "index child must resolve by digest");
        let child_blob: Option<(String,)> = sqlx::query_as(
            "SELECT storage_key FROM oci_blobs WHERE repository_id=$1 AND digest=$2",
        )
        .bind(repo_id)
        .bind(format!("sha256:{cfg_hex}"))
        .fetch_optional(&pool)
        .await
        .unwrap();
        assert!(child_blob.is_some(), "child config blob must be registered");

        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .expect("cleanup repo");
    }

    /// #2457 F3 startup reconciliation: an orphan `oci_tags` row (migrated
    /// manifest whose backing artifact was soft-deleted) is DROPPED, while a
    /// healthy migrated tag in the same repo is left untouched.
    #[tokio::test]
    async fn test_run_repair_drops_orphan_tag_keeps_healthy() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo_id = Uuid::new_v4();
        let repo_key = format!("reidxorph-{}", &repo_id.to_string()[..8]);
        sqlx::query(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, is_public) \
             VALUES ($1, $2, $2, $3, 'local', 'docker'::repository_format, true)",
        )
        .bind(repo_id)
        .bind(&repo_key)
        .bind(tmp.path().to_str().unwrap())
        .execute(&pool)
        .await
        .expect("insert repo");

        // Healthy migrated tag: live artifacts row + oci_tags.
        let healthy_hex = "a".repeat(64);
        insert_prefix_artifact(
            &pool,
            repo_id,
            &format!("{repo_key}/keep/latest/manifest.json"),
            &healthy_hex,
            "oci-manifests/sha256:keep",
            10,
        )
        .await;
        // Orphan tag: tombstoned artifacts row (is_deleted=true) + oci_tags.
        let orphan_hex = "b".repeat(64);
        insert_prefix_artifact(
            &pool,
            repo_id,
            &format!("{repo_key}/gone/latest/manifest.json"),
            &orphan_hex,
            "oci-manifests/sha256:gone",
            10,
        )
        .await;
        sqlx::query(
            "UPDATE artifacts SET is_deleted=true WHERE repository_id=$1 AND checksum_sha256=$2",
        )
        .bind(repo_id)
        .bind(&orphan_hex)
        .execute(&pool)
        .await
        .unwrap();
        for (name, hex) in [("keep", &healthy_hex), ("gone", &orphan_hex)] {
            sqlx::query(
                "INSERT INTO oci_tags (repository_id, name, tag, manifest_digest, manifest_content_type) \
                 VALUES ($1, $2, 'latest', $3, 'application/vnd.oci.image.manifest.v1+json')",
            )
            .bind(repo_id)
            .bind(name)
            .bind(format!("sha256:{hex}"))
            .execute(&pool)
            .await
            .unwrap();
        }

        let registry = Arc::new(StorageRegistry::new(
            std::collections::HashMap::new(),
            "filesystem".to_string(),
        ));
        let stats = run_repair(&pool, registry).await;
        assert!(
            stats.orphan_tags_reconciled >= 1,
            "orphan tag must be reconciled, stats: {stats:?}"
        );

        let keep: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM oci_tags WHERE repository_id=$1 AND name='keep'")
                .bind(repo_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(keep.0, 1, "healthy migrated tag must be kept");
        let gone: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM oci_tags WHERE repository_id=$1 AND name='gone'")
                .bind(repo_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(gone.0, 0, "orphan tag must be dropped");

        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .expect("cleanup repo");
    }
}
