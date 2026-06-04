//! One-shot backfill for `manifest_blob_refs` (artifact-keeper#1635).
//!
//! GC prerequisite for #1408 / #1610. The push handler in
//! `api::handlers::oci_v2` populates `manifest_blob_refs` eagerly whenever
//! a regular (non-index) image manifest is committed. That covers every
//! push that lands after the upgrade to a release containing migration
//! 120, but it does not cover image manifests that were pushed before the
//! upgrade and are still reachable: those manifests exist in storage (and
//! are referenced from `oci_tags` and/or `oci_manifest_refs.child_digest`)
//! with no corresponding rows in `manifest_blob_refs`.
//!
//! This module walks the image manifests reachable via `oci_tags`
//! (directly tagged manifests whose content-type is NOT an image index)
//! and via `oci_manifest_refs.child_digest` (the per-architecture child
//! manifests of multi-arch image indexes, which are always image
//! manifests) that have zero `manifest_blob_refs` rows, loads each
//! manifest body from storage, parses the JSON, and inserts the
//! (manifest, blob, repo, kind) edges. The backfill is idempotent
//! (`ON CONFLICT DO NOTHING`) and best-effort: a missing storage file or
//! a malformed manifest is logged at WARN and skipped; it does not stop
//! the backfill or fail startup.
//!
//! Called once from `main.rs` after migrations run. On the next restart
//! the same query returns zero rows and the backfill is effectively a
//! no-op SQL query. This reconstructs blob references for the existing
//! corpus so a future blob GC can judge `oci_blobs` orphanhood safely.
//!
//! ADDITIVE ONLY (#1635): this backfill only makes blob references
//! KNOWABLE. It performs no deletion of any kind.

use std::sync::Arc;

use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::storage::{StorageLocation, StorageRegistry};

/// Result of a backfill pass. Returned for tracing and tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct BackfillStats {
    /// Number of (manifest_digest, repository_id) candidates we tried to
    /// process. Equals the number of distinct image manifests visited.
    pub candidates_scanned: usize,
    /// Number of edges (manifest -> blob) inserted into the table.
    pub edges_inserted: usize,
    /// Number of candidates we could not process (manifest missing from
    /// storage, malformed JSON, DB write failure). These are logged at
    /// WARN level but otherwise ignored; the next restart re-tries.
    pub candidates_failed: usize,
}

/// Run the one-shot backfill. Returns a stats struct; never errors at the
/// function boundary (backfill failures are logged and counted in
/// `candidates_failed`). Server startup must not be blocked by a single
/// corrupted manifest.
pub async fn run_backfill(db: &PgPool, registry: Arc<StorageRegistry>) -> BackfillStats {
    let candidates = match select_unbackfilled_manifests(db).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "manifest_blob_refs backfill: failed to scan candidates; skipping"
            );
            return BackfillStats::default();
        }
    };

    let mut stats = BackfillStats {
        candidates_scanned: candidates.len(),
        ..BackfillStats::default()
    };

    if candidates.is_empty() {
        return stats;
    }

    tracing::info!(
        candidate_count = candidates.len(),
        "manifest_blob_refs backfill: processing image manifests"
    );

    for candidate in candidates {
        match process_candidate(db, &registry, &candidate).await {
            Ok(inserted) => stats.edges_inserted += inserted,
            Err(e) => {
                tracing::warn!(
                    manifest_digest = candidate.manifest_digest.as_str(),
                    repository_id = %candidate.repository_id,
                    error = %e,
                    "manifest_blob_refs backfill: skipped image manifest"
                );
                stats.candidates_failed += 1;
            }
        }
    }

    tracing::info!(
        candidates_scanned = stats.candidates_scanned,
        edges_inserted = stats.edges_inserted,
        candidates_failed = stats.candidates_failed,
        "manifest_blob_refs backfill: complete"
    );
    stats
}

#[derive(Debug)]
struct BackfillCandidate {
    manifest_digest: String,
    repository_id: Uuid,
    storage_backend: String,
    storage_path: String,
}

/// Select the distinct (manifest_digest, repository_id) tuples for image
/// manifests that have zero rows in `manifest_blob_refs`. Two reachability
/// sources are unioned:
///
///   1. `oci_tags` rows whose content-type is NOT an image index -- these
///      are directly tagged image manifests.
///   2. `oci_manifest_refs.child_digest` -- the per-architecture child
///      manifests of multi-arch image indexes. These never appear in
///      `oci_tags` directly but are image manifests with their own blobs.
///
/// We pull `storage_backend` / `storage_path` from the repositories table
/// along the way so the per-candidate work can resolve the correct backend
/// without a second query. `DISTINCT ON` deduplicates a digest that is
/// tagged under multiple names (or is both tagged and an index child) in
/// the same repository; the first row wins, and since all rows for the
/// same (digest, repo) point at the same manifest body, that is fine.
async fn select_unbackfilled_manifests(db: &PgPool) -> sqlx::Result<Vec<BackfillCandidate>> {
    let rows = sqlx::query(
        r#"
        SELECT DISTINCT ON (c.manifest_digest, c.repository_id)
            c.manifest_digest AS manifest_digest,
            c.repository_id AS repository_id,
            r.storage_backend AS storage_backend,
            r.storage_path AS storage_path
        FROM (
            SELECT ot.manifest_digest AS manifest_digest,
                   ot.repository_id AS repository_id
            FROM oci_tags ot
            WHERE ot.manifest_content_type NOT IN (
                    'application/vnd.oci.image.index.v1+json',
                    'application/vnd.docker.distribution.manifest.list.v2+json'
                )
            UNION
            SELECT omr.child_digest AS manifest_digest,
                   omr.repository_id AS repository_id
            FROM oci_manifest_refs omr
        ) AS c
        JOIN repositories r ON r.id = c.repository_id
        WHERE NOT EXISTS (
                SELECT 1 FROM manifest_blob_refs mbr
                WHERE mbr.manifest_digest = c.manifest_digest
                  AND mbr.repository_id = c.repository_id
          )
        "#,
    )
    .fetch_all(db)
    .await?;

    let candidates = rows
        .into_iter()
        .map(|r| BackfillCandidate {
            manifest_digest: r.try_get("manifest_digest").unwrap_or_default(),
            repository_id: r.try_get("repository_id").unwrap_or_default(),
            storage_backend: r.try_get("storage_backend").unwrap_or_default(),
            storage_path: r.try_get("storage_path").unwrap_or_default(),
        })
        .collect();
    Ok(candidates)
}

/// Hard cap on the manifest body size we are willing to load and parse
/// during backfill. OCI image manifests are tiny in practice (one JSON
/// entry per layer, a few hundred bytes each); a 4 MiB ceiling is far
/// above legitimate sizes and prevents a corrupted or malicious storage
/// key from OOMing startup. If a body exceeds this, we log at WARN and
/// skip the candidate; its blobs just stay unreferenced (same state as
/// before this PR) until the manifest is re-pushed through the live
/// handler.
pub(crate) const MAX_IMAGE_MANIFEST_BYTES: usize = 4 * 1024 * 1024;

/// Load one image manifest from storage, parse it, and insert the
/// resulting (manifest, blob, repo, kind) edges into `manifest_blob_refs`.
async fn process_candidate(
    db: &PgPool,
    registry: &StorageRegistry,
    candidate: &BackfillCandidate,
) -> Result<usize, String> {
    let location = StorageLocation {
        backend: candidate.storage_backend.clone(),
        path: candidate.storage_path.clone(),
    };
    let storage = registry
        .backend_for(&location)
        .map_err(|e| format!("resolve storage backend: {}", e))?;

    let storage_key = format!("oci-manifests/{}", candidate.manifest_digest);
    let body = storage
        .get(&storage_key)
        .await
        .map_err(|e| format!("read manifest from storage: {}", e))?;

    if body.len() > MAX_IMAGE_MANIFEST_BYTES {
        return Err(format!(
            "image manifest body exceeds {} bytes (got {}); skipping JSON parse",
            MAX_IMAGE_MANIFEST_BYTES,
            body.len()
        ));
    }

    let inserted = crate::api::handlers::oci_v2::record_manifest_blob_refs(
        db,
        candidate.repository_id,
        &candidate.manifest_digest,
        &body,
    )
    .await
    .map_err(|e| format!("insert manifest_blob_refs rows: {}", e))?;

    Ok(inserted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backfill_stats_default_is_zero() {
        let s = BackfillStats::default();
        assert_eq!(s.candidates_scanned, 0);
        assert_eq!(s.edges_inserted, 0);
        assert_eq!(s.candidates_failed, 0);
    }

    #[test]
    fn backfill_stats_is_copy() {
        // Compile-time only: confirms BackfillStats stays Copy so it can
        // be returned across async boundaries cheaply.
        fn assert_copy<T: Copy>() {}
        assert_copy::<BackfillStats>();
    }

    // The cap exists to protect startup from a corrupted/malicious body.
    // Real OCI image manifests are well under 1 MiB; a 4 MiB ceiling is
    // far above legitimate sizes but small enough that a single bad blob
    // cannot exhaust process memory. Asserted at compile time so a future
    // bump out of the safe range fails the build rather than a single test
    // invocation.
    const _SANE_LOWER: () = assert!(MAX_IMAGE_MANIFEST_BYTES >= 64 * 1024);
    const _SANE_UPPER: () = assert!(MAX_IMAGE_MANIFEST_BYTES <= 16 * 1024 * 1024);
}
