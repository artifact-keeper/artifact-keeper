//! One-shot backfill for `oci_manifest_refs` (artifact-keeper#1179).
//!
//! The push handler in `api::handlers::oci_v2` populates `oci_manifest_refs`
//! eagerly whenever a multi-arch image index manifest is committed. That
//! covers every push that lands after the upgrade to a release containing
//! migration 092, but it does not cover index manifests that were pushed
//! before the upgrade and are still tagged: those tags exist in
//! `oci_tags` with no corresponding rows in `oci_manifest_refs`, and the
//! storage GC's protection for their per-architecture children only
//! kicks in once the refs are written.
//!
//! This module walks the index-typed `oci_tags` rows that have zero
//! refs, loads each manifest body from storage, parses the JSON, and
//! inserts the (parent, child, repository_id) edges. The backfill is
//! idempotent (`ON CONFLICT DO NOTHING`) and best-effort: a missing
//! storage file or a malformed manifest is logged at WARN and skipped,
//! it does not stop the backfill or fail server startup.
//!
//! Called once from `main.rs` after migrations run. On the next restart
//! the same query returns zero rows and the backfill is effectively a
//! no-op SQL query.

use std::sync::Arc;

use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::storage::keys::OCI_MANIFEST_STORAGE_PREFIX;
use crate::storage::{StorageLocation, StorageRegistry};

/// Result of a backfill pass. Returned for tracing and tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct BackfillStats {
    /// Number of (parent_digest, repository_id) candidates we tried to
    /// process. Equals the number of distinct index manifests visited.
    pub candidates_scanned: usize,
    /// Number of edges (parent -> child) inserted into the table.
    pub edges_inserted: usize,
    /// Number of candidates we could not process (manifest missing from
    /// storage, malformed JSON, DB write failure). These are logged at
    /// WARN level but otherwise ignored; the next restart re-tries.
    pub candidates_failed: usize,
}

/// Run the one-shot backfill. Returns a stats struct; never errors at
/// the function boundary (backfill failures are logged and counted in
/// `candidates_failed`). Server startup must not be blocked by a single
/// corrupted manifest.
pub async fn run_backfill(db: &PgPool, registry: Arc<StorageRegistry>) -> BackfillStats {
    let candidates = match select_unbackfilled_indexes(db).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "oci_manifest_refs backfill: failed to scan candidates; skipping"
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
        "oci_manifest_refs backfill: processing index manifests"
    );

    for candidate in candidates {
        match process_candidate(db, &registry, &candidate).await {
            Ok(inserted) => stats.edges_inserted += inserted,
            Err(e) => {
                tracing::warn!(
                    parent_digest = candidate.parent_digest.as_str(),
                    repository_id = %candidate.repository_id,
                    error = %e,
                    "oci_manifest_refs backfill: skipped index manifest"
                );
                stats.candidates_failed += 1;
            }
        }
    }

    tracing::info!(
        candidates_scanned = stats.candidates_scanned,
        edges_inserted = stats.edges_inserted,
        candidates_failed = stats.candidates_failed,
        "oci_manifest_refs backfill: complete"
    );
    stats
}

#[derive(Debug)]
struct BackfillCandidate {
    parent_digest: String,
    repository_id: Uuid,
    storage_backend: String,
    storage_path: String,
}

/// Select the distinct (parent_digest, repository_id) tuples whose
/// content-type marks them as an image index and that have zero rows in
/// `oci_manifest_refs`. We pull `storage_backend` / `storage_path` from
/// the repositories table along the way so the per-candidate work can
/// resolve the correct backend without a second query.
///
/// Uses `DISTINCT ON` to deduplicate when the same digest is tagged
/// under multiple tag names in the same repository. The first row wins;
/// since all rows for the same (digest, repo) point at the same
/// manifest body, that's fine.
async fn select_unbackfilled_indexes(db: &PgPool) -> sqlx::Result<Vec<BackfillCandidate>> {
    let rows = sqlx::query(
        r#"
        SELECT DISTINCT ON (ot.manifest_digest, ot.repository_id)
            ot.manifest_digest AS parent_digest,
            ot.repository_id AS repository_id,
            r.storage_backend AS storage_backend,
            r.storage_path AS storage_path
        FROM oci_tags ot
        JOIN repositories r ON r.id = ot.repository_id
        WHERE ot.manifest_content_type IN (
                'application/vnd.oci.image.index.v1+json',
                'application/vnd.docker.distribution.manifest.list.v2+json'
            )
          AND NOT EXISTS (
                SELECT 1 FROM oci_manifest_refs omr
                WHERE omr.parent_digest = ot.manifest_digest
                  AND omr.repository_id = ot.repository_id
          )
        "#,
    )
    .fetch_all(db)
    .await?;

    let candidates = rows
        .into_iter()
        .map(|r| BackfillCandidate {
            parent_digest: r.try_get("parent_digest").unwrap_or_default(),
            repository_id: r.try_get("repository_id").unwrap_or_default(),
            storage_backend: r.try_get("storage_backend").unwrap_or_default(),
            storage_path: r.try_get("storage_path").unwrap_or_default(),
        })
        .collect();
    Ok(candidates)
}

/// Hard cap on the manifest body size we are willing to load and parse
/// during backfill. OCI image-index manifests are tiny in practice (one
/// JSON entry per platform, a few hundred bytes each); a 4 MiB ceiling
/// is two orders of magnitude above legitimate sizes and prevents a
/// corrupted or malicious storage key from OOMing startup. If a body
/// exceeds this, we log at WARN and skip the candidate; the child
/// manifests for that index just stay unprotected (same state as before
/// this PR) until the index is re-pushed through the live handler.
pub(crate) const MAX_INDEX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;

/// Load one index manifest from storage, parse it, and insert the
/// resulting (parent, child, repo) edges into `oci_manifest_refs`.
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

    let storage_key = format!("{}{}", OCI_MANIFEST_STORAGE_PREFIX, candidate.parent_digest);
    let body = storage
        .get(&storage_key)
        .await
        .map_err(|e| format!("read manifest from storage: {}", e))?;

    if body.len() > MAX_INDEX_MANIFEST_BYTES {
        return Err(format!(
            "index manifest body exceeds {} bytes (got {}); skipping JSON parse",
            MAX_INDEX_MANIFEST_BYTES,
            body.len()
        ));
    }

    let inserted = crate::api::handlers::oci_v2::record_oci_manifest_refs(
        db,
        candidate.repository_id,
        &candidate.parent_digest,
        &body,
    )
    .await
    .map_err(|e| format!("insert oci_manifest_refs rows: {}", e))?;

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

    // The cap exists to protect startup from a corrupted/malicious
    // body. Real OCI image-index manifests are well under 1 MiB; a
    // 4 MiB ceiling is far above legitimate sizes but small enough
    // that a single bad blob cannot exhaust process memory. Asserted
    // at compile time so a future bump out of the safe range fails the
    // build rather than a single test invocation.
    const _SANE_LOWER: () = assert!(MAX_INDEX_MANIFEST_BYTES >= 64 * 1024);
    const _SANE_UPPER: () = assert!(MAX_INDEX_MANIFEST_BYTES <= 16 * 1024 * 1024);
}
