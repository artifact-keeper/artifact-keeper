//! One-shot backfill for `manifest_blob_refs` (artifact-keeper#1635).
//!
//! GC prerequisite for #1408 / #1610. The push handler in
//! `api::handlers::oci_v2` populates `manifest_blob_refs` eagerly whenever
//! a regular (non-index) image manifest is committed. That covers every
//! push that lands after the upgrade to a release containing migration
//! 120, but it does not cover image manifests that were pushed before the
//! upgrade and are still reachable: those manifests exist in storage (and
//! are referenced from `oci_tags`) with no corresponding rows in
//! `manifest_blob_refs`.
//!
//! This module walks the image manifests safely backfillable from `oci_tags`
//! (directly tagged manifests whose content-type is NOT an image index) that
//! have zero `manifest_blob_refs` rows, loads each manifest body from storage,
//! parses the JSON, and inserts the
//! (manifest, blob, repo, kind) edges. The backfill is idempotent
//! (`ON CONFLICT DO NOTHING`) and best-effort: a missing storage file or
//! a malformed manifest is logged at WARN and skipped; it does not stop
//! the backfill or fail startup.
//!
//! A bare `oci_manifest_refs.child_digest` is intentionally not a backfill
//! source: an index body can reference a digest whose manifest body was never
//! uploaded to this repository. On shared cloud backends, loading that digest
//! from `oci-manifests/<digest>` would import another repository's manifest
//! metadata and later authorize digest fallback through the wrong repository.
//! Child manifests that were actually pushed to this repository are still
//! covered through their `oci_tags` rows. The blob-GC readiness gate still
//! treats live child edges as missing refs, so destructive blob GC stays off
//! rather than collecting legacy child blobs that could not be backfilled
//! safely.
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

use crate::storage::keys::OCI_MANIFEST_STORAGE_PREFIX;
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

impl BackfillStats {
    /// Initial stats for a pass over `n` candidates: `candidates_scanned`
    /// is fixed up front (it equals the number of distinct manifests we
    /// will visit), the per-candidate counters start at zero. Pure so the
    /// initialization is unit-testable without a DB scan.
    fn for_candidates(n: usize) -> Self {
        Self {
            candidates_scanned: n,
            ..Self::default()
        }
    }

    /// Fold one candidate's outcome into the running totals: a success adds
    /// its inserted-edge count, a failure bumps `candidates_failed`.
    /// `candidates_scanned` is untouched (it is fixed by
    /// [`for_candidates`]). Pure so the loop's accounting is unit-testable
    /// without exercising the DB-backed `process_candidate`.
    fn record_candidate_result(&mut self, outcome: &Result<usize, String>) {
        match outcome {
            Ok(inserted) => self.edges_inserted += inserted,
            Err(_) => self.candidates_failed += 1,
        }
    }
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

    let mut stats = BackfillStats::for_candidates(candidates.len());

    if candidates.is_empty() {
        return stats;
    }

    tracing::info!(
        candidate_count = candidates.len(),
        "manifest_blob_refs backfill: processing image manifests"
    );

    for candidate in candidates {
        let outcome = process_candidate(db, &registry, &candidate).await;
        if let Err(e) = &outcome {
            tracing::warn!(
                manifest_digest = candidate.manifest_digest.as_str(),
                repository_id = %candidate.repository_id,
                error = %e,
                "manifest_blob_refs backfill: skipped image manifest"
            );
        }
        stats.record_candidate_result(&outcome);
    }

    tracing::info!(
        candidates_scanned = stats.candidates_scanned,
        edges_inserted = stats.edges_inserted,
        candidates_failed = stats.candidates_failed,
        "manifest_blob_refs backfill: complete"
    );
    stats
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BackfillCandidate {
    manifest_digest: String,
    repository_id: Uuid,
    storage_backend: String,
    storage_path: String,
}

impl BackfillCandidate {
    /// Build a candidate from the four scalar columns of the selection
    /// query. Pure (no DB row coupling) so the field wiring is unit-
    /// testable; `select_unbackfilled_manifests` calls this once per row.
    fn new(
        manifest_digest: String,
        repository_id: Uuid,
        storage_backend: String,
        storage_path: String,
    ) -> Self {
        Self {
            manifest_digest,
            repository_id,
            storage_backend,
            storage_path,
        }
    }

    /// The storage key under which an OCI image manifest body is stored.
    /// Kept here (next to its only consumer) and pure so the key layout is
    /// pinned by a unit test rather than only exercised by Tier-2 storage
    /// reads.
    fn storage_key(&self) -> String {
        format!("{}{}", OCI_MANIFEST_STORAGE_PREFIX, self.manifest_digest)
    }

    /// The [`StorageLocation`] used to resolve this candidate's backend.
    fn location(&self) -> StorageLocation {
        StorageLocation {
            backend: self.storage_backend.clone(),
            path: self.storage_path.clone(),
        }
    }
}

/// Reject a manifest body that exceeds [`MAX_IMAGE_MANIFEST_BYTES`] before
/// it is parsed, returning the WARN-level skip reason. Pure size check,
/// split out so the cap behaviour is unit-testable without storage.
fn check_manifest_size(len: usize) -> Result<(), String> {
    if len > MAX_IMAGE_MANIFEST_BYTES {
        return Err(format!(
            "image manifest body exceeds {} bytes (got {}); skipping JSON parse",
            MAX_IMAGE_MANIFEST_BYTES, len
        ));
    }
    Ok(())
}

/// The skip reason recorded when a candidate's storage backend cannot be
/// resolved. Pure formatter so the message is unit-testable without a
/// `StorageRegistry`; `process_candidate` maps the backend-resolution
/// error through it.
fn backend_resolve_error(e: impl std::fmt::Display) -> String {
    format!("resolve storage backend: {}", e)
}

/// The skip reason recorded when the manifest body cannot be read from
/// storage (missing key, IO failure). Pure formatter, mapped from the
/// storage `get` error in `process_candidate`.
fn storage_read_error(e: impl std::fmt::Display) -> String {
    format!("read manifest from storage: {}", e)
}

/// The skip reason recorded when the `manifest_blob_refs` insert fails.
/// Pure formatter, mapped from the `record_manifest_blob_refs` DB error in
/// `process_candidate`.
fn insert_rows_error(e: impl std::fmt::Display) -> String {
    format!("insert manifest_blob_refs rows: {}", e)
}

/// Select the distinct (manifest_digest, repository_id) tuples for tagged image
/// manifests that have zero rows in `manifest_blob_refs` and are safe to
/// backfill from storage.
///
/// `oci_tags` rows whose content-type is NOT an image index AND which are not
/// structurally an index (no children in `oci_manifest_refs`) are directly
/// tagged image manifests. The structural guard (#1409 C1) keeps an index
/// pushed with a wrong/absent Content-Type out of the image-candidate set,
/// since it has no blobs of its own and would otherwise pin the readiness gate
/// forever.
///
/// `oci_manifest_refs.child_digest` rows are deliberately not selected on
/// their own. The edge proves a parent index references that digest, not that
/// the child manifest body was pushed into the same repository.
///
/// We pull `storage_backend` / `storage_path` from the repositories table
/// along the way so the per-candidate work can resolve the correct backend
/// without a second query. `DISTINCT ON` deduplicates a digest that is tagged
/// under multiple names in the same repository; the first row wins, and since
/// all rows for the same (digest, repo) point at the same manifest body, that
/// is fine.
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
              -- Structural index guard (#1409 C1): exclude any tagged digest
              -- that is itself an index (has children in oci_manifest_refs),
              -- even when its stored content-type does not match the two
              -- index media types above (pushed with a wrong/absent
              -- Content-Type). An index carries no blobs of its own, so it
              -- can never gain manifest_blob_refs rows; left in the candidate
              -- set it would pin the readiness gate true forever and disable
              -- blob GC permanently.
              AND NOT EXISTS (
                    SELECT 1 FROM oci_manifest_refs omr_parent
                    WHERE omr_parent.repository_id = ot.repository_id
                      AND omr_parent.parent_digest = ot.manifest_digest
                )
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
        .map(|r| {
            BackfillCandidate::new(
                r.try_get("manifest_digest").unwrap_or_default(),
                r.try_get("repository_id").unwrap_or_default(),
                r.try_get("storage_backend").unwrap_or_default(),
                r.try_get("storage_path").unwrap_or_default(),
            )
        })
        .collect();
    Ok(candidates)
}

/// Blob-GC readiness gate (#1408; design from #1409 review, finding 3).
///
/// Returns `true` while any *live* image manifest (a tagged non-index
/// manifest, or a per-architecture child of a tagged index) still has
/// zero rows in `manifest_blob_refs` — i.e. a successful backfill has not
/// yet established the full live blob set.
///
/// Blob GC MUST NOT delete while this holds: a blob that looks
/// unreferenced may simply belong to a manifest whose refs have not been
/// backfilled yet (e.g. the startup backfill could not read some bodies
/// because object storage was briefly unreachable). Deleting it would
/// corrupt a live image. The check is self-healing — once refs are
/// complete (backfill finished, or the affected manifests were re-pushed
/// through the push handler) it returns `false` and GC resumes on the
/// next scheduler tick.
///
/// This is deliberately broader than [`select_unbackfilled_manifests`]:
/// backfill cannot safely import bare `oci_manifest_refs.child_digest` bodies
/// from shared storage, but blob GC must still treat those live children as
/// incomplete and force dry-run until refs are established by a re-push or the
/// parent index is untagged.
pub async fn any_live_manifest_missing_refs(db: &PgPool) -> sqlx::Result<bool> {
    sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM (
                SELECT ot.manifest_digest AS manifest_digest,
                       ot.repository_id AS repository_id
                FROM oci_tags ot
                WHERE ot.manifest_content_type NOT IN (
                        'application/vnd.oci.image.index.v1+json',
                        'application/vnd.docker.distribution.manifest.list.v2+json'
                    )
                  AND NOT EXISTS (
                        SELECT 1 FROM oci_manifest_refs omr_parent
                        WHERE omr_parent.repository_id = ot.repository_id
                          AND omr_parent.parent_digest = ot.manifest_digest
                    )
                UNION
                SELECT omr.child_digest AS manifest_digest,
                       omr.repository_id AS repository_id
                FROM oci_manifest_refs omr
                JOIN oci_tags ot_parent
                  ON ot_parent.repository_id = omr.repository_id
                 AND ot_parent.manifest_digest = omr.parent_digest
            ) AS live
            WHERE NOT EXISTS (
                SELECT 1 FROM manifest_blob_refs mbr
                WHERE mbr.manifest_digest = live.manifest_digest
                  AND mbr.repository_id = live.repository_id
            )
        )
        "#,
    )
    .fetch_one(db)
    .await
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
    let storage = registry
        .backend_for(&candidate.location())
        .map_err(backend_resolve_error)?;

    let body = storage
        .get(&candidate.storage_key())
        .await
        .map_err(storage_read_error)?;

    check_manifest_size(body.len())?;

    let inserted = crate::api::handlers::oci_v2::record_manifest_blob_refs(
        db,
        candidate.repository_id,
        &candidate.manifest_digest,
        &body,
    )
    .await
    .map_err(insert_rows_error)?;

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

    // -- BackfillStats accounting helpers -----------------------------------

    #[test]
    fn for_candidates_fixes_scanned_and_zeroes_counters() {
        let s = BackfillStats::for_candidates(7);
        assert_eq!(s.candidates_scanned, 7);
        assert_eq!(s.edges_inserted, 0);
        assert_eq!(s.candidates_failed, 0);
    }

    #[test]
    fn for_candidates_zero_is_all_zero() {
        let s = BackfillStats::for_candidates(0);
        assert_eq!(s.candidates_scanned, 0);
        assert_eq!(s.edges_inserted, 0);
        assert_eq!(s.candidates_failed, 0);
    }

    #[test]
    fn record_candidate_result_accumulates_inserted_edges() {
        let mut s = BackfillStats::for_candidates(3);
        s.record_candidate_result(&Ok(2));
        s.record_candidate_result(&Ok(5));
        assert_eq!(s.edges_inserted, 7);
        assert_eq!(s.candidates_failed, 0);
        // candidates_scanned is fixed up front, never touched by folding.
        assert_eq!(s.candidates_scanned, 3);
    }

    #[test]
    fn record_candidate_result_counts_failures() {
        let mut s = BackfillStats::for_candidates(3);
        s.record_candidate_result(&Err("boom".to_string()));
        s.record_candidate_result(&Ok(4));
        s.record_candidate_result(&Err("missing".to_string()));
        assert_eq!(s.candidates_failed, 2);
        assert_eq!(s.edges_inserted, 4);
        assert_eq!(s.candidates_scanned, 3);
    }

    #[test]
    fn record_candidate_result_ok_zero_is_noop_on_counts() {
        // A successfully-processed manifest that contributed no new edges
        // (e.g. all rows already present) must not be counted as a failure.
        let mut s = BackfillStats::for_candidates(1);
        s.record_candidate_result(&Ok(0));
        assert_eq!(s.edges_inserted, 0);
        assert_eq!(s.candidates_failed, 0);
    }

    // -- BackfillCandidate pure derivations ---------------------------------

    fn sample_candidate() -> BackfillCandidate {
        BackfillCandidate::new(
            "sha256:abc123".to_string(),
            Uuid::nil(),
            "filesystem".to_string(),
            "/var/lib/ak/repo".to_string(),
        )
    }

    #[test]
    fn candidate_new_wires_all_fields() {
        let c = sample_candidate();
        assert_eq!(c.manifest_digest, "sha256:abc123");
        assert_eq!(c.repository_id, Uuid::nil());
        assert_eq!(c.storage_backend, "filesystem");
        assert_eq!(c.storage_path, "/var/lib/ak/repo");
    }

    #[test]
    fn candidate_storage_key_prefixes_oci_manifests() {
        assert_eq!(
            sample_candidate().storage_key(),
            "oci-manifests/sha256:abc123"
        );
    }

    #[test]
    fn candidate_location_carries_backend_and_path() {
        let loc = sample_candidate().location();
        assert_eq!(loc.backend, "filesystem");
        assert_eq!(loc.path, "/var/lib/ak/repo");
    }

    // -- check_manifest_size cap --------------------------------------------

    #[test]
    fn check_manifest_size_accepts_small_and_boundary_bodies() {
        assert!(check_manifest_size(0).is_ok());
        assert!(check_manifest_size(1024).is_ok());
        // Exactly at the cap is allowed; only strictly-larger is rejected.
        assert!(check_manifest_size(MAX_IMAGE_MANIFEST_BYTES).is_ok());
    }

    #[test]
    fn check_manifest_size_rejects_oversized_body() {
        let err = check_manifest_size(MAX_IMAGE_MANIFEST_BYTES + 1)
            .expect_err("body over the cap must be rejected");
        assert!(err.contains("exceeds"));
        assert!(err.contains(&(MAX_IMAGE_MANIFEST_BYTES + 1).to_string()));
    }

    // -- per-stage skip-reason formatters -----------------------------------

    #[test]
    fn backend_resolve_error_describes_stage_and_cause() {
        let msg = backend_resolve_error("no such backend 's3'");
        assert_eq!(msg, "resolve storage backend: no such backend 's3'");
    }

    #[test]
    fn storage_read_error_describes_stage_and_cause() {
        let msg = storage_read_error("key not found");
        assert_eq!(msg, "read manifest from storage: key not found");
    }

    #[test]
    fn insert_rows_error_describes_stage_and_cause() {
        let msg = insert_rows_error("connection reset");
        assert_eq!(msg, "insert manifest_blob_refs rows: connection reset");
    }

    // -- readiness gate (#1408; DB-backed, skips without DATABASE_URL) -------

    /// `any_live_manifest_missing_refs` is the blob-GC readiness gate
    /// (design from #1409 review, finding 3). A live tagged image manifest
    /// with no `manifest_blob_refs` rows must make it return `true` so the
    /// scheduler skips the destructive blob-GC pass until the backfill (or
    /// an atomic push) has established the refs.
    #[tokio::test]
    async fn any_live_manifest_missing_refs_flags_unbackfilled_tag() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        // A tagged image manifest (non-index) with NO manifest_blob_refs.
        let manifest_digest = format!("sha256:{}", "4".repeat(64));
        sqlx::query(
            r#"
            INSERT INTO oci_tags (repository_id, name, tag, manifest_digest, manifest_content_type)
            VALUES ($1, 'gate/app', 'latest', $2, 'application/vnd.oci.image.manifest.v1+json')
            "#,
        )
        .bind(fixture.repo_id)
        .bind(&manifest_digest)
        .execute(&fixture.pool)
        .await
        .expect("insert tagged manifest");

        let missing = any_live_manifest_missing_refs(&fixture.pool)
            .await
            .expect("gate query runs");

        // Now record refs for it; the gate must clear (for this manifest).
        sqlx::query(
            r#"
            INSERT INTO manifest_blob_refs (manifest_digest, blob_digest, repository_id, kind)
            VALUES ($1, $2, $3, 'config')
            "#,
        )
        .bind(&manifest_digest)
        .bind(format!("sha256:{}", "5".repeat(64)))
        .bind(fixture.repo_id)
        .execute(&fixture.pool)
        .await
        .expect("insert ref");

        // Other concurrent test repos may still be unbackfilled, so we can
        // only assert this specific tag no longer appears as a candidate,
        // not the global flag. Re-scope via the candidate predicate.
        let still_candidate: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM oci_tags ot
            WHERE ot.repository_id = $1
              AND ot.manifest_digest = $2
              AND NOT EXISTS (
                SELECT 1 FROM manifest_blob_refs mbr
                WHERE mbr.manifest_digest = ot.manifest_digest
                  AND mbr.repository_id = ot.repository_id
              )
            "#,
        )
        .bind(fixture.repo_id)
        .bind(&manifest_digest)
        .fetch_one(&fixture.pool)
        .await
        .expect("scoped candidate count");

        fixture.teardown().await;

        assert!(
            missing,
            "a live tagged image manifest with no manifest_blob_refs must gate blob GC off"
        );
        assert_eq!(
            still_candidate, 0,
            "once refs are recorded the manifest must no longer be an unbackfilled candidate"
        );
    }

    /// C1 (#1409): a tagged manifest that is structurally an index (has
    /// children in `oci_manifest_refs`) but was pushed with a wrong/absent
    /// Content-Type must NOT appear as an unbackfilled image candidate. An
    /// index carries no blobs of its own, so it can never gain
    /// `manifest_blob_refs` rows; if it stayed in the candidate set it would
    /// be retried forever as an image manifest. The structural guard in
    /// [`select_unbackfilled_manifests`] excludes it regardless of its stored
    /// content-type.
    #[tokio::test]
    async fn select_unbackfilled_manifests_excludes_mislabeled_index() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let index_digest = format!("sha256:{}", "a".repeat(64));
        let child_digest = format!("sha256:{}", "b".repeat(64));

        // Tag the index with a NON-index content-type, so only the structural
        // guard (its oci_manifest_refs children), not the content-type filter,
        // can keep it out of the candidate set.
        sqlx::query(
            r#"
            INSERT INTO oci_tags (repository_id, name, tag, manifest_digest, manifest_content_type)
            VALUES ($1, 'c1/index', 'latest', $2, 'application/octet-stream')
            "#,
        )
        .bind(fixture.repo_id)
        .bind(&index_digest)
        .execute(&fixture.pool)
        .await
        .expect("insert mislabeled index tag");
        sqlx::query(
            r#"
            INSERT INTO oci_manifest_refs (parent_digest, child_digest, repository_id)
            VALUES ($1, $2, $3)
            "#,
        )
        .bind(&index_digest)
        .bind(&child_digest)
        .bind(fixture.repo_id)
        .execute(&fixture.pool)
        .await
        .expect("insert index child");

        let candidates = select_unbackfilled_manifests(&fixture.pool)
            .await
            .expect("candidate query runs");
        let gate_missing = any_live_manifest_missing_refs(&fixture.pool)
            .await
            .expect("gate query runs");

        assert!(
            !candidates
                .iter()
                .any(|c| c.manifest_digest == index_digest && c.repository_id == fixture.repo_id),
            "a tagged index with a non-index content-type must be excluded from image candidates; \
             otherwise it would pin the readiness gate forever and disable blob GC"
        );
        assert!(
            !candidates
                .iter()
                .any(|c| c.manifest_digest == child_digest && c.repository_id == fixture.repo_id),
            "a bare child edge must not authorize backfilling that child from shared storage"
        );
        assert!(
            gate_missing,
            "a live child edge without manifest_blob_refs must still keep destructive blob GC gated"
        );

        sqlx::query(
            r#"
            INSERT INTO oci_tags (repository_id, name, tag, manifest_digest, manifest_content_type)
            VALUES ($1, 'c1/index', $2, $2, 'application/vnd.oci.image.manifest.v1+json')
            "#,
        )
        .bind(fixture.repo_id)
        .bind(&child_digest)
        .execute(&fixture.pool)
        .await
        .expect("insert child tag");

        let candidates = select_unbackfilled_manifests(&fixture.pool)
            .await
            .expect("candidate query runs after child tag");

        fixture.teardown().await;

        assert!(
            candidates
                .iter()
                .any(|c| c.manifest_digest == child_digest && c.repository_id == fixture.repo_id),
            "a child manifest that was actually pushed/tagged in this repo must still be \
             enumerated as an unbackfilled candidate"
        );
    }
}
