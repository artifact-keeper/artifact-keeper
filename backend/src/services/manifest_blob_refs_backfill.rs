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
//! This module walks the image manifests safely backfillable from this
//! repository's own corpus — directly tagged manifests whose content-type is
//! NOT an image index, plus the children of tagged indexes whose manifest body
//! this repository actually holds (#3285) — that
//! have zero `manifest_blob_refs` rows, loads each manifest body from storage,
//! parses the JSON, and inserts the
//! (manifest, blob, repo, kind) edges. The backfill is idempotent
//! (`ON CONFLICT DO NOTHING`) and best-effort: a missing storage file or
//! a malformed manifest is logged at WARN and skipped; it does not stop
//! the backfill or fail startup.
//!
//! A *bare* `oci_manifest_refs.child_digest` is intentionally not a backfill
//! source: an index body can reference a digest whose manifest body was never
//! uploaded to this repository. On shared cloud backends, loading that digest
//! from `oci-manifests/<digest>` would import another repository's manifest
//! metadata and later authorize digest fallback through the wrong repository.
//! A child whose manifest body *was* committed into this repository — proven by
//! a live `artifacts` row at `oci-manifests/<child_digest>` under that
//! repository id — carries no such risk and IS backfilled (#3285); see
//! [`LIVE_IMAGE_MANIFEST_SET_SQL`].
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

/// The set of *live* image manifests, shared verbatim by the backfill
/// candidate query and the blob-GC readiness gate (#3285).
///
/// **The two must be the same set.** The gate is "does any live image manifest
/// still lack `manifest_blob_refs` rows"; the backfill is "populate refs for
/// every live image manifest". If the gate's set is any wider than the
/// backfill's, the members of the difference can never gain refs and the gate
/// is closed forever — `BLOB_GC_ENABLED=true` silently becomes a no-op while
/// object storage grows without bound. That is exactly what #3285 reported: the
/// gate counted children of tagged indexes that the candidate query never
/// selected, so 365 manifests held blob GC off permanently with no operator
/// remedy. Deriving both from this one fragment makes the failure mode
/// unrepresentable.
///
/// Two arms, both filtered to manifests that can actually own blobs:
///
/// 1. **Directly tagged manifests.** `oci_tags` rows whose content-type is not
///    an image index and which are not *structurally* an index. The structural
///    guard (#1409 C1) catches an index pushed with a wrong/absent
///    Content-Type: it has no blobs of its own, so it could never gain
///    `manifest_blob_refs` rows and would pin the gate forever.
///
/// 2. **Children of tagged indexes whose manifest body is local.** A bare
///    `oci_manifest_refs` edge only proves that some parent index *references*
///    the digest — on a shared cloud namespace, blindly reading
///    `oci-manifests/<digest>` could import another repository's manifest. The
///    `artifacts` join is the locality proof: a live row in THIS repository at
///    exactly that storage key means this repository committed that manifest
///    body (both the push path and the proxy path write it), so reading it back
///    is safe. The same structural + content-type guards are applied so a
///    nested index cannot slip in.
///
/// Consequently a child that is merely *referenced* — the normal steady state
/// for a proxy cache, which only fetches the architecture actually pulled —
/// is in neither set. It cannot be backfilled (there is no local body to
/// parse) and it no longer gates: with no manifest body there are no local
/// blobs attributable to it that a sweep could wrongly reclaim.
const LIVE_IMAGE_MANIFEST_SET_SQL: &str = r#"
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
    JOIN artifacts a
      ON a.repository_id = omr.repository_id
     AND a.storage_key = 'oci-manifests/' || omr.child_digest
     AND a.is_deleted = false
    WHERE a.content_type NOT IN (
            'application/vnd.oci.image.index.v1+json',
            'application/vnd.docker.distribution.manifest.list.v2+json'
        )
      AND NOT EXISTS (
            SELECT 1 FROM oci_manifest_refs omr_child
            WHERE omr_child.repository_id = omr.repository_id
              AND omr_child.parent_digest = omr.child_digest
        )
"#;

// Pin the `oci-manifests/` literal embedded above to the Rust constant the
// candidate's `storage_key()` builds from, so the locality join can never
// address a different key space than the read it authorizes.
const _: () = assert!(crate::storage::keys::prefix_matches("oci-manifests/"));

/// The *un-backfilled live manifest* relation: [`LIVE_IMAGE_MANIFEST_SET_SQL`]
/// restricted to members with zero `manifest_blob_refs` rows, exposed under
/// `alias` with columns `manifest_digest` / `repository_id`.
///
/// Every consumer — the backfill candidate query, the readiness gate, and the
/// operator diagnostic — builds its FROM clause from this one function. That is
/// what makes "the gate can only be closed by something the backfill selects"
/// a structural property rather than a convention (#3285).
fn unbackfilled_live_manifests(alias: &str) -> String {
    format!(
        r#"(
            SELECT u.manifest_digest AS manifest_digest,
                   u.repository_id AS repository_id
            FROM ({live}) AS u
            WHERE NOT EXISTS (
                    SELECT 1 FROM manifest_blob_refs mbr
                    WHERE mbr.manifest_digest = u.manifest_digest
                      AND mbr.repository_id = u.repository_id
                )
        ) AS {alias}"#,
        live = LIVE_IMAGE_MANIFEST_SET_SQL,
    )
}

/// SQL for [`select_unbackfilled_manifests`]. Pure builder so the query text is
/// assertable without a database.
fn candidate_query_sql() -> String {
    format!(
        r#"
        SELECT DISTINCT ON (c.manifest_digest, c.repository_id)
            c.manifest_digest AS manifest_digest,
            c.repository_id AS repository_id,
            r.storage_backend AS storage_backend,
            r.storage_path AS storage_path
        FROM {rel}
        JOIN repositories r ON r.id = c.repository_id
        "#,
        rel = unbackfilled_live_manifests("c"),
    )
}

/// SQL for [`any_live_manifest_missing_refs`]. Pure builder, see
/// [`candidate_query_sql`].
fn gate_query_sql() -> String {
    format!(
        "SELECT EXISTS (SELECT 1 FROM {rel})",
        rel = unbackfilled_live_manifests("live"),
    )
}

/// SQL for [`list_live_manifests_missing_refs`]. Pure builder, see
/// [`candidate_query_sql`].
fn blocker_query_sql() -> String {
    format!(
        r#"
        SELECT live.manifest_digest AS manifest_digest,
               live.repository_id AS repository_id
        FROM {rel}
        LIMIT $1
        "#,
        rel = unbackfilled_live_manifests("live"),
    )
}

/// Select the distinct (manifest_digest, repository_id) tuples for live image
/// manifests that have zero rows in `manifest_blob_refs` and are safe to
/// backfill from storage — i.e. [`LIVE_IMAGE_MANIFEST_SET_SQL`] restricted by
/// [`missing_refs_predicate`].
///
/// We pull `storage_backend` / `storage_path` from the repositories table
/// along the way so the per-candidate work can resolve the correct backend
/// without a second query. `DISTINCT ON` deduplicates a digest that is tagged
/// under multiple names in the same repository; the first row wins, and since
/// all rows for the same (digest, repo) point at the same manifest body, that
/// is fine.
async fn select_unbackfilled_manifests(db: &PgPool) -> sqlx::Result<Vec<BackfillCandidate>> {
    let rows = sqlx::query(sqlx::AssertSqlSafe(&*candidate_query_sql()))
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
/// Returns `true` while any *live* image manifest — a tagged non-index
/// manifest, or a per-architecture child of a tagged index whose body this
/// repository actually holds — still has zero rows in `manifest_blob_refs`,
/// i.e. a successful backfill has not yet established the full live blob set.
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
/// This is evaluated over exactly [`LIVE_IMAGE_MANIFEST_SET_SQL`], the same
/// set [`select_unbackfilled_manifests`] enumerates, so every manifest that
/// can close this gate is also one the backfill can open it with (#3285).
pub async fn any_live_manifest_missing_refs(db: &PgPool) -> sqlx::Result<bool> {
    sqlx::query_scalar::<_, bool>(sqlx::AssertSqlSafe(&*gate_query_sql()))
        .fetch_one(db)
        .await
}

/// Bounded operator diagnostic for a closed readiness gate (#3285): the
/// `(manifest_digest, repository_id)` pairs currently holding blob GC off.
///
/// Reported by the reporter's own request — before this, diagnosing a stuck
/// gate meant reconstructing both queries by hand against the database. Capped
/// at `limit` rows so a large stuck corpus cannot produce an unbounded log
/// line or an unbounded result set.
pub async fn list_live_manifests_missing_refs(
    db: &PgPool,
    limit: i64,
) -> sqlx::Result<Vec<(String, Uuid)>> {
    let rows = sqlx::query(sqlx::AssertSqlSafe(&*blocker_query_sql()))
        .bind(limit)
        .fetch_all(db)
        .await?;

    Ok(rows
        .into_iter()
        .map(|r| {
            (
                r.try_get("manifest_digest").unwrap_or_default(),
                r.try_get("repository_id").unwrap_or_default(),
            )
        })
        .collect())
}

/// How many gate-blocking manifests [`describe_gate_blockers`] names in one log
/// line. Enough to spot the pattern (one bad repo, one bad index) without
/// flooding the log every scheduler tick.
pub const GATE_BLOCKER_SAMPLE_LIMIT: i64 = 20;

/// Render a gate-blocker sample as a single log-friendly string. Pure, so the
/// operator-facing wording is unit-testable without a database.
pub fn describe_gate_blockers(blockers: &[(String, Uuid)]) -> String {
    if blockers.is_empty() {
        return "none (the gate query found no blocking manifest)".to_string();
    }
    blockers
        .iter()
        .map(|(digest, repo)| format!("{digest}@{repo}"))
        .collect::<Vec<_>>()
        .join(", ")
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
        // The gate is instance-wide, so a bare boolean says nothing about THIS
        // fixture while other tests share the database. Scope both sides to the
        // fixture's repository and compare them directly — that comparison is
        // the #3285 invariant (gate set == candidate set).
        let blockers = list_live_manifests_missing_refs(&fixture.pool, 1_000_000)
            .await
            .expect("gate blocker listing runs");

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
        // #3285: and therefore it must not gate either. A proxy cache that only
        // fetched linux/amd64 legitimately references an arm64 child it will
        // never hold; while that child gated, BLOB_GC_ENABLED=true was a
        // permanent no-op on every proxy-backed registry.
        assert!(
            !blockers
                .iter()
                .any(|(d, r)| *d == child_digest && *r == fixture.repo_id),
            "a child with no local manifest body cannot be backfilled, so it must not hold the \
             readiness gate closed (#3285)"
        );

        // Now give the child a live artifacts row at its manifest storage key —
        // the locality proof that this repository committed the body. It must
        // become a candidate WITHOUT needing a tag of its own (index children
        // never carry one), and it must gate until its refs are recorded.
        sqlx::query(
            r#"
            INSERT INTO artifacts
                (repository_id, path, name, version, size_bytes, checksum_sha256,
                 content_type, storage_key)
            VALUES ($1, $2, $3, $4, 1, $5, 'application/vnd.oci.image.manifest.v1+json', $6)
            "#,
        )
        .bind(fixture.repo_id)
        .bind(format!("v2/c1/index/manifests/{child_digest}"))
        .bind(format!("c1/index:{child_digest}"))
        .bind(&child_digest)
        .bind(child_digest.trim_start_matches("sha256:"))
        .bind(format!("oci-manifests/{child_digest}"))
        .execute(&fixture.pool)
        .await
        .expect("insert child manifest artifact row");

        let candidates = select_unbackfilled_manifests(&fixture.pool)
            .await
            .expect("candidate query runs after the child body is local");
        let blockers = list_live_manifests_missing_refs(&fixture.pool, 1_000_000)
            .await
            .expect("gate blocker listing runs after the child body is local");

        fixture.teardown().await;

        assert!(
            candidates
                .iter()
                .any(|c| c.manifest_digest == child_digest && c.repository_id == fixture.repo_id),
            "an index child whose manifest body is committed in this repository must be \
             enumerated as an unbackfilled candidate (#3285); before the fix only tagged \
             manifests were, so index children could never gain refs"
        );
        assert!(
            blockers
                .iter()
                .any(|(d, r)| *d == child_digest && *r == fixture.repo_id),
            "and it must gate until its refs are recorded"
        );
    }

    /// #3285 core invariant, asserted structurally so it holds regardless of
    /// database contents: the readiness gate and the backfill candidate set are
    /// derived from the SAME live-manifest fragment under the SAME missing-refs
    /// predicate. Any divergence reintroduces a gate that a successful backfill
    /// can never open.
    #[test]
    fn gate_and_candidate_queries_share_one_live_set_definition() {
        // Byte-identical relation text, differing only in the outer alias:
        // neither query can range over a manifest the other cannot see.
        let relation = unbackfilled_live_manifests("c");
        assert_eq!(
            relation.replace(") AS c", ") AS live"),
            unbackfilled_live_manifests("live"),
            "the un-backfilled live relation must depend only on its alias"
        );
        for (name, sql) in [
            ("candidate", candidate_query_sql()),
            ("gate", gate_query_sql()),
            ("blocker", blocker_query_sql()),
        ] {
            let alias_free = sql.replace(") AS live", ") AS c");
            assert!(
                alias_free.contains(&relation),
                "the {name} query must be built from the shared un-backfilled live relation \
                 (#3285); a wider gate than candidate set can never be opened by a backfill"
            );
        }
    }

    #[test]
    fn candidate_query_carries_the_backend_columns_the_read_needs() {
        let sql = candidate_query_sql();
        assert!(sql.contains("r.storage_backend"));
        assert!(sql.contains("r.storage_path"));
        assert!(sql.contains("JOIN repositories r ON r.id = c.repository_id"));
        assert!(
            sql.contains("DISTINCT ON (c.manifest_digest, c.repository_id)"),
            "a digest tagged under several names in one repo must be visited once"
        );
    }

    #[test]
    fn blocker_query_is_bounded() {
        assert!(
            blocker_query_sql().contains("LIMIT $1"),
            "the operator diagnostic must never return an unbounded result set"
        );
    }

    #[test]
    fn live_set_backfills_index_children_only_with_a_local_body() {
        // The locality proof: the child arm joins `artifacts` on this
        // repository's own row at the child's manifest storage key. Without it
        // a bare `oci_manifest_refs` edge would authorize reading another
        // repository's manifest off a shared cloud namespace.
        assert!(
            LIVE_IMAGE_MANIFEST_SET_SQL.contains("omr.child_digest"),
            "index children must be reachable by the live set (#3285)"
        );
        assert!(
            LIVE_IMAGE_MANIFEST_SET_SQL
                .contains("a.storage_key = 'oci-manifests/' || omr.child_digest"),
            "the child arm must require a live artifacts row in the SAME repository at the \
             child's manifest storage key"
        );
        assert!(
            LIVE_IMAGE_MANIFEST_SET_SQL.contains("a.repository_id = omr.repository_id"),
            "the locality join must be repository-scoped"
        );
        assert!(
            LIVE_IMAGE_MANIFEST_SET_SQL.contains("a.is_deleted = false"),
            "a soft-deleted manifest row is not a local body"
        );
        // Nested indexes own no blobs; letting one in would pin the gate.
        assert!(
            LIVE_IMAGE_MANIFEST_SET_SQL.contains("omr_child.parent_digest = omr.child_digest"),
            "the structural index guard must apply to the child arm too"
        );
    }

    #[test]
    fn unbackfilled_relation_excludes_manifests_that_already_have_refs() {
        let rel = unbackfilled_live_manifests("live");
        assert!(rel.contains("NOT EXISTS"));
        assert!(rel.contains("FROM manifest_blob_refs mbr"));
        assert!(rel.contains("mbr.manifest_digest = u.manifest_digest"));
        assert!(rel.contains("mbr.repository_id = u.repository_id"));
        assert!(
            rel.trim_end().ends_with(") AS live"),
            "the relation must expose the caller's alias"
        );
    }

    // -- operator diagnostic (#3285) ----------------------------------------

    #[test]
    fn describe_gate_blockers_names_digest_and_repository() {
        let repo = Uuid::nil();
        let out = describe_gate_blockers(&[
            ("sha256:aaa".to_string(), repo),
            ("sha256:bbb".to_string(), repo),
        ]);
        assert_eq!(out, format!("sha256:aaa@{repo}, sha256:bbb@{repo}"));
    }

    #[test]
    fn describe_gate_blockers_empty_is_explicit() {
        assert!(describe_gate_blockers(&[]).contains("none"));
    }

    // The sample is logged once per scheduler tick; keep it small enough to
    // read and large enough to show a pattern.
    const _SAMPLE_SANE: () =
        assert!(GATE_BLOCKER_SAMPLE_LIMIT >= 5 && GATE_BLOCKER_SAMPLE_LIMIT <= 100);
}
