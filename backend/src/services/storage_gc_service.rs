//! Storage garbage collection service.
//!
//! Finds soft-deleted artifacts whose storage keys are no longer referenced
//! by any live artifact, deletes the physical storage files, and hard-deletes
//! the artifact records from the database.

use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::sync::Arc;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::storage::{StorageBackend, StorageLocation, StorageRegistry};

const ABANDONED_OCI_UPLOAD_TTL_SQL: &str = "INTERVAL '24 hours'";
const ABANDONED_OCI_UPLOAD_SCAN_LIMIT: i64 = 1000;
const OCI_UPLOAD_CLEANUP_KEY_SCAN_LIMIT: i64 = 1000;

/// SQL fragment expressing the orphan-storage-key predicate.
///
/// A storage key is "orphaned" when:
/// 1. Every artifact pointing at it is soft-deleted (no live artifact shares
///    the key);
/// 2. It is not protected by an `oci_tags` row (manifests still tagged);
/// 3. It is not protected by an `oci_blobs` row (named blobs);
/// 4. It is not the per-architecture child of a still-tagged OCI image index
///    (`oci_manifest_refs` joined against `oci_tags`; see migration 092).
///
/// The fragment expects two bindings: the outer `artifacts` row aliased
/// `a` and the outer `repositories` row aliased `r`. Callers either inline
/// it in the main SELECT (where `a`/`r` come from the outer joins) or use
/// it under [`is_still_orphan`] to re-check a single (storage_key,
/// repository_id) tuple under a row-level lock.
///
/// Both the initial SELECT and the per-key re-check feed off this same
/// constant so the two checks cannot drift out of sync. Drift between the
/// two predicates is what makes a TOCTOU window real in the first place
/// (#1180); keeping them literally identical is the cheap structural
/// guarantee that they stay aligned.
const ORPHAN_PREDICATE_SQL: &str = r#"
a.is_deleted = true
AND NOT EXISTS (
    SELECT 1 FROM artifacts a2
    WHERE a2.storage_key = a.storage_key
      AND a2.is_deleted = false
)
AND NOT EXISTS (
    SELECT 1
    FROM oci_tags ot
    JOIN repositories otr ON otr.id = ot.repository_id
    WHERE a.storage_key LIKE 'oci-manifests/%'
      AND ot.manifest_digest = SUBSTRING(
        a.storage_key FROM LENGTH('oci-manifests/') + 1
      )
      AND otr.storage_backend = r.storage_backend
      AND (
        r.storage_backend <> 'filesystem'
        OR otr.storage_path = r.storage_path
      )
)
AND NOT EXISTS (
    SELECT 1
    FROM oci_blobs ob
    JOIN repositories obr ON obr.id = ob.repository_id
    WHERE a.storage_key LIKE 'oci-blobs/%'
      AND ob.digest = SUBSTRING(
        a.storage_key FROM LENGTH('oci-blobs/') + 1
      )
      AND obr.storage_backend = r.storage_backend
      AND (
        r.storage_backend <> 'filesystem'
        OR obr.storage_path = r.storage_path
      )
)
AND NOT EXISTS (
    SELECT 1
    FROM oci_manifest_refs omr
    JOIN oci_tags ot2 ON ot2.repository_id = omr.repository_id
                     AND ot2.manifest_digest = omr.parent_digest
    JOIN repositories omrr ON omrr.id = omr.repository_id
    WHERE a.storage_key LIKE 'oci-manifests/%'
      AND omr.child_digest = SUBSTRING(
        a.storage_key FROM LENGTH('oci-manifests/') + 1
      )
      AND omrr.storage_backend = r.storage_backend
      AND (
        r.storage_backend <> 'filesystem'
        OR omrr.storage_path = r.storage_path
      )
)
"#;

/// Minimum age (seconds) a blob must reach before [`StorageGcService::run_blob_gc`]
/// will consider it for deletion (#1408).
///
/// Pushes do not commit `oci_blobs` and `manifest_blob_refs` in a single
/// transaction: blobs are uploaded one by one through their own PUT
/// requests, then the manifest is pushed at the end. Between the blob
/// upload and the manifest push, the row exists with no live reference —
/// it is technically orphan but only because the client is mid-push. A
/// grace period absorbs the normal push window so blob GC can stay cheap
/// (no global advisory lock) while still being safe in practice.
/// Twenty-four hours is far above the longest realistic
/// upload-then-manifest gap and short enough that abandoned uploads do
/// not waste storage indefinitely. The bound is pinned by compile-time
/// `assert!`s in the test module to keep accidental drift out of band.
pub(crate) const MIN_BLOB_AGE_SECS: u64 = 24 * 60 * 60;

/// SQL fragment: `EXISTS (...)` — true when some `manifest_blob_refs` row
/// still protects the outer blob row aliased `ob` (joined to its
/// repository aliased `r`). Negate it to get "this blob is orphaned".
///
/// Scope mirrors the cloud/filesystem branch of [`ORPHAN_PREDICATE_SQL`],
/// because blob storage is content-addressed under `oci-blobs/<digest>`:
/// - Cloud backends (S3/Azure/GCS) share one bucket, so that key resolves
///   to the SAME physical object for every repo on the backend. A
///   reference from ANY same-backend repo must protect it; deleting on the
///   first orphan `(repo, digest)` row would destroy a blob other repos
///   still serve — the cross-repo dedup incident this table guards (57
///   blobs across 85 tags broken in prod by a per-`(repo,digest)`
///   reconciler).
/// - Filesystem repos each root their own tree at `storage_path`, so the
///   key resolves to a DISTINCT file per repo. Only a reference whose repo
///   shares this `storage_path` protects this repo's copy; another repo's
///   copy is independently reclaimable.
///
/// The outer query must expose `ob` (oci_blobs) and `r` (repositories) so
/// the initial scan and the locked re-check feed off one definition and
/// cannot drift (the #1180 lesson, applied to blob GC).
const BLOB_PROTECTED_BY_REFS_SQL: &str = r#"
    EXISTS (
        SELECT 1
        FROM manifest_blob_refs mbr
        JOIN repositories mr ON mr.id = mbr.repository_id
        WHERE mbr.blob_digest = ob.digest
          AND mr.storage_backend = r.storage_backend
          AND (
            r.storage_backend <> 'filesystem'
            OR mr.storage_path = r.storage_path
          )
    )
"#;

/// Result of a storage GC run.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct StorageGcResult {
    pub dry_run: bool,
    pub storage_keys_deleted: i64,
    pub artifacts_removed: i64,
    pub bytes_freed: i64,
    pub errors: Vec<String>,
}

/// Default grace window (hours) used to classify "recent" OCI blobs in the
/// reclaimable report. A blob younger than this is excluded from the
/// `aged_*` figures because its parent manifest push may still be in
/// flight (the upload writes the `oci_blobs` row before the manifest that
/// references it commits). This mirrors the grace-window guard that the
/// future blob GC sweep will use, but here it only affects *reporting* —
/// nothing is ever deleted by this path.
pub const BLOB_REPORT_GRACE_HOURS_DEFAULT: i64 = 24;

/// Per-repository row in the OCI blob footprint report.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq)]
pub struct OciBlobRepoFootprint {
    /// Repository id owning these `oci_blobs` rows.
    pub repository_id: Uuid,
    /// Number of `oci_blobs` rows attributed to this repository.
    pub blob_rows: i64,
    /// Sum of `oci_blobs.size_bytes` for this repository's rows. Because OCI
    /// blob storage is content-addressed and deduplicated across repos, the
    /// same physical bytes can be counted under more than one repository
    /// here; see [`OciBlobFootprintReport::physical_bytes`] for the
    /// dedup-aware total.
    pub logical_bytes: i64,
}

/// Read-only OCI blob storage footprint report (issue #1408).
///
/// This is a **reporting-only** view. It performs no deletion and takes no
/// locks. It surfaces how much storage the tracked `oci_blobs` rows
/// account for so operators can see the magnitude of un-reclaimed blob
/// layers before any garbage-collection mechanism is enabled.
///
/// It deliberately does NOT attempt to classify which blobs are
/// "reclaimable orphans": that requires a manifest -> blob reference table
/// that does not yet exist in the schema, and any per-`(repository_id,
/// digest)` orphan heuristic would mis-handle the cross-repo dedup case
/// (multiple `oci_blobs` rows, one physical object) and report in-use
/// blobs as reclaimable. The numbers here are exact aggregates only.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq)]
pub struct OciBlobFootprintReport {
    /// Total number of `oci_blobs` rows across all repositories.
    pub total_blob_rows: i64,
    /// Number of distinct blob digests (content-addressed identities). When
    /// this is smaller than `total_blob_rows`, the difference is cross-repo
    /// deduplication: rows that share one physical storage object.
    pub distinct_digests: i64,
    /// Sum of `size_bytes` over every `oci_blobs` row. Double-counts
    /// deduplicated blobs once per referencing repository.
    pub logical_bytes: i64,
    /// Sum of `size_bytes` counting each distinct digest exactly once. This
    /// approximates the physical bytes occupied in the storage backend.
    pub physical_bytes: i64,
    /// Grace window (hours) applied to the `aged_*` figures below.
    pub grace_hours: i64,
    /// Distinct digests older than `grace_hours` (eligible to be *considered*
    /// by a future GC sweep once a reference table exists). Reporting only.
    pub aged_distinct_digests: i64,
    /// Physical bytes (distinct-digest) older than `grace_hours`.
    pub aged_physical_bytes: i64,
    /// Per-repository logical footprint, largest `logical_bytes` first.
    pub per_repository: Vec<OciBlobRepoFootprint>,
}

/// Storage garbage collection service.
///
/// For cloud backends (S3/Azure/GCS), the shared storage instance handles all
/// deletions directly since storage keys are globally unique. For filesystem,
/// each repository has its own storage directory, so the service resolves the
/// correct backend per repo using the repository's `storage_path`.
pub struct StorageGcService {
    db: PgPool,
    storage_registry: Arc<StorageRegistry>,
}

#[derive(Debug)]
struct AbandonedOciUploadSession {
    id: Uuid,
    location: StorageLocation,
    storage_keys: Vec<String>,
    bytes_received: i64,
}

#[derive(Debug)]
struct OciUploadCleanupKey {
    id: i64,
    location: StorageLocation,
    storage_key: String,
}

impl StorageGcService {
    pub fn new(db: PgPool, storage_registry: Arc<StorageRegistry>) -> Self {
        Self {
            db,
            storage_registry,
        }
    }

    /// Get the storage backend for a given storage location.
    pub(crate) fn storage_for_location(
        &self,
        location: &StorageLocation,
    ) -> Result<Arc<dyn StorageBackend>> {
        self.storage_registry.backend_for(location)
    }

    /// Run garbage collection on orphaned storage keys.
    ///
    /// Finds storage keys referenced only by soft-deleted artifacts (no live
    /// artifact shares the same key), deletes the physical file from the
    /// correct storage backend, then hard-deletes the database records.
    ///
    /// Each per-key deletion runs inside its own transaction. The
    /// transaction first re-verifies the orphan predicate under
    /// `FOR UPDATE` row locks so a concurrent push that lands between the
    /// outer SELECT and this point does not lose its newly-written
    /// references (#1180). The physical storage delete happens while the
    /// row lock is held but is not itself transactional; storage backends
    /// are not part of Postgres' atomic write boundary. The DB row deletes
    /// (`promotion_approvals` + `artifacts`) happen inside the same
    /// transaction so the row lock prevents any racing writer from
    /// resurrecting the rows before they are hard-deleted.
    pub async fn run_gc(&self, dry_run: bool) -> Result<StorageGcResult> {
        let orphans = self.select_orphans().await?;

        let mut result = empty_gc_result(dry_run);

        if dry_run {
            for row in &orphans {
                let bytes: i64 = row.try_get("total_bytes").unwrap_or(0);
                let count: i64 = row.try_get("artifact_count").unwrap_or(0);
                accumulate_dry_run(&mut result, bytes, count);
            }
        } else {
            for row in &orphans {
                let storage_key: String = row.try_get("storage_key").unwrap_or_default();
                let storage_backend: String = row.try_get("storage_backend").unwrap_or_default();
                let storage_path: String = row.try_get("storage_path").unwrap_or_default();
                let bytes: i64 = row.try_get("total_bytes").unwrap_or(0);
                let count: i64 = row.try_get("artifact_count").unwrap_or(0);

                // Resolve the correct storage backend for this repo
                let location = StorageLocation {
                    backend: storage_backend.clone(),
                    path: storage_path.clone(),
                };
                let storage = match self.storage_for_location(&location) {
                    Ok(s) => s,
                    Err(e) => {
                        let msg = format_gc_error("resolve storage", &storage_key, &e.to_string());
                        tracing::warn!("{}", msg);
                        result.errors.push(msg);
                        continue;
                    }
                };

                // Begin a per-key transaction. The transaction holds row locks
                // on the matching `artifacts` rows from `is_still_orphan`'s
                // FOR UPDATE clause through the storage delete and the DB row
                // deletes. Any writer trying to flip `is_deleted = false` or
                // insert a new reference is blocked behind the lock.
                let mut tx = match self.db.begin().await {
                    Ok(t) => t,
                    Err(e) => {
                        let msg = format_gc_error("begin gc tx", &storage_key, &e.to_string());
                        tracing::warn!("{}", msg);
                        result.errors.push(msg);
                        continue;
                    }
                };

                // Re-verify the orphan predicate inside the tx, taking a row
                // lock on the matching artifact rows. If a concurrent push has
                // landed a live reference (`oci_tags`, `oci_blobs`,
                // `oci_manifest_refs` parent re-tag, or a new live artifact
                // sharing the key), this returns `false` and the GC pass
                // skips the key to revisit on the next run.
                match is_still_orphan(&mut tx, &storage_key, &storage_backend, &storage_path).await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        let _ = tx.rollback().await;
                        tracing::debug!(
                            storage_key = storage_key.as_str(),
                            "GC skipped key: no longer orphan after row-lock re-check"
                        );
                        continue;
                    }
                    Err(e) => {
                        let _ = tx.rollback().await;
                        let msg = format_gc_error("re-check orphan", &storage_key, &e.to_string());
                        tracing::warn!("{}", msg);
                        result.errors.push(msg);
                        continue;
                    }
                }

                // Storage delete is not transactional, but it happens while
                // the row lock is still held by `tx`. A racing pusher cannot
                // begin re-using this storage key until we commit/rollback.
                if let Err(e) = storage.delete(&storage_key).await {
                    let _ = tx.rollback().await;
                    let msg = format_gc_error("delete storage key", &storage_key, &e.to_string());
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    // Skip DB cleanup if storage delete fails
                    continue;
                }

                // Delete promotion_approvals (no CASCADE on this FK)
                if let Err(e) = sqlx::query(
                    r#"
                    DELETE FROM promotion_approvals
                    WHERE artifact_id IN (
                        SELECT id FROM artifacts
                        WHERE storage_key = $1 AND is_deleted = true
                    )
                    "#,
                )
                .bind(&storage_key)
                .execute(&mut *tx)
                .await
                {
                    let _ = tx.rollback().await;
                    let msg =
                        format_gc_error("delete promotion_approvals", &storage_key, &e.to_string());
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }

                // Hard-delete artifact records (cascades to child tables)
                if let Err(e) = sqlx::query(
                    "DELETE FROM artifacts WHERE storage_key = $1 AND is_deleted = true",
                )
                .bind(&storage_key)
                .execute(&mut *tx)
                .await
                {
                    let _ = tx.rollback().await;
                    let msg =
                        format_gc_error("hard-delete artifacts", &storage_key, &e.to_string());
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }

                if let Err(e) = tx.commit().await {
                    let msg = format_gc_error("commit gc tx", &storage_key, &e.to_string());
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }

                record_gc_success(&mut result, bytes, count);
            }
        }

        // Run each OCI cleanup sweep independently so a failure in one does
        // not skip the others. Each sweep already isolates per-key errors
        // into `result.errors`; here we capture a failure of the sweep's
        // own setup query (e.g. the candidate SELECT) the same way instead
        // of `?`-propagating out of run_gc and aborting later sweeps.
        if let Err(e) = self
            .cleanup_abandoned_oci_uploads(dry_run, &mut result)
            .await
        {
            let msg = format_gc_error(
                "run abandoned OCI upload cleanup",
                "<sweep>",
                &e.to_string(),
            );
            tracing::warn!("{}", msg);
            result.errors.push(msg);
        }
        if let Err(e) = self
            .cleanup_unreferenced_oci_upload_keys(dry_run, &mut result)
            .await
        {
            let msg = format_gc_error(
                "run unreferenced OCI upload cleanup-key sweep",
                "<sweep>",
                &e.to_string(),
            );
            tracing::warn!("{}", msg);
            result.errors.push(msg);
        }
        if let Err(e) = self
            .reap_pending_oci_upload_cleanup_keys(dry_run, &mut result)
            .await
        {
            let msg = format_gc_error(
                "run pending OCI upload cleanup-key reaper",
                "<sweep>",
                &e.to_string(),
            );
            tracing::warn!("{}", msg);
            result.errors.push(msg);
        }

        if result.storage_keys_deleted > 0 {
            tracing::info!(
                "Storage GC: deleted {} keys, removed {} artifacts, freed {} bytes",
                result.storage_keys_deleted,
                result.artifacts_removed,
                result.bytes_freed
            );
        }

        Ok(result)
    }

    /// Reclaim OCI blob layers that no live manifest references (#1408).
    ///
    /// Deletion design originated in #1409; this rebuilds it on top of the
    /// merged `manifest_blob_refs` table + backfill (#1641/#1635).
    ///
    /// Iterates `oci_blobs` rows whose digest has zero matching rows in
    /// `manifest_blob_refs` and deletes both the storage object and the DB
    /// row.
    ///
    /// The orphan predicate is **backend-aware** (see
    /// [`BLOB_PROTECTED_BY_REFS_SQL`]). Blob storage is content-addressed
    /// under `oci-blobs/<digest>`: on cloud backends (S3/Azure/GCS) that
    /// key is one shared object across every repo on the bucket, so a
    /// reference from ANY same-backend repo protects it and orphan-ness is
    /// scoped per digest cross-repo — deleting per `(repo, digest)` would
    /// destroy a blob other repos still serve (`BLOB_UNKNOWN` on pull). On
    /// filesystem each repo roots its own tree, so the key is a distinct
    /// file per repo and orphan-ness is scoped to the same `storage_path`.
    /// This mirrors the cloud/filesystem branch of `ORPHAN_PREDICATE_SQL`.
    ///
    /// Grace period (`MIN_BLOB_AGE_SECS`) shields in-flight pushes: a
    /// client first uploads blobs, then PUTs the manifest, which writes the
    /// matching `manifest_blob_refs` rows. Between those two steps the blob
    /// is "orphan" in the strict sense; skipping rows younger than the
    /// grace period covers the typical push window without serializing push
    /// throughput on a global lock.
    ///
    /// Per-row deletion runs in its own transaction with a `FOR UPDATE`
    /// lock on the `oci_blobs` row and a re-check of the orphan predicate
    /// inside the tx (#1180 style). A residual TOCTOU still exists if a new
    /// manifest's `INSERT manifest_blob_refs` interleaves with this flow at
    /// sub-grace-period speeds; closing it fully would require the
    /// manifest-push path to take `SELECT ... FOR UPDATE` on `oci_blobs`
    /// rows before writing `manifest_blob_refs`. That is left as a follow-up
    /// to keep this change focused.
    ///
    /// SAFETY: callers (the scheduler) must additionally gate the live pass
    /// behind
    /// [`manifest_blob_refs_backfill::any_live_manifest_missing_refs`] and
    /// an explicit operator opt-in; this method itself only enforces the
    /// grace window and the per-row locked re-check. Every deletion is
    /// audit-logged at INFO with the digest and freed byte count.
    pub async fn run_blob_gc(&self, dry_run: bool) -> Result<StorageGcResult> {
        let orphans = self.select_orphan_blobs().await?;

        let mut result = empty_gc_result(dry_run);

        if dry_run {
            for row in &orphans {
                let digest: String = row.try_get("digest").unwrap_or_default();
                let bytes: i64 = row.try_get("size_bytes").unwrap_or(0);
                tracing::info!(
                    digest = digest.as_str(),
                    size_bytes = bytes,
                    "Blob GC (dry-run): would reclaim orphan blob"
                );
                accumulate_dry_run(&mut result, bytes, 1);
            }
            return Ok(result);
        }

        for row in &orphans {
            let digest: String = row.try_get("digest").unwrap_or_default();
            let storage_key: String = row.try_get("storage_key").unwrap_or_default();
            let storage_backend: String = row.try_get("storage_backend").unwrap_or_default();
            let storage_path: String = row.try_get("storage_path").unwrap_or_default();
            let repository_id: Uuid = match row.try_get("repository_id") {
                Ok(v) => v,
                Err(e) => {
                    let msg = format_gc_error("read repo id", &digest, &e.to_string());
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }
            };
            let bytes: i64 = row.try_get("size_bytes").unwrap_or(0);

            let location = StorageLocation {
                backend: storage_backend.clone(),
                path: storage_path.clone(),
            };
            let storage = match self.storage_for_location(&location) {
                Ok(s) => s,
                Err(e) => {
                    let msg = format_gc_error("resolve storage", &storage_key, &e.to_string());
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }
            };

            let mut tx = match self.db.begin().await {
                Ok(t) => t,
                Err(e) => {
                    let msg = format_gc_error("begin blob gc tx", &storage_key, &e.to_string());
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }
            };

            match is_blob_still_orphan(&mut tx, repository_id, &digest).await {
                Ok(true) => {}
                Ok(false) => {
                    let _ = tx.rollback().await;
                    tracing::debug!(
                        digest = digest.as_str(),
                        "Blob GC skipped digest: no longer orphan after row-lock re-check"
                    );
                    continue;
                }
                Err(e) => {
                    let _ = tx.rollback().await;
                    let msg = format_gc_error("re-check blob orphan", &storage_key, &e.to_string());
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }
            }

            if let Err(e) = storage.delete(&storage_key).await {
                let _ = tx.rollback().await;
                let msg = format_gc_error("delete blob storage", &storage_key, &e.to_string());
                tracing::warn!("{}", msg);
                result.errors.push(msg);
                continue;
            }

            if let Err(e) =
                sqlx::query("DELETE FROM oci_blobs WHERE repository_id = $1 AND digest = $2")
                    .bind(repository_id)
                    .bind(&digest)
                    .execute(&mut *tx)
                    .await
            {
                let _ = tx.rollback().await;
                let msg = format_gc_error("delete oci_blobs row", &storage_key, &e.to_string());
                tracing::warn!("{}", msg);
                result.errors.push(msg);
                continue;
            }

            if let Err(e) = tx.commit().await {
                let msg = format_gc_error("commit blob gc tx", &storage_key, &e.to_string());
                tracing::warn!("{}", msg);
                result.errors.push(msg);
                continue;
            }

            // Audit log: every committed blob deletion is recorded with its
            // digest and freed bytes. Blob deletion is irreversible, so this
            // trail is the operator's record of exactly what GC reclaimed.
            tracing::info!(
                digest = digest.as_str(),
                size_bytes = bytes,
                storage_key = storage_key.as_str(),
                "Blob GC: reclaimed orphan blob"
            );
            record_gc_success(&mut result, bytes, 1);
        }

        if result.storage_keys_deleted > 0 {
            tracing::info!(
                "Blob GC: deleted {} blob objects, freed {} bytes",
                result.storage_keys_deleted,
                result.bytes_freed
            );
        }

        Ok(result)
    }

    /// List `oci_blobs` rows older than the grace period whose digest is
    /// not protected by any in-scope `manifest_blob_refs` row
    /// ([`BLOB_PROTECTED_BY_REFS_SQL`]: cloud backends protect cross-repo on
    /// the shared bucket; filesystem protects only within the same
    /// `storage_path`). The grace period is the only safeguard against the
    /// push-time race described on [`Self::run_blob_gc`].
    async fn select_orphan_blobs(&self) -> Result<Vec<sqlx::postgres::PgRow>> {
        let sql = format!(
            r#"
            SELECT ob.repository_id,
                   ob.digest,
                   ob.size_bytes,
                   ob.storage_key,
                   r.storage_backend,
                   r.storage_path
            FROM oci_blobs ob
            JOIN repositories r ON r.id = ob.repository_id
            WHERE ob.created_at < NOW() - make_interval(secs => $1::BIGINT)
              AND NOT {protected}
            "#,
            protected = BLOB_PROTECTED_BY_REFS_SQL,
        );
        sqlx::query(&sql)
            .bind(MIN_BLOB_AGE_SECS as i64)
            .fetch_all(&self.db)
            .await
            .map_err(|e| crate::error::AppError::Database(e.to_string()))
    }

    /// Initial scan that lists candidate orphan storage keys.
    ///
    /// This is a snapshot of the orphan set at one point in time. Each
    /// candidate is re-checked under a row-level lock by
    /// [`is_still_orphan`] before deletion so that pushes landing between
    /// this scan and the per-key delete cannot get their references
    /// silently dropped (#1180).
    ///
    /// Visibility is `pub(crate)` so that unit tests in the same crate can
    /// inspect the candidate set per-storage-key. The dry-run regression
    /// tests (#1490 / #1493) cannot assert on the global
    /// `storage_keys_deleted` counter because concurrent integration tests
    /// share the same Postgres database, and a peer test's in-flight
    /// orphan row would inflate that counter. Asserting per-key against
    /// this candidate list keeps each test isolated from its neighbors.
    pub(crate) async fn select_orphans(&self) -> Result<Vec<sqlx::postgres::PgRow>> {
        let sql = format!(
            r#"
            SELECT a.storage_key, r.storage_backend, r.storage_path,
                   SUM(a.size_bytes) as total_bytes,
                   COUNT(*) as artifact_count
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            WHERE {predicate}
            GROUP BY a.storage_key, r.storage_backend, r.storage_path
            "#,
            predicate = ORPHAN_PREDICATE_SQL,
        );
        sqlx::query(&sql)
            .fetch_all(&self.db)
            .await
            .map_err(|e| crate::error::AppError::Database(e.to_string()))
    }

    /// Build the read-only OCI blob footprint report (issue #1408).
    ///
    /// Performs only `SELECT` aggregates against `oci_blobs`; it never
    /// deletes anything, takes no row locks, and touches no storage
    /// backend. Safe to call on a hot production database — the two
    /// aggregate queries are index-friendly scans of `oci_blobs`.
    ///
    /// `grace_hours` is clamped to a sane range via
    /// [`clamp_grace_hours`]; the clamped value is echoed back in the
    /// report so callers see exactly what window was applied.
    pub async fn oci_blob_footprint_report(
        &self,
        grace_hours: i64,
    ) -> Result<OciBlobFootprintReport> {
        let grace_hours = clamp_grace_hours(grace_hours);

        // Aggregate 1: global totals + dedup-aware physical bytes + aged
        // figures, all in one pass. `size_bytes` is taken as MAX per digest
        // so a single physical object is counted once even though it has one
        // row per referencing repository (rows for the same digest share a
        // size, so MAX == the per-object size).
        let totals_sql = r#"
            WITH per_digest AS (
                SELECT digest,
                       MAX(size_bytes) AS size_bytes,
                       MIN(created_at) AS first_seen
                FROM oci_blobs
                GROUP BY digest
            )
            SELECT
                (SELECT COUNT(*) FROM oci_blobs)                       AS total_blob_rows,
                (SELECT COALESCE(SUM(size_bytes), 0) FROM oci_blobs)   AS logical_bytes,
                COUNT(*)                                               AS distinct_digests,
                COALESCE(SUM(size_bytes), 0)                           AS physical_bytes,
                COUNT(*) FILTER (
                    WHERE first_seen < NOW() - make_interval(hours => $1)
                )                                                      AS aged_distinct_digests,
                COALESCE(SUM(size_bytes) FILTER (
                    WHERE first_seen < NOW() - make_interval(hours => $1)
                ), 0)                                                  AS aged_physical_bytes
            FROM per_digest
        "#;

        let totals = sqlx::query(totals_sql)
            .bind(grace_hours)
            .fetch_one(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        // Aggregate 2: per-repository logical footprint, biggest first.
        let per_repo_sql = r#"
            SELECT repository_id,
                   COUNT(*) AS blob_rows,
                   COALESCE(SUM(size_bytes), 0) AS logical_bytes
            FROM oci_blobs
            GROUP BY repository_id
            ORDER BY logical_bytes DESC, repository_id ASC
        "#;
        let per_repo_rows = sqlx::query(per_repo_sql)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        let per_repository = per_repo_rows
            .into_iter()
            .map(|row| {
                let repository_id = row
                    .try_get("repository_id")
                    .map_err(|e| AppError::Database(e.to_string()))?;
                Ok(map_repo_footprint(
                    repository_id,
                    row.try_get("blob_rows").unwrap_or(0),
                    row.try_get("logical_bytes").unwrap_or(0),
                ))
            })
            .collect::<Result<Vec<_>>>()?;

        let totals = BlobFootprintTotals {
            total_blob_rows: totals.try_get("total_blob_rows").unwrap_or(0),
            distinct_digests: totals.try_get("distinct_digests").unwrap_or(0),
            logical_bytes: totals.try_get("logical_bytes").unwrap_or(0),
            physical_bytes: totals.try_get("physical_bytes").unwrap_or(0),
            aged_distinct_digests: totals.try_get("aged_distinct_digests").unwrap_or(0),
            aged_physical_bytes: totals.try_get("aged_physical_bytes").unwrap_or(0),
        };

        Ok(assemble_blob_footprint_report(
            totals,
            grace_hours,
            per_repository,
        ))
    }

    async fn cleanup_abandoned_oci_uploads(
        &self,
        dry_run: bool,
        result: &mut StorageGcResult,
    ) -> Result<()> {
        let session_ids = self.select_abandoned_oci_upload_session_ids().await?;
        let mut sessions_removed = 0_i64;
        let mut upload_keys_deleted = 0_i64;

        for session_id in session_ids {
            let mut tx = match self.db.begin().await {
                Ok(t) => t,
                Err(e) => {
                    let msg = format_gc_error(
                        "begin abandoned OCI upload cleanup tx",
                        &session_id.to_string(),
                        &e.to_string(),
                    );
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }
            };

            let session = match lock_abandoned_oci_upload_session(&mut tx, session_id).await {
                Ok(Some(session)) => session,
                Ok(None) => {
                    let _ = tx.rollback().await;
                    continue;
                }
                Err(e) => {
                    let _ = tx.rollback().await;
                    let msg = format_gc_error(
                        "lock abandoned OCI upload session",
                        &session_id.to_string(),
                        &e.to_string(),
                    );
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }
            };

            if dry_run {
                let _ = tx.rollback().await;
                result.storage_keys_deleted += session.storage_keys.len() as i64;
                result.bytes_freed += session.bytes_received.max(0);
                continue;
            }

            let storage = match self.storage_for_location(&session.location) {
                Ok(s) => s,
                Err(e) => {
                    let _ = tx.rollback().await;
                    let msg = format_gc_error(
                        "resolve abandoned OCI upload storage",
                        &session.id.to_string(),
                        &e.to_string(),
                    );
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }
            };

            let mut delete_failed = false;
            for key in &session.storage_keys {
                match storage.delete(key).await {
                    Ok(()) | Err(AppError::NotFound(_)) => {}
                    Err(e) => {
                        let msg = format_gc_error(
                            "delete abandoned OCI upload storage key",
                            key,
                            &e.to_string(),
                        );
                        tracing::warn!("{}", msg);
                        result.errors.push(msg);
                        delete_failed = true;
                    }
                }
            }
            if delete_failed {
                let _ = tx.rollback().await;
                continue;
            }

            if let Err(e) = sqlx::query("DELETE FROM oci_upload_sessions WHERE id = $1")
                .bind(session.id)
                .execute(&mut *tx)
                .await
            {
                let _ = tx.rollback().await;
                let msg = format_gc_error(
                    "delete abandoned OCI upload session",
                    &session.id.to_string(),
                    &e.to_string(),
                );
                tracing::warn!("{}", msg);
                result.errors.push(msg);
                continue;
            }

            // NOTE: we intentionally do NOT delete this session's
            // oci_upload_cleanup_keys rows here. This sweep only deletes the
            // session's temp + part objects (session.storage_keys); the
            // final-part / completion-temp objects left by a failed completion
            // attempt are journaled under this session but are NOT in
            // session.storage_keys (they were never inserted into
            // oci_upload_parts), so they are reaped by the unreferenced-key
            // sweep instead. Deleting the journal rows here would remove their
            // only owner and strand those objects forever. The cost is that the
            // unreferenced sweep re-issues a now-NotFound delete for the
            // already-removed temp/part keys (a benign metrics double-count).
            if let Err(e) = tx.commit().await {
                let msg = format_gc_error(
                    "commit abandoned OCI upload cleanup tx",
                    &session.id.to_string(),
                    &e.to_string(),
                );
                tracing::warn!("{}", msg);
                result.errors.push(msg);
                continue;
            }

            sessions_removed += 1;
            upload_keys_deleted += session.storage_keys.len() as i64;
            result.storage_keys_deleted += session.storage_keys.len() as i64;
            result.bytes_freed += session.bytes_received.max(0);
        }

        if sessions_removed > 0 {
            tracing::info!(
                "Storage GC: removed {} abandoned OCI upload sessions and deleted {} upload keys",
                sessions_removed,
                upload_keys_deleted
            );
        }

        Ok(())
    }

    async fn select_abandoned_oci_upload_session_ids(&self) -> Result<Vec<Uuid>> {
        let sql = format!(
            r#"
            SELECT id
            FROM oci_upload_sessions
            WHERE updated_at < NOW() - {ttl}
            ORDER BY updated_at ASC
            LIMIT $1
            "#,
            ttl = ABANDONED_OCI_UPLOAD_TTL_SQL,
        );
        let rows = sqlx::query(&sql)
            .bind(ABANDONED_OCI_UPLOAD_SCAN_LIMIT)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        rows.into_iter()
            .map(|row| {
                row.try_get::<Uuid, _>("id")
                    .map_err(|e| AppError::Database(e.to_string()))
            })
            .collect()
    }

    async fn cleanup_unreferenced_oci_upload_keys(
        &self,
        dry_run: bool,
        result: &mut StorageGcResult,
    ) -> Result<()> {
        let cleanup_keys = self.select_unreferenced_oci_upload_cleanup_keys().await?;
        let mut cleanup_rows_removed = 0_i64;

        for cleanup_key in cleanup_keys {
            if dry_run {
                result.storage_keys_deleted += 1;
                continue;
            }

            let storage = match self.storage_for_location(&cleanup_key.location) {
                Ok(s) => s,
                Err(e) => {
                    let msg = format_gc_error(
                        "resolve OCI upload cleanup-key storage",
                        &cleanup_key.storage_key,
                        &e.to_string(),
                    );
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }
            };

            match storage.delete(&cleanup_key.storage_key).await {
                Ok(()) | Err(AppError::NotFound(_)) => {}
                Err(e) => {
                    let msg = format_gc_error(
                        "delete OCI upload cleanup-key storage",
                        &cleanup_key.storage_key,
                        &e.to_string(),
                    );
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }
            }

            if let Err(e) = sqlx::query(
                r#"
                DELETE FROM oci_upload_cleanup_keys
                WHERE id = $1
                  AND storage_write_completed_at IS NOT NULL
                  -- Intentionally NOT guarded by `s.id = upload_session_id`
                  -- (unlike the pending reaper): a committed cleanup key is a
                  -- part / final-part / completion-temp key, never a session's
                  -- storage_temp_key. The part check below protects live PATCH
                  -- parts; the final-part / completion-temp objects left behind
                  -- by a FAILED completion attempt are genuine orphans even
                  -- while their session survives (it was reset to `open` for
                  -- retry), so they MUST be reapable without waiting for the
                  -- session to be abandoned. Adding the session-id branch here
                  -- would strand them until the 24h sweep.
                  AND NOT EXISTS (
                    SELECT 1 FROM oci_upload_sessions s
                    WHERE s.storage_temp_key = oci_upload_cleanup_keys.storage_key
                  )
                  AND NOT EXISTS (
                    SELECT 1 FROM oci_upload_parts p
                    WHERE p.storage_key = oci_upload_cleanup_keys.storage_key
                  )
                "#,
            )
            .bind(cleanup_key.id)
            .execute(&self.db)
            .await
            {
                let msg = format_gc_error(
                    "delete OCI upload cleanup-key row",
                    &cleanup_key.storage_key,
                    &e.to_string(),
                );
                tracing::warn!("{}", msg);
                result.errors.push(msg);
                continue;
            }

            cleanup_rows_removed += 1;
            result.storage_keys_deleted += 1;
        }

        if cleanup_rows_removed > 0 {
            tracing::info!(
                "Storage GC: removed {} stale OCI upload cleanup-key rows",
                cleanup_rows_removed
            );
        }

        Ok(())
    }

    async fn select_unreferenced_oci_upload_cleanup_keys(
        &self,
    ) -> Result<Vec<OciUploadCleanupKey>> {
        let sql = format!(
            r#"
            SELECT c.id, c.storage_key, r.storage_backend, r.storage_path
            FROM oci_upload_cleanup_keys c
            JOIN repositories r ON r.id = c.repository_id
            WHERE c.storage_write_completed_at IS NOT NULL
              AND c.storage_write_completed_at < NOW() - {ttl}
              -- See the matching DELETE: a committed key (part/final/completion
              -- temp) is intentionally reapable even while its session lives,
              -- so this is NOT guarded by `s.id = c.upload_session_id`.
              AND NOT EXISTS (
                SELECT 1 FROM oci_upload_sessions s
                WHERE s.storage_temp_key = c.storage_key
              )
              AND NOT EXISTS (
                SELECT 1 FROM oci_upload_parts p
                WHERE p.storage_key = c.storage_key
              )
            ORDER BY c.created_at ASC
            LIMIT $1
            "#,
            ttl = ABANDONED_OCI_UPLOAD_TTL_SQL,
        );
        let rows = sqlx::query(&sql)
            .bind(OCI_UPLOAD_CLEANUP_KEY_SCAN_LIMIT)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        rows.into_iter()
            .map(|row| decode_oci_cleanup_key_row(&row))
            .collect()
    }

    /// Reconcile aged `oci_upload_cleanup_keys` rows whose storage write was
    /// never marked complete (`storage_write_completed_at IS NULL`).
    ///
    /// The normal sweep ([`cleanup_unreferenced_oci_upload_keys`]) only
    /// reaps rows whose write has been marked complete. A crash or failed
    /// storage write between the register-row INSERT and the mark leaves the
    /// row stuck at NULL forever, so the table grows without bound. This
    /// reaper closes that leak: it picks up rows that are
    ///
    /// 1. still NULL (never marked complete), and
    /// 2. older than [`ABANDONED_OCI_UPLOAD_TTL_SQL`] (so no in-flight write
    ///    can still be racing to create the object), and
    /// 3. not referenced by any live upload session or part.
    ///
    /// For each, it best-effort deletes the storage object (treating
    /// `NotFound` as success, since a crashed write may never have created
    /// it) and then deletes the row, re-asserting the NULL + unreferenced
    /// predicate in the DELETE's WHERE clause so it cannot race the writer
    /// that may be marking the row complete concurrently.
    async fn reap_pending_oci_upload_cleanup_keys(
        &self,
        dry_run: bool,
        result: &mut StorageGcResult,
    ) -> Result<()> {
        let cleanup_keys = self.select_pending_oci_upload_cleanup_keys().await?;
        let mut cleanup_rows_removed = 0_i64;

        for cleanup_key in cleanup_keys {
            if dry_run {
                result.storage_keys_deleted += 1;
                continue;
            }

            let storage = match self.storage_for_location(&cleanup_key.location) {
                Ok(s) => s,
                Err(e) => {
                    let msg = format_gc_error(
                        "resolve pending OCI upload cleanup-key storage",
                        &cleanup_key.storage_key,
                        &e.to_string(),
                    );
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }
            };

            match storage.delete(&cleanup_key.storage_key).await {
                Ok(()) | Err(AppError::NotFound(_)) => {}
                Err(e) => {
                    let msg = format_gc_error(
                        "delete pending OCI upload cleanup-key storage",
                        &cleanup_key.storage_key,
                        &e.to_string(),
                    );
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }
            }

            // Re-assert NULL + unreferenced in the DELETE so a concurrent
            // mark (writer flipping storage_write_completed_at to a value
            // and inserting a session/part) cannot have the row reaped out
            // from under it after we observed it as pending. The owning
            // session (upload_session_id) is also re-checked so a row whose
            // upload is still live is never reaped, even when the row's
            // storage_key is a part key that does not textually match the
            // session's storage_temp_key.
            if let Err(e) = sqlx::query(
                r#"
                DELETE FROM oci_upload_cleanup_keys
                WHERE id = $1
                  AND storage_write_completed_at IS NULL
                  AND NOT EXISTS (
                    SELECT 1 FROM oci_upload_sessions s
                    WHERE s.id = oci_upload_cleanup_keys.upload_session_id
                       OR s.storage_temp_key = oci_upload_cleanup_keys.storage_key
                  )
                  AND NOT EXISTS (
                    SELECT 1 FROM oci_upload_parts p
                    WHERE p.storage_key = oci_upload_cleanup_keys.storage_key
                  )
                "#,
            )
            .bind(cleanup_key.id)
            .execute(&self.db)
            .await
            {
                let msg = format_gc_error(
                    "delete pending OCI upload cleanup-key row",
                    &cleanup_key.storage_key,
                    &e.to_string(),
                );
                tracing::warn!("{}", msg);
                result.errors.push(msg);
                continue;
            }

            cleanup_rows_removed += 1;
            result.storage_keys_deleted += 1;
        }

        if cleanup_rows_removed > 0 {
            tracing::info!(
                "Storage GC: reaped {} aged pending OCI upload cleanup-key rows",
                cleanup_rows_removed
            );
        }

        Ok(())
    }

    async fn select_pending_oci_upload_cleanup_keys(&self) -> Result<Vec<OciUploadCleanupKey>> {
        let sql = format!(
            r#"
            SELECT c.id, c.storage_key, r.storage_backend, r.storage_path
            FROM oci_upload_cleanup_keys c
            JOIN repositories r ON r.id = c.repository_id
            WHERE c.storage_write_completed_at IS NULL
              AND c.created_at < NOW() - {ttl}
              AND NOT EXISTS (
                SELECT 1 FROM oci_upload_sessions s
                WHERE s.id = c.upload_session_id
                   OR s.storage_temp_key = c.storage_key
              )
              AND NOT EXISTS (
                SELECT 1 FROM oci_upload_parts p
                WHERE p.storage_key = c.storage_key
              )
            ORDER BY c.created_at ASC
            LIMIT $1
            "#,
            ttl = ABANDONED_OCI_UPLOAD_TTL_SQL,
        );
        let rows = sqlx::query(&sql)
            .bind(OCI_UPLOAD_CLEANUP_KEY_SCAN_LIMIT)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        rows.into_iter()
            .map(|row| decode_oci_cleanup_key_row(&row))
            .collect()
    }
}

/// Decode an `oci_upload_cleanup_keys` JOIN `repositories` row into an
/// [`OciUploadCleanupKey`]. Shared by the unreferenced and pending cleanup-key
/// selects, which project the identical column set.
fn decode_oci_cleanup_key_row(row: &sqlx::postgres::PgRow) -> Result<OciUploadCleanupKey> {
    Ok(OciUploadCleanupKey {
        id: row
            .try_get::<i64, _>("id")
            .map_err(|e| AppError::Database(e.to_string()))?,
        storage_key: row
            .try_get::<String, _>("storage_key")
            .map_err(|e| AppError::Database(e.to_string()))?,
        location: StorageLocation {
            backend: row
                .try_get::<String, _>("storage_backend")
                .map_err(|e| AppError::Database(e.to_string()))?,
            path: row
                .try_get::<String, _>("storage_path")
                .map_err(|e| AppError::Database(e.to_string()))?,
        },
    })
}

async fn lock_abandoned_oci_upload_session(
    tx: &mut Transaction<'_, Postgres>,
    session_id: Uuid,
) -> sqlx::Result<Option<AbandonedOciUploadSession>> {
    let sql = format!(
        r#"
        SELECT s.id, r.storage_backend, r.storage_path,
               s.storage_temp_key, s.bytes_received
        FROM oci_upload_sessions s
        JOIN repositories r ON r.id = s.repository_id
        WHERE s.id = $1
          AND s.updated_at < NOW() - {ttl}
        FOR UPDATE OF s
        "#,
        ttl = ABANDONED_OCI_UPLOAD_TTL_SQL,
    );
    let Some(row) = sqlx::query(&sql)
        .bind(session_id)
        .fetch_optional(&mut **tx)
        .await?
    else {
        return Ok(None);
    };

    let storage_temp_key: String = row.try_get("storage_temp_key")?;
    let part_rows = sqlx::query(
        r#"
        SELECT storage_key
        FROM oci_upload_parts
        WHERE upload_session_id = $1
        ORDER BY part_index ASC
        "#,
    )
    .bind(session_id)
    .fetch_all(&mut **tx)
    .await?;

    let mut storage_keys: Vec<String> = part_rows
        .into_iter()
        .map(|row| row.try_get::<String, _>("storage_key"))
        .collect::<sqlx::Result<Vec<_>>>()?;
    storage_keys.push(storage_temp_key);
    storage_keys.sort();
    storage_keys.dedup();

    Ok(Some(AbandonedOciUploadSession {
        id: row.try_get("id")?,
        location: StorageLocation {
            backend: row.try_get("storage_backend")?,
            path: row.try_get("storage_path")?,
        },
        storage_keys,
        bytes_received: row.try_get("bytes_received")?,
    }))
}

/// Re-verify the orphan predicate for a single (storage_key, repo
/// location) inside an open transaction with a `FOR UPDATE` lock on the
/// candidate `artifacts` rows.
///
/// Returns `Ok(true)` if every soft-deleted `artifacts` row matching the
/// key still satisfies the orphan predicate; `Ok(false)` if any racing
/// writer has landed a protecting reference.
///
/// Postgres forbids `FOR UPDATE` together with aggregate functions in
/// the same SELECT, so we split the check into two steps:
///
/// 1. Acquire row locks on every `artifacts` row matching the
///    (storage_key, backend) tuple (path-narrowed only on `filesystem`
///    because cloud backends share a global keyspace across repos on
///    the same backend type) with a separate `SELECT ... FOR UPDATE`.
///    This is the bit that blocks any racing writer from flipping
///    `is_deleted` or otherwise modifying these rows until our tx ends.
/// 2. Re-evaluate the orphan predicate (an aggregate over the locked
///    rows) in a second non-locking SELECT. Because we hold the lock
///    from step 1, no row visible in step 2 can change underneath us
///    for the rest of the transaction.
///
/// The aggregate uses `bool_and`; if there are no matching rows the
/// aggregate is NULL and `COALESCE` returns false so we skip the delete
/// (there's nothing left to delete anyway).
///
/// Lock scope rationale: `ORPHAN_PREDICATE_SQL` treats `oci_tags`,
/// `oci_blobs`, and `oci_manifest_refs` as cross-repo on cloud backends
/// because S3/GCS/Azure storage keys are globally unique within the
/// configured bucket. The lock here must match the same scope, or a
/// racing writer in a sibling cloud repo could flip `is_deleted=false`
/// on a row that shares the storage_key without being blocked, and the
/// recheck would still observe the new live row in step 2 only if it
/// committed before the snapshot. Widening the lock to all repos on
/// the same cloud backend closes that window.
async fn is_still_orphan(
    tx: &mut Transaction<'_, Postgres>,
    storage_key: &str,
    storage_backend: &str,
    storage_path: &str,
) -> sqlx::Result<bool> {
    // Step 1: acquire row locks. We do not care about the returned
    // rows; we just need them locked for the rest of the transaction.
    // `FOR UPDATE OF a` restricts the lock to the artifacts table so
    // we do not inadvertently lock the joined repositories row.
    //
    // Filesystem narrows by `storage_path` (each repo has its own
    // filesystem root); cloud backends span every repo on the same
    // backend type because they all share one bucket and the same
    // storage_key resolves to the same object.
    sqlx::query(
        r#"
        SELECT a.id
        FROM artifacts a
        JOIN repositories r ON r.id = a.repository_id
        WHERE a.storage_key = $1
          AND r.storage_backend = $2
          AND (
            r.storage_backend <> 'filesystem'
            OR r.storage_path = $3
          )
        FOR UPDATE OF a
        "#,
    )
    .bind(storage_key)
    .bind(storage_backend)
    .bind(storage_path)
    .fetch_all(&mut **tx)
    .await?;

    // Step 2: re-evaluate the orphan predicate against the locked rows.
    // Match scope used by step 1.
    let sql = format!(
        r#"
        SELECT COALESCE(bool_and({predicate}), false) AS still_orphan
        FROM artifacts a
        JOIN repositories r ON r.id = a.repository_id
        WHERE a.storage_key = $1
          AND r.storage_backend = $2
          AND (
            r.storage_backend <> 'filesystem'
            OR r.storage_path = $3
          )
        "#,
        predicate = ORPHAN_PREDICATE_SQL,
    );

    let row = sqlx::query(&sql)
        .bind(storage_key)
        .bind(storage_backend)
        .bind(storage_path)
        .fetch_one(&mut **tx)
        .await?;

    Ok(row.try_get::<bool, _>("still_orphan").unwrap_or(false))
}

/// Re-verify the blob-orphan predicate for a single (repo, digest) inside
/// an open transaction with a `FOR UPDATE` lock on the `oci_blobs` row
/// (#1408; design from #1409).
///
/// The lock is narrowed to the (repo, digest) row because
/// `oci_blobs.repository_id` is part of its primary key. The orphan
/// re-check uses the same backend-aware [`BLOB_PROTECTED_BY_REFS_SQL`]
/// fragment as [`StorageGcService::select_orphan_blobs`] (cloud =
/// cross-repo on the shared bucket, filesystem = same `storage_path`), so
/// the initial scan and the locked re-check cannot drift.
///
/// `bool_and` collapses to a single value; an empty result (row gone)
/// returns `false` so the caller skips the delete.
async fn is_blob_still_orphan(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: Uuid,
    digest: &str,
) -> sqlx::Result<bool> {
    // Step 1: lock the (repo, digest) row so a racing pusher cannot
    // re-reference this blob between the re-check and the delete.
    sqlx::query(
        r#"
        SELECT id FROM oci_blobs
        WHERE repository_id = $1 AND digest = $2
        FOR UPDATE
        "#,
    )
    .bind(repository_id)
    .bind(digest)
    .fetch_all(&mut **tx)
    .await?;

    // Step 2: join the locked row back to its repository so the shared
    // `ob`/`r`-correlated fragment can resolve the row's backend and
    // storage_path; this keeps the re-check identical in scope to the
    // initial scan.
    let sql = format!(
        r#"
        SELECT COALESCE(bool_and(NOT {protected}), false) AS still_orphan
        FROM oci_blobs ob
        JOIN repositories r ON r.id = ob.repository_id
        WHERE ob.repository_id = $1 AND ob.digest = $2
        "#,
        protected = BLOB_PROTECTED_BY_REFS_SQL,
    );
    let row = sqlx::query(&sql)
        .bind(repository_id)
        .bind(digest)
        .fetch_one(&mut **tx)
        .await?;

    Ok(row.try_get::<bool, _>("still_orphan").unwrap_or(false))
}

/// Accumulate dry-run totals into a GC result.
pub(crate) fn accumulate_dry_run(result: &mut StorageGcResult, bytes: i64, count: i64) {
    result.storage_keys_deleted += 1;
    result.artifacts_removed += count;
    result.bytes_freed += bytes;
}

/// Record a successful GC deletion in the result.
pub(crate) fn record_gc_success(result: &mut StorageGcResult, bytes: i64, count: i64) {
    result.storage_keys_deleted += 1;
    result.artifacts_removed += count;
    result.bytes_freed += bytes;
}

/// Format a GC error message for a specific operation and storage key.
pub(crate) fn format_gc_error(operation: &str, storage_key: &str, error: &str) -> String {
    format!("Failed to {} for key {}: {}", operation, storage_key, error)
}

/// Decoded global aggregate values for the OCI blob footprint report.
///
/// This is the row-free intermediate between the `totals_sql` query in
/// [`StorageGcService::oci_blob_footprint_report`] and the final
/// [`OciBlobFootprintReport`]. Splitting it out lets the report-assembly
/// logic (which is pure arithmetic/struct shuffling, not I/O) be unit
/// tested without a live database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BlobFootprintTotals {
    pub total_blob_rows: i64,
    pub distinct_digests: i64,
    pub logical_bytes: i64,
    pub physical_bytes: i64,
    pub aged_distinct_digests: i64,
    pub aged_physical_bytes: i64,
}

/// Build a single per-repository footprint row from decoded column values.
///
/// Pure mapping helper shared by the per-repo aggregate decode loop and
/// the unit tests. Holds no row/DB dependency so the construction can be
/// exercised without Postgres.
pub(crate) fn map_repo_footprint(
    repository_id: Uuid,
    blob_rows: i64,
    logical_bytes: i64,
) -> OciBlobRepoFootprint {
    OciBlobRepoFootprint {
        repository_id,
        blob_rows,
        logical_bytes,
    }
}

/// Assemble the final [`OciBlobFootprintReport`] from already-decoded
/// totals, the (already clamped) grace window, and the per-repository
/// rows.
///
/// Pure: it does no I/O and takes no locks. Extracted from
/// [`StorageGcService::oci_blob_footprint_report`] so the report-assembly
/// step is covered by `--lib` unit tests even though the surrounding query
/// execution requires a database.
pub(crate) fn assemble_blob_footprint_report(
    totals: BlobFootprintTotals,
    grace_hours: i64,
    per_repository: Vec<OciBlobRepoFootprint>,
) -> OciBlobFootprintReport {
    OciBlobFootprintReport {
        total_blob_rows: totals.total_blob_rows,
        distinct_digests: totals.distinct_digests,
        logical_bytes: totals.logical_bytes,
        physical_bytes: totals.physical_bytes,
        grace_hours,
        aged_distinct_digests: totals.aged_distinct_digests,
        aged_physical_bytes: totals.aged_physical_bytes,
        per_repository,
    }
}

/// Clamp a caller-supplied grace window (hours) for the blob footprint
/// report into a defensible range.
///
/// A non-positive or absurd value is coerced rather than rejected so the
/// reporting endpoint never errors on a bad query parameter:
/// - values `<= 0` fall back to [`BLOB_REPORT_GRACE_HOURS_DEFAULT`]
///   (a zero/negative grace window would mark freshly-uploaded blobs as
///   "aged", defeating the upload-race guard the window represents);
/// - values are capped at one year (8760 h) so `make_interval` cannot be
///   handed a pathological argument.
pub(crate) fn clamp_grace_hours(grace_hours: i64) -> i64 {
    const MAX_GRACE_HOURS: i64 = 24 * 365;
    if grace_hours <= 0 {
        BLOB_REPORT_GRACE_HOURS_DEFAULT
    } else {
        grace_hours.min(MAX_GRACE_HOURS)
    }
}

/// Check whether a storage backend type uses a shared (cloud) backend.
#[cfg(test)]
pub(crate) fn is_cloud_backend(backend_type: &str) -> bool {
    matches!(backend_type, "s3" | "azure" | "gcs")
}

/// Create an empty GC result for a given dry_run mode.
pub(crate) fn empty_gc_result(dry_run: bool) -> StorageGcResult {
    StorageGcResult {
        dry_run,
        storage_keys_deleted: 0,
        artifacts_removed: 0,
        bytes_freed: 0,
        errors: Vec::new(),
    }
}

#[cfg(test)]
static STORAGE_GC_TEST_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

#[cfg(test)]
pub(crate) async fn storage_gc_test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    STORAGE_GC_TEST_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    use async_trait::async_trait;
    use bytes::Bytes;
    use std::sync::Arc;
    use uuid::Uuid;

    // -----------------------------------------------------------------------
    // Mock storage backend for unit tests
    // -----------------------------------------------------------------------

    struct MockStorage;

    #[async_trait]
    impl crate::storage::StorageBackend for MockStorage {
        async fn put(&self, _key: &str, _content: Bytes) -> crate::error::Result<()> {
            Ok(())
        }
        async fn get(&self, _key: &str) -> crate::error::Result<Bytes> {
            Ok(Bytes::new())
        }
        async fn exists(&self, _key: &str) -> crate::error::Result<bool> {
            Ok(false)
        }
        async fn delete(&self, _key: &str) -> crate::error::Result<()> {
            Ok(())
        }
    }

    fn make_pool() -> PgPool {
        use sqlx::postgres::PgPoolOptions;
        PgPoolOptions::new()
            .max_connections(1)
            .idle_timeout(std::time::Duration::from_secs(1))
            .connect_lazy_with(
                sqlx::postgres::PgConnectOptions::new()
                    .host("localhost")
                    .database("test"),
            )
    }

    fn make_service(backend_type: &str) -> StorageGcService {
        let mut backends = std::collections::HashMap::new();
        if backend_type != "filesystem" {
            backends.insert(
                backend_type.to_string(),
                Arc::new(MockStorage) as Arc<dyn crate::storage::StorageBackend>,
            );
        }
        let registry = Arc::new(crate::storage::StorageRegistry::new(
            backends,
            backend_type.to_string(),
        ));
        StorageGcService::new(make_pool(), registry)
    }

    // -----------------------------------------------------------------------
    // StorageGcResult: serialization (existing tests)
    // -----------------------------------------------------------------------

    #[test]
    fn test_storage_gc_result_serialization() {
        let result = StorageGcResult {
            dry_run: false,
            storage_keys_deleted: 5,
            artifacts_removed: 12,
            bytes_freed: 1024 * 1024,
            errors: vec![],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"storage_keys_deleted\":5"));
        assert!(json.contains("\"artifacts_removed\":12"));
    }

    #[test]
    fn test_storage_gc_result_dry_run() {
        let result = StorageGcResult {
            dry_run: true,
            storage_keys_deleted: 0,
            artifacts_removed: 0,
            bytes_freed: 0,
            errors: vec![],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"dry_run\":true"));
    }

    #[test]
    fn test_storage_gc_result_with_errors() {
        let result = StorageGcResult {
            dry_run: false,
            storage_keys_deleted: 3,
            artifacts_removed: 3,
            bytes_freed: 512,
            errors: vec!["Failed to delete key abc".to_string()],
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: StorageGcResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.errors.len(), 1);
        assert_eq!(deserialized.storage_keys_deleted, 3);
    }

    // -----------------------------------------------------------------------
    // StorageGcResult: additional serde and edge-case tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_storage_gc_result_serde_roundtrip() {
        let original = StorageGcResult {
            dry_run: true,
            storage_keys_deleted: 42,
            artifacts_removed: 100,
            bytes_freed: 999_999_999,
            errors: vec![
                "error one".to_string(),
                "error two".to_string(),
                "error three".to_string(),
            ],
        };
        let json = serde_json::to_string(&original).unwrap();
        let restored: StorageGcResult = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.dry_run, original.dry_run);
        assert_eq!(restored.storage_keys_deleted, original.storage_keys_deleted);
        assert_eq!(restored.artifacts_removed, original.artifacts_removed);
        assert_eq!(restored.bytes_freed, original.bytes_freed);
        assert_eq!(restored.errors, original.errors);
    }

    #[test]
    fn test_storage_gc_result_deserialization_from_json() {
        let json = r#"{
            "dry_run": false,
            "storage_keys_deleted": 7,
            "artifacts_removed": 20,
            "bytes_freed": 4096,
            "errors": ["something went wrong"]
        }"#;
        let result: StorageGcResult = serde_json::from_str(json).unwrap();
        assert!(!result.dry_run);
        assert_eq!(result.storage_keys_deleted, 7);
        assert_eq!(result.artifacts_removed, 20);
        assert_eq!(result.bytes_freed, 4096);
        assert_eq!(result.errors, vec!["something went wrong"]);
    }

    #[test]
    fn test_storage_gc_result_large_numbers() {
        let result = StorageGcResult {
            dry_run: false,
            storage_keys_deleted: i64::MAX,
            artifacts_removed: i64::MAX,
            bytes_freed: i64::MAX,
            errors: vec![],
        };
        let json = serde_json::to_string(&result).unwrap();
        let restored: StorageGcResult = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.storage_keys_deleted, i64::MAX);
        assert_eq!(restored.artifacts_removed, i64::MAX);
        assert_eq!(restored.bytes_freed, i64::MAX);
    }

    #[test]
    fn test_storage_gc_result_empty_errors_vec() {
        let result = StorageGcResult {
            dry_run: false,
            storage_keys_deleted: 0,
            artifacts_removed: 0,
            bytes_freed: 0,
            errors: vec![],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"errors\":[]"));
    }

    #[test]
    fn test_storage_gc_result_debug_format() {
        let result = StorageGcResult {
            dry_run: true,
            storage_keys_deleted: 1,
            artifacts_removed: 2,
            bytes_freed: 3,
            errors: vec!["err".to_string()],
        };
        let debug = format!("{:?}", result);
        assert!(debug.contains("StorageGcResult"));
        assert!(debug.contains("dry_run: true"));
        assert!(debug.contains("storage_keys_deleted: 1"));
        assert!(debug.contains("artifacts_removed: 2"));
        assert!(debug.contains("bytes_freed: 3"));
        assert!(debug.contains("err"));
    }

    #[test]
    fn test_storage_gc_result_multiple_errors() {
        let errors: Vec<String> = (0..50).map(|i| format!("error {}", i)).collect();
        let result = StorageGcResult {
            dry_run: false,
            storage_keys_deleted: 50,
            artifacts_removed: 50,
            bytes_freed: 50 * 1024,
            errors: errors.clone(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let restored: StorageGcResult = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.errors.len(), 50);
        assert_eq!(restored.errors[0], "error 0");
        assert_eq!(restored.errors[49], "error 49");
    }

    // -----------------------------------------------------------------------
    // empty_gc_result
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_gc_result_dry_run_true() {
        let result = empty_gc_result(true);
        assert!(result.dry_run);
        assert_eq!(result.storage_keys_deleted, 0);
        assert_eq!(result.artifacts_removed, 0);
        assert_eq!(result.bytes_freed, 0);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_empty_gc_result_dry_run_false() {
        let result = empty_gc_result(false);
        assert!(!result.dry_run);
        assert_eq!(result.storage_keys_deleted, 0);
        assert_eq!(result.artifacts_removed, 0);
        assert_eq!(result.bytes_freed, 0);
        assert!(result.errors.is_empty());
    }

    // -----------------------------------------------------------------------
    // is_cloud_backend
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_cloud_backend_s3() {
        assert!(is_cloud_backend("s3"));
    }

    #[test]
    fn test_is_cloud_backend_azure() {
        assert!(is_cloud_backend("azure"));
    }

    #[test]
    fn test_is_cloud_backend_gcs() {
        assert!(is_cloud_backend("gcs"));
    }

    #[test]
    fn test_is_cloud_backend_filesystem() {
        assert!(!is_cloud_backend("filesystem"));
    }

    #[test]
    fn test_is_cloud_backend_empty_string() {
        assert!(!is_cloud_backend(""));
    }

    #[test]
    fn test_is_cloud_backend_unknown() {
        assert!(!is_cloud_backend("unknown"));
    }

    #[test]
    fn test_is_cloud_backend_case_sensitive() {
        assert!(!is_cloud_backend("S3"));
        assert!(!is_cloud_backend("Azure"));
        assert!(!is_cloud_backend("GCS"));
    }

    // -----------------------------------------------------------------------
    // format_gc_error
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_gc_error_basic() {
        let msg = format_gc_error("delete storage key", "abc123", "file not found");
        assert_eq!(
            msg,
            "Failed to delete storage key for key abc123: file not found"
        );
    }

    #[test]
    fn test_format_gc_error_hard_delete() {
        let msg = format_gc_error(
            "hard-delete artifacts",
            "sha256:deadbeef",
            "connection reset",
        );
        assert_eq!(
            msg,
            "Failed to hard-delete artifacts for key sha256:deadbeef: connection reset"
        );
    }

    #[test]
    fn test_format_gc_error_promotion_approvals() {
        let msg = format_gc_error(
            "delete promotion_approvals",
            "key-42",
            "foreign key violation",
        );
        assert_eq!(
            msg,
            "Failed to delete promotion_approvals for key key-42: foreign key violation"
        );
    }

    #[test]
    fn test_format_gc_error_special_chars_in_key() {
        let msg = format_gc_error("delete", "path/to/key with spaces", "denied");
        assert_eq!(
            msg,
            "Failed to delete for key path/to/key with spaces: denied"
        );
    }

    #[test]
    fn test_format_gc_error_special_chars_in_error() {
        let msg = format_gc_error("delete", "key1", "error: \"quote\" & <angle>");
        assert_eq!(
            msg,
            "Failed to delete for key key1: error: \"quote\" & <angle>"
        );
    }

    #[test]
    fn test_format_gc_error_empty_strings() {
        let msg = format_gc_error("", "", "");
        assert_eq!(msg, "Failed to  for key : ");
    }

    // -----------------------------------------------------------------------
    // accumulate_dry_run
    // -----------------------------------------------------------------------

    #[test]
    fn test_accumulate_dry_run_single_call() {
        let mut result = empty_gc_result(true);
        accumulate_dry_run(&mut result, 1024, 3);

        assert_eq!(result.storage_keys_deleted, 1);
        assert_eq!(result.artifacts_removed, 3);
        assert_eq!(result.bytes_freed, 1024);
    }

    #[test]
    fn test_accumulate_dry_run_multiple_calls() {
        let mut result = empty_gc_result(true);
        accumulate_dry_run(&mut result, 100, 2);
        accumulate_dry_run(&mut result, 200, 5);
        accumulate_dry_run(&mut result, 300, 1);

        assert_eq!(result.storage_keys_deleted, 3);
        assert_eq!(result.artifacts_removed, 8);
        assert_eq!(result.bytes_freed, 600);
    }

    #[test]
    fn test_accumulate_dry_run_zero_values() {
        let mut result = empty_gc_result(true);
        accumulate_dry_run(&mut result, 0, 0);

        assert_eq!(result.storage_keys_deleted, 1);
        assert_eq!(result.artifacts_removed, 0);
        assert_eq!(result.bytes_freed, 0);
    }

    #[test]
    fn test_accumulate_dry_run_preserves_errors() {
        let mut result = empty_gc_result(true);
        result.errors.push("pre-existing error".to_string());
        accumulate_dry_run(&mut result, 512, 1);

        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0], "pre-existing error");
    }

    // -----------------------------------------------------------------------
    // record_gc_success
    // -----------------------------------------------------------------------

    #[test]
    fn test_record_gc_success_single_call() {
        let mut result = empty_gc_result(false);
        record_gc_success(&mut result, 2048, 4);

        assert_eq!(result.storage_keys_deleted, 1);
        assert_eq!(result.artifacts_removed, 4);
        assert_eq!(result.bytes_freed, 2048);
    }

    #[test]
    fn test_record_gc_success_multiple_calls() {
        let mut result = empty_gc_result(false);
        record_gc_success(&mut result, 1000, 1);
        record_gc_success(&mut result, 2000, 2);
        record_gc_success(&mut result, 3000, 3);

        assert_eq!(result.storage_keys_deleted, 3);
        assert_eq!(result.artifacts_removed, 6);
        assert_eq!(result.bytes_freed, 6000);
    }

    #[test]
    fn test_record_gc_success_zero_values() {
        let mut result = empty_gc_result(false);
        record_gc_success(&mut result, 0, 0);

        assert_eq!(result.storage_keys_deleted, 1);
        assert_eq!(result.artifacts_removed, 0);
        assert_eq!(result.bytes_freed, 0);
    }

    #[test]
    fn test_record_gc_success_preserves_errors() {
        let mut result = empty_gc_result(false);
        result.errors.push("earlier failure".to_string());
        record_gc_success(&mut result, 512, 1);

        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0], "earlier failure");
        assert_eq!(result.storage_keys_deleted, 1);
    }

    // -----------------------------------------------------------------------
    // StorageGcService::new and storage_for_location
    // -----------------------------------------------------------------------

    fn loc(backend: &str, path: &str) -> StorageLocation {
        StorageLocation {
            backend: backend.to_string(),
            path: path.to_string(),
        }
    }

    #[tokio::test]
    async fn test_storage_for_location_s3_returns_shared() {
        let service = make_service("s3");
        let storage_a = service.storage_for_location(&loc("s3", "/repo/a")).unwrap();
        let storage_b = service.storage_for_location(&loc("s3", "/repo/b")).unwrap();

        // Both should point to the same Arc allocation (the shared storage).
        assert!(Arc::ptr_eq(&storage_a, &storage_b));
    }

    #[tokio::test]
    async fn test_storage_for_location_azure_returns_shared() {
        let service = make_service("azure");
        let storage_a = service
            .storage_for_location(&loc("azure", "/data/repo1"))
            .unwrap();
        let storage_b = service
            .storage_for_location(&loc("azure", "/data/repo2"))
            .unwrap();

        assert!(Arc::ptr_eq(&storage_a, &storage_b));
    }

    #[tokio::test]
    async fn test_storage_for_location_gcs_returns_shared() {
        let service = make_service("gcs");
        let storage_a = service
            .storage_for_location(&loc("gcs", "/bucket/path1"))
            .unwrap();
        let storage_b = service
            .storage_for_location(&loc("gcs", "/bucket/path2"))
            .unwrap();

        assert!(Arc::ptr_eq(&storage_a, &storage_b));
    }

    #[tokio::test]
    async fn test_storage_for_location_filesystem_creates_new() {
        let service = make_service("filesystem");
        let storage_a = service
            .storage_for_location(&loc("filesystem", "/data/repo-a"))
            .unwrap();
        let storage_b = service
            .storage_for_location(&loc("filesystem", "/data/repo-b"))
            .unwrap();

        // Filesystem backends should be distinct allocations per path.
        assert!(!Arc::ptr_eq(&storage_a, &storage_b));
    }

    #[tokio::test]
    async fn test_storage_for_location_unknown_returns_error() {
        let service = make_service("filesystem");
        let result = service.storage_for_location(&loc("minio", "/local/path"));
        assert!(result.is_err(), "Unknown backend should return error");
    }

    #[tokio::test]
    async fn test_storage_for_location_cloud_ignores_path() {
        let service = make_service("s3");
        let storage_root = service.storage_for_location(&loc("s3", "/")).unwrap();
        let storage_deep = service
            .storage_for_location(&loc("s3", "/very/deep/nested/path/to/repo"))
            .unwrap();

        // Cloud backends always return the same shared storage regardless of path.
        assert!(Arc::ptr_eq(&storage_root, &storage_deep));
    }

    // -----------------------------------------------------------------------
    // run_gc (database error path)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_run_gc_returns_error_when_db_unreachable() {
        let service = make_service("filesystem");
        // The lazy pool has no real database behind it, so run_gc must fail
        // when it tries to execute the orphan query.
        let result = service.run_gc(false).await;
        assert!(result.is_err(), "run_gc should fail without a database");
    }

    #[tokio::test]
    async fn test_run_gc_dry_run_returns_error_when_db_unreachable() {
        let service = make_service("s3");
        let result = service.run_gc(true).await;
        assert!(
            result.is_err(),
            "run_gc dry_run should also fail without a database"
        );
    }

    /// Reference kind for [`insert_referenced_soft_deleted_artifact`].
    enum RefKind {
        /// Insert an `oci_tags` row pointing at the digest.
        Tag {
            image: &'static str,
            tag: &'static str,
        },
        /// Insert an `oci_blobs` row pointing at the digest.
        Blob,
    }

    /// Set up the canonical "soft-deleted artifact still referenced by an
    /// OCI table" scenario for storage-GC isolation tests.
    ///
    /// Inserts an `oci_tags` or `oci_blobs` row for `digest` and a
    /// soft-deleted `artifacts` row pointing at the same `storage_key`.
    /// Returns the byte size that was written to the `artifacts` row so
    /// callers can correlate with on-disk data when needed.
    ///
    /// Centralizing this layout removes the boilerplate duplication that
    /// previously lived inline in the three GC isolation tests and makes
    /// it easy for new regression tests to follow the same pattern.
    async fn insert_referenced_soft_deleted_artifact(
        pool: &PgPool,
        repo_id: Uuid,
        user_id: Uuid,
        digest: &str,
        storage_key: &str,
        size_bytes: i64,
        kind: RefKind,
    ) {
        let (path, name, version, content_type, checksum) = match &kind {
            RefKind::Tag { image, tag } => {
                sqlx::query(
                    r#"
                    INSERT INTO oci_tags (
                        repository_id, name, tag, manifest_digest, manifest_content_type
                    )
                    VALUES ($1, $2, $3, $4, 'application/vnd.oci.image.manifest.v1+json')
                    "#,
                )
                .bind(repo_id)
                .bind(*image)
                .bind(*tag)
                .bind(digest)
                .execute(pool)
                .await
                .expect("insert oci tag");
                (
                    format!("v2/{}/manifests/{}", image, tag),
                    format!("{}:{}", image, tag),
                    (*tag).to_string(),
                    "application/vnd.oci.image.manifest.v1+json",
                    digest.trim_start_matches("sha256:").to_string(),
                )
            }
            RefKind::Blob => {
                sqlx::query(
                    r#"
                    INSERT INTO oci_blobs (repository_id, digest, size_bytes, storage_key)
                    VALUES ($1, $2, $3, $4)
                    "#,
                )
                .bind(repo_id)
                .bind(digest)
                .bind(size_bytes)
                .bind(storage_key)
                .execute(pool)
                .await
                .expect("insert oci blob");
                (
                    format!("v2/gc-image/blobs/{}", digest),
                    format!("gc-image:{}", digest),
                    digest.to_string(),
                    "application/octet-stream",
                    digest.trim_start_matches("sha256:").to_string(),
                )
            }
        };

        sqlx::query(
            r#"
            INSERT INTO artifacts (
                id, repository_id, path, name, version, size_bytes,
                checksum_sha256, content_type, storage_key, uploaded_by, is_deleted
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, true)
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(repo_id)
        .bind(path)
        .bind(name)
        .bind(version)
        .bind(size_bytes)
        .bind(checksum)
        .bind(content_type)
        .bind(storage_key)
        .bind(user_id)
        .execute(pool)
        .await
        .expect("insert soft-deleted artifact");
    }

    /// Assert that `(storage_key, "filesystem", storage_path)` does NOT
    /// appear in the dry-run orphan-candidate set returned by
    /// [`StorageGcService::select_orphans`]. The per-key form is the
    /// isolation-safe alternative to asserting on the global
    /// `storage_keys_deleted` counter (see #1493).
    fn assert_key_not_orphaned(
        orphans: &[sqlx::postgres::PgRow],
        storage_key: &str,
        storage_path: &str,
        ref_kind: &str,
    ) {
        let our_key_collected = orphans.iter().any(|row| {
            let key: String = row.try_get("storage_key").unwrap_or_default();
            let backend: String = row.try_get("storage_backend").unwrap_or_default();
            let path: String = row.try_get("storage_path").unwrap_or_default();
            key == storage_key && backend == "filesystem" && path == storage_path
        });
        assert!(
            !our_key_collected,
            "GC must not flag {} as orphan while it is still referenced by {}",
            storage_key, ref_kind
        );
    }

    #[tokio::test]
    async fn test_run_gc_dry_run_keeps_oci_manifest_referenced_by_tag() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let digest = format!("sha256:{}", "a".repeat(64));
        let storage_key = format!("oci-manifests/{}", digest);

        insert_referenced_soft_deleted_artifact(
            &fixture.pool,
            fixture.repo_id,
            fixture.user_id,
            &digest,
            &storage_key,
            123,
            RefKind::Tag {
                image: "gc-image",
                tag: "latest",
            },
        )
        .await;

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let orphans = service.select_orphans().await;

        let storage_path_str = fixture.storage_dir.to_string_lossy().into_owned();
        fixture.teardown().await;

        let orphans = orphans.expect("dry-run candidate scan succeeds");
        assert_key_not_orphaned(&orphans, &storage_key, &storage_path_str, "oci_tags");
    }

    #[tokio::test]
    async fn test_run_gc_dry_run_keeps_oci_blob_referenced_by_blob_index() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let digest = format!("sha256:{}", "b".repeat(64));
        let storage_key = format!("oci-blobs/{}", digest);

        insert_referenced_soft_deleted_artifact(
            &fixture.pool,
            fixture.repo_id,
            fixture.user_id,
            &digest,
            &storage_key,
            456,
            RefKind::Blob,
        )
        .await;

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let orphans = service.select_orphans().await;

        let storage_path_str = fixture.storage_dir.to_string_lossy().into_owned();
        fixture.teardown().await;

        let orphans = orphans.expect("dry-run candidate scan succeeds");
        assert_key_not_orphaned(&orphans, &storage_key, &storage_path_str, "oci_blobs");
    }

    /// End-to-end variant of the manifest-survival test: run GC with
    /// `dry_run = false` so the entire delete path executes (storage delete
    /// + promotion_approvals + artifacts hard-delete) and assert the
    /// physical manifest file is still on disk afterward.
    ///
    /// The dry-run tests above prove the SQL filter is correct; this proves
    /// the filter is also honored by the code path that actually deletes
    /// files. Without this, a future refactor of the delete loop could
    /// regress the fix and the dry-run tests would still pass.
    #[tokio::test]
    async fn test_run_gc_live_keeps_oci_manifest_referenced_by_tag() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let digest = format!("sha256:{}", "c".repeat(64));
        let storage_key = format!("oci-manifests/{}", digest);
        let manifest_body = Bytes::from_static(
            b"{\"schemaVersion\":2,\"mediaType\":\
              \"application/vnd.oci.image.manifest.v1+json\",\"config\":{},\"layers\":[]}",
        );

        // Materialize the manifest in the filesystem backend so the GC
        // delete path has a real file to operate on.
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");
        storage
            .put(&storage_key, manifest_body.clone())
            .await
            .expect("write manifest to storage");
        assert!(
            storage.exists(&storage_key).await.expect("exists check"),
            "manifest must exist before GC runs"
        );

        insert_referenced_soft_deleted_artifact(
            &fixture.pool,
            fixture.repo_id,
            fixture.user_id,
            &digest,
            &storage_key,
            manifest_body.len() as i64,
            RefKind::Tag {
                image: "gc-image-live",
                tag: "latest",
            },
        )
        .await;

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let _ = service.run_gc(false).await.expect("live gc succeeds");

        let file_still_exists = storage.exists(&storage_key).await.expect("exists check");
        let row_still_exists = count_soft_deleted_with_key(&fixture.pool, &storage_key).await == 1;

        fixture.teardown().await;

        // Per-key assertions: concurrent integration tests share this DB,
        // so the global `storage_keys_deleted` counter is not isolation-safe
        // here. Verifying our specific row + file survived is.
        assert!(
            row_still_exists,
            "soft-deleted artifact row for {} must survive a live GC pass while oci_tags references it",
            storage_key
        );
        assert!(
            file_still_exists,
            "manifest file must remain on disk after a live GC pass when oci_tags references it"
        );
    }

    #[tokio::test]
    async fn test_run_gc_removes_abandoned_oci_upload_session_storage() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let (storage, upload_id, temp_key, part_key) =
            seed_abandoned_oci_upload_session(&fixture).await;

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let result = service.run_gc(false).await.expect("live gc succeeds");

        let temp_exists = storage.exists(&temp_key).await.expect("temp exists check");
        let part_exists = storage.exists(&part_key).await.expect("part exists check");
        let session_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM oci_upload_sessions WHERE id = $1")
                .bind(upload_id)
                .fetch_one(&fixture.pool)
                .await
                .expect("count upload sessions");
        let part_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_upload_parts WHERE upload_session_id = $1",
        )
        .bind(upload_id)
        .fetch_one(&fixture.pool)
        .await
        .expect("count upload parts");
        let key_errors = result
            .errors
            .iter()
            .filter(|err| err.contains(&temp_key) || err.contains(&part_key))
            .cloned()
            .collect::<Vec<_>>();

        fixture.teardown().await;

        assert!(
            key_errors.is_empty(),
            "GC produced errors for abandoned upload keys: {:?}",
            key_errors
        );
        assert!(!temp_exists, "GC must delete stale upload temp objects");
        assert!(!part_exists, "GC must delete stale upload part objects");
        assert_eq!(session_count, 0, "GC must remove the stale upload session");
        assert_eq!(part_count, 0, "GC must cascade stale upload parts");
        assert!(
            result.storage_keys_deleted >= 2,
            "GC result should include the upload temp and part keys"
        );
    }

    #[tokio::test]
    async fn test_run_gc_dry_run_reports_abandoned_oci_upload_session_storage() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let (storage, upload_id, temp_key, part_key) =
            seed_abandoned_oci_upload_session(&fixture).await;

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let result = service.run_gc(true).await.expect("dry-run gc succeeds");

        let temp_exists = storage.exists(&temp_key).await.expect("temp exists check");
        let part_exists = storage.exists(&part_key).await.expect("part exists check");
        let session_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM oci_upload_sessions WHERE id = $1")
                .bind(upload_id)
                .fetch_one(&fixture.pool)
                .await
                .expect("count upload sessions");
        let part_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_upload_parts WHERE upload_session_id = $1",
        )
        .bind(upload_id)
        .fetch_one(&fixture.pool)
        .await
        .expect("count upload parts");
        let key_errors = result
            .errors
            .iter()
            .filter(|err| err.contains(&temp_key) || err.contains(&part_key))
            .cloned()
            .collect::<Vec<_>>();

        fixture.teardown().await;

        assert!(
            key_errors.is_empty(),
            "dry-run GC produced errors for abandoned upload keys: {:?}",
            key_errors
        );
        assert!(temp_exists, "dry-run must not delete upload temp objects");
        assert!(part_exists, "dry-run must not delete upload part objects");
        assert_eq!(session_count, 1, "dry-run must keep the upload session");
        assert_eq!(part_count, 1, "dry-run must keep upload parts");
        assert!(
            result.storage_keys_deleted >= 2,
            "dry-run result should count the upload temp and part keys"
        );
        assert!(
            result.bytes_freed >= 8,
            "dry-run result should count abandoned upload bytes"
        );
    }

    #[tokio::test]
    async fn test_run_gc_removes_unreferenced_oci_upload_cleanup_key_storage() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let storage_key = format!(
            "oci-uploads/{}.part.00000000.{}",
            Uuid::new_v4(),
            Uuid::new_v4()
        );
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");
        storage
            .put(&storage_key, Bytes::from_static(b"unreferenced"))
            .await
            .expect("write unreferenced cleanup key");

        sqlx::query(
            r#"
            INSERT INTO oci_upload_cleanup_keys (
                repository_id, storage_key, created_at, storage_write_completed_at
            )
            VALUES ($1, $2, NOW() - INTERVAL '25 hours', NOW() - INTERVAL '25 hours')
            "#,
        )
        .bind(fixture.repo_id)
        .bind(&storage_key)
        .execute(&fixture.pool)
        .await
        .expect("insert cleanup key row");

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let result = service.run_gc(false).await.expect("live gc succeeds");

        let key_exists = storage.exists(&storage_key).await.expect("exists check");
        let cleanup_key_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_upload_cleanup_keys WHERE storage_key = $1",
        )
        .bind(&storage_key)
        .fetch_one(&fixture.pool)
        .await
        .expect("count cleanup key rows");
        let key_errors = result
            .errors
            .iter()
            .filter(|err| err.contains(&storage_key))
            .cloned()
            .collect::<Vec<_>>();

        fixture.teardown().await;

        assert!(
            key_errors.is_empty(),
            "GC produced errors for cleanup key: {:?}",
            key_errors
        );
        assert!(
            !key_exists,
            "GC must delete unreferenced cleanup-key storage"
        );
        assert_eq!(cleanup_key_count, 0, "GC must delete cleanup-key row");
        assert!(
            result.storage_keys_deleted >= 1,
            "GC result should include the cleanup-key storage object"
        );
    }

    #[tokio::test]
    async fn test_run_gc_keeps_cleanup_key_referenced_by_active_upload_part() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let upload_id = Uuid::new_v4();
        let temp_key = format!("oci-uploads/{}", upload_id);
        let part_key = format!("{}.part.00000000.{}", temp_key, Uuid::new_v4());
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");
        storage
            .put(&part_key, Bytes::from_static(b"active"))
            .await
            .expect("write active part");

        sqlx::query(
            r#"
            INSERT INTO oci_upload_sessions (
                id, repository_id, user_id, bytes_received, storage_temp_key, updated_at
            )
            VALUES ($1, $2, $3, 6, $4, NOW())
            "#,
        )
        .bind(upload_id)
        .bind(fixture.repo_id)
        .bind(fixture.user_id)
        .bind(&temp_key)
        .execute(&fixture.pool)
        .await
        .expect("insert active upload session");
        sqlx::query(
            r#"
            INSERT INTO oci_upload_parts (
                upload_session_id, part_index, storage_key, size_bytes, digest_sha256
            )
            VALUES ($1, 0, $2, 6, 'unused-test-digest')
            "#,
        )
        .bind(upload_id)
        .bind(&part_key)
        .execute(&fixture.pool)
        .await
        .expect("insert active upload part");
        sqlx::query(
            r#"
            INSERT INTO oci_upload_cleanup_keys (
                repository_id, upload_session_id, storage_key, created_at,
                storage_write_completed_at
            )
            VALUES ($1, $2, $3, NOW() - INTERVAL '25 hours', NOW() - INTERVAL '25 hours')
            "#,
        )
        .bind(fixture.repo_id)
        .bind(upload_id)
        .bind(&part_key)
        .execute(&fixture.pool)
        .await
        .expect("insert cleanup key row");

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let result = service.run_gc(false).await.expect("live gc succeeds");

        let key_exists = storage.exists(&part_key).await.expect("exists check");
        let cleanup_key_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_upload_cleanup_keys WHERE storage_key = $1",
        )
        .bind(&part_key)
        .fetch_one(&fixture.pool)
        .await
        .expect("count cleanup key rows");
        let key_errors = result
            .errors
            .iter()
            .filter(|err| err.contains(&part_key))
            .cloned()
            .collect::<Vec<_>>();

        fixture.teardown().await;

        assert!(
            key_errors.is_empty(),
            "GC produced errors for active cleanup key: {:?}",
            key_errors
        );
        assert!(key_exists, "GC must not delete active upload part storage");
        assert_eq!(
            cleanup_key_count, 1,
            "GC must keep cleanup row while a live part references it"
        );
    }

    #[tokio::test]
    async fn test_run_gc_keeps_cleanup_key_referenced_by_active_upload_session() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let upload_id = Uuid::new_v4();
        let temp_key = format!("oci-uploads/{}", upload_id);
        let pending_part_key = format!("{}.part.00000001.{}", temp_key, Uuid::new_v4());
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");
        storage
            .put(&pending_part_key, Bytes::from_static(b"pending"))
            .await
            .expect("write pending part");

        sqlx::query(
            r#"
            INSERT INTO oci_upload_sessions (
                id, repository_id, user_id, bytes_received, storage_temp_key, updated_at
            )
            VALUES ($1, $2, $3, 7, $4, NOW())
            "#,
        )
        .bind(upload_id)
        .bind(fixture.repo_id)
        .bind(fixture.user_id)
        .bind(&temp_key)
        .execute(&fixture.pool)
        .await
        .expect("insert active upload session");
        sqlx::query(
            r#"
            INSERT INTO oci_upload_cleanup_keys (
                repository_id, upload_session_id, storage_key, created_at
            )
            VALUES ($1, $2, $3, NOW() - INTERVAL '8 days')
            "#,
        )
        .bind(fixture.repo_id)
        .bind(upload_id)
        .bind(&pending_part_key)
        .execute(&fixture.pool)
        .await
        .expect("insert cleanup key row");

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let result = service.run_gc(false).await.expect("live gc succeeds");

        let key_exists = storage
            .exists(&pending_part_key)
            .await
            .expect("exists check");
        let cleanup_key_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_upload_cleanup_keys WHERE storage_key = $1",
        )
        .bind(&pending_part_key)
        .fetch_one(&fixture.pool)
        .await
        .expect("count cleanup key rows");
        let key_errors = result
            .errors
            .iter()
            .filter(|err| err.contains(&pending_part_key))
            .cloned()
            .collect::<Vec<_>>();

        fixture.teardown().await;

        assert!(
            key_errors.is_empty(),
            "GC produced errors for active-session cleanup key: {:?}",
            key_errors
        );
        assert!(
            key_exists,
            "GC must not delete pending upload storage while its session is live"
        );
        assert_eq!(
            cleanup_key_count, 1,
            "GC must keep cleanup row while a live upload session references it"
        );
    }

    #[tokio::test]
    async fn test_run_gc_keeps_pending_cleanup_key_until_storage_write_is_marked() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let storage_key = format!(
            "oci-uploads/{}.part.00000000.{}",
            Uuid::new_v4(),
            Uuid::new_v4()
        );
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");

        // A recent (within-TTL) pending row: the writer may still be racing
        // to create the object and mark the write complete, so GC must leave
        // it alone. Only once the row ages past the TTL without being marked
        // does the pending reaper treat it as a crashed-writer leak
        // (covered by test_run_gc_reaps_aged_pending_oci_upload_cleanup_key).
        sqlx::query(
            r#"
            INSERT INTO oci_upload_cleanup_keys (repository_id, storage_key, created_at)
            VALUES ($1, $2, NOW())
            "#,
        )
        .bind(fixture.repo_id)
        .bind(&storage_key)
        .execute(&fixture.pool)
        .await
        .expect("insert pending cleanup key row");

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let result = service.run_gc(false).await.expect("live gc succeeds");

        let key_exists = storage.exists(&storage_key).await.expect("exists check");
        let cleanup_key_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_upload_cleanup_keys WHERE storage_key = $1",
        )
        .bind(&storage_key)
        .fetch_one(&fixture.pool)
        .await
        .expect("count cleanup key rows");
        let key_errors = result
            .errors
            .iter()
            .filter(|err| err.contains(&storage_key))
            .cloned()
            .collect::<Vec<_>>();

        fixture.teardown().await;

        assert!(
            key_errors.is_empty(),
            "GC produced errors for missing pending cleanup key: {:?}",
            key_errors
        );
        assert!(
            !key_exists,
            "test fixture should not create the pending key"
        );
        assert_eq!(
            cleanup_key_count, 1,
            "GC must keep a within-TTL pending cleanup row until the writer marks the storage write complete"
        );
    }

    /// An AGED, unreferenced NULL row (the writer crashed between the
    /// register INSERT and the storage-write-completed mark) must be
    /// reaped: the storage object is best-effort deleted and the row is
    /// removed. Without the reaper this row would leak forever because
    /// the committed-row sweep requires `storage_write_completed_at IS NOT
    /// NULL`.
    #[tokio::test]
    async fn test_run_gc_reaps_aged_pending_oci_upload_cleanup_key() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let storage_key = format!(
            "oci-uploads/{}.part.00000000.{}",
            Uuid::new_v4(),
            Uuid::new_v4()
        );
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");
        // The crashed write may or may not have materialized the object;
        // here we materialize it to assert the reaper deletes it.
        storage
            .put(&storage_key, Bytes::from_static(b"orphaned-pending"))
            .await
            .expect("write aged pending cleanup key");

        sqlx::query(
            r#"
            INSERT INTO oci_upload_cleanup_keys (repository_id, storage_key, created_at)
            VALUES ($1, $2, NOW() - INTERVAL '25 hours')
            "#,
        )
        .bind(fixture.repo_id)
        .bind(&storage_key)
        .execute(&fixture.pool)
        .await
        .expect("insert aged pending cleanup key row");

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let result = service.run_gc(false).await.expect("live gc succeeds");

        let key_exists = storage.exists(&storage_key).await.expect("exists check");
        let cleanup_key_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_upload_cleanup_keys WHERE storage_key = $1",
        )
        .bind(&storage_key)
        .fetch_one(&fixture.pool)
        .await
        .expect("count cleanup key rows");
        let key_errors = result
            .errors
            .iter()
            .filter(|err| err.contains(&storage_key))
            .cloned()
            .collect::<Vec<_>>();

        fixture.teardown().await;

        assert!(
            key_errors.is_empty(),
            "GC produced errors for aged pending cleanup key: {:?}",
            key_errors
        );
        assert!(
            !key_exists,
            "reaper must delete the storage object for an aged pending cleanup key"
        );
        assert_eq!(
            cleanup_key_count, 0,
            "reaper must delete the aged pending cleanup-key row"
        );
    }

    /// A RECENT NULL row (created within the TTL) must NOT be reaped: a
    /// write may still be in flight and racing to create the object, so
    /// reaping now could delete an object the writer is about to record.
    #[tokio::test]
    async fn test_run_gc_keeps_recent_pending_oci_upload_cleanup_key() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let storage_key = format!(
            "oci-uploads/{}.part.00000000.{}",
            Uuid::new_v4(),
            Uuid::new_v4()
        );
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");
        storage
            .put(&storage_key, Bytes::from_static(b"recent-pending"))
            .await
            .expect("write recent pending cleanup key");

        sqlx::query(
            r#"
            INSERT INTO oci_upload_cleanup_keys (repository_id, storage_key, created_at)
            VALUES ($1, $2, NOW())
            "#,
        )
        .bind(fixture.repo_id)
        .bind(&storage_key)
        .execute(&fixture.pool)
        .await
        .expect("insert recent pending cleanup key row");

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let result = service.run_gc(false).await.expect("live gc succeeds");

        let key_exists = storage.exists(&storage_key).await.expect("exists check");
        let cleanup_key_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_upload_cleanup_keys WHERE storage_key = $1",
        )
        .bind(&storage_key)
        .fetch_one(&fixture.pool)
        .await
        .expect("count cleanup key rows");
        let key_errors = result
            .errors
            .iter()
            .filter(|err| err.contains(&storage_key))
            .cloned()
            .collect::<Vec<_>>();

        fixture.teardown().await;

        assert!(
            key_errors.is_empty(),
            "GC produced errors for recent pending cleanup key: {:?}",
            key_errors
        );
        assert!(
            key_exists,
            "reaper must not delete the storage object for a recent pending cleanup key"
        );
        assert_eq!(
            cleanup_key_count, 1,
            "reaper must keep a recent pending cleanup-key row inside the TTL"
        );
    }

    /// An aged NULL row that is still referenced by a live upload session
    /// must NOT be reaped: the session still owns the storage object and
    /// will eventually finalize or be swept by the abandoned-session path.
    #[tokio::test]
    async fn test_run_gc_keeps_aged_pending_cleanup_key_referenced_by_live_session() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let upload_id = Uuid::new_v4();
        let temp_key = format!("oci-uploads/{}", upload_id);
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");
        storage
            .put(&temp_key, Bytes::from_static(b"live-session-temp"))
            .await
            .expect("write live session temp object");

        // A live (recently updated) session whose storage_temp_key matches
        // the cleanup row's storage_key, so the reaper's NOT EXISTS guard
        // must protect it despite the cleanup row being aged + NULL.
        sqlx::query(
            r#"
            INSERT INTO oci_upload_sessions (
                id, repository_id, user_id, bytes_received, storage_temp_key, updated_at
            )
            VALUES ($1, $2, $3, 0, $4, NOW())
            "#,
        )
        .bind(upload_id)
        .bind(fixture.repo_id)
        .bind(fixture.user_id)
        .bind(&temp_key)
        .execute(&fixture.pool)
        .await
        .expect("insert live upload session");
        sqlx::query(
            r#"
            INSERT INTO oci_upload_cleanup_keys (
                repository_id, upload_session_id, storage_key, created_at
            )
            VALUES ($1, $2, $3, NOW() - INTERVAL '25 hours')
            "#,
        )
        .bind(fixture.repo_id)
        .bind(upload_id)
        .bind(&temp_key)
        .execute(&fixture.pool)
        .await
        .expect("insert aged pending cleanup key row");

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let result = service.run_gc(false).await.expect("live gc succeeds");

        let key_exists = storage.exists(&temp_key).await.expect("exists check");
        let cleanup_key_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_upload_cleanup_keys WHERE storage_key = $1",
        )
        .bind(&temp_key)
        .fetch_one(&fixture.pool)
        .await
        .expect("count cleanup key rows");
        let key_errors = result
            .errors
            .iter()
            .filter(|err| err.contains(&temp_key))
            .cloned()
            .collect::<Vec<_>>();

        fixture.teardown().await;

        assert!(
            key_errors.is_empty(),
            "GC produced errors for referenced aged pending cleanup key: {:?}",
            key_errors
        );
        assert!(
            key_exists,
            "reaper must not delete storage referenced by a live upload session"
        );
        assert_eq!(
            cleanup_key_count, 1,
            "reaper must keep an aged pending cleanup row while a live session references it"
        );
    }

    // -----------------------------------------------------------------------
    // Regression for #1179: multi-arch index child-manifest protection
    // -----------------------------------------------------------------------

    /// Helper: count how many soft-deleted `artifacts` rows still exist
    /// for a given storage_key. Used by the #1179 / #1180 tests below to
    /// assert "the GC did/did not collect MY rows" rather than asserting
    /// global GC counts. Tests share the database with other concurrent
    /// integration tests, so global counts are unreliable for narrow
    /// regression assertions; per-key checks are not.
    async fn count_soft_deleted_with_key(pool: &PgPool, storage_key: &str) -> i64 {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM artifacts WHERE storage_key = $1 AND is_deleted = true",
        )
        .bind(storage_key)
        .fetch_one(pool)
        .await
        .expect("count soft-deleted artifacts")
    }

    async fn seed_abandoned_oci_upload_session(
        fixture: &crate::api::handlers::test_db_helpers::Fixture,
    ) -> (Arc<dyn StorageBackend>, Uuid, String, String) {
        let upload_id = Uuid::new_v4();
        let temp_key = format!("oci-uploads/{}", upload_id);
        let part_key = format!("{}.part.00000000.{}", temp_key, Uuid::new_v4());
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");

        storage
            .put(&temp_key, Bytes::new())
            .await
            .expect("write upload temp object");
        storage
            .put(&part_key, Bytes::from_static(b"orphaned"))
            .await
            .expect("write upload part object");

        sqlx::query(
            r#"
            INSERT INTO oci_upload_sessions (
                id, repository_id, user_id, bytes_received, storage_temp_key, updated_at
            )
            VALUES ($1, $2, $3, 8, $4, NOW() - INTERVAL '25 hours')
            "#,
        )
        .bind(upload_id)
        .bind(fixture.repo_id)
        .bind(fixture.user_id)
        .bind(&temp_key)
        .execute(&fixture.pool)
        .await
        .expect("insert abandoned upload session");
        sqlx::query(
            r#"
            INSERT INTO oci_upload_parts (
                upload_session_id, part_index, storage_key, size_bytes, digest_sha256
            )
            VALUES ($1, 0, $2, 8, $3)
            "#,
        )
        .bind(upload_id)
        .bind(&part_key)
        .bind("unused-test-digest")
        .execute(&fixture.pool)
        .await
        .expect("insert abandoned upload part");

        (storage, upload_id, temp_key, part_key)
    }

    /// Push a multi-arch image scenario: the index manifest is tagged
    /// (recorded in `oci_tags`) and its per-architecture child manifests
    /// are recorded in `oci_manifest_refs`. Each child manifest also has
    /// a soft-deleted `artifacts` row (a typical sequence: the index
    /// was tagged once with one child, then re-tagged with a new child,
    /// which soft-deleted the old child's `artifacts` row). Storage GC
    /// must not collect either the index or the children while the
    /// index remains tagged.
    ///
    /// Without the #1179 fix, the index itself is protected by
    /// `oci_tags` but the children are unprotected and a multi-arch
    /// `pull <repo>@<index-digest>` after GC would return
    /// MANIFEST_UNKNOWN for the platform-specific layers.
    ///
    /// Runs a live (non-dry-run) GC and asserts per-storage-key that
    /// the specific child rows survived, so concurrent integration
    /// tests against the same database cannot interfere.
    #[tokio::test]
    async fn test_run_gc_keeps_oci_index_child_manifests() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let image = "gc-multi-arch";
        let tag = "v1";
        let index_digest = format!("sha256:{}", "1".repeat(64));
        let child_amd64_digest = format!("sha256:{}", "2".repeat(64));
        let child_arm64_digest = format!("sha256:{}", "3".repeat(64));
        let child_keys = [
            format!("oci-manifests/{}", child_amd64_digest),
            format!("oci-manifests/{}", child_arm64_digest),
        ];

        // Materialize the index manifest body in storage so the live
        // GC delete path resolves real files. (The children themselves
        // do not need bodies; the GC's protection runs against the DB
        // predicates, not the filesystem.)
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");
        for child_key in &child_keys {
            storage
                .put(child_key, Bytes::from_static(b"{}"))
                .await
                .expect("write child manifest stub");
        }

        sqlx::query(
            r#"
            INSERT INTO oci_tags (
                repository_id, name, tag, manifest_digest, manifest_content_type
            )
            VALUES ($1, $2, $3, $4, 'application/vnd.oci.image.index.v1+json')
            "#,
        )
        .bind(fixture.repo_id)
        .bind(image)
        .bind(tag)
        .bind(&index_digest)
        .execute(&fixture.pool)
        .await
        .expect("insert oci tag for index");

        for child in [&child_amd64_digest, &child_arm64_digest] {
            sqlx::query(
                r#"
                INSERT INTO oci_manifest_refs (parent_digest, child_digest, repository_id)
                VALUES ($1, $2, $3)
                "#,
            )
            .bind(&index_digest)
            .bind(child)
            .bind(fixture.repo_id)
            .execute(&fixture.pool)
            .await
            .expect("insert oci_manifest_refs row");

            // A soft-deleted artifacts row makes the child a GC candidate
            // unless something else protects it. The new oci_manifest_refs
            // NOT EXISTS clause is the only thing that should protect it
            // here: the child digest is not in oci_tags or oci_blobs.
            sqlx::query(
                r#"
                INSERT INTO artifacts (
                    id, repository_id, path, name, version, size_bytes,
                    checksum_sha256, content_type, storage_key, uploaded_by, is_deleted
                )
                VALUES (
                    $1, $2, $3, $4, $5, 1024,
                    $6, 'application/vnd.oci.image.manifest.v1+json', $7, $8, true
                )
                "#,
            )
            .bind(Uuid::new_v4())
            .bind(fixture.repo_id)
            .bind(format!("v2/{}/manifests/{}", image, child))
            .bind(format!("{}:{}", image, child))
            .bind(child)
            .bind(child.trim_start_matches("sha256:"))
            .bind(format!("oci-manifests/{}", child))
            .bind(fixture.user_id)
            .execute(&fixture.pool)
            .await
            .expect("insert soft-deleted child artifact");
        }

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let _ = service.run_gc(false).await.expect("live gc succeeds");

        let mut surviving = Vec::new();
        for child_key in &child_keys {
            surviving.push((
                child_key.clone(),
                count_soft_deleted_with_key(&fixture.pool, child_key).await,
                storage.exists(child_key).await.expect("exists check"),
            ));
        }

        fixture.teardown().await;

        for (key, db_count, on_disk) in surviving {
            assert_eq!(
                db_count, 1,
                "child manifest row {} must survive GC while the parent index is tagged",
                key
            );
            assert!(
                on_disk,
                "child manifest file {} must remain on disk after GC",
                key
            );
        }
    }

    /// Counterpart: once the parent index tag is gone, the children
    /// become eligible for collection. Verifies the predicate is keyed
    /// on the parent being live in `oci_tags`, not just on the presence
    /// of any `oci_manifest_refs` row.
    ///
    /// Asserts per-storage-key (live GC) so the test does not collide
    /// with other DB-using tests running in parallel against a shared
    /// Postgres instance.
    #[tokio::test]
    async fn test_run_gc_collects_orphaned_index_children() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let image = "gc-multi-arch-orphan";
        let index_digest = format!("sha256:{}", "4".repeat(64));
        let child_digest = format!("sha256:{}", "5".repeat(64));
        let child_key = format!("oci-manifests/{}", child_digest);

        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");
        storage
            .put(&child_key, Bytes::from_static(b"{}"))
            .await
            .expect("write child manifest stub");

        // oci_manifest_refs row exists, but oci_tags does NOT point at
        // the index (e.g. the tag was overwritten or deleted).
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
        .expect("insert orphaned ref row");

        sqlx::query(
            r#"
            INSERT INTO artifacts (
                id, repository_id, path, name, version, size_bytes,
                checksum_sha256, content_type, storage_key, uploaded_by, is_deleted
            )
            VALUES (
                $1, $2, $3, $4, $5, 1024,
                $6, 'application/vnd.oci.image.manifest.v1+json', $7, $8, true
            )
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(fixture.repo_id)
        .bind(format!("v2/{}/manifests/{}", image, child_digest))
        .bind(format!("{}:{}", image, child_digest))
        .bind(&child_digest)
        .bind(child_digest.trim_start_matches("sha256:"))
        .bind(&child_key)
        .bind(fixture.user_id)
        .execute(&fixture.pool)
        .await
        .expect("insert soft-deleted child artifact");

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let _ = service.run_gc(false).await.expect("live gc succeeds");

        let remaining_rows = count_soft_deleted_with_key(&fixture.pool, &child_key).await;
        let file_still_exists = storage.exists(&child_key).await.expect("exists check");

        fixture.teardown().await;

        assert_eq!(
            remaining_rows, 0,
            "child manifest of an untagged index should be hard-deleted by GC"
        );
        assert!(
            !file_still_exists,
            "child manifest file must be removed from storage when no parent tag protects it"
        );
    }

    // -----------------------------------------------------------------------
    // Regression for #1180: TOCTOU race between SELECT and per-key delete
    // -----------------------------------------------------------------------

    /// Race a tag-insert against the per-key re-verification window.
    ///
    /// The simulation: pre-stage a soft-deleted artifact that would
    /// normally be collected, run GC, but BEFORE the re-check runs (or
    /// while it runs against an empty `oci_tags`), race in an
    /// `oci_tags` row pointing at the same manifest digest. The new
    /// FOR UPDATE re-check must observe the inserted row and skip the
    /// delete; the storage file must survive.
    ///
    /// Synchronization approach: we run GC inside one task and the
    /// racing tag-insert inside another, joined via `tokio::join!`. To
    /// make the race deterministic we drive it inside a transaction
    /// the test controls: the tag-insert task starts its tx, inserts
    /// the protecting row, sleeps briefly to let GC's outer SELECT run
    /// (which uses its own connection and will observe the empty
    /// `oci_tags` since the insert is uncommitted), then commits. The
    /// GC's per-key re-check runs after, sees the committed row, and
    /// skips the delete.
    ///
    /// On a system without the FOR UPDATE re-check (the pre-#1180
    /// code), the racing tag-insert would be observed by neither the
    /// outer SELECT nor the per-key delete, and GC would proceed to
    /// remove the storage file even though it is now referenced.
    #[tokio::test]
    async fn test_run_gc_toctou_skips_key_when_tag_inserted_during_pass() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let image = "gc-race";
        let tag = "racy";
        let digest = format!("sha256:{}", "9".repeat(64));
        let storage_key = format!("oci-manifests/{}", digest);
        let manifest_body = Bytes::from_static(
            b"{\"schemaVersion\":2,\"mediaType\":\
              \"application/vnd.oci.image.manifest.v1+json\",\"config\":{},\"layers\":[]}",
        );

        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");
        storage
            .put(&storage_key, manifest_body.clone())
            .await
            .expect("write manifest to storage");

        sqlx::query(
            r#"
            INSERT INTO artifacts (
                id, repository_id, path, name, version, size_bytes,
                checksum_sha256, content_type, storage_key, uploaded_by, is_deleted
            )
            VALUES (
                $1, $2, $3, $4, $5, $9,
                $6, 'application/vnd.oci.image.manifest.v1+json', $7, $8, true
            )
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(fixture.repo_id)
        .bind(format!("v2/{}/manifests/{}", image, tag))
        .bind(format!("{}:{}", image, tag))
        .bind(tag)
        .bind("9".repeat(64))
        .bind(&storage_key)
        .bind(fixture.user_id)
        .bind(manifest_body.len() as i64)
        .execute(&fixture.pool)
        .await
        .expect("insert soft-deleted artifact");

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());

        // Channel to let the racer signal "I have started my tx and
        // inserted the protecting row" so we can deterministically
        // order: outer SELECT runs first (no protecting row visible),
        // then the racer commits before the per-key re-check runs.
        let (insert_started_tx, insert_started_rx) = tokio::sync::oneshot::channel::<()>();
        let (gc_outer_select_done_tx, gc_outer_select_done_rx) =
            tokio::sync::oneshot::channel::<()>();

        let pool_for_racer = fixture.pool.clone();
        let repo_id = fixture.repo_id;
        let digest_for_racer = digest.clone();
        let image_for_racer = image.to_string();
        let tag_for_racer = tag.to_string();

        let racer = tokio::spawn(async move {
            // Wait until GC has run its outer SELECT so we are racing
            // with the per-key delete window, not the initial scan.
            gc_outer_select_done_rx
                .await
                .expect("gc signals after outer select");
            // The protecting tag-insert. The pre-#1180 code path would
            // happily delete the storage file because its per-key
            // delete did not re-check, so the new live row would point
            // at a dangling key.
            sqlx::query(
                r#"
                INSERT INTO oci_tags (
                    repository_id, name, tag, manifest_digest, manifest_content_type
                )
                VALUES ($1, $2, $3, $4, 'application/vnd.oci.image.manifest.v1+json')
                "#,
            )
            .bind(repo_id)
            .bind(image_for_racer)
            .bind(tag_for_racer)
            .bind(digest_for_racer)
            .execute(&pool_for_racer)
            .await
            .expect("racing tag insert");

            // Signal the GC task to proceed into its per-key delete now
            // that the protecting row is committed.
            insert_started_tx
                .send(())
                .expect("signal gc to continue after insert");
        });

        let gc_task = async {
            // Manually replicate run_gc but expose the SELECT-vs-recheck
            // boundary so the racer can land its insert at the right
            // moment. We can't insert this hook into the production
            // run_gc method without polluting its signature, so instead
            // we drive the service through its public API and rely on
            // synchronization via two oneshot channels.

            // Step 1: call the outer SELECT directly through the same
            // service instance so we can signal afterwards.
            let orphans = service.select_orphans().await.expect("select orphans");
            assert!(
                orphans.iter().any(|r| {
                    let key: String = r.try_get("storage_key").unwrap_or_default();
                    key == storage_key
                }),
                "outer SELECT should still see the candidate before the racer commits"
            );

            // Signal the racer that the outer SELECT has run, then
            // wait for the racer's INSERT to commit.
            gc_outer_select_done_tx
                .send(())
                .expect("signal racer after outer select");
            insert_started_rx.await.expect("racer signals after insert");

            // Step 2: run the full GC pass. Internally this re-issues
            // the outer SELECT and then the per-key transactional
            // re-check, which is now expected to find the protecting
            // oci_tags row and skip the delete.
            service.run_gc(false).await.expect("gc run")
        };

        let (gc_result, _) = tokio::join!(gc_task, racer);

        let file_still_exists = storage.exists(&storage_key).await.expect("exists check");
        let row_still_exists = count_soft_deleted_with_key(&fixture.pool, &storage_key).await == 1;
        let any_error_for_our_key = gc_result
            .errors
            .iter()
            .any(|e| e.contains(storage_key.as_str()));

        fixture.teardown().await;

        assert!(
            !any_error_for_our_key,
            "GC produced an error for our specific key (other-test errors ignored): \
             our key {}, all errors {:?}",
            storage_key, gc_result.errors
        );
        assert!(
            file_still_exists,
            "manifest file must survive the racing tag insert"
        );
        assert!(
            row_still_exists,
            "the soft-deleted artifact row must still exist (not hard-deleted) after the racing \
             tag insert"
        );
    }

    // -----------------------------------------------------------------------
    // clamp_grace_hours (issue #1408 blob footprint report)
    // -----------------------------------------------------------------------

    #[test]
    fn test_clamp_grace_hours_zero_falls_back_to_default() {
        assert_eq!(clamp_grace_hours(0), BLOB_REPORT_GRACE_HOURS_DEFAULT);
    }

    #[test]
    fn test_clamp_grace_hours_negative_falls_back_to_default() {
        assert_eq!(clamp_grace_hours(-5), BLOB_REPORT_GRACE_HOURS_DEFAULT);
        assert_eq!(clamp_grace_hours(i64::MIN), BLOB_REPORT_GRACE_HOURS_DEFAULT);
    }

    #[test]
    fn test_clamp_grace_hours_passes_through_normal_values() {
        assert_eq!(clamp_grace_hours(1), 1);
        assert_eq!(clamp_grace_hours(24), 24);
        assert_eq!(clamp_grace_hours(168), 168);
    }

    #[test]
    fn test_clamp_grace_hours_caps_at_one_year() {
        let one_year = 24 * 365;
        assert_eq!(clamp_grace_hours(one_year), one_year);
        assert_eq!(clamp_grace_hours(one_year + 1), one_year);
        assert_eq!(clamp_grace_hours(i64::MAX), one_year);
    }

    #[test]
    fn test_clamp_grace_hours_default_is_positive() {
        // A zero input must clamp to a strictly positive window, otherwise
        // the upload-race guard the grace window represents is defeated.
        assert!(clamp_grace_hours(0) > 0);
    }

    // -----------------------------------------------------------------------
    // OciBlobFootprintReport / OciBlobRepoFootprint serde contract
    // -----------------------------------------------------------------------

    fn sample_report() -> OciBlobFootprintReport {
        OciBlobFootprintReport {
            total_blob_rows: 120,
            distinct_digests: 95,
            logical_bytes: 432_000_000_000,
            physical_bytes: 403_000_000_000,
            grace_hours: 24,
            aged_distinct_digests: 80,
            aged_physical_bytes: 344_000_000_000,
            per_repository: vec![
                OciBlobRepoFootprint {
                    repository_id: Uuid::nil(),
                    blob_rows: 70,
                    logical_bytes: 300_000_000_000,
                },
                OciBlobRepoFootprint {
                    repository_id: Uuid::from_u128(1),
                    blob_rows: 50,
                    logical_bytes: 132_000_000_000,
                },
            ],
        }
    }

    #[test]
    fn test_blob_footprint_report_serde_roundtrip() {
        let original = sample_report();
        let json = serde_json::to_string(&original).unwrap();
        let restored: OciBlobFootprintReport = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, original);
    }

    #[test]
    fn test_blob_footprint_report_field_names() {
        let json = serde_json::to_string(&sample_report()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        for field in [
            "total_blob_rows",
            "distinct_digests",
            "logical_bytes",
            "physical_bytes",
            "grace_hours",
            "aged_distinct_digests",
            "aged_physical_bytes",
            "per_repository",
        ] {
            assert!(value.get(field).is_some(), "missing field '{field}'");
        }
    }

    #[test]
    fn test_blob_footprint_report_preserves_large_byte_totals() {
        // The whole point of the report is making ~403 GB visible; ensure the
        // i64 byte fields survive a serde round trip without truncation.
        let json = serde_json::to_string(&sample_report()).unwrap();
        let restored: OciBlobFootprintReport = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.logical_bytes, 432_000_000_000);
        assert_eq!(restored.physical_bytes, 403_000_000_000);
        assert_eq!(restored.aged_physical_bytes, 344_000_000_000);
    }

    #[test]
    fn test_blob_footprint_report_physical_le_logical_in_sample() {
        // Dedup-aware physical bytes can never exceed the double-counting
        // logical sum; the sample data must respect that invariant.
        let r = sample_report();
        assert!(r.physical_bytes <= r.logical_bytes);
        assert!(r.distinct_digests <= r.total_blob_rows);
        assert!(r.aged_physical_bytes <= r.physical_bytes);
        assert!(r.aged_distinct_digests <= r.distinct_digests);
    }

    #[test]
    fn test_blob_repo_footprint_serde_roundtrip() {
        let original = OciBlobRepoFootprint {
            repository_id: Uuid::from_u128(42),
            blob_rows: 7,
            logical_bytes: 9_999,
        };
        let json = serde_json::to_string(&original).unwrap();
        let restored: OciBlobRepoFootprint = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, original);
    }

    // -----------------------------------------------------------------------
    // map_repo_footprint / assemble_blob_footprint_report (pure assembly)
    // -----------------------------------------------------------------------

    #[test]
    fn test_map_repo_footprint_copies_all_fields() {
        let id = Uuid::from_u128(7);
        let row = map_repo_footprint(id, 13, 4096);
        assert_eq!(row.repository_id, id);
        assert_eq!(row.blob_rows, 13);
        assert_eq!(row.logical_bytes, 4096);
    }

    #[test]
    fn test_map_repo_footprint_zero_values() {
        let row = map_repo_footprint(Uuid::nil(), 0, 0);
        assert_eq!(row.repository_id, Uuid::nil());
        assert_eq!(row.blob_rows, 0);
        assert_eq!(row.logical_bytes, 0);
    }

    fn sample_totals() -> BlobFootprintTotals {
        BlobFootprintTotals {
            total_blob_rows: 120,
            distinct_digests: 95,
            logical_bytes: 432_000_000_000,
            physical_bytes: 403_000_000_000,
            aged_distinct_digests: 80,
            aged_physical_bytes: 344_000_000_000,
        }
    }

    #[test]
    fn test_assemble_blob_footprint_report_maps_every_total() {
        let totals = sample_totals();
        let per_repo = vec![
            map_repo_footprint(Uuid::nil(), 70, 300_000_000_000),
            map_repo_footprint(Uuid::from_u128(1), 50, 132_000_000_000),
        ];
        let report = assemble_blob_footprint_report(totals, 24, per_repo.clone());

        assert_eq!(report.total_blob_rows, totals.total_blob_rows);
        assert_eq!(report.distinct_digests, totals.distinct_digests);
        assert_eq!(report.logical_bytes, totals.logical_bytes);
        assert_eq!(report.physical_bytes, totals.physical_bytes);
        assert_eq!(report.aged_distinct_digests, totals.aged_distinct_digests);
        assert_eq!(report.aged_physical_bytes, totals.aged_physical_bytes);
        assert_eq!(report.per_repository, per_repo);
    }

    #[test]
    fn test_assemble_blob_footprint_report_echoes_grace_hours() {
        // The clamped grace window is threaded straight through; assembly
        // must not re-clamp or otherwise mutate it.
        let report = assemble_blob_footprint_report(sample_totals(), 168, vec![]);
        assert_eq!(report.grace_hours, 168);
        assert!(report.per_repository.is_empty());
    }

    #[test]
    fn test_assemble_blob_footprint_report_matches_sample_report_shape() {
        // Building via the assembly helper must yield the same value as the
        // hand-written sample used by the serde contract tests.
        let report = assemble_blob_footprint_report(
            sample_totals(),
            24,
            vec![
                map_repo_footprint(Uuid::nil(), 70, 300_000_000_000),
                map_repo_footprint(Uuid::from_u128(1), 50, 132_000_000_000),
            ],
        );
        assert_eq!(report, sample_report());
    }

    #[test]
    fn test_assemble_blob_footprint_report_empty_repositories() {
        let report = assemble_blob_footprint_report(
            BlobFootprintTotals {
                total_blob_rows: 0,
                distinct_digests: 0,
                logical_bytes: 0,
                physical_bytes: 0,
                aged_distinct_digests: 0,
                aged_physical_bytes: 0,
            },
            BLOB_REPORT_GRACE_HOURS_DEFAULT,
            vec![],
        );
        assert_eq!(report.total_blob_rows, 0);
        assert_eq!(report.grace_hours, BLOB_REPORT_GRACE_HOURS_DEFAULT);
        assert!(report.per_repository.is_empty());
    }

    #[test]
    fn test_blob_footprint_report_empty_per_repository() {
        let report = OciBlobFootprintReport {
            total_blob_rows: 0,
            distinct_digests: 0,
            logical_bytes: 0,
            physical_bytes: 0,
            grace_hours: BLOB_REPORT_GRACE_HOURS_DEFAULT,
            aged_distinct_digests: 0,
            aged_physical_bytes: 0,
            per_repository: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"per_repository\":[]"));
        let restored: OciBlobFootprintReport = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, report);
    }

    // -----------------------------------------------------------------------
    // run_blob_gc (#1408; deletion design ported from #1409)
    //
    // The no-DB error-mapping tests run anywhere. The database-backed tests
    // exercise the blob-orphan source against a real postgres + filesystem
    // backend; they are gated on `tdh::Fixture::setup` returning Some, which
    // only happens when DATABASE_URL is set and migrations are applied (the
    // same gate the pre-existing storage GC tests above use).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_run_blob_gc_returns_error_when_db_unreachable() {
        let service = make_service("filesystem");
        let result = service.run_blob_gc(false).await;
        assert!(
            result.is_err(),
            "run_blob_gc must fail when select_orphan_blobs cannot reach DB"
        );
    }

    #[tokio::test]
    async fn test_run_blob_gc_dry_run_returns_error_when_db_unreachable() {
        let service = make_service("s3");
        let result = service.run_blob_gc(true).await;
        assert!(
            result.is_err(),
            "run_blob_gc dry_run shares the same SELECT and must also fail without a DB"
        );
    }

    // Compile-time pins: the grace period stays inside a sane corridor.
    // 1 hour minimum gives in-flight pushes room to finish blob upload and
    // manifest PUT; 7 days maximum prevents long-lived debris from
    // accumulating after the user has long forgotten the abandoned upload.
    // Any change crossing these bounds should be a conscious policy
    // decision, not an accidental typo.
    const _BLOB_AGE_LOWER: () = assert!(MIN_BLOB_AGE_SECS >= 60 * 60);
    const _BLOB_AGE_UPPER: () = assert!(MIN_BLOB_AGE_SECS <= 7 * 24 * 60 * 60);

    /// Stash a blob row with a `created_at` far enough in the past that
    /// `MIN_BLOB_AGE_SECS` does not protect it.
    async fn insert_old_blob(
        pool: &PgPool,
        repo_id: Uuid,
        digest: &str,
        storage_key: &str,
        size: i64,
    ) {
        sqlx::query(
            r#"
            INSERT INTO oci_blobs (repository_id, digest, size_bytes, storage_key, created_at)
            VALUES ($1, $2, $3, $4, NOW() - INTERVAL '30 days')
            "#,
        )
        .bind(repo_id)
        .bind(digest)
        .bind(size)
        .bind(storage_key)
        .execute(pool)
        .await
        .expect("insert old oci_blobs row");
    }

    /// Flip a test repo to a cloud backend. On cloud, blob storage is a
    /// single content-addressed object shared by every repo on the bucket,
    /// so the GC predicate protects it cross-repo; filesystem fixtures (the
    /// default) get an independent copy per `storage_path`. Exercises the
    /// cloud branch of [`BLOB_PROTECTED_BY_REFS_SQL`].
    async fn set_repo_backend(pool: &PgPool, repo_id: Uuid, backend: &str) {
        sqlx::query("UPDATE repositories SET storage_backend = $2 WHERE id = $1")
            .bind(repo_id)
            .bind(backend)
            .execute(pool)
            .await
            .expect("update repo storage_backend");
    }

    /// Set up two repos that both hold the same aged blob digest, with a
    /// `manifest_blob_refs` entry only in repo A. Returns `(fixture_a,
    /// fixture_b, shared_digest)` or `None` when no DB is configured. Shared
    /// by the cloud and filesystem scope tests so they assert the backend
    /// difference without duplicating the setup.
    async fn setup_two_repos_one_ref(
        digest_seed: char,
    ) -> Option<(
        crate::api::handlers::test_db_helpers::Fixture,
        crate::api::handlers::test_db_helpers::Fixture,
        String,
    )> {
        use crate::api::handlers::test_db_helpers as tdh;
        let fixture_a = tdh::Fixture::setup("local", "docker").await?;
        let Some(fixture_b) = tdh::Fixture::setup("local", "docker").await else {
            fixture_a.teardown().await;
            return None;
        };

        let shared_digest = format!("sha256:{}", digest_seed.to_string().repeat(64));
        let storage_key = format!("oci-blobs/{}", shared_digest);
        // Repo A has the blob and a manifest referencing it.
        insert_old_blob(
            &fixture_a.pool,
            fixture_a.repo_id,
            &shared_digest,
            &storage_key,
            555,
        )
        .await;
        sqlx::query(
            r#"
            INSERT INTO manifest_blob_refs (manifest_digest, blob_digest, repository_id, kind)
            VALUES ($1, $2, $3, 'layer')
            "#,
        )
        .bind(format!("sha256:{}", "1".repeat(64)))
        .bind(&shared_digest)
        .bind(fixture_a.repo_id)
        .execute(&fixture_a.pool)
        .await
        .expect("insert ref in repo A");
        // Repo B has the same blob digest but no manifest references it.
        insert_old_blob(
            &fixture_b.pool,
            fixture_b.repo_id,
            &shared_digest,
            &storage_key,
            555,
        )
        .await;

        Some((fixture_a, fixture_b, shared_digest))
    }

    /// Report whether the blob `(repo_id, digest)` WOULD be flagged orphan,
    /// re-evaluating the exact backend-aware predicate `select_orphan_blobs`
    /// uses ([`BLOB_PROTECTED_BY_REFS_SQL`]). Scoped to one (repo, digest)
    /// so concurrent tests' rows can't leak into the assertion, and so
    /// cloud-vs-filesystem scoping is observable from the evaluated repo's
    /// perspective.
    async fn would_gc_flag_blob(pool: &PgPool, repo_id: Uuid, digest: &str) -> bool {
        let sql = format!(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM oci_blobs ob
                JOIN repositories r ON r.id = ob.repository_id
                WHERE ob.repository_id = $1
                  AND ob.digest = $2
                  AND ob.created_at < NOW() - make_interval(secs => $3::BIGINT)
                  AND NOT {protected}
            )
            "#,
            protected = BLOB_PROTECTED_BY_REFS_SQL,
        );
        sqlx::query_scalar::<_, bool>(&sql)
            .bind(repo_id)
            .bind(digest)
            .bind(MIN_BLOB_AGE_SECS as i64)
            .fetch_one(pool)
            .await
            .expect("orphan-blob predicate check")
    }

    #[tokio::test]
    async fn test_run_blob_gc_flags_orphan_blob() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let digest = format!("sha256:{}", "c".repeat(64));
        let storage_key = format!("oci-blobs/{}", digest);
        insert_old_blob(&fixture.pool, fixture.repo_id, &digest, &storage_key, 789).await;

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        // Dry-run must complete without errors. We don't pin a count because
        // concurrent tests may insert other orphans.
        let result = service.run_blob_gc(true).await.expect("dry-run succeeds");
        assert!(
            result.dry_run,
            "dry-run result must carry the dry_run flag for the scheduler's gate"
        );
        assert!(
            result.errors.is_empty(),
            "blob gc dry-run must not surface errors: {:?}",
            result.errors
        );
        // OUR digest must be flagged orphan by the underlying predicate.
        let flagged = would_gc_flag_blob(&fixture.pool, fixture.repo_id, &digest).await;

        fixture.teardown().await;

        assert!(
            flagged,
            "an aged oci_blobs row with no manifest_blob_refs must be flagged orphan"
        );
    }

    #[tokio::test]
    async fn test_run_blob_gc_keeps_blob_referenced_by_manifest_blob_refs() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let manifest_digest = format!("sha256:{}", "d".repeat(64));
        let blob_digest = format!("sha256:{}", "e".repeat(64));
        let storage_key = format!("oci-blobs/{}", blob_digest);

        insert_old_blob(
            &fixture.pool,
            fixture.repo_id,
            &blob_digest,
            &storage_key,
            321,
        )
        .await;
        sqlx::query(
            r#"
            INSERT INTO manifest_blob_refs (manifest_digest, blob_digest, repository_id, kind)
            VALUES ($1, $2, $3, 'layer')
            "#,
        )
        .bind(&manifest_digest)
        .bind(&blob_digest)
        .bind(fixture.repo_id)
        .execute(&fixture.pool)
        .await
        .expect("insert manifest_blob_refs row");

        let flagged = would_gc_flag_blob(&fixture.pool, fixture.repo_id, &blob_digest).await;

        fixture.teardown().await;

        assert!(
            !flagged,
            "blob must not be flagged orphan while manifest_blob_refs references it"
        );
    }

    /// Incident-replay (the production bug that motivated #1409): on CLOUD
    /// backends blob storage is a single content-addressed object per
    /// bucket, so an `oci_blobs` row in any same-backend repo with a live
    /// `manifest_blob_refs` entry must protect the shared object — even when
    /// the row being evaluated lives in a different repo with no references
    /// of its own. The earlier per-`(repo,digest)` reconciler deleted on the
    /// first orphan row and destroyed a shared blob (57 blobs / 85 tags).
    #[tokio::test]
    async fn test_run_blob_gc_keeps_blob_referenced_from_another_repo() {
        let Some((fixture_a, fixture_b, shared_digest)) = setup_two_repos_one_ref('9').await else {
            return;
        };
        // Both repos live on the same cloud backend, where the digest
        // resolves to one shared object.
        set_repo_backend(&fixture_a.pool, fixture_a.repo_id, "s3").await;
        set_repo_backend(&fixture_b.pool, fixture_b.repo_id, "s3").await;

        // Evaluate from repo B (the one WITHOUT a local ref): repo A's
        // reference on the shared cloud object must still protect it.
        let flagged = would_gc_flag_blob(&fixture_b.pool, fixture_b.repo_id, &shared_digest).await;

        fixture_a.teardown().await;
        fixture_b.teardown().await;

        assert!(
            !flagged,
            "on a cloud backend a blob must not be flagged orphan while ANY same-backend repo's \
             manifest_blob_refs references the digest; otherwise blob GC would delete the shared \
             object and break the other repo"
        );
    }

    /// Apply-mode counterpart to [`test_run_blob_gc_flags_orphan_blob`]. The
    /// live pass must actually delete the file from storage and the row from
    /// `oci_blobs`. Covers the per-row loop body in
    /// [`StorageGcService::run_blob_gc`] that dry-run skips.
    #[tokio::test]
    async fn test_run_blob_gc_apply_deletes_orphan_blob() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let digest = format!("sha256:{}", "1".repeat(64));
        let storage_key = format!("oci-blobs/{}", digest);
        let blob_body = Bytes::from_static(b"orphan-payload");
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");
        storage
            .put(&storage_key, blob_body.clone())
            .await
            .expect("write blob to storage");

        insert_old_blob(
            &fixture.pool,
            fixture.repo_id,
            &digest,
            &storage_key,
            blob_body.len() as i64,
        )
        .await;

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let _ = service.run_blob_gc(false).await.expect("apply succeeds");

        let row_remaining: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM oci_blobs WHERE digest = $1")
                .bind(&digest)
                .fetch_one(&fixture.pool)
                .await
                .expect("count oci_blobs");
        let file_still_exists = storage.exists(&storage_key).await.expect("exists check");

        fixture.teardown().await;

        assert_eq!(
            row_remaining, 0,
            "live blob GC must hard-delete the oci_blobs row for an orphan digest"
        );
        assert!(
            !file_still_exists,
            "live blob GC must delete the storage object for an orphan digest"
        );
    }

    /// Apply-mode counterpart to
    /// [`test_run_blob_gc_keeps_blob_referenced_by_manifest_blob_refs`].
    /// Ensures the per-row `is_blob_still_orphan` re-check inside the
    /// transaction sees the live `manifest_blob_refs` row and skips delete.
    #[tokio::test]
    async fn test_run_blob_gc_apply_keeps_referenced_blob() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let manifest_digest = format!("sha256:{}", "2".repeat(64));
        let blob_digest = format!("sha256:{}", "3".repeat(64));
        let storage_key = format!("oci-blobs/{}", blob_digest);
        let blob_body = Bytes::from_static(b"referenced-payload");
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");
        storage
            .put(&storage_key, blob_body.clone())
            .await
            .expect("write blob to storage");

        insert_old_blob(
            &fixture.pool,
            fixture.repo_id,
            &blob_digest,
            &storage_key,
            blob_body.len() as i64,
        )
        .await;
        sqlx::query(
            r#"
            INSERT INTO manifest_blob_refs (manifest_digest, blob_digest, repository_id, kind)
            VALUES ($1, $2, $3, 'layer')
            "#,
        )
        .bind(&manifest_digest)
        .bind(&blob_digest)
        .bind(fixture.repo_id)
        .execute(&fixture.pool)
        .await
        .expect("insert manifest_blob_refs row");

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let _ = service.run_blob_gc(false).await.expect("apply succeeds");

        let row_remaining: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_blobs WHERE repository_id = $1 AND digest = $2",
        )
        .bind(fixture.repo_id)
        .bind(&blob_digest)
        .fetch_one(&fixture.pool)
        .await
        .expect("count oci_blobs");
        let file_still_exists = storage.exists(&storage_key).await.expect("exists check");

        fixture.teardown().await;

        assert_eq!(
            row_remaining, 1,
            "oci_blobs row must survive when a manifest_blob_refs entry references the digest"
        );
        assert!(
            file_still_exists,
            "storage object must survive when a manifest_blob_refs entry references the digest"
        );
    }

    #[tokio::test]
    async fn test_run_blob_gc_respects_grace_period() {
        // Even with zero manifest_blob_refs rows, a blob still inside the
        // grace window represents an in-flight push and must be left alone.
        // This is the explicit safeguard against the upload-then-manifest
        // race documented on run_blob_gc.
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let digest = format!("sha256:{}", "f".repeat(64));
        let storage_key = format!("oci-blobs/{}", digest);
        // created_at = NOW() default; well inside MIN_BLOB_AGE_SECS.
        sqlx::query(
            r#"
            INSERT INTO oci_blobs (repository_id, digest, size_bytes, storage_key)
            VALUES ($1, $2, 1024, $3)
            "#,
        )
        .bind(fixture.repo_id)
        .bind(&digest)
        .bind(&storage_key)
        .execute(&fixture.pool)
        .await
        .expect("insert fresh oci_blobs row");

        let flagged = would_gc_flag_blob(&fixture.pool, fixture.repo_id, &digest).await;

        fixture.teardown().await;

        assert!(
            !flagged,
            "blobs younger than MIN_BLOB_AGE_SECS must be skipped to protect in-flight pushes"
        );
    }

    #[tokio::test]
    async fn test_run_blob_gc_filesystem_scopes_orphan_per_storage_path() {
        // Filesystem counterpart to the cloud cross-repo test: each
        // filesystem repo roots its own tree, so the same digest is a
        // DISTINCT physical file per repo. A reference in repo A must NOT
        // protect repo B's independent copy (otherwise B's orphan file would
        // leak forever), while repo A's own copy stays protected. The
        // predicate is backend-aware, not unconditionally global.
        let Some((fixture_a, fixture_b, shared_digest)) = setup_two_repos_one_ref('7').await else {
            return;
        };
        // Both repos keep the default `filesystem` backend, each with its
        // own storage_path.

        let flagged_b =
            would_gc_flag_blob(&fixture_b.pool, fixture_b.repo_id, &shared_digest).await;
        let flagged_a =
            would_gc_flag_blob(&fixture_a.pool, fixture_a.repo_id, &shared_digest).await;

        fixture_a.teardown().await;
        fixture_b.teardown().await;

        assert!(
            flagged_b,
            "on filesystem a blob referenced only from another repo's storage_path must still be \
             flagged orphan: the copies are physically distinct files"
        );
        assert!(
            !flagged_a,
            "repo A's own copy must remain protected by its own manifest_blob_refs entry"
        );
    }
}
