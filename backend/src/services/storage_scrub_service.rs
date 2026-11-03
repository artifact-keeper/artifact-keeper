//! Storage scrub: detect (and, where a verified good copy exists, repair)
//! content-addressed objects whose stored bytes no longer match their
//! recorded SHA-256 (#3910, the verify-and-repair half of #3837).
//!
//! The walk covers live `artifacts` rows (content-addressed storage keys,
//! including `oci-manifests/*`) and `oci_blobs` rows (`oci-blobs/*`). Each
//! object is re-read through its repository's storage backend with
//! [`StorageBackend::get_stream`] — so migration-mode cloud backends resolve
//! the same fallback keys a download does (#3530/#3837) — and hashed
//! incrementally (memory stays at one chunk).
//!
//! Safety properties:
//! - **Bounded and resumable**: a run stops after `max_objects` objects or
//!   `max_bytes` bytes read, whichever comes first. The keyset cursor
//!   (`storage_scrub_state`, one row per scope: the instance or a repository)
//!   is written after every object, so a run that is cut short (the admin
//!   request timeout, a restart) resumes where it stopped instead of redoing
//!   the same work.
//! - **Single runner**: a cluster-wide advisory lock admits one scrub at a
//!   time; a second caller gets [`AppError::Conflict`].
//! - **Race-tolerant**: a mismatch or a missing object is only recorded after
//!   re-reading the row and confirming it is still live and still points at
//!   the same key and digest, so a concurrent republish, soft-delete, or
//!   storage GC reap is never reported as corruption.
//! - **Non-destructive**: a finding never mutates the referencing row (the
//!   download path already refuses to complete a corrupt body, #3919). A
//!   repair is attempted only when `repair` is requested, the object's key is
//!   content-addressed (derived from its digest: CAS `ab/cd/<sha>`,
//!   `oci-blobs/sha256:<sha>`, `oci-manifests/sha256:<sha>`), AND another
//!   stored copy of the same digest re-hashes correctly. A path-keyed object
//!   (`maven/{repo}/{path}` …) is only reported: a republish writes new bytes
//!   to the same key before it updates the row's digest, so "restoring" the
//!   old digest there could overwrite the newer, correct upload; the good bytes are spooled
//!   to a temp file, verified, written with the backend's atomic `put_file`,
//!   then the target is re-verified. Bad bytes can therefore never overwrite
//!   anything, and without a good copy the object is only reported.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::services::cluster_lock::{ClusterLock, PgAdvisoryLock};
use crate::storage::verify::{
    checksum_is_content_digest, hash_stream, parse_sha256_hex, spool_and_verify,
};
use crate::storage::{StorageBackend, StorageLocation, StorageRegistry};

/// Advisory-lock class for the scrub (one runner cluster-wide).
pub const STORAGE_SCRUB_LOCK_CLASS: i32 = 0x3910;

/// Cap on the findings/errors echoed in one run's result (all findings are
/// persisted; the report only samples them).
const REPORT_SAMPLE_CAP: usize = 100;

/// How many alternative copies a repair tries before giving up.
const MAX_REPAIR_DONORS: i64 = 5;

/// Cursor scope of the instance-wide walk.
const INSTANCE_SCOPE: &str = "instance";

/// Whether `key` is derived from the object's digest, i.e. the key can only
/// ever hold these exact bytes. Only such keys may be repaired in place.
pub fn key_is_content_addressed(key: &str, recorded_sha256: &str) -> bool {
    let Some(expected) = parse_sha256_hex(recorded_sha256) else {
        return false;
    };
    // Only the real content-addressed layouts: the artifact CAS
    // (`ab/cd/<sha>`, `ArtifactService::storage_key_from_checksum`) and the OCI
    // blob/manifest stores. Matching just the last segment would also accept a
    // path-keyed object that happens to be NAMED after its digest (e.g. a
    // protobuf `modules/{m}/commits/{digest}` key or a user file called
    // `<sha>`), which a republish can rewrite in place (#3910 review).
    let hex = hex::encode(expected);
    let candidates = [
        format!("{}/{}/{}", &hex[..2], &hex[2..4], hex),
        format!("oci-blobs/sha256:{hex}"),
        format!("oci-manifests/sha256:{hex}"),
    ];
    candidates.iter().any(|c| c.eq_ignore_ascii_case(key))
}

/// Rows fetched per keyset page.
const PAGE_SIZE: i64 = 200;

/// Budget and mode for one scrub run.
#[derive(Debug, Clone)]
pub struct ScrubOptions {
    /// Stop after this many objects have been checked.
    pub max_objects: u64,
    /// Stop after this many bytes have been read.
    pub max_bytes: u64,
    /// Attempt repair from a verified good copy.
    pub repair: bool,
    /// Restrict the walk to one repository. A scoped run keeps its own
    /// resumable cursor and does not move the instance-wide one.
    pub repository_id: Option<Uuid>,
}

/// Kind of object a finding refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScrubObjectKind {
    Artifact,
    OciBlob,
}

impl ScrubObjectKind {
    fn as_str(self) -> &'static str {
        match self {
            ScrubObjectKind::Artifact => "artifact",
            ScrubObjectKind::OciBlob => "oci_blob",
        }
    }
}

/// One corrupt, missing, or repaired object.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ScrubFinding {
    pub object_kind: ScrubObjectKind,
    pub object_id: Uuid,
    pub repository_id: Uuid,
    pub storage_key: String,
    pub expected_sha256: String,
    pub actual_sha256: Option<String>,
    pub expected_size: Option<i64>,
    pub actual_size: Option<i64>,
    /// `corrupt`, `missing`, or `repaired`.
    pub status: String,
    pub detail: Option<String>,
    pub detected_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

/// Summary of one scrub run.
#[derive(Debug, Default, Clone, Serialize, ToSchema)]
pub struct ScrubResult {
    pub objects_checked: u64,
    pub bytes_read: u64,
    pub intact: u64,
    pub corrupt: u64,
    pub missing: u64,
    pub repaired: u64,
    /// Rows whose recorded checksum is not a SHA-256 digest (nothing to
    /// verify against).
    pub unverifiable: u64,
    /// Mismatches dropped because the row changed or was deleted meanwhile.
    pub skipped_concurrent: u64,
    /// True when this run reached the end of the walk (the cursor wrapped).
    pub cycle_completed: bool,
    pub findings: Vec<ScrubFinding>,
    pub errors: Vec<String>,
}

/// A row to verify.
#[derive(Debug, Clone, sqlx::FromRow)]
struct ScrubTarget {
    id: Uuid,
    repository_id: Uuid,
    storage_key: String,
    checksum: String,
    /// Length the stored object must have, or `None` to verify by digest
    /// alone. Not `artifacts.size_bytes` for an OCI manifest row: that column
    /// holds the IMAGE size there (#3601), so the length comes from
    /// `oci_manifests.size_bytes`, the manifest body length (#4666). See
    /// [`artifact_page_sql`]. Defaults to `None` for donor rows, which are
    /// only read, never judged by length.
    #[sqlx(default)]
    stored_len: Option<i64>,
    storage_backend: String,
    storage_path: String,
    /// Repository format key and artifact path, for
    /// [`checksum_is_content_digest`] (OCI blobs: `oci`, the storage key).
    format: String,
    path: String,
}

impl ScrubTarget {
    fn location(&self) -> StorageLocation {
        StorageLocation {
            backend: self.storage_backend.clone(),
            path: self.storage_path.clone(),
        }
    }
}

/// Result of checking a single object.
#[derive(Debug, PartialEq, Eq)]
enum ObjectCheck {
    Intact,
    Unverifiable,
    Corrupt {
        actual_sha256: String,
        actual_len: u64,
    },
    Missing,
}

pub struct StorageScrubService {
    db: PgPool,
    storage_registry: Arc<StorageRegistry>,
}

fn artifact_page_sql(scoped: bool) -> String {
    // `size_bytes` of an OCI manifest row (`oci-manifests/<digest>` key) is
    // the image size -- config plus layers -- not the length of the stored
    // manifest body (#3601), so it can never be the expected object length
    // (#4666). The body length is recorded in `oci_manifests.size_bytes`
    // (#4433); a manifest with no record yet (the startup backfill has not
    // reached it) is verified by digest alone, which already catches a
    // truncated or altered body.
    format!(
        "SELECT a.id, a.repository_id, a.storage_key, a.checksum_sha256 AS checksum, \
                CASE WHEN a.storage_key LIKE 'oci-manifests/%' THEN om.size_bytes \
                     ELSE a.size_bytes END AS stored_len, \
                r.storage_backend, r.storage_path, r.format::text AS format, \
                a.path \
         FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
         LEFT JOIN oci_manifests om ON a.storage_key LIKE 'oci-manifests/%' \
              AND om.repository_id = a.repository_id \
              AND om.digest = substr(a.storage_key, length('oci-manifests/') + 1) \
         WHERE a.is_deleted = false AND ($1::uuid IS NULL OR a.id > $1) {} \
         ORDER BY a.id LIMIT $2",
        if scoped {
            "AND a.repository_id = $3"
        } else {
            ""
        }
    )
}
const _: () = assert!(crate::storage::keys::prefix_matches("oci-manifests/"));

fn oci_blob_page_sql(scoped: bool) -> String {
    format!(
        "SELECT b.id, b.repository_id, b.storage_key, b.digest AS checksum, \
                b.size_bytes AS stored_len, r.storage_backend, r.storage_path, \
                'oci' AS format, b.storage_key AS path \
         FROM oci_blobs b JOIN repositories r ON r.id = b.repository_id \
         WHERE ($1::uuid IS NULL OR b.id > $1) {} \
         ORDER BY b.id LIMIT $2",
        if scoped {
            "AND b.repository_id = $3"
        } else {
            ""
        }
    )
}

/// Re-read a row and confirm it still references the same key and digest.
fn still_live_sql(kind: ScrubObjectKind) -> &'static str {
    match kind {
        ScrubObjectKind::Artifact => {
            "SELECT EXISTS (SELECT 1 FROM artifacts WHERE id = $1 AND is_deleted = false \
             AND storage_key = $2 AND checksum_sha256 = $3)"
        }
        ScrubObjectKind::OciBlob => {
            "SELECT EXISTS (SELECT 1 FROM oci_blobs WHERE id = $1 \
             AND storage_key = $2 AND digest = $3)"
        }
    }
}

/// What [`StorageScrubService::try_repair`] did with a damaged object.
enum RepairOutcome {
    /// Restored; describes the donor.
    Repaired(String),
    /// Every candidate was tried and none could be used.
    NoVerifiedCopy,
    /// `max_bytes` ran out with candidates still unread.
    BudgetExhausted,
}

impl StorageScrubService {
    pub fn new(db: PgPool, storage_registry: Arc<StorageRegistry>) -> Self {
        Self {
            db,
            storage_registry,
        }
    }

    /// Run one bounded scrub pass. Returns [`AppError::Conflict`] when another
    /// scrub holds the cluster-wide lock.
    pub async fn run(&self, opts: &ScrubOptions) -> Result<ScrubResult> {
        let lease = PgAdvisoryLock::new(self.db.clone())
            .try_acquire(STORAGE_SCRUB_LOCK_CLASS, 0)
            .await?
            .ok_or_else(|| AppError::Conflict("A storage scrub is already running".into()))?;
        let result = self.run_locked(opts).await;
        lease.release().await;
        result
    }

    async fn run_locked(&self, opts: &ScrubOptions) -> Result<ScrubResult> {
        let mut result = ScrubResult::default();
        self.prune_bookkeeping().await?;
        let scoped = opts.repository_id.is_some();
        let scope = opts
            .repository_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| INSTANCE_SCOPE.to_string());
        let (mut art_cursor, mut blob_cursor) = self.load_cursors(&scope).await?;

        // Phase 1: artifacts; phase 2 (once the artifact walk wrapped, i.e.
        // its cursor is NULL again after a full pass): OCI blobs.
        let mut artifacts_done = false;
        let mut blobs_done = false;
        if blob_cursor.is_some() && art_cursor.is_none() {
            // A previous run finished artifacts and stopped inside blobs.
            artifacts_done = true;
        }
        while !artifacts_done && self.within_budget(&result, opts) {
            let page = self
                .fetch_page(&artifact_page_sql(scoped), art_cursor, opts)
                .await?;
            if page.is_empty() {
                artifacts_done = true;
                art_cursor = None;
                // Mark "artifacts finished, blobs next" durably: the nil
                // UUID sorts before every row id, so the blob walk starts
                // from the beginning while a resumed run skips artifacts.
                blob_cursor = blob_cursor.or(Some(Uuid::nil()));
                break;
            }
            for t in page {
                if !self.within_budget(&result, opts) {
                    break;
                }
                self.scrub_one(ScrubObjectKind::Artifact, &t, opts, &mut result)
                    .await;
                art_cursor = Some(t.id);
                self.save_cursors(&scope, art_cursor, blob_cursor, false)
                    .await?;
            }
        }
        if artifacts_done {
            while !blobs_done && self.within_budget(&result, opts) {
                let page = self
                    .fetch_page(&oci_blob_page_sql(scoped), blob_cursor, opts)
                    .await?;
                if page.is_empty() {
                    blobs_done = true;
                    blob_cursor = None;
                    break;
                }
                for t in page {
                    if !self.within_budget(&result, opts) {
                        break;
                    }
                    self.scrub_one(ScrubObjectKind::OciBlob, &t, opts, &mut result)
                        .await;
                    blob_cursor = Some(t.id);
                    self.save_cursors(&scope, None, blob_cursor, false).await?;
                }
            }
        }

        result.cycle_completed = artifacts_done && blobs_done;
        self.save_cursors(&scope, art_cursor, blob_cursor, result.cycle_completed)
            .await?;
        Ok(result)
    }

    /// Drop bookkeeping whose subject no longer exists (#4323): findings for
    /// an artifact or OCI blob row that was hard-deleted (the findings table
    /// has no foreign key, so nothing else removes them and they would be
    /// listed forever), and the resumable cursor of a deleted repository's
    /// scoped runs. Runs under the scrub lock, once per run; both tables are
    /// small and the probes are primary-key lookups.
    async fn prune_bookkeeping(&self) -> Result<()> {
        sqlx::query(
            "DELETE FROM storage_scrub_findings f WHERE \
               (f.object_kind = 'artifact' \
                 AND NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.id = f.object_id)) \
            OR (f.object_kind = 'oci_blob' \
                 AND NOT EXISTS (SELECT 1 FROM oci_blobs b WHERE b.id = f.object_id))",
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        sqlx::query(
            "DELETE FROM storage_scrub_state s WHERE s.scope <> $1 \
             AND NOT EXISTS (SELECT 1 FROM repositories r WHERE r.id::text = s.scope)",
        )
        .bind(INSTANCE_SCOPE)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(())
    }

    fn within_budget(&self, result: &ScrubResult, opts: &ScrubOptions) -> bool {
        result.objects_checked < opts.max_objects && result.bytes_read < opts.max_bytes
    }

    async fn fetch_page(
        &self,
        sql: &str,
        cursor: Option<Uuid>,
        opts: &ScrubOptions,
    ) -> Result<Vec<ScrubTarget>> {
        let mut q = sqlx::query_as::<_, ScrubTarget>(sqlx::AssertSqlSafe(sql))
            .bind(cursor)
            .bind(PAGE_SIZE);
        if let Some(repo) = opts.repository_id {
            q = q.bind(repo);
        }
        q.fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))
    }

    async fn load_cursors(&self, scope: &str) -> Result<(Option<Uuid>, Option<Uuid>)> {
        let row: Option<(Option<Uuid>, Option<Uuid>)> = sqlx::query_as(
            "SELECT artifact_cursor, oci_blob_cursor FROM storage_scrub_state WHERE scope = $1",
        )
        .bind(scope)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(row.unwrap_or((None, None)))
    }

    async fn save_cursors(
        &self,
        scope: &str,
        artifact_cursor: Option<Uuid>,
        oci_blob_cursor: Option<Uuid>,
        cycle_completed: bool,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO storage_scrub_state (scope, artifact_cursor, oci_blob_cursor, \
                 last_run_at, last_cycle_completed_at) \
             VALUES ($4, $1, $2, NOW(), CASE WHEN $3 THEN NOW() END) \
             ON CONFLICT (scope) DO UPDATE SET artifact_cursor = $1, oci_blob_cursor = $2, \
                 last_run_at = NOW(), \
                 last_cycle_completed_at = CASE WHEN $3 THEN NOW() \
                     ELSE storage_scrub_state.last_cycle_completed_at END",
        )
        .bind(artifact_cursor)
        .bind(oci_blob_cursor)
        .bind(cycle_completed)
        .bind(scope)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(())
    }

    /// Hash one object and compare with the record.
    async fn check_object(
        storage: &dyn StorageBackend,
        t: &ScrubTarget,
    ) -> Result<(ObjectCheck, u64)> {
        // A row whose recorded checksum does not describe the stored bytes
        // (protobuf commit bundles, #3919 review B1) cannot be verified.
        if !checksum_is_content_digest(&t.format, &t.path) {
            return Ok((ObjectCheck::Unverifiable, 0));
        }
        let Some(expected) = parse_sha256_hex(&t.checksum) else {
            return Ok((ObjectCheck::Unverifiable, 0));
        };
        let stream = match storage.get_stream(&t.storage_key).await {
            Ok(s) => s,
            Err(AppError::NotFound(_)) => return Ok((ObjectCheck::Missing, 0)),
            Err(e) => return Err(e),
        };
        let (actual_hex, len) = match hash_stream(stream).await {
            Ok(v) => v,
            Err(AppError::NotFound(_)) => return Ok((ObjectCheck::Missing, 0)),
            Err(e) => return Err(e),
        };
        let expected_len = t.stored_len.and_then(|l| u64::try_from(l).ok());
        let check = match crate::storage::verify::verdict(
            &expected,
            expected_len,
            &hex::decode(&actual_hex).unwrap_or_default(),
            len,
        ) {
            crate::storage::verify::IntegrityVerdict::Intact => ObjectCheck::Intact,
            crate::storage::verify::IntegrityVerdict::Mismatch {
                actual_sha256,
                actual_len,
            } => ObjectCheck::Corrupt {
                actual_sha256,
                actual_len,
            },
        };
        Ok((check, len))
    }

    async fn scrub_one(
        &self,
        kind: ScrubObjectKind,
        t: &ScrubTarget,
        opts: &ScrubOptions,
        result: &mut ScrubResult,
    ) {
        // Counted here, once per object, whether or not the check got far
        // enough to read it: counting inside `scrub_one_inner` as well
        // double-counted every object whose finding failed to record (#4323).
        result.objects_checked += 1;
        if let Err(e) = self.scrub_one_inner(kind, t, opts, result).await {
            if result.errors.len() < REPORT_SAMPLE_CAP {
                result.errors.push(format!(
                    "{} {} ({}): {e}",
                    kind.as_str(),
                    t.id,
                    t.storage_key
                ));
            }
        }
    }

    async fn scrub_one_inner(
        &self,
        kind: ScrubObjectKind,
        t: &ScrubTarget,
        opts: &ScrubOptions,
        result: &mut ScrubResult,
    ) -> Result<()> {
        let storage = self.storage_registry.backend_for(&t.location())?;
        let (check, len) = Self::check_object(storage.as_ref(), t).await?;
        result.bytes_read += len;

        let (status, actual_sha, actual_len) = match check {
            ObjectCheck::Unverifiable => {
                result.unverifiable += 1;
                return Ok(());
            }
            ObjectCheck::Intact => {
                result.intact += 1;
                self.clear_finding(kind, t.id).await?;
                return Ok(());
            }
            ObjectCheck::Missing => ("missing", None, None),
            ObjectCheck::Corrupt {
                actual_sha256,
                actual_len,
            } => ("corrupt", Some(actual_sha256), Some(actual_len as i64)),
        };

        // Confirm the row still references this key and digest: a concurrent
        // republish, delete, or GC reap is not corruption.
        let live: bool = sqlx::query_scalar(still_live_sql(kind))
            .bind(t.id)
            .bind(&t.storage_key)
            .bind(&t.checksum)
            .fetch_one(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        if !live {
            result.skipped_concurrent += 1;
            return Ok(());
        }

        let mut status = status.to_string();
        let mut detail = None;
        if opts.repair && !key_is_content_addressed(&t.storage_key, &t.checksum) {
            detail = Some(
                "path-keyed object: reported only (repair needs a content-addressed key)".into(),
            );
        } else if opts.repair {
            match self
                .try_repair(kind, t, storage.as_ref(), opts.max_bytes, result)
                .await
            {
                Ok(RepairOutcome::Repaired(donor)) => {
                    status = "repaired".into();
                    detail = Some(format!("restored from verified copy {donor}"));
                }
                Ok(RepairOutcome::NoVerifiedCopy) => {
                    detail = Some("no verified good copy available".into())
                }
                Ok(RepairOutcome::BudgetExhausted) => {
                    detail = Some(
                        "repair stopped at the byte budget before every copy was tried; \
                         a later run retries it"
                            .into(),
                    )
                }
                Err(e) => detail = Some(format!("repair failed: {e}")),
            }
        }
        match status.as_str() {
            "repaired" => result.repaired += 1,
            "missing" => result.missing += 1,
            _ => result.corrupt += 1,
        }
        tracing::error!(
            kind = kind.as_str(),
            object_id = %t.id,
            repository_id = %t.repository_id,
            storage_key = %t.storage_key,
            status = %status,
            "storage scrub finding"
        );
        let finding = self
            .record_finding(kind, t, &status, actual_sha, actual_len, detail)
            .await?;
        if result.findings.len() < REPORT_SAMPLE_CAP {
            result.findings.push(finding);
        }
        Ok(())
    }

    /// Find another stored copy of the same digest whose bytes verify, spool
    /// it to a temp file while hashing, and write it over the damaged key.
    ///
    /// Every byte read here (donor copies, and the re-verification of the
    /// repaired object) counts toward `bytes_read`, so a repair run honours
    /// `max_bytes` (#4323). The budget is checked between donors, so a run of
    /// corrupt copies stops there (#5168). The first donor is always tried,
    /// even when reading the damaged object used up the budget, or an object
    /// as large as the budget could never be repaired. A copy that verified is
    /// always written.
    async fn try_repair(
        &self,
        kind: ScrubObjectKind,
        t: &ScrubTarget,
        target: &dyn StorageBackend,
        max_bytes: u64,
        result: &mut ScrubResult,
    ) -> Result<RepairOutcome> {
        let Some(expected) = parse_sha256_hex(&t.checksum) else {
            return Ok(RepairOutcome::NoVerifiedCopy);
        };
        let hex_digest = hex::encode(expected);
        let donors: Vec<ScrubTarget> = sqlx::query_as(
            "SELECT id, repository_id, storage_key, checksum, storage_backend, \
                    storage_path, format, path FROM ( \
               SELECT a.id, a.repository_id, a.storage_key, a.checksum_sha256 AS checksum, \
                      r.storage_backend, r.storage_path, \
                      r.format::text AS format, a.path \
               FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
               WHERE a.is_deleted = false AND a.checksum_sha256 = $1 AND a.id <> $3 \
               UNION ALL \
               SELECT b.id, b.repository_id, b.storage_key, b.digest AS checksum, \
                      r.storage_backend, r.storage_path, 'oci' AS format, \
                      b.storage_key AS path \
               FROM oci_blobs b JOIN repositories r ON r.id = b.repository_id \
               WHERE b.digest = $2 AND b.id <> $3 \
             ) d LIMIT $4",
        )
        .bind(&hex_digest)
        .bind(format!("sha256:{hex_digest}"))
        .bind(t.id)
        .bind(MAX_REPAIR_DONORS)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let mut tried_a_donor = false;
        for donor in donors {
            if tried_a_donor && result.bytes_read >= max_bytes {
                return Ok(RepairOutcome::BudgetExhausted);
            }
            let Ok(source) = self.storage_registry.backend_for(&donor.location()) else {
                continue;
            };
            tried_a_donor = true;
            let (spool, read) =
                match spool_verified(source.as_ref(), &donor.storage_key, &expected).await {
                    Ok(spooled) => spooled,
                    Err(_) => continue,
                };
            result.bytes_read += read;
            let Some(spool) = spool else {
                continue;
            };
            // Re-check the target row right before writing so a key that was
            // deleted or re-pointed meanwhile is not resurrected.
            let live: bool = sqlx::query_scalar(still_live_sql(kind))
                .bind(t.id)
                .bind(&t.storage_key)
                .bind(&t.checksum)
                .fetch_one(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
            if !live {
                return Ok(RepairOutcome::NoVerifiedCopy);
            }
            target.put_file(&t.storage_key, spool.path()).await?;
            let (check, read) = Self::check_object(target, t).await?;
            result.bytes_read += read;
            if check == ObjectCheck::Intact {
                return Ok(RepairOutcome::Repaired(format!(
                    "{}:{} ({})",
                    donor.storage_backend, donor.storage_key, donor.id
                )));
            }
        }
        Ok(RepairOutcome::NoVerifiedCopy)
    }

    async fn clear_finding(&self, kind: ScrubObjectKind, id: Uuid) -> Result<()> {
        sqlx::query(
            "DELETE FROM storage_scrub_findings WHERE object_kind = $1 AND object_id = $2 \
             AND status <> 'repaired'",
        )
        .bind(kind.as_str())
        .bind(id)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(())
    }

    async fn record_finding(
        &self,
        kind: ScrubObjectKind,
        t: &ScrubTarget,
        status: &str,
        actual_sha256: Option<String>,
        actual_size: Option<i64>,
        detail: Option<String>,
    ) -> Result<ScrubFinding> {
        let (detected_at, updated_at): (DateTime<Utc>, DateTime<Utc>) = sqlx::query_as(
            "INSERT INTO storage_scrub_findings (object_kind, object_id, repository_id, \
                 storage_key, expected_sha256, actual_sha256, expected_size, actual_size, \
                 status, detail) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (object_kind, object_id) DO UPDATE SET \
                 storage_key = EXCLUDED.storage_key, \
                 expected_sha256 = EXCLUDED.expected_sha256, \
                 actual_sha256 = EXCLUDED.actual_sha256, \
                 expected_size = EXCLUDED.expected_size, \
                 actual_size = EXCLUDED.actual_size, \
                 status = EXCLUDED.status, detail = EXCLUDED.detail, updated_at = NOW() \
             RETURNING detected_at, updated_at",
        )
        .bind(kind.as_str())
        .bind(t.id)
        .bind(t.repository_id)
        .bind(&t.storage_key)
        .bind(t.checksum.trim())
        .bind(&actual_sha256)
        .bind(t.stored_len)
        .bind(actual_size)
        .bind(status)
        .bind(&detail)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(ScrubFinding {
            object_kind: kind,
            object_id: t.id,
            repository_id: t.repository_id,
            storage_key: t.storage_key.clone(),
            expected_sha256: t.checksum.trim().to_string(),
            actual_sha256,
            expected_size: t.stored_len,
            actual_size,
            status: status.to_string(),
            detail,
            detected_at: Some(detected_at),
            updated_at: Some(updated_at),
        })
    }

    /// Most recent findings, optionally filtered by status.
    pub async fn list_findings(
        &self,
        status: Option<&str>,
        limit: i64,
    ) -> Result<Vec<ScrubFinding>> {
        #[derive(sqlx::FromRow)]
        struct Row {
            object_kind: String,
            object_id: Uuid,
            repository_id: Uuid,
            storage_key: String,
            expected_sha256: String,
            actual_sha256: Option<String>,
            expected_size: Option<i64>,
            actual_size: Option<i64>,
            status: String,
            detail: Option<String>,
            detected_at: DateTime<Utc>,
            updated_at: DateTime<Utc>,
        }
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT object_kind, object_id, repository_id, storage_key, expected_sha256, \
                    actual_sha256, expected_size, actual_size, status, detail, detected_at, \
                    updated_at \
             FROM storage_scrub_findings WHERE ($1::text IS NULL OR status = $1) \
             ORDER BY updated_at DESC LIMIT $2",
        )
        .bind(status)
        .bind(limit.clamp(1, 1000))
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(rows
            .into_iter()
            .map(|r| ScrubFinding {
                object_kind: if r.object_kind == "oci_blob" {
                    ScrubObjectKind::OciBlob
                } else {
                    ScrubObjectKind::Artifact
                },
                object_id: r.object_id,
                repository_id: r.repository_id,
                storage_key: r.storage_key,
                expected_sha256: r.expected_sha256,
                actual_sha256: r.actual_sha256,
                expected_size: r.expected_size,
                actual_size: r.actual_size,
                status: r.status,
                detail: r.detail,
                detected_at: Some(r.detected_at),
                updated_at: Some(r.updated_at),
            })
            .collect())
    }
}

/// Stream `key` from `source` into a temp file while hashing it. Returns the
/// temp file only when its bytes hash to `expected` (bad bytes are
/// discarded), together with the number of bytes read either way.
async fn spool_verified(
    source: &dyn StorageBackend,
    key: &str,
    expected: &[u8; 32],
) -> Result<(Option<tempfile::NamedTempFile>, u64)> {
    let spool = tempfile::NamedTempFile::new()
        .map_err(|e| AppError::Storage(format!("scrub spool file: {e}")))?;
    let stream = source.get_stream(key).await?;
    let (intact, read) = spool_and_verify(stream, &spool, expected, None).await?;
    Ok((intact.then_some(spool), read))
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_sql_scopes_only_when_asked() {
        assert!(!artifact_page_sql(false).contains("$3"));
        assert!(artifact_page_sql(true).contains("a.repository_id = $3"));
        assert!(oci_blob_page_sql(true).contains("b.repository_id = $3"));
        assert!(artifact_page_sql(false).contains("is_deleted = false"));
        // #4666: an OCI manifest row is judged by its body length, never by
        // the image size `artifacts.size_bytes` carries for it (#3601).
        assert!(artifact_page_sql(false).contains("LEFT JOIN oci_manifests om"));
        assert!(artifact_page_sql(false)
            .contains("WHEN a.storage_key LIKE 'oci-manifests/%' THEN om.size_bytes"));
    }

    #[test]
    fn object_kind_strings_match_migration_check() {
        assert_eq!(ScrubObjectKind::Artifact.as_str(), "artifact");
        assert_eq!(ScrubObjectKind::OciBlob.as_str(), "oci_blob");
    }
}

/// DB-backed scrub tests. They take the cluster-wide scrub lock, so they are
/// serialized through nextest's `db-serial` group (`.config/nextest.toml`).
#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod db_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use bytes::Bytes;

    fn sha_hex(b: &[u8]) -> String {
        hex::encode(<sha2::Sha256 as sha2::Digest>::digest(b))
    }

    /// Seed a live artifact with a real recorded SHA-256 of `original`, while
    /// the stored object holds `stored`.
    async fn seed(fx: &tdh::Fixture, path: &str, original: &[u8], stored: &[u8]) -> (Uuid, String) {
        seed_at(
            fx,
            &format!("scrub-test/{}", Uuid::new_v4()),
            path,
            original,
            stored,
        )
        .await
    }

    /// [`seed`] at an explicit storage key.
    async fn seed_at(
        fx: &tdh::Fixture,
        key: &str,
        path: &str,
        original: &[u8],
        stored: &[u8],
    ) -> (Uuid, String) {
        let key = key.to_string();
        let id = tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &fx.repo_info("local", None),
            &key,
            path,
            "blob",
            "1.0.0",
            "application/octet-stream",
            Bytes::copy_from_slice(stored),
            fx.user_id,
        )
        .await;
        sqlx::query("UPDATE artifacts SET checksum_sha256 = $1, size_bytes = $2 WHERE id = $3")
            .bind(sha_hex(original))
            .bind(original.len() as i64)
            .bind(id)
            .execute(&fx.pool)
            .await
            .expect("record checksum");
        (id, key)
    }

    fn opts(fx: &tdh::Fixture, repair: bool) -> ScrubOptions {
        ScrubOptions {
            max_objects: 1000,
            max_bytes: 1 << 30,
            repair,
            repository_id: Some(fx.repo_id),
        }
    }

    async fn finding_status(pool: &PgPool, id: Uuid) -> Option<String> {
        sqlx::query_scalar(
            "SELECT status FROM storage_scrub_findings WHERE object_kind = 'artifact' \
             AND object_id = $1",
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .expect("query finding")
    }

    fn fs_storage(fx: &tdh::Fixture) -> Arc<dyn StorageBackend> {
        fx.state
            .storage_for_repo(&StorageLocation {
                backend: "filesystem".into(),
                path: fx.storage_dir.to_string_lossy().into_owned(),
            })
            .expect("storage")
    }

    #[test]
    fn content_addressed_keys_are_recognised() {
        let hex = "ab".repeat(32);
        assert!(key_is_content_addressed(&format!("ab/ab/{hex}"), &hex));
        assert!(key_is_content_addressed(
            &format!("oci-blobs/sha256:{hex}"),
            &hex
        ));
        assert!(key_is_content_addressed(
            &format!("oci-manifests/sha256:{hex}"),
            &format!("sha256:{hex}")
        ));
        assert!(!key_is_content_addressed(
            "maven/r/com/x/1.0/x-1.0.jar",
            &hex
        ));
        assert!(!key_is_content_addressed(
            &format!("ab/ab/{hex}"),
            "test-seed"
        ));
        // Named after the digest but NOT a content-addressed layout.
        assert!(!key_is_content_addressed(
            &format!("scrub-test/{hex}"),
            &hex
        ));
        assert!(!key_is_content_addressed(
            &format!("modules/a/b/commits/{hex}"),
            &hex
        ));
        assert!(!key_is_content_addressed(&format!("x/ab/ab/{hex}"), &hex));
        assert!(!key_is_content_addressed(&format!("cd/ab/{hex}"), &hex));
    }

    /// #3910 review (S1): a path-keyed object (`maven/{repo}/{path}`, …) can
    /// be rewritten by a republish BEFORE the row's digest is updated, so a
    /// mismatch there is reported but never "repaired" — even when a verified
    /// copy of the recorded digest exists. An intact neighbour is not flagged.
    #[tokio::test]
    async fn scrub_reports_path_keyed_corruption_without_writing() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let original = b"scrub-original-bytes";
        let (bad, bad_key) = seed(&fx, "a/bad.bin", original, b"scrub-original-byteZ").await;
        let (good, _) = seed(&fx, "a/good.bin", original, original).await;

        let svc = StorageScrubService::new(fx.pool.clone(), fx.state.storage_registry.clone());
        let res = svc.run(&opts(&fx, true)).await.expect("scrub run");

        let bad_status = finding_status(&fx.pool, bad).await;
        let good_status = finding_status(&fx.pool, good).await;
        let still_bad = fs_storage(&fx).get(&bad_key).await.expect("object");
        fx.teardown().await;

        assert_eq!(res.corrupt, 1, "{res:?}");
        assert_eq!(res.intact, 1, "{res:?}");
        assert_eq!(res.repaired, 0, "{res:?}");
        assert_eq!(bad_status.as_deref(), Some("corrupt"));
        assert_eq!(good_status, None);
        assert_eq!(
            &still_bad[..],
            b"scrub-original-byteZ",
            "a path-keyed object must never be written by the scrub"
        );
        assert!(res.findings[0]
            .detail
            .as_deref()
            .unwrap_or_default()
            .contains("path-keyed"));
    }

    /// #4323: an object whose finding cannot be recorded counts once in
    /// `objects_checked`, not twice. A trigger scoped to this test's key makes
    /// the finding insert fail after the object was read.
    #[tokio::test]
    async fn scrub_counts_an_object_once_when_its_finding_fails_4323() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let key = format!("scrub-dc-{}", Uuid::new_v4().simple());
        let func = format!("ak_test_fail_{}", Uuid::new_v4().simple());
        seed_at(
            &fx,
            &key,
            "dc/bad.bin",
            b"double-count-original",
            b"double-count-originaX",
        )
        .await;
        for sql in [
            format!(
                "CREATE FUNCTION {func}() RETURNS trigger LANGUAGE plpgsql AS \
                 $$BEGIN IF NEW.storage_key = '{key}' THEN RAISE EXCEPTION 'test'; END IF; \
                 RETURN NEW; END$$"
            ),
            format!(
                "CREATE TRIGGER {func} BEFORE INSERT ON storage_scrub_findings \
                 FOR EACH ROW EXECUTE FUNCTION {func}()"
            ),
        ] {
            sqlx::query(sqlx::AssertSqlSafe(&*sql))
                .execute(&fx.pool)
                .await
                .expect("install trigger");
        }
        let svc = StorageScrubService::new(fx.pool.clone(), fx.state.storage_registry.clone());
        let res = svc.run(&opts(&fx, false)).await;
        for sql in [
            format!("DROP TRIGGER {func} ON storage_scrub_findings"),
            format!("DROP FUNCTION {func}()"),
        ] {
            let _ = sqlx::query(sqlx::AssertSqlSafe(&*sql))
                .execute(&fx.pool)
                .await;
        }
        fx.teardown().await;
        let res = res.expect("scrub run");
        assert_eq!(res.errors.len(), 1, "{res:?}");
        assert_eq!(res.objects_checked, 1, "{res:?}");
    }

    /// #4323: a repair reads the donor copy and re-reads the repaired object;
    /// both count toward `bytes_read` (and so toward `max_bytes`).
    #[tokio::test]
    async fn scrub_repair_reads_count_toward_bytes_read_4323() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let Some(donor_fx) = tdh::Fixture::setup("local", "generic").await else {
            fx.teardown().await;
            return;
        };
        let original = b"scrub-bytes-read-accounting";
        let cas = crate::services::artifact_service::ArtifactService::storage_key_from_checksum(
            &sha_hex(original),
        );
        seed_at(
            &fx,
            &cas,
            "b/bad.bin",
            original,
            b"scrub-bytes-read-accountinX",
        )
        .await;
        seed_at(&donor_fx, &cas, "b/copy.bin", original, original).await;
        let svc = StorageScrubService::new(fx.pool.clone(), fx.state.storage_registry.clone());
        let res = svc.run(&opts(&fx, true)).await.expect("scrub run");
        fx.teardown().await;
        donor_fx.teardown().await;
        assert_eq!(res.repaired, 1, "{res:?}");
        // At least the target, one donor and the re-verification (a donor
        // row can be listed more than once by the UNION of its sources).
        assert!(
            res.bytes_read >= 3 * original.len() as u64,
            "target, donor and re-verification reads: {res:?}"
        );
    }

    /// #5168: the repair loop checks `max_bytes` between donors. With three
    /// corrupt copies and a budget one donor past the target, it reads one
    /// donor and stops, and the finding does not claim no good copy exists:
    /// the copies it did not read may be good.
    #[tokio::test]
    async fn scrub_repair_stops_between_donors_at_the_byte_budget_5168() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let mut donors = Vec::new();
        for _ in 0..3 {
            let Some(donor_fx) = tdh::Fixture::setup("local", "generic").await else {
                fx.teardown().await;
                return;
            };
            donors.push(donor_fx);
        }
        let original = b"scrub-donor-budget-bytes";
        let corrupt = b"scrub-donor-budget-byteX";
        let len = original.len() as u64;
        let cas = crate::services::artifact_service::ArtifactService::storage_key_from_checksum(
            &sha_hex(original),
        );
        let (bad, _) = seed_at(&fx, &cas, "d/bad.bin", original, corrupt).await;
        for donor_fx in &donors {
            seed_at(donor_fx, &cas, "d/copy.bin", original, corrupt).await;
        }
        let svc = StorageScrubService::new(fx.pool.clone(), fx.state.storage_registry.clone());
        let res = svc
            .run(&ScrubOptions {
                max_bytes: 2 * len,
                ..opts(&fx, true)
            })
            .await
            .expect("scrub run");
        let detail: Option<String> = sqlx::query_scalar(
            "SELECT detail FROM storage_scrub_findings WHERE object_kind = 'artifact' \
             AND object_id = $1",
        )
        .bind(bad)
        .fetch_one(&fx.pool)
        .await
        .expect("finding");

        // A later run with room for every copy reads them all and reports
        // that none verified.
        sqlx::query("DELETE FROM storage_scrub_state WHERE scope = $1")
            .bind(fx.repo_id.to_string())
            .execute(&fx.pool)
            .await
            .expect("reset cursor");
        let full = svc.run(&opts(&fx, true)).await.expect("full run");
        let full_detail: Option<String> = sqlx::query_scalar(
            "SELECT detail FROM storage_scrub_findings WHERE object_kind = 'artifact' \
             AND object_id = $1",
        )
        .bind(bad)
        .fetch_one(&fx.pool)
        .await
        .expect("finding");
        fx.teardown().await;
        for donor_fx in donors {
            donor_fx.teardown().await;
        }

        assert_eq!(res.corrupt, 1, "{res:?}");
        assert_eq!(res.repaired, 0, "{res:?}");
        assert_eq!(res.bytes_read, 2 * len, "the target and one donor: {res:?}");
        assert!(
            detail.as_deref().is_some_and(|d| d.contains("byte budget")),
            "{detail:?}"
        );
        assert_eq!(
            full.bytes_read,
            4 * len,
            "the target and all three: {full:?}"
        );
        assert_eq!(
            full_detail.as_deref(),
            Some("no verified good copy available")
        );
    }

    /// #5168: the budget never stops the first donor, or an object as large as
    /// the budget could never be repaired.
    #[tokio::test]
    async fn scrub_repair_tries_the_first_donor_past_the_budget_5168() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let Some(donor_fx) = tdh::Fixture::setup("local", "generic").await else {
            fx.teardown().await;
            return;
        };
        let original = b"scrub-first-donor-bytes";
        let cas = crate::services::artifact_service::ArtifactService::storage_key_from_checksum(
            &sha_hex(original),
        );
        let (bad, _) = seed_at(&fx, &cas, "f/bad.bin", original, b"scrub-first-donor-byteX").await;
        seed_at(&donor_fx, &cas, "f/copy.bin", original, original).await;
        let svc = StorageScrubService::new(fx.pool.clone(), fx.state.storage_registry.clone());
        let res = svc
            .run(&ScrubOptions {
                max_bytes: original.len() as u64,
                ..opts(&fx, true)
            })
            .await
            .expect("scrub run");
        let status = finding_status(&fx.pool, bad).await;
        let fixed = fs_storage(&fx).get(&cas).await.expect("object");
        fx.teardown().await;
        donor_fx.teardown().await;

        assert_eq!(res.repaired, 1, "{res:?}");
        assert_eq!(status.as_deref(), Some("repaired"));
        assert_eq!(&fixed[..], original);
    }

    /// #4323: findings of hard-deleted rows and the cursor of a deleted
    /// repository's scoped runs are removed by the next run.
    #[tokio::test]
    async fn scrub_prunes_orphaned_bookkeeping_4323() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let gone_artifact = Uuid::new_v4();
        let gone_scope = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO storage_scrub_findings (object_kind, object_id, repository_id, \
                 storage_key, expected_sha256, status) \
             VALUES ('artifact', $1, $2, 'gone/key', 'x', 'corrupt')",
        )
        .bind(gone_artifact)
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .expect("seed finding");
        sqlx::query("INSERT INTO storage_scrub_state (scope) VALUES ($1)")
            .bind(&gone_scope)
            .execute(&fx.pool)
            .await
            .expect("seed state");
        let svc = StorageScrubService::new(fx.pool.clone(), fx.state.storage_registry.clone());
        svc.run(&opts(&fx, false)).await.expect("scrub run");
        let finding = finding_status(&fx.pool, gone_artifact).await;
        let state: i64 =
            sqlx::query_scalar("SELECT count(*) FROM storage_scrub_state WHERE scope = $1")
                .bind(&gone_scope)
                .fetch_one(&fx.pool)
                .await
                .expect("count state");
        let own: i64 =
            sqlx::query_scalar("SELECT count(*) FROM storage_scrub_state WHERE scope = $1")
                .bind(fx.repo_id.to_string())
                .fetch_one(&fx.pool)
                .await
                .expect("count own state");
        fx.teardown().await;
        assert_eq!(finding, None, "a finding of a hard-deleted row is pruned");
        assert_eq!(state, 0, "a deleted repository's cursor is pruned");
        assert_eq!(own, 1, "a live repository's cursor is kept");
    }

    /// #3910: a corrupt CONTENT-ADDRESSED object with a verified copy of the
    /// same digest elsewhere is restored and re-verified; without a good copy
    /// it would only be reported.
    #[tokio::test]
    async fn scrub_repairs_cas_object_from_verified_copy() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let Some(donor_fx) = tdh::Fixture::setup("local", "generic").await else {
            fx.teardown().await;
            return;
        };
        let original = b"scrub-repairable-bytes";
        let cas = crate::services::artifact_service::ArtifactService::storage_key_from_checksum(
            &sha_hex(original),
        );
        let (bad, _) = seed_at(&fx, &cas, "r/bad.bin", original, b"scrub-repairable-byteX").await;
        // The donor lives in another repository's storage root.
        seed_at(&donor_fx, &cas, "r/copy.bin", original, original).await;

        let svc = StorageScrubService::new(fx.pool.clone(), fx.state.storage_registry.clone());
        let res = svc.run(&opts(&fx, true)).await.expect("scrub run");
        let status = finding_status(&fx.pool, bad).await;
        let fixed = fs_storage(&fx).get(&cas).await.expect("object");

        // A second pass finds it intact; the repaired finding stays as record.
        let res2 = svc.run(&opts(&fx, false)).await.expect("second run");
        fx.teardown().await;
        donor_fx.teardown().await;

        assert_eq!(res.repaired, 1, "{res:?}");
        assert_eq!(status.as_deref(), Some("repaired"));
        assert_eq!(&fixed[..], original);
        assert_eq!(res2.corrupt, 0, "{res2:?}");
        assert_eq!(res2.intact, 1, "{res2:?}");
    }

    /// #3910 review (nit): a path-keyed object whose file name IS its digest
    /// must still be treated as path-keyed — reported, never overwritten —
    /// even with a verified copy of the recorded digest available.
    #[tokio::test]
    async fn scrub_does_not_repair_path_keyed_object_named_after_its_digest() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let Some(donor_fx) = tdh::Fixture::setup("local", "generic").await else {
            fx.teardown().await;
            return;
        };
        let original = b"scrub-sha-named-bytes";
        let hex = sha_hex(original);
        let key = format!("uploads/{hex}");
        let (bad, _) = seed_at(&fx, &key, "u/named.bin", original, b"scrub-sha-named-byteX").await;
        let cas =
            crate::services::artifact_service::ArtifactService::storage_key_from_checksum(&hex);
        seed_at(&donor_fx, &cas, "u/copy.bin", original, original).await;

        let svc = StorageScrubService::new(fx.pool.clone(), fx.state.storage_registry.clone());
        let res = svc.run(&opts(&fx, true)).await.expect("scrub run");
        let status = finding_status(&fx.pool, bad).await;
        let still = fs_storage(&fx).get(&key).await.expect("object");
        fx.teardown().await;
        donor_fx.teardown().await;

        assert_eq!(res.repaired, 0, "{res:?}");
        assert_eq!(res.corrupt, 1, "{res:?}");
        assert_eq!(status.as_deref(), Some("corrupt"));
        assert_eq!(&still[..], b"scrub-sha-named-byteX");
    }

    /// A multi-layer image manifest: its image size (config + layers, what
    /// `artifacts.size_bytes` records since #3601) is far larger than the body.
    fn multi_layer_manifest() -> (Vec<u8>, i64) {
        let body = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": format!("sha256:{}", "c".repeat(64)),
                "size": 1_469
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": format!("sha256:{}", "1".repeat(64)),
                    "size": 3_623_807
                },
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": format!("sha256:{}", "2".repeat(64)),
                    "size": 29_126_484
                }
            ]
        })
        .to_string()
        .into_bytes();
        (body, 1_469 + 3_623_807 + 29_126_484)
    }

    /// Seed an OCI manifest row as the push path writes it: key
    /// `oci-manifests/<digest>`, `size_bytes` = image size, and (when
    /// `recorded`) an `oci_manifests` record of the body length.
    async fn seed_manifest(
        fx: &tdh::Fixture,
        body: &[u8],
        image_size: i64,
        stored: &[u8],
        recorded: bool,
    ) -> Uuid {
        let hex = sha_hex(body);
        let digest = format!("sha256:{hex}");
        let (id, _) = seed_at(
            fx,
            &format!("oci-manifests/{digest}"),
            &format!("v2/img/manifests/{digest}"),
            body,
            stored,
        )
        .await;
        sqlx::query("UPDATE artifacts SET size_bytes = $1 WHERE id = $2")
            .bind(image_size)
            .bind(id)
            .execute(&fx.pool)
            .await
            .expect("record image size");
        if recorded {
            sqlx::query(
                "INSERT INTO oci_manifests (repository_id, digest, content_type, size_bytes) \
                 VALUES ($1, $2, 'application/vnd.oci.image.manifest.v1+json', $3)",
            )
            .bind(fx.repo_id)
            .bind(&digest)
            .bind(body.len() as i64)
            .execute(&fx.pool)
            .await
            .expect("record manifest");
        }
        id
    }

    /// #4666: an intact OCI manifest whose image size (`size_bytes`, #3601)
    /// differs from its body length verifies clean, with and without an
    /// `oci_manifests` record; a truncated manifest body is still corrupt and
    /// the finding reports the body length, not the image size.
    #[tokio::test]
    async fn scrub_verifies_oci_manifest_by_stored_length() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let (body, image_size) = multi_layer_manifest();
        assert_ne!(image_size, body.len() as i64);
        let recorded = seed_manifest(&fx, &body, image_size, &body, true).await;

        let mut other = body.clone();
        other.extend_from_slice(b"\n");
        let unrecorded = seed_manifest(&fx, &other, image_size, &other, false).await;

        let mut third = body.clone();
        third.extend_from_slice(b"\n\n");
        let truncated =
            seed_manifest(&fx, &third, image_size, &third[..third.len() - 7], true).await;

        let svc = StorageScrubService::new(fx.pool.clone(), fx.state.storage_registry.clone());
        let res = svc.run(&opts(&fx, false)).await.expect("scrub run");
        let statuses = (
            finding_status(&fx.pool, recorded).await,
            finding_status(&fx.pool, unrecorded).await,
            finding_status(&fx.pool, truncated).await,
        );
        fx.teardown().await;

        assert_eq!(res.intact, 2, "{res:?}");
        assert_eq!(res.corrupt, 1, "{res:?}");
        assert_eq!(statuses.0, None);
        assert_eq!(statuses.1, None);
        assert_eq!(statuses.2.as_deref(), Some("corrupt"));
        let f = &res.findings[0];
        assert_eq!(f.object_id, truncated);
        assert_eq!(f.expected_size, Some(third.len() as i64));
        assert_eq!(f.actual_size, Some(third.len() as i64 - 7));
    }

    /// #3910 review (S3): the cursor is persisted per object, so consecutive
    /// bounded runs (or a run cut short) continue where the last stopped
    /// instead of re-checking the same first object forever.
    #[tokio::test]
    async fn scrub_scoped_runs_resume_from_cursor() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        seed(&fx, "c/one.bin", b"cursor-one", b"cursor-one").await;
        seed(&fx, "c/two.bin", b"cursor-two", b"cursor-twX").await;
        let svc = StorageScrubService::new(fx.pool.clone(), fx.state.storage_registry.clone());
        let one = ScrubOptions {
            max_objects: 1,
            ..opts(&fx, false)
        };
        let r1 = svc.run(&one).await.expect("run 1");
        let r2 = svc.run(&one).await.expect("run 2");
        let r3 = svc.run(&one).await.expect("run 3");
        fx.teardown().await;

        assert_eq!((r1.objects_checked, r2.objects_checked), (1, 1));
        assert_eq!(r1.intact + r2.intact, 1, "{r1:?} {r2:?}");
        assert_eq!(r1.corrupt + r2.corrupt, 1, "{r1:?} {r2:?}");
        assert!(!r1.cycle_completed && !r2.cycle_completed);
        assert_eq!(r3.objects_checked, 0);
        assert!(r3.cycle_completed, "{r3:?}");
    }

    /// Only one scrub may run at a time.
    #[tokio::test]
    async fn scrub_refuses_concurrent_run() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let lease = PgAdvisoryLock::new(pool.clone())
            .try_acquire(STORAGE_SCRUB_LOCK_CLASS, 0)
            .await
            .expect("lock")
            .expect("free");
        let svc = StorageScrubService::new(
            pool.clone(),
            Arc::new(StorageRegistry::new(
                Default::default(),
                "filesystem".into(),
            )),
        );
        let res = svc
            .run(&ScrubOptions {
                max_objects: 1,
                max_bytes: 1,
                repair: false,
                repository_id: None,
            })
            .await;
        lease.release().await;
        assert!(matches!(res, Err(AppError::Conflict(_))), "{res:?}");
    }
}
