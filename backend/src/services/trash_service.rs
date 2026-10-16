//! Artifact trash: list and restore soft-deleted artifacts (#2072).
//!
//! A soft delete (`artifacts.is_deleted = true`) keeps the row and its stored
//! object until storage GC reclaims them. Migration 261 records when the row
//! entered the trash (`artifacts.deleted_at`, stamped by a trigger) and
//! `GC_TRASH_RETENTION_DAYS` holds trashed rows back from GC for that many
//! days. This service is the operator's view of that window: list what is in
//! the trash, put an artifact back, or purge it at once.
//!
//! Restore is deliberately narrow:
//!
//! * OCI manifests and blobs (`oci-manifests/…`, `oci-blobs/…` storage keys)
//!   are refused. Deleting an OCI manifest also prunes its `oci_tags` rows
//!   (the lifecycle cascade) and blob GC reclaims `oci_blobs` independently of
//!   the `artifacts` row, so flipping `is_deleted` back would resurrect a
//!   manifest no tag points at, possibly over layers already gone. Re-push the
//!   image instead.
//! * Legacy proxy-cache rows (`proxy-cache/…` keys, #3368) are refused: the
//!   object belongs to the proxy cache catalog, which expires it on its own.
//! * The stored object must still exist. GC removes the object before it
//!   hard-deletes the rows, and a crash in between can leave a trashed row
//!   whose bytes are gone; restoring that would publish a dangling artifact.
//! * The path must be free (409 otherwise). Today `UNIQUE (repository_id,
//!   path)` covers trashed rows, so an upload to a trashed path revives or
//!   replaces that very row and a live duplicate cannot exist; the check is
//!   kept so a restore stays correct if that constraint is ever narrowed to
//!   live rows.
//!
//! The restore runs under a `FOR UPDATE` lock on the artifact row, the same
//! lock storage GC's re-check takes (`is_still_orphan`), so a restore and a GC
//! pass on the same row serialize: either GC sees a live row and skips the key,
//! or the restore finds the row gone and reports 404.
//!
//! Purge hard-deletes one trashed row now instead of waiting for GC, which
//! frees its path for a different-bytes re-upload (the upload paths refuse one
//! while the trashed row exists). It takes the same row lock, and refuses OCI
//! manifests and blobs for the same reasons restore does. Storage keys can be
//! shared, so the object (and its Maven checksum sidecars) is deleted only when
//! no other `artifacts` row or `artifact_versions` revision in the same storage
//! scope still references it; otherwise GC reclaims it later. Proxy-cache
//! objects are never deleted: only the stale row goes.

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use sqlx::PgPool;
use std::sync::Arc;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::api::dto::{Pagination, PaginationQuery};
use crate::error::{AppError, Result};
use crate::storage::{StorageLocation, StorageRegistry};

/// Largest `per_page` the list endpoint honours.
pub const MAX_TRASH_PAGE_SIZE: u32 = 500;

/// `per_page` when the caller does not ask for one.
pub const DEFAULT_TRASH_PAGE_SIZE: u32 = 50;

/// Storage-key prefixes whose artifacts cannot be restored (OCI manifests and
/// blobs; see the module docs).
const NON_RESTORABLE_KEY_PREFIXES: [&str; 2] = ["oci-manifests/", "oci-blobs/"];

/// Why an OCI artifact is refused, shared by the list flag and the 409.
pub const OCI_RESTORE_BLOCKED_REASON: &str =
    "OCI manifests and blobs cannot be restored: deleting them also removed their tags, \
     and blob GC reclaims layers independently. Re-push the image instead.";

/// Why an OCI artifact cannot be purged on its own.
pub const OCI_PURGE_BLOCKED_REASON: &str =
    "OCI manifests and blobs cannot be purged individually: their tags and shared layers \
     are reclaimed by storage GC and blob GC.";

/// Why a legacy proxy-cache row is refused (#3368): its object belongs to the
/// proxy cache catalog (`proxy_cache_artifacts`), which `purge_repo_cache` and
/// TTL expiry delete on their own schedule, so a restored live row would soon
/// point at nothing.
pub const PROXY_CACHE_RESTORE_BLOCKED_REASON: &str =
    "Proxy cache entries cannot be restored: the cached object is owned by the proxy cache \
     and is re-fetched from upstream on the next request.";

/// One artifact in the trash.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TrashedArtifact {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub repository_key: String,
    pub path: String,
    pub name: String,
    pub version: Option<String>,
    pub size_bytes: i64,
    pub checksum_sha256: String,
    /// When the artifact entered the trash. `null` for artifacts deleted
    /// before the trash existed (migration 261); GC treats those as expired.
    pub deleted_at: Option<DateTime<Utc>>,
    /// Earliest time storage GC may reclaim the artifact. `null` means it is
    /// already eligible (retention is 0, or `deleted_at` is unknown).
    pub purge_eligible_at: Option<DateTime<Utc>>,
    /// Whether `POST /api/v1/admin/trash/{id}/restore` can restore it
    /// (`false` in the restore response, since it is no longer in the trash).
    pub restorable: bool,
    /// Why it cannot be restored, when `restorable` is false.
    pub restore_blocked_reason: Option<String>,
}

/// One page of the trash listing.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TrashPage {
    pub items: Vec<TrashedArtifact>,
    /// Standard `page` / `per_page` metadata (`api::dto::Pagination`).
    pub pagination: Pagination,
    /// The configured `GC_TRASH_RETENTION_DAYS`.
    pub retention_days: u32,
}

/// A purged artifact, and whether its stored object went with it.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PurgedArtifact {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub repository_key: String,
    pub path: String,
    pub name: String,
    pub version: Option<String>,
    pub size_bytes: i64,
    pub checksum_sha256: String,
    /// `false` when another artifact or revision still references the stored
    /// object, or the object belongs to the proxy cache; storage GC reclaims
    /// it once nothing does.
    pub storage_reclaimed: bool,
}

/// Row shape shared by the list query and the restore and purge lock queries.
#[derive(Debug, sqlx::FromRow)]
struct TrashRow {
    id: Uuid,
    repository_id: Uuid,
    repository_key: String,
    path: String,
    name: String,
    version: Option<String>,
    size_bytes: i64,
    checksum_sha256: String,
    storage_key: String,
    deleted_at: Option<DateTime<Utc>>,
}

impl TrashRow {
    fn into_trashed(self, retention_days: u32) -> TrashedArtifact {
        let blocked = restore_blocked_reason(&self.storage_key);
        TrashedArtifact {
            purge_eligible_at: purge_eligible_at(self.deleted_at, retention_days),
            restorable: blocked.is_none(),
            restore_blocked_reason: blocked.map(str::to_string),
            id: self.id,
            repository_id: self.repository_id,
            repository_key: self.repository_key,
            path: self.path,
            name: self.name,
            version: self.version,
            size_bytes: self.size_bytes,
            checksum_sha256: self.checksum_sha256,
            deleted_at: self.deleted_at,
        }
    }

    fn into_purged(self, storage_reclaimed: bool) -> PurgedArtifact {
        PurgedArtifact {
            id: self.id,
            repository_id: self.repository_id,
            repository_key: self.repository_key,
            path: self.path,
            name: self.name,
            version: self.version,
            size_bytes: self.size_bytes,
            checksum_sha256: self.checksum_sha256,
            storage_reclaimed,
        }
    }

    /// The artifact as it stands once restored: live, so no deletion time,
    /// no purge time, and nothing left to restore.
    fn into_restored(self) -> TrashedArtifact {
        TrashedArtifact {
            deleted_at: None,
            purge_eligible_at: None,
            restorable: false,
            restore_blocked_reason: None,
            ..self.into_trashed(0)
        }
    }
}

/// Why an artifact with this storage key cannot be restored, if it cannot.
pub fn restore_blocked_reason(storage_key: &str) -> Option<&'static str> {
    if crate::services::proxy_service::ProxyService::is_proxy_cache_key(storage_key) {
        return Some(PROXY_CACHE_RESTORE_BLOCKED_REASON);
    }
    NON_RESTORABLE_KEY_PREFIXES
        .iter()
        .any(|p| storage_key.starts_with(p))
        .then_some(OCI_RESTORE_BLOCKED_REASON)
}

/// Earliest time GC may reclaim a row trashed at `deleted_at` under a
/// `retention_days` window; `None` when it is already eligible. Mirrors
/// `storage_gc_service::trash_retention_clause`.
pub fn purge_eligible_at(
    deleted_at: Option<DateTime<Utc>>,
    retention_days: u32,
) -> Option<DateTime<Utc>> {
    if retention_days == 0 {
        return None;
    }
    deleted_at.map(|at| at + Duration::days(i64::from(retention_days)))
}

/// Normalize caller-supplied `page` / `per_page` (page >= 1, per_page in
/// `[1, MAX_TRASH_PAGE_SIZE]`, default `DEFAULT_TRASH_PAGE_SIZE`).
pub fn clamp_trash_paging(page: Option<u32>, per_page: Option<u32>) -> PaginationQuery {
    PaginationQuery {
        page: Some(page.unwrap_or(1).max(1)),
        per_page: Some(
            per_page
                .unwrap_or(DEFAULT_TRASH_PAGE_SIZE)
                .clamp(1, MAX_TRASH_PAGE_SIZE),
        ),
    }
}

/// Decide whether a locked trash candidate may be restored, before any
/// storage I/O: it must still be in the trash, not be OCI content, and its
/// path must be free.
fn check_restorable(is_deleted: bool, storage_key: &str, path_taken: bool) -> Result<()> {
    if !is_deleted {
        return Err(AppError::NotFound(
            "Artifact is not in the trash".to_string(),
        ));
    }
    if let Some(reason) = restore_blocked_reason(storage_key) {
        return Err(AppError::Conflict(reason.to_string()));
    }
    if path_taken {
        return Err(AppError::Conflict(
            "Another live artifact already occupies this path; delete it first".to_string(),
        ));
    }
    Ok(())
}

/// Decide whether a locked trash candidate may be purged: it must still be in
/// the trash and not be OCI content.
fn check_purgeable(is_deleted: bool, storage_key: &str) -> Result<()> {
    if !is_deleted {
        return Err(AppError::NotFound(
            "Artifact is not in the trash".to_string(),
        ));
    }
    if NON_RESTORABLE_KEY_PREFIXES
        .iter()
        .any(|p| storage_key.starts_with(p))
    {
        return Err(AppError::Conflict(OCI_PURGE_BLOCKED_REASON.to_string()));
    }
    Ok(())
}

/// Locks every `artifacts` row holding storage key `$1` in the storage scope
/// `($2 backend, $3 filesystem root)`, the scope `is_still_orphan` locks.
const LOCK_KEY_ROWS_SQL: &str = "SELECT a.id FROM artifacts a \
     JOIN repositories r ON r.id = a.repository_id \
     WHERE a.storage_key = $1 AND r.storage_backend = $2 \
       AND (r.storage_backend <> 'filesystem' OR r.storage_path = $3) \
     FOR UPDATE OF a";

/// Whether anything other than artifact `$4` references storage key `$1` in
/// the same storage scope: another row (live or trashed) or a revision.
const KEY_STILL_REFERENCED_SQL: &str = "SELECT EXISTS ( \
         SELECT 1 FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
         WHERE a.storage_key = $1 AND a.id <> $4 AND r.storage_backend = $2 \
           AND (r.storage_backend <> 'filesystem' OR r.storage_path = $3) \
     ) OR EXISTS ( \
         SELECT 1 FROM artifact_versions v JOIN repositories r ON r.id = v.repository_id \
         WHERE v.storage_key = $1 AND r.storage_backend = $2 \
           AND (r.storage_backend <> 'filesystem' OR r.storage_path = $3) \
     )";

const TRASH_COLUMNS_SQL: &str = "a.id, a.repository_id, r.key AS repository_key, a.path, a.name, \
     a.version, a.size_bytes, a.checksum_sha256, a.storage_key, a.deleted_at";

pub struct TrashService {
    db: PgPool,
    storage_registry: Arc<StorageRegistry>,
    retention_days: u32,
}

impl TrashService {
    pub fn new(db: PgPool, storage_registry: Arc<StorageRegistry>, retention_days: u32) -> Self {
        Self {
            db,
            storage_registry,
            retention_days,
        }
    }

    /// List trashed artifacts, most recently deleted first, optionally only
    /// those of one repository.
    pub async fn list(
        &self,
        repository_key: Option<&str>,
        page: Option<u32>,
        per_page: Option<u32>,
    ) -> Result<TrashPage> {
        let paging = clamp_trash_paging(page, per_page);
        let limit = i64::from(paging.per_page());
        let offset = i64::from(paging.page() - 1) * limit;
        let filter = "FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
                      WHERE a.is_deleted = true AND ($1::text IS NULL OR r.key = $1)";
        let total: i64 =
            sqlx::query_scalar(sqlx::AssertSqlSafe(&*format!("SELECT COUNT(*) {filter}")))
                .bind(repository_key)
                .fetch_one(&self.db)
                .await?;
        let rows: Vec<TrashRow> = sqlx::query_as(sqlx::AssertSqlSafe(&*format!(
            "SELECT {TRASH_COLUMNS_SQL} {filter} \
             ORDER BY a.deleted_at DESC NULLS LAST, a.id \
             LIMIT $2 OFFSET $3"
        )))
        .bind(repository_key)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await?;
        Ok(TrashPage {
            items: rows
                .into_iter()
                .map(|r| r.into_trashed(self.retention_days))
                .collect(),
            pagination: Pagination::from_query_and_total(&paging, total),
            retention_days: self.retention_days,
        })
    }

    /// Restore one trashed artifact. Returns its post-restore state (no
    /// `deleted_at`, no purge time); `NotFound` if it is not (or no longer) there, `Conflict` if it is
    /// OCI content, its path is taken, or its stored object is gone.
    pub async fn restore(&self, id: Uuid) -> Result<TrashedArtifact> {
        let mut tx = self.db.begin().await?;
        let sql = format!(
            "SELECT {TRASH_COLUMNS_SQL}, a.is_deleted, r.storage_backend, r.storage_path, \
                    EXISTS (SELECT 1 FROM artifacts l \
                            WHERE l.repository_id = a.repository_id AND l.path = a.path \
                              AND l.is_deleted = false AND l.id <> a.id) AS path_taken \
             FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
             WHERE a.id = $1 \
             FOR UPDATE OF a"
        );
        let candidate: RestoreCandidate =
            sqlx::query_as::<_, RestoreCandidate>(sqlx::AssertSqlSafe(&*sql))
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| AppError::NotFound("Artifact not found".to_string()))?;

        check_restorable(
            candidate.is_deleted,
            &candidate.row.storage_key,
            candidate.path_taken,
        )?;

        let storage = self.storage_registry.backend_for(&StorageLocation {
            backend: candidate.storage_backend.clone(),
            path: candidate.storage_path.clone(),
        })?;
        if !storage.exists(&candidate.row.storage_key).await? {
            return Err(AppError::Conflict(
                "The artifact's stored object no longer exists; it cannot be restored".to_string(),
            ));
        }

        // The deleted_at trigger (migration 261) clears deleted_at, and the
        // usage-ledger trigger (migration 182) re-charges the bytes.
        sqlx::query(
            "UPDATE artifacts SET is_deleted = false, updated_at = NOW() \
             WHERE id = $1 AND is_deleted = true",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(candidate.row.into_restored())
    }

    /// Permanently delete one trashed artifact: its row now, and its stored
    /// object unless something else still references it. `NotFound` if it is
    /// not (or no longer) in the trash, `Conflict` if it is OCI content.
    pub async fn purge(&self, id: Uuid) -> Result<PurgedArtifact> {
        let mut tx = self.db.begin().await?;
        let sql = format!(
            "SELECT {TRASH_COLUMNS_SQL}, a.is_deleted, r.storage_backend, r.storage_path \
             FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
             WHERE a.id = $1 \
             FOR UPDATE OF a"
        );
        let candidate: PurgeCandidate =
            sqlx::query_as::<_, PurgeCandidate>(sqlx::AssertSqlSafe(&*sql))
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| AppError::NotFound("Artifact not found".to_string()))?;
        check_purgeable(candidate.is_deleted, &candidate.row.storage_key)?;

        let storage_key = candidate.row.storage_key.clone();
        sqlx::query(LOCK_KEY_ROWS_SQL)
            .bind(&storage_key)
            .bind(&candidate.storage_backend)
            .bind(&candidate.storage_path)
            .fetch_all(&mut *tx)
            .await?;
        let still_referenced: bool = sqlx::query_scalar(KEY_STILL_REFERENCED_SQL)
            .bind(&storage_key)
            .bind(&candidate.storage_backend)
            .bind(&candidate.storage_path)
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;

        // promotion_approvals has no ON DELETE CASCADE.
        sqlx::query("DELETE FROM promotion_approvals WHERE artifact_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM artifacts WHERE id = $1 AND is_deleted = true")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        if let Err(e) = crate::services::package_service::prune_catalog_for_purged_artifact(
            &mut tx,
            candidate.row.repository_id,
            &candidate.row.checksum_sha256,
        )
        .await
        {
            tracing::warn!(
                "Purge could not prune catalog rows for {}: {}",
                storage_key,
                e
            );
        }

        let is_cache_object =
            crate::services::proxy_service::ProxyService::is_proxy_cache_key(&storage_key);
        let storage_reclaimed = !still_referenced && !is_cache_object;
        if storage_reclaimed {
            let storage = self.storage_registry.backend_for(&StorageLocation {
                backend: candidate.storage_backend.clone(),
                path: candidate.storage_path.clone(),
            })?;
            // Deleted under the row locks, as GC does; an absent object is fine.
            match storage.delete(&storage_key).await {
                Ok(()) | Err(AppError::NotFound(_)) => {}
                Err(e) => return Err(e),
            }
            crate::services::storage_gc_service::reclaim_maven_sidecars(
                &mut tx,
                storage.as_ref(),
                &storage_key,
                &candidate.storage_backend,
            )
            .await?;
        }
        tx.commit().await?;

        Ok(candidate.row.into_purged(storage_reclaimed))
    }
}

#[derive(Debug, sqlx::FromRow)]
struct PurgeCandidate {
    #[sqlx(flatten)]
    row: TrashRow,
    is_deleted: bool,
    storage_backend: String,
    storage_path: String,
}

#[derive(Debug, sqlx::FromRow)]
struct RestoreCandidate {
    #[sqlx(flatten)]
    row: TrashRow,
    is_deleted: bool,
    storage_backend: String,
    storage_path: String,
    path_taken: bool,
}

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use bytes::Bytes;

    #[test]
    fn oci_content_is_not_restorable() {
        assert_eq!(
            restore_blocked_reason("oci-manifests/sha256:abc"),
            Some(OCI_RESTORE_BLOCKED_REASON)
        );
        assert!(restore_blocked_reason("oci-blobs/sha256:abc").is_some());
        assert_eq!(restore_blocked_reason("maven/com/acme/a-1.jar"), None);
        assert_eq!(restore_blocked_reason("generic/oci-manifests/x"), None);
        assert_eq!(
            restore_blocked_reason("proxy-cache/remote-x/simple/six/__content__"),
            Some(PROXY_CACHE_RESTORE_BLOCKED_REASON)
        );
    }

    #[test]
    fn purge_eligibility_follows_the_retention_window() {
        let at = Utc::now();
        assert_eq!(purge_eligible_at(Some(at), 0), None, "0 = eligible now");
        assert_eq!(purge_eligible_at(None, 30), None, "unknown = eligible now");
        assert_eq!(
            purge_eligible_at(Some(at), 30),
            Some(at + Duration::days(30))
        );
    }

    #[test]
    fn trash_paging_is_clamped() {
        let q = clamp_trash_paging(None, None);
        assert_eq!((q.page(), q.per_page()), (1, DEFAULT_TRASH_PAGE_SIZE));
        let q = clamp_trash_paging(Some(0), Some(0));
        assert_eq!((q.page(), q.per_page()), (1, 1));
        let q = clamp_trash_paging(Some(7), Some(10_000));
        assert_eq!((q.page(), q.per_page()), (7, MAX_TRASH_PAGE_SIZE));
    }

    #[test]
    fn restore_precheck_maps_each_refusal() {
        assert!(check_restorable(true, "generic/a", false).is_ok());
        assert!(matches!(
            check_restorable(false, "generic/a", false),
            Err(AppError::NotFound(_))
        ));
        assert!(matches!(
            check_restorable(true, "oci-manifests/sha256:x", false),
            Err(AppError::Conflict(_))
        ));
        assert!(matches!(
            check_restorable(true, "generic/a", true),
            Err(AppError::Conflict(_))
        ));
    }

    /// Insert a trashed row at `path` (storage key = path) and optionally its
    /// object; returns the artifact id.
    pub(crate) async fn seed_trashed(fx: &tdh::Fixture, path: &str, with_object: bool) -> Uuid {
        if with_object {
            put_object(fx, path).await;
        }
        seed_row(fx, path, path, true).await
    }

    fn storage(fx: &tdh::Fixture) -> Arc<dyn crate::storage::StorageBackend> {
        fx.state
            .storage_for_repo(
                &tdh::make_repo_info(fx.repo_id, &fx.repo_key, &fx.storage_dir, "local", None)
                    .storage_location(),
            )
            .expect("resolve storage")
    }

    async fn put_object(fx: &tdh::Fixture, key: &str) {
        storage(fx)
            .put(key, Bytes::from_static(b"payload"))
            .await
            .expect("seed object");
    }

    async fn object_exists(fx: &tdh::Fixture, key: &str) -> bool {
        storage(fx).exists(key).await.expect("exists")
    }

    /// Insert a row at `path` holding `storage_key`; returns the artifact id.
    async fn seed_row(fx: &tdh::Fixture, path: &str, storage_key: &str, is_deleted: bool) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO artifacts (repository_id, path, name, size_bytes, checksum_sha256, \
                 content_type, storage_key, uploaded_by, is_deleted) \
             VALUES ($1, $2, 'trashed', 7, 'cafe', 'application/octet-stream', $3, $4, $5) \
             RETURNING id",
        )
        .bind(fx.repo_id)
        .bind(path)
        .bind(storage_key)
        .bind(fx.user_id)
        .bind(is_deleted)
        .fetch_one(&fx.pool)
        .await
        .expect("insert row")
    }

    async fn row_exists(fx: &tdh::Fixture, id: Uuid) -> bool {
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM artifacts WHERE id = $1)")
            .bind(id)
            .fetch_one(&fx.pool)
            .await
            .expect("row exists")
    }

    fn service(fx: &tdh::Fixture, retention_days: u32) -> TrashService {
        TrashService::new(
            fx.pool.clone(),
            fx.state.storage_registry.clone(),
            retention_days,
        )
    }

    #[tokio::test]
    async fn list_shows_trashed_rows_with_purge_time_and_restorability() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let uid = Uuid::new_v4().simple().to_string();
        let plain = seed_trashed(&fx, &format!("generic/list-{uid}"), false).await;
        let oci = seed_trashed(&fx, &format!("oci-manifests/sha256:{uid}"), false).await;

        let page = service(&fx, 14)
            .list(Some(&fx.repo_key), None, None)
            .await
            .expect("list");
        let other = service(&fx, 14)
            .list(Some("no-such-repo-key"), Some(1), None)
            .await
            .expect("list other");
        fx.teardown().await;

        assert_eq!(page.pagination.total, 2);
        assert_eq!(page.pagination.per_page, DEFAULT_TRASH_PAGE_SIZE);
        assert_eq!(page.retention_days, 14);
        let by_id = |id| page.items.iter().find(|i| i.id == id).expect("listed");
        let plain = by_id(plain);
        assert!(plain.restorable);
        let deleted_at = plain.deleted_at.expect("stamped by the trigger");
        assert_eq!(
            plain.purge_eligible_at,
            Some(deleted_at + Duration::days(14))
        );
        let oci = by_id(oci);
        assert!(!oci.restorable);
        assert_eq!(
            oci.restore_blocked_reason.as_deref(),
            Some(OCI_RESTORE_BLOCKED_REASON)
        );
        assert_eq!(other.pagination.total, 0);
        assert!(other.items.is_empty());
    }

    #[tokio::test]
    async fn restore_brings_back_a_trashed_artifact_once() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let path = format!("generic/restore-{}", Uuid::new_v4().simple());
        let id = seed_trashed(&fx, &path, true).await;
        let svc = service(&fx, 0);

        let restored = svc.restore(id).await;
        let row: (bool, Option<DateTime<Utc>>) =
            sqlx::query_as("SELECT is_deleted, deleted_at FROM artifacts WHERE id = $1")
                .bind(id)
                .fetch_one(&fx.pool)
                .await
                .expect("read row");
        let again = svc.restore(id).await;
        let missing = svc.restore(Uuid::new_v4()).await;
        fx.teardown().await;

        let restored = restored.expect("restore");
        assert_eq!(restored.path, path);
        assert_eq!(
            restored.deleted_at, None,
            "response is the post-restore state"
        );
        assert_eq!(restored.purge_eligible_at, None);
        assert_eq!(
            row,
            (false, None),
            "restored row is live with no deleted_at"
        );
        assert!(matches!(again, Err(AppError::NotFound(_))), "{again:?}");
        assert!(matches!(missing, Err(AppError::NotFound(_))), "{missing:?}");
    }

    #[tokio::test]
    async fn restore_refuses_oci_content_and_missing_objects() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let uid = Uuid::new_v4().simple().to_string();
        let oci = seed_trashed(&fx, &format!("oci-blobs/sha256:{uid}"), true).await;
        let gone = seed_trashed(&fx, &format!("generic/gone-{uid}"), false).await;
        let svc = service(&fx, 0);

        let oci_result = svc.restore(oci).await;
        let gone_result = svc.restore(gone).await;
        let still_trashed: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifacts WHERE id = ANY($1) AND is_deleted = true",
        )
        .bind(vec![oci, gone])
        .fetch_one(&fx.pool)
        .await
        .expect("count");
        fx.teardown().await;

        assert!(
            matches!(oci_result, Err(AppError::Conflict(_))),
            "{oci_result:?}"
        );
        assert!(
            matches!(gone_result, Err(AppError::Conflict(_))),
            "{gone_result:?}"
        );
        assert_eq!(still_trashed, 2, "a refused restore must change nothing");
    }

    #[test]
    fn purge_precheck_maps_each_refusal() {
        assert!(check_purgeable(true, "generic/a").is_ok());
        assert!(check_purgeable(true, "proxy-cache/remote-x/a").is_ok());
        assert!(matches!(
            check_purgeable(false, "generic/a"),
            Err(AppError::NotFound(_))
        ));
        assert!(matches!(
            check_purgeable(true, "oci-manifests/sha256:x"),
            Err(AppError::Conflict(_))
        ));
        assert!(matches!(
            check_purgeable(true, "oci-blobs/sha256:x"),
            Err(AppError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn purge_removes_the_row_and_its_object_once() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let path = format!("generic/purge-{}", Uuid::new_v4().simple());
        let id = seed_trashed(&fx, &path, true).await;
        let svc = service(&fx, 30);

        let purged = svc.purge(id).await;
        let row_left = row_exists(&fx, id).await;
        let object_left = object_exists(&fx, &path).await;
        let again = svc.purge(id).await;
        fx.teardown().await;

        let purged = purged.expect("purge");
        assert_eq!(purged.path, path);
        assert!(purged.storage_reclaimed);
        assert!(!row_left, "the trashed row is hard-deleted");
        assert!(!object_left, "an unshared object is deleted");
        assert!(matches!(again, Err(AppError::NotFound(_))), "{again:?}");
    }

    #[tokio::test]
    async fn purge_keeps_an_object_another_row_still_references() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let uid = Uuid::new_v4().simple().to_string();
        let key = format!("generic/shared-{uid}");
        put_object(&fx, &key).await;
        let target = seed_row(&fx, &format!("generic/a-{uid}"), &key, true).await;
        let trashed_peer = seed_row(&fx, &format!("generic/b-{uid}"), &key, true).await;
        let live_peer = seed_row(&fx, &format!("generic/c-{uid}"), &key, false).await;

        let purged = service(&fx, 30).purge(target).await;
        let target_left = row_exists(&fx, target).await;
        let trashed_peer_left = row_exists(&fx, trashed_peer).await;
        let live_peer_left = row_exists(&fx, live_peer).await;
        let object_left = object_exists(&fx, &key).await;
        fx.teardown().await;

        assert!(!purged.expect("purge").storage_reclaimed);
        assert!(!target_left);
        assert!(
            trashed_peer_left,
            "a peer still inside its retention window stays in the trash"
        );
        assert!(live_peer_left);
        assert!(object_left, "a shared object is left for GC");
    }

    #[tokio::test]
    async fn purge_reclaims_maven_checksum_sidecars() {
        let Some(fx) = tdh::Fixture::setup("local", "maven").await else {
            return;
        };
        let key = format!(
            "maven/com/acme/purge-{0}/1.0/purge-{0}-1.0.jar",
            Uuid::new_v4().simple()
        );
        let sidecar = format!("{key}.sha1");
        put_object(&fx, &key).await;
        put_object(&fx, &sidecar).await;
        let id = seed_row(&fx, &key["maven/".len()..], &key, true).await;

        let purged = service(&fx, 0).purge(id).await;
        let sidecar_left = object_exists(&fx, &sidecar).await;
        fx.teardown().await;

        assert!(purged.expect("purge").storage_reclaimed);
        assert!(!sidecar_left, "the .sha1 sidecar goes with its jar");
    }

    #[tokio::test]
    async fn purge_refuses_live_rows_and_oci_content() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let uid = Uuid::new_v4().simple().to_string();
        let live_path = format!("generic/live-{uid}");
        put_object(&fx, &live_path).await;
        let live = seed_row(&fx, &live_path, &live_path, false).await;
        let oci = seed_trashed(&fx, &format!("oci-blobs/sha256:{uid}"), true).await;
        let svc = service(&fx, 0);

        let live_result = svc.purge(live).await;
        let oci_result = svc.purge(oci).await;
        let missing = svc.purge(Uuid::new_v4()).await;
        let both_left = row_exists(&fx, live).await && row_exists(&fx, oci).await;
        let live_object_left = object_exists(&fx, &live_path).await;
        fx.teardown().await;

        assert!(
            matches!(live_result, Err(AppError::NotFound(_))),
            "{live_result:?}"
        );
        assert!(
            matches!(oci_result, Err(AppError::Conflict(_))),
            "{oci_result:?}"
        );
        assert!(matches!(missing, Err(AppError::NotFound(_))), "{missing:?}");
        assert!(both_left, "a refused purge must change nothing");
        assert!(live_object_left);
    }
}
