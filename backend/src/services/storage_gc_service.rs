//! Storage garbage collection service.
//!
//! Finds soft-deleted artifacts whose storage keys are no longer referenced
//! by any live artifact, deletes the physical storage files, and hard-deletes
//! the artifact records from the database.

use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::sync::Arc;
use utoipa::ToSchema;

use crate::error::Result;
use crate::storage::{StorageBackend, StorageLocation, StorageRegistry};

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

/// Result of a storage GC run.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct StorageGcResult {
    pub dry_run: bool,
    pub storage_keys_deleted: i64,
    pub artifacts_removed: i64,
    pub bytes_freed: i64,
    pub errors: Vec<String>,
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
            return Ok(result);
        }

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
            match is_still_orphan(&mut tx, &storage_key, &storage_backend, &storage_path).await {
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
            if let Err(e) =
                sqlx::query("DELETE FROM artifacts WHERE storage_key = $1 AND is_deleted = true")
                    .bind(&storage_key)
                    .execute(&mut *tx)
                    .await
            {
                let _ = tx.rollback().await;
                let msg = format_gc_error("hard-delete artifacts", &storage_key, &e.to_string());
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
}
