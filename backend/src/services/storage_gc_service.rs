//! Storage garbage collection service.
//!
//! Finds soft-deleted artifacts whose storage keys are no longer referenced
//! by any live artifact, deletes the physical storage files, and hard-deletes
//! the artifact records from the database.

use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use utoipa::ToSchema;

use crate::error::Result;
use crate::storage::StorageBackend;

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
    shared_storage: Arc<dyn StorageBackend>,
    storage_backend_type: String,
}

impl StorageGcService {
    pub fn new(
        db: PgPool,
        shared_storage: Arc<dyn StorageBackend>,
        storage_backend_type: String,
    ) -> Self {
        Self {
            db,
            shared_storage,
            storage_backend_type,
        }
    }

    /// Get the storage backend for a given repository path.
    pub(crate) fn storage_for_path(&self, repo_storage_path: &str) -> Arc<dyn StorageBackend> {
        match self.storage_backend_type.as_str() {
            "s3" | "azure" | "gcs" => self.shared_storage.clone(),
            _ => Arc::new(crate::storage::filesystem::FilesystemStorage::new(
                repo_storage_path,
            )),
        }
    }

    /// Run garbage collection on orphaned storage keys.
    ///
    /// Finds storage keys referenced only by soft-deleted artifacts (no live
    /// artifact shares the same key), deletes the physical file from the
    /// correct storage backend, then hard-deletes the database records.
    pub async fn run_gc(&self, dry_run: bool) -> Result<StorageGcResult> {
        // Find orphaned storage keys joined with their repository storage paths.
        // Group by (storage_key, storage_path) so filesystem mode deletes from
        // each repo directory that held a copy of the content.
        let orphans = sqlx::query(
            r#"
            SELECT a.storage_key, r.storage_path,
                   SUM(a.size_bytes) as total_bytes,
                   COUNT(*) as artifact_count
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            WHERE a.is_deleted = true
              AND NOT EXISTS (
                SELECT 1 FROM artifacts a2
                WHERE a2.storage_key = a.storage_key
                  AND a2.is_deleted = false
              )
            GROUP BY a.storage_key, r.storage_path
            "#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| crate::error::AppError::Database(e.to_string()))?;

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
            let storage_path: String = row.try_get("storage_path").unwrap_or_default();
            let bytes: i64 = row.try_get("total_bytes").unwrap_or(0);
            let count: i64 = row.try_get("artifact_count").unwrap_or(0);

            // Resolve the correct storage backend for this repo's path
            let storage = self.storage_for_path(&storage_path);

            // Delete the physical file first
            if let Err(e) = storage.delete(&storage_key).await {
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
            .execute(&self.db)
            .await
            {
                let msg =
                    format_gc_error("delete promotion_approvals", &storage_key, &e.to_string());
                tracing::warn!("{}", msg);
                result.errors.push(msg);
                continue;
            }

            // Hard-delete artifact records (cascades to child tables)
            match sqlx::query("DELETE FROM artifacts WHERE storage_key = $1 AND is_deleted = true")
                .bind(&storage_key)
                .execute(&self.db)
                .await
            {
                Ok(_) => {
                    record_gc_success(&mut result, bytes, count);
                }
                Err(e) => {
                    let msg =
                        format_gc_error("hard-delete artifacts", &storage_key, &e.to_string());
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                }
            }
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
        StorageGcService::new(
            make_pool(),
            Arc::new(MockStorage) as Arc<dyn crate::storage::StorageBackend>,
            backend_type.to_string(),
        )
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
    // StorageGcService::new and storage_for_path
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_service_new_stores_backend_type() {
        let service = make_service("s3");
        assert_eq!(service.storage_backend_type, "s3");
    }

    #[tokio::test]
    async fn test_storage_for_path_s3_returns_shared() {
        let service = make_service("s3");
        let storage_a = service.storage_for_path("/repo/a");
        let storage_b = service.storage_for_path("/repo/b");

        // Both should point to the same Arc allocation (the shared storage).
        assert!(Arc::ptr_eq(&storage_a, &storage_b));
    }

    #[tokio::test]
    async fn test_storage_for_path_azure_returns_shared() {
        let service = make_service("azure");
        let storage_a = service.storage_for_path("/data/repo1");
        let storage_b = service.storage_for_path("/data/repo2");

        assert!(Arc::ptr_eq(&storage_a, &storage_b));
    }

    #[tokio::test]
    async fn test_storage_for_path_gcs_returns_shared() {
        let service = make_service("gcs");
        let storage_a = service.storage_for_path("/bucket/path1");
        let storage_b = service.storage_for_path("/bucket/path2");

        assert!(Arc::ptr_eq(&storage_a, &storage_b));
    }

    #[tokio::test]
    async fn test_storage_for_path_filesystem_creates_new() {
        let service = make_service("filesystem");
        let storage_a = service.storage_for_path("/data/repo-a");
        let storage_b = service.storage_for_path("/data/repo-b");

        // Filesystem backends should be distinct allocations per path.
        assert!(!Arc::ptr_eq(&storage_a, &storage_b));
    }

    #[tokio::test]
    async fn test_storage_for_path_filesystem_not_shared_with_mock() {
        let service = make_service("filesystem");
        let storage = service.storage_for_path("/some/path");

        // The returned storage should NOT be the shared mock backend.
        assert!(!Arc::ptr_eq(&storage, &service.shared_storage));
    }

    #[tokio::test]
    async fn test_storage_for_path_unknown_backend_creates_filesystem() {
        let service = make_service("minio");
        let storage = service.storage_for_path("/local/path");

        // Unknown types fall into the default match arm (filesystem).
        assert!(!Arc::ptr_eq(&storage, &service.shared_storage));
    }

    #[tokio::test]
    async fn test_storage_for_path_empty_backend_creates_filesystem() {
        let service = make_service("");
        let storage = service.storage_for_path("/local/path");

        assert!(!Arc::ptr_eq(&storage, &service.shared_storage));
    }

    #[tokio::test]
    async fn test_storage_for_path_cloud_ignores_path() {
        let service = make_service("s3");
        let storage_root = service.storage_for_path("/");
        let storage_deep = service.storage_for_path("/very/deep/nested/path/to/repo");

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
}
