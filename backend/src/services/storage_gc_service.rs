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
use crate::storage::{StorageBackend, StorageLocation, StorageRegistry};

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
    pub async fn run_gc(&self, dry_run: bool) -> Result<StorageGcResult> {
        // Find orphaned storage keys joined with their repository storage paths.
        // Group by (storage_key, storage_path) so filesystem mode deletes from
        // each repo directory that held a copy of the content.
        let orphans = sqlx::query(
            r#"
            SELECT a.storage_key, r.storage_backend, r.storage_path,
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
            GROUP BY a.storage_key, r.storage_backend, r.storage_path
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
            let storage_backend: String = row.try_get("storage_backend").unwrap_or_default();
            let storage_path: String = row.try_get("storage_path").unwrap_or_default();
            let bytes: i64 = row.try_get("total_bytes").unwrap_or(0);
            let count: i64 = row.try_get("artifact_count").unwrap_or(0);

            // Resolve the correct storage backend for this repo
            let location = StorageLocation {
                backend: storage_backend,
                path: storage_path,
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

    #[tokio::test]
    async fn test_run_gc_dry_run_keeps_oci_manifest_referenced_by_tag() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let image = "gc-image";
        let tag = "latest";
        let digest = format!("sha256:{}", "a".repeat(64));
        let storage_key = format!("oci-manifests/{}", digest);

        sqlx::query(
            r#"
            INSERT INTO oci_tags (
                repository_id, name, tag, manifest_digest, manifest_content_type
            )
            VALUES ($1, $2, $3, $4, 'application/vnd.oci.image.manifest.v1+json')
            "#,
        )
        .bind(fixture.repo_id)
        .bind(image)
        .bind(tag)
        .bind(&digest)
        .execute(&fixture.pool)
        .await
        .expect("insert oci tag");

        sqlx::query(
            r#"
            INSERT INTO artifacts (
                id, repository_id, path, name, version, size_bytes,
                checksum_sha256, content_type, storage_key, uploaded_by, is_deleted
            )
            VALUES (
                $1, $2, $3, $4, $5, 123,
                $6, 'application/vnd.oci.image.manifest.v1+json', $7, $8, true
            )
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(fixture.repo_id)
        .bind(format!("v2/{}/manifests/{}", image, tag))
        .bind(format!("{}:{}", image, tag))
        .bind(tag)
        .bind("a".repeat(64))
        .bind(&storage_key)
        .bind(fixture.user_id)
        .execute(&fixture.pool)
        .await
        .expect("insert soft-deleted oci manifest artifact");

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let result = service.run_gc(true).await;

        fixture.teardown().await;

        let result = result.expect("dry-run gc succeeds");
        assert_eq!(
            result.storage_keys_deleted, 0,
            "GC must not delete manifest storage that is still referenced by oci_tags"
        );
        assert_eq!(result.artifacts_removed, 0);
        assert_eq!(result.bytes_freed, 0);
    }

    #[tokio::test]
    async fn test_run_gc_dry_run_keeps_oci_blob_referenced_by_blob_index() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let digest = format!("sha256:{}", "b".repeat(64));
        let storage_key = format!("oci-blobs/{}", digest);

        sqlx::query(
            r#"
            INSERT INTO oci_blobs (repository_id, digest, size_bytes, storage_key)
            VALUES ($1, $2, 456, $3)
            "#,
        )
        .bind(fixture.repo_id)
        .bind(&digest)
        .bind(&storage_key)
        .execute(&fixture.pool)
        .await
        .expect("insert oci blob");

        sqlx::query(
            r#"
            INSERT INTO artifacts (
                id, repository_id, path, name, version, size_bytes,
                checksum_sha256, content_type, storage_key, uploaded_by, is_deleted
            )
            VALUES (
                $1, $2, $3, $4, $5, 456,
                $6, 'application/octet-stream', $7, $8, true
            )
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(fixture.repo_id)
        .bind(format!("v2/gc-image/blobs/{}", digest))
        .bind(format!("gc-image:{}", digest))
        .bind(&digest)
        .bind("b".repeat(64))
        .bind(&storage_key)
        .bind(fixture.user_id)
        .execute(&fixture.pool)
        .await
        .expect("insert soft-deleted oci blob artifact");

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let result = service.run_gc(true).await;

        fixture.teardown().await;

        let result = result.expect("dry-run gc succeeds");
        assert_eq!(
            result.storage_keys_deleted, 0,
            "GC must not delete blob storage that is still referenced by oci_blobs"
        );
        assert_eq!(result.artifacts_removed, 0);
        assert_eq!(result.bytes_freed, 0);
    }
}
