//! Backup and restore service.
//!
//! Handles full and incremental backups of the registry data and artifacts.

use bytes::Bytes;
use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::io::Read;
use std::sync::Arc;
use tar::{Archive, Builder};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::services::storage_service::StorageService;

/// Backup status
#[derive(Debug, Clone, Copy, PartialEq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "backup_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum BackupStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Cancelled,
}

impl std::fmt::Display for BackupStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackupStatus::Pending => write!(f, "pending"),
            BackupStatus::InProgress => write!(f, "in_progress"),
            BackupStatus::Completed => write!(f, "completed"),
            BackupStatus::Failed => write!(f, "failed"),
            BackupStatus::Cancelled => write!(f, "cancelled"),
        }
    }
}

/// Backup type
#[derive(Debug, Clone, Copy, PartialEq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "backup_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum BackupType {
    Full,
    Incremental,
    Metadata,
}

/// Backup record
#[derive(Debug)]
pub struct Backup {
    pub id: Uuid,
    pub backup_type: BackupType,
    pub status: BackupStatus,
    pub storage_path: Option<String>,
    pub size_bytes: Option<i64>,
    pub artifact_count: Option<i64>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// Backup manifest stored in each backup
#[derive(Debug, Serialize, Deserialize)]
pub struct BackupManifest {
    pub version: String,
    pub backup_id: Uuid,
    pub backup_type: BackupType,
    pub created_at: DateTime<Utc>,
    pub database_tables: Vec<String>,
    pub artifact_count: i64,
    pub total_size_bytes: i64,
    pub checksum: String,
}

/// Request to create a backup
#[derive(Debug)]
pub struct CreateBackupRequest {
    pub backup_type: BackupType,
    pub repository_ids: Option<Vec<Uuid>>,
    pub created_by: Option<Uuid>,
}

/// Backup service
pub struct BackupService {
    db: PgPool,
    storage: Arc<StorageService>,
    active_backup: Arc<Mutex<Option<Uuid>>>,
}

impl BackupService {
    pub fn new(db: PgPool, storage: Arc<StorageService>) -> Self {
        Self {
            db,
            storage,
            active_backup: Arc::new(Mutex::new(None)),
        }
    }

    /// Create a new backup job
    pub async fn create(&self, req: CreateBackupRequest) -> Result<Backup> {
        let storage_path = format!(
            "backups/{}/{}.tar.gz",
            Utc::now().format("%Y/%m/%d"),
            Uuid::new_v4()
        );

        let backup = sqlx::query_as!(
            Backup,
            r#"
            INSERT INTO backups (backup_type, storage_path, created_by, metadata)
            VALUES ($1, $2, $3, $4)
            RETURNING
                id, backup_type as "backup_type: BackupType",
                status as "status: BackupStatus",
                storage_path, size_bytes, artifact_count,
                started_at, completed_at, error_message,
                metadata, created_by, created_at
            "#,
            req.backup_type as BackupType,
            storage_path,
            req.created_by,
            serde_json::json!({
                "repository_ids": req.repository_ids,
            })
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(backup)
    }

    /// Get backup by ID
    pub async fn get_by_id(&self, id: Uuid) -> Result<Backup> {
        let backup = sqlx::query_as!(
            Backup,
            r#"
            SELECT
                id, backup_type as "backup_type: BackupType",
                status as "status: BackupStatus",
                storage_path, size_bytes, artifact_count,
                started_at, completed_at, error_message,
                metadata, created_by, created_at
            FROM backups
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Backup not found".to_string()))?;

        Ok(backup)
    }

    /// List backups
    pub async fn list(
        &self,
        status: Option<BackupStatus>,
        backup_type: Option<BackupType>,
        offset: i64,
        limit: i64,
    ) -> Result<(Vec<Backup>, i64)> {
        let backups = sqlx::query_as!(
            Backup,
            r#"
            SELECT
                id, backup_type as "backup_type: BackupType",
                status as "status: BackupStatus",
                storage_path, size_bytes, artifact_count,
                started_at, completed_at, error_message,
                metadata, created_by, created_at
            FROM backups
            WHERE ($1::backup_status IS NULL OR status = $1)
              AND ($2::backup_type IS NULL OR backup_type = $2)
            ORDER BY created_at DESC
            OFFSET $3
            LIMIT $4
            "#,
            status as Option<BackupStatus>,
            backup_type as Option<BackupType>,
            offset,
            limit
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let total = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM backups
            WHERE ($1::backup_status IS NULL OR status = $1)
              AND ($2::backup_type IS NULL OR backup_type = $2)
            "#,
            status as Option<BackupStatus>,
            backup_type as Option<BackupType>
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok((backups, total))
    }

    /// Execute a backup
    pub async fn execute(&self, backup_id: Uuid) -> Result<Backup> {
        // Check if another backup is running
        {
            let mut active = self.active_backup.lock().await;
            if active.is_some() {
                return Err(AppError::Conflict(
                    "Another backup is already in progress".to_string(),
                ));
            }
            *active = Some(backup_id);
        }

        // Mark as in progress
        self.update_status(backup_id, BackupStatus::InProgress, None)
            .await?;

        let result = self.do_backup(backup_id).await;

        // Clear active backup
        {
            let mut active = self.active_backup.lock().await;
            *active = None;
        }

        match result {
            Ok(backup) => {
                self.update_status(backup_id, BackupStatus::Completed, None)
                    .await?;
                Ok(backup)
            }
            Err(e) => {
                self.update_status(backup_id, BackupStatus::Failed, Some(&e.to_string()))
                    .await?;
                Err(e)
            }
        }
    }

    async fn do_backup(&self, backup_id: Uuid) -> Result<Backup> {
        let backup = self.get_by_id(backup_id).await?;

        // Create tar.gz in memory
        let mut tar_buffer = Vec::new();
        {
            let encoder = GzEncoder::new(&mut tar_buffer, Compression::default());
            let mut tar = Builder::new(encoder);

            // Export database tables as JSON
            let tables = vec![
                "users",
                "repositories",
                "artifacts",
                "download_stats",
                "api_tokens",
                "roles",
                "user_roles",
                "repository_permissions",
            ];

            for table in &tables {
                let json_data = self.export_table(table).await?;
                let json_bytes = serde_json::to_vec_pretty(&json_data)?;

                let mut header = tar::Header::new_gnu();
                header.set_path(format!("database/{}.json", table))?;
                header.set_size(json_bytes.len() as u64);
                header.set_mode(0o644);
                header.set_mtime(Utc::now().timestamp() as u64);
                header.set_cksum();

                tar.append(&header, json_bytes.as_slice())?;
            }

            // Add artifact storage keys
            let storage_keys = self
                .get_artifact_storage_keys(backup.metadata.as_ref())
                .await?;
            let mut artifact_count = 0i64;

            for key in storage_keys {
                if let Ok(content) = self.storage.get(&key).await {
                    let mut header = tar::Header::new_gnu();
                    header.set_path(format!("artifacts/{}", key))?;
                    header.set_size(content.len() as u64);
                    header.set_mode(0o644);
                    header.set_mtime(Utc::now().timestamp() as u64);
                    header.set_cksum();

                    tar.append(&header, content.as_ref())?;
                    artifact_count += 1;
                }
            }

            // Create manifest placeholder (actual size/checksum set after finalization)
            let manifest = BackupManifest {
                version: "1.0".to_string(),
                backup_id,
                backup_type: backup.backup_type,
                created_at: Utc::now(),
                database_tables: tables.iter().map(|s| s.to_string()).collect(),
                artifact_count,
                total_size_bytes: 0,     // Will be actual size in final backup
                checksum: String::new(), // Will be computed after archive is complete
            };

            let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
            let mut header = tar::Header::new_gnu();
            header.set_path("manifest.json")?;
            header.set_size(manifest_bytes.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(Utc::now().timestamp() as u64);
            header.set_cksum();

            tar.append(&header, manifest_bytes.as_slice())?;

            tar.into_inner()?.finish()?;
        }

        // Store backup
        let storage_path = backup
            .storage_path
            .as_ref()
            .ok_or_else(|| AppError::Internal("Backup has no storage path".to_string()))?;
        self.storage
            .put(storage_path, Bytes::from(tar_buffer.clone()))
            .await?;

        // Update backup record
        let artifact_count = self.count_artifacts_in_backup(&tar_buffer)?;
        sqlx::query(
            r#"
            UPDATE backups
            SET size_bytes = $2, artifact_count = $3, completed_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(backup_id)
        .bind(tar_buffer.len() as i64)
        .bind(artifact_count)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        self.get_by_id(backup_id).await
    }

    async fn export_table(&self, table: &str) -> Result<serde_json::Value> {
        // Export table data as JSON array
        let query = format!("SELECT row_to_json(t) FROM {} t", table);
        let rows: Vec<serde_json::Value> = sqlx::query_scalar(&query)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(serde_json::Value::Array(rows))
    }

    async fn get_artifact_storage_keys(
        &self,
        metadata: Option<&serde_json::Value>,
    ) -> Result<Vec<String>> {
        let repository_filter: Option<Vec<Uuid>> = metadata
            .and_then(|m| m.get("repository_ids"))
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        let keys: Vec<String> = if let Some(repo_ids) = repository_filter {
            sqlx::query_scalar!(
                "SELECT storage_key FROM artifacts WHERE repository_id = ANY($1)",
                &repo_ids
            )
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
        } else {
            sqlx::query_scalar!("SELECT storage_key FROM artifacts")
                .fetch_all(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?
        };

        Ok(keys)
    }

    fn count_artifacts_in_backup(&self, tar_data: &[u8]) -> Result<i64> {
        let decoder = GzDecoder::new(tar_data);
        let mut archive = Archive::new(decoder);
        let mut count = 0i64;

        for entry in archive
            .entries()
            .map_err(|e| AppError::Internal(e.to_string()))?
        {
            let entry = entry.map_err(|e| AppError::Internal(e.to_string()))?;
            let path = entry
                .path()
                .map_err(|e| AppError::Internal(e.to_string()))?;
            if path.starts_with("artifacts/") {
                count += 1;
            }
        }

        Ok(count)
    }

    async fn update_status(
        &self,
        backup_id: Uuid,
        status: BackupStatus,
        error_message: Option<&str>,
    ) -> Result<()> {
        let started_at = if status == BackupStatus::InProgress {
            Some(Utc::now())
        } else {
            None
        };

        let completed_at = if matches!(
            status,
            BackupStatus::Completed | BackupStatus::Failed | BackupStatus::Cancelled
        ) {
            Some(Utc::now())
        } else {
            None
        };

        sqlx::query(
            r#"
            UPDATE backups
            SET
                status = $2,
                error_message = COALESCE($3, error_message),
                started_at = COALESCE($4, started_at),
                completed_at = COALESCE($5, completed_at)
            WHERE id = $1
            "#,
        )
        .bind(backup_id)
        .bind(status)
        .bind(error_message)
        .bind(started_at)
        .bind(completed_at)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Restore from a backup.
    ///
    /// Extracts all tar entries synchronously first (tar::Archive is !Send),
    /// then performs async database/storage restore operations.
    pub async fn restore(&self, backup_id: Uuid, options: RestoreOptions) -> Result<RestoreResult> {
        let backup = self.get_by_id(backup_id).await?;

        if backup.status != BackupStatus::Completed {
            return Err(AppError::Validation(
                "Can only restore from completed backups".to_string(),
            ));
        }

        // Download backup archive
        let storage_path = backup
            .storage_path
            .as_ref()
            .ok_or_else(|| AppError::Internal("Backup has no storage path".to_string()))?;
        let tar_data = self.storage.get(storage_path).await?;

        // Phase 1: Extract all entries synchronously (tar::Archive is !Send)
        let entries = Self::extract_entries(&tar_data)?;

        // Phase 2: Async restore from extracted data
        let mut result = RestoreResult {
            tables_restored: Vec::new(),
            artifacts_restored: 0,
            errors: Vec::new(),
        };

        // Restore database tables in dependency order
        if options.restore_database {
            let table_order = [
                "users",
                "roles",
                "user_roles",
                "repositories",
                "repository_permissions",
                "artifacts",
                "download_stats",
                "api_tokens",
            ];

            // Restore ordered tables first
            for table_name in &table_order {
                if let Some(content) = entries.iter().find(|(p, _)| {
                    p.starts_with("database/")
                        && p.file_stem().and_then(|s| s.to_str()) == Some(table_name)
                }) {
                    match self.restore_table(table_name, &content.1).await {
                        Ok(rows) => {
                            tracing::info!("Restored {} rows into table '{}'", rows, table_name);
                            result.tables_restored.push(table_name.to_string());
                        }
                        Err(e) => result
                            .errors
                            .push(format!("Failed to restore {}: {}", table_name, e)),
                    }
                }
            }

            // Restore any remaining database entries not in the ordered list
            for (path, content) in &entries {
                if !path.starts_with("database/") {
                    continue;
                }
                let table_name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown");
                if table_order.contains(&table_name) {
                    continue; // already restored above
                }
                match self.restore_table(table_name, content).await {
                    Ok(rows) => {
                        tracing::info!("Restored {} rows into table '{}'", rows, table_name);
                        result.tables_restored.push(table_name.to_string());
                    }
                    Err(e) => result
                        .errors
                        .push(format!("Failed to restore {}: {}", table_name, e)),
                }
            }
        }

        // Restore artifact files
        if options.restore_artifacts {
            for (path, content) in &entries {
                if !path.starts_with("artifacts/") {
                    continue;
                }
                let storage_key = path
                    .strip_prefix("artifacts/")
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                if storage_key.is_empty() {
                    continue;
                }

                match self
                    .storage
                    .put(&storage_key, Bytes::from(content.clone()))
                    .await
                {
                    Ok(_) => result.artifacts_restored += 1,
                    Err(e) => result
                        .errors
                        .push(format!("Failed to restore {}: {}", storage_key, e)),
                }
            }
        }

        Ok(result)
    }

    /// Extract all entries from a tar.gz archive synchronously.
    /// Returns a Vec of (path, content) pairs so that async code can
    /// process them without holding the non-Send Archive across await points.
    fn extract_entries(tar_data: &[u8]) -> Result<Vec<(std::path::PathBuf, Vec<u8>)>> {
        let decoder = GzDecoder::new(tar_data);
        let mut archive = Archive::new(decoder);
        let mut entries = Vec::new();

        for entry in archive
            .entries()
            .map_err(|e| AppError::Internal(format!("Failed to read archive entries: {}", e)))?
        {
            let mut entry =
                entry.map_err(|e| AppError::Internal(format!("Failed to read entry: {}", e)))?;
            let path = entry
                .path()
                .map_err(|e| AppError::Internal(format!("Failed to read entry path: {}", e)))?
                .to_path_buf();

            let mut content = Vec::new();
            entry
                .read_to_end(&mut content)
                .map_err(|e| AppError::Internal(format!("Failed to read entry data: {}", e)))?;

            entries.push((path, content));
        }

        Ok(entries)
    }

    /// Restore a single database table from JSON data.
    /// Uses jsonb_populate_record for proper type coercion.
    async fn restore_table(&self, table: &str, content: &[u8]) -> Result<usize> {
        let rows: Vec<serde_json::Value> = serde_json::from_slice(content)?;
        let mut restored = 0usize;

        // Validate table name to prevent SQL injection (only allow alphanumeric + underscore)
        if !table.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err(AppError::Validation(format!(
                "Invalid table name: {}",
                table
            )));
        }

        for row in &rows {
            // Use jsonb_populate_record to let Postgres handle type coercion
            let query = format!(
                "INSERT INTO {table} SELECT * FROM jsonb_populate_record(NULL::{table}, $1) ON CONFLICT DO NOTHING"
            );

            match sqlx::query(&query).bind(row).execute(&self.db).await {
                Ok(result) => {
                    restored += result.rows_affected() as usize;
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to restore row in '{}': {} (row: {})",
                        table,
                        e,
                        serde_json::to_string(row).unwrap_or_default()
                    );
                }
            }
        }

        Ok(restored)
    }

    /// Delete a backup
    pub async fn delete(&self, backup_id: Uuid) -> Result<()> {
        let backup = self.get_by_id(backup_id).await?;

        // Delete from storage if path exists
        if let Some(storage_path) = &backup.storage_path {
            if self.storage.exists(storage_path).await? {
                self.storage.delete(storage_path).await?;
            }
        }

        // Delete from database
        sqlx::query("DELETE FROM backups WHERE id = $1")
            .bind(backup_id)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Cancel a running backup
    pub async fn cancel(&self, backup_id: Uuid) -> Result<()> {
        let backup = self.get_by_id(backup_id).await?;

        if backup.status != BackupStatus::InProgress && backup.status != BackupStatus::Pending {
            return Err(AppError::Validation(
                "Can only cancel pending or in-progress backups".to_string(),
            ));
        }

        self.update_status(backup_id, BackupStatus::Cancelled, None)
            .await?;

        Ok(())
    }

    /// Clean up old backups based on retention policy
    pub async fn cleanup(&self, keep_count: i32, keep_days: i32) -> Result<u64> {
        // Keep the most recent N backups
        let result = sqlx::query(
            r#"
            DELETE FROM backups
            WHERE id NOT IN (
                SELECT id FROM backups
                WHERE status = 'completed'
                ORDER BY created_at DESC
                LIMIT $1
            )
            AND created_at < NOW() - make_interval(days => $2)
            AND status = 'completed'
            "#,
        )
        .bind(keep_count as i64)
        .bind(keep_days)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(result.rows_affected())
    }
}

/// Options for restore operation
#[derive(Debug, Default)]
pub struct RestoreOptions {
    pub restore_database: bool,
    pub restore_artifacts: bool,
    pub target_repository_id: Option<Uuid>,
}

/// Result of restore operation
#[derive(Debug, Serialize)]
pub struct RestoreResult {
    pub tables_restored: Vec<String>,
    pub artifacts_restored: i32,
    pub errors: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use chrono::Utc;
    #[allow(unused_imports)]
    use flate2::write::GzEncoder;
    #[allow(unused_imports)]
    use flate2::Compression;
    #[allow(unused_imports)]
    use tar::Builder;

    // -----------------------------------------------------------------------
    // BackupStatus Display tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_backup_status_display_pending() {
        assert_eq!(BackupStatus::Pending.to_string(), "pending");
    }

    #[test]
    fn test_backup_status_display_in_progress() {
        assert_eq!(BackupStatus::InProgress.to_string(), "in_progress");
    }

    #[test]
    fn test_backup_status_display_completed() {
        assert_eq!(BackupStatus::Completed.to_string(), "completed");
    }

    #[test]
    fn test_backup_status_display_failed() {
        assert_eq!(BackupStatus::Failed.to_string(), "failed");
    }

    #[test]
    fn test_backup_status_display_cancelled() {
        assert_eq!(BackupStatus::Cancelled.to_string(), "cancelled");
    }

    // -----------------------------------------------------------------------
    // BackupStatus equality tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_backup_status_equality() {
        assert_eq!(BackupStatus::Pending, BackupStatus::Pending);
        assert_ne!(BackupStatus::Pending, BackupStatus::InProgress);
        assert_ne!(BackupStatus::Completed, BackupStatus::Failed);
    }

    // -----------------------------------------------------------------------
    // BackupType serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_backup_type_serialization() {
        let full = serde_json::to_string(&BackupType::Full).unwrap();
        assert_eq!(full, "\"full\"");

        let incremental = serde_json::to_string(&BackupType::Incremental).unwrap();
        assert_eq!(incremental, "\"incremental\"");

        let metadata = serde_json::to_string(&BackupType::Metadata).unwrap();
        assert_eq!(metadata, "\"metadata\"");
    }

    #[test]
    fn test_backup_type_deserialization() {
        let full: BackupType = serde_json::from_str("\"full\"").unwrap();
        assert_eq!(full, BackupType::Full);

        let incremental: BackupType = serde_json::from_str("\"incremental\"").unwrap();
        assert_eq!(incremental, BackupType::Incremental);

        let metadata: BackupType = serde_json::from_str("\"metadata\"").unwrap();
        assert_eq!(metadata, BackupType::Metadata);
    }

    // -----------------------------------------------------------------------
    // BackupStatus serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_backup_status_serialization() {
        assert_eq!(
            serde_json::to_string(&BackupStatus::Pending).unwrap(),
            "\"pending\""
        );
        assert_eq!(
            serde_json::to_string(&BackupStatus::InProgress).unwrap(),
            "\"in_progress\""
        );
        assert_eq!(
            serde_json::to_string(&BackupStatus::Completed).unwrap(),
            "\"completed\""
        );
        assert_eq!(
            serde_json::to_string(&BackupStatus::Failed).unwrap(),
            "\"failed\""
        );
        assert_eq!(
            serde_json::to_string(&BackupStatus::Cancelled).unwrap(),
            "\"cancelled\""
        );
    }

    #[test]
    fn test_backup_status_deserialization() {
        let pending: BackupStatus = serde_json::from_str("\"pending\"").unwrap();
        assert_eq!(pending, BackupStatus::Pending);

        let completed: BackupStatus = serde_json::from_str("\"completed\"").unwrap();
        assert_eq!(completed, BackupStatus::Completed);
    }

    // -----------------------------------------------------------------------
    // BackupManifest serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_backup_manifest_serialization_roundtrip() {
        let manifest = BackupManifest {
            version: "1.0".to_string(),
            backup_id: Uuid::nil(),
            backup_type: BackupType::Full,
            created_at: Utc::now(),
            database_tables: vec!["users".to_string(), "artifacts".to_string()],
            artifact_count: 42,
            total_size_bytes: 1024 * 1024,
            checksum: "abc123".to_string(),
        };

        let json = serde_json::to_string(&manifest).unwrap();
        let deserialized: BackupManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.version, "1.0");
        assert_eq!(deserialized.backup_id, Uuid::nil());
        assert_eq!(deserialized.backup_type, BackupType::Full);
        assert_eq!(deserialized.database_tables.len(), 2);
        assert_eq!(deserialized.artifact_count, 42);
        assert_eq!(deserialized.total_size_bytes, 1024 * 1024);
        assert_eq!(deserialized.checksum, "abc123");
    }

    // -----------------------------------------------------------------------
    // RestoreOptions tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_restore_options_default() {
        let opts = RestoreOptions::default();
        assert!(!opts.restore_database);
        assert!(!opts.restore_artifacts);
        assert!(opts.target_repository_id.is_none());
    }

    // -----------------------------------------------------------------------
    // RestoreResult serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_restore_result_serialization() {
        let result = RestoreResult {
            tables_restored: vec!["users".to_string()],
            artifacts_restored: 5,
            errors: vec!["some error".to_string()],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"tables_restored\":[\"users\"]"));
        assert!(json.contains("\"artifacts_restored\":5"));
        assert!(json.contains("\"errors\":[\"some error\"]"));
    }

    // -----------------------------------------------------------------------
    // count_artifacts_in_backup tests (via extract_entries + tar creation)
    // -----------------------------------------------------------------------

    /// Helper: create a tar.gz archive in memory with the given entries.
    fn create_test_tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_buffer = Vec::new();
        {
            let encoder = GzEncoder::new(&mut tar_buffer, Compression::default());
            let mut tar = Builder::new(encoder);

            for (path, data) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_path(path).unwrap();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_mtime(0);
                header.set_cksum();
                tar.append(&header, *data).unwrap();
            }

            tar.into_inner().unwrap().finish().unwrap();
        }
        tar_buffer
    }

    #[test]
    fn test_extract_entries_empty_archive() {
        let tar_data = create_test_tar_gz(&[]);
        let entries = BackupService::extract_entries(&tar_data).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_extract_entries_with_entries() {
        let tar_data = create_test_tar_gz(&[
            ("manifest.json", b"{}"),
            ("database/users.json", b"[]"),
            ("artifacts/key1", b"binary data"),
        ]);
        let entries = BackupService::extract_entries(&tar_data).unwrap();
        assert_eq!(entries.len(), 3);

        let paths: Vec<String> = entries
            .iter()
            .map(|(p, _)| p.to_string_lossy().to_string())
            .collect();
        assert!(paths.contains(&"manifest.json".to_string()));
        assert!(paths.contains(&"database/users.json".to_string()));
        assert!(paths.contains(&"artifacts/key1".to_string()));
    }

    #[test]
    fn test_extract_entries_preserves_content() {
        let tar_data = create_test_tar_gz(&[("test.txt", b"hello world")]);
        let entries = BackupService::extract_entries(&tar_data).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1, b"hello world");
    }

    #[test]
    fn test_extract_entries_invalid_data() {
        let result = BackupService::extract_entries(b"not a tar gz");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // CreateBackupRequest construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_backup_request_construction() {
        let req = CreateBackupRequest {
            backup_type: BackupType::Full,
            repository_ids: Some(vec![Uuid::new_v4()]),
            created_by: Some(Uuid::new_v4()),
        };
        assert_eq!(req.backup_type, BackupType::Full);
        assert!(req.repository_ids.is_some());
        assert!(req.created_by.is_some());
    }

    #[test]
    fn test_create_backup_request_no_optional_fields() {
        let req = CreateBackupRequest {
            backup_type: BackupType::Metadata,
            repository_ids: None,
            created_by: None,
        };
        assert_eq!(req.backup_type, BackupType::Metadata);
        assert!(req.repository_ids.is_none());
        assert!(req.created_by.is_none());
    }

    // -----------------------------------------------------------------------
    // BackupType Copy/Clone tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_backup_type_clone_and_copy() {
        let bt = BackupType::Full;
        let bt2 = bt; // Copy
        let bt3 = bt; // Clone
        assert_eq!(bt, bt2);
        assert_eq!(bt, bt3);
    }

    #[test]
    fn test_backup_status_clone_and_copy() {
        let bs = BackupStatus::Completed;
        let bs2 = bs; // Copy
        let bs3 = bs; // Clone
        assert_eq!(bs, bs2);
        assert_eq!(bs, bs3);
    }
}
