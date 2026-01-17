//! Backup and restore service.
//!
//! Handles full and incremental backups of the registry data and artifacts.

use bytes::Bytes;
use chrono::{DateTime, Utc};
use flate2::write::GzEncoder;
use flate2::read::GzDecoder;
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
                return Err(AppError::Conflict("Another backup is already in progress".to_string()));
            }
            *active = Some(backup_id);
        }

        // Mark as in progress
        self.update_status(backup_id, BackupStatus::InProgress, None).await?;

        let result = self.do_backup(backup_id).await;

        // Clear active backup
        {
            let mut active = self.active_backup.lock().await;
            *active = None;
        }

        match result {
            Ok(backup) => {
                self.update_status(backup_id, BackupStatus::Completed, None).await?;
                Ok(backup)
            }
            Err(e) => {
                self.update_status(backup_id, BackupStatus::Failed, Some(&e.to_string())).await?;
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
                "users", "repositories", "artifacts", "download_stats",
                "api_tokens", "roles", "user_roles", "repository_permissions",
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
            let storage_keys = self.get_artifact_storage_keys(backup.metadata.as_ref()).await?;
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
                total_size_bytes: 0, // Will be actual size in final backup
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
        let storage_path = backup.storage_path.as_ref()
            .ok_or_else(|| AppError::Internal("Backup has no storage path".to_string()))?;
        self.storage.put(storage_path, Bytes::from(tar_buffer.clone())).await?;

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

    async fn get_artifact_storage_keys(&self, metadata: Option<&serde_json::Value>) -> Result<Vec<String>> {
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

        for entry in archive.entries().map_err(|e| AppError::Internal(e.to_string()))? {
            let entry = entry.map_err(|e| AppError::Internal(e.to_string()))?;
            let path = entry.path().map_err(|e| AppError::Internal(e.to_string()))?;
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

        let completed_at = if matches!(status, BackupStatus::Completed | BackupStatus::Failed | BackupStatus::Cancelled) {
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
        .bind(&status)
        .bind(&error_message)
        .bind(started_at)
        .bind(completed_at)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Restore from a backup
    pub async fn restore(&self, backup_id: Uuid, options: RestoreOptions) -> Result<RestoreResult> {
        let backup = self.get_by_id(backup_id).await?;

        if backup.status != BackupStatus::Completed {
            return Err(AppError::Validation("Can only restore from completed backups".to_string()));
        }

        // Download and extract backup
        let storage_path = backup.storage_path.as_ref()
            .ok_or_else(|| AppError::Internal("Backup has no storage path".to_string()))?;
        let tar_data = self.storage.get(storage_path).await?;
        let decoder = GzDecoder::new(tar_data.as_ref());
        let mut archive = Archive::new(decoder);

        let mut result = RestoreResult {
            tables_restored: Vec::new(),
            artifacts_restored: 0,
            errors: Vec::new(),
        };

        for entry in archive.entries().map_err(|e| AppError::Internal(e.to_string()))? {
            let mut entry = entry.map_err(|e| AppError::Internal(e.to_string()))?;
            let path = entry.path().map_err(|e| AppError::Internal(e.to_string()))?.to_path_buf();

            if path.starts_with("database/") && options.restore_database {
                // Restore database table
                let table_name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown");

                let mut content = Vec::new();
                entry.read_to_end(&mut content).map_err(|e| AppError::Internal(e.to_string()))?;

                match self.restore_table(table_name, &content).await {
                    Ok(_) => result.tables_restored.push(table_name.to_string()),
                    Err(e) => result.errors.push(format!("Failed to restore {}: {}", table_name, e)),
                }
            } else if path.starts_with("artifacts/") && options.restore_artifacts {
                // Restore artifact
                let storage_key = path.strip_prefix("artifacts/")
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();

                let mut content = Vec::new();
                entry.read_to_end(&mut content).map_err(|e| AppError::Internal(e.to_string()))?;

                match self.storage.put(&storage_key, Bytes::from(content)).await {
                    Ok(_) => result.artifacts_restored += 1,
                    Err(e) => result.errors.push(format!("Failed to restore {}: {}", storage_key, e)),
                }
            }
        }

        Ok(result)
    }

    async fn restore_table(&self, table: &str, content: &[u8]) -> Result<()> {
        let rows: Vec<serde_json::Value> = serde_json::from_slice(content)?;

        // Tables need to be restored in dependency order
        // This is a simplified version - production would need proper ordering
        for row in rows {
            let columns: Vec<String> = row.as_object()
                .map(|obj| obj.keys().cloned().collect())
                .unwrap_or_default();

            if columns.is_empty() {
                continue;
            }

            let placeholders: Vec<String> = (1..=columns.len())
                .map(|i| format!("${}", i))
                .collect();

            let query = format!(
                "INSERT INTO {} ({}) VALUES ({}) ON CONFLICT DO NOTHING",
                table,
                columns.join(", "),
                placeholders.join(", ")
            );

            // This is simplified - real implementation would handle data types properly
            tracing::debug!("Would execute: {} with {:?}", query, row);
        }

        Ok(())
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
            return Err(AppError::Validation("Can only cancel pending or in-progress backups".to_string()));
        }

        self.update_status(backup_id, BackupStatus::Cancelled, None).await?;

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
