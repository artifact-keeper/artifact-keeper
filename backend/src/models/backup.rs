//! Backup model for disaster recovery.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Backup type enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "backup_type", rename_all = "snake_case")]
pub enum BackupType {
    Full,
    Incremental,
    MetadataOnly,
    Metadata,
}

/// Backup status enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "backup_status", rename_all = "lowercase")]
pub enum BackupStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Cancelled,
}

/// Backup entity for tracking backup operations.
///
/// This model represents individual backup operations created by
/// the backup service or triggered manually by administrators.
#[derive(Debug, Clone, FromRow, Serialize)]
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

/// Backup job entity for scheduled backup operations.
///
/// Backup jobs are configured backup operations that can be
/// triggered manually or via schedules.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct BackupJob {
    pub id: Uuid,
    pub name: String,
    pub backup_type: BackupType,
    pub status: BackupStatus,
    pub storage_destination: String,
    pub include_repositories: Option<Vec<Uuid>>,
    pub include_metadata: bool,
    pub include_configs: bool,
    pub compression: String,
    pub encryption_enabled: bool,
    pub encryption_key_id: Option<String>,
    pub total_size_bytes: Option<i64>,
    pub files_count: Option<i32>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// Backup schedule entity for automated backups.
///
/// Schedules define recurring backup jobs using cron expressions.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct BackupSchedule {
    pub id: Uuid,
    pub name: String,
    pub backup_type: BackupType,
    pub cron_expression: String,
    pub storage_destination: String,
    pub include_repositories: Option<Vec<Uuid>>,
    pub retention_days: i32,
    pub is_enabled: bool,
    pub last_run_at: Option<DateTime<Utc>>,
    pub next_run_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Restore job entity for backup restoration operations.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct RestoreJob {
    pub id: Uuid,
    pub backup_job_id: Option<Uuid>,
    pub source_path: String,
    pub status: BackupStatus,
    pub restore_metadata: bool,
    pub restore_artifacts: bool,
    pub target_repositories: Option<Vec<Uuid>>,
    pub files_restored: Option<i32>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}
