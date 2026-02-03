//! Admin handlers (backups, system settings).

use axum::{
    extract::{Extension, Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::backup_service::{
    BackupService, BackupStatus, BackupType, CreateBackupRequest as ServiceCreateBackup,
    RestoreOptions,
};
use crate::services::storage_service::StorageService;

/// Create admin routes
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/backups", get(list_backups).post(create_backup))
        .route("/backups/:id", get(get_backup).delete(delete_backup))
        .route("/backups/:id/execute", post(execute_backup))
        .route("/backups/:id/restore", post(restore_backup))
        .route("/backups/:id/cancel", post(cancel_backup))
        .route("/settings", get(get_settings).post(update_settings))
        .route("/stats", get(get_system_stats))
        .route("/cleanup", post(run_cleanup))
        .route("/reindex", post(trigger_reindex))
}

#[derive(Debug, Deserialize)]
pub struct ListBackupsQuery {
    pub status: Option<String>,
    #[serde(rename = "type")]
    pub backup_type: Option<String>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct CreateBackupRequest {
    #[serde(rename = "type")]
    pub backup_type: Option<String>,
    pub repository_ids: Option<Vec<Uuid>>,
}

#[derive(Debug, Serialize)]
pub struct BackupResponse {
    pub id: Uuid,
    #[serde(rename = "type")]
    pub backup_type: String,
    pub status: String,
    pub storage_path: Option<String>,
    pub size_bytes: i64,
    pub artifact_count: i64,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub error_message: Option<String>,
    pub created_by: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct BackupListResponse {
    pub items: Vec<BackupResponse>,
    pub total: i64,
}

fn parse_backup_type(s: &str) -> Option<BackupType> {
    match s.to_lowercase().as_str() {
        "full" => Some(BackupType::Full),
        "incremental" => Some(BackupType::Incremental),
        "metadata" => Some(BackupType::Metadata),
        _ => None,
    }
}

fn parse_backup_status(s: &str) -> Option<BackupStatus> {
    match s.to_lowercase().as_str() {
        "pending" => Some(BackupStatus::Pending),
        "in_progress" => Some(BackupStatus::InProgress),
        "completed" => Some(BackupStatus::Completed),
        "failed" => Some(BackupStatus::Failed),
        "cancelled" => Some(BackupStatus::Cancelled),
        _ => None,
    }
}

/// List backups
pub async fn list_backups(
    State(state): State<SharedState>,
    Query(query): Query<ListBackupsQuery>,
) -> Result<Json<BackupListResponse>> {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = ((page - 1) * per_page) as i64;

    let status = query.status.as_ref().and_then(|s| parse_backup_status(s));
    let backup_type = query
        .backup_type
        .as_ref()
        .and_then(|t| parse_backup_type(t));

    let storage = Arc::new(StorageService::from_config(&state.config).await?);
    let service = BackupService::new(state.db.clone(), storage);
    let (backups, total) = service
        .list(status, backup_type, offset, per_page as i64)
        .await?;

    let items = backups
        .into_iter()
        .map(|b| BackupResponse {
            id: b.id,
            backup_type: format!("{:?}", b.backup_type).to_lowercase(),
            status: b.status.to_string(),
            storage_path: b.storage_path,
            size_bytes: b.size_bytes.unwrap_or(0),
            artifact_count: b.artifact_count.unwrap_or(0),
            started_at: b.started_at,
            completed_at: b.completed_at,
            error_message: b.error_message,
            created_by: b.created_by,
            created_at: b.created_at,
        })
        .collect();

    Ok(Json(BackupListResponse { items, total }))
}

/// Get backup by ID
pub async fn get_backup(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<BackupResponse>> {
    let storage = Arc::new(StorageService::from_config(&state.config).await?);
    let service = BackupService::new(state.db.clone(), storage);
    let backup = service.get_by_id(id).await?;

    Ok(Json(BackupResponse {
        id: backup.id,
        backup_type: format!("{:?}", backup.backup_type).to_lowercase(),
        status: backup.status.to_string(),
        storage_path: backup.storage_path,
        size_bytes: backup.size_bytes.unwrap_or(0),
        artifact_count: backup.artifact_count.unwrap_or(0),
        started_at: backup.started_at,
        completed_at: backup.completed_at,
        error_message: backup.error_message,
        created_by: backup.created_by,
        created_at: backup.created_at,
    }))
}

/// Create backup
pub async fn create_backup(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(payload): Json<CreateBackupRequest>,
) -> Result<Json<BackupResponse>> {
    let backup_type = payload
        .backup_type
        .as_ref()
        .and_then(|t| parse_backup_type(t))
        .unwrap_or(BackupType::Full);

    let storage = Arc::new(StorageService::from_config(&state.config).await?);
    let service = BackupService::new(state.db.clone(), storage);

    let backup = service
        .create(ServiceCreateBackup {
            backup_type,
            repository_ids: payload.repository_ids,
            created_by: Some(auth.user_id),
        })
        .await?;

    Ok(Json(BackupResponse {
        id: backup.id,
        backup_type: format!("{:?}", backup.backup_type).to_lowercase(),
        status: backup.status.to_string(),
        storage_path: backup.storage_path,
        size_bytes: backup.size_bytes.unwrap_or(0),
        artifact_count: backup.artifact_count.unwrap_or(0),
        started_at: backup.started_at,
        completed_at: backup.completed_at,
        error_message: backup.error_message,
        created_by: backup.created_by,
        created_at: backup.created_at,
    }))
}

/// Execute a pending backup
pub async fn execute_backup(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<BackupResponse>> {
    let storage = Arc::new(StorageService::from_config(&state.config).await?);
    let service = BackupService::new(state.db.clone(), storage);

    let backup = service.execute(id).await?;

    Ok(Json(BackupResponse {
        id: backup.id,
        backup_type: format!("{:?}", backup.backup_type).to_lowercase(),
        status: backup.status.to_string(),
        storage_path: backup.storage_path,
        size_bytes: backup.size_bytes.unwrap_or(0),
        artifact_count: backup.artifact_count.unwrap_or(0),
        started_at: backup.started_at,
        completed_at: backup.completed_at,
        error_message: backup.error_message,
        created_by: backup.created_by,
        created_at: backup.created_at,
    }))
}

#[derive(Debug, Deserialize)]
pub struct RestoreRequest {
    pub restore_database: Option<bool>,
    pub restore_artifacts: Option<bool>,
    pub target_repository_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct RestoreResponse {
    pub tables_restored: Vec<String>,
    pub artifacts_restored: i32,
    pub errors: Vec<String>,
}

/// Restore from backup
pub async fn restore_backup(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<RestoreRequest>,
) -> Result<Json<RestoreResponse>> {
    let storage = Arc::new(
        StorageService::from_config(&state.config)
            .await
            .map_err(|e: AppError| e)?,
    );
    let service = BackupService::new(state.db.clone(), storage);

    let options = RestoreOptions {
        restore_database: payload.restore_database.unwrap_or(true),
        restore_artifacts: payload.restore_artifacts.unwrap_or(true),
        target_repository_id: payload.target_repository_id,
    };

    let result = service.restore(id, options).await?;

    Ok(Json(RestoreResponse {
        tables_restored: result.tables_restored,
        artifacts_restored: result.artifacts_restored,
        errors: result.errors,
    }))
}

/// Cancel a running backup
pub async fn cancel_backup(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    let storage = Arc::new(StorageService::from_config(&state.config).await?);
    let service = BackupService::new(state.db.clone(), storage);

    service.cancel(id).await?;
    Ok(())
}

/// Delete a backup
pub async fn delete_backup(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    let storage = Arc::new(StorageService::from_config(&state.config).await?);
    let service = BackupService::new(state.db.clone(), storage);

    service.delete(id).await?;
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SystemSettings {
    pub allow_anonymous_download: bool,
    pub max_upload_size_bytes: i64,
    pub retention_days: i32,
    pub audit_retention_days: i32,
    pub backup_retention_count: i32,
    pub edge_stale_threshold_minutes: i32,
}

/// Get system settings
pub async fn get_settings(State(state): State<SharedState>) -> Result<Json<SystemSettings>> {
    let settings = sqlx::query_as!(
        SystemSettingsRow,
        r#"
        SELECT key, value
        FROM system_settings
        WHERE key IN (
            'allow_anonymous_download',
            'max_upload_size_bytes',
            'retention_days',
            'audit_retention_days',
            'backup_retention_count',
            'edge_stale_threshold_minutes'
        )
        "#
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let mut result = SystemSettings {
        allow_anonymous_download: false,
        max_upload_size_bytes: 100 * 1024 * 1024, // 100MB default
        retention_days: 365,
        audit_retention_days: 90,
        backup_retention_count: 10,
        edge_stale_threshold_minutes: 5,
    };

    for row in settings {
        match row.key.as_str() {
            "allow_anonymous_download" => {
                result.allow_anonymous_download = row.value.as_bool().unwrap_or(false);
            }
            "max_upload_size_bytes" => {
                result.max_upload_size_bytes =
                    row.value.as_i64().unwrap_or(result.max_upload_size_bytes);
            }
            "retention_days" => {
                result.retention_days =
                    row.value.as_i64().unwrap_or(result.retention_days as i64) as i32;
            }
            "audit_retention_days" => {
                result.audit_retention_days =
                    row.value
                        .as_i64()
                        .unwrap_or(result.audit_retention_days as i64) as i32;
            }
            "backup_retention_count" => {
                result.backup_retention_count =
                    row.value
                        .as_i64()
                        .unwrap_or(result.backup_retention_count as i64) as i32;
            }
            "edge_stale_threshold_minutes" => {
                result.edge_stale_threshold_minutes = row
                    .value
                    .as_i64()
                    .unwrap_or(result.edge_stale_threshold_minutes as i64)
                    as i32;
            }
            _ => {}
        }
    }

    Ok(Json(result))
}

struct SystemSettingsRow {
    key: String,
    value: serde_json::Value,
}

/// Update system settings
pub async fn update_settings(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Json(settings): Json<SystemSettings>,
) -> Result<Json<SystemSettings>> {
    // Update each setting
    let settings_to_update = vec![
        (
            "allow_anonymous_download",
            serde_json::json!(settings.allow_anonymous_download),
        ),
        (
            "max_upload_size_bytes",
            serde_json::json!(settings.max_upload_size_bytes),
        ),
        ("retention_days", serde_json::json!(settings.retention_days)),
        (
            "audit_retention_days",
            serde_json::json!(settings.audit_retention_days),
        ),
        (
            "backup_retention_count",
            serde_json::json!(settings.backup_retention_count),
        ),
        (
            "edge_stale_threshold_minutes",
            serde_json::json!(settings.edge_stale_threshold_minutes),
        ),
    ];

    for (setting_key, setting_value) in settings_to_update {
        sqlx::query!(
            r#"
            INSERT INTO system_settings (key, value)
            VALUES ($1, $2)
            ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()
            "#,
            setting_key,
            setting_value
        )
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    }

    Ok(Json(settings))
}

#[derive(Debug, Serialize)]
pub struct SystemStats {
    pub total_repositories: i64,
    pub total_artifacts: i64,
    pub total_storage_bytes: i64,
    pub total_downloads: i64,
    pub total_users: i64,
    pub active_peers: i64,
    pub pending_sync_tasks: i64,
}

/// Get system statistics
pub async fn get_system_stats(State(state): State<SharedState>) -> Result<Json<SystemStats>> {
    let repo_count = sqlx::query_scalar!("SELECT COUNT(*) as \"count!\" FROM repositories")
        .fetch_one(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let artifact_stats = sqlx::query!(
        r#"
        SELECT
            COUNT(*) as "count!",
            COALESCE(SUM(size_bytes), 0)::BIGINT as "size!"
        FROM artifacts
        WHERE is_deleted = false
        "#
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let download_count =
        sqlx::query_scalar!("SELECT COUNT(*) as \"count!\" FROM download_statistics")
            .fetch_one(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

    let user_count = sqlx::query_scalar!("SELECT COUNT(*) as \"count!\" FROM users")
        .fetch_one(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let active_edge_count = sqlx::query_scalar!(
        "SELECT COUNT(*) as \"count!\" FROM peer_instances WHERE status = 'online'"
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let pending_sync_count = sqlx::query_scalar!(
        "SELECT COUNT(*) as \"count!\" FROM sync_tasks WHERE status = 'pending'"
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(SystemStats {
        total_repositories: repo_count,
        total_artifacts: artifact_stats.count,
        total_storage_bytes: artifact_stats.size,
        total_downloads: download_count,
        total_users: user_count,
        active_peers: active_edge_count,
        pending_sync_tasks: pending_sync_count,
    }))
}

#[derive(Debug, Deserialize)]
pub struct CleanupRequest {
    pub cleanup_audit_logs: Option<bool>,
    pub cleanup_old_backups: Option<bool>,
    pub cleanup_stale_peers: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct CleanupResponse {
    pub audit_logs_deleted: i64,
    pub backups_deleted: i64,
    pub peers_marked_offline: i64,
}

/// Run cleanup tasks
pub async fn run_cleanup(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Json(request): Json<CleanupRequest>,
) -> Result<Json<CleanupResponse>> {
    let mut result = CleanupResponse {
        audit_logs_deleted: 0,
        backups_deleted: 0,
        peers_marked_offline: 0,
    };

    // Get settings for cleanup
    let settings = get_settings(State(state.clone())).await?.0;

    if request.cleanup_audit_logs.unwrap_or(false) {
        use crate::services::audit_service::AuditService;
        let audit_service = AuditService::new(state.db.clone());
        result.audit_logs_deleted =
            audit_service.cleanup(settings.audit_retention_days).await? as i64;
    }

    if request.cleanup_old_backups.unwrap_or(false) {
        let storage = Arc::new(StorageService::from_config(&state.config).await?);
        let backup_service = BackupService::new(state.db.clone(), storage);
        result.backups_deleted = backup_service
            .cleanup(settings.backup_retention_count, settings.retention_days)
            .await? as i64;
    }

    if request.cleanup_stale_peers.unwrap_or(false) {
        use crate::services::peer_instance_service::PeerInstanceService;
        let peer_service = PeerInstanceService::new(state.db.clone());
        result.peers_marked_offline = peer_service
            .mark_stale_offline(settings.edge_stale_threshold_minutes)
            .await? as i64;
    }

    Ok(Json(result))
}

#[derive(Debug, Serialize)]
pub struct ReindexResponse {
    pub message: String,
    pub artifacts_indexed: i64,
    pub repositories_indexed: i64,
}

/// Trigger a full Meilisearch reindex of all artifacts and repositories.
///
/// Requires admin privileges and Meilisearch to be configured.
pub async fn trigger_reindex(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<ReindexResponse>> {
    if !auth.is_admin {
        return Err(AppError::Unauthorized(
            "Admin privileges required".to_string(),
        ));
    }

    let meili = state
        .meili_service
        .as_ref()
        .ok_or_else(|| AppError::Internal("Meilisearch is not configured".to_string()))?;

    // Count artifacts and repositories before reindex so we can report counts
    let artifact_stats = sqlx::query!(
        r#"
        SELECT
            COUNT(*) as "count!",
            COALESCE(SUM(size_bytes), 0)::BIGINT as "size!"
        FROM artifacts
        WHERE is_deleted = false
        "#
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let repo_count = sqlx::query_scalar!("SELECT COUNT(*) as \"count!\" FROM repositories")
        .fetch_one(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    meili.full_reindex(&state.db).await?;

    Ok(Json(ReindexResponse {
        message: "Full reindex completed successfully".to_string(),
        artifacts_indexed: artifact_stats.count,
        repositories_indexed: repo_count,
    }))
}
