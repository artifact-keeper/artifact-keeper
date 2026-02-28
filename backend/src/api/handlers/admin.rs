//! Admin handlers (backups, system settings).

use axum::{
    extract::{Extension, Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::{IntoParams, OpenApi, ToSchema};
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

#[derive(Debug, Deserialize, IntoParams, ToSchema)]
pub struct ListBackupsQuery {
    pub status: Option<String>,
    #[serde(rename = "type")]
    pub backup_type: Option<String>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateBackupRequest {
    #[serde(rename = "type")]
    pub backup_type: Option<String>,
    pub repository_ids: Option<Vec<Uuid>>,
}

#[derive(Debug, Serialize, ToSchema)]
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

#[derive(Debug, Serialize, ToSchema)]
pub struct BackupListResponse {
    pub items: Vec<BackupResponse>,
    pub total: i64,
}

pub(crate) fn parse_backup_type(s: &str) -> Option<BackupType> {
    match s.to_lowercase().as_str() {
        "full" => Some(BackupType::Full),
        "incremental" => Some(BackupType::Incremental),
        "metadata" => Some(BackupType::Metadata),
        _ => None,
    }
}

pub(crate) fn parse_backup_status(s: &str) -> Option<BackupStatus> {
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
#[utoipa::path(
    get,
    path = "/backups",
    context_path = "/api/v1/admin",
    tag = "admin",
    params(ListBackupsQuery),
    responses(
        (status = 200, description = "List of backups", body = BackupListResponse),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    get,
    path = "/backups/{id}",
    context_path = "/api/v1/admin",
    tag = "admin",
    params(
        ("id" = Uuid, Path, description = "Backup ID")
    ),
    responses(
        (status = 200, description = "Backup details", body = BackupResponse),
        (status = 404, description = "Backup not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    post,
    path = "/backups",
    context_path = "/api/v1/admin",
    tag = "admin",
    request_body = CreateBackupRequest,
    responses(
        (status = 200, description = "Backup created", body = BackupResponse),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    post,
    path = "/backups/{id}/execute",
    context_path = "/api/v1/admin",
    tag = "admin",
    params(
        ("id" = Uuid, Path, description = "Backup ID")
    ),
    responses(
        (status = 200, description = "Backup executed", body = BackupResponse),
        (status = 404, description = "Backup not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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

#[derive(Debug, Deserialize, ToSchema)]
pub struct RestoreRequest {
    pub restore_database: Option<bool>,
    pub restore_artifacts: Option<bool>,
    pub target_repository_id: Option<Uuid>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RestoreResponse {
    pub tables_restored: Vec<String>,
    pub artifacts_restored: i32,
    pub errors: Vec<String>,
}

/// Restore from backup
#[utoipa::path(
    post,
    path = "/backups/{id}/restore",
    context_path = "/api/v1/admin",
    tag = "admin",
    params(
        ("id" = Uuid, Path, description = "Backup ID")
    ),
    request_body = RestoreRequest,
    responses(
        (status = 200, description = "Backup restored", body = RestoreResponse),
        (status = 404, description = "Backup not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    post,
    path = "/backups/{id}/cancel",
    context_path = "/api/v1/admin",
    tag = "admin",
    params(
        ("id" = Uuid, Path, description = "Backup ID")
    ),
    responses(
        (status = 200, description = "Backup cancelled"),
        (status = 404, description = "Backup not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    delete,
    path = "/backups/{id}",
    context_path = "/api/v1/admin",
    tag = "admin",
    params(
        ("id" = Uuid, Path, description = "Backup ID")
    ),
    responses(
        (status = 200, description = "Backup deleted"),
        (status = 404, description = "Backup not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SystemSettings {
    pub storage_backend: String,
    pub storage_path: String,
    pub allow_anonymous_download: bool,
    pub max_upload_size_bytes: i64,
    pub retention_days: i32,
    pub audit_retention_days: i32,
    pub backup_retention_count: i32,
    pub edge_stale_threshold_minutes: i32,
}

/// Get system settings
#[utoipa::path(
    get,
    path = "/settings",
    context_path = "/api/v1/admin",
    tag = "admin",
    responses(
        (status = 200, description = "System settings", body = SystemSettings),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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
        storage_backend: state.config.storage_backend.clone(),
        storage_path: state.config.storage_path.clone(),
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
#[utoipa::path(
    post,
    path = "/settings",
    context_path = "/api/v1/admin",
    tag = "admin",
    request_body = SystemSettings,
    responses(
        (status = 200, description = "Settings updated", body = SystemSettings),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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

#[derive(Debug, Serialize, ToSchema)]
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
#[utoipa::path(
    get,
    path = "/stats",
    context_path = "/api/v1/admin",
    tag = "admin",
    responses(
        (status = 200, description = "System statistics", body = SystemStats),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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

#[derive(Debug, Deserialize, ToSchema)]
pub struct CleanupRequest {
    pub cleanup_audit_logs: Option<bool>,
    pub cleanup_old_backups: Option<bool>,
    pub cleanup_stale_peers: Option<bool>,
    pub cleanup_stale_uploads: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CleanupResponse {
    pub audit_logs_deleted: i64,
    pub backups_deleted: i64,
    pub peers_marked_offline: i64,
    pub stale_uploads_deleted: i64,
}

/// Run cleanup tasks
#[utoipa::path(
    post,
    path = "/cleanup",
    context_path = "/api/v1/admin",
    tag = "admin",
    request_body = CleanupRequest,
    responses(
        (status = 200, description = "Cleanup completed", body = CleanupResponse),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn run_cleanup(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Json(request): Json<CleanupRequest>,
) -> Result<Json<CleanupResponse>> {
    let mut result = CleanupResponse {
        audit_logs_deleted: 0,
        backups_deleted: 0,
        peers_marked_offline: 0,
        stale_uploads_deleted: 0,
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

    if request.cleanup_stale_uploads.unwrap_or(false) {
        use crate::api::handlers::incus::cleanup_stale_sessions;
        result.stale_uploads_deleted = cleanup_stale_sessions(&state.db, 24)
            .await
            .map_err(AppError::Internal)?;
    }

    Ok(Json(result))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ReindexResponse {
    pub message: String,
    pub artifacts_indexed: i64,
    pub repositories_indexed: i64,
}

/// Trigger a full Meilisearch reindex of all artifacts and repositories.
///
/// Requires admin privileges and Meilisearch to be configured.
#[utoipa::path(
    post,
    path = "/reindex",
    context_path = "/api/v1/admin",
    tag = "admin",
    responses(
        (status = 200, description = "Reindex completed", body = ReindexResponse),
        (status = 401, description = "Admin privileges required"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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

#[derive(OpenApi)]
#[openapi(
    paths(
        list_backups,
        get_backup,
        create_backup,
        execute_backup,
        restore_backup,
        cancel_backup,
        delete_backup,
        get_settings,
        update_settings,
        get_system_stats,
        run_cleanup,
        trigger_reindex,
    ),
    components(schemas(
        ListBackupsQuery,
        CreateBackupRequest,
        BackupResponse,
        BackupListResponse,
        RestoreRequest,
        RestoreResponse,
        SystemSettings,
        SystemStats,
        CleanupRequest,
        CleanupResponse,
        ReindexResponse,
    ))
)]
pub struct AdminApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // parse_backup_type
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_backup_type_full() {
        assert_eq!(parse_backup_type("full"), Some(BackupType::Full));
    }

    #[test]
    fn test_parse_backup_type_incremental() {
        assert_eq!(
            parse_backup_type("incremental"),
            Some(BackupType::Incremental)
        );
    }

    #[test]
    fn test_parse_backup_type_metadata() {
        assert_eq!(parse_backup_type("metadata"), Some(BackupType::Metadata));
    }

    #[test]
    fn test_parse_backup_type_case_insensitive() {
        assert_eq!(parse_backup_type("FULL"), Some(BackupType::Full));
        assert_eq!(parse_backup_type("Full"), Some(BackupType::Full));
        assert_eq!(
            parse_backup_type("INCREMENTAL"),
            Some(BackupType::Incremental)
        );
        assert_eq!(parse_backup_type("Metadata"), Some(BackupType::Metadata));
    }

    #[test]
    fn test_parse_backup_type_invalid() {
        assert_eq!(parse_backup_type("unknown"), None);
        assert_eq!(parse_backup_type(""), None);
        assert_eq!(parse_backup_type("partial"), None);
    }

    // -----------------------------------------------------------------------
    // parse_backup_status
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_backup_status_pending() {
        assert_eq!(parse_backup_status("pending"), Some(BackupStatus::Pending));
    }

    #[test]
    fn test_parse_backup_status_in_progress() {
        assert_eq!(
            parse_backup_status("in_progress"),
            Some(BackupStatus::InProgress)
        );
    }

    #[test]
    fn test_parse_backup_status_completed() {
        assert_eq!(
            parse_backup_status("completed"),
            Some(BackupStatus::Completed)
        );
    }

    #[test]
    fn test_parse_backup_status_failed() {
        assert_eq!(parse_backup_status("failed"), Some(BackupStatus::Failed));
    }

    #[test]
    fn test_parse_backup_status_cancelled() {
        assert_eq!(
            parse_backup_status("cancelled"),
            Some(BackupStatus::Cancelled)
        );
    }

    #[test]
    fn test_parse_backup_status_case_insensitive() {
        assert_eq!(
            parse_backup_status("COMPLETED"),
            Some(BackupStatus::Completed)
        );
        assert_eq!(parse_backup_status("Failed"), Some(BackupStatus::Failed));
        assert_eq!(
            parse_backup_status("IN_PROGRESS"),
            Some(BackupStatus::InProgress)
        );
    }

    #[test]
    fn test_parse_backup_status_invalid() {
        assert_eq!(parse_backup_status("unknown"), None);
        assert_eq!(parse_backup_status(""), None);
        assert_eq!(parse_backup_status("running"), None);
    }

    // -----------------------------------------------------------------------
    // SystemSettings defaults
    // -----------------------------------------------------------------------

    #[test]
    fn test_system_settings_defaults() {
        let settings = SystemSettings {
            storage_backend: "filesystem".to_string(),
            storage_path: "/data/artifacts".to_string(),
            allow_anonymous_download: false,
            max_upload_size_bytes: 100 * 1024 * 1024,
            retention_days: 365,
            audit_retention_days: 90,
            backup_retention_count: 10,
            edge_stale_threshold_minutes: 5,
        };
        assert!(!settings.allow_anonymous_download);
        assert_eq!(settings.max_upload_size_bytes, 104_857_600);
        assert_eq!(settings.retention_days, 365);
        assert_eq!(settings.audit_retention_days, 90);
        assert_eq!(settings.backup_retention_count, 10);
        assert_eq!(settings.edge_stale_threshold_minutes, 5);
        assert_eq!(settings.storage_backend, "filesystem");
    }

    #[test]
    fn test_system_settings_serialization_roundtrip() {
        let settings = SystemSettings {
            storage_backend: "s3".to_string(),
            storage_path: "/data/artifacts".to_string(),
            allow_anonymous_download: true,
            max_upload_size_bytes: 500_000_000,
            retention_days: 30,
            audit_retention_days: 7,
            backup_retention_count: 5,
            edge_stale_threshold_minutes: 10,
        };
        let json = serde_json::to_string(&settings).unwrap();
        let parsed: SystemSettings = serde_json::from_str(&json).unwrap();
        assert!(parsed.allow_anonymous_download);
        assert_eq!(parsed.max_upload_size_bytes, 500_000_000);
        assert_eq!(parsed.retention_days, 30);
        assert_eq!(parsed.audit_retention_days, 7);
        assert_eq!(parsed.backup_retention_count, 5);
        assert_eq!(parsed.edge_stale_threshold_minutes, 10);
    }

    // -----------------------------------------------------------------------
    // BackupResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_backup_response_serialization() {
        let resp = BackupResponse {
            id: Uuid::nil(),
            backup_type: "full".to_string(),
            status: "completed".to_string(),
            storage_path: Some("backups/2024/01/01/test.tar.gz".to_string()),
            size_bytes: 1024,
            artifact_count: 42,
            started_at: None,
            completed_at: None,
            error_message: None,
            created_by: None,
            created_at: chrono::Utc::now(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["type"], "full");
        assert_eq!(json["status"], "completed");
        assert_eq!(json["size_bytes"], 1024);
        assert_eq!(json["artifact_count"], 42);
    }

    // -----------------------------------------------------------------------
    // SystemStats serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_system_stats_serialization() {
        let stats = SystemStats {
            total_repositories: 10,
            total_artifacts: 500,
            total_storage_bytes: 1_000_000_000,
            total_downloads: 5000,
            total_users: 25,
            active_peers: 3,
            pending_sync_tasks: 0,
        };
        let json = serde_json::to_value(&stats).unwrap();
        assert_eq!(json["total_repositories"], 10);
        assert_eq!(json["total_artifacts"], 500);
        assert_eq!(json["total_storage_bytes"], 1_000_000_000i64);
        assert_eq!(json["total_downloads"], 5000);
        assert_eq!(json["total_users"], 25);
    }

    // -----------------------------------------------------------------------
    // CleanupResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_cleanup_response_serialization() {
        let resp = CleanupResponse {
            audit_logs_deleted: 100,
            backups_deleted: 2,
            peers_marked_offline: 1,
            stale_uploads_deleted: 3,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["audit_logs_deleted"], 100);
        assert_eq!(json["backups_deleted"], 2);
        assert_eq!(json["peers_marked_offline"], 1);
        assert_eq!(json["stale_uploads_deleted"], 3);
    }

    // -----------------------------------------------------------------------
    // ReindexResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_reindex_response_serialization() {
        let resp = ReindexResponse {
            message: "Full reindex completed successfully".to_string(),
            artifacts_indexed: 500,
            repositories_indexed: 10,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["artifacts_indexed"], 500);
        assert_eq!(json["repositories_indexed"], 10);
        assert!(json["message"].as_str().unwrap().contains("reindex"));
    }

    // -----------------------------------------------------------------------
    // RestoreResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_restore_response_serialization() {
        let resp = RestoreResponse {
            tables_restored: vec!["users".to_string(), "artifacts".to_string()],
            artifacts_restored: 42,
            errors: vec![],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["tables_restored"].as_array().unwrap().len(), 2);
        assert_eq!(json["artifacts_restored"], 42);
        assert!(json["errors"].as_array().unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // Request deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_backup_request_deserialization() {
        let json = r#"{"type": "full"}"#;
        let req: CreateBackupRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.backup_type, Some("full".to_string()));
        assert!(req.repository_ids.is_none());
    }

    #[test]
    fn test_create_backup_request_with_repository_ids() {
        let id = Uuid::new_v4();
        let json = serde_json::json!({"type": "incremental", "repository_ids": [id]});
        let req: CreateBackupRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.backup_type, Some("incremental".to_string()));
        assert_eq!(req.repository_ids.unwrap().len(), 1);
    }

    #[test]
    fn test_cleanup_request_deserialization() {
        let json = r#"{"cleanup_audit_logs": true, "cleanup_old_backups": false}"#;
        let req: CleanupRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.cleanup_audit_logs, Some(true));
        assert_eq!(req.cleanup_old_backups, Some(false));
        assert!(req.cleanup_stale_peers.is_none());
    }

    #[test]
    fn test_restore_request_deserialization() {
        let json = r#"{"restore_database": true}"#;
        let req: RestoreRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.restore_database, Some(true));
        assert!(req.restore_artifacts.is_none());
        assert!(req.target_repository_id.is_none());
    }

    // -----------------------------------------------------------------------
    // settings row parsing logic
    // -----------------------------------------------------------------------

    #[test]
    fn test_settings_row_parsing_bool_value() {
        let val = serde_json::json!(true);
        assert!(val.as_bool().unwrap_or(false));
    }

    #[test]
    fn test_settings_row_parsing_int_value() {
        let val = serde_json::json!(42);
        assert_eq!(val.as_i64().unwrap_or(0), 42);
    }

    #[test]
    fn test_settings_row_parsing_fallback_on_wrong_type() {
        let val = serde_json::json!("not a number");
        assert_eq!(val.as_i64().unwrap_or(100), 100);
    }
}
