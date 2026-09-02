//! Admin handlers (backups, system settings).

use crate::services::audit_service::{
    audit_fire_and_forget, AuditAction, AuditEntry, ResourceType,
};
use crate::services::totp_policy::{self, check_policy_activation, TotpPolicy, TotpPolicySource};
use axum::{
    extract::{Extension, Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, OnceLock};
use tokio::sync::Semaphore;
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
        .route(
            "/settings/totp-policy",
            get(get_totp_policy).put(update_totp_policy),
        )
        .route("/stats", get(get_system_stats))
        .route("/downloads", get(list_downloads))
        .route("/downloads/by-ip/:ip", get(list_downloads_by_ip))
        .route("/downloads/by-user/:user_id", get(list_downloads_by_user))
        .route("/cleanup", post(run_cleanup))
        .route("/reindex", post(trigger_reindex))
        .route("/rescan-for-inventory", post(rescan_for_inventory))
        .route("/storage-backends", get(list_storage_backends))
        .route("/audit", get(list_audit_logs))
        .route(
            "/proxy-scan-verdicts/:digest",
            get(get_proxy_scan_verdicts).delete(delete_proxy_scan_verdicts),
        )
}

// ---------------------------------------------------------------------------
// Audit log query endpoint (#2366 functional audit log)
// ---------------------------------------------------------------------------

/// Default page size for the audit-log query when the caller does not specify.
const AUDIT_DEFAULT_PER_PAGE: u32 = 50;
/// Hard cap on page size so a single query cannot pull an unbounded slice.
const AUDIT_MAX_PER_PAGE: u32 = 200;

/// Normalize/clamp audit-query pagination into a `(offset, limit, page,
/// per_page)` tuple.
///
/// Pure (no I/O) so the coverage gate exercises the pagination arithmetic even
/// where Postgres is unavailable. `page` is 1-based and floored at 1;
/// `per_page` defaults to [`AUDIT_DEFAULT_PER_PAGE`] and is clamped to
/// `1..=AUDIT_MAX_PER_PAGE`.
pub(crate) fn audit_page_bounds(page: Option<u32>, per_page: Option<u32>) -> (i64, i64, u32, u32) {
    let page = page.unwrap_or(1).max(1);
    let per_page = per_page
        .unwrap_or(AUDIT_DEFAULT_PER_PAGE)
        .clamp(1, AUDIT_MAX_PER_PAGE);
    let offset = i64::from(page - 1) * i64::from(per_page);
    (offset, i64::from(per_page), page, per_page)
}

/// Filters for `GET /api/v1/admin/audit`.
#[derive(Debug, Deserialize, IntoParams)]
pub struct AuditLogQuery {
    /// Filter by acting/subject user id.
    pub user_id: Option<Uuid>,
    /// Filter by action string (e.g. `LOGIN`, `USER_CREATED`, `ARTIFACT_DOWNLOADED`).
    pub action: Option<String>,
    /// Filter by resource type (e.g. `user`, `repository`, `artifact`).
    pub resource_type: Option<String>,
    /// Filter by the affected resource id.
    pub resource_id: Option<Uuid>,
    /// Filter by exact correlation ID (#2414) — the request's
    /// `X-Correlation-ID` / trace ID as stored on each audit event.
    pub correlation_id: Option<String>,
    /// Inclusive lower time bound (RFC 3339).
    pub from: Option<chrono::DateTime<chrono::Utc>>,
    /// Inclusive upper time bound (RFC 3339).
    pub to: Option<chrono::DateTime<chrono::Utc>>,
    /// 1-based page index (default 1).
    pub page: Option<u32>,
    /// Page size (default 50, max 200).
    pub per_page: Option<u32>,
}

/// A single audit-log row in a query response.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuditLogItem {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    /// Username of the acting user, embedded server-side (#2392). `null` for
    /// system/non-user actors and for actors that have since been deleted.
    pub actor_username: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<Uuid>,
    pub details: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    /// Request correlation ID (#2414): a string — caller-supplied values and
    /// W3C trace IDs are not UUIDs.
    pub correlation_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<crate::services::audit_service::AuditLogEntryWithActor> for AuditLogItem {
    fn from(e: crate::services::audit_service::AuditLogEntryWithActor) -> Self {
        Self {
            id: e.id,
            user_id: e.user_id,
            actor_username: e.actor_username,
            action: e.action,
            resource_type: e.resource_type,
            resource_id: e.resource_id,
            details: e.details,
            ip_address: e.ip_address,
            correlation_id: e.correlation_id,
            created_at: e.created_at,
        }
    }
}

/// Paginated audit-log query response.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuditLogListResponse {
    pub items: Vec<AuditLogItem>,
    pub total: i64,
    pub page: u32,
    pub per_page: u32,
}

/// Query the audit log (admin only).
///
/// Returns recorded audit events ordered newest-first, filtered by any
/// combination of actor/user, action, resource type/id, and time range, with
/// page/per_page pagination. Backed by the `audit_log` table and
/// [`AuditService::query`]; admin-only both via the `/admin` `admin_middleware`
/// and a defense-in-depth check here (#2366).
#[utoipa::path(
    get,
    path = "/audit",
    context_path = "/api/v1/admin",
    tag = "admin",
    params(AuditLogQuery),
    responses(
        (status = 200, description = "Audit events", body = AuditLogListResponse),
        (status = 403, description = "Admin privileges required"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_audit_logs(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Query(query): Query<AuditLogQuery>,
) -> Result<Json<AuditLogListResponse>> {
    // Defense-in-depth: the `/admin` nest already enforces `admin_middleware`,
    // but never rely on a single gate for a security-sensitive read.
    if !auth.is_admin {
        return Err(AppError::Authorization(
            "Admin privileges required".to_string(),
        ));
    }

    let (offset, limit, page, per_page) = audit_page_bounds(query.page, query.per_page);

    let audit_service = crate::services::audit_service::AuditService::new(state.db.clone());
    let (entries, total) = audit_service
        .query(
            query.user_id,
            query.action.as_deref(),
            query.resource_type.as_deref(),
            query.resource_id,
            query.correlation_id.as_deref(),
            query.from,
            query.to,
            offset,
            limit,
        )
        .await?;

    Ok(Json(AuditLogListResponse {
        items: entries.into_iter().map(AuditLogItem::from).collect(),
        total,
        page,
        per_page,
    }))
}

/// List available storage backends.
///
/// Returns the names of all configured and available storage backends.
/// Requires admin privileges.
#[utoipa::path(
    get,
    path = "/storage-backends",
    context_path = "/api/v1/admin",
    tag = "admin",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Available storage backends", body = Vec<String>),
        (status = 403, description = "Admin privileges required"),
    )
)]
pub async fn list_storage_backends(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<Vec<String>>> {
    if !auth.is_admin {
        return Err(AppError::Authorization(
            "Admin privileges required".to_string(),
        ));
    }
    let mut backends = vec!["filesystem".to_string()];
    for name in ["s3", "azure", "gcs"] {
        if state.storage_registry.is_available(name) {
            backends.push(name.to_string());
        }
    }
    Ok(Json(backends))
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
    /// Explicit allow-list of repository ids to include in the backup.
    ///
    /// When omitted every repository is backed up (subject to
    /// `exclude_repositories`).
    pub repository_ids: Option<Vec<Uuid>>,
    /// Repository ids to exclude from a full or incremental backup (#2772).
    ///
    /// Airgapped or bandwidth-limited deployments use this to keep specific
    /// repositories out of the backup. When omitted or empty nothing is
    /// excluded, so existing behavior is unchanged. If `repository_ids` is
    /// also supplied the excluded ids are removed from that include list;
    /// otherwise every repository except the excluded ones is backed up.
    pub exclude_repositories: Option<Vec<Uuid>>,
    /// Optional RFC3339 lower bound on artifact modification time (#2789).
    ///
    /// When set, the (typically incremental) backup includes only artifacts
    /// whose `updated_at` is at or after this timestamp, capturing just the
    /// changes made from the given date/time to now. When omitted every
    /// artifact is included, so backup behavior is unchanged.
    pub since: Option<chrono::DateTime<chrono::Utc>>,
    /// Optional custom name/label for the backup archive (#2790).
    ///
    /// When provided it becomes the identifying part of the archive
    /// filename. Restricted to letters, digits, `.`, `_`, and `-`; when
    /// omitted the archive keeps its default `{uuid}` name.
    pub name: Option<String>,
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
            exclude_repository_ids: payload.exclude_repositories,
            since: payload.since,
            created_by: Some(auth.user_id),
            name: payload.name,
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
///
/// Answers with the backup resource as persisted after the run. A run that
/// FAILED is reported as `status = "failed"` with `error_message` naming the
/// cause — it is not a transport-level error, because the request was
/// understood and carried out and the outcome belongs to the backup (#3327).
/// Clients must read `status`, not just the HTTP code. `500` is reserved for
/// the cases where no run outcome exists to report at all.
#[utoipa::path(
    post,
    path = "/backups/{id}/execute",
    context_path = "/api/v1/admin",
    tag = "admin",
    params(
        ("id" = Uuid, Path, description = "Backup ID")
    ),
    responses(
        (status = 200, description = "Backup run finished; `status` is `completed` or `failed` and `error_message` carries the cause of a failure", body = BackupResponse),
        (status = 404, description = "Backup not found"),
        (status = 409, description = "Another backup is already in progress"),
        (status = 500, description = "The run could not be started or its outcome could not be recorded")
    ),
    security(("bearer_auth" = []))
)]
pub async fn execute_backup(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<BackupResponse>> {
    // Two distinct handles, deliberately (#3171):
    //  * `archive_root` is the prefix-less handle backup ARCHIVES have always
    //    been written to/read from; it must stay prefix-less or existing
    //    archives become unreachable.
    //  * `source` reads ARTIFACT BYTES and must carry the configured
    //    `S3_PREFIX`, because that is where primary storage wrote them.
    let archive_root = Arc::new(StorageService::from_config(&state.config).await?);
    let archive_storage =
        StorageService::backup_archive_from_config(&state.config, &archive_root).await?;
    let source = Arc::new(StorageService::artifact_source_from_config(&state.config).await?);
    let service = BackupService::with_archive_storage(state.db.clone(), source, archive_storage);

    // `execute_run`, not `execute`: a run that ends FAILED has already recorded
    // its own terminal state and the message naming what went wrong, and that
    // is what the caller is answered with. Collapsing it into an `Err` here
    // produced a bare `500 {"code":"INTERNAL_ERROR"}` whose body threw away the
    // very message the failure exists to deliver (#3327).
    let run = service.execute_run(id).await?;
    if let Some(ref message) = run.failure {
        tracing::warn!(
            backup_id = %id,
            "backup run finished in state failed: {}",
            message
        );
    }
    let backup = run.backup;

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
    /// Accept an archive whose integrity cannot be established (#3373).
    ///
    /// A restore refuses an archive it cannot check: since #3373 every backup
    /// records its payload checksum on the `backups` row, outside the archive,
    /// and the archive's contents are verified against it before any row is
    /// ingested. Archives captured before that column existed fall back to the
    /// checksum in their own manifest; one carrying neither cannot be verified
    /// at all, and this flag is the deliberate, audited way to restore it
    /// anyway. It never waives a checksum that is present and does not match.
    #[serde(default)]
    pub allow_unverified_archive: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RestoreResponse {
    pub tables_restored: Vec<String>,
    pub artifacts_restored: i32,
    pub errors: Vec<String>,
    /// What the archive's contents were checked against (#3373):
    /// `recorded` (the digest on the `backups` row, the strong case),
    /// `manifest` (the archive's own checksum -- detects corruption, not
    /// tampering), or `waived` (`allow_unverified_archive` was set).
    pub integrity_anchor: String,
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
        (status = 400, description = "Archive integrity could not be established, or an \
                                      unsupported option was supplied"),
        (status = 404, description = "Backup not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn restore_backup(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(payload): Json<RestoreRequest>,
) -> Result<Json<RestoreResponse>> {
    // As in `execute_backup`: archives keep the prefix-less handle, artifact
    // bytes are restored through the prefixed artifact-source handle so they
    // land at the keys the rest of the system reads them from (#3171).
    let archive_root = Arc::new(
        StorageService::from_config(&state.config)
            .await
            .map_err(|e: AppError| e)?,
    );
    let archive_storage =
        StorageService::backup_archive_from_config(&state.config, &archive_root).await?;
    let source = Arc::new(StorageService::artifact_source_from_config(&state.config).await?);
    let service = BackupService::with_archive_storage(state.db.clone(), source, archive_storage);

    let options = RestoreOptions {
        restore_database: payload.restore_database.unwrap_or(true),
        restore_artifacts: payload.restore_artifacts.unwrap_or(true),
        target_repository_id: payload.target_repository_id,
        allow_unverified_archive: payload.allow_unverified_archive,
        actor: Some(auth.user_id),
    };

    let result = service.restore(id, options).await?;

    Ok(Json(RestoreResponse {
        tables_restored: result.tables_restored,
        artifacts_restored: result.artifacts_restored,
        errors: result.errors,
        integrity_anchor: result.integrity_anchor.to_string(),
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
        (status = 409, description = "Backup is not in a cancellable state"),
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
    let archive_storage =
        StorageService::backup_archive_from_config(&state.config, &storage).await?;
    let service = BackupService::with_archive_storage(state.db.clone(), storage, archive_storage);

    service.delete(id).await?;
    Ok(())
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SystemSettings {
    pub storage_backend: String,
    pub storage_path: String,
    /// Read-only deployment environment name, sourced from the `ENVIRONMENT`
    /// config value. Defaulted on deserialization so it is not required in the
    /// update-settings request body.
    #[serde(default)]
    pub environment: String,
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
        environment: state.config.environment.clone(),
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

// ---------------------------------------------------------------------------
// TOTP (2FA) enforcement policy (#2805)
// ---------------------------------------------------------------------------

/// Current 2FA enforcement policy plus the context an operator needs before
/// tightening it.
#[derive(Debug, Serialize, ToSchema)]
pub struct TotpPolicyResponse {
    /// The policy in force.
    pub policy: TotpPolicy,
    /// Whether it comes from the `TOTP_POLICY` environment variable (in which
    /// case `PUT` is refused) or from the database.
    pub source: TotpPolicySource,
    /// Whether `PUT` can change the policy at all right now.
    pub editable: bool,
    /// Local (password-authenticating, non-service) administrators.
    pub local_admins: i64,
    /// How many of those already have TOTP enabled. Under
    /// `required_for_admins`, `local_admins - local_admins_with_totp` is the
    /// number of administrators who will be sent through forced enrollment at
    /// their next sign-in.
    pub local_admins_with_totp: i64,
    /// Local (password-authenticating, non-service) users, admins included.
    pub local_users: i64,
    /// How many of those already have TOTP enabled.
    pub local_users_with_totp: i64,
    /// Whether the *calling* administrator has TOTP enabled. Tightening the
    /// policy requires this.
    pub caller_totp_enabled: bool,
}

/// Request body for `PUT /admin/settings/totp-policy`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateTotpPolicyRequest {
    pub policy: TotpPolicy,
}

/// Counts of local (password) accounts and how many have TOTP enrolled.
struct LocalTotpCounts {
    admins: i64,
    admins_with_totp: i64,
    users: i64,
    users_with_totp: i64,
}

/// Population the policy can actually apply to: active, local-provider,
/// non-service accounts. SSO/LDAP/CI users and service accounts are exempt, so
/// counting them here would overstate the blast radius of a policy change.
async fn local_totp_counts(db: &sqlx::PgPool) -> Result<LocalTotpCounts> {
    let row = sqlx::query!(
        r#"
        SELECT
            COUNT(*) FILTER (WHERE is_admin)                     as "admins!",
            COUNT(*) FILTER (WHERE is_admin AND totp_enabled)    as "admins_with_totp!",
            COUNT(*)                                             as "users!",
            COUNT(*) FILTER (WHERE totp_enabled)                 as "users_with_totp!"
        FROM users
        WHERE is_active = true
          AND is_service_account = false
          AND auth_provider = 'local'
        "#
    )
    .fetch_one(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(LocalTotpCounts {
        admins: row.admins,
        admins_with_totp: row.admins_with_totp,
        users: row.users,
        users_with_totp: row.users_with_totp,
    })
}

async fn build_totp_policy_response(
    state: &SharedState,
    caller_id: Uuid,
) -> Result<TotpPolicyResponse> {
    let (policy, source) = totp_policy::effective_policy(&state.db, state.config.totp_policy).await;
    let counts = local_totp_counts(&state.db).await?;
    let caller_totp_enabled =
        sqlx::query_scalar!("SELECT totp_enabled FROM users WHERE id = $1", caller_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
            .unwrap_or(false);

    Ok(TotpPolicyResponse {
        policy,
        source,
        editable: source == TotpPolicySource::Database,
        local_admins: counts.admins,
        local_admins_with_totp: counts.admins_with_totp,
        local_users: counts.users,
        local_users_with_totp: counts.users_with_totp,
        caller_totp_enabled,
    })
}

/// Read the system-wide 2FA enforcement policy.
#[utoipa::path(
    get,
    path = "/settings/totp-policy",
    context_path = "/api/v1/admin",
    tag = "admin",
    responses(
        (status = 200, description = "Current 2FA enforcement policy", body = TotpPolicyResponse),
        (status = 403, description = "Admin privileges required", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_totp_policy(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<TotpPolicyResponse>> {
    Ok(Json(
        build_totp_policy_response(&state, auth.user_id).await?,
    ))
}

/// Change the system-wide 2FA enforcement policy.
///
/// Tightening the policy requires the calling administrator to have TOTP
/// enabled — that is the lockout-safety guard: it guarantees at least one
/// administrator whose (pre-existing, already-working) sign-in path survives the
/// change. Loosening is never refused. A policy change does **not** invalidate
/// existing sessions or refresh tokens; it takes effect at the next interactive
/// password login, so the administrator making the change keeps their session.
#[utoipa::path(
    put,
    path = "/settings/totp-policy",
    context_path = "/api/v1/admin",
    tag = "admin",
    request_body = UpdateTotpPolicyRequest,
    responses(
        (status = 200, description = "Policy updated", body = TotpPolicyResponse),
        (status = 403, description = "Admin privileges required", body = crate::api::openapi::ErrorResponse),
        (status = 409, description = "Refused: policy pinned by TOTP_POLICY, or the calling admin has not enrolled in TOTP", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_totp_policy(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(payload): Json<UpdateTotpPolicyRequest>,
) -> Result<Json<TotpPolicyResponse>> {
    let current = build_totp_policy_response(&state, auth.user_id).await?;

    if let Err(refusal) = check_policy_activation(
        current.policy,
        payload.policy,
        current.source == TotpPolicySource::Environment,
        current.caller_totp_enabled,
    ) {
        return Err(AppError::Conflict(refusal.message().to_string()));
    }

    totp_policy::store_policy(&state.db, payload.policy, auth.user_id).await?;

    audit_fire_and_forget(
        state.db.clone(),
        AuditEntry::new(AuditAction::TotpPolicyChanged, ResourceType::User)
            .user(auth.user_id)
            .resource(auth.user_id)
            .actor_name(&auth.username)
            .details(serde_json::json!({
                "from": current.policy.as_str(),
                "to": payload.policy.as_str(),
                "local_admins": current.local_admins,
                "local_admins_with_totp": current.local_admins_with_totp,
            })),
    )
    .await;

    Ok(Json(
        build_totp_policy_response(&state, auth.user_id).await?,
    ))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SystemStats {
    pub total_repositories: i64,
    /// Rows in `artifacts` (for OCI repositories that is manifests only —
    /// layer/config blobs are content-addressed objects, not artifacts).
    /// Unlike the byte total, this count still includes legacy backfilled
    /// `proxy-cache/%` rows.
    pub total_artifacts: i64,
    /// All stored bytes, summed from `repository_usage_ledger`
    /// (`hosted_bytes + proxy_bytes + oci_bytes`) — the same source the
    /// per-repository `storage_used_bytes` figures are read from, so the
    /// dashboard total is consistent with the per-repo column by
    /// construction (#3134). Includes OCI layer/config blob bytes
    /// (`oci_blobs`) and proxy-cached bytes; `proxy_storage_bytes` below is
    /// a *breakdown* of this total, not a disjoint bucket.
    pub total_storage_bytes: i64,
    pub total_downloads: i64,
    pub total_users: i64,
    pub active_peers: i64,
    pub pending_sync_tasks: i64,
    /// Proxy-cached (pull-through) objects, tracked in `proxy_cache_artifacts`
    /// rather than `artifacts`. Since #3134 the byte figure is a breakdown of
    /// `total_storage_bytes` (do not add the two).
    pub proxy_artifact_count: i64,
    pub proxy_storage_bytes: i64,
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

    let artifact_count = sqlx::query_scalar!(
        r#"SELECT COUNT(*) as "count!" FROM artifacts WHERE is_deleted = false"#
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // #3134: byte totals come from the usage ledger, not a raw `artifacts`
    // aggregate. The `artifacts` table holds no OCI layer/config blobs (only
    // manifests land there — blobs live in `oci_blobs`), so summing it
    // under-reported a docker repository by orders of magnitude. The ledger's
    // per-repository components are maintained by the migration-182 triggers
    // and trued up by `reconcile_all_usage_ledgers` from the authoritative
    // 3-way source sums (`artifacts` excluding legacy `proxy-cache/%` keys +
    // `proxy_cache_artifacts` + `oci_blobs`), and are exactly what the
    // per-repository `storage_used_bytes` column and quota admission already
    // read — one accounting implementation, so the dashboard total equals the
    // sum of the per-repo figures by construction. This is the logical
    // (per-repository) figure: a blob cross-repo-mounted into N repositories
    // counts once per repository, matching quota; physical dedup on shared
    // backends is the storage-GC footprint report's concern. Virtual
    // repositories own no rows in the source tables, so nothing is
    // double-counted (#2785). Also the O(repositories) shape #3094 asks for.
    let storage_totals = sqlx::query!(
        r#"
        SELECT
            COALESCE(SUM(hosted_bytes + proxy_bytes + oci_bytes), 0)::BIGINT as "total!",
            COALESCE(SUM(proxy_bytes), 0)::BIGINT as "proxy!"
        FROM repository_usage_ledger
        "#
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let proxy_count =
        sqlx::query_scalar!(r#"SELECT COUNT(*) as "count!" FROM proxy_cache_artifacts"#)
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
        total_artifacts: artifact_count,
        total_storage_bytes: storage_totals.total,
        total_downloads: download_count,
        total_users: user_count,
        active_peers: active_edge_count,
        pending_sync_tasks: pending_sync_count,
        proxy_artifact_count: proxy_count,
        proxy_storage_bytes: storage_totals.proxy,
    }))
}

/// Query parameters for the download-telemetry listing (#2365).
#[derive(Debug, Default, Deserialize, ToSchema, IntoParams)]
pub struct ListDownloadsQuery {
    /// Filter to downloads of one artifact.
    pub artifact_id: Option<Uuid>,
    /// Filter to downloads by one user.
    pub user_id: Option<Uuid>,
    /// Filter to downloads from one client IP (exact match).
    pub ip: Option<String>,
    /// Inclusive lower bound on `downloaded_at` (RFC 3339).
    pub from: Option<String>,
    /// Inclusive upper bound on `downloaded_at` (RFC 3339).
    pub to: Option<String>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

/// One attributed download event.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct DownloadRecord {
    pub artifact_id: Uuid,
    pub user_id: Option<Uuid>,
    /// Username of the downloader, when the download was authenticated and
    /// the user still exists.
    pub username: Option<String>,
    /// Resolved client IP; NULL for legacy rows and unresolvable clients.
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub downloaded_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DownloadListResponse {
    pub downloads: Vec<DownloadRecord>,
    pub total: i64,
    pub page: u32,
    pub per_page: u32,
}

/// Parse an optional RFC 3339 query timestamp, rejecting malformed input.
/// Shared with the blast-radius endpoints (`admin_security`, #2364).
pub(crate) fn parse_rfc3339_bound(
    value: Option<&str>,
    name: &str,
) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
    value
        .map(|s| {
            chrono::DateTime::parse_from_rfc3339(s)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .map_err(|e| AppError::Validation(format!("invalid `{name}` timestamp: {e}")))
        })
        .transpose()
}

/// Append the shared WHERE clauses for the download-telemetry queries.
fn push_download_filters(
    builder: &mut sqlx::QueryBuilder<sqlx::Postgres>,
    query: &ListDownloadsQuery,
    from: Option<chrono::DateTime<chrono::Utc>>,
    to: Option<chrono::DateTime<chrono::Utc>>,
) {
    builder.push(" WHERE TRUE");
    if let Some(artifact_id) = query.artifact_id {
        builder.push(" AND d.artifact_id = ").push_bind(artifact_id);
    }
    if let Some(user_id) = query.user_id {
        builder.push(" AND d.user_id = ").push_bind(user_id);
    }
    if let Some(ip) = &query.ip {
        builder.push(" AND d.ip_address = ").push_bind(ip);
    }
    if let Some(from) = from {
        builder.push(" AND d.downloaded_at >= ").push_bind(from);
    }
    if let Some(to) = to {
        builder.push(" AND d.downloaded_at <= ").push_bind(to);
    }
}

/// Shared listing core for the three download-telemetry endpoints.
async fn query_downloads(
    db: &sqlx::PgPool,
    query: &ListDownloadsQuery,
) -> Result<DownloadListResponse> {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).clamp(1, 100);
    let offset = ((page - 1) * per_page) as i64;
    let from = parse_rfc3339_bound(query.from.as_deref(), "from")?;
    let to = parse_rfc3339_bound(query.to.as_deref(), "to")?;

    let mut count_builder = sqlx::QueryBuilder::new("SELECT COUNT(*) FROM download_statistics d");
    push_download_filters(&mut count_builder, query, from, to);
    let total: i64 = count_builder
        .build_query_scalar()
        .fetch_one(db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let mut builder = sqlx::QueryBuilder::new(
        "SELECT d.artifact_id, d.user_id, u.username, d.ip_address, d.user_agent, \
         d.downloaded_at \
         FROM download_statistics d LEFT JOIN users u ON u.id = d.user_id",
    );
    push_download_filters(&mut builder, query, from, to);
    builder
        .push(" ORDER BY d.downloaded_at DESC LIMIT ")
        .push_bind(per_page as i64)
        .push(" OFFSET ")
        .push_bind(offset);
    let downloads: Vec<DownloadRecord> = builder
        .build_query_as()
        .fetch_all(db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(DownloadListResponse {
        downloads,
        total,
        page,
        per_page,
    })
}

/// List attributed downloads (client IP + user), filterable by artifact,
/// user, IP, and time range (#2365). Admin-only: download attribution is
/// sensitive.
#[utoipa::path(
    get,
    path = "/downloads",
    context_path = "/api/v1/admin",
    tag = "admin",
    params(ListDownloadsQuery),
    responses(
        (status = 200, description = "Attributed download events", body = DownloadListResponse),
        (status = 400, description = "Invalid filter parameter"),
        (status = 403, description = "Admin privileges required")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_downloads(
    State(state): State<SharedState>,
    Query(query): Query<ListDownloadsQuery>,
) -> Result<Json<DownloadListResponse>> {
    Ok(Json(query_downloads(&state.db, &query).await?))
}

/// Downloads originating from one client IP: "what did this network
/// location pull?" (#2365).
#[utoipa::path(
    get,
    path = "/downloads/by-ip/{ip}",
    context_path = "/api/v1/admin",
    tag = "admin",
    // NOTE: enumerate the query filters instead of `params(ListDownloadsQuery)`
    // so the `ip` filter is not emitted a second time alongside the `{ip}` path
    // parameter. A duplicate parameter name (path + query) is valid OpenAPI but
    // makes the openapi-generator Rust client generate the path parameter as
    // `Option<&str>`, which fails to compile. The path IP overrides the filter
    // anyway (see handler body), so dropping the redundant `ip` query is a no-op
    // for callers.
    params(
        ("ip" = String, Path, description = "Client IP address"),
        ("artifact_id" = Option<Uuid>, Query, description = "Filter to downloads of one artifact"),
        ("user_id" = Option<Uuid>, Query, description = "Filter to downloads by one user"),
        ("from" = Option<String>, Query, description = "Inclusive lower bound on downloaded_at (RFC 3339)"),
        ("to" = Option<String>, Query, description = "Inclusive upper bound on downloaded_at (RFC 3339)"),
        ("page" = Option<u32>, Query),
        ("per_page" = Option<u32>, Query),
    ),
    responses(
        (status = 200, description = "Downloads from the IP", body = DownloadListResponse),
        (status = 400, description = "Invalid IP address"),
        (status = 403, description = "Admin privileges required")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_downloads_by_ip(
    State(state): State<SharedState>,
    Path(ip): Path<String>,
    Query(query): Query<ListDownloadsQuery>,
) -> Result<Json<DownloadListResponse>> {
    let ip: std::net::IpAddr = ip
        .parse()
        .map_err(|_| AppError::Validation("invalid IP address".to_string()))?;
    let query = ListDownloadsQuery {
        ip: Some(ip.to_string()),
        ..query
    };
    Ok(Json(query_downloads(&state.db, &query).await?))
}

/// Downloads performed by one user: "what did this user pull?" (#2365).
#[utoipa::path(
    get,
    path = "/downloads/by-user/{user_id}",
    context_path = "/api/v1/admin",
    tag = "admin",
    // See list_downloads_by_ip: enumerate the query filters so the `user_id`
    // filter is not emitted alongside the `{user_id}` path parameter (a
    // duplicate name breaks the openapi-generator Rust client). The path
    // user_id overrides the filter anyway.
    params(
        ("user_id" = Uuid, Path, description = "User id"),
        ("artifact_id" = Option<Uuid>, Query, description = "Filter to downloads of one artifact"),
        ("ip" = Option<String>, Query, description = "Filter to downloads from one client IP (exact match)"),
        ("from" = Option<String>, Query, description = "Inclusive lower bound on downloaded_at (RFC 3339)"),
        ("to" = Option<String>, Query, description = "Inclusive upper bound on downloaded_at (RFC 3339)"),
        ("page" = Option<u32>, Query),
        ("per_page" = Option<u32>, Query),
    ),
    responses(
        (status = 200, description = "Downloads by the user", body = DownloadListResponse),
        (status = 403, description = "Admin privileges required")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_downloads_by_user(
    State(state): State<SharedState>,
    Path(user_id): Path<Uuid>,
    Query(query): Query<ListDownloadsQuery>,
) -> Result<Json<DownloadListResponse>> {
    let query = ListDownloadsQuery {
        user_id: Some(user_id),
        ..query
    };
    Ok(Json(query_downloads(&state.db, &query).await?))
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
        let archive_storage =
            StorageService::backup_archive_from_config(&state.config, &storage).await?;
        let backup_service =
            BackupService::with_archive_storage(state.db.clone(), storage, archive_storage);
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
        use crate::api::handlers::incus::{cleanup_stale_sessions, sweep_orphan_staging_files};
        result.stale_uploads_deleted = cleanup_stale_sessions(&state.db, 24)
            .await
            .map_err(AppError::Internal)?;
        // #1573: also reap crash-orphaned staging files that never reached a
        // DB session row, on the same max-age threshold as the reaper above.
        result.stale_uploads_deleted +=
            sweep_orphan_staging_files(&state.config.storage_path, 24).await;
    }

    Ok(Json(result))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ReindexResponse {
    pub message: String,
    pub artifacts_indexed: i64,
    pub repositories_indexed: i64,
}

/// Trigger a full OpenSearch reindex of all artifacts and repositories.
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

    let search = state
        .search_service
        .as_ref()
        .ok_or_else(|| AppError::Internal("Search engine is not configured".to_string()))?;

    let (artifacts, repositories) = search.full_reindex(&state.db).await?;

    Ok(Json(ReindexResponse {
        message: "Full reindex completed successfully".to_string(),
        artifacts_indexed: artifacts as i64,
        repositories_indexed: repositories as i64,
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RescanForInventoryRequest {
    /// Maximum number of artifacts to enqueue in this call. Operators
    /// run the endpoint repeatedly to drain large backfills without
    /// stalling a single HTTP worker; the handler returns the actual
    /// number enqueued so the caller can detect when work is done.
    /// Defaults to 100. Hard-capped at 1000 to avoid pathological inputs.
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RescanForInventoryResponse {
    /// Number of artifacts whose latest scan had no inventory rows and
    /// for which a rescan was enqueued in this call.
    pub artifacts_enqueued: i64,
    /// Echo of the requested (or defaulted) limit, useful for clients
    /// driving the loop programmatically.
    pub limit: i64,
}

/// Enqueue rescans for artifacts whose latest scan has no scan_packages
/// inventory rows.
///
/// Targets pre-#903 (migration 085) scans, and any post-#903 scan whose
/// inventory was lost or never produced. The SBOM read path falls back to
/// `scan_findings` for these artifacts and produces a vulnerability-only
/// component list, which is exactly the bug #903 set out to fix. This
/// endpoint is the one-shot operator command for rebuilding the
/// inventory across a whole instance after upgrading. (#1155)
///
/// Requires admin privileges and a configured scanner service. Returns
/// 503 if the scanner is not configured (operationally normal on
/// minimal stacks, not a server bug).
///
/// The handler is dispatch-and-return: scans run on background tokio
/// tasks. Callers poll the response.artifacts_enqueued value across
/// repeated calls to drive a full backfill, stopping when a call
/// returns zero.
/// Bound on simultaneously in-flight rescan tasks across all calls of
/// the rescan-for-inventory endpoint. Each permit corresponds to one
/// background scan; the cap exists so a polling admin (or a stolen
/// admin token) cannot pin every Tokio worker on scanner I/O and
/// starve normal upload traffic. 16 leaves headroom for parallel
/// rescans on a default 8-vCPU runtime without monopolising the pool.
///
/// Back-pressure model: dispatch is unbounded (`tokio::spawn` per
/// artifact), but each task awaits a permit before doing scanner work.
/// A tight polling loop will accumulate parked tasks proportional to
/// the dispatch rate; the resulting memory is bounded by the operator
/// pacing because each call returns immediately and exposes
/// `artifacts_enqueued`. We do NOT acquire pre-spawn / 503-on-contention
/// here: the dispatch-and-return contract is the point of the endpoint
/// (callers poll until `artifacts_enqueued == 0`).
const RESCAN_INFLIGHT_CAP: usize = 16;

fn rescan_inflight_semaphore() -> &'static Arc<Semaphore> {
    static SEM: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SEM.get_or_init(|| Arc::new(Semaphore::new(RESCAN_INFLIGHT_CAP)))
}

#[utoipa::path(
    post,
    path = "/rescan-for-inventory",
    context_path = "/api/v1/admin",
    tag = "admin",
    request_body(content = RescanForInventoryRequest, description = "Optional; empty body uses defaults"),
    responses(
        (status = 200, description = "Rescans enqueued", body = RescanForInventoryResponse),
        (status = 403, description = "Admin privileges required"),
        (status = 503, description = "Scanner service not configured"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn rescan_for_inventory(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    body: Option<Json<RescanForInventoryRequest>>,
) -> Result<Json<RescanForInventoryResponse>> {
    if !auth.is_admin {
        return Err(AppError::Authorization(
            "Admin privileges required".to_string(),
        ));
    }

    let scanner = state
        .scanner_service
        .as_ref()
        .ok_or_else(|| AppError::ServiceUnavailable("Scanner service not configured".to_string()))?
        .clone();

    // Cap the limit at 1000 to bound work per call regardless of what the
    // caller asks for. The default of 100 matches the typical operator
    // pace: each rescan eats scanner capacity, so 100 is enough to keep
    // a backfill moving without crowding out new uploads.
    let requested_limit = body.as_ref().and_then(|b| b.0.limit).unwrap_or(100);
    let limit = requested_limit.clamp(1, 1000);

    let scan_result_service =
        crate::services::scan_result_service::ScanResultService::new(state.db.clone());
    let artifact_ids = scan_result_service
        .list_artifacts_missing_inventory(limit)
        .await?;
    let enqueued = artifact_ids.len() as i64;

    tracing::info!(
        actor_user_id = %auth.user_id,
        actor_username = %auth.username,
        limit,
        enqueued,
        "admin.rescan_for_inventory: dispatching background rescans"
    );

    let semaphore = rescan_inflight_semaphore().clone();
    for artifact_id in artifact_ids {
        let scanner_for_spawn = scanner.clone();
        let permit_sem = semaphore.clone();
        tokio::spawn(async move {
            // Acquire a permit before doing scanner work. Bounds total
            // in-flight rescans across all callers of this endpoint so
            // a tight polling loop can't pin every Tokio worker. The
            // permit is held for the duration of the scan and released
            // on task completion (success or failure).
            // Nothing in this binary calls `close()` on the semaphore, so
            // the only way `acquire_owned` errors is if a future change
            // adds an explicit shutdown path. Bail quietly if that happens.
            let _permit = match permit_sem.acquire_owned().await {
                Ok(p) => p,
                Err(_) => return,
            };
            // Use `force = true` (via scan_artifact_with_options) so the
            // repo's scan-enabled config doesn't block the backfill. The
            // operator already chose to rescan; respecting per-repo config
            // here would silently skip exactly the repos the inventory
            // gap most likely affects.
            //
            // `bypass_dedup = true` (#1469) is required here too: the
            // inventory backfill is the user-visible "rescan to populate
            // SBOM rows" admin path. If a prior scan completed with zero
            // findings due to a silent extraction failure, the cached row
            // would short-circuit this rescan too and the inventory would
            // stay empty.
            if let Err(e) = scanner_for_spawn
                .scan_artifact_with_options(artifact_id, true, true)
                .await
            {
                tracing::error!(
                    artifact_id = %artifact_id,
                    error = %e,
                    "rescan-for-inventory: scan failed"
                );
            }
        });
    }

    Ok(Json(RescanForInventoryResponse {
        artifacts_enqueued: enqueued,
        limit,
    }))
}

// ---------------------------------------------------------------------------
// Proxy scan verdict inspect / invalidate (#3244)
// ---------------------------------------------------------------------------

/// Normalize an operator-supplied content digest for the `proxy_scan_results`
/// key: accepts either `sha256:<64 hex>` or the bare 64-hex form (the stored
/// shape), lowercases it, and rejects anything else. Pure so the validation is
/// unit-testable without a DB.
pub(crate) fn normalize_verdict_digest(raw: &str) -> Option<String> {
    let hex = raw.trim().strip_prefix("sha256:").unwrap_or(raw.trim());
    if hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(hex.to_ascii_lowercase())
    } else {
        None
    }
}

/// One stored `proxy_scan_results` row, as returned by the admin
/// inspect/invalidate endpoints (#3244).
#[derive(Debug, Serialize, ToSchema)]
pub struct ProxyScanVerdictItem {
    pub checksum_sha256: String,
    pub scan_type: String,
    pub verdict: String,
    pub findings_count: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub max_severity: Option<String>,
    pub scanner_version: Option<String>,
    pub scanned_at: chrono::DateTime<chrono::Utc>,
}

impl From<crate::services::proxy_scan_service::ProxyScanRow> for ProxyScanVerdictItem {
    fn from(r: crate::services::proxy_scan_service::ProxyScanRow) -> Self {
        Self {
            checksum_sha256: r.checksum_sha256,
            scan_type: r.scan_type,
            verdict: r.verdict,
            findings_count: r.findings_count,
            critical_count: r.critical_count,
            high_count: r.high_count,
            medium_count: r.medium_count,
            low_count: r.low_count,
            max_severity: r.max_severity,
            scanner_version: r.scanner_version,
            scanned_at: r.scanned_at,
        }
    }
}

/// Response for the admin proxy-scan-verdict endpoints (#3244).
#[derive(Debug, Serialize, ToSchema)]
pub struct ProxyScanVerdictListResponse {
    /// The normalized (bare-hex) digest the verdicts are keyed on.
    pub digest: String,
    pub verdicts: Vec<ProxyScanVerdictItem>,
}

/// Inspect the stored proxy scan verdict(s) for a content digest (#3244).
///
/// The verdict store is content-addressed and GLOBAL across repositories and
/// tenants (the same bytes are the same CVEs), which is why this surface is
/// instance-admin only: no repo-scoped principal should read — let alone
/// clear — a lever that spans every repo.
#[utoipa::path(
    get,
    path = "/proxy-scan-verdicts/{digest}",
    context_path = "/api/v1/admin",
    tag = "admin",
    params(("digest" = String, Path, description = "Content digest: `sha256:<64 hex>` or bare 64-hex")),
    responses(
        (status = 200, description = "Stored verdict rows for the digest", body = ProxyScanVerdictListResponse),
        (status = 400, description = "Malformed digest"),
        (status = 403, description = "Admin privileges required"),
        (status = 404, description = "No stored verdict for this digest"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_proxy_scan_verdicts(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(digest): Path<String>,
) -> Result<Json<ProxyScanVerdictListResponse>> {
    // Defense-in-depth behind the /admin nest's admin_middleware, with the
    // RBAC-deny recorded (#2321 G-AUDIT convention).
    crate::services::audit_service::enforce_admin_audited(
        auth.is_admin,
        state.db.clone(),
        auth.user_id,
        crate::services::audit_service::ResourceType::ScanResult,
        "/api/v1/admin/proxy-scan-verdicts",
        "GET",
    )
    .await?;
    let normalized = normalize_verdict_digest(&digest).ok_or_else(|| {
        AppError::Validation("digest must be sha256:<64 hex> or bare 64-hex".to_string())
    })?;
    let rows = crate::services::proxy_scan_service::ProxyScanService::new(state.db.clone())
        .list_verdicts_for_digest(&normalized)
        .await?;
    if rows.is_empty() {
        return Err(AppError::NotFound(
            "no stored proxy scan verdict for this digest".to_string(),
        ));
    }
    Ok(Json(ProxyScanVerdictListResponse {
        digest: normalized,
        verdicts: rows.into_iter().map(Into::into).collect(),
    }))
}

/// Invalidate (delete) the stored proxy scan verdict(s) for a content digest
/// (#3244).
///
/// This forces RE-ASSESSMENT on the next pull — it is NOT a waiver. The next
/// pull of the digest re-scans (inline under `fail_closed`, asynchronously
/// under `fail_open`) and records a fresh verdict; a still-flagged image is
/// immediately re-blocked. Only a stale verdict (advisory withdrawn, CVE-DB
/// corrected) is durably cleared. Deleting by digest un-blocks that content
/// EVERYWHERE (the store is global by design), hence instance-admin only.
/// The deletion is audited with the removed rows' verdict summary.
#[utoipa::path(
    delete,
    path = "/proxy-scan-verdicts/{digest}",
    context_path = "/api/v1/admin",
    tag = "admin",
    params(("digest" = String, Path, description = "Content digest: `sha256:<64 hex>` or bare 64-hex")),
    responses(
        (status = 200, description = "Deleted verdict rows (re-assessment forced on next pull)", body = ProxyScanVerdictListResponse),
        (status = 400, description = "Malformed digest"),
        (status = 403, description = "Admin privileges required"),
        (status = 404, description = "No stored verdict for this digest"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_proxy_scan_verdicts(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(digest): Path<String>,
) -> Result<Json<ProxyScanVerdictListResponse>> {
    crate::services::audit_service::enforce_admin_audited(
        auth.is_admin,
        state.db.clone(),
        auth.user_id,
        crate::services::audit_service::ResourceType::ScanResult,
        "/api/v1/admin/proxy-scan-verdicts",
        "DELETE",
    )
    .await?;
    let normalized = normalize_verdict_digest(&digest).ok_or_else(|| {
        AppError::Validation("digest must be sha256:<64 hex> or bare 64-hex".to_string())
    })?;
    let rows = crate::services::proxy_scan_service::ProxyScanService::new(state.db.clone())
        .delete_verdicts_for_digest(&normalized)
        .await?;
    if rows.is_empty() {
        return Err(AppError::NotFound(
            "no stored proxy scan verdict for this digest".to_string(),
        ));
    }
    // Audit the clear: who removed which verdicts for which digest. Details
    // carry the verdict summary so the trail shows what protection state was
    // discarded, never any credential material.
    let audit = crate::services::audit_service::AuditService::new(state.db.clone());
    let entry = crate::services::audit_service::AuditEntry::new(
        crate::services::audit_service::AuditAction::ProxyScanVerdictDeleted,
        crate::services::audit_service::ResourceType::ScanResult,
    )
    .user(auth.user_id)
    .details(serde_json::json!({
        "digest": normalized,
        "deleted": rows
            .iter()
            .map(|r| serde_json::json!({
                "scan_type": r.scan_type,
                "verdict": r.verdict,
                "findings_count": r.findings_count,
                "max_severity": r.max_severity,
                "scanner_version": r.scanner_version,
                "scanned_at": r.scanned_at,
            }))
            .collect::<Vec<_>>(),
    }));
    if let Err(e) = audit.log(entry).await {
        // Fire-and-forget posture: an audit-table outage must not turn a
        // completed delete into a 500, but it must be loud.
        tracing::error!(digest = %normalized, error = %e, "failed to audit proxy scan verdict deletion");
    }
    tracing::warn!(
        actor_user_id = %auth.user_id,
        digest = %normalized,
        deleted = rows.len(),
        "admin cleared proxy scan verdict(s); next pull re-assesses"
    );
    Ok(Json(ProxyScanVerdictListResponse {
        digest: normalized,
        verdicts: rows.into_iter().map(Into::into).collect(),
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
        get_totp_policy,
        update_totp_policy,
        get_system_stats,
        list_downloads,
        list_downloads_by_ip,
        list_downloads_by_user,
        run_cleanup,
        trigger_reindex,
        rescan_for_inventory,
        list_storage_backends,
        list_audit_logs,
        get_proxy_scan_verdicts,
        delete_proxy_scan_verdicts,
    ),
    components(schemas(
        ListBackupsQuery,
        CreateBackupRequest,
        BackupResponse,
        BackupListResponse,
        RestoreRequest,
        RestoreResponse,
        SystemSettings,
        TotpPolicyResponse,
        UpdateTotpPolicyRequest,
        TotpPolicy,
        TotpPolicySource,
        SystemStats,
        ListDownloadsQuery,
        DownloadRecord,
        DownloadListResponse,
        CleanupRequest,
        CleanupResponse,
        ReindexResponse,
        RescanForInventoryRequest,
        RescanForInventoryResponse,
        AuditLogItem,
        AuditLogListResponse,
        ProxyScanVerdictItem,
        ProxyScanVerdictListResponse,
    ))
)]
pub struct AdminApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // audit_page_bounds (#2366) — pure pagination arithmetic, no DB required so
    // the coverage gate exercises it even without Postgres.
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // normalize_verdict_digest (#3244) — pure digest validation, no DB.
    // -----------------------------------------------------------------------

    #[test]
    fn test_normalize_verdict_digest_accepts_both_forms() {
        let hex = "a".repeat(64);
        assert_eq!(
            normalize_verdict_digest(&format!("sha256:{hex}")).as_deref(),
            Some(hex.as_str()),
            "prefixed digest normalizes to the stored bare-hex shape"
        );
        assert_eq!(
            normalize_verdict_digest(&hex).as_deref(),
            Some(hex.as_str())
        );
        // Uppercase hex lowercases (the store is lowercase hex).
        let upper = "A".repeat(64);
        assert_eq!(
            normalize_verdict_digest(&upper).as_deref(),
            Some(hex.as_str())
        );
        // Surrounding whitespace is tolerated.
        assert_eq!(
            normalize_verdict_digest(&format!("  sha256:{hex}  ")).as_deref(),
            Some(hex.as_str())
        );
    }

    #[test]
    fn test_normalize_verdict_digest_rejects_malformed() {
        assert_eq!(normalize_verdict_digest(""), None);
        assert_eq!(normalize_verdict_digest("sha256:"), None);
        assert_eq!(normalize_verdict_digest(&"a".repeat(63)), None, "too short");
        assert_eq!(normalize_verdict_digest(&"a".repeat(65)), None, "too long");
        assert_eq!(
            normalize_verdict_digest(&format!("{}g", "a".repeat(63))),
            None,
            "non-hex"
        );
        assert_eq!(
            normalize_verdict_digest(&format!("md5:{}", "a".repeat(64))),
            None,
            "unknown algorithm prefix must not silently pass through"
        );
        // SQL-shaped garbage can never reach the query.
        assert_eq!(
            normalize_verdict_digest("'; DROP TABLE proxy_scan_results;--"),
            None
        );
    }

    #[test]
    fn test_audit_page_bounds_defaults() {
        // No page/per_page -> page 1, default page size, offset 0.
        let (offset, limit, page, per_page) = audit_page_bounds(None, None);
        assert_eq!(offset, 0);
        assert_eq!(limit, AUDIT_DEFAULT_PER_PAGE as i64);
        assert_eq!(page, 1);
        assert_eq!(per_page, AUDIT_DEFAULT_PER_PAGE);
    }

    #[test]
    fn test_audit_page_bounds_computes_offset() {
        // Page 3 at 25/page -> offset 50.
        let (offset, limit, page, per_page) = audit_page_bounds(Some(3), Some(25));
        assert_eq!(offset, 50);
        assert_eq!(limit, 25);
        assert_eq!(page, 3);
        assert_eq!(per_page, 25);
    }

    #[test]
    fn test_audit_page_bounds_floors_page_at_one() {
        // Page 0 must not underflow (page-1) or produce a negative offset.
        let (offset, _limit, page, _pp) = audit_page_bounds(Some(0), Some(10));
        assert_eq!(offset, 0);
        assert_eq!(page, 1);
    }

    #[test]
    fn test_audit_page_bounds_clamps_per_page_to_max() {
        // An over-large per_page is clamped to the hard cap.
        let (_offset, limit, _page, per_page) = audit_page_bounds(Some(1), Some(10_000));
        assert_eq!(limit, AUDIT_MAX_PER_PAGE as i64);
        assert_eq!(per_page, AUDIT_MAX_PER_PAGE);
    }

    #[test]
    fn test_audit_page_bounds_clamps_zero_per_page_to_one() {
        // per_page = 0 would return an empty page forever; clamp up to 1.
        let (_offset, limit, _page, per_page) = audit_page_bounds(Some(1), Some(0));
        assert_eq!(limit, 1);
        assert_eq!(per_page, 1);
    }

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
            environment: "development".to_string(),
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
        assert_eq!(settings.environment, "development");
    }

    #[test]
    fn test_system_settings_serialization_roundtrip() {
        let settings = SystemSettings {
            storage_backend: "s3".to_string(),
            storage_path: "/data/artifacts".to_string(),
            environment: "staging".to_string(),
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
        assert_eq!(parsed.environment, "staging");
    }

    /// Regression: the settings DTO must serialize an `environment` field so
    /// the admin UI can render the true deployment environment instead of a
    /// hardcoded value. This fails if the field is dropped from the response.
    #[test]
    fn test_system_settings_serializes_environment() {
        let settings = SystemSettings {
            storage_backend: "filesystem".to_string(),
            storage_path: "/data/artifacts".to_string(),
            environment: "production".to_string(),
            allow_anonymous_download: false,
            max_upload_size_bytes: 100 * 1024 * 1024,
            retention_days: 365,
            audit_retention_days: 90,
            backup_retention_count: 10,
            edge_stale_threshold_minutes: 5,
        };
        let json = serde_json::to_string(&settings).unwrap();
        assert!(
            json.contains("\"environment\":\"production\""),
            "settings response must expose environment: {json}"
        );
    }

    /// Regression: `serde(default)` on `environment` keeps it optional in the
    /// update-settings request body, so older clients that omit it still
    /// deserialize (defaulting to an empty string).
    #[test]
    fn test_system_settings_environment_defaults_when_absent() {
        let json = r#"{
            "storage_backend": "filesystem",
            "storage_path": "/data/artifacts",
            "allow_anonymous_download": false,
            "max_upload_size_bytes": 104857600,
            "retention_days": 365,
            "audit_retention_days": 90,
            "backup_retention_count": 10,
            "edge_stale_threshold_minutes": 5
        }"#;
        let parsed: SystemSettings = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.environment, "");
    }

    /// Regression (DB-backed, no-op without `DATABASE_URL`): `get_settings`
    /// must thread `config.environment` into the response. The test config
    /// defaults this to "development", matching the runtime default.
    #[tokio::test]
    async fn test_get_settings_exposes_config_environment() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let state = tdh::build_state(pool, "/tmp/admin-settings-env");

        let Json(settings) = get_settings(State(state)).await.unwrap();

        assert_eq!(settings.environment, "development");
    }

    // -----------------------------------------------------------------------
    // #2805 — 2FA enforcement policy endpoints (DB-backed; no-op without
    // DATABASE_URL). Serialized on the shared policy-row advisory lock.
    // -----------------------------------------------------------------------

    /// Build an `AuthExtension` for `user_id` as an admin caller.
    fn admin_auth(user_id: Uuid, username: &str) -> AuthExtension {
        AuthExtension {
            user_id,
            username: username.to_string(),
            email: format!("{username}@test.local"),
            is_admin: true,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: None,
        }
    }

    /// The lockout-safety guard, end to end: an admin who has not enrolled
    /// cannot tighten the policy; the same admin, once enrolled, can; and
    /// loosening never requires enrollment.
    #[tokio::test]
    async fn test_totp_policy_put_enforces_the_you_first_guard() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let _guard = tdh::totp_policy_serial_lock().await;
        let restore = totp_policy::stored_policy(&pool).await;

        // Deliberately NOT flagged `is_admin` in the database: the admin check
        // is route middleware, and `admin_security`'s accessible-users test
        // asserts a global count that every active admin enters. Creating one
        // here would make that pre-existing race fire. Nothing under test reads
        // the column -- `check_policy_activation` keys on the actor's TOTP
        // state, not their role.
        let (user_id, username) = tdh::create_user(&pool).await;
        totp_policy::store_policy(&pool, TotpPolicy::Disabled, user_id)
            .await
            .expect("seed disabled");

        let state = tdh::build_state(pool.clone(), "/tmp/admin-totp-policy");
        let auth = admin_auth(user_id, &username);

        // 1. Not enrolled -> tightening is refused with 409.
        let refused = update_totp_policy(
            State(state.clone()),
            Extension(auth.clone()),
            Json(UpdateTotpPolicyRequest {
                policy: TotpPolicy::RequiredForAdmins,
            }),
        )
        .await;
        let refused_err = refused.err();

        // 2. Enrol the caller, then the same change is accepted.
        sqlx::query("UPDATE users SET totp_enabled = true WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("enrol caller");
        let accepted = update_totp_policy(
            State(state.clone()),
            Extension(auth.clone()),
            Json(UpdateTotpPolicyRequest {
                policy: TotpPolicy::RequiredForAll,
            }),
        )
        .await;

        // 3. Loosening never requires enrollment.
        sqlx::query("UPDATE users SET totp_enabled = false WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("un-enrol caller");
        let loosened = update_totp_policy(
            State(state.clone()),
            Extension(auth.clone()),
            Json(UpdateTotpPolicyRequest {
                policy: TotpPolicy::Disabled,
            }),
        )
        .await;

        let read = get_totp_policy(State(state), Extension(auth)).await;

        totp_policy::store_policy(&pool, restore, user_id)
            .await
            .expect("restore policy");
        tdh::cleanup_user(&pool, user_id).await;

        assert!(
            matches!(refused_err, Some(AppError::Conflict(_))),
            "an unenrolled admin must not be able to tighten the policy: {refused_err:?}"
        );
        let accepted = accepted.expect("an enrolled admin may tighten").0;
        assert_eq!(accepted.policy, TotpPolicy::RequiredForAll);
        assert_eq!(accepted.source, TotpPolicySource::Database);
        assert!(accepted.editable);

        let loosened = loosened.expect("loosening must never be refused").0;
        assert_eq!(loosened.policy, TotpPolicy::Disabled);

        let read = read.expect("read policy").0;
        assert_eq!(read.policy, TotpPolicy::Disabled);
        // The blast-radius counts must see the local user we created, and the
        // admin subset can never exceed the whole.
        assert!(read.local_users >= 1);
        assert!(read.local_admins <= read.local_users);
    }

    /// While `TOTP_POLICY` pins the policy, the API reports it as
    /// non-editable and refuses every change — including a loosening one,
    /// because the write would silently do nothing.
    #[tokio::test]
    async fn test_totp_policy_put_is_refused_while_pinned_by_env() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let _guard = tdh::totp_policy_serial_lock().await;

        let (user_id, username) = tdh::create_user(&pool).await;
        // `is_admin` is deliberately left alone -- see the sibling test.
        sqlx::query("UPDATE users SET totp_enabled = true WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("enrol caller");

        let state = tdh::build_state_with(pool.clone(), "/tmp/admin-totp-pinned", |cfg| {
            cfg.totp_policy = Some(TotpPolicy::RequiredForAll);
        });
        let auth = admin_auth(user_id, &username);

        let read = get_totp_policy(State(state.clone()), Extension(auth.clone())).await;
        let write = update_totp_policy(
            State(state),
            Extension(auth),
            Json(UpdateTotpPolicyRequest {
                policy: TotpPolicy::Disabled,
            }),
        )
        .await;
        let write_err = write.err();

        tdh::cleanup_user(&pool, user_id).await;

        let read = read.expect("read policy").0;
        assert_eq!(read.policy, TotpPolicy::RequiredForAll);
        assert_eq!(read.source, TotpPolicySource::Environment);
        assert!(!read.editable);
        assert!(read.caller_totp_enabled);
        assert!(
            matches!(write_err, Some(AppError::Conflict(_))),
            "a pinned policy must refuse writes: {write_err:?}"
        );
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
            proxy_artifact_count: 12,
            proxy_storage_bytes: 2_000_000,
        };
        let json = serde_json::to_value(&stats).unwrap();
        assert_eq!(json["total_repositories"], 10);
        assert_eq!(json["total_artifacts"], 500);
        assert_eq!(json["total_storage_bytes"], 1_000_000_000i64);
        assert_eq!(json["total_downloads"], 5000);
        assert_eq!(json["total_users"], 25);
        assert_eq!(json["proxy_artifact_count"], 12);
        assert_eq!(json["proxy_storage_bytes"], 2_000_000i64);
    }

    /// DB-backed (skips without `DATABASE_URL`): `get_system_stats` must
    /// surface `proxy_cache_artifacts` rows through `proxy_artifact_count` /
    /// `proxy_storage_bytes`.
    ///
    /// The endpoint aggregates the WHOLE table and the test database is
    /// shared across concurrently running test processes, so assert on the
    /// exact DELTA produced by this test's rows rather than on absolute
    /// totals. A bounded retry absorbs the rare interleaving where another
    /// test mutates the table between the two handler calls; a real wiring
    /// bug fails every attempt.
    #[tokio::test]
    async fn test_get_system_stats_reports_proxy_cache_totals_db() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, _repo_key, _dir) = tdh::create_repo(&pool, "remote", "pypi").await;
        let state = tdh::build_state(pool.clone(), "/tmp/admin-proxy-stats");

        let sizes: [i64; 2] = [1_234, 8_766];
        let mut matched = false;
        for _attempt in 0..3 {
            let Json(before) = get_system_stats(State(state.clone())).await.unwrap();

            for (i, size) in sizes.iter().enumerate() {
                sqlx::query(
                    "INSERT INTO proxy_cache_artifacts \
                     (repository_id, path, storage_key, metadata_key, size_bytes) \
                     VALUES ($1, $2, $3, $4, $5)",
                )
                .bind(repo_id)
                .bind(format!("stats/pkg-{i}.whl"))
                .bind(format!(
                    "proxy-cache/{repo_id}/stats/pkg-{i}.whl/__content__"
                ))
                .bind(format!(
                    "proxy-cache/{repo_id}/stats/pkg-{i}.whl/__cache_meta__.json"
                ))
                .bind(size)
                .execute(&pool)
                .await
                .expect("seed proxy cache row");
            }

            let Json(after) = get_system_stats(State(state.clone())).await.unwrap();

            // Remove this attempt's rows before deciding, so a retry
            // re-seeds from a clean slate (`(repository_id, path)` is
            // unique).
            sqlx::query("DELETE FROM proxy_cache_artifacts WHERE repository_id = $1")
                .bind(repo_id)
                .execute(&pool)
                .await
                .expect("cleanup proxy cache rows");

            if after.proxy_artifact_count == before.proxy_artifact_count + sizes.len() as i64
                && after.proxy_storage_bytes
                    == before.proxy_storage_bytes + sizes.iter().sum::<i64>()
            {
                matched = true;
                break;
            }
        }
        assert!(
            matched,
            "get_system_stats never reflected the seeded proxy_cache_artifacts \
             rows (+{} rows / +{} bytes)",
            sizes.len(),
            sizes.iter().sum::<i64>()
        );

        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .expect("cleanup repo");
    }

    /// DB-backed (skips without `DATABASE_URL`): the proxy-cache aggregate
    /// must COALESCE `SUM(size_bytes)` to 0 — not NULL — over an empty set,
    /// since the handler decodes the column as a non-nullable BIGINT
    /// (`"size!"`). Without the COALESCE, `SUM` yields SQL NULL and the
    /// `(i64, i64)` decode below is a hard error, so this test fails.
    ///
    /// #3277: the empty set is a SCOPED subset, not the whole table. The
    /// suite runs process-per-test against a SHARED database, and the
    /// previous shape (DELETE everything + cluster-wide aggregate inside a
    /// rolled-back transaction) raced concurrent tests: READ COMMITTED lets
    /// the SELECT see rows other tests commit after the DELETE. Filtering on
    /// a freshly generated `repository_id` gives a subset the FK to
    /// `repositories` guarantees is empty — `SUM` over zero rows is NULL
    /// either way, so the COALESCE contract is exercised identically with no
    /// global assumption. Same approach as #3242 for the storage-GC
    /// footprint test.
    #[tokio::test]
    async fn test_proxy_cache_stats_query_empty_table_coalesces_to_zero_db() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        // Never inserted into `repositories`, so the FK guarantees no
        // `proxy_cache_artifacts` row can carry it: a deterministically
        // empty subset regardless of concurrent suite activity.
        let unused_repo_id = Uuid::new_v4();

        let (count, size): (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*), COALESCE(SUM(size_bytes), 0)::BIGINT \
             FROM proxy_cache_artifacts WHERE repository_id = $1",
        )
        .bind(unused_repo_id)
        .fetch_one(&pool)
        .await
        .expect("aggregate over empty proxy cache subset");

        assert_eq!(count, 0);
        assert_eq!(size, 0, "COALESCE must map SUM's NULL to 0 on an empty set");
    }

    /// DB-backed regression for #3134: the dashboard `total_storage_bytes`
    /// must include OCI layer/config blob bytes. Blobs live in `oci_blobs`,
    /// not `artifacts` (only manifests land there), so the old raw
    /// `SUM(artifacts.size_bytes)` reported a docker repository at a few KiB
    /// of manifests while it held GiBs of layers.
    ///
    /// The fixture also pins the surrounding accounting semantics:
    ///  - LOGICAL counting: a blob digest cross-repo-mounted into two
    ///    repositories counts once per repository (like the per-repo storage
    ///    column and quota), while extra manifest references to the same blob
    ///    within one repository do NOT multiply the figure (two
    ///    `manifest_blob_refs` rows are seeded for the shared digest).
    ///  - Positive control: a non-OCI repository's hosted bytes are still
    ///    counted, and a proxy-cache catalog row is still counted.
    ///  - No double count: a legacy backfilled `artifacts` row with a
    ///    `proxy-cache/%` storage key is excluded from the total (its bytes
    ///    are represented by the catalog row instead).
    ///
    /// Assertions are before/after deltas produced by this fixture's own
    /// rows. The suite runs process-per-test against a SHARED database, so a
    /// cluster-wide delta races every concurrently running test (the #3129
    /// flake class): under a full-suite parallel run an exact-equality check
    /// here fails reliably. Two defenses, both required:
    ///  - fixture sizes are TERABYTE-scale integers (no real storage is
    ///    written), so each accounting component sits 4+ orders of magnitude
    ///    above realistic concurrent churn, and every wrong composition
    ///    (blob bytes missing, per-reference double count, physical-once
    ///    dedup, legacy row double count) lands >= 23 TB away from the
    ///    expected window while concurrent tests move KBs-to-GBs;
    ///  - the check tolerates +/- `SLACK` (10 GB) of unrelated churn inside
    ///    the observation window and retries a few times in case a concurrent
    ///    test ever moves more than that (like
    ///    `test_get_system_stats_reports_proxy_cache_totals_db` above).
    #[tokio::test]
    async fn test_system_stats_total_storage_includes_oci_blob_bytes() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::repository_service::RepositoryService;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let state = tdh::build_state(pool.clone(), "/tmp/admin-oci-stats");
        let repo_service = RepositoryService::new(pool.clone());

        // Distinctive prime multiples of 1 TB so the expected delta cannot be
        // assembled by accident from a different combination of components.
        const TB: i64 = 1_000_000_000_000;
        const MANIFEST: i64 = 11 * TB; // artifacts row in the docker repo
        const BLOB_SHARED: i64 = 23 * TB; // digest mounted in BOTH docker repos
        const BLOB_SOLO: i64 = 37 * TB; // blob only in the first docker repo
        const HOSTED_PLAIN: i64 = 41 * TB; // artifacts row in the generic repo
        const LEGACY: i64 = 53 * TB; // legacy `proxy-cache/%` artifacts row
        const CACHED: i64 = 61 * TB; // proxy_cache_artifacts catalog row
        const SLACK: i64 = 10_000_000_000; // unrelated concurrent churn budget

        // Once per repo: BLOB_SHARED twice (two repos), refs don't multiply.
        const EXPECTED_TOTAL_DELTA: i64 =
            MANIFEST + 2 * BLOB_SHARED + BLOB_SOLO + HOSTED_PLAIN + CACHED;

        let (oci_a, _, _) = tdh::create_repo(&pool, "local", "docker").await;
        let (oci_b, _, _) = tdh::create_repo(&pool, "local", "docker").await;
        let (plain, _, _) = tdh::create_repo(&pool, "local", "generic").await;
        let (remote, _, _) = tdh::create_repo(&pool, "remote", "pypi").await;
        let repo_ids = [oci_a, oci_b, plain, remote];

        let mut matched = false;
        for _attempt in 0..5 {
            let Json(before) = get_system_stats(State(state.clone())).await.unwrap();

            let digest_shared = format!("sha256:{:0>64}", Uuid::new_v4().simple());
            let digest_solo = format!("sha256:{:0>64}", Uuid::new_v4().simple());

            for (repo, name, size, storage_key) in [
                (
                    oci_a,
                    "manifest",
                    MANIFEST,
                    format!("oci/{oci_a}/manifests/m"),
                ),
                (
                    plain,
                    "plain",
                    HOSTED_PLAIN,
                    format!("generic/{plain}/plain.bin"),
                ),
                (
                    remote,
                    "legacy",
                    LEGACY,
                    format!("proxy-cache/{remote}/legacy.whl"),
                ),
            ] {
                sqlx::query(
                    "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
                     checksum_sha256, content_type, storage_key) \
                     VALUES ($1, $2, $3, '1.0.0', $4, $5, 'application/octet-stream', $6)",
                )
                .bind(repo)
                .bind(format!("stats-3134/{name}/{}", Uuid::new_v4()))
                .bind(name)
                .bind(size)
                .bind(format!("{:0>64}", "3134"))
                .bind(storage_key)
                .execute(&pool)
                .await
                .expect("seed artifacts row");
            }

            for (repo, digest, size) in [
                (oci_a, &digest_shared, BLOB_SHARED),
                (oci_b, &digest_shared, BLOB_SHARED),
                (oci_a, &digest_solo, BLOB_SOLO),
            ] {
                sqlx::query(
                    "INSERT INTO oci_blobs (repository_id, digest, size_bytes, storage_key) \
                     VALUES ($1, $2, $3, $4)",
                )
                .bind(repo)
                .bind(digest)
                .bind(size)
                .bind(format!("oci-blobs/{digest}"))
                .execute(&pool)
                .await
                .expect("seed oci_blobs row");
            }

            // Two manifests referencing the shared blob in the same repo:
            // per-REFERENCE counting would inflate the figure; per-repo-row
            // counting (the ledger's) must not.
            for i in 0..2 {
                sqlx::query(
                    "INSERT INTO manifest_blob_refs \
                     (manifest_digest, blob_digest, repository_id, kind) \
                     VALUES ($1, $2, $3, 'layer')",
                )
                .bind(format!("sha256:{:0>63}{i}", Uuid::new_v4().simple()))
                .bind(&digest_shared)
                .bind(oci_a)
                .execute(&pool)
                .await
                .expect("seed manifest_blob_refs row");
            }

            sqlx::query(
                "INSERT INTO proxy_cache_artifacts \
                 (repository_id, path, storage_key, metadata_key, size_bytes) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(remote)
            .bind("stats-3134/legacy.whl")
            .bind(format!(
                "proxy-cache/{remote}/stats-3134/legacy.whl/__content__"
            ))
            .bind(format!(
                "proxy-cache/{remote}/stats-3134/legacy.whl/__cache_meta__.json"
            ))
            .bind(CACHED)
            .execute(&pool)
            .await
            .expect("seed proxy cache row");

            // The migration-182 triggers charge the ledger inline; reconcile
            // anyway so the assertion binds to the documented authoritative
            // per-repo sums rather than to trigger bookkeeping.
            for repo in repo_ids {
                repo_service
                    .reconcile_usage_ledger(repo)
                    .await
                    .expect("reconcile usage ledger");
            }

            let Json(after) = get_system_stats(State(state.clone())).await.unwrap();

            // Remove this attempt's rows before deciding, so a retry re-seeds
            // from a clean slate.
            for table in ["manifest_blob_refs", "oci_blobs", "proxy_cache_artifacts"] {
                let sql = format!("DELETE FROM {table} WHERE repository_id = ANY($1)");
                sqlx::query(sqlx::AssertSqlSafe(&*sql))
                    .bind(&repo_ids[..])
                    .execute(&pool)
                    .await
                    .expect("cleanup seeded rows");
            }
            sqlx::query("DELETE FROM artifacts WHERE repository_id = ANY($1)")
                .bind(&repo_ids[..])
                .execute(&pool)
                .await
                .expect("cleanup seeded artifacts");

            let total_delta = after.total_storage_bytes - before.total_storage_bytes;
            let proxy_delta = after.proxy_storage_bytes - before.proxy_storage_bytes;
            if (total_delta - EXPECTED_TOTAL_DELTA).abs() <= SLACK
                && (proxy_delta - CACHED).abs() <= SLACK
            {
                matched = true;
                break;
            }
            eprintln!(
                "attempt saw total delta {total_delta} (expected {EXPECTED_TOTAL_DELTA}) / \
                 proxy delta {proxy_delta} (expected {CACHED}); retrying"
            );
        }
        // Clean up the fixture repositories BEFORE asserting, so a failing
        // run does not leak them into the shared test database.
        sqlx::query("DELETE FROM repositories WHERE id = ANY($1)")
            .bind(&repo_ids[..])
            .execute(&pool)
            .await
            .expect("cleanup repos");

        assert!(
            matched,
            "get_system_stats never reflected the seeded storage: expected \
             total_storage_bytes +{EXPECTED_TOTAL_DELTA} +/- {SLACK} (manifest {MANIFEST} + \
             shared blob {BLOB_SHARED} once per mounted repo + solo blob {BLOB_SOLO} + hosted \
             {HOSTED_PLAIN} + cached {CACHED}, legacy proxy-cache/% row {LEGACY} excluded) \
             and proxy_storage_bytes +{CACHED} +/- {SLACK}"
        );
    }

    /// DB-backed (skips without `DATABASE_URL`): the #3134 ledger aggregate
    /// must COALESCE `SUM(...)` to 0 — not NULL — over an empty
    /// `repository_usage_ledger` set (a fresh install's dashboard), since
    /// the handler decodes both columns as non-nullable BIGINT (`"total!"`,
    /// `"proxy!"`). Without the COALESCE, `SUM` yields SQL NULL and the
    /// `(i64, i64)` decode is a hard error, so this test fails.
    ///
    /// #3277: same scoped-empty-subset shape as the proxy-cache test above —
    /// the previous DELETE-then-aggregate-in-a-rolled-back-transaction raced
    /// concurrent tests under READ COMMITTED (this table is written by the
    /// migration-182 triggers on every artifact insert suite-wide).
    #[tokio::test]
    async fn test_ledger_totals_query_empty_table_coalesces_to_zero_db() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        // Never inserted into `repositories`; the ledger PK/FK guarantees an
        // empty subset for it.
        let unused_repo_id = Uuid::new_v4();

        let (total, proxy): (i64, i64) = sqlx::query_as(
            "SELECT COALESCE(SUM(hosted_bytes + proxy_bytes + oci_bytes), 0)::BIGINT, \
                    COALESCE(SUM(proxy_bytes), 0)::BIGINT \
             FROM repository_usage_ledger WHERE repository_id = $1",
        )
        .bind(unused_repo_id)
        .fetch_one(&pool)
        .await
        .expect("aggregate over empty ledger subset");

        assert_eq!(total, 0, "COALESCE must map SUM's NULL to 0");
        assert_eq!(proxy, 0, "COALESCE must map SUM's NULL to 0");
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
            integrity_anchor: "recorded".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["tables_restored"].as_array().unwrap().len(), 2);
        assert_eq!(json["artifacts_restored"], 42);
        assert!(json["errors"].as_array().unwrap().is_empty());
        // The caller must be able to see WHAT the archive was checked against
        // (#3373), not just that the restore returned 200.
        assert_eq!(json["integrity_anchor"], "recorded");
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
    fn test_create_backup_request_custom_name() {
        let json = r#"{"type": "full", "name": "nightly-prod"}"#;
        let req: CreateBackupRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, Some("nightly-prod".to_string()));
    }

    #[test]
    fn test_create_backup_request_name_defaults_none() {
        let json = r#"{"type": "full"}"#;
        let req: CreateBackupRequest = serde_json::from_str(json).unwrap();
        assert!(req.name.is_none());
    }

    #[test]
    fn test_create_backup_request_since_defaults_none() {
        // #2789: without `since` the backup keeps its default (all artifacts).
        let json = r#"{"type": "incremental"}"#;
        let req: CreateBackupRequest = serde_json::from_str(json).unwrap();
        assert!(req.since.is_none());
    }

    #[test]
    fn test_create_backup_request_parses_rfc3339_since() {
        // #2789: an RFC3339 timestamp is accepted and parsed to a UTC instant.
        let json = r#"{"type": "incremental", "since": "2026-01-15T12:30:00Z"}"#;
        let req: CreateBackupRequest = serde_json::from_str(json).unwrap();
        let expected = chrono::DateTime::parse_from_rfc3339("2026-01-15T12:30:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert_eq!(req.since, Some(expected));
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

    // -----------------------------------------------------------------------
    // #2366: GET /admin/audit — admin can read recorded events; a non-admin is
    // refused by the handler's defense-in-depth check. Skips without
    // `DATABASE_URL`.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_list_audit_logs_admin_reads_and_non_admin_forbidden_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::audit_service::{AuditAction, AuditEntry, AuditService, ResourceType};
        use axum::body::Body;
        use axum::http::{Method, Request, StatusCode};
        use axum::Extension as AxumExtension;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;

        // Seed one audit event keyed by a unique resource id.
        let resource_id = Uuid::new_v4();
        AuditService::new(pool.clone())
            .log(
                AuditEntry::new(AuditAction::UserCreated, ResourceType::User)
                    .user(user_id)
                    .resource(resource_id),
            )
            .await
            .expect("seed audit event");

        let state = tdh::build_state(pool.clone(), "/tmp");

        // Admin caller -> 200, and our event is returned when filtered.
        let mut admin_auth = tdh::make_auth(user_id, &username);
        admin_auth.is_admin = true;
        let app = router()
            .with_state(state.clone())
            .layer(AxumExtension::<AuthExtension>(admin_auth));
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("/audit?resource_id={}", resource_id))
            .body(Body::empty())
            .unwrap();
        let (status, body) = tdh::send(app, req).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "admin can read audit; body: {}",
            String::from_utf8_lossy(&body)
        );
        let v: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(v["total"], 1);
        assert_eq!(v["items"][0]["action"], "USER_CREATED");
        assert_eq!(v["items"][0]["resource_id"], resource_id.to_string());
        // #2392: the actor's username is embedded server-side so the UI does
        // not have to client-side-join against /admin/users.
        assert_eq!(v["items"][0]["actor_username"], username);

        // Non-admin caller -> 403 (handler defense-in-depth, independent of the
        // `/admin` admin_middleware which is not mounted in this unit router).
        let non_admin = tdh::make_auth(user_id, &username);
        let app2 = router()
            .with_state(state)
            .layer(AxumExtension::<AuthExtension>(non_admin));
        let req2 = Request::builder()
            .method(Method::GET)
            .uri("/audit")
            .body(Body::empty())
            .unwrap();
        let (status2, _) = tdh::send(app2, req2).await;
        assert_eq!(status2, StatusCode::FORBIDDEN);

        let _ = sqlx::query("DELETE FROM audit_log WHERE resource_id = $1")
            .bind(resource_id)
            .execute(&pool)
            .await;
        tdh::cleanup_user(&pool, user_id).await;
    }

    // -----------------------------------------------------------------------
    // download telemetry (#2365)
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_rfc3339_bound_accepts_valid_and_none() {
        assert_eq!(parse_rfc3339_bound(None, "from").unwrap(), None);
        let parsed = parse_rfc3339_bound(Some("2026-07-01T00:00:00Z"), "from")
            .unwrap()
            .unwrap();
        assert_eq!(parsed.to_rfc3339(), "2026-07-01T00:00:00+00:00");
    }

    #[test]
    fn test_parse_rfc3339_bound_rejects_malformed() {
        let err = parse_rfc3339_bound(Some("yesterday"), "to").unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[tokio::test]
    async fn test_query_downloads_filters_by_ip_user_and_artifact() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let (repo_id, _repo_key, _dir) = tdh::create_repo(&pool, "local", "generic").await;
        let artifact_id: Uuid = sqlx::query_scalar(
            "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
             checksum_sha256, content_type, storage_key) \
             VALUES ($1, $2, 'dl-telemetry', '1.0.0', 10, $3, 'application/octet-stream', $2) \
             RETURNING id",
        )
        .bind(repo_id)
        .bind(format!("dl-telemetry/{}.bin", Uuid::new_v4()))
        .bind(format!("{:0>64}", "1"))
        .fetch_one(&pool)
        .await
        .expect("insert artifact");

        // One authenticated download from 203.0.113.10, one anonymous from
        // 203.0.113.11.
        let ctx_authed = crate::api::middleware::download_telemetry::DownloadContext {
            client_ip: Some("203.0.113.10".parse().unwrap()),
            user_id: Some(user_id),
            user_agent: Some("admin-dl-test/1.0".to_string()),
            is_head: false,
        };
        let ctx_anon = crate::api::middleware::download_telemetry::DownloadContext {
            client_ip: Some("203.0.113.11".parse().unwrap()),
            user_id: None,
            user_agent: None,
            is_head: false,
        };
        crate::services::artifact_service::record_download(&pool, artifact_id, &ctx_authed).await;
        crate::services::artifact_service::record_download(&pool, artifact_id, &ctx_anon).await;
        // #2522: the two INSERTs are now spawned off the hot path — wait for
        // both rows to land before asserting on them.
        assert_eq!(
            tdh::download_count_eventually(&pool, artifact_id, 2).await,
            2
        );

        // Filter by artifact: both rows.
        let by_artifact = query_downloads(
            &pool,
            &ListDownloadsQuery {
                artifact_id: Some(artifact_id),
                ..Default::default()
            },
        )
        .await
        .expect("query by artifact");
        assert_eq!(by_artifact.total, 2);
        assert_eq!(by_artifact.downloads.len(), 2);

        // Filter by IP: only the authenticated row, with the username joined.
        let by_ip = query_downloads(
            &pool,
            &ListDownloadsQuery {
                artifact_id: Some(artifact_id),
                ip: Some("203.0.113.10".to_string()),
                ..Default::default()
            },
        )
        .await
        .expect("query by ip");
        assert_eq!(by_ip.total, 1);
        let row = &by_ip.downloads[0];
        assert_eq!(row.user_id, Some(user_id));
        assert_eq!(row.username.as_deref(), Some(username.as_str()));
        assert_eq!(row.ip_address.as_deref(), Some("203.0.113.10"));
        assert_eq!(row.user_agent.as_deref(), Some("admin-dl-test/1.0"));

        // Filter by user: only the authenticated row.
        let by_user = query_downloads(
            &pool,
            &ListDownloadsQuery {
                artifact_id: Some(artifact_id),
                user_id: Some(user_id),
                ..Default::default()
            },
        )
        .await
        .expect("query by user");
        assert_eq!(by_user.total, 1);

        // The anonymous row keeps a NULL user but a real IP.
        let anon = query_downloads(
            &pool,
            &ListDownloadsQuery {
                artifact_id: Some(artifact_id),
                ip: Some("203.0.113.11".to_string()),
                ..Default::default()
            },
        )
        .await
        .expect("query anon row");
        assert_eq!(anon.total, 1);
        assert_eq!(anon.downloads[0].user_id, None);

        // Pagination clamps per_page and honors page.
        let paged = query_downloads(
            &pool,
            &ListDownloadsQuery {
                artifact_id: Some(artifact_id),
                page: Some(2),
                per_page: Some(1),
                ..Default::default()
            },
        )
        .await
        .expect("paged query");
        assert_eq!(paged.total, 2);
        assert_eq!(paged.downloads.len(), 1);
        assert_eq!(paged.page, 2);

        tdh::cleanup(&pool, repo_id, user_id).await;
    }

    #[tokio::test]
    async fn test_record_download_unresolvable_ip_is_null_not_sentinel() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let (user_id, _username) = tdh::create_user(&pool).await;
        let (repo_id, _repo_key, _dir) = tdh::create_repo(&pool, "local", "generic").await;
        let artifact_id: Uuid = sqlx::query_scalar(
            "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
             checksum_sha256, content_type, storage_key) \
             VALUES ($1, $2, 'dl-null-ip', '1.0.0', 10, $3, 'application/octet-stream', $2) \
             RETURNING id",
        )
        .bind(repo_id)
        .bind(format!("dl-null-ip/{}.bin", Uuid::new_v4()))
        .bind(format!("{:0>64}", "2"))
        .fetch_one(&pool)
        .await
        .expect("insert artifact");

        crate::services::artifact_service::record_download(&pool, artifact_id, &Default::default())
            .await;
        // #2522: the INSERT is now spawned — wait for the row before reading it.
        assert_eq!(
            tdh::download_count_eventually(&pool, artifact_id, 1).await,
            1
        );

        let (ip, uid): (Option<String>, Option<Uuid>) = sqlx::query_as(
            "SELECT ip_address, user_id FROM download_statistics WHERE artifact_id = $1",
        )
        .bind(artifact_id)
        .fetch_one(&pool)
        .await
        .expect("stats row");
        assert_eq!(
            ip, None,
            "unresolvable client must record NULL, not 0.0.0.0"
        );
        assert_eq!(uid, None);

        tdh::cleanup(&pool, repo_id, user_id).await;
    }

    // -----------------------------------------------------------------------
    // #3327: a backup run that ends FAILED is reported as the backup resource
    // (HTTP 200, `status = "failed"`, `error_message` naming the cause), not as
    // a transport-level 500.
    //
    // The regression this pins: `execute_backup` used to call
    // `BackupService::execute`, whose `Err` for a failed run propagated through
    // `Result<Json<_>>` into `500 {"code":"INTERNAL_ERROR","message":"Internal
    // server error"}`. The message #3170 composes — the one naming every
    // artifact object whose bytes could not be read, which is the entire point
    // of failing the job — was written to `backups.error_message` and to the
    // server log, and then discarded at the HTTP boundary. An operator
    // triggering a backup got a bare 500 and no way to learn why.
    //
    // The assertion is deliberately on BOTH halves: the status code must not be
    // 5xx, AND the body must carry the failed status plus the causal message.
    // Asserting only on the code would pass for a handler that reports success.
    // -----------------------------------------------------------------------

    /// Insert an artifact row whose bytes are absent from the repository's
    /// resolved storage root, so the backup enumerates a key it cannot read.
    #[cfg(test)]
    async fn insert_unreadable_artifact(pool: &sqlx::PgPool, repo_id: Uuid) -> String {
        let key = format!("bk-3327/{}", Uuid::new_v4());
        sqlx::query(
            r#"
            INSERT INTO artifacts
                (repository_id, path, name, size_bytes, checksum_sha256,
                 content_type, storage_key)
            VALUES ($1, $2, 'unreadable', 10, $3, 'application/octet-stream', $4)
            "#,
        )
        .bind(repo_id)
        .bind(format!("path/{}", key))
        .bind("0".repeat(64))
        .bind(&key)
        .execute(pool)
        .await
        .expect("insert artifact row with no bytes behind it");
        key
    }

    #[tokio::test]
    async fn execute_reports_a_failed_run_as_the_backup_resource_not_a_500() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(f) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };

        let missing_key = insert_unreadable_artifact(&f.pool, f.repo_id).await;

        // Scope the backup to the fixture repository so the assertion cannot be
        // satisfied (or broken) by unrelated rows in a shared test database.
        let storage = Arc::new(
            StorageService::from_config(&f.state.config)
                .await
                .expect("storage from test config"),
        );
        let service = BackupService::new(f.pool.clone(), storage);
        let backup = service
            .create(ServiceCreateBackup {
                backup_type: BackupType::Full,
                repository_ids: Some(vec![f.repo_id]),
                exclude_repository_ids: None,
                since: None,
                created_by: None,
                name: None,
            })
            .await
            .expect("create backup job");

        // `execute_backup` extracts the non-Option `Extension<AuthExtension>`,
        // exactly as the production auth middleware inserts it.
        let app = tdh::router_with_auth_ext(
            super::router(),
            f.state.clone(),
            tdh::make_auth(f.user_id, &f.username),
        );
        let (status, body) = tdh::send(
            app,
            tdh::post(
                format!("/backups/{}/execute", backup.id),
                "application/json",
                bytes::Bytes::new(),
            ),
        )
        .await;

        assert!(
            !status.is_server_error(),
            "a recorded run outcome must not surface as a transport error; got {status} body={}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(
            status,
            axum::http::StatusCode::OK,
            "the trigger answers with the backup resource"
        );

        let json: serde_json::Value =
            serde_json::from_slice(&body).expect("execute must answer with a BackupResponse");
        assert_eq!(
            json["status"], "failed",
            "the run failed, so the resource must say so rather than report success: {json}"
        );
        let message = json["error_message"].as_str().unwrap_or_default();
        assert!(
            message.contains(&missing_key),
            "the response must carry the message naming the unreadable object; got {message:?}"
        );

        // The persisted row agrees with what the caller was told.
        let row = service.get_by_id(backup.id).await.expect("reload backup");
        assert_eq!(row.status, BackupStatus::Failed);

        let _ = sqlx::query("DELETE FROM backups WHERE id = $1")
            .bind(backup.id)
            .execute(&f.pool)
            .await;
        f.teardown().await;
    }
}
