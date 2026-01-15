//! Audit logging service.
//!
//! Tracks all significant actions in the system for compliance and debugging.

use sqlx::PgPool;
use std::net::IpAddr;
use uuid::Uuid;

use crate::error::{AppError, Result};

/// Audit action types
#[derive(Debug, Clone, Copy)]
pub enum AuditAction {
    // Authentication
    Login,
    Logout,
    LoginFailed,
    PasswordChanged,
    ApiTokenCreated,
    ApiTokenRevoked,

    // User management
    UserCreated,
    UserUpdated,
    UserDeleted,
    UserDisabled,
    RoleAssigned,
    RoleRevoked,

    // Repository management
    RepositoryCreated,
    RepositoryUpdated,
    RepositoryDeleted,
    RepositoryPermissionChanged,

    // Artifact operations
    ArtifactUploaded,
    ArtifactDownloaded,
    ArtifactDeleted,
    ArtifactMetadataUpdated,

    // System operations
    BackupStarted,
    BackupCompleted,
    BackupFailed,
    RestoreStarted,
    RestoreCompleted,
    RestoreFailed,

    // Edge nodes
    EdgeNodeRegistered,
    EdgeNodeUnregistered,
    EdgeNodeSyncStarted,
    EdgeNodeSyncCompleted,

    // Configuration
    SettingChanged,
    PluginInstalled,
    PluginUninstalled,
    PluginEnabled,
    PluginDisabled,
}

impl AuditAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditAction::Login => "LOGIN",
            AuditAction::Logout => "LOGOUT",
            AuditAction::LoginFailed => "LOGIN_FAILED",
            AuditAction::PasswordChanged => "PASSWORD_CHANGED",
            AuditAction::ApiTokenCreated => "API_TOKEN_CREATED",
            AuditAction::ApiTokenRevoked => "API_TOKEN_REVOKED",
            AuditAction::UserCreated => "USER_CREATED",
            AuditAction::UserUpdated => "USER_UPDATED",
            AuditAction::UserDeleted => "USER_DELETED",
            AuditAction::UserDisabled => "USER_DISABLED",
            AuditAction::RoleAssigned => "ROLE_ASSIGNED",
            AuditAction::RoleRevoked => "ROLE_REVOKED",
            AuditAction::RepositoryCreated => "REPOSITORY_CREATED",
            AuditAction::RepositoryUpdated => "REPOSITORY_UPDATED",
            AuditAction::RepositoryDeleted => "REPOSITORY_DELETED",
            AuditAction::RepositoryPermissionChanged => "REPOSITORY_PERMISSION_CHANGED",
            AuditAction::ArtifactUploaded => "ARTIFACT_UPLOADED",
            AuditAction::ArtifactDownloaded => "ARTIFACT_DOWNLOADED",
            AuditAction::ArtifactDeleted => "ARTIFACT_DELETED",
            AuditAction::ArtifactMetadataUpdated => "ARTIFACT_METADATA_UPDATED",
            AuditAction::BackupStarted => "BACKUP_STARTED",
            AuditAction::BackupCompleted => "BACKUP_COMPLETED",
            AuditAction::BackupFailed => "BACKUP_FAILED",
            AuditAction::RestoreStarted => "RESTORE_STARTED",
            AuditAction::RestoreCompleted => "RESTORE_COMPLETED",
            AuditAction::RestoreFailed => "RESTORE_FAILED",
            AuditAction::EdgeNodeRegistered => "EDGE_NODE_REGISTERED",
            AuditAction::EdgeNodeUnregistered => "EDGE_NODE_UNREGISTERED",
            AuditAction::EdgeNodeSyncStarted => "EDGE_NODE_SYNC_STARTED",
            AuditAction::EdgeNodeSyncCompleted => "EDGE_NODE_SYNC_COMPLETED",
            AuditAction::SettingChanged => "SETTING_CHANGED",
            AuditAction::PluginInstalled => "PLUGIN_INSTALLED",
            AuditAction::PluginUninstalled => "PLUGIN_UNINSTALLED",
            AuditAction::PluginEnabled => "PLUGIN_ENABLED",
            AuditAction::PluginDisabled => "PLUGIN_DISABLED",
        }
    }
}

/// Resource types for audit logging
#[derive(Debug, Clone, Copy)]
pub enum ResourceType {
    User,
    Repository,
    Artifact,
    Role,
    ApiToken,
    EdgeNode,
    Backup,
    Setting,
    Plugin,
}

impl ResourceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResourceType::User => "user",
            ResourceType::Repository => "repository",
            ResourceType::Artifact => "artifact",
            ResourceType::Role => "role",
            ResourceType::ApiToken => "api_token",
            ResourceType::EdgeNode => "edge_node",
            ResourceType::Backup => "backup",
            ResourceType::Setting => "setting",
            ResourceType::Plugin => "plugin",
        }
    }
}

/// Audit log entry builder
pub struct AuditEntry {
    user_id: Option<Uuid>,
    action: AuditAction,
    resource_type: ResourceType,
    resource_id: Option<Uuid>,
    details: Option<serde_json::Value>,
    ip_address: Option<IpAddr>,
    correlation_id: Uuid,
}

impl AuditEntry {
    pub fn new(action: AuditAction, resource_type: ResourceType) -> Self {
        Self {
            user_id: None,
            action,
            resource_type,
            resource_id: None,
            details: None,
            ip_address: None,
            correlation_id: Uuid::new_v4(),
        }
    }

    pub fn user(mut self, user_id: Uuid) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn resource(mut self, resource_id: Uuid) -> Self {
        self.resource_id = Some(resource_id);
        self
    }

    pub fn details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn ip(mut self, ip_address: IpAddr) -> Self {
        self.ip_address = Some(ip_address);
        self
    }

    pub fn correlation(mut self, correlation_id: Uuid) -> Self {
        self.correlation_id = correlation_id;
        self
    }
}

/// Audit service
pub struct AuditService {
    db: PgPool,
}

impl AuditService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Log an audit entry
    pub async fn log(&self, entry: AuditEntry) -> Result<Uuid> {
        let id = sqlx::query_scalar!(
            r#"
            INSERT INTO audit_log (user_id, action, resource_type, resource_id, details, ip_address, correlation_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id
            "#,
            entry.user_id,
            entry.action.as_str(),
            entry.resource_type.as_str(),
            entry.resource_id,
            entry.details,
            entry.ip_address.map(|ip| ip.to_string()),
            entry.correlation_id
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(id)
    }

    /// Query audit logs
    pub async fn query(
        &self,
        user_id: Option<Uuid>,
        action: Option<&str>,
        resource_type: Option<&str>,
        resource_id: Option<Uuid>,
        from: Option<chrono::DateTime<chrono::Utc>>,
        to: Option<chrono::DateTime<chrono::Utc>>,
        offset: i64,
        limit: i64,
    ) -> Result<(Vec<AuditLogEntry>, i64)> {
        let entries = sqlx::query_as!(
            AuditLogEntry,
            r#"
            SELECT
                id, user_id, action, resource_type, resource_id,
                details, ip_address, correlation_id, created_at
            FROM audit_log
            WHERE ($1::uuid IS NULL OR user_id = $1)
              AND ($2::text IS NULL OR action = $2)
              AND ($3::text IS NULL OR resource_type = $3)
              AND ($4::uuid IS NULL OR resource_id = $4)
              AND ($5::timestamptz IS NULL OR created_at >= $5)
              AND ($6::timestamptz IS NULL OR created_at <= $6)
            ORDER BY created_at DESC
            OFFSET $7
            LIMIT $8
            "#,
            user_id,
            action,
            resource_type,
            resource_id,
            from,
            to,
            offset,
            limit
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let total = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM audit_log
            WHERE ($1::uuid IS NULL OR user_id = $1)
              AND ($2::text IS NULL OR action = $2)
              AND ($3::text IS NULL OR resource_type = $3)
              AND ($4::uuid IS NULL OR resource_id = $4)
              AND ($5::timestamptz IS NULL OR created_at >= $5)
              AND ($6::timestamptz IS NULL OR created_at <= $6)
            "#,
            user_id,
            action,
            resource_type,
            resource_id,
            from,
            to
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok((entries, total))
    }

    /// Get audit logs for a specific resource
    pub async fn get_resource_history(
        &self,
        resource_type: ResourceType,
        resource_id: Uuid,
        limit: i64,
    ) -> Result<Vec<AuditLogEntry>> {
        let entries = sqlx::query_as!(
            AuditLogEntry,
            r#"
            SELECT
                id, user_id, action, resource_type, resource_id,
                details, ip_address, correlation_id, created_at
            FROM audit_log
            WHERE resource_type = $1 AND resource_id = $2
            ORDER BY created_at DESC
            LIMIT $3
            "#,
            resource_type.as_str(),
            resource_id,
            limit
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(entries)
    }

    /// Get audit logs by correlation ID (for tracking related actions)
    pub async fn get_by_correlation(&self, correlation_id: Uuid) -> Result<Vec<AuditLogEntry>> {
        let entries = sqlx::query_as!(
            AuditLogEntry,
            r#"
            SELECT
                id, user_id, action, resource_type, resource_id,
                details, ip_address, correlation_id, created_at
            FROM audit_log
            WHERE correlation_id = $1
            ORDER BY created_at
            "#,
            correlation_id
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(entries)
    }

    /// Clean up old audit logs
    pub async fn cleanup(&self, retention_days: i32) -> Result<u64> {
        let result = sqlx::query!(
            "DELETE FROM audit_log WHERE created_at < NOW() - make_interval(days => $1)",
            retention_days
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(result.rows_affected())
    }
}

/// Audit log entry from database
#[derive(Debug)]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<Uuid>,
    pub details: Option<serde_json::Value>,
    pub ip_address: Option<std::net::IpAddr>,
    pub correlation_id: Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Helper macro for logging audit events
#[macro_export]
macro_rules! audit_log {
    ($service:expr, $action:expr, $resource_type:expr) => {
        $service.log(AuditEntry::new($action, $resource_type))
    };
    ($service:expr, $action:expr, $resource_type:expr, $user_id:expr) => {
        $service.log(AuditEntry::new($action, $resource_type).user($user_id))
    };
    ($service:expr, $action:expr, $resource_type:expr, $user_id:expr, $resource_id:expr) => {
        $service.log(
            AuditEntry::new($action, $resource_type)
                .user($user_id)
                .resource($resource_id),
        )
    };
}
