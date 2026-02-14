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

    // Peer instances
    PeerRegistered,
    PeerUnregistered,
    PeerSyncStarted,
    PeerSyncCompleted,

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
            AuditAction::PeerRegistered => "PEER_REGISTERED",
            AuditAction::PeerUnregistered => "PEER_UNREGISTERED",
            AuditAction::PeerSyncStarted => "PEER_SYNC_STARTED",
            AuditAction::PeerSyncCompleted => "PEER_SYNC_COMPLETED",
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
    PeerInstance,
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
            ResourceType::PeerInstance => "peer_instance",
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
    #[allow(clippy::too_many_arguments)]
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
    pub ip_address: Option<String>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // -----------------------------------------------------------------------
    // AuditAction::as_str
    // -----------------------------------------------------------------------

    #[test]
    fn test_audit_action_as_str_authentication() {
        assert_eq!(AuditAction::Login.as_str(), "LOGIN");
        assert_eq!(AuditAction::Logout.as_str(), "LOGOUT");
        assert_eq!(AuditAction::LoginFailed.as_str(), "LOGIN_FAILED");
        assert_eq!(AuditAction::PasswordChanged.as_str(), "PASSWORD_CHANGED");
        assert_eq!(AuditAction::ApiTokenCreated.as_str(), "API_TOKEN_CREATED");
        assert_eq!(AuditAction::ApiTokenRevoked.as_str(), "API_TOKEN_REVOKED");
    }

    #[test]
    fn test_audit_action_as_str_user_management() {
        assert_eq!(AuditAction::UserCreated.as_str(), "USER_CREATED");
        assert_eq!(AuditAction::UserUpdated.as_str(), "USER_UPDATED");
        assert_eq!(AuditAction::UserDeleted.as_str(), "USER_DELETED");
        assert_eq!(AuditAction::UserDisabled.as_str(), "USER_DISABLED");
        assert_eq!(AuditAction::RoleAssigned.as_str(), "ROLE_ASSIGNED");
        assert_eq!(AuditAction::RoleRevoked.as_str(), "ROLE_REVOKED");
    }

    #[test]
    fn test_audit_action_as_str_repository() {
        assert_eq!(
            AuditAction::RepositoryCreated.as_str(),
            "REPOSITORY_CREATED"
        );
        assert_eq!(
            AuditAction::RepositoryUpdated.as_str(),
            "REPOSITORY_UPDATED"
        );
        assert_eq!(
            AuditAction::RepositoryDeleted.as_str(),
            "REPOSITORY_DELETED"
        );
        assert_eq!(
            AuditAction::RepositoryPermissionChanged.as_str(),
            "REPOSITORY_PERMISSION_CHANGED"
        );
    }

    #[test]
    fn test_audit_action_as_str_artifact() {
        assert_eq!(AuditAction::ArtifactUploaded.as_str(), "ARTIFACT_UPLOADED");
        assert_eq!(
            AuditAction::ArtifactDownloaded.as_str(),
            "ARTIFACT_DOWNLOADED"
        );
        assert_eq!(AuditAction::ArtifactDeleted.as_str(), "ARTIFACT_DELETED");
        assert_eq!(
            AuditAction::ArtifactMetadataUpdated.as_str(),
            "ARTIFACT_METADATA_UPDATED"
        );
    }

    #[test]
    fn test_audit_action_as_str_system() {
        assert_eq!(AuditAction::BackupStarted.as_str(), "BACKUP_STARTED");
        assert_eq!(AuditAction::BackupCompleted.as_str(), "BACKUP_COMPLETED");
        assert_eq!(AuditAction::BackupFailed.as_str(), "BACKUP_FAILED");
        assert_eq!(AuditAction::RestoreStarted.as_str(), "RESTORE_STARTED");
        assert_eq!(AuditAction::RestoreCompleted.as_str(), "RESTORE_COMPLETED");
        assert_eq!(AuditAction::RestoreFailed.as_str(), "RESTORE_FAILED");
    }

    #[test]
    fn test_audit_action_as_str_peer() {
        assert_eq!(AuditAction::PeerRegistered.as_str(), "PEER_REGISTERED");
        assert_eq!(AuditAction::PeerUnregistered.as_str(), "PEER_UNREGISTERED");
        assert_eq!(AuditAction::PeerSyncStarted.as_str(), "PEER_SYNC_STARTED");
        assert_eq!(
            AuditAction::PeerSyncCompleted.as_str(),
            "PEER_SYNC_COMPLETED"
        );
    }

    #[test]
    fn test_audit_action_as_str_configuration() {
        assert_eq!(AuditAction::SettingChanged.as_str(), "SETTING_CHANGED");
        assert_eq!(AuditAction::PluginInstalled.as_str(), "PLUGIN_INSTALLED");
        assert_eq!(
            AuditAction::PluginUninstalled.as_str(),
            "PLUGIN_UNINSTALLED"
        );
        assert_eq!(AuditAction::PluginEnabled.as_str(), "PLUGIN_ENABLED");
        assert_eq!(AuditAction::PluginDisabled.as_str(), "PLUGIN_DISABLED");
    }

    // -----------------------------------------------------------------------
    // ResourceType::as_str
    // -----------------------------------------------------------------------

    #[test]
    fn test_resource_type_as_str_all_variants() {
        assert_eq!(ResourceType::User.as_str(), "user");
        assert_eq!(ResourceType::Repository.as_str(), "repository");
        assert_eq!(ResourceType::Artifact.as_str(), "artifact");
        assert_eq!(ResourceType::Role.as_str(), "role");
        assert_eq!(ResourceType::ApiToken.as_str(), "api_token");
        assert_eq!(ResourceType::PeerInstance.as_str(), "peer_instance");
        assert_eq!(ResourceType::Backup.as_str(), "backup");
        assert_eq!(ResourceType::Setting.as_str(), "setting");
        assert_eq!(ResourceType::Plugin.as_str(), "plugin");
    }

    // -----------------------------------------------------------------------
    // AuditEntry builder
    // -----------------------------------------------------------------------

    #[test]
    fn test_audit_entry_new_defaults() {
        let entry = AuditEntry::new(AuditAction::Login, ResourceType::User);
        assert!(entry.user_id.is_none());
        assert!(entry.resource_id.is_none());
        assert!(entry.details.is_none());
        assert!(entry.ip_address.is_none());
        // correlation_id should be set (a random UUID)
        assert!(!entry.correlation_id.is_nil());
    }

    #[test]
    fn test_audit_entry_builder_user() {
        let user_id = Uuid::new_v4();
        let entry = AuditEntry::new(AuditAction::Login, ResourceType::User).user(user_id);
        assert_eq!(entry.user_id, Some(user_id));
    }

    #[test]
    fn test_audit_entry_builder_resource() {
        let resource_id = Uuid::new_v4();
        let entry = AuditEntry::new(AuditAction::ArtifactUploaded, ResourceType::Artifact)
            .resource(resource_id);
        assert_eq!(entry.resource_id, Some(resource_id));
    }

    #[test]
    fn test_audit_entry_builder_details() {
        let details = serde_json::json!({"key": "value", "count": 42});
        let entry = AuditEntry::new(AuditAction::SettingChanged, ResourceType::Setting)
            .details(details.clone());
        assert_eq!(entry.details, Some(details));
    }

    #[test]
    fn test_audit_entry_builder_ip_v4() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let entry = AuditEntry::new(AuditAction::Login, ResourceType::User).ip(ip);
        assert_eq!(entry.ip_address, Some(ip));
    }

    #[test]
    fn test_audit_entry_builder_ip_v6() {
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let entry = AuditEntry::new(AuditAction::Login, ResourceType::User).ip(ip);
        assert_eq!(entry.ip_address, Some(ip));
    }

    #[test]
    fn test_audit_entry_builder_correlation() {
        let correlation_id = Uuid::new_v4();
        let entry = AuditEntry::new(AuditAction::BackupStarted, ResourceType::Backup)
            .correlation(correlation_id);
        assert_eq!(entry.correlation_id, correlation_id);
    }

    #[test]
    fn test_audit_entry_builder_full_chain() {
        let user_id = Uuid::new_v4();
        let resource_id = Uuid::new_v4();
        let correlation_id = Uuid::new_v4();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let details = serde_json::json!({"action": "test"});

        let entry = AuditEntry::new(AuditAction::ArtifactDeleted, ResourceType::Artifact)
            .user(user_id)
            .resource(resource_id)
            .details(details.clone())
            .ip(ip)
            .correlation(correlation_id);

        assert_eq!(entry.user_id, Some(user_id));
        assert_eq!(entry.resource_id, Some(resource_id));
        assert_eq!(entry.details, Some(details));
        assert_eq!(entry.ip_address, Some(ip));
        assert_eq!(entry.correlation_id, correlation_id);
    }

    // -----------------------------------------------------------------------
    // AuditAction Debug trait
    // -----------------------------------------------------------------------

    #[test]
    fn test_audit_action_debug() {
        let debug_str = format!("{:?}", AuditAction::Login);
        assert_eq!(debug_str, "Login");
    }

    #[test]
    fn test_resource_type_debug() {
        let debug_str = format!("{:?}", ResourceType::Artifact);
        assert_eq!(debug_str, "Artifact");
    }

    // -----------------------------------------------------------------------
    // AuditLogEntry struct construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_audit_log_entry_construction() {
        let entry = AuditLogEntry {
            id: Uuid::new_v4(),
            user_id: Some(Uuid::new_v4()),
            action: "LOGIN".to_string(),
            resource_type: "user".to_string(),
            resource_id: Some(Uuid::new_v4()),
            details: Some(serde_json::json!({"ip": "127.0.0.1"})),
            ip_address: Some("127.0.0.1".to_string()),
            correlation_id: Uuid::new_v4(),
            created_at: chrono::Utc::now(),
        };
        assert_eq!(entry.action, "LOGIN");
        assert_eq!(entry.resource_type, "user");
        assert!(entry.user_id.is_some());
        assert!(entry.ip_address.is_some());
    }

    #[test]
    fn test_audit_log_entry_optional_fields_none() {
        let entry = AuditLogEntry {
            id: Uuid::new_v4(),
            user_id: None,
            action: "BACKUP_STARTED".to_string(),
            resource_type: "backup".to_string(),
            resource_id: None,
            details: None,
            ip_address: None,
            correlation_id: Uuid::new_v4(),
            created_at: chrono::Utc::now(),
        };
        assert!(entry.user_id.is_none());
        assert!(entry.resource_id.is_none());
        assert!(entry.details.is_none());
        assert!(entry.ip_address.is_none());
    }

    // -----------------------------------------------------------------------
    // AuditAction Clone + Copy
    // -----------------------------------------------------------------------

    #[test]
    fn test_audit_action_clone_copy() {
        let action = AuditAction::Login;
        let cloned = action;
        assert_eq!(action.as_str(), cloned.as_str());
    }

    #[test]
    fn test_resource_type_clone_copy() {
        let rt = ResourceType::Artifact;
        let cloned = rt;
        assert_eq!(rt.as_str(), cloned.as_str());
    }
}
