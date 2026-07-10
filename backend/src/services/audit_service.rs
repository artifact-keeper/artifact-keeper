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

    // Email subscriptions (#1170)
    EmailSubscriptionCreated,
    EmailSubscriptionDeleted,

    // SBOM operations (#1156). The SBOM endpoints emit audit trail entries
    // tied to the underlying artifact so SOC 2 / EU CRA auditors can answer
    // "who generated or fetched this attestation, and when?". `SbomRead`
    // covers both `GET /sbom/:id` and `GET /sbom/by-artifact/:artifact_id`.
    SbomGenerated,
    SbomRead,

    // Scanning / janitors
    ScanReaped,

    // Auth-event audit completeness (#386 / #1617 Phase 1). Appended at the
    // END of the enum so the additive change has no effect on the ordering of
    // existing variants and minimizes merge-conflict surface with other
    // in-flight audit-taxonomy work.
    TotpEnabled,
    TotpDisabled,
    SessionsInvalidated,

    // Age gate
    AgeGateQueued,
    AgeGateApproved,
    AgeGateRejected,

    // Authorization decisions (#2366 functional audit log). Recorded when an
    // authenticated principal is refused a privileged operation (e.g. a
    // non-admin reaching an admin-only route) so the audit trail captures
    // denials, not just successful state changes. Appended at the END of the
    // enum to keep the additive change conflict-free with in-flight taxonomy
    // work.
    PermissionDenied,
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
            AuditAction::EmailSubscriptionCreated => "EMAIL_SUBSCRIPTION_CREATED",
            AuditAction::EmailSubscriptionDeleted => "EMAIL_SUBSCRIPTION_DELETED",
            AuditAction::SbomGenerated => "SBOM_GENERATED",
            AuditAction::SbomRead => "SBOM_READ",
            AuditAction::ScanReaped => "SCAN_REAPED",
            AuditAction::TotpEnabled => "TOTP_ENABLED",
            AuditAction::TotpDisabled => "TOTP_DISABLED",
            AuditAction::SessionsInvalidated => "SESSIONS_INVALIDATED",
            AuditAction::AgeGateQueued => "AGE_GATE_QUEUED",
            AuditAction::AgeGateApproved => "AGE_GATE_APPROVED",
            AuditAction::AgeGateRejected => "AGE_GATE_REJECTED",
            AuditAction::PermissionDenied => "PERMISSION_DENIED",
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
    ScanResult,
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
            ResourceType::ScanResult => "scan_result",
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

    /// Attach an arbitrary JSON payload to this audit entry's `details` column.
    ///
    /// Reserved key: `details.actor`. System-initiated audit emitters use this
    /// to advertise themselves to SIEM filters (e.g. `"system:stuck_scan_janitor"`
    /// in #1063). To prevent an attacker who controls part of a caller's
    /// `details` payload from spoofing a system actor in the audit stream
    /// (PR #1212 audit, finding H1), we enforce the contract here rather than
    /// trusting every caller: any `"actor"` key present in the supplied
    /// `Object` is stripped before storage and the strip is logged at error
    /// level so the offending call site is visible in production logs.
    /// System emitters that legitimately need to set `details.actor` must
    /// call [`AuditEntry::system_actor`] after `.details(...)`; that
    /// method bypasses the user-input path and is the only sanctioned way
    /// to populate the field.
    pub fn details(mut self, details: serde_json::Value) -> Self {
        let sanitized = match details {
            serde_json::Value::Object(mut map) => {
                if map.remove("actor").is_some() {
                    tracing::error!(
                        "AuditEntry::details received an 'actor' key from a caller; \
                         stripping to prevent system-actor spoofing. Use \
                         AuditEntry::system_actor() for system-initiated entries."
                    );
                }
                serde_json::Value::Object(map)
            }
            other => other,
        };
        self.details = Some(sanitized);
        self
    }

    /// Set `details.actor` to a fixed system-actor label.
    ///
    /// System-initiated emitters (background janitors, periodic schedulers,
    /// internal reconciliation jobs) advertise themselves in the audit
    /// stream via `details.actor` so SIEM rules can distinguish them from
    /// human-initiated state changes keyed off `user_id`. This setter
    /// bypasses the user-input strip in [`AuditEntry::details`] and is the
    /// only sanctioned path for writing the reserved key. The supplied
    /// label is taken from a static / build-time string in the caller, not
    /// from request input.
    ///
    /// If `.details(...)` was not called first, this seeds an Object with
    /// just the actor key. If `.details(...)` was called with a non-Object
    /// value, that value is replaced (the schema requires an Object for
    /// `actor` to live in).
    pub fn system_actor(mut self, label: &'static str) -> Self {
        let mut map = match self.details.take() {
            Some(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        };
        map.insert(
            "actor".to_string(),
            serde_json::Value::String(label.to_string()),
        );
        self.details = Some(serde_json::Value::Object(map));
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

    // -----------------------------------------------------------------------
    // crate-internal accessors so batched-INSERT call sites (e.g. the
    // stuck-scan janitor in `scan_result_service`, PR #1212 audit M1) can
    // read the post-sanitization fields off a builder without going
    // through the per-row `log()` path. Read-only by design: the only way
    // to construct the underlying values is the public builder API.
    // -----------------------------------------------------------------------

    pub(crate) fn user_id(&self) -> Option<Uuid> {
        self.user_id
    }

    pub(crate) fn action(&self) -> AuditAction {
        self.action
    }

    pub(crate) fn resource_type(&self) -> ResourceType {
        self.resource_type
    }

    pub(crate) fn resource_id(&self) -> Option<Uuid> {
        self.resource_id
    }

    pub(crate) fn details_ref(&self) -> Option<&serde_json::Value> {
        self.details.as_ref()
    }

    // `ip_address` not yet used by a batched call site; kept symmetric so
    // future system emitters (e.g. periodic lifecycle scheduler) can write
    // an originating IP via the same accessor surface.
    #[allow(dead_code)]
    pub(crate) fn ip_address(&self) -> Option<IpAddr> {
        self.ip_address
    }

    pub(crate) fn correlation_id(&self) -> Uuid {
        self.correlation_id
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

/// Fire-and-forget audit write for auth-event and token-lifecycle emitters
/// (#1617 Phase 1: auth-event audit completeness).
///
/// A write failure is swallowed — logged at `warn`, never propagated — so an
/// audit-table outage can never fail the originating request. Logins and token
/// mint/revoke MUST succeed even when audit is unavailable; the audit trail is
/// a side effect, never a gate. Mirrors the `audit_auth` fire-and-forget
/// contract already used on the local-password login path.
pub async fn audit_fire_and_forget(db: PgPool, entry: AuditEntry) {
    if let Err(e) = AuditService::new(db).log(entry).await {
        tracing::warn!(error = %e, "audit log write failed; ignored (fire-and-forget)");
    }
}

/// Fire-and-forget `PermissionDenied` audit for a HANDLER-level admin gate
/// (#2321 G-AUDIT).
///
/// Handlers that enforce `require_admin()` themselves (rather than riding
/// `admin_middleware`) must still record the RBAC-deny the same way the
/// middleware does (`admin_middleware`, #2366): an authenticated non-admin
/// reaching an admin-only surface is exactly the decision an auditor wants
/// logged. Records only the attempted `path`/`method` + a fixed reason, never
/// any credential material, and is fire-and-forget so an audit-table outage can
/// never turn a clean 403 into a 500.
pub async fn audit_admin_permission_denied(
    db: PgPool,
    user_id: uuid::Uuid,
    resource_type: ResourceType,
    path: &str,
    method: &str,
) {
    let entry = AuditEntry::new(AuditAction::PermissionDenied, resource_type)
        .user(user_id)
        .resource(user_id)
        .details(serde_json::json!({
            "path": path,
            "method": method,
            "reason": "admin_privileges_required",
        }));
    audit_fire_and_forget(db, entry).await;
}

/// Handler-level admin gate that ALSO records the RBAC-deny (#2321 G3/G4/G5 +
/// G-AUDIT). Returns `Ok(())` for admins; for a non-admin, emits the
/// fire-and-forget `PermissionDenied` audit (via
/// [`audit_admin_permission_denied`]) and returns `AppError::Authorization`
/// (403) with the same message `AuthExtension::require_admin` uses. Factored so
/// each admin-only handler is a single call, keeping the deny-and-audit logic in
/// one place instead of copy-pasting the block per handler (jscpd dedup).
pub async fn enforce_admin_audited(
    is_admin: bool,
    db: PgPool,
    user_id: uuid::Uuid,
    resource_type: ResourceType,
    path: &str,
    method: &str,
) -> crate::error::Result<()> {
    if is_admin {
        return Ok(());
    }
    audit_admin_permission_denied(db, user_id, resource_type, path, method).await;
    Err(crate::error::AppError::Authorization(
        "Admin access required".to_string(),
    ))
}

/// Build the `details` JSON for a federated (SSO) login audit event.
///
/// `provider` is a stable label (`"oidc"` | `"saml"` | `"ldap"`) recorded so
/// SOC 2 / EU CRA auditors can attribute enterprise-auth events per provider.
/// Any object keys in `extra` (e.g. the attempted username on a failure) are
/// merged in; a non-object `extra` is ignored. Pure so it is unit-testable
/// without a database.
pub fn federated_login_details(provider: &str, extra: serde_json::Value) -> serde_json::Value {
    let mut details = serde_json::json!({
        "provider": provider,
        "auth_method": "federated",
    });
    if let (serde_json::Value::Object(base), serde_json::Value::Object(more)) =
        (&mut details, extra)
    {
        base.extend(more);
    }
    details
}

/// Build an audit entry for an API-token lifecycle event (mint or revoke)
/// (#1617 Phase 1).
///
/// Records the acting principal (`actor`), the token id as the resource, and
/// the token id/name/surface in `details`. The token SECRET is NEVER included.
/// `surface` labels the endpoint family (`"user"`, `"profile"`, `"repo"`,
/// `"service_account"`) for SIEM attribution. Pure builder — unit-testable.
pub fn api_token_audit_entry(
    action: AuditAction,
    actor: Uuid,
    token_id: Uuid,
    token_name: Option<&str>,
    surface: &str,
) -> AuditEntry {
    AuditEntry::new(action, ResourceType::ApiToken)
        .user(actor)
        .resource(token_id)
        .details(serde_json::json!({
            "token_id": token_id.to_string(),
            "token_name": token_name,
            "surface": surface,
        }))
}

/// Build an audit entry for a self-service or admin password change (#386 /
/// #1617 Phase 1).
///
/// `subject` is the user whose password changed (recorded as `user_id` and the
/// resource). `actor` is the principal that performed the change; it equals
/// `subject` on a self-change and is the acting admin on an admin reset. The
/// plaintext password and any hash are NEVER included. The acting principal is
/// recorded under `actor_id` (not the reserved `actor` key, which
/// [`AuditEntry::details`] strips as an anti-spoof measure). Pure builder —
/// unit-testable without a database.
pub fn password_change_audit_entry(subject: Uuid, actor: Uuid, by_admin: bool) -> AuditEntry {
    AuditEntry::new(AuditAction::PasswordChanged, ResourceType::User)
        .user(subject)
        .resource(subject)
        .details(serde_json::json!({
            "actor_id": actor.to_string(),
            "by_admin": by_admin,
        }))
}

/// Build an audit entry for a TOTP enable/disable — a self-service
/// credential-posture change (#386). `action` is [`AuditAction::TotpEnabled`]
/// or [`AuditAction::TotpDisabled`]; `subject` is the user whose 2FA changed.
/// Pure builder — unit-testable without a database.
pub fn totp_audit_entry(action: AuditAction, subject: Uuid) -> AuditEntry {
    AuditEntry::new(action, ResourceType::User)
        .user(subject)
        .resource(subject)
}

/// Build an audit entry for a mass session / refresh-token invalidation (#386).
///
/// `subject` is the user whose sessions were invalidated; `actor` is the
/// principal that triggered it (equals `subject` on a self-service change,
/// the acting admin otherwise). `trigger` is a stable static label
/// (`"totp_enable"` | `"totp_disable"` | `"password_change"` |
/// `"password_reset"` | `"force_password_change"`). Recorded under `actor_id`
/// (not the reserved `actor` key). Pure builder — unit-testable.
pub fn sessions_invalidated_audit_entry(subject: Uuid, actor: Uuid, trigger: &str) -> AuditEntry {
    AuditEntry::new(AuditAction::SessionsInvalidated, ResourceType::User)
        .user(subject)
        .resource(subject)
        .details(serde_json::json!({
            "actor_id": actor.to_string(),
            "trigger": trigger,
        }))
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
        assert_eq!(
            AuditAction::EmailSubscriptionCreated.as_str(),
            "EMAIL_SUBSCRIPTION_CREATED"
        );
        assert_eq!(
            AuditAction::EmailSubscriptionDeleted.as_str(),
            "EMAIL_SUBSCRIPTION_DELETED"
        );
        assert_eq!(AuditAction::SbomGenerated.as_str(), "SBOM_GENERATED");
        assert_eq!(AuditAction::SbomRead.as_str(), "SBOM_READ");
    }

    #[test]
    fn test_audit_action_as_str_scanning() {
        assert_eq!(AuditAction::ScanReaped.as_str(), "SCAN_REAPED");
    }

    #[test]
    fn test_audit_action_as_str_permission_denied() {
        // #2366: authorization-denial event.
        assert_eq!(AuditAction::PermissionDenied.as_str(), "PERMISSION_DENIED");
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
        assert_eq!(ResourceType::ScanResult.as_str(), "scan_result");
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

    // -----------------------------------------------------------------------
    // PR #1212 audit, finding H1: `details(...)` strips user-supplied
    // `actor` so a future call site that forwards partially user-controlled
    // JSON cannot spoof a system actor in the audit stream. `system_actor()`
    // is the only sanctioned writer of the reserved key.
    // -----------------------------------------------------------------------

    #[test]
    fn test_audit_entry_details_strips_user_supplied_actor_key() {
        let supplied = serde_json::json!({
            "actor": "system:fake_janitor",
            "subscription_id": "abc-123",
        });
        let entry =
            AuditEntry::new(AuditAction::SettingChanged, ResourceType::Setting).details(supplied);
        let details = entry.details.expect("details populated");
        let obj = details
            .as_object()
            .expect("details remains an Object after strip");
        assert!(
            !obj.contains_key("actor"),
            "details(...) must strip user-supplied actor; H1 enforcement"
        );
        assert_eq!(
            obj.get("subscription_id"),
            Some(&serde_json::Value::String("abc-123".to_string())),
            "other keys must round-trip after the strip"
        );
    }

    #[test]
    fn test_audit_entry_details_passes_non_object_values_through() {
        // Non-Object values cannot carry a key, so the strip is a no-op.
        let entry = AuditEntry::new(AuditAction::SettingChanged, ResourceType::Setting)
            .details(serde_json::json!("a scalar string"));
        assert_eq!(
            entry.details,
            Some(serde_json::Value::String("a scalar string".to_string()))
        );
    }

    #[test]
    fn test_audit_entry_details_strips_actor_even_when_only_key() {
        let entry = AuditEntry::new(AuditAction::SettingChanged, ResourceType::Setting)
            .details(serde_json::json!({"actor": "system:fake"}));
        let obj = entry
            .details
            .as_ref()
            .and_then(|v| v.as_object())
            .expect("details remains an Object after strip");
        assert!(obj.is_empty());
    }

    #[test]
    fn test_audit_entry_system_actor_sets_actor_key() {
        let entry = AuditEntry::new(AuditAction::ScanReaped, ResourceType::ScanResult)
            .details(serde_json::json!({"reason": "stuck_running_janitor"}))
            .system_actor("system:stuck_scan_janitor");
        let obj = entry
            .details
            .as_ref()
            .and_then(|v| v.as_object())
            .expect("details Object after system_actor");
        assert_eq!(
            obj.get("actor"),
            Some(&serde_json::Value::String(
                "system:stuck_scan_janitor".to_string()
            ))
        );
        assert_eq!(
            obj.get("reason"),
            Some(&serde_json::Value::String(
                "stuck_running_janitor".to_string()
            ))
        );
    }

    #[test]
    fn test_audit_entry_system_actor_seeds_object_when_no_details_set() {
        // `system_actor()` without a prior `.details(...)` still produces a
        // valid Object with just the actor; callers that have no payload
        // (e.g. heartbeat-style audit entries) get a clean shape.
        let entry = AuditEntry::new(AuditAction::ScanReaped, ResourceType::ScanResult)
            .system_actor("system:stuck_scan_janitor");
        let obj = entry
            .details
            .as_ref()
            .and_then(|v| v.as_object())
            .expect("details Object seeded by system_actor");
        assert_eq!(obj.len(), 1);
        assert_eq!(
            obj.get("actor"),
            Some(&serde_json::Value::String(
                "system:stuck_scan_janitor".to_string()
            ))
        );
    }

    #[test]
    fn test_audit_entry_system_actor_overrides_stripped_actor() {
        // A user-supplied `actor` is stripped in `.details(...)`; the
        // janitor's subsequent `.system_actor()` is the only path that
        // can write the reserved key. Composed in order, the final value
        // is exactly what `system_actor` set.
        let entry = AuditEntry::new(AuditAction::ScanReaped, ResourceType::ScanResult)
            .details(serde_json::json!({
                "actor": "spoofed:attacker",
                "reason": "stuck_running_janitor",
            }))
            .system_actor("system:stuck_scan_janitor");
        let obj = entry
            .details
            .as_ref()
            .and_then(|v| v.as_object())
            .expect("details Object");
        assert_eq!(
            obj.get("actor"),
            Some(&serde_json::Value::String(
                "system:stuck_scan_janitor".to_string()
            ))
        );
    }

    #[test]
    fn test_audit_entry_system_actor_replaces_non_object_details() {
        // If `.details(...)` was set to a scalar, `system_actor()` cannot
        // attach a key in place; the documented behaviour is to seed a
        // fresh Object so the schema is consistent.
        let entry = AuditEntry::new(AuditAction::ScanReaped, ResourceType::ScanResult)
            .details(serde_json::json!("scalar"))
            .system_actor("system:stuck_scan_janitor");
        let obj = entry
            .details
            .as_ref()
            .and_then(|v| v.as_object())
            .expect("details replaced with Object");
        assert_eq!(obj.len(), 1);
        assert_eq!(
            obj.get("actor"),
            Some(&serde_json::Value::String(
                "system:stuck_scan_janitor".to_string()
            ))
        );
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

    // -----------------------------------------------------------------------
    // #1617 Phase 1: auth-event audit helpers
    // -----------------------------------------------------------------------

    #[test]
    fn test_federated_login_details_marks_provider_and_method() {
        let details = federated_login_details("oidc", serde_json::json!({}));
        assert_eq!(details["provider"], "oidc");
        assert_eq!(details["auth_method"], "federated");
    }

    #[test]
    fn test_federated_login_details_merges_extra_object() {
        let details = federated_login_details("ldap", serde_json::json!({ "username": "alice" }));
        assert_eq!(details["provider"], "ldap");
        assert_eq!(details["username"], "alice");
    }

    #[test]
    fn test_federated_login_details_ignores_non_object_extra() {
        // A non-object `extra` must not clobber the base object.
        let details = federated_login_details("saml", serde_json::json!("nope"));
        assert_eq!(details["provider"], "saml");
        assert_eq!(details["auth_method"], "federated");
    }

    #[test]
    fn test_api_token_audit_entry_created_shape() {
        let actor = Uuid::new_v4();
        let token_id = Uuid::new_v4();
        let entry = api_token_audit_entry(
            AuditAction::ApiTokenCreated,
            actor,
            token_id,
            Some("ci-token"),
            "profile",
        );
        assert_eq!(entry.user_id(), Some(actor));
        assert_eq!(entry.resource_id(), Some(token_id));
        assert_eq!(entry.action().as_str(), "API_TOKEN_CREATED");
        assert_eq!(entry.resource_type().as_str(), "api_token");
        let details = entry.details_ref().expect("details present");
        assert_eq!(details["token_id"], token_id.to_string());
        assert_eq!(details["token_name"], "ci-token");
        assert_eq!(details["surface"], "profile");
    }

    #[test]
    fn test_api_token_audit_entry_revoked_without_name() {
        let actor = Uuid::new_v4();
        let token_id = Uuid::new_v4();
        let entry = api_token_audit_entry(
            AuditAction::ApiTokenRevoked,
            actor,
            token_id,
            None,
            "service_account",
        );
        assert_eq!(entry.action().as_str(), "API_TOKEN_REVOKED");
        let details = entry.details_ref().expect("details present");
        // A missing name serializes to JSON null, never the secret.
        assert!(details["token_name"].is_null());
        assert_eq!(details["surface"], "service_account");
    }

    #[test]
    fn test_api_token_audit_entry_never_carries_secret_key() {
        let entry = api_token_audit_entry(
            AuditAction::ApiTokenCreated,
            Uuid::new_v4(),
            Uuid::new_v4(),
            Some("t"),
            "user",
        );
        let details = entry.details_ref().expect("details present");
        let obj = details.as_object().expect("details is object");
        assert!(!obj.contains_key("token"));
        assert!(!obj.contains_key("secret"));
    }

    // -----------------------------------------------------------------------
    // #386 (#1617 Phase 1): auth-event audit completeness — new action
    // variants + pure builder helpers.
    // -----------------------------------------------------------------------

    #[test]
    fn test_audit_action_as_str_auth_event_completeness() {
        assert_eq!(AuditAction::TotpEnabled.as_str(), "TOTP_ENABLED");
        assert_eq!(AuditAction::TotpDisabled.as_str(), "TOTP_DISABLED");
        assert_eq!(
            AuditAction::SessionsInvalidated.as_str(),
            "SESSIONS_INVALIDATED"
        );
    }

    #[test]
    fn test_password_change_audit_entry_self_shape() {
        let subject = Uuid::new_v4();
        let entry = password_change_audit_entry(subject, subject, false);
        assert_eq!(entry.user_id(), Some(subject));
        assert_eq!(entry.resource_id(), Some(subject));
        assert_eq!(entry.action().as_str(), "PASSWORD_CHANGED");
        assert_eq!(entry.resource_type().as_str(), "user");
        let details = entry.details_ref().expect("details present");
        assert_eq!(details["actor_id"], subject.to_string());
        assert_eq!(details["by_admin"], false);
        let obj = details.as_object().expect("details is object");
        // The audit entry must never carry the password, a hash, or the
        // reserved (stripped) `actor` key.
        assert!(!obj.contains_key("password"));
        assert!(!obj.contains_key("hash"));
        assert!(!obj.contains_key("password_hash"));
        assert!(!obj.contains_key("actor"));
    }

    #[test]
    fn test_password_change_audit_entry_admin_records_distinct_actor() {
        let subject = Uuid::new_v4();
        let actor = Uuid::new_v4();
        let entry = password_change_audit_entry(subject, actor, true);
        assert_eq!(entry.user_id(), Some(subject));
        let details = entry.details_ref().expect("details present");
        assert_eq!(details["actor_id"], actor.to_string());
        assert_eq!(details["by_admin"], true);
    }

    #[test]
    fn test_totp_audit_entry_enable_shape() {
        let subject = Uuid::new_v4();
        let entry = totp_audit_entry(AuditAction::TotpEnabled, subject);
        assert_eq!(entry.action().as_str(), "TOTP_ENABLED");
        assert_eq!(entry.resource_type().as_str(), "user");
        assert_eq!(entry.user_id(), Some(subject));
        assert_eq!(entry.resource_id(), Some(subject));
    }

    #[test]
    fn test_totp_audit_entry_disable_shape() {
        let subject = Uuid::new_v4();
        let entry = totp_audit_entry(AuditAction::TotpDisabled, subject);
        assert_eq!(entry.action().as_str(), "TOTP_DISABLED");
        assert_eq!(entry.user_id(), Some(subject));
        assert_eq!(entry.resource_id(), Some(subject));
    }

    #[test]
    fn test_sessions_invalidated_audit_entry_shape_and_trigger_roundtrip() {
        let subject = Uuid::new_v4();
        let actor = Uuid::new_v4();
        let entry = sessions_invalidated_audit_entry(subject, actor, "password_change");
        assert_eq!(entry.action().as_str(), "SESSIONS_INVALIDATED");
        assert_eq!(entry.resource_type().as_str(), "user");
        assert_eq!(entry.user_id(), Some(subject));
        assert_eq!(entry.resource_id(), Some(subject));
        let details = entry.details_ref().expect("details present");
        assert_eq!(details["actor_id"], actor.to_string());
        assert_eq!(details["trigger"], "password_change");
        // Reserved key must not survive into the stored payload.
        assert!(!details.as_object().expect("object").contains_key("actor"));
    }

    // -----------------------------------------------------------------------
    // #2366: emit -> query round-trip against a real database. Skips cleanly
    // when `DATABASE_URL` is unset (the CI coverage job seeds Postgres, so it
    // is exercised there). Uses `user_id = None` to avoid the users FK.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_log_then_query_roundtrip_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let service = AuditService::new(pool);

        // A unique resource id keys this test's rows so parallel test processes
        // never see each other's events.
        let resource_id = Uuid::new_v4();
        let entry = AuditEntry::new(AuditAction::RepositoryCreated, ResourceType::Repository)
            .resource(resource_id)
            .details(serde_json::json!({ "key": "audit-roundtrip-test" }));
        let id = service.log(entry).await.expect("log succeeds");
        assert!(!id.is_nil());

        // Query by the unique resource id: exactly our row comes back, with the
        // action, resource type/id, and a populated timestamp.
        let (rows, total) = service
            .query(
                None,
                None,
                Some("repository"),
                Some(resource_id),
                None,
                None,
                0,
                50,
            )
            .await
            .expect("query succeeds");
        assert_eq!(total, 1, "exactly one event for the unique resource id");
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.action, "REPOSITORY_CREATED");
        assert_eq!(row.resource_type, "repository");
        assert_eq!(row.resource_id, Some(resource_id));
        assert_eq!(row.details.as_ref().unwrap()["key"], "audit-roundtrip-test");

        // A non-matching action filter excludes the row (filter is applied).
        let (rows2, total2) = service
            .query(
                None,
                Some("LOGIN"),
                None,
                Some(resource_id),
                None,
                None,
                0,
                50,
            )
            .await
            .expect("query succeeds");
        assert_eq!(total2, 0);
        assert!(rows2.is_empty());

        // Cleanup our row so the table does not accrete across test runs.
        // Runtime (non-macro) query so no offline `.sqlx` prepare is needed.
        let _ = sqlx::query("DELETE FROM audit_log WHERE resource_id = $1")
            .bind(resource_id)
            .execute(&service.db)
            .await;
    }
}
