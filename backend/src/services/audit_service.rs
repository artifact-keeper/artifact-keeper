//! Audit logging service.
//!
//! Tracks all significant actions in the system for compliance and debugging.

use sqlx::PgPool;
use std::net::IpAddr;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::services::audit_export::{self, Outcome};

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

    // Curation/RPM manual sync trigger (#2357). Recorded when an authorized
    // principal manually triggers an upstream metadata sync for a repository
    // via `POST /curation/repos/{key}/sync`, capturing who initiated an
    // outbound sync and when. Appended at the END of the enum to keep the
    // additive change conflict-free with in-flight taxonomy work.
    CurationSyncTriggered,

    // Curated RPM snapshot publish (#2358 — RPM Phase-3). `CurationVersionCreated`
    // is recorded when an authorized principal freezes the approved curation set
    // into a new immutable `repository_version`; `CurationVersionPublished` when
    // that version's signed repodata is generated and served under `/rpm/{key}/@N/`.
    // Both capture repo_key + version_number + package_count only (no upstream
    // secrets). Appended at the END of the enum to keep the additive change
    // conflict-free with in-flight taxonomy work.
    CurationVersionCreated,
    CurationVersionPublished,
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
            AuditAction::CurationSyncTriggered => "CURATION_SYNC_TRIGGERED",
            AuditAction::CurationVersionCreated => "CURATION_VERSION_CREATED",
            AuditAction::CurationVersionPublished => "CURATION_VERSION_PUBLISHED",
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
    /// Client-minted event id (#2413). Passed explicitly to the INSERT so the
    /// exported stream record and the DB row share one id — the SIEM ↔
    /// admin-API join key — and so a record can be emitted even when the row
    /// write fails.
    event_id: Uuid,
    user_id: Option<Uuid>,
    action: AuditAction,
    resource_type: ResourceType,
    resource_id: Option<Uuid>,
    /// Best-effort resource name for the export envelope (#2413); never stored
    /// in the DB row.
    resource_name: Option<String>,
    details: Option<serde_json::Value>,
    ip_address: Option<IpAddr>,
    correlation_id: String,
    /// Best-effort actor display name for the export envelope (#2413); populated
    /// where the handler already has it, never via a query-time join. Not stored
    /// in the DB row (the admin API joins `users` at query time, #2392).
    actor_name: Option<String>,
    /// Optional explicit outcome for the export envelope (#2413). When unset the
    /// outcome is derived from the action name. Not stored in the DB row.
    outcome_override: Option<Outcome>,
    /// Export-envelope actor-id override (#2413) for entries whose DB `user_id`
    /// deliberately records a different principal (the subject-keyed password /
    /// session events). Not stored in the DB row.
    actor_id_override: Option<Uuid>,
}

/// Central sanitation for the free-form compatibility payload: the anti-spoof
/// `actor` strip, normalization of legacy scalar payloads, and recursive
/// redaction of known secret-bearing keys — the last line of defense before a
/// `details` value reaches the DB row or the export stream. Size-bounding of
/// the exported copy lives in [`crate::services::audit_export`]; the DB row
/// always keeps the full (sanitized) payload.
const AUDIT_LABEL_MAX_BYTES: usize = 4096;
const AUDIT_REDACTED_VALUE: &str = "[REDACTED]";

fn clamp_audit_label(value: impl Into<String>) -> String {
    let mut value = value.into();
    if value.len() <= AUDIT_LABEL_MAX_BYTES {
        return value;
    }
    let mut end = AUDIT_LABEL_MAX_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    value
}

fn audit_detail_key_is_sensitive(key: &str) -> bool {
    let normalized = key.trim().to_ascii_lowercase().replace('-', "_");
    matches!(
        normalized.as_str(),
        "authorization"
            | "proxy_authorization"
            | "cookie"
            | "set_cookie"
            | "password"
            | "password_hash"
            | "current_password"
            | "new_password"
            | "old_password"
            | "secret"
            | "client_secret"
            | "credential"
            | "credentials"
            | "token"
            | "access_token"
            | "refresh_token"
            | "id_token"
            | "totp_token"
            | "totp_secret"
            | "api_key"
            | "private_key"
            | "saml_response"
            | "upstream_password"
    )
}

fn redact_audit_detail_secrets(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                if audit_detail_key_is_sensitive(key) {
                    *child = serde_json::Value::String(AUDIT_REDACTED_VALUE.to_owned());
                } else {
                    redact_audit_detail_secrets(child);
                }
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                redact_audit_detail_secrets(child);
            }
        }
        _ => {}
    }
}

fn sanitize_audit_details(mut details: serde_json::Value) -> serde_json::Value {
    if let serde_json::Value::Object(map) = &mut details {
        if map.remove("actor").is_some() {
            tracing::error!(
                "AuditEntry::details received an 'actor' key from a caller; \
                 stripping to prevent system-actor spoofing. Use \
                 AuditEntry::system_actor() for system-initiated entries."
            );
        }
    }

    // The published envelope permits `details` as object|null. Preserve legacy
    // scalar/array payloads under a stable object key instead of emitting a
    // schema-invalid record.
    if !details.is_object() && !details.is_null() {
        details = serde_json::json!({ "value": details });
    }

    redact_audit_detail_secrets(&mut details);
    details
}

impl AuditEntry {
    /// Start building an audit entry.
    ///
    /// The correlation ID defaults to the in-flight request's correlation ID
    /// (#2414) — the value `correlation_id_middleware` resolved from
    /// `X-Correlation-ID` / `traceparent` (or generated), stamped on the
    /// request span, and echoes to the caller — so every event emitted while
    /// handling one request shares the ID an operator can join against
    /// request logs and traces. Outside a request scope (background jobs,
    /// startup, detached tasks) a fresh UUID is generated, preserving the
    /// previous behavior; jobs that emit several related events should group
    /// them under one explicit [`AuditEntry::correlation`] value per logical
    /// operation.
    pub fn new(action: AuditAction, resource_type: ResourceType) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            user_id: None,
            action,
            resource_type,
            resource_id: None,
            resource_name: None,
            details: None,
            ip_address: None,
            correlation_id: crate::api::middleware::tracing::current_correlation_id()
                .map(crate::api::middleware::tracing::CorrelationId::into_string)
                .unwrap_or_else(|| Uuid::new_v4().to_string()),
            actor_name: None,
            outcome_override: None,
            actor_id_override: None,
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
        self.details = Some(sanitize_audit_details(details));
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
    /// If `.details(...)` was not called first, this seeds an Object with just
    /// the actor key. Legacy scalar/array payloads have already been normalized
    /// under `details.value`, so they remain intact when this label is added.
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

    /// Attach a best-effort actor display name for the export envelope (#2413).
    ///
    /// Populate this where the handler already has the acting principal's name
    /// in hand (login, token, repository, role handlers). It is emitted as
    /// `actor.name` in the audit stream and is NOT written to the DB row — the
    /// admin API still joins `users` at query time (#2392). Absent, `actor.name`
    /// serializes to `null`.
    pub fn actor_name(mut self, name: impl Into<String>) -> Self {
        self.actor_name = Some(clamp_audit_label(name));
        self
    }

    /// Attach a best-effort resource name for the export envelope (#2413).
    ///
    /// Emitted as `resource.name` in the audit stream; not stored in the DB row.
    pub fn resource_name(mut self, name: impl Into<String>) -> Self {
        self.resource_name = Some(clamp_audit_label(name));
        self
    }

    /// Override the exported outcome (#2413). Unset, the outcome is derived from
    /// the action name ([`AuditAction::outcome`](crate::services::audit_export)).
    /// For future emitters that record one action with variable outcomes.
    pub fn outcome(mut self, outcome: Outcome) -> Self {
        self.outcome_override = Some(outcome);
        self
    }

    /// Override the export envelope's `actor.id` (#2413) where the DB row's
    /// `user_id` deliberately records a different principal — the subject-keyed
    /// password / session events, whose column semantics predate the export and
    /// must not change underneath existing consumers. Envelope-only: the DB
    /// row, the admin API, and its `user_id` filter are unaffected. Unset,
    /// `actor.id` is `user_id`.
    pub fn actor_id(mut self, actor_id: Uuid) -> Self {
        self.actor_id_override = Some(actor_id);
        self
    }

    /// Attach a typed detail payload (#2413), serialized into the existing
    /// `details` column through the same anti-spoof sanitization as
    /// [`AuditEntry::details`]. The typed structs in
    /// [`crate::services::audit_export`] anchor the published JSON Schema for
    /// the representative security-lifecycle events.
    ///
    /// A serialization failure (not expected for the plain detail structs)
    /// leaves `details` unchanged and logs at error level rather than dropping
    /// the whole audit entry.
    pub fn details_typed<T: serde::Serialize>(self, payload: T) -> Self {
        match serde_json::to_value(payload) {
            Ok(value) => self.details(value),
            Err(e) => {
                tracing::error!(error = %e, "failed to serialize typed audit details; leaving details unset");
                self
            }
        }
    }

    /// Override the correlation ID (#2414: a string — caller-supplied header
    /// values and W3C trace IDs are not UUIDs). Background jobs use this to
    /// group all events of one logical operation under one generated value.
    /// Clamped to `CORRELATION_ID_MAX_BYTES` like every other correlation
    /// path — copying only the bounded prefix — so no builder input can
    /// violate the audit_log length CHECK and fail the (fire-and-forget)
    /// audit write.
    pub fn correlation(mut self, correlation_id: impl AsRef<str>) -> Self {
        self.correlation_id =
            crate::api::middleware::tracing::clamp_correlation_value(correlation_id.as_ref())
                .to_owned();
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

    pub(crate) fn ip_address(&self) -> Option<IpAddr> {
        self.ip_address
    }

    pub(crate) fn correlation_id(&self) -> &str {
        &self.correlation_id
    }

    /// The client-minted event id (#2413), shared with the DB row.
    pub(crate) fn event_id(&self) -> Uuid {
        self.event_id
    }

    /// Best-effort actor display name for the export envelope (#2413).
    /// Named `_ref` to avoid colliding with the [`AuditEntry::actor_name`]
    /// builder setter of the same base name.
    pub(crate) fn actor_name_ref(&self) -> Option<&str> {
        self.actor_name.as_deref()
    }

    /// Best-effort resource name for the export envelope (#2413).
    /// Named `_ref` to avoid colliding with the [`AuditEntry::resource_name`]
    /// builder setter of the same base name.
    pub(crate) fn resource_name_ref(&self) -> Option<&str> {
        self.resource_name.as_deref()
    }

    /// Explicit outcome override for the export envelope (#2413), if set.
    pub(crate) fn outcome_override(&self) -> Option<Outcome> {
        self.outcome_override
    }

    /// Export-envelope actor-id override (#2413), if set. Named `_override` to
    /// avoid colliding with the [`AuditEntry::actor_id`] builder setter.
    pub(crate) fn actor_id_override(&self) -> Option<Uuid> {
        self.actor_id_override
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

    /// Log an audit entry.
    ///
    /// Emits the structured export record (#2413) to the audit stream BEFORE
    /// the row INSERT and regardless of its outcome: the stdout stream is the
    /// SIEM-availability story, so a DB outage (or the fire-and-forget swallow
    /// path) must not also lose the SIEM copy. The `id` is minted client-side
    /// ([`AuditEntry::new`]) and passed explicitly to the INSERT so the exported
    /// record and the DB row share one id. When the stream is off (the default)
    /// the emit is a cheap no-op — the export record is never even constructed,
    /// so existing deployments pay one sink check and nothing more.
    ///
    /// Runtime (non-macro) query so the #2414 `correlation_id` type change
    /// (UUID -> TEXT) needs no offline `.sqlx` prepare, matching the pattern
    /// [`AuditService::query`] already uses; the #2413 change only adds the `id`
    /// column to this INSERT's column list.
    pub async fn log(&self, entry: AuditEntry) -> Result<Uuid> {
        audit_export::emit_entry(&entry);

        let id = entry.event_id;
        sqlx::query(
            r#"
            INSERT INTO audit_log (id, user_id, action, resource_type, resource_id, details, ip_address, correlation_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(id)
        .bind(entry.user_id)
        .bind(entry.action.as_str())
        .bind(entry.resource_type.as_str())
        .bind(entry.resource_id)
        .bind(entry.details)
        .bind(entry.ip_address.map(|ip| ip.to_string()))
        .bind(entry.correlation_id)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(id)
    }

    /// Query audit logs, with each row joined to its actor's username (#2392).
    ///
    /// A `LEFT JOIN` on `users` embeds `actor_username` without ever dropping
    /// an audit row: system events (`user_id` NULL) and events whose acting
    /// user has since been deleted come back with `actor_username = None`.
    /// `correlation_id` is an exact-match filter (#2414) served by
    /// `idx_audit_log_correlation`. Runtime (non-macro) queries so no offline
    /// `.sqlx` prepare is needed.
    #[allow(clippy::too_many_arguments)]
    pub async fn query(
        &self,
        user_id: Option<Uuid>,
        action: Option<&str>,
        resource_type: Option<&str>,
        resource_id: Option<Uuid>,
        correlation_id: Option<&str>,
        from: Option<chrono::DateTime<chrono::Utc>>,
        to: Option<chrono::DateTime<chrono::Utc>>,
        offset: i64,
        limit: i64,
    ) -> Result<(Vec<AuditLogEntryWithActor>, i64)> {
        let entries = sqlx::query_as::<_, AuditLogEntryWithActor>(
            r#"
            SELECT
                a.id, a.user_id, a.action, a.resource_type, a.resource_id,
                a.details, a.ip_address, a.correlation_id, a.created_at,
                u.username AS actor_username
            FROM audit_log a
            LEFT JOIN users u ON u.id = a.user_id
            WHERE ($1::uuid IS NULL OR a.user_id = $1)
              AND ($2::text IS NULL OR a.action = $2)
              AND ($3::text IS NULL OR a.resource_type = $3)
              AND ($4::uuid IS NULL OR a.resource_id = $4)
              AND ($5::text IS NULL OR a.correlation_id = $5)
              AND ($6::timestamptz IS NULL OR a.created_at >= $6)
              AND ($7::timestamptz IS NULL OR a.created_at <= $7)
            ORDER BY a.created_at DESC
            OFFSET $8
            LIMIT $9
            "#,
        )
        .bind(user_id)
        .bind(action)
        .bind(resource_type)
        .bind(resource_id)
        .bind(correlation_id)
        .bind(from)
        .bind(to)
        .bind(offset)
        .bind(limit)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let total: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM audit_log
            WHERE ($1::uuid IS NULL OR user_id = $1)
              AND ($2::text IS NULL OR action = $2)
              AND ($3::text IS NULL OR resource_type = $3)
              AND ($4::uuid IS NULL OR resource_id = $4)
              AND ($5::text IS NULL OR correlation_id = $5)
              AND ($6::timestamptz IS NULL OR created_at >= $6)
              AND ($7::timestamptz IS NULL OR created_at <= $7)
            "#,
        )
        .bind(user_id)
        .bind(action)
        .bind(resource_type)
        .bind(resource_id)
        .bind(correlation_id)
        .bind(from)
        .bind(to)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok((entries, total))
    }

    /// Get audit logs for a specific resource.
    ///
    /// Runtime (non-macro) query so the #2414 `correlation_id` type change
    /// needs no offline `.sqlx` prepare.
    pub async fn get_resource_history(
        &self,
        resource_type: ResourceType,
        resource_id: Uuid,
        limit: i64,
    ) -> Result<Vec<AuditLogEntry>> {
        let entries = sqlx::query_as::<_, AuditLogEntry>(
            r#"
            SELECT
                id, user_id, action, resource_type, resource_id,
                details, ip_address, correlation_id, created_at
            FROM audit_log
            WHERE resource_type = $1 AND resource_id = $2
            ORDER BY created_at DESC
            LIMIT $3
            "#,
        )
        .bind(resource_type.as_str())
        .bind(resource_id)
        .bind(limit)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(entries)
    }

    /// Get audit logs by correlation ID (for tracking related actions).
    ///
    /// `correlation_id` is a string (#2414): caller-supplied header values,
    /// W3C trace IDs, or generated UUIDs. Runtime (non-macro) query so the
    /// type change needs no offline `.sqlx` prepare.
    pub async fn get_by_correlation(&self, correlation_id: &str) -> Result<Vec<AuditLogEntry>> {
        let entries = sqlx::query_as::<_, AuditLogEntry>(
            r#"
            SELECT
                id, user_id, action, resource_type, resource_id,
                details, ip_address, correlation_id, created_at
            FROM audit_log
            WHERE correlation_id = $1
            ORDER BY created_at
            "#,
        )
        .bind(correlation_id)
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
        .details_typed(audit_export::details::AuthDetails::permission_denied(
            path,
            method,
            "admin_privileges_required",
        ));
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
    // Typed payload (#2413): `TokenDetails` has no secret field, so the token
    // secret cannot leak into the audit stream by construction, and the shape is
    // pinned by the published schema.
    AuditEntry::new(action, ResourceType::ApiToken)
        .user(actor)
        .resource(token_id)
        .details_typed(audit_export::details::TokenDetails::new(
            token_id, token_name, surface,
        ))
}

/// Build an audit entry for a self-service or admin password change (#386 /
/// #1617 Phase 1).
///
/// `subject` is the user whose password changed (recorded as `user_id` and the
/// resource — the established column semantics, unchanged by #2413). `actor` is
/// the principal that performed the change; it equals `subject` on a
/// self-change and is the acting admin on an admin reset. It is recorded under
/// `details.actor_id` (not the reserved `actor` key, which
/// [`AuditEntry::details`] strips as an anti-spoof measure) and exported as the
/// envelope's `actor.id` via the envelope-only [`AuditEntry::actor_id`]
/// override. The plaintext password and any hash are NEVER included. Pure
/// builder — unit-testable without a database.
pub fn password_change_audit_entry(subject: Uuid, actor: Uuid, by_admin: bool) -> AuditEntry {
    AuditEntry::new(AuditAction::PasswordChanged, ResourceType::User)
        .user(subject)
        .actor_id(actor)
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
/// `subject` is the user whose sessions were invalidated (recorded as
/// `user_id` and the resource — the established column semantics, unchanged by
/// #2413); `actor` is the principal that triggered it (equals `subject` on a
/// self-service change, the acting admin otherwise), recorded under
/// `details.actor_id` and exported as the envelope's `actor.id` via the
/// envelope-only [`AuditEntry::actor_id`] override. `trigger` is a stable
/// static label (`"totp_enable"` | `"totp_disable"` | `"password_change"` |
/// `"password_reset"` | `"force_password_change"`). Pure builder.
pub fn sessions_invalidated_audit_entry(subject: Uuid, actor: Uuid, trigger: &str) -> AuditEntry {
    AuditEntry::new(AuditAction::SessionsInvalidated, ResourceType::User)
        .user(subject)
        .actor_id(actor)
        .resource(subject)
        .details(serde_json::json!({
            "actor_id": actor.to_string(),
            "trigger": trigger,
        }))
}

/// Audit log entry from database
#[derive(Debug, sqlx::FromRow)]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<Uuid>,
    pub details: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub correlation_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Audit log entry joined with the actor's username (#2392).
///
/// Returned by [`AuditService::query`] so the admin audit endpoint can render
/// actors without a client-side join against `/admin/users`. `actor_username`
/// is `None` for system events (no `user_id`) and for events whose acting
/// user has since been deleted (`audit_log.user_id` is `ON DELETE SET NULL`);
/// the row itself is always preserved.
#[derive(Debug, sqlx::FromRow)]
pub struct AuditLogEntryWithActor {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<Uuid>,
    pub details: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub correlation_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub actor_username: Option<String>,
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
        // Outside a request scope the correlation_id falls back to a
        // generated UUID (#2414 preserves the pre-existing behavior here).
        assert!(Uuid::parse_str(&entry.correlation_id).is_ok());
    }

    /// #2414: inside a correlation scope (what `correlation_id_middleware`
    /// establishes per request), `new()` inherits the scoped ID instead of
    /// generating one.
    #[tokio::test]
    async fn test_audit_entry_new_inherits_scoped_correlation() {
        use crate::api::middleware::tracing::{with_correlation_scope, CorrelationId};
        let entry = with_correlation_scope(CorrelationId::new("scoped-audit-correlation"), async {
            AuditEntry::new(AuditAction::Login, ResourceType::User)
        })
        .await;
        assert_eq!(entry.correlation_id, "scoped-audit-correlation");
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
    fn test_audit_entry_details_wraps_non_object_values() {
        // The envelope contract requires an object/null details value.
        let entry = AuditEntry::new(AuditAction::SettingChanged, ResourceType::Setting)
            .details(serde_json::json!("a scalar string"));
        assert_eq!(entry.details.unwrap()["value"], "a scalar string");
    }

    #[test]
    fn test_audit_entry_details_recursively_redacts_secret_keys() {
        let entry = AuditEntry::new(AuditAction::SettingChanged, ResourceType::Setting).details(
            serde_json::json!({
                "password": "hunter2",
                "nested": {
                    "Authorization": "Bearer secret",
                    "token_name": "safe metadata"
                },
                "items": [{"client-secret": "secret-value"}]
            }),
        );
        let details = entry.details.unwrap();
        assert_eq!(details["password"], AUDIT_REDACTED_VALUE);
        assert_eq!(details["nested"]["Authorization"], AUDIT_REDACTED_VALUE);
        assert_eq!(details["nested"]["token_name"], "safe metadata");
        assert_eq!(details["items"][0]["client-secret"], AUDIT_REDACTED_VALUE);
    }

    #[test]
    fn test_audit_entry_details_keeps_oversized_payload_for_the_db_row() {
        // Size-bounding applies only to the exported copy (see audit_export's
        // `bounded_details_for_export`); the stored details must never lose
        // data to an export concern.
        let big = "x".repeat(70_000);
        let entry = AuditEntry::new(AuditAction::SettingChanged, ResourceType::Setting)
            .details(serde_json::json!({"value": big}));
        let details = entry.details.unwrap();
        assert_eq!(details["value"].as_str().unwrap().len(), 70_000);
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
    fn test_audit_entry_system_actor_preserves_wrapped_scalar_details() {
        let entry = AuditEntry::new(AuditAction::ScanReaped, ResourceType::ScanResult)
            .details(serde_json::json!("scalar"))
            .system_actor("system:stuck_scan_janitor");
        let obj = entry
            .details
            .as_ref()
            .and_then(|v| v.as_object())
            .expect("details normalized to Object");
        assert_eq!(obj.len(), 2);
        assert_eq!(obj.get("value"), Some(&serde_json::json!("scalar")));
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
        // #2414: correlation IDs are strings — caller-supplied header values
        // and W3C trace IDs, not just UUIDs.
        let entry = AuditEntry::new(AuditAction::BackupStarted, ResourceType::Backup)
            .correlation("caller-supplied-correlation");
        assert_eq!(entry.correlation_id, "caller-supplied-correlation");
    }

    #[test]
    fn test_audit_entry_builder_full_chain() {
        let user_id = Uuid::new_v4();
        let resource_id = Uuid::new_v4();
        let correlation_id = "full-chain-correlation".to_string();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let details = serde_json::json!({"action": "test"});

        let entry = AuditEntry::new(AuditAction::ArtifactDeleted, ResourceType::Artifact)
            .user(user_id)
            .resource(resource_id)
            .details(details.clone())
            .ip(ip)
            .correlation(correlation_id.clone());

        assert_eq!(entry.user_id, Some(user_id));
        assert_eq!(entry.resource_id, Some(resource_id));
        assert_eq!(entry.details, Some(details));
        assert_eq!(entry.ip_address, Some(ip));
        assert_eq!(entry.correlation_id, correlation_id);
    }

    // -----------------------------------------------------------------------
    // #2413: export-envelope builder fields (event_id, actor_name,
    // resource_name, outcome override, typed details).
    // -----------------------------------------------------------------------

    #[test]
    fn test_audit_entry_mints_unique_event_id() {
        let a = AuditEntry::new(AuditAction::Login, ResourceType::User);
        let b = AuditEntry::new(AuditAction::Login, ResourceType::User);
        assert!(!a.event_id().is_nil());
        assert_ne!(a.event_id(), b.event_id(), "each entry gets a fresh id");
    }

    #[test]
    fn test_audit_entry_actor_and_resource_name_builders() {
        let entry = AuditEntry::new(AuditAction::RepositoryCreated, ResourceType::Repository)
            .actor_name("alice")
            .resource_name("maven-releases");
        assert_eq!(entry.actor_name_ref(), Some("alice"));
        assert_eq!(entry.resource_name_ref(), Some("maven-releases"));
    }

    #[test]
    fn test_audit_entry_labels_are_bounded_on_utf8_boundary() {
        let oversized = "é".repeat(AUDIT_LABEL_MAX_BYTES);
        let entry = AuditEntry::new(AuditAction::RepositoryCreated, ResourceType::Repository)
            .actor_name(&oversized)
            .resource_name(&oversized);
        for value in [
            entry.actor_name_ref().unwrap(),
            entry.resource_name_ref().unwrap(),
        ] {
            assert!(value.len() <= AUDIT_LABEL_MAX_BYTES);
            assert!(value.is_char_boundary(value.len()));
        }
    }

    #[test]
    fn test_audit_entry_outcome_override_builder() {
        let entry =
            AuditEntry::new(AuditAction::Login, ResourceType::User).outcome(Outcome::Failure);
        assert_eq!(entry.outcome_override(), Some(Outcome::Failure));
        // Unset by default.
        let plain = AuditEntry::new(AuditAction::Login, ResourceType::User);
        assert_eq!(plain.outcome_override(), None);
    }

    #[test]
    fn test_audit_entry_details_typed_serializes_and_sanitizes() {
        #[derive(serde::Serialize)]
        struct Payload {
            key: &'static str,
            actor: &'static str,
        }
        // The typed path routes through `details(...)`, so the reserved `actor`
        // key is still stripped (anti-spoof).
        let entry = AuditEntry::new(AuditAction::SettingChanged, ResourceType::Setting)
            .details_typed(Payload {
                key: "maven-releases",
                actor: "spoof",
            });
        let details = entry.details_ref().expect("details present");
        let obj = details.as_object().unwrap();
        assert_eq!(obj.get("key").unwrap(), "maven-releases");
        assert!(!obj.contains_key("actor"), "typed details still sanitized");
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
            correlation_id: Uuid::new_v4().to_string(),
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
            correlation_id: Uuid::new_v4().to_string(),
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
        // DB column semantics unchanged by #2413: `user_id` stays the subject;
        // the initiator rides the envelope-only override and details.actor_id.
        assert_eq!(entry.user_id(), Some(subject));
        assert_eq!(entry.actor_id_override(), Some(actor));
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
        // DB column semantics unchanged by #2413 (see password-change test).
        assert_eq!(entry.user_id(), Some(subject));
        assert_eq!(entry.actor_id_override(), Some(actor));
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
        // No acting user on this event -> no embedded actor username (#2392).
        assert_eq!(row.actor_username, None);

        // A non-matching action filter excludes the row (filter is applied).
        let (rows2, total2) = service
            .query(
                None,
                Some("LOGIN"),
                None,
                Some(resource_id),
                None,
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

    // -----------------------------------------------------------------------
    // #2413: the exported stream record shares the DB row's id (the SIEM ↔
    // admin-API join key) and is emitted even when the DB write fails.
    // -----------------------------------------------------------------------

    /// The emitted record's `event_id` equals the `audit_log` row id, so a SIEM
    /// can join a stream event back to `GET /api/v1/admin/audit`. Requires a DB.
    #[tokio::test]
    async fn test_log_emits_record_sharing_event_id_with_db_row() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::audit_export::test_sink;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (buffer, _guard) = test_sink::install();
        let service = AuditService::new(pool);

        let resource_id = Uuid::new_v4();
        let corr = format!("emit-join-{}", Uuid::new_v4());
        let entry = AuditEntry::new(AuditAction::RepositoryDeleted, ResourceType::Repository)
            .resource(resource_id)
            .correlation(&corr)
            .actor_name("bob");
        let id = service.log(entry).await.expect("log succeeds");

        let mine: Vec<_> = buffer
            .records()
            .into_iter()
            .filter(|r| r["correlation_id"] == corr)
            .collect();
        assert_eq!(mine.len(), 1, "exactly one stream record for this event");
        assert_eq!(mine[0]["event_id"], id.to_string());
        assert_eq!(mine[0]["actor"]["name"], "bob");

        // The DB row carries the same id the record advertised.
        let (rows, _) = service
            .query(
                None,
                None,
                Some("repository"),
                Some(resource_id),
                None,
                None,
                None,
                0,
                10,
            )
            .await
            .expect("query succeeds");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, id);

        let _ = sqlx::query("DELETE FROM audit_log WHERE resource_id = $1")
            .bind(resource_id)
            .execute(&service.db)
            .await;
    }

    /// A DB-write failure must not also lose the SIEM copy: emission happens
    /// before the INSERT, so an unreachable pool still yields the stream record.
    /// Needs no database (the pool is lazy and never connects).
    #[tokio::test]
    async fn test_log_emits_record_even_when_db_write_fails() {
        use crate::services::audit_export::test_sink;
        use sqlx::postgres::PgPoolOptions;

        let (buffer, _guard) = test_sink::install();
        // Lazy pool to an unreachable address: connect_lazy never blocks; the
        // execute() inside log() is what fails.
        let pool = PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(250))
            .connect_lazy("postgres://u:p@127.0.0.1:1/none")
            .expect("lazy pool builds");
        let service = AuditService::new(pool);

        let corr = format!("db-down-{}", Uuid::new_v4());
        let entry =
            AuditEntry::new(AuditAction::LoginFailed, ResourceType::User).correlation(&corr);
        let event_id = entry.event_id();
        let result = service.log(entry).await;
        assert!(result.is_err(), "write fails against an unreachable pool");

        let mine: Vec<_> = buffer
            .records()
            .into_iter()
            .filter(|r| r["correlation_id"] == corr)
            .collect();
        assert_eq!(mine.len(), 1, "record emitted despite DB failure");
        assert_eq!(mine[0]["event_id"], event_id.to_string());
        assert_eq!(mine[0]["outcome"], "failure");
    }

    // -----------------------------------------------------------------------
    // #2392: the query embeds the actor's username via LEFT JOIN users —
    // present for a known user, NULL for system events, and NULL (row kept)
    // once the acting user is deleted.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_query_embeds_actor_username_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let service = AuditService::new(pool.clone());

        // Two events under one unique resource id: one by the known user, one
        // with no actor (system-style event).
        let resource_id = Uuid::new_v4();
        service
            .log(
                AuditEntry::new(AuditAction::RepositoryUpdated, ResourceType::Repository)
                    .user(user_id)
                    .resource(resource_id),
            )
            .await
            .expect("log user-actor event");
        service
            .log(
                AuditEntry::new(AuditAction::RepositoryCreated, ResourceType::Repository)
                    .resource(resource_id),
            )
            .await
            .expect("log system event");

        let (rows, total) = service
            .query(None, None, None, Some(resource_id), None, None, None, 0, 50)
            .await
            .expect("query succeeds");
        assert_eq!(total, 2);
        let user_row = rows
            .iter()
            .find(|r| r.user_id == Some(user_id))
            .expect("user-actor row present");
        assert_eq!(
            user_row.actor_username.as_deref(),
            Some(username.as_str()),
            "known actor's username is embedded"
        );
        let system_row = rows
            .iter()
            .find(|r| r.user_id.is_none())
            .expect("system row present");
        assert_eq!(system_row.actor_username, None, "system actor has no name");

        // Delete the acting user: the audit rows must survive (FK is
        // ON DELETE SET NULL) with the username now unresolvable -> NULL.
        tdh::cleanup_user(&pool, user_id).await;
        let (rows_after, total_after) = service
            .query(None, None, None, Some(resource_id), None, None, None, 0, 50)
            .await
            .expect("query after actor deletion succeeds");
        assert_eq!(total_after, 2, "rows survive actor deletion");
        assert!(
            rows_after.iter().all(|r| r.actor_username.is_none()),
            "deleted actor resolves to NULL username"
        );

        let _ = sqlx::query("DELETE FROM audit_log WHERE resource_id = $1")
            .bind(resource_id)
            .execute(&service.db)
            .await;
    }

    // -----------------------------------------------------------------------
    // #2414: end-to-end request → audit-row correlation contract. A request
    // carrying `X-Correlation-ID` is driven through the real
    // `correlation_id_middleware` into a handler that logs audit entries the
    // way production emitters do; the STORED rows must carry the caller's
    // exact value (which is a string, not a UUID) and all rows from one
    // request must share it.
    // -----------------------------------------------------------------------

    /// Logs two audit entries tagged with the test's unique resource id,
    /// mirroring a production handler that audits twice in one request.
    async fn double_audit_handler(
        axum::extract::State((pool, resource_id)): axum::extract::State<(PgPool, Uuid)>,
    ) -> &'static str {
        let service = AuditService::new(pool);
        service
            .log(
                AuditEntry::new(AuditAction::RepositoryCreated, ResourceType::Repository)
                    .resource(resource_id),
            )
            .await
            .expect("first audit write succeeds");
        service
            .log(
                AuditEntry::new(AuditAction::RepositoryUpdated, ResourceType::Repository)
                    .resource(resource_id),
            )
            .await
            .expect("second audit write succeeds");
        "ok"
    }

    /// Fetches the stored correlation values for the test's rows as text.
    /// The `::text` cast reads identically whether the column is the legacy
    /// UUID type or the #2414 TEXT type, so this test compiles and runs
    /// against both schemas — red before the fix, green after.
    async fn stored_correlations(pool: &PgPool, resource_id: Uuid) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT correlation_id::text FROM audit_log \
             WHERE resource_id = $1 ORDER BY created_at, id",
        )
        .bind(resource_id)
        .fetch_all(pool)
        .await
        .expect("read stored correlation ids")
    }

    #[tokio::test]
    async fn request_correlation_id_round_trips_into_stored_audit_rows_db() {
        use crate::api::middleware::tracing::{correlation_id_middleware, CORRELATION_ID_HEADER};
        use axum::{body::Body, http::Request, middleware, routing::post, Router};
        use tower::ServiceExt;

        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let resource_id = Uuid::new_v4();
        let app = Router::new()
            .route("/audited-op", post(double_audit_handler))
            .with_state((pool.clone(), resource_id))
            .layer(middleware::from_fn(correlation_id_middleware));

        let supplied = format!("audit-correlation-test-{}", resource_id.as_simple());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/audited-op")
                    .header(CORRELATION_ID_HEADER, &supplied)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("audited request");
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let stored = stored_correlations(&pool, resource_id).await;
        assert_eq!(stored.len(), 2, "both audit writes must land");
        assert!(
            stored.iter().all(|c| *c == supplied),
            "stored audit rows must preserve the caller-supplied correlation ID \
             (#2414); got {stored:?}, want {supplied:?}"
        );

        let _ = sqlx::query("DELETE FROM audit_log WHERE resource_id = $1")
            .bind(resource_id)
            .execute(&pool)
            .await;
    }

    /// #2414: the query correlation filter and `get_by_correlation` retrieve
    /// exactly the rows sharing a (string) correlation ID.
    #[tokio::test]
    async fn test_query_filters_by_correlation_id_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let service = AuditService::new(pool);

        let resource_id = Uuid::new_v4();
        let wanted = format!("corr-a-{}", resource_id.as_simple());
        let other = format!("corr-b-{}", resource_id.as_simple());
        for (action, correlation) in [
            (AuditAction::RepositoryCreated, &wanted),
            (AuditAction::RepositoryUpdated, &wanted),
            (AuditAction::RepositoryDeleted, &other),
        ] {
            service
                .log(
                    AuditEntry::new(action, ResourceType::Repository)
                        .resource(resource_id)
                        .correlation(correlation.clone()),
                )
                .await
                .expect("log succeeds");
        }

        // The admin-endpoint filter path: only rows with the exact
        // correlation ID come back, and the COUNT agrees.
        let (rows, total) = service
            .query(
                None,
                None,
                None,
                Some(resource_id),
                Some(&wanted),
                None,
                None,
                0,
                50,
            )
            .await
            .expect("query succeeds");
        assert_eq!(total, 2);
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.correlation_id == wanted));

        // get_by_correlation joins the same rows, oldest-first.
        let related = service
            .get_by_correlation(&wanted)
            .await
            .expect("get_by_correlation succeeds");
        let ours: Vec<_> = related
            .iter()
            .filter(|r| r.resource_id == Some(resource_id))
            .collect();
        assert_eq!(ours.len(), 2);
        assert_eq!(ours[0].action, "REPOSITORY_CREATED");
        assert_eq!(ours[1].action, "REPOSITORY_UPDATED");

        // get_resource_history returns all three rows for the resource with
        // their stored (string) correlation IDs intact.
        let history = service
            .get_resource_history(ResourceType::Repository, resource_id, 10)
            .await
            .expect("get_resource_history succeeds");
        assert_eq!(history.len(), 3);
        assert!(history
            .iter()
            .all(|r| r.correlation_id == wanted || r.correlation_id == other));

        let _ = sqlx::query("DELETE FROM audit_log WHERE resource_id = $1")
            .bind(resource_id)
            .execute(&service.db)
            .await;
    }

    /// #2414 hardening: the 256-byte cap. A value exactly at the cap
    /// round-trips unchanged; an oversized `.correlation()` input is clamped
    /// to the cap before it reaches the database, so no builder input can
    /// trip the `audit_log_correlation_id_len` CHECK and fail the
    /// (fire-and-forget) audit write.
    #[test]
    fn test_audit_entry_correlation_clamps_oversized_values() {
        use crate::api::middleware::tracing::CORRELATION_ID_MAX_BYTES;
        let oversized = "c".repeat(CORRELATION_ID_MAX_BYTES + 50);
        let entry = AuditEntry::new(AuditAction::BackupStarted, ResourceType::Backup)
            .correlation(oversized.clone());
        assert_eq!(entry.correlation_id.len(), CORRELATION_ID_MAX_BYTES);
        assert_eq!(entry.correlation_id, oversized[..CORRELATION_ID_MAX_BYTES]);
    }

    #[tokio::test]
    async fn test_correlation_id_at_the_cap_round_trips_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::api::middleware::tracing::CORRELATION_ID_MAX_BYTES;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let service = AuditService::new(pool);

        let resource_id = Uuid::new_v4();
        // Unique suffix keys the value to this test run; padded out to
        // exactly the 256-byte cap, the largest value the middleware can
        // ever hand the audit layer and the largest the DB CHECK admits.
        let mut at_cap = format!("cap-{}", resource_id.as_simple());
        at_cap.push_str(&"p".repeat(CORRELATION_ID_MAX_BYTES - at_cap.len()));
        assert_eq!(at_cap.len(), CORRELATION_ID_MAX_BYTES);

        service
            .log(
                AuditEntry::new(AuditAction::RepositoryCreated, ResourceType::Repository)
                    .resource(resource_id)
                    .correlation(at_cap.clone()),
            )
            .await
            .expect("a cap-length correlation ID must not fail the audit write");

        let related = service
            .get_by_correlation(&at_cap)
            .await
            .expect("get_by_correlation succeeds");
        assert_eq!(related.len(), 1);
        assert_eq!(related[0].resource_id, Some(resource_id));
        assert_eq!(related[0].correlation_id, at_cap);

        let _ = sqlx::query("DELETE FROM audit_log WHERE resource_id = $1")
            .bind(resource_id)
            .execute(&service.db)
            .await;
    }
}
