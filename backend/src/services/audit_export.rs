//! Structured audit-event export (#2413).
//!
//! Every recorded audit action is also emitted as a self-contained,
//! machine-distinguishable structured log record so operators can ship the
//! audit trail to a SIEM by collecting stdout — without polling the admin API
//! or reading Postgres. The emitted line IS an instance of the published JSON
//! Schema (`backend/schemas/audit-event.v1.schema.json`): collectors read exactly
//! what the schema describes, with no message-text parsing and no nested
//! JSON-string unwrapping.
//!
//! Design (see the plan for the full rationale):
//!
//! * **Envelope, not ad-hoc fields.** [`AuditEventRecord`] is a serde type with
//!   a stable, versioned shape: `schema_version`, `category` (always `"audit"`
//!   — the machine marker), `event_id` (shared with the DB row, the SIEM ↔
//!   admin-API join key), `timestamp`, `action`, `outcome`, `actor`,
//!   `source_ip`, `resource`, `correlation_id`, and typed `details`.
//! * **Dedicated stream, not stringified tracing fields.** Records are
//!   serialized with serde, enqueued without blocking request workers, and
//!   written as complete NDJSON lines through the [`AuditSink`] seam. The
//!   stream has its own always-on path that an
//!   operator's `RUST_LOG` filter can never accidentally silence, and the seam
//!   is where a future OTLP-logs exporter plugs in without reopening the design.
//! * **Emit regardless of the DB write.** [`crate::services::audit_service`]
//!   emits the record before the row INSERT, so a DB outage (or the
//!   fire-and-forget swallow path) never also loses the SIEM copy. `event_id`
//!   is minted client-side so the exported record and the DB row share one ID.
//!
//! Opt-in via `AUDIT_STREAM=stdout` (default `off`); see
//! [`init_audit_stream_from_env`].

use std::net::IpAddr;
use std::sync::{mpsc, Arc, OnceLock, RwLock};

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::services::audit_service::{AuditAction, AuditEntry};

/// Envelope schema version. Bumped only on a breaking change to the emitted
/// shape; additive fields are non-breaking (documented in
/// `docs/audit-events.md`).
pub const SCHEMA_VERSION: u32 = 1;

/// The `category` value stamped on every audit record. A collector matches on
/// this to distinguish audit events from ordinary diagnostics without parsing
/// message text.
pub const AUDIT_CATEGORY: &str = "audit";

// ---------------------------------------------------------------------------
// Outcome
// ---------------------------------------------------------------------------

/// The result flavor of an audited action, derived from the action name
/// ([`AuditAction::outcome`]) so no DB column or migration is needed — the
/// audit_log table keeps encoding outcome in the action string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    /// The action completed / the state change was applied.
    Success,
    /// The action was attempted and failed (e.g. `LOGIN_FAILED`).
    Failure,
    /// The principal was refused (e.g. `PERMISSION_DENIED`, `AGE_GATE_REJECTED`).
    Denied,
}

impl AuditAction {
    /// Map an action to its [`Outcome`] for the export envelope.
    ///
    /// A total classification: the failure/denied-flavored actions encode the
    /// result in their name, everything else is a `success`. This match is
    /// intentionally exhaustive so adding a new action forces an explicit
    /// outcome decision at compile time.
    pub fn outcome(&self) -> Outcome {
        match self {
            AuditAction::LoginFailed | AuditAction::BackupFailed | AuditAction::RestoreFailed => {
                Outcome::Failure
            }
            AuditAction::PermissionDenied | AuditAction::AgeGateRejected => Outcome::Denied,
            AuditAction::Login
            | AuditAction::Logout
            | AuditAction::PasswordChanged
            | AuditAction::ApiTokenCreated
            | AuditAction::ApiTokenRevoked
            | AuditAction::UserCreated
            | AuditAction::UserUpdated
            | AuditAction::UserDeleted
            | AuditAction::UserDisabled
            | AuditAction::RoleAssigned
            | AuditAction::RoleRevoked
            | AuditAction::RepositoryCreated
            | AuditAction::RepositoryUpdated
            | AuditAction::RepositoryDeleted
            | AuditAction::RepositoryPermissionChanged
            | AuditAction::ArtifactUploaded
            | AuditAction::ArtifactDownloaded
            | AuditAction::ArtifactDeleted
            | AuditAction::ArtifactMetadataUpdated
            | AuditAction::BackupStarted
            | AuditAction::BackupCompleted
            | AuditAction::RestoreStarted
            | AuditAction::RestoreCompleted
            | AuditAction::PeerRegistered
            | AuditAction::PeerUnregistered
            | AuditAction::PeerSyncStarted
            | AuditAction::PeerSyncCompleted
            | AuditAction::SettingChanged
            | AuditAction::PluginInstalled
            | AuditAction::PluginUninstalled
            | AuditAction::PluginEnabled
            | AuditAction::PluginDisabled
            | AuditAction::EmailSubscriptionCreated
            | AuditAction::EmailSubscriptionDeleted
            | AuditAction::SbomGenerated
            | AuditAction::SbomRead
            | AuditAction::ScanReaped
            | AuditAction::TotpEnabled
            | AuditAction::TotpDisabled
            | AuditAction::SessionsInvalidated
            | AuditAction::AgeGateQueued
            | AuditAction::AgeGateApproved
            | AuditAction::CurationSyncTriggered => Outcome::Success,
        }
    }
}

// ---------------------------------------------------------------------------
// Actor
// ---------------------------------------------------------------------------

/// How the acting principal is classified in the envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    /// A system-initiated emitter (a janitor / scheduler / reconciliation job).
    /// The `details.actor` label set via
    /// [`AuditEntry::system_actor`](crate::services::audit_service::AuditEntry::system_actor)
    /// becomes the actor `name`.
    System,
    /// An authenticated human/user principal (`user_id` present).
    User,
    /// No authenticated principal (e.g. `LOGIN_FAILED` for an unknown user).
    Anonymous,
    /// Reserved: a non-human service-account principal. Not yet emitted —
    /// emitters do not currently carry principal kind. Present in the schema so
    /// consumers can be written against it ahead of the follow-up that wires it.
    #[allow(dead_code)]
    ServiceAccount,
}

/// The acting principal: id, best-effort name, and classification.
///
/// `name` is populated only where the emitter already had it in hand (no
/// query-time join at emit time); an absent name serializes to `null` and is
/// documented as such.
#[derive(Debug, Clone, Serialize)]
pub struct Actor {
    /// The acting user's id, when known (`audit_log.user_id`).
    pub id: Option<Uuid>,
    /// Best-effort display name / label. `null` when the emitter did not carry
    /// one.
    pub name: Option<String>,
    /// Principal classification.
    #[serde(rename = "type")]
    pub kind: ActorType,
}

// ---------------------------------------------------------------------------
// Resource
// ---------------------------------------------------------------------------

/// The resource an audited action targeted.
#[derive(Debug, Clone, Serialize)]
pub struct Resource {
    /// Resource type (`ResourceType::as_str`): `user`, `repository`, ….
    #[serde(rename = "type")]
    pub kind: &'static str,
    /// Resource id, when the action targets a specific row.
    pub id: Option<Uuid>,
    /// Best-effort resource name/label. `null` when the emitter did not carry
    /// one.
    pub name: Option<String>,
}

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

/// One exported audit event. The serialized form of this type is exactly the
/// emitted NDJSON line and exactly what the published JSON Schema describes.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEventRecord {
    /// Envelope version ([`SCHEMA_VERSION`]).
    pub schema_version: u32,
    /// Always [`AUDIT_CATEGORY`] — the machine marker distinguishing audit
    /// events from diagnostics.
    pub category: &'static str,
    /// Event id, shared with the `audit_log` row (SIEM ↔ admin-API join key).
    pub event_id: Uuid,
    /// Emit-time timestamp (UTC). Approximates the row's `created_at`; the
    /// authoritative join key across systems is `event_id`.
    pub timestamp: DateTime<Utc>,
    /// Action name (`AuditAction::as_str`, SCREAMING_SNAKE).
    pub action: &'static str,
    /// Derived result flavor ([`Outcome`]).
    pub outcome: Outcome,
    /// The acting principal.
    pub actor: Actor,
    /// Source IP when known (request-scoped events).
    pub source_ip: Option<IpAddr>,
    /// The targeted resource.
    pub resource: Resource,
    /// Request/operation correlation id (joins to request logs and traces;
    /// #2414). For background jobs, one value per logical operation.
    pub correlation_id: String,
    /// Typed detail payload for the representative security-lifecycle events;
    /// a permissive object for actions not yet typed. Never carries
    /// credentials, tokens, or authorization material.
    pub details: Option<serde_json::Value>,
}

/// Maximum encoded size of a `details` payload copied into an exported record.
///
/// Applied to the export copy ONLY — the DB row always keeps the full
/// (sanitized) payload, so this bound can never lose data from the
/// authoritative audit trail. It exists to keep the stdout queue's worst-case
/// memory finite ([`AUDIT_QUEUE_CAPACITY`] × line size).
const AUDIT_DETAILS_MAX_BYTES: usize = 64 * 1024;

/// Bound the exported copy of a `details` payload, replacing an oversized
/// value with a small truncation marker (`TruncatedDetails` in the published
/// schema).
fn bounded_details_for_export(details: &serde_json::Value) -> serde_json::Value {
    let encoded_len = serde_json::to_vec(details).map(|v| v.len()).unwrap_or(0);
    if encoded_len > AUDIT_DETAILS_MAX_BYTES {
        tracing::warn!(
            encoded_len,
            limit = AUDIT_DETAILS_MAX_BYTES,
            "audit details exceeded export limit; streaming a bounded marker (the DB row keeps the full payload)"
        );
        serde_json::json!({
            "details_truncated": true,
            "original_size_bytes": encoded_len,
        })
    } else {
        details.clone()
    }
}

impl AuditEventRecord {
    /// Build the export record from a finished [`AuditEntry`].
    ///
    /// Pure and side-effect free (no I/O, no DB): the `timestamp` is captured
    /// as emit time and everything else is read off the builder. Keeping this
    /// separate from emission is what makes the contract unit-testable without
    /// touching the global sink.
    pub fn from_entry(entry: &AuditEntry) -> Self {
        let action = entry.action();
        // `details.actor` is the system-actor label; its presence is the
        // system-vs-human distinction the audit trail already carries.
        let system_label = entry
            .details_ref()
            .and_then(|d| d.get("actor"))
            .and_then(|v| v.as_str());
        // Envelope actor id: the export-only override wins where the DB row's
        // `user_id` deliberately records a different principal (the legacy
        // subject-keyed password/session events); otherwise `user_id`.
        let actor_id = entry.actor_id_override().or(entry.user_id());
        let actor = if let Some(label) = system_label {
            Actor {
                id: entry.user_id(),
                name: Some(label.to_string()),
                kind: ActorType::System,
            }
        } else if actor_id.is_some() {
            Actor {
                id: actor_id,
                name: entry.actor_name_ref().map(str::to_owned),
                kind: ActorType::User,
            }
        } else {
            Actor {
                id: None,
                name: entry.actor_name_ref().map(str::to_owned),
                kind: ActorType::Anonymous,
            }
        };

        Self {
            schema_version: SCHEMA_VERSION,
            category: AUDIT_CATEGORY,
            event_id: entry.event_id(),
            timestamp: Utc::now(),
            action: action.as_str(),
            outcome: entry.outcome_override().unwrap_or_else(|| action.outcome()),
            actor,
            source_ip: entry.ip_address(),
            resource: Resource {
                kind: entry.resource_type().as_str(),
                id: entry.resource_id(),
                name: entry.resource_name_ref().map(str::to_owned),
            },
            correlation_id: entry.correlation_id().to_owned(),
            details: entry.details_ref().map(bounded_details_for_export),
        }
    }

    /// Serialize to a single newline-terminated NDJSON line.
    ///
    /// The record is composed only of strings, integers, UUIDs, timestamps and
    /// a `serde_json::Value` payload, so serialization cannot fail in practice;
    /// on the impossible error path we log and return an empty string rather
    /// than panic on the audit write path.
    pub fn to_ndjson_line(&self) -> String {
        match serde_json::to_string(self) {
            Ok(mut line) => {
                line.push('\n');
                line
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to serialize audit export record; dropping stream copy");
                String::new()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Typed detail payloads (#2413 §6)
// ---------------------------------------------------------------------------

/// Typed `details` payloads for the representative security-lifecycle events.
///
/// These anchor the published JSON Schema (`backend/schemas/audit-event.v1.schema.json`):
/// each struct is a stable, documented shape for the `details` object of the
/// actions it covers. Attach one with
/// [`AuditEntry::details_typed`](crate::services::audit_service::AuditEntry::details_typed),
/// which routes through the same anti-spoof sanitization as the ad-hoc
/// [`AuditEntry::details`](crate::services::audit_service::AuditEntry::details)
/// path.
///
/// Only the representative families are typed; other actions keep ad-hoc
/// `json!` payloads and are schema-valid under the permissive `details`
/// fallback (see `docs/audit-events.md`). None of these ever carry credentials,
/// tokens, or other authorization material.
///
/// `Option` fields are omitted from the emitted JSON when absent
/// (`skip_serializing_if`) so a payload only carries what the emitter knew.
pub mod details {
    use serde::Serialize;
    use uuid::Uuid;

    /// `REPOSITORY_CREATED` / `REPOSITORY_UPDATED` / `REPOSITORY_DELETED`.
    #[derive(Debug, Clone, Serialize)]
    pub struct RepositoryDetails {
        /// Acting principal id, retained for compatibility with the existing
        /// database details payload. The envelope actor is authoritative.
        pub actor_id: Uuid,
        /// Repository key / slug.
        pub key: String,
        /// Existing boolean visibility field retained for admin-API consumers.
        pub is_public: bool,
        /// Package format (`maven`, `npm`, `cargo`, …), when known.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub format: Option<String>,
        /// Visibility (`public`, `private`, …), when known.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub visibility: Option<String>,
        /// Age-gate toggle when `REPOSITORY_UPDATED` represents a policy change.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub age_gate_enabled: Option<bool>,
        /// Minimum upstream publish age for that policy change.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub age_gate_min_age_days: Option<i32>,
    }

    /// `ROLE_ASSIGNED` / `ROLE_REVOKED` / `REPOSITORY_PERMISSION_CHANGED`.
    #[derive(Debug, Clone, Serialize)]
    pub struct PermissionDetails {
        /// Acting principal id, retained for existing details consumers.
        pub actor_id: Uuid,
        /// Role id for role assignment/revocation events.
        pub role_id: Uuid,
        /// The grantee principal id (currently a user).
        pub grantee_id: Uuid,
        /// Repository id for repository-scoped grants, when applicable.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub repository_id: Option<Uuid>,
    }

    /// `API_TOKEN_CREATED` / `API_TOKEN_REVOKED`. The token SECRET is never
    /// included — only identifying metadata.
    #[derive(Debug, Clone, Serialize)]
    pub struct TokenDetails {
        /// The token's id (not the secret).
        pub token_id: String,
        /// The token's display name, when set.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub token_name: Option<String>,
        /// The endpoint family that minted/revoked it (`user`, `profile`,
        /// `repo`, `service_account`).
        pub surface: String,
    }

    /// `LOGIN_FAILED` / `PERMISSION_DENIED` and related authorization events.
    #[derive(Debug, Clone, Serialize)]
    pub struct AuthDetails {
        /// The username attempted, for a failed login of an unknown/!matched
        /// principal. Never a password or credential.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// The request path the principal was denied.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub path: Option<String>,
        /// HTTP method for authorization denials, or authentication method for
        /// failed multi-factor authentication.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub method: Option<String>,
        /// The permission/reason the request was refused.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        /// Federated provider kind (`oidc`, `saml`, `ldap`), when applicable.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub provider: Option<String>,
        /// Stable authentication family label, when applicable.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub auth_method: Option<String>,
    }

    /// `ARTIFACT_UPLOADED` / `ARTIFACT_DOWNLOADED` / `ARTIFACT_DELETED`.
    #[derive(Debug, Clone, Serialize)]
    pub struct ArtifactDetails {
        /// The repository the artifact lives in.
        pub repository_id: Uuid,
        /// The artifact path within the repository.
        pub path: String,
        /// Artifact display name.
        pub name: String,
        /// The version/coordinate, when applicable.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub version: Option<String>,
        /// Size in bytes, when known.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub size_bytes: Option<u64>,
        /// Content digest (e.g. `sha256:…`), when known.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub digest: Option<String>,
        /// Original uploader, when known (not necessarily the delete actor).
        #[serde(skip_serializing_if = "Option::is_none")]
        pub uploaded_by: Option<Uuid>,
    }

    /// `SETTING_CHANGED` — a security/system configuration change. Secret-bearing
    /// values are redacted by the caller; only the key and non-secret summaries
    /// belong here.
    #[derive(Debug, Clone, Serialize)]
    pub struct SettingDetails {
        /// The setting key that changed.
        pub key: String,
        /// A non-secret summary of the previous value, when safe to record.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub old_value: Option<String>,
        /// A non-secret summary of the new value, when safe to record.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub new_value: Option<String>,
    }

    impl TokenDetails {
        /// Build token metadata from a lifecycle event. Mirrors the invariant of
        /// the existing `api_token_audit_entry` helper: the secret is never a
        /// field here, so it cannot leak into the audit stream.
        pub fn new(token_id: Uuid, token_name: Option<&str>, surface: &str) -> Self {
            Self {
                token_id: token_id.to_string(),
                token_name: token_name.map(str::to_owned),
                surface: surface.to_owned(),
            }
        }
    }

    impl AuthDetails {
        /// Failed local authentication attempt.
        pub fn failed_login(username: Option<&str>, reason: Option<&str>) -> Self {
            Self {
                username: username.map(str::to_owned),
                path: None,
                method: None,
                reason: reason.map(str::to_owned),
                provider: None,
                auth_method: None,
            }
        }

        /// Failed federated authentication attempt.
        pub fn failed_federated(username: Option<&str>, provider: &str) -> Self {
            Self {
                username: username.map(str::to_owned),
                path: None,
                method: None,
                reason: None,
                provider: Some(provider.to_owned()),
                auth_method: Some("federated".to_owned()),
            }
        }

        /// Authorization denial at an HTTP boundary.
        pub fn permission_denied(path: &str, method: &str, reason: &str) -> Self {
            Self {
                username: None,
                path: Some(path.to_owned()),
                method: Some(method.to_owned()),
                reason: Some(reason.to_owned()),
                provider: None,
                auth_method: None,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Sink seam
// ---------------------------------------------------------------------------

/// A destination for emitted audit NDJSON lines.
///
/// The seam isolates the transport from the envelope/schema/tests: production
/// writes to stdout, tests capture in-process, and a future OTLP-logs exporter
/// implements this trait without touching the record shape.
pub trait AuditSink: Send + Sync {
    /// Write one already-newline-terminated NDJSON line.
    fn emit(&self, line: &str);
    /// Whether this sink wants records at all. `false` lets the emitter skip
    /// serialization entirely when the stream is off.
    fn enabled(&self) -> bool {
        true
    }
}

/// The disabled sink (default, `AUDIT_STREAM=off`): drops everything and
/// reports itself disabled so no record is ever serialized.
struct NoopSink;
impl AuditSink for NoopSink {
    fn emit(&self, _line: &str) {}
    fn enabled(&self) -> bool {
        false
    }
}

/// Maximum number of audit records waiting on stdout. A bounded queue prevents
/// a stalled container log driver from turning audit traffic into unbounded
/// memory growth. Producers use `try_send`, so stdout backpressure never blocks
/// a Tokio request worker.
const AUDIT_QUEUE_CAPACITY: usize = 4096;

/// Production sink: enqueue records to a dedicated blocking stdout writer.
struct StdoutSink {
    sender: mpsc::SyncSender<String>,
}
impl AuditSink for StdoutSink {
    fn emit(&self, line: &str) {
        match self.sender.try_send(line.to_owned()) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => {
                crate::services::metrics_service::record_audit_stream_failure("queue_full");
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                crate::services::metrics_service::record_audit_stream_failure(
                    "writer_disconnected",
                );
            }
        }
    }
}

fn spawn_stdout_sink() -> std::io::Result<(Arc<dyn AuditSink>, std::thread::JoinHandle<()>)> {
    let (sender, receiver) = mpsc::sync_channel::<String>(AUDIT_QUEUE_CAPACITY);
    let worker = std::thread::Builder::new()
        .name("audit-stdout-writer".to_owned())
        .spawn(move || {
            use std::io::Write;

            for line in receiver {
                let stdout = std::io::stdout();
                let mut lock = stdout.lock();
                if let Err(error) = lock.write_all(line.as_bytes()).and_then(|_| lock.flush()) {
                    crate::services::metrics_service::record_audit_stream_failure("write_error");
                    eprintln!(
                        "audit stdout writer failed; structured audit delivery stopped: {error}"
                    );
                    break;
                }
            }
        })?;
    Ok((Arc::new(StdoutSink { sender }), worker))
}

fn sink_cell() -> &'static RwLock<Arc<dyn AuditSink>> {
    static CELL: OnceLock<RwLock<Arc<dyn AuditSink>>> = OnceLock::new();
    CELL.get_or_init(|| RwLock::new(Arc::new(NoopSink)))
}

/// The currently installed process audit sink.
fn current_sink() -> Arc<dyn AuditSink> {
    sink_cell()
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .clone()
}

/// Whether the process audit stream currently accepts records at all.
///
/// Callers that build export records ahead of emission (the janitor's batched
/// path) use this to skip record construction entirely when the stream is off.
pub fn stream_enabled() -> bool {
    current_sink().enabled()
}

/// Build and emit the export record for a finished [`AuditEntry`].
///
/// The `AUDIT_STREAM=off` default costs one sink check per audit event and
/// nothing more: the record is not even constructed when the stream is off.
/// Never returns an error — delivery failures are counted and the audit
/// stream never gates the originating operation.
pub fn emit_entry(entry: &AuditEntry) {
    let sink = current_sink();
    if !sink.enabled() {
        return;
    }
    let record = AuditEventRecord::from_entry(entry);
    let line = record.to_ndjson_line();
    if !line.is_empty() {
        sink.emit(&line);
    }
}

/// Emit one already-built audit record to the process audit sink.
///
/// Cheap when the stream is off (short-circuits before serialization) and
/// non-blocking when enabled (the stdout sink uses bounded `try_send`). Never
/// returns an error. Prefer [`emit_entry`] where the record is not already in
/// hand — it also skips record construction on the disabled path.
pub fn emit_audit_event(record: &AuditEventRecord) {
    let sink = current_sink();
    if !sink.enabled() {
        return;
    }
    let line = record.to_ndjson_line();
    if !line.is_empty() {
        sink.emit(&line);
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// The audit-stream delivery mode, selected via `AUDIT_STREAM`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditStreamMode {
    /// No audit records are emitted (default for v1).
    Off,
    /// Audit records are written as NDJSON to stdout.
    Stdout,
}

impl AuditStreamMode {
    /// Parse an `AUDIT_STREAM` value. Anything other than an explicit
    /// stdout/on/true opt-in is `off`, so an operator typo never silently
    /// starts double-emitting.
    fn from_value(val: &str) -> Self {
        match val.trim().to_lowercase().as_str() {
            "stdout" | "on" | "true" | "1" => Self::Stdout,
            _ => Self::Off,
        }
    }

    /// Read from `AUDIT_STREAM`. Defaults to `off` when unset.
    pub fn from_env() -> Self {
        Self::from_value(&std::env::var("AUDIT_STREAM").unwrap_or_default())
    }

    /// Canonical name, for the startup log line.
    pub fn name(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Stdout => "stdout",
        }
    }
}

/// Initialize the process audit sink from `AUDIT_STREAM` and return the
/// resolved mode. Follows the pre-`Config` env-read pattern telemetry uses so
/// it can run alongside `init_tracing` in `main`.
#[must_use = "dropping the guard disables the audit stream"]
pub struct AuditStreamGuard {
    mode: AuditStreamMode,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl AuditStreamGuard {
    /// Active stream mode after initialization.
    pub fn mode(&self) -> AuditStreamMode {
        self.mode
    }
}

impl Drop for AuditStreamGuard {
    fn drop(&mut self) {
        // Drop the process-held sender first. The detached worker observes
        // channel closure and drains on a best-effort basis. Do not join here:
        // a blocked container stdout must not hang graceful shutdown either.
        *sink_cell().write().unwrap_or_else(|p| p.into_inner()) = Arc::new(NoopSink);
        let _ = self.worker.take();
    }
}

pub fn init_audit_stream_from_env() -> AuditStreamGuard {
    let mode = AuditStreamMode::from_env();
    let (resolved_mode, sink, worker): (
        AuditStreamMode,
        Arc<dyn AuditSink>,
        Option<std::thread::JoinHandle<()>>,
    ) = match mode {
        AuditStreamMode::Stdout => match spawn_stdout_sink() {
            Ok((sink, worker)) => (AuditStreamMode::Stdout, sink, Some(worker)),
            Err(error) => {
                tracing::error!(%error, "failed to start audit stdout writer; stream disabled");
                (AuditStreamMode::Off, Arc::new(NoopSink), None)
            }
        },
        AuditStreamMode::Off => (AuditStreamMode::Off, Arc::new(NoopSink), None),
    };
    *sink_cell().write().unwrap_or_else(|p| p.into_inner()) = sink;
    AuditStreamGuard {
        mode: resolved_mode,
        worker,
    }
}

// ---------------------------------------------------------------------------
// Test sink
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod test_sink {
    //! In-process capture sink + a swap guard so `log()`-path emission can be
    //! asserted without process isolation. A global mutex serializes tests that
    //! touch the shared sink; the guard restores the previous sink on drop.

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static SINK_TEST_MUTEX: Mutex<()> = Mutex::new(());

    /// Captures every emitted line for assertions.
    #[derive(Default)]
    pub struct BufferSink {
        lines: Mutex<Vec<String>>,
    }

    impl BufferSink {
        /// Snapshot of the lines captured so far.
        pub fn lines(&self) -> Vec<String> {
            self.lines.lock().unwrap_or_else(|p| p.into_inner()).clone()
        }

        /// Parse the captured lines as JSON values (each line must be valid
        /// NDJSON).
        pub fn records(&self) -> Vec<serde_json::Value> {
            self.lines()
                .iter()
                .map(|l| serde_json::from_str(l).expect("emitted line is valid NDJSON"))
                .collect()
        }
    }

    impl AuditSink for BufferSink {
        fn emit(&self, line: &str) {
            self.lines
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(line.to_string());
        }
    }

    /// Holds the sink swap for the duration of a test and restores it on drop.
    pub struct SinkGuard {
        prev: Arc<dyn AuditSink>,
        // Held to serialize sink-dependent tests; released after `prev` is
        // restored (fields drop in declaration order).
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for SinkGuard {
        fn drop(&mut self) {
            *sink_cell().write().unwrap_or_else(|p| p.into_inner()) = self.prev.clone();
        }
    }

    /// Install a fresh [`BufferSink`] as the process sink, returning it plus a
    /// guard that restores the prior sink when dropped.
    pub fn install() -> (Arc<BufferSink>, SinkGuard) {
        let lock = SINK_TEST_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let buffer = Arc::new(BufferSink::default());
        let dyn_buf: Arc<dyn AuditSink> = buffer.clone();
        let prev = {
            let mut w = sink_cell().write().unwrap_or_else(|p| p.into_inner());
            let old = w.clone();
            *w = dyn_buf;
            old
        };
        (buffer, SinkGuard { prev, _lock: lock })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::audit_service::{AuditEntry, ResourceType};
    use std::net::{IpAddr, Ipv4Addr};

    // ── Outcome derivation ──────────────────────────────────────────────

    #[test]
    fn test_outcome_failure_variants() {
        assert_eq!(AuditAction::LoginFailed.outcome(), Outcome::Failure);
        assert_eq!(AuditAction::BackupFailed.outcome(), Outcome::Failure);
        assert_eq!(AuditAction::RestoreFailed.outcome(), Outcome::Failure);
    }

    #[test]
    fn test_outcome_denied_variants() {
        assert_eq!(AuditAction::PermissionDenied.outcome(), Outcome::Denied);
        assert_eq!(AuditAction::AgeGateRejected.outcome(), Outcome::Denied);
    }

    #[test]
    fn test_outcome_success_default() {
        for a in [
            AuditAction::Login,
            AuditAction::Logout,
            AuditAction::ApiTokenCreated,
            AuditAction::RepositoryCreated,
            AuditAction::ArtifactUploaded,
            AuditAction::ScanReaped,
            AuditAction::BackupCompleted,
            AuditAction::AgeGateApproved,
        ] {
            assert_eq!(a.outcome(), Outcome::Success, "{}", a.as_str());
        }
    }

    #[test]
    fn test_outcome_serializes_lowercase() {
        assert_eq!(
            serde_json::to_value(Outcome::Denied).unwrap(),
            serde_json::json!("denied")
        );
    }

    // ── Actor typing ────────────────────────────────────────────────────

    #[test]
    fn test_from_entry_user_actor_with_name() {
        let uid = Uuid::new_v4();
        let entry = AuditEntry::new(AuditAction::Login, ResourceType::User)
            .user(uid)
            .actor_name("alice");
        let rec = AuditEventRecord::from_entry(&entry);
        assert_eq!(rec.actor.kind, ActorType::User);
        assert_eq!(rec.actor.id, Some(uid));
        assert_eq!(rec.actor.name.as_deref(), Some("alice"));
    }

    #[test]
    fn test_from_entry_anonymous_actor_when_no_user_and_not_system() {
        let entry = AuditEntry::new(AuditAction::LoginFailed, ResourceType::User);
        let rec = AuditEventRecord::from_entry(&entry);
        assert_eq!(rec.actor.kind, ActorType::Anonymous);
        assert_eq!(rec.actor.id, None);
    }

    #[test]
    fn test_from_entry_system_actor_from_details_label() {
        let entry = AuditEntry::new(AuditAction::ScanReaped, ResourceType::ScanResult)
            .system_actor("system:stuck_scan_janitor");
        let rec = AuditEventRecord::from_entry(&entry);
        assert_eq!(rec.actor.kind, ActorType::System);
        assert_eq!(rec.actor.name.as_deref(), Some("system:stuck_scan_janitor"));
    }

    // ── Envelope shape ──────────────────────────────────────────────────

    #[test]
    fn test_from_entry_populates_envelope() {
        let uid = Uuid::new_v4();
        let rid = Uuid::new_v4();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let entry = AuditEntry::new(AuditAction::RepositoryCreated, ResourceType::Repository)
            .user(uid)
            .resource(rid)
            .ip(ip)
            .correlation("corr-xyz");
        let rec = AuditEventRecord::from_entry(&entry);
        assert_eq!(rec.schema_version, SCHEMA_VERSION);
        assert_eq!(rec.category, "audit");
        assert_eq!(rec.action, "REPOSITORY_CREATED");
        assert_eq!(rec.outcome, Outcome::Success);
        assert_eq!(rec.resource.kind, "repository");
        assert_eq!(rec.resource.id, Some(rid));
        assert_eq!(rec.source_ip, Some(ip));
        assert_eq!(rec.correlation_id, "corr-xyz");
        assert_eq!(rec.event_id, entry.event_id());
    }

    /// The subject-keyed builders (password/session events) keep `subject` in
    /// the DB row's `user_id` but export the true initiator: the envelope-only
    /// `.actor_id()` override wins over `user_id` for `actor.id`.
    #[test]
    fn test_from_entry_actor_id_override_wins_over_user_id() {
        let subject = Uuid::new_v4();
        let admin = Uuid::new_v4();
        let entry = AuditEntry::new(AuditAction::PasswordChanged, ResourceType::User)
            .user(subject)
            .resource(subject)
            .actor_id(admin);
        let rec = AuditEventRecord::from_entry(&entry);
        assert_eq!(rec.actor.kind, ActorType::User);
        assert_eq!(rec.actor.id, Some(admin), "envelope actor is the initiator");
        assert_eq!(rec.resource.id, Some(subject));
    }

    /// Size-bounding applies to the exported copy ONLY: the record carries the
    /// truncation marker while the builder — i.e. the DB row — keeps the full
    /// payload.
    #[test]
    fn test_from_entry_truncates_oversized_details_in_export_copy_only() {
        let entry = AuditEntry::new(AuditAction::SettingChanged, ResourceType::Setting)
            .details(serde_json::json!({"value": "x".repeat(AUDIT_DETAILS_MAX_BYTES)}));
        let rec = AuditEventRecord::from_entry(&entry);
        let exported = rec.details.expect("exported details present");
        assert_eq!(exported["details_truncated"], true);
        assert!(exported["original_size_bytes"].as_u64().unwrap() > AUDIT_DETAILS_MAX_BYTES as u64);
        let stored = entry.details_ref().expect("stored details present");
        assert_eq!(
            stored["value"].as_str().unwrap().len(),
            AUDIT_DETAILS_MAX_BYTES,
            "DB copy keeps the full payload"
        );
    }

    #[test]
    fn test_to_ndjson_line_is_single_parseable_line() {
        let entry = AuditEntry::new(AuditAction::Login, ResourceType::User);
        let line = AuditEventRecord::from_entry(&entry).to_ndjson_line();
        assert!(line.ends_with('\n'));
        assert_eq!(line.matches('\n').count(), 1, "exactly one line");
        let v: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(v["category"], "audit");
        assert_eq!(v["schema_version"], SCHEMA_VERSION);
    }

    /// Envelope snapshot pinning field names + casing — this is the compat
    /// contract, so a rename must fail a test, never slip through.
    #[test]
    fn test_envelope_field_names_and_casing() {
        let entry = AuditEntry::new(AuditAction::PermissionDenied, ResourceType::User);
        let v = serde_json::to_value(AuditEventRecord::from_entry(&entry)).unwrap();
        let obj = v.as_object().unwrap();
        for key in [
            "schema_version",
            "category",
            "event_id",
            "timestamp",
            "action",
            "outcome",
            "actor",
            "source_ip",
            "resource",
            "correlation_id",
            "details",
        ] {
            assert!(obj.contains_key(key), "missing envelope key: {key}");
        }
        // Nested renames: `type` (not `kind`) inside actor and resource.
        assert!(v["actor"].as_object().unwrap().contains_key("type"));
        assert!(v["resource"].as_object().unwrap().contains_key("type"));
    }

    // ── Sink / emission ─────────────────────────────────────────────────

    #[test]
    fn test_default_sink_disabled_emits_nothing() {
        // With no stream installed (or explicitly off) emission is a no-op:
        // capture with a buffer, restore, and confirm the disabled path.
        let entry = AuditEntry::new(AuditAction::Login, ResourceType::User);
        let rec = AuditEventRecord::from_entry(&entry);
        // NoopSink reports disabled.
        assert!(!NoopSink.enabled());
        // to_ndjson_line still works standalone.
        assert!(rec.to_ndjson_line().contains("\"category\":\"audit\""));
    }

    /// Records matching a unique correlation id. The process sink is global, so
    /// a concurrent `log()` in another test could append to the same buffer;
    /// filtering by a per-test unique correlation makes the assertions immune to
    /// that interleaving.
    fn recs_for(buffer: &super::test_sink::BufferSink, corr: &str) -> Vec<serde_json::Value> {
        buffer
            .records()
            .into_iter()
            .filter(|r| r["correlation_id"] == corr)
            .collect()
    }

    #[test]
    fn test_emit_captures_exactly_one_line_via_buffer_sink() {
        let (buffer, _guard) = test_sink::install();
        let corr = format!("emit-one-{}", Uuid::new_v4());
        let entry = AuditEntry::new(AuditAction::RepositoryDeleted, ResourceType::Repository)
            .correlation(&corr);
        emit_audit_event(&AuditEventRecord::from_entry(&entry));
        let recs = recs_for(&buffer, &corr);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0]["category"], "audit");
        assert_eq!(recs[0]["action"], "REPOSITORY_DELETED");
    }

    #[test]
    fn test_stream_enabled_and_emit_entry_via_installed_sink() {
        let (buffer, _guard) = test_sink::install();
        assert!(stream_enabled(), "installed buffer sink reports enabled");
        let corr = format!("emit-entry-{}", Uuid::new_v4());
        let entry = AuditEntry::new(AuditAction::Login, ResourceType::User).correlation(&corr);
        emit_entry(&entry);
        let recs = recs_for(&buffer, &corr);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0]["event_id"], entry.event_id().to_string());
    }

    #[test]
    fn test_buffer_sink_captures_multiple_in_order() {
        let (buffer, _guard) = test_sink::install();
        let base = Uuid::new_v4();
        let corrs: Vec<String> = (0..3).map(|i| format!("{base}-{i}")).collect();
        for corr in &corrs {
            let entry = AuditEntry::new(AuditAction::Login, ResourceType::User).correlation(corr);
            emit_audit_event(&AuditEventRecord::from_entry(&entry));
        }
        // Filter to this test's records; append order is preserved.
        let mine: Vec<String> = buffer
            .records()
            .into_iter()
            .filter_map(|r| r["correlation_id"].as_str().map(str::to_owned))
            .filter(|c| corrs.contains(c))
            .collect();
        assert_eq!(mine, corrs);
    }

    // ── AuditStreamMode ─────────────────────────────────────────────────

    #[test]
    fn test_stream_mode_from_value() {
        assert_eq!(
            AuditStreamMode::from_value("stdout"),
            AuditStreamMode::Stdout
        );
        assert_eq!(AuditStreamMode::from_value("ON"), AuditStreamMode::Stdout);
        assert_eq!(AuditStreamMode::from_value("true"), AuditStreamMode::Stdout);
        assert_eq!(AuditStreamMode::from_value(""), AuditStreamMode::Off);
        assert_eq!(AuditStreamMode::from_value("off"), AuditStreamMode::Off);
        assert_eq!(AuditStreamMode::from_value("bogus"), AuditStreamMode::Off);
    }

    #[test]
    fn test_stream_mode_name() {
        assert_eq!(AuditStreamMode::Off.name(), "off");
        assert_eq!(AuditStreamMode::Stdout.name(), "stdout");
    }

    // ── Typed detail payloads (#2413 §6) ────────────────────────────────

    #[test]
    fn test_repository_details_omits_absent_optionals() {
        let d = details::RepositoryDetails {
            actor_id: Uuid::new_v4(),
            key: "maven-releases".into(),
            is_public: false,
            format: Some("maven".into()),
            visibility: None,
            age_gate_enabled: None,
            age_gate_min_age_days: None,
        };
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["key"], "maven-releases");
        assert_eq!(v["format"], "maven");
        assert!(
            !v.as_object().unwrap().contains_key("visibility"),
            "absent Option is omitted, not null"
        );
    }

    #[test]
    fn test_permission_details_shape() {
        let role_id = Uuid::new_v4();
        let grantee_id = Uuid::new_v4();
        let d = details::PermissionDetails {
            actor_id: Uuid::new_v4(),
            role_id,
            grantee_id,
            repository_id: None,
        };
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["role_id"], role_id.to_string());
        assert_eq!(v["grantee_id"], grantee_id.to_string());
    }

    #[test]
    fn test_token_details_never_carries_secret() {
        let d = details::TokenDetails::new(Uuid::new_v4(), Some("ci-token"), "profile");
        let v = serde_json::to_value(&d).unwrap();
        let obj = v.as_object().unwrap();
        assert_eq!(v["surface"], "profile");
        assert_eq!(v["token_name"], "ci-token");
        // The struct has no field that could hold the secret.
        assert!(!obj.contains_key("secret"));
        assert!(!obj.contains_key("token"));
        assert!(!obj.contains_key("value"));
    }

    #[test]
    fn test_token_details_omits_absent_name() {
        let d = details::TokenDetails::new(Uuid::new_v4(), None, "service_account");
        let v = serde_json::to_value(&d).unwrap();
        assert!(!v.as_object().unwrap().contains_key("token_name"));
    }

    #[test]
    fn test_auth_details_shape() {
        let d = details::AuthDetails {
            username: Some("attacker".into()),
            path: Some("/api/v1/admin/users".into()),
            method: Some("GET".into()),
            reason: Some("admin_privileges_required".into()),
            provider: None,
            auth_method: None,
        };
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["username"], "attacker");
        assert_eq!(v["path"], "/api/v1/admin/users");
        assert_eq!(v["reason"], "admin_privileges_required");
    }

    #[test]
    fn test_artifact_details_shape() {
        let repository_id = Uuid::new_v4();
        let d = details::ArtifactDetails {
            repository_id,
            path: "@scope/pkg/-/pkg-1.2.3.tgz".into(),
            name: "pkg-1.2.3.tgz".into(),
            version: Some("1.2.3".into()),
            size_bytes: Some(4096),
            digest: Some("sha256:abcd".into()),
            uploaded_by: None,
        };
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["repository_id"], repository_id.to_string());
        assert_eq!(v["size_bytes"], 4096);
        assert_eq!(v["digest"], "sha256:abcd");
    }

    #[test]
    fn test_setting_details_shape() {
        let d = details::SettingDetails {
            key: "auth.session_ttl".into(),
            old_value: Some("3600".into()),
            new_value: Some("1800".into()),
        };
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["key"], "auth.session_ttl");
        assert_eq!(v["old_value"], "3600");
        assert_eq!(v["new_value"], "1800");
    }

    /// A typed detail payload lands in the envelope's `details` unchanged and is
    /// emitted as part of the record.
    #[test]
    fn test_typed_details_round_trip_through_envelope() {
        let corr = format!("typed-{}", Uuid::new_v4());
        let entry = AuditEntry::new(AuditAction::ApiTokenCreated, ResourceType::ApiToken)
            .correlation(&corr)
            .details_typed(details::TokenDetails::new(
                Uuid::new_v4(),
                Some("ci"),
                "profile",
            ));
        let rec = AuditEventRecord::from_entry(&entry);
        let v = serde_json::to_value(&rec).unwrap();
        assert_eq!(v["details"]["surface"], "profile");
        assert_eq!(v["details"]["token_name"], "ci");
    }
}
