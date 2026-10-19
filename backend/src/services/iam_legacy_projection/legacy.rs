//! The legacy authorization state, as plain values.
//!
//! Everything the mapping needs and nothing else: no credential material
//! (password hashes, token hashes, provider secrets) is part of this type. The
//! database reader that fills it lives apart from the pure mapping, so the
//! mapping performs no I/O.

use uuid::Uuid;

/// How a user authenticates; decides whether `is_admin` is trustworthy.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum LegacyAuthSource {
    Local,
    /// An external identity provider (`oidc`, `ldap`, `saml`, ...).
    External(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyUser {
    pub id: Uuid,
    pub username: String,
    pub auth_source: LegacyAuthSource,
    pub is_admin: bool,
    pub is_active: bool,
    /// Service accounts are principals like users in the `permissions` table.
    pub is_service_account: bool,
}

/// A row of `roles`. `permissions` holds the legacy actions
/// (`read`, `write`, `delete`, `admin`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyRole {
    pub id: Uuid,
    pub name: String,
    pub permissions: Vec<String>,
}

/// A row of `role_assignments`; `repository_id: None` is a global assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyRoleAssignment {
    pub id: Uuid,
    pub user_id: Uuid,
    pub role_id: Uuid,
    pub repository_id: Option<Uuid>,
}

/// `permissions.principal_type`, kept as the raw string when unrecognized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegacyPrincipal {
    User(Uuid),
    ServiceAccount(Uuid),
    Group(Uuid),
    Unknown { principal_type: String, id: Uuid },
}

/// A row of `permissions`. `conditions` is the raw JSON column: it is parsed
/// during mapping so that a malformed value becomes a diagnostic instead of
/// failing the read.
#[derive(Debug, Clone, PartialEq)]
pub struct LegacyRule {
    pub id: Uuid,
    pub principal: LegacyPrincipal,
    pub target_type: String,
    pub target_id: Uuid,
    pub actions: Vec<String>,
    pub conditions: Option<serde_json::Value>,
}

/// A row of `groups`, with the provider tag when the group mirrors an IdP group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyGroup {
    pub id: Uuid,
    pub name: String,
    pub external_provider: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyMembership {
    pub user_id: Uuid,
    pub group_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyRepository {
    pub id: Uuid,
    pub key: String,
    pub project_id: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyProject {
    pub id: Uuid,
    pub key: String,
}

/// An API token's authority-limiting fields. Never the secret or its hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub scopes: Vec<String>,
    /// `None`: no repository restriction.
    pub allowed_repo_ids: Option<Vec<Uuid>>,
}

/// A CI mapping and the group(s) it places its principal in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyCiMapping {
    pub id: Uuid,
    pub service_account_id: Uuid,
    pub group_ids: Vec<Uuid>,
    /// `None`: the mapping declares no repository ceiling.
    pub allowed_repo_ids: Option<Vec<Uuid>>,
    pub kubernetes_provider: bool,
}

/// An administrator-group setting of one identity provider, or `None` when the
/// setting could not be read (a missing source is a diagnostic, not "no admins").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacySsoAdminConfig {
    pub provider: String,
    pub admin_group: Option<String>,
    /// Group-to-role map entries whose role is `admin`.
    pub admin_role_groups: Vec<String>,
}

/// Non-secret SSO configuration captured with the database snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LegacySsoConfig {
    pub providers: Vec<LegacySsoAdminConfig>,
    /// Providers that are configured but whose settings could not be loaded.
    pub unreadable_providers: Vec<String>,
}

/// One coherent snapshot of the legacy authorization state.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct LegacyAuthorizationState {
    pub users: Vec<LegacyUser>,
    pub roles: Vec<LegacyRole>,
    pub role_assignments: Vec<LegacyRoleAssignment>,
    pub rules: Vec<LegacyRule>,
    pub groups: Vec<LegacyGroup>,
    pub memberships: Vec<LegacyMembership>,
    pub repositories: Vec<LegacyRepository>,
    pub projects: Vec<LegacyProject>,
    pub tokens: Vec<LegacyToken>,
    pub ci_mappings: Vec<LegacyCiMapping>,
    pub sso: LegacySsoConfig,
}
