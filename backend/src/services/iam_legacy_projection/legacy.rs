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
    /// `principal_type = 'anonymous'`: the IP-restrictable anonymous read grant.
    Anonymous,
    Unknown {
        principal_type: String,
        id: Uuid,
    },
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
    /// `groups.external_source` (`oidc`, `ldap`, `saml`, ...).
    pub external_source: Option<String>,
    /// `groups.external_provider_id`.
    pub external_provider_id: Option<Uuid>,
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
#[derive(Debug, Clone, PartialEq)]
pub struct LegacyToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub scopes: Vec<String>,
    /// Explicit `api_token_repositories` rows; `None` when the token has none.
    pub allowed_repo_ids: Option<Vec<Uuid>>,
    /// `api_tokens.repo_selector`, which takes precedence over the explicit
    /// rows. Kept raw: a selector cannot be pinned to a fixed repository set.
    pub repo_selector: Option<serde_json::Value>,
}

/// A CI identity mapping (`ci_oidc_identity_mappings`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyCiMapping {
    pub id: Uuid,
    pub provider_id: Uuid,
    /// `ci_oidc_providers.provider_type` (`gitlab`, `github`, `generic`, `kubernetes`, ...).
    pub provider_type: Option<String>,
    /// The service account the mapping resolves to, if one exists yet.
    pub service_account_id: Option<Uuid>,
    /// `None`: the mapping makes no claim about memberships.
    pub group_binding_ids: Option<Vec<Uuid>>,
    /// `None`: the mapping declares no repository ceiling.
    pub allowed_repo_ids: Option<Vec<Uuid>>,
    pub is_enabled: bool,
}

/// The administrator-group setting of one identity provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacySsoAdminConfig {
    /// The provider kind, equal to `users.auth_provider` for its users
    /// (`oidc`, `ldap`, `saml`).
    pub provider: String,
    /// Local group names that confer administrator on login. For LDAP these are
    /// the configured DN and its common name.
    pub admin_groups: Vec<String>,
}

/// Non-secret SSO configuration captured with the database snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LegacySsoConfig {
    pub providers: Vec<LegacySsoAdminConfig>,
    /// Providers that are configured but whose settings could not be loaded.
    pub unreadable_providers: Vec<String>,
}

/// A row of `user_roles`. It confers nothing in any decision path today.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyUserRole {
    pub user_id: Uuid,
    pub role_id: Uuid,
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
    /// `user_roles` rows (non-authoritative; reported, never converted).
    pub user_roles: Vec<LegacyUserRole>,
    /// Ids of `permission_grants` rows (non-authoritative; reported, never converted).
    pub permission_grants: Vec<Uuid>,
}
