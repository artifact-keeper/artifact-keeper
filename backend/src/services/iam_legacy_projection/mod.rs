//! Read-only projection of the legacy authorization state into the target IAM
//! policy model.
//!
//! The legacy decision paths (`check_permission`, `check_repository_action`,
//! role assignments, rules, group memberships, token scopes) are described by a
//! plain [`LegacyAuthorizationState`] value; the projector turns it into
//! [`PolicyProjection`], a canonical set of policy intents plus a report of
//! everything that could not be mapped faithfully. Nothing here writes IAM
//! records, changes a legacy record, or takes part in request handling.
//!
//! See the `iam-legacy-authorization-projection` change (umbrella OpenSpec) and
//! the IAM epic (#4214).

pub mod conditions;
pub mod intent;
pub mod legacy;
pub mod mapping;
pub mod project;
pub mod reader;
pub mod regions;

pub use intent::{
    Binding, Cidr, Completeness, Conditions, CredentialCeiling, CredentialRef, Deny, Diagnostic,
    DiagnosticCategory, ExternalGroupMapping, Membership, MembershipSource, PolicyProjection,
    ProjectionBuilder, ProjectionReport, Provenance, RoleDefinition, RoleRef, ScopeRef, Severity,
    SourceKind, SourceRef, Sourced, SubjectRef, SystemRole,
};
pub use legacy::LegacyAuthorizationState;
pub use project::{project, project_legacy_state, ProjectionLimits};
pub use reader::{begin_snapshot, capture_legacy_state, read_database_state, read_sso_config};

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests;
