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
//! Part of the IAM epic (#4214).

pub mod intent;
pub mod legacy;

pub use intent::{
    Binding, Cidr, Completeness, Conditions, CredentialCeiling, CredentialRef, Deny, Diagnostic,
    DiagnosticCategory, ExternalGroupMapping, Membership, MembershipSource, PolicyProjection,
    ProjectionBuilder, ProjectionReport, Provenance, RoleDefinition, RoleRef, ScopeRef, Severity,
    SourceKind, SourceRef, Sourced, SubjectRef, SystemRole,
};
pub use legacy::LegacyAuthorizationState;
