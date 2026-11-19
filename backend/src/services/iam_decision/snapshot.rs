//! The immutable inputs a decision reads: the policy (bindings, denies,
//! memberships, ceilings) and the facts about resources (placement and
//! visibility), indexed for lookup by subject.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::context::RequestContext;
use crate::api::authz::catalog::Permission;
use crate::models::repository::RepositoryVisibility;
use crate::services::iam_legacy_projection::mapping::role_effective_permissions;
use crate::services::iam_legacy_projection::regions;
use crate::services::iam_legacy_projection::{
    Cidr, Conditions, CredentialRef, PolicyProjection, RoleRef, ScopeRef, SubjectRef,
};

// ---------------------------------------------------------------------------
// Conditions
// ---------------------------------------------------------------------------

/// The result of evaluating a condition against a request context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Truth {
    True,
    False,
    /// The condition needs the client IP and none is known.
    Unknown,
}

/// Conditions on a binding or deny: all present fields must hold (AND); the
/// CIDRs within `allowed_cidrs` combine with OR. Absent conditions always hold.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DecisionConditions {
    allowed_cidrs: Option<BTreeSet<Cidr>>,
    not_before: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
}

impl DecisionConditions {
    /// Validated conditions: a CIDR list must not be empty (it would mean
    /// "never") and both time bounds, when present, must leave a non-empty
    /// interval.
    pub fn new(
        allowed_cidrs: Option<BTreeSet<Cidr>>,
        not_before: Option<DateTime<Utc>>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<DecisionConditions, String> {
        if allowed_cidrs.as_ref().is_some_and(BTreeSet::is_empty) {
            return Err("allowed_cidrs must not be empty".to_string());
        }
        if let (Some(start), Some(end)) = (not_before, expires_at) {
            if start >= end {
                return Err(format!(
                    "not_before ({start}) must be before expires_at ({end})"
                ));
            }
        }
        Ok(DecisionConditions {
            allowed_cidrs,
            not_before,
            expires_at,
        })
    }

    /// The projection's conditions carry only CIDRs; the conversion is lossless.
    pub fn from_projection(conditions: &Conditions) -> DecisionConditions {
        DecisionConditions {
            allowed_cidrs: Some(conditions.cidrs().clone()),
            not_before: None,
            expires_at: None,
        }
    }

    /// Evaluate at `ctx`. Any definitely false field makes the whole conjunction
    /// false; otherwise a CIDR without a known IP makes it unknown.
    pub fn evaluate(&self, ctx: &RequestContext) -> Truth {
        if self.not_before.is_some_and(|t| ctx.now < t) {
            return Truth::False;
        }
        if self.expires_at.is_some_and(|t| ctx.now >= t) {
            return Truth::False;
        }
        match (&self.allowed_cidrs, ctx.client_ip) {
            (None, _) => Truth::True,
            (Some(_), None) => Truth::Unknown,
            (Some(cidrs), Some(ip)) if regions::contains(cidrs, ip) => Truth::True,
            (Some(_), Some(_)) => Truth::False,
        }
    }
}

/// Evaluate optional conditions: none always hold.
pub fn evaluate(conditions: Option<&DecisionConditions>, ctx: &RequestContext) -> Truth {
    conditions.map_or(Truth::True, |c| c.evaluate(ctx))
}

// ---------------------------------------------------------------------------
// Resources
// ---------------------------------------------------------------------------

/// What the decision needs to know about one repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepositoryFacts {
    pub project: Option<Uuid>,
    pub visibility: RepositoryVisibility,
}

/// Facts about resources, read in the same snapshot as the policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceIndex {
    pub repositories: BTreeMap<Uuid, RepositoryFacts>,
    pub projects: BTreeSet<Uuid>,
    pub groups: BTreeSet<Uuid>,
}

impl ResourceIndex {
    /// The resource and its ancestors, narrowest first, or `None` when the
    /// resource is unknown. A repository's ancestors are its project (if any)
    /// and the instance.
    pub fn chain(&self, resource: ScopeRef) -> Option<Vec<ScopeRef>> {
        match resource {
            ScopeRef::Instance => Some(vec![ScopeRef::Instance]),
            ScopeRef::Project(id) => self
                .projects
                .contains(&id)
                .then(|| vec![resource, ScopeRef::Instance]),
            ScopeRef::Group(id) => self
                .groups
                .contains(&id)
                .then(|| vec![resource, ScopeRef::Instance]),
            ScopeRef::Repository(id) => {
                let facts = self.repositories.get(&id)?;
                let mut chain = vec![resource];
                if let Some(project) = facts.project {
                    chain.push(ScopeRef::Project(project));
                }
                chain.push(ScopeRef::Instance);
                Some(chain)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// A binding ready for evaluation. `permissions` is the role's permissions that
/// apply at the binding scope, or `None` when the role could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotBinding {
    pub subject: SubjectRef,
    pub role: RoleRef,
    pub scope: ScopeRef,
    pub permissions: Option<BTreeSet<Permission>>,
    pub conditions: Option<DecisionConditions>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotDeny {
    pub subject: SubjectRef,
    pub scope: ScopeRef,
    pub permissions: BTreeSet<Permission>,
    pub excepted_scopes: BTreeSet<ScopeRef>,
    pub conditions: Option<DecisionConditions>,
}

/// A credential's ceiling: `None` leaves that dimension unrestricted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ceiling {
    pub permissions: Option<BTreeSet<Permission>>,
    pub repository_ids: Option<BTreeSet<Uuid>>,
}

impl Ceiling {
    /// Whether `permission` on `resource` is within the ceiling. A credential
    /// restricted to repositories reaches only those repositories, never a
    /// project, group or the instance.
    pub fn allows(&self, permission: Permission, resource: ScopeRef) -> bool {
        let permission_ok = self
            .permissions
            .as_ref()
            .is_none_or(|set| set.contains(&permission));
        let resource_ok = match (&self.repository_ids, resource) {
            (None, _) => true,
            (Some(repos), ScopeRef::Repository(id)) => repos.contains(&id),
            (Some(_), _) => false,
        };
        permission_ok && resource_ok
    }
}

/// An input the snapshot could not resolve. Decisions that depend on it are
/// unavailable; the others are unaffected.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SnapshotGap {
    /// A binding refers to a compatibility role with no matching definition.
    UnresolvedRole { role: String },
}

/// Everything one decision reads, immutable once built.
#[derive(Debug, Clone, Default)]
pub struct PolicySnapshot {
    pub(crate) bindings: Vec<SnapshotBinding>,
    pub(crate) bindings_by_subject: HashMap<SubjectRef, Vec<usize>>,
    pub(crate) denies: Vec<SnapshotDeny>,
    pub(crate) denies_by_subject: HashMap<SubjectRef, Vec<usize>>,
    pub(crate) groups_of: HashMap<Uuid, BTreeSet<Uuid>>,
    pub(crate) ceilings: BTreeMap<CredentialRef, Ceiling>,
    pub(crate) break_glass: BTreeSet<Uuid>,
    pub(crate) resources: ResourceIndex,
    gaps: Vec<SnapshotGap>,
}

impl PolicySnapshot {
    /// Build from a legacy projection and the resource facts read with it.
    /// Collections keep the projection's canonical order, so explanations are
    /// deterministic.
    pub fn from_projection(projection: &PolicyProjection, resources: ResourceIndex) -> Self {
        let mut snapshot = PolicySnapshot {
            resources,
            ..Default::default()
        };
        let defined: BTreeSet<&RoleRef> = projection.roles.iter().map(|r| &r.item.role).collect();
        for binding in projection.bindings.iter().map(|b| &b.item) {
            let resolved = match &binding.role {
                RoleRef::System(_) => true,
                RoleRef::Compatibility(_) => defined.contains(&binding.role),
            };
            if !resolved {
                snapshot.gaps.push(SnapshotGap::UnresolvedRole {
                    role: binding.role.name(),
                });
            }
            snapshot.push_binding(SnapshotBinding {
                subject: binding.subject,
                role: binding.role.clone(),
                scope: binding.scope,
                permissions: resolved
                    .then(|| role_effective_permissions(&binding.role, binding.scope)),
                conditions: binding
                    .conditions
                    .as_ref()
                    .map(DecisionConditions::from_projection),
            });
        }
        for deny in projection.denies.iter().map(|d| &d.item) {
            snapshot.push_deny(SnapshotDeny {
                subject: deny.subject,
                scope: deny.scope,
                permissions: deny.permissions.clone(),
                excepted_scopes: deny.excepted_scopes.clone(),
                conditions: deny
                    .conditions
                    .as_ref()
                    .map(DecisionConditions::from_projection),
            });
        }
        for membership in projection.memberships.iter().map(|m| &m.item) {
            snapshot
                .groups_of
                .entry(membership.user_id)
                .or_default()
                .insert(membership.group_id);
        }
        for ceiling in projection.ceilings.iter().map(|c| &c.item) {
            snapshot.ceilings.insert(
                ceiling.credential,
                Ceiling {
                    permissions: ceiling.permissions.clone(),
                    repository_ids: ceiling.repository_ids.clone(),
                },
            );
        }
        snapshot.gaps.sort();
        snapshot.gaps.dedup();
        snapshot
    }

    /// Mark principals as break-glass. Legacy state has none.
    pub fn with_break_glass(mut self, principals: impl IntoIterator<Item = Uuid>) -> Self {
        self.break_glass.extend(principals);
        self
    }

    pub fn push_binding(&mut self, binding: SnapshotBinding) {
        self.bindings_by_subject
            .entry(binding.subject)
            .or_default()
            .push(self.bindings.len());
        self.bindings.push(binding);
    }

    pub fn push_deny(&mut self, deny: SnapshotDeny) {
        self.denies_by_subject
            .entry(deny.subject)
            .or_default()
            .push(self.denies.len());
        self.denies.push(deny);
    }

    pub fn add_membership(&mut self, user: Uuid, group: Uuid) {
        self.groups_of.entry(user).or_default().insert(group);
    }

    pub fn set_ceiling(&mut self, credential: CredentialRef, ceiling: Ceiling) {
        self.ceilings.insert(credential, ceiling);
    }

    pub fn resources(&self) -> &ResourceIndex {
        &self.resources
    }

    pub fn resources_mut(&mut self) -> &mut ResourceIndex {
        &mut self.resources
    }

    pub fn gaps(&self) -> &[SnapshotGap] {
        &self.gaps
    }

    pub fn bindings(&self) -> &[SnapshotBinding] {
        &self.bindings
    }

    pub fn denies(&self) -> &[SnapshotDeny] {
        &self.denies
    }

    pub fn ceiling(&self, credential: CredentialRef) -> Option<&Ceiling> {
        self.ceilings.get(&credential)
    }

    pub fn groups_of(&self, principal: Uuid) -> Option<&BTreeSet<Uuid>> {
        self.groups_of.get(&principal)
    }

    pub fn is_break_glass(&self, principal: Uuid) -> bool {
        self.break_glass.contains(&principal)
    }
}
