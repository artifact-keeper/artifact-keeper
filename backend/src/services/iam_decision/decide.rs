//! The decision function of the IAM authorization model over a [`PolicySnapshot`].
//!
//! Pure and synchronous. It reads nothing but its arguments: no clock, no
//! database, no environment. The same arguments always give the same
//! [`Decision`], including its explanation.

use std::collections::BTreeSet;

use serde::Serialize;

use super::context::{Caller, Principal, RequestContext};
use super::snapshot::{evaluate, PolicySnapshot, SnapshotBinding, Truth};
use crate::api::authz::catalog::Permission;
use crate::models::repository::RepositoryVisibility;
use crate::services::iam_legacy_projection::mapping::scope_kind;
use crate::services::iam_legacy_projection::{RoleRef, ScopeRef, SubjectRef, SystemRole};

/// Access-management permissions no deny withholds from an instance
/// administrator, so an administrator can always correct a policy.
pub const ADMIN_UNDENIABLE: [Permission; 4] = [
    Permission::IamManage,
    Permission::RepositoryIamManage,
    Permission::RoleManage,
    Permission::DenyManage,
];

/// The permissions a repository's visibility grants as its read baseline.
pub const BASELINE_READ: [Permission; 2] = [Permission::RepositoryRead, Permission::ArtifactRead];

/// What granted a permitted request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Grant {
    /// The repository's visibility read baseline.
    Baseline { visibility: RepositoryVisibility },
    /// A binding: its subject (the principal or one of its groups), role and scope.
    Binding {
        subject: SubjectRef,
        role: String,
        scope: ScopeRef,
    },
}

/// The refusal class of a refused decision. It names at most the
/// missing permission, never the binding or deny that decided the refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "class", rename_all = "snake_case")]
pub enum RefusalClass {
    /// No credential and the resource is not readable anonymously (401).
    Unauthenticated,
    /// The caller cannot read the resource (404), whatever it asked for.
    NotFound,
    /// The caller can read the resource, or it is an instance operation, but
    /// lacks this permission (403).
    Forbidden { missing: Permission },
}

/// Why a decision could not be made. Reported as a retryable server-side
/// error, never as a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Unavailability {
    /// The resource is not in the snapshot's resource index.
    UnknownResource,
    /// The presented credential's ceiling is not in the snapshot.
    UnknownCredential,
    /// A binding that could grant refers to a role the snapshot could not resolve.
    UnresolvedRole,
    /// A deny that may withhold the permission needs the client IP, which is unknown.
    UnknownDeny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Decision {
    Permit { grant: Grant },
    Refuse { refusal: RefusalClass },
    Unavailable { reason: Unavailability },
}

impl Decision {
    pub fn is_permit(&self) -> bool {
        matches!(self, Decision::Permit { .. })
    }
}

/// Decide whether `caller` may use `permission` on `resource`.
pub fn decide(
    snapshot: &PolicySnapshot,
    caller: &Caller,
    permission: Permission,
    resource: ScopeRef,
    ctx: &RequestContext,
) -> Decision {
    match core(snapshot, caller, permission, resource, ctx) {
        Core::Permit(grant) => Decision::Permit { grant },
        Core::Unavailable(reason) => Decision::Unavailable { reason },
        Core::Refuse => Decision::Refuse {
            refusal: refusal_class(snapshot, caller, permission, resource, ctx),
        },
    }
}

enum Core {
    Permit(Grant),
    Refuse,
    Unavailable(Unavailability),
}

fn core(
    snapshot: &PolicySnapshot,
    caller: &Caller,
    permission: Permission,
    resource: ScopeRef,
    ctx: &RequestContext,
) -> Core {
    let Some(chain) = snapshot.resources().chain(resource) else {
        return Core::Unavailable(Unavailability::UnknownResource);
    };

    // The credential ceiling bounds everything, the baseline included.
    let mut narrow_credential = false;
    if let Some(credential) = caller.credential {
        let Some(ceiling) = snapshot.ceiling(credential) else {
            return Core::Unavailable(Unavailability::UnknownCredential);
        };
        if !ceiling.allows(permission, resource) {
            return Core::Refuse;
        }
        narrow_credential = ceiling.permissions.is_some();
    }

    // A permission is only ever checked where it applies.
    if !permission.applies_at(scope_kind(resource)) {
        return Core::Refuse;
    }

    if let Some(visibility) = baseline(snapshot, caller.principal, permission, resource) {
        return Core::Permit(Grant::Baseline { visibility });
    }

    let subjects = subjects_of(snapshot, caller.principal);
    let mut granting: Option<&SnapshotBinding> = None;
    let mut unresolved = false;
    let mut is_admin = false;
    for binding in bindings_in_chain(snapshot, &subjects, &chain) {
        if narrow_credential && is_admin_role(binding) {
            continue;
        }
        let truth = evaluate(binding.conditions.as_ref(), ctx);
        match &binding.permissions {
            // An unknown IP makes an allow condition false, so only a binding
            // whose conditions hold could have granted.
            None => unresolved |= truth == Truth::True,
            Some(perms) if truth == Truth::True => {
                if binding.scope == ScopeRef::Instance && is_admin_role(binding) {
                    is_admin = true;
                }
                if granting.is_none() && perms.contains(&permission) {
                    granting = Some(binding);
                }
            }
            Some(_) => {}
        }
    }
    let Some(binding) = granting else {
        return if unresolved {
            Core::Unavailable(Unavailability::UnresolvedRole)
        } else {
            Core::Refuse
        };
    };
    let grant = Grant::Binding {
        subject: binding.subject,
        role: binding.role.name(),
        scope: binding.scope,
    };

    let break_glass = caller
        .principal
        .id()
        .is_some_and(|id| snapshot.is_break_glass(id));
    if break_glass || (is_admin && ADMIN_UNDENIABLE.contains(&permission)) {
        return Core::Permit(grant);
    }

    let mut unknown = false;
    for deny in denies_in_chain(snapshot, &subjects, &chain) {
        if !deny.permissions.contains(&permission) {
            continue;
        }
        match evaluate(deny.conditions.as_ref(), ctx) {
            Truth::True => return Core::Refuse,
            Truth::Unknown => unknown = true,
            Truth::False => {}
        }
    }
    if unknown {
        Core::Unavailable(Unavailability::UnknownDeny)
    } else {
        Core::Permit(grant)
    }
}

/// The visibility baseline for `permission` on `resource`, if it grants one.
fn baseline(
    snapshot: &PolicySnapshot,
    principal: Principal,
    permission: Permission,
    resource: ScopeRef,
) -> Option<RepositoryVisibility> {
    let ScopeRef::Repository(id) = resource else {
        return None;
    };
    if !BASELINE_READ.contains(&permission) {
        return None;
    }
    let visibility = snapshot.resources().repositories.get(&id)?.visibility;
    let grants = match visibility {
        RepositoryVisibility::Public => true,
        RepositoryVisibility::Internal => principal.is_authenticated(),
        RepositoryVisibility::Private => false,
    };
    grants.then_some(visibility)
}

/// The principal's own subject and the groups it belongs to.
fn subjects_of(snapshot: &PolicySnapshot, principal: Principal) -> BTreeSet<SubjectRef> {
    let mut subjects = BTreeSet::from([principal.subject()]);
    if let Some(groups) = principal.id().and_then(|id| snapshot.groups_of(id)) {
        subjects.extend(groups.iter().map(|g| SubjectRef::Group(*g)));
    }
    subjects
}

/// The bindings of `subjects` at a scope in `chain`, in snapshot order.
fn bindings_in_chain<'a>(
    snapshot: &'a PolicySnapshot,
    subjects: &BTreeSet<SubjectRef>,
    chain: &[ScopeRef],
) -> impl Iterator<Item = &'a SnapshotBinding> {
    let indices = indices_for(&snapshot.bindings_by_subject, subjects);
    let chain = chain.to_vec();
    indices
        .into_iter()
        .map(|i| &snapshot.bindings[i])
        .filter(move |b| chain.contains(&b.scope))
}

/// The denies of `subjects` at a scope in `chain` that do not except any scope
/// in `chain`, in snapshot order.
fn denies_in_chain<'a>(
    snapshot: &'a PolicySnapshot,
    subjects: &BTreeSet<SubjectRef>,
    chain: &[ScopeRef],
) -> impl Iterator<Item = &'a super::snapshot::SnapshotDeny> {
    let indices = indices_for(&snapshot.denies_by_subject, subjects);
    let chain = chain.to_vec();
    indices
        .into_iter()
        .map(|i| &snapshot.denies[i])
        .filter(move |d| {
            chain.contains(&d.scope) && !d.excepted_scopes.iter().any(|e| chain.contains(e))
        })
}

fn indices_for(
    by_subject: &std::collections::HashMap<SubjectRef, Vec<usize>>,
    subjects: &BTreeSet<SubjectRef>,
) -> BTreeSet<usize> {
    subjects
        .iter()
        .filter_map(|s| by_subject.get(s))
        .flatten()
        .copied()
        .collect()
}

/// The refusal class, decided from the caller's effective permissions: can it
/// read the resource at all?
fn refusal_class(
    snapshot: &PolicySnapshot,
    caller: &Caller,
    permission: Permission,
    resource: ScopeRef,
    ctx: &RequestContext,
) -> RefusalClass {
    let read = match resource {
        // An instance operation names no resource to hide: always forbidden.
        ScopeRef::Instance => {
            return RefusalClass::Forbidden {
                missing: permission,
            }
        }
        ScopeRef::Repository(_) => Permission::RepositoryRead,
        ScopeRef::Project(_) => Permission::ProjectRead,
        ScopeRef::Group(_) => Permission::GroupRead,
    };
    let can_read = permission != read
        && matches!(core(snapshot, caller, read, resource, ctx), Core::Permit(_));
    match (can_read, caller.principal) {
        (true, _) => RefusalClass::Forbidden {
            missing: permission,
        },
        (false, Principal::Anonymous) => RefusalClass::Unauthenticated,
        (false, _) => RefusalClass::NotFound,
    }
}

/// A binding of the `admin` system role. It confers nothing through a
/// credential whose ceiling restricts permissions: an administrator acts as
/// one only with an unrestricted credential, as a legacy token needs the
/// `admin` or `*` scope to be an administrator.
fn is_admin_role(binding: &SnapshotBinding) -> bool {
    binding.role == RoleRef::System(SystemRole::Admin)
}

/// Whether `caller` acts as an instance administrator in this context.
pub fn is_instance_admin(snapshot: &PolicySnapshot, caller: &Caller, ctx: &RequestContext) -> bool {
    if let Some(credential) = caller.credential {
        match snapshot.ceiling(credential) {
            Some(ceiling) if ceiling.permissions.is_none() => {}
            _ => return false,
        }
    }
    let subjects = subjects_of(snapshot, caller.principal);
    bindings_in_chain(snapshot, &subjects, &[ScopeRef::Instance]).any(|b| {
        is_admin_role(b)
            && b.permissions.is_some()
            && evaluate(b.conditions.as_ref(), ctx) == Truth::True
    })
}
