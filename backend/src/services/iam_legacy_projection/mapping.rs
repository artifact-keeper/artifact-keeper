//! The fixed mapping tables: legacy actions to catalog permissions, system
//! roles to their permission sets, token scopes to ceilings.
//!
//! These encode the upgrade plan of the IAM design. One rule runs through all of
//! them: a mapping may remove access only where the design enumerates a
//! tightening, and may never add access. In particular no `build.*` permission
//! is inferred from a generic legacy `read` or `write`, because the product
//! mapping for builds is not agreed.

use std::collections::BTreeSet;

use crate::api::authz::catalog::{Permission, Scope};

use super::intent::{RoleDefinition, RoleRef, ScopeRef, SystemRole};

use Permission as P;

/// The legacy action vocabulary (`roles.permissions`, `permissions.actions`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LegacyAction {
    Read,
    Write,
    Delete,
    Admin,
}

impl LegacyAction {
    pub fn parse(text: &str) -> Option<LegacyAction> {
        match text {
            "read" => Some(LegacyAction::Read),
            "write" => Some(LegacyAction::Write),
            "delete" => Some(LegacyAction::Delete),
            "admin" => Some(LegacyAction::Admin),
            _ => None,
        }
    }
}

/// Split action strings into the known vocabulary and the unknown strings.
pub fn parse_actions(actions: &[String]) -> (BTreeSet<LegacyAction>, Vec<String>) {
    let mut known = BTreeSet::new();
    let mut unknown = Vec::new();
    for action in actions {
        match LegacyAction::parse(action) {
            Some(a) => {
                known.insert(a);
            }
            None => unknown.push(action.clone()),
        }
    }
    (known, unknown)
}

fn set(perms: &[Permission]) -> BTreeSet<Permission> {
    perms.iter().copied().collect()
}

/// The permissions of a system role, as the `iam-model` spec defines them.
pub fn system_role_permissions(role: SystemRole) -> BTreeSet<Permission> {
    let viewer = [
        P::RepositoryRead,
        P::ArtifactRead,
        P::SecurityRead,
        P::EnvironmentRead,
        P::BuildRead,
    ];
    let developer_extra = [
        P::ArtifactWrite,
        P::ArtifactAnnotate,
        P::RepositoryLabelManage,
        P::EnvironmentWrite,
        P::BuildWrite,
    ];
    let maintainer_extra = [
        P::ArtifactDelete,
        P::RepositoryUpdate,
        P::RepositoryNotificationsManage,
        P::RepositoryMaintenance,
        P::PromotionReject,
        P::SecurityScan,
        P::ImageBuildCreate,
    ];
    let owner_extra = [
        P::RepositoryDelete,
        P::RepositoryCredentialsUpdate,
        P::RepositoryTokenManage,
        P::RepositoryIamManage,
    ];
    match role {
        SystemRole::Viewer => set(&viewer),
        SystemRole::Developer => set(&viewer)
            .union(&set(&developer_extra))
            .copied()
            .collect(),
        SystemRole::Maintainer => [&viewer[..], &developer_extra, &maintainer_extra]
            .concat()
            .into_iter()
            .collect(),
        SystemRole::Owner => [
            &viewer[..],
            &developer_extra,
            &maintainer_extra,
            &owner_extra,
        ]
        .concat()
        .into_iter()
        .collect(),
        SystemRole::ReleaseManager => set(&[
            P::PromotionCreate,
            P::PromotionReceive,
            P::PromotionRequest,
            P::PromotionApprove,
        ]),
        SystemRole::SecurityOfficer => Permission::ALL
            .iter()
            .copied()
            .filter(|p| p.id().starts_with("security.") && *p != P::SecurityFindingsIngest)
            .chain([P::CurationReview, P::AgeGateReview])
            .collect(),
        SystemRole::Admin => Permission::ALL.iter().copied().collect(),
    }
}

pub fn scope_kind(scope: ScopeRef) -> Scope {
    match scope {
        ScopeRef::Instance => Scope::Instance,
        ScopeRef::Group(_) => Scope::Group,
        ScopeRef::Project(_) => Scope::Project,
        ScopeRef::Repository(_) => Scope::Repository,
    }
}

/// The permissions of a role that take effect at `scope`: the others are not
/// applicable there and contribute nothing.
pub fn effective_permissions(
    permissions: &BTreeSet<Permission>,
    scope: Scope,
) -> BTreeSet<Permission> {
    permissions
        .iter()
        .copied()
        .filter(|p| p.applies_at(scope))
        .collect()
}

fn is_build(p: Permission) -> bool {
    p.id().starts_with("build.")
}

/// What a legacy action grants in the target model, with no `build.*`.
///
/// `write` stops at the `developer` content set: the repository-configuration
/// writes `write` allowed before (#4588 aside) are an enumerated tightening and
/// are not reproduced. `admin` means every action, which is the `owner` set.
pub fn action_permissions(action: LegacyAction) -> BTreeSet<Permission> {
    let viewer = system_role_permissions(SystemRole::Viewer);
    let developer = system_role_permissions(SystemRole::Developer);
    let owner = system_role_permissions(SystemRole::Owner);
    let without_builds = |s: BTreeSet<Permission>| -> BTreeSet<Permission> {
        s.into_iter().filter(|p| !is_build(*p)).collect()
    };
    match action {
        LegacyAction::Read => without_builds(viewer),
        LegacyAction::Write => without_builds(developer.difference(&viewer).copied().collect()),
        LegacyAction::Delete => set(&[P::ArtifactDelete]),
        LegacyAction::Admin => without_builds(owner),
    }
}

/// The union of the permissions of a set of legacy actions. `admin` allows
/// every action, so it subsumes the others.
pub fn permissions_for_actions(actions: &BTreeSet<LegacyAction>) -> BTreeSet<Permission> {
    actions
        .iter()
        .flat_map(|a| action_permissions(*a))
        .collect()
}

/// The role to bind for `permissions` at `scope`: a system role when its
/// scope-applicable permissions are exactly `permissions`, otherwise a
/// compatibility role holding exactly them.
pub fn role_for(
    permissions: &BTreeSet<Permission>,
    scope: ScopeRef,
) -> (RoleRef, Option<RoleDefinition>) {
    let kind = scope_kind(scope);
    for role in [
        SystemRole::Viewer,
        SystemRole::Developer,
        SystemRole::Maintainer,
        SystemRole::Owner,
    ] {
        if &effective_permissions(&system_role_permissions(role), kind) == permissions {
            return (RoleRef::System(role), None);
        }
    }
    let role = RoleRef::Compatibility(permissions.clone());
    let definition = RoleDefinition {
        role: role.clone(),
        permissions: permissions.clone(),
    };
    (role, Some(definition))
}

/// The permissions a binding of `role` confers at `scope`.
pub fn role_effective_permissions(role: &RoleRef, scope: ScopeRef) -> BTreeSet<Permission> {
    let all = match role {
        RoleRef::System(r) => system_role_permissions(*r),
        RoleRef::Compatibility(p) => p.clone(),
    };
    effective_permissions(&all, scope_kind(scope))
}

/// The exact capability the project `admin` rule (#4391) confers on one project.
pub fn project_admin_permissions() -> BTreeSet<Permission> {
    set(&[
        P::ProjectRead,
        P::ProjectUpdate,
        P::IamManage,
        P::RepositoryCreate,
    ])
}

/// The capability the instance-level sentinel `admin` rule gates today.
pub fn sentinel_admin_permissions() -> BTreeSet<Permission> {
    set(&[P::RepositoryCreate])
}

/// What a group target's legacy action set confers, or `None` when the set has
/// neither `admin` nor `read` (nothing the model can represent).
pub fn group_permissions(actions: &BTreeSet<LegacyAction>) -> Option<BTreeSet<Permission>> {
    if actions.contains(&LegacyAction::Admin) {
        Some(set(&[P::GroupRead, P::GroupManage]))
    } else if actions == &BTreeSet::from([LegacyAction::Read]) {
        Some(set(&[P::GroupRead]))
    } else {
        None
    }
}

/// A token scope's ceiling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeCeiling {
    Unrestricted,
    Permissions(BTreeSet<Permission>),
}

/// Permissions that manage access or the instance itself; a `write` token
/// never reaches them.
fn is_access_or_instance_admin(p: Permission) -> bool {
    matches!(
        p,
        P::IamManage
            | P::RepositoryIamManage
            | P::RoleManage
            | P::DenyManage
            | P::UserManage
            | P::UserCredentialsManage
            | P::ServiceAccountManage
            | P::ServiceAccountTokenCreate
            | P::IdentityProviderManage
            | P::GroupManage
            | P::GroupCreate
    ) || p.id().starts_with("system.")
}

/// The ceiling a legacy token scope string maps to, or `None` for a scope the
/// mapping does not know.
pub fn scope_ceiling(scope: &str) -> Option<ScopeCeiling> {
    let all = || Permission::ALL.iter().copied();
    let perms: BTreeSet<Permission> = match scope {
        "admin" | "*" => return Some(ScopeCeiling::Unrestricted),
        "read" => all().filter(|p| p.id().ends_with(".read")).collect(),
        "read:artifacts" => set(&[P::ArtifactRead, P::RepositoryRead]),
        "write" => all()
            .filter(|p| {
                !p.id().ends_with(".read")
                    && !p.id().ends_with(".delete")
                    && !is_access_or_instance_admin(*p)
            })
            .collect(),
        "write:artifacts" => set(&[P::ArtifactWrite, P::ArtifactAnnotate]),
        "write:repositories" => set(&[P::RepositoryUpdate, P::RepositoryNotificationsManage]),
        "write:findings" => set(&[P::SecurityFindingsIngest]),
        "write:users" => set(&[P::UserManage]),
        "delete" => all().filter(|p| p.id().ends_with(".delete")).collect(),
        "delete:artifacts" => set(&[P::ArtifactDelete]),
        "promote:artifacts" => all().filter(|p| p.id().starts_with("promotion.")).collect(),
        "trigger:sync" => set(&[P::ReplicationTrigger, P::CurationPublish]),
        _ => return None,
    };
    Some(ScopeCeiling::Permissions(perms))
}

/// The capability a scope grants (not merely limits): `promote:artifacts` and
/// `trigger:sync` also create a binding for the token's owning principal.
pub fn scope_grant(scope: &str) -> Option<ScopeGrant> {
    match scope {
        "promote:artifacts" => Some(ScopeGrant::ReleaseManager),
        "trigger:sync" => Some(ScopeGrant::Compat(set(&[
            P::ReplicationTrigger,
            P::CurationPublish,
        ]))),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeGrant {
    ReleaseManager,
    Compat(BTreeSet<Permission>),
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn actions(list: &[&str]) -> BTreeSet<LegacyAction> {
        let owned: Vec<String> = list.iter().map(|s| s.to_string()).collect();
        parse_actions(&owned).0
    }

    #[test]
    fn unknown_actions_are_separated() {
        let (known, unknown) = parse_actions(&["read".into(), "execute".into(), "admin".into()]);
        assert_eq!(
            known,
            BTreeSet::from([LegacyAction::Read, LegacyAction::Admin])
        );
        assert_eq!(unknown, vec!["execute".to_string()]);
    }

    #[test]
    fn no_action_infers_build_permissions() {
        for a in [
            LegacyAction::Read,
            LegacyAction::Write,
            LegacyAction::Delete,
            LegacyAction::Admin,
        ] {
            assert!(
                action_permissions(a)
                    .iter()
                    .all(|p| !p.id().starts_with("build.")),
                "{a:?}"
            );
        }
    }

    #[test]
    fn admin_action_is_every_action() {
        let admin = permissions_for_actions(&actions(&["admin"]));
        for a in [
            LegacyAction::Read,
            LegacyAction::Write,
            LegacyAction::Delete,
        ] {
            assert!(admin.is_superset(&action_permissions(a)), "{a:?}");
        }
        assert!(admin.contains(&P::RepositoryDelete));
        assert!(admin.contains(&P::RepositoryIamManage));
    }

    #[test]
    fn repository_scope_picks_system_roles_only_on_exact_match() {
        let repo = ScopeRef::Repository(Uuid::nil());
        let read = permissions_for_actions(&actions(&["read"]));
        assert_eq!(role_for(&read, repo).0, RoleRef::System(SystemRole::Viewer));
        let rw = permissions_for_actions(&actions(&["read", "write"]));
        assert_eq!(
            role_for(&rw, repo).0,
            RoleRef::System(SystemRole::Developer)
        );
        let admin = permissions_for_actions(&actions(&["admin"]));
        assert_eq!(role_for(&admin, repo).0, RoleRef::System(SystemRole::Owner));
        // read+write+delete matches no system role at repository scope.
        let rwd = permissions_for_actions(&actions(&["read", "write", "delete"]));
        let (role, def) = role_for(&rwd, repo);
        assert!(matches!(role, RoleRef::Compatibility(_)));
        assert_eq!(def.unwrap().permissions, rwd);
    }

    #[test]
    fn project_and_instance_scope_do_not_infer_builds() {
        // At project scope `developer` would add build.read/build.write, which
        // no legacy action granted, so the exact-match rule falls back.
        for scope in [ScopeRef::Project(Uuid::nil()), ScopeRef::Instance] {
            let rw = permissions_for_actions(&actions(&["read", "write"]));
            let (role, def) = role_for(&rw, scope);
            assert!(matches!(role, RoleRef::Compatibility(_)), "{scope:?}");
            assert!(def
                .unwrap()
                .permissions
                .iter()
                .all(|p| !p.id().starts_with("build.")));
        }
    }

    #[test]
    fn role_effective_permissions_follow_scope_applicability() {
        let eff = role_effective_permissions(
            &RoleRef::System(SystemRole::Developer),
            ScopeRef::Repository(Uuid::nil()),
        );
        assert!(eff.contains(&P::ArtifactWrite));
        // build.* is project scope: not effective through a repository binding.
        assert!(!eff.contains(&P::BuildWrite));
        let at_project = role_effective_permissions(
            &RoleRef::System(SystemRole::Developer),
            ScopeRef::Project(Uuid::nil()),
        );
        assert!(at_project.contains(&P::BuildWrite));
    }

    #[test]
    fn delegated_capabilities_are_exact() {
        assert_eq!(sentinel_admin_permissions(), set(&[P::RepositoryCreate]));
        let project_admin = project_admin_permissions();
        assert!(project_admin.contains(&P::ProjectUpdate));
        assert!(!project_admin.contains(&P::ProjectDelete));
        assert!(!project_admin.contains(&P::RepositoryDelete));
        assert_eq!(
            group_permissions(&actions(&["admin"])),
            Some(set(&[P::GroupRead, P::GroupManage]))
        );
        assert_eq!(
            group_permissions(&actions(&["read"])),
            Some(set(&[P::GroupRead]))
        );
        assert_eq!(group_permissions(&actions(&["write"])), None);
    }

    #[test]
    fn scope_ceilings_match_the_table() {
        assert_eq!(scope_ceiling("admin"), Some(ScopeCeiling::Unrestricted));
        assert_eq!(scope_ceiling("*"), Some(ScopeCeiling::Unrestricted));
        assert_eq!(
            scope_ceiling("read:artifacts"),
            Some(ScopeCeiling::Permissions(set(&[
                P::ArtifactRead,
                P::RepositoryRead
            ])))
        );
        assert_eq!(
            scope_ceiling("write:artifacts"),
            Some(ScopeCeiling::Permissions(set(&[
                P::ArtifactWrite,
                P::ArtifactAnnotate
            ])))
        );
        let Some(ScopeCeiling::Permissions(read)) = scope_ceiling("read") else {
            panic!()
        };
        assert!(read.iter().all(|p| p.id().ends_with(".read")));
        let Some(ScopeCeiling::Permissions(write)) = scope_ceiling("write") else {
            panic!()
        };
        assert!(write.contains(&P::ArtifactWrite));
        assert!(!write.contains(&P::ArtifactRead) && !write.contains(&P::ArtifactDelete));
        assert!(!write.contains(&P::IamManage) && !write.contains(&P::SystemSettingsUpdate));
        assert_eq!(scope_ceiling("nonsense"), None);
    }

    #[test]
    fn only_two_scopes_also_grant() {
        assert_eq!(
            scope_grant("promote:artifacts"),
            Some(ScopeGrant::ReleaseManager)
        );
        assert!(matches!(
            scope_grant("trigger:sync"),
            Some(ScopeGrant::Compat(_))
        ));
        for scope in ["read", "write", "admin", "write:artifacts", "delete"] {
            assert_eq!(scope_grant(scope), None, "{scope}");
        }
    }
}
