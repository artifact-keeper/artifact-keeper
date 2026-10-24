//! Scenario, equivalence and determinism tests for the projection.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use serde_json::json;
use uuid::Uuid;

use super::intent::*;
use super::legacy::*;
use super::mapping::{permissions_for_actions, role_effective_permissions, LegacyAction};
use super::project::{project, project_legacy_state, ProjectionLimits};
use crate::api::authz::catalog::Permission;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

struct World {
    state: LegacyAuthorizationState,
    next: u128,
}

const ROLE_ADMIN: u128 = 1;
const ROLE_DEVELOPER: u128 = 2;
const ROLE_READER: u128 = 3;
const ROLE_OWNER: u128 = 4;
const ROLE_USER: u128 = 5;

impl World {
    fn new() -> World {
        let role = |id: u128, name: &str, perms: &[&str]| LegacyRole {
            id: Uuid::from_u128(id),
            name: name.to_string(),
            permissions: perms.iter().map(|p| p.to_string()).collect(),
        };
        World {
            state: LegacyAuthorizationState {
                roles: vec![
                    role(ROLE_ADMIN, "admin", &["read", "write", "delete", "admin"]),
                    role(ROLE_DEVELOPER, "developer", &["read", "write"]),
                    role(ROLE_READER, "reader", &["read"]),
                    role(
                        ROLE_OWNER,
                        "repository-owner",
                        &["read", "write", "delete", "admin"],
                    ),
                    role(ROLE_USER, "user", &[]),
                ],
                ..Default::default()
            },
            next: 1000,
        }
    }

    fn id(&mut self) -> Uuid {
        self.next += 1;
        Uuid::from_u128(self.next)
    }

    fn user(&mut self, name: &str) -> Uuid {
        self.add_user(name, LegacyAuthSource::Local, false, false)
    }

    fn admin(&mut self, name: &str) -> Uuid {
        self.add_user(name, LegacyAuthSource::Local, true, false)
    }

    fn service_account(&mut self, name: &str) -> Uuid {
        self.add_user(name, LegacyAuthSource::Local, false, true)
    }

    fn sso_user(&mut self, name: &str, kind: &str, is_admin: bool) -> Uuid {
        self.add_user(
            name,
            LegacyAuthSource::External(kind.to_string()),
            is_admin,
            false,
        )
    }

    fn add_user(&mut self, name: &str, source: LegacyAuthSource, is_admin: bool, sa: bool) -> Uuid {
        let id = self.id();
        self.state.users.push(LegacyUser {
            id,
            username: name.to_string(),
            auth_source: source,
            is_admin,
            is_active: true,
            is_service_account: sa,
        });
        id
    }

    fn group(&mut self, name: &str) -> Uuid {
        let id = self.id();
        self.state.groups.push(LegacyGroup {
            id,
            name: name.to_string(),
            external_source: None,
            external_provider_id: None,
        });
        id
    }

    fn tagged_group(&mut self, name: &str, source: &str) -> Uuid {
        let id = self.group(name);
        let provider = self.id();
        let g = self.state.groups.iter_mut().find(|g| g.id == id).unwrap();
        g.external_source = Some(source.to_string());
        g.external_provider_id = Some(provider);
        id
    }

    fn member(&mut self, user: Uuid, group: Uuid) {
        self.state.memberships.push(LegacyMembership {
            user_id: user,
            group_id: group,
        });
    }

    fn project(&mut self, key: &str) -> Uuid {
        let id = self.id();
        self.state.projects.push(LegacyProject {
            id,
            key: key.to_string(),
        });
        id
    }

    fn repo(&mut self, key: &str, project: Option<Uuid>) -> Uuid {
        let id = self.id();
        self.state.repositories.push(LegacyRepository {
            id,
            key: key.to_string(),
            project_id: project,
        });
        id
    }

    fn assign(&mut self, user: Uuid, role: u128, repo: Option<Uuid>) -> Uuid {
        let id = self.id();
        self.state.role_assignments.push(LegacyRoleAssignment {
            id,
            user_id: user,
            role_id: Uuid::from_u128(role),
            repository_id: repo,
        });
        id
    }

    fn rule(
        &mut self,
        principal: LegacyPrincipal,
        target_type: &str,
        target: Uuid,
        actions: &[&str],
        cidrs: Option<&[&str]>,
    ) -> Uuid {
        let id = self.id();
        self.state.rules.push(LegacyRule {
            id,
            principal,
            target_type: target_type.to_string(),
            target_id: target,
            actions: actions.iter().map(|a| a.to_string()).collect(),
            conditions: cidrs.map(|c| json!({ "allowed_cidrs": c })),
        });
        id
    }

    fn project_it(&self) -> PolicyProjection {
        project_legacy_state(&self.state)
    }
}

fn user_rule(
    w: &mut World,
    user: Uuid,
    target_type: &str,
    target: Uuid,
    actions: &[&str],
    cidrs: Option<&[&str]>,
) -> Uuid {
    w.rule(
        LegacyPrincipal::User(user),
        target_type,
        target,
        actions,
        cidrs,
    )
}

fn bindings_of(p: &PolicyProjection, subject: SubjectRef) -> Vec<&Binding> {
    p.bindings
        .iter()
        .map(|b| &b.item)
        .filter(|b| b.subject == subject)
        .collect()
}

fn categories(p: &PolicyProjection) -> Vec<DiagnosticCategory> {
    p.report.diagnostics.iter().map(|d| d.category).collect()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

// ---------------------------------------------------------------------------
// 2.1 role assignments, rules, scopes
// ---------------------------------------------------------------------------

#[test]
fn repository_roles_map_to_system_roles_at_repository_scope() {
    let mut w = World::new();
    let dev = w.user("dev");
    let reader = w.user("reader");
    let owner = w.user("owner");
    let repo = w.repo("r", None);
    w.assign(dev, ROLE_DEVELOPER, Some(repo));
    w.assign(reader, ROLE_READER, Some(repo));
    w.assign(owner, ROLE_OWNER, Some(repo));
    let p = w.project_it();

    let scope = ScopeRef::Repository(repo);
    let role = |u| bindings_of(&p, SubjectRef::User(u))[0].role.clone();
    assert_eq!(role(dev), RoleRef::System(SystemRole::Developer));
    assert_eq!(role(reader), RoleRef::System(SystemRole::Viewer));
    assert_eq!(role(owner), RoleRef::System(SystemRole::Owner));
    assert!(bindings_of(&p, SubjectRef::User(dev))[0].scope == scope);
    // The owner gains repository administration: reported, not hidden.
    assert!(categories(&p).contains(&DiagnosticCategory::OwnerWidening));
}

#[test]
fn global_roles_do_not_infer_build_permissions() {
    let mut w = World::new();
    let dev = w.user("dev");
    w.assign(dev, ROLE_DEVELOPER, None);
    let p = w.project_it();
    let b = bindings_of(&p, SubjectRef::User(dev));
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].scope, ScopeRef::Instance);
    // `developer` at instance scope would add build.*, so a compatibility role is used.
    let RoleRef::Compatibility(perms) = &b[0].role else {
        panic!("expected a compatibility role, got {:?}", b[0].role)
    };
    assert!(perms.iter().all(|p| !p.id().starts_with("build.")));
    assert!(perms.contains(&Permission::ArtifactWrite));
    assert_eq!(p.roles.len(), 1);
}

#[test]
fn project_rules_bind_at_project_scope_without_builds() {
    let mut w = World::new();
    let u = w.user("u");
    let project = w.project("p");
    user_rule(&mut w, u, "project", project, &["read", "write"], None);
    let p = w.project_it();
    let b = bindings_of(&p, SubjectRef::User(u));
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].scope, ScopeRef::Project(project));
    let eff = role_effective_permissions(&b[0].role, b[0].scope);
    assert!(eff.contains(&Permission::ArtifactWrite));
    assert!(!eff.contains(&Permission::BuildWrite) && !eff.contains(&Permission::BuildRead));
}

#[test]
fn roles_conferring_nothing_and_non_authoritative_tables_create_no_grants() {
    let mut w = World::new();
    let u = w.user("u");
    let repo = w.repo("r", None);
    w.assign(u, ROLE_USER, Some(repo));
    w.state.user_roles.push(LegacyUserRole {
        user_id: u,
        role_id: Uuid::from_u128(ROLE_ADMIN),
    });
    w.state.permission_grants.push(Uuid::from_u128(77));
    let p = w.project_it();
    assert!(p.bindings.is_empty() && p.denies.is_empty());
    let dropped = p
        .report
        .diagnostics
        .iter()
        .filter(|d| d.category == DiagnosticCategory::Dropped)
        .count();
    assert_eq!(dropped, 2);
    assert_eq!(p.report.completeness, Completeness::Complete);
}

// ---------------------------------------------------------------------------
// 2.2 delegated capabilities
// ---------------------------------------------------------------------------

#[test]
fn sentinel_admin_becomes_repository_creation_not_instance_admin() {
    let mut w = World::new();
    let u = w.user("delegate");
    user_rule(&mut w, u, "repository", Uuid::nil(), &["admin"], None);
    let p = w.project_it();
    let b = bindings_of(&p, SubjectRef::User(u));
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].scope, ScopeRef::Instance);
    assert_eq!(
        role_effective_permissions(&b[0].role, ScopeRef::Instance),
        BTreeSet::from([Permission::RepositoryCreate])
    );
    assert_ne!(b[0].role, RoleRef::System(SystemRole::Admin));
}

#[test]
fn group_admin_manages_only_its_group() {
    let mut w = World::new();
    let u = w.user("delegate");
    let g = w.group("team");
    let other = w.group("other");
    user_rule(&mut w, u, "group", g, &["admin"], None);
    let p = w.project_it();
    let b = bindings_of(&p, SubjectRef::User(u));
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].scope, ScopeRef::Group(g));
    assert_ne!(b[0].scope, ScopeRef::Group(other));
    assert_eq!(
        role_effective_permissions(&b[0].role, b[0].scope),
        BTreeSet::from([Permission::GroupRead, Permission::GroupManage])
    );
    // No access-policy authority.
    assert!(!role_effective_permissions(&b[0].role, b[0].scope).contains(&Permission::IamManage));
}

#[test]
fn project_admin_is_exactly_the_project_gate_capabilities() {
    let mut w = World::new();
    let u = w.user("pa");
    let project = w.project("p");
    user_rule(&mut w, u, "project", project, &["admin"], None);
    let p = w.project_it();
    let mut all: BTreeSet<Permission> = BTreeSet::new();
    for b in bindings_of(&p, SubjectRef::User(u)) {
        assert_eq!(b.scope, ScopeRef::Project(project));
        all.extend(role_effective_permissions(&b.role, b.scope));
    }
    for needed in [
        Permission::ProjectRead,
        Permission::ProjectUpdate,
        Permission::IamManage,
        Permission::RepositoryCreate,
    ] {
        assert!(all.contains(&needed), "{needed}");
    }
    for never in [
        Permission::ProjectDelete,
        Permission::ProjectCreate,
        Permission::UserManage,
        Permission::SystemSettingsUpdate,
    ] {
        assert!(!all.contains(&never), "{never}");
    }
    assert!(bindings_of(&p, SubjectRef::User(u))
        .iter()
        .all(|b| b.role != RoleRef::System(SystemRole::Admin)));
}

#[test]
fn unsupported_group_actions_are_reported_not_granted() {
    let mut w = World::new();
    let u = w.user("u");
    let g = w.group("team");
    user_rule(&mut w, u, "group", g, &["write"], None);
    let p = w.project_it();
    assert!(p.bindings.is_empty());
    assert_eq!(p.report.completeness, Completeness::Incomplete);
}

// ---------------------------------------------------------------------------
// 2.3 administrators and groups
// ---------------------------------------------------------------------------

#[test]
fn local_admin_gets_an_instance_admin_binding() {
    let mut w = World::new();
    let a = w.admin("root");
    let p = w.project_it();
    let b = bindings_of(&p, SubjectRef::User(a));
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].role, RoleRef::System(SystemRole::Admin));
    assert_eq!(b[0].scope, ScopeRef::Instance);
}

#[test]
fn sso_admin_is_explained_by_a_configured_group_or_reported_ambiguous() {
    let mut w = World::new();
    let explained = w.sso_user("alice", "oidc", true);
    let ambiguous = w.sso_user("bob", "oidc", true);
    let group = w.tagged_group("platform-admins", "oidc");
    w.member(explained, group);
    w.state.sso.providers.push(LegacySsoAdminConfig {
        provider: "oidc".into(),
        admin_groups: vec!["platform-admins".into()],
    });
    let p = w.project_it();

    // The group is the administrator; no user binding for either SSO user.
    assert!(bindings_of(&p, SubjectRef::User(explained)).is_empty());
    assert!(bindings_of(&p, SubjectRef::User(ambiguous)).is_empty());
    let group_bindings = bindings_of(&p, SubjectRef::Group(group));
    assert_eq!(group_bindings.len(), 1);
    assert_eq!(group_bindings[0].role, RoleRef::System(SystemRole::Admin));
    assert_eq!(p.external_group_mappings.len(), 1);
    assert_eq!(
        p.external_group_mappings[0].item.external_group,
        "platform-admins"
    );

    let ambiguous_diags: Vec<_> = p
        .report
        .diagnostics
        .iter()
        .filter(|d| d.category == DiagnosticCategory::AmbiguousSsoAdmin)
        .collect();
    assert_eq!(ambiguous_diags.len(), 1);
    assert_eq!(
        ambiguous_diags[0].source,
        SourceRef::new(SourceKind::User, ambiguous)
    );
    assert_eq!(p.report.completeness, Completeness::Incomplete);
}

#[test]
fn an_sso_admin_with_no_provider_configuration_is_never_promoted() {
    let mut w = World::new();
    let u = w.sso_user("carol", "saml", true);
    let p = w.project_it();
    assert!(bindings_of(&p, SubjectRef::User(u)).is_empty());
    assert!(categories(&p).contains(&DiagnosticCategory::AmbiguousSsoAdmin));
}

#[test]
fn unreadable_sso_settings_make_the_projection_incomplete() {
    let mut w = World::new();
    w.state.sso.unreadable_providers.push("oidc:corp".into());
    let p = w.project_it();
    assert_eq!(
        categories(&p),
        vec![DiagnosticCategory::MissingSourceConfig]
    );
    assert_eq!(p.report.completeness, Completeness::Incomplete);
}

#[test]
fn group_memberships_keep_their_source() {
    let mut w = World::new();
    let manual_user = w.user("m");
    let idp_user = w.sso_user("i", "oidc", false);
    let sa = w.service_account("ci");
    let manual = w.group("manual-group");
    let tagged = w.tagged_group("idp-group", "oidc");
    let bound = w.group("ci-group");
    w.member(manual_user, manual);
    w.member(idp_user, tagged);
    w.member(sa, bound);
    let mapping = w.id();
    let provider = w.id();
    w.state.ci_mappings.push(LegacyCiMapping {
        id: mapping,
        provider_id: provider,
        provider_type: Some("gitlab".into()),
        service_account_id: Some(sa),
        group_binding_ids: Some(vec![bound]),
        allowed_repo_ids: None,
        is_enabled: true,
    });
    let p = w.project_it();
    let source_of = |user: Uuid| {
        p.memberships
            .iter()
            .find(|m| m.item.user_id == user)
            .unwrap()
            .item
            .source
            .clone()
    };
    assert_eq!(source_of(manual_user), MembershipSource::Manual);
    assert!(matches!(source_of(idp_user), MembershipSource::Idp(ref s) if s.starts_with("oidc:")));
    assert_eq!(source_of(sa), MembershipSource::CiMapping(mapping));
    // The tagged group is mapped to its provider group of the same name.
    assert_eq!(p.external_group_mappings.len(), 1);
    assert_eq!(p.external_group_mappings[0].item.local_group_id, tagged);
}

// ---------------------------------------------------------------------------
// 2.4 credentials
// ---------------------------------------------------------------------------

#[test]
fn token_scopes_become_ceilings_within_the_repository_ceiling() {
    let mut w = World::new();
    let u = w.user("u");
    let repo = w.repo("r", None);
    let token = w.id();
    w.state.tokens.push(LegacyToken {
        id: token,
        user_id: u,
        scopes: vec!["read:artifacts".into(), "write:artifacts".into()],
        allowed_repo_ids: Some(vec![repo]),
        repo_selector: None,
    });
    let p = w.project_it();
    assert_eq!(p.ceilings.len(), 1);
    let c = &p.ceilings[0].item;
    assert_eq!(c.credential, CredentialRef::Token(token));
    assert_eq!(
        c.permissions,
        Some(BTreeSet::from([
            Permission::ArtifactRead,
            Permission::RepositoryRead,
            Permission::ArtifactWrite,
            Permission::ArtifactAnnotate,
        ]))
    );
    assert_eq!(c.repository_ids, Some(BTreeSet::from([repo])));
    // A ceiling never grants.
    assert!(p.bindings.is_empty());
}

#[test]
fn admin_scope_is_unrestricted_and_unknown_scopes_are_reported() {
    let mut w = World::new();
    let u = w.user("u");
    for (scopes, expect_unrestricted) in [
        (vec!["admin"], true),
        (vec!["*"], true),
        (vec!["bogus"], false),
    ] {
        let token = w.id();
        w.state.tokens.push(LegacyToken {
            id: token,
            user_id: u,
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            allowed_repo_ids: None,
            repo_selector: None,
        });
        let p = w.project_it();
        let c = p
            .ceilings
            .iter()
            .find(|c| c.item.credential == CredentialRef::Token(token))
            .unwrap();
        assert_eq!(
            c.item.permissions.is_none(),
            expect_unrestricted,
            "{scopes:?}"
        );
    }
    let p = w.project_it();
    assert!(categories(&p).contains(&DiagnosticCategory::UnsupportedAction));
}

#[test]
fn granting_scopes_create_bindings_for_the_owning_principal() {
    let mut w = World::new();
    let sa = w.service_account("release-bot");
    let repo = w.repo("releases", None);
    for (scope, limited) in [("promote:artifacts", true), ("trigger:sync", false)] {
        let token = w.id();
        w.state.tokens.push(LegacyToken {
            id: token,
            user_id: sa,
            scopes: vec![scope.into()],
            allowed_repo_ids: limited.then(|| vec![repo]),
            repo_selector: None,
        });
    }
    let p = w.project_it();
    let b = bindings_of(&p, SubjectRef::ServiceAccount(sa));
    assert!(b
        .iter()
        .any(|b| b.role == RoleRef::System(SystemRole::ReleaseManager)
            && b.scope == ScopeRef::Repository(repo)));
    // `trigger:sync` is instance-scope (replication.trigger is instance-only).
    assert!(b.iter().any(|b| b.scope == ScopeRef::Instance
        && role_effective_permissions(&b.role, b.scope).contains(&Permission::ReplicationTrigger)));
}

#[test]
fn a_repo_selector_cannot_be_pinned_and_fails_closed() {
    let mut w = World::new();
    let u = w.user("u");
    let token = w.id();
    w.state.tokens.push(LegacyToken {
        id: token,
        user_id: u,
        scopes: vec!["read".into()],
        allowed_repo_ids: None,
        repo_selector: Some(json!({"format": "maven"})),
    });
    let p = w.project_it();
    assert_eq!(p.ceilings[0].item.repository_ids, Some(BTreeSet::new()));
    assert!(categories(&p).contains(&DiagnosticCategory::UnsupportedCredentialRestriction));
    assert_eq!(p.report.completeness, Completeness::Incomplete);
}

#[test]
fn ci_mapping_ceilings_follow_group_grants_and_kubernetes_is_pull_only() {
    let mut w = World::new();
    let sa = w.service_account("ci");
    let group = w.group("ci-writers");
    let repo = w.repo("r", None);
    w.rule(
        LegacyPrincipal::Group(group),
        "repository",
        repo,
        &["read", "write"],
        None,
    );
    let provider = w.id();
    let plain = w.id();
    let kube = w.id();
    for (id, kind, groups) in [
        (plain, "gitlab", vec![group]),
        (kube, "kubernetes", vec![group]),
    ] {
        w.state.ci_mappings.push(LegacyCiMapping {
            id,
            provider_id: provider,
            provider_type: Some(kind.into()),
            service_account_id: Some(sa),
            group_binding_ids: Some(groups),
            allowed_repo_ids: Some(vec![repo]),
            is_enabled: true,
        });
    }
    let p = w.project_it();
    let ceiling = |id| {
        p.ceilings
            .iter()
            .find(|c| c.item.credential == CredentialRef::CiMapping(id))
            .unwrap()
            .item
            .clone()
    };
    let plain_perms = ceiling(plain).permissions.unwrap();
    assert!(
        plain_perms.contains(&Permission::ArtifactWrite)
            && plain_perms.contains(&Permission::ArtifactRead)
    );
    assert_eq!(
        ceiling(kube).permissions,
        Some(BTreeSet::from([Permission::ArtifactRead]))
    );
    assert_eq!(ceiling(plain).repository_ids, Some(BTreeSet::from([repo])));
}

// ---------------------------------------------------------------------------
// 2.5 anonymous
// ---------------------------------------------------------------------------

#[test]
fn anonymous_read_keeps_its_cidr_condition_and_never_gains_write() {
    let mut w = World::new();
    let repo = w.repo("public-ish", None);
    w.rule(
        LegacyPrincipal::Anonymous,
        "repository",
        repo,
        &["read", "write"],
        Some(&["10.0.0.0/8"]),
    );
    let p = w.project_it();
    let b = bindings_of(&p, SubjectRef::Anonymous);
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].role, RoleRef::System(SystemRole::Viewer));
    assert_eq!(
        b[0].conditions.as_ref().unwrap().cidrs(),
        &BTreeSet::from([Cidr::parse("10.0.0.0/8").unwrap()])
    );
    let eff = role_effective_permissions(&b[0].role, b[0].scope);
    assert!(!eff.contains(&Permission::ArtifactWrite));
}

// ---------------------------------------------------------------------------
// 3.x overrides
// ---------------------------------------------------------------------------

fn deny_for(p: &PolicyProjection, user: Uuid, scope: ScopeRef) -> Vec<&Deny> {
    p.denies
        .iter()
        .map(|d| &d.item)
        .filter(|d| d.subject == SubjectRef::User(user) && d.scope == scope)
        .collect()
}

#[test]
fn a_repository_rule_narrows_the_role_with_an_unconditional_deny() {
    let mut w = World::new();
    let u = w.user("u");
    let repo = w.repo("r", None);
    w.assign(u, ROLE_DEVELOPER, None);
    user_rule(&mut w, u, "repository", repo, &["read"], None);
    let p = w.project_it();
    let denies = deny_for(&p, u, ScopeRef::Repository(repo));
    assert_eq!(denies.len(), 1);
    assert!(denies[0].conditions.is_none());
    assert!(denies[0].permissions.contains(&Permission::ArtifactWrite));
    assert!(!denies[0].permissions.contains(&Permission::ArtifactRead));
}

#[test]
fn an_admin_role_is_never_narrowed() {
    let mut w = World::new();
    let global = w.user("g");
    let on_repo = w.user("r");
    let repo = w.repo("r", None);
    w.assign(global, ROLE_ADMIN, None);
    w.assign(on_repo, ROLE_DEVELOPER, None);
    w.assign(on_repo, ROLE_OWNER, Some(repo));
    user_rule(&mut w, global, "repository", repo, &["read"], None);
    user_rule(&mut w, on_repo, "repository", repo, &["read"], None);
    let p = w.project_it();
    assert!(p.denies.is_empty(), "{:?}", p.denies);
}

#[test]
fn project_narrowing_reaches_future_repositories_but_not_a_repository_exception() {
    let mut w = World::new();
    let u = w.user("u");
    let project = w.project("p");
    let plain = w.repo("plain", Some(project));
    let special = w.repo("special", Some(project));
    w.assign(u, ROLE_DEVELOPER, None);
    user_rule(&mut w, u, "project", project, &["read"], None);
    user_rule(&mut w, u, "repository", special, &["read", "write"], None);
    let p = w.project_it();

    let project_denies = deny_for(&p, u, ScopeRef::Project(project));
    assert_eq!(project_denies.len(), 1, "{:?}", p.denies);
    assert!(project_denies[0]
        .permissions
        .contains(&Permission::ArtifactWrite));
    // The repository that gets write back is excepted from the project deny.
    assert_eq!(
        project_denies[0].excepted_scopes,
        BTreeSet::from([ScopeRef::Repository(special)])
    );
    assert!(!project_denies[0]
        .excepted_scopes
        .contains(&ScopeRef::Repository(plain)));
    // Nothing else is withheld on the excepted repository.
    assert!(deny_for(&p, u, ScopeRef::Repository(special)).is_empty());
}

#[test]
fn overlapping_cidr_rules_are_combined_before_narrowing() {
    // Design D16: global developer, read-only on 10.0.0.0/8, then read/write on
    // 10.1.0.0/16. Write is denied in 10/8 except the /16.
    let mut w = World::new();
    let u = w.user("u");
    let repo = w.repo("r", None);
    w.assign(u, ROLE_DEVELOPER, None);
    user_rule(
        &mut w,
        u,
        "repository",
        repo,
        &["read"],
        Some(&["10.0.0.0/8"]),
    );
    user_rule(
        &mut w,
        u,
        "repository",
        repo,
        &["read", "write"],
        Some(&["10.1.0.0/16"]),
    );
    let p = w.project_it();
    let denies = deny_for(&p, u, ScopeRef::Repository(repo));
    assert_eq!(denies.len(), 1, "{denies:?}");
    let cond = denies[0].conditions.as_ref().expect("conditional deny");
    assert!(denies[0].permissions.contains(&Permission::ArtifactWrite));
    let covered = |a: &str| super::regions::contains(cond.cidrs(), ip(a));
    assert!(covered("10.0.0.1"));
    assert!(covered("10.2.0.1"));
    assert!(covered("10.255.255.255"));
    assert!(!covered("10.1.0.0"), "the /16 gets write back");
    assert!(!covered("10.1.255.255"));
    assert!(!covered("11.0.0.0"), "outside the range the role applies");
    assert!(categories(&p).contains(&DiagnosticCategory::UnknownIpTightening));
}

#[test]
fn region_overflow_marks_the_projection_incomplete_instead_of_truncating() {
    let mut w = World::new();
    let u = w.user("u");
    let repo = w.repo("r", None);
    w.assign(u, ROLE_DEVELOPER, None);
    for i in 0..6 {
        let cidr = format!("10.{i}.0.0/16");
        user_rule(
            &mut w,
            u,
            "repository",
            repo,
            &["read"],
            Some(&[cidr.as_str()]),
        );
    }
    let p = project(&w.state, &ProjectionLimits { max_regions: 4 });
    assert!(categories(&p).contains(&DiagnosticCategory::RegionOverflow));
    assert_eq!(p.report.completeness, Completeness::Incomplete);
    assert!(
        p.denies.is_empty(),
        "no narrowing may be silently dropped into a partial deny"
    );
}

// ---------------------------------------------------------------------------
// 3.4 diagnostics: nothing unknown becomes an allow
// ---------------------------------------------------------------------------

#[test]
fn unmappable_records_are_reported_and_grant_nothing() {
    let mut w = World::new();
    let u = w.user("u");
    let repo = w.repo("r", None);
    let missing_user = w.id();
    let missing_repo = w.id();
    // Unknown principal type, unknown target type, unknown action, bad conditions,
    // dangling user, dangling repository.
    w.rule(
        LegacyPrincipal::Unknown {
            principal_type: "team".into(),
            id: u,
        },
        "repository",
        repo,
        &["read"],
        None,
    );
    user_rule(&mut w, u, "artifact", repo, &["read"], None);
    user_rule(&mut w, u, "repository", repo, &["execute"], None);
    let malformed = w.id();
    w.state.rules.push(LegacyRule {
        id: malformed,
        principal: LegacyPrincipal::User(u),
        target_type: "repository".into(),
        target_id: repo,
        actions: vec!["read".into()],
        conditions: Some(json!({"allowed_cidrs": ["nope"]})),
    });
    user_rule(&mut w, missing_user, "repository", repo, &["read"], None);
    user_rule(&mut w, u, "repository", missing_repo, &["read"], None);
    let p = w.project_it();

    assert!(p.bindings.is_empty(), "{:?}", p.bindings);
    assert!(p.denies.is_empty());
    let cats = categories(&p);
    for expected in [
        DiagnosticCategory::UnknownPrincipal,
        DiagnosticCategory::UnknownTarget,
        DiagnosticCategory::UnsupportedAction,
        DiagnosticCategory::InvalidCondition,
    ] {
        assert!(cats.contains(&expected), "{expected:?} in {cats:?}");
    }
    assert!(p
        .report
        .diagnostics
        .iter()
        .any(|d| d.source == SourceRef::new(SourceKind::Rule, malformed)));
    assert_eq!(p.report.completeness, Completeness::Incomplete);
}

// ---------------------------------------------------------------------------
// 4.1 equivalence against an independent reference
// ---------------------------------------------------------------------------

fn legacy_cond_ok(rule: &LegacyRule, ip: Option<IpAddr>) -> bool {
    match super::conditions::parse_conditions(rule.conditions.as_ref()) {
        Ok(RuleCondition::Always) => true,
        Ok(RuleCondition::Cidrs(c)) => ip.is_some_and(|ip| super::regions::contains(&c, ip)),
        Err(_) => false,
    }
}

use super::conditions::RuleCondition;

/// The legacy decision (`check_repository_action`), re-stated independently.
fn legacy_allows(
    state: &LegacyAuthorizationState,
    user: Uuid,
    repo: Uuid,
    action: &str,
    ip: Option<IpAddr>,
) -> bool {
    let u = state.users.iter().find(|u| u.id == user).unwrap();
    if u.is_admin {
        return true;
    }
    let project = state
        .repositories
        .iter()
        .find(|r| r.id == repo)
        .and_then(|r| r.project_id);
    let groups: Vec<Uuid> = state
        .memberships
        .iter()
        .filter(|m| m.user_id == user)
        .map(|m| m.group_id)
        .collect();
    let roles: Vec<&LegacyRole> = state
        .role_assignments
        .iter()
        .filter(|a| {
            a.user_id == user && (a.repository_id == Some(repo) || a.repository_id.is_none())
        })
        .filter_map(|a| state.roles.iter().find(|r| r.id == a.role_id))
        .collect();
    if roles
        .iter()
        .any(|r| r.permissions.iter().any(|p| p == "admin"))
    {
        return true;
    }
    let rules: Vec<&LegacyRule> = state
        .rules
        .iter()
        .filter(|r| match r.principal {
            LegacyPrincipal::User(id) | LegacyPrincipal::ServiceAccount(id) => id == user,
            LegacyPrincipal::Group(g) => groups.contains(&g),
            _ => false,
        })
        .filter(|r| {
            (r.target_type == "repository" && r.target_id == repo)
                || (r.target_type == "project" && Some(r.target_id) == project)
        })
        .filter(|r| legacy_cond_ok(r, ip))
        .collect();
    let has = |actions: &[String]| actions.iter().any(|a| a == action || a == "admin");
    if !rules.is_empty() {
        rules.iter().any(|r| has(&r.actions))
    } else {
        roles.iter().any(|r| has(&r.permissions))
    }
}

/// The target decision over the projection: additive bindings minus denies.
fn target_allows(
    p: &PolicyProjection,
    state: &LegacyAuthorizationState,
    user: Uuid,
    repo: Uuid,
    action: LegacyAction,
    ip: Option<IpAddr>,
) -> bool {
    let u = state.users.iter().find(|u| u.id == user).unwrap();
    let me = if u.is_service_account {
        SubjectRef::ServiceAccount(user)
    } else {
        SubjectRef::User(user)
    };
    let project = state
        .repositories
        .iter()
        .find(|r| r.id == repo)
        .and_then(|r| r.project_id);
    let groups: Vec<Uuid> = state
        .memberships
        .iter()
        .filter(|m| m.user_id == user)
        .map(|m| m.group_id)
        .collect();
    let mine = |s: SubjectRef| s == me || matches!(s, SubjectRef::Group(g) if groups.contains(&g));
    let covers = |scope: ScopeRef| match scope {
        ScopeRef::Instance => true,
        ScopeRef::Project(pid) => Some(pid) == project,
        ScopeRef::Repository(r) => r == repo,
        ScopeRef::Group(_) => false,
    };
    // A condition holds only with a known IP inside the range. For a deny an
    // unknown IP is "unknown", which withholds the permission.
    let allow_cond = |c: &Option<Conditions>| match c {
        None => true,
        Some(c) => ip.is_some_and(|ip| super::regions::contains(c.cidrs(), ip)),
    };
    let deny_cond = |c: &Option<Conditions>| match c {
        None => true,
        Some(c) => ip.is_none_or(|ip| super::regions::contains(c.cidrs(), ip)),
    };

    let mut effective: BTreeSet<Permission> = BTreeSet::new();
    for b in p.bindings.iter().map(|b| &b.item) {
        if mine(b.subject) && covers(b.scope) && allow_cond(&b.conditions) {
            effective.extend(role_effective_permissions(&b.role, b.scope));
        }
    }
    for d in p.denies.iter().map(|d| &d.item) {
        if mine(d.subject)
            && covers(d.scope)
            && !d.excepted_scopes.iter().any(|e| covers(*e))
            && deny_cond(&d.conditions)
        {
            for perm in &d.permissions {
                effective.remove(perm);
            }
        }
    }
    let required = permissions_for_actions(&BTreeSet::from([action]));
    effective.is_superset(&required)
}

fn all_actions() -> [(LegacyAction, &'static str); 4] {
    [
        (LegacyAction::Read, "read"),
        (LegacyAction::Write, "write"),
        (LegacyAction::Delete, "delete"),
        (LegacyAction::Admin, "admin"),
    ]
}

/// Compare every user, repository, action and sampled IP. Returns the number of
/// comparisons. Widening is allowed only for the enumerated repository-owner
/// case; tightening only for an unknown IP.
fn assert_equivalent(w: &World, label: &str) -> usize {
    let p = w.project_it();
    let samples: Vec<Option<IpAddr>> = std::iter::once(None)
        .chain(
            [
                "8.8.8.8",
                "10.0.0.0",
                "10.0.0.1",
                "10.1.0.0",
                "10.1.2.3",
                "10.1.255.255",
                "10.2.0.1",
                "10.255.255.255",
                "11.0.0.0",
                "192.168.1.1",
                "192.169.0.1",
                "2001:db8::1",
            ]
            .iter()
            .map(|s| Some(ip(s))),
        )
        .collect();
    let owners: HashMap<(Uuid, Uuid), ()> = w
        .state
        .role_assignments
        .iter()
        .filter(|a| {
            a.repository_id.is_some()
                && w.state
                    .roles
                    .iter()
                    .find(|r| r.id == a.role_id)
                    .is_some_and(|r| r.permissions.iter().any(|p| p == "admin"))
        })
        .map(|a| ((a.user_id, a.repository_id.unwrap()), ()))
        .collect();
    let mut compared = 0;
    for user in &w.state.users {
        for repo in &w.state.repositories {
            for (action, name) in all_actions() {
                for sample in &samples {
                    let legacy = legacy_allows(&w.state, user.id, repo.id, name, *sample);
                    let target = target_allows(&p, &w.state, user.id, repo.id, action, *sample);
                    compared += 1;
                    let ctx = format!(
                        "{label}: user={} repo={} action={name} ip={sample:?}",
                        user.username, repo.key
                    );
                    if target && !legacy {
                        assert!(
                            owners.contains_key(&(user.id, repo.id)),
                            "WIDENING {ctx}\nprojection: {}",
                            p.to_canonical_json()
                        );
                    }
                    if legacy && !target {
                        assert!(
                            sample.is_none(),
                            "TIGHTENING with a known IP {ctx}\nprojection: {}",
                            p.to_canonical_json()
                        );
                    }
                }
            }
        }
    }
    compared
}

#[test]
fn the_design_examples_are_equivalent_to_the_legacy_decision() {
    let mut w = World::new();
    let dev = w.user("dev");
    let group_user = w.user("group-user");
    let owner = w.user("owner");
    let team = w.group("team");
    let project = w.project("p");
    let _plain = w.repo("plain", Some(project));
    let special = w.repo("special", Some(project));
    let solo = w.repo("solo", None);
    w.member(group_user, team);
    w.assign(dev, ROLE_DEVELOPER, None);
    w.assign(group_user, ROLE_READER, None);
    w.assign(owner, ROLE_OWNER, Some(solo));
    user_rule(&mut w, dev, "project", project, &["read"], None);
    user_rule(&mut w, dev, "repository", special, &["read", "write"], None);
    user_rule(
        &mut w,
        dev,
        "repository",
        solo,
        &["read"],
        Some(&["10.0.0.0/8"]),
    );
    user_rule(
        &mut w,
        dev,
        "repository",
        solo,
        &["read", "write"],
        Some(&["10.1.0.0/16"]),
    );
    w.rule(
        LegacyPrincipal::Group(team),
        "project",
        project,
        &["read", "write", "delete"],
        Some(&["192.168.0.0/16"]),
    );
    let compared = assert_equivalent(&w, "design examples");
    // 3 users x 3 repositories x 4 actions x 13 sampled IPs (one unknown).
    assert_eq!(compared, 3 * 3 * 4 * 13);
}

#[test]
fn pseudorandom_legacy_states_project_without_widening_or_known_ip_tightening() {
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    let mut next = move |modulo: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % modulo
    };
    let cidr_pool = [
        "10.0.0.0/8",
        "10.1.0.0/16",
        "10.1.2.0/24",
        "192.168.0.0/16",
        "2001:db8::/32",
        "0.0.0.0/0",
    ];
    let action_pool: [&[&str]; 7] = [
        &["read"],
        &["write"],
        &["read", "write"],
        &["delete"],
        &["read", "write", "delete"],
        &["admin"],
        &[],
    ];
    for scenario in 0..120 {
        let mut w = World::new();
        let users: Vec<Uuid> = (0..3).map(|i| w.user(&format!("u{i}"))).collect();
        let groups: Vec<Uuid> = (0..2).map(|i| w.group(&format!("g{i}"))).collect();
        let projects: Vec<Uuid> = (0..2).map(|i| w.project(&format!("p{i}"))).collect();
        let mut repos = Vec::new();
        for i in 0..4 {
            let project = match next(3) {
                0 => None,
                n => Some(projects[(n - 1) as usize]),
            };
            repos.push(w.repo(&format!("r{i}"), project));
        }
        for &u in &users {
            if next(3) == 0 {
                w.member(u, groups[next(2) as usize]);
            }
            match next(6) {
                0 => {
                    w.assign(u, ROLE_READER, None);
                }
                1 => {
                    w.assign(u, ROLE_DEVELOPER, None);
                }
                2 => {
                    w.assign(u, ROLE_DEVELOPER, Some(repos[next(4) as usize]));
                }
                3 => {
                    w.assign(u, ROLE_OWNER, Some(repos[next(4) as usize]));
                }
                4 if next(8) == 0 => {
                    w.assign(u, ROLE_ADMIN, None);
                }
                _ => {}
            }
        }
        for _ in 0..(1 + next(6)) {
            let principal = if next(3) == 0 {
                LegacyPrincipal::Group(groups[next(2) as usize])
            } else {
                LegacyPrincipal::User(users[next(3) as usize])
            };
            let (target_type, target) = if next(2) == 0 {
                ("project", projects[next(2) as usize])
            } else {
                ("repository", repos[next(4) as usize])
            };
            let actions = action_pool[next(action_pool.len() as u64) as usize];
            let cidrs: Option<Vec<&str>> = if next(2) == 0 {
                None
            } else {
                Some(
                    (0..1 + next(2))
                        .map(|_| cidr_pool[next(cidr_pool.len() as u64) as usize])
                        .collect(),
                )
            };
            w.rule(principal, target_type, target, actions, cidrs.as_deref());
        }
        let p = w.project_it();
        assert_eq!(
            p.report.completeness,
            Completeness::Complete,
            "scenario {scenario}: {:?}",
            p.report.diagnostics
        );
        assert_equivalent(&w, &format!("scenario {scenario}"));
    }
}

// ---------------------------------------------------------------------------
// 4.2 determinism
// ---------------------------------------------------------------------------

fn busy_world() -> World {
    let mut w = World::new();
    let dev = w.user("dev");
    let other = w.user("other");
    let team = w.group("team");
    let project = w.project("p");
    let repo = w.repo("r", Some(project));
    w.member(dev, team);
    w.assign(dev, ROLE_DEVELOPER, None);
    w.assign(other, ROLE_READER, Some(repo));
    user_rule(
        &mut w,
        dev,
        "project",
        project,
        &["read"],
        Some(&["10.0.0.0/8"]),
    );
    w.rule(
        LegacyPrincipal::Group(team),
        "repository",
        repo,
        &["read", "write"],
        Some(&["10.1.0.0/16"]),
    );
    w
}

#[test]
fn identical_state_projects_to_identical_bytes_regardless_of_row_order() {
    let a = busy_world();
    let mut b = busy_world();
    b.state.users.reverse();
    b.state.rules.reverse();
    b.state.memberships.reverse();
    b.state.role_assignments.reverse();
    b.state.repositories.reverse();
    b.state.groups.reverse();
    assert_eq!(
        a.project_it().to_canonical_json(),
        a.project_it().to_canonical_json()
    );
    assert_eq!(
        a.project_it().to_canonical_json(),
        b.project_it().to_canonical_json()
    );
}

#[test]
fn a_changed_membership_changes_the_next_projection() {
    let w = busy_world();
    let before = w.project_it().to_canonical_json();
    let mut changed = busy_world();
    changed.state.memberships.clear();
    let after = changed.project_it().to_canonical_json();
    assert_ne!(before, after);
    // And a changed grant too.
    let mut regranted = busy_world();
    regranted.state.rules[0].actions = vec!["read".into(), "write".into()];
    assert_ne!(before, regranted.project_it().to_canonical_json());
}
