//! The pure projection: [`LegacyAuthorizationState`] in, [`PolicyProjection`] out.
//!
//! No I/O. Each step reads the snapshot and records intents with the legacy
//! records they came from; anything that cannot be mapped faithfully becomes a
//! diagnostic and is left out, never turned into an allow.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use uuid::Uuid;

use crate::api::authz::catalog::Permission;

use super::conditions::{parse_conditions, RuleCondition};
use super::intent::{
    Binding, Cidr, Conditions, CredentialCeiling, CredentialRef, Deny, DiagnosticCategory,
    ExternalGroupMapping, Membership, MembershipSource, PolicyProjection, ProjectionBuilder,
    RoleRef, ScopeRef, SourceKind, SourceRef, SubjectRef, SystemRole,
};
use super::legacy::{
    LegacyAuthSource, LegacyAuthorizationState, LegacyGroup, LegacyPrincipal, LegacyRepository,
    LegacyRole, LegacyUser,
};
use super::mapping::{
    group_permissions, parse_actions, permissions_for_actions, project_admin_permissions,
    role_effective_permissions, role_for, scope_ceiling, scope_grant, sentinel_admin_permissions,
    LegacyAction, ScopeCeiling, ScopeGrant,
};
use super::regions::partition;

/// Tunables of the projection.
#[derive(Debug, Clone)]
pub struct ProjectionLimits {
    /// The most elementary IP ranges one principal's rule scope may be cut into.
    /// Beyond it the projection is marked incomplete; nothing is truncated.
    pub max_regions: usize,
}

impl Default for ProjectionLimits {
    fn default() -> Self {
        Self { max_regions: 256 }
    }
}

/// Project the legacy state with default limits.
pub fn project_legacy_state(state: &LegacyAuthorizationState) -> PolicyProjection {
    project(state, &ProjectionLimits::default())
}

pub fn project(state: &LegacyAuthorizationState, limits: &ProjectionLimits) -> PolicyProjection {
    let mut p = Projector::new(state, limits);
    p.admins();
    p.role_assignments();
    p.rules();
    p.groups();
    p.credentials();
    p.overrides();
    p.dropped_tables();
    p.b.build()
}

/// A rule on a repository or project that names a user, service account or
/// group: the input to the override (narrowing) calculation.
struct AppliedRule {
    id: Uuid,
    principal: AppliedPrincipal,
    scope: ScopeRef,
    permissions: BTreeSet<Permission>,
    /// `None`: no CIDR condition.
    cidrs: Option<BTreeSet<Cidr>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AppliedPrincipal {
    User(Uuid),
    Group(Uuid),
}

/// A role assignment, kept for the override calculation.
struct RoleGrant {
    assignment: Uuid,
    user: Uuid,
    repository: Option<Uuid>,
    permissions: BTreeSet<Permission>,
    admin: bool,
}

struct Projector<'a> {
    state: &'a LegacyAuthorizationState,
    limits: &'a ProjectionLimits,
    b: ProjectionBuilder,
    users: HashMap<Uuid, &'a LegacyUser>,
    groups: HashMap<Uuid, &'a LegacyGroup>,
    repositories: HashMap<Uuid, &'a LegacyRepository>,
    projects: HashSet<Uuid>,
    roles: HashMap<Uuid, &'a LegacyRole>,
    applied: Vec<AppliedRule>,
    role_grants: Vec<RoleGrant>,
    /// What projected bindings confer on each group, for CI mapping ceilings.
    group_permissions: HashMap<Uuid, BTreeSet<Permission>>,
}

fn src(kind: SourceKind, id: impl std::fmt::Display) -> SourceRef {
    SourceRef::new(kind, id)
}

/// The provider string of a provider-tagged group.
fn provider_key(group: &LegacyGroup) -> Option<String> {
    match (&group.external_source, group.external_provider_id) {
        (Some(source), Some(id)) => Some(format!("{source}:{id}")),
        (Some(source), None) => Some(source.clone()),
        _ => None,
    }
}

impl<'a> Projector<'a> {
    fn new(state: &'a LegacyAuthorizationState, limits: &'a ProjectionLimits) -> Self {
        Self {
            state,
            limits,
            b: ProjectionBuilder::new(),
            users: state.users.iter().map(|u| (u.id, u)).collect(),
            groups: state.groups.iter().map(|g| (g.id, g)).collect(),
            repositories: state.repositories.iter().map(|r| (r.id, r)).collect(),
            projects: state.projects.iter().map(|p| p.id).collect(),
            roles: state.roles.iter().map(|r| (r.id, r)).collect(),
            applied: Vec::new(),
            role_grants: Vec::new(),
            group_permissions: HashMap::new(),
        }
    }

    fn subject_for_user(&self, id: Uuid) -> SubjectRef {
        match self.users.get(&id) {
            Some(u) if u.is_service_account => SubjectRef::ServiceAccount(id),
            _ => SubjectRef::User(id),
        }
    }

    fn note_group_permissions(&mut self, subject: SubjectRef, permissions: &BTreeSet<Permission>) {
        if let SubjectRef::Group(id) = subject {
            self.group_permissions
                .entry(id)
                .or_default()
                .extend(permissions.iter().copied());
        }
    }

    /// Bind `permissions` at `scope` through the system role with exactly those
    /// scope-applicable permissions, or a compatibility role.
    fn bind(
        &mut self,
        subject: SubjectRef,
        permissions: &BTreeSet<Permission>,
        scope: ScopeRef,
        conditions: Option<Conditions>,
        from: Vec<SourceRef>,
    ) {
        if permissions.is_empty() {
            return;
        }
        let (role, definition) = role_for(permissions, scope);
        if let Some(definition) = definition {
            self.b.role(definition, from.clone());
        }
        self.note_group_permissions(subject, &role_effective_permissions(&role, scope));
        self.b.binding(
            Binding {
                subject,
                role,
                scope,
                conditions,
            },
            from,
        );
    }

    fn bind_system(
        &mut self,
        subject: SubjectRef,
        role: SystemRole,
        scope: ScopeRef,
        conditions: Option<Conditions>,
        from: Vec<SourceRef>,
    ) {
        let role = RoleRef::System(role);
        self.note_group_permissions(subject, &role_effective_permissions(&role, scope));
        self.b.binding(
            Binding {
                subject,
                role,
                scope,
                conditions,
            },
            from,
        );
    }

    // -- 2.3: administrators ------------------------------------------------

    fn admins(&mut self) {
        let state = self.state;
        for provider in &state.sso.unreadable_providers {
            self.b.diagnostic(
                DiagnosticCategory::MissingSourceConfig,
                src(SourceKind::SsoConfig, provider),
                "the administrator-group setting of this identity provider could not be read",
            );
        }

        // Configured administrator groups: the group is the administrator, not
        // the SSO users in it.
        let mut admin_groups: HashMap<String, HashSet<Uuid>> = HashMap::new();
        for cfg in &state.sso.providers {
            for name in &cfg.admin_groups {
                for group in state.groups.iter().filter(|g| &g.name == name) {
                    admin_groups
                        .entry(cfg.provider.clone())
                        .or_default()
                        .insert(group.id);
                    let from = vec![
                        src(SourceKind::SsoConfig, &cfg.provider),
                        src(SourceKind::Group, group.id),
                    ];
                    self.bind_system(
                        SubjectRef::Group(group.id),
                        SystemRole::Admin,
                        ScopeRef::Instance,
                        None,
                        from.clone(),
                    );
                    self.b.external_group_mapping(
                        ExternalGroupMapping {
                            provider: provider_key(group).unwrap_or_else(|| cfg.provider.clone()),
                            external_group: name.clone(),
                            local_group_id: group.id,
                        },
                        from,
                    );
                }
            }
        }

        for user in state.users.iter().filter(|u| u.is_admin) {
            match &user.auth_source {
                LegacyAuthSource::Local => self.bind_system(
                    self.subject_for_user(user.id),
                    SystemRole::Admin,
                    ScopeRef::Instance,
                    None,
                    vec![src(SourceKind::User, user.id)],
                ),
                LegacyAuthSource::External(kind) => {
                    let explained = admin_groups.get(kind).is_some_and(|groups| {
                        state
                            .memberships
                            .iter()
                            .any(|m| m.user_id == user.id && groups.contains(&m.group_id))
                    });
                    if !explained {
                        self.b.diagnostic(
                            DiagnosticCategory::AmbiguousSsoAdmin,
                            src(SourceKind::User, user.id),
                            format!(
                                "`{}` has is_admin set but belongs to no configured administrator group of provider `{kind}`; no administrator binding was created",
                                user.username
                            ),
                        );
                    }
                }
            }
        }
    }

    // -- 2.1: role assignments ----------------------------------------------

    fn role_assignments(&mut self) {
        let state = self.state;
        for a in &state.role_assignments {
            let source = src(SourceKind::RoleAssignment, a.id);
            let Some(user) = self.users.get(&a.user_id).copied() else {
                self.b.diagnostic(
                    DiagnosticCategory::UnknownPrincipal,
                    source,
                    "the assignment names a user that does not exist",
                );
                continue;
            };
            let Some(role) = self.roles.get(&a.role_id).copied() else {
                self.b.diagnostic(
                    DiagnosticCategory::UnsupportedRole,
                    source,
                    "the assignment names a role that does not exist",
                );
                continue;
            };
            let (actions, unknown) = parse_actions(&role.permissions);
            for action in unknown {
                self.b.diagnostic(
                    DiagnosticCategory::UnsupportedAction,
                    src(SourceKind::Role, role.id),
                    format!("role `{}` has unknown action `{action}`", role.name),
                );
            }
            if actions.is_empty() {
                // The `user` role: no actions, confers nothing.
                continue;
            }
            let from = vec![source.clone(), src(SourceKind::Role, role.id)];
            let subject = self.subject_for_user(user.id);
            let admin = actions.contains(&LegacyAction::Admin);
            let permissions = permissions_for_actions(&actions);
            match a.repository_id {
                None if admin => {
                    self.bind_system(subject, SystemRole::Admin, ScopeRef::Instance, None, from)
                }
                None => self.bind(subject, &permissions, ScopeRef::Instance, None, from),
                Some(repo) => {
                    if !self.repositories.contains_key(&repo) {
                        self.b.diagnostic(
                            DiagnosticCategory::UnknownTarget,
                            source,
                            "the assignment names a repository that does not exist",
                        );
                        continue;
                    }
                    let scope = ScopeRef::Repository(repo);
                    if admin {
                        self.bind_system(subject, SystemRole::Owner, scope, None, from);
                        self.b.diagnostic(
                            DiagnosticCategory::OwnerWidening,
                            source,
                            format!(
                                "`{}` gains administration of repository {repo} (configuration, deletion, credentials)",
                                user.username
                            ),
                        );
                    } else {
                        self.bind(subject, &permissions, scope, None, from);
                    }
                }
            }
            self.role_grants.push(RoleGrant {
                assignment: a.id,
                user: user.id,
                repository: a.repository_id,
                permissions,
                admin,
            });
        }
    }

    // -- 2.1 / 2.2: permission rules ------------------------------------------

    fn rules(&mut self) {
        let state = self.state;
        for rule in &state.rules {
            let source = src(SourceKind::Rule, rule.id);
            let condition = match parse_conditions(rule.conditions.as_ref()) {
                Ok(c) => c,
                Err(reason) => {
                    self.b
                        .diagnostic(DiagnosticCategory::InvalidCondition, source, reason);
                    continue;
                }
            };
            if condition.never_applies() {
                self.b.diagnostic(
                    DiagnosticCategory::Dropped,
                    source,
                    "allowed_cidrs is empty, so the rule never applies",
                );
                continue;
            }
            let (cidrs, conditions) = match &condition {
                RuleCondition::Always => (None, None),
                RuleCondition::Cidrs(set) => (
                    Some(set.clone()),
                    Conditions::allowed_cidrs(set.iter().copied()),
                ),
            };
            let (actions, unknown) = parse_actions(&rule.actions);
            for action in unknown {
                self.b.diagnostic(
                    DiagnosticCategory::UnsupportedAction,
                    source.clone(),
                    format!("unknown action `{action}`"),
                );
            }

            let (subject, applied) = match &rule.principal {
                LegacyPrincipal::User(id) | LegacyPrincipal::ServiceAccount(id) => {
                    if !self.users.contains_key(id) {
                        self.b.diagnostic(
                            DiagnosticCategory::UnknownPrincipal,
                            source,
                            "the rule names a user that does not exist",
                        );
                        continue;
                    }
                    (
                        self.subject_for_user(*id),
                        Some(AppliedPrincipal::User(*id)),
                    )
                }
                LegacyPrincipal::Group(id) => {
                    if !self.groups.contains_key(id) {
                        self.b.diagnostic(
                            DiagnosticCategory::UnknownPrincipal,
                            source,
                            "the rule names a group that does not exist",
                        );
                        continue;
                    }
                    (SubjectRef::Group(*id), Some(AppliedPrincipal::Group(*id)))
                }
                LegacyPrincipal::Anonymous => (SubjectRef::Anonymous, None),
                LegacyPrincipal::Unknown { principal_type, .. } => {
                    self.b.diagnostic(
                        DiagnosticCategory::UnknownPrincipal,
                        source,
                        format!("unsupported principal type `{principal_type}`"),
                    );
                    continue;
                }
            };

            let from = vec![source.clone()];
            let anonymous = subject == SubjectRef::Anonymous;

            // The instance-level sentinel gates repository creation.
            if rule.target_id == Uuid::nil() {
                if anonymous {
                    continue;
                }
                if actions.contains(&LegacyAction::Admin) {
                    self.bind(
                        subject,
                        &sentinel_admin_permissions(),
                        ScopeRef::Instance,
                        conditions,
                        from,
                    );
                } else {
                    self.b.diagnostic(
                        DiagnosticCategory::Dropped,
                        source,
                        "a sentinel rule without `admin` gates nothing",
                    );
                }
                continue;
            }

            match rule.target_type.as_str() {
                "repository" | "project" => {
                    let is_project = rule.target_type == "project";
                    let exists = if is_project {
                        self.projects.contains(&rule.target_id)
                    } else {
                        self.repositories.contains_key(&rule.target_id)
                    };
                    if !exists {
                        self.b.diagnostic(
                            DiagnosticCategory::UnknownTarget,
                            source,
                            format!("the {} does not exist", rule.target_type),
                        );
                        continue;
                    }
                    let scope = if is_project {
                        ScopeRef::Project(rule.target_id)
                    } else {
                        ScopeRef::Repository(rule.target_id)
                    };
                    let mut from = from;
                    from.push(src(
                        if is_project {
                            SourceKind::Project
                        } else {
                            SourceKind::Repository
                        },
                        rule.target_id,
                    ));
                    if anonymous {
                        // Anonymous rules confer read only, whatever they list.
                        if actions.contains(&LegacyAction::Read)
                            || actions.contains(&LegacyAction::Admin)
                        {
                            let read =
                                permissions_for_actions(&BTreeSet::from([LegacyAction::Read]));
                            self.bind(subject, &read, scope, conditions, from);
                        } else {
                            self.b.diagnostic(
                                DiagnosticCategory::Dropped,
                                source,
                                "an anonymous rule without `read` grants nothing",
                            );
                        }
                        continue;
                    }
                    let permissions = permissions_for_actions(&actions);
                    self.bind(
                        subject,
                        &permissions,
                        scope,
                        conditions.clone(),
                        from.clone(),
                    );
                    if is_project && actions.contains(&LegacyAction::Admin) {
                        // #4391: project `admin` also administers the project.
                        self.bind(
                            subject,
                            &project_admin_permissions(),
                            scope,
                            conditions,
                            from,
                        );
                    }
                    if let Some(principal) = applied {
                        self.applied.push(AppliedRule {
                            id: rule.id,
                            principal,
                            scope,
                            permissions,
                            cidrs,
                        });
                    }
                }
                "group" => {
                    if anonymous {
                        continue;
                    }
                    if !self.groups.contains_key(&rule.target_id) {
                        self.b.diagnostic(
                            DiagnosticCategory::UnknownTarget,
                            source,
                            "the group does not exist",
                        );
                        continue;
                    }
                    match group_permissions(&actions) {
                        Some(permissions) => {
                            let mut from = from;
                            from.push(src(SourceKind::Group, rule.target_id));
                            self.bind(
                                subject,
                                &permissions,
                                ScopeRef::Group(rule.target_id),
                                conditions,
                                from,
                            );
                        }
                        None => self.b.diagnostic(
                            DiagnosticCategory::UnsupportedAction,
                            source,
                            "a group rule must contain `admin` or be exactly `read`",
                        ),
                    }
                }
                other => self.b.diagnostic(
                    DiagnosticCategory::UnknownTarget,
                    source,
                    format!(
                        "target type `{other}` is read by no decision path and confers nothing"
                    ),
                ),
            }
        }
    }

    // -- 2.3 / 2.5: groups and memberships --------------------------------------

    fn groups(&mut self) {
        let state = self.state;
        for group in &state.groups {
            if let (Some(_), Some(provider)) = (&group.external_source, provider_key(group)) {
                self.b.external_group_mapping(
                    ExternalGroupMapping {
                        provider,
                        external_group: group.name.clone(),
                        local_group_id: group.id,
                    },
                    vec![src(SourceKind::Group, group.id)],
                );
            }
        }
        let ci_managed: HashMap<(Uuid, Uuid), Uuid> = state
            .ci_mappings
            .iter()
            .filter_map(|m| m.service_account_id.map(|sa| (m, sa)))
            .flat_map(|(m, sa)| {
                m.group_binding_ids
                    .iter()
                    .flatten()
                    .map(move |g| ((sa, *g), m.id))
            })
            .collect();
        for m in &state.memberships {
            let (Some(_), Some(group)) = (self.users.get(&m.user_id), self.groups.get(&m.group_id))
            else {
                continue;
            };
            let source = if let Some(mapping) = ci_managed.get(&(m.user_id, m.group_id)) {
                MembershipSource::CiMapping(*mapping)
            } else if let Some(provider) = provider_key(group) {
                MembershipSource::Idp(provider)
            } else {
                MembershipSource::Manual
            };
            self.b.membership(
                Membership {
                    group_id: m.group_id,
                    user_id: m.user_id,
                    source,
                },
                vec![src(
                    SourceKind::Membership,
                    format!("{}:{}", m.group_id, m.user_id),
                )],
            );
        }
    }

    // -- 2.4: credentials ---------------------------------------------------------

    fn credentials(&mut self) {
        let state = self.state;
        for token in &state.tokens {
            let source = src(SourceKind::Token, token.id);
            let Some(owner) = self.users.get(&token.user_id).copied() else {
                self.b.diagnostic(
                    DiagnosticCategory::UnknownPrincipal,
                    source,
                    "the token names a user that does not exist",
                );
                continue;
            };
            let repository_ids: Option<BTreeSet<Uuid>> = match (
                &token.repo_selector,
                &token.allowed_repo_ids,
            ) {
                (Some(_), _) => {
                    self.b.diagnostic(
                            DiagnosticCategory::UnsupportedCredentialRestriction,
                            source.clone(),
                            "the token restricts repositories with a selector, which cannot be pinned to a fixed set; its ceiling excludes every repository",
                        );
                    Some(BTreeSet::new())
                }
                (None, Some(ids)) => Some(ids.iter().copied().collect()),
                (None, None) => None,
            };

            let mut unrestricted = false;
            let mut permissions: BTreeSet<Permission> = BTreeSet::new();
            for scope in &token.scopes {
                match scope_ceiling(scope) {
                    Some(ScopeCeiling::Unrestricted) => unrestricted = true,
                    Some(ScopeCeiling::Permissions(p)) => permissions.extend(p),
                    None => self.b.diagnostic(
                        DiagnosticCategory::UnsupportedAction,
                        source.clone(),
                        format!("unknown token scope `{scope}`"),
                    ),
                }
                // A scope that grants, not only limits, becomes a binding for the
                // owning principal on the token's repository ceiling.
                if let Some(grant) = scope_grant(scope) {
                    let subject = self.subject_for_user(owner.id);
                    let from = vec![source.clone()];
                    let scopes: Vec<ScopeRef> = match (&grant, &repository_ids) {
                        (ScopeGrant::Compat(_), _) | (_, None) => vec![ScopeRef::Instance],
                        (_, Some(ids)) => ids.iter().map(|r| ScopeRef::Repository(*r)).collect(),
                    };
                    for scope_ref in scopes {
                        match &grant {
                            ScopeGrant::ReleaseManager => self.bind_system(
                                subject,
                                SystemRole::ReleaseManager,
                                scope_ref,
                                None,
                                from.clone(),
                            ),
                            ScopeGrant::Compat(p) => {
                                self.bind(subject, p, scope_ref, None, from.clone())
                            }
                        }
                    }
                }
            }
            self.b.ceiling(
                CredentialCeiling {
                    credential: CredentialRef::Token(token.id),
                    permissions: (!unrestricted).then_some(permissions),
                    repository_ids,
                },
                vec![source, src(SourceKind::User, owner.id)],
            );
        }

        for mapping in &state.ci_mappings {
            let permissions: BTreeSet<Permission> =
                if mapping.provider_type.as_deref() == Some("kubernetes") {
                    BTreeSet::from([Permission::ArtifactRead])
                } else {
                    // No declared ceiling: the permissions its groups confer today.
                    let groups: Vec<Uuid> = match &mapping.group_binding_ids {
                        Some(ids) => ids.clone(),
                        None => mapping
                            .service_account_id
                            .map(|sa| {
                                state
                                    .memberships
                                    .iter()
                                    .filter(|m| m.user_id == sa)
                                    .map(|m| m.group_id)
                                    .collect()
                            })
                            .unwrap_or_default(),
                    };
                    groups
                        .iter()
                        .filter_map(|g| self.group_permissions.get(g))
                        .flatten()
                        .copied()
                        .collect()
                };
            self.b.ceiling(
                CredentialCeiling {
                    credential: CredentialRef::CiMapping(mapping.id),
                    permissions: Some(permissions),
                    repository_ids: mapping
                        .allowed_repo_ids
                        .as_ref()
                        .map(|ids| ids.iter().copied().collect()),
                },
                vec![src(SourceKind::CiMapping, mapping.id)],
            );
        }
    }

    // -- 3.x: legacy overrides --------------------------------------------------------

    /// Legacy semantics: when any rule applies to a principal on a repository,
    /// the rules replace the principal's roles there. Bindings are additive, so
    /// the difference (role permissions minus the applicable rules' permissions)
    /// is projected as a deny, per IP region, reaching repositories created later
    /// through a project-scope deny with repository exceptions.
    fn overrides(&mut self) {
        let state = self.state;
        let mut groups_of: HashMap<Uuid, BTreeSet<Uuid>> = HashMap::new();
        for m in &state.memberships {
            groups_of.entry(m.user_id).or_default().insert(m.group_id);
        }

        // Per user, the rules grouped by scope group: a project together with
        // its repositories, or one repository that is in no project. The key is
        // (id, is_project).
        type ScopeKey = (Uuid, bool);
        let mut per_user: BTreeMap<Uuid, BTreeMap<ScopeKey, Vec<&AppliedRule>>> = BTreeMap::new();
        for user in &state.users {
            let groups = groups_of.get(&user.id).cloned().unwrap_or_default();
            for rule in &self.applied {
                let mine = match rule.principal {
                    AppliedPrincipal::User(id) => id == user.id,
                    AppliedPrincipal::Group(g) => groups.contains(&g),
                };
                if !mine {
                    continue;
                }
                let key = match rule.scope {
                    ScopeRef::Project(p) => (p, true),
                    ScopeRef::Repository(r) => match self
                        .repositories
                        .get(&r)
                        .and_then(|repo| repo.project_id)
                        .filter(|p| self.projects.contains(p))
                    {
                        Some(p) => (p, true),
                        None => (r, false),
                    },
                    _ => continue,
                };
                per_user
                    .entry(user.id)
                    .or_default()
                    .entry(key)
                    .or_default()
                    .push(rule);
            }
        }

        for (user_id, scope_groups) in per_user {
            let user = self.users[&user_id];
            if user.is_admin
                || self
                    .role_grants
                    .iter()
                    .any(|g| g.user == user_id && g.repository.is_none() && g.admin)
            {
                // The legacy administrator carve-out: no narrowing applies.
                continue;
            }
            let global: BTreeSet<Permission> = self
                .role_grants
                .iter()
                .filter(|g| g.user == user_id && g.repository.is_none() && !g.admin)
                .flat_map(|g| g.permissions.iter().copied())
                .collect();
            let mut repo_roles: HashMap<Uuid, BTreeSet<Permission>> = HashMap::new();
            let mut repo_admin: HashSet<Uuid> = HashSet::new();
            for g in self.role_grants.iter().filter(|g| g.user == user_id) {
                if let Some(repo) = g.repository {
                    if g.admin {
                        repo_admin.insert(repo);
                    } else {
                        repo_roles
                            .entry(repo)
                            .or_default()
                            .extend(g.permissions.iter().copied());
                    }
                }
            }
            let subject = self.subject_for_user(user_id);
            let groups = groups_of.get(&user_id).cloned().unwrap_or_default();

            for ((id, is_project), rules) in scope_groups {
                // Project rules first (their repository is None), then repository rules.
                let mut ordered: Vec<(&AppliedRule, Option<Uuid>)> = Vec::new();
                for r in &rules {
                    if matches!(r.scope, ScopeRef::Project(_)) {
                        ordered.push((r, None));
                    }
                }
                for r in &rules {
                    if let ScopeRef::Repository(repo) = r.scope {
                        ordered.push((r, Some(repo)));
                    }
                }
                let cidr_inputs: Vec<Option<&BTreeSet<Cidr>>> =
                    ordered.iter().map(|(r, _)| r.cidrs.as_ref()).collect();
                let regions = match partition(&cidr_inputs, self.limits.max_regions) {
                    Ok(r) => r,
                    Err(overflow) => {
                        self.b.diagnostic(
                            DiagnosticCategory::RegionOverflow,
                            src(SourceKind::User, user_id),
                            format!(
                                "the IP conditions of {} rules need {} regions, above the limit of {}; no narrowing was projected for scope {id}",
                                ordered.len(),
                                overflow.regions,
                                overflow.limit
                            ),
                        );
                        continue;
                    }
                };

                // The repositories this scope group covers.
                let repos: Vec<Uuid> = if is_project {
                    state
                        .repositories
                        .iter()
                        .filter(|r| r.project_id == Some(id))
                        .map(|r| r.id)
                        .collect()
                } else {
                    vec![id]
                };

                type Spec = (ScopeRef, BTreeSet<Permission>, BTreeSet<ScopeRef>);
                let mut specs: BTreeMap<Spec, BTreeSet<usize>> = BTreeMap::new();
                for (region_index, region) in regions.iter().enumerate() {
                    let applies_to = |i: usize, repo: Uuid| -> bool {
                        region.applicable.contains(&i)
                            && ordered[i].1.is_none_or(|rule_repo| rule_repo == repo)
                    };
                    let project_applicable: Vec<usize> = (0..ordered.len())
                        .filter(|i| ordered[*i].1.is_none() && region.applicable.contains(i))
                        .collect();
                    // Repositories created later carry no repository rules or
                    // assignments: only the project rules narrow the global roles.
                    let future: BTreeSet<Permission> =
                        if is_project && !project_applicable.is_empty() {
                            let project_perms: BTreeSet<Permission> = project_applicable
                                .iter()
                                .flat_map(|i| ordered[*i].0.permissions.iter().copied())
                                .collect();
                            global.difference(&project_perms).copied().collect()
                        } else {
                            BTreeSet::new()
                        };
                    let mut excepted: BTreeSet<ScopeRef> = BTreeSet::new();
                    let mut repo_denies: Vec<(Uuid, BTreeSet<Permission>)> = Vec::new();
                    for repo in &repos {
                        let applicable: Vec<usize> = (0..ordered.len())
                            .filter(|i| applies_to(*i, *repo))
                            .collect();
                        let need: BTreeSet<Permission> =
                            if applicable.is_empty() || repo_admin.contains(repo) {
                                BTreeSet::new()
                            } else {
                                let mut role_perms = global.clone();
                                if let Some(extra) = repo_roles.get(repo) {
                                    role_perms.extend(extra.iter().copied());
                                }
                                let rule_perms: BTreeSet<Permission> = applicable
                                    .iter()
                                    .flat_map(|i| ordered[*i].0.permissions.iter().copied())
                                    .collect();
                                role_perms.difference(&rule_perms).copied().collect()
                            };
                        if !future.is_empty() && !future.is_subset(&need) {
                            // A repository rule gives back some of what the project
                            // deny withholds: the deny must not reach this repository.
                            excepted.insert(ScopeRef::Repository(*repo));
                            if !need.is_empty() {
                                repo_denies.push((*repo, need));
                            }
                        } else {
                            let extra: BTreeSet<Permission> =
                                need.difference(&future).copied().collect();
                            if !extra.is_empty() {
                                repo_denies.push((*repo, extra));
                            }
                        }
                    }
                    if !future.is_empty() {
                        specs
                            .entry((ScopeRef::Project(id), future, excepted))
                            .or_default()
                            .insert(region_index);
                    }
                    for (repo, perms) in repo_denies {
                        specs
                            .entry((ScopeRef::Repository(repo), perms, BTreeSet::new()))
                            .or_default()
                            .insert(region_index);
                    }
                }

                let mut from: Vec<SourceRef> = ordered
                    .iter()
                    .map(|(r, _)| src(SourceKind::Rule, r.id))
                    .collect();
                from.extend(
                    self.role_grants
                        .iter()
                        .filter(|g| g.user == user_id)
                        .map(|g| src(SourceKind::RoleAssignment, g.assignment)),
                );
                for (r, _) in &ordered {
                    if let AppliedPrincipal::Group(g) = r.principal {
                        if groups.contains(&g) {
                            from.push(src(SourceKind::Membership, format!("{g}:{user_id}")));
                        }
                    }
                }
                from.sort();
                from.dedup();

                for ((scope, permissions, excepted_scopes), region_indexes) in specs {
                    let conditions = if region_indexes.len() == regions.len() {
                        None
                    } else {
                        let cidrs: BTreeSet<Cidr> = region_indexes
                            .iter()
                            .flat_map(|i| regions[*i].cidrs.iter().copied())
                            .collect();
                        Conditions::allowed_cidrs(cidrs)
                    };
                    if conditions.is_some() {
                        self.b.diagnostic(
                            DiagnosticCategory::UnknownIpTightening,
                            from.first()
                                .cloned()
                                .unwrap_or_else(|| src(SourceKind::User, user_id)),
                            format!(
                                "the narrowing for `{}` on {scope:?} applies only inside some IP ranges; a request without a verified client IP is refused where the legacy role fallback would have allowed it",
                                user.username
                            ),
                        );
                    }
                    self.b.deny(
                        Deny {
                            subject,
                            scope,
                            permissions,
                            excepted_scopes,
                            conditions,
                        },
                        from.clone(),
                    );
                }
            }
        }
    }

    // -- 2.5: non-authoritative tables ---------------------------------------------------

    fn dropped_tables(&mut self) {
        let state = self.state;
        for ur in &state.user_roles {
            self.b.diagnostic(
                DiagnosticCategory::Dropped,
                src(
                    SourceKind::LegacyTable,
                    format!("user_roles:{}:{}", ur.user_id, ur.role_id),
                ),
                "user_roles confers nothing in any decision path and is not converted",
            );
        }
        for id in &state.permission_grants {
            self.b.diagnostic(
                DiagnosticCategory::Dropped,
                src(SourceKind::LegacyTable, format!("permission_grants:{id}")),
                "permission_grants confers nothing and is not converted",
            );
        }
    }
}
