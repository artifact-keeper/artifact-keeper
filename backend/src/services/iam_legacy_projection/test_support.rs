//! Test fixtures shared by the projection tests and by the decision evaluator's
//! equivalence tests: a builder for legacy states, an independent restatement of
//! the legacy repository decision, and the pseudorandom legacy states both suites
//! check. Test-only; nothing here is compiled into the server.

use std::collections::BTreeSet;
use std::net::IpAddr;

use serde_json::json;
use uuid::Uuid;

use super::conditions::RuleCondition;
use super::intent::PolicyProjection;
use super::legacy::*;
use super::mapping::LegacyAction;
use super::project::project_legacy_state;

pub(crate) struct World {
    pub(crate) state: LegacyAuthorizationState,
    next: u128,
}

pub(crate) const ROLE_ADMIN: u128 = 1;
pub(crate) const ROLE_DEVELOPER: u128 = 2;
pub(crate) const ROLE_READER: u128 = 3;
pub(crate) const ROLE_OWNER: u128 = 4;
pub(crate) const ROLE_USER: u128 = 5;

impl World {
    pub(crate) fn new() -> World {
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

    pub(crate) fn id(&mut self) -> Uuid {
        self.next += 1;
        Uuid::from_u128(self.next)
    }

    pub(crate) fn user(&mut self, name: &str) -> Uuid {
        self.add_user(name, LegacyAuthSource::Local, false, false)
    }

    pub(crate) fn admin(&mut self, name: &str) -> Uuid {
        self.add_user(name, LegacyAuthSource::Local, true, false)
    }

    pub(crate) fn service_account(&mut self, name: &str) -> Uuid {
        self.add_user(name, LegacyAuthSource::Local, false, true)
    }

    pub(crate) fn sso_user(&mut self, name: &str, kind: &str, is_admin: bool) -> Uuid {
        self.add_user(
            name,
            LegacyAuthSource::External(kind.to_string()),
            is_admin,
            false,
        )
    }

    pub(crate) fn add_user(
        &mut self,
        name: &str,
        source: LegacyAuthSource,
        is_admin: bool,
        sa: bool,
    ) -> Uuid {
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

    pub(crate) fn group(&mut self, name: &str) -> Uuid {
        let id = self.id();
        self.state.groups.push(LegacyGroup {
            id,
            name: name.to_string(),
            external_source: None,
            external_provider_id: None,
        });
        id
    }

    pub(crate) fn tagged_group(&mut self, name: &str, source: &str) -> Uuid {
        let id = self.group(name);
        let provider = self.id();
        let g = self.state.groups.iter_mut().find(|g| g.id == id).unwrap();
        g.external_source = Some(source.to_string());
        g.external_provider_id = Some(provider);
        id
    }

    pub(crate) fn member(&mut self, user: Uuid, group: Uuid) {
        self.state.memberships.push(LegacyMembership {
            user_id: user,
            group_id: group,
        });
    }

    pub(crate) fn project(&mut self, key: &str) -> Uuid {
        let id = self.id();
        self.state.projects.push(LegacyProject {
            id,
            key: key.to_string(),
        });
        id
    }

    pub(crate) fn repo(&mut self, key: &str, project: Option<Uuid>) -> Uuid {
        let id = self.id();
        self.state.repositories.push(LegacyRepository {
            id,
            key: key.to_string(),
            project_id: project,
        });
        id
    }

    pub(crate) fn assign(&mut self, user: Uuid, role: u128, repo: Option<Uuid>) -> Uuid {
        let id = self.id();
        self.state.role_assignments.push(LegacyRoleAssignment {
            id,
            user_id: user,
            role_id: Uuid::from_u128(role),
            repository_id: repo,
        });
        id
    }

    pub(crate) fn rule(
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

    pub(crate) fn project_it(&self) -> PolicyProjection {
        project_legacy_state(&self.state)
    }
}

pub(crate) fn user_rule(
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

pub(crate) fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

pub(crate) fn legacy_cond_ok(rule: &LegacyRule, ip: Option<IpAddr>) -> bool {
    match super::conditions::parse_conditions(rule.conditions.as_ref()) {
        Ok(RuleCondition::Always) => true,
        Ok(RuleCondition::Cidrs(c)) => ip.is_some_and(|ip| super::regions::contains(&c, ip)),
        Err(_) => false,
    }
}

/// The legacy decision (`check_repository_action`), re-stated independently.
pub(crate) fn legacy_allows(
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
        .any(|r| r.permissions.contains(&"admin".to_string()))
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
    let has = |actions: &[String]| {
        actions.iter().any(|a| a == action) || actions.contains(&"admin".to_string())
    };
    if !rules.is_empty() {
        rules.iter().any(|r| has(&r.actions))
    } else {
        roles.iter().any(|r| has(&r.permissions))
    }
}

pub(crate) fn all_actions() -> [(LegacyAction, &'static str); 4] {
    [
        (LegacyAction::Read, "read"),
        (LegacyAction::Write, "write"),
        (LegacyAction::Delete, "delete"),
        (LegacyAction::Admin, "admin"),
    ]
}

/// The client IPs the equivalence checks sample: absent, and addresses on both
/// sides of every range boundary the generated states use.
pub(crate) fn ip_samples() -> Vec<Option<IpAddr>> {
    std::iter::once(None)
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
        .collect()
}

/// The (user, repository) pairs holding a repository-scoped legacy role with
/// `admin`: the one case where the projection is allowed to widen (owner).
pub(crate) fn repository_owner_pairs(state: &LegacyAuthorizationState) -> BTreeSet<(Uuid, Uuid)> {
    state
        .role_assignments
        .iter()
        .filter(|a| {
            a.repository_id.is_some()
                && state
                    .roles
                    .iter()
                    .find(|r| r.id == a.role_id)
                    .is_some_and(|r| r.permissions.contains(&"admin".to_string()))
        })
        .map(|a| (a.user_id, a.repository_id.unwrap()))
        .collect()
}

/// 120 pseudorandom legacy states (users, groups, projects, repositories, role
/// assignments and CIDR-conditioned rules). The sequence is fixed by the seed.
pub(crate) fn pseudorandom_worlds() -> Vec<World> {
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
    let mut worlds = Vec::new();
    for _ in 0..120 {
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
        worlds.push(w);
    }
    worlds
}
