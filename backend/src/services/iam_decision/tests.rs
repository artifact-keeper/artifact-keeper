//! Scenario, property and legacy-equivalence tests for the decision function.

use std::collections::BTreeSet;
use std::net::IpAddr;

use chrono::{DateTime, Duration, TimeZone, Utc};
use uuid::Uuid;

use super::context::{Caller, Principal, RequestContext};
use super::decide::{decide, Decision, Grant, RefusalClass, Unavailability};
use super::snapshot::{
    Ceiling, DecisionConditions, PolicySnapshot, RepositoryFacts, ResourceIndex, SnapshotBinding,
    SnapshotDeny, SnapshotGap, Truth,
};
use crate::api::authz::catalog::Permission;
use crate::models::repository::RepositoryVisibility;
use crate::services::iam_legacy_projection::mapping::{
    action_permissions, role_effective_permissions,
};
use crate::services::iam_legacy_projection::test_support::*;
use crate::services::iam_legacy_projection::{regions, Conditions};
use crate::services::iam_legacy_projection::{
    Cidr, CredentialRef, RoleRef, ScopeRef, SubjectRef, SystemRole,
};

use Permission as P;
use RepositoryVisibility as V;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap()
}

fn at(ip: Option<&str>) -> RequestContext {
    RequestContext::new(ip.map(|s| s.parse::<IpAddr>().unwrap()), t0())
}

fn cidrs(list: &[&str]) -> Option<DecisionConditions> {
    let set: BTreeSet<Cidr> = list.iter().map(|c| Cidr::parse(c).unwrap()).collect();
    Some(DecisionConditions::new(Some(set), None, None).unwrap())
}

/// A small world: project P with repositories A, B (private) and C (internal),
/// repository D (public) outside any project, and group G.
struct Fx {
    s: PolicySnapshot,
    p: Uuid,
    a: Uuid,
    b: Uuid,
    c: Uuid,
    d: Uuid,
    g: Uuid,
}

impl Fx {
    fn new() -> Fx {
        let (p, a, b, c, d, g) = (id(10), id(11), id(12), id(13), id(14), id(15));
        let mut resources = ResourceIndex::default();
        resources.projects.insert(p);
        resources.groups.insert(g);
        for (repo, project, visibility) in [
            (a, Some(p), V::Private),
            (b, Some(p), V::Private),
            (c, Some(p), V::Internal),
            (d, None, V::Public),
        ] {
            resources.repositories.insert(
                repo,
                RepositoryFacts {
                    project,
                    visibility,
                },
            );
        }
        let mut s = PolicySnapshot::default();
        *s.resources_mut() = resources;
        Fx {
            s,
            p,
            a,
            b,
            c,
            d,
            g,
        }
    }

    fn bind(&mut self, subject: SubjectRef, role: SystemRole, scope: ScopeRef) {
        self.bind_if(subject, role, scope, None);
    }

    fn bind_if(
        &mut self,
        subject: SubjectRef,
        role: SystemRole,
        scope: ScopeRef,
        conditions: Option<DecisionConditions>,
    ) {
        let role = RoleRef::System(role);
        self.s.push_binding(SnapshotBinding {
            subject,
            permissions: Some(role_effective_permissions(&role, scope)),
            role,
            scope,
            conditions,
        });
    }

    fn deny(
        &mut self,
        subject: SubjectRef,
        scope: ScopeRef,
        perms: &[Permission],
        except: &[ScopeRef],
        conditions: Option<DecisionConditions>,
    ) {
        self.s.push_deny(SnapshotDeny {
            subject,
            scope,
            permissions: perms.iter().copied().collect(),
            excepted_scopes: except.iter().copied().collect(),
            conditions,
        });
    }

    fn decide(&self, caller: Caller, perm: Permission, resource: ScopeRef) -> Decision {
        decide(&self.s, &caller, perm, resource, &at(Some("10.0.0.1")))
    }
}

fn user(n: u128) -> Principal {
    Principal::User(id(n))
}

fn session(n: u128) -> Caller {
    Caller::session(user(n))
}

fn subj(n: u128) -> SubjectRef {
    SubjectRef::User(id(n))
}

fn repo(r: Uuid) -> ScopeRef {
    ScopeRef::Repository(r)
}

fn refused(class: RefusalClass) -> Decision {
    Decision::Refuse { refusal: class }
}

fn unavailable(reason: Unavailability) -> Decision {
    Decision::Unavailable { reason }
}

const U: u128 = 1;
const ADMIN: u128 = 2;

// ---------------------------------------------------------------------------
// 3.1 scenarios: outcome and refusal class
// ---------------------------------------------------------------------------

#[test]
fn repeated_evaluation_is_identical() {
    let mut fx = Fx::new();
    fx.bind(
        SubjectRef::Group(fx.g),
        SystemRole::Developer,
        ScopeRef::Project(fx.p),
    );
    fx.s.add_membership(id(U), fx.g);
    for perm in [P::ArtifactWrite, P::ArtifactDelete, P::RepositoryRead] {
        for r in [fx.a, fx.b, fx.c, fx.d, id(99)] {
            assert_eq!(
                fx.decide(session(U), perm, repo(r)),
                fx.decide(session(U), perm, repo(r))
            );
        }
    }
}

#[test]
fn writer_without_read_is_not_found() {
    let fx = Fx::new();
    assert_eq!(
        fx.decide(session(U), P::ArtifactWrite, repo(fx.a)),
        refused(RefusalClass::NotFound)
    );
}

#[test]
fn reader_asking_to_write_is_forbidden() {
    let mut fx = Fx::new();
    fx.bind(subj(U), SystemRole::Viewer, repo(fx.a));
    assert_eq!(
        fx.decide(session(U), P::ArtifactWrite, repo(fx.a)),
        refused(RefusalClass::Forbidden {
            missing: P::ArtifactWrite
        })
    );
}

#[test]
fn anonymous_without_baseline_is_unauthenticated() {
    let fx = Fx::new();
    assert_eq!(
        fx.decide(Caller::anonymous(), P::ArtifactRead, repo(fx.a)),
        refused(RefusalClass::Unauthenticated)
    );
    // Instance refusals are always forbidden, even for an anonymous caller.
    assert_eq!(
        fx.decide(Caller::anonymous(), P::AuditRead, ScopeRef::Instance),
        refused(RefusalClass::Forbidden {
            missing: P::AuditRead
        })
    );
}

// ---------------------------------------------------------------------------
// 1.1 / 1.2 inputs
// ---------------------------------------------------------------------------

#[test]
fn projected_conditions_convert_losslessly() {
    let samples = ip_samples();
    for list in [
        &["10.0.0.0/8"][..],
        &["10.1.2.0/24", "192.168.0.0/16"],
        &["2001:db8::/32"],
        &["0.0.0.0/0"],
    ] {
        let set: BTreeSet<Cidr> = list.iter().map(|c| Cidr::parse(c).unwrap()).collect();
        let projected = Conditions::allowed_cidrs(set.clone()).unwrap();
        let converted = DecisionConditions::from_projection(&projected);
        assert_eq!(Some(converted.clone()), cidrs(list));
        for ip in &samples {
            let expected = match ip {
                None => Truth::Unknown,
                Some(ip) if regions::contains(&set, *ip) => Truth::True,
                Some(_) => Truth::False,
            };
            assert_eq!(
                converted.evaluate(&RequestContext::new(*ip, t0())),
                expected
            );
        }
    }
}

#[test]
fn snapshot_exposes_every_projected_binding_deny_and_ceiling() {
    for w in pseudorandom_worlds().iter().take(30) {
        let projection = w.project_it();
        let s = PolicySnapshot::from_projection(&projection, ResourceIndex::default());
        assert_eq!(s.bindings().len(), projection.bindings.len());
        assert_eq!(s.denies().len(), projection.denies.len());
        for (b, p) in s.bindings().iter().zip(&projection.bindings) {
            assert_eq!(
                (b.subject, &b.role, b.scope),
                (p.item.subject, &p.item.role, p.item.scope)
            );
            assert_eq!(
                b.permissions,
                Some(role_effective_permissions(&p.item.role, p.item.scope))
            );
        }
        for c in &projection.ceilings {
            assert!(s.ceiling(c.item.credential).is_some());
        }
        for m in &projection.memberships {
            assert!(s
                .groups_of(m.item.user_id)
                .unwrap()
                .contains(&m.item.group_id));
        }
        assert!(s.gaps().is_empty());
    }
}

#[test]
fn an_undefined_compatibility_role_is_a_gap() {
    let mut w = World::new();
    let dev = w.user("dev");
    let r = w.repo("r", None);
    // read + delete matches no system role: a compatibility role.
    user_rule(&mut w, dev, "repository", r, &["read", "delete"], None);
    let mut projection = w.project_it();
    assert!(!projection.roles.is_empty());
    projection.roles.clear();
    let s = PolicySnapshot::from_projection(&projection, ResourceIndex::default());
    assert!(matches!(s.gaps(), [SnapshotGap::UnresolvedRole { .. }]));
    assert!(s.bindings().iter().any(|b| b.permissions.is_none()));
}

#[test]
fn instance_operation_refusal_is_forbidden() {
    let fx = Fx::new();
    assert_eq!(
        fx.decide(session(U), P::AuditRead, ScopeRef::Instance),
        refused(RefusalClass::Forbidden {
            missing: P::AuditRead
        })
    );
}

#[test]
fn permit_names_its_grant() {
    let mut fx = Fx::new();
    fx.bind(
        SubjectRef::Group(fx.g),
        SystemRole::Developer,
        ScopeRef::Project(fx.p),
    );
    fx.s.add_membership(id(U), fx.g);
    assert_eq!(
        fx.decide(session(U), P::ArtifactWrite, repo(fx.a)),
        Decision::Permit {
            grant: Grant::Binding {
                subject: SubjectRef::Group(fx.g),
                role: "developer".to_string(),
                scope: ScopeRef::Project(fx.p),
            }
        }
    );
    assert_eq!(
        fx.decide(session(U), P::ArtifactRead, repo(fx.d)),
        Decision::Permit {
            grant: Grant::Baseline {
                visibility: V::Public
            }
        }
    );
}

// ---------------------------------------------------------------------------
// 3.1 scenarios: the algorithm
// ---------------------------------------------------------------------------

#[test]
fn project_binding_reaches_its_repositories_only() {
    let mut fx = Fx::new();
    fx.bind(
        SubjectRef::Group(fx.g),
        SystemRole::Developer,
        ScopeRef::Project(fx.p),
    );
    fx.s.add_membership(id(U), fx.g);
    for r in [fx.a, fx.b, fx.c] {
        assert!(fx.decide(session(U), P::ArtifactWrite, repo(r)).is_permit());
    }
    assert!(!fx
        .decide(session(U), P::ArtifactWrite, repo(fx.d))
        .is_permit());
}

#[test]
fn repository_binding_does_not_confer_project_permissions() {
    let mut fx = Fx::new();
    fx.bind(subj(U), SystemRole::Developer, repo(fx.a));
    assert!(fx
        .decide(session(U), P::ArtifactWrite, repo(fx.a))
        .is_permit());
    assert!(!fx
        .decide(session(U), P::BuildWrite, ScopeRef::Project(fx.p))
        .is_permit());
}

#[test]
fn a_permission_is_refused_where_it_does_not_apply() {
    let mut fx = Fx::new();
    fx.bind(subj(U), SystemRole::Admin, ScopeRef::Instance);
    // audit.read is an instance permission: never meaningful on a repository.
    assert!(!fx.decide(session(U), P::AuditRead, repo(fx.a)).is_permit());
    assert!(fx
        .decide(session(U), P::AuditRead, ScopeRef::Instance)
        .is_permit());
}

#[test]
fn ceiling_narrows_a_binding() {
    let mut fx = Fx::new();
    fx.bind(subj(U), SystemRole::Developer, repo(fx.a));
    fx.bind(subj(U), SystemRole::Developer, repo(fx.b));
    let token = CredentialRef::Token(id(500));
    fx.s.set_ceiling(
        token,
        Ceiling {
            permissions: None,
            repository_ids: Some(BTreeSet::from([fx.a])),
        },
    );
    let caller = Caller::with_credential(user(U), token);
    assert!(fx.decide(caller, P::ArtifactWrite, repo(fx.a)).is_permit());
    assert_eq!(
        fx.decide(caller, P::ArtifactWrite, repo(fx.b)),
        refused(RefusalClass::NotFound)
    );
}

#[test]
fn ceiling_bounds_the_baseline_too() {
    let fx_ceiling = |perms: &[Permission]| Ceiling {
        permissions: Some(perms.iter().copied().collect()),
        repository_ids: None,
    };
    let mut fx = Fx::new();
    let token = CredentialRef::Token(id(500));
    fx.s.set_ceiling(token, fx_ceiling(&[P::ArtifactWrite]));
    let caller = Caller::with_credential(user(U), token);
    assert!(!fx.decide(caller, P::ArtifactRead, repo(fx.d)).is_permit());
}

#[test]
fn internal_baseline_needs_authentication() {
    let fx = Fx::new();
    assert_eq!(
        fx.decide(session(U), P::ArtifactRead, repo(fx.c)),
        Decision::Permit {
            grant: Grant::Baseline {
                visibility: V::Internal
            }
        }
    );
    assert_eq!(
        fx.decide(Caller::anonymous(), P::ArtifactRead, repo(fx.c)),
        refused(RefusalClass::Unauthenticated)
    );
    // The baseline is read only.
    assert!(!fx
        .decide(session(U), P::ArtifactWrite, repo(fx.c))
        .is_permit());
    assert!(!fx
        .decide(Caller::anonymous(), P::ArtifactWrite, repo(fx.d))
        .is_permit());
}

#[test]
fn deny_exception_keeps_a_repository_open() {
    let mut fx = Fx::new();
    let g = SubjectRef::Group(fx.g);
    fx.bind(g, SystemRole::Developer, ScopeRef::Project(fx.p));
    fx.deny(
        g,
        ScopeRef::Project(fx.p),
        &[P::ArtifactWrite],
        &[repo(fx.a)],
        None,
    );
    fx.s.add_membership(id(U), fx.g);
    assert!(fx
        .decide(session(U), P::ArtifactWrite, repo(fx.a))
        .is_permit());
    for r in [fx.b, fx.c] {
        assert_eq!(
            fx.decide(session(U), P::ArtifactWrite, repo(r)),
            refused(RefusalClass::Forbidden {
                missing: P::ArtifactWrite
            })
        );
    }
}

#[test]
fn deny_on_project_covers_a_repository_placed_there_later() {
    let mut fx = Fx::new();
    fx.bind(subj(U), SystemRole::Owner, ScopeRef::Instance);
    fx.deny(
        subj(U),
        ScopeRef::Project(fx.p),
        &[P::ArtifactDelete],
        &[],
        None,
    );
    assert!(fx
        .decide(session(U), P::ArtifactDelete, repo(fx.d))
        .is_permit());
    // D moves into P: same policy, new placement.
    fx.s.resources_mut()
        .repositories
        .get_mut(&fx.d)
        .unwrap()
        .project = Some(fx.p);
    assert!(!fx
        .decide(session(U), P::ArtifactDelete, repo(fx.d))
        .is_permit());
}

#[test]
fn deny_cannot_remove_the_public_baseline() {
    let mut fx = Fx::new();
    fx.deny(subj(U), repo(fx.d), &[P::ArtifactRead], &[], None);
    assert!(fx
        .decide(session(U), P::ArtifactRead, repo(fx.d))
        .is_permit());
}

// ---------------------------------------------------------------------------
// 3.1 scenarios: conditions
// ---------------------------------------------------------------------------

#[test]
fn time_comes_only_from_the_context_with_exact_boundaries() {
    let (t1, t2) = (t0(), t0() + Duration::hours(1));
    let mut fx = Fx::new();
    fx.bind_if(
        subj(U),
        SystemRole::Developer,
        repo(fx.a),
        Some(DecisionConditions::new(None, Some(t1), Some(t2)).unwrap()),
    );
    let at_time = |t| RequestContext::new(None, t);
    let permits = |t| {
        decide(
            &fx.s,
            &session(U),
            P::ArtifactWrite,
            repo(fx.a),
            &at_time(t),
        )
        .is_permit()
    };
    assert!(!permits(t1 - Duration::nanoseconds(1)));
    assert!(permits(t1));
    assert!(permits(t2 - Duration::nanoseconds(1)));
    assert!(!permits(t2));
}

#[test]
fn conditions_reject_an_empty_interval_or_cidr_list() {
    assert!(DecisionConditions::new(None, Some(t0()), Some(t0())).is_err());
    assert!(DecisionConditions::new(Some(BTreeSet::new()), None, None).is_err());
}

#[test]
fn exact_cidr_boundaries() {
    let mut fx = Fx::new();
    fx.bind_if(
        subj(U),
        SystemRole::Developer,
        repo(fx.a),
        cidrs(&["10.0.0.0/24"]),
    );
    let permits = |ip: &str| {
        decide(
            &fx.s,
            &session(U),
            P::ArtifactWrite,
            repo(fx.a),
            &at(Some(ip)),
        )
        .is_permit()
    };
    assert!(permits("10.0.0.0"));
    assert!(permits("10.0.0.255"));
    assert!(!permits("10.0.1.0"));
}

#[test]
fn unknown_ip_does_not_satisfy_an_allow() {
    let mut fx = Fx::new();
    fx.bind_if(
        subj(U),
        SystemRole::Developer,
        repo(fx.a),
        cidrs(&["10.0.0.0/8"]),
    );
    assert!(matches!(
        decide(&fx.s, &session(U), P::ArtifactWrite, repo(fx.a), &at(None)),
        Decision::Refuse { .. }
    ));
}

#[test]
fn unknown_ip_with_a_relevant_deny_is_unavailable() {
    let mut fx = Fx::new();
    fx.bind(subj(U), SystemRole::Developer, repo(fx.a));
    fx.deny(
        subj(U),
        repo(fx.a),
        &[P::ArtifactWrite],
        &[],
        cidrs(&["10.0.0.0/8"]),
    );
    assert_eq!(
        decide(&fx.s, &session(U), P::ArtifactWrite, repo(fx.a), &at(None)),
        unavailable(Unavailability::UnknownDeny)
    );
    // With the IP known the deny is decided either way.
    assert!(!fx
        .decide(session(U), P::ArtifactWrite, repo(fx.a))
        .is_permit());
    assert!(decide(
        &fx.s,
        &session(U),
        P::ArtifactWrite,
        repo(fx.a),
        &at(Some("192.168.0.1"))
    )
    .is_permit());
    // A deny that does not name the permission needs no IP.
    assert!(decide(&fx.s, &session(U), P::ArtifactRead, repo(fx.a), &at(None)).is_permit());
}

#[test]
fn expired_deny_needs_no_ip() {
    let mut fx = Fx::new();
    fx.bind(subj(U), SystemRole::Developer, repo(fx.a));
    let set: BTreeSet<Cidr> = BTreeSet::from([Cidr::parse("10.0.0.0/8").unwrap()]);
    let expired = DecisionConditions::new(Some(set), None, Some(t0() - Duration::seconds(1)));
    fx.deny(
        subj(U),
        repo(fx.a),
        &[P::ArtifactWrite],
        &[],
        Some(expired.unwrap()),
    );
    assert!(decide(&fx.s, &session(U), P::ArtifactWrite, repo(fx.a), &at(None)).is_permit());
}

// ---------------------------------------------------------------------------
// 3.1 scenarios: administrator and break-glass
// ---------------------------------------------------------------------------

#[test]
fn deny_applies_to_an_administrator_except_access_management() {
    let mut fx = Fx::new();
    fx.bind(subj(ADMIN), SystemRole::Admin, ScopeRef::Instance);
    fx.deny(
        subj(ADMIN),
        ScopeRef::Instance,
        &[P::ArtifactDelete, P::DenyManage, P::IamManage, P::AuditRead],
        &[],
        None,
    );
    assert!(!fx
        .decide(session(ADMIN), P::ArtifactDelete, repo(fx.a))
        .is_permit());
    assert!(!fx
        .decide(session(ADMIN), P::AuditRead, ScopeRef::Instance)
        .is_permit());
    for perm in [P::DenyManage, P::IamManage] {
        assert!(fx
            .decide(session(ADMIN), perm, ScopeRef::Instance)
            .is_permit());
    }
}

#[test]
fn break_glass_ignores_deny_but_not_the_ceiling() {
    let mut fx = Fx::new();
    fx.bind(subj(ADMIN), SystemRole::Admin, ScopeRef::Instance);
    fx.deny(
        subj(ADMIN),
        ScopeRef::Project(fx.p),
        &[P::ArtifactDelete],
        &[],
        None,
    );
    fx.s = std::mem::take(&mut fx.s).with_break_glass([id(ADMIN)]);
    assert!(fx
        .decide(session(ADMIN), P::ArtifactDelete, repo(fx.a))
        .is_permit());
    let token = CredentialRef::Token(id(501));
    fx.s.set_ceiling(
        token,
        Ceiling {
            permissions: Some(BTreeSet::from([P::ArtifactRead])),
            repository_ids: None,
        },
    );
    assert!(!fx
        .decide(
            Caller::with_credential(user(ADMIN), token),
            P::ArtifactDelete,
            repo(fx.a)
        )
        .is_permit());
}

// ---------------------------------------------------------------------------
// 3.1 scenarios: missing inputs
// ---------------------------------------------------------------------------

#[test]
fn missing_repository_is_unavailable_for_everyone() {
    let mut fx = Fx::new();
    fx.bind(subj(ADMIN), SystemRole::Admin, ScopeRef::Instance);
    for caller in [session(U), session(ADMIN), Caller::anonymous()] {
        for perm in [P::ArtifactRead, P::ArtifactWrite, P::RepositoryRead] {
            assert_eq!(
                fx.decide(caller, perm, repo(id(404))),
                unavailable(Unavailability::UnknownResource)
            );
        }
    }
}

#[test]
fn unknown_credential_is_unavailable() {
    let mut fx = Fx::new();
    fx.bind(subj(U), SystemRole::Developer, repo(fx.a));
    let caller = Caller::with_credential(user(U), CredentialRef::Token(id(777)));
    assert_eq!(
        fx.decide(caller, P::ArtifactRead, repo(fx.d)),
        unavailable(Unavailability::UnknownCredential)
    );
}

#[test]
fn unresolved_role_is_unavailable_unless_something_else_grants() {
    let mut fx = Fx::new();
    fx.s.push_binding(SnapshotBinding {
        subject: subj(U),
        role: RoleRef::Compatibility(BTreeSet::from([P::ArtifactWrite])),
        scope: repo(fx.a),
        permissions: None,
        conditions: None,
    });
    assert_eq!(
        fx.decide(session(U), P::ArtifactWrite, repo(fx.a)),
        unavailable(Unavailability::UnresolvedRole)
    );
    // Only bindings in the resource's chain matter.
    assert!(matches!(
        fx.decide(session(U), P::ArtifactWrite, repo(fx.b)),
        Decision::Refuse { .. }
    ));
    fx.bind(subj(U), SystemRole::Developer, repo(fx.a));
    assert!(fx
        .decide(session(U), P::ArtifactWrite, repo(fx.a))
        .is_permit());
}

#[test]
fn group_membership_never_reduces_access() {
    let mut fx = Fx::new();
    fx.bind(subj(U), SystemRole::Developer, repo(fx.a));
    assert!(fx
        .decide(session(U), P::ArtifactWrite, repo(fx.a))
        .is_permit());
    fx.bind(SubjectRef::Group(fx.g), SystemRole::Viewer, repo(fx.a));
    fx.s.add_membership(id(U), fx.g);
    assert!(fx
        .decide(session(U), P::ArtifactWrite, repo(fx.a))
        .is_permit());
}

#[test]
fn service_accounts_are_their_own_subjects() {
    let mut fx = Fx::new();
    fx.bind(
        SubjectRef::ServiceAccount(id(U)),
        SystemRole::Developer,
        repo(fx.a),
    );
    let sa = Caller::session(Principal::ServiceAccount(id(U)));
    assert!(fx.decide(sa, P::ArtifactWrite, repo(fx.a)).is_permit());
    assert!(!fx
        .decide(session(U), P::ArtifactWrite, repo(fx.a))
        .is_permit());
}

#[test]
fn decisions_serialize_without_naming_the_deciding_policy() {
    let mut fx = Fx::new();
    fx.bind(subj(U), SystemRole::Viewer, repo(fx.a));
    let refusal =
        serde_json::to_value(fx.decide(session(U), P::ArtifactWrite, repo(fx.a))).unwrap();
    assert_eq!(
        refusal,
        serde_json::json!({
            "outcome": "refuse",
            "refusal": { "class": "forbidden", "missing": "artifact.write" }
        })
    );
}

// ---------------------------------------------------------------------------
// 3.2 seeded properties
// ---------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn next(&mut self, modulo: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % modulo
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.next(items.len() as u64) as usize]
    }
}

const PERMS: [Permission; 8] = [
    P::RepositoryRead,
    P::ArtifactRead,
    P::ArtifactWrite,
    P::ArtifactDelete,
    P::BuildWrite,
    P::ProjectRead,
    P::DenyManage,
    P::AuditRead,
];
const ROLES: [SystemRole; 5] = [
    SystemRole::Viewer,
    SystemRole::Developer,
    SystemRole::Maintainer,
    SystemRole::Owner,
    SystemRole::Admin,
];
const USERS: [u128; 3] = [1, 2, 3];
const IPS: [Option<&str>; 4] = [
    None,
    Some("10.0.0.1"),
    Some("10.1.0.1"),
    Some("192.168.0.1"),
];
const CIDR_SETS: [&[&str]; 3] = [&["10.0.0.0/8"], &["10.0.0.0/16"], &["192.168.0.0/16"]];

fn random_scope(rng: &mut Rng, fx: &Fx) -> ScopeRef {
    rng.pick(&[
        ScopeRef::Instance,
        ScopeRef::Project(fx.p),
        ScopeRef::Group(fx.g),
        repo(fx.a),
        repo(fx.b),
        repo(fx.c),
        repo(fx.d),
    ])
}

fn random_subject(rng: &mut Rng, fx: &Fx) -> SubjectRef {
    match rng.next(4) {
        0 => SubjectRef::Group(fx.g),
        _ => subj(rng.pick(&USERS)),
    }
}

fn random_conditions(rng: &mut Rng) -> Option<DecisionConditions> {
    match rng.next(4) {
        0 => cidrs(rng.pick(&CIDR_SETS)),
        1 => Some(
            DecisionConditions::new(
                None,
                None,
                Some(t0() + Duration::hours(rng.next(3) as i64 - 1)),
            )
            .unwrap_or_default(),
        ),
        _ => None,
    }
}

fn add_random_binding(rng: &mut Rng, fx: &mut Fx) {
    let (subject, scope) = (random_subject(rng, fx), random_scope(rng, fx));
    let role = rng.pick(&ROLES);
    let role = if role == SystemRole::Admin && scope != ScopeRef::Instance {
        SystemRole::Owner
    } else {
        role
    };
    let conditions = random_conditions(rng);
    fx.bind_if(subject, role, scope, conditions);
}

fn add_random_deny(rng: &mut Rng, fx: &mut Fx) {
    let (subject, scope) = (random_subject(rng, fx), random_scope(rng, fx));
    let perms = [rng.pick(&PERMS), rng.pick(&PERMS)];
    let except = if rng.next(3) == 0 {
        vec![random_scope(rng, fx)]
    } else {
        vec![]
    };
    let conditions = random_conditions(rng);
    fx.deny(subject, scope, &perms, &except, conditions);
}

fn random_world(rng: &mut Rng) -> Fx {
    let mut fx = Fx::new();
    for _ in 0..rng.next(5) {
        add_random_binding(rng, &mut fx);
    }
    for _ in 0..rng.next(3) {
        add_random_deny(rng, &mut fx);
    }
    if rng.next(2) == 0 {
        fx.s.add_membership(id(rng.pick(&USERS)), fx.g);
    }
    fx
}

/// Every decision of `fx`: (caller, permission, resource, ip) -> decision.
fn all_decisions(fx: &Fx, callers: &[Caller]) -> Vec<Decision> {
    let resources = [
        ScopeRef::Instance,
        ScopeRef::Project(fx.p),
        ScopeRef::Group(fx.g),
        repo(fx.a),
        repo(fx.b),
        repo(fx.c),
        repo(fx.d),
    ];
    let mut out = Vec::new();
    for caller in callers {
        for perm in PERMS {
            for resource in resources {
                for ip in IPS {
                    out.push(decide(&fx.s, caller, perm, resource, &at(ip)));
                }
            }
        }
    }
    out
}

fn sessions() -> Vec<Caller> {
    USERS
        .iter()
        .map(|u| session(*u))
        .chain([Caller::anonymous()])
        .collect()
}

const PROPERTY_RUNS: usize = 250;

#[test]
fn adding_a_binding_never_removes_a_permit() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for run in 0..PROPERTY_RUNS {
        let mut fx = random_world(&mut rng);
        let before = all_decisions(&fx, &sessions());
        add_random_binding(&mut rng, &mut fx);
        let after = all_decisions(&fx, &sessions());
        for (b, a) in before.iter().zip(&after) {
            assert!(!b.is_permit() || a.is_permit(), "run {run}: {b:?} -> {a:?}");
        }
    }
}

#[test]
fn joining_a_group_no_deny_names_never_removes_a_permit() {
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    for run in 0..PROPERTY_RUNS {
        let mut fx = random_world(&mut rng);
        let g = SubjectRef::Group(fx.g);
        let kept: Vec<SnapshotDeny> = std::mem::take(&mut fx.s.denies)
            .into_iter()
            .filter(|d| d.subject != g)
            .collect();
        fx.s.denies_by_subject.clear();
        for deny in kept {
            fx.s.push_deny(deny);
        }
        let before = all_decisions(&fx, &sessions());
        fx.s.add_membership(id(rng.pick(&USERS)), fx.g);
        let after = all_decisions(&fx, &sessions());
        for (b, a) in before.iter().zip(&after) {
            assert!(!b.is_permit() || a.is_permit(), "run {run}: {b:?} -> {a:?}");
        }
    }
}

#[test]
fn adding_a_deny_never_permits_what_was_refused() {
    let mut rng = Rng(0xdead_beef_cafe_f00d);
    for run in 0..PROPERTY_RUNS {
        let mut fx = random_world(&mut rng);
        let before = all_decisions(&fx, &sessions());
        add_random_deny(&mut rng, &mut fx);
        let after = all_decisions(&fx, &sessions());
        for (b, a) in before.iter().zip(&after) {
            assert!(b.is_permit() || !a.is_permit(), "run {run}: {b:?} -> {a:?}");
        }
    }
}

#[test]
fn narrowing_a_ceiling_never_permits_what_was_refused() {
    let mut rng = Rng(0x1357_9bdf_2468_ace0);
    let token = CredentialRef::Token(id(600));
    for run in 0..PROPERTY_RUNS {
        let mut fx = random_world(&mut rng);
        let wide = Ceiling {
            permissions: (rng.next(2) == 0).then(|| PERMS[..6].iter().copied().collect()),
            repository_ids: (rng.next(2) == 0).then(|| BTreeSet::from([fx.a, fx.b, fx.d])),
        };
        let narrow = Ceiling {
            permissions: Some(
                wide.permissions
                    .clone()
                    .unwrap_or_else(|| PERMS.iter().copied().collect())
                    .into_iter()
                    .filter(|_| rng.next(2) == 0)
                    .collect(),
            ),
            repository_ids: Some(
                wide.repository_ids
                    .clone()
                    .unwrap_or_else(|| BTreeSet::from([fx.a, fx.b, fx.c, fx.d]))
                    .into_iter()
                    .filter(|_| rng.next(2) == 0)
                    .collect(),
            ),
        };
        let callers: Vec<Caller> = USERS
            .iter()
            .map(|u| Caller::with_credential(user(*u), token))
            .collect();
        fx.s.set_ceiling(token, wide.clone());
        let before = all_decisions(&fx, &callers);
        fx.s.set_ceiling(token, narrow.clone());
        let after = all_decisions(&fx, &callers);
        for (b, a) in before.iter().zip(&after) {
            assert!(b.is_permit() || !a.is_permit(), "run {run}: {b:?} -> {a:?}");
        }
        // And a session never gets less than the narrowest credential.
        let sessions_after = all_decisions(&fx, &sessions()[..USERS.len()]);
        for (s, c) in sessions_after.iter().zip(&after) {
            assert!(s.is_permit() || !c.is_permit(), "run {run}: {s:?} vs {c:?}");
        }
    }
}

#[test]
fn deny_never_removes_a_baseline_read() {
    let mut rng = Rng(0x0f0f_f0f0_1234_4321);
    for run in 0..PROPERTY_RUNS {
        let mut fx = random_world(&mut rng);
        for _ in 0..3 {
            add_random_deny(&mut rng, &mut fx);
        }
        for caller in sessions() {
            for perm in [P::RepositoryRead, P::ArtifactRead] {
                for ip in IPS {
                    let ctx = at(ip);
                    assert!(
                        decide(&fx.s, &caller, perm, repo(fx.d), &ctx).is_permit(),
                        "run {run}: public {perm} for {caller:?}"
                    );
                    if caller.principal.is_authenticated() {
                        assert!(
                            decide(&fx.s, &caller, perm, repo(fx.c), &ctx).is_permit(),
                            "run {run}: internal {perm} for {caller:?}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn decisions_are_deterministic_across_rebuilt_snapshots() {
    let mut rng_a = Rng(0x2468_1357_aaaa_5555);
    let mut rng_b = Rng(0x2468_1357_aaaa_5555);
    for _ in 0..PROPERTY_RUNS {
        let a = random_world(&mut rng_a);
        let b = random_world(&mut rng_b);
        assert_eq!(
            all_decisions(&a, &sessions()),
            all_decisions(&b, &sessions())
        );
    }
}

// ---------------------------------------------------------------------------
// 3.2 equivalence with the legacy decision over projected state
// ---------------------------------------------------------------------------

/// The projection's world as a snapshot. Every repository is private: the
/// legacy repository decision ignores visibility, so no baseline may grant.
fn snapshot_of(w: &World) -> PolicySnapshot {
    let resources = ResourceIndex {
        repositories: w
            .state
            .repositories
            .iter()
            .map(|r| {
                (
                    r.id,
                    RepositoryFacts {
                        project: r.project_id,
                        visibility: V::Private,
                    },
                )
            })
            .collect(),
        projects: w.state.projects.iter().map(|p| p.id).collect(),
        groups: w.state.groups.iter().map(|g| g.id).collect(),
    };
    PolicySnapshot::from_projection(&w.project_it(), resources)
}

/// Compare every user, repository, legacy action and sampled IP. A legacy
/// action is allowed in the target model only if every permission it maps to
/// is permitted. Returns the number of comparisons.
fn assert_agrees_with_legacy(w: &World, label: &str) -> usize {
    let snapshot = snapshot_of(w);
    assert!(snapshot.gaps().is_empty(), "{label}: {:?}", snapshot.gaps());
    let owners = repository_owner_pairs(&w.state);
    let mut compared = 0;
    for u in &w.state.users {
        let principal = if u.is_service_account {
            Principal::ServiceAccount(u.id)
        } else {
            Principal::User(u.id)
        };
        for r in &w.state.repositories {
            for (action, name) in all_actions() {
                for sample in ip_samples() {
                    let ctx = RequestContext::new(sample, t0());
                    let decisions: Vec<Decision> = action_permissions(action)
                        .into_iter()
                        .map(|p| {
                            decide(&snapshot, &Caller::session(principal), p, repo(r.id), &ctx)
                        })
                        .collect();
                    let permit = decisions.iter().all(Decision::is_permit);
                    let legacy = legacy_allows(&w.state, u.id, r.id, name, sample);
                    compared += 1;
                    let at = format!(
                        "{label}: user={} repo={} action={name} ip={sample:?} decisions={decisions:?}",
                        u.username, r.key
                    );
                    if permit && !legacy {
                        assert!(owners.contains(&(u.id, r.id)), "WIDENING {at}");
                    }
                    if legacy && !permit {
                        assert!(
                            sample.is_none()
                                && decisions
                                    .iter()
                                    .any(|d| matches!(d, Decision::Unavailable { .. })),
                            "TIGHTENING {at}"
                        );
                    }
                }
            }
        }
    }
    compared
}

#[test]
fn design_example_agrees_with_legacy() {
    let mut w = World::new();
    let dev = w.user("dev");
    let group_user = w.user("group-user");
    let owner = w.user("owner");
    let boss = w.admin("boss");
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
    w.rule(
        crate::services::iam_legacy_projection::legacy::LegacyPrincipal::Group(team),
        "repository",
        special,
        &["read", "write", "delete"],
        Some(&["10.1.0.0/16"]),
    );
    let _ = boss;
    let compared = assert_agrees_with_legacy(&w, "design example");
    assert_eq!(compared, 4 * 3 * 4 * ip_samples().len());
}

#[test]
fn pseudorandom_legacy_states_agree_with_legacy() {
    let mut compared = 0;
    for (scenario, w) in pseudorandom_worlds().iter().enumerate() {
        compared += assert_agrees_with_legacy(w, &format!("scenario {scenario}"));
    }
    assert!(compared > 10_000, "only {compared} comparisons");
}
