//! Policy intents: the projection's canonical, deterministic output.
//!
//! Intents describe target-model policy (bindings, denies, memberships,
//! mappings, ceilings) without persisting anything and without random IDs. Each
//! carries the legacy records it came from. [`ProjectionBuilder`] is the only
//! way to assemble a [`PolicyProjection`]: it sorts, de-duplicates and merges
//! the provenance of equal intents, so the same source state always yields the
//! same value and the same serialized bytes.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;

use serde::{Serialize, Serializer};
use uuid::Uuid;

use crate::api::authz::catalog::Permission;

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

/// Which legacy table or setting a record came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    User,
    Role,
    RoleAssignment,
    Rule,
    Group,
    Membership,
    Repository,
    Project,
    Token,
    CiMapping,
    SsoConfig,
    /// A legacy table that confers nothing today (`user_roles`, `permission_grants`).
    LegacyTable,
}

/// A stable reference to one legacy record or setting.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct SourceRef {
    pub kind: SourceKind,
    pub id: String,
}

impl SourceRef {
    pub fn new(kind: SourceKind, id: impl fmt::Display) -> Self {
        Self {
            kind,
            id: id.to_string(),
        }
    }
}

/// The legacy records an intent was derived from, in a stable order.
pub type Provenance = BTreeSet<SourceRef>;

/// An intent together with its provenance.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Sourced<T> {
    #[serde(flatten)]
    pub item: T,
    pub provenance: Provenance,
}

// ---------------------------------------------------------------------------
// Subjects, scopes, roles
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectRef {
    User(Uuid),
    ServiceAccount(Uuid),
    Group(Uuid),
    Anonymous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeRef {
    Instance,
    Group(Uuid),
    Project(Uuid),
    Repository(Uuid),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SystemRole {
    Viewer,
    Developer,
    Maintainer,
    Owner,
    ReleaseManager,
    SecurityOfficer,
    Admin,
}

/// A role a binding refers to: a system role, or a compatibility role holding
/// exactly the permissions of a legacy grant that no system role matches.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RoleRef {
    System(SystemRole),
    Compatibility(BTreeSet<Permission>),
}

impl RoleRef {
    /// A deterministic name: `developer`, or `legacy:<id>,<id>,...`.
    pub fn name(&self) -> String {
        match self {
            RoleRef::System(role) => serde_json::to_value(role)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default(),
            RoleRef::Compatibility(perms) => {
                let ids: Vec<&str> = perms.iter().map(|p| p.id()).collect();
                format!("legacy:{}", ids.join(","))
            }
        }
    }
}

impl Serialize for RoleRef {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.name())
    }
}

/// The definition of a compatibility role a projection's bindings need.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct RoleDefinition {
    pub role: RoleRef,
    pub permissions: BTreeSet<Permission>,
}

// ---------------------------------------------------------------------------
// Conditions
// ---------------------------------------------------------------------------

/// A CIDR range, normalized to its network address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cidr {
    addr: IpAddr,
    prefix_len: u8,
}

impl Cidr {
    /// Parse `addr/len` (a bare address is a host route); host bits are cleared.
    pub fn parse(text: &str) -> Result<Cidr, String> {
        let text = text.trim();
        let (addr_text, len_text) = match text.split_once('/') {
            Some((a, l)) => (a, Some(l)),
            None => (text, None),
        };
        let addr: IpAddr = addr_text
            .parse()
            .map_err(|_| format!("`{text}` is not an IP address range"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix_len = match len_text {
            None => max,
            Some(l) => l
                .parse::<u8>()
                .ok()
                .filter(|l| *l <= max)
                .ok_or_else(|| format!("`{text}` has an invalid prefix length"))?,
        };
        Ok(Cidr {
            addr: mask(addr, prefix_len),
            prefix_len,
        })
    }

    /// A range from its parts; host bits are cleared. `prefix_len` is clamped to
    /// the address family's width.
    pub fn from_parts(addr: IpAddr, prefix_len: u8) -> Cidr {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix_len = prefix_len.min(max);
        Cidr {
            addr: mask(addr, prefix_len),
            prefix_len,
        }
    }

    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }
}

fn mask(addr: IpAddr, prefix_len: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let m = if prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix_len))
            };
            IpAddr::V4((bits & m).into())
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let m = if prefix_len == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix_len))
            };
            IpAddr::V6((bits & m).into())
        }
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

impl Serialize for Cidr {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Conditions on an allow or deny. Version one carries only `allowed_cidrs`.
/// The list is never empty: an empty list would mean "never", and an absent
/// condition means "always".
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Conditions {
    allowed_cidrs: BTreeSet<Cidr>,
}

impl Conditions {
    /// `None` when `cidrs` is empty.
    pub fn allowed_cidrs(cidrs: impl IntoIterator<Item = Cidr>) -> Option<Conditions> {
        let allowed_cidrs: BTreeSet<Cidr> = cidrs.into_iter().collect();
        (!allowed_cidrs.is_empty()).then_some(Conditions { allowed_cidrs })
    }

    pub fn cidrs(&self) -> &BTreeSet<Cidr> {
        &self.allowed_cidrs
    }
}

// ---------------------------------------------------------------------------
// Intents
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Binding {
    pub subject: SubjectRef,
    pub role: RoleRef,
    pub scope: ScopeRef,
    pub conditions: Option<Conditions>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Deny {
    pub subject: SubjectRef,
    pub scope: ScopeRef,
    pub permissions: BTreeSet<Permission>,
    /// Scopes below `scope` where the deny does not withhold. Never a grant.
    pub excepted_scopes: BTreeSet<ScopeRef>,
    pub conditions: Option<Conditions>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MembershipSource {
    Manual,
    Idp(String),
    CiMapping(Uuid),
}

impl fmt::Display for MembershipSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MembershipSource::Manual => f.write_str("manual"),
            MembershipSource::Idp(provider) => write!(f, "idp:{provider}"),
            MembershipSource::CiMapping(id) => write!(f, "ci-mapping:{id}"),
        }
    }
}

impl Serialize for MembershipSource {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Membership {
    pub group_id: Uuid,
    pub user_id: Uuid,
    pub source: MembershipSource,
}

/// An identity-provider group mapped to a local group of the same name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ExternalGroupMapping {
    pub provider: String,
    pub external_group: String,
    pub local_group_id: Uuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialRef {
    Token(Uuid),
    CiMapping(Uuid),
}

/// A credential ceiling: it narrows what the credential's principal can do and
/// never grants. `None` means that dimension is unrestricted.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct CredentialCeiling {
    pub credential: CredentialRef,
    pub permissions: Option<BTreeSet<Permission>>,
    pub repository_ids: Option<BTreeSet<Uuid>>,
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticCategory {
    /// An SSO user with `is_admin` and no configured admin-group evidence.
    AmbiguousSsoAdmin,
    /// A rule or assignment naming a principal that does not exist or is unsupported.
    UnknownPrincipal,
    /// A rule target type the IAM model does not recognize.
    UnknownTarget,
    /// An action string outside the legacy vocabulary.
    UnsupportedAction,
    /// A role whose shape cannot be mapped.
    UnsupportedRole,
    /// A malformed or unsupported `conditions` value.
    InvalidCondition,
    /// A setting needed by the mapping could not be read.
    MissingSourceConfig,
    /// CIDR-region expansion exceeded its safety limit.
    RegionOverflow,
    /// A legacy record dropped without conversion because it confers nothing.
    Dropped,
    /// The one permission widening the model makes: repository owners.
    OwnerWidening,
    /// A conditional deny: a request without a verified client IP is refused
    /// where the legacy fallback to the role would have allowed it.
    UnknownIpTightening,
    /// A token restriction that cannot be pinned to a fixed repository set.
    UnsupportedCredentialRestriction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Recorded for the upgrade report; the projection stays comparable.
    Informational,
    /// The projection omits something that legacy grants: it is incomplete.
    Blocking,
}

impl DiagnosticCategory {
    pub fn severity(self) -> Severity {
        match self {
            DiagnosticCategory::Dropped
            | DiagnosticCategory::UnknownTarget
            | DiagnosticCategory::OwnerWidening
            | DiagnosticCategory::UnknownIpTightening => Severity::Informational,
            DiagnosticCategory::AmbiguousSsoAdmin
            | DiagnosticCategory::UnknownPrincipal
            | DiagnosticCategory::UnsupportedAction
            | DiagnosticCategory::UnsupportedRole
            | DiagnosticCategory::InvalidCondition
            | DiagnosticCategory::MissingSourceConfig
            | DiagnosticCategory::UnsupportedCredentialRestriction
            | DiagnosticCategory::RegionOverflow => Severity::Blocking,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Diagnostic {
    pub category: DiagnosticCategory,
    pub source: SourceRef,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Completeness {
    Complete,
    /// A later shadow evaluation must treat this as unavailable input, not as
    /// a clean allow or deny.
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProjectionReport {
    pub completeness: Completeness,
    pub diagnostics: Vec<Diagnostic>,
}

// ---------------------------------------------------------------------------
// The projection and its builder
// ---------------------------------------------------------------------------

/// The canonical output. Every collection is sorted and free of duplicates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyProjection {
    pub roles: Vec<Sourced<RoleDefinition>>,
    pub bindings: Vec<Sourced<Binding>>,
    pub denies: Vec<Sourced<Deny>>,
    pub memberships: Vec<Sourced<Membership>>,
    pub external_group_mappings: Vec<Sourced<ExternalGroupMapping>>,
    pub ceilings: Vec<Sourced<CredentialCeiling>>,
    pub report: ProjectionReport,
}

impl PolicyProjection {
    /// Canonical bytes: identical source state and configuration give identical output.
    pub fn to_canonical_json(&self) -> String {
        serde_json::to_string(self).expect("projection serializes")
    }
}

#[derive(Debug, Default)]
pub struct ProjectionBuilder {
    roles: BTreeMap<RoleDefinition, Provenance>,
    bindings: BTreeMap<Binding, Provenance>,
    denies: BTreeMap<Deny, Provenance>,
    memberships: BTreeMap<Membership, Provenance>,
    external_group_mappings: BTreeMap<ExternalGroupMapping, Provenance>,
    ceilings: BTreeMap<CredentialCeiling, Provenance>,
    diagnostics: BTreeSet<Diagnostic>,
}

fn sourced<T: Ord>(map: BTreeMap<T, Provenance>) -> Vec<Sourced<T>> {
    map.into_iter()
        .map(|(item, provenance)| Sourced { item, provenance })
        .collect()
}

fn merge<T: Ord>(
    map: &mut BTreeMap<T, Provenance>,
    item: T,
    from: impl IntoIterator<Item = SourceRef>,
) {
    map.entry(item).or_default().extend(from);
}

impl ProjectionBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Equal intents coalesce and union their provenance.
    pub fn role(&mut self, role: RoleDefinition, from: impl IntoIterator<Item = SourceRef>) {
        merge(&mut self.roles, role, from);
    }

    pub fn binding(&mut self, binding: Binding, from: impl IntoIterator<Item = SourceRef>) {
        merge(&mut self.bindings, binding, from);
    }

    pub fn deny(&mut self, deny: Deny, from: impl IntoIterator<Item = SourceRef>) {
        merge(&mut self.denies, deny, from);
    }

    pub fn membership(&mut self, m: Membership, from: impl IntoIterator<Item = SourceRef>) {
        merge(&mut self.memberships, m, from);
    }

    pub fn external_group_mapping(
        &mut self,
        m: ExternalGroupMapping,
        from: impl IntoIterator<Item = SourceRef>,
    ) {
        merge(&mut self.external_group_mappings, m, from);
    }

    pub fn ceiling(&mut self, c: CredentialCeiling, from: impl IntoIterator<Item = SourceRef>) {
        merge(&mut self.ceilings, c, from);
    }

    pub fn diagnostic(
        &mut self,
        category: DiagnosticCategory,
        source: SourceRef,
        detail: impl Into<String>,
    ) {
        self.diagnostics.insert(Diagnostic {
            category,
            source,
            detail: detail.into(),
        });
    }

    pub fn build(self) -> PolicyProjection {
        let completeness = if self
            .diagnostics
            .iter()
            .any(|d| d.category.severity() == Severity::Blocking)
        {
            Completeness::Incomplete
        } else {
            Completeness::Complete
        };
        PolicyProjection {
            roles: sourced(self.roles),
            bindings: sourced(self.bindings),
            denies: sourced(self.denies),
            memberships: sourced(self.memberships),
            external_group_mappings: sourced(self.external_group_mappings),
            ceilings: sourced(self.ceilings),
            report: ProjectionReport {
                completeness,
                diagnostics: self.diagnostics.into_iter().collect(),
            },
        }
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn src(kind: SourceKind, n: u128) -> SourceRef {
        SourceRef::new(kind, id(n))
    }

    fn binding(user: u128, role: SystemRole, scope: ScopeRef) -> Binding {
        Binding {
            subject: SubjectRef::User(id(user)),
            role: RoleRef::System(role),
            scope,
            conditions: None,
        }
    }

    /// Fill a builder with the same intents in the given order.
    fn fill(order: &[usize]) -> PolicyProjection {
        let mut b = ProjectionBuilder::new();
        for &i in order {
            match i {
                0 => b.binding(
                    binding(1, SystemRole::Developer, ScopeRef::Repository(id(10))),
                    [src(SourceKind::RoleAssignment, 100)],
                ),
                1 => b.binding(
                    binding(2, SystemRole::Admin, ScopeRef::Instance),
                    [src(SourceKind::User, 2)],
                ),
                2 => b.deny(
                    Deny {
                        subject: SubjectRef::User(id(1)),
                        scope: ScopeRef::Project(id(20)),
                        permissions: [Permission::ArtifactWrite].into(),
                        excepted_scopes: [ScopeRef::Repository(id(10))].into(),
                        conditions: None,
                    },
                    [src(SourceKind::Rule, 200)],
                ),
                3 => b.membership(
                    Membership {
                        group_id: id(30),
                        user_id: id(1),
                        source: MembershipSource::Idp("okta".into()),
                    },
                    [src(SourceKind::Membership, 300)],
                ),
                4 => b.external_group_mapping(
                    ExternalGroupMapping {
                        provider: "okta".into(),
                        external_group: "devs".into(),
                        local_group_id: id(30),
                    },
                    [src(SourceKind::Group, 30)],
                ),
                5 => b.ceiling(
                    CredentialCeiling {
                        credential: CredentialRef::Token(id(40)),
                        permissions: Some([Permission::ArtifactRead].into()),
                        repository_ids: None,
                    },
                    [src(SourceKind::Token, 40)],
                ),
                6 => b.diagnostic(
                    DiagnosticCategory::Dropped,
                    src(SourceKind::LegacyTable, 0),
                    "user_roles confers nothing",
                ),
                _ => unreachable!(),
            }
        }
        b.build()
    }

    #[test]
    fn output_is_independent_of_insertion_order() {
        let a = fill(&[0, 1, 2, 3, 4, 5, 6]);
        let b = fill(&[6, 5, 4, 3, 2, 1, 0]);
        let c = fill(&[3, 0, 6, 1, 5, 2, 4]);
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_eq!(a.to_canonical_json(), b.to_canonical_json());
        assert_eq!(a.to_canonical_json(), c.to_canonical_json());
    }

    #[test]
    fn output_collections_are_sorted() {
        let p = fill(&[0, 1]);
        let keys: Vec<_> = p.bindings.iter().map(|s| s.item.clone()).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn equal_intents_coalesce_and_union_provenance() {
        let mut b = ProjectionBuilder::new();
        let intent = binding(1, SystemRole::Viewer, ScopeRef::Instance);
        b.binding(intent.clone(), [src(SourceKind::RoleAssignment, 1)]);
        b.binding(
            intent.clone(),
            [
                src(SourceKind::RoleAssignment, 2),
                src(SourceKind::RoleAssignment, 1),
            ],
        );
        let p = b.build();
        assert_eq!(p.bindings.len(), 1);
        assert_eq!(p.bindings[0].item, intent);
        assert_eq!(p.bindings[0].provenance.len(), 2);
    }

    #[test]
    fn differing_scope_or_conditions_do_not_coalesce() {
        let cidr = Cidr::parse("10.0.0.0/8").unwrap();
        let mut b = ProjectionBuilder::new();
        let base = binding(1, SystemRole::Viewer, ScopeRef::Instance);
        let conditional = Binding {
            conditions: Conditions::allowed_cidrs([cidr]),
            ..base.clone()
        };
        let narrower = Binding {
            scope: ScopeRef::Repository(id(9)),
            ..base.clone()
        };
        for x in [base, conditional, narrower] {
            b.binding(x, [src(SourceKind::Rule, 1)]);
        }
        assert_eq!(b.build().bindings.len(), 3);
    }

    #[test]
    fn completeness_follows_blocking_diagnostics() {
        let complete = fill(&[0, 6]);
        assert_eq!(complete.report.completeness, Completeness::Complete);
        assert_eq!(complete.report.diagnostics.len(), 1);

        for blocking in [
            DiagnosticCategory::AmbiguousSsoAdmin,
            DiagnosticCategory::UnknownPrincipal,
            DiagnosticCategory::UnsupportedAction,
            DiagnosticCategory::UnsupportedRole,
            DiagnosticCategory::InvalidCondition,
            DiagnosticCategory::MissingSourceConfig,
            DiagnosticCategory::RegionOverflow,
            DiagnosticCategory::UnsupportedCredentialRestriction,
        ] {
            assert_eq!(blocking.severity(), Severity::Blocking);
            let mut b = ProjectionBuilder::new();
            b.diagnostic(blocking, src(SourceKind::Rule, 1), "x");
            assert_eq!(b.build().report.completeness, Completeness::Incomplete);
        }
        for info in [
            DiagnosticCategory::Dropped,
            DiagnosticCategory::UnknownTarget,
            DiagnosticCategory::OwnerWidening,
            DiagnosticCategory::UnknownIpTightening,
        ] {
            assert_eq!(info.severity(), Severity::Informational);
        }
    }

    #[test]
    fn identical_diagnostics_are_reported_once() {
        let mut b = ProjectionBuilder::new();
        for _ in 0..3 {
            b.diagnostic(
                DiagnosticCategory::InvalidCondition,
                src(SourceKind::Rule, 7),
                "bad cidr",
            );
        }
        assert_eq!(b.build().report.diagnostics.len(), 1);
    }

    #[test]
    fn empty_projection_is_complete_and_empty() {
        let p = ProjectionBuilder::new().build();
        assert_eq!(p.report.completeness, Completeness::Complete);
        assert!(p.bindings.is_empty() && p.denies.is_empty() && p.report.diagnostics.is_empty());
    }

    #[test]
    fn cidr_parses_and_normalizes() {
        assert_eq!(Cidr::parse("10.1.2.3/8").unwrap().to_string(), "10.0.0.0/8");
        assert_eq!(
            Cidr::parse("192.168.1.7").unwrap().to_string(),
            "192.168.1.7/32"
        );
        assert_eq!(Cidr::parse("0.0.0.0/0").unwrap().to_string(), "0.0.0.0/0");
        assert_eq!(
            Cidr::parse("2001:db8::1/32").unwrap().to_string(),
            "2001:db8::/32"
        );
        assert_eq!(Cidr::parse("::/0").unwrap().prefix_len(), 0);
        for bad in [
            "",
            "x",
            "10.0.0.0/33",
            "10.0.0.0/-1",
            "::/129",
            "10.0.0.0/8/8",
            "10.0.0/8",
        ] {
            assert!(Cidr::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn empty_cidr_list_is_not_a_condition() {
        assert_eq!(Conditions::allowed_cidrs([]), None);
        let c = Conditions::allowed_cidrs([
            Cidr::parse("10.0.0.0/8").unwrap(),
            Cidr::parse("10.0.0.0/8").unwrap(),
        ])
        .unwrap();
        assert_eq!(c.cidrs().len(), 1);
    }

    #[test]
    fn role_names_are_stable() {
        assert_eq!(
            RoleRef::System(SystemRole::ReleaseManager).name(),
            "release-manager"
        );
        assert_eq!(RoleRef::System(SystemRole::Developer).name(), "developer");
        let compat =
            RoleRef::Compatibility([Permission::ArtifactWrite, Permission::ArtifactRead].into());
        // Sorted by catalog order, not insertion order.
        assert_eq!(compat.name(), "legacy:artifact.read,artifact.write");
    }

    #[test]
    fn canonical_json_uses_stable_names() {
        let p = fill(&[0, 3, 5]);
        let json = p.to_canonical_json();
        assert!(json.contains("\"developer\""), "{json}");
        assert!(json.contains("idp:okta"), "{json}");
        assert!(json.contains("artifact.read"), "{json}");
        assert!(json.contains("\"completeness\":\"complete\""), "{json}");
    }
}
