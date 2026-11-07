//! The IAM permission catalog.
//!
//! One closed set of `<resource>.<action>` permissions, each with the scopes at
//! which a binding of it can apply. The identifiers are the contract with the
//! `iam-model` spec (`openspec/changes/add-iam-authorization-model`); the
//! stable string is what route declarations carry in `x-required-permission`.
//! Nothing here evaluates a decision.

use std::fmt;
use std::str::FromStr;

/// A level at which a permission can be granted or checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    Repository,
    Project,
    Group,
    Instance,
}

/// The narrowest-scope class a catalog entry is listed under.
///
/// `Repository` (R) applies at a repository, a project or the instance;
/// `Project` (P) at a project or the instance; `Group` (G) at a group or the
/// instance; `Instance` (I) only at the instance. `Any` is for the one
/// permission the spec lists at every level (`deny.manage`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reach {
    Repository,
    Project,
    Group,
    Instance,
    Any,
}

impl Reach {
    /// Every scope a permission of this class can apply at.
    pub const fn scopes(self) -> &'static [Scope] {
        match self {
            Reach::Repository => &[Scope::Repository, Scope::Project, Scope::Instance],
            Reach::Project => &[Scope::Project, Scope::Instance],
            Reach::Group => &[Scope::Group, Scope::Instance],
            Reach::Instance => &[Scope::Instance],
            Reach::Any => &[
                Scope::Repository,
                Scope::Project,
                Scope::Group,
                Scope::Instance,
            ],
        }
    }
}

macro_rules! catalog {
    ($($variant:ident => ($id:literal, $reach:ident, $description:literal);)*) => {
        /// A permission from the closed catalog.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum Permission {
            $($variant),*
        }

        impl Permission {
            /// Every catalog permission, in catalog order.
            pub const ALL: &'static [Permission] = &[$(Permission::$variant),*];

            /// The stable identifier used in declarations and APIs.
            pub const fn id(self) -> &'static str {
                match self {
                    $(Permission::$variant => $id),*
                }
            }

            /// The scope class this permission is listed under.
            pub const fn reach(self) -> Reach {
                match self {
                    $(Permission::$variant => Reach::$reach),*
                }
            }

            /// Human-readable description, for later catalog publication.
            pub const fn description(self) -> &'static str {
                match self {
                    $(Permission::$variant => $description),*
                }
            }
        }
    };
}

catalog! {
    // Repository content
    RepositoryRead => ("repository.read", Repository, "View a repository and its contents listing");
    ArtifactRead => ("artifact.read", Repository, "Download and read artifacts");
    ArtifactAnnotate => ("artifact.annotate", Repository, "Set metadata and labels on artifacts");
    ArtifactWrite => ("artifact.write", Repository, "Publish artifacts");
    ArtifactDelete => ("artifact.delete", Repository, "Delete artifacts");
    ArtifactSign => ("artifact.sign", Repository, "Sign artifacts");
    // Repository management
    RepositoryCreate => ("repository.create", Project, "Create repositories");
    RepositoryUpdate => ("repository.update", Repository, "Change repository configuration");
    RepositoryLabelManage => ("repository.label.manage", Repository, "Set, add and delete repository labels");
    RepositoryCredentialsUpdate => ("repository.credentials.update", Repository, "Change repository upstream credentials");
    RepositoryDelete => ("repository.delete", Repository, "Delete a repository");
    RepositoryNotificationsManage => ("repository.notifications.manage", Repository, "Manage repository notification subscriptions");
    RepositoryMaintenance => ("repository.maintenance", Repository, "Run repository maintenance operations");
    RepositoryTokenManage => ("repository.token.manage", Repository, "Manage repository-scoped tokens");
    RepositoryIamManage => ("repository.iam.manage", Repository, "Manage access bindings on a repository");
    // Deny administration
    DenyManage => ("deny.manage", Any, "Manage deny policies");
    // Promotion
    PromotionCreate => ("promotion.create", Repository, "Promote artifacts out of a repository");
    PromotionReceive => ("promotion.receive", Repository, "Accept promotions into a repository");
    PromotionReject => ("promotion.reject", Repository, "Reject promotions");
    PromotionRequest => ("promotion.request", Repository, "Request a promotion");
    PromotionApprove => ("promotion.approve", Repository, "Approve promotions");
    PromotionRuleManage => ("promotion.rule.manage", Project, "Manage promotion rules");
    // Security and curation
    SecurityRead => ("security.read", Repository, "Read scan results and findings");
    SecurityScan => ("security.scan", Repository, "Trigger security scans");
    SecurityFindingsIngest => ("security.findings.ingest", Repository, "Ingest external security findings");
    SecurityTriage => ("security.triage", Repository, "Triage security findings");
    SecurityQuarantine => ("security.quarantine", Repository, "Quarantine and release artifacts");
    CurationReview => ("curation.review", Repository, "Review curated packages");
    CurationPublish => ("curation.publish", Repository, "Publish curated packages");
    AgeGateReview => ("age_gate.review", Repository, "Review age-gated packages");
    SecurityPolicyManage => ("security.policy.manage", Project, "Manage security policies");
    // Builds and environments
    BuildRead => ("build.read", Project, "Read builds");
    BuildWrite => ("build.write", Project, "Record builds");
    ImageBuildCreate => ("image_build.create", Repository, "Create image builds");
    EnvironmentRead => ("environment.read", Repository, "Read environments");
    EnvironmentWrite => ("environment.write", Repository, "Change environments");
    // Projects
    ProjectRead => ("project.read", Project, "Read a project");
    ProjectUpdate => ("project.update", Project, "Change a project");
    ProjectDelete => ("project.delete", Project, "Delete a project");
    IamManage => ("iam.manage", Project, "Manage access bindings and members in a project");
    ProjectCreate => ("project.create", Instance, "Create projects");
    // Identity and access
    GroupRead => ("group.read", Group, "Read a group and its members");
    GroupManage => ("group.manage", Group, "Manage a group and its members");
    GroupCreate => ("group.create", Instance, "Create groups");
    UserRead => ("user.read", Instance, "Read users");
    UserManage => ("user.manage", Instance, "Manage users");
    UserCredentialsManage => ("user.credentials.manage", Instance, "Manage other users' credentials");
    RoleManage => ("role.manage", Instance, "Manage roles");
    ServiceAccountManage => ("service_account.manage", Instance, "Manage service accounts");
    ServiceAccountTokenCreate => ("service_account.token.create", Instance, "Create service account tokens");
    IdentityProviderManage => ("identity_provider.manage", Instance, "Manage identity providers");
    // Platform
    ReplicationRead => ("replication.read", Instance, "Read replication state");
    ReplicationManage => ("replication.manage", Instance, "Manage replication");
    ReplicationTrigger => ("replication.trigger", Instance, "Trigger replication");
    WebhookRead => ("webhook.read", Instance, "Read webhooks");
    WebhookManage => ("webhook.manage", Instance, "Manage webhooks");
    PluginManage => ("plugin.manage", Instance, "Manage plugins");
    FormatManage => ("format.manage", Instance, "Manage package formats");
    MigrationManage => ("migration.manage", Instance, "Run migrations from other registries");
    RetentionPolicyManage => ("retention.policy.manage", Instance, "Manage retention policies");
    SigningKeyManage => ("signing.key.manage", Instance, "Manage signing keys");
    SystemSettingsRead => ("system.settings.read", Instance, "Read system settings");
    SystemSettingsUpdate => ("system.settings.update", Instance, "Change system settings");
    SystemBackupManage => ("system.backup.manage", Instance, "Manage backups");
    SystemMaintenance => ("system.maintenance", Instance, "Run system maintenance");
    AuditRead => ("audit.read", Instance, "Read the audit log");
    MonitoringRead => ("monitoring.read", Instance, "Read monitoring data");
    MonitoringManage => ("monitoring.manage", Instance, "Manage monitoring");
    AnalyticsRead => ("analytics.read", Instance, "Read analytics");
}

impl Permission {
    /// The narrowest scope this permission can apply at.
    pub fn narrowest_scope(self) -> Scope {
        self.reach().scopes()[0]
    }

    /// Whether a binding or check of this permission is meaningful at `scope`.
    pub fn applies_at(self, scope: Scope) -> bool {
        self.reach().scopes().contains(&scope)
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// An identifier that is not in the catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownPermission(pub String);

impl fmt::Display for UnknownPermission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown permission `{}`", self.0)
    }
}

impl std::error::Error for UnknownPermission {}

impl FromStr for Permission {
    type Err = UnknownPermission;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Permission::ALL
            .iter()
            .copied()
            .find(|p| p.id() == s)
            .ok_or_else(|| UnknownPermission(s.to_string()))
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn every_identifier_round_trips_and_is_unique() {
        let mut seen = HashSet::new();
        for &p in Permission::ALL {
            assert!(seen.insert(p.id()), "duplicate identifier {}", p.id());
            assert_eq!(p.id().parse::<Permission>(), Ok(p));
            assert_eq!(p.to_string(), p.id());
        }
        assert_eq!(seen.len(), Permission::ALL.len());
    }

    #[test]
    fn identifiers_follow_the_resource_action_shape() {
        for &p in Permission::ALL {
            let id = p.id();
            assert!(id.contains('.'), "{id}");
            assert!(
                id.split('.').all(|part| !part.is_empty()
                    && part.chars().all(|c| c.is_ascii_lowercase() || c == '_')),
                "{id}"
            );
            assert!(!p.description().is_empty(), "{id}");
        }
    }

    #[test]
    fn every_permission_has_scope_metadata() {
        for &p in Permission::ALL {
            assert!(!p.reach().scopes().is_empty());
            // The instance is always an applicable scope.
            assert!(p.applies_at(Scope::Instance), "{p}");
        }
    }

    #[test]
    fn scopes_match_the_spec_classes() {
        let cases = [
            ("repository.read", Scope::Repository),
            ("repository.label.manage", Scope::Repository),
            ("repository.create", Scope::Project),
            ("promotion.rule.manage", Scope::Project),
            ("build.write", Scope::Project),
            ("iam.manage", Scope::Project),
            ("project.create", Scope::Instance),
            ("group.manage", Scope::Group),
            ("group.create", Scope::Instance),
            ("system.settings.update", Scope::Instance),
        ];
        for (id, scope) in cases {
            let p: Permission = id.parse().unwrap();
            assert_eq!(p.narrowest_scope(), scope, "{id}");
        }
        let deny: Permission = "deny.manage".parse().unwrap();
        for scope in [
            Scope::Repository,
            Scope::Project,
            Scope::Group,
            Scope::Instance,
        ] {
            assert!(deny.applies_at(scope));
        }
        let rl: Permission = "repository.label.manage".parse().unwrap();
        assert!(rl.applies_at(Scope::Project));
        assert!(!rl.applies_at(Scope::Group));
        let pr: Permission = "project.read".parse().unwrap();
        assert!(!pr.applies_at(Scope::Repository));
    }

    #[test]
    fn unknown_identifiers_are_rejected() {
        for bad in [
            "",
            "repository",
            "repository.read ",
            "Repository.Read",
            "repository.labels.manage",
            "repository.update.",
        ] {
            assert_eq!(
                bad.parse::<Permission>(),
                Err(UnknownPermission(bad.to_string())),
                "{bad:?}"
            );
        }
    }
}
