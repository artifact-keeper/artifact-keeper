//! The authorization of every `/api/v1/admin` operation, as a table checked
//! against the declarations in the OpenAPI document, and the rule that keeps
//! the area administrator-only: no admin operation names a permission a
//! non-administrator can hold on the instance after the upgrade.

use std::collections::BTreeSet;

use super::catalog::Permission;
use super::declaration::RouteRequirement;
use super::declaration_table::{differences, parse, registry, unknown_requirement};
use super::registry::RouteKey;
use crate::services::iam_legacy_projection::mapping::{
    action_permissions, scope_grant, sentinel_admin_permissions, system_role_permissions,
    LegacyAction, ScopeGrant,
};
use crate::services::iam_legacy_projection::SystemRole;

/// Rows in the format of [`parse`].
const TABLE: &str = "
GET    /api/v1/admin/age-gate/reviews  age_gate.review  instance
GET    /api/v1/admin/age-gate/reviews/:id  age_gate.review  instance
POST   /api/v1/admin/age-gate/reviews/:id/approve  age_gate.review  instance
POST   /api/v1/admin/age-gate/reviews/:id/reject  age_gate.review  instance
POST   /api/v1/admin/age-gate/reviews/:id/reopen  age_gate.review  instance
GET    /api/v1/admin/analytics/artifacts/stale  analytics.read  instance
GET    /api/v1/admin/analytics/downloads/trend  analytics.read  instance
GET    /api/v1/admin/analytics/repositories/:id/trend  analytics.read  instance
POST   /api/v1/admin/analytics/snapshot  system.maintenance  instance
GET    /api/v1/admin/analytics/storage/breakdown  analytics.read  instance
GET    /api/v1/admin/analytics/storage/growth  analytics.read  instance
GET    /api/v1/admin/analytics/storage/trend  analytics.read  instance
GET    /api/v1/admin/audit  audit.read  instance
GET    /api/v1/admin/backups  system.backup.manage  instance
POST   /api/v1/admin/backups  system.backup.manage  instance
DELETE /api/v1/admin/backups/:id  system.backup.manage  instance
GET    /api/v1/admin/backups/:id  system.backup.manage  instance
POST   /api/v1/admin/backups/:id/cancel  system.backup.manage  instance
POST   /api/v1/admin/backups/:id/execute  system.backup.manage  instance
POST   /api/v1/admin/backups/:id/restore  system.backup.manage  instance
GET    /api/v1/admin/banners  system.settings.read  instance
POST   /api/v1/admin/banners  system.settings.update  instance
DELETE /api/v1/admin/banners/:id  system.settings.update  instance
GET    /api/v1/admin/banners/:id  system.settings.read  instance
PUT    /api/v1/admin/banners/:id  system.settings.update  instance
GET    /api/v1/admin/ci-oidc  identity_provider.manage  instance
POST   /api/v1/admin/ci-oidc  identity_provider.manage  instance
DELETE /api/v1/admin/ci-oidc/:id  identity_provider.manage  instance
GET    /api/v1/admin/ci-oidc/:id  identity_provider.manage  instance
PUT    /api/v1/admin/ci-oidc/:id  identity_provider.manage  instance
GET    /api/v1/admin/ci-oidc/:id/mappings  identity_provider.manage  instance
POST   /api/v1/admin/ci-oidc/:id/mappings  identity_provider.manage  instance
DELETE /api/v1/admin/ci-oidc/:id/mappings/:mid  identity_provider.manage  instance
GET    /api/v1/admin/ci-oidc/:id/mappings/:mid  identity_provider.manage  instance
PUT    /api/v1/admin/ci-oidc/:id/mappings/:mid  identity_provider.manage  instance
PATCH  /api/v1/admin/ci-oidc/:id/mappings/:mid/toggle  identity_provider.manage  instance
PATCH  /api/v1/admin/ci-oidc/:id/toggle  identity_provider.manage  instance
POST   /api/v1/admin/cleanup  system.maintenance  instance
GET    /api/v1/admin/config/export  system.settings.read  instance
POST   /api/v1/admin/config/import  system.settings.update  instance
GET    /api/v1/admin/downloads  audit.read  instance
GET    /api/v1/admin/downloads/by-ip/:ip  audit.read  instance
GET    /api/v1/admin/downloads/by-user/:user_id  audit.read  instance
GET    /api/v1/admin/holds/policy-blocks  audit.read  instance
GET    /api/v1/admin/holds/quarantine  audit.read  instance
GET    /api/v1/admin/holds/summary  audit.read  instance
GET    /api/v1/admin/lifecycle  retention.policy.manage  instance
POST   /api/v1/admin/lifecycle  retention.policy.manage  instance
DELETE /api/v1/admin/lifecycle/:id  retention.policy.manage  instance
GET    /api/v1/admin/lifecycle/:id  retention.policy.manage  instance
PATCH  /api/v1/admin/lifecycle/:id  retention.policy.manage  instance
POST   /api/v1/admin/lifecycle/:id/execute  retention.policy.manage  instance
POST   /api/v1/admin/lifecycle/:id/preview  retention.policy.manage  instance
DELETE /api/v1/admin/lifecycle/:id/repositories/:repository_id  retention.policy.manage  instance
PUT    /api/v1/admin/lifecycle/:id/repositories/:repository_id  retention.policy.manage  instance
GET    /api/v1/admin/lifecycle/capabilities  retention.policy.manage  instance
POST   /api/v1/admin/lifecycle/execute-all  retention.policy.manage  instance
GET    /api/v1/admin/mcp/namespace-proofs  system.settings.read  instance
POST   /api/v1/admin/mcp/namespace-proofs  system.settings.update  instance
DELETE /api/v1/admin/mcp/namespace-proofs/:id  system.settings.update  instance
GET    /api/v1/admin/mcp/namespace-proofs/:id  system.settings.read  instance
POST   /api/v1/admin/mcp/namespace-proofs/:id/verify  system.settings.update  instance
GET    /api/v1/admin/metrics  monitoring.read  instance
GET    /api/v1/admin/monitoring/alerts  monitoring.read  instance
POST   /api/v1/admin/monitoring/alerts/suppress  monitoring.manage  instance
POST   /api/v1/admin/monitoring/check  monitoring.manage  instance
GET    /api/v1/admin/monitoring/health-log  monitoring.read  instance
GET    /api/v1/admin/npm/upstream-feed/status  monitoring.read  instance
POST   /api/v1/admin/packages/backfill  system.maintenance  instance
DELETE /api/v1/admin/proxy-scan-verdicts/:digest  system.maintenance  instance
GET    /api/v1/admin/proxy-scan-verdicts/:digest  system.maintenance  instance
GET    /api/v1/admin/quality-checks  monitoring.read  instance
POST   /api/v1/admin/reindex  system.maintenance  instance
POST   /api/v1/admin/repositories/:key/backfill-debian  system.maintenance  instance
POST   /api/v1/admin/repositories/:key/reindex-storage  system.maintenance  instance
POST   /api/v1/admin/rescan-for-inventory  system.maintenance  instance
POST   /api/v1/admin/search/reindex  system.maintenance  instance
GET    /api/v1/admin/security/artifact/:artifact_id/accessible-users  audit.read  instance
GET    /api/v1/admin/security/artifact/:artifact_id/blast-radius  audit.read  instance
GET    /api/v1/admin/security/cve/:cve_id/accessible-users  audit.read  instance
GET    /api/v1/admin/security/cve/:cve_id/blast-radius  audit.read  instance
GET    /api/v1/admin/settings  system.settings.read  instance
POST   /api/v1/admin/settings  system.settings.update  instance
GET    /api/v1/admin/settings/system  system.settings.read  instance
PATCH  /api/v1/admin/settings/system  system.settings.update  instance
GET    /api/v1/admin/settings/token-policy  system.settings.read  instance
PUT    /api/v1/admin/settings/token-policy  system.settings.update  instance
GET    /api/v1/admin/settings/totp-policy  system.settings.read  instance
PUT    /api/v1/admin/settings/totp-policy  system.settings.update  instance
POST   /api/v1/admin/smtp/test  system.settings.update  instance
GET    /api/v1/admin/sso/ldap  identity_provider.manage  instance
POST   /api/v1/admin/sso/ldap  identity_provider.manage  instance
DELETE /api/v1/admin/sso/ldap/:id  identity_provider.manage  instance
GET    /api/v1/admin/sso/ldap/:id  identity_provider.manage  instance
PUT    /api/v1/admin/sso/ldap/:id  identity_provider.manage  instance
POST   /api/v1/admin/sso/ldap/:id/test  identity_provider.manage  instance
PATCH  /api/v1/admin/sso/ldap/:id/toggle  identity_provider.manage  instance
GET    /api/v1/admin/sso/oidc  identity_provider.manage  instance
POST   /api/v1/admin/sso/oidc  identity_provider.manage  instance
DELETE /api/v1/admin/sso/oidc/:id  identity_provider.manage  instance
GET    /api/v1/admin/sso/oidc/:id  identity_provider.manage  instance
PUT    /api/v1/admin/sso/oidc/:id  identity_provider.manage  instance
PATCH  /api/v1/admin/sso/oidc/:id/toggle  identity_provider.manage  instance
POST   /api/v1/admin/sso/oidc/:provider_id/groups  identity_provider.manage  instance
GET    /api/v1/admin/sso/providers  identity_provider.manage  instance
GET    /api/v1/admin/sso/saml  identity_provider.manage  instance
POST   /api/v1/admin/sso/saml  identity_provider.manage  instance
DELETE /api/v1/admin/sso/saml/:id  identity_provider.manage  instance
GET    /api/v1/admin/sso/saml/:id  identity_provider.manage  instance
PUT    /api/v1/admin/sso/saml/:id  identity_provider.manage  instance
PATCH  /api/v1/admin/sso/saml/:id/toggle  identity_provider.manage  instance
GET    /api/v1/admin/stats  monitoring.read  instance
GET    /api/v1/admin/storage-backends  system.settings.read  instance
POST   /api/v1/admin/storage-gc  system.maintenance  instance
GET    /api/v1/admin/storage-gc/oci-blob-report  system.maintenance  instance
POST   /api/v1/admin/storage-scrub  system.maintenance  instance
GET    /api/v1/admin/storage-scrub/findings  system.maintenance  instance
POST   /api/v1/admin/storage/ledger/backfill  system.maintenance  instance
GET    /api/v1/admin/telemetry/crashes  monitoring.read  instance
DELETE /api/v1/admin/telemetry/crashes/:id  monitoring.manage  instance
GET    /api/v1/admin/telemetry/crashes/:id  monitoring.read  instance
GET    /api/v1/admin/telemetry/crashes/pending  monitoring.read  instance
POST   /api/v1/admin/telemetry/crashes/submit  monitoring.manage  instance
GET    /api/v1/admin/telemetry/settings  monitoring.read  instance
POST   /api/v1/admin/telemetry/settings  monitoring.manage  instance
GET    /api/v1/admin/trash  system.maintenance  instance
DELETE /api/v1/admin/trash/:id  system.maintenance  instance
POST   /api/v1/admin/trash/:id/restore  system.maintenance  instance
";

const PREFIXES: [&str; 1] = ["/api/v1/admin"];

/// The one permission an admin operation may name although a non-administrator
/// can hold it on the instance: `owner` bound there (a migrated global `admin`
/// role assignment) reviews age-gated packages in every repository, which is
/// what the instance-wide review queue covers.
const EXEMPT: [Permission; 1] = [Permission::AgeGateReview];

/// Every permission a principal other than an instance administrator can hold
/// on the instance after the upgrade: through a global role assignment, the
/// instance-level sentinel, or a token scope that confers capability.
fn non_administrator_instance_permissions() -> BTreeSet<Permission> {
    let mut held: BTreeSet<Permission> = [
        LegacyAction::Read,
        LegacyAction::Write,
        LegacyAction::Delete,
        LegacyAction::Admin,
    ]
    .into_iter()
    .flat_map(action_permissions)
    .collect();
    held.extend(sentinel_admin_permissions());
    for scope in crate::services::token_service::ALLOWED_SCOPES {
        match scope_grant(scope) {
            Some(ScopeGrant::Compat(perms)) => held.extend(perms),
            Some(ScopeGrant::ReleaseManager) => {
                held.extend(system_role_permissions(SystemRole::ReleaseManager))
            }
            None => {}
        }
    }
    held
}

/// Admin operations among `declared` whose permission a non-administrator can
/// hold on the instance, each naming its route and permission.
fn admin_only_violations<'a>(
    declared: impl Iterator<Item = (&'a RouteKey, &'a RouteRequirement)>,
) -> Vec<String> {
    let held = non_administrator_instance_permissions();
    declared
        .filter(|((_, route), _)| route.starts_with(PREFIXES[0]))
        .filter_map(|((method, route), requirement)| match requirement {
            RouteRequirement::Permission { permission, .. }
                if held.contains(permission) && !EXEMPT.contains(permission) =>
            {
                Some(format!("{method} {route}: {permission}"))
            }
            RouteRequirement::Permission { .. } => None,
            _ => Some(format!("{method} {route}: not an instance permission")),
        })
        .collect()
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::authz::declaration::Resolver;

    #[test]
    fn the_table_matches_the_declarations() {
        let expected = parse(TABLE);
        assert_eq!(expected.len(), 128);
        let diff = differences(&expected, &registry(), &PREFIXES);
        assert!(diff.is_empty(), "{}", diff.join("\n"));
    }

    #[test]
    fn every_table_requirement_is_known() {
        assert_eq!(unknown_requirement(&parse(TABLE)), None);
    }

    #[test]
    fn a_changed_row_is_reported_with_its_route() {
        let mut expected = parse(TABLE);
        let key = ("GET".to_string(), "/api/v1/admin/audit".to_string());
        expected.insert(key, ("monitoring.read".into(), "instance".into()));
        let diff = differences(&expected, &registry(), &PREFIXES);
        assert_eq!(
            diff,
            vec![
                "GET /api/v1/admin/audit: table monitoring.read instance, declared audit.read instance"
                    .to_string()
            ]
        );
    }

    #[test]
    fn admin_operations_name_only_administrator_permissions() {
        let violations = admin_only_violations(registry().declared());
        assert!(violations.is_empty(), "{}", violations.join("\n"));
    }

    #[test]
    fn the_non_administrator_set_comes_from_the_projection() {
        let held = non_administrator_instance_permissions();
        // A global reader, developer or admin role, the sentinel, token grants.
        for p in [
            Permission::SecurityRead,
            Permission::ArtifactWrite,
            Permission::RepositoryDelete,
            Permission::AgeGateReview,
            Permission::RepositoryCreate,
            Permission::GroupCreate,
            Permission::ReplicationTrigger,
            Permission::PromotionApprove,
        ] {
            assert!(held.contains(&p), "{p}");
        }
        for p in [
            Permission::AuditRead,
            Permission::SystemSettingsUpdate,
            Permission::IdentityProviderManage,
            Permission::SystemMaintenance,
        ] {
            assert!(!held.contains(&p), "{p}");
        }
    }

    #[test]
    fn a_declaration_that_opens_an_admin_route_is_reported() {
        let key: RouteKey = (
            "GET".to_string(),
            "/api/v1/admin/security/cve/:cve_id/blast-radius".to_string(),
        );
        let requirement = RouteRequirement::Permission {
            permission: Permission::SecurityRead,
            resolver: Resolver::lookup("instance").unwrap(),
        };
        assert_eq!(
            admin_only_violations(std::iter::once((&key, &requirement))),
            vec!["GET /api/v1/admin/security/cve/:cve_id/blast-radius: security.read".to_string()]
        );
    }
}
