//! The authorization of every sign-in, self-service, user-administration,
//! service-account and access-API operation under `/api/v1`, as a table checked
//! against the declarations in the OpenAPI document, and the rule that keeps
//! identity administration administrator-only.

use super::admin_declarations::non_administrator_instance_permissions;
use super::declaration::RouteRequirement;
use super::registry::RouteKey;

/// Rows in the format of [`super::declaration_table::parse`].
const TABLE: &str = "
POST   /api/v1/auth/ci/token  public  -
POST   /api/v1/auth/device/approve  authenticated  -
POST   /api/v1/auth/device/code  public  -
POST   /api/v1/auth/device/deny  authenticated  -
POST   /api/v1/auth/device/token  public  -
POST   /api/v1/auth/device/verify  authenticated  -
POST   /api/v1/auth/login  public  -
POST   /api/v1/auth/logout  public  -
GET    /api/v1/auth/me  authenticated  -
POST   /api/v1/auth/refresh  public  -
POST   /api/v1/auth/sso/exchange  public  -
POST   /api/v1/auth/sso/ldap/:id/login  public  -
GET    /api/v1/auth/sso/oidc/:id/callback  public  -
GET    /api/v1/auth/sso/oidc/:id/login  public  -
GET    /api/v1/auth/sso/oidc/callback  public  -
GET    /api/v1/auth/sso/providers  public  -
POST   /api/v1/auth/sso/saml/:id/acs  public  -
GET    /api/v1/auth/sso/saml/:id/login  public  -
POST   /api/v1/auth/ticket  authenticated  -
POST   /api/v1/auth/tokens  authenticated  -
DELETE /api/v1/auth/tokens/:token_id  authenticated  -
POST   /api/v1/auth/totp/disable  authenticated  -
POST   /api/v1/auth/totp/enable  authenticated  -
POST   /api/v1/auth/totp/enroll/complete  public  -
POST   /api/v1/auth/totp/enroll/setup  public  -
POST   /api/v1/auth/totp/setup  authenticated  -
POST   /api/v1/auth/totp/verify  public  -
GET    /api/v1/permissions  iam.manage  instance
POST   /api/v1/permissions  iam.manage  instance
DELETE /api/v1/permissions/:id  iam.manage  instance
GET    /api/v1/permissions/:id  iam.manage  instance
PUT    /api/v1/permissions/:id  iam.manage  instance
GET    /api/v1/profile/access-tokens  authenticated  -
POST   /api/v1/profile/access-tokens  authenticated  -
DELETE /api/v1/profile/access-tokens/:token_id  authenticated  -
GET    /api/v1/service-accounts  service_account.manage  instance
POST   /api/v1/service-accounts  service_account.manage  instance
DELETE /api/v1/service-accounts/:id  service_account.manage  instance
GET    /api/v1/service-accounts/:id  service_account.manage  instance
PATCH  /api/v1/service-accounts/:id  service_account.manage  instance
GET    /api/v1/service-accounts/:id/tokens  service_account.manage  instance
POST   /api/v1/service-accounts/:id/tokens  service_account.token.create  instance
DELETE /api/v1/service-accounts/:id/tokens/:token_id  service_account.manage  instance
GET    /api/v1/service-accounts/:id/tokens/:token_id/scope-analysis  service_account.manage  instance
POST   /api/v1/service-accounts/repo-selector/preview  service_account.manage  instance
GET    /api/v1/users  user.read  instance
POST   /api/v1/users  user.manage  instance
DELETE /api/v1/users/:id  user.manage  instance
GET    /api/v1/users/:id  user.read  user:id
PATCH  /api/v1/users/:id  user.manage  instance
POST   /api/v1/users/:id/force-password-change  user.credentials.manage  instance
POST   /api/v1/users/:id/password  user.credentials.manage  user:id
POST   /api/v1/users/:id/password/reset  user.credentials.manage  instance
GET    /api/v1/users/:id/roles  iam.manage  instance
POST   /api/v1/users/:id/roles  iam.manage  instance
DELETE /api/v1/users/:id/roles/:role_id  iam.manage  instance
GET    /api/v1/users/:id/tokens  user.credentials.manage  user:id
POST   /api/v1/users/:id/tokens  user.credentials.manage  user:id
DELETE /api/v1/users/:id/tokens/:token_id  user.credentials.manage  user:id
GET    /api/v1/users/me  authenticated  -
POST   /api/v1/users/me/password  authenticated  -
GET    /api/v1/users/me/tokens  authenticated  -
POST   /api/v1/users/me/tokens  authenticated  -
DELETE /api/v1/users/me/tokens/:token_id  authenticated  -
";

const PREFIXES: [&str; 5] = [
    "/api/v1/auth",
    "/api/v1/users",
    "/api/v1/profile",
    "/api/v1/permissions",
    "/api/v1/service-accounts",
];

fn in_area(route: &str) -> bool {
    PREFIXES
        .iter()
        .any(|p| route == *p || route.strip_prefix(p).is_some_and(|r| r.starts_with('/')))
}

/// Permission-declared operations in the area whose permission a
/// non-administrator can hold on the instance, each naming its route.
fn admin_only_violations<'a>(
    declared: impl Iterator<Item = (&'a RouteKey, &'a RouteRequirement)>,
) -> Vec<String> {
    let held = non_administrator_instance_permissions();
    declared
        .filter(|((_, route), _)| in_area(route))
        .filter_map(|((method, route), requirement)| match requirement {
            RouteRequirement::Permission { permission, .. } if held.contains(permission) => {
                Some(format!("{method} {route}: {permission}"))
            }
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::authz::catalog::Permission;
    use crate::api::authz::declaration::Resolver;
    use crate::api::authz::declaration_table::{differences, parse, registry, unknown_requirement};

    #[test]
    fn the_table_matches_the_declarations() {
        let expected = parse(TABLE);
        assert_eq!(expected.len(), 64);
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
        let key = ("POST".to_string(), "/api/v1/auth/tokens".to_string());
        expected.insert(key, ("public".into(), "-".into()));
        let diff = differences(&expected, &registry(), &PREFIXES);
        assert_eq!(
            diff,
            vec!["POST /api/v1/auth/tokens: table public -, declared authenticated -".to_string()]
        );
    }

    #[test]
    fn identity_administration_names_only_administrator_permissions() {
        let violations = admin_only_violations(registry().declared());
        assert!(violations.is_empty(), "{}", violations.join("\n"));
    }

    #[test]
    fn a_declaration_that_opens_identity_administration_is_reported() {
        let key: RouteKey = ("GET".to_string(), "/api/v1/users".to_string());
        let requirement = RouteRequirement::Permission {
            permission: Permission::SecurityRead,
            resolver: Resolver::lookup("instance").unwrap(),
        };
        assert_eq!(
            admin_only_violations(std::iter::once((&key, &requirement))),
            vec!["GET /api/v1/users: security.read".to_string()]
        );
        // Outside the area, the same declaration is another table's business.
        let other: RouteKey = ("GET".to_string(), "/api/v1/usersx".to_string());
        assert!(admin_only_violations(std::iter::once((&other, &requirement))).is_empty());
    }
}
