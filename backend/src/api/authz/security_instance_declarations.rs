//! The authorization of every security operation decided on the instance
//! (cross-repository security reads, security, license and quality-gate
//! policies, Dependency-Track and the attestation policy), as a table checked
//! against the declarations in the OpenAPI document.
//!
//! `/security`, `/sbom` and `/quality` also hold operations on one
//! repository's objects, which another table covers, so under those prefixes
//! only the routes in [`SHARED_PREFIX_ROUTES`] belong to this table.

/// Rows in the format of [`super::declaration_table::parse`].
const TABLE: &str = "
GET    /api/v1/attestations/policy  authenticated  -
GET    /api/v1/dependency-track/metrics/portfolio  security.read  instance
PUT    /api/v1/dependency-track/analysis  security.triage  instance
GET    /api/v1/dependency-track/policies  security.read  instance
GET    /api/v1/dependency-track/projects  security.read  instance
GET    /api/v1/dependency-track/projects/:project_uuid  security.read  instance
GET    /api/v1/dependency-track/projects/:project_uuid/components  security.read  instance
GET    /api/v1/dependency-track/projects/:project_uuid/findings  security.read  instance
GET    /api/v1/dependency-track/projects/:project_uuid/metrics  security.read  instance
GET    /api/v1/dependency-track/projects/:project_uuid/metrics/history  security.read  instance
GET    /api/v1/dependency-track/projects/:project_uuid/violations  security.read  instance
GET    /api/v1/dependency-track/status  security.read  instance
GET    /api/v1/quality/gates  authenticated  -
POST   /api/v1/quality/gates  security.policy.manage  instance
DELETE /api/v1/quality/gates/:id  security.policy.manage  instance
GET    /api/v1/quality/gates/:id  authenticated  -
PUT    /api/v1/quality/gates/:id  security.policy.manage  instance
GET    /api/v1/quality/health/dashboard  monitoring.read  instance
GET    /api/v1/sbom/cve/history/by-cve/:cve_id  security.read  instance
GET    /api/v1/sbom/cve/trends  security.read  instance
POST   /api/v1/sbom/environment  authenticated  -
GET    /api/v1/sbom/license-policies  authenticated  -
POST   /api/v1/sbom/license-policies  security.policy.manage  instance
DELETE /api/v1/sbom/license-policies/:id  security.policy.manage  instance
GET    /api/v1/sbom/license-policies/:id  authenticated  -
GET    /api/v1/security/acknowledgements  security.read  instance
GET    /api/v1/security/configs  security.read  instance
GET    /api/v1/security/dashboard  security.read  instance
GET    /api/v1/security/policies  authenticated  -
POST   /api/v1/security/policies  security.policy.manage  instance
DELETE /api/v1/security/policies/:id  security.policy.manage  instance
GET    /api/v1/security/policies/:id  authenticated  -
PUT    /api/v1/security/policies/:id  security.policy.manage  instance
GET    /api/v1/security/proxy-blocked  security.read  instance
GET    /api/v1/security/scores  security.read  instance
";

/// Prefixes whose every operation belongs to this table.
const PREFIXES: [&str; 2] = ["/api/v1/dependency-track", "/api/v1/attestations"];

/// The routes of this table under `/security`, `/sbom` and `/quality`, every
/// method included.
const SHARED_PREFIX_ROUTES: [&str; 15] = [
    "/api/v1/quality/gates",
    "/api/v1/quality/gates/:id",
    "/api/v1/quality/health/dashboard",
    "/api/v1/sbom/cve/history/by-cve/:cve_id",
    "/api/v1/sbom/cve/trends",
    "/api/v1/sbom/environment",
    "/api/v1/sbom/license-policies",
    "/api/v1/sbom/license-policies/:id",
    "/api/v1/security/acknowledgements",
    "/api/v1/security/configs",
    "/api/v1/security/dashboard",
    "/api/v1/security/policies",
    "/api/v1/security/policies/:id",
    "/api/v1/security/proxy-blocked",
    "/api/v1/security/scores",
];

/// Whether a canonical route belongs to this table.
fn in_area(route: &str) -> bool {
    SHARED_PREFIX_ROUTES.contains(&route)
        || PREFIXES
            .iter()
            .any(|p| route == *p || route.strip_prefix(p).is_some_and(|r| r.starts_with('/')))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::authz::declaration_table::{
        differences_within, parse, registry, unknown_requirement,
    };

    #[test]
    fn the_table_matches_the_declarations() {
        let expected = parse(TABLE);
        assert_eq!(expected.len(), 35);
        let diff = differences_within(&expected, &registry(), in_area);
        assert!(diff.is_empty(), "{}", diff.join("\n"));
    }

    #[test]
    fn every_table_requirement_is_known() {
        assert_eq!(unknown_requirement(&parse(TABLE)), None);
    }

    #[test]
    fn every_table_route_is_in_the_area() {
        let outside: Vec<_> = parse(TABLE)
            .into_keys()
            .filter(|(_, route)| !in_area(route))
            .collect();
        assert!(outside.is_empty(), "{outside:?}");
    }

    #[test]
    fn the_shared_prefixes_leave_object_operations_to_another_table() {
        assert!(!in_area("/api/v1/security/scans/:id"));
        assert!(!in_area("/api/v1/security/acknowledgements/:id"));
        assert!(!in_area("/api/v1/sbom/:id"));
        assert!(!in_area("/api/v1/quality/checks"));
        assert!(in_area("/api/v1/dependency-track/projects/:project_uuid"));
    }

    #[test]
    fn a_changed_row_is_reported_with_its_route() {
        let mut expected = parse(TABLE);
        let key = ("GET".to_string(), "/api/v1/security/configs".to_string());
        expected.insert(key, ("authenticated".into(), "-".into()));
        let diff = differences_within(&expected, &registry(), in_area);
        assert_eq!(
            diff,
            vec![
                "GET /api/v1/security/configs: table authenticated -, declared security.read instance"
                    .to_string()
            ]
        );
    }
}
