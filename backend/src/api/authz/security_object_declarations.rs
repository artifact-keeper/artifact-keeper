//! The authorization of every security operation on one repository's
//! objects (scans and findings, SBOMs and CVE history, quality checks and
//! issues, quarantine, signing), as a table checked against the declarations
//! in the OpenAPI document.
//!
//! Under `/security`, `/sbom` and `/quality` this table holds every route the
//! instance-level table does not; `/quarantine` and `/signing` are its own.

use super::security_instance_declarations;

/// Rows in the format of [`super::declaration_table::parse`].
const TABLE: &str = "
GET    /api/v1/quality/checks  authenticated  -
GET    /api/v1/quality/checks/:id  security.read  quality_check:id
GET    /api/v1/quality/checks/:id/issues  security.read  quality_check:id
POST   /api/v1/quality/checks/trigger  security.scan  repository:body
POST   /api/v1/quality/gates/evaluate/:artifact_id  security.scan  artifact:artifact_id
GET    /api/v1/quality/health/artifacts/:artifact_id  security.read  artifact:artifact_id
GET    /api/v1/quality/health/repositories/:key  security.read  repo:key
DELETE /api/v1/quality/issues/:id/suppress  security.triage  quality_issue:id
POST   /api/v1/quality/issues/:id/suppress  security.triage  quality_issue:id
GET    /api/v1/quarantine/:artifact_id  security.read  artifact:artifact_id
POST   /api/v1/quarantine/:artifact_id/quarantine  security.quarantine  artifact:artifact_id
POST   /api/v1/quarantine/:artifact_id/reject  security.quarantine  artifact:artifact_id
POST   /api/v1/quarantine/:artifact_id/release  security.quarantine  artifact:artifact_id
POST   /api/v1/quarantine/proxy-cache/:repo_key/release  security.quarantine  repo:repo_key
GET    /api/v1/sbom  authenticated  -
POST   /api/v1/sbom  security.scan  repository:body
DELETE /api/v1/sbom/:id  artifact.delete  sbom:id
GET    /api/v1/sbom/:id  security.read  sbom:id
GET    /api/v1/sbom/:id/components  security.read  sbom:id
POST   /api/v1/sbom/:id/convert  security.scan  sbom:id
GET    /api/v1/sbom/by-artifact/:artifact_id  security.read  artifact:artifact_id
POST   /api/v1/sbom/check-compliance  authenticated  -
GET    /api/v1/sbom/cve/history/:id  security.read  cve_subject:id
GET    /api/v1/sbom/cve/history/by-artifact/:artifact_id  security.read  artifact:artifact_id
POST   /api/v1/sbom/cve/status/:id  security.triage  cve_entry:id
POST   /api/v1/sbom/cve/status/by-artifact/:artifact_id/by-cve/:cve_id  security.triage  artifact:artifact_id
DELETE /api/v1/security/acknowledgements/:id  security.triage  acknowledgement:id
GET    /api/v1/security/artifacts/:artifact_id/scans  security.read  artifact:artifact_id
DELETE /api/v1/security/findings/:id/acknowledge  security.triage  finding:id
POST   /api/v1/security/findings/:id/acknowledge  security.triage  finding:id
POST   /api/v1/security/findings/external  security.findings.ingest  repository:body
POST   /api/v1/security/scan  security.scan  repository:body
GET    /api/v1/security/scans  authenticated  -
GET    /api/v1/security/scans/:id  security.read  scan:id
GET    /api/v1/security/scans/:id/findings  security.read  scan:id
POST   /api/v1/signing/artifacts/:artifact_id/sign  artifact.sign  artifact:artifact_id
GET    /api/v1/signing/keys  signing.key.manage  instance
POST   /api/v1/signing/keys  signing.key.manage  instance
DELETE /api/v1/signing/keys/:key_id  signing.key.manage  instance
GET    /api/v1/signing/keys/:key_id  signing.key.manage  instance
GET    /api/v1/signing/keys/:key_id/public  signing.key.manage  instance
POST   /api/v1/signing/keys/:key_id/revoke  signing.key.manage  instance
POST   /api/v1/signing/keys/:key_id/rotate  signing.key.manage  instance
GET    /api/v1/signing/keys/:key_id/trust-attestation  signing.key.manage  instance
GET    /api/v1/signing/keys/:key_id/trust-attestation/challenge  signing.key.manage  instance
POST   /api/v1/signing/keys/:key_id/trust-attestation/verify  signing.key.manage  instance
GET    /api/v1/signing/repositories/:repo_id/config  repository.read  repository:repo_id
POST   /api/v1/signing/repositories/:repo_id/config  repository.update  repository:repo_id
GET    /api/v1/signing/repositories/:repo_id/public-key  artifact.read  repository:repo_id
";

/// Prefixes whose every operation belongs to this table.
const PREFIXES: [&str; 2] = ["/api/v1/quarantine", "/api/v1/signing"];

/// Prefixes shared with the instance-level table.
const SHARED_PREFIXES: [&str; 3] = ["/api/v1/security", "/api/v1/sbom", "/api/v1/quality"];

fn under(route: &str, prefix: &str) -> bool {
    route == prefix
        || route
            .strip_prefix(prefix)
            .is_some_and(|r| r.starts_with('/'))
}

/// Whether a canonical route belongs to this table.
fn in_area(route: &str) -> bool {
    PREFIXES.iter().any(|p| under(route, p))
        || (SHARED_PREFIXES.iter().any(|p| under(route, p))
            && !security_instance_declarations::in_area(route))
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
        assert_eq!(expected.len(), 49);
        let diff = differences_within(&expected, &registry(), in_area);
        assert!(diff.is_empty(), "{}", diff.join("\n"));
    }

    #[test]
    fn every_table_requirement_is_known() {
        assert_eq!(unknown_requirement(&parse(TABLE)), None);
    }

    #[test]
    fn the_two_security_tables_do_not_overlap() {
        let overlap: Vec<_> = parse(TABLE)
            .into_keys()
            .filter(|(_, route)| !in_area(route) || security_instance_declarations::in_area(route))
            .collect();
        assert!(overlap.is_empty(), "{overlap:?}");
        assert!(!in_area("/api/v1/security/configs"));
        assert!(!in_area("/api/v1/dependency-track/status"));
        assert!(in_area("/api/v1/security/acknowledgements/:id"));
        assert!(in_area("/api/v1/sbom"));
    }

    #[test]
    fn a_changed_row_is_reported_with_its_route() {
        let mut expected = parse(TABLE);
        let key = ("GET".to_string(), "/api/v1/signing/keys".to_string());
        expected.insert(key, ("authenticated".into(), "-".into()));
        let diff = differences_within(&expected, &registry(), in_area);
        assert_eq!(
            diff,
            vec![
                "GET /api/v1/signing/keys: table authenticated -, declared signing.key.manage instance"
                    .to_string()
            ]
        );
    }
}
