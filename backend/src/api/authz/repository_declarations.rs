//! The authorization of every `/api/v1/repositories` and `/api/v1/artifacts`
//! operation, as a table checked against the declarations in the OpenAPI
//! document. A changed declaration fails here with the operation named, so
//! the change is deliberate.

use super::declaration_table::{differences, parse, registry, unknown_requirement};

/// Rows in the format of [`parse`].
const TABLE: &str = "
GET    /api/v1/artifacts/:id  artifact.read  artifact:id
GET    /api/v1/artifacts/:id/labels  artifact.read  artifact:id
PUT    /api/v1/artifacts/:id/labels  artifact.annotate  artifact:id
DELETE /api/v1/artifacts/:id/labels/:label_key  artifact.annotate  artifact:id
POST   /api/v1/artifacts/:id/labels/:label_key  artifact.annotate  artifact:id
GET    /api/v1/artifacts/:id/metadata  artifact.read  artifact:id
GET    /api/v1/artifacts/:id/package-analysis  artifact.read  artifact:id
GET    /api/v1/artifacts/:id/stats  artifact.read  artifact:id
GET    /api/v1/repositories  public  -
POST   /api/v1/repositories  repository.create  project:body
DELETE /api/v1/repositories/:key  repository.delete  repo:key
GET    /api/v1/repositories/:key  repository.read  repo:key
PATCH  /api/v1/repositories/:key  repository.update  repo:key
GET    /api/v1/repositories/:key/age-gate  repository.update  repo:key
PUT    /api/v1/repositories/:key/age-gate  repository.update  repo:key
GET    /api/v1/repositories/:key/age-gate/reviews  age_gate.review  repo:key
GET    /api/v1/repositories/:key/age-gate/reviews/:id  age_gate.review  repo:key
POST   /api/v1/repositories/:key/age-gate/reviews/:id/:decision  age_gate.review  repo:key
DELETE /api/v1/repositories/:key/allowlist  repository.update  repo:key
GET    /api/v1/repositories/:key/allowlist  repository.update  repo:key
PUT    /api/v1/repositories/:key/allowlist  repository.update  repo:key
GET    /api/v1/repositories/:key/artifacts  repository.read  repo:key
POST   /api/v1/repositories/:key/artifacts  artifact.write  repo:key
POST   /api/v1/repositories/:key/artifacts-missing  artifact.read  repo:key
DELETE /api/v1/repositories/:key/artifacts/*path  artifact.delete  repo:key
GET    /api/v1/repositories/:key/artifacts/*path  artifact.read  repo:key
POST   /api/v1/repositories/:key/artifacts/*path  artifact.write  repo:key
PUT    /api/v1/repositories/:key/artifacts/*path  artifact.write  repo:key
GET    /api/v1/repositories/:key/cache-ttl  repository.read  repo:key
PUT    /api/v1/repositories/:key/cache-ttl  repository.update  repo:key
POST   /api/v1/repositories/:key/cache/invalidate  repository.maintenance  repo:key
POST   /api/v1/repositories/:key/cache/seed  repository.maintenance  repo:key
GET    /api/v1/repositories/:key/cache/seed/:job_id  repository.maintenance  repo:key
GET    /api/v1/repositories/:key/download/*path  artifact.read  repo:key
GET    /api/v1/repositories/:key/egress-proxy  repository.update  repo:key
PUT    /api/v1/repositories/:key/egress-proxy  repository.credentials.update  repo:key
GET    /api/v1/repositories/:key/email-subscriptions  repository.notifications.manage  repo:key
POST   /api/v1/repositories/:key/email-subscriptions  repository.notifications.manage  repo:key
DELETE /api/v1/repositories/:key/email-subscriptions/:subscription_id  repository.notifications.manage  repo:key
GET    /api/v1/repositories/:key/environments  environment.read  repo:key
POST   /api/v1/repositories/:key/environments  environment.write  repo:key
DELETE /api/v1/repositories/:key/environments/:id  environment.write  repo:key
GET    /api/v1/repositories/:key/environments/:id  environment.read  repo:key
GET    /api/v1/repositories/:key/environments/:id/advisories  environment.read  repo:key
GET    /api/v1/repositories/:key/image-builds  repository.read  repo:key
POST   /api/v1/repositories/:key/image-builds  image_build.create  repo:key
GET    /api/v1/repositories/:key/image-builds/:id  repository.read  repo:key
GET    /api/v1/repositories/:key/image-builds/:id/log  repository.read  repo:key
GET    /api/v1/repositories/:key/image-builds/base-info  repository.read  repo:key
POST   /api/v1/repositories/:key/image-builds/render  image_build.create  repo:key
GET    /api/v1/repositories/:key/image-builds/settings  repository.read  repo:key
GET    /api/v1/repositories/:key/image-inspect  artifact.read  repo:key
GET    /api/v1/repositories/:key/labels  repository.read  repo:key
PUT    /api/v1/repositories/:key/labels  repository.label.manage  repo:key
DELETE /api/v1/repositories/:key/labels/:label_key  repository.label.manage  repo:key
POST   /api/v1/repositories/:key/labels/:label_key  repository.label.manage  repo:key
GET    /api/v1/repositories/:key/mcp/catalog  repository.read  repo:key
POST   /api/v1/repositories/:key/mcp/catalog/:id/:decision  curation.review  repo:key
POST   /api/v1/repositories/:key/mcp/catalog/:id/request-approval  repository.read  repo:key
POST   /api/v1/repositories/:key/mcp/catalog/bulk-approve  curation.review  repo:key
POST   /api/v1/repositories/:key/mcp/catalog/bulk-block  curation.review  repo:key
POST   /api/v1/repositories/:key/mcp/catalog/bulk-decide  curation.review  repo:key
POST   /api/v1/repositories/:key/mcp/catalog/pins  curation.review  repo:key
GET    /api/v1/repositories/:key/mcp/catalog/servers/:ns  repository.read  repo:key
GET    /api/v1/repositories/:key/mcp/catalog/servers/:ns/:name  repository.read  repo:key
POST   /api/v1/repositories/:key/mcp/seed  repository.maintenance  repo:key
GET    /api/v1/repositories/:key/mcp/seed/:job_id  repository.read  repo:key
GET    /api/v1/repositories/:key/mcp/servers/:name/versions/:version/health  repository.read  repo:key
GET    /api/v1/repositories/:key/mcp/servers/:ns/:name/versions/:version/health  repository.read  repo:key
GET    /api/v1/repositories/:key/mcp/sync  repository.read  repo:key
POST   /api/v1/repositories/:key/mcp/sync  repository.maintenance  repo:key
GET    /api/v1/repositories/:key/members  repository.read  repo:key
POST   /api/v1/repositories/:key/members  repository.update  repo:key
PUT    /api/v1/repositories/:key/members  repository.update  repo:key
DELETE /api/v1/repositories/:key/members/:member_key  repository.update  repo:key
GET    /api/v1/repositories/:key/npm-scope-policy  repository.update  repo:key
PUT    /api/v1/repositories/:key/npm-scope-policy  repository.update  repo:key
PUT    /api/v1/repositories/:key/oci/blobs/:digest  artifact.write  repo:key
PUT    /api/v1/repositories/:key/oci/manifests/:digest  artifact.write  repo:key
GET    /api/v1/repositories/:key/on-upstream-not-found  repository.read  repo:key
PUT    /api/v1/repositories/:key/on-upstream-not-found  repository.update  repo:key
DELETE /api/v1/repositories/:key/proxy-cache-cap  repository.update  repo:key
GET    /api/v1/repositories/:key/proxy-cache-cap  repository.update  repo:key
PUT    /api/v1/repositories/:key/proxy-cache-cap  repository.update  repo:key
GET    /api/v1/repositories/:key/pypi-tracks  repository.read  repo:key
DELETE /api/v1/repositories/:key/pypi-tracks/:project  repository.update  repo:key
PUT    /api/v1/repositories/:key/pypi-tracks/:project  repository.update  repo:key
DELETE /api/v1/repositories/:key/routing-rules  repository.update  repo:key
GET    /api/v1/repositories/:key/routing-rules  repository.read  repo:key
POST   /api/v1/repositories/:key/routing-rules  repository.update  repo:key
POST   /api/v1/repositories/:key/rpm/repodata/rebuild  repository.maintenance  repo:key
GET    /api/v1/repositories/:key/security  security.read  repo:key
PUT    /api/v1/repositories/:key/security  repository.update  repo:key
GET    /api/v1/repositories/:key/security/proxy-sbom  security.read  repo:key
GET    /api/v1/repositories/:key/security/proxy-scans  security.read  repo:key
POST   /api/v1/repositories/:key/security/proxy-scans/rescan  security.scan  repo:key
GET    /api/v1/repositories/:key/security/scans  security.read  repo:key
GET    /api/v1/repositories/:key/stale-if-error-grace  repository.read  repo:key
PUT    /api/v1/repositories/:key/stale-if-error-grace  repository.update  repo:key
GET    /api/v1/repositories/:key/storage  repository.read  repo:key
POST   /api/v1/repositories/:key/storage-gc  system.maintenance  instance
GET    /api/v1/repositories/:key/storage/tree  repository.read  repo:key
POST   /api/v1/repositories/:key/test-upstream  repository.credentials.update  repo:key
GET    /api/v1/repositories/:key/tokens  repository.token.manage  repo:key
POST   /api/v1/repositories/:key/tokens  repository.token.manage  repo:key
DELETE /api/v1/repositories/:key/tokens/:token_id  repository.token.manage  repo:key
GET    /api/v1/repositories/:key/tokens/:token_id  repository.token.manage  repo:key
PUT    /api/v1/repositories/:key/upstream-auth  repository.credentials.update  repo:key
DELETE /api/v1/repositories/:key/upstream-filter  repository.update  repo:key
GET    /api/v1/repositories/:key/upstream-filter  repository.update  repo:key
PUT    /api/v1/repositories/:key/upstream-filter  repository.update  repo:key
GET    /api/v1/repositories/:key/upstream-mode  repository.read  repo:key
PUT    /api/v1/repositories/:key/upstream-mode  repository.update  repo:key
GET    /api/v1/repositories/:key/versions/*path  artifact.read  repo:key
GET    /api/v1/repositories/_/capabilities  public  -
";

const PREFIXES: [&str; 2] = ["/api/v1/repositories", "/api/v1/artifacts"];

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_matches_the_declarations() {
        let expected = parse(TABLE);
        assert_eq!(expected.len(), 115);
        let diff = differences(&expected, &registry(), &PREFIXES);
        assert!(diff.is_empty(), "{}", diff.join("\n"));
    }

    #[test]
    fn every_table_requirement_is_known() {
        assert_eq!(unknown_requirement(&parse(TABLE)), None);
    }

    #[test]
    fn a_changed_row_is_reported_with_its_route() {
        let registry = registry();
        let mut expected = parse(TABLE);
        let key = (
            "PUT".to_string(),
            "/api/v1/repositories/:key/cache-ttl".to_string(),
        );
        expected.insert(key, ("repository.read".into(), "repo:key".into()));
        let missing = (
            "GET".to_string(),
            "/api/v1/repositories/:key/storage".to_string(),
        );
        expected.remove(&missing);
        let diff = differences(&expected, &registry, &PREFIXES);
        assert_eq!(diff.len(), 2, "{diff:?}");
        assert!(diff.iter().any(
            |d| d.starts_with("PUT /api/v1/repositories/:key/cache-ttl: table repository.read")
        ));
        assert!(diff
            .iter()
            .any(|d| d == "GET /api/v1/repositories/:key/storage: declared, not in the table"));
    }
}
