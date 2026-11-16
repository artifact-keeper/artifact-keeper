//! The authorization of every promotion, curation, approval and build
//! operation, as a table checked against the declarations in the OpenAPI
//! document.
//!
//! Listing curation rules and promotion rules is `authenticated`: each handler
//! answers one repository's rules to its readers and every rule to
//! administrators. Builds are `authenticated` until a build belongs to a
//! project; the handler keeps its creator check.

/// Rows in the format of [`super::declaration_table::parse`].
const TABLE: &str = "
GET    /api/v1/approval/:id  repository.read  approval:id
POST   /api/v1/approval/:id/approve  promotion.approve  approval:id
POST   /api/v1/approval/:id/reject  promotion.approve  approval:id
GET    /api/v1/approval/history  promotion.approve  instance
GET    /api/v1/approval/pending  promotion.approve  instance
POST   /api/v1/approval/request  artifact.read  repository:body
GET    /api/v1/builds  authenticated  -
POST   /api/v1/builds  authenticated  -
GET    /api/v1/builds/:id  authenticated  -
PUT    /api/v1/builds/:id  authenticated  -
POST   /api/v1/builds/:id/artifacts  authenticated  -
GET    /api/v1/builds/diff  authenticated  -
GET    /api/v1/curation/packages  artifact.read  repository:body
GET    /api/v1/curation/packages/:id  artifact.read  curation_package:id
POST   /api/v1/curation/packages/:id/approve  curation.review  curation_package:id
POST   /api/v1/curation/packages/:id/block  curation.review  curation_package:id
POST   /api/v1/curation/packages/bulk-approve  curation.review  repository:body
POST   /api/v1/curation/packages/bulk-block  curation.review  repository:body
POST   /api/v1/curation/packages/re-evaluate  curation.review  repository:body
GET    /api/v1/curation/repos/:repo_key/packages/search  artifact.read  repo:repo_key
POST   /api/v1/curation/repos/:repo_key/sync  curation.publish  repo:repo_key
POST   /api/v1/curation/repos/:repo_key/versions  curation.publish  repo:repo_key
POST   /api/v1/curation/repos/:repo_key/versions/:n/publish  curation.publish  repo:repo_key
GET    /api/v1/curation/rules  authenticated  -
POST   /api/v1/curation/rules  curation.review  repository:body
DELETE /api/v1/curation/rules/:id  curation.review  curation_rule:id
GET    /api/v1/curation/rules/:id  repository.read  curation_rule:id
PUT    /api/v1/curation/rules/:id  curation.review  curation_rule:id
GET    /api/v1/curation/stats  artifact.read  repository:body
GET    /api/v1/promotion-rules  authenticated  -
POST   /api/v1/promotion-rules  promotion.rule.manage  instance
DELETE /api/v1/promotion-rules/:id  promotion.rule.manage  instance
GET    /api/v1/promotion-rules/:id  repository.read  promotion_rule:id
PUT    /api/v1/promotion-rules/:id  promotion.rule.manage  instance
POST   /api/v1/promotion-rules/:id/evaluate  repository.read  promotion_rule:id
POST   /api/v1/promotion/repositories/:key/artifacts/:artifact_id/promote  promotion.create  repo:key
POST   /api/v1/promotion/repositories/:key/artifacts/:artifact_id/reject  promotion.reject  repo:key
POST   /api/v1/promotion/repositories/:key/promote  promotion.create  repo:key
GET    /api/v1/promotion/repositories/:key/promotion-history  repository.read  repo:key
GET    /api/v1/promotion/repositories/:key/release-target  repository.read  repo:key
PUT    /api/v1/promotion/repositories/:key/release-target  repository.update  repo:key
";

/// Prefixes whose every operation belongs to this table.
const PREFIXES: [&str; 5] = [
    "/api/v1/curation",
    "/api/v1/promotion",
    "/api/v1/promotion-rules",
    "/api/v1/approval",
    "/api/v1/builds",
];

/// Whether a canonical route belongs to this table.
fn in_area(route: &str) -> bool {
    PREFIXES
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
        assert_eq!(expected.len(), 41);
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
        assert!(!in_area("/api/v1/admin/builds"));
        assert!(!in_area("/api/v1/curation-other"));
    }

    #[test]
    fn a_changed_row_is_reported_with_its_route() {
        let mut expected = parse(TABLE);
        let key = (
            "POST".to_string(),
            "/api/v1/approval/:id/approve".to_string(),
        );
        expected.insert(key, ("promotion.create".into(), "approval:id".into()));
        let diff = differences_within(&expected, &registry(), in_area);
        assert_eq!(
            diff,
            vec![
                "POST /api/v1/approval/:id/approve: table promotion.create approval:id, declared promotion.approve approval:id"
                    .to_string()
            ]
        );
    }
}
