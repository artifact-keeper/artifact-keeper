//! The authorization of every `/api/v1/projects` and `/api/v1/groups`
//! operation, as a table checked against the declarations in the OpenAPI
//! document. A changed declaration fails here with the operation named, so
//! the change is deliberate.

use super::declaration_table::{differences, parse, registry, unknown_requirement};

/// Rows in the format of [`parse`].
const TABLE: &str = "
GET    /api/v1/projects  project.read  instance
POST   /api/v1/projects  project.create  instance
DELETE /api/v1/projects/:id  project.delete  project:id
GET    /api/v1/projects/:id  project.read  project:id
PUT    /api/v1/projects/:id  project.update  project:id
DELETE /api/v1/projects/:id/members  iam.manage  project:id
GET    /api/v1/projects/:id/members  iam.manage  project:id
POST   /api/v1/projects/:id/members  iam.manage  project:id
GET    /api/v1/groups  authenticated  -
POST   /api/v1/groups  group.create  instance
DELETE /api/v1/groups/:id  group.manage  group:id
GET    /api/v1/groups/:id  authenticated  -
PUT    /api/v1/groups/:id  group.manage  group:id
DELETE /api/v1/groups/:id/members  group.manage  group:id
GET    /api/v1/groups/:id/members  authenticated  -
POST   /api/v1/groups/:id/members  group.manage  group:id
";

const PREFIXES: [&str; 2] = ["/api/v1/projects", "/api/v1/groups"];

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_matches_the_declarations() {
        let expected = parse(TABLE);
        assert_eq!(expected.len(), 16);
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
        let key = (
            "GET".to_string(),
            "/api/v1/projects/:id/members".to_string(),
        );
        expected.insert(key, ("project.read".into(), "project:id".into()));
        let diff = differences(&expected, &registry(), &PREFIXES);
        assert_eq!(
            diff,
            vec![
                "GET /api/v1/projects/:id/members: table project.read project:id, \
                 declared iam.manage project:id"
                    .to_string()
            ]
        );
    }
}
