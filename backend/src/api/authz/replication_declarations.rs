//! The authorization of every replication operation (peer instances, sync
//! policies and saved remote instances), as a table checked against the
//! declarations in the OpenAPI document.
//!
//! Listing peers is `authenticated`: the handler answers a non-administrator
//! with an empty list, which a peer's heartbeat probe relies on. A saved remote
//! instance belongs to the user who created it, and the handler finds it only
//! among that user's own, so the `/instances` operations are `authenticated`
//! too.

/// Rows in the format of [`super::declaration_table::parse`].
const TABLE: &str = "
GET    /api/v1/instances  authenticated  -
POST   /api/v1/instances  authenticated  -
DELETE /api/v1/instances/:id  authenticated  -
DELETE /api/v1/instances/:id/proxy/*path  authenticated  -
GET    /api/v1/instances/:id/proxy/*path  authenticated  -
PATCH  /api/v1/instances/:id/proxy/*path  authenticated  -
POST   /api/v1/instances/:id/proxy/*path  authenticated  -
PUT    /api/v1/instances/:id/proxy/*path  authenticated  -
GET    /api/v1/peers  authenticated  -
POST   /api/v1/peers  replication.manage  instance
DELETE /api/v1/peers/:id  replication.manage  instance
GET    /api/v1/peers/:id  replication.read  instance
GET    /api/v1/peers/:id/chunks/:artifact_id  replication.read  instance
PUT    /api/v1/peers/:id/chunks/:artifact_id  replication.manage  instance
GET    /api/v1/peers/:id/chunks/:artifact_id/peers  replication.read  instance
GET    /api/v1/peers/:id/chunks/:artifact_id/scored-peers  replication.read  instance
GET    /api/v1/peers/:id/connections  replication.read  instance
POST   /api/v1/peers/:id/connections/:target_id/unreachable  replication.manage  instance
GET    /api/v1/peers/:id/connections/discover  replication.read  instance
POST   /api/v1/peers/:id/connections/probe  replication.manage  instance
POST   /api/v1/peers/:id/heartbeat  replication.manage  instance
GET    /api/v1/peers/:id/labels  replication.read  instance
PUT    /api/v1/peers/:id/labels  replication.manage  instance
DELETE /api/v1/peers/:id/labels/:label_key  replication.manage  instance
POST   /api/v1/peers/:id/labels/:label_key  replication.manage  instance
PUT    /api/v1/peers/:id/network-profile  replication.manage  instance
GET    /api/v1/peers/:id/repositories  replication.read  instance
POST   /api/v1/peers/:id/repositories  replication.manage  instance
DELETE /api/v1/peers/:id/repositories/:repo_id  replication.manage  instance
GET    /api/v1/peers/:id/repositories/:repo_id  replication.read  instance
POST   /api/v1/peers/:id/repositories/:repo_id/sync  replication.trigger  instance
POST   /api/v1/peers/:id/sync  replication.trigger  instance
GET    /api/v1/peers/:id/sync/tasks  replication.read  instance
GET    /api/v1/peers/:id/transfer/:session_id  replication.read  instance
POST   /api/v1/peers/:id/transfer/:session_id/chunk/:chunk_index/complete  replication.manage  instance
POST   /api/v1/peers/:id/transfer/:session_id/chunk/:chunk_index/fail  replication.manage  instance
POST   /api/v1/peers/:id/transfer/:session_id/chunk/:chunk_index/retry  replication.manage  instance
GET    /api/v1/peers/:id/transfer/:session_id/chunks  replication.read  instance
POST   /api/v1/peers/:id/transfer/:session_id/complete  replication.manage  instance
POST   /api/v1/peers/:id/transfer/:session_id/fail  replication.manage  instance
POST   /api/v1/peers/:id/transfer/init  replication.manage  instance
POST   /api/v1/peers/announce  replication.manage  instance
GET    /api/v1/peers/identity  replication.read  instance
GET    /api/v1/sync-policies  replication.read  instance
POST   /api/v1/sync-policies  replication.manage  instance
DELETE /api/v1/sync-policies/:id  replication.manage  instance
GET    /api/v1/sync-policies/:id  replication.read  instance
PUT    /api/v1/sync-policies/:id  replication.manage  instance
POST   /api/v1/sync-policies/:id/toggle  replication.manage  instance
POST   /api/v1/sync-policies/evaluate  replication.trigger  instance
POST   /api/v1/sync-policies/preview  replication.read  instance
";

/// Prefixes whose every operation belongs to this table.
const PREFIXES: [&str; 3] = [
    "/api/v1/peers",
    "/api/v1/sync-policies",
    "/api/v1/instances",
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
        assert_eq!(expected.len(), 51);
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
        assert!(!in_area("/api/v1/admin/peers"));
        assert!(!in_area("/api/v1/peers-other"));
    }

    #[test]
    fn a_changed_row_is_reported_with_its_route() {
        let mut expected = parse(TABLE);
        let key = ("POST".to_string(), "/api/v1/peers/:id/sync".to_string());
        expected.insert(key, ("replication.manage".into(), "instance".into()));
        let diff = differences_within(&expected, &registry(), in_area);
        assert_eq!(
            diff,
            vec![
                "POST /api/v1/peers/:id/sync: table replication.manage instance, declared replication.trigger instance"
                    .to_string()
            ]
        );
    }
}
