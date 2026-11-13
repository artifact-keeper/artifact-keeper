//! The authorization of every integration operation (migrations, content
//! bundles, plugins, package formats, webhooks) and of four public reads, as a
//! table checked against the declarations in the OpenAPI document.
//!
//! `GET /api/v1/events/stream` stays in the router baseline: the SSE stream is
//! deliberately left out of the OpenAPI document, so it has nowhere to declare.

/// Rows in the format of [`super::declaration_table::parse`].
const TABLE: &str = "
GET    /api/v1/banners  public  -
POST   /api/v1/bundles/exports  migration.manage  instance
GET    /api/v1/bundles/format  migration.manage  instance
POST   /api/v1/bundles/imports  migration.manage  instance
GET    /api/v1/bundles/jobs  migration.manage  instance
GET    /api/v1/bundles/jobs/:id  migration.manage  instance
GET    /api/v1/bundles/jobs/:id/items  migration.manage  instance
POST   /api/v1/bundles/manifest/validate  migration.manage  instance
GET    /api/v1/formats  public  -
GET    /api/v1/formats/:format_key  public  -
POST   /api/v1/formats/:format_key/disable  format.manage  instance
POST   /api/v1/formats/:format_key/enable  format.manage  instance
POST   /api/v1/formats/:format_key/test  format.manage  instance
GET    /api/v1/migrations  migration.manage  instance
POST   /api/v1/migrations  migration.manage  instance
DELETE /api/v1/migrations/:id  migration.manage  instance
GET    /api/v1/migrations/:id  migration.manage  instance
POST   /api/v1/migrations/:id/assess  migration.manage  instance
GET    /api/v1/migrations/:id/assessment  migration.manage  instance
POST   /api/v1/migrations/:id/cancel  migration.manage  instance
GET    /api/v1/migrations/:id/items  migration.manage  instance
POST   /api/v1/migrations/:id/pause  migration.manage  instance
GET    /api/v1/migrations/:id/report  migration.manage  instance
POST   /api/v1/migrations/:id/resume  migration.manage  instance
POST   /api/v1/migrations/:id/start  migration.manage  instance
GET    /api/v1/migrations/:id/stream  migration.manage  instance
GET    /api/v1/migrations/connections  migration.manage  instance
POST   /api/v1/migrations/connections  migration.manage  instance
DELETE /api/v1/migrations/connections/:id  migration.manage  instance
GET    /api/v1/migrations/connections/:id  migration.manage  instance
GET    /api/v1/migrations/connections/:id/repositories  migration.manage  instance
POST   /api/v1/migrations/connections/:id/test  migration.manage  instance
GET    /api/v1/plugins  authenticated  -
POST   /api/v1/plugins  plugin.manage  instance
DELETE /api/v1/plugins/:id  plugin.manage  instance
GET    /api/v1/plugins/:id  authenticated  -
GET    /api/v1/plugins/:id/config  plugin.manage  instance
POST   /api/v1/plugins/:id/config  plugin.manage  instance
POST   /api/v1/plugins/:id/disable  plugin.manage  instance
POST   /api/v1/plugins/:id/enable  plugin.manage  instance
GET    /api/v1/plugins/:id/events  authenticated  -
POST   /api/v1/plugins/:id/reload  plugin.manage  instance
POST   /api/v1/plugins/install/git  plugin.manage  instance
POST   /api/v1/plugins/install/local  plugin.manage  instance
POST   /api/v1/plugins/install/zip  plugin.manage  instance
GET    /api/v1/setup/status  public  -
GET    /api/v1/system/config  public  -
GET    /api/v1/webhooks  authenticated  -
POST   /api/v1/webhooks  repository.notifications.manage  webhook:body
DELETE /api/v1/webhooks/:id  repository.notifications.manage  webhook:id
GET    /api/v1/webhooks/:id  repository.notifications.manage  webhook:id
GET    /api/v1/webhooks/:id/deliveries  repository.notifications.manage  webhook:id
POST   /api/v1/webhooks/:id/deliveries/:delivery_id/redeliver  repository.notifications.manage  webhook:id
POST   /api/v1/webhooks/:id/disable  repository.notifications.manage  webhook:id
POST   /api/v1/webhooks/:id/enable  repository.notifications.manage  webhook:id
POST   /api/v1/webhooks/:id/rotate-secret  repository.notifications.manage  webhook:id
POST   /api/v1/webhooks/:id/test  repository.notifications.manage  webhook:id
GET    /api/v1/webhooks/jwks  public  -
";

/// Prefixes whose every operation belongs to this table.
const PREFIXES: [&str; 5] = [
    "/api/v1/migrations",
    "/api/v1/bundles",
    "/api/v1/plugins",
    "/api/v1/formats",
    "/api/v1/webhooks",
];

/// Single routes of this table outside those prefixes. The administrators'
/// banners are under `/api/v1/admin`, in the admin table.
const ROUTES: [&str; 3] = [
    "/api/v1/system/config",
    "/api/v1/banners",
    "/api/v1/setup/status",
];

/// Whether a canonical route belongs to this table.
fn in_area(route: &str) -> bool {
    ROUTES.contains(&route)
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
        assert_eq!(expected.len(), 58);
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
        assert!(!in_area("/api/v1/admin/banners"));
        assert!(!in_area("/api/v1/webhooks-other"));
    }

    #[test]
    fn a_changed_row_is_reported_with_its_route() {
        let mut expected = parse(TABLE);
        let key = ("GET".to_string(), "/api/v1/webhooks/:id".to_string());
        expected.insert(key, ("webhook.read".into(), "instance".into()));
        let diff = differences_within(&expected, &registry(), in_area);
        assert_eq!(
            diff,
            vec![
                "GET /api/v1/webhooks/:id: table webhook.read instance, declared repository.notifications.manage webhook:id"
                    .to_string()
            ]
        );
    }
}
