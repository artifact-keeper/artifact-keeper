//! Shared checking for the per-area declaration tables (`*_declarations.rs`):
//! each holds the authorization of every operation in its area as a table,
//! checked here against the declarations in the OpenAPI document.

use std::collections::BTreeMap;

use super::declaration::RouteRequirement;
use super::registry::{canonical_route, RouteKey, RouteRegistry};

/// A table row's requirement and resolver, as rendered from a declaration.
pub type Row = (String, String);

/// The registry built from the published OpenAPI document.
pub fn registry() -> RouteRegistry {
    RouteRegistry::from_api_doc(&crate::api::openapi::build_openapi())
        .expect("valid authorization declarations")
}

fn in_scope(prefixes: &[&str], route: &str) -> bool {
    prefixes
        .iter()
        .any(|p| route == *p || route.strip_prefix(p).is_some_and(|r| r.starts_with('/')))
}

/// Parse `METHOD route  requirement  resolver` rows, where the requirement is
/// a catalog permission, `authenticated` or `public`, and the resolver is `-`
/// for the last two, into `(method, canonical route) -> (requirement, resolver)`.
pub fn parse(table: &str) -> BTreeMap<RouteKey, Row> {
    let mut rows = BTreeMap::new();
    for line in table.lines().filter(|l| !l.trim().is_empty()) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        let [method, route, requirement, resolver] = cols[..] else {
            panic!("malformed table row: {line}");
        };
        let key = (method.to_string(), canonical_route(route));
        let previous = rows.insert(key, (requirement.to_string(), resolver.to_string()));
        assert!(previous.is_none(), "duplicate table row: {line}");
    }
    rows
}

/// Whether every requirement in `rows` is `public`, `authenticated` or a
/// catalog permission; returns the first that is not.
pub fn unknown_requirement(rows: &BTreeMap<RouteKey, Row>) -> Option<String> {
    rows.iter().find_map(|(key, (requirement, _))| {
        let known = requirement == "public"
            || requirement == "authenticated"
            || requirement.parse::<super::catalog::Permission>().is_ok();
        (!known).then(|| format!("{key:?}: {requirement}"))
    })
}

fn rendered(requirement: &RouteRequirement) -> Row {
    match requirement {
        RouteRequirement::Permission {
            permission,
            resolver,
        } => (permission.id().to_string(), resolver.id.to_string()),
        RouteRequirement::AuthenticationOnly => ("authenticated".into(), "-".into()),
        RouteRequirement::Public => ("public".into(), "-".into()),
    }
}

/// Rows that differ between the table and the registry under `prefixes`, each
/// naming its route.
pub fn differences(
    expected: &BTreeMap<RouteKey, Row>,
    registry: &RouteRegistry,
    prefixes: &[&str],
) -> Vec<String> {
    let declared: BTreeMap<RouteKey, Row> = registry
        .declared()
        .filter(|((_, route), _)| in_scope(prefixes, route))
        .map(|((method, route), req)| ((method.clone(), canonical_route(route)), rendered(req)))
        .collect();
    let mut out = Vec::new();
    for ((method, route), want) in expected {
        match declared.get(&(method.clone(), route.clone())) {
            None => out.push(format!("{method} {route}: in the table, not declared")),
            Some(got) if got != want => out.push(format!(
                "{method} {route}: table {} {}, declared {} {}",
                want.0, want.1, got.0, got.1
            )),
            Some(_) => {}
        }
    }
    for (method, route) in declared.keys() {
        if !expected.contains_key(&(method.clone(), route.clone())) {
            out.push(format!("{method} {route}: declared, not in the table"));
        }
    }
    out
}
