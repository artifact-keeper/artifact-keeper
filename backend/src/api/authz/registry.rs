//! Route registry: authorization declarations keyed by method and route.
//!
//! Built from the merged OpenAPI document (`build_openapi()`), restricted to
//! the `/api/v1` management API. Keys use Axum's `:param` syntax so they can be
//! compared with `MatchedPath` and with the assembled router. The registry is
//! metadata only; it does not take part in request handling.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::declaration::{
    parse_operation, DeclarationError, DeclarationErrorKind, RouteRequirement,
};

/// The management API this registry covers. Native package protocols, OCI,
/// gRPC and peer endpoints are out of scope for the first guard.
pub const API_V1_PREFIX: &str = "/api/v1";

/// Upper-case HTTP method and Axum-style normalized route template.
pub type RouteKey = (String, String);

const HTTP_METHODS: &[&str] = &[
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

/// OpenAPI `{param}` segments to Axum `:param` segments.
pub fn normalize_template(template: &str) -> String {
    template
        .split('/')
        .map(
            |seg| match seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                Some(name) => format!(":{name}"),
                None => seg.to_string(),
            },
        )
        .collect::<Vec<_>>()
        .join("/")
}

fn is_api_v1(path: &str) -> bool {
    path == API_V1_PREFIX
        || path
            .strip_prefix(API_V1_PREFIX)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Declarations for the `/api/v1` operations of an OpenAPI document.
#[derive(Debug, Clone, Default)]
pub struct RouteRegistry {
    /// Every `/api/v1` operation; `None` when it declares nothing.
    operations: BTreeMap<RouteKey, Option<RouteRequirement>>,
}

impl RouteRegistry {
    /// Build from the serialized merged OpenAPI document.
    ///
    /// Every problem is collected, with its operation, rather than stopping at
    /// the first: duplicate method/route keys and any partial, conflicting,
    /// unknown or malformed declaration.
    pub fn from_openapi(doc: &Value) -> Result<Self, Vec<DeclarationError>> {
        let paths = doc.get("paths").and_then(Value::as_object);
        let mut operations = Vec::new();
        for (path, item) in paths.into_iter().flatten() {
            let Some(item) = item.as_object() else {
                continue;
            };
            for (verb, op) in item {
                if HTTP_METHODS.contains(&verb.as_str()) {
                    operations.push((verb.as_str(), path.as_str(), op));
                }
            }
        }
        Self::from_operations(operations)
    }

    /// Build from `(method, OpenAPI path template, operation)` triples.
    pub fn from_operations<'a>(
        operations: impl IntoIterator<Item = (&'a str, &'a str, &'a Value)>,
    ) -> Result<Self, Vec<DeclarationError>> {
        let mut registry = RouteRegistry::default();
        let mut errors = Vec::new();
        for (method, path, op) in operations {
            if !is_api_v1(path) {
                continue;
            }
            let key = (method.to_uppercase(), normalize_template(path));
            let context = format!("{} {}", key.0, key.1);
            let parsed = match parse_operation(op) {
                Ok(parsed) => parsed,
                Err(e) => {
                    errors.push(e.in_operation(&context));
                    continue;
                }
            };
            if registry.operations.insert(key, parsed).is_some() {
                errors.push(
                    DeclarationError {
                        operation: String::new(),
                        kind: DeclarationErrorKind::DuplicateOperation,
                    }
                    .in_operation(&context),
                );
            }
        }
        if errors.is_empty() {
            Ok(registry)
        } else {
            Err(errors)
        }
    }

    /// Build from the application's merged OpenAPI document.
    pub fn from_api_doc(doc: &utoipa::openapi::OpenApi) -> Result<Self, Vec<DeclarationError>> {
        let value = serde_json::to_value(doc).expect("OpenAPI document serializes");
        Self::from_openapi(&value)
    }

    /// The declaration for an exact method and normalized route, if any.
    pub fn requirement(&self, method: &str, route: &str) -> Option<&RouteRequirement> {
        self.operations
            .get(&(method.to_uppercase(), route.to_string()))
            .and_then(Option::as_ref)
    }

    /// All declared operations, in key order.
    pub fn declared(&self) -> impl Iterator<Item = (&RouteKey, &RouteRequirement)> {
        self.operations
            .iter()
            .filter_map(|(k, v)| v.as_ref().map(|r| (k, r)))
    }

    pub fn declared_keys(&self) -> BTreeSet<RouteKey> {
        self.declared().map(|(k, _)| k.clone()).collect()
    }

    /// Number of `/api/v1` operations in the document, declared or not.
    pub fn operation_count(&self) -> usize {
        self.operations.len()
    }
}

/// How the declared operations relate to the live router.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Coverage {
    /// Live `/api/v1` routes with no declaration.
    pub uncovered: BTreeSet<RouteKey>,
    /// Declared operations that no live route serves.
    pub stale: BTreeSet<RouteKey>,
}

/// Compare the declared operations with the live `/api/v1` routes, in both
/// directions. `live` holds method/route pairs already restricted to `/api/v1`.
pub fn compare_with_live(registry: &RouteRegistry, live: &BTreeSet<RouteKey>) -> Coverage {
    let declared = registry.declared_keys();
    Coverage {
        uncovered: live.difference(&declared).cloned().collect(),
        stale: declared.difference(live).cloned().collect(),
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn doc(paths: Value) -> Value {
        json!({ "paths": paths })
    }

    #[test]
    fn templates_normalize_to_axum_syntax() {
        assert_eq!(
            normalize_template("/api/v1/repositories/{key}/labels/{label_key}"),
            "/api/v1/repositories/:key/labels/:label_key"
        );
        assert_eq!(normalize_template("/api/v1/health"), "/api/v1/health");
        // Only a whole `{segment}` is a parameter.
        assert_eq!(normalize_template("/a/x{y}"), "/a/x{y}");
    }

    #[test]
    fn only_api_v1_operations_are_registered() {
        let reg = RouteRegistry::from_openapi(&doc(json!({
            "/api/v1/things/{id}": {
                "get": {"x-auth-requirement": "authenticated"},
                "parameters": [],
            },
            "/api/v10/things": {"get": {"x-auth-requirement": "public"}},
            "/v2/{name}/blobs": {"get": {"x-auth-requirement": "public"}},
            "/npm/{repo}": {"get": {}},
        })))
        .unwrap();
        assert_eq!(reg.operation_count(), 1);
        assert_eq!(
            reg.requirement("get", "/api/v1/things/:id"),
            Some(&RouteRequirement::AuthenticationOnly)
        );
    }

    #[test]
    fn unknown_method_route_pairs_do_not_resolve() {
        let reg = RouteRegistry::from_openapi(&doc(json!({
            "/api/v1/things/{id}": {"get": {"x-auth-requirement": "public"}, "delete": {}},
        })))
        .unwrap();
        assert!(reg.requirement("GET", "/api/v1/things/:id").is_some());
        // Present but undeclared.
        assert!(reg.requirement("DELETE", "/api/v1/things/:id").is_none());
        // Wrong method, wrong spelling, unknown route.
        assert!(reg.requirement("POST", "/api/v1/things/:id").is_none());
        assert!(reg.requirement("GET", "/api/v1/things/{id}").is_none());
        assert!(reg.requirement("GET", "/api/v1/other").is_none());
        assert_eq!(reg.operation_count(), 2);
    }

    #[test]
    fn invalid_declarations_are_collected_with_their_operation() {
        let errors = RouteRegistry::from_openapi(&doc(json!({
            "/api/v1/a": {"get": {"x-required-permission": "repository.read"}},
            "/api/v1/b": {"post": {
                "x-required-permission": "no.such",
                "x-resource": "repo:key",
            }},
            "/api/v1/c": {"get": {"x-auth-requirement": "public"}},
        })))
        .unwrap_err();
        assert_eq!(errors.len(), 2, "{errors:?}");
        let text: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
        assert!(
            text.iter().any(|t| t.starts_with("GET /api/v1/a: ")),
            "{text:?}"
        );
        assert!(
            text.iter().any(|t| t.starts_with("POST /api/v1/b: ")),
            "{text:?}"
        );
    }

    #[test]
    fn duplicate_keys_are_rejected_not_overwritten() {
        let first = json!({"x-auth-requirement": "public"});
        let second = json!({"x-auth-requirement": "authenticated"});
        let errors = RouteRegistry::from_operations([
            ("get", "/api/v1/x/{id}", &first),
            ("get", "/api/v1/x/:id", &second),
        ])
        .unwrap_err();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].kind, DeclarationErrorKind::DuplicateOperation);
        assert_eq!(errors[0].operation, "GET /api/v1/x/:id");
    }

    fn key(m: &str, p: &str) -> RouteKey {
        (m.to_string(), p.to_string())
    }

    #[test]
    fn coverage_is_compared_in_both_directions() {
        let reg = RouteRegistry::from_openapi(&doc(json!({
            "/api/v1/a": {"get": {"x-auth-requirement": "public"}},
            "/api/v1/gone": {"get": {"x-auth-requirement": "public"}},
            "/api/v1/documented-only": {"get": {}},
        })))
        .unwrap();
        let live: BTreeSet<RouteKey> = [
            key("GET", "/api/v1/a"),
            key("GET", "/api/v1/documented-only"),
            key("POST", "/api/v1/new"),
        ]
        .into();
        let cov = compare_with_live(&reg, &live);
        assert_eq!(
            cov.uncovered,
            [
                key("GET", "/api/v1/documented-only"),
                key("POST", "/api/v1/new")
            ]
            .into()
        );
        assert_eq!(cov.stale, [key("GET", "/api/v1/gone")].into());
    }
}
