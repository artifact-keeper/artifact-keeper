//! Route authorization declarations and their parser.
//!
//! An OpenAPI operation declares its authorization in exactly one of three
//! forms (see `openspec/changes/iam-permission-catalog-and-route-guard`):
//!
//! ```text
//! x-required-permission: <catalog identifier>   # with
//! x-resource: <resolver identifier>
//!
//! x-auth-requirement: authenticated
//! x-auth-requirement: public
//! ```
//!
//! Nothing here enforces anything; the result is metadata for the registry and
//! the route-coverage guard.

use std::fmt;

use serde_json::Value;

use super::catalog::{Permission, Scope};

pub const PERMISSION_KEY: &str = "x-required-permission";
pub const RESOURCE_KEY: &str = "x-resource";
pub const AUTH_REQUIREMENT_KEY: &str = "x-auth-requirement";

/// A resource resolver: how the guarded resource is found from the request.
///
/// The set is closed. An entry is added only for a resource kind that an
/// `/api/v1` path actually names, and carries the scope it resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Resolver {
    pub id: &'static str,
    pub scope: Scope,
}

/// The closed resolver table. `kind:param` names the resource kind and the
/// path parameter that identifies it.
pub const RESOLVERS: &[Resolver] = &[
    Resolver {
        id: "repo:key",
        scope: Scope::Repository,
    },
    Resolver {
        id: "artifact:id",
        scope: Scope::Repository,
    },
    Resolver {
        id: "project:id",
        scope: Scope::Project,
    },
    Resolver {
        id: "group:id",
        scope: Scope::Group,
    },
    Resolver {
        id: "instance",
        scope: Scope::Instance,
    },
];

impl Resolver {
    pub fn lookup(id: &str) -> Option<&'static Resolver> {
        RESOLVERS.iter().find(|r| r.id == id)
    }
}

/// What a declared operation requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteRequirement {
    /// A catalog permission on the resource found by the resolver.
    Permission {
        permission: Permission,
        resolver: &'static Resolver,
    },
    /// Any authenticated caller; no catalog permission.
    AuthenticationOnly,
    /// No authentication; explicitly public.
    Public,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeclarationErrorKind {
    /// `x-required-permission` without `x-resource`, or the reverse.
    Partial {
        missing: &'static str,
    },
    /// A permission declaration combined with `x-auth-requirement`.
    Conflicting,
    UnknownPermission(String),
    UnknownResolver(String),
    UnknownAuthRequirement(String),
    /// An extension whose value is not a string.
    Malformed {
        key: &'static str,
    },
    /// The permission cannot be evaluated at the resolver's scope.
    ScopeMismatch {
        permission: Permission,
        resolver: &'static str,
        resolver_scope: Scope,
    },
    /// Two operations normalize to the same method and route.
    DuplicateOperation,
}

/// A declaration problem, with the operation it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclarationError {
    /// `METHOD path`, or empty when parsing a bare operation.
    pub operation: String,
    pub kind: DeclarationErrorKind,
}

impl DeclarationError {
    pub fn in_operation(mut self, operation: impl Into<String>) -> Self {
        self.operation = operation.into();
        self
    }
}

impl fmt::Display for DeclarationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.operation.is_empty() {
            write!(f, "{}: ", self.operation)?;
        }
        match &self.kind {
            DeclarationErrorKind::Partial { missing } => {
                write!(f, "`{missing}` is required alongside its pair")
            }
            DeclarationErrorKind::Conflicting => write!(
                f,
                "`{AUTH_REQUIREMENT_KEY}` cannot be combined with `{PERMISSION_KEY}`/`{RESOURCE_KEY}`"
            ),
            DeclarationErrorKind::UnknownPermission(p) => write!(f, "unknown permission `{p}`"),
            DeclarationErrorKind::UnknownResolver(r) => write!(f, "unknown resource resolver `{r}`"),
            DeclarationErrorKind::UnknownAuthRequirement(a) => write!(
                f,
                "`{AUTH_REQUIREMENT_KEY}` must be `authenticated` or `public`, got `{a}`"
            ),
            DeclarationErrorKind::Malformed { key } => write!(f, "`{key}` must be a string"),
            DeclarationErrorKind::ScopeMismatch {
                permission,
                resolver,
                resolver_scope,
            } => write!(
                f,
                "permission `{permission}` cannot be evaluated at {resolver_scope:?} scope (resolver `{resolver}`)"
            ),
            DeclarationErrorKind::DuplicateOperation => {
                write!(f, "duplicate method and route in the OpenAPI document")
            }
        }
    }
}

impl std::error::Error for DeclarationError {}

fn err(kind: DeclarationErrorKind) -> DeclarationError {
    DeclarationError {
        operation: String::new(),
        kind,
    }
}

fn string_ext<'a>(op: &'a Value, key: &'static str) -> Result<Option<&'a str>, DeclarationError> {
    match op.get(key) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.as_str())),
        Some(_) => Err(err(DeclarationErrorKind::Malformed { key })),
    }
}

/// Parse the authorization declaration of one serialized OpenAPI operation.
///
/// `Ok(None)` means the operation declares nothing (it is uncovered, which the
/// route guard tracks separately); any partial, conflicting, unknown or
/// malformed declaration is an error.
pub fn parse_operation(op: &Value) -> Result<Option<RouteRequirement>, DeclarationError> {
    let permission = string_ext(op, PERMISSION_KEY)?;
    let resource = string_ext(op, RESOURCE_KEY)?;
    let auth = string_ext(op, AUTH_REQUIREMENT_KEY)?;

    match (permission, resource, auth) {
        (None, None, None) => Ok(None),
        (Some(_), _, Some(_)) | (_, Some(_), Some(_)) => {
            Err(err(DeclarationErrorKind::Conflicting))
        }
        (Some(_), None, None) => Err(err(DeclarationErrorKind::Partial {
            missing: RESOURCE_KEY,
        })),
        (None, Some(_), None) => Err(err(DeclarationErrorKind::Partial {
            missing: PERMISSION_KEY,
        })),
        (None, None, Some("authenticated")) => Ok(Some(RouteRequirement::AuthenticationOnly)),
        (None, None, Some("public")) => Ok(Some(RouteRequirement::Public)),
        (None, None, Some(other)) => Err(err(DeclarationErrorKind::UnknownAuthRequirement(
            other.to_string(),
        ))),
        (Some(p), Some(r), None) => {
            let permission = p
                .parse::<Permission>()
                .map_err(|e| err(DeclarationErrorKind::UnknownPermission(e.0)))?;
            let resolver = Resolver::lookup(r)
                .ok_or_else(|| err(DeclarationErrorKind::UnknownResolver(r.to_string())))?;
            if !permission.applies_at(resolver.scope) {
                return Err(err(DeclarationErrorKind::ScopeMismatch {
                    permission,
                    resolver: resolver.id,
                    resolver_scope: resolver.scope,
                }));
            }
            Ok(Some(RouteRequirement::Permission {
                permission,
                resolver,
            }))
        }
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn kind(op: Value) -> DeclarationErrorKind {
        parse_operation(&op).unwrap_err().kind
    }

    #[test]
    fn valid_forms_are_accepted() {
        let perm = parse_operation(&json!({
            "x-required-permission": "repository.label.manage",
            "x-resource": "repo:key",
        }))
        .unwrap();
        assert_eq!(
            perm,
            Some(RouteRequirement::Permission {
                permission: Permission::RepositoryLabelManage,
                resolver: Resolver::lookup("repo:key").unwrap(),
            })
        );
        assert_eq!(
            parse_operation(&json!({"x-auth-requirement": "authenticated"})).unwrap(),
            Some(RouteRequirement::AuthenticationOnly)
        );
        assert_eq!(
            parse_operation(&json!({"x-auth-requirement": "public"})).unwrap(),
            Some(RouteRequirement::Public)
        );
        // Unrelated operation fields are ignored; no declaration is not an error.
        assert_eq!(parse_operation(&json!({"summary": "x"})).unwrap(), None);
    }

    #[test]
    fn partial_declarations_fail() {
        assert_eq!(
            kind(json!({"x-required-permission": "repository.read"})),
            DeclarationErrorKind::Partial {
                missing: RESOURCE_KEY
            }
        );
        assert_eq!(
            kind(json!({"x-resource": "repo:key"})),
            DeclarationErrorKind::Partial {
                missing: PERMISSION_KEY
            }
        );
    }

    #[test]
    fn conflicting_declarations_fail() {
        for op in [
            json!({"x-required-permission": "repository.read", "x-auth-requirement": "public"}),
            json!({"x-resource": "repo:key", "x-auth-requirement": "authenticated"}),
            json!({
                "x-required-permission": "repository.read",
                "x-resource": "repo:key",
                "x-auth-requirement": "public",
            }),
        ] {
            assert_eq!(kind(op), DeclarationErrorKind::Conflicting);
        }
    }

    #[test]
    fn unknown_values_fail() {
        assert_eq!(
            kind(json!({"x-required-permission": "repository.nope", "x-resource": "repo:key"})),
            DeclarationErrorKind::UnknownPermission("repository.nope".into())
        );
        assert_eq!(
            kind(json!({"x-required-permission": "repository.read", "x-resource": "repo:id"})),
            DeclarationErrorKind::UnknownResolver("repo:id".into())
        );
        assert_eq!(
            kind(json!({"x-auth-requirement": "anonymous"})),
            DeclarationErrorKind::UnknownAuthRequirement("anonymous".into())
        );
    }

    #[test]
    fn malformed_values_fail() {
        for (op, key) in [
            (
                json!({"x-required-permission": 7, "x-resource": "repo:key"}),
                PERMISSION_KEY,
            ),
            (
                json!({"x-required-permission": "repository.read", "x-resource": ["repo:key"]}),
                RESOURCE_KEY,
            ),
            (json!({"x-auth-requirement": true}), AUTH_REQUIREMENT_KEY),
            (json!({"x-auth-requirement": null}), AUTH_REQUIREMENT_KEY),
        ] {
            assert_eq!(kind(op), DeclarationErrorKind::Malformed { key });
        }
    }

    #[test]
    fn resolver_scope_above_the_permission_is_rejected() {
        // `project.read` is not meaningful at repository scope.
        assert!(matches!(
            kind(json!({"x-required-permission": "project.read", "x-resource": "repo:key"})),
            DeclarationErrorKind::ScopeMismatch {
                permission: Permission::ProjectRead,
                resolver: "repo:key",
                resolver_scope: Scope::Repository,
            }
        ));
        // A repository permission resolved at project or instance scope is fine.
        assert!(parse_operation(
            &json!({"x-required-permission": "repository.read", "x-resource": "project:id"})
        )
        .is_ok());
        assert!(parse_operation(
            &json!({"x-required-permission": "system.settings.read", "x-resource": "instance"})
        )
        .is_ok());
        // Group permissions need a group or the instance.
        assert!(parse_operation(
            &json!({"x-required-permission": "group.manage", "x-resource": "repo:key"})
        )
        .is_err());
    }

    #[test]
    fn errors_carry_operation_context() {
        let e = parse_operation(&json!({"x-resource": "repo:key"}))
            .unwrap_err()
            .in_operation("GET /api/v1/repositories/:key/labels");
        let msg = e.to_string();
        assert!(
            msg.starts_with("GET /api/v1/repositories/:key/labels: "),
            "{msg}"
        );
        assert!(msg.contains(PERMISSION_KEY), "{msg}");
    }

    #[test]
    fn resolver_table_is_closed_and_unique() {
        let mut ids = std::collections::HashSet::new();
        for r in RESOLVERS {
            assert!(ids.insert(r.id), "duplicate resolver {}", r.id);
            assert_eq!(Resolver::lookup(r.id), Some(r));
        }
        assert!(Resolver::lookup("repo:").is_none());
        assert!(Resolver::lookup("").is_none());
    }
}
