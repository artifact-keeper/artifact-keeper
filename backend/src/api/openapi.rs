//! OpenAPI specification generated from handler annotations via utoipa.

use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

/// Top-level OpenAPI document for the Artifact Keeper API.
///
/// Each handler module contributes its own paths and schemas via per-module
/// `#[derive(OpenApi)]` structs that are merged into this root document at
/// startup.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Artifact Keeper API",
        description = "Enterprise artifact registry supporting 45+ package formats.\n\n\
## Authentication\n\n\
The JSON management API under `/api/v1/*` accepts **API tokens only as `Authorization: Bearer <token>`**. \
This is the canonical scheme for programmatic access; JWTs issued by the login flow also use `Bearer`. \
HTTP Basic credentials on `/api/v1/*` are validated *only* as a real `username:password` login — the \
password half is **not** retried as an API token. A request to `/api/v1/*` that sends an API token in the \
password field of Basic auth therefore returns `401 AUTH_ERROR`; switch to `Authorization: Bearer <token>`.\n\n\
Format (package-manager) endpoints such as `/v2/*` (OCI), `/incus/*`, `/debian/*`, and the language \
registries are intentionally more permissive for client compatibility: in addition to Bearer, they accept \
HTTP **Basic** auth with the API token supplied in the *password* field (any username), matching the \
`pip` netrc / Artifactory-style `token:<api_token>` convention used by package managers that cannot send a \
Bearer header. The one `/api/v1` route that shares this contract is the repository download route, \
`GET /api/v1/repositories/{key}/download/{path}`: it serves the same bytes as the format endpoints, so it \
accepts the API token as the Basic password and answers an anonymous request on a non-public repository \
with `401` and a `WWW-Authenticate` challenge, like they do. Every other `/api/v1/*` route refuses the \
Basic-with-token fallback.",
        version = "1.11.3",
        license(name = "MIT", url = "https://opensource.org/licenses/MIT"),
        contact(name = "Artifact Keeper", url = "https://artifactkeeper.com")
    ),
    servers(
        (url = "/", description = "Current server"),
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "auth", description = "Authentication and token management"),
        (name = "repositories", description = "Repository CRUD and artifact operations"),
        (name = "artifacts", description = "Standalone artifact access by ID"),
        (name = "users", description = "User management and API tokens"),
        (name = "groups", description = "User group management"),
        (name = "permissions", description = "RBAC permission management"),
        (name = "builds", description = "Build management and tracking"),
        (name = "packages", description = "Package discovery and version listing"),
        (name = "search", description = "Full-text search and filtering"),
        (name = "promotion", description = "Staging-to-release artifact promotion"),
        (name = "approval", description = "Promotion approval workflow"),
        (name = "security", description = "Security policies and scanning"),
        (name = "sbom", description = "Software Bill of Materials"),
        (name = "signing", description = "Signing key management"),
        (name = "plugins", description = "WASM plugin lifecycle"),
        (name = "webhooks", description = "Event webhook management"),
        (name = "peers", description = "Peer replication and sync"),
        (name = "admin", description = "System administration"),
        (name = "banners", description = "System-wide maintenance and downtime banners"),
        (name = "analytics", description = "Storage and download analytics"),
        (name = "lifecycle", description = "Retention policies and cleanup"),
        (name = "monitoring", description = "Health monitoring and alerts"),
        (name = "telemetry", description = "Crash reporting and telemetry"),
        (name = "sso", description = "Single sign-on configuration"),
        (name = "migration", description = "Data migration and import"),
        (name = "bundles", description = "Offline content bundle export and import"),
        (name = "quarantine", description = "Artifact quarantine period management"),
        (name = "quality", description = "Artifact health scoring and quality gates"),
        (name = "age-gate", description = "Age-based proxy quality gate"),
        (name = "service_accounts", description = "Service account management"),
        (name = "health", description = "Health and readiness checks"),
        (name = "pypi", description = "PyPI endpoints beyond the Simple API: legacy JSON API and XML-RPC"),
        (name = "system", description = "Public system configuration"),
    ),
    components(schemas(ErrorResponse))
)]
pub struct ApiDoc;

/// Standard error response body returned by all endpoints on failure.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct ErrorResponse {
    /// Machine-readable error code (e.g. "NOT_FOUND", "VALIDATION_ERROR")
    pub code: String,
    /// Human-readable error message
    pub message: String,
}

/// Adds the supported security schemes to the OpenAPI spec.
///
/// `bearer_auth` is the canonical scheme for `/api/v1/*`: API tokens and
/// login-issued JWTs are both sent as `Authorization: Bearer <token>`.
///
/// `basic_auth` is documented for the format (package-manager) endpoints
/// and the repository download route. Those endpoints additionally accept
/// HTTP Basic with the API token in the password field for clients that
/// cannot send a Bearer header. The rest of the `/api/v1/*` middleware does
/// NOT honour the Basic-with-token fallback — see the API description for
/// the asymmetry (#2809, #4654).
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .description(Some(
                            "Canonical scheme for `/api/v1/*`. Send an API token or a \
                             login-issued JWT as `Authorization: Bearer <token>`.",
                        ))
                        .build(),
                ),
            );
            components.add_security_scheme(
                "basic_auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Basic)
                        .description(Some(
                            "Format (package-manager) endpoints only. Accepts a \
                             `username:password` login, or an API token in the password \
                             field (any username) for `pip` netrc / Artifactory-style \
                             clients. Not accepted as a token carrier on `/api/v1/*`.",
                        ))
                        .build(),
                ),
            );
        }
    }
}

/// Per-module OpenAPI documents, in merge order.
///
/// Kept as a named list (rather than inline `doc.merge(...)` calls) so tests
/// can inspect each module's contribution BEFORE the first-wins merge
/// collapses schema-name collisions -- see
/// `test_openapi_schema_names_are_unique_across_modules`.
pub(crate) fn module_docs() -> Vec<(&'static str, utoipa::openapi::OpenApi)> {
    use super::handlers;
    vec![
        ("auth", handlers::auth::AuthApiDoc::openapi()),
        (
            "repositories",
            handlers::repositories::RepositoriesApiDoc::openapi(),
        ),
        ("artifacts", handlers::artifacts::ArtifactsApiDoc::openapi()),
        (
            "package_analysis",
            handlers::package_analysis::PackageAnalysisApiDoc::openapi(),
        ),
        ("users", handlers::users::UsersApiDoc::openapi()),
        ("groups", handlers::groups::GroupsApiDoc::openapi()),
        ("packages", handlers::packages::PackagesApiDoc::openapi()),
        ("search", handlers::search::SearchApiDoc::openapi()),
        ("builds", handlers::builds::BuildsApiDoc::openapi()),
        ("promotion", handlers::promotion::PromotionApiDoc::openapi()),
        ("health", handlers::health::HealthApiDoc::openapi()),
        ("plugins", handlers::plugins::PluginsApiDoc::openapi()),
        ("webhooks", handlers::webhooks::WebhooksApiDoc::openapi()),
        (
            "email_subscriptions",
            handlers::email_subscriptions::EmailSubscriptionsApiDoc::openapi(),
        ),
        ("signing", handlers::signing::SigningApiDoc::openapi()),
        ("security", handlers::security::SecurityApiDoc::openapi()),
        ("sbom", handlers::sbom::SbomApiDoc::openapi()),
        (
            "attestations",
            handlers::attestations::AttestationsApiDoc::openapi(),
        ),
        (
            "environments",
            handlers::environments::EnvironmentsApiDoc::openapi(),
        ),
        (
            "artifact_presence",
            handlers::artifact_presence::ArtifactPresenceApiDoc::openapi(),
        ),
        (
            "proxy_cache_cap",
            handlers::proxy_cache_cap::ProxyCacheCapApiDoc::openapi(),
        ),
        ("admin", handlers::admin::AdminApiDoc::openapi()),
        ("banners", handlers::banners::BannersApiDoc::openapi()),
        (
            "admin_security",
            handlers::admin_security::AdminSecurityApiDoc::openapi(),
        ),
        ("analytics", handlers::analytics::AnalyticsApiDoc::openapi()),
        ("lifecycle", handlers::lifecycle::LifecycleApiDoc::openapi()),
        (
            "storage_gc",
            handlers::storage_gc::StorageGcApiDoc::openapi(),
        ),
        (
            "storage_integrity",
            handlers::storage_integrity::StorageIntegrityApiDoc::openapi(),
        ),
        ("trash", handlers::trash::TrashApiDoc::openapi()),
        (
            "monitoring",
            handlers::monitoring::MonitoringApiDoc::openapi(),
        ),
        ("telemetry", handlers::telemetry::TelemetryApiDoc::openapi()),
        ("peers", handlers::peers::PeersApiDoc::openapi()),
        (
            "permissions",
            handlers::permissions::PermissionsApiDoc::openapi(),
        ),
        ("projects", handlers::projects::ProjectsApiDoc::openapi()),
        ("migration", handlers::migration::MigrationApiDoc::openapi()),
        ("bundles", handlers::bundles::BundlesApiDoc::openapi()),
        ("sso", handlers::sso::SsoApiDoc::openapi()),
        (
            "device_authorization",
            handlers::device::DeviceApiDoc::openapi(),
        ),
        ("sso_admin", handlers::sso_admin::SsoAdminApiDoc::openapi()),
        ("totp", handlers::totp::TotpApiDoc::openapi()),
        (
            "remote_instances",
            handlers::remote_instances::RemoteInstancesApiDoc::openapi(),
        ),
        (
            "dependency_track",
            handlers::dependency_track::DependencyTrackApiDoc::openapi(),
        ),
        ("peer", handlers::peer::PeerApiDoc::openapi()),
        ("transfer", handlers::transfer::TransferApiDoc::openapi()),
        ("tree", handlers::tree::TreeApiDoc::openapi()),
        (
            "repository_labels",
            handlers::repository_labels::RepositoryLabelsApiDoc::openapi(),
        ),
        (
            "image_builds",
            handlers::image_builds::ImageBuildsApiDoc::openapi(),
        ),
        (
            "sync_policies",
            handlers::sync_policies::SyncPoliciesApiDoc::openapi(),
        ),
        (
            "peer_instance_labels",
            handlers::peer_instance_labels::PeerInstanceLabelsApiDoc::openapi(),
        ),
        (
            "quality_gates",
            handlers::quality_gates::QualityGatesApiDoc::openapi(),
        ),
        ("approval", handlers::approval::ApprovalApiDoc::openapi()),
        ("age_gate", handlers::age_gate::AgeGateApi::openapi()),
        (
            "download_holds",
            handlers::download_holds::DownloadHoldsApiDoc::openapi(),
        ),
        (
            "promotion_rules",
            handlers::promotion_rules::PromotionRulesApiDoc::openapi(),
        ),
        (
            "service_accounts",
            handlers::service_accounts::ServiceAccountsApiDoc::openapi(),
        ),
        (
            "artifact_labels",
            handlers::artifact_labels::ArtifactLabelsApiDoc::openapi(),
        ),
        ("curation", handlers::curation::CurationApiDoc::openapi()),
        (
            "quarantine",
            handlers::quarantine::QuarantineApiDoc::openapi(),
        ),
        ("upload", handlers::upload::UploadApiDoc::openapi()),
        (
            "system_config",
            handlers::system_config::SystemConfigApiDoc::openapi(),
        ),
        (
            "repo_tokens",
            handlers::repo_tokens::RepoTokensApiDoc::openapi(),
        ),
        ("smtp", handlers::smtp::SmtpApiDoc::openapi()),
        ("ci_auth", handlers::ci_auth::CiAuthApiDoc::openapi()),
        ("pypi", handlers::pypi::PypiApiDoc::openapi()),
        (
            "ci_auth_admin",
            handlers::ci_auth_admin::CiAuthAdminApiDoc::openapi(),
        ),
    ]
}

/// Build the merged OpenAPI document from all handler modules.
pub fn build_openapi() -> utoipa::openapi::OpenApi {
    let mut doc = ApiDoc::openapi();

    // Merge per-module OpenAPI structs as they are annotated. NOTE: the merge
    // is FIRST-WINS on schema names -- a name collision between two modules
    // silently publishes only the earlier module's shape. The schema-name
    // uniqueness test below guards against that.
    for (_module, module_doc) in module_docs() {
        doc.merge(module_doc);
    }

    doc
}

#[cfg(ak_test_shard = "router")]
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    use axum::body::Body;
    use axum::extract::{MatchedPath, Path as AxumPath, Request};
    use axum::http::{Method, StatusCode};
    use axum::middleware::{self, Next};
    use axum::response::{IntoResponse, Response};
    use axum::routing::put;
    use axum::Router;
    use tower::ServiceExt;

    #[test]
    fn test_openapi_spec_is_valid() {
        let spec = build_openapi();

        // Verify basic structure
        assert_eq!(spec.info.title, "Artifact Keeper API");

        // Verify we have a reasonable number of paths (catches missing module merges)
        let path_count = spec.paths.paths.len();
        assert!(
            path_count >= 200,
            "Expected at least 200 paths, got {path_count}. A module merge may be missing."
        );

        // Verify schemas are present
        let schema_count = spec.components.as_ref().map_or(0, |c| c.schemas.len());
        assert!(
            schema_count >= 200,
            "Expected at least 200 schemas, got {schema_count}."
        );

        // Verify security scheme is registered
        let has_bearer = spec
            .components
            .as_ref()
            .is_some_and(|c| c.security_schemes.contains_key("bearer_auth"));
        assert!(has_bearer, "Bearer auth security scheme is missing.");

        // The format-endpoint Basic scheme is documented so the auth asymmetry
        // (Basic-with-token works on format endpoints but not /api/v1/*) is
        // discoverable from the spec rather than only the middleware source.
        let has_basic = spec
            .components
            .as_ref()
            .is_some_and(|c| c.security_schemes.contains_key("basic_auth"));
        assert!(has_basic, "Basic auth security scheme is missing.");

        // The API description must spell out the asymmetry: Bearer is canonical
        // for /api/v1/*, and the Basic-with-token fallback is format-only.
        let description = spec.info.description.as_deref().unwrap_or_default();
        assert!(
            description.contains("Bearer") && description.contains("/api/v1/*"),
            "API description should document Bearer auth for /api/v1/*."
        );

        // Verify all expected tags are present
        let tags: Vec<&str> = spec
            .tags
            .as_ref()
            .map_or(vec![], |t| t.iter().map(|tag| tag.name.as_str()).collect());
        for expected_tag in [
            "auth",
            "repositories",
            "artifacts",
            "users",
            "groups",
            "health",
            "admin",
            "search",
        ] {
            assert!(
                tags.contains(&expected_tag),
                "Missing expected tag: {expected_tag}"
            );
        }

        // Verify the spec serializes to valid JSON
        let json = serde_json::to_string(&spec).expect("Spec should serialize to JSON");
        assert!(
            json.len() > 100_000,
            "Spec JSON seems too small: {} bytes",
            json.len()
        );
    }

    #[test]
    fn test_openapi_spec_operation_count() {
        let spec = build_openapi();
        let mut op_count = 0;

        for item in spec.paths.paths.values() {
            if item.get.is_some() {
                op_count += 1;
            }
            if item.put.is_some() {
                op_count += 1;
            }
            if item.post.is_some() {
                op_count += 1;
            }
            if item.delete.is_some() {
                op_count += 1;
            }
            if item.patch.is_some() {
                op_count += 1;
            }
            if item.head.is_some() {
                op_count += 1;
            }
        }

        assert!(
            op_count >= 250,
            "Expected at least 250 operations, got {op_count}. Handler annotations may be missing."
        );
    }

    /// Regression: every operation must have a globally unique `operationId`.
    /// utoipa derives it from the handler fn name by default, so two handlers
    /// that share a name (e.g. `reject_artifact` in both promotion.rs and
    /// quarantine.rs) silently produce a duplicate `operationId`. That fails the
    /// artifact-keeper-api spectral gate (`operation-operationId-unique`), which
    /// skips ALL SDK generation/publishing for the release — the reason the
    /// published `@artifact-keeper/sdk` stalled at 1.1.6. Catch it here, in
    /// backend CI, instead of discovering it after a release tag is cut.
    #[test]
    fn test_openapi_operation_ids_are_unique() {
        use std::collections::HashMap;

        let spec = build_openapi();
        let mut seen: HashMap<String, Vec<String>> = HashMap::new();

        for (path, item) in &spec.paths.paths {
            for (method, op) in [
                ("GET", &item.get),
                ("PUT", &item.put),
                ("POST", &item.post),
                ("DELETE", &item.delete),
                ("PATCH", &item.patch),
                ("HEAD", &item.head),
            ] {
                if let Some(op) = op {
                    if let Some(id) = &op.operation_id {
                        seen.entry(id.clone())
                            .or_default()
                            .push(format!("{method} {path}"));
                    }
                }
            }
        }

        let mut dups: Vec<String> = seen
            .iter()
            .filter(|(_, locs)| locs.len() > 1)
            .map(|(id, locs)| format!("  {id}: {}", locs.join(", ")))
            .collect();
        dups.sort();

        assert!(
            dups.is_empty(),
            "Duplicate operationId(s) found — these fail the api-repo spectral gate \
             and block SDK generation/publishing. Give one handler an explicit \
             `operation_id = \"...\"` in its #[utoipa::path]:\n{}",
            dups.join("\n")
        );
    }

    /// Regression: utoipa's `merge` is FIRST-WINS on schema NAMES. Two
    /// different structs that share a name across handler modules mean the
    /// later module's operations silently publish the earlier module's
    /// shape — a spec-fidelity drift no per-operation check can see. This
    /// is exactly how GET /api/v1/artifacts/{id} published the wrong
    /// `ArtifactResponse` and PATCH /admin/lifecycle/{id} published the
    /// quality-gate `UpdatePolicyRequest` (CLI repo #98). Registering the
    /// SAME struct from several modules is fine (identical definition);
    /// two different definitions under one name is not.
    #[test]
    fn test_openapi_schema_names_are_unique_across_modules() {
        use std::collections::{HashMap, HashSet};

        // Ratchet: pre-existing collisions grandfathered until each is
        // renamed (same fix as `ArtifactResponse`/`UpdatePolicyRequest`).
        // For every name below, the FIRST-listed module's definition is the
        // one the published spec currently carries; the other module's
        // operations publish the wrong shape. This list may only SHRINK —
        // the assertions below fail both on a NEW collision and on a stale
        // entry (so a fixed collision must be removed here).
        // All previously grandfathered collisions have been resolved by
        // renaming the less-canonical struct in each pair (see #2334 for the
        // ArtifactResponse/UpdatePolicyRequest precedent). The ratchet is now
        // empty: any new divergent same-name schema fails this test outright.
        const KNOWN_COLLISIONS: &[&str] = &[];

        // name -> (first module that registered it, serialized schema)
        let mut seen: HashMap<String, (String, String)> = HashMap::new();
        let mut conflicts: HashSet<String> = HashSet::new();
        let mut conflict_details: Vec<String> = Vec::new();

        let mut docs = module_docs();
        // Include the base doc's own components too.
        docs.insert(0, ("(base ApiDoc)", ApiDoc::openapi()));

        for (module, doc) in docs {
            let Some(components) = doc.components else {
                continue;
            };
            for (name, schema) in components.schemas {
                let json = serde_json::to_string(&schema).expect("schema must serialize");
                match seen.get(&name) {
                    Some((first_module, first_json)) => {
                        if *first_json != json && conflicts.insert(name.clone()) {
                            conflict_details.push(format!(
                                "  {name}: `{first_module}` and `{module}` register \
                                 different definitions under the same schema name"
                            ));
                        }
                    }
                    None => {
                        seen.insert(name, (module.to_string(), json));
                    }
                }
            }
        }

        let mut new_conflicts: Vec<String> = conflict_details
            .iter()
            .filter(|d| {
                !KNOWN_COLLISIONS
                    .iter()
                    .any(|k| d.contains(&format!("  {k}:")))
            })
            .cloned()
            .collect();
        new_conflicts.sort();
        assert!(
            new_conflicts.is_empty(),
            "Duplicate OpenAPI schema name(s) with divergent definitions — \
             utoipa keeps only the FIRST definition, so every other module's \
             operations publish the wrong shape in the spec. Rename the \
             colliding struct(s) or share one canonical type:\n{}",
            new_conflicts.join("\n")
        );

        // Ratchet enforcement: a grandfathered entry that no longer collides
        // must be deleted from KNOWN_COLLISIONS so the list only shrinks.
        let stale: Vec<&&str> = KNOWN_COLLISIONS
            .iter()
            .filter(|k| !conflicts.contains(**k))
            .collect();
        assert!(
            stale.is_empty(),
            "KNOWN_COLLISIONS entries no longer collide — remove them so the \
             grandfather list only shrinks: {stale:?}"
        );
    }

    #[test]
    fn test_repository_labels_endpoints_in_spec() {
        let spec = build_openapi();

        // Verify the label endpoints are registered in the OpenAPI spec
        let paths: Vec<&str> = spec.paths.paths.keys().map(|k| k.as_str()).collect();

        // GET/PUT /{key}/labels
        let labels_path = paths
            .iter()
            .find(|p| p.contains("/labels") && !p.contains("{label_key}"));
        assert!(
            labels_path.is_some(),
            "Missing /{{key}}/labels path in OpenAPI spec. Registered paths: {:?}",
            paths
                .iter()
                .filter(|p| p.contains("label"))
                .collect::<Vec<_>>()
        );

        // POST/DELETE /{key}/labels/{label_key}
        let label_key_path = paths
            .iter()
            .find(|p| p.contains("/labels/") && p.contains("{label_key}"));
        assert!(
            label_key_path.is_some(),
            "Missing /{{key}}/labels/{{label_key}} path in OpenAPI spec"
        );

        // Verify the label paths have the correct HTTP methods
        if let Some(path) = labels_path {
            let item = &spec.paths.paths[*path];
            assert!(item.get.is_some(), "GET /{{key}}/labels should exist");
            assert!(item.put.is_some(), "PUT /{{key}}/labels should exist");
        }

        if let Some(path) = label_key_path {
            let item = &spec.paths.paths[*path];
            assert!(
                item.post.is_some(),
                "POST /{{key}}/labels/{{label_key}} should exist"
            );
            assert!(
                item.delete.is_some(),
                "DELETE /{{key}}/labels/{{label_key}} should exist"
            );
        }
    }

    #[test]
    fn test_repository_labels_schemas_in_spec() {
        let spec = build_openapi();

        let schema_names: Vec<&str> = spec
            .components
            .as_ref()
            .map_or(vec![], |c| c.schemas.keys().map(|k| k.as_str()).collect());

        // Verify our label schemas are registered
        for expected_schema in [
            "LabelResponse",
            "LabelsListResponse",
            "SetLabelsRequest",
            "LabelEntrySchema",
            "AddLabelRequest",
        ] {
            assert!(
                schema_names.contains(&expected_schema),
                "Missing schema '{expected_schema}' in OpenAPI spec. Available: {:?}",
                schema_names
                    .iter()
                    .filter(|s| s.to_lowercase().contains("label"))
                    .collect::<Vec<_>>()
            );
        }
    }

    /// #3522: `POST /api/v1/users/{id}/roles` is deprecated in favour of
    /// `POST /api/v1/permissions`, and the spec must say so (generated SDKs
    /// key their deprecation warnings off this flag). The sibling `GET` on
    /// the same path is not deprecated.
    #[test]
    fn test_3522_openapi_assign_user_role_is_deprecated() {
        let spec = serde_json::to_value(build_openapi()).expect("serialize spec");
        let item = &spec["paths"]["/api/v1/users/{id}/roles"];
        assert!(item.is_object(), "path missing from the spec");
        assert_eq!(item["post"]["deprecated"], serde_json::Value::Bool(true));
        assert!(item["get"]["deprecated"].is_null());
        let headers = &item["post"]["responses"]["200"]["headers"];
        assert!(
            headers["Deprecation"].is_object(),
            "Deprecation header documented"
        );
        assert!(headers["Link"].is_object(), "Link header documented");
        assert!(spec["paths"]["/api/v1/permissions"]["post"].is_object());
    }

    /// #3812: `visibility` is the authoritative field; the legacy boolean and
    /// its alias stay accepted and returned but are flagged deprecated in the
    /// spec so generated SDKs surface it.
    #[test]
    fn test_repository_legacy_visibility_booleans_are_deprecated_in_spec() {
        let spec = serde_json::to_value(build_openapi()).expect("serialize spec");
        for schema in [
            "CreateRepositoryRequest",
            "UpdateRepositoryRequest",
            "RepositoryResponse",
        ] {
            let props = &spec["components"]["schemas"][schema]["properties"];
            assert!(props.is_object(), "schema {schema} missing from the spec");
            for field in ["is_public", "allow_anonymous_access"] {
                assert_eq!(
                    props[field]["deprecated"],
                    serde_json::Value::Bool(true),
                    "{schema}.{field} must be marked deprecated"
                );
            }
            assert!(
                props["visibility"]["deprecated"].is_null(),
                "{schema}.visibility must not be deprecated"
            );
        }
    }

    /// #4330: `UpdateRepositoryRequest.curation_default_action` is an
    /// `Option<String>` (absent leaves the stored value unchanged), but a
    /// `value_type = String` override made the spec list it as required, so
    /// generated clients had to read-modify-write it on every update.
    #[test]
    fn test_4330_update_repository_curation_default_action_not_required() {
        let spec = serde_json::to_value(build_openapi()).expect("serialize spec");
        let schema = &spec["components"]["schemas"]["UpdateRepositoryRequest"];
        assert!(
            schema["properties"]["curation_default_action"].is_object(),
            "UpdateRepositoryRequest.curation_default_action missing from the spec"
        );
        let required: Vec<&str> = schema["required"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        assert!(
            !required.contains(&"curation_default_action"),
            "UpdateRepositoryRequest.curation_default_action must be optional, required = {required:?}"
        );
    }

    /// #3924 added a second 409 to chunked-upload completion (immutable path
    /// occupied) alongside the checksum mismatch, and clients that mapped every
    /// 409 there to a checksum error misreported it. The documented 409 must
    /// name both causes and point clients at the body.
    #[test]
    fn test_openapi_upload_complete_409_documents_both_causes() {
        let spec = serde_json::to_value(build_openapi()).unwrap();
        let paths = spec["paths"].as_object().unwrap();
        let (_, item) = paths
            .iter()
            .find(|(p, _)| p.ends_with("/uploads/{session_id}/complete"))
            .expect("upload completion path missing from OpenAPI spec");
        let description = item["put"]["responses"]["409"]["description"]
            .as_str()
            .expect("upload completion must document a 409 response");
        assert!(description.contains("Checksum mismatch"), "{description}");
        assert!(
            description.contains("Artifact version already exists and is immutable"),
            "{description}"
        );
        assert!(description.contains("response body"), "{description}");
    }

    /// #4832: the direct PUT answers 409 for an occupied immutable path, and
    /// is the single winner's 201 under concurrent PUTs to one path. The spec
    /// must document the 409 and its body.
    #[test]
    fn test_openapi_artifact_put_documents_409() {
        let spec = serde_json::to_value(build_openapi()).unwrap();
        let paths = spec["paths"].as_object().unwrap();
        let (_, item) = paths
            .iter()
            .find(|(p, _)| p.ends_with("/repositories/{key}/artifacts/{path}"))
            .expect("artifact PUT path missing from OpenAPI spec");
        let description = item["put"]["responses"]["409"]["description"]
            .as_str()
            .expect("artifact PUT must document a 409 response");
        assert!(
            description.contains("Artifact version already exists and is immutable"),
            "{description}"
        );
        assert!(description.contains("concurrent"), "{description}");
    }

    /// Verify every path documented in the OpenAPI spec is served by the real
    /// production router, and that each handler extracts the same number of
    /// path parameters the document advertises.
    ///
    /// The previous version walked a hand-maintained map from context prefix to
    /// handler source and skipped any path whose first segment below that prefix
    /// was a `{param}`. That silently skipped `/peers/{id}/network-profile`, so
    /// the #4884 miswire (router mounted at `/peers`, handler still binding
    /// `Path(peer_id)`) shipped. This version instead:
    ///
    /// 1. replaces each `{param}` with a well-formed probe value,
    /// 2. sends the documented method through `create_router`, with a
    ///    `route_layer` that answers 204 only after axum has matched both the
    ///    path and the method (so no handler or database is touched), and
    /// 3. compares the path parameter count with the handler signature's
    ///    `Path(...)` extractor arity found next to its `#[utoipa::path]`.
    ///
    /// The negative test below re-introduces the #4884 mount and proves this
    /// probe rejects it.
    #[tokio::test]
    async fn test_all_openapi_paths_have_handlers() {
        let spec = serde_json::to_value(build_openapi()).expect("serialize OpenAPI");
        let handlers = scan_handler_signatures();
        let paths = spec["paths"].as_object().expect("paths object");

        let mut operations = Vec::new();
        let mut failures = Vec::new();
        for (path, item) in paths {
            let Some(item) = item.as_object() else {
                continue;
            };
            for (method_name, op) in item {
                let method = match method_name.as_str() {
                    "get" => Method::GET,
                    "post" => Method::POST,
                    "put" => Method::PUT,
                    "delete" => Method::DELETE,
                    "patch" => Method::PATCH,
                    _ => continue,
                };
                let uri = concrete_path(path, op);
                operations.push((method.clone(), uri));

                let operation_id = op["operationId"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{method_name} {path} has no operationId"));
                let Some(handler) = handlers.get(operation_id) else {
                    failures.push(format!(
                        "{method} {path} (operationId {operation_id}) has no scanned #[utoipa::path] handler"
                    ));
                    continue;
                };
                let documented = path_parameter_count(path);
                if handler.path_extractors != documented {
                    failures.push(format!(
                        "{method} {path} (operationId {operation_id}, {}::{}) documents {documented} \
                         path parameter(s) but extracts {} with Path(...)",
                        handler.file, handler.fn_name, handler.path_extractors
                    ));
                }
            }
        }

        assert!(
            operations.len() >= 500,
            "only {} documented operations found; the route probe is not covering the API",
            operations.len()
        );

        // `create_router` is the production router. `route_layer` (unlike
        // `layer`) wraps each method handler *after* axum has selected the
        // method, so an unsupported method still answers 405 and the probe
        // answers 204 for every matched path+method without running a handler.
        let state = crate::api::handlers::test_db_helpers::build_state(
            crate::api::handlers::test_db_helpers::lazy_pool(),
            "/tmp/ak-openapi-route-probe",
        );
        let app =
            crate::api::routes::create_router(state).route_layer(middleware::from_fn(route_probe));
        failures.extend(probe_operations(app, &operations).await);

        assert!(
            failures.is_empty(),
            "OpenAPI-documented endpoints that the production router does not serve \
             (or whose handler extractor arity disagrees with the document):\n{}",
            failures.join("\n")
        );
    }

    /// The marker the route probe puts on a successful response, so a failure
    /// message can name the route axum actually matched.
    #[derive(Clone, Debug)]
    struct ProbedRoute(String);

    /// Runs only after axum has matched a documented method to a route, because
    /// it is installed with `Router::route_layer`. Return 204 without invoking
    /// the handler: route registration is what this test asserts, and a real
    /// handler would need auth, a database row, or an upstream.
    async fn route_probe(req: Request, _next: Next) -> Response {
        let matched = req
            .extensions()
            .get::<MatchedPath>()
            .map(|path| path.as_str().to_string())
            .unwrap_or_default();
        let mut response = StatusCode::NO_CONTENT.into_response();
        response.extensions_mut().insert(ProbedRoute(matched));
        response
    }

    async fn probe_operations(app: Router, operations: &[(Method, String)]) -> Vec<String> {
        let mut failures = Vec::new();
        for (method, uri) in operations {
            let request = Request::builder()
                .method(method.clone())
                .uri(uri)
                .body(Body::empty())
                .expect("build route-probe request");
            match app.clone().oneshot(request).await {
                Ok(response) => {
                    if response.status() != StatusCode::NO_CONTENT {
                        let matched = response
                            .extensions()
                            .get::<ProbedRoute>()
                            .map(|route| route.0.as_str())
                            .unwrap_or("<none>");
                        failures.push(format!(
                            "{method} {uri} — expected the documented route to answer 204, got {} \
                             (axum matched {matched})",
                            response.status()
                        ));
                    }
                }
                Err(error) => failures.push(format!("{method} {uri} — router error: {error}")),
            }
        }
        failures
    }

    /// Replace every `{param}` with a value matching the parameter's OpenAPI
    /// schema where one is documented (UUID, integer, enum, ...), and with a
    /// non-empty segment otherwise. Route probing only needs a well-formed
    /// value; handlers are not invoked.
    fn concrete_path(path: &str, operation: &serde_json::Value) -> String {
        let mut resolved = String::new();
        let mut rest = path;
        while let Some(open) = rest.find('{') {
            resolved.push_str(&rest[..open]);
            let close = rest[open..]
                .find('}')
                .expect("unbalanced {param} in OpenAPI path")
                + open;
            let raw = &rest[open + 1..close];
            let name = raw.trim_start_matches('*').split(':').next().unwrap_or(raw);
            resolved.push_str(&placeholder_for(name, operation));
            rest = &rest[close + 1..];
        }
        resolved.push_str(rest);
        resolved
    }

    fn placeholder_for(name: &str, operation: &serde_json::Value) -> String {
        let schema = operation["parameters"]
            .as_array()
            .and_then(|parameters| {
                parameters.iter().find(|parameter| {
                    parameter["in"] == "path" && parameter["name"].as_str() == Some(name)
                })
            })
            .map(|parameter| &parameter["schema"]);

        if let Some(value) = schema
            .and_then(|schema| schema["enum"].as_array())
            .and_then(|values| values.first())
            .and_then(|value| value.as_str())
        {
            if value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c))
            {
                return value.to_string();
            }
        }

        let schema_type = schema
            .and_then(|schema| {
                schema["type"].as_str().or_else(|| {
                    schema["type"]
                        .as_array()?
                        .iter()
                        .find_map(|value| value.as_str())
                })
            })
            .unwrap_or_default();
        let format = schema
            .and_then(|schema| schema["format"].as_str())
            .unwrap_or_default();

        match (schema_type, format) {
            ("integer" | "number", _) => "1".to_string(),
            ("boolean", _) => "true".to_string(),
            ("string", "uuid") => uuid::Uuid::new_v4().to_string(),
            ("string", "date-time") => "2020-01-01T00:00:00Z".to_string(),
            _ if name == "id" || name.ends_with("_id") => uuid::Uuid::new_v4().to_string(),
            _ => "probe".to_string(),
        }
    }

    fn path_parameter_count(path: &str) -> usize {
        path.matches('{').count()
    }

    #[derive(Debug)]
    struct HandlerSignature {
        file: String,
        fn_name: String,
        path_extractors: usize,
    }

    /// Every `#[utoipa::path]` handler, keyed by the operationId utoipa emits
    /// for it. Mirrors the scan in `test_every_annotated_handler_is_in_the_openapi_spec`
    /// so the route probe can compare the documented parameter list with the
    /// handler's actual `Path(...)` extractors.
    fn scan_handler_signatures() -> HashMap<String, HandlerSignature> {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let handlers_dir = manifest_dir.join("src/api/handlers");
        let mut files = Vec::new();
        collect_handler_sources(&handlers_dir, &mut files);
        files.sort();

        let marker = "#[utoipa::path(";
        let mut signatures = HashMap::new();
        for file in files {
            let source = std::fs::read_to_string(&file).expect("read handler source");
            let relative = file.strip_prefix(manifest_dir).unwrap_or(&file).display();
            let mut cursor = 0;
            while let Some(offset) = source[cursor..].find(marker) {
                let start = cursor + offset;
                let Some(attr_len) = source[start..].find("\n)]") else {
                    panic!("unterminated utoipa::path in {file:?}");
                };
                let end = start + attr_len;
                let attr = &source[start..end];
                let after = &source[end..];
                let Some(fn_pos) = after.find("fn ") else {
                    panic!("no fn after utoipa::path in {file:?}");
                };
                let fn_name: String = after[fn_pos + 3..]
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                let signature_end = after[fn_pos..].find('{').expect("handler body");
                let signature = &after[fn_pos..fn_pos + signature_end];
                let operation_id =
                    quoted_value(attr, "operation_id = \"").unwrap_or_else(|| fn_name.clone());
                signatures.insert(
                    operation_id,
                    HandlerSignature {
                        file: relative.to_string(),
                        fn_name,
                        path_extractors: path_extractor_count(signature),
                    },
                );
                cursor = end;
            }
        }
        signatures
    }

    fn quoted_value(source: &str, prefix: &str) -> Option<String> {
        let start = source.find(prefix)? + prefix.len();
        let rest = &source[start..];
        Some(rest[..rest.find('"')?].to_string())
    }

    fn collect_handler_sources(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read handlers dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                collect_handler_sources(&path, out);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                out.push(path);
            }
        }
    }

    /// Count the path parameters a handler destructures with `Path(...)`.
    /// Scalars (`Path(id)`) count once; tuples (`Path((a, b))`) count their
    /// elements. A `Path<...>` *type* (the extractor's generic argument) is
    /// ignored because `Path` is followed by `<`, not `(`.
    fn path_extractor_count(signature: &str) -> usize {
        let bytes = signature.as_bytes();
        let mut index = 0;
        let mut total = 0;
        while index + 4 <= bytes.len() {
            if &bytes[index..index + 4] == b"Path" {
                let boundary = index == 0
                    || !(bytes[index - 1].is_ascii_alphanumeric() || bytes[index - 1] == b'_');
                let mut open = index + 4;
                while open < bytes.len() && bytes[open].is_ascii_whitespace() {
                    open += 1;
                }
                if boundary && open < bytes.len() && bytes[open] == b'(' {
                    let mut depth = 1;
                    let mut close = open + 1;
                    while close < bytes.len() && depth > 0 {
                        match bytes[close] {
                            b'(' => depth += 1,
                            b')' => depth -= 1,
                            _ => {}
                        }
                        close += 1;
                    }
                    total += path_pattern_arity(&signature[open + 1..close - 1]);
                    index = close;
                    continue;
                }
            }
            index += 1;
        }
        total
    }

    fn path_pattern_arity(pattern: &str) -> usize {
        let pattern = pattern.trim();
        if pattern.starts_with('(') && pattern.ends_with(')') {
            split_top_level(&pattern[1..pattern.len() - 1]).len()
        } else {
            1
        }
    }

    fn split_top_level(source: &str) -> Vec<&str> {
        let mut parts = Vec::new();
        let mut depth = 0usize;
        let mut start = 0usize;
        for (index, character) in source.char_indices() {
            match character {
                '(' | '[' | '<' | '{' => depth += 1,
                ')' | ']' | '>' | '}' => depth = depth.saturating_sub(1),
                ',' if depth == 0 => {
                    parts.push(source[start..index].trim());
                    start = index + 1;
                }
                _ => {}
            }
        }
        let tail = source[start..].trim();
        if !tail.is_empty() {
            parts.push(tail);
        }
        parts
    }

    #[test]
    fn path_extractor_count_handles_scalars_tuples_and_qualified_paths() {
        assert_eq!(path_extractor_count("fn h(Path(id): Path<Uuid>)"), 1);
        assert_eq!(
            path_extractor_count("fn h(Path((key, path)): Path<(String, String)>)"),
            2
        );
        assert_eq!(
            path_extractor_count(
                "fn h(axum::extract::Path((a, b, c)): axum::extract::Path<(u8, u8, u8)>)"
            ),
            3
        );
        assert_eq!(
            path_extractor_count("fn h(Path(a): Path<String>, Path(b): Path<Uuid>)"),
            2
        );
    }

    /// #4884: the network-profile router was merged at `/peers` instead of
    /// nested under `/:id`. Reintroduce that mount in a throwaway router and
    /// prove the production-router probe above rejects it.
    #[tokio::test]
    async fn test_route_probe_catches_miswired_peer_network_profile_4930() {
        async fn update_network_profile(AxumPath(_peer_id): AxumPath<uuid::Uuid>) -> StatusCode {
            StatusCode::OK
        }

        let documented = (
            Method::PUT,
            format!("/api/v1/peers/{}/network-profile", uuid::Uuid::new_v4()),
        );

        let correct = Router::new()
            .route(
                "/api/v1/peers/:id/network-profile",
                put(update_network_profile),
            )
            .route_layer(middleware::from_fn(route_probe));
        assert!(
            probe_operations(correct.clone(), std::slice::from_ref(&documented))
                .await
                .is_empty(),
            "the correctly nested route must pass the probe"
        );

        let miswired = Router::new()
            .route("/api/v1/peers/network-profile", put(update_network_profile))
            .route_layer(middleware::from_fn(route_probe));
        let failures = probe_operations(miswired, &[documented]).await;
        assert_eq!(failures.len(), 1, "miswired mount must fail the probe");
        assert!(
            failures[0].contains("404"),
            "the documented path must miss the miswired mount: {failures:?}"
        );
    }

    /// Regression (#4095): every handler carrying a `#[utoipa::path]` must be
    /// listed in its module's `#[openapi(paths(...))]` AND that module doc must
    /// be merged in [`module_docs`]. Without this, an annotated and mounted
    /// route silently drops out of the exported spec and every generated SDK
    /// (`get_proxy_sbom` shipped that way in 1.10.0, as did the whole
    /// `PackageAnalysisApiDoc`). `test_all_openapi_paths_have_handlers` checks
    /// the other direction (documented => routed); this one checks
    /// annotated => documented, by operationId (utoipa defaults it to the fn
    /// name unless `operation_id = "..."` overrides it).
    #[test]
    fn test_every_annotated_handler_is_in_the_openapi_spec() {
        use std::collections::HashSet;

        // Handlers annotated on purpose but deliberately left out of the spec.
        // Each entry needs a reason; do not add to this list to silence a
        // handler that is simply missing from its ApiDoc.
        const NOT_DOCUMENTED: &[&str] = &[
            // SSE stream: no ApiDoc in events.rs and no generated-SDK support
            // for text/event-stream; the web UI consumes it via EventSource.
            "event_stream",
        ];

        fn collect_rs(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).expect("read handlers dir") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    collect_rs(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }

        let spec = build_openapi();
        let mut documented: HashSet<String> = HashSet::new();
        for item in spec.paths.paths.values() {
            let ops = [
                &item.get,
                &item.put,
                &item.post,
                &item.delete,
                &item.patch,
                &item.head,
            ];
            for op in ops.into_iter().flatten() {
                if let Some(id) = &op.operation_id {
                    documented.insert(id.clone());
                }
            }
        }

        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let handlers_dir = manifest_dir.join("src/api/handlers");
        let mut files = Vec::new();
        collect_rs(&handlers_dir, &mut files);
        files.sort();

        let marker = "#[utoipa::path(";
        let mut annotated = 0usize;
        let mut missing = Vec::new();
        // Every annotated handler, by the operationId it resolves to. Two
        // same-named handlers in different files resolve to ONE operationId,
        // and the spec (whose ids are unique) can hold only one of them, so a
        // presence check alone would let the registered one mask the other.
        let mut by_op_id: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        for file in &files {
            let src = std::fs::read_to_string(file).expect("read handler source");
            let mut cursor = 0usize;
            while let Some(rel) = src[cursor..].find(marker) {
                let start = cursor + rel;
                // Every annotation in the handlers closes with `)]` on its own
                // line; the handler fn follows (possibly after other attributes
                // or comments).
                let Some(attr_len) = src[start..].find("\n)]") else {
                    panic!("unterminated utoipa::path in {file:?}");
                };
                let end = start + attr_len;
                let attr = &src[start..end];
                let after = &src[end..];
                let Some(fn_pos) = after.find("fn ") else {
                    panic!("no fn after utoipa::path in {file:?}");
                };
                let fn_name: String = after[fn_pos + 3..]
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                let op_id_key = "operation_id = \"";
                let op_id = match attr.find(op_id_key) {
                    Some(i) => {
                        let rest = &attr[i + op_id_key.len()..];
                        rest[..rest.find('"').expect("closing quote")].to_string()
                    }
                    None => fn_name.clone(),
                };
                annotated += 1;
                let exempt = NOT_DOCUMENTED.contains(&fn_name.as_str());
                let rel = file.strip_prefix(manifest_dir).unwrap_or(file).display();
                if !exempt {
                    by_op_id
                        .entry(op_id.clone())
                        .or_default()
                        .push(format!("{rel} :: {fn_name}"));
                }
                if !exempt && !documented.contains(&op_id) {
                    missing.push(format!("{rel} :: {fn_name} (operationId {op_id})"));
                }
                cursor = end;
            }
        }

        for (op_id, sites) in &by_op_id {
            if sites.len() > 1 {
                missing.push(format!(
                    "operationId {op_id} is claimed by {} handlers ({}); only one can be in \
                     the spec, so give each an explicit `operation_id = \"...\"`",
                    sites.len(),
                    sites.join(", ")
                ));
            }
        }

        // Guard the scanner itself: if the marker or layout changes and nothing
        // is found, this test must not pass vacuously.
        assert!(
            annotated >= 250,
            "found only {annotated} #[utoipa::path] annotations; the source scan is broken"
        );
        assert!(
            missing.is_empty(),
            "Handlers annotated with #[utoipa::path] but absent from the merged OpenAPI spec. \
             Add each to its module's `#[openapi(paths(...))]`, and make sure that ApiDoc is \
             listed in `module_docs()`:\n{}",
            missing.join("\n")
        );
    }

    /// Export OpenAPI spec to files when EXPORT_OPENAPI_SPEC env var is set.
    /// Used by CI to generate the spec without starting the server.
    ///
    /// Usage: EXPORT_OPENAPI_SPEC=1 cargo test --lib export_openapi_spec -- --ignored
    #[test]
    #[ignore]
    fn export_openapi_spec() {
        if std::env::var("EXPORT_OPENAPI_SPEC").is_err() {
            return;
        }

        let spec = build_openapi();
        let json = serde_json::to_string_pretty(&spec).expect("Failed to serialize to JSON");

        let out_dir = std::env::var("EXPORT_OPENAPI_DIR").unwrap_or_else(|_| ".".to_string());

        let json_path = format!("{}/openapi.json", out_dir);
        std::fs::write(&json_path, &json).expect("Failed to write openapi.json");

        eprintln!(
            "Exported OpenAPI spec: {} paths, {} schemas → {}",
            spec.paths.paths.len(),
            spec.components.as_ref().map_or(0, |c| c.schemas.len()),
            json_path
        );
    }
}
