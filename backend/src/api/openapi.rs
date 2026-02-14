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
        description = "Enterprise artifact registry supporting 45+ package formats.",
        version = "1.0.0-rc.3",
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
        (name = "analytics", description = "Storage and download analytics"),
        (name = "lifecycle", description = "Retention policies and cleanup"),
        (name = "monitoring", description = "Health monitoring and alerts"),
        (name = "telemetry", description = "Crash reporting and telemetry"),
        (name = "sso", description = "Single sign-on configuration"),
        (name = "migration", description = "Data migration and import"),
        (name = "quality", description = "Artifact health scoring and quality gates"),
        (name = "health", description = "Health and readiness checks"),
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

/// Adds Bearer JWT security scheme to the OpenAPI spec.
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
                        .build(),
                ),
            );
        }
    }
}

/// Build the merged OpenAPI document from all handler modules.
pub fn build_openapi() -> utoipa::openapi::OpenApi {
    let mut doc = ApiDoc::openapi();

    // Merge per-module OpenAPI structs as they are annotated.
    // Each module defines its own XxxApiDoc that lists its paths and schemas.
    doc.merge(super::handlers::auth::AuthApiDoc::openapi());
    doc.merge(super::handlers::repositories::RepositoriesApiDoc::openapi());
    doc.merge(super::handlers::artifacts::ArtifactsApiDoc::openapi());
    doc.merge(super::handlers::users::UsersApiDoc::openapi());
    doc.merge(super::handlers::groups::GroupsApiDoc::openapi());
    doc.merge(super::handlers::packages::PackagesApiDoc::openapi());
    doc.merge(super::handlers::search::SearchApiDoc::openapi());
    doc.merge(super::handlers::builds::BuildsApiDoc::openapi());
    doc.merge(super::handlers::promotion::PromotionApiDoc::openapi());
    doc.merge(super::handlers::health::HealthApiDoc::openapi());
    doc.merge(super::handlers::plugins::PluginsApiDoc::openapi());
    doc.merge(super::handlers::webhooks::WebhooksApiDoc::openapi());
    doc.merge(super::handlers::signing::SigningApiDoc::openapi());
    doc.merge(super::handlers::security::SecurityApiDoc::openapi());
    doc.merge(super::handlers::sbom::SbomApiDoc::openapi());
    doc.merge(super::handlers::admin::AdminApiDoc::openapi());
    doc.merge(super::handlers::analytics::AnalyticsApiDoc::openapi());
    doc.merge(super::handlers::lifecycle::LifecycleApiDoc::openapi());
    doc.merge(super::handlers::monitoring::MonitoringApiDoc::openapi());
    doc.merge(super::handlers::telemetry::TelemetryApiDoc::openapi());
    doc.merge(super::handlers::peers::PeersApiDoc::openapi());
    doc.merge(super::handlers::permissions::PermissionsApiDoc::openapi());
    doc.merge(super::handlers::migration::MigrationApiDoc::openapi());
    doc.merge(super::handlers::sso::SsoApiDoc::openapi());
    doc.merge(super::handlers::sso_admin::SsoAdminApiDoc::openapi());
    doc.merge(super::handlers::totp::TotpApiDoc::openapi());
    doc.merge(super::handlers::remote_instances::RemoteInstancesApiDoc::openapi());
    doc.merge(super::handlers::dependency_track::DependencyTrackApiDoc::openapi());
    doc.merge(super::handlers::peer::PeerApiDoc::openapi());
    doc.merge(super::handlers::transfer::TransferApiDoc::openapi());
    doc.merge(super::handlers::tree::TreeApiDoc::openapi());
    doc.merge(super::handlers::repository_labels::RepositoryLabelsApiDoc::openapi());
    doc.merge(super::handlers::sync_policies::SyncPoliciesApiDoc::openapi());
    doc.merge(super::handlers::peer_instance_labels::PeerInstanceLabelsApiDoc::openapi());
    doc.merge(super::handlers::quality_gates::QualityGatesApiDoc::openapi());
    doc.merge(super::handlers::approval::ApprovalApiDoc::openapi());
    doc.merge(super::handlers::promotion_rules::PromotionRulesApiDoc::openapi());

    doc
}

#[cfg(test)]
mod tests {
    use super::*;

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
