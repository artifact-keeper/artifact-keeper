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

    doc
}
