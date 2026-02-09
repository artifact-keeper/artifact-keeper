//! SSO administration handlers (OIDC, LDAP, SAML config CRUD).
//!
//! All endpoints require admin privileges.

use axum::{
    extract::{Extension, Path, State},
    routing::{get, patch, post},
    Json, Router,
};
use utoipa::OpenApi;
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::auth_config_service::{
    AuthConfigService, CreateLdapConfigRequest, CreateOidcConfigRequest, CreateSamlConfigRequest,
    LdapConfigResponse, LdapTestResult, OidcConfigResponse, SamlConfigResponse, SsoProviderInfo,
    ToggleRequest, UpdateLdapConfigRequest, UpdateOidcConfigRequest, UpdateSamlConfigRequest,
};

/// Create SSO admin routes
pub fn router() -> Router<SharedState> {
    Router::new()
        // OIDC config CRUD
        .route("/oidc", get(list_oidc).post(create_oidc))
        .route(
            "/oidc/:id",
            get(get_oidc).put(update_oidc).delete(delete_oidc),
        )
        .route("/oidc/:id/toggle", patch(toggle_oidc))
        // LDAP config CRUD
        .route("/ldap", get(list_ldap).post(create_ldap))
        .route(
            "/ldap/:id",
            get(get_ldap).put(update_ldap).delete(delete_ldap),
        )
        .route("/ldap/:id/toggle", patch(toggle_ldap))
        .route("/ldap/:id/test", post(test_ldap))
        // SAML config CRUD
        .route("/saml", get(list_saml).post(create_saml))
        .route(
            "/saml/:id",
            get(get_saml).put(update_saml).delete(delete_saml),
        )
        .route("/saml/:id/toggle", patch(toggle_saml))
        // All enabled providers
        .route("/providers", get(list_providers))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn require_admin(auth: &AuthExtension) -> Result<()> {
    if !auth.is_admin {
        return Err(AppError::Unauthorized("Admin required".into()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// OIDC
// ---------------------------------------------------------------------------

/// List all OIDC provider configurations
#[utoipa::path(
    get,
    path = "/oidc",
    context_path = "/api/v1/admin/sso",
    tag = "sso",
    responses(
        (status = 200, description = "List of OIDC configurations", body = Vec<OidcConfigResponse>),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_oidc(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<Vec<OidcConfigResponse>>> {
    require_admin(&auth)?;
    let result = AuthConfigService::list_oidc(&state.db).await?;
    Ok(Json(result))
}

/// Get OIDC provider configuration by ID
#[utoipa::path(
    get,
    path = "/oidc/{id}",
    context_path = "/api/v1/admin/sso",
    tag = "sso",
    params(
        ("id" = Uuid, Path, description = "OIDC configuration ID")
    ),
    responses(
        (status = 200, description = "OIDC configuration details", body = OidcConfigResponse),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Configuration not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_oidc(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<OidcConfigResponse>> {
    require_admin(&auth)?;
    let result = AuthConfigService::get_oidc(&state.db, id).await?;
    Ok(Json(result))
}

/// Create a new OIDC provider configuration
#[utoipa::path(
    post,
    path = "/oidc",
    context_path = "/api/v1/admin/sso",
    tag = "sso",
    request_body = CreateOidcConfigRequest,
    responses(
        (status = 200, description = "OIDC configuration created", body = OidcConfigResponse),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_oidc(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(req): Json<CreateOidcConfigRequest>,
) -> Result<Json<OidcConfigResponse>> {
    require_admin(&auth)?;
    let result = AuthConfigService::create_oidc(&state.db, req).await?;
    Ok(Json(result))
}

/// Update an OIDC provider configuration
#[utoipa::path(
    put,
    path = "/oidc/{id}",
    context_path = "/api/v1/admin/sso",
    tag = "sso",
    params(
        ("id" = Uuid, Path, description = "OIDC configuration ID")
    ),
    request_body = UpdateOidcConfigRequest,
    responses(
        (status = 200, description = "OIDC configuration updated", body = OidcConfigResponse),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Configuration not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_oidc(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateOidcConfigRequest>,
) -> Result<Json<OidcConfigResponse>> {
    require_admin(&auth)?;
    let result = AuthConfigService::update_oidc(&state.db, id, req).await?;
    Ok(Json(result))
}

/// Delete an OIDC provider configuration
#[utoipa::path(
    delete,
    path = "/oidc/{id}",
    context_path = "/api/v1/admin/sso",
    tag = "sso",
    params(
        ("id" = Uuid, Path, description = "OIDC configuration ID")
    ),
    responses(
        (status = 200, description = "OIDC configuration deleted"),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Configuration not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_oidc(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    require_admin(&auth)?;
    AuthConfigService::delete_oidc(&state.db, id).await?;
    Ok(())
}

/// Toggle an OIDC provider enabled/disabled
#[utoipa::path(
    patch,
    path = "/oidc/{id}/toggle",
    context_path = "/api/v1/admin/sso",
    tag = "sso",
    params(
        ("id" = Uuid, Path, description = "OIDC configuration ID")
    ),
    request_body = ToggleRequest,
    responses(
        (status = 200, description = "OIDC configuration toggled"),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Configuration not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn toggle_oidc(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(req): Json<ToggleRequest>,
) -> Result<()> {
    require_admin(&auth)?;
    AuthConfigService::toggle_oidc(&state.db, id, req).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// LDAP
// ---------------------------------------------------------------------------

/// List all LDAP provider configurations
#[utoipa::path(
    get,
    path = "/ldap",
    context_path = "/api/v1/admin/sso",
    tag = "sso",
    responses(
        (status = 200, description = "List of LDAP configurations", body = Vec<LdapConfigResponse>),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_ldap(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<Vec<LdapConfigResponse>>> {
    require_admin(&auth)?;
    let result = AuthConfigService::list_ldap(&state.db).await?;
    Ok(Json(result))
}

/// Get LDAP provider configuration by ID
#[utoipa::path(
    get,
    path = "/ldap/{id}",
    context_path = "/api/v1/admin/sso",
    tag = "sso",
    params(
        ("id" = Uuid, Path, description = "LDAP configuration ID")
    ),
    responses(
        (status = 200, description = "LDAP configuration details", body = LdapConfigResponse),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Configuration not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_ldap(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<LdapConfigResponse>> {
    require_admin(&auth)?;
    let result = AuthConfigService::get_ldap(&state.db, id).await?;
    Ok(Json(result))
}

/// Create a new LDAP provider configuration
#[utoipa::path(
    post,
    path = "/ldap",
    context_path = "/api/v1/admin/sso",
    tag = "sso",
    request_body = CreateLdapConfigRequest,
    responses(
        (status = 200, description = "LDAP configuration created", body = LdapConfigResponse),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_ldap(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(req): Json<CreateLdapConfigRequest>,
) -> Result<Json<LdapConfigResponse>> {
    require_admin(&auth)?;
    let result = AuthConfigService::create_ldap(&state.db, req).await?;
    Ok(Json(result))
}

/// Update an LDAP provider configuration
#[utoipa::path(
    put,
    path = "/ldap/{id}",
    context_path = "/api/v1/admin/sso",
    tag = "sso",
    params(
        ("id" = Uuid, Path, description = "LDAP configuration ID")
    ),
    request_body = UpdateLdapConfigRequest,
    responses(
        (status = 200, description = "LDAP configuration updated", body = LdapConfigResponse),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Configuration not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_ldap(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateLdapConfigRequest>,
) -> Result<Json<LdapConfigResponse>> {
    require_admin(&auth)?;
    let result = AuthConfigService::update_ldap(&state.db, id, req).await?;
    Ok(Json(result))
}

/// Delete an LDAP provider configuration
#[utoipa::path(
    delete,
    path = "/ldap/{id}",
    context_path = "/api/v1/admin/sso",
    tag = "sso",
    params(
        ("id" = Uuid, Path, description = "LDAP configuration ID")
    ),
    responses(
        (status = 200, description = "LDAP configuration deleted"),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Configuration not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_ldap(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    require_admin(&auth)?;
    AuthConfigService::delete_ldap(&state.db, id).await?;
    Ok(())
}

/// Toggle an LDAP provider enabled/disabled
#[utoipa::path(
    patch,
    path = "/ldap/{id}/toggle",
    context_path = "/api/v1/admin/sso",
    tag = "sso",
    params(
        ("id" = Uuid, Path, description = "LDAP configuration ID")
    ),
    request_body = ToggleRequest,
    responses(
        (status = 200, description = "LDAP configuration toggled"),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Configuration not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn toggle_ldap(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(req): Json<ToggleRequest>,
) -> Result<()> {
    require_admin(&auth)?;
    AuthConfigService::toggle_ldap(&state.db, id, req).await?;
    Ok(())
}

/// Test an LDAP provider connection
#[utoipa::path(
    post,
    path = "/ldap/{id}/test",
    context_path = "/api/v1/admin/sso",
    tag = "sso",
    params(
        ("id" = Uuid, Path, description = "LDAP configuration ID")
    ),
    responses(
        (status = 200, description = "LDAP connection test result", body = LdapTestResult),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Configuration not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn test_ldap(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<LdapTestResult>> {
    require_admin(&auth)?;
    let result = AuthConfigService::test_ldap_connection(&state.db, id).await?;
    Ok(Json(result))
}

// ---------------------------------------------------------------------------
// SAML
// ---------------------------------------------------------------------------

/// List all SAML provider configurations
#[utoipa::path(
    get,
    path = "/saml",
    context_path = "/api/v1/admin/sso",
    tag = "sso",
    responses(
        (status = 200, description = "List of SAML configurations", body = Vec<SamlConfigResponse>),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_saml(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<Vec<SamlConfigResponse>>> {
    require_admin(&auth)?;
    let result = AuthConfigService::list_saml(&state.db).await?;
    Ok(Json(result))
}

/// Get SAML provider configuration by ID
#[utoipa::path(
    get,
    path = "/saml/{id}",
    context_path = "/api/v1/admin/sso",
    tag = "sso",
    params(
        ("id" = Uuid, Path, description = "SAML configuration ID")
    ),
    responses(
        (status = 200, description = "SAML configuration details", body = SamlConfigResponse),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Configuration not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_saml(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<SamlConfigResponse>> {
    require_admin(&auth)?;
    let result = AuthConfigService::get_saml(&state.db, id).await?;
    Ok(Json(result))
}

/// Create a new SAML provider configuration
#[utoipa::path(
    post,
    path = "/saml",
    context_path = "/api/v1/admin/sso",
    tag = "sso",
    request_body = CreateSamlConfigRequest,
    responses(
        (status = 200, description = "SAML configuration created", body = SamlConfigResponse),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_saml(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(req): Json<CreateSamlConfigRequest>,
) -> Result<Json<SamlConfigResponse>> {
    require_admin(&auth)?;
    let result = AuthConfigService::create_saml(&state.db, req).await?;
    Ok(Json(result))
}

/// Update a SAML provider configuration
#[utoipa::path(
    put,
    path = "/saml/{id}",
    context_path = "/api/v1/admin/sso",
    tag = "sso",
    params(
        ("id" = Uuid, Path, description = "SAML configuration ID")
    ),
    request_body = UpdateSamlConfigRequest,
    responses(
        (status = 200, description = "SAML configuration updated", body = SamlConfigResponse),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Configuration not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_saml(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateSamlConfigRequest>,
) -> Result<Json<SamlConfigResponse>> {
    require_admin(&auth)?;
    let result = AuthConfigService::update_saml(&state.db, id, req).await?;
    Ok(Json(result))
}

/// Delete a SAML provider configuration
#[utoipa::path(
    delete,
    path = "/saml/{id}",
    context_path = "/api/v1/admin/sso",
    tag = "sso",
    params(
        ("id" = Uuid, Path, description = "SAML configuration ID")
    ),
    responses(
        (status = 200, description = "SAML configuration deleted"),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Configuration not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_saml(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    require_admin(&auth)?;
    AuthConfigService::delete_saml(&state.db, id).await?;
    Ok(())
}

/// Toggle a SAML provider enabled/disabled
#[utoipa::path(
    patch,
    path = "/saml/{id}/toggle",
    context_path = "/api/v1/admin/sso",
    tag = "sso",
    params(
        ("id" = Uuid, Path, description = "SAML configuration ID")
    ),
    request_body = ToggleRequest,
    responses(
        (status = 200, description = "SAML configuration toggled"),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Configuration not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn toggle_saml(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(req): Json<ToggleRequest>,
) -> Result<()> {
    require_admin(&auth)?;
    AuthConfigService::toggle_saml(&state.db, id, req).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// All providers
// ---------------------------------------------------------------------------

/// List all enabled SSO providers (admin view)
#[utoipa::path(
    get,
    path = "/providers",
    context_path = "/api/v1/admin/sso",
    tag = "sso",
    responses(
        (status = 200, description = "List of enabled SSO providers", body = Vec<SsoProviderInfo>),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_providers(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<Vec<SsoProviderInfo>>> {
    require_admin(&auth)?;
    let result = AuthConfigService::list_enabled_providers(&state.db).await?;
    Ok(Json(result))
}

#[derive(OpenApi)]
#[openapi(
    paths(
        list_oidc,
        get_oidc,
        create_oidc,
        update_oidc,
        delete_oidc,
        toggle_oidc,
        list_ldap,
        get_ldap,
        create_ldap,
        update_ldap,
        delete_ldap,
        toggle_ldap,
        test_ldap,
        list_saml,
        get_saml,
        create_saml,
        update_saml,
        delete_saml,
        toggle_saml,
        list_providers,
    ),
    components(schemas(
        OidcConfigResponse,
        LdapConfigResponse,
        SamlConfigResponse,
        CreateOidcConfigRequest,
        UpdateOidcConfigRequest,
        CreateLdapConfigRequest,
        UpdateLdapConfigRequest,
        CreateSamlConfigRequest,
        UpdateSamlConfigRequest,
        ToggleRequest,
        LdapTestResult,
        SsoProviderInfo,
    ))
)]
pub struct SsoAdminApiDoc;
