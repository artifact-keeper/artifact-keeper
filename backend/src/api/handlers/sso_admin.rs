//! SSO administration handlers (OIDC, LDAP, SAML config CRUD).
//!
//! All endpoints require admin privileges.

use axum::{
    extract::{Extension, Path, State},
    routing::{get, patch, post},
    Json, Router,
};
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

async fn list_oidc(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<Vec<OidcConfigResponse>>> {
    require_admin(&auth)?;
    let result = AuthConfigService::list_oidc(&state.db).await?;
    Ok(Json(result))
}

async fn get_oidc(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<OidcConfigResponse>> {
    require_admin(&auth)?;
    let result = AuthConfigService::get_oidc(&state.db, id).await?;
    Ok(Json(result))
}

async fn create_oidc(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(req): Json<CreateOidcConfigRequest>,
) -> Result<Json<OidcConfigResponse>> {
    require_admin(&auth)?;
    let result = AuthConfigService::create_oidc(&state.db, req).await?;
    Ok(Json(result))
}

async fn update_oidc(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateOidcConfigRequest>,
) -> Result<Json<OidcConfigResponse>> {
    require_admin(&auth)?;
    let result = AuthConfigService::update_oidc(&state.db, id, req).await?;
    Ok(Json(result))
}

async fn delete_oidc(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    require_admin(&auth)?;
    AuthConfigService::delete_oidc(&state.db, id).await?;
    Ok(())
}

async fn toggle_oidc(
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

async fn list_ldap(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<Vec<LdapConfigResponse>>> {
    require_admin(&auth)?;
    let result = AuthConfigService::list_ldap(&state.db).await?;
    Ok(Json(result))
}

async fn get_ldap(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<LdapConfigResponse>> {
    require_admin(&auth)?;
    let result = AuthConfigService::get_ldap(&state.db, id).await?;
    Ok(Json(result))
}

async fn create_ldap(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(req): Json<CreateLdapConfigRequest>,
) -> Result<Json<LdapConfigResponse>> {
    require_admin(&auth)?;
    let result = AuthConfigService::create_ldap(&state.db, req).await?;
    Ok(Json(result))
}

async fn update_ldap(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateLdapConfigRequest>,
) -> Result<Json<LdapConfigResponse>> {
    require_admin(&auth)?;
    let result = AuthConfigService::update_ldap(&state.db, id, req).await?;
    Ok(Json(result))
}

async fn delete_ldap(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    require_admin(&auth)?;
    AuthConfigService::delete_ldap(&state.db, id).await?;
    Ok(())
}

async fn toggle_ldap(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(req): Json<ToggleRequest>,
) -> Result<()> {
    require_admin(&auth)?;
    AuthConfigService::toggle_ldap(&state.db, id, req).await?;
    Ok(())
}

async fn test_ldap(
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

async fn list_saml(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<Vec<SamlConfigResponse>>> {
    require_admin(&auth)?;
    let result = AuthConfigService::list_saml(&state.db).await?;
    Ok(Json(result))
}

async fn get_saml(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<SamlConfigResponse>> {
    require_admin(&auth)?;
    let result = AuthConfigService::get_saml(&state.db, id).await?;
    Ok(Json(result))
}

async fn create_saml(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(req): Json<CreateSamlConfigRequest>,
) -> Result<Json<SamlConfigResponse>> {
    require_admin(&auth)?;
    let result = AuthConfigService::create_saml(&state.db, req).await?;
    Ok(Json(result))
}

async fn update_saml(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateSamlConfigRequest>,
) -> Result<Json<SamlConfigResponse>> {
    require_admin(&auth)?;
    let result = AuthConfigService::update_saml(&state.db, id, req).await?;
    Ok(Json(result))
}

async fn delete_saml(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    require_admin(&auth)?;
    AuthConfigService::delete_saml(&state.db, id).await?;
    Ok(())
}

async fn toggle_saml(
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

async fn list_providers(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<Vec<SsoProviderInfo>>> {
    require_admin(&auth)?;
    let result = AuthConfigService::list_enabled_providers(&state.db).await?;
    Ok(Json(result))
}
