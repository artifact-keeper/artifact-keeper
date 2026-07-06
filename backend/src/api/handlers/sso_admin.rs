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
use crate::error::Result;
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
    auth.require_admin()?;
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
    auth.require_admin()?;
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
    auth.require_admin()?;
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
    auth.require_admin()?;
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
    auth.require_admin()?;
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
    auth.require_admin()?;
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
    auth.require_admin()?;
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
    auth.require_admin()?;
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
    auth.require_admin()?;
    crate::api::validation::validate_outbound_ldap_url(&req.server_url, "LDAP server URL")?;
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
    auth.require_admin()?;
    if let Some(server_url) = &req.server_url {
        crate::api::validation::validate_outbound_ldap_url(server_url, "LDAP server URL")?;
    }
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
    auth.require_admin()?;
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
    auth.require_admin()?;
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
    auth.require_admin()?;
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
    auth.require_admin()?;
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
    auth.require_admin()?;
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
    auth.require_admin()?;
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
    auth.require_admin()?;
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
    auth.require_admin()?;
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
    auth.require_admin()?;
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
    operation_id = "list_sso_providers_admin",
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
    auth.require_admin()?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -----------------------------------------------------------------------
    // require_admin tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_require_admin_passes_for_admin() {
        let auth = AuthExtension {
            user_id: Uuid::new_v4(),
            username: "admin".to_string(),
            email: "admin@example.com".to_string(),
            is_admin: true,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: None,
        };
        assert!(auth.require_admin().is_ok());
    }

    #[test]
    fn test_require_admin_fails_for_non_admin() {
        let auth = AuthExtension {
            user_id: Uuid::new_v4(),
            username: "user".to_string(),
            email: "user@example.com".to_string(),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: None,
        };
        let err = auth.require_admin().unwrap_err();
        assert!(
            format!("{}", err).contains("Admin access required"),
            "Expected 'Admin access required' in error: {}",
            err
        );
    }

    #[test]
    fn test_require_admin_fails_even_with_api_token() {
        let auth = AuthExtension {
            user_id: Uuid::new_v4(),
            username: "api-user".to_string(),
            email: "api@example.com".to_string(),
            is_admin: false,
            is_api_token: true,
            is_service_account: false,
            scopes: Some(vec!["read".to_string(), "write".to_string()]),
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: None,
        };
        assert!(auth.require_admin().is_err());
    }

    #[test]
    fn test_require_admin_passes_for_admin_api_token() {
        let auth = AuthExtension {
            user_id: Uuid::new_v4(),
            username: "admin-api".to_string(),
            email: "admin-api@example.com".to_string(),
            is_admin: true,
            is_api_token: true,
            is_service_account: false,
            scopes: Some(vec!["admin".to_string()]),
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: None,
        };
        assert!(auth.require_admin().is_ok());
    }

    // -----------------------------------------------------------------------
    // Admin gate is enforced at the top of every route handler
    // -----------------------------------------------------------------------

    // Assert that a handler result is the canonical 403 admin-denial. The gate
    // runs before any database access, so these calls short-circuit on a lazy
    // (never-connected) pool.
    fn assert_admin_denied<T>(res: crate::error::Result<T>) {
        match res {
            Err(crate::error::AppError::Authorization(msg)) => {
                assert_eq!(msg, "Admin access required")
            }
            Err(other) => panic!("expected admin denial, got error: {other}"),
            Ok(_) => panic!("expected admin denial, got Ok"),
        }
    }

    #[tokio::test]
    async fn non_admin_denied_on_every_sso_admin_route() {
        use crate::api::handlers::test_db_helpers as tdh;

        let dir = std::env::temp_dir().join(format!("ph-sso-admin-{}", Uuid::new_v4()));
        let state = tdh::build_state(tdh::lazy_pool(), dir.to_str().unwrap());
        let auth = tdh::make_auth(Uuid::new_v4(), "not-admin");
        let id = Uuid::new_v4();

        // OIDC
        assert_admin_denied(list_oidc(State(state.clone()), Extension(auth.clone())).await);
        assert_admin_denied(
            get_oidc(State(state.clone()), Extension(auth.clone()), Path(id)).await,
        );
        assert_admin_denied(
            create_oidc(
                State(state.clone()),
                Extension(auth.clone()),
                Json(
                    serde_json::from_value(json!({
                        "name": "x",
                        "issuer_url": "https://issuer.example.com",
                        "client_id": "c",
                        "client_secret": "s"
                    }))
                    .unwrap(),
                ),
            )
            .await,
        );
        assert_admin_denied(
            update_oidc(
                State(state.clone()),
                Extension(auth.clone()),
                Path(id),
                Json(serde_json::from_value(json!({})).unwrap()),
            )
            .await,
        );
        assert_admin_denied(
            delete_oidc(State(state.clone()), Extension(auth.clone()), Path(id)).await,
        );
        assert_admin_denied(
            toggle_oidc(
                State(state.clone()),
                Extension(auth.clone()),
                Path(id),
                Json(serde_json::from_value(json!({"enabled": true})).unwrap()),
            )
            .await,
        );

        // LDAP
        assert_admin_denied(list_ldap(State(state.clone()), Extension(auth.clone())).await);
        assert_admin_denied(
            get_ldap(State(state.clone()), Extension(auth.clone()), Path(id)).await,
        );
        assert_admin_denied(
            create_ldap(
                State(state.clone()),
                Extension(auth.clone()),
                Json(
                    serde_json::from_value(json!({
                        "name": "x",
                        "server_url": "ldaps://ldap.example.com:636",
                        "user_base_dn": "ou=u,dc=example,dc=com"
                    }))
                    .unwrap(),
                ),
            )
            .await,
        );
        assert_admin_denied(
            update_ldap(
                State(state.clone()),
                Extension(auth.clone()),
                Path(id),
                Json(serde_json::from_value(json!({})).unwrap()),
            )
            .await,
        );
        assert_admin_denied(
            delete_ldap(State(state.clone()), Extension(auth.clone()), Path(id)).await,
        );
        assert_admin_denied(
            toggle_ldap(
                State(state.clone()),
                Extension(auth.clone()),
                Path(id),
                Json(serde_json::from_value(json!({"enabled": false})).unwrap()),
            )
            .await,
        );
        assert_admin_denied(
            test_ldap(State(state.clone()), Extension(auth.clone()), Path(id)).await,
        );

        // SAML
        assert_admin_denied(list_saml(State(state.clone()), Extension(auth.clone())).await);
        assert_admin_denied(
            get_saml(State(state.clone()), Extension(auth.clone()), Path(id)).await,
        );
        assert_admin_denied(
            create_saml(
                State(state.clone()),
                Extension(auth.clone()),
                Json(
                    serde_json::from_value(json!({
                        "name": "x",
                        "entity_id": "urn:entity",
                        "sso_url": "https://sso.example.com",
                        "certificate": "cert"
                    }))
                    .unwrap(),
                ),
            )
            .await,
        );
        assert_admin_denied(
            update_saml(
                State(state.clone()),
                Extension(auth.clone()),
                Path(id),
                Json(serde_json::from_value(json!({})).unwrap()),
            )
            .await,
        );
        assert_admin_denied(
            delete_saml(State(state.clone()), Extension(auth.clone()), Path(id)).await,
        );
        assert_admin_denied(
            toggle_saml(
                State(state.clone()),
                Extension(auth.clone()),
                Path(id),
                Json(serde_json::from_value(json!({"enabled": true})).unwrap()),
            )
            .await,
        );

        // Providers
        assert_admin_denied(list_providers(State(state.clone()), Extension(auth.clone())).await);
    }

    // -----------------------------------------------------------------------
    // CreateOidcConfigRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_oidc_request_deserialize_minimal() {
        let json = json!({
            "name": "Okta",
            "issuer_url": "https://dev-123.okta.com",
            "client_id": "client-id-123",
            "client_secret": "secret-456"
        });
        let req: CreateOidcConfigRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.name, "Okta");
        assert_eq!(req.issuer_url, "https://dev-123.okta.com");
        assert_eq!(req.client_id, "client-id-123");
        assert_eq!(req.client_secret, "secret-456");
        assert!(req.scopes.is_none());
        assert!(req.attribute_mapping.is_none());
        assert!(req.is_enabled.is_none());
        assert!(req.auto_create_users.is_none());
    }

    #[test]
    fn test_create_oidc_request_deserialize_full() {
        let json = json!({
            "name": "Azure AD",
            "issuer_url": "https://login.microsoftonline.com/tenant-id/v2.0",
            "client_id": "azure-client",
            "client_secret": "azure-secret",
            "scopes": ["openid", "profile", "email"],
            "attribute_mapping": {"email": "preferred_username"},
            "is_enabled": true,
            "auto_create_users": false
        });
        let req: CreateOidcConfigRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.scopes.as_ref().unwrap().len(), 3);
        assert!(req.is_enabled.unwrap());
        assert!(!req.auto_create_users.unwrap());
    }

    // -----------------------------------------------------------------------
    // UpdateOidcConfigRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_update_oidc_request_all_none() {
        let json = json!({});
        let req: UpdateOidcConfigRequest = serde_json::from_value(json).unwrap();
        assert!(req.name.is_none());
        assert!(req.issuer_url.is_none());
        assert!(req.client_id.is_none());
        assert!(req.client_secret.is_none());
        assert!(req.scopes.is_none());
        assert!(req.attribute_mapping.is_none());
        assert!(req.is_enabled.is_none());
        assert!(req.auto_create_users.is_none());
    }

    #[test]
    fn test_update_oidc_request_partial() {
        let json = json!({
            "name": "Updated Name",
            "is_enabled": false
        });
        let req: UpdateOidcConfigRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.name.as_deref(), Some("Updated Name"));
        assert_eq!(req.is_enabled, Some(false));
        assert!(req.issuer_url.is_none());
    }

    // -----------------------------------------------------------------------
    // CreateLdapConfigRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_ldap_request_deserialize_minimal() {
        let json = json!({
            "name": "Corporate LDAP",
            "server_url": "ldaps://ldap.example.com:636",
            "user_base_dn": "ou=users,dc=example,dc=com"
        });
        let req: CreateLdapConfigRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.name, "Corporate LDAP");
        assert_eq!(req.server_url, "ldaps://ldap.example.com:636");
        assert_eq!(req.user_base_dn, "ou=users,dc=example,dc=com");
        assert!(req.bind_dn.is_none());
        assert!(req.bind_password.is_none());
        assert!(req.user_filter.is_none());
        assert!(req.use_starttls.is_none());
        assert!(req.is_enabled.is_none());
    }

    #[test]
    fn test_create_ldap_request_deserialize_full() {
        let json = json!({
            "name": "Corp LDAP",
            "server_url": "ldap://ldap.corp.com",
            "bind_dn": "cn=admin,dc=corp,dc=com",
            "bind_password": "admin-pass",
            "user_base_dn": "ou=people,dc=corp,dc=com",
            "user_filter": "(objectClass=inetOrgPerson)",
            "group_base_dn": "ou=groups,dc=corp,dc=com",
            "group_filter": "(objectClass=groupOfNames)",
            "email_attribute": "mail",
            "display_name_attribute": "cn",
            "username_attribute": "uid",
            "groups_attribute": "memberOf",
            "admin_group_dn": "cn=admins,ou=groups,dc=corp,dc=com",
            "use_starttls": true,
            "is_enabled": true,
            "priority": 10
        });
        let req: CreateLdapConfigRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.bind_dn.as_deref(), Some("cn=admin,dc=corp,dc=com"));
        assert!(req.use_starttls.unwrap());
        assert_eq!(req.priority, Some(10));
        assert_eq!(req.email_attribute.as_deref(), Some("mail"));
    }

    // -----------------------------------------------------------------------
    // CreateSamlConfigRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_saml_request_deserialize() {
        let json = json!({
            "name": "Okta SAML",
            "entity_id": "http://www.okta.com/exk1234",
            "sso_url": "https://dev-123.okta.com/app/exk1234/sso/saml",
            "certificate": "MIIDpDCCA...",
            "sp_entity_id": "https://registry.example.com/saml/metadata"
        });
        let req: CreateSamlConfigRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.name, "Okta SAML");
        assert_eq!(req.entity_id, "http://www.okta.com/exk1234");
        assert_eq!(
            req.sp_entity_id,
            Some("https://registry.example.com/saml/metadata".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // ToggleRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_toggle_request_enabled() {
        let json = json!({"enabled": true});
        let req: ToggleRequest = serde_json::from_value(json).unwrap();
        assert!(req.enabled);
    }

    #[test]
    fn test_toggle_request_disabled() {
        let json = json!({"enabled": false});
        let req: ToggleRequest = serde_json::from_value(json).unwrap();
        assert!(!req.enabled);
    }

    // -----------------------------------------------------------------------
    // OidcConfigResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_oidc_config_response_serialize() {
        let resp = OidcConfigResponse {
            id: Uuid::nil(),
            name: "Test OIDC".to_string(),
            issuer_url: "https://issuer.example.com".to_string(),
            client_id: "client-abc".to_string(),
            has_secret: true,
            scopes: vec!["openid".to_string(), "profile".to_string()],
            attribute_mapping: json!({"email": "email"}),
            is_enabled: true,
            auto_create_users: false,
            pkce_enabled: true,
            map_groups_to_groups: false,
            allow_legacy_rsa_keys: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["name"], "Test OIDC");
        assert_eq!(json["has_secret"], true);
        assert_eq!(json["scopes"].as_array().unwrap().len(), 2);
        assert!(json["is_enabled"].as_bool().unwrap());
        assert!(!json["auto_create_users"].as_bool().unwrap());
        assert!(json["pkce_enabled"].as_bool().unwrap());
        assert!(!json["map_groups_to_groups"].as_bool().unwrap());
    }

    #[test]
    fn test_update_oidc_request_pkce_and_group_mapping_fields() {
        let json = json!({
            "pkce_enabled": false,
            "map_groups_to_groups": true,
            "attribute_mapping_replace": true,
        });
        let req: UpdateOidcConfigRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.pkce_enabled, Some(false));
        assert_eq!(req.map_groups_to_groups, Some(true));
        assert_eq!(req.attribute_mapping_replace, Some(true));
    }

    #[test]
    fn test_create_oidc_request_pkce_default_unset() {
        let json = json!({
            "name": "Okta",
            "issuer_url": "https://example.okta.com",
            "client_id": "c",
            "client_secret": "s"
        });
        let req: CreateOidcConfigRequest = serde_json::from_value(json).unwrap();
        // Default is None at the wire layer; the service applies `true`.
        assert!(req.pkce_enabled.is_none());
        assert!(req.map_groups_to_groups.is_none());
    }

    // -----------------------------------------------------------------------
    // LdapConfigResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_ldap_config_response_serialize() {
        let resp = LdapConfigResponse {
            id: Uuid::nil(),
            name: "Test LDAP".to_string(),
            server_url: "ldaps://ldap.example.com".to_string(),
            bind_dn: Some("cn=admin,dc=example,dc=com".to_string()),
            has_bind_password: true,
            user_base_dn: "ou=users,dc=example,dc=com".to_string(),
            user_filter: "(objectClass=person)".to_string(),
            group_base_dn: None,
            group_filter: None,
            email_attribute: "mail".to_string(),
            display_name_attribute: "cn".to_string(),
            username_attribute: "uid".to_string(),
            groups_attribute: "memberOf".to_string(),
            admin_group_dn: None,
            use_starttls: false,
            is_enabled: true,
            priority: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["name"], "Test LDAP");
        assert_eq!(json["has_bind_password"], true);
        assert_eq!(json["priority"], 1);
        assert!(json["group_base_dn"].is_null());
    }

    // -----------------------------------------------------------------------
    // SamlConfigResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_saml_config_response_serialize() {
        let resp = SamlConfigResponse {
            id: Uuid::nil(),
            name: "Test SAML".to_string(),
            entity_id: "http://idp.example.com".to_string(),
            sso_url: "https://idp.example.com/sso".to_string(),
            slo_url: Some("https://idp.example.com/slo".to_string()),
            has_certificate: true,
            name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string(),
            attribute_mapping: json!({"email": "user.email"}),
            sp_entity_id: "https://sp.example.com/metadata".to_string(),
            sign_requests: true,
            require_signed_assertions: true,
            admin_group: Some("admin-group".to_string()),
            is_enabled: false,
            use_absolute_acs_url: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["name"], "Test SAML");
        assert!(json["sign_requests"].as_bool().unwrap());
        assert!(json["require_signed_assertions"].as_bool().unwrap());
        assert!(!json["is_enabled"].as_bool().unwrap());
        assert_eq!(json["slo_url"], "https://idp.example.com/slo");
    }

    // -----------------------------------------------------------------------
    // SsoProviderInfo serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_sso_provider_info_serialize() {
        let info = SsoProviderInfo::new(Uuid::nil(), "My OIDC Provider".to_string(), "oidc");
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["provider_type"], "oidc");
        assert!(json["login_url"].as_str().unwrap().contains("/login"));
    }

    // -----------------------------------------------------------------------
    // LdapTestResult serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_ldap_test_result_success() {
        let result = LdapTestResult {
            success: true,
            message: "Connection successful".to_string(),
            response_time_ms: 45,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert!(json["success"].as_bool().unwrap());
        assert_eq!(json["response_time_ms"], 45);
    }

    #[test]
    fn test_ldap_test_result_failure() {
        let result = LdapTestResult {
            success: false,
            message: "Connection timed out".to_string(),
            response_time_ms: 30000,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert!(!json["success"].as_bool().unwrap());
        assert!(json["message"].as_str().unwrap().contains("timed out"));
    }
}
