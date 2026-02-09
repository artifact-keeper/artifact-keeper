//! Public SSO flow endpoints (no auth middleware required).
//!
//! Handles OIDC login redirects, callbacks, and SAML endpoints.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::handlers::auth::set_auth_cookies;

use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::user::AuthProvider;
use crate::services::auth_config_service::AuthConfigService;
use crate::services::auth_config_service::SsoProviderInfo;
use crate::services::auth_service::{AuthService, FederatedCredentials};
use crate::services::ldap_service::LdapService;
use crate::services::saml_service::SamlService;

/// Create public SSO routes (no auth required)
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/providers", get(list_providers))
        .route("/oidc/:id/login", get(oidc_login))
        .route("/oidc/:id/callback", get(oidc_callback))
        .route("/ldap/:id/login", post(ldap_login))
        .route("/saml/:id/login", get(saml_login))
        .route("/saml/:id/acs", post(saml_acs))
        .route("/exchange", post(exchange_code))
}

// ---------------------------------------------------------------------------
// List enabled providers (public)
// ---------------------------------------------------------------------------

/// List all enabled SSO providers
#[utoipa::path(
    get,
    path = "/providers",
    context_path = "/api/v1/auth/sso",
    tag = "sso",
    responses(
        (status = 200, description = "List of enabled SSO providers", body = Vec<SsoProviderInfo>),
    )
)]
pub async fn list_providers(
    State(state): State<SharedState>,
) -> Result<Json<Vec<SsoProviderInfo>>> {
    let result = AuthConfigService::list_enabled_providers(&state.db).await?;
    Ok(Json(result))
}

// ---------------------------------------------------------------------------
// OIDC login redirect
// ---------------------------------------------------------------------------

/// Initiate OIDC login redirect
#[utoipa::path(
    get,
    path = "/oidc/{id}/login",
    context_path = "/api/v1/auth/sso",
    tag = "sso",
    params(
        ("id" = Uuid, Path, description = "OIDC provider configuration ID")
    ),
    responses(
        (status = 307, description = "Redirect to OIDC authorization endpoint"),
        (status = 404, description = "OIDC provider not found", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn oidc_login(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Redirect> {
    // 1. Get decrypted OIDC config
    let (row, _client_secret) = AuthConfigService::get_oidc_decrypted(&state.db, id).await?;

    // 2. Create SSO session for CSRF protection (generates state + nonce internally)
    let session = AuthConfigService::create_sso_session(&state.db, "oidc", id).await?;
    let state_str = session.state;
    let nonce_str = session.nonce.unwrap_or_default();

    // 3. Fetch OIDC discovery document to find authorization_endpoint
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        row.issuer_url.trim_end_matches('/')
    );

    let http_client = reqwest::Client::new();
    let discovery: serde_json::Value = http_client
        .get(&discovery_url)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch OIDC discovery: {e}")))?
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to parse OIDC discovery: {e}")))?;

    let authorization_endpoint = discovery["authorization_endpoint"]
        .as_str()
        .ok_or_else(|| {
            AppError::Internal("OIDC discovery missing authorization_endpoint".into())
        })?;

    // 4. Build redirect_uri (default to our callback endpoint)
    let redirect_uri = format!("/api/v1/auth/sso/oidc/{id}/callback");

    // 5. Build authorization URL
    let scope = if row.scopes.is_empty() {
        "openid profile email".to_string()
    } else {
        row.scopes.join(" ")
    };

    let auth_url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}",
        authorization_endpoint,
        urlencoding::encode(&row.client_id),
        urlencoding::encode(&redirect_uri),
        urlencoding::encode(&scope),
        urlencoding::encode(&state_str),
        urlencoding::encode(&nonce_str),
    );

    Ok(Redirect::temporary(&auth_url))
}

// ---------------------------------------------------------------------------
// OIDC callback
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, IntoParams)]
pub struct OidcCallbackQuery {
    code: String,
    state: String,
}

/// Handle OIDC authorization callback
#[utoipa::path(
    get,
    path = "/oidc/{id}/callback",
    context_path = "/api/v1/auth/sso",
    tag = "sso",
    params(
        ("id" = Uuid, Path, description = "OIDC provider configuration ID"),
        OidcCallbackQuery,
    ),
    responses(
        (status = 307, description = "Redirect to frontend with exchange code"),
        (status = 400, description = "Invalid callback parameters", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn oidc_callback(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Query(params): Query<OidcCallbackQuery>,
) -> Result<Redirect> {
    // 1. Validate SSO session (CSRF check)
    let _session = AuthConfigService::validate_sso_session(&state.db, &params.state).await?;

    // 2. Get decrypted OIDC config
    let (row, client_secret) = AuthConfigService::get_oidc_decrypted(&state.db, id).await?;

    // 3. Fetch OIDC discovery for token_endpoint
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        row.issuer_url.trim_end_matches('/')
    );

    let http_client = reqwest::Client::new();
    let discovery: serde_json::Value = http_client
        .get(&discovery_url)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch OIDC discovery: {e}")))?
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to parse OIDC discovery: {e}")))?;

    let token_endpoint = discovery["token_endpoint"]
        .as_str()
        .ok_or_else(|| AppError::Internal("OIDC discovery missing token_endpoint".into()))?;

    // 4. Build redirect_uri (must match the one used in the login request)
    let redirect_uri = format!("/api/v1/auth/sso/oidc/{id}/callback");

    // 5. Exchange authorization code for tokens
    let token_response: serde_json::Value = http_client
        .post(token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &params.code),
            ("redirect_uri", &redirect_uri),
            ("client_id", &row.client_id),
            ("client_secret", &client_secret),
        ])
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Token exchange failed: {e}")))?
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to parse token response: {e}")))?;

    let id_token = token_response["id_token"]
        .as_str()
        .ok_or_else(|| AppError::Internal("Token response missing id_token".into()))?;

    // 6. Decode JWT payload (base64 decode the middle segment)
    let claims = decode_jwt_payload(id_token)?;

    // 7. Extract user claims
    let sub = claims["sub"]
        .as_str()
        .ok_or_else(|| AppError::Internal("ID token missing sub claim".into()))?
        .to_string();

    let email = claims["email"].as_str().unwrap_or_default().to_string();

    let preferred_username = claims["preferred_username"]
        .as_str()
        .or_else(|| claims["email"].as_str())
        .unwrap_or(&sub)
        .to_string();

    let display_name = claims["name"].as_str().map(|s| s.to_string());

    let groups = claims["groups"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // 8. Authenticate via federated flow (find/create user + generate tokens)
    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));

    let (_user, tokens) = auth_service
        .authenticate_federated(
            AuthProvider::Oidc,
            FederatedCredentials {
                external_id: sub,
                username: preferred_username,
                email,
                display_name,
                groups,
            },
        )
        .await?;

    // 9. Create a short-lived exchange code instead of passing raw tokens in the URL
    let exchange_code = AuthConfigService::create_exchange_code(
        &state.db,
        &tokens.access_token,
        &tokens.refresh_token,
    )
    .await?;

    let frontend_url = format!(
        "/auth/callback?code={}",
        urlencoding::encode(&exchange_code),
    );

    Ok(Redirect::temporary(&frontend_url))
}

// ---------------------------------------------------------------------------
// LDAP login
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct LdapLoginRequest {
    username: String,
    password: String,
}

/// Authenticate via LDAP
#[utoipa::path(
    post,
    path = "/ldap/{id}/login",
    context_path = "/api/v1/auth/sso",
    tag = "sso",
    params(
        ("id" = Uuid, Path, description = "LDAP provider configuration ID")
    ),
    request_body = LdapLoginRequest,
    responses(
        (status = 200, description = "Authentication successful with tokens"),
        (status = 401, description = "Invalid credentials", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "LDAP provider not found", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn ldap_login(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Json(req): Json<LdapLoginRequest>,
) -> Result<Response> {
    // Get decrypted LDAP config
    let (row, bind_password) = AuthConfigService::get_ldap_decrypted(&state.db, id).await?;

    // Create LDAP service from DB config
    let ldap_svc = LdapService::from_db_config(
        state.db.clone(),
        &row.name,
        &row.server_url,
        row.bind_dn.as_deref(),
        bind_password.as_deref(),
        &row.user_base_dn,
        &row.user_filter,
        &row.username_attribute,
        &row.email_attribute,
        &row.display_name_attribute,
        &row.groups_attribute,
        row.admin_group_dn.as_deref(),
        row.use_starttls,
    );

    // Authenticate against LDAP
    let ldap_user = ldap_svc.authenticate(&req.username, &req.password).await?;

    // Sync user to local DB and generate JWT
    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    let (_user, tokens) = auth_service
        .authenticate_federated(
            AuthProvider::Ldap,
            FederatedCredentials {
                external_id: ldap_user.dn,
                username: ldap_user.username,
                email: ldap_user.email,
                display_name: ldap_user.display_name,
                groups: ldap_user.groups,
            },
        )
        .await?;

    let body = serde_json::json!({
        "access_token": tokens.access_token,
        "refresh_token": tokens.refresh_token,
        "token_type": "Bearer",
    });

    // Default expires_in for LDAP tokens (1 hour = 3600 seconds)
    let mut response = Json(body).into_response();
    set_auth_cookies(
        response.headers_mut(),
        &tokens.access_token,
        &tokens.refresh_token,
        3600,
    );
    Ok(response)
}

// ---------------------------------------------------------------------------
// SAML login + ACS
// ---------------------------------------------------------------------------

/// Initiate SAML login redirect
#[utoipa::path(
    get,
    path = "/saml/{id}/login",
    context_path = "/api/v1/auth/sso",
    tag = "sso",
    params(
        ("id" = Uuid, Path, description = "SAML provider configuration ID")
    ),
    responses(
        (status = 307, description = "Redirect to SAML IdP SSO endpoint"),
        (status = 404, description = "SAML provider not found", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn saml_login(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Redirect> {
    // Get SAML config from DB
    let row = AuthConfigService::get_saml_decrypted(&state.db, id).await?;

    // Create SSO session for CSRF
    let _session = AuthConfigService::create_sso_session(&state.db, "saml", id).await?;

    // Build ACS URL
    let acs_url = format!("/api/v1/auth/sso/saml/{}/acs", id);

    // Create SAML service from DB config
    let saml_svc = SamlService::from_db_config(
        state.db.clone(),
        &row.entity_id,
        &row.sso_url,
        row.slo_url.as_deref(),
        Some(&row.certificate),
        &row.sp_entity_id,
        &acs_url,
        &row.name_id_format,
        &row.attribute_mapping,
        row.sign_requests,
        row.require_signed_assertions,
        row.admin_group.as_deref(),
    );

    // Generate AuthnRequest
    let authn_request = saml_svc.create_authn_request()?;

    Ok(Redirect::temporary(&authn_request.redirect_url))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SamlAcsForm {
    #[serde(rename = "SAMLResponse")]
    saml_response: String,
    #[serde(rename = "RelayState")]
    #[allow(dead_code)]
    relay_state: Option<String>,
}

/// Handle SAML Assertion Consumer Service (ACS) callback
#[utoipa::path(
    post,
    path = "/saml/{id}/acs",
    context_path = "/api/v1/auth/sso",
    tag = "sso",
    params(
        ("id" = Uuid, Path, description = "SAML provider configuration ID")
    ),
    responses(
        (status = 307, description = "Redirect to frontend with exchange code"),
        (status = 400, description = "Invalid SAML response", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn saml_acs(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    axum::extract::Form(form): axum::extract::Form<SamlAcsForm>,
) -> Result<Redirect> {
    // Get SAML config from DB
    let row = AuthConfigService::get_saml_decrypted(&state.db, id).await?;

    // Build ACS URL
    let acs_url = format!("/api/v1/auth/sso/saml/{}/acs", id);

    // Create SAML service
    let saml_svc = SamlService::from_db_config(
        state.db.clone(),
        &row.entity_id,
        &row.sso_url,
        row.slo_url.as_deref(),
        Some(&row.certificate),
        &row.sp_entity_id,
        &acs_url,
        &row.name_id_format,
        &row.attribute_mapping,
        row.sign_requests,
        row.require_signed_assertions,
        row.admin_group.as_deref(),
    );

    // Process SAML response
    let saml_user = saml_svc.authenticate(&form.saml_response).await?;

    // Sync user and generate tokens
    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    let (_user, tokens) = auth_service
        .authenticate_federated(
            AuthProvider::Saml,
            FederatedCredentials {
                external_id: saml_user.name_id,
                username: saml_user.username,
                email: saml_user.email,
                display_name: saml_user.display_name,
                groups: saml_user.groups,
            },
        )
        .await?;

    // Create a short-lived exchange code instead of passing raw tokens in the URL
    let exchange_code = AuthConfigService::create_exchange_code(
        &state.db,
        &tokens.access_token,
        &tokens.refresh_token,
    )
    .await?;

    let frontend_url = format!(
        "/auth/callback?code={}",
        urlencoding::encode(&exchange_code),
    );

    Ok(Redirect::temporary(&frontend_url))
}

// ---------------------------------------------------------------------------
// Exchange code endpoint
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct ExchangeCodeRequest {
    code: String,
}

#[derive(Debug, Serialize, ToSchema)]
struct ExchangeCodeResponse {
    access_token: String,
    refresh_token: String,
    token_type: String,
}

/// Exchange a short-lived code for access and refresh tokens
#[utoipa::path(
    post,
    path = "/exchange",
    context_path = "/api/v1/auth/sso",
    tag = "sso",
    request_body = ExchangeCodeRequest,
    responses(
        (status = 200, description = "Token exchange successful", body = ExchangeCodeResponse),
        (status = 400, description = "Invalid or expired exchange code", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn exchange_code(
    State(state): State<SharedState>,
    Json(req): Json<ExchangeCodeRequest>,
) -> Result<Response> {
    let (access_token, refresh_token) =
        AuthConfigService::exchange_code(&state.db, &req.code).await?;

    let body = ExchangeCodeResponse {
        access_token: access_token.clone(),
        refresh_token: refresh_token.clone(),
        token_type: "Bearer".to_string(),
    };

    // Default expires_in for SSO tokens (1 hour = 3600 seconds)
    let mut response = Json(body).into_response();
    set_auth_cookies(response.headers_mut(), &access_token, &refresh_token, 3600);
    Ok(response)
}

#[derive(OpenApi)]
#[openapi(
    paths(
        list_providers,
        oidc_login,
        oidc_callback,
        ldap_login,
        saml_login,
        saml_acs,
        exchange_code,
    ),
    components(schemas(
        LdapLoginRequest,
        SamlAcsForm,
        ExchangeCodeRequest,
        ExchangeCodeResponse,
        crate::services::auth_config_service::SsoProviderInfo,
    ))
)]
pub struct SsoApiDoc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Decode the payload segment of a JWT without verifying the signature.
///
/// This is safe here because we just received the token directly from the
/// identity provider over a TLS-secured backchannel.
fn decode_jwt_payload(token: &str) -> Result<serde_json::Value> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AppError::Internal("Invalid JWT format".into()));
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| AppError::Internal(format!("Failed to decode JWT payload: {e}")))?;

    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| AppError::Internal(format!("Failed to parse JWT claims: {e}")))?;

    Ok(claims)
}
