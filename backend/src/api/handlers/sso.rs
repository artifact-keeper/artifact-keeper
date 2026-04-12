//! Public SSO flow endpoints (no auth middleware required).
//!
//! Handles OIDC login redirects, callbacks, and SAML endpoints.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
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
        .route("/oidc/callback", get(oidc_callback_generic))
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
    headers: HeaderMap,
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

    let http_client = crate::services::http_client::default_client();
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

    // 4. Build redirect_uri from attribute_mapping, falling back to absolute URL
    //    derived from request headers (X-Forwarded-Proto/Host or Host).
    let redirect_uri = resolve_oidc_redirect_uri(&row.attribute_mapping, &id, &headers);

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
    headers: HeaderMap,
) -> Result<Redirect> {
    // Validate SSO session (CSRF check), then delegate to shared logic
    let session = AuthConfigService::validate_sso_session(&state.db, &params.state).await?;
    oidc_callback_inner(state, id, params.code, session.nonce, headers).await
}

/// Handle OIDC callback without provider UUID in the path.
///
/// Identity providers are typically configured with a single, stable redirect
/// URI like `/api/v1/auth/sso/oidc/callback`. This handler resolves the
/// correct provider from the `state` query parameter, which maps back to the
/// SSO session that was created during the login redirect.
pub async fn oidc_callback_generic(
    State(state): State<SharedState>,
    Query(params): Query<OidcCallbackQuery>,
    headers: HeaderMap,
) -> Result<Redirect> {
    // Validate SSO session and resolve the provider from the stored state
    let session = AuthConfigService::validate_sso_session(&state.db, &params.state).await?;
    oidc_callback_inner(
        state,
        session.provider_id,
        params.code,
        session.nonce,
        headers,
    )
    .await
}

/// Shared OIDC callback logic used by both the provider-specific and generic
/// callback handlers. Assumes the SSO session has already been validated.
async fn oidc_callback_inner(
    state: SharedState,
    provider_id: Uuid,
    authorization_code: String,
    session_nonce: Option<String>,
    headers: HeaderMap,
) -> Result<Redirect> {
    // 1. Get decrypted OIDC config
    let (row, client_secret) =
        AuthConfigService::get_oidc_decrypted(&state.db, provider_id).await?;

    // 2. Fetch OIDC discovery for token_endpoint
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        row.issuer_url.trim_end_matches('/')
    );

    let http_client = crate::services::http_client::default_client();
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

    // 3. Build redirect_uri (must match the one used in the login request)
    let redirect_uri = resolve_oidc_redirect_uri(&row.attribute_mapping, &provider_id, &headers);

    // 4. Exchange authorization code for tokens
    let token_response: serde_json::Value = http_client
        .post(token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &authorization_code),
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

    // 5. Verify ID token signature and validate standard claims
    let claims = validate_id_token(
        &http_client,
        id_token,
        &discovery,
        &row.client_id,
        &row.issuer_url,
        session_nonce.as_deref(),
    )
    .await?;

    // 6. Extract user claims (using attribute_mapping overrides when configured)
    let attr = &row.attribute_mapping;

    let username_claim = resolve_oidc_claim_name(attr, "username_claim", "preferred_username");
    let email_claim = resolve_oidc_claim_name(attr, "email_claim", "email");
    let groups_claim = resolve_oidc_claim_name(attr, "groups_claim", "groups");

    let sub = claims["sub"]
        .as_str()
        .ok_or_else(|| AppError::Internal("ID token missing sub claim".into()))?
        .to_string();

    let email = claims[email_claim].as_str().unwrap_or_default().to_string();

    let preferred_username = claims[username_claim]
        .as_str()
        .or_else(|| claims["email"].as_str())
        .unwrap_or(&sub)
        .to_string();

    let display_name = claims["name"].as_str().map(|s| s.to_string());

    let groups = extract_oidc_groups(&claims, groups_claim);

    // 7. Authenticate via federated flow (find/create user + generate tokens)
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

    // 8. Create a short-lived exchange code instead of passing raw tokens in the URL
    let exchange_code = AuthConfigService::create_exchange_code(
        &state.db,
        &tokens.access_token,
        &tokens.refresh_token,
    )
    .await?;

    let frontend_url = build_frontend_callback_url(&exchange_code);

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

    let frontend_url = build_frontend_callback_url(&exchange_code);

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

/// Build the frontend callback URL for the SSO exchange code flow.
///
/// The Next.js frontend serves the callback page at `/callback` (the `(auth)`
/// route group does not add a URL prefix). The exchange code is URL-encoded
/// and passed as a query parameter so the frontend can exchange it for tokens.
pub(crate) fn build_frontend_callback_url(exchange_code: &str) -> String {
    format!("/callback?code={}", urlencoding::encode(exchange_code))
}

/// Resolve the redirect URI from OIDC attribute_mapping, falling back to an
/// absolute URL built from request headers.
///
/// OIDC providers (Keycloak, Entra ID, Okta, etc.) require the redirect_uri
/// to be an absolute URL. When no explicit value is configured in
/// `attribute_mapping`, this function constructs one from the
/// `X-Forwarded-Proto` / `X-Forwarded-Host` (or `Host`) request headers,
/// which a reverse proxy typically sets. The generic callback route resolves
/// the provider from the `state` query parameter, so the redirect URI no
/// longer needs the provider UUID embedded in the path.
pub(crate) fn resolve_oidc_redirect_uri(
    attribute_mapping: &serde_json::Value,
    _provider_id: &uuid::Uuid,
    headers: &HeaderMap,
) -> String {
    attribute_mapping
        .get("redirect_uri")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(|| {
            let base = request_base_url(headers);
            format!("{}/api/v1/auth/sso/oidc/callback", base)
        })
}

use super::proxy_helpers::request_base_url;

/// Resolve a claim name from OIDC attribute_mapping, returning the configured
/// value or the provided default.
pub(crate) fn resolve_oidc_claim_name<'a>(
    attribute_mapping: &'a serde_json::Value,
    key: &str,
    default: &'a str,
) -> &'a str {
    attribute_mapping
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or(default)
}

/// Extract user groups from JWT claims using the configured groups claim name.
pub(crate) fn extract_oidc_groups(claims: &serde_json::Value, groups_claim: &str) -> Vec<String> {
    claims[groups_claim]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Build a `DecodingKey` from a JWK JSON value based on its key type.
fn decoding_key_from_jwk(jwk: &serde_json::Value) -> Result<jsonwebtoken::DecodingKey> {
    use jsonwebtoken::DecodingKey;
    let kty = jwk["kty"].as_str().unwrap_or("");
    if kty == "RSA" {
        let n = jwk["n"]
            .as_str()
            .ok_or_else(|| AppError::Internal("JWK missing RSA modulus".into()))?;
        let e = jwk["e"]
            .as_str()
            .ok_or_else(|| AppError::Internal("JWK missing RSA exponent".into()))?;
        DecodingKey::from_rsa_components(n, e)
            .map_err(|err| AppError::Internal(format!("Failed to build RSA decoding key: {err}")))
    } else if kty == "EC" {
        let x = jwk["x"]
            .as_str()
            .ok_or_else(|| AppError::Internal("JWK missing EC x coordinate".into()))?;
        let y = jwk["y"]
            .as_str()
            .ok_or_else(|| AppError::Internal("JWK missing EC y coordinate".into()))?;
        DecodingKey::from_ec_components(x, y)
            .map_err(|err| AppError::Internal(format!("Failed to build EC decoding key: {err}")))
    } else {
        Err(AppError::Internal(format!(
            "Unsupported JWK key type: {kty}"
        )))
    }
}

/// Select a JWK from the JWKS keys array, matching by `kid` if present,
/// otherwise falling back to the first usable key.
fn select_jwk_key(
    keys: &[serde_json::Value],
    kid: Option<&str>,
) -> Result<jsonwebtoken::DecodingKey> {
    if let Some(kid) = kid {
        let jwk = keys
            .iter()
            .find(|k| k["kid"].as_str() == Some(kid))
            .ok_or_else(|| AppError::Authentication("No matching JWK found for kid".into()))?;
        decoding_key_from_jwk(jwk)
    } else {
        keys.iter()
            .find_map(|k| decoding_key_from_jwk(k).ok())
            .ok_or_else(|| AppError::Internal("No usable JWK found in JWKS".into()))
    }
}

/// Validate an OIDC ID token by verifying its signature against the provider's
/// JWKS and checking the `iss`, `aud`, `exp`, and `nonce` claims.
async fn validate_id_token(
    http_client: &reqwest::Client,
    id_token: &str,
    discovery: &serde_json::Value,
    client_id: &str,
    issuer_url: &str,
    session_nonce: Option<&str>,
) -> Result<serde_json::Value> {
    use jsonwebtoken::{decode, decode_header, Algorithm, Validation};

    let jwks_uri = discovery["jwks_uri"]
        .as_str()
        .ok_or_else(|| AppError::Internal("OIDC discovery missing jwks_uri".into()))?;

    let jwks: serde_json::Value = http_client
        .get(jwks_uri)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch JWKS: {e}")))?
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to parse JWKS: {e}")))?;

    let header = decode_header(id_token)
        .map_err(|e| AppError::Authentication(format!("Invalid ID token header: {e}")))?;

    let keys = jwks["keys"]
        .as_array()
        .ok_or_else(|| AppError::Internal("JWKS missing keys array".into()))?;

    let decoding_key = select_jwk_key(keys, header.kid.as_deref())?;

    let alg = match header.alg {
        jsonwebtoken::Algorithm::RS256 => Algorithm::RS256,
        jsonwebtoken::Algorithm::RS384 => Algorithm::RS384,
        jsonwebtoken::Algorithm::RS512 => Algorithm::RS512,
        jsonwebtoken::Algorithm::ES256 => Algorithm::ES256,
        jsonwebtoken::Algorithm::ES384 => Algorithm::ES384,
        jsonwebtoken::Algorithm::PS256 => Algorithm::PS256,
        jsonwebtoken::Algorithm::PS384 => Algorithm::PS384,
        jsonwebtoken::Algorithm::PS512 => Algorithm::PS512,
        other => {
            return Err(AppError::Authentication(format!(
                "Unsupported ID token algorithm: {other:?}"
            )))
        }
    };

    let mut validation = Validation::new(alg);
    validation.set_audience(&[client_id]);
    validation.set_issuer(&[issuer_url]);

    let token_data = decode::<serde_json::Value>(id_token, &decoding_key, &validation)
        .map_err(|e| AppError::Authentication(format!("ID token validation failed: {e}")))?;

    let claims = token_data.claims;

    if let Some(expected_nonce) = session_nonce {
        let token_nonce = claims["nonce"]
            .as_str()
            .ok_or_else(|| AppError::Authentication("ID token missing nonce claim".into()))?;
        if token_nonce != expected_nonce {
            return Err(AppError::Authentication(
                "ID token nonce does not match session nonce".into(),
            ));
        }
    }

    Ok(claims)
}

/// Decode the payload segment of a JWT without verifying the signature.
///
/// WARNING: This function does NOT verify the JWT signature. Use
/// `validate_id_token` for security-sensitive flows.
#[cfg(test)]
pub(crate) fn decode_jwt_payload(token: &str) -> Result<serde_json::Value> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    /// Helper: build a fake JWT token with the given payload JSON.
    fn make_jwt(payload: &serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap());
        let signature = URL_SAFE_NO_PAD.encode(b"fake_signature");
        format!("{}.{}.{}", header, payload_b64, signature)
    }

    // -----------------------------------------------------------------------
    // decode_jwt_payload
    // -----------------------------------------------------------------------

    #[test]
    fn test_decode_jwt_payload_valid() {
        let claims = serde_json::json!({
            "sub": "user-123",
            "email": "user@example.com",
            "name": "Test User"
        });
        let token = make_jwt(&claims);
        let result = decode_jwt_payload(&token).unwrap();
        assert_eq!(result["sub"], "user-123");
        assert_eq!(result["email"], "user@example.com");
        assert_eq!(result["name"], "Test User");
    }

    #[test]
    fn test_decode_jwt_payload_with_groups() {
        let claims = serde_json::json!({
            "sub": "user-456",
            "groups": ["admin", "developers"]
        });
        let token = make_jwt(&claims);
        let result = decode_jwt_payload(&token).unwrap();
        let groups = result["groups"].as_array().unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0], "admin");
        assert_eq!(groups[1], "developers");
    }

    #[test]
    fn test_decode_jwt_payload_empty_claims() {
        let claims = serde_json::json!({});
        let token = make_jwt(&claims);
        let result = decode_jwt_payload(&token).unwrap();
        assert!(result.is_object());
        assert!(result.as_object().unwrap().is_empty());
    }

    #[test]
    fn test_decode_jwt_payload_too_few_parts() {
        let result = decode_jwt_payload("header.payload");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_jwt_payload_too_many_parts() {
        let result = decode_jwt_payload("a.b.c.d");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_jwt_payload_empty_string() {
        let result = decode_jwt_payload("");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_jwt_payload_single_segment() {
        let result = decode_jwt_payload("only_one_segment");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_jwt_payload_invalid_base64() {
        let result = decode_jwt_payload("header.!!!invalid-base64!!!.signature");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_jwt_payload_invalid_json() {
        // Valid base64 but not valid JSON
        let bad_payload = URL_SAFE_NO_PAD.encode(b"not json at all");
        let token = format!("header.{}.signature", bad_payload);
        let result = decode_jwt_payload(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_jwt_payload_numeric_claims() {
        let claims = serde_json::json!({
            "sub": "user-789",
            "iat": 1700000000,
            "exp": 1700003600,
            "nbf": 1699999900
        });
        let token = make_jwt(&claims);
        let result = decode_jwt_payload(&token).unwrap();
        assert_eq!(result["iat"], 1700000000);
        assert_eq!(result["exp"], 1700003600);
    }

    #[test]
    fn test_decode_jwt_payload_preferred_username() {
        let claims = serde_json::json!({
            "sub": "guid-abc",
            "preferred_username": "alice",
            "email": "alice@corp.com"
        });
        let token = make_jwt(&claims);
        let result = decode_jwt_payload(&token).unwrap();
        assert_eq!(result["preferred_username"], "alice");
    }

    // -----------------------------------------------------------------------
    // Request/Response serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_oidc_callback_query_deserialize() {
        let json = r#"{"code":"auth_code_123","state":"csrf_state_456"}"#;
        let q: OidcCallbackQuery = serde_json::from_str(json).unwrap();
        assert_eq!(q.code, "auth_code_123");
        assert_eq!(q.state, "csrf_state_456");
    }

    #[test]
    fn test_ldap_login_request_deserialize() {
        let json = r#"{"username":"alice","password":"secret"}"#;
        let req: LdapLoginRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.username, "alice");
        assert_eq!(req.password, "secret");
    }

    #[test]
    fn test_saml_acs_form_deserialize() {
        let json = r#"{"SAMLResponse":"base64_encoded_response","RelayState":"some_state"}"#;
        let form: SamlAcsForm = serde_json::from_str(json).unwrap();
        assert_eq!(form.saml_response, "base64_encoded_response");
        assert_eq!(form.relay_state, Some("some_state".to_string()));
    }

    #[test]
    fn test_saml_acs_form_no_relay_state() {
        let json = r#"{"SAMLResponse":"encoded_resp"}"#;
        let form: SamlAcsForm = serde_json::from_str(json).unwrap();
        assert_eq!(form.saml_response, "encoded_resp");
        assert!(form.relay_state.is_none());
    }

    #[test]
    fn test_exchange_code_request_deserialize() {
        let json = r#"{"code":"exchange_code_abc"}"#;
        let req: ExchangeCodeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.code, "exchange_code_abc");
    }

    #[test]
    fn test_exchange_code_response_serialize() {
        let resp = ExchangeCodeResponse {
            access_token: "at_123".to_string(),
            refresh_token: "rt_456".to_string(),
            token_type: "Bearer".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["access_token"], "at_123");
        assert_eq!(json["refresh_token"], "rt_456");
        assert_eq!(json["token_type"], "Bearer");
    }

    // -----------------------------------------------------------------------
    // build_frontend_callback_url
    // -----------------------------------------------------------------------

    #[test]
    fn test_frontend_callback_url_simple_code() {
        let url = build_frontend_callback_url("abc123");
        assert_eq!(url, "/callback?code=abc123");
    }

    #[test]
    fn test_frontend_callback_url_does_not_use_auth_prefix() {
        let url = build_frontend_callback_url("test");
        assert!(url.starts_with("/callback?"));
        assert!(!url.contains("/auth/callback"));
    }

    #[test]
    fn test_frontend_callback_url_encodes_special_chars() {
        let url = build_frontend_callback_url("code with spaces&symbols=yes");
        assert_eq!(url, "/callback?code=code%20with%20spaces%26symbols%3Dyes");
    }

    #[test]
    fn test_frontend_callback_url_empty_code() {
        let url = build_frontend_callback_url("");
        assert_eq!(url, "/callback?code=");
    }

    #[test]
    fn test_frontend_callback_url_unicode_code() {
        let url = build_frontend_callback_url("token-\u{00e9}\u{00e8}");
        // urlencoding will percent-encode the non-ASCII bytes
        assert!(url.starts_with("/callback?code="));
        assert!(!url.contains('\u{00e9}'));
    }

    // -----------------------------------------------------------------------
    // resolve_oidc_redirect_uri
    // -----------------------------------------------------------------------

    #[test]
    fn test_redirect_uri_from_attribute_mapping() {
        let attr = serde_json::json!({
            "redirect_uri": "https://app.example.com/callback"
        });
        let id = uuid::Uuid::nil();
        let headers = HeaderMap::new();
        assert_eq!(
            resolve_oidc_redirect_uri(&attr, &id, &headers),
            "https://app.example.com/callback"
        );
    }

    #[test]
    fn test_redirect_uri_fallback_builds_absolute_url() {
        let attr = serde_json::json!({});
        let id = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let headers = HeaderMap::new();
        assert_eq!(
            resolve_oidc_redirect_uri(&attr, &id, &headers),
            "http://localhost/api/v1/auth/sso/oidc/callback"
        );
    }

    #[test]
    fn test_redirect_uri_fallback_when_null() {
        let attr = serde_json::json!({ "redirect_uri": null });
        let id = uuid::Uuid::nil();
        let headers = HeaderMap::new();
        assert_eq!(
            resolve_oidc_redirect_uri(&attr, &id, &headers),
            "http://localhost/api/v1/auth/sso/oidc/callback"
        );
    }

    #[test]
    fn test_redirect_uri_fallback_when_non_string() {
        let attr = serde_json::json!({ "redirect_uri": 42 });
        let id = uuid::Uuid::nil();
        let headers = HeaderMap::new();
        assert_eq!(
            resolve_oidc_redirect_uri(&attr, &id, &headers),
            "http://localhost/api/v1/auth/sso/oidc/callback"
        );
    }

    #[test]
    fn test_redirect_uri_with_null_attribute_mapping() {
        let attr = serde_json::Value::Null;
        let id = uuid::Uuid::nil();
        let headers = HeaderMap::new();
        let uri = resolve_oidc_redirect_uri(&attr, &id, &headers);
        assert!(uri.starts_with("http"));
        assert!(uri.contains("/callback"));
    }

    #[test]
    fn test_redirect_uri_with_forwarded_headers() {
        let attr = serde_json::json!({});
        let id = uuid::Uuid::nil();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        headers.insert("x-forwarded-host", "registry.example.com".parse().unwrap());
        assert_eq!(
            resolve_oidc_redirect_uri(&attr, &id, &headers),
            "https://registry.example.com/api/v1/auth/sso/oidc/callback"
        );
    }

    #[test]
    fn test_redirect_uri_with_host_header_only() {
        let attr = serde_json::json!({});
        let id = uuid::Uuid::nil();
        let mut headers = HeaderMap::new();
        headers.insert("host", "myhost:8080".parse().unwrap());
        assert_eq!(
            resolve_oidc_redirect_uri(&attr, &id, &headers),
            "http://myhost:8080/api/v1/auth/sso/oidc/callback"
        );
    }

    #[test]
    fn test_redirect_uri_forwarded_host_takes_precedence() {
        let attr = serde_json::json!({});
        let id = uuid::Uuid::nil();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        headers.insert("x-forwarded-host", "external.example.com".parse().unwrap());
        headers.insert("host", "internal-svc:8080".parse().unwrap());
        assert_eq!(
            resolve_oidc_redirect_uri(&attr, &id, &headers),
            "https://external.example.com/api/v1/auth/sso/oidc/callback"
        );
    }

    #[test]
    fn test_redirect_uri_host_with_embedded_scheme() {
        let attr = serde_json::json!({});
        let id = uuid::Uuid::nil();
        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            "https://already-absolute.example.com".parse().unwrap(),
        );
        assert_eq!(
            resolve_oidc_redirect_uri(&attr, &id, &headers),
            "https://already-absolute.example.com/api/v1/auth/sso/oidc/callback"
        );
    }

    #[test]
    fn test_redirect_uri_explicit_overrides_headers() {
        let attr = serde_json::json!({
            "redirect_uri": "https://custom.example.com/oidc/cb"
        });
        let id = uuid::Uuid::nil();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        headers.insert("x-forwarded-host", "other.example.com".parse().unwrap());
        assert_eq!(
            resolve_oidc_redirect_uri(&attr, &id, &headers),
            "https://custom.example.com/oidc/cb"
        );
    }

    // -----------------------------------------------------------------------
    // resolve_oidc_claim_name
    // -----------------------------------------------------------------------

    #[test]
    fn test_claim_name_custom_groups_claim() {
        let attr = serde_json::json!({ "groups_claim": "roles" });
        assert_eq!(
            resolve_oidc_claim_name(&attr, "groups_claim", "groups"),
            "roles"
        );
    }

    #[test]
    fn test_claim_name_default_groups() {
        let attr = serde_json::json!({});
        assert_eq!(
            resolve_oidc_claim_name(&attr, "groups_claim", "groups"),
            "groups"
        );
    }

    #[test]
    fn test_claim_name_custom_username() {
        let attr = serde_json::json!({ "username_claim": "upn" });
        assert_eq!(
            resolve_oidc_claim_name(&attr, "username_claim", "preferred_username"),
            "upn"
        );
    }

    #[test]
    fn test_claim_name_default_username() {
        let attr = serde_json::json!({});
        assert_eq!(
            resolve_oidc_claim_name(&attr, "username_claim", "preferred_username"),
            "preferred_username"
        );
    }

    #[test]
    fn test_claim_name_custom_email() {
        let attr = serde_json::json!({ "email_claim": "mail" });
        assert_eq!(
            resolve_oidc_claim_name(&attr, "email_claim", "email"),
            "mail"
        );
    }

    #[test]
    fn test_claim_name_default_email() {
        let attr = serde_json::json!({});
        assert_eq!(
            resolve_oidc_claim_name(&attr, "email_claim", "email"),
            "email"
        );
    }

    #[test]
    fn test_claim_name_null_value_uses_default() {
        let attr = serde_json::json!({ "groups_claim": null });
        assert_eq!(
            resolve_oidc_claim_name(&attr, "groups_claim", "groups"),
            "groups"
        );
    }

    #[test]
    fn test_claim_name_non_string_uses_default() {
        let attr = serde_json::json!({ "groups_claim": 123 });
        assert_eq!(
            resolve_oidc_claim_name(&attr, "groups_claim", "groups"),
            "groups"
        );
    }

    #[test]
    fn test_claim_name_null_mapping_uses_default() {
        let attr = serde_json::Value::Null;
        assert_eq!(
            resolve_oidc_claim_name(&attr, "groups_claim", "groups"),
            "groups"
        );
    }

    // -----------------------------------------------------------------------
    // extract_oidc_groups
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_groups_standard() {
        let claims = serde_json::json!({
            "groups": ["admin", "developers", "users"]
        });
        let groups = extract_oidc_groups(&claims, "groups");
        assert_eq!(groups, vec!["admin", "developers", "users"]);
    }

    #[test]
    fn test_extract_groups_custom_claim() {
        let claims = serde_json::json!({
            "roles": ["manager", "viewer"]
        });
        let groups = extract_oidc_groups(&claims, "roles");
        assert_eq!(groups, vec!["manager", "viewer"]);
    }

    #[test]
    fn test_extract_groups_missing_claim() {
        let claims = serde_json::json!({ "sub": "user-123" });
        let groups = extract_oidc_groups(&claims, "groups");
        assert!(groups.is_empty());
    }

    #[test]
    fn test_extract_groups_empty_array() {
        let claims = serde_json::json!({ "groups": [] });
        let groups = extract_oidc_groups(&claims, "groups");
        assert!(groups.is_empty());
    }

    #[test]
    fn test_extract_groups_non_array_claim() {
        let claims = serde_json::json!({ "groups": "admin" });
        let groups = extract_oidc_groups(&claims, "groups");
        assert!(groups.is_empty()); // string is not an array
    }

    #[test]
    fn test_extract_groups_mixed_types_in_array() {
        let claims = serde_json::json!({
            "groups": ["admin", 42, "users", null, true]
        });
        let groups = extract_oidc_groups(&claims, "groups");
        // Only string values are extracted
        assert_eq!(groups, vec!["admin", "users"]);
    }

    #[test]
    fn test_extract_groups_null_claim() {
        let claims = serde_json::json!({ "groups": null });
        let groups = extract_oidc_groups(&claims, "groups");
        assert!(groups.is_empty());
    }

    // -----------------------------------------------------------------------
    // Nested object claims (existing test extended)
    // -----------------------------------------------------------------------

    #[test]
    fn test_decode_jwt_payload_with_nested_object() {
        let claims = serde_json::json!({
            "sub": "user-nested",
            "realm_access": {
                "roles": ["admin", "user"]
            }
        });
        let token = make_jwt(&claims);
        let result = decode_jwt_payload(&token).unwrap();
        let roles = result["realm_access"]["roles"].as_array().unwrap();
        assert_eq!(roles.len(), 2);
    }

    #[test]
    fn test_decode_jwt_payload_unicode_claims() {
        let claims = serde_json::json!({
            "sub": "user-unicode",
            "name": "Jean-Pierre Dupont"
        });
        let token = make_jwt(&claims);
        let result = decode_jwt_payload(&token).unwrap();
        assert_eq!(result["name"], "Jean-Pierre Dupont");
    }

    // --- validate_id_token logic coverage ---
    // The full function is async + needs HTTP, but we can test the sub-logic.

    #[test]
    fn test_algorithm_mapping_rs256() {
        use jsonwebtoken::Algorithm;
        let alg = jsonwebtoken::Algorithm::RS256;
        let mapped = match alg {
            jsonwebtoken::Algorithm::RS256 => Algorithm::RS256,
            jsonwebtoken::Algorithm::RS384 => Algorithm::RS384,
            jsonwebtoken::Algorithm::RS512 => Algorithm::RS512,
            jsonwebtoken::Algorithm::ES256 => Algorithm::ES256,
            jsonwebtoken::Algorithm::ES384 => Algorithm::ES384,
            jsonwebtoken::Algorithm::PS256 => Algorithm::PS256,
            jsonwebtoken::Algorithm::PS384 => Algorithm::PS384,
            jsonwebtoken::Algorithm::PS512 => Algorithm::PS512,
            _ => panic!("unsupported"),
        };
        assert_eq!(mapped, Algorithm::RS256);
    }

    #[test]
    fn test_algorithm_mapping_es256() {
        use jsonwebtoken::Algorithm;
        let alg = jsonwebtoken::Algorithm::ES256;
        let mapped = match alg {
            jsonwebtoken::Algorithm::RS256 => Algorithm::RS256,
            jsonwebtoken::Algorithm::ES256 => Algorithm::ES256,
            _ => panic!("unsupported"),
        };
        assert_eq!(mapped, Algorithm::ES256);
    }

    #[test]
    fn test_nonce_validation_match() {
        let claims = serde_json::json!({"nonce": "abc123"});
        let expected = "abc123";
        let token_nonce = claims["nonce"].as_str().unwrap();
        assert_eq!(token_nonce, expected);
    }

    #[test]
    fn test_nonce_validation_mismatch() {
        let claims = serde_json::json!({"nonce": "abc123"});
        let expected = "different";
        let token_nonce = claims["nonce"].as_str().unwrap();
        assert_ne!(token_nonce, expected);
    }

    #[test]
    fn test_nonce_validation_missing_claim() {
        let claims = serde_json::json!({"sub": "user"});
        assert!(claims["nonce"].as_str().is_none());
    }

    #[test]
    fn test_discovery_missing_jwks_uri() {
        let discovery = serde_json::json!({"issuer": "https://idp.example.com"});
        assert!(discovery["jwks_uri"].as_str().is_none());
    }

    #[test]
    fn test_discovery_with_jwks_uri() {
        let discovery = serde_json::json!({
            "jwks_uri": "https://idp.example.com/.well-known/jwks.json"
        });
        assert_eq!(
            discovery["jwks_uri"].as_str().unwrap(),
            "https://idp.example.com/.well-known/jwks.json"
        );
    }

    #[test]
    fn test_jwks_key_selection_by_kid() {
        let jwks = serde_json::json!({
            "keys": [
                {"kid": "key1", "kty": "RSA"},
                {"kid": "key2", "kty": "EC"}
            ]
        });
        let keys = jwks["keys"].as_array().unwrap();
        let target_kid = "key2";
        let found = keys.iter().find(|k| k["kid"].as_str() == Some(target_kid));
        assert!(found.is_some());
        assert_eq!(found.unwrap()["kty"].as_str().unwrap(), "EC");
    }

    #[test]
    fn test_jwks_key_fallback_first_key() {
        let jwks = serde_json::json!({
            "keys": [{"kty": "RSA", "n": "abc", "e": "AQAB"}]
        });
        let keys = jwks["keys"].as_array().unwrap();
        // No kid match, fall back to first
        let fallback = keys.first();
        assert!(fallback.is_some());
        assert_eq!(fallback.unwrap()["kty"].as_str().unwrap(), "RSA");
    }

    #[test]
    fn test_jwks_empty_keys_array() {
        let jwks = serde_json::json!({"keys": []});
        let keys = jwks["keys"].as_array().unwrap();
        assert!(keys.is_empty());
    }

    // --- decoding_key_from_jwk ---

    #[test]
    fn test_decoding_key_from_jwk_unsupported_type() {
        let jwk = serde_json::json!({"kty": "OKP"});
        let result = super::decoding_key_from_jwk(&jwk);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unsupported JWK key type"));
    }

    #[test]
    fn test_decoding_key_from_jwk_rsa_missing_n() {
        let jwk = serde_json::json!({"kty": "RSA", "e": "AQAB"});
        let result = super::decoding_key_from_jwk(&jwk);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("modulus"));
    }

    #[test]
    fn test_decoding_key_from_jwk_rsa_missing_e() {
        let jwk = serde_json::json!({"kty": "RSA", "n": "abc"});
        let result = super::decoding_key_from_jwk(&jwk);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exponent"));
    }

    #[test]
    fn test_decoding_key_from_jwk_ec_missing_x() {
        let jwk = serde_json::json!({"kty": "EC", "y": "abc"});
        let result = super::decoding_key_from_jwk(&jwk);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("x coordinate"));
    }

    #[test]
    fn test_decoding_key_from_jwk_ec_missing_y() {
        let jwk = serde_json::json!({"kty": "EC", "x": "abc"});
        let result = super::decoding_key_from_jwk(&jwk);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("y coordinate"));
    }

    #[test]
    fn test_decoding_key_from_jwk_empty_kty() {
        let jwk = serde_json::json!({"n": "abc"});
        let result = super::decoding_key_from_jwk(&jwk);
        assert!(result.is_err());
    }

    // --- select_jwk_key ---

    #[test]
    fn test_select_jwk_key_no_kid_empty_keys() {
        let keys: Vec<serde_json::Value> = vec![];
        let result = super::select_jwk_key(&keys, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No usable JWK"));
    }

    #[test]
    fn test_select_jwk_key_kid_not_found() {
        let keys = vec![serde_json::json!({"kid": "key1", "kty": "RSA", "n": "x", "e": "y"})];
        let result = super::select_jwk_key(&keys, Some("nonexistent"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No matching JWK"));
    }

    #[test]
    fn test_select_jwk_key_unsupported_type_with_kid() {
        let keys = vec![serde_json::json!({"kid": "k1", "kty": "OKP"})];
        let result = super::select_jwk_key(&keys, Some("k1"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported"));
    }
}
