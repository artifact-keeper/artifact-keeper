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
}
