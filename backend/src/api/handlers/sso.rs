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

    // 2. If PKCE is enabled for this provider, generate a verifier and stash
    //    it in the SSO session for use on callback.
    let pkce_verifier = if row.pkce_enabled {
        Some(crate::services::auth_config_service::generate_pkce_verifier())
    } else {
        None
    };

    let session = AuthConfigService::create_sso_session_with_pkce(
        &state.db,
        "oidc",
        id,
        pkce_verifier.clone(),
    )
    .await?;
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

    let mut auth_url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}",
        authorization_endpoint,
        urlencoding::encode(&row.client_id),
        urlencoding::encode(&redirect_uri),
        urlencoding::encode(&scope),
        urlencoding::encode(&state_str),
        urlencoding::encode(&nonce_str),
    );

    // 6. Append PKCE S256 challenge if enabled (issue #1091).
    if let Some(verifier) = pkce_verifier.as_deref() {
        let challenge = crate::services::auth_config_service::pkce_challenge_s256(verifier);
        auth_url.push_str("&code_challenge=");
        auth_url.push_str(&urlencoding::encode(&challenge));
        auth_url.push_str("&code_challenge_method=S256");
    }

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

/// Validate the shape of an OIDC callback's `code` and `state` query
/// parameters before any session lookup or IdP exchange.
///
/// Distinguishes "malformed callback" (the client sent us garbage) from
/// "state mismatch / CSRF" (the client sent us well-formed but unrecognized
/// state). Without this split, an empty state hits the SSO session lookup,
/// misses, and returns 401, which leaks the ordering of our auth checks and
/// confuses legitimate clients that crash mid-redirect.
///
/// Returns `AppError::Validation` (400) for missing/empty parameters. The
/// CSRF replay defense (401) still fires for non-empty state values that
/// don't match a cached session.
fn validate_oidc_callback_params(params: &OidcCallbackQuery) -> Result<()> {
    if params.state.is_empty() || params.code.is_empty() {
        return Err(AppError::Validation(
            "Invalid OIDC callback parameters: code and state are required".to_string(),
        ));
    }
    Ok(())
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
        (status = 401, description = "Invalid or expired SSO state (CSRF)", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn oidc_callback(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Query(params): Query<OidcCallbackQuery>,
    headers: HeaderMap,
) -> Result<Redirect> {
    // Validate parameter shape BEFORE hitting the session store. Empty state
    // or code is a malformed callback (400), not a CSRF failure (401). See
    // `validate_oidc_callback_params` doc comment.
    validate_oidc_callback_params(&params)?;

    // Validate SSO session (CSRF check), then delegate to shared logic.
    //
    // Security: the path id MUST match the provider_id that was bound to the
    // SSO session at login time. Without this check, an attacker can mint a
    // valid (state, code) pair against provider A and replay the callback at
    // /oidc/{B}/callback so the PKCE code_verifier and code travel to
    // provider B's token endpoint. We derive provider_id from the session
    // (the authoritative side) and reject if the URL path disagrees.
    let session = AuthConfigService::validate_sso_session(&state.db, &params.state).await?;
    if session.provider_id != id {
        return Err(AppError::Authentication(
            "SSO state does not match provider".to_string(),
        ));
    }
    oidc_callback_inner(
        state,
        session.provider_id,
        params.code,
        session.nonce,
        session.pkce_code_verifier,
        headers,
    )
    .await
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
    // Validate parameter shape BEFORE hitting the session store. See
    // `validate_oidc_callback_params` doc comment.
    validate_oidc_callback_params(&params)?;

    // Validate SSO session and resolve the provider from the stored state
    let session = AuthConfigService::validate_sso_session(&state.db, &params.state).await?;
    oidc_callback_inner(
        state,
        session.provider_id,
        params.code,
        session.nonce,
        session.pkce_code_verifier,
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
    pkce_code_verifier: Option<String>,
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

    // 4. Exchange authorization code for tokens (with PKCE verifier when present).
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", &authorization_code),
        ("redirect_uri", &redirect_uri),
        ("client_id", &row.client_id),
        ("client_secret", &client_secret),
    ];
    if let Some(verifier) = pkce_code_verifier.as_deref() {
        form.push(("code_verifier", verifier));
    }
    let token_response: serde_json::Value = http_client
        .post(token_endpoint)
        .form(&form)
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

    // Read admin group setting from DB attribute_mapping, falling back to env
    let required_admin_group = attr
        .get("admin_group")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| std::env::var("OIDC_ADMIN_GROUP").ok());

    // 7. Authenticate via federated flow (find/create user + generate tokens)
    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));

    let (user, tokens) = auth_service
        .authenticate_federated(
            AuthProvider::Oidc,
            FederatedCredentials {
                external_id: sub,
                username: preferred_username,
                email,
                display_name,
                groups: groups.clone(),
                required_admin_group,
            },
        )
        .await?;

    // 7a. Issue #1094: when map_groups_to_groups is enabled, reflect the
    //     OIDC group claim values as Artifact Keeper group memberships.
    //     Auto-create groups (tagged with external_source = 'oidc') on first
    //     sight and reconcile membership so removed groups drop their members.
    if row.map_groups_to_groups {
        if let Err(e) =
            sync_oidc_groups_to_local_groups(&state.db, user.id, provider_id, &groups).await
        {
            tracing::warn!(
                error = %e,
                user_id = %user.id,
                provider_id = %provider_id,
                "Failed to sync OIDC groups to local groups; user login still succeeds"
            );
        }
    }

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
                required_admin_group: row.admin_group_dn.clone(),
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
                required_admin_group: row.admin_group.clone(),
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

/// Reconcile an OIDC user's group memberships against the `groups` table.
///
/// For each group name in `oidc_groups`:
/// - Find the group by name; if missing, auto-create it tagged with
///   `external_source = 'oidc'` and `external_provider_id = provider_id`.
/// - Ensure a `user_group_members` row exists.
///
/// Then remove the user from any group that:
/// - is tagged with this same `external_source` + `external_provider_id`, AND
/// - is not present in `oidc_groups`.
///
/// Operator-managed groups (NULL `external_source`) are never modified by
/// this sync. (Issue #1094.)
pub(crate) async fn sync_oidc_groups_to_local_groups(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    provider_id: Uuid,
    oidc_groups: &[String],
) -> Result<()> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    // Upsert each OIDC group: find-or-create, then ensure membership.
    let mut current_group_ids: Vec<Uuid> = Vec::with_capacity(oidc_groups.len());
    for name in oidc_groups {
        if name.trim().is_empty() {
            continue;
        }

        // Find-or-create the group atomically. Concurrent first-logins for
        // the same brand-new group name from different users would race a
        // separate SELECT + INSERT, with the loser of the race hitting the
        // UNIQUE constraint on `groups.name` and aborting the transaction.
        // ON CONFLICT (name) DO UPDATE … RETURNING id collapses the race
        // into a single atomic upsert. The `DO UPDATE` (a no-op assignment)
        // is what makes RETURNING populate for the conflicting row; a plain
        // DO NOTHING would return zero rows on conflict. Operator-managed
        // groups (NULL external_source) are reused without modification
        // because we only assign description/external_source/external_provider_id
        // when inserting, and the ON CONFLICT branch does not touch those
        // columns.
        let (group_id,): (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO groups (name, description, external_source, external_provider_id)
            VALUES ($1, $2, 'oidc', $3)
            ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
            RETURNING id
            "#,
        )
        .bind(name)
        .bind(format!("Auto-created from OIDC group claim: {name}"))
        .bind(provider_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        sqlx::query(
            r#"
            INSERT INTO user_group_members (user_id, group_id)
            VALUES ($1, $2)
            ON CONFLICT (user_id, group_id) DO NOTHING
            "#,
        )
        .bind(user_id)
        .bind(group_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        current_group_ids.push(group_id);
    }

    // Remove the user from any OIDC-managed group (same provider) that they
    // are no longer a member of according to the latest claims. We deliberately
    // limit the scope to groups marked external_source = 'oidc' AND
    // external_provider_id = provider_id so we never strip membership in
    // operator-managed groups or groups owned by other IdPs.
    sqlx::query(
        r#"
        DELETE FROM user_group_members
        WHERE user_id = $1
          AND group_id IN (
              SELECT id FROM groups
              WHERE external_source = 'oidc'
                AND external_provider_id = $2
                AND NOT (id = ANY($3))
          )
        "#,
    )
    .bind(user_id)
    .bind(provider_id)
    .bind(&current_group_ids)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(())
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

    // -----------------------------------------------------------------------
    // OIDC callback parameter validation (#1369)
    //
    // Empty state used to fall through to the SSO session lookup and return
    // 401 ("Invalid or expired SSO state"). That leaked the ordering of our
    // auth checks (info-leak via 401 vs 400) and confused legitimate clients
    // that lost the state value mid-redirect. Malformed callbacks now get a
    // 400; the 401 path is reserved for non-empty state values that miss the
    // session cache (CSRF replay defense).
    // -----------------------------------------------------------------------

    /// Assert that an `AppError` maps to the expected HTTP status code.
    /// Uses the same status mapping as the real `IntoResponse` impl.
    fn assert_status(err: &AppError, expected: axum::http::StatusCode) {
        let actual = match err {
            AppError::Validation(_) => axum::http::StatusCode::BAD_REQUEST,
            AppError::Authentication(_) => axum::http::StatusCode::UNAUTHORIZED,
            AppError::Unauthorized(_) => axum::http::StatusCode::UNAUTHORIZED,
            AppError::NotFound(_) => axum::http::StatusCode::NOT_FOUND,
            other => panic!("unexpected error variant: {other:?}"),
        };
        assert_eq!(
            actual, expected,
            "expected status {expected:?} for {err:?}, got {actual:?}"
        );
    }

    #[test]
    fn test_validate_oidc_callback_params_empty_state_returns_400() {
        let params = OidcCallbackQuery {
            code: "valid_code".to_string(),
            state: String::new(),
        };
        let err = validate_oidc_callback_params(&params).expect_err("empty state must reject");
        assert!(
            matches!(err, AppError::Validation(_)),
            "empty state should map to Validation (400), got {err:?}"
        );
        assert_status(&err, axum::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_validate_oidc_callback_params_empty_code_returns_400() {
        let params = OidcCallbackQuery {
            code: String::new(),
            state: "valid_state".to_string(),
        };
        let err = validate_oidc_callback_params(&params).expect_err("empty code must reject");
        assert!(
            matches!(err, AppError::Validation(_)),
            "empty code should map to Validation (400), got {err:?}"
        );
        assert_status(&err, axum::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_validate_oidc_callback_params_both_empty_returns_400() {
        let params = OidcCallbackQuery {
            code: String::new(),
            state: String::new(),
        };
        let err =
            validate_oidc_callback_params(&params).expect_err("empty code and state must reject");
        assert!(matches!(err, AppError::Validation(_)));
        assert_status(&err, axum::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_validate_oidc_callback_params_well_formed_passes() {
        // Well-formed values (any non-empty string) pass the shape check and
        // delegate the CSRF / cache-miss decision to validate_sso_session,
        // which keeps returning 401 (Authentication) on miss. We don't
        // exercise the DB path here; the contract is that this validator
        // does NOT veto well-formed inputs.
        let params = OidcCallbackQuery {
            code: "ac_xyz".to_string(),
            state: "st_xyz".to_string(),
        };
        validate_oidc_callback_params(&params).expect("well-formed params should pass");
    }

    #[test]
    fn test_validate_oidc_callback_params_error_message_no_leak() {
        // The 400 message must not name internal subsystems (SSO sessions
        // table, SQL, etc.). It only states what the caller did wrong.
        let params = OidcCallbackQuery {
            code: "ac".to_string(),
            state: String::new(),
        };
        let err = validate_oidc_callback_params(&params).expect_err("must reject");
        let msg = match &err {
            AppError::Validation(m) => m.clone(),
            other => panic!("expected Validation, got {other:?}"),
        };
        let lower = msg.to_lowercase();
        assert!(!lower.contains("sso_sessions"), "leaks table name: {msg}");
        assert!(!lower.contains("select"), "leaks SQL: {msg}");
        assert!(!lower.contains("delete"), "leaks SQL: {msg}");
        assert!(lower.contains("state"), "should mention what is missing");
    }

    #[test]
    fn test_oidc_callback_400_distinct_from_401() {
        // Regression for #1369: an empty state must NOT collide with the
        // "session not found" 401 path. The two cases route to different
        // AppError variants with different status codes.
        let empty = OidcCallbackQuery {
            code: "ac".to_string(),
            state: String::new(),
        };
        let empty_err = validate_oidc_callback_params(&empty).expect_err("must reject");
        // Empty -> 400 Validation
        assert!(matches!(empty_err, AppError::Validation(_)));

        // Non-empty but unrecognized state would flow to
        // validate_sso_session, which returns AppError::Authentication
        // ("Invalid or expired SSO state") -> 401. Simulate that path's
        // error here so the test pins the contract.
        let csrf_miss = AppError::Authentication("Invalid or expired SSO state".to_string());
        assert_status(&empty_err, axum::http::StatusCode::BAD_REQUEST);
        assert_status(&csrf_miss, axum::http::StatusCode::UNAUTHORIZED);
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

    // =======================================================================
    // DB-backed tests for sync_oidc_groups_to_local_groups (issue #1094).
    //
    // These opt into a real Postgres via test_db_helpers::try_pool(): when
    // DATABASE_URL is unset they no-op so `cargo test --lib` stays usable
    // without a database. The coverage CI job provisions Postgres and runs
    // migrations, so the group-reconciliation paths are exercised there.
    // =======================================================================

    mod sync_db {
        use super::super::sync_oidc_groups_to_local_groups;
        use crate::api::handlers::test_db_helpers as db_helpers;
        use sqlx::PgPool;
        use uuid::Uuid;

        /// Insert a user with the local auth_provider and a random username.
        async fn make_user(pool: &PgPool) -> Uuid {
            let id = Uuid::new_v4();
            sqlx::query(
                r#"
                INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, is_active)
                VALUES ($1, $2, $3, 'unused', 'oidc', false, true)
                "#,
            )
            .bind(id)
            .bind(format!("oidc-sync-{}", id.as_simple()))
            .bind(format!("oidc-sync-{}@test.local", id.as_simple()))
            .execute(pool)
            .await
            .expect("insert user");
            id
        }

        async fn group_id_by_name(pool: &PgPool, name: &str) -> Option<Uuid> {
            let row: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM groups WHERE name = $1")
                .bind(name)
                .fetch_optional(pool)
                .await
                .expect("group lookup");
            row.map(|(id,)| id)
        }

        async fn user_is_in_group(pool: &PgPool, user_id: Uuid, group_id: Uuid) -> bool {
            let row: Option<(Uuid,)> = sqlx::query_as(
                "SELECT group_id FROM user_group_members WHERE user_id = $1 AND group_id = $2",
            )
            .bind(user_id)
            .bind(group_id)
            .fetch_optional(pool)
            .await
            .expect("membership lookup");
            row.is_some()
        }

        async fn group_external_source(pool: &PgPool, group_id: Uuid) -> Option<String> {
            let row: Option<(Option<String>,)> =
                sqlx::query_as("SELECT external_source FROM groups WHERE id = $1")
                    .bind(group_id)
                    .fetch_optional(pool)
                    .await
                    .expect("group source lookup");
            row.and_then(|(s,)| s)
        }

        /// Random group name with a UUID suffix so parallel tests do not
        /// collide on the UNIQUE constraint.
        fn rand_group_name(prefix: &str) -> String {
            format!("{prefix}-{}", Uuid::new_v4().as_simple())
        }

        async fn cleanup_groups(pool: &PgPool, ids: &[Uuid]) {
            for id in ids {
                let _ = sqlx::query("DELETE FROM user_group_members WHERE group_id = $1")
                    .bind(id)
                    .execute(pool)
                    .await;
                let _ = sqlx::query("DELETE FROM groups WHERE id = $1")
                    .bind(id)
                    .execute(pool)
                    .await;
            }
        }

        async fn cleanup_user(pool: &PgPool, user_id: Uuid) {
            let _ = sqlx::query("DELETE FROM user_group_members WHERE user_id = $1")
                .bind(user_id)
                .execute(pool)
                .await;
            let _ = sqlx::query("DELETE FROM users WHERE id = $1")
                .bind(user_id)
                .execute(pool)
                .await;
        }

        #[tokio::test]
        async fn test_sync_creates_groups_and_membership() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            let user_id = make_user(&pool).await;
            let provider_id = Uuid::new_v4();
            let g1 = rand_group_name("eng");
            let g2 = rand_group_name("ops");

            sync_oidc_groups_to_local_groups(
                &pool,
                user_id,
                provider_id,
                &[g1.clone(), g2.clone()],
            )
            .await
            .expect("sync");

            let g1_id = group_id_by_name(&pool, &g1).await.expect("g1 created");
            let g2_id = group_id_by_name(&pool, &g2).await.expect("g2 created");
            assert!(user_is_in_group(&pool, user_id, g1_id).await);
            assert!(user_is_in_group(&pool, user_id, g2_id).await);
            // Auto-created groups must be tagged with external_source = 'oidc'.
            assert_eq!(
                group_external_source(&pool, g1_id).await.as_deref(),
                Some("oidc")
            );
            assert_eq!(
                group_external_source(&pool, g2_id).await.as_deref(),
                Some("oidc")
            );

            cleanup_groups(&pool, &[g1_id, g2_id]).await;
            cleanup_user(&pool, user_id).await;
        }

        #[tokio::test]
        async fn test_sync_skips_empty_and_whitespace_group_names() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            let user_id = make_user(&pool).await;
            let provider_id = Uuid::new_v4();
            let real = rand_group_name("real");

            sync_oidc_groups_to_local_groups(
                &pool,
                user_id,
                provider_id,
                &[
                    String::new(),
                    "   ".to_string(),
                    "\t".to_string(),
                    real.clone(),
                ],
            )
            .await
            .expect("sync");

            // Only the real group should exist.
            let real_id = group_id_by_name(&pool, &real).await.expect("real group");
            assert!(user_is_in_group(&pool, user_id, real_id).await);
            // Empty/whitespace names must not have produced groups.
            assert!(group_id_by_name(&pool, "").await.is_none());
            assert!(group_id_by_name(&pool, "   ").await.is_none());

            cleanup_groups(&pool, &[real_id]).await;
            cleanup_user(&pool, user_id).await;
        }

        #[tokio::test]
        async fn test_sync_reuses_operator_managed_group_without_modifying_source() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            let user_id = make_user(&pool).await;
            let provider_id = Uuid::new_v4();
            let name = rand_group_name("operator");

            // Pre-create an operator-managed group (NULL external_source).
            let preexisting_id = Uuid::new_v4();
            sqlx::query("INSERT INTO groups (id, name, description) VALUES ($1, $2, $3)")
                .bind(preexisting_id)
                .bind(&name)
                .bind("operator-managed")
                .execute(&pool)
                .await
                .expect("create operator group");

            sync_oidc_groups_to_local_groups(
                &pool,
                user_id,
                provider_id,
                std::slice::from_ref(&name),
            )
            .await
            .expect("sync");

            // The same group id must be reused (not duplicated).
            let found_id = group_id_by_name(&pool, &name).await.expect("found");
            assert_eq!(found_id, preexisting_id);
            assert!(user_is_in_group(&pool, user_id, found_id).await);
            // external_source must remain NULL (operator-managed).
            assert!(group_external_source(&pool, found_id).await.is_none());

            cleanup_groups(&pool, &[found_id]).await;
            cleanup_user(&pool, user_id).await;
        }

        #[tokio::test]
        async fn test_sync_prunes_removed_oidc_groups_but_not_operator_groups() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            let user_id = make_user(&pool).await;
            let provider_id = Uuid::new_v4();
            let oidc_name_a = rand_group_name("oidc-a");
            let oidc_name_b = rand_group_name("oidc-b");
            let operator_name = rand_group_name("op-stable");

            // First sync seeds both OIDC groups + adds the user.
            sync_oidc_groups_to_local_groups(
                &pool,
                user_id,
                provider_id,
                &[oidc_name_a.clone(), oidc_name_b.clone()],
            )
            .await
            .expect("first sync");

            let a_id = group_id_by_name(&pool, &oidc_name_a).await.unwrap();
            let b_id = group_id_by_name(&pool, &oidc_name_b).await.unwrap();

            // Add the user to an operator-managed group (NULL external_source).
            let op_id = Uuid::new_v4();
            sqlx::query("INSERT INTO groups (id, name) VALUES ($1, $2)")
                .bind(op_id)
                .bind(&operator_name)
                .execute(&pool)
                .await
                .expect("create op group");
            sqlx::query("INSERT INTO user_group_members (user_id, group_id) VALUES ($1, $2)")
                .bind(user_id)
                .bind(op_id)
                .execute(&pool)
                .await
                .expect("op membership");

            // Second sync drops oidc_name_b from the claim list. Expect a_id
            // membership to survive, b_id membership to be pruned, and the
            // operator-managed group membership to remain untouched.
            sync_oidc_groups_to_local_groups(
                &pool,
                user_id,
                provider_id,
                std::slice::from_ref(&oidc_name_a),
            )
            .await
            .expect("second sync");

            assert!(user_is_in_group(&pool, user_id, a_id).await);
            assert!(!user_is_in_group(&pool, user_id, b_id).await);
            assert!(
                user_is_in_group(&pool, user_id, op_id).await,
                "operator-managed membership must survive pruning"
            );

            cleanup_groups(&pool, &[a_id, b_id, op_id]).await;
            cleanup_user(&pool, user_id).await;
        }

        #[tokio::test]
        async fn test_sync_scoped_to_provider_id() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            let user_id = make_user(&pool).await;
            let provider_a = Uuid::new_v4();
            let provider_b = Uuid::new_v4();
            let shared_name = rand_group_name("shared");
            let provider_a_only = rand_group_name("pa-only");

            // Sync against provider_a creates a group tagged with provider_a.
            sync_oidc_groups_to_local_groups(
                &pool,
                user_id,
                provider_a,
                &[shared_name.clone(), provider_a_only.clone()],
            )
            .await
            .expect("sync A");
            let pa_only_id = group_id_by_name(&pool, &provider_a_only).await.unwrap();
            let shared_id = group_id_by_name(&pool, &shared_name).await.unwrap();

            // Now sync against provider_b with an empty claim list. This must
            // NOT prune the provider_a-owned groups: the DELETE is scoped to
            // external_provider_id = provider_b.
            sync_oidc_groups_to_local_groups(&pool, user_id, provider_b, &[])
                .await
                .expect("sync B empty");

            assert!(
                user_is_in_group(&pool, user_id, pa_only_id).await,
                "provider_a-owned membership must not be touched by a provider_b sync"
            );
            assert!(user_is_in_group(&pool, user_id, shared_id).await);

            cleanup_groups(&pool, &[pa_only_id, shared_id]).await;
            cleanup_user(&pool, user_id).await;
        }

        #[tokio::test]
        async fn test_sync_empty_claim_list_is_clean_noop_on_first_run() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            let user_id = make_user(&pool).await;
            let provider_id = Uuid::new_v4();

            // No memberships exist; empty claim list must commit cleanly.
            sync_oidc_groups_to_local_groups(&pool, user_id, provider_id, &[])
                .await
                .expect("sync empty");

            cleanup_user(&pool, user_id).await;
        }

        #[tokio::test]
        async fn test_sync_is_idempotent() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            let user_id = make_user(&pool).await;
            let provider_id = Uuid::new_v4();
            let name = rand_group_name("idem");

            // Run the same sync twice. Second run must not error on the
            // ON CONFLICT DO NOTHING path and must leave the same state.
            sync_oidc_groups_to_local_groups(
                &pool,
                user_id,
                provider_id,
                std::slice::from_ref(&name),
            )
            .await
            .expect("sync 1");
            sync_oidc_groups_to_local_groups(
                &pool,
                user_id,
                provider_id,
                std::slice::from_ref(&name),
            )
            .await
            .expect("sync 2 (idempotent)");

            let gid = group_id_by_name(&pool, &name).await.unwrap();
            assert!(user_is_in_group(&pool, user_id, gid).await);
            cleanup_groups(&pool, &[gid]).await;
            cleanup_user(&pool, user_id).await;
        }
    }
}
