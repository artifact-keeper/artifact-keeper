//! Public SSO flow endpoints (no auth middleware required).
//!
//! Handles OIDC login redirects, callbacks, and SAML endpoints.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    response::Redirect,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::user::AuthProvider;
use crate::services::auth_config_service::{AuthConfigService, SsoProviderInfo};
use crate::services::auth_service::{AuthService, FederatedCredentials};

/// Create public SSO routes (no auth required)
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/providers", get(list_providers))
        .route("/oidc/:id/login", get(oidc_login))
        .route("/oidc/:id/callback", get(oidc_callback))
        .route("/saml/:id/login", get(saml_login))
        .route("/saml/:id/acs", post(saml_acs))
}

// ---------------------------------------------------------------------------
// List enabled providers (public)
// ---------------------------------------------------------------------------

async fn list_providers(
    State(state): State<SharedState>,
) -> Result<Json<Vec<SsoProviderInfo>>> {
    let result = AuthConfigService::list_enabled_providers(&state.db).await?;
    Ok(Json(result))
}

// ---------------------------------------------------------------------------
// OIDC login redirect
// ---------------------------------------------------------------------------

async fn oidc_login(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Redirect> {
    // 1. Get decrypted OIDC config
    let (row, _client_secret) =
        AuthConfigService::get_oidc_decrypted(&state.db, id).await?;

    // 2. Create SSO session for CSRF protection (generates state + nonce internally)
    let session =
        AuthConfigService::create_sso_session(&state.db, "oidc", id).await?;
    let state_str = session.state;
    let nonce_str = session.nonce.unwrap_or_default();

    // 4. Fetch OIDC discovery document to find authorization_endpoint
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

    // 5. Build redirect_uri (default to our callback endpoint)
    let redirect_uri = format!("/api/v1/auth/sso/oidc/{id}/callback");

    // 6. Build authorization URL
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

#[derive(Debug, Deserialize)]
struct OidcCallbackQuery {
    code: String,
    state: String,
}

async fn oidc_callback(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Query(params): Query<OidcCallbackQuery>,
) -> Result<Redirect> {
    // 1. Validate SSO session (CSRF check)
    let _session =
        AuthConfigService::validate_sso_session(&state.db, &params.state).await?;

    // 2. Get decrypted OIDC config
    let (row, client_secret) =
        AuthConfigService::get_oidc_decrypted(&state.db, id).await?;

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

    let email = claims["email"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    let preferred_username = claims["preferred_username"]
        .as_str()
        .or_else(|| claims["email"].as_str())
        .unwrap_or(&sub)
        .to_string();

    let display_name = claims["name"]
        .as_str()
        .map(|s| s.to_string());

    let groups = claims["groups"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // 8. Authenticate via federated flow (find/create user + generate tokens)
    let auth_service =
        AuthService::new(state.db.clone(), Arc::new(state.config.clone()));

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

    // 9. Redirect to frontend with tokens
    let frontend_url = format!(
        "/auth/callback?token={}&refresh_token={}",
        urlencoding::encode(&tokens.access_token),
        urlencoding::encode(&tokens.refresh_token),
    );

    Ok(Redirect::temporary(&frontend_url))
}

// ---------------------------------------------------------------------------
// SAML (placeholder)
// ---------------------------------------------------------------------------

async fn saml_login(
    Path(_id): Path<Uuid>,
) -> Result<Redirect> {
    Err(AppError::Internal(
        "SAML SSO not yet implemented".into(),
    ))
}

async fn saml_acs(
    Path(_id): Path<Uuid>,
) -> Result<Redirect> {
    Err(AppError::Internal(
        "SAML SSO not yet implemented".into(),
    ))
}

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
