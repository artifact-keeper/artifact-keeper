//! TOTP two-factor authentication handlers.

use std::sync::Arc;

use axum::{
    extract::State,
    response::{IntoResponse, Response},
    routing::post,
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};
use utoipa::{OpenApi, ToSchema};

use crate::api::handlers::auth::set_auth_cookies;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::auth_service::AuthService;

/// Build a TOTP instance from raw secret bytes and a username label.
fn build_totp(secret_bytes: Vec<u8>, username: String) -> Result<TOTP> {
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some("ArtifactKeeper".to_string()),
        username,
    )
    .map_err(|e| AppError::Internal(format!("TOTP error: {}", e)))
}

/// Decode a base32-encoded secret string into raw bytes.
fn decode_secret(encoded: &str) -> Result<Vec<u8>> {
    Secret::Encoded(encoded.to_string())
        .to_bytes()
        .map_err(|e| AppError::Internal(format!("Secret error: {}", e)))
}

/// Public TOTP routes (no auth required -- uses totp_token)
pub fn public_router() -> Router<SharedState> {
    Router::new().route("/verify", post(verify_totp))
}

/// Protected TOTP routes (requires auth)
pub fn protected_router() -> Router<SharedState> {
    Router::new()
        .route("/setup", post(setup_totp))
        .route("/enable", post(enable_totp))
        .route("/disable", post(disable_totp))
}

// --- Setup ---

#[derive(Debug, Serialize, ToSchema)]
pub struct TotpSetupResponse {
    pub secret: String,
    pub qr_code_url: String,
}

/// Generate a new TOTP secret and QR code URL for the authenticated user
#[utoipa::path(
    post,
    path = "/setup",
    context_path = "/api/v1/auth/totp",
    tag = "auth",
    responses(
        (status = 200, description = "TOTP setup details with secret and QR code URL", body = TotpSetupResponse),
        (status = 401, description = "Unauthorized", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn setup_totp(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<TotpSetupResponse>> {
    let secret = Secret::generate_secret();
    let secret_base32 = secret.to_encoded().to_string();

    // Get username for the TOTP label
    let user = sqlx::query!("SELECT username FROM users WHERE id = $1", auth.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let secret_bytes = secret
        .to_bytes()
        .map_err(|e| AppError::Internal(format!("Secret error: {}", e)))?;
    let totp = build_totp(secret_bytes, user.username.clone())?;

    let qr_code_url = totp.get_url();

    // Store the secret (not yet enabled)
    sqlx::query!(
        "UPDATE users SET totp_secret = $2 WHERE id = $1",
        auth.user_id,
        secret_base32
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(TotpSetupResponse {
        secret: secret_base32,
        qr_code_url,
    }))
}

// --- Enable ---

#[derive(Debug, Deserialize, ToSchema)]
pub struct TotpCodeRequest {
    pub code: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TotpEnableResponse {
    pub backup_codes: Vec<String>,
}

/// Enable TOTP by verifying the initial code and generating backup codes
#[utoipa::path(
    post,
    path = "/enable",
    context_path = "/api/v1/auth/totp",
    tag = "auth",
    request_body = TotpCodeRequest,
    responses(
        (status = 200, description = "TOTP enabled with backup codes", body = TotpEnableResponse),
        (status = 401, description = "Unauthorized or invalid TOTP code", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn enable_totp(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(payload): Json<TotpCodeRequest>,
) -> Result<Json<TotpEnableResponse>> {
    // Fetch stored secret
    let user = sqlx::query!("SELECT totp_secret FROM users WHERE id = $1", auth.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let secret_str = user.totp_secret.ok_or_else(|| {
        AppError::Validation("TOTP not set up. Call /auth/totp/setup first.".to_string())
    })?;

    let username_row = sqlx::query!("SELECT username FROM users WHERE id = $1", auth.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let totp = build_totp(decode_secret(&secret_str)?, username_row.username)?;

    // Verify code
    if !totp
        .check_current(&payload.code)
        .map_err(|e| AppError::Internal(format!("TOTP check error: {}", e)))?
    {
        return Err(AppError::Authentication("Invalid TOTP code".to_string()));
    }

    // Generate backup codes (scoped to drop rng before any .await)
    let (backup_codes, hashed_codes) = {
        use rand::Rng;
        let mut rng = rand::rng();
        let codes: Vec<String> = (0..10)
            .map(|_| {
                let code: String = (0..8)
                    .map(|_| {
                        let idx = rng.random_range(0..36u32);
                        if idx < 10 {
                            (b'0' + idx as u8) as char
                        } else {
                            (b'A' + (idx - 10) as u8) as char
                        }
                    })
                    .collect();
                format!("{}-{}", &code[..4], &code[4..])
            })
            .collect();
        let hashed: Vec<String> = codes
            .iter()
            .map(|code| {
                let clean = code.replace('-', "");
                bcrypt::hash(&clean, 10).unwrap_or_default()
            })
            .collect();
        (codes, hashed)
    };
    let hashed_json = serde_json::to_string(&hashed_codes)
        .map_err(|e| AppError::Internal(format!("JSON error: {}", e)))?;

    // Enable TOTP
    sqlx::query!(
        "UPDATE users SET totp_enabled = true, totp_backup_codes = $2, totp_verified_at = NOW() WHERE id = $1",
        auth.user_id,
        hashed_json
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(TotpEnableResponse { backup_codes }))
}

// --- Verify (during login) ---

#[derive(Debug, Deserialize, ToSchema)]
pub struct TotpVerifyRequest {
    pub totp_token: String,
    pub code: String,
}

/// Verify TOTP code during login (exchanges totp_token + code for full auth tokens)
#[utoipa::path(
    post,
    path = "/verify",
    context_path = "/api/v1/auth/totp",
    tag = "auth",
    request_body = TotpVerifyRequest,
    responses(
        (status = 200, description = "TOTP verified, authentication tokens returned", body = super::auth::LoginResponse),
        (status = 401, description = "Invalid TOTP code or token", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn verify_totp(
    State(state): State<SharedState>,
    Json(payload): Json<TotpVerifyRequest>,
) -> Result<Response> {
    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));

    // Validate the pending token
    let claims = auth_service.validate_totp_pending_token(&payload.totp_token)?;

    // Fetch user
    let user_row = sqlx::query!(
        "SELECT totp_secret, totp_enabled, totp_backup_codes, username FROM users WHERE id = $1 AND is_active = true",
        claims.sub
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::Authentication("User not found".to_string()))?;

    if !user_row.totp_enabled {
        return Err(AppError::Authentication(
            "TOTP not enabled for this user".to_string(),
        ));
    }

    let secret_str = user_row
        .totp_secret
        .ok_or_else(|| AppError::Authentication("TOTP not configured".to_string()))?;

    let totp = build_totp(decode_secret(&secret_str)?, user_row.username.clone())?;

    let code_valid = totp
        .check_current(&payload.code)
        .map_err(|e| AppError::Internal(format!("TOTP check error: {}", e)))?;

    if !code_valid {
        // Try backup codes
        let clean_code = payload.code.replace('-', "").to_uppercase();
        let mut backup_used = false;

        if let Some(ref backup_json) = user_row.totp_backup_codes {
            if let Ok(hashed_codes) = serde_json::from_str::<Vec<String>>(backup_json) {
                for (i, hash) in hashed_codes.iter().enumerate() {
                    if !hash.is_empty() && bcrypt::verify(&clean_code, hash).unwrap_or(false) {
                        // Remove used backup code
                        let mut codes = hashed_codes.clone();
                        codes[i] = String::new();
                        let updated_json = serde_json::to_string(&codes)
                            .map_err(|e| AppError::Internal(format!("JSON error: {}", e)))?;
                        sqlx::query!(
                            "UPDATE users SET totp_backup_codes = $2 WHERE id = $1",
                            claims.sub,
                            updated_json
                        )
                        .execute(&state.db)
                        .await
                        .map_err(|e| AppError::Database(e.to_string()))?;
                        backup_used = true;
                        break;
                    }
                }
            }
        }

        if !backup_used {
            return Err(AppError::Authentication("Invalid TOTP code".to_string()));
        }
    }

    // TOTP verified -- now fetch full user and generate real tokens
    use crate::models::user::{AuthProvider, User};
    let user = sqlx::query_as!(
        User,
        r#"
        SELECT
            id, username, email, password_hash, display_name,
            auth_provider as "auth_provider: AuthProvider",
            external_id, is_admin, is_active, must_change_password,
            totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
            last_login_at, created_at, updated_at
        FROM users
        WHERE id = $1 AND is_active = true
        "#,
        claims.sub
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // Update last login
    sqlx::query!(
        "UPDATE users SET last_login_at = NOW() WHERE id = $1",
        claims.sub
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let tokens = auth_service.generate_tokens(&user)?;

    let body = super::auth::LoginResponse {
        access_token: tokens.access_token.clone(),
        refresh_token: tokens.refresh_token.clone(),
        expires_in: tokens.expires_in,
        token_type: "Bearer".to_string(),
        must_change_password: user.must_change_password,
        totp_required: None,
        totp_token: None,
    };

    let mut response = Json(body).into_response();
    set_auth_cookies(
        response.headers_mut(),
        &tokens.access_token,
        &tokens.refresh_token,
        tokens.expires_in,
    );
    Ok(response)
}

// --- Disable ---

#[derive(Debug, Deserialize, ToSchema)]
pub struct TotpDisableRequest {
    pub password: String,
    pub code: String,
}

/// Disable TOTP for the authenticated user (requires password and current TOTP code)
#[utoipa::path(
    post,
    path = "/disable",
    context_path = "/api/v1/auth/totp",
    tag = "auth",
    request_body = TotpDisableRequest,
    responses(
        (status = 200, description = "TOTP disabled successfully"),
        (status = 401, description = "Invalid password or TOTP code", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn disable_totp(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(payload): Json<TotpDisableRequest>,
) -> Result<()> {
    // Verify password
    let user = sqlx::query!(
        "SELECT password_hash, totp_secret, totp_enabled, username FROM users WHERE id = $1",
        auth.user_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let password_hash = user
        .password_hash
        .ok_or_else(|| AppError::Authentication("No password set".to_string()))?;

    if !bcrypt::verify(&payload.password, &password_hash)
        .map_err(|e| AppError::Internal(format!("Password verification failed: {}", e)))?
    {
        return Err(AppError::Authentication("Invalid password".to_string()));
    }

    // Verify TOTP code
    if !user.totp_enabled {
        return Err(AppError::Validation("TOTP is not enabled".to_string()));
    }

    let secret_str = user
        .totp_secret
        .ok_or_else(|| AppError::Authentication("TOTP not configured".to_string()))?;

    let totp = build_totp(decode_secret(&secret_str)?, user.username)?;

    if !totp
        .check_current(&payload.code)
        .map_err(|e| AppError::Internal(format!("TOTP check error: {}", e)))?
    {
        return Err(AppError::Authentication("Invalid TOTP code".to_string()));
    }

    // Disable TOTP
    sqlx::query!(
        "UPDATE users SET totp_secret = NULL, totp_enabled = false, totp_backup_codes = NULL, totp_verified_at = NULL WHERE id = $1",
        auth.user_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(())
}

#[derive(OpenApi)]
#[openapi(
    paths(setup_totp, enable_totp, verify_totp, disable_totp,),
    components(schemas(
        TotpSetupResponse,
        TotpCodeRequest,
        TotpEnableResponse,
        TotpVerifyRequest,
        TotpDisableRequest,
    ))
)]
pub struct TotpApiDoc;
