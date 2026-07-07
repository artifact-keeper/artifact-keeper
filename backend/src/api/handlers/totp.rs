//! TOTP two-factor authentication handlers.

use std::sync::Arc;

use axum::{
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::post,
    Extension, Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};
use utoipa::{OpenApi, ToSchema};

use crate::api::extractors::request_scheme_is_https;
use crate::api::handlers::auth::set_auth_cookies;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::audit_service::{
    audit_fire_and_forget, sessions_invalidated_audit_entry, totp_audit_entry, AuditAction,
    AuditEntry, ResourceType,
};
use crate::services::auth_service::{invalidate_other_sessions, AuthService};

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

/// Normalize a user-supplied backup code into the canonical form that is
/// bcrypt-matched: strip dashes and upper-case. Pure and unit-testable.
fn normalize_backup_code(code: &str) -> String {
    code.replace('-', "").to_uppercase()
}

/// True when this slot is a live (not-yet-consumed) backup-code hash. An empty
/// string marks an already-consumed slot and is skipped. Pure helper so the
/// skip logic is unit-testable without running bcrypt.
fn is_live_backup_slot(hash: &str) -> bool {
    !hash.is_empty()
}

/// Find the index of the first non-empty backup-code hash that matches
/// `clean_code` (normalization already applied by the caller via
/// [`normalize_backup_code`]).
///
/// First-match-wins over the slots, preserving the consume-exactly-once
/// invariant (#1822). Each candidate bcrypt verify runs through
/// [`AuthService::verify_password`] so it is offloaded with
/// `spawn_blocking` and bounded by the process-wide auth-concurrency
/// semaphore — exactly like password login — instead of blocking a tokio
/// worker inline. An empty hash marks an already-consumed slot and is skipped.
async fn find_backup_code_index(hashed_codes: &[String], clean_code: &str) -> Option<usize> {
    for (idx, hash) in hashed_codes.iter().enumerate() {
        if !is_live_backup_slot(hash) {
            continue;
        }
        // bcrypt::verify reads the cost from the stored hash, so both legacy
        // cost-10 and newer DEFAULT_COST backup-code hashes verify here.
        if AuthService::verify_password(clean_code, hash)
            .await
            .unwrap_or(false)
        {
            return Some(idx);
        }
    }
    None
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

    // Generate the plaintext backup codes (scoped to drop rng before any
    // .await — the rng is not Send).
    let backup_codes: Vec<String> = {
        use rand::Rng;
        let mut rng = rand::rng();
        (0..10)
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
            .collect()
    };
    // Hash each code through the capped + spawn_blocking auth path
    // (`AuthService::hash_password`) so the 10 bcrypt hashes are offloaded
    // off the tokio worker and bounded by the auth-concurrency semaphore,
    // instead of running inline and starving the runtime.
    let mut hashed_codes: Vec<String> = Vec::with_capacity(backup_codes.len());
    for code in &backup_codes {
        let clean = code.replace('-', "");
        hashed_codes.push(AuthService::hash_password(&clean).await?);
    }
    let hashed_json = serde_json::to_string(&hashed_codes)
        .map_err(|e| AppError::Internal(format!("JSON error: {}", e)))?;

    // Enable TOTP. We bump `totp_verified_at` to a value that invalidates
    // every JWT issued strictly before the calling session's `iat` while
    // letting the calling token itself survive (#1370). The DB-backed check
    // at `is_token_invalidated_replica_safe` uses strict `<` so a token
    // whose `iat` equals the watermark passes; pre-fix this UPDATE used
    // `NOW()`, which on a fast test path always exceeded the caller's `iat`
    // and locked the caller out of their own session right after enable.
    //
    // When the caller didn't use a JWT (no `iat`), fall back to `NOW()` so
    // the original #1146 semantic still holds for any other JWT sessions
    // this user has.
    let caller_iat_ms = auth.caller_iat_ms();
    let verified_ts: DateTime<Utc> = match caller_iat_ms {
        Some(iat_ms) => DateTime::<Utc>::from_timestamp_millis(iat_ms).ok_or_else(|| {
            AppError::Internal(format!(
                "Invalid caller iat_ms for totp_verified_at: {iat_ms}"
            ))
        })?,
        None => Utc::now(),
    };
    sqlx::query!(
        "UPDATE users SET totp_enabled = true, totp_backup_codes = $2, totp_verified_at = $3 WHERE id = $1",
        auth.user_id,
        hashed_json,
        verified_ts
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // Enabling 2FA is a credential change: invalidate every JWT issued before
    // this point so existing sessions cannot keep operating under the old
    // (TOTP-not-required) policy. The calling session is exempted so the
    // user is not signed out by their own action (#1370); every other
    // session is still killed.
    //
    // Refresh tokens are revoked via the DB on every replica below so the
    // OAuth refresh-grant cannot mint a fresh access token from a stale
    // refresh JWT — that's the original #1146 threat.
    invalidate_other_sessions(auth.user_id, caller_iat_ms);

    // Refresh-token family revocation (#1146 / #1370): a refresh JWT issued
    // before TOTP was enabled stays valid until natural expiry. Mark every
    // active row in `refresh_token_jti` for this user as revoked so the
    // DB-backed replay check rejects them on every replica.
    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    if let Err(e) = auth_service
        .revoke_all_refresh_token_families(auth.user_id)
        .await
    {
        // Best-effort: a failure here is logged but does not block enable.
        // The in-memory watermark and DB `totp_verified_at` already block
        // refresh-grant on this replica; the explicit family revocation
        // covers the cross-replica fan-out window.
        tracing::warn!(
            user_id = %auth.user_id,
            error = %e,
            "Failed to revoke refresh-token families after TOTP enable",
        );
    }

    // Audit the credential-posture change and the mass session invalidation
    // it triggered (#386). Fire-and-forget and placed AFTER the state change
    // has committed so an audit-table outage can never fail the enable.
    audit_fire_and_forget(
        state.db.clone(),
        totp_audit_entry(AuditAction::TotpEnabled, auth.user_id),
    )
    .await;
    audit_fire_and_forget(
        state.db.clone(),
        sessions_invalidated_audit_entry(auth.user_id, auth.user_id, "totp_enable"),
    )
    .await;

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
    headers: HeaderMap,
    Json(payload): Json<TotpVerifyRequest>,
) -> Result<Response> {
    let client_is_https = request_scheme_is_https(&headers);
    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));

    // Validate the pending token, then atomically consume its `jti` so it is
    // single-use. This caps a stolen/replayed pending token to one verify
    // attempt -- defeating brute force of the 6-digit code (#1820) and
    // serializing concurrent backup-code verifies (#1822).
    let claims = auth_service.validate_totp_pending_token(&payload.totp_token)?;
    auth_service.consume_totp_pending_jti(&claims).await?;

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
        // A 2FA login attempt against a user without TOTP enabled is a failed
        // login; record it (#386). Fire-and-forget, non-gating.
        audit_fire_and_forget(
            state.db.clone(),
            AuditEntry::new(AuditAction::LoginFailed, ResourceType::User)
                .user(claims.sub)
                .resource(claims.sub)
                .details(serde_json::json!({ "reason": "totp_not_enabled" })),
        )
        .await;
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

    // Track which factor authenticated so the success audit event can label
    // the login method (#386): a primary TOTP code vs a one-time backup code.
    let mut used_backup_code = false;

    if !code_valid {
        // Try backup codes. Consumption must be atomic: a previous read of
        // `user_row.totp_backup_codes` is a stale snapshot, and concurrent
        // verifiers sharing it would each pass bcrypt and clobber each other's
        // UPDATE (last-write-wins), letting one code authenticate many
        // sessions (TOCTOU, #1822). Re-read under `SELECT ... FOR UPDATE`
        // inside a transaction so concurrent verifiers serialize on the row
        // and only the first observes the code as unused.
        let clean_code = normalize_backup_code(&payload.code);

        let mut tx = state
            .db
            .begin()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        let locked_json: Option<String> =
            sqlx::query_scalar("SELECT totp_backup_codes FROM users WHERE id = $1 FOR UPDATE")
                .bind(claims.sub)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;

        let backup_used = match locked_json
            .as_deref()
            .and_then(|j| serde_json::from_str::<Vec<String>>(j).ok())
        {
            Some(hashed_codes) => match find_backup_code_index(&hashed_codes, &clean_code).await {
                Some(idx) => {
                    let mut codes = hashed_codes;
                    codes[idx] = String::new();
                    let updated_json = serde_json::to_string(&codes)
                        .map_err(|e| AppError::Internal(format!("JSON error: {}", e)))?;
                    sqlx::query("UPDATE users SET totp_backup_codes = $2 WHERE id = $1")
                        .bind(claims.sub)
                        .bind(updated_json)
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| AppError::Database(e.to_string()))?;
                    true
                }
                None => false,
            },
            None => false,
        };

        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        if !backup_used {
            // Neither the primary TOTP code nor a backup code matched: this is
            // a failed 2FA login and MUST be audited (#386). Fire-and-forget,
            // non-gating, emitted before returning the error.
            audit_fire_and_forget(
                state.db.clone(),
                AuditEntry::new(AuditAction::LoginFailed, ResourceType::User)
                    .user(claims.sub)
                    .resource(claims.sub)
                    .details(serde_json::json!({
                        "reason": "invalid_totp_code",
                        "method": "totp",
                    })),
            )
            .await;
            return Err(AppError::Authentication("Invalid TOTP code".to_string()));
        }
        used_backup_code = true;
    }

    // TOTP verified -- now fetch full user and generate real tokens
    use crate::models::user::{AuthProvider, User};
    let user = sqlx::query_as!(
        User,
        r#"
        SELECT
            id, username, email, password_hash, display_name,
            auth_provider as "auth_provider: AuthProvider",
            external_id, is_admin, is_active, is_service_account, must_change_password,
            totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
            failed_login_attempts, locked_until, last_failed_login_at,
            password_changed_at, last_login_at, created_at, updated_at
        FROM users
        WHERE id = $1 AND is_active = true
        "#,
        claims.sub
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // Update last login. Throttled to at most once per 5 minutes per user:
    // last_login_at is display-only, and package managers re-auth per request,
    // so unconditional writes cause needless WAL churn (#2107).
    sqlx::query!(
        "UPDATE users SET last_login_at = NOW() \
         WHERE id = $1 \
           AND (last_login_at IS NULL OR last_login_at < NOW() - INTERVAL '5 minutes')",
        claims.sub
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let tokens = auth_service.generate_tokens(&user)?;
    // Persist the refresh `jti` exactly like the password login path
    // (authenticate -> persist_refresh_jti_from_pair). Without this the
    // RFC 6819 reuse/replay check has no backing row for 2FA sessions, so
    // stolen refresh tokens of 2FA users are infinitely replayable and the
    // token family is never revoked (#1819).
    auth_service
        .persist_refresh_jti_from_pair(&tokens, user.id)
        .await?;

    // A completed TOTP verify IS a login: record it so 2FA users' logins are
    // no longer invisible in the audit trail (#386). Fire-and-forget,
    // non-gating, placed after the refresh jti is durably persisted.
    let method_label = if used_backup_code {
        "totp_backup_code"
    } else {
        "totp"
    };
    audit_fire_and_forget(
        state.db.clone(),
        AuditEntry::new(AuditAction::Login, ResourceType::User)
            .user(user.id)
            .resource(user.id)
            .details(serde_json::json!({
                "username": user.username,
                "method": method_label,
            })),
    )
    .await;

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
        client_is_https,
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

    // Verify through the capped + spawn_blocking auth path so this bcrypt
    // verify is offloaded and load-shed-bounded exactly like password login,
    // rather than blocking a tokio worker inline.
    if !AuthService::verify_password(&payload.password, &password_hash).await? {
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

    // Disable TOTP. `totp_verified_at` is cleared (NULL) so the DB-backed
    // credential-change watermark falls back to `password_changed_at` which
    // doesn't change here. To still invalidate other JWT sessions that were
    // issued under the TOTP-required policy, we set the in-memory watermark
    // explicitly via `invalidate_user_tokens_except_caller` below (#1370).
    sqlx::query!(
        "UPDATE users SET totp_secret = NULL, totp_enabled = false, totp_backup_codes = NULL, totp_verified_at = NULL WHERE id = $1",
        auth.user_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // Symmetric with `enable_totp`: removing 2FA is a credential change too.
    // Invalidate prior tokens issued under the stricter (TOTP-required)
    // policy while exempting the calling session so the user is not signed
    // out by their own disable action (#1370).
    invalidate_other_sessions(auth.user_id, auth.caller_iat_ms());

    // Refresh-token family revocation (#1146 / #1370): kill every refresh
    // JWT for this user across replicas so the OAuth refresh-grant cannot
    // mint a new access token from a stale refresh JWT minted under the
    // TOTP-required policy. Best-effort; logged on failure.
    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    if let Err(e) = auth_service
        .revoke_all_refresh_token_families(auth.user_id)
        .await
    {
        tracing::warn!(
            user_id = %auth.user_id,
            error = %e,
            "Failed to revoke refresh-token families after TOTP disable",
        );
    }

    // Audit the credential-posture change and the mass session invalidation
    // it triggered (#386). Fire-and-forget, POST-commit, non-gating.
    audit_fire_and_forget(
        state.db.clone(),
        totp_audit_entry(AuditAction::TotpDisabled, auth.user_id),
    )
    .await;
    audit_fire_and_forget(
        state.db.clone(),
        sessions_invalidated_audit_entry(auth.user_id, auth.user_id, "totp_disable"),
    )
    .await;

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

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // TotpSetupResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_totp_setup_response_serialize() {
        let resp = TotpSetupResponse {
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            qr_code_url:
                "otpauth://totp/ArtifactKeeper:admin?secret=JBSWY3DPEHPK3PXP&issuer=ArtifactKeeper"
                    .to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["secret"], "JBSWY3DPEHPK3PXP");
        assert!(json["qr_code_url"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://"));
    }

    #[test]
    fn test_totp_setup_response_serialize_empty() {
        let resp = TotpSetupResponse {
            secret: "".to_string(),
            qr_code_url: "".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["secret"], "");
        assert_eq!(json["qr_code_url"], "");
    }

    // -----------------------------------------------------------------------
    // TotpCodeRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_totp_code_request() {
        let json = r#"{"code": "123456"}"#;
        let req: TotpCodeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.code, "123456");
    }

    #[test]
    fn test_totp_code_request_empty_code() {
        let json = r#"{"code": ""}"#;
        let req: TotpCodeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.code, "");
    }

    #[test]
    fn test_totp_code_request_missing_field() {
        let json = r#"{}"#;
        let result = serde_json::from_str::<TotpCodeRequest>(json);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // TotpEnableResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_totp_enable_response_serialize() {
        let resp = TotpEnableResponse {
            backup_codes: vec!["ABCD-1234".to_string(), "EFGH-5678".to_string()],
        };
        let json = serde_json::to_value(&resp).unwrap();
        let codes = json["backup_codes"].as_array().unwrap();
        assert_eq!(codes.len(), 2);
        assert_eq!(codes[0], "ABCD-1234");
        assert_eq!(codes[1], "EFGH-5678");
    }

    #[test]
    fn test_totp_enable_response_serialize_empty() {
        let resp = TotpEnableResponse {
            backup_codes: vec![],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["backup_codes"].as_array().unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // TotpVerifyRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_totp_verify_request() {
        let json = r#"{"totp_token": "pending_abc123", "code": "654321"}"#;
        let req: TotpVerifyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.totp_token, "pending_abc123");
        assert_eq!(req.code, "654321");
    }

    #[test]
    fn test_totp_verify_request_missing_code() {
        let json = r#"{"totp_token": "tok"}"#;
        let result = serde_json::from_str::<TotpVerifyRequest>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_totp_verify_request_missing_token() {
        let json = r#"{"code": "123456"}"#;
        let result = serde_json::from_str::<TotpVerifyRequest>(json);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // TotpDisableRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_totp_disable_request() {
        let json = r#"{"password": "mypassword", "code": "123456"}"#;
        let req: TotpDisableRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.password, "mypassword");
        assert_eq!(req.code, "123456");
    }

    #[test]
    fn test_totp_disable_request_missing_password() {
        let json = r#"{"code": "123456"}"#;
        let result = serde_json::from_str::<TotpDisableRequest>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_totp_disable_request_missing_code() {
        let json = r#"{"password": "pass"}"#;
        let result = serde_json::from_str::<TotpDisableRequest>(json);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // build_totp helper
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_totp_success() {
        // Use a known valid secret (20 bytes for SHA1)
        let secret_bytes = vec![0u8; 20];
        let result = build_totp(secret_bytes, "testuser".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_totp_generates_6_digit_codes() {
        let secret_bytes = vec![
            0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde, 0xad, 0xbe, 0xef, 0x48, 0x65, 0x6c, 0x6c,
            0x6f, 0x21, 0xde, 0xad, 0xbe, 0xef,
        ];
        let totp = build_totp(secret_bytes, "user@example.com".to_string()).unwrap();
        // Generate a code at a specific time
        let code = totp.generate(1_000_000_000);
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_build_totp_uses_correct_issuer() {
        let secret_bytes = vec![0u8; 20];
        let totp = build_totp(secret_bytes, "admin".to_string()).unwrap();
        let url = totp.get_url();
        assert!(url.contains("ArtifactKeeper"));
        assert!(url.contains("admin"));
    }

    #[test]
    fn test_build_totp_url_format() {
        let secret_bytes = vec![0u8; 20];
        let totp = build_totp(secret_bytes, "testuser".to_string()).unwrap();
        let url = totp.get_url();
        assert!(url.starts_with("otpauth://totp/"));
    }

    // -----------------------------------------------------------------------
    // decode_secret helper
    // -----------------------------------------------------------------------

    #[test]
    fn test_decode_secret_valid() {
        // JBSWY3DPEHPK3PXP is base32 for "Hello!\xde\xad\xbe\xef"
        let result = decode_secret("JBSWY3DPEHPK3PXP");
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_decode_secret_round_trip() {
        // Generate a secret and decode it back
        let secret = Secret::generate_secret();
        let encoded = secret.to_encoded().to_string();
        let result = decode_secret(&encoded);
        assert!(result.is_ok());
    }

    #[test]
    fn test_decode_secret_invalid() {
        // "!!!invalid!!!" is not valid base32
        let result = decode_secret("!!!invalid!!!");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Backup code cleanup logic (from verify_totp)
    // -----------------------------------------------------------------------

    #[test]
    fn test_backup_code_clean_format() {
        assert_eq!(normalize_backup_code("ABCD-1234"), "ABCD1234");
    }

    #[test]
    fn test_backup_code_clean_already_clean() {
        assert_eq!(normalize_backup_code("ABCD1234"), "ABCD1234");
    }

    #[test]
    fn test_backup_code_clean_lowercase() {
        assert_eq!(normalize_backup_code("abcd-1234"), "ABCD1234");
    }

    #[test]
    fn test_is_live_backup_slot() {
        assert!(is_live_backup_slot("$2b$10$somehash"));
        assert!(!is_live_backup_slot(""));
    }

    // -----------------------------------------------------------------------
    // find_backup_code_index — first-match-wins over live slots, skips
    // consumed (empty) slots, and matches regardless of stored bcrypt cost
    // (verify reads the cost from the hash, so legacy cost-10 and newer
    // DEFAULT_COST hashes both verify).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_find_backup_code_index_matches_first_live_slot() {
        let clean = "1YUU4B8U";
        let hashed = vec![
            String::new(),                          // already consumed
            bcrypt::hash(clean, 4).expect("hash"),  // the match
            bcrypt::hash(clean, 4).expect("hash2"), // duplicate, must not win
        ];
        assert_eq!(find_backup_code_index(&hashed, clean).await, Some(1));
    }

    #[tokio::test]
    async fn test_find_backup_code_index_no_match() {
        let hashed = vec![bcrypt::hash("OTHERCODE", 4).expect("hash")];
        assert_eq!(find_backup_code_index(&hashed, "1YUU4B8U").await, None);
    }

    #[tokio::test]
    async fn test_find_backup_code_index_skips_empty() {
        let clean = "ABCD1234";
        let hashed = vec![String::new(), String::new()];
        assert_eq!(find_backup_code_index(&hashed, clean).await, None);
    }

    #[tokio::test]
    async fn test_find_backup_code_index_legacy_cost10_still_verifies() {
        // A pre-existing cost-10 hash (the old enable_totp default) must keep
        // verifying after the fix routes hashing through DEFAULT_COST.
        let clean = "C0ST10VR";
        let legacy = bcrypt::hash(clean, 10).expect("legacy cost-10 hash");
        let hashed = vec![legacy];
        assert_eq!(find_backup_code_index(&hashed, clean).await, Some(0));
    }

    // -----------------------------------------------------------------------
    // Backup codes JSON serialization/deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_backup_codes_json_roundtrip() {
        let codes = vec!["hash1".to_string(), "hash2".to_string(), "".to_string()];
        let json = serde_json::to_string(&codes).unwrap();
        let parsed: Vec<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0], "hash1");
        assert_eq!(parsed[2], "");
    }

    #[test]
    fn test_backup_codes_marking_used() {
        let hashed_codes = vec![
            "hash_a".to_string(),
            "hash_b".to_string(),
            "hash_c".to_string(),
        ];
        let mut codes = hashed_codes.clone();
        // Mark the second code as used
        codes[1] = String::new();
        assert_eq!(codes[0], "hash_a");
        assert_eq!(codes[1], "");
        assert_eq!(codes[2], "hash_c");
    }

    #[test]
    fn test_backup_codes_skip_empty_hashes() {
        let hashed_codes = ["".to_string(), "valid_hash".to_string(), "".to_string()];
        let non_empty: Vec<_> = hashed_codes.iter().filter(|h| !h.is_empty()).collect();
        assert_eq!(non_empty.len(), 1);
        assert_eq!(*non_empty[0], "valid_hash");
    }
}

// ---------------------------------------------------------------------------
// TOTP enable/disable must invalidate tokens issued before the change so
// stale refresh tokens cannot bypass the new (or old) factor via
// refresh-grant. DB-backed because the bug is observable only after
// `is_token_invalidated` is consulted with a real user row in place.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod totp_token_invalidation_regression_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use crate::services::auth_service::is_token_invalidated;
    use chrono::Utc;
    use uuid::Uuid;

    /// Pre-fix `enable_totp` UPDATEd `users.totp_enabled = true` but did not
    /// bump the credential-invalidation timestamp. A refresh token issued
    /// *before* TOTP was enabled stayed valid until natural expiry, letting
    /// the bearer swap it for a fresh access token via the refresh-grant
    /// path — bypassing the new factor. This test pins the invalidation
    /// call.
    #[tokio::test]
    async fn enable_totp_invalidates_pre_change_user_tokens() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, _) = tdh::create_user(&pool).await;

        let secret = totp_rs::Secret::generate_secret();
        let secret_b32 = secret.to_encoded().to_string();
        let secret_bytes = secret.to_bytes().expect("secret bytes");
        sqlx::query("UPDATE users SET totp_secret = $1 WHERE id = $2")
            .bind(&secret_b32)
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("set totp_secret");

        let storage_dir =
            std::env::temp_dir().join(format!("totp-invalidate-enable-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&storage_dir).expect("create storage dir");
        let state = tdh::build_state(pool.clone(), storage_dir.to_str().unwrap());
        let totp = build_totp(secret_bytes, format!("test-{user_id}")).expect("build totp");
        let code = totp.generate_current().expect("generate code");

        let auth = AuthExtension {
            user_id,
            username: format!("test-{user_id}"),
            email: format!("test-{user_id}@example.test"),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            // Non-JWT caller (API-token / basic-auth): no `iat` to exempt.
            iat_ms: None,
        };

        // Token issued one minute before the change (millisecond issued-at,
        // matching `Claims::effective_iat_ms`) — should fail
        // is_token_invalidated after enable_totp runs.
        let pre_change_iat = Utc::now().timestamp_millis() - 60_000;
        assert!(
            !is_token_invalidated(user_id, pre_change_iat),
            "fresh user must not be pre-invalidated"
        );

        // Simulate a non-JWT auth path (no TokenIat extension) so the handler
        // falls back to the "invalidate everything" semantic. This pins the
        // legacy #1146 behaviour for API-token / basic-auth callers.
        let result = enable_totp(
            State(state),
            Extension(auth),
            Json(TotpCodeRequest { code }),
        )
        .await;

        // Cleanup BEFORE assertions so DB stays clean even on failure.
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&storage_dir);

        assert!(
            result.is_ok(),
            "enable_totp must succeed: {:?}",
            result.err()
        );
        assert!(
            is_token_invalidated(user_id, pre_change_iat),
            "enable_totp must invalidate tokens issued before this point"
        );
    }

    /// Companion regression for the #1370 carve-out: when `enable_totp` is
    /// called with a `TokenIat` matching a recent token, the calling token
    /// itself must NOT be invalidated, while older tokens still are.
    ///
    /// Pre-#1370 the handler unconditionally bumped the in-memory watermark
    /// to `NOW()` and `totp_verified_at` to `NOW()`, so a release-gate run
    /// that re-used the just-issued login token to disable TOTP saw a 401
    /// on every subsequent request.
    #[tokio::test]
    async fn enable_totp_exempts_caller_iat_from_invalidation() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, _) = tdh::create_user(&pool).await;

        let secret = totp_rs::Secret::generate_secret();
        let secret_b32 = secret.to_encoded().to_string();
        let secret_bytes = secret.to_bytes().expect("secret bytes");
        sqlx::query("UPDATE users SET totp_secret = $1 WHERE id = $2")
            .bind(&secret_b32)
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("set totp_secret");

        let storage_dir =
            std::env::temp_dir().join(format!("totp-exempt-enable-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&storage_dir).expect("create storage dir");
        let state = tdh::build_state(pool.clone(), storage_dir.to_str().unwrap());
        let totp = build_totp(secret_bytes, format!("test-{user_id}")).expect("build totp");
        let code = totp.generate_current().expect("generate code");

        // The caller's token was issued "now" (millisecond `iat_ms`, as the
        // middleware now supplies via `Claims::effective_iat_ms`); tokens
        // issued before now must be killed; the caller's own token must
        // survive. An older token from the SAME second (caller - 1 ms) must
        // also be caught now that the watermark is millisecond-precise.
        let caller_iat_ms = Utc::now().timestamp_millis();
        let pre_caller_iat_ms = caller_iat_ms - 60_000;
        let older_same_second_ms = caller_iat_ms - 1;

        // The calling JWT's issued-at now travels on `AuthExtension::iat_ms`
        // (folded from the former separate `TokenIat` extension, #1394).
        let auth = AuthExtension {
            user_id,
            username: format!("test-{user_id}"),
            email: format!("test-{user_id}@example.test"),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: Some(caller_iat_ms),
        };

        let result = enable_totp(
            State(state),
            Extension(auth),
            Json(TotpCodeRequest { code }),
        )
        .await;

        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&storage_dir);

        assert!(
            result.is_ok(),
            "enable_totp must succeed: {:?}",
            result.err()
        );
        assert!(
            !is_token_invalidated(user_id, caller_iat_ms),
            "calling token (iat == watermark anchor) must NOT be invalidated"
        );
        assert!(
            is_token_invalidated(user_id, pre_caller_iat_ms),
            "tokens issued strictly before the caller's iat must be invalidated"
        );
        assert!(
            is_token_invalidated(user_id, older_same_second_ms),
            "an older token from the SAME second must now be invalidated (ms precision)"
        );
    }

    /// Symmetric check for `disable_totp`. Removing 2FA is also a credential
    /// change and must invalidate tokens issued under the stricter (TOTP-
    /// required) policy.
    #[tokio::test]
    async fn disable_totp_invalidates_pre_change_user_tokens() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, _) = tdh::create_user(&pool).await;

        // disable_totp wants the user to have totp_enabled=true, a real
        // password_hash to bcrypt-verify against, and a totp_secret. Set all
        // three directly.
        let pwd_hash = bcrypt::hash("real-test-password", 4).expect("bcrypt hash");
        let secret = totp_rs::Secret::generate_secret();
        let secret_b32 = secret.to_encoded().to_string();
        let secret_bytes = secret.to_bytes().expect("secret bytes");
        sqlx::query(
            "UPDATE users SET totp_secret = $1, totp_enabled = true, password_hash = $2 \
             WHERE id = $3",
        )
        .bind(&secret_b32)
        .bind(&pwd_hash)
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("set totp+password");

        let storage_dir =
            std::env::temp_dir().join(format!("totp-invalidate-disable-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&storage_dir).expect("create storage dir");
        let state = tdh::build_state(pool.clone(), storage_dir.to_str().unwrap());
        let totp = build_totp(secret_bytes, format!("test-{user_id}")).expect("build totp");
        let code = totp.generate_current().expect("generate code");

        let auth = AuthExtension {
            user_id,
            username: format!("test-{user_id}"),
            email: format!("test-{user_id}@example.test"),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: None,
        };

        let pre_change_iat = Utc::now().timestamp_millis() - 60_000;
        // Note: enable_totp already invalidates by other tests' side effects
        // potentially, but `tdh::create_user` returns a fresh Uuid, so this
        // user_id has never been invalidated before.
        assert!(!is_token_invalidated(user_id, pre_change_iat));

        // Legacy non-JWT path (no TokenIat) — must still invalidate all
        // sessions for this user, as in #1146.
        let result = disable_totp(
            State(state),
            Extension(auth),
            Json(TotpDisableRequest {
                password: "real-test-password".to_string(),
                code,
            }),
        )
        .await;

        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&storage_dir);

        assert!(
            result.is_ok(),
            "disable_totp must succeed: {:?}",
            result.err()
        );
        assert!(
            is_token_invalidated(user_id, pre_change_iat),
            "disable_totp must invalidate tokens issued before this point"
        );
    }

    /// #1370 regression: `disable_totp` called with the calling session's
    /// `TokenIat` must return 2xx, exempt the caller from invalidation, and
    /// leave `users.totp_enabled = false` so a subsequent `/auth/me` call
    /// reports the correct state.
    ///
    /// This is the unit-level companion of the release-gate assertion
    /// `auth-totp-disable / Disable succeeds with correct password and TOTP
    /// code` + `User profile shows totp_enabled = false after disable`.
    #[tokio::test]
    async fn disable_totp_returns_ok_and_clears_totp_enabled_for_caller() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, _) = tdh::create_user(&pool).await;

        let pwd_hash = bcrypt::hash("real-test-password", 4).expect("bcrypt hash");
        let secret = totp_rs::Secret::generate_secret();
        let secret_b32 = secret.to_encoded().to_string();
        let secret_bytes = secret.to_bytes().expect("secret bytes");
        sqlx::query(
            "UPDATE users SET totp_secret = $1, totp_enabled = true, password_hash = $2 \
             WHERE id = $3",
        )
        .bind(&secret_b32)
        .bind(&pwd_hash)
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("set totp+password");

        let storage_dir =
            std::env::temp_dir().join(format!("totp-exempt-disable-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&storage_dir).expect("create storage dir");
        let state = tdh::build_state(pool.clone(), storage_dir.to_str().unwrap());
        let totp = build_totp(secret_bytes, format!("test-{user_id}")).expect("build totp");
        let code = totp.generate_current().expect("generate code");

        let caller_iat_ms = Utc::now().timestamp_millis();
        let pre_caller_iat_ms = caller_iat_ms - 60_000;
        let older_same_second_ms = caller_iat_ms - 1;

        // The calling JWT's issued-at now travels on `AuthExtension::iat_ms`
        // (folded from the former separate `TokenIat` extension, #1394).
        let auth = AuthExtension {
            user_id,
            username: format!("test-{user_id}"),
            email: format!("test-{user_id}@example.test"),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: Some(caller_iat_ms),
        };

        let result = disable_totp(
            State(state),
            Extension(auth),
            Json(TotpDisableRequest {
                password: "real-test-password".to_string(),
                code,
            }),
        )
        .await;

        // Read post-disable state BEFORE cleanup so the assertion can
        // exercise what `/auth/me` would observe.
        let totp_enabled_after: Option<bool> =
            sqlx::query_scalar("SELECT totp_enabled FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_one(&pool)
                .await
                .ok();

        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&storage_dir);

        assert!(
            result.is_ok(),
            "disable_totp must return Ok with correct creds + caller iat: {:?}",
            result.err()
        );
        assert_eq!(
            totp_enabled_after,
            Some(false),
            "users.totp_enabled must be false after disable (drives /auth/me response)"
        );
        assert!(
            !is_token_invalidated(user_id, caller_iat_ms),
            "calling token must survive its own disable (#1370)"
        );
        assert!(
            is_token_invalidated(user_id, pre_caller_iat_ms),
            "older tokens must still be invalidated by disable"
        );
        assert!(
            is_token_invalidated(user_id, older_same_second_ms),
            "an older token from the SAME second must now be invalidated (ms precision)"
        );
    }
}

#[cfg(test)]
mod totp_verify_hardening_tests {
    //! Regression coverage for the round-3 2FA hardening:
    //!  * #1819 — `verify_totp` must persist the refresh `jti` so RFC 6819
    //!    replay detection works for 2FA sessions.
    //!  * #1820 — the `totp_pending` token must be single-use (a second
    //!    `/verify` with the same token is rejected).
    //!  * #1822 — backup-code consumption must serialize so one code cannot
    //!    authenticate concurrent sessions.
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use crate::models::user::User;
    use uuid::Uuid;

    /// Enrol a fresh user in TOTP with the given backup-code hashes and return
    /// everything a `verify_totp` call needs: the handler state, a TOTP secret
    /// for generating live codes, and a freshly minted single-use pending
    /// token signed with the same key the handler validates against.
    async fn setup_totp_user(
        pool: &sqlx::PgPool,
        backup_hashes: &[String],
    ) -> (User, SharedState, Vec<u8>, String, std::path::PathBuf) {
        let fx = tdh::create_totp_user(pool, backup_hashes).await;
        let auth_service = AuthService::new(pool.clone(), Arc::new(fx.state.config.clone()));
        let pending = auth_service
            .generate_totp_pending_token(&fx.user)
            .expect("pending token");
        (fx.user, fx.state, fx.secret_bytes, pending, fx.storage_dir)
    }

    async fn cleanup(pool: &sqlx::PgPool, user_id: Uuid, dir: &std::path::Path) {
        let _ = sqlx::query("DELETE FROM totp_pending_jti WHERE user_id = $1")
            .bind(user_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM refresh_token_jti WHERE user_id = $1")
            .bind(user_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(pool)
            .await;
        let _ = std::fs::remove_dir_all(dir);
    }

    /// #1819 + #1820: a TOTP code verify persists the refresh `jti`, and the
    /// pending token cannot be reused for a second verify.
    #[tokio::test]
    async fn verify_persists_refresh_jti_and_pending_token_is_single_use() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user, state, secret_bytes, pending, dir) = setup_totp_user(&pool, &[]).await;
        let user_id = user.id;
        let totp = build_totp(secret_bytes, format!("test-{user_id}")).expect("build totp");
        let code = totp.generate_current().expect("code");

        let first = verify_totp(
            State(state.clone()),
            HeaderMap::new(),
            Json(TotpVerifyRequest {
                totp_token: pending.clone(),
                code: code.clone(),
            }),
        )
        .await;

        // Replay the SAME pending token (a fresh valid code, to isolate the
        // single-use property from code validity).
        let code2 = totp.generate_current().expect("code");
        let replay = verify_totp(
            State(state.clone()),
            HeaderMap::new(),
            Json(TotpVerifyRequest {
                totp_token: pending,
                code: code2,
            }),
        )
        .await;

        let jti_rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM refresh_token_jti WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(&pool)
                .await
                .expect("count jti");

        cleanup(&pool, user_id, &dir).await;

        assert!(
            first.is_ok(),
            "first verify must succeed: {:?}",
            first.err()
        );
        assert_eq!(
            jti_rows, 1,
            "verify_totp must persist exactly one refresh_token_jti row (#1819)"
        );
        assert!(
            replay.is_err(),
            "reusing a consumed pending token must be rejected (#1820)"
        );
    }

    /// #1822: the same backup code presented by concurrent verifies must
    /// authenticate at most once. The single-use pending token already caps a
    /// single login to one verify, so each concurrent attempt uses its own
    /// freshly minted pending token (the realistic worst case) — the
    /// `FOR UPDATE` row lock is what must serialize consumption.
    #[tokio::test]
    async fn backup_code_consumed_at_most_once_under_concurrency() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let backup_plain = "1YUU4B8U";
        let hash = bcrypt::hash(backup_plain, 4).expect("hash");
        let (user, state, _secret, _pending, dir) = setup_totp_user(&pool, &[hash]).await;
        let user_id = user.id;

        // Mint one valid pending token per concurrent request (single-use
        // tokens mean an attacker would re-login to feed the race).
        let cfg = Arc::new(state.config.clone());
        let svc = AuthService::new(pool.clone(), cfg);

        let mut handles = Vec::new();
        for _ in 0..16 {
            let token = svc.generate_totp_pending_token(&user).expect("pending");
            let st = state.clone();
            handles.push(tokio::spawn(async move {
                verify_totp(
                    State(st),
                    HeaderMap::new(),
                    Json(TotpVerifyRequest {
                        totp_token: token,
                        code: "1YUU-4B8U".to_string(),
                    }),
                )
                .await
                .is_ok()
            }));
        }
        let mut successes = 0;
        for h in handles {
            if h.await.unwrap_or(false) {
                successes += 1;
            }
        }

        let remaining: Option<String> =
            sqlx::query_scalar("SELECT totp_backup_codes FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_one(&pool)
                .await
                .ok()
                .flatten();

        cleanup(&pool, user_id, &dir).await;

        assert_eq!(
            successes, 1,
            "a single backup code must authenticate exactly one concurrent verify (#1822)"
        );
        let codes: Vec<String> =
            serde_json::from_str(&remaining.unwrap_or_default()).unwrap_or_default();
        assert!(
            codes.iter().all(|c| c.is_empty()),
            "the consumed backup-code slot must be cleared"
        );
    }
}

/// DB-backed tests for the auth-event audit trail added in #386 (#1617
/// Phase 1): TOTP enable, disable and login-verify must each emit the right
/// audit rows, while a failed 2FA verify emits `LOGIN_FAILED`. Each test
/// no-ops when `DATABASE_URL` is unset (`tdh::try_pool`).
#[cfg(test)]
mod totp_audit_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;

    /// Pick a 6-digit code guaranteed to differ from the live TOTP code so the
    /// verify path takes the failure branch deterministically.
    fn wrong_code(current: &str) -> String {
        if current == "000000" {
            "111111".to_string()
        } else {
            "000000".to_string()
        }
    }

    #[tokio::test]
    async fn enable_totp_emits_totp_enabled_and_sessions_invalidated() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let fx = tdh::create_totp_user(&pool, &[]).await;
        let user_id = fx.user.id;
        let auth = tdh::make_auth(user_id, &fx.user.username);
        let totp = build_totp(fx.secret_bytes.clone(), fx.user.username.clone()).expect("totp");
        let code = totp.generate_current().expect("code");

        let res = enable_totp(
            State(fx.state.clone()),
            Extension(auth),
            Json(TotpCodeRequest { code }),
        )
        .await;

        let enabled = tdh::audit_count(&pool, user_id, "TOTP_ENABLED").await;
        let invalidated = tdh::audit_count(&pool, user_id, "SESSIONS_INVALIDATED").await;
        tdh::cleanup_user(&pool, user_id).await;
        let _ = std::fs::remove_dir_all(&fx.storage_dir);

        assert!(res.is_ok(), "enable_totp failed: {:?}", res.err());
        assert_eq!(enabled, 1, "enable_totp MUST write one TOTP_ENABLED row");
        assert_eq!(
            invalidated, 1,
            "enable_totp MUST write one SESSIONS_INVALIDATED row"
        );
    }

    #[tokio::test]
    async fn disable_totp_emits_totp_disabled_and_sessions_invalidated() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let fx = tdh::create_totp_user(&pool, &[]).await;
        let user_id = fx.user.id;
        let password = "Disable!2026pw";
        let hash = bcrypt::hash(password, 4).expect("hash password");
        sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
            .bind(&hash)
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("seed password hash");
        let auth = tdh::make_auth(user_id, &fx.user.username);
        let totp = build_totp(fx.secret_bytes.clone(), fx.user.username.clone()).expect("totp");
        let code = totp.generate_current().expect("code");

        let res = disable_totp(
            State(fx.state.clone()),
            Extension(auth),
            Json(TotpDisableRequest {
                password: password.to_string(),
                code,
            }),
        )
        .await;

        let disabled = tdh::audit_count(&pool, user_id, "TOTP_DISABLED").await;
        let invalidated = tdh::audit_count(&pool, user_id, "SESSIONS_INVALIDATED").await;
        tdh::cleanup_user(&pool, user_id).await;
        let _ = std::fs::remove_dir_all(&fx.storage_dir);

        assert!(res.is_ok(), "disable_totp failed: {:?}", res.err());
        assert_eq!(disabled, 1, "disable_totp MUST write one TOTP_DISABLED row");
        assert_eq!(
            invalidated, 1,
            "disable_totp MUST write one SESSIONS_INVALIDATED row"
        );
    }

    #[tokio::test]
    async fn verify_totp_success_emits_login_and_wrong_code_emits_login_failed() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let fx = tdh::create_totp_user(&pool, &[]).await;
        let user_id = fx.user.id;
        let svc = AuthService::new(pool.clone(), Arc::new(fx.state.config.clone()));
        let totp = build_totp(fx.secret_bytes.clone(), fx.user.username.clone()).expect("totp");

        // Wrong-code attempt -> LOGIN_FAILED (fresh single-use pending token).
        let bad_pending = svc.generate_totp_pending_token(&fx.user).expect("pending");
        let current = totp.generate_current().expect("code");
        let bad = verify_totp(
            State(fx.state.clone()),
            HeaderMap::new(),
            Json(TotpVerifyRequest {
                totp_token: bad_pending,
                code: wrong_code(&current),
            }),
        )
        .await;

        // Successful verify -> LOGIN (a second fresh pending token + live code).
        let ok_pending = svc.generate_totp_pending_token(&fx.user).expect("pending");
        let code = totp.generate_current().expect("code");
        let ok = verify_totp(
            State(fx.state.clone()),
            HeaderMap::new(),
            Json(TotpVerifyRequest {
                totp_token: ok_pending,
                code,
            }),
        )
        .await;

        let logins = tdh::audit_count(&pool, user_id, "LOGIN").await;
        let failed = tdh::audit_count(&pool, user_id, "LOGIN_FAILED").await;
        tdh::cleanup_user(&pool, user_id).await;
        let _ = std::fs::remove_dir_all(&fx.storage_dir);

        assert!(bad.is_err(), "wrong TOTP code must be rejected");
        assert!(
            ok.is_ok(),
            "verify with live code must succeed: {:?}",
            ok.err()
        );
        assert_eq!(logins, 1, "successful TOTP verify MUST write one LOGIN row");
        assert_eq!(
            failed, 1,
            "a wrong-code TOTP verify MUST write one LOGIN_FAILED row"
        );
    }

    #[tokio::test]
    async fn verify_totp_on_non_2fa_user_emits_login_failed() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let fx = tdh::create_totp_user(&pool, &[]).await;
        let user_id = fx.user.id;
        // Flip the DB row so the handler takes the "TOTP not enabled" branch.
        sqlx::query("UPDATE users SET totp_enabled = false WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("clear totp_enabled");
        let svc = AuthService::new(pool.clone(), Arc::new(fx.state.config.clone()));
        let pending = svc.generate_totp_pending_token(&fx.user).expect("pending");

        let res = verify_totp(
            State(fx.state.clone()),
            HeaderMap::new(),
            Json(TotpVerifyRequest {
                totp_token: pending,
                code: "000000".to_string(),
            }),
        )
        .await;

        let failed = tdh::audit_count(&pool, user_id, "LOGIN_FAILED").await;
        tdh::cleanup_user(&pool, user_id).await;
        let _ = std::fs::remove_dir_all(&fx.storage_dir);

        assert!(
            res.is_err(),
            "verify against a non-2FA user must be rejected"
        );
        assert_eq!(
            failed, 1,
            "a TOTP verify against a user without 2FA MUST write one LOGIN_FAILED row"
        );
    }
}
