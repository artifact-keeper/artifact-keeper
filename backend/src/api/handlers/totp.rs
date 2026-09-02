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
use crate::services::totp_policy;

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

/// Generate a fresh TOTP secret for `user_id`, store it unverified, and return
/// the enrollment material.
///
/// Shared by the authenticated `/setup` route and the policy-driven
/// `/enroll/setup` route (#2805) so both provision an identical secret with an
/// identical `otpauth://` label — a second implementation would be a place for
/// the two flows to drift (different issuer, different digit count) and produce
/// codes one endpoint accepts and the other rejects.
async fn provision_totp_secret(
    db: &sqlx::PgPool,
    user_id: uuid::Uuid,
) -> Result<TotpSetupResponse> {
    let secret = Secret::generate_secret();
    let secret_base32 = secret.to_encoded().to_string();

    // Get username for the TOTP label
    let user = sqlx::query!("SELECT username FROM users WHERE id = $1", user_id)
        .fetch_one(db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let secret_bytes = secret
        .to_bytes()
        .map_err(|e| AppError::Internal(format!("Secret error: {}", e)))?;
    let totp = build_totp(secret_bytes, user.username)?;
    let qr_code_url = totp.get_url();

    // Store the secret (not yet enabled)
    sqlx::query!(
        "UPDATE users SET totp_secret = $2 WHERE id = $1",
        user_id,
        secret_base32
    )
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(TotpSetupResponse {
        secret: secret_base32,
        qr_code_url,
    })
}

/// Check `code` against the secret stored for `user_id` by
/// [`provision_totp_secret`]. Shared by `/enable` and `/enroll/complete`.
async fn check_provisioned_totp_code(
    db: &sqlx::PgPool,
    user_id: uuid::Uuid,
    code: &str,
) -> Result<()> {
    let user = sqlx::query!(
        "SELECT totp_secret, username FROM users WHERE id = $1",
        user_id
    )
    .fetch_one(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let secret_str = user.totp_secret.ok_or_else(|| {
        AppError::Validation("TOTP not set up. Call /auth/totp/setup first.".to_string())
    })?;

    let totp = build_totp(decode_secret(&secret_str)?, user.username)?;
    if !totp
        .check_current(code)
        .map_err(|e| AppError::Internal(format!("TOTP check error: {}", e)))?
    {
        return Err(AppError::Authentication("Invalid TOTP code".to_string()));
    }
    Ok(())
}

/// Mint 10 one-time backup codes, returning `(plaintext, hashed_json)`.
///
/// Hashing runs through `AuthService::hash_password` so the 10 bcrypt hashes are
/// offloaded off the tokio worker and bounded by the auth-concurrency semaphore,
/// instead of running inline and starving the runtime.
async fn mint_backup_codes() -> Result<(Vec<String>, String)> {
    // Scoped so the rng drops before any `.await` -- the rng is not Send.
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
    let mut hashed_codes: Vec<String> = Vec::with_capacity(backup_codes.len());
    for code in &backup_codes {
        let clean = code.replace('-', "");
        hashed_codes.push(AuthService::hash_password(&clean).await?);
    }
    let hashed_json = serde_json::to_string(&hashed_codes)
        .map_err(|e| AppError::Internal(format!("JSON error: {}", e)))?;
    Ok((backup_codes, hashed_json))
}

/// Flip `users` into the TOTP-enabled state with the given backup codes and
/// credential-change watermark.
async fn mark_totp_enabled(
    db: &sqlx::PgPool,
    user_id: uuid::Uuid,
    hashed_json: &str,
    verified_ts: DateTime<Utc>,
) -> Result<()> {
    sqlx::query!(
        "UPDATE users SET totp_enabled = true, totp_backup_codes = $2, totp_verified_at = $3 WHERE id = $1",
        user_id,
        hashed_json,
        verified_ts
    )
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(())
}

/// Public TOTP routes (no auth required -- uses totp_token)
///
/// `/enroll/*` are public for the same reason `/verify` is: the caller has
/// proven its password but has no session yet, and under a `required_*` policy
/// (#2805) it cannot get one until it enrols. Both carry a signed, short-lived,
/// type-scoped ticket in the request body instead.
pub fn public_router() -> Router<SharedState> {
    Router::new()
        .route("/verify", post(verify_totp))
        .route("/enroll/setup", post(enroll_setup))
        .route("/enroll/complete", post(enroll_complete))
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
    Ok(Json(provision_totp_secret(&state.db, auth.user_id).await?))
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
    check_provisioned_totp_code(&state.db, auth.user_id, &payload.code).await?;
    let (backup_codes, hashed_json) = mint_backup_codes().await?;

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
    mark_totp_enabled(&state.db, auth.user_id, &hashed_json, verified_ts).await?;

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
                .details_typed(
                    crate::services::audit_export::details::AuthDetails::failed_login(
                        None,
                        Some("totp_not_enabled"),
                    ),
                ),
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
                    .details_typed(crate::services::audit_export::details::AuthDetails {
                        username: None,
                        path: None,
                        method: Some("totp".to_owned()),
                        reason: Some("invalid_totp_code".to_owned()),
                        provider: None,
                        auth_method: None,
                    }),
            )
            .await;
            return Err(AppError::Authentication("Invalid TOTP code".to_string()));
        }
        used_backup_code = true;
    }

    // TOTP verified -- now fetch full user and generate real tokens
    let method_label = if used_backup_code {
        "totp_backup_code"
    } else {
        "totp"
    };
    let (user, tokens) =
        issue_session_after_totp(&state, &auth_service, claims.sub, method_label).await?;

    let body = super::auth::LoginResponse {
        access_token: tokens.access_token.clone(),
        refresh_token: tokens.refresh_token.clone(),
        expires_in: tokens.expires_in,
        token_type: "Bearer".to_string(),
        must_change_password: user.must_change_password,
        totp_required: None,
        totp_enrollment_required: None,
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

/// Issue the real session that follows a satisfied second factor.
///
/// Shared by `/verify` (code or backup code accepted) and `/enroll/complete`
/// (enrollment finished under the policy, #2805). Keeping one implementation
/// matters for more than tidiness: the refresh-`jti` persistence below is what
/// backs the RFC 6819 replay check, and a second copy of this tail that forgot
/// it would silently mint 2FA sessions whose refresh tokens are infinitely
/// replayable — exactly the regression #1819 fixed.
async fn issue_session_after_totp(
    state: &SharedState,
    auth_service: &AuthService,
    user_id: uuid::Uuid,
    method_label: &str,
) -> Result<(
    crate::models::user::User,
    crate::services::auth_service::TokenPair,
)> {
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
        user_id
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
        user_id
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

    // A completed second factor IS a login: record it so 2FA users' logins are
    // no longer invisible in the audit trail (#386). Fire-and-forget,
    // non-gating, placed after the refresh jti is durably persisted.
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

    Ok((user, tokens))
}

// --- Forced enrollment (2FA policy, #2805) ---

/// Resolve an enrollment ticket to the user it was minted for, re-checking that
/// enrollment is still the right thing to do.
///
/// The re-check is not paranoia. A ticket lives 10 minutes, and in that window
/// the user may have enrolled from another device or an administrator may have
/// relaxed the policy. Re-reading means the ticket can never be used to enrol a
/// *second* secret over an already-active one (which would silently invalidate
/// the authenticator the user just registered), and can never be used against an
/// account that has since been deactivated.
async fn resolve_enrollment_ticket(
    state: &SharedState,
    auth_service: &AuthService,
    ticket: &str,
) -> Result<crate::services::auth_service::Claims> {
    let claims = auth_service.validate_totp_enrollment_token(ticket)?;
    let row = sqlx::query!(
        "SELECT totp_enabled FROM users WHERE id = $1 AND is_active = true",
        claims.sub
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::Authentication("User not found".to_string()))?;

    if row.totp_enabled {
        // Already enrolled: the correct next step is the ordinary challenge, not
        // a second enrollment. Say so rather than clobbering the live secret.
        return Err(AppError::Validation(
            "TOTP is already enabled for this account. Sign in again and enter a code.".to_string(),
        ));
    }
    Ok(claims)
}

/// Request body carrying an enrollment ticket issued by `POST /auth/login`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct TotpEnrollSetupRequest {
    /// The `totp_token` returned alongside `totp_enrollment_required: true`.
    pub totp_token: String,
}

/// Request body completing forced enrollment.
#[derive(Debug, Deserialize, ToSchema)]
pub struct TotpEnrollCompleteRequest {
    /// The `totp_token` returned alongside `totp_enrollment_required: true`.
    pub totp_token: String,
    /// The current 6-digit code from the authenticator that scanned the secret.
    pub code: String,
}

/// Successful forced enrollment: a real session *plus* the backup codes.
///
/// The session is returned here, in the same response that completes
/// enrollment, so a user subject to the policy is never left holding a valid
/// password and no way in.
#[derive(Debug, Serialize, ToSchema)]
pub struct TotpEnrollCompleteResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub token_type: String,
    pub must_change_password: bool,
    /// One-time recovery codes. Shown exactly once — they are stored hashed.
    pub backup_codes: Vec<String>,
}

/// Begin policy-required TOTP enrollment using a login-issued enrollment ticket.
#[utoipa::path(
    post,
    path = "/enroll/setup",
    context_path = "/api/v1/auth/totp",
    tag = "auth",
    request_body = TotpEnrollSetupRequest,
    responses(
        (status = 200, description = "TOTP secret and QR code URL for enrollment", body = TotpSetupResponse),
        (status = 400, description = "TOTP is already enabled for this account", body = crate::api::openapi::ErrorResponse),
        (status = 401, description = "Invalid or expired enrollment ticket", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn enroll_setup(
    State(state): State<SharedState>,
    Json(payload): Json<TotpEnrollSetupRequest>,
) -> Result<Json<TotpSetupResponse>> {
    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    // Deliberately does NOT consume the ticket's `jti`: a user who mistypes the
    // secret, or whose authenticator app is reinstalled mid-flow, must be able
    // to ask for a fresh QR code without starting the login over. Only
    // `/enroll/complete` consumes it, so the ticket still yields exactly one
    // session.
    let claims = resolve_enrollment_ticket(&state, &auth_service, &payload.totp_token).await?;
    Ok(Json(provision_totp_secret(&state.db, claims.sub).await?))
}

/// Complete policy-required TOTP enrollment and receive a session.
#[utoipa::path(
    post,
    path = "/enroll/complete",
    context_path = "/api/v1/auth/totp",
    tag = "auth",
    request_body = TotpEnrollCompleteRequest,
    responses(
        (status = 200, description = "TOTP enrolled; session and backup codes returned", body = TotpEnrollCompleteResponse),
        (status = 400, description = "TOTP is already enabled, or /enroll/setup was not called first", body = crate::api::openapi::ErrorResponse),
        (status = 401, description = "Invalid code, or invalid/expired/already-used enrollment ticket", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn enroll_complete(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(payload): Json<TotpEnrollCompleteRequest>,
) -> Result<Response> {
    let client_is_https = request_scheme_is_https(&headers);
    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    let claims = resolve_enrollment_ticket(&state, &auth_service, &payload.totp_token).await?;

    // Single-use, claimed BEFORE the code is checked — the same ordering
    // `/verify` uses (#1820). Otherwise one stolen ticket could be replayed to
    // brute-force the 6-digit code of a secret the attacker just provisioned.
    auth_service.consume_totp_pending_jti(&claims).await?;

    if let Err(e) = check_provisioned_totp_code(&state.db, claims.sub, &payload.code).await {
        audit_fire_and_forget(
            state.db.clone(),
            AuditEntry::new(AuditAction::LoginFailed, ResourceType::User)
                .user(claims.sub)
                .resource(claims.sub)
                .details_typed(crate::services::audit_export::details::AuthDetails {
                    username: None,
                    path: None,
                    method: Some("totp_enroll".to_owned()),
                    reason: Some("invalid_totp_code".to_owned()),
                    provider: None,
                    auth_method: None,
                }),
        )
        .await;
        return Err(e);
    }

    let (backup_codes, hashed_json) = mint_backup_codes().await?;
    // `Utc::now()` (not a caller `iat`, as `/enable` uses): there is no caller
    // session to preserve here — the whole point is that none was issued — and
    // any JWT predating enrollment was minted before the account satisfied the
    // policy, so invalidating all of them is correct.
    mark_totp_enabled(&state.db, claims.sub, &hashed_json, Utc::now()).await?;
    invalidate_other_sessions(claims.sub, None);
    if let Err(e) = auth_service
        .revoke_all_refresh_token_families(claims.sub)
        .await
    {
        tracing::warn!(
            user_id = %claims.sub,
            error = %e,
            "Failed to revoke refresh-token families after forced TOTP enrollment",
        );
    }

    let (user, tokens) =
        issue_session_after_totp(&state, &auth_service, claims.sub, "totp_enrollment").await?;

    audit_fire_and_forget(
        state.db.clone(),
        totp_audit_entry(AuditAction::TotpEnabled, claims.sub),
    )
    .await;

    let body = TotpEnrollCompleteResponse {
        access_token: tokens.access_token.clone(),
        refresh_token: tokens.refresh_token.clone(),
        expires_in: tokens.expires_in,
        token_type: "Bearer".to_string(),
        must_change_password: user.must_change_password,
        backup_codes,
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
        (status = 409, description = "The 2FA enforcement policy requires TOTP for this account", body = crate::api::openapi::ErrorResponse),
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
        r#"SELECT password_hash, totp_secret, totp_enabled, username, is_admin, is_service_account,
                  auth_provider as "auth_provider: crate::models::user::AuthProvider"
           FROM users WHERE id = $1"#,
        auth.user_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // #2805: refuse while the enforcement policy covers this account. Without
    // this, a user under `required_for_*` could turn 2FA off and keep operating
    // on the current session until it expires — enforcement that only bites at
    // the next login is not enforcement. This creates no new lockout: disabling
    // already requires a valid current code, so anyone who can reach this point
    // can also still sign in.
    let (policy, _) = totp_policy::effective_policy(&state.db, state.config.totp_policy).await;
    if totp_policy::policy_requires_totp(
        policy,
        totp_policy::TotpSubject {
            auth_provider: user.auth_provider,
            is_admin: user.is_admin,
            is_service_account: user.is_service_account,
            totp_enabled: user.totp_enabled,
        },
    ) {
        return Err(AppError::Conflict(format!(
            "Two-factor authentication is required for this account by the system policy \
             ({}). It cannot be disabled.",
            policy.as_str()
        )));
    }

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
    paths(
        setup_totp,
        enable_totp,
        verify_totp,
        disable_totp,
        enroll_setup,
        enroll_complete,
    ),
    components(schemas(
        TotpSetupResponse,
        TotpCodeRequest,
        TotpEnableResponse,
        TotpVerifyRequest,
        TotpDisableRequest,
        TotpEnrollSetupRequest,
        TotpEnrollCompleteRequest,
        TotpEnrollCompleteResponse,
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

        // #2522: audit writes are fire-and-forget (spawned) — poll for each.
        let enabled = tdh::audit_count_eventually(&pool, user_id, "TOTP_ENABLED", 1).await;
        let invalidated =
            tdh::audit_count_eventually(&pool, user_id, "SESSIONS_INVALIDATED", 1).await;
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

        // #2522: audit writes are fire-and-forget (spawned) — poll for each.
        let disabled = tdh::audit_count_eventually(&pool, user_id, "TOTP_DISABLED", 1).await;
        let invalidated =
            tdh::audit_count_eventually(&pool, user_id, "SESSIONS_INVALIDATED", 1).await;
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

        // #2522: audit writes are fire-and-forget (spawned) — poll for each.
        let logins = tdh::audit_count_eventually(&pool, user_id, "LOGIN", 1).await;
        let failed = tdh::audit_count_eventually(&pool, user_id, "LOGIN_FAILED", 1).await;
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

        // #2522: audit writes are fire-and-forget (spawned) — poll for it.
        let failed = tdh::audit_count_eventually(&pool, user_id, "LOGIN_FAILED", 1).await;
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

    use axum::http::StatusCode;

    // -----------------------------------------------------------------------
    // #2805 — forced TOTP enrollment. These exercise the policy-driven flow
    // end to end against Postgres; they no-op cleanly when DATABASE_URL is
    // unset, and CI provisions Postgres before `cargo test --lib`.
    // -----------------------------------------------------------------------

    /// Seed an active local user with NO TOTP, plus a state, and mint a real
    /// enrollment ticket for them. Mirrors what `POST /auth/login` hands back
    /// under a `required_*` policy.
    async fn enrollment_fixture(
        pool: &sqlx::PgPool,
    ) -> (uuid::Uuid, SharedState, String, std::path::PathBuf) {
        let fx = tdh::create_totp_user(pool, &[]).await;
        // Undo the fixture's enrollment: the point here is a user who has NOT
        // enrolled yet.
        sqlx::query(
            "UPDATE users SET totp_enabled = false, totp_secret = NULL, \
             totp_backup_codes = NULL WHERE id = $1",
        )
        .bind(fx.user.id)
        .execute(pool)
        .await
        .expect("clear totp");

        let svc = AuthService::new(pool.clone(), Arc::new(fx.state.config.clone()));
        let mut user = fx.user.clone();
        user.totp_enabled = false;
        user.totp_secret = None;
        let ticket = svc
            .generate_totp_enrollment_token(&user)
            .expect("enrollment ticket");
        (fx.user.id, fx.state, ticket, fx.storage_dir)
    }

    /// The whole point of the design: a user the policy covers can go from
    /// "correct password, no session" to "session" without any other
    /// credential, inside one login. If this breaks, enabling the policy locks
    /// people out.
    #[tokio::test]
    async fn enroll_setup_then_complete_issues_a_session_and_backup_codes() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, state, ticket, storage_dir) = enrollment_fixture(&pool).await;

        let setup = enroll_setup(
            State(state.clone()),
            Json(TotpEnrollSetupRequest {
                totp_token: ticket.clone(),
            }),
        )
        .await
        .expect("enroll setup");
        assert!(setup.0.qr_code_url.starts_with("otpauth://"));

        let secret_bytes = decode_secret(&setup.0.secret).expect("decode secret");
        let code = build_totp(secret_bytes, format!("test-{user_id}"))
            .expect("totp")
            .generate_current()
            .expect("code");

        let res = enroll_complete(
            State(state.clone()),
            HeaderMap::new(),
            Json(TotpEnrollCompleteRequest {
                totp_token: ticket.clone(),
                code: code.clone(),
            }),
        )
        .await;

        let enabled: Option<bool> =
            sqlx::query_scalar("SELECT totp_enabled FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_optional(&pool)
                .await
                .expect("read totp_enabled");

        // A used ticket must not work a second time.
        let replay = enroll_complete(
            State(state.clone()),
            HeaderMap::new(),
            Json(TotpEnrollCompleteRequest {
                totp_token: ticket,
                code,
            }),
        )
        .await;

        tdh::cleanup_user(&pool, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);

        let response = res.expect("enroll complete must succeed");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response
                .headers()
                .get_all(axum::http::header::SET_COOKIE)
                .iter()
                .count()
                > 0,
            "completing enrollment must set the session cookies a login would"
        );
        assert_eq!(enabled, Some(true), "TOTP must be enabled after enrollment");
        assert!(
            replay.is_err(),
            "an enrollment ticket must yield exactly one session"
        );
    }

    /// Token-type separation: an enrollment ticket must never be redeemable at
    /// `/verify`, which would hand out a session to someone who has proven no
    /// second factor at all.
    #[tokio::test]
    async fn enrollment_ticket_is_rejected_by_verify() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, state, ticket, storage_dir) = enrollment_fixture(&pool).await;

        let res = verify_totp(
            State(state),
            HeaderMap::new(),
            Json(TotpVerifyRequest {
                totp_token: ticket,
                code: "000000".to_string(),
            }),
        )
        .await;

        tdh::cleanup_user(&pool, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);
        assert!(res.is_err(), "an enroll ticket must not satisfy /verify");
    }

    /// And the converse: a `totp_pending` verification ticket must not drive
    /// enrollment.
    #[tokio::test]
    async fn pending_ticket_is_rejected_by_enroll_setup() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let fx = tdh::create_totp_user(&pool, &[]).await;
        let svc = AuthService::new(pool.clone(), Arc::new(fx.state.config.clone()));
        let pending = svc
            .generate_totp_pending_token(&fx.user)
            .expect("pending token");

        let res = enroll_setup(
            State(fx.state.clone()),
            Json(TotpEnrollSetupRequest {
                totp_token: pending,
            }),
        )
        .await;

        tdh::cleanup_user(&pool, fx.user.id).await;
        let _ = std::fs::remove_dir_all(&fx.storage_dir);
        assert!(res.is_err(), "a pending ticket must not drive enrollment");
    }

    /// A ticket must not clobber a secret the user has since enrolled from
    /// another device.
    #[tokio::test]
    async fn enroll_setup_refuses_when_totp_is_already_enabled() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, state, ticket, storage_dir) = enrollment_fixture(&pool).await;
        sqlx::query("UPDATE users SET totp_enabled = true WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("re-enable");

        let res = enroll_setup(
            State(state),
            Json(TotpEnrollSetupRequest { totp_token: ticket }),
        )
        .await;

        tdh::cleanup_user(&pool, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);
        assert!(res.is_err(), "must not re-provision over a live secret");
    }

    /// `/enroll/setup` may be called repeatedly (reinstalled authenticator,
    /// mistyped secret) — only `/enroll/complete` consumes the ticket.
    #[tokio::test]
    async fn enroll_setup_may_be_repeated_with_the_same_ticket() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, state, ticket, storage_dir) = enrollment_fixture(&pool).await;

        let first = enroll_setup(
            State(state.clone()),
            Json(TotpEnrollSetupRequest {
                totp_token: ticket.clone(),
            }),
        )
        .await;
        let second = enroll_setup(
            State(state),
            Json(TotpEnrollSetupRequest { totp_token: ticket }),
        )
        .await;

        tdh::cleanup_user(&pool, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);
        assert!(first.is_ok() && second.is_ok(), "setup must be repeatable");
    }

    /// Enforcement that only bites at the next login is not enforcement: a user
    /// the policy covers must not be able to turn 2FA off on the current
    /// session.
    #[tokio::test]
    async fn disable_totp_is_refused_while_the_policy_requires_it() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let fx = tdh::create_totp_user(&pool, &[]).await;
        let pwd_hash = bcrypt::hash("real-test-password", 4).expect("bcrypt hash");
        sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
            .bind(&pwd_hash)
            .bind(fx.user.id)
            .execute(&pool)
            .await
            .expect("set password");

        // Pin the policy through config so the test does not race another
        // test mutating the shared `system_settings` row.
        let storage = fx.storage_dir.to_str().unwrap().to_string();
        let state = tdh::build_state_with(pool.clone(), &storage, |cfg| {
            cfg.totp_policy = Some(totp_policy::TotpPolicy::RequiredForAll);
        });

        let code = build_totp(fx.secret_bytes.clone(), fx.user.username.clone())
            .expect("totp")
            .generate_current()
            .expect("code");

        let auth = AuthExtension {
            user_id: fx.user.id,
            username: fx.user.username.clone(),
            email: fx.user.email.clone(),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: None,
        };
        let res = disable_totp(
            State(state),
            Extension(auth),
            Json(TotpDisableRequest {
                password: "real-test-password".to_string(),
                code,
            }),
        )
        .await;

        let still_enabled: Option<bool> =
            sqlx::query_scalar("SELECT totp_enabled FROM users WHERE id = $1")
                .bind(fx.user.id)
                .fetch_optional(&pool)
                .await
                .expect("read totp_enabled");

        tdh::cleanup_user(&pool, fx.user.id).await;
        let _ = std::fs::remove_dir_all(&fx.storage_dir);

        let err = res.expect_err("disable must be refused under a required policy");
        assert!(
            matches!(err, AppError::Conflict(_)),
            "expected a 409 Conflict, got {err:?}"
        );
        assert_eq!(still_enabled, Some(true), "TOTP must remain enabled");
    }
}
