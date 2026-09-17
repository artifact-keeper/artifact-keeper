//! Public CI OIDC token exchange endpoint.
//!
//! CI pipelines POST a CI-issued JWT here and receive a short-lived
//! Artifact Keeper access token in return — no static secrets required.
//!
//! # Request
//! ```text
//! POST /api/v1/auth/ci/token
//! Authorization: Bearer <CI-issued OIDC JWT>
//! ```
//!
//! The CI JWT is supplied in the `Authorization` header rather than the
//! request body to prevent it from appearing in access logs, HTTP traces,
//! or any middleware that records request payloads.
//!
//! The request body is **optional** (#3548). The provider is resolved from
//! the assertion's own `iss` claim, so a pipeline needs nothing but its JWT.
//! A body naming a provider explicitly is still accepted:
//!
//! ```text
//! Content-Type: application/json
//!
//! {"provider_id": "<uuid>"}
//! ```
//!
//! # Response
//! ```json
//! {
//!   "access_token": "...",
//!   "token_type": "Bearer",
//!   "expires_in": 900,
//!   "username": "ci-abc12345"
//! }
//! ```
//!
//! The `username` field can be used directly as the Docker login username,
//! removing the need for a separate `GET /api/v1/auth/me` call.
//!
//! **Token lifetime:** `expires_in` is the TTL in seconds (default 900 s /
//! 15 min).  Docker caches credentials and does not auto-refresh — if your
//! pipeline runs longer than this window, re-exchange the CI JWT before each
//! `docker push` step.

use std::sync::Arc;

use axum::{body::Bytes, extract::State, http::HeaderMap, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::user::User;
use crate::services::auth_service::{AuthService, FederatedCredentials, TokenPair};
use crate::services::ci_oidc_service::CiOidcService;

/// Create public CI auth routes (no auth middleware needed — the CI JWT is the
/// credential).
pub fn router() -> Router<SharedState> {
    Router::new().route("/token", post(exchange_ci_token))
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct CiTokenRequest {
    /// Optional UUID of the `ci_oidc_providers` row to validate against.
    ///
    /// Leave it out — and omit the body entirely — to have the provider
    /// resolved from the assertion's own `iss` claim (#3548). The UUID is
    /// server-generated and only published by the admin-only
    /// `GET /api/v1/admin/ci-oidc`, so requiring it here meant a keyless CI
    /// job had to authenticate with the admin password first.
    ///
    /// It is still honoured as an explicit override, for callers written
    /// against the pre-#3548 shape and for instances that configure two
    /// enabled providers on the same issuer. It must agree with the
    /// assertion's `iss`; a provider that does not is a 400.
    #[serde(default)]
    pub provider_id: Option<Uuid>,
    // NOTE: The CI JWT is NOT in this struct. It must be supplied in the
    // `Authorization: Bearer <jwt>` header to keep it out of access logs.
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CiTokenResponse {
    /// Short-lived Artifact Keeper access token.
    pub access_token: String,
    pub token_type: String,
    /// Lifetime in seconds (default 900 = 15 min).
    ///
    /// Docker caches credentials and does not auto-refresh. Re-exchange the
    /// CI JWT before each `docker push` step if the pipeline runs longer
    /// than this window.
    pub expires_in: u64,
    /// The provisioned CI service-account username.
    ///
    /// Use this directly as `docker login --username` — no separate
    /// `GET /api/v1/auth/me` call is needed.
    pub username: String,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Exchange a CI-issued OIDC JWT for an Artifact Keeper access token.
///
/// The JWT must be supplied in the `Authorization: Bearer <jwt>` header.
/// The CI platform (GitLab / GitHub Actions / generic OIDC) must be
/// pre-configured by an administrator via `POST /api/v1/admin/ci-oidc`.
///
/// The request body is optional: with no body the provider is resolved from
/// the assertion's `iss` claim, so the JWT is the only thing a pipeline needs
/// (#3548). Send `{"provider_id": "<uuid>"}` to name a provider explicitly.
#[utoipa::path(
    post,
    path = "/token",
    context_path = "/api/v1/auth/ci",
    tag = "auth",
    request_body(
        content = CiTokenRequest,
        description = "Optional. Omit the body entirely to resolve the provider from \
                       the assertion's iss claim; send provider_id only to override that.",
    ),
    responses(
        (status = 200, description = "CI token exchange successful", body = CiTokenResponse),
        (status = 400, description = "Malformed body, provider_id disagrees with the assertion's iss, or the issuer matches several enabled providers", body = crate::api::openapi::ErrorResponse),
        (status = 401, description = "Invalid CI token or provider configuration", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "No enabled CI OIDC provider matches the assertion's issuer", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn exchange_ci_token(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<CiTokenResponse>> {
    // Extract the CI JWT from the Authorization header. This keeps it out of
    // the request body and therefore out of access logs and HTTP traces.
    let jwt = extract_bearer_jwt(&headers)?;

    let req = parse_optional_body(&body)?;

    let svc = CiOidcService::new(state.db.clone());

    // 1. Pick the provider from the assertion's own `iss` claim, or from the
    //    explicit `provider_id` override when one was sent (#3548).
    let provider = svc
        .resolve_provider_for_assertion(jwt, req.provider_id)
        .await?;

    // 2. Validate the CI JWT (signature, audience, issuer — no claim check yet)
    let claims = svc.validate_ci_jwt(&provider, jwt).await?;

    // 3. Find the first matching enabled identity mapping (enforces claim filters)
    let mapping = svc.resolve_mapping(provider.id, &claims).await?;

    // 4. Map CI claims + mapping to stable FederatedCredentials
    let credentials = CiOidcService::extract_identity_from_mapping(&provider, &mapping, &claims);

    // 5. Provision / sync the CI service account and generate scoped tokens.
    //
    //    The minted access token's `exp` is capped at the presented
    //    assertion's own `exp` (#3820), the rule every other arm that
    //    exchanges a presented credential follows after #3625/#3460: an
    //    exchange narrows a lifetime, never extends it, so access dies with
    //    the credential that anchored it. An assertion with no usable `exp`
    //    yields `None` and the configured base TTL stands — the verifier in
    //    step 2 has already rejected anything actually expired.
    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    let (user, tokens) = mint_ci_session(
        &state.db,
        &auth_service,
        credentials,
        mapping.allowed_repo_ids.clone(),
        assertion_expiry(&claims),
    )
    .await?;

    Ok(Json(CiTokenResponse {
        access_token: tokens.access_token,
        token_type: "Bearer".to_string(),
        expires_in: tokens.expires_in,
        username: user.username,
    }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Provision / sync the CI service account and mint its tokens, capping the
/// ACCESS token's `exp` at `assertion_exp` (#3820).
///
/// This is `AuthService::authenticate_federated_with_scope` with one thing
/// changed, composed here from that method's own public parts rather than
/// added to `AuthService` as a fourth near-identical `..._with_scope_capped`
/// wrapper. The capped minter `generate_tokens_with_scope_capped` already
/// exists and is already public — it is what the Conan `users/authenticate`
/// and OCI `/v2/token` arms mint through after #3625/#3460 — so the only
/// difference between the SSO path and this one is which expiry is passed to
/// it. The three SSO callers keep the uncapped method untouched: they
/// authenticate afresh rather than exchanging a credential that already
/// carries an expiry, so capping them would be wrong.
async fn mint_ci_session(
    db: &sqlx::PgPool,
    auth_service: &AuthService,
    credentials: FederatedCredentials,
    allowed_repo_ids: Option<Vec<Uuid>>,
    assertion_exp: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<(User, TokenPair)> {
    let user = auth_service
        .sync_federated_user(CiOidcService::auth_provider(), &credentials)
        .await?;

    // Display-only field, throttled to at most once per 5 minutes per user
    // (#2107) so a pipeline re-exchanging on every job does not churn WAL.
    sqlx::query(
        "UPDATE users SET last_login_at = NOW() \
         WHERE id = $1 \
           AND (last_login_at IS NULL OR last_login_at < NOW() - INTERVAL '5 minutes')",
    )
    .bind(user.id)
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // `scopes: None` — a CI exchange mints an action-unrestricted token, as
    // the federated path always has (#2430); the repository allow-list comes
    // from the resolved identity mapping.
    let tokens = auth_service.generate_tokens_with_scope_capped(
        &user,
        None,
        allowed_repo_ids,
        assertion_exp,
    )?;
    auth_service
        .persist_refresh_jti_from_pair(&tokens, user.id)
        .await?;
    Ok((user, tokens))
}

/// Parse the optional JSON request body.
///
/// An absent body is the #3548 happy path (the provider comes from the
/// assertion), but a body that WAS sent and is malformed must be a 400 rather
/// than a silently ignored `provider_id`. `Option<Json<T>>` cannot express
/// that on axum 0.7 — its `FromRequest` impl maps every rejection, wrong
/// content-type and invalid JSON alike, to `None` — so the raw bytes are
/// parsed here instead (same approach as `quarantine.rs`, #2912).
fn parse_optional_body(body: &Bytes) -> Result<CiTokenRequest> {
    if body.is_empty() {
        return Ok(CiTokenRequest::default());
    }
    serde_json::from_slice(body)
        .map_err(|e| AppError::Validation(format!("Invalid request body: {e}")))
}

/// The `exp` of the presented assertion, as the cap for the minted access
/// token (#3820).
///
/// `None` when the assertion carries no numeric `exp`: the cap may only ever
/// narrow the lifetime, so an unreadable expiry leaves the configured base TTL
/// in place rather than minting something arbitrary.
fn assertion_expiry(claims: &serde_json::Value) -> Option<chrono::DateTime<chrono::Utc>> {
    claims
        .get("exp")
        .and_then(serde_json::Value::as_i64)
        .and_then(|exp| chrono::DateTime::<chrono::Utc>::from_timestamp(exp, 0))
}

/// Extract the raw token value from an `Authorization: Bearer <token>` header.
///
/// Returns `AppError::Authentication` if the header is missing, uses the wrong
/// scheme, or is otherwise malformed.
fn extract_bearer_jwt(headers: &HeaderMap) -> Result<&str> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            AppError::Authentication(
                "Missing Authorization header. \
                 Supply the CI JWT as: Authorization: Bearer <jwt>"
                    .into(),
            )
        })?;

    value
        .strip_prefix("Bearer ")
        .filter(|t| !t.is_empty())
        .ok_or_else(|| {
            AppError::Authentication(
                "Authorization header must use the Bearer scheme: \
                 Authorization: Bearer <jwt>"
                    .into(),
            )
        })
}

#[derive(OpenApi)]
#[openapi(
    paths(exchange_ci_token),
    components(schemas(CiTokenRequest, CiTokenResponse))
)]
pub struct CiAuthApiDoc;

#[cfg(test)]
mod tests {
    use super::{assertion_expiry, exchange_ci_token, extract_bearer_jwt, parse_optional_body};
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::body::Bytes;
    use axum::extract::State;
    use axum::http::{HeaderMap, HeaderValue};
    use serde_json::json;
    use sqlx::postgres::PgPoolOptions;
    use uuid::Uuid;

    /// `{"provider_id": "<uuid>"}` as a raw body.
    fn body_with_provider(provider_id: Uuid) -> Bytes {
        Bytes::from(json!({ "provider_id": provider_id }).to_string())
    }

    fn lazy_test_state() -> crate::api::SharedState {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://localhost/artifact_keeper_test")
            .expect("lazy pool should build for header-validation tests");
        let storage_path = std::env::temp_dir()
            .join(format!("ci-auth-tests-{}", Uuid::new_v4()))
            .to_string_lossy()
            .to_string();
        tdh::build_state(pool, &storage_path)
    }

    #[test]
    fn extract_bearer_jwt_success() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer ci.jwt.token"),
        );

        let token = extract_bearer_jwt(&headers).expect("Bearer token should be parsed");
        assert_eq!(token, "ci.jwt.token");
    }

    #[test]
    fn extract_bearer_jwt_missing_header_fails() {
        let headers = HeaderMap::new();
        let err = extract_bearer_jwt(&headers).expect_err("missing header must fail");
        assert!(err.to_string().contains("Missing Authorization header"));
    }

    #[test]
    fn extract_bearer_jwt_wrong_scheme_fails() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic abc123"),
        );

        let err = extract_bearer_jwt(&headers).expect_err("non-bearer scheme must fail");
        assert!(err
            .to_string()
            .contains("Authorization header must use the Bearer scheme"));
    }

    #[test]
    fn extract_bearer_jwt_empty_bearer_fails() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer "),
        );

        let err = extract_bearer_jwt(&headers).expect_err("empty bearer token must fail");
        assert!(err
            .to_string()
            .contains("Authorization header must use the Bearer scheme"));
    }

    #[tokio::test]
    async fn exchange_ci_token_missing_header_fails_before_db() {
        let state = lazy_test_state();

        let err = exchange_ci_token(
            State(state),
            HeaderMap::new(),
            body_with_provider(Uuid::new_v4()),
        )
        .await
        .expect_err("missing Authorization header must fail");

        assert!(err.to_string().contains("Missing Authorization header"));
    }

    #[tokio::test]
    async fn exchange_ci_token_rejects_disabled_provider() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let storage_path = std::env::temp_dir()
            .join(format!("ci-auth-tests-{}", Uuid::new_v4()))
            .to_string_lossy()
            .to_string();
        let state = tdh::build_state(pool.clone(), &storage_path);

        let provider_id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO ci_oidc_providers
               (id, name, provider_type, issuer_url, audience, is_enabled)
               VALUES ($1, $2, $3, $4, $5, false)"#,
        )
        .bind(provider_id)
        .bind("disabled-provider")
        .bind("generic")
        .bind("https://issuer.example.com")
        .bind("artifact-keeper")
        .execute(&pool)
        .await
        .expect("insert disabled provider");

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer ci.jwt.token"),
        );

        let err = exchange_ci_token(State(state), headers, body_with_provider(provider_id))
            .await
            .expect_err("disabled provider should be rejected");

        assert!(err.to_string().contains("provider is disabled"));

        let _ = sqlx::query("DELETE FROM ci_oidc_identity_mappings WHERE provider_id = $1")
            .bind(provider_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM ci_oidc_providers WHERE id = $1")
            .bind(provider_id)
            .execute(&pool)
            .await;
    }
    // -----------------------------------------------------------------------
    // Optional request body (#3548)
    // -----------------------------------------------------------------------

    /// The #3548 happy path: no body at all, so a CI job needs nothing but the
    /// assertion it already holds.
    #[test]
    fn parse_optional_body_accepts_an_absent_body() {
        let req = parse_optional_body(&Bytes::new()).expect("an empty body is the default shape");
        assert_eq!(req.provider_id, None);

        // An explicit empty object is the same thing.
        let req = parse_optional_body(&Bytes::from_static(b"{}"))
            .expect("an empty JSON object must parse");
        assert_eq!(req.provider_id, None);
    }

    #[test]
    fn parse_optional_body_keeps_the_provider_id_override() {
        let id = Uuid::new_v4();
        let req = parse_optional_body(&body_with_provider(id)).expect("override body must parse");
        assert_eq!(req.provider_id, Some(id));
    }

    /// A body that was *sent* and is malformed must be a 400, not a silently
    /// dropped `provider_id` (the `Option<Json<T>>` trap, #2912).
    #[test]
    fn parse_optional_body_rejects_a_malformed_body() {
        for bad in [
            "not json",
            r#"{"provider_id": "not-a-uuid"}"#,
            r#"{"provider_id": 7}"#,
            r#"{"provider_id": "#,
        ] {
            let err = parse_optional_body(&Bytes::from(bad))
                .expect_err("a malformed body must not be ignored");
            assert!(
                err.to_string().contains("Invalid request body"),
                "got: {err}"
            );
            assert_eq!(
                axum::response::IntoResponse::into_response(err).status(),
                axum::http::StatusCode::BAD_REQUEST
            );
        }
    }

    /// With no body the handler still reaches the credential check first — the
    /// Authorization header stays mandatory, the body never carried the JWT.
    #[tokio::test]
    async fn exchange_ci_token_without_a_body_still_requires_the_bearer() {
        let state = lazy_test_state();

        let err = exchange_ci_token(State(state), HeaderMap::new(), Bytes::new())
            .await
            .expect_err("missing Authorization header must fail even with no body");

        assert!(err.to_string().contains("Missing Authorization header"));
    }

    // -----------------------------------------------------------------------
    // Minted-token expiry cap (#3820)
    // -----------------------------------------------------------------------

    #[test]
    fn assertion_expiry_reads_the_exp_claim() {
        let at = chrono::Utc::now().timestamp() + 300;
        assert_eq!(
            assertion_expiry(&json!({ "exp": at })),
            chrono::DateTime::<chrono::Utc>::from_timestamp(at, 0)
        );
        // An assertion with no usable `exp` leaves the base TTL in place: the
        // cap may only ever narrow.
        assert_eq!(assertion_expiry(&json!({})), None);
        assert_eq!(assertion_expiry(&json!({ "exp": "soon" })), None);
    }

    /// `POST /api/v1/auth/ci/token` exchanges a presented credential, so the
    /// token it mints must not outlive that credential (#3820) — the rule the
    /// Conan and OCI `/v2/token` arms adopted in #3625/#3460. Drives the mint
    /// site directly: the handler's steps 1-4 need a live OIDC issuer, step 5
    /// is what the cap changes.
    ///
    /// DB-backed; no-ops when no database is configured.
    #[tokio::test]
    async fn test_3820_ci_token_exchange_caps_the_mint_at_the_assertion_expiry() {
        use crate::services::auth_service::{AuthService, FederatedCredentials};
        use std::sync::Arc;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let storage_path = std::env::temp_dir()
            .join(format!("ci-auth-cap-{}", Uuid::new_v4()))
            .to_string_lossy()
            .to_string();
        let state = tdh::build_state(pool.clone(), &storage_path);
        let base_ttl_minutes = state.config.jwt_access_token_expiry_minutes;
        let auth_service = AuthService::new(pool.clone(), Arc::new(state.config.clone()));

        let creds = |tag: &str| FederatedCredentials {
            external_id: format!("ci-3820-{tag}"),
            username: format!("ci_3820_{tag}"),
            email: format!("ci_3820_{tag}@ci.artifact-keeper.internal"),
            display_name: Some("CI cap probe".to_string()),
            groups: vec!["ci".to_string()],
            required_admin_group: None,
            auto_create_users: true,
        };

        // An assertion expiring well after the base TTL must not extend it:
        // the cap only ever narrows.
        let tag = &Uuid::new_v4().to_string()[..8];
        let far = chrono::Utc::now().timestamp() + (base_ttl_minutes * 60) + 3600;
        let (far_user, far_tokens) = super::mint_ci_session(
            &pool,
            &auth_service,
            creds(&format!("far{tag}")),
            None,
            assertion_expiry(&json!({ "exp": far })),
        )
        .await
        .expect("federated CI exchange should succeed");
        let claims = auth_service
            .validate_access_token(&far_tokens.access_token)
            .expect("minted token validates");
        let remaining = claims.exp - chrono::Utc::now().timestamp();
        assert!(
            remaining > (base_ttl_minutes * 60) - 120,
            "a long-lived assertion must still get the uncapped base TTL: {remaining}s"
        );
        // `expires_in` was computed at mint time and `remaining` a few
        // statements later, so a second boundary between the two is normal;
        // what must hold is that they describe the same lifetime.
        let drift = far_tokens.expires_in as i64 - remaining;
        assert!(
            (0..=2).contains(&drift),
            "expires_in must report the real lifetime so the pipeline schedules renewal right \
             (expires_in={} remaining={remaining})",
            far_tokens.expires_in
        );

        // An assertion expiring BEFORE the base TTL caps the minted token at
        // its own `exp` to the second.
        let tag = &Uuid::new_v4().to_string()[..8];
        let soon = chrono::Utc::now().timestamp() + 300;
        assert!(
            soon < chrono::Utc::now().timestamp() + base_ttl_minutes * 60,
            "the test only means anything while the base TTL exceeds 5 minutes"
        );
        let (soon_user, soon_tokens) = super::mint_ci_session(
            &pool,
            &auth_service,
            creds(&format!("soon{tag}")),
            None,
            assertion_expiry(&json!({ "exp": soon })),
        )
        .await
        .expect("federated CI exchange should succeed");
        let claims = auth_service
            .validate_access_token(&soon_tokens.access_token)
            .expect("minted token validates");
        assert_eq!(
            claims.exp, soon,
            "the minted token must expire exactly with the assertion that bought it"
        );

        for user_id in [far_user.id, soon_user.id] {
            let _ = sqlx::query("DELETE FROM refresh_token_jti WHERE user_id = $1")
                .bind(user_id)
                .execute(&pool)
                .await;
            let _ = sqlx::query("DELETE FROM user_roles WHERE user_id = $1")
                .bind(user_id)
                .execute(&pool)
                .await;
            let _ = sqlx::query("DELETE FROM users WHERE id = $1")
                .bind(user_id)
                .execute(&pool)
                .await;
        }
    }
}
