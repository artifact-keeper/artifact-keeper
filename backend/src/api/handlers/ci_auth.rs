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
//!   "username": "ci-abc123456789"
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
use crate::services::ci_oidc_service::{CiOidcProvider, CiOidcService};

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

    // 3-5. Resolve the mapping, its service account, and mint.
    let (user, tokens) = exchange_validated_claims(&state, &svc, &provider, &claims).await?;

    Ok(Json(CiTokenResponse {
        access_token: tokens.access_token,
        token_type: "Bearer".to_string(),
        expires_in: tokens.expires_in,
        username: user.username,
    }))
}

/// Everything the exchange does once the assertion is verified: pick the
/// mapping, resolve its service account, mint the session.
///
/// Split from the handler so tests can drive the account resolution with
/// claims of their choosing — steps 1-2 need a live OIDC issuer.
async fn exchange_validated_claims(
    state: &SharedState,
    svc: &CiOidcService,
    provider: &CiOidcProvider,
    claims: &serde_json::Value,
) -> Result<(User, TokenPair)> {
    // 3. Find the first matching enabled identity mapping (enforces claim filters)
    let mapping = svc.resolve_mapping(provider.id, claims).await?;

    // 4. The account is keyed on the mapping, never on a claim; point the
    //    credentials at the mapping's existing account (adopting one minted
    //    by an earlier version if need be).
    let credentials = CiOidcService::extract_identity_from_mapping(provider, &mapping, claims);
    let credentials = svc.resolve_service_account(&mapping, credentials).await?;

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
    let mint = |credentials| {
        mint_ci_session(
            &state.db,
            &auth_service,
            credentials,
            mapping.allowed_repo_ids.clone(),
            assertion_expiry(claims),
        )
    };
    let (user, tokens) = match mint(credentials.clone()).await {
        // Only reachable when the account is created here (a mapping from an
        // earlier version that never had one) and a concurrent exchange for
        // the same mapping created it first: the retry now finds that row.
        Err(AppError::Conflict(_)) => {
            let credentials = svc.resolve_service_account(&mapping, credentials).await?;
            mint(credentials).await?
        }
        other => other?,
    };

    // The subject names the presenting project and ref: it is recorded here,
    // for audit, and confers no identity.
    tracing::info!(
        target: "security",
        user_id = %user.id,
        username = %user.username,
        mapping_id = %mapping.id,
        subject = claims["sub"].as_str().unwrap_or(""),
        "CI OIDC token exchange"
    );
    Ok((user, tokens))
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
    // The sync keeps a CI account's `is_active` as it finds it (#4031).
    // `resolve_service_account` already refused an inactive account; this
    // catches one deactivated since, e.g. by a mapping delete committing
    // mid-exchange, so no token or refresh JTI is minted for it.
    if !user.is_active {
        tracing::warn!(
            target: "security",
            user_id = %user.id,
            username = %user.username,
            "CI OIDC: service account deactivated during the exchange; refusing"
        );
        return Err(AppError::Authentication(
            "The service account for this CI identity mapping is deactivated".into(),
        ));
    }

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

#[cfg(ak_test_shard = "handlers-1")]
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

    // -----------------------------------------------------------------------
    // One mapping, one principal (fix-ci-oidc-identity-key)
    //
    // The bug these pin was a mismatch between a SELECT and an INSERT two
    // layers apart — looked up by the token subject, inserted under the
    // mapping-derived username — so only a DB-backed exchange can catch it.
    // Each drives the real post-verification path (`exchange_validated_claims`)
    // with GitLab-shaped claims; signature verification is steps 1-2.
    // -----------------------------------------------------------------------

    mod one_principal {
        use super::super::{exchange_validated_claims, mint_ci_session};
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::api::SharedState;
        use crate::error::AppError;
        use crate::models::user::User;
        use crate::services::auth_service::AuthService;
        use crate::services::ci_oidc_service::{
            service_account_external_id, service_account_username, CiOidcService,
            CreateCiOidcMappingRequest, CreateCiOidcProviderRequest,
        };
        use serde_json::json;
        use sqlx::PgPool;
        use std::sync::Arc;
        use uuid::Uuid;

        struct Fixture {
            pool: PgPool,
            state: SharedState,
            svc: CiOidcService,
            provider_id: Uuid,
            /// Extra user rows a test seeded outside the provider's key space.
            seeded: Vec<Uuid>,
        }

        impl Fixture {
            async fn new() -> Option<Self> {
                let pool = tdh::try_pool().await?;
                let storage_path = std::env::temp_dir()
                    .join(format!("ci-auth-principal-{}", Uuid::new_v4()))
                    .to_string_lossy()
                    .to_string();
                let state = tdh::build_state(pool.clone(), &storage_path);
                let svc = CiOidcService::new(pool.clone());
                let provider = svc
                    .create(CreateCiOidcProviderRequest {
                        name: format!("gitlab-{}", Uuid::new_v4()),
                        provider_type: Some("gitlab".into()),
                        issuer_url: "https://gitlab.example.com".into(),
                        audience: None,
                        is_enabled: Some(true),
                    })
                    .await
                    .expect("create provider");
                Some(Self {
                    pool,
                    state,
                    svc,
                    provider_id: provider.id,
                    seeded: Vec::new(),
                })
            }

            async fn mapping(&self, claim_filters: serde_json::Value) -> Uuid {
                self.svc
                    .create_mapping(
                        self.provider_id,
                        CreateCiOidcMappingRequest {
                            name: "deploy".into(),
                            priority: None,
                            claim_filters,
                            allowed_repo_ids: None,
                            is_enabled: None,
                        },
                    )
                    .await
                    .expect("create mapping")
                    .id
            }

            /// A mapping row as an earlier version wrote it: no account yet.
            async fn legacy_mapping(&self, id: Uuid, claim_filters: serde_json::Value) {
                sqlx::query(
                    "INSERT INTO ci_oidc_identity_mappings (id, provider_id, name, claim_filters) \
                     VALUES ($1, $2, 'legacy', $3)",
                )
                .bind(id)
                .bind(self.provider_id)
                .bind(claim_filters)
                .execute(&self.pool)
                .await
                .expect("insert legacy mapping");
            }

            /// A CI account as an earlier version minted it: keyed on a raw
            /// token subject.
            async fn legacy_account(&mut self, username: &str, subject: &str) -> Uuid {
                let id: Uuid = sqlx::query_scalar(
                    "INSERT INTO users (username, email, auth_provider, external_id) \
                     VALUES ($1, $2, 'ci', $3) RETURNING id",
                )
                .bind(username)
                .bind(format!("{username}@ci.artifact-keeper.internal"))
                .bind(subject)
                .fetch_one(&self.pool)
                .await
                .expect("seed legacy CI account");
                self.seeded.push(id);
                id
            }

            async fn exchange(&self, claims: serde_json::Value) -> crate::error::Result<User> {
                let provider = self.svc.get(self.provider_id).await?;
                exchange_validated_claims(&self.state, &self.svc, &provider, &claims)
                    .await
                    .map(|(user, _)| user)
            }

            /// CI accounts keyed under this fixture's provider.
            async fn provider_accounts(&self) -> Vec<(Uuid, bool)> {
                sqlx::query_as(
                    "SELECT id, is_active FROM users \
                     WHERE auth_provider = 'ci' AND external_id LIKE $1 ORDER BY id",
                )
                .bind(format!("ci:{}:%", self.provider_id))
                .fetch_all(&self.pool)
                .await
                .expect("list provider accounts")
            }

            async fn cleanup(self) {
                let mut ids: Vec<Uuid> = self
                    .provider_accounts()
                    .await
                    .into_iter()
                    .map(|(id, _)| id)
                    .collect();
                ids.extend(self.seeded);
                for sql in [
                    "DELETE FROM refresh_token_jti WHERE user_id = ANY($1)",
                    "DELETE FROM user_roles WHERE user_id = ANY($1)",
                    "DELETE FROM ci_oidc_service_account_rekey_log WHERE user_id = ANY($1)",
                    "DELETE FROM users WHERE id = ANY($1)",
                ] {
                    let _ = sqlx::query(sql).bind(&ids).execute(&self.pool).await;
                }
                let _ = sqlx::query("DELETE FROM ci_oidc_providers WHERE id = $1")
                    .bind(self.provider_id)
                    .execute(&self.pool)
                    .await;
            }
        }

        /// GitLab ID-token claims for one pipeline.
        fn gitlab(project: &str, ref_type: &str, git_ref: &str) -> serde_json::Value {
            json!({
                "sub": format!("project_path:{project}:ref_type:{ref_type}:ref:{git_ref}"),
                "project_path": project,
                "ref_type": ref_type,
                "ref": git_ref,
            })
        }

        /// 1.2 — two refs of one project. Before the fix the second exchange
        /// failed with `409 "Username already exists"`.
        #[tokio::test]
        async fn two_refs_of_one_project_resolve_to_one_account() {
            let Some(fx) = Fixture::new().await else {
                return;
            };
            fx.mapping(json!({"project_path": "group/app"})).await;

            let main = fx
                .exchange(gitlab("group/app", "branch", "main"))
                .await
                .expect("main pipeline exchanges");
            let feature = fx
                .exchange(gitlab("group/app", "branch", "feature/x"))
                .await
                .expect("a second ref of the same project must not be refused");
            let tag = fx
                .exchange(gitlab("group/app", "tag", "v1.0.0"))
                .await
                .expect("a tag pipeline after a branch pipeline must not be refused");

            assert_eq!(feature.id, main.id);
            assert_eq!(tag.id, main.id);
            fx.cleanup().await;
        }

        /// 1.3 — two projects admitted by one any-of filter share the root
        /// cause: two subjects, one derived username.
        #[tokio::test]
        async fn any_of_filter_resolves_both_projects_to_one_account() {
            let Some(fx) = Fixture::new().await else {
                return;
            };
            fx.mapping(json!({"project_path": ["group/app", "group/app-fork"]}))
                .await;

            let upstream = fx
                .exchange(gitlab("group/app", "branch", "main"))
                .await
                .expect("upstream exchanges");
            let fork = fx
                .exchange(gitlab("group/app-fork", "branch", "main"))
                .await
                .expect("the second project admitted by the any-of filter must not be refused");

            assert_eq!(fork.id, upstream.id);
            fx.cleanup().await;
        }

        /// 1.4 — N distinct subjects through one mapping leave exactly one
        /// `auth_provider = 'ci'` row for it.
        #[tokio::test]
        async fn many_subjects_leave_exactly_one_account() {
            let Some(fx) = Fixture::new().await else {
                return;
            };
            let mapping_id = fx.mapping(json!({"project_path": "group/app"})).await;

            for i in 0..5 {
                fx.exchange(gitlab("group/app", "branch", &format!("branch-{i}")))
                    .await
                    .expect("every ref exchanges");
            }

            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM users WHERE auth_provider = 'ci' AND external_id = $1",
            )
            .bind(service_account_external_id(fx.provider_id, mapping_id))
            .fetch_one(&fx.pool)
            .await
            .unwrap();
            assert_eq!(count, 1);
            assert_eq!(fx.provider_accounts().await.len(), 1);
            fx.cleanup().await;
        }

        /// 3.3 — the account exists from mapping creation; the first exchange
        /// resolves to it and creates nothing.
        #[tokio::test]
        async fn first_exchange_uses_the_pre_provisioned_account() {
            let Some(fx) = Fixture::new().await else {
                return;
            };
            let mapping_id = fx.mapping(json!({"project_path": "group/app"})).await;
            let reported = fx
                .svc
                .get_mapping(fx.provider_id, mapping_id)
                .await
                .unwrap()
                .service_account_id
                .expect("the mapping reports its account before any exchange");
            let before = fx.provider_accounts().await;
            assert_eq!(before, vec![(reported, true)]);

            let user = fx
                .exchange(gitlab("group/app", "branch", "main"))
                .await
                .expect("first exchange");

            assert_eq!(user.id, reported);
            assert_eq!(user.username, service_account_username(mapping_id));
            assert_eq!(fx.provider_accounts().await, before, "nothing was created");
            fx.cleanup().await;
        }

        /// 3.4 — deleting the mapping deactivates, never deletes, the account,
        /// and the mapping's pipelines are refused afterwards.
        #[tokio::test]
        async fn deleting_the_mapping_deactivates_its_account() {
            let Some(fx) = Fixture::new().await else {
                return;
            };
            let mapping_id = fx.mapping(json!({"project_path": "group/app"})).await;
            let user = fx
                .exchange(gitlab("group/app", "branch", "main"))
                .await
                .expect("exchange before delete");

            let deactivated = fx
                .svc
                .delete_mapping(fx.provider_id, mapping_id)
                .await
                .expect("delete mapping");
            assert_eq!(deactivated, vec![user.id]);
            assert_eq!(
                fx.provider_accounts().await,
                vec![(user.id, false)],
                "the row survives, inactive, so its audit trail stays attributable"
            );

            let err = fx
                .exchange(gitlab("group/app", "branch", "main"))
                .await
                .expect_err("a deleted mapping's pipelines must be refused");
            assert!(matches!(err, AppError::Authentication(_)), "got: {err}");
            assert_eq!(fx.provider_accounts().await, vec![(user.id, false)]);
            fx.cleanup().await;
        }

        /// Deleting the provider cascades to its mappings, so their accounts
        /// are deactivated the same way.
        #[tokio::test]
        async fn deleting_the_provider_deactivates_its_accounts() {
            let Some(fx) = Fixture::new().await else {
                return;
            };
            fx.mapping(json!({"project_path": "group/a"})).await;
            fx.mapping(json!({"project_path": "group/b"})).await;
            let mut accounts: Vec<Uuid> = fx
                .provider_accounts()
                .await
                .into_iter()
                .map(|(id, _)| id)
                .collect();

            let mut deactivated = fx.svc.delete(fx.provider_id).await.expect("delete");
            deactivated.sort();
            accounts.sort();
            assert_eq!(deactivated, accounts);
            assert!(fx
                .provider_accounts()
                .await
                .iter()
                .all(|(_, active)| !active));
            fx.cleanup().await;
        }

        /// A mapping from an earlier version that never had an account gets
        /// one on its first exchange. If a non-CI account already holds the
        /// name, the exchange retries once and then refuses with 409; it must
        /// never bind the pipeline to that account.
        #[tokio::test]
        async fn legacy_mapping_without_an_account_never_binds_to_a_squatter() {
            let Some(mut fx) = Fixture::new().await else {
                return;
            };
            let mapping_id = Uuid::new_v4();
            fx.legacy_mapping(mapping_id, json!({"project_path": "group/app"}))
                .await;
            let name = service_account_username(mapping_id);
            let squatter: Uuid = sqlx::query_scalar(
                "INSERT INTO users (username, email) VALUES ($1, $2) RETURNING id",
            )
            .bind(&name)
            .bind(format!("{}@example.com", Uuid::new_v4()))
            .fetch_one(&fx.pool)
            .await
            .unwrap();
            fx.seeded.push(squatter);

            let err = fx
                .exchange(gitlab("group/app", "branch", "main"))
                .await
                .expect_err("a local account holding the name must not become the CI principal");
            assert!(matches!(err, AppError::Conflict(_)), "got: {err}");
            assert!(fx.provider_accounts().await.is_empty());

            // Without the squatter the same mapping provisions lazily, once.
            sqlx::query("UPDATE users SET username = $2 WHERE id = $1")
                .bind(squatter)
                .bind(format!("renamed-{}", Uuid::new_v4()))
                .execute(&fx.pool)
                .await
                .unwrap();
            let user = fx
                .exchange(gitlab("group/app", "branch", "main"))
                .await
                .expect("first exchange provisions the legacy mapping's account");
            assert_eq!(user.username, name);
            assert_eq!(fx.provider_accounts().await, vec![(user.id, true)]);
            fx.cleanup().await;
        }

        /// 2.3 — an account minted by an earlier version (`ci-<8hex>`, keyed
        /// on a raw GitLab subject) is adopted, keeping its `users.id`.
        ///
        /// In the `db-serial` group (`ci_rekey_`): migration 232's test
        /// rewrites every legacy-shaped row it can attribute.
        #[tokio::test]
        async fn ci_rekey_adopts_a_pre_upgrade_account() {
            let Some(mut fx) = Fixture::new().await else {
                return;
            };
            let mapping_id = Uuid::new_v4();
            fx.legacy_mapping(mapping_id, json!({"project_path": "group/app"}))
                .await;
            let legacy_name = format!("ci-{}", &mapping_id.simple().to_string()[..8]);
            let old_sub = "project_path:group/app:ref_type:branch:ref:main";
            let legacy_id = fx.legacy_account(&legacy_name, old_sub).await;

            let user = fx
                .exchange(gitlab("group/app", "branch", "release"))
                .await
                .expect("a pre-upgrade account must be adopted, not collided with");
            assert_eq!(user.id, legacy_id, "same principal, so its grants survive");
            assert_eq!(
                user.username, legacy_name,
                "existing names are not rewritten"
            );
            assert_eq!(
                user.external_id.as_deref(),
                Some(service_account_external_id(fx.provider_id, mapping_id).as_str())
            );

            let logged: (Option<String>, String) = sqlx::query_as(
                "SELECT previous_external_id, outcome FROM ci_oidc_service_account_rekey_log \
                 WHERE user_id = $1",
            )
            .bind(legacy_id)
            .fetch_one(&fx.pool)
            .await
            .expect("adoption is recorded for rollback");
            assert_eq!(logged, (Some(old_sub.to_string()), "adopted".to_string()));

            let again = fx
                .exchange(gitlab("group/app", "tag", "v2.0.0"))
                .await
                .expect("later exchanges resolve by the new key");
            assert_eq!(again.id, legacy_id);
            fx.cleanup().await;
        }

        /// 2.4 — two rows that could each be this mapping's account: the
        /// exchange refuses rather than binding to either.
        #[tokio::test]
        async fn ci_rekey_refuses_two_candidate_accounts() {
            let Some(mut fx) = Fixture::new().await else {
                return;
            };
            let mapping_id = Uuid::new_v4();
            fx.legacy_mapping(mapping_id, json!({"project_path": "group/app"}))
                .await;
            let hex = mapping_id.simple().to_string();
            let a = fx
                .legacy_account(
                    &format!("ci-{}", &hex[..8]),
                    "project_path:group/app:ref_type:branch:ref:main",
                )
                .await;
            let b = fx
                .legacy_account(
                    &format!("ci-{}", &hex[..12]),
                    "project_path:group/app:ref_type:tag:ref:v1",
                )
                .await;

            let err = fx
                .exchange(gitlab("group/app", "branch", "main"))
                .await
                .expect_err("an ambiguous account must not be guessed");
            assert!(err.to_string().contains("ambiguous"), "got: {err}");

            let keys: Vec<Option<String>> = sqlx::query_scalar(
                "SELECT external_id FROM users WHERE id = ANY($1) ORDER BY username",
            )
            .bind(vec![a, b])
            .fetch_all(&fx.pool)
            .await
            .unwrap();
            assert!(
                keys.iter()
                    .all(|k| !k.as_deref().unwrap_or("").starts_with("ci:")),
                "neither candidate was rewritten: {keys:?}"
            );
            assert!(
                fx.provider_accounts().await.is_empty(),
                "nothing was created"
            );
            fx.cleanup().await;
        }

        /// A legacy `ci-<8hex>` name shared by two mappings' UUID prefixes
        /// cannot be attributed, so it is never adopted by either — the
        /// same rule migration 232 applies.
        #[tokio::test]
        async fn ci_rekey_does_not_adopt_across_a_prefix_collision() {
            let Some(mut fx) = Fixture::new().await else {
                return;
            };
            let prefix = &Uuid::new_v4().simple().to_string()[..8];
            let twin =
                |tail: &str| Uuid::parse_str(&format!("{prefix}-0000-4000-8000-{tail}")).unwrap();
            let (first, second) = (twin("000000000001"), twin("000000000002"));
            fx.legacy_mapping(first, json!({"project_path": "group/app"}))
                .await;
            fx.legacy_mapping(second, json!({"project_path": "group/other"}))
                .await;
            let legacy_id = fx
                .legacy_account(
                    &format!("ci-{prefix}"),
                    "project_path:group/other:ref_type:branch:ref:main",
                )
                .await;

            let user = fx
                .exchange(gitlab("group/app", "branch", "main"))
                .await
                .expect("the mapping still authenticates, as its own new account");
            assert_ne!(user.id, legacy_id);
            assert_eq!(user.username, service_account_username(first));
            let untouched: Option<String> =
                sqlx::query_scalar("SELECT external_id FROM users WHERE id = $1")
                    .bind(legacy_id)
                    .fetch_one(&fx.pool)
                    .await
                    .unwrap();
            assert_eq!(
                untouched.as_deref(),
                Some("project_path:group/other:ref_type:branch:ref:main")
            );
            fx.cleanup().await;
        }

        async fn is_active(pool: &PgPool, user_id: Uuid) -> bool {
            sqlx::query_scalar("SELECT is_active FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_one(pool)
                .await
                .expect("read is_active")
        }

        async fn deactivate(pool: &PgPool, user_id: Uuid) {
            sqlx::query("UPDATE users SET is_active = false WHERE id = $1")
                .bind(user_id)
                .execute(pool)
                .await
                .expect("deactivate account");
        }

        /// Deactivating a CI account is a kill switch: the next pipeline is
        /// refused, and neither reactivates the account nor gets a new one.
        #[tokio::test]
        async fn ci_oidc_deactivated_account_stays_deactivated() {
            let Some(fx) = Fixture::new().await else {
                return;
            };
            fx.mapping(json!({"project_path": "group/app"})).await;
            let user = fx
                .exchange(gitlab("group/app", "branch", "main"))
                .await
                .expect("exchange before deactivation");

            deactivate(&fx.pool, user.id).await;

            let err = fx
                .exchange(gitlab("group/app", "branch", "main"))
                .await
                .expect_err("a deactivated account must not be exchanged for");
            assert!(matches!(err, AppError::Authentication(_)), "got: {err}");
            assert!(
                !is_active(&fx.pool, user.id).await,
                "the exchange must not reactivate the account"
            );
            assert_eq!(
                fx.provider_accounts().await,
                vec![(user.id, false)],
                "no replacement account is created"
            );
            fx.cleanup().await;
        }

        /// An account deactivated after `resolve_service_account` looked at it
        /// (a mapping delete committing mid-exchange) is not reactivated by
        /// the sync, and nothing is minted for it.
        #[tokio::test]
        async fn ci_oidc_sync_never_reactivates_a_service_account() {
            let Some(fx) = Fixture::new().await else {
                return;
            };
            let mapping_id = fx.mapping(json!({"project_path": "group/app"})).await;
            let claims = gitlab("group/app", "branch", "main");
            let provider = fx.svc.get(fx.provider_id).await.unwrap();
            let mapping = fx
                .svc
                .resolve_mapping(fx.provider_id, &claims)
                .await
                .unwrap();
            assert_eq!(mapping.id, mapping_id);
            let credentials =
                CiOidcService::extract_identity_from_mapping(&provider, &mapping, &claims);
            let credentials = fx
                .svc
                .resolve_service_account(&mapping, credentials)
                .await
                .expect("the account is active when resolved");
            let (account, _) = fx.provider_accounts().await[0];

            deactivate(&fx.pool, account).await;

            let auth_service =
                AuthService::new(fx.state.db.clone(), Arc::new(fx.state.config.clone()));
            let err = mint_ci_session(&fx.pool, &auth_service, credentials, None, None)
                .await
                .expect_err("nothing may be minted for a deactivated account");
            assert!(matches!(err, AppError::Authentication(_)), "got: {err}");
            assert!(!is_active(&fx.pool, account).await);
            let jtis: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM refresh_token_jti WHERE user_id = $1")
                    .bind(account)
                    .fetch_one(&fx.pool)
                    .await
                    .unwrap();
            assert_eq!(jtis, 0, "no refresh token was persisted");
            fx.cleanup().await;
        }

        /// A deactivated pre-upgrade account is neither adopted nor stepped
        /// around by creating a fresh account for its mapping. (`ci_rekey_`:
        /// it seeds a legacy-shaped row, so it runs in the `db-serial` group.)
        #[tokio::test]
        async fn ci_rekey_deactivated_legacy_account_is_not_bypassed() {
            let Some(mut fx) = Fixture::new().await else {
                return;
            };
            let mapping_id = Uuid::new_v4();
            fx.legacy_mapping(mapping_id, json!({"project_path": "group/app"}))
                .await;
            let subject = "project_path:group/app:ref_type:branch:ref:main";
            let legacy_id = fx
                .legacy_account(
                    &format!("ci-{}", &mapping_id.simple().to_string()[..8]),
                    subject,
                )
                .await;
            deactivate(&fx.pool, legacy_id).await;

            let err = fx
                .exchange(gitlab("group/app", "branch", "main"))
                .await
                .expect_err("a deactivated legacy account must refuse the exchange");
            assert!(matches!(err, AppError::Authentication(_)), "got: {err}");
            assert!(!is_active(&fx.pool, legacy_id).await);
            assert!(
                fx.provider_accounts().await.is_empty(),
                "neither adopted nor replaced by a new keyed account"
            );
            fx.cleanup().await;
        }

        /// The same token subject under two providers is two principals.
        /// Before #4031 the account was looked up by the bare `sub`, so two
        /// issuers presenting the same string landed on one row.
        #[tokio::test]
        async fn ci_oidc_same_subject_under_two_providers_is_two_accounts() {
            let Some(a) = Fixture::new().await else {
                return;
            };
            let Some(b) = Fixture::new().await else {
                a.cleanup().await;
                return;
            };
            let mapping_a = a.mapping(json!({"project_path": "group/app"})).await;
            let mapping_b = b.mapping(json!({"project_path": "group/app"})).await;
            let claims = gitlab("group/app", "branch", "main");

            let via_a = a.exchange(claims.clone()).await.expect("provider a");
            let via_b = b.exchange(claims).await.expect("provider b");

            assert_ne!(via_a.id, via_b.id);
            assert_eq!(via_a.username, service_account_username(mapping_a));
            assert_eq!(via_b.username, service_account_username(mapping_b));
            assert_eq!(a.provider_accounts().await, vec![(via_a.id, true)]);
            assert_eq!(b.provider_accounts().await, vec![(via_b.id, true)]);
            a.cleanup().await;
            b.cleanup().await;
        }

        /// The same token subject matched by two mappings of one provider is
        /// two principals: the filters differ on a claim `sub` does not carry.
        #[tokio::test]
        async fn ci_oidc_same_subject_under_two_mappings_is_two_accounts() {
            let Some(fx) = Fixture::new().await else {
                return;
            };
            let staging = fx
                .mapping(json!({"project_path": "group/app", "environment": "staging"}))
                .await;
            let production = fx
                .mapping(json!({"project_path": "group/app", "environment": "production"}))
                .await;
            let claims = |environment: &str| {
                let mut c = gitlab("group/app", "branch", "main");
                c["environment"] = json!(environment);
                c
            };
            assert_eq!(claims("staging")["sub"], claims("production")["sub"]);

            let to_staging = fx.exchange(claims("staging")).await.expect("staging");
            let to_production = fx.exchange(claims("production")).await.expect("production");

            assert_ne!(to_staging.id, to_production.id);
            assert_eq!(to_staging.username, service_account_username(staging));
            assert_eq!(to_production.username, service_account_username(production));
            let again = fx.exchange(claims("staging")).await.expect("staging again");
            assert_eq!(again.id, to_staging.id);
            assert_eq!(fx.provider_accounts().await.len(), 2);
            fx.cleanup().await;
        }
    }
}
