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
//! **Token lifetime:** `expires_in` is the minted token's lifetime in seconds.
//! For every provider type except `kubernetes` it is the provider's
//! `token_ttl_secs` (default 900 s, at most 3600 s), whatever the presented
//! CI JWT's own `exp` (#5054): the CI JWT only has to be valid when it is
//! exchanged, as for AWS STS, GCP Workload Identity Federation, Azure, PyPI
//! trusted publishing and Vault. A `kubernetes` provider's pull-only
//! credential still expires no later than the ServiceAccount token it was
//! exchanged for (#3820). No refresh token is returned and a CI session cannot
//! be refreshed. Docker caches credentials and does not auto-refresh, so a job
//! that runs longer than the TTL requests a fresh CI JWT, exchanges it again
//! and re-runs `docker login` before the steps that talk to Artifact Keeper.

use std::sync::Arc;

use axum::{body::Bytes, extract::State, http::HeaderMap, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::user::User;
use crate::services::auth_service::{AccessToken, AuthService, FederatedCredentials};
use crate::services::ci_oidc_service::{claim_value, CiOidcProvider, CiOidcService};
use crate::services::metrics_service::AuthFailureReason;

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
        .await
        .inspect_err(|e| record_ci_auth_failure(e, AuthFailureReason::InvalidToken))?;

    // 2. Validate the CI JWT (signature, audience, issuer — no claim check yet)
    let claims = svc
        .validate_ci_jwt(&provider, jwt)
        .await
        .inspect_err(|e| record_ci_auth_failure(e, AuthFailureReason::InvalidToken))?;

    // 3-5. Resolve the mapping, its service account, and mint. A verified
    // assertion refused here is refused by policy (no mapping matches).
    let (user, tokens) = exchange_validated_claims(&state, &svc, &provider, &claims)
        .await
        .inspect_err(|e| record_ci_auth_failure(e, AuthFailureReason::Scope))?;

    Ok(Json(CiTokenResponse {
        access_token: tokens.access_token,
        token_type: "Bearer".to_string(),
        expires_in: tokens.expires_in,
        username: user.username,
    }))
}

/// Count a rejected CI assertion in `ak_auth_failures_total` (#4676): only
/// credential rejections, `expired` when the validator said so.
fn record_ci_auth_failure(err: &AppError, fallback: AuthFailureReason) {
    crate::services::metrics_service::record_auth_failure_for_error(
        crate::services::metrics_service::AuthFailureSurface::CiOidc,
        err,
        fallback,
    );
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
) -> Result<(User, AccessToken)> {
    // The verifier accepts an assertion up to its leeway past `exp` (clock
    // skew between the CI issuer and this server). That leeway must not chain
    // into a session: refuse here, before any account is touched, when the
    // assertion has no validity left (#4663). The assertion must be valid at
    // exchange time for every provider type; only a Kubernetes exchange also
    // caps the minted token at its `exp` (#5054).
    let assertion_exp = mintable_assertion_expiry(claims, chrono::Utc::now())?;

    // 3. Find the first matching enabled identity mapping (enforces claim filters)
    let mapping = svc.resolve_mapping(provider.id, claims).await?;

    // 4. The account is keyed on the mapping, never on a claim; point the
    //    credentials at the mapping's existing account (adopting one minted
    //    by an earlier version if need be).
    let credentials = CiOidcService::extract_identity_from_mapping(provider, &mapping, claims);
    let credentials = svc.resolve_service_account(&mapping, credentials).await?;

    // 5. Provision / sync the CI service account and generate scoped tokens.
    //
    //    The minted lifetime is decided by the provider (see
    //    `CredentialShape`): its `token_ttl_secs` for every type but
    //    `kubernetes`, which keeps the #3820 cap at the assertion's `exp`.
    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    let mint = |credentials| {
        mint_ci_session(
            svc,
            &auth_service,
            credentials,
            CredentialShape::for_provider(provider),
            mapping.allowed_repo_ids.clone(),
            mapping.group_binding_ids.is_some().then_some(mapping.id),
            assertion_exp,
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
    let subject = claims["sub"].as_str().unwrap_or("");
    if provider.provider_type == KUBERNETES_PROVIDER_TYPE {
        // One mapping serves many workloads and its account is named after
        // the mapping (design D5), so this line is where the pulling workload
        // is recorded. A claim the token lacks is logged as absent.
        let k8s = |pointer| {
            claim_value(claims, pointer)
                .and_then(serde_json::Value::as_str)
                .unwrap_or(ABSENT_CLAIM)
        };
        tracing::info!(
            target: "security",
            user_id = %user.id,
            username = %user.username,
            mapping_id = %mapping.id,
            subject,
            k8s_namespace = k8s("/kubernetes.io/namespace"),
            k8s_serviceaccount = k8s("/kubernetes.io/serviceaccount/name"),
            k8s_pod = k8s("/kubernetes.io/pod/name"),
            k8s_node = k8s("/kubernetes.io/node/name"),
            "CI OIDC token exchange"
        );
    } else {
        tracing::info!(
            target: "security",
            user_id = %user.id,
            username = %user.username,
            mapping_id = %mapping.id,
            subject,
            "CI OIDC token exchange"
        );
    }
    Ok((user, tokens))
}

/// `provider_type` whose exchange mints a pull-only, non-renewable credential.
const KUBERNETES_PROVIDER_TYPE: &str = "kubernetes";

/// Action scopes of a Kubernetes-exchanged access token: pull, nothing else.
const KUBERNETES_SCOPES: [&str; 2] = ["read:artifacts", "read:repositories"];

/// Logged for a `kubernetes.io` claim a token does not carry, such as the pod
/// of a token not bound to one.
const ABSENT_CLAIM: &str = "(absent)";

/// What an exchange mints, decided by the provider alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredentialShape {
    /// Action-unrestricted access token plus a persisted (never returned)
    /// refresh JTI, as every CI exchange has minted since #2430. The access
    /// token lives exactly `ttl`, the provider's `token_ttl_secs` (at most
    /// one hour, `ci_oidc_service::MAX_TOKEN_TTL_SECS`), and is NOT capped at
    /// the assertion's `exp` (#5054). CI assertions are short-lived by design (GitHub Actions ID
    /// tokens live about five minutes) and only have to be valid when they
    /// are exchanged; tying the session to them cut every GitHub Actions
    /// session to five minutes whatever the operator configured. The
    /// lifetime stays bounded: the hard maximum, no refresh (the refresh JWT
    /// is never returned and `AuthService` refuses to refresh a CI account),
    /// and every re-mint downstream (`/v2/token`, Conan) capped at this
    /// token's own `exp` (#3460/#3625). This token is not accepted as a CI
    /// assertion, so it cannot be exchanged into a later one either.
    Unrestricted { ttl: chrono::Duration },
    /// [`KUBERNETES_SCOPES`] only, no refresh token at all, and the access
    /// token's `exp` capped at the assertion's (#3820).
    ReadOnlyNoRefresh,
}

impl CredentialShape {
    fn for_provider(provider: &CiOidcProvider) -> Self {
        if provider.provider_type == KUBERNETES_PROVIDER_TYPE {
            Self::ReadOnlyNoRefresh
        } else {
            Self::Unrestricted {
                ttl: provider.minted_token_ttl(),
            }
        }
    }

    /// The default-provider shape (900 s), for tests.
    #[cfg(test)]
    fn unrestricted_default() -> Self {
        Self::Unrestricted {
            ttl: chrono::Duration::seconds(i64::from(
                crate::services::ci_oidc_service::DEFAULT_TOKEN_TTL_SECS,
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Provision / sync the CI service account and mint its tokens, with the
/// lifetime `shape` decides: the provider's TTL, or for a Kubernetes exchange
/// the configured TTL capped at `assertion_exp` (#3820, #5054).
///
/// This is `AuthService::authenticate_federated_with_scope` composed from
/// that method's own public parts, so the SSO callers keep their minter
/// untouched while this one picks the lifetime. Either way `assertion_exp`
/// must still have validity left when the token is minted (#4663).
async fn mint_ci_session(
    svc: &CiOidcService,
    auth_service: &AuthService,
    credentials: FederatedCredentials,
    shape: CredentialShape,
    allowed_repo_ids: Option<Vec<Uuid>>,
    bound_mapping_id: Option<Uuid>,
    assertion_exp: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<(User, AccessToken)> {
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

    // Reconcile the account's group memberships to the mapping's binding on
    // EVERY exchange (design D3), not only on mapping write: this is what
    // makes the binding authoritative in practice, self-healing against any
    // membership added by other means. `bound_mapping_id` is `Some` only when
    // the resolved mapping declared a binding; an unbound mapping's account
    // keeps whatever memberships it already holds (design D2), with no query
    // on this path.
    //
    // Fails closed (design D7). The binding is the authorization control
    // itself, not a mirror of an external IdP, so an exchange that cannot
    // enforce it mints nothing: a token issued now would be backed by
    // memberships the mapping may no longer grant. The reconciler reads the
    // binding as stored rather than the copy resolved at the start of this
    // exchange, so a narrowing committed in between is not undone here.
    if let Some(mapping_id) = bound_mapping_id {
        match svc.reconcile_mapping_binding(mapping_id, user.id).await {
            Ok(_) => {}
            Err(AppError::NotFound(_)) => {
                tracing::warn!(
                    target: "security",
                    user_id = %user.id,
                    mapping_id = %mapping_id,
                    "CI OIDC: identity mapping deleted during the exchange; refusing"
                );
                return Err(AppError::Authentication(
                    "The CI identity mapping for this exchange no longer exists".into(),
                ));
            }
            Err(e) => {
                tracing::error!(
                    target: "security",
                    user_id = %user.id,
                    mapping_id = %mapping_id,
                    error = %e,
                    "CI OIDC: failed to reconcile service account's group binding; \
                     refusing the exchange"
                );
                return Err(AppError::ServiceUnavailable(
                    "Could not apply the CI identity mapping's group binding; retry the exchange"
                        .into(),
                ));
            }
        }
    }

    // Display-only field, throttled to at most once per 5 minutes per user
    // (#2107) so a pipeline re-exchanging on every job does not churn WAL.
    sqlx::query(
        "UPDATE users SET last_login_at = NOW() \
         WHERE id = $1 \
           AND (last_login_at IS NULL OR last_login_at < NOW() - INTERVAL '5 minutes')",
    )
    .bind(user.id)
    .execute(auth_service.db())
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // The account sync and binding reconcile above take time; re-check that
    // the assertion still has validity left right before the mint (#4663).
    mintable_expiry(assertion_exp, chrono::Utc::now())?;

    let tokens = match shape {
        // `scopes: None` — a CI exchange mints an action-unrestricted token,
        // as the federated path always has (#2430); the repository allow-list
        // comes from the resolved identity mapping. The lifetime is the
        // provider's, not the assertion's (#5054); see `CredentialShape`.
        CredentialShape::Unrestricted { ttl } => {
            let tokens =
                auth_service.generate_tokens_with_scope_ttl(&user, None, allowed_repo_ids, ttl)?;
            refuse_zero_lifetime(tokens.expires_in)?;
            auth_service
                .persist_refresh_jti_from_pair(&tokens, user.id)
                .await?;
            tokens.into()
        }
        // A deliberate ceiling, fixed by provider type and not configurable,
        // so no misconfiguration can widen it. The kubelet caches this
        // credential on a long-lived node, where anything with root on the
        // host can read it, and a leaked token that could push would let an
        // attacker replace images for every consumer of the registry. So it
        // can pull and nothing else (whatever the account's groups would
        // allow), and it cannot be renewed: no refresh JWT is even signed.
        // The mapping's repository ceiling and the expiry cap still apply.
        //
        // Other provider types still mint action-unrestricted tokens. The
        // general fix, action scopes on a mapping or finer-grained grants
        // alongside the mapping's group binding, is tracked in #4132.
        CredentialShape::ReadOnlyNoRefresh => {
            let token = auth_service.generate_access_token_capped(
                &user,
                Some(KUBERNETES_SCOPES.map(str::to_owned).to_vec()),
                allowed_repo_ids,
                assertion_exp,
            )?;
            refuse_zero_lifetime(token.expires_in)?;
            token
        }
    };
    Ok((user, tokens))
}

/// The assertion has no validity left to mint a session from (#4663).
fn expired_assertion() -> AppError {
    AppError::Authentication(
        "CI token has expired; request a fresh one from the CI platform".into(),
    )
}

/// The presented assertion's `exp`, refusing when less than one whole second
/// of it remains at `now` (#4663). It caps the minted token only for a
/// Kubernetes exchange (#3820, #5054).
///
/// The verifier keeps its clock-skew leeway, so an assertion up to 60 s past
/// `exp` verifies. Minting from one would cap the session at an `exp` that
/// has already passed (`expires_in: 0`), so the exchange is refused instead.
/// One second, not zero, because `expires_in` counts whole seconds.
fn mintable_assertion_expiry(
    claims: &serde_json::Value,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
    mintable_expiry(assertion_expiry(claims), now)
}

/// See [`mintable_assertion_expiry`]. `None` (no usable `exp`) passes: the
/// verifier has already rejected anything actually expired.
fn mintable_expiry(
    exp: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
    match exp {
        Some(exp) if (exp - now).num_seconds() < 1 => Err(expired_assertion()),
        other => Ok(other),
    }
}

/// Never hand out a session with `expires_in: 0` (#4663): the clamp can still
/// land there when the mint runs in the last second of the assertion.
fn refuse_zero_lifetime(expires_in: u64) -> Result<()> {
    if expires_in == 0 {
        return Err(expired_assertion());
    }
    Ok(())
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

/// The `exp` of the presented assertion: checked for remaining validity on
/// every exchange, and the cap on a Kubernetes exchange's token (#3820).
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
    use super::{
        assertion_expiry, exchange_ci_token, expired_assertion, extract_bearer_jwt,
        mintable_assertion_expiry, mintable_expiry, parse_optional_body, refuse_zero_lifetime,
    };
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

    /// #4676: a rejected CI assertion is counted in
    /// `ak_auth_failures_total{surface="ci_oidc"}`; a request that presents no
    /// assertion at all is not. Both are rejected before any DB lookup.
    #[test]
    fn exchange_ci_token_counts_rejected_assertions_4676() {
        use crate::services::metrics_service::capture_counters_async;
        let ((), counted) = capture_counters_async(|| async {
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::header::AUTHORIZATION,
                HeaderValue::from_static("Bearer not-a-jwt"),
            );
            exchange_ci_token(State(lazy_test_state()), headers, Bytes::new())
                .await
                .expect_err("an unreadable assertion must be rejected");
            exchange_ci_token(State(lazy_test_state()), HeaderMap::new(), Bytes::new())
                .await
                .expect_err("a missing assertion must be rejected");
        });
        assert_eq!(
            counted.get(
                "ak_auth_failures_total",
                &[("surface", "ci_oidc"), ("reason", "invalid_token")]
            ),
            1
        );
        assert_eq!(counted.get("ak_auth_failures_total", &[]), 1);
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
    // Assertion expiry (#3820, #4663, #5054)
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

    /// #4663: the verifier accepts an assertion up to 60 s past `exp`; the
    /// exchange must not mint from one with no validity left, so the session
    /// never inherits a second leeway window and never reports
    /// `expires_in: 0`.
    #[test]
    fn mintable_expiry_refuses_an_assertion_with_no_validity_left() {
        let now = chrono::Utc::now();
        let at = |secs: i64| assertion_expiry(&json!({ "exp": now.timestamp() + secs }));
        for (offset, why) in [
            (-59, "inside the verifier leeway, past exp"),
            (-1, "one second past exp"),
            (0, "exp is this second"),
        ] {
            let err = mintable_expiry(at(offset), now).expect_err(why);
            assert_eq!(
                axum::response::IntoResponse::into_response(err).status(),
                axum::http::StatusCode::UNAUTHORIZED,
                "{why}"
            );
        }
        assert_eq!(mintable_expiry(at(120), now).unwrap(), at(120));
        // No usable `exp`: the base TTL stands, as before.
        assert_eq!(mintable_expiry(None, now).unwrap(), None);
        assert_eq!(
            mintable_assertion_expiry(&json!({ "exp": now.timestamp() - 30 }), now)
                .expect_err("expired assertion")
                .to_string(),
            expired_assertion().to_string()
        );

        assert!(refuse_zero_lifetime(0).is_err());
        assert!(refuse_zero_lifetime(1).is_ok());
    }

    /// #5054: a non-Kubernetes exchange mints a token that lives the
    /// provider's TTL, not the assertion's remaining lifetime; a Kubernetes
    /// exchange keeps the #3820 cap; an expired assertion mints nothing
    /// (#4663); and the resulting CI session cannot be refreshed. Drives the
    /// mint site directly: the handler's steps 1-4 need a live OIDC issuer,
    /// step 5 is what decides the lifetime.
    ///
    /// DB-backed; no-ops when no database is configured.
    #[tokio::test]
    async fn test_5054_ci_token_lifetime_comes_from_the_provider() {
        use crate::models::user::AuthProvider;
        use crate::services::auth_service::{AuthService, FederatedCredentials};
        use crate::services::ci_oidc_service::CiOidcService;
        use std::sync::Arc;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let storage_path = std::env::temp_dir()
            .join(format!("ci-auth-ttl-{}", Uuid::new_v4()))
            .to_string_lossy()
            .to_string();
        let state = tdh::build_state(pool.clone(), &storage_path);
        let base_ttl_minutes = state.config.jwt_access_token_expiry_minutes;
        let auth_service = AuthService::new(pool.clone(), Arc::new(state.config.clone()));
        let svc = CiOidcService::new(pool.clone());

        let creds = |tag: &str| FederatedCredentials {
            external_id: format!("ci-5054-{tag}"),
            username: format!("ci_5054_{tag}"),
            email: format!("ci_5054_{tag}@ci.artifact-keeper.internal"),
            display_name: Some("CI TTL probe".to_string()),
            groups: vec!["ci".to_string()],
            required_admin_group: None,
            auto_create_users: true,
        };
        let remaining = |token: &str| {
            let claims = auth_service
                .validate_access_token(token)
                .expect("minted token validates");
            claims.exp - chrono::Utc::now().timestamp()
        };
        let mut users = Vec::new();

        // A GitHub-shaped assertion: about five minutes left. The minted token
        // lives the provider's configured TTL (default 900 s), not five minutes.
        let tag = &Uuid::new_v4().to_string()[..8];
        let github_exp = chrono::Utc::now().timestamp() + 300;
        let (user, tokens) = super::mint_ci_session(
            &svc,
            &auth_service,
            creds(&format!("gh{tag}")),
            super::CredentialShape::unrestricted_default(),
            None,
            None,
            assertion_expiry(&json!({ "exp": github_exp })),
        )
        .await
        .expect("a GitHub-shaped exchange should succeed");
        users.push(user.id);
        let left = remaining(&tokens.access_token);
        assert!(
            (900 - 5..=900).contains(&left),
            "the token must live the provider TTL, not the assertion's 300 s: {left}s"
        );
        let drift = tokens.expires_in as i64 - left;
        assert!(
            (0..=2).contains(&drift),
            "expires_in must report the real lifetime (expires_in={} remaining={left})",
            tokens.expires_in
        );

        // A provider TTL longer than the global access-token TTL wins too:
        // the provider owns the CI lifetime.
        let tag = &Uuid::new_v4().to_string()[..8];
        let hour = chrono::Duration::seconds(3600);
        assert!(
            base_ttl_minutes * 60 < 3600,
            "test needs a base TTL under 1 h"
        );
        let (user, tokens) = super::mint_ci_session(
            &svc,
            &auth_service,
            creds(&format!("hr{tag}")),
            super::CredentialShape::Unrestricted { ttl: hour },
            None,
            None,
            assertion_expiry(&json!({ "exp": github_exp })),
        )
        .await
        .expect("exchange should succeed");
        users.push(user.id);
        let left = remaining(&tokens.access_token);
        assert!((3600 - 5..=3600).contains(&left), "{left}s");

        // The session cannot be refreshed: a refresh JWT for a CI account,
        // were one ever exposed, is refused on both refresh paths.
        let pair = auth_service
            .generate_tokens_with_scope_ttl(&user, None, None, hour)
            .expect("mint pair");
        auth_service
            .persist_refresh_jti_from_pair(&pair, user.id)
            .await
            .expect("persist jti");
        assert_eq!(user.auth_provider, AuthProvider::Ci);
        let err = auth_service
            .refresh_tokens(&pair.refresh_token)
            .await
            .expect_err("a CI session must not be refreshable");
        assert!(
            matches!(err, crate::error::AppError::Authentication(_)),
            "{err}"
        );

        // Kubernetes keeps the #3820 cap: the token expires with the
        // ServiceAccount token that bought it, to the second.
        let tag = &Uuid::new_v4().to_string()[..8];
        let soon = chrono::Utc::now().timestamp() + 300;
        let (user, token) = super::mint_ci_session(
            &svc,
            &auth_service,
            creds(&format!("k8s{tag}")),
            super::CredentialShape::ReadOnlyNoRefresh,
            None,
            None,
            assertion_expiry(&json!({ "exp": soon })),
        )
        .await
        .expect("kubernetes exchange should succeed");
        users.push(user.id);
        let claims = auth_service
            .validate_access_token(&token.access_token)
            .expect("minted token validates");
        assert_eq!(
            claims.exp, soon,
            "a Kubernetes token must expire exactly with its ServiceAccount token"
        );

        // #4663: an assertion past its `exp` (the verifier accepted it inside
        // its leeway) mints nothing on either shape.
        let past = chrono::Utc::now().timestamp() - 30;
        for shape in [
            super::CredentialShape::unrestricted_default(),
            super::CredentialShape::ReadOnlyNoRefresh,
        ] {
            let tag = &Uuid::new_v4().to_string()[..8];
            let err = super::mint_ci_session(
                &svc,
                &auth_service,
                creds(&format!("past{tag}")),
                shape,
                None,
                None,
                assertion_expiry(&json!({ "exp": past })),
            )
            .await
            .expect_err("an expired assertion must not mint a session");
            assert!(
                matches!(err, crate::error::AppError::Authentication(_)),
                "{err}"
            );
            let past_user: Option<Uuid> =
                sqlx::query_scalar("SELECT id FROM users WHERE username = $1")
                    .bind(format!("ci_5054_past{tag}"))
                    .fetch_optional(&pool)
                    .await
                    .expect("lookup past user");
            users.extend(past_user);
        }

        for user_id in users {
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

    /// #5054: the provider TTL is clamped to 60..=3600 s at mint time, and
    /// only a Kubernetes provider keeps the assertion cap.
    #[test]
    fn credential_shape_takes_the_clamped_provider_ttl() {
        use crate::services::ci_oidc_service::{
            CiOidcProvider, KEY_SOURCE_DISCOVERY, MAX_TOKEN_TTL_SECS, MIN_TOKEN_TTL_SECS,
        };
        let provider = |provider_type: &str, token_ttl_secs: i32| CiOidcProvider {
            id: Uuid::new_v4(),
            name: "p".into(),
            provider_type: provider_type.into(),
            issuer_url: "https://token.actions.githubusercontent.com".into(),
            audience: "artifact-keeper".into(),
            is_enabled: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            key_source: KEY_SOURCE_DISCOVERY.into(),
            static_jwks: None,
            token_ttl_secs,
        };
        let ttl = |secs: i64| super::CredentialShape::Unrestricted {
            ttl: chrono::Duration::seconds(secs),
        };
        use super::CredentialShape as S;
        assert_eq!(S::for_provider(&provider("github", 900)), ttl(900));
        assert_eq!(S::for_provider(&provider("gitlab", 1800)), ttl(1800));
        assert_eq!(
            S::for_provider(&provider("github", 86_400)),
            ttl(MAX_TOKEN_TTL_SECS.into()),
            "a TTL above the hard maximum is clamped to it"
        );
        assert_eq!(
            S::for_provider(&provider("generic", 1)),
            ttl(MIN_TOKEN_TTL_SECS.into())
        );
        assert_eq!(
            S::for_provider(&provider("kubernetes", 3600)),
            S::ReadOnlyNoRefresh
        );
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
        use super::super::{exchange_validated_claims, mint_ci_session, CredentialShape};
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
                        token_ttl_secs: None,
                        name: format!("gitlab-{}", Uuid::new_v4()),
                        provider_type: Some("gitlab".into()),
                        issuer_url: "https://gitlab.example.com".into(),
                        audience: None,
                        is_enabled: Some(true),
                        key_source: None,
                        static_jwks: None,
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
                            group_binding_ids: None,
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
            let err = mint_ci_session(
                &fx.svc,
                &auth_service,
                credentials,
                CredentialShape::unrestricted_default(),
                None,
                None,
                None,
            )
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

    // -----------------------------------------------------------------------
    // Group bindings confer access (add-ci-oidc-mapping-grants)
    //
    // `allowed_repo_ids` reads like a grant but is only ever a ceiling
    // intersected with RBAC; a CI account starts with no RBAC of its own.
    // These drive the full exchange (`exchange_validated_claims`, which now
    // also reconciles the account's group memberships) and then ask the same
    // `RepositoryService::user_can_access_repo` predicate the REST/OCI
    // content paths ask, so "the exchange granted access" and "the request
    // succeeds" cannot drift apart.
    // -----------------------------------------------------------------------

    mod group_bindings {
        use super::super::{exchange_validated_claims, mint_ci_session, CredentialShape};
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::api::SharedState;
        use crate::models::access_scope::AccessScope;
        use crate::services::auth_service::{AccessToken, AuthService};
        use crate::services::ci_oidc_service::{
            CiOidcService, CreateCiOidcMappingRequest, CreateCiOidcProviderRequest,
            UpdateCiOidcMappingRequest,
        };
        use crate::services::repository_service::{RepoAccess, RepositoryService};
        use serde_json::json;
        use sqlx::PgPool;
        use std::sync::Arc;
        use uuid::Uuid;

        struct Fixture {
            pool: PgPool,
            state: SharedState,
            svc: CiOidcService,
            provider_id: Uuid,
            repos: Vec<(Uuid, std::path::PathBuf)>,
            groups: Vec<Uuid>,
        }

        impl Fixture {
            async fn new() -> Option<Self> {
                Self::with_provider_type("gitlab").await
            }

            async fn with_provider_type(provider_type: &str) -> Option<Self> {
                let pool = tdh::try_pool().await?;
                let storage_path = std::env::temp_dir()
                    .join(format!("ci-auth-grants-{}", Uuid::new_v4()))
                    .to_string_lossy()
                    .to_string();
                let state = tdh::build_state(pool.clone(), &storage_path);
                let svc = CiOidcService::new(pool.clone());
                let provider = svc
                    .create(CreateCiOidcProviderRequest {
                        token_ttl_secs: None,
                        name: format!("{provider_type}-{}", Uuid::new_v4()),
                        provider_type: Some(provider_type.into()),
                        issuer_url: "https://gitlab.example.com".into(),
                        audience: None,
                        is_enabled: Some(true),
                        key_source: None,
                        static_jwks: None,
                    })
                    .await
                    .expect("create provider");
                Some(Self {
                    pool,
                    state,
                    svc,
                    provider_id: provider.id,
                    repos: Vec::new(),
                    groups: Vec::new(),
                })
            }

            async fn repo(&mut self) -> Uuid {
                let (id, _key, dir) = tdh::create_repo(&self.pool, "local", "generic").await;
                self.repos.push((id, dir));
                id
            }

            /// A group granting `actions` on `repo_id`.
            async fn group_granting(&mut self, repo_id: Uuid, actions: &[&str]) -> Uuid {
                let (group_id, _name) = tdh::create_group(&self.pool).await;
                tdh::grant_permission(
                    &self.pool,
                    "group",
                    group_id,
                    "repository",
                    repo_id,
                    actions,
                )
                .await;
                self.groups.push(group_id);
                group_id
            }

            async fn mapping(
                &self,
                claim_filters: serde_json::Value,
                allowed_repo_ids: Option<Vec<Uuid>>,
                group_binding_ids: Option<Vec<Uuid>>,
            ) -> (Uuid, Uuid) {
                let created = self
                    .svc
                    .create_mapping(
                        self.provider_id,
                        CreateCiOidcMappingRequest {
                            name: "deploy".into(),
                            priority: None,
                            claim_filters,
                            allowed_repo_ids,
                            is_enabled: None,
                            group_binding_ids,
                        },
                    )
                    .await
                    .expect("create mapping");
                (created.id, created.service_account_id.expect("account"))
            }

            async fn set_binding(&self, mapping_id: Uuid, group_binding_ids: Option<Vec<Uuid>>) {
                self.svc
                    .update_mapping(
                        self.provider_id,
                        mapping_id,
                        UpdateCiOidcMappingRequest {
                            name: None,
                            priority: None,
                            claim_filters: None,
                            allowed_repo_ids: None,
                            is_enabled: None,
                            group_binding_ids: Some(group_binding_ids),
                        },
                    )
                    .await
                    .expect("set binding");
            }

            async fn set_enabled(&self, mapping_id: Uuid, enabled: bool) {
                self.svc
                    .toggle_mapping(self.provider_id, mapping_id, enabled)
                    .await
                    .expect("toggle mapping");
            }

            async fn exchange(
                &self,
                claims: serde_json::Value,
            ) -> crate::error::Result<(crate::models::user::User, AccessToken)> {
                let provider = self.svc.get(self.provider_id).await?;
                exchange_validated_claims(&self.state, &self.svc, &provider, &claims).await
            }

            /// What the issued credential can actually do: the SAME two
            /// gates production checks (`require_repo_write_access`), not
            /// just the RBAC half. `allowed_repo_ids` is a ceiling baked into
            /// the access token's claims at mint time (`mint_ci_session` ->
            /// `generate_tokens_with_scope_capped`) and never re-derived; the
            /// binding's group grant is the floor, re-evaluated live against
            /// `user_group_members`/`permissions` on every call
            /// (`RepositoryService::user_can_access_repo`), same as any other
            /// principal. Checking only the floor — as an earlier version of
            /// this harness did — cannot observe the ceiling excluding a
            /// repository the binding reaches, which is exactly the
            /// "narrows and never widens" property tasks 5.1-5.3 exist to
            /// pin.
            async fn can(&self, tokens: &AccessToken, repo_id: Uuid, access: RepoAccess) -> bool {
                let auth_service =
                    AuthService::new(self.pool.clone(), Arc::new(self.state.config.clone()));
                let claims = auth_service
                    .validate_access_token(&tokens.access_token)
                    .expect("valid access token");
                let ceiling = AccessScope::from(claims.allowed_repo_ids);
                if !ceiling.grants(repo_id) {
                    return false;
                }
                RepositoryService::new(self.pool.clone())
                    .user_can_access_repo(repo_id, claims.sub, access)
                    // `access` is the RepoAccess::READ / RepoAccess::Action(_) the
                    // CALLER of `can(...)` names at each call site in this module
                    // (#3331's structural gate scans for a `RepoAccess::` literal
                    // near every `.user_can_access_repo(` call; this helper never
                    // defaults or infers one, and no caller here asks the
                    // action-blind tenant-only question).
                    .await
                    .expect("permission query")
            }

            async fn cleanup(self) {
                let accounts: Vec<Uuid> = sqlx::query_scalar(
                    "SELECT id FROM users WHERE auth_provider = 'ci' AND external_id LIKE $1",
                )
                .bind(format!("ci:{}:%", self.provider_id))
                .fetch_all(&self.pool)
                .await
                .unwrap_or_default();
                for sql in [
                    "DELETE FROM refresh_token_jti WHERE user_id = ANY($1)",
                    "DELETE FROM user_roles WHERE user_id = ANY($1)",
                    "DELETE FROM user_group_members WHERE user_id = ANY($1)",
                    "DELETE FROM users WHERE id = ANY($1)",
                ] {
                    let _ = sqlx::query(sql).bind(&accounts).execute(&self.pool).await;
                }
                for (repo_id, _) in &self.repos {
                    let _ = sqlx::query(
                        "DELETE FROM permissions WHERE target_type = 'repository' AND target_id = $1",
                    )
                    .bind(repo_id)
                    .execute(&self.pool)
                    .await;
                    let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
                        .bind(repo_id)
                        .execute(&self.pool)
                        .await;
                }
                for (_, dir) in &self.repos {
                    let _ = std::fs::remove_dir_all(dir);
                }
                let _ = sqlx::query("DELETE FROM groups WHERE id = ANY($1)")
                    .bind(&self.groups)
                    .execute(&self.pool)
                    .await;
                let _ = sqlx::query("DELETE FROM ci_oidc_providers WHERE id = $1")
                    .bind(self.provider_id)
                    .execute(&self.pool)
                    .await;
            }
        }

        fn gitlab(project: &str, git_ref: &str) -> serde_json::Value {
            json!({
                "sub": format!("project_path:{project}:ref_type:branch:ref:{git_ref}"),
                "project_path": project,
                "ref_type": "branch",
                "ref": git_ref,
            })
        }

        /// 1.3 (characterization) — pinned so the ceiling's own semantics
        /// cannot silently drift: naming a repository in `allowed_repo_ids`
        /// grants nothing by itself. An account with no binding and no other
        /// grant is refused on every repository the mapping names.
        #[tokio::test]
        async fn ceiling_alone_grants_nothing_without_a_binding() {
            let Some(mut fx) = Fixture::new().await else {
                return;
            };
            let repo_id = fx.repo().await;
            let (_mapping_id, _account) = fx
                .mapping(
                    json!({"project_path": "group/app"}),
                    Some(vec![repo_id]),
                    None,
                )
                .await;

            let (_user, tokens) = fx.exchange(gitlab("group/app", "main")).await.unwrap();
            assert!(
                !fx.can(&tokens, repo_id, RepoAccess::READ).await,
                "the ceiling names the repo, but nothing granted access to it"
            );
            fx.cleanup().await;
        }

        /// Spec "A bound pipeline can act without any separate grant": a
        /// mapping's binding alone is sufficient — no group membership,
        /// role, or permission was configured outside the mapping.
        #[tokio::test]
        async fn bound_pipeline_can_act_without_any_separate_grant() {
            let Some(mut fx) = Fixture::new().await else {
                return;
            };
            let repo_id = fx.repo().await;
            let group_id = fx.group_granting(repo_id, &["read", "write"]).await;
            let (_mapping_id, _account) = fx
                .mapping(
                    json!({"project_path": "group/app"}),
                    None,
                    Some(vec![group_id]),
                )
                .await;

            let (_user, tokens) = fx.exchange(gitlab("group/app", "main")).await.unwrap();
            assert!(fx.can(&tokens, repo_id, RepoAccess::READ).await);
            assert!(fx.can(&tokens, repo_id, RepoAccess::Action("write")).await);
            fx.cleanup().await;
        }

        /// Spec "An unbound mapping confers nothing": declaring an EMPTY
        /// binding (not absent — declared "no memberships") grants nothing.
        #[tokio::test]
        async fn declared_empty_binding_confers_nothing() {
            let Some(mut fx) = Fixture::new().await else {
                return;
            };
            let repo_id = fx.repo().await;
            let group_id = fx.group_granting(repo_id, &["read"]).await;
            // A group exists and grants access, but the binding names none.
            let (_mapping_id, _account) = fx
                .mapping(json!({"project_path": "group/app"}), None, Some(vec![]))
                .await;
            let _ = group_id;

            let (_user, tokens) = fx.exchange(gitlab("group/app", "main")).await.unwrap();
            assert!(!fx.can(&tokens, repo_id, RepoAccess::READ).await);
            fx.cleanup().await;
        }

        /// Spec "A binding confers no more than its groups do": a read-only
        /// group does not also confer write.
        #[tokio::test]
        async fn binding_confers_no_more_than_its_groups_do() {
            let Some(mut fx) = Fixture::new().await else {
                return;
            };
            let repo_id = fx.repo().await;
            let group_id = fx.group_granting(repo_id, &["read"]).await;
            let (_mapping_id, _account) = fx
                .mapping(
                    json!({"project_path": "group/app"}),
                    None,
                    Some(vec![group_id]),
                )
                .await;

            let (_user, tokens) = fx.exchange(gitlab("group/app", "main")).await.unwrap();
            assert!(fx.can(&tokens, repo_id, RepoAccess::READ).await);
            assert!(!fx.can(&tokens, repo_id, RepoAccess::Action("write")).await);
            fx.cleanup().await;
        }

        /// Spec "Removing a group from the binding revokes it" / "Adding a
        /// group to the binding grants it": reconciliation runs again on the
        /// very next exchange, with no separate action required.
        #[tokio::test]
        async fn narrowing_or_widening_the_binding_takes_effect_on_the_next_exchange() {
            let Some(mut fx) = Fixture::new().await else {
                return;
            };
            let repo_id = fx.repo().await;
            let group_id = fx.group_granting(repo_id, &["read"]).await;
            let (mapping_id, _account) = fx
                .mapping(
                    json!({"project_path": "group/app"}),
                    None,
                    Some(vec![group_id]),
                )
                .await;

            let (first, first_tokens) = fx.exchange(gitlab("group/app", "main")).await.unwrap();
            assert!(fx.can(&first_tokens, repo_id, RepoAccess::READ).await);

            // Narrow: the binding no longer names any group.
            fx.set_binding(mapping_id, Some(vec![])).await;
            let (second, second_tokens) = fx.exchange(gitlab("group/app", "main")).await.unwrap();
            assert_eq!(second.id, first.id, "same principal throughout");
            assert!(
                !fx.can(&second_tokens, repo_id, RepoAccess::READ).await,
                "narrowing the binding must revoke by the next exchange"
            );

            // Widen again.
            fx.set_binding(mapping_id, Some(vec![group_id])).await;
            let (_third, third_tokens) = fx.exchange(gitlab("group/app", "main")).await.unwrap();
            assert!(fx.can(&third_tokens, repo_id, RepoAccess::READ).await);
            fx.cleanup().await;
        }

        /// Spec "A narrowed binding applies to a credential already issued"
        /// (design D3, corrected): the floor a binding confers is never
        /// carried on the token, so it is not the credential's expiry that
        /// bounds a narrowing — a mapping WRITE alone reconciles the
        /// account's memberships immediately, and every access check
        /// re-derives the floor live from `user_id`. A credential minted
        /// before the write, used with no new exchange, must see the
        /// narrower access on its very next request. (The ceiling,
        /// `allowed_repo_ids`, is the one thing that genuinely IS baked into
        /// the token at mint time and so is unaffected by this test — this
        /// mapping leaves it unset so only the floor is under test.)
        #[tokio::test]
        async fn narrowing_a_binding_at_write_time_narrows_an_already_issued_credential() {
            let Some(mut fx) = Fixture::new().await else {
                return;
            };
            let repo_id = fx.repo().await;
            let group_id = fx.group_granting(repo_id, &["read"]).await;
            let (mapping_id, _account) = fx
                .mapping(
                    json!({"project_path": "group/app"}),
                    None,
                    Some(vec![group_id]),
                )
                .await;

            let (_user, tokens) = fx.exchange(gitlab("group/app", "main")).await.unwrap();
            assert!(
                fx.can(&tokens, repo_id, RepoAccess::READ).await,
                "the credential holds the group's access right after mint"
            );

            // Narrow via a mapping WRITE only — no second exchange.
            fx.set_binding(mapping_id, Some(vec![])).await;

            assert!(
                !fx.can(&tokens, repo_id, RepoAccess::READ).await,
                "the SAME already-issued credential must lose the removed \
                 group's access on its next request, without being \
                 re-exchanged: the floor is checked live, not cached on the \
                 token, so a write-time reconciliation reaches every \
                 outstanding credential for the account immediately"
            );
            fx.cleanup().await;
        }

        /// Spec "A membership added outside the mapping does not survive":
        /// a binding is authoritative over its account's ENTIRE membership
        /// set, not merely additive.
        #[tokio::test]
        async fn membership_added_outside_the_mapping_does_not_survive_exchange() {
            let Some(mut fx) = Fixture::new().await else {
                return;
            };
            let repo_id = fx.repo().await;
            let bound_group = fx.group_granting(repo_id, &["read"]).await;
            let other_repo = fx.repo().await;
            let other_group = fx.group_granting(other_repo, &["read"]).await;
            let (_mapping_id, account_id) = fx
                .mapping(
                    json!({"project_path": "group/app"}),
                    None,
                    Some(vec![bound_group]),
                )
                .await;

            // Hand-wire a membership the mapping never declared.
            sqlx::query("INSERT INTO user_group_members (user_id, group_id) VALUES ($1, $2)")
                .bind(account_id)
                .bind(other_group)
                .execute(&fx.pool)
                .await
                .unwrap();

            let (user, tokens) = fx.exchange(gitlab("group/app", "main")).await.unwrap();
            assert_eq!(user.id, account_id);
            assert!(fx.can(&tokens, repo_id, RepoAccess::READ).await);
            assert!(
                !fx.can(&tokens, other_repo, RepoAccess::READ).await,
                "the hand-wired membership must not survive a reconciling exchange"
            );
            fx.cleanup().await;
        }

        /// Spec "An unbound mapping leaves existing memberships alone": with
        /// NO binding declared at all (absent, not empty), reconciliation
        /// never runs and a hand-wired membership survives.
        #[tokio::test]
        async fn unbound_mapping_leaves_existing_memberships_alone() {
            let Some(mut fx) = Fixture::new().await else {
                return;
            };
            let repo_id = fx.repo().await;
            let group_id = fx.group_granting(repo_id, &["read"]).await;
            let (_mapping_id, account_id) = fx
                .mapping(json!({"project_path": "group/app"}), None, None)
                .await;

            sqlx::query("INSERT INTO user_group_members (user_id, group_id) VALUES ($1, $2)")
                .bind(account_id)
                .bind(group_id)
                .execute(&fx.pool)
                .await
                .unwrap();

            let (_user, tokens) = fx.exchange(gitlab("group/app", "main")).await.unwrap();
            assert!(
                fx.can(&tokens, repo_id, RepoAccess::READ).await,
                "an absent binding must not reconcile away a hand-wired membership"
            );
            fx.cleanup().await;
        }

        /// Spec "The ceiling excludes a repository the binding grants": the
        /// binding reaches a repository the ceiling does not name, so the
        /// ceiling still refuses it — defence in depth, never widened.
        #[tokio::test]
        async fn ceiling_excludes_a_repository_the_binding_grants() {
            let Some(mut fx) = Fixture::new().await else {
                return;
            };
            let allowed_repo = fx.repo().await;
            let excluded_repo = fx.repo().await;
            let group_id = fx.group_granting(allowed_repo, &["read"]).await;
            // Same group also grants the excluded repo, so only the CEILING
            // stands between the binding and it.
            tdh::grant_permission(
                &fx.pool,
                "group",
                group_id,
                "repository",
                excluded_repo,
                &["read"],
            )
            .await;
            let (_mapping_id, _account) = fx
                .mapping(
                    json!({"project_path": "group/app"}),
                    Some(vec![allowed_repo]),
                    Some(vec![group_id]),
                )
                .await;

            let (_user, tokens) = fx.exchange(gitlab("group/app", "main")).await.unwrap();
            assert!(fx.can(&tokens, allowed_repo, RepoAccess::READ).await);
            assert!(
                !fx.can(&tokens, excluded_repo, RepoAccess::READ).await,
                "the repo ceiling must still exclude a repo the binding reaches"
            );
            fx.cleanup().await;
        }

        /// Spec "An unrestricted mapping is bounded by its binding alone":
        /// with no `allowed_repo_ids` ceiling at all, reach is exactly what
        /// the binding confers — not everything.
        #[tokio::test]
        async fn unrestricted_mapping_is_bounded_by_its_binding_alone() {
            let Some(mut fx) = Fixture::new().await else {
                return;
            };
            let in_binding = fx.repo().await;
            let outside_binding = fx.repo().await;
            let group_id = fx.group_granting(in_binding, &["read"]).await;
            let (_mapping_id, _account) = fx
                .mapping(
                    json!({"project_path": "group/app"}),
                    None,
                    Some(vec![group_id]),
                )
                .await;

            let (_user, tokens) = fx.exchange(gitlab("group/app", "main")).await.unwrap();
            assert!(fx.can(&tokens, in_binding, RepoAccess::READ).await);
            assert!(!fx.can(&tokens, outside_binding, RepoAccess::READ).await);
            fx.cleanup().await;
        }

        /// Spec "Disabling a mapping stops its binding taking effect": a
        /// disabled mapping cannot be matched at all, so no credential is
        /// issued under it afterwards — its binding confers nothing further.
        #[tokio::test]
        async fn disabling_a_mapping_stops_its_binding_conferring_further_access() {
            let Some(mut fx) = Fixture::new().await else {
                return;
            };
            let repo_id = fx.repo().await;
            let group_id = fx.group_granting(repo_id, &["read"]).await;
            let (mapping_id, account_id) = fx
                .mapping(
                    json!({"project_path": "group/app"}),
                    None,
                    Some(vec![group_id]),
                )
                .await;
            let (_first, first_tokens) = fx.exchange(gitlab("group/app", "main")).await.unwrap();
            assert!(fx.can(&first_tokens, repo_id, RepoAccess::READ).await);

            fx.set_enabled(mapping_id, false).await;
            let err = fx
                .exchange(gitlab("group/app", "main"))
                .await
                .expect_err("a disabled mapping must not match");
            assert!(matches!(err, crate::error::AppError::Authentication(_)));
            // The account's last-reconciled membership is untouched by
            // disabling (no exchange ran to reconcile it away), so whether
            // it "confers further access" is answered by "no credential is
            // issued", which this refusal demonstrates.
            let _ = account_id;
            fx.cleanup().await;
        }

        /// Spec "Deleting a mapping withdraws its conferral": the account is
        /// deactivated (fix-ci-oidc-identity-key), so it can no longer
        /// authenticate at all, which is strictly stronger than "no longer
        /// conferred access by this mapping".
        #[tokio::test]
        async fn deleting_a_mapping_withdraws_its_conferral() {
            let Some(mut fx) = Fixture::new().await else {
                return;
            };
            let repo_id = fx.repo().await;
            let group_id = fx.group_granting(repo_id, &["read"]).await;
            let (mapping_id, account_id) = fx
                .mapping(
                    json!({"project_path": "group/app"}),
                    None,
                    Some(vec![group_id]),
                )
                .await;
            let (_first, first_tokens) = fx.exchange(gitlab("group/app", "main")).await.unwrap();
            assert!(fx.can(&first_tokens, repo_id, RepoAccess::READ).await);

            fx.svc
                .delete_mapping(fx.provider_id, mapping_id)
                .await
                .expect("delete mapping");

            let active: bool = sqlx::query_scalar("SELECT is_active FROM users WHERE id = $1")
                .bind(account_id)
                .fetch_one(&fx.pool)
                .await
                .unwrap();
            assert!(!active, "the account is deactivated, not deleted");

            let err = fx
                .exchange(gitlab("group/app", "main"))
                .await
                .expect_err("a deleted mapping must not match");
            assert!(matches!(err, crate::error::AppError::Authentication(_)));
            fx.cleanup().await;
        }

        /// Resolve `claims` to its mapping and credentials exactly as an
        /// exchange does, stopping short of the mint, so a test can mint
        /// through a service of its choosing or with a stale mapping.
        async fn resolved(
            fx: &Fixture,
            claims: &serde_json::Value,
        ) -> (
            crate::services::ci_oidc_service::CiOidcIdentityMapping,
            crate::services::auth_service::FederatedCredentials,
        ) {
            let provider = fx.svc.get(fx.provider_id).await.unwrap();
            let mapping = fx
                .svc
                .resolve_mapping(fx.provider_id, claims)
                .await
                .unwrap();
            let credentials = fx
                .svc
                .resolve_service_account(
                    &mapping,
                    CiOidcService::extract_identity_from_mapping(&provider, &mapping, claims),
                )
                .await
                .unwrap();
            (mapping, credentials)
        }

        /// A service whose every query fails: nothing listens on port 1.
        fn broken_svc() -> CiOidcService {
            let unreachable = sqlx::postgres::PgPoolOptions::new()
                .acquire_timeout(std::time::Duration::from_millis(200))
                .connect_lazy("postgresql://nobody:nobody@127.0.0.1:1/none")
                .expect("lazy pool");
            CiOidcService::new(unreachable)
        }

        // -------------------------------------------------------------------
        // Kubernetes provider type (add-ci-oidc-kubernetes-provider D4, D5)
        // -------------------------------------------------------------------

        /// A kubelet-issued ServiceAccount token's verified claims; `pod`
        /// `None` models a token not bound to a pod.
        fn k8s(namespace: &str, sa: &str, pod: Option<&str>) -> serde_json::Value {
            let mut claims = json!({
                "sub": format!("system:serviceaccount:{namespace}:{sa}"),
                "exp": chrono::Utc::now().timestamp() + 600,
                "kubernetes.io": {
                    "namespace": namespace,
                    "serviceaccount": {"name": sa},
                    "node": {"name": "node-3"},
                },
            });
            if let Some(pod) = pod {
                claims["kubernetes.io"]["pod"] = json!({ "name": pod });
            }
            claims
        }

        async fn refresh_jtis(pool: &PgPool, user_id: Uuid) -> i64 {
            sqlx::query_scalar("SELECT COUNT(*) FROM refresh_token_jti WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(pool)
                .await
                .unwrap()
        }

        /// Design D7, spec "An exchange that cannot reconcile issues
        /// nothing": the binding is the authorization control, so a bound
        /// mapping whose reconcile fails refuses the exchange with a
        /// retryable 503 and mints no access or refresh token.
        #[tokio::test]
        async fn a_failed_reconcile_refuses_the_exchange() {
            let Some(mut fx) = Fixture::new().await else {
                return;
            };
            let repo_id = fx.repo().await;
            let group_id = fx.group_granting(repo_id, &["read"]).await;
            let (mapping_id, account_id) = fx
                .mapping(
                    json!({"project_path": "group/app"}),
                    None,
                    Some(vec![group_id]),
                )
                .await;
            let (_mapping, credentials) = resolved(&fx, &gitlab("group/app", "main")).await;
            let auth_service = AuthService::new(fx.pool.clone(), Arc::new(fx.state.config.clone()));

            let err = mint_ci_session(
                &broken_svc(),
                &auth_service,
                credentials,
                CredentialShape::unrestricted_default(),
                None,
                Some(mapping_id),
                None,
            )
            .await
            .expect_err("a bound exchange whose reconcile fails must mint nothing");

            assert!(
                matches!(err, crate::error::AppError::ServiceUnavailable(_)),
                "got: {err}"
            );
            assert_eq!(refresh_jtis(&fx.pool, account_id).await, 0);
            fx.cleanup().await;
        }

        /// Spec "An unbound mapping is unaffected by reconciliation
        /// failures": with no binding there is nothing to enforce, so no
        /// reconcile is attempted and the exchange succeeds even where one
        /// would have failed.
        #[tokio::test]
        async fn an_unbound_exchange_never_fails_on_reconcile() {
            let Some(fx) = Fixture::new().await else {
                return;
            };
            let (_mapping_id, account_id) = fx
                .mapping(json!({"project_path": "group/app"}), None, None)
                .await;
            let (mapping, credentials) = resolved(&fx, &gitlab("group/app", "main")).await;
            let auth_service = AuthService::new(fx.pool.clone(), Arc::new(fx.state.config.clone()));

            let (user, _tokens) = mint_ci_session(
                &broken_svc(),
                &auth_service,
                credentials,
                CredentialShape::unrestricted_default(),
                None,
                mapping.group_binding_ids.is_some().then_some(mapping.id),
                None,
            )
            .await
            .expect("an unbound exchange does not touch the reconciler");

            assert_eq!(user.id, account_id);
            fx.cleanup().await;
        }

        /// Design D7, spec "An exchange in flight cannot undo a narrowing":
        /// an exchange resolves the mapping while it binds {a, b}; an
        /// operator narrows it to {b} before that exchange reconciles. The
        /// exchange then reconciles to what is stored, so `a` stays revoked.
        #[tokio::test]
        async fn an_exchange_in_flight_cannot_undo_a_narrowing() {
            let Some(mut fx) = Fixture::new().await else {
                return;
            };
            let repo_a = fx.repo().await;
            let repo_b = fx.repo().await;
            let group_a = fx.group_granting(repo_a, &["read"]).await;
            let group_b = fx.group_granting(repo_b, &["read"]).await;
            let (mapping_id, _account) = fx
                .mapping(
                    json!({"project_path": "group/app"}),
                    None,
                    Some(vec![group_a, group_b]),
                )
                .await;
            let (stale, credentials) = resolved(&fx, &gitlab("group/app", "main")).await;
            assert_eq!(stale.group_binding_ids.as_ref().map(Vec::len), Some(2));

            fx.set_binding(mapping_id, Some(vec![group_b])).await;

            let auth_service = AuthService::new(fx.pool.clone(), Arc::new(fx.state.config.clone()));
            let (_user, tokens) = mint_ci_session(
                &fx.svc,
                &auth_service,
                credentials,
                CredentialShape::unrestricted_default(),
                stale.allowed_repo_ids.clone(),
                stale.group_binding_ids.is_some().then_some(stale.id),
                None,
            )
            .await
            .expect("the exchange succeeds");

            assert!(
                !fx.can(&tokens, repo_a, RepoAccess::READ).await,
                "the exchange must not restore the group the narrowing removed"
            );
            assert!(fx.can(&tokens, repo_b, RepoAccess::READ).await);
            fx.cleanup().await;
        }

        /// Spec "Deleting a mapping withdraws its conferral", mid-exchange:
        /// a mapping deleted after the exchange resolved it refuses as an
        /// authentication failure rather than minting.
        #[tokio::test]
        async fn a_mapping_deleted_mid_exchange_refuses() {
            let Some(mut fx) = Fixture::new().await else {
                return;
            };
            let repo_id = fx.repo().await;
            let group_id = fx.group_granting(repo_id, &["read"]).await;
            let (mapping_id, account_id) = fx
                .mapping(
                    json!({"project_path": "group/app"}),
                    None,
                    Some(vec![group_id]),
                )
                .await;
            let (_mapping, credentials) = resolved(&fx, &gitlab("group/app", "main")).await;
            // Remove only the mapping row: the account stays active, so the
            // refusal can only come from the reconcile finding no mapping.
            sqlx::query("DELETE FROM ci_oidc_identity_mappings WHERE id = $1")
                .bind(mapping_id)
                .execute(&fx.pool)
                .await
                .unwrap();

            let auth_service = AuthService::new(fx.pool.clone(), Arc::new(fx.state.config.clone()));
            let err = mint_ci_session(
                &fx.svc,
                &auth_service,
                credentials,
                CredentialShape::unrestricted_default(),
                None,
                Some(mapping_id),
                None,
            )
            .await
            .expect_err("a deleted mapping must not mint");

            assert!(
                matches!(err, crate::error::AppError::Authentication(_)),
                "got: {err}"
            );
            assert_eq!(refresh_jtis(&fx.pool, account_id).await, 0);
            fx.cleanup().await;
        }

        fn access_claims(
            fx: &Fixture,
            tokens: &AccessToken,
        ) -> crate::services::auth_service::Claims {
            AuthService::new(fx.pool.clone(), Arc::new(fx.state.config.clone()))
                .validate_access_token(&tokens.access_token)
                .expect("valid access token")
        }

        /// 4.2 — a Kubernetes exchange mints exactly the two read scopes,
        /// whatever the bound group grants, persists no refresh token, and
        /// still honours the expiry cap. The namespace-pointer mapping is
        /// what matched it.
        #[tokio::test]
        async fn kubernetes_exchange_is_read_only_and_not_renewable() {
            let Some(mut fx) = Fixture::with_provider_type("kubernetes").await else {
                return;
            };
            let repo_id = fx.repo().await;
            let group_id = fx.group_granting(repo_id, &["read", "write"]).await;
            fx.mapping(
                json!({"/kubernetes.io/namespace": "payments"}),
                None,
                Some(vec![group_id]),
            )
            .await;

            let assertion = k8s("payments", "api", Some("api-7d9f"));
            let (user, tokens) = fx.exchange(assertion.clone()).await.unwrap();
            let claims = access_claims(&fx, &tokens);
            assert_eq!(
                claims.scopes,
                Some(vec![
                    "read:artifacts".to_string(),
                    "read:repositories".to_string()
                ]),
                "exactly the two read scopes, although the group grants write"
            );
            assert!(claims.exp <= assertion["exp"].as_i64().unwrap());
            assert_eq!(refresh_jtis(&fx.pool, user.id).await, 0, "no refresh row");

            // A second exchange of the same workload still writes none.
            fx.exchange(assertion).await.unwrap();
            assert_eq!(refresh_jtis(&fx.pool, user.id).await, 0);

            let err = fx
                .exchange(k8s("payments-sandbox", "api", Some("api-1")))
                .await
                .expect_err("the namespace filter is exact");
            assert!(matches!(err, crate::error::AppError::Authentication(_)));
            fx.cleanup().await;
        }

        /// Other provider types are unchanged: unrestricted, with a refresh
        /// token persisted as before.
        #[tokio::test]
        async fn non_kubernetes_exchange_keeps_its_credential_shape() {
            let Some(fx) = Fixture::new().await else {
                return;
            };
            fx.mapping(json!({"project_path": "group/app"}), None, None)
                .await;
            let (user, tokens) = fx.exchange(gitlab("group/app", "main")).await.unwrap();
            assert_eq!(access_claims(&fx, &tokens).scopes, None);
            assert_eq!(refresh_jtis(&fx.pool, user.id).await, 1);
            fx.cleanup().await;
        }

        /// No exchanged credential can mint an API token for its account: a
        /// pull-only, non-renewable Kubernetes credential would otherwise
        /// turn into a permanent one, and a GitHub/GitLab credential would
        /// outlive the pipeline. Both self-service mint endpoints, through
        /// the full router, refuse with 403 and write no token row.
        #[tokio::test]
        async fn an_exchanged_credential_cannot_mint_an_api_token() {
            for provider_type in ["kubernetes", "gitlab"] {
                let Some(fx) = Fixture::with_provider_type(provider_type).await else {
                    return;
                };
                let (assertion, filters) = if provider_type == "kubernetes" {
                    (
                        k8s("payments", "api", Some("api-7d9f")),
                        json!({"/kubernetes.io/namespace": "payments"}),
                    )
                } else {
                    (
                        gitlab("group/app", "main"),
                        json!({"project_path": "group/app"}),
                    )
                };
                fx.mapping(filters, None, None).await;
                let (user, tokens) = fx.exchange(assertion).await.unwrap();

                for uri in ["/api/v1/profile/access-tokens", "/api/v1/auth/tokens"] {
                    let req = axum::http::Request::builder()
                        .method("POST")
                        .uri(uri)
                        .header("Authorization", format!("Bearer {}", tokens.access_token))
                        .header("Content-Type", "application/json")
                        .body(axum::body::Body::from(
                            json!({"name": "keep", "scopes": ["read:artifacts"]}).to_string(),
                        ))
                        .unwrap();
                    let (status, body) =
                        tdh::send(crate::api::routes::create_router(fx.state.clone()), req).await;
                    assert_eq!(
                        status,
                        axum::http::StatusCode::FORBIDDEN,
                        "{provider_type} {uri}: {}",
                        String::from_utf8_lossy(&body)
                    );
                }
                let minted: i64 =
                    sqlx::query_scalar("SELECT COUNT(*) FROM api_tokens WHERE user_id = $1")
                        .bind(user.id)
                        .fetch_one(&fx.pool)
                        .await
                        .unwrap();
                assert_eq!(minted, 0, "{provider_type}: no token row");
                fx.cleanup().await;
            }
        }

        /// 4.3 — two workloads through one mapping leave the same display
        /// name, which carries neither of them.
        #[tokio::test]
        async fn kubernetes_display_name_is_stable_across_workloads() {
            let Some(fx) = Fixture::with_provider_type("kubernetes").await else {
                return;
            };
            fx.mapping(json!({"/kubernetes.io/namespace": "payments"}), None, None)
                .await;
            let display_name = |user_id: Uuid| {
                let pool = fx.pool.clone();
                async move {
                    sqlx::query_scalar::<_, Option<String>>(
                        "SELECT display_name FROM users WHERE id = $1",
                    )
                    .bind(user_id)
                    .fetch_one(&pool)
                    .await
                    .unwrap()
                    .unwrap()
                }
            };

            let (api, _) = fx
                .exchange(k8s("payments", "api", Some("api-7d9f")))
                .await
                .unwrap();
            let after_api = display_name(api.id).await;
            let (worker, _) = fx
                .exchange(k8s("payments", "worker", Some("worker-5c2a")))
                .await
                .unwrap();
            assert_eq!(api.id, worker.id, "one account per mapping");
            let after_worker = display_name(worker.id).await;
            assert_eq!(after_api, after_worker);
            assert!(after_api.starts_with("CI [Kubernetes] "), "{after_api}");
            assert!(!after_api.contains("api-7d9f") && !after_api.contains("worker"));
            fx.cleanup().await;
        }

        /// 4.4 — the exchange's `security` line names the workload; a claim
        /// the token lacks is logged as absent and does not fail it.
        #[tokio::test]
        async fn kubernetes_exchange_is_attributed_to_its_workload() {
            let Some(fx) = Fixture::with_provider_type("kubernetes").await else {
                return;
            };
            fx.mapping(json!({"/kubernetes.io/namespace": "payments"}), None, None)
                .await;
            let exchange_line = |claims: serde_json::Value| {
                let fx = &fx;
                async move {
                    let capture = crate::api::handlers::test_db_helpers::LogCapture::default();
                    let _guard = capture.install(tracing::Level::INFO);
                    fx.exchange(claims).await.expect("exchange succeeds");
                    capture
                        .text()
                        .lines()
                        .find(|l| l.contains("CI OIDC token exchange"))
                        .expect("an exchange security line")
                        .to_owned()
                }
            };

            let bound = exchange_line(k8s("payments", "api", Some("api-7d9f"))).await;
            for field in [
                "k8s_namespace=\"payments\"",
                "k8s_serviceaccount=\"api\"",
                "k8s_pod=\"api-7d9f\"",
                "k8s_node=\"node-3\"",
                "subject=\"system:serviceaccount:payments:api\"",
            ] {
                assert!(bound.contains(field), "missing {field} in: {bound}");
            }

            let podless = exchange_line(k8s("payments", "api", None)).await;
            assert!(
                podless.contains("k8s_pod=\"(absent)\""),
                "a pod-less token logs the pod as absent: {podless}"
            );
            fx.cleanup().await;
        }
    }
}
