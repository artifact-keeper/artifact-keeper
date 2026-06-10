//! Public CI OIDC token exchange endpoint.
//!
//! CI pipelines POST a CI-issued JWT here and receive a short-lived
//! Artifact Keeper access token in return — no static secrets required.
//!
//! # Request
//! ```text
//! POST /api/v1/auth/ci/token
//! Authorization: Bearer <CI-issued OIDC JWT>
//! Content-Type: application/json
//!
//! {"provider_id": "<uuid>"}
//! ```
//!
//! The CI JWT is supplied in the `Authorization` header rather than the
//! request body to prevent it from appearing in access logs, HTTP traces,
//! or any middleware that records request payloads.
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

use axum::{extract::State, http::HeaderMap, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::auth_service::AuthService;
use crate::services::ci_oidc_service::CiOidcService;

/// Create public CI auth routes (no auth middleware needed — the CI JWT is the
/// credential).
pub fn router() -> Router<SharedState> {
    Router::new().route("/token", post(exchange_ci_token))
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct CiTokenRequest {
    /// UUID of the `ci_oidc_providers` row to use for validation.
    pub provider_id: Uuid,
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
#[utoipa::path(
    post,
    path = "/token",
    context_path = "/api/v1/auth/ci",
    tag = "auth",
    request_body = CiTokenRequest,
    responses(
        (status = 200, description = "CI token exchange successful", body = CiTokenResponse),
        (status = 401, description = "Invalid CI token or provider configuration", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "CI OIDC provider not found", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn exchange_ci_token(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<CiTokenRequest>,
) -> Result<Json<CiTokenResponse>> {
    // Extract the CI JWT from the Authorization header. This keeps it out of
    // the request body and therefore out of access logs and HTTP traces.
    let jwt = extract_bearer_jwt(&headers)?;

    let svc = CiOidcService::new(state.db.clone());

    // 1. Load provider config
    let provider = svc.get(req.provider_id).await?;
    if !provider.is_enabled {
        return Err(AppError::Authentication(
            "CI OIDC provider is disabled".into(),
        ));
    }

    // 2. Validate the CI JWT (signature, audience, issuer — no claim check yet)
    let claims = svc.validate_ci_jwt(&provider, jwt).await?;

    // 3. Find the first matching enabled identity mapping (enforces claim filters)
    let mapping = svc.resolve_mapping(provider.id, &claims).await?;

    // 4. Map CI claims + mapping to stable FederatedCredentials
    let credentials = CiOidcService::extract_identity_from_mapping(&provider, &mapping, &claims);

    // 5. Provision / sync the CI service account and generate scoped tokens.
    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    let (user, tokens) = auth_service
        .authenticate_federated_with_scope(
            CiOidcService::auth_provider(),
            credentials,
            mapping.allowed_repo_ids.clone(),
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
    use super::{exchange_ci_token, extract_bearer_jwt, CiTokenRequest};
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::extract::State;
    use axum::http::{HeaderMap, HeaderValue};
    use axum::Json;
    use sqlx::postgres::PgPoolOptions;
    use uuid::Uuid;

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
            Json(CiTokenRequest {
                provider_id: Uuid::new_v4(),
            }),
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

        let err = exchange_ci_token(State(state), headers, Json(CiTokenRequest { provider_id }))
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
}
