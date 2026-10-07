//! Attestation trust-policy endpoint (#4033).
//!
//! `GET /api/v1/attestations/policy` reports the CEP-27 conda attestation
//! trust policy the registry enforces on upload: whether an attestation must
//! verify, the OIDC issuers and certificate identities accepted on keyless
//! bundles, and the public keys accepted on key-based bundles.
//!
//! Any authenticated caller may read it. Everything it returns is public
//! material by construction (issuer URLs, identity patterns, public-key
//! fingerprints), and a publisher or consumer needs it to know which
//! signatures this registry will accept — the same posture as the signing
//! public-key endpoints. The key bytes themselves are never returned, only
//! their fingerprint and algorithm, and neither are file paths from the
//! configuration.

use axum::{extract::State, routing::get, Extension, Json, Router};
use utoipa::OpenApi;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::services::curation::attestation_verify::policy::{
    AttestationPolicyResponse, CondaTrustPolicy, TrustedKeyInfo,
};

pub fn router() -> Router<SharedState> {
    Router::new().route("/policy", get(get_attestation_policy))
}

/// Read the CEP-27 attestation trust policy.
#[utoipa::path(
    get,
    path = "/policy",
    context_path = "/api/v1/attestations",
    tag = "attestations",
    responses(
        (status = 200, description = "Attestation trust policy", body = AttestationPolicyResponse),
        (status = 401, description = "Authentication required", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_attestation_policy(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
) -> Json<AttestationPolicyResponse> {
    let policy = CondaTrustPolicy::from_config(&state.config);
    Json(AttestationPolicyResponse::from_policy(
        &policy,
        state.config.conda_attestation_require_verified,
    ))
}

#[derive(OpenApi)]
#[openapi(
    paths(get_attestation_policy),
    components(schemas(AttestationPolicyResponse, TrustedKeyInfo))
)]
pub struct AttestationsApiDoc;

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};

    const P256_PEM: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsW64iyufTRQg4Fd9id8IYtGCYEQe
HNYNSRk2PJuUF5StCz79cUDr02b/3c/Sgilw7T1ft6JA+7P64duptm46sw==
-----END PUBLIC KEY-----";

    #[tokio::test]
    async fn policy_endpoint_reports_the_configured_trust_policy() {
        let pool = tdh::lazy_pool();
        let state = tdh::build_state_with(pool, "/tmp", |c| {
            c.conda_attestation_issuers = vec!["https://ci.example.internal".into()];
            c.conda_attestation_identities = vec!["https://ci.example.internal/acme/*".into()];
            c.conda_attestation_public_keys = vec![format!("acme-ci={P256_PEM}")];
        });
        let app = tdh::router_with_auth_ext(
            router(),
            state,
            tdh::make_auth(uuid::Uuid::new_v4(), "reader"),
        );
        let (status, body) = tdh::send(
            app,
            Request::builder()
                .uri("/policy")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "require_verified": true,
                "issuers": ["https://ci.example.internal"],
                "identities": ["https://ci.example.internal/acme/*"],
                "keys": [{
                    "id": "8ef972c8a32ae989",
                    "name": "acme-ci",
                    "fingerprint": "8ef972c8a32ae9895a41291a27819c5d87681024e8fd9c553bea38db5e0b93ec",
                    "algorithm": "ecdsa-p256-sha256",
                }],
            })
        );
    }

    #[tokio::test]
    async fn policy_defaults_to_the_github_actions_issuer() {
        let state = tdh::build_state_with(tdh::lazy_pool(), "/tmp", |_| {});
        let app = tdh::router_with_auth_ext(
            router(),
            state,
            tdh::make_auth(uuid::Uuid::new_v4(), "reader"),
        );
        let (status, body) = tdh::send(
            app,
            Request::builder()
                .uri("/policy")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["issuers"],
            serde_json::json!(["https://token.actions.githubusercontent.com"])
        );
        assert_eq!(v["identities"], serde_json::json!([]));
        assert_eq!(v["keys"], serde_json::json!([]));
    }
}
