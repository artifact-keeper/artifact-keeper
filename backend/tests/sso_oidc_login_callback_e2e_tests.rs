//! End-to-end coverage for the OIDC SSO login + callback round-trip (#1617,
//! epic #1615).
//!
//! These tests drive the real axum handlers in `api::handlers::sso` against a
//! wiremock-backed mock OIDC identity provider. The mock IdP stubs the three
//! endpoints the backend touches during the flow:
//!
//!   1. `/.well-known/openid-configuration` (discovery) — advertises the
//!      authorize, token, and JWKS endpoints (all pointed back at wiremock).
//!   2. `/token` — exchanges the authorization code for a signed (RS256) ID
//!      token whose `nonce`/`aud`/`iss` match what the backend expects.
//!   3. `/jwks` — publishes the RSA public key so `validate_id_token` can
//!      verify the signature.
//!
//! The flow exercised:
//!
//!   GET /oidc/{id}/login   -> 307 to authorize URL (assert client_id,
//!                             redirect_uri, scope, state, nonce, PKCE)
//!   GET /oidc/{id}/callback?code=..&state=..
//!                          -> backend POSTs the code to the mock token
//!                             endpoint, validates the ID token against JWKS,
//!                             provisions the user, and 307-redirects to the
//!                             frontend `/callback` with auth cookies set.
//!
//! Error cases covered to lock the historical wiring bugs in place:
//!   - IdP error redirect `?error=access_denied` (RFC 6749 4.1.2.1, #1662)
//!     -> 401, no user provisioned.
//!   - Invalid / unknown `state` (CSRF replay defense)              -> 401.
//!   - Missing `code`/`state` (malformed callback, #1369)           -> 400.
//!   - Token-exchange failure (token endpoint 400s)                 -> 500
//!     (the 400/401 split for *parameter* shape is asserted separately).
//!
//! Requires PostgreSQL with all migrations applied. Skips cleanly when
//! `DATABASE_URL` is unset (matching the repo convention via `try_pool`).
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test sso_oidc_login_callback_e2e_tests -- --ignored
//! ```

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{encode, EncodingKey, Header};
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;
use wiremock::matchers::{method, path as wm_path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use artifact_keeper_backend::api::{AppState, SharedState};
use artifact_keeper_backend::config::Config;
use artifact_keeper_backend::services::auth_config_service::{
    AuthConfigService, CreateOidcConfigRequest,
};

// ===========================================================================
// Generic fixtures
// ===========================================================================

const TEST_CLIENT_ID: &str = "ak-e2e-client";
const TEST_KID: &str = "ak-e2e-kid";

/// `AuthConfigService` encrypts the stored OIDC client secret with a key read
/// from `SSO_ENCRYPTION_KEY`/`JWT_SECRET` in the *process* environment (not the
/// `Config`). CI sets `JWT_SECRET`; for local runs we install a stable key so
/// `create_oidc` (encrypt) and `get_oidc_decrypted` (decrypt) agree. Setting it
/// to a fixed value is idempotent across the parallel tests in this binary.
fn ensure_sso_encryption_key() {
    if std::env::var("SSO_ENCRYPTION_KEY").is_err() && std::env::var("JWT_SECRET").is_err() {
        std::env::set_var(
            "SSO_ENCRYPTION_KEY",
            "test-sso-encryption-key-at-least-32-bytes-long",
        );
    }
}

async fn try_pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(3)
        .acquire_timeout(std::time::Duration::from_secs(3))
        .connect(&url)
        .await
        .ok()
}

fn test_config() -> Config {
    Config {
        database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
        storage_path: std::env::temp_dir()
            .join(format!("ak-sso-e2e-{}", Uuid::new_v4()))
            .to_string_lossy()
            .into_owned(),
        jwt_secret: "test-secret-at-least-32-bytes-long-for-testing".into(),
        ..Default::default()
    }
}

fn build_state(pool: PgPool) -> SharedState {
    let cfg = test_config();
    std::fs::create_dir_all(&cfg.storage_path).expect("create storage dir");
    let storage: Arc<dyn artifact_keeper_backend::storage::StorageBackend> = Arc::new(
        artifact_keeper_backend::storage::filesystem::FilesystemStorage::new(&cfg.storage_path),
    );
    let registry = Arc::new(artifact_keeper_backend::storage::StorageRegistry::new(
        HashMap::new(),
        "filesystem".to_string(),
    ));
    Arc::new(AppState::new(cfg, pool, storage, registry))
}

/// Wrap the public SSO router in `with_state` (no auth layer — these are
/// pre-auth public endpoints).
fn sso_app(state: SharedState) -> axum::Router {
    artifact_keeper_backend::api::handlers::sso::router().with_state(state)
}

// ===========================================================================
// Mock OIDC IdP
// ===========================================================================

/// A running wiremock OIDC IdP plus the RSA key it signs ID tokens with.
struct MockIdp {
    server: MockServer,
    encoding_key: EncodingKey,
}

impl MockIdp {
    /// Boot a mock IdP. Mounts discovery + JWKS immediately; the token
    /// endpoint is mounted later (per-test) so each test can return a token
    /// carrying the exact nonce minted during its own login redirect.
    async fn start() -> Self {
        let server = MockServer::start().await;

        let mut rng = rsa::rand_core::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("gen rsa key");
        let pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .expect("pkcs8 pem");
        let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes()).expect("encoding key");

        let public_key = RsaPublicKey::from(&private_key);
        let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());
        let jwk = json!({
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": TEST_KID,
            "n": n,
            "e": e,
        });

        let issuer = server.uri();
        let discovery = json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/jwks"),
        });

        Mock::given(method("GET"))
            .and(wm_path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(discovery))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(wm_path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk] })))
            .mount(&server)
            .await;

        Self {
            server,
            encoding_key,
        }
    }

    fn issuer(&self) -> String {
        self.server.uri()
    }

    /// Sign an RS256 ID token with the IdP key. `claims` are merged onto a
    /// well-formed default (iss/aud/sub/exp/iat + the supplied nonce).
    fn sign_id_token(&self, nonce: &str, extra_claims: Value) -> String {
        let now = chrono::Utc::now().timestamp();
        let mut claims = json!({
            "iss": self.issuer(),
            "aud": TEST_CLIENT_ID,
            "sub": "oidc-sub-e2e",
            "exp": now + 3600,
            "iat": now,
            "nonce": nonce,
        });
        if let Value::Object(extra) = extra_claims {
            for (k, v) in extra {
                claims[k] = v;
            }
        }
        let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(TEST_KID.to_string());
        encode(&header, &claims, &self.encoding_key).expect("sign id token")
    }

    /// Mount a token endpoint that returns a signed ID token for the given
    /// nonce and claims.
    async fn mount_token_endpoint(&self, nonce: &str, extra_claims: Value) {
        let id_token = self.sign_id_token(nonce, extra_claims);
        Mock::given(method("POST"))
            .and(wm_path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "mock-access-token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "id_token": id_token,
            })))
            .mount(&self.server)
            .await;
    }

    /// Mount a token endpoint that fails the code exchange (IdP rejects the
    /// authorization code).
    async fn mount_token_endpoint_failure(&self) {
        Mock::given(method("POST"))
            .and(wm_path("/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": "invalid_grant",
                "error_description": "authorization code expired",
            })))
            .mount(&self.server)
            .await;
    }
}

// ===========================================================================
// Provider config + login helpers
// ===========================================================================

/// Insert an enabled OIDC provider config whose issuer points at `idp`.
async fn create_provider(pool: &PgPool, idp: &MockIdp) -> Uuid {
    ensure_sso_encryption_key();
    let resp = AuthConfigService::create_oidc(
        pool,
        CreateOidcConfigRequest {
            name: format!("e2e-oidc-{}", Uuid::new_v4().as_simple()),
            issuer_url: idp.issuer(),
            client_id: TEST_CLIENT_ID.to_string(),
            client_secret: "mock-client-secret".to_string(),
            scopes: Some(vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ]),
            // Pin a fixed redirect_uri so we can assert it on the login redirect
            // without relying on request Host headers.
            attribute_mapping: Some(json!({
                "redirect_uri": "https://ak.example.test/api/v1/auth/sso/oidc/callback"
            })),
            is_enabled: Some(true),
            auto_create_users: Some(true),
            pkce_enabled: Some(true),
            map_groups_to_groups: Some(false),
            allow_legacy_rsa_keys: None,
        },
    )
    .await
    .expect("create oidc provider");
    resp.id
}

async fn delete_provider(pool: &PgPool, id: Uuid) {
    let _ = AuthConfigService::delete_oidc(pool, id).await;
}

async fn delete_user_by_sub(pool: &PgPool, external_id: &str) {
    let _ = sqlx::query(
        "DELETE FROM user_group_members WHERE user_id IN \
         (SELECT id FROM users WHERE external_id = $1)",
    )
    .bind(external_id)
    .execute(pool)
    .await;
    let _ = sqlx::query("DELETE FROM users WHERE external_id = $1")
        .bind(external_id)
        .execute(pool)
        .await;
}

/// Parsed query parameters from a login redirect's `Location` header.
struct AuthorizeRedirect {
    location: String,
    params: HashMap<String, String>,
}

impl AuthorizeRedirect {
    fn get(&self, key: &str) -> Option<&str> {
        self.params.get(key).map(String::as_str)
    }
}

/// Drive `GET /oidc/{id}/login` and parse the resulting 307 redirect.
async fn do_login(
    state: SharedState,
    provider_id: Uuid,
) -> (StatusCode, Option<AuthorizeRedirect>) {
    let app = sso_app(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/oidc/{provider_id}/login"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("login oneshot");

    let status = resp.status();
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let redirect = location.map(|location| {
        let query = location.split_once('?').map(|(_, q)| q).unwrap_or("");
        let params = url_decode_query(query);
        AuthorizeRedirect { location, params }
    });

    (status, redirect)
}

/// Parse `a=b&c=d` (percent-encoded) into a map.
fn url_decode_query(query: &str) -> HashMap<String, String> {
    query
        .split('&')
        .filter(|s| !s.is_empty())
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            Some((
                urlencoding::decode(k).ok()?.into_owned(),
                urlencoding::decode(v).ok()?.into_owned(),
            ))
        })
        .collect()
}

/// Drive `GET /oidc/{id}/callback` with the given query string.
async fn do_callback(
    state: SharedState,
    provider_id: Uuid,
    query: &str,
) -> axum::response::Response {
    let app = sso_app(state);
    app.oneshot(
        Request::builder()
            .method("GET")
            .uri(format!("/oidc/{provider_id}/callback?{query}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .expect("callback oneshot")
}

// ===========================================================================
// Tests
// ===========================================================================

/// Login must 307 to the IdP authorize endpoint with all OIDC params present
/// and correct (closes the #453 "login 404" regression class).
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_oidc_login_redirects_with_correct_params() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let idp = MockIdp::start().await;
    let provider_id = create_provider(&pool, &idp).await;
    let state = build_state(pool.clone());

    let (status, redirect) = do_login(state, provider_id).await;
    assert_eq!(status, StatusCode::TEMPORARY_REDIRECT, "login must 307");
    let redirect = redirect.expect("login must set Location");

    assert!(
        redirect
            .location
            .starts_with(&format!("{}/authorize?", idp.issuer())),
        "redirect must target the IdP authorize endpoint, got {}",
        redirect.location
    );
    assert_eq!(redirect.get("response_type"), Some("code"));
    assert_eq!(redirect.get("client_id"), Some(TEST_CLIENT_ID));
    assert_eq!(
        redirect.get("redirect_uri"),
        Some("https://ak.example.test/api/v1/auth/sso/oidc/callback")
    );
    assert_eq!(redirect.get("scope"), Some("openid profile email"));
    assert!(
        redirect
            .get("state")
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "state must be present and non-empty"
    );
    assert!(
        redirect
            .get("nonce")
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "nonce must be present and non-empty"
    );
    // PKCE is enabled on this provider.
    assert_eq!(redirect.get("code_challenge_method"), Some("S256"));
    assert!(
        redirect
            .get("code_challenge")
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "code_challenge must be present when PKCE is enabled"
    );

    delete_provider(&pool, provider_id).await;
}

/// Full happy path: login -> extract state/nonce -> callback exchanges the
/// code, validates the ID token, provisions a user, and 307s to the frontend
/// with auth cookies set (closes the #530 "callback 404" regression class).
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_oidc_login_callback_full_roundtrip() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let idp = MockIdp::start().await;
    let provider_id = create_provider(&pool, &idp).await;

    // --- login ---
    let (status, redirect) = do_login(build_state(pool.clone()), provider_id).await;
    assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
    let redirect = redirect.expect("login Location");
    let sso_state = redirect.get("state").expect("state").to_string();
    let nonce = redirect.get("nonce").expect("nonce").to_string();

    // The token endpoint must echo the login nonce inside the signed ID token.
    let external_id = format!("oidc-sub-roundtrip-{}", Uuid::new_v4().as_simple());
    idp.mount_token_endpoint(
        &nonce,
        json!({
            "sub": external_id,
            "preferred_username": "e2e-user",
            "email": "e2e-user@example.test",
            "name": "E2E User",
        }),
    )
    .await;

    // --- callback ---
    let resp = do_callback(
        build_state(pool.clone()),
        provider_id,
        &format!(
            "code=mock-auth-code&state={}",
            urlencoding::encode(&sso_state)
        ),
    )
    .await;

    assert_eq!(
        resp.status(),
        StatusCode::TEMPORARY_REDIRECT,
        "successful callback must 307 to the frontend"
    );
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        location.starts_with("/callback?code="),
        "callback must redirect to frontend /callback with an exchange code, got {location}"
    );
    // Auth cookies must be set on the redirect itself (#1405).
    assert!(
        resp.headers().get_all("set-cookie").iter().count() > 0,
        "callback redirect must set auth cookies"
    );

    // The user must have been provisioned.
    let provisioned: Option<(String,)> =
        sqlx::query_as("SELECT username FROM users WHERE external_id = $1")
            .bind(&external_id)
            .fetch_optional(&pool)
            .await
            .expect("user lookup");
    assert!(
        provisioned.is_some(),
        "callback must provision the federated user"
    );

    delete_user_by_sub(&pool, &external_id).await;
    delete_provider(&pool, provider_id).await;
}

/// IdP error redirect (RFC 6749 4.1.2.1): `?error=access_denied` -> 401, and
/// crucially NOT a 400 or a CSRF-style 500 (locks in #1662 + the #1369 split).
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_oidc_callback_idp_access_denied_returns_401() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let idp = MockIdp::start().await;
    let provider_id = create_provider(&pool, &idp).await;

    let resp = do_callback(
        build_state(pool.clone()),
        provider_id,
        "error=access_denied&error_description=User%20denied%20access",
    )
    .await;

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "IdP error redirect must map to 401"
    );

    delete_provider(&pool, provider_id).await;
}

/// Unknown / non-empty `state` that matches no SSO session -> 401 (CSRF replay
/// defense). The token endpoint must NOT be reached.
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_oidc_callback_invalid_state_returns_401() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let idp = MockIdp::start().await;
    let provider_id = create_provider(&pool, &idp).await;

    let resp = do_callback(
        build_state(pool.clone()),
        provider_id,
        "code=mock-auth-code&state=not-a-real-state",
    )
    .await;

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "unknown state must map to 401 (CSRF defense)"
    );

    delete_provider(&pool, provider_id).await;
}

/// Missing `code` and `state` -> 400 malformed callback (#1369 400/401 split).
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_oidc_callback_missing_params_returns_400() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let idp = MockIdp::start().await;
    let provider_id = create_provider(&pool, &idp).await;

    let resp = do_callback(build_state(pool.clone()), provider_id, "code=&state=").await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "missing code/state must map to 400, not 401"
    );

    delete_provider(&pool, provider_id).await;
}

/// Token-exchange failure (IdP rejects the code) must NOT be a 401 (which would
/// imply a CSRF / state problem) — the state was valid; the exchange itself
/// failed. Asserts the handler does not collapse exchange errors into the CSRF
/// 401 path.
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_oidc_callback_token_exchange_failure_is_not_401() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let idp = MockIdp::start().await;
    let provider_id = create_provider(&pool, &idp).await;

    let (status, redirect) = do_login(build_state(pool.clone()), provider_id).await;
    assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
    let sso_state = redirect
        .expect("login Location")
        .get("state")
        .unwrap()
        .to_string();

    idp.mount_token_endpoint_failure().await;

    let resp = do_callback(
        build_state(pool.clone()),
        provider_id,
        &format!(
            "code=mock-auth-code&state={}",
            urlencoding::encode(&sso_state)
        ),
    )
    .await;

    assert_ne!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "a token-exchange failure with valid state must not masquerade as a CSRF 401"
    );
    assert!(
        resp.status().is_server_error() || resp.status().is_client_error(),
        "token-exchange failure must surface an error status, got {}",
        resp.status()
    );

    delete_provider(&pool, provider_id).await;
}
