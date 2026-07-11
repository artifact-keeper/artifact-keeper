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
//! **Non-loopback bind (load-bearing):** the OIDC handler screens every
//! outbound fetch (discovery/token/JWKS) through the SSRF guard, which HARD
//! blocks loopback under every relaxation (`api::validation::is_hard_blocked_ipv4`).
//! wiremock's default `MockServer::start()` binds `127.0.0.1`, so the mock IdP
//! must instead bind the host's primary non-loopback interface and opt that IP
//! into `AK_SSRF_ALLOW_PRIVATE_CIDRS` — see `common::sso_support`.
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
//! Error / regression cases covered:
//!   - IdP error redirect `?error=access_denied` (RFC 6749 4.1.2.1, #1662) -> 401.
//!   - Invalid / unknown `state` (CSRF replay defense)                     -> 401.
//!   - Missing `code`/`state` (malformed callback, #1369 400/401 split)    -> 400.
//!   - Token-exchange failure (token endpoint 400s)                        -> not 401.
//!   - nonce mismatch / wrong audience / expired ID token                  -> 401.
//!   - claim-key mapping overrides (username/email/groups claim names).
//!   - `map_groups_to_groups` on (sync + prune) vs off (no local groups).
//!   - audit LOGIN on success / LOGIN_FAILED on federated-auth failure.
//!
//! Requires PostgreSQL with all migrations applied AND a non-loopback local IP.
//! Skips cleanly when `DATABASE_URL` is unset or no non-loopback IP exists
//! (matching the repo `--ignored` convention via `try_pool`).
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test sso_oidc_login_callback_e2e_tests -- --ignored --test-threads=1
//! ```

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

mod common;

use std::collections::HashMap;

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

use artifact_keeper_backend::api::SharedState;
use artifact_keeper_backend::services::audit_service::AuditService;
use artifact_keeper_backend::services::auth_config_service::{
    AuthConfigService, CreateOidcConfigRequest,
};

use common::sso_support::{
    allow_private_sso_ip, build_state, ensure_sso_encryption_key, non_loopback_bind_ip, sso_app,
    try_pool,
};

// ===========================================================================
// Generic fixtures
// ===========================================================================

const TEST_CLIENT_ID: &str = "ak-e2e-client";
const TEST_KID: &str = "ak-e2e-kid";

// ===========================================================================
// Mock OIDC IdP
// ===========================================================================

/// A running wiremock OIDC IdP plus the RSA key it signs ID tokens with.
struct MockIdp {
    server: MockServer,
    encoding_key: EncodingKey,
}

impl MockIdp {
    /// Boot a mock IdP bound to a **non-loopback** interface (the OIDC SSRF
    /// guard hard-blocks loopback). Mounts discovery + JWKS immediately; the
    /// token endpoint is mounted later (per-test) so each test can return a
    /// token carrying the exact nonce minted during its own login redirect.
    ///
    /// Returns `None` when there is no non-loopback local IP (isolated runner),
    /// so the caller can skip the test the same way it skips on missing DB.
    async fn start() -> Option<Self> {
        let ip = non_loopback_bind_ip()?;
        // Opt the mock IdP's IP into the SSRF private-IP allowlist so the
        // handler's discovery/token/JWKS fetches are permitted.
        allow_private_sso_ip(ip);
        let listener = std::net::TcpListener::bind((ip, 0)).ok()?;
        let server = MockServer::builder().listener(listener).start().await;

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

        Some(Self {
            server,
            encoding_key,
        })
    }

    fn issuer(&self) -> String {
        self.server.uri()
    }

    /// Sign an RS256 ID token with the IdP key. `extra_claims` are merged onto a
    /// well-formed default (iss/aud/sub/exp/iat + the supplied nonce), so a case
    /// can override `aud`/`exp`/etc. simply by providing that key.
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

    /// Like [`mount_token_endpoint`] but the mock only matches once, so a
    /// subsequent (later-mounted) token mock takes over the next exchange.
    /// Used to drive two consecutive callbacks with different group claims.
    async fn mount_token_endpoint_once(&self, nonce: &str, extra_claims: Value) {
        let id_token = self.sign_id_token(nonce, extra_claims);
        Mock::given(method("POST"))
            .and(wm_path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "mock-access-token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "id_token": id_token,
            })))
            .up_to_n_times(1)
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

/// Options for the OIDC provider fixture.
struct ProviderOpts {
    /// Extra `attribute_mapping` keys merged onto the pinned `redirect_uri`.
    attr_extra: Value,
    map_groups_to_groups: bool,
    auto_create_users: bool,
}

impl Default for ProviderOpts {
    fn default() -> Self {
        Self {
            attr_extra: json!({}),
            map_groups_to_groups: false,
            auto_create_users: true,
        }
    }
}

/// Insert an enabled OIDC provider config whose issuer points at `idp`.
async fn create_provider(pool: &PgPool, idp: &MockIdp) -> Uuid {
    create_provider_with(pool, idp, ProviderOpts::default()).await
}

async fn create_provider_with(pool: &PgPool, idp: &MockIdp, opts: ProviderOpts) -> Uuid {
    ensure_sso_encryption_key();
    // Pin a fixed redirect_uri so we can assert it on the login redirect
    // without relying on request Host headers, then merge any case-specific
    // claim overrides on top.
    let mut attr = json!({
        "redirect_uri": "https://ak.example.test/api/v1/auth/sso/oidc/callback"
    });
    if let (Value::Object(base), Value::Object(more)) = (&mut attr, opts.attr_extra) {
        base.extend(more);
    }
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
            attribute_mapping: Some(attr),
            is_enabled: Some(true),
            auto_create_users: Some(opts.auto_create_users),
            pkce_enabled: Some(true),
            map_groups_to_groups: Some(opts.map_groups_to_groups),
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

/// Look up a provisioned federated user by `external_id`.
async fn get_user(pool: &PgPool, external_id: &str) -> Option<(Uuid, String, Option<String>)> {
    sqlx::query_as("SELECT id, username, email FROM users WHERE external_id = $1")
        .bind(external_id)
        .fetch_optional(pool)
        .await
        .expect("user lookup")
}

/// OIDC-managed group names the user is currently a member of, sorted.
async fn oidc_group_names(pool: &PgPool, user_id: Uuid) -> Vec<String> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT g.name FROM groups g \
         JOIN user_group_members m ON m.group_id = g.id \
         WHERE m.user_id = $1 AND g.external_source = 'oidc' \
         ORDER BY g.name",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .expect("group lookup");
    rows.into_iter().map(|(n,)| n).collect()
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

/// login, returning the fresh (state, nonce) pair for the created SSO session.
async fn login_state_nonce(pool: &PgPool, provider_id: Uuid) -> (String, String) {
    let (status, redirect) = do_login(build_state(pool.clone()), provider_id).await;
    assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
    let redirect = redirect.expect("login Location");
    (
        redirect.get("state").expect("state").to_string(),
        redirect.get("nonce").expect("nonce").to_string(),
    )
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

/// Convenience: callback with `code=mock-auth-code&state=<state>`.
async fn do_callback_state(
    pool: &PgPool,
    provider_id: Uuid,
    state: &str,
) -> axum::response::Response {
    do_callback(
        build_state(pool.clone()),
        provider_id,
        &format!("code=mock-auth-code&state={}", urlencoding::encode(state)),
    )
    .await
}

// ===========================================================================
// Tests
// ===========================================================================

/// Login must 307 to the IdP authorize endpoint with all OIDC params present
/// and correct (locks the #453 "login 404" regression class).
#[tokio::test]
#[ignore = "requires DATABASE_URL + non-loopback IP"]
async fn test_oidc_login_redirects_with_correct_params() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let Some(idp) = MockIdp::start().await else {
        return;
    };
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
/// with auth cookies set (locks the #530 "callback 404" regression class).
#[tokio::test]
#[ignore = "requires DATABASE_URL + non-loopback IP"]
async fn test_oidc_login_callback_full_roundtrip() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let Some(idp) = MockIdp::start().await else {
        return;
    };
    let provider_id = create_provider(&pool, &idp).await;

    let (sso_state, nonce) = login_state_nonce(&pool, provider_id).await;

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

    let resp = do_callback_state(&pool, provider_id, &sso_state).await;

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

    // The user must have been provisioned with the mapped username/email.
    let user = get_user(&pool, &external_id).await;
    let (_, username, email) = user.expect("callback must provision the federated user");
    assert_eq!(username, "e2e-user");
    assert_eq!(email.as_deref(), Some("e2e-user@example.test"));

    delete_user_by_sub(&pool, &external_id).await;
    delete_provider(&pool, provider_id).await;
}

/// Claim-key mapping: `attribute_mapping` overrides `username_claim`/
/// `email_claim`/`groups_claim`; the ID token carries the *non-default* claim
/// keys, and the provisioned user's username/email + synced groups must come
/// from the overridden keys (exercises `resolve_oidc_claim_name` /
/// `extract_oidc_groups`).
#[tokio::test]
#[ignore = "requires DATABASE_URL + non-loopback IP"]
async fn test_oidc_callback_claim_key_mapping() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let Some(idp) = MockIdp::start().await else {
        return;
    };
    let provider_id = create_provider_with(
        &pool,
        &idp,
        ProviderOpts {
            attr_extra: json!({
                "username_claim": "upn",
                "email_claim": "mail",
                "groups_claim": "roles",
            }),
            map_groups_to_groups: true,
            ..ProviderOpts::default()
        },
    )
    .await;

    let (sso_state, nonce) = login_state_nonce(&pool, provider_id).await;

    let external_id = format!("oidc-sub-claimmap-{}", Uuid::new_v4().as_simple());
    let mapped_group = format!("claim-mapped-{}", Uuid::new_v4().as_simple());
    idp.mount_token_endpoint(
        &nonce,
        json!({
            "sub": external_id,
            // Non-default claim keys carry the identity; the *default* keys are
            // deliberately absent/wrong to prove the override is honored.
            "upn": "mapped-user",
            "mail": "mapped-user@corp.test",
            "roles": [mapped_group],
            // Default keys present but must be IGNORED.
            "preferred_username": "WRONG-default-username",
            "email": "wrong-default@corp.test",
        }),
    )
    .await;

    let resp = do_callback_state(&pool, provider_id, &sso_state).await;
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);

    let (user_id, username, email) = get_user(&pool, &external_id)
        .await
        .expect("user provisioned");
    assert_eq!(
        username, "mapped-user",
        "username must come from `upn` claim"
    );
    assert_eq!(
        email.as_deref(),
        Some("mapped-user@corp.test"),
        "email must come from `mail` claim"
    );
    let groups = oidc_group_names(&pool, user_id).await;
    assert!(
        groups.contains(&mapped_group),
        "group must come from the overridden `roles` claim, got {groups:?}"
    );

    delete_user_by_sub(&pool, &external_id).await;
    delete_provider(&pool, provider_id).await;
}

/// nonce mismatch: the ID token's `nonce` differs from the login nonce -> 401
/// (`validate_id_token` nonce check). State-CSRF is covered separately; this
/// pins the nonce leg.
#[tokio::test]
#[ignore = "requires DATABASE_URL + non-loopback IP"]
async fn test_oidc_callback_nonce_mismatch_returns_401() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let Some(idp) = MockIdp::start().await else {
        return;
    };
    let provider_id = create_provider(&pool, &idp).await;

    let (sso_state, _nonce) = login_state_nonce(&pool, provider_id).await;

    // Mint a token whose nonce does NOT match the session nonce.
    idp.mount_token_endpoint(
        "totally-different-nonce",
        json!({ "sub": "oidc-sub-nonce-mismatch" }),
    )
    .await;

    let resp = do_callback_state(&pool, provider_id, &sso_state).await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "nonce mismatch must map to 401"
    );

    delete_provider(&pool, provider_id).await;
}

/// wrong audience: the ID token's `aud` != provider `client_id` -> 401
/// (`validate_id_token` `set_audience`).
#[tokio::test]
#[ignore = "requires DATABASE_URL + non-loopback IP"]
async fn test_oidc_callback_wrong_audience_returns_401() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let Some(idp) = MockIdp::start().await else {
        return;
    };
    let provider_id = create_provider(&pool, &idp).await;

    let (sso_state, nonce) = login_state_nonce(&pool, provider_id).await;
    idp.mount_token_endpoint(
        &nonce,
        json!({ "sub": "oidc-sub-wrong-aud", "aud": "some-other-client" }),
    )
    .await;

    let resp = do_callback_state(&pool, provider_id, &sso_state).await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "wrong audience must map to 401"
    );

    delete_provider(&pool, provider_id).await;
}

/// expired token: the ID token's `exp` is in the past -> 401 (jsonwebtoken exp
/// validation).
#[tokio::test]
#[ignore = "requires DATABASE_URL + non-loopback IP"]
async fn test_oidc_callback_expired_token_returns_401() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let Some(idp) = MockIdp::start().await else {
        return;
    };
    let provider_id = create_provider(&pool, &idp).await;

    let (sso_state, nonce) = login_state_nonce(&pool, provider_id).await;
    let past = chrono::Utc::now().timestamp() - 3600;
    idp.mount_token_endpoint(
        &nonce,
        json!({ "sub": "oidc-sub-expired", "exp": past, "iat": past - 60 }),
    )
    .await;

    let resp = do_callback_state(&pool, provider_id, &sso_state).await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "expired token must map to 401"
    );

    delete_provider(&pool, provider_id).await;
}

/// `map_groups_to_groups=true`: first login with groups `[dev, sec]` creates
/// both local `external_source='oidc'` groups with membership; a second login
/// with `[dev]` prunes the `sec` membership (but keeps `dev`) via
/// `sync_oidc_groups_to_local_groups`.
#[tokio::test]
#[ignore = "requires DATABASE_URL + non-loopback IP"]
async fn test_oidc_callback_map_groups_sync_and_prune() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let Some(idp) = MockIdp::start().await else {
        return;
    };
    let provider_id = create_provider_with(
        &pool,
        &idp,
        ProviderOpts {
            map_groups_to_groups: true,
            ..ProviderOpts::default()
        },
    )
    .await;

    let external_id = format!("oidc-sub-groups-{}", Uuid::new_v4().as_simple());
    let g_dev = format!("dev-{}", Uuid::new_v4().as_simple());
    let g_sec = format!("sec-{}", Uuid::new_v4().as_simple());

    // --- first login: groups [dev, sec] ---
    let (state1, nonce1) = login_state_nonce(&pool, provider_id).await;
    idp.mount_token_endpoint_once(
        &nonce1,
        json!({ "sub": external_id, "groups": [g_dev, g_sec] }),
    )
    .await;
    let resp1 = do_callback_state(&pool, provider_id, &state1).await;
    assert_eq!(resp1.status(), StatusCode::TEMPORARY_REDIRECT);

    let (user_id, _, _) = get_user(&pool, &external_id)
        .await
        .expect("user provisioned");
    let after1 = oidc_group_names(&pool, user_id).await;
    assert!(
        after1.contains(&g_dev) && after1.contains(&g_sec),
        "both groups present after first login, got {after1:?}"
    );

    // --- second login: groups [dev] only -> sec pruned ---
    let (state2, nonce2) = login_state_nonce(&pool, provider_id).await;
    idp.mount_token_endpoint(&nonce2, json!({ "sub": external_id, "groups": [g_dev] }))
        .await;
    let resp2 = do_callback_state(&pool, provider_id, &state2).await;
    assert_eq!(resp2.status(), StatusCode::TEMPORARY_REDIRECT);

    let after2 = oidc_group_names(&pool, user_id).await;
    assert!(
        after2.contains(&g_dev),
        "dev membership must persist, got {after2:?}"
    );
    assert!(
        !after2.contains(&g_sec),
        "sec membership must be pruned after it dropped from the claim, got {after2:?}"
    );

    // cleanup: membership + the auto-created oidc groups.
    delete_user_by_sub(&pool, &external_id).await;
    let _ = sqlx::query("DELETE FROM groups WHERE external_provider_id = $1")
        .bind(provider_id)
        .execute(&pool)
        .await;
    delete_provider(&pool, provider_id).await;
}

/// `map_groups_to_groups=false`: even with a non-empty groups claim, NO local
/// groups are created for the provider (legacy role-mapping behavior preserved).
#[tokio::test]
#[ignore = "requires DATABASE_URL + non-loopback IP"]
async fn test_oidc_callback_map_groups_disabled_creates_no_groups() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let Some(idp) = MockIdp::start().await else {
        return;
    };
    let provider_id = create_provider_with(
        &pool,
        &idp,
        ProviderOpts {
            map_groups_to_groups: false,
            ..ProviderOpts::default()
        },
    )
    .await;

    let external_id = format!("oidc-sub-nogroups-{}", Uuid::new_v4().as_simple());
    let (sso_state, nonce) = login_state_nonce(&pool, provider_id).await;
    idp.mount_token_endpoint(
        &nonce,
        json!({ "sub": external_id, "groups": ["dev", "sec"] }),
    )
    .await;
    let resp = do_callback_state(&pool, provider_id, &sso_state).await;
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);

    let created: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM groups WHERE external_provider_id = $1")
            .bind(provider_id)
            .fetch_one(&pool)
            .await
            .expect("count groups");
    assert_eq!(
        created.0, 0,
        "no local groups may be created when map_groups_to_groups is off"
    );

    delete_user_by_sub(&pool, &external_id).await;
    delete_provider(&pool, provider_id).await;
}

/// Audit: a happy-path login emits exactly a `LOGIN` audit row for the
/// provisioned user with `details.provider="oidc"`; a federated-auth failure
/// (auto-create disabled + unknown user) emits a `LOGIN_FAILED` row with
/// `details.provider="oidc"`.
#[tokio::test]
#[ignore = "requires DATABASE_URL + non-loopback IP"]
async fn test_oidc_callback_emits_audit_records() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let Some(idp) = MockIdp::start().await else {
        return;
    };
    let audit = AuditService::new(pool.clone());

    // --- success -> LOGIN ---
    let provider_id = create_provider(&pool, &idp).await;
    let external_id = format!("oidc-sub-audit-ok-{}", Uuid::new_v4().as_simple());
    let (state_ok, nonce_ok) = login_state_nonce(&pool, provider_id).await;
    idp.mount_token_endpoint_once(
        &nonce_ok,
        json!({ "sub": external_id, "preferred_username": "audit-ok-user" }),
    )
    .await;
    let resp = do_callback_state(&pool, provider_id, &state_ok).await;
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);

    let (user_id, _, _) = get_user(&pool, &external_id).await.expect("provisioned");
    let (login_rows, _) = audit
        .query(
            Some(user_id),
            Some("LOGIN"),
            None,
            None,
            None,
            None,
            None,
            0,
            50,
        )
        .await
        .expect("audit query LOGIN");
    assert!(
        login_rows.iter().any(|r| {
            r.resource_type == "user"
                && r.details
                    .as_ref()
                    .and_then(|d| d.get("provider"))
                    .and_then(|p| p.as_str())
                    == Some("oidc")
        }),
        "a LOGIN audit row with details.provider=oidc must exist for the user"
    );

    // --- failure -> LOGIN_FAILED ---
    // auto_create_users=false + a brand-new sub -> authenticate_federated errors,
    // the handler fires a LOGIN_FAILED audit before returning.
    let fail_provider = create_provider_with(
        &pool,
        &idp,
        ProviderOpts {
            auto_create_users: false,
            ..ProviderOpts::default()
        },
    )
    .await;
    let fail_username = format!("audit-fail-{}", Uuid::new_v4().as_simple());
    let (state_fail, nonce_fail) = login_state_nonce(&pool, fail_provider).await;
    idp.mount_token_endpoint(
        &nonce_fail,
        json!({
            "sub": format!("oidc-sub-audit-fail-{}", Uuid::new_v4().as_simple()),
            "preferred_username": fail_username,
        }),
    )
    .await;
    let resp = do_callback_state(&pool, fail_provider, &state_fail).await;
    assert!(
        resp.status().is_client_error() || resp.status().is_server_error(),
        "federated-auth failure must surface an error status, got {}",
        resp.status()
    );

    let (fail_rows, _) = audit
        .query(
            None,
            Some("LOGIN_FAILED"),
            None,
            None,
            None,
            None,
            None,
            0,
            200,
        )
        .await
        .expect("audit query LOGIN_FAILED");
    assert!(
        fail_rows.iter().any(|r| {
            let details = r.details.as_ref();
            details
                .and_then(|d| d.get("provider"))
                .and_then(|p| p.as_str())
                == Some("oidc")
                && details
                    .and_then(|d| d.get("username"))
                    .and_then(|u| u.as_str())
                    == Some(fail_username.as_str())
        }),
        "a LOGIN_FAILED audit row with details.provider=oidc for the attempted username must exist"
    );

    delete_user_by_sub(&pool, &external_id).await;
    delete_provider(&pool, provider_id).await;
    delete_provider(&pool, fail_provider).await;
}

/// IdP error redirect (RFC 6749 4.1.2.1): `?error=access_denied` -> 401, and
/// crucially NOT a 400 or a CSRF-style 500 (locks in #1662 + the #1369 split).
#[tokio::test]
#[ignore = "requires DATABASE_URL + non-loopback IP"]
async fn test_oidc_callback_idp_access_denied_returns_401() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let Some(idp) = MockIdp::start().await else {
        return;
    };
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
#[ignore = "requires DATABASE_URL + non-loopback IP"]
async fn test_oidc_callback_invalid_state_returns_401() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let Some(idp) = MockIdp::start().await else {
        return;
    };
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
#[ignore = "requires DATABASE_URL + non-loopback IP"]
async fn test_oidc_callback_missing_params_returns_400() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let Some(idp) = MockIdp::start().await else {
        return;
    };
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
/// failed.
#[tokio::test]
#[ignore = "requires DATABASE_URL + non-loopback IP"]
async fn test_oidc_callback_token_exchange_failure_is_not_401() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let Some(idp) = MockIdp::start().await else {
        return;
    };
    let provider_id = create_provider(&pool, &idp).await;

    let (sso_state, _nonce) = login_state_nonce(&pool, provider_id).await;

    idp.mount_token_endpoint_failure().await;

    let resp = do_callback_state(&pool, provider_id, &sso_state).await;

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
