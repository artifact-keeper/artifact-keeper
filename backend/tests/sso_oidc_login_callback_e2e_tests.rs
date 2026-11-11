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
    allow_private_sso_ip, audit_row_eventually, build_state, build_state_with_config,
    ensure_sso_encryption_key, non_loopback_bind_ip, sso_app, test_config, try_pool,
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
        self.sign_id_token_omitting(nonce, extra_claims, &[])
    }

    /// [`Self::sign_id_token`] with the named default claims removed, for the
    /// cases where a claim must be absent rather than overridden (#5482).
    fn sign_id_token_omitting(&self, nonce: &str, extra_claims: Value, omit: &[&str]) -> String {
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
        for key in omit {
            claims.as_object_mut().unwrap().remove(*key);
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
        self.mount_id_token_once(self.sign_id_token(nonce, extra_claims))
            .await;
    }

    /// Mount a one-shot token endpoint answering with this exact ID token.
    async fn mount_id_token_once(&self, id_token: String) {
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
    /// Pin `attribute_mapping.redirect_uri`. Off only for the cases that
    /// assert the request-derived redirect_uri (#4143).
    pin_redirect_uri: bool,
}

impl Default for ProviderOpts {
    fn default() -> Self {
        Self {
            attr_extra: json!({}),
            map_groups_to_groups: false,
            auto_create_users: true,
            pin_redirect_uri: true,
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
    let mut attr = if opts.pin_redirect_uri {
        json!({
            "redirect_uri": "https://ak.example.test/api/v1/auth/sso/oidc/callback"
        })
    } else {
        json!({})
    };
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
            admin_group: None,
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
    // Poll: the LOGIN row is written by a detached task (#2905), so it is not
    // guaranteed to be visible the instant the callback returns.
    let login_ok = audit_row_eventually(&audit, Some(user_id), "LOGIN", |r| {
        r.resource_type == "user"
            && r.details
                .as_ref()
                .and_then(|d| d.get("provider"))
                .and_then(|p| p.as_str())
                == Some("oidc")
    })
    .await;

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

    // Same detached-write race as the LOGIN row above.
    let fail_ok = audit_row_eventually(&audit, None, "LOGIN_FAILED", |r| {
        let details = r.details.as_ref();
        details
            .and_then(|d| d.get("provider"))
            .and_then(|p| p.as_str())
            == Some("oidc")
            && details
                .and_then(|d| d.get("username"))
                .and_then(|u| u.as_str())
                == Some(fail_username.as_str())
    })
    .await;

    // Clean up BEFORE asserting. A panicking assertion would otherwise skip
    // these deletes and strand a provisioned user, and because a federated user
    // with no `email` claim is stored with an empty-string email against the
    // `users_email_key` UNIQUE constraint, that single leftover row makes every
    // later no-email-claim test in this file fail with a duplicate-key error.
    // Deferring the asserts keeps one failure from cascading into three.
    delete_user_by_sub(&pool, &external_id).await;
    delete_provider(&pool, provider_id).await;
    delete_provider(&pool, fail_provider).await;

    assert!(
        login_ok,
        "a LOGIN audit row with details.provider=oidc must exist for the user"
    );
    assert!(
        fail_ok,
        "a LOGIN_FAILED audit row with details.provider=oidc for the attempted username must exist"
    );
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

// ===========================================================================
// Silent SSO (check-sso): prompt=none forwarding + silent_denied callback
// ===========================================================================

/// Drive `GET /oidc/{id}/login` with an extra query string and parse the 307.
async fn do_login_query(
    state: SharedState,
    provider_id: Uuid,
    query: &str,
) -> (StatusCode, Option<AuthorizeRedirect>) {
    let app = sso_app(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/oidc/{provider_id}/login?{query}"))
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

/// `?prompt=none` on the login redirect must be forwarded verbatim to the IdP
/// authorize URL (the silent check-sso probe), leaving every other parameter
/// of the ordinary flow untouched.
#[tokio::test]
#[ignore = "requires DATABASE_URL + non-loopback IP"]
async fn test_oidc_login_prompt_none_forwarded_to_idp() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let Some(idp) = MockIdp::start().await else {
        return;
    };
    let provider_id = create_provider(&pool, &idp).await;

    let (status, redirect) =
        do_login_query(build_state(pool.clone()), provider_id, "prompt=none").await;
    assert_eq!(status, StatusCode::TEMPORARY_REDIRECT, "login must 307");
    let redirect = redirect.expect("login must set Location");
    assert_eq!(
        redirect.get("prompt"),
        Some("none"),
        "prompt=none must be forwarded to the authorize URL, got {}",
        redirect.location
    );
    // The rest of the ordinary flow is unchanged.
    assert_eq!(redirect.get("response_type"), Some("code"));
    assert_eq!(redirect.get("client_id"), Some(TEST_CLIENT_ID));

    // The explicit button path (no prompt param) must NOT grow a prompt.
    let (status, redirect) = do_login(build_state(pool.clone()), provider_id).await;
    assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
    let redirect = redirect.expect("login must set Location");
    assert_eq!(
        redirect.get("prompt"),
        None,
        "the explicit sign-in flow must never carry a prompt parameter"
    );

    delete_provider(&pool, provider_id).await;
}

/// Any prompt value other than `none` is rejected with a 400 before any SSO
/// session is created.
#[tokio::test]
#[ignore = "requires DATABASE_URL + non-loopback IP"]
async fn test_oidc_login_prompt_other_values_rejected() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let Some(idp) = MockIdp::start().await else {
        return;
    };
    let provider_id = create_provider(&pool, &idp).await;

    let (status, _redirect) =
        do_login_query(build_state(pool.clone()), provider_id, "prompt=login").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "prompt values other than none must be rejected"
    );

    delete_provider(&pool, provider_id).await;
}

/// The "no live IdP session" answer to a silent probe (`error=login_required`)
/// must produce a clean 307 to `/callback?silent_denied=1` — no error status,
/// no error payload — and must consume the one-time SSO session so the state
/// cannot be replayed afterwards.
#[tokio::test]
#[ignore = "requires DATABASE_URL + non-loopback IP"]
async fn test_oidc_callback_login_required_redirects_silent_denied() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let Some(idp) = MockIdp::start().await else {
        return;
    };
    let provider_id = create_provider(&pool, &idp).await;

    let (sso_state, _nonce) = login_state_nonce(&pool, provider_id).await;

    let resp = do_callback(
        build_state(pool.clone()),
        provider_id,
        &format!(
            "error=login_required&error_description=Authentication%20required&state={}",
            urlencoding::encode(&sso_state)
        ),
    )
    .await;

    assert_eq!(
        resp.status(),
        StatusCode::TEMPORARY_REDIRECT,
        "a denied silent probe is not an error; it must 307 back to the frontend"
    );
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("silent-denied redirect must set Location");
    assert_eq!(
        location, "/callback?silent_denied=1",
        "silent denial must land on the frontend callback with the marker and nothing else"
    );

    // The one-time session was consumed: replaying the state with a code now
    // hits the CSRF replay defense.
    let replay = do_callback_state(&pool, provider_id, &sso_state).await;
    assert_eq!(
        replay.status(),
        StatusCode::UNAUTHORIZED,
        "the silent-denied path must burn the single-use SSO session"
    );

    delete_provider(&pool, provider_id).await;
}

/// Same contract on the generic (provider-less) callback route, which is the
/// redirect URI production IdPs are configured with.
#[tokio::test]
#[ignore = "requires DATABASE_URL + non-loopback IP"]
async fn test_oidc_generic_callback_login_required_redirects_silent_denied() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let Some(idp) = MockIdp::start().await else {
        return;
    };
    let provider_id = create_provider(&pool, &idp).await;

    let (sso_state, _nonce) = login_state_nonce(&pool, provider_id).await;

    let app = sso_app(build_state(pool.clone()));
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/oidc/callback?error=interaction_required&state={}",
                    urlencoding::encode(&sso_state)
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("generic callback oneshot");

    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("Location");
    assert_eq!(location, "/callback?silent_denied=1");

    delete_provider(&pool, provider_id).await;
}

// ===========================================================================
// Token request carries `scope` (#4699)
// ===========================================================================

/// The form fields the backend POSTed to the mock token endpoint (the last
/// token request received).
async fn last_token_request_form(idp: &MockIdp) -> HashMap<String, String> {
    let requests = idp
        .server
        .received_requests()
        .await
        .expect("wiremock request recording is on");
    let token_req = requests
        .iter()
        .rev()
        .find(|r| r.url.path() == "/token")
        .expect("backend POSTed to the token endpoint");
    url::form_urlencoded::parse(&token_req.body)
        .into_owned()
        .collect()
}

/// #4699: Microsoft Entra's v2 token endpoint returns an `id_token` only when
/// the token request itself carries the `openid` scope, so the code exchange
/// must repeat the provider's configured scopes (RFC 6749 permits `scope` on
/// the token request). Before the fix the form had no `scope` field at all.
#[tokio::test]
#[ignore = "requires DATABASE_URL + non-loopback IP"]
async fn test_oidc_token_request_sends_configured_scopes() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let Some(idp) = MockIdp::start().await else {
        return;
    };
    let provider_id = create_provider(&pool, &idp).await;

    let (sso_state, nonce) = login_state_nonce(&pool, provider_id).await;
    idp.mount_token_endpoint(&nonce, json!({ "sub": "oidc-sub-4699-scope" }))
        .await;

    let resp = do_callback_state(&pool, provider_id, &sso_state).await;
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);

    let form = last_token_request_form(&idp).await;
    assert_eq!(
        form.get("scope").map(String::as_str),
        Some("openid profile email"),
        "token request must repeat the configured scopes, got form {form:?}"
    );
    assert_eq!(
        form.get("grant_type").map(String::as_str),
        Some("authorization_code")
    );

    delete_user_by_sub(&pool, "oidc-sub-4699-scope").await;
    delete_provider(&pool, provider_id).await;
}

/// #4699: a token response without `id_token` is an IdP-side problem. It must
/// surface as a 502 that names the provider and says the IdP returned no
/// id_token, not as an opaque 500 `INTERNAL_ERROR`.
#[tokio::test]
#[ignore = "requires DATABASE_URL + non-loopback IP"]
#[allow(clippy::disallowed_methods)] // streaming-invariant: test exempt — buffering a small JSON error body in a test assertion is not an artifact path (#1608)
async fn test_oidc_token_response_without_id_token_is_502_naming_provider() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let Some(idp) = MockIdp::start().await else {
        return;
    };
    let provider_id = create_provider(&pool, &idp).await;
    let provider_name: String = sqlx::query_scalar("SELECT name FROM oidc_configs WHERE id = $1")
        .bind(provider_id)
        .fetch_one(&pool)
        .await
        .expect("provider name");

    let (sso_state, _nonce) = login_state_nonce(&pool, provider_id).await;
    Mock::given(method("POST"))
        .and(wm_path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "mock-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        })))
        .mount(&idp.server)
        .await;

    let resp = do_callback_state(&pool, provider_id, &sso_state).await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .expect("body");
    let body: Value = serde_json::from_slice(&body).expect("json error body");
    assert_eq!(body["code"], "OIDC_NO_ID_TOKEN", "body: {body}");
    let message = body["message"].as_str().unwrap_or_default();
    assert!(
        message.contains(&provider_name) && message.contains("id_token"),
        "message must name the provider and the missing id_token: {message}"
    );

    delete_provider(&pool, provider_id).await;
}

// ===========================================================================
// Request-derived redirect_uri behind a reverse proxy (#4143)
// ===========================================================================

/// Drive `GET /oidc/{id}/login` as if the TCP peer were `peer`, with the
/// headers a TLS-terminating proxy sets, and return the `redirect_uri` sent
/// to the IdP.
async fn login_redirect_uri_from_peer(
    state: SharedState,
    provider_id: Uuid,
    peer: std::net::SocketAddr,
) -> String {
    let mut req = Request::builder()
        .method("GET")
        .uri(format!("/oidc/{provider_id}/login"))
        .header("host", "backend.internal:8080")
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-host", "ak.example.test")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(peer));
    let resp = sso_app(state).oneshot(req).await.expect("login oneshot");
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let query = location.split_once('?').map(|(_, q)| q).unwrap_or("");
    url_decode_query(query)
        .remove("redirect_uri")
        .expect("redirect_uri on the authorize URL")
}

/// #4143: with `RATE_LIMIT_TRUSTED_PROXY_CIDRS` set, `X-Forwarded-Proto` /
/// `X-Forwarded-Host` decide the OIDC `redirect_uri` only when the TCP peer is
/// one of those proxies. Behind a trusted proxy that sets
/// `X-Forwarded-Proto: https` the redirect_uri is `https://`; the same headers
/// from an untrusted peer are ignored (before the fix they were believed from
/// any peer, so a client could steer the redirect_uri sent to the IdP).
#[tokio::test]
#[ignore = "requires DATABASE_URL + non-loopback IP"]
async fn test_oidc_redirect_uri_forwarded_headers_only_from_trusted_proxy() {
    if std::env::var("AK_EXTERNAL_URL").is_ok() {
        // AK_EXTERNAL_URL overrides every request-derived base URL.
        return;
    }
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
            pin_redirect_uri: false,
            ..Default::default()
        },
    )
    .await;

    let mut cfg = test_config();
    cfg.rate_limit_trusted_proxy_cidrs = vec![
        artifact_keeper_backend::api::middleware::rate_limit::CidrRange::parse("10.0.0.0/8")
            .unwrap(),
    ];
    let state = build_state_with_config(pool.clone(), cfg);

    let trusted = login_redirect_uri_from_peer(
        state.clone(),
        provider_id,
        "10.20.30.40:51000".parse().unwrap(),
    )
    .await;
    assert_eq!(
        trusted, "https://ak.example.test/api/v1/auth/sso/oidc/callback",
        "a trusted proxy's X-Forwarded-Proto/Host must decide the redirect_uri"
    );

    let untrusted =
        login_redirect_uri_from_peer(state, provider_id, "203.0.113.7:51000".parse().unwrap())
            .await;
    assert_eq!(
        untrusted, "http://backend.internal:8080/api/v1/auth/sso/oidc/callback",
        "forwarding headers from an untrusted peer must be ignored"
    );

    delete_provider(&pool, provider_id).await;
}

// ===========================================================================
// SSO session lifetime is reported to the client (#4648)
// ===========================================================================

/// #4648: login sessions are short-lived, so every login response must say
/// how long the access token lives. `POST /auth/login` already returns
/// `expires_in`; the SSO exchange (`POST /sso/exchange`, which hands the
/// browser its OIDC/SAML session) did not. It must report the configured
/// `JWT_ACCESS_TOKEN_EXPIRY_MINUTES`, here set to a non-default 45.
#[tokio::test]
#[ignore = "requires DATABASE_URL + non-loopback IP"]
#[allow(clippy::disallowed_methods)] // streaming-invariant: test exempt — buffering a small JSON body in a test assertion is not an artifact path (#1608)
async fn test_sso_exchange_reports_configured_expires_in() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let Some(idp) = MockIdp::start().await else {
        return;
    };
    let provider_id = create_provider(&pool, &idp).await;
    let (sso_state, nonce) = login_state_nonce(&pool, provider_id).await;
    let external_id = format!("oidc-sub-4648-{}", Uuid::new_v4().as_simple());
    idp.mount_token_endpoint(&nonce, json!({ "sub": external_id }))
        .await;

    let mut cfg = test_config();
    cfg.jwt_access_token_expiry_minutes = 45;
    let state = build_state_with_config(pool.clone(), cfg);

    let resp = do_callback(
        state.clone(),
        provider_id,
        &format!(
            "code=mock-auth-code&state={}",
            urlencoding::encode(&sso_state)
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = resp.headers()["location"].to_str().unwrap().to_string();
    let code = url_decode_query(location.split_once('?').map(|(_, q)| q).unwrap_or(""))
        .remove("code")
        .expect("exchange code on the frontend redirect");

    let resp = sso_app(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/exchange")
                .header("content-type", "application/json")
                .body(Body::from(json!({ "code": code }).to_string()))
                .unwrap(),
        )
        .await
        .expect("exchange oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .expect("body");
    let body: Value = serde_json::from_slice(&body).expect("json body");
    assert_eq!(body["token_type"], "Bearer");
    let expires_in = body["expires_in"]
        .as_u64()
        .unwrap_or_else(|| panic!("exchange response must carry expires_in: {body}"));
    assert!(
        (45 * 60 - 10..=45 * 60).contains(&expires_in),
        "expires_in must be the configured 45-minute lifetime, got {expires_in}"
    );

    delete_user_by_sub(&pool, &external_id).await;
    delete_provider(&pool, provider_id).await;
}

// ===========================================================================
// #5482: id_token claim strictness and disabled providers
// ===========================================================================

/// Run one login + callback whose token endpoint returns `id_token`, and
/// return the callback status.
async fn callback_with_id_token(
    pool: &PgPool,
    idp: &MockIdp,
    provider_id: Uuid,
    id_token: impl FnOnce(&str) -> String,
) -> StatusCode {
    let (sso_state, nonce) = login_state_nonce(pool, provider_id).await;
    idp.mount_id_token_once(id_token(&nonce)).await;
    do_callback_state(pool, provider_id, &sso_state)
        .await
        .status()
}

/// #5482 item 1: a validly signed id_token with no `aud`, `aud: null`, a
/// non-string `aud`, or no `iss` is refused. `jsonwebtoken` only compares the
/// two when present, so each of these used to sign the user in.
#[tokio::test]
#[ignore = "requires DATABASE_URL + non-loopback IP"]
async fn test_oidc_callback_id_token_without_aud_or_iss_returns_401() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let Some(idp) = MockIdp::start().await else {
        return;
    };
    let provider_id = create_provider(&pool, &idp).await;

    let cases: [(&str, Value, &[&str]); 4] = [
        ("no aud", json!({}), &["aud"]),
        ("aud: null", json!({ "aud": null }), &[]),
        ("aud: 42", json!({ "aud": 42 }), &[]),
        ("no iss", json!({}), &["iss"]),
    ];
    for (case, extra, omit) in cases {
        let sub = format!("oidc-sub-5482-{}", Uuid::new_v4().as_simple());
        let mut claims = extra;
        claims["sub"] = json!(sub);
        let status = callback_with_id_token(&pool, &idp, provider_id, |nonce| {
            idp.sign_id_token_omitting(nonce, claims, omit)
        })
        .await;
        let provisioned = get_user(&pool, &sub).await.is_some();
        delete_user_by_sub(&pool, &sub).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{case}");
        assert!(!provisioned, "{case}: no account");
    }

    delete_provider(&pool, provider_id).await;
}

/// #5482 item 3: `sub: ""` (or whitespace) is not a federated identity. It
/// used to provision one account that every such token then signed in as.
#[tokio::test]
#[ignore = "requires DATABASE_URL + non-loopback IP"]
async fn test_oidc_callback_blank_sub_returns_401() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let Some(idp) = MockIdp::start().await else {
        return;
    };
    let provider_id = create_provider(&pool, &idp).await;

    for blank in ["", "   "] {
        let status = callback_with_id_token(&pool, &idp, provider_id, |nonce| {
            idp.sign_id_token(nonce, json!({ "sub": blank }))
        })
        .await;
        let provisioned = get_user(&pool, blank).await.is_some();
        delete_user_by_sub(&pool, blank).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "sub {blank:?}");
        assert!(!provisioned, "sub {blank:?}: no account");
    }

    delete_provider(&pool, provider_id).await;
}

async fn set_oidc_enabled(pool: &PgPool, id: Uuid, enabled: bool) {
    AuthConfigService::toggle_oidc(
        pool,
        id,
        artifact_keeper_backend::services::auth_config_service::ToggleRequest { enabled },
    )
    .await
    .expect("toggle oidc provider");
}

/// #5482 item 2: a disabled OIDC provider starts no login (404, like a
/// missing one), and a login started before it was disabled cannot be
/// completed.
#[tokio::test]
#[ignore = "requires DATABASE_URL + non-loopback IP"]
async fn test_oidc_disabled_provider_cannot_log_in() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let Some(idp) = MockIdp::start().await else {
        return;
    };
    let provider_id = create_provider(&pool, &idp).await;

    // A login that is already in flight when the operator disables it.
    let (sso_state, nonce) = login_state_nonce(&pool, provider_id).await;
    let sub = format!("oidc-sub-5482-disabled-{}", Uuid::new_v4().as_simple());
    idp.mount_token_endpoint(&nonce, json!({ "sub": sub }))
        .await;
    set_oidc_enabled(&pool, provider_id, false).await;

    let (status, _) = do_login(build_state(pool.clone()), provider_id).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "login on a disabled provider"
    );

    let resp = do_callback_state(&pool, provider_id, &sso_state).await;
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "callback on a disabled provider"
    );
    let provisioned = get_user(&pool, &sub).await.is_some();
    delete_user_by_sub(&pool, &sub).await;
    assert!(!provisioned, "no account");

    delete_provider(&pool, provider_id).await;
}

/// #5482 item 2: `POST /ldap/{id}/login` on a disabled provider is refused
/// before the directory is contacted.
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_ldap_login_on_disabled_provider_returns_404() {
    use artifact_keeper_backend::services::auth_config_service::{
        CreateLdapConfigRequest, ToggleRequest,
    };
    let Some(pool) = try_pool().await else {
        return;
    };
    ensure_sso_encryption_key();
    let created = AuthConfigService::create_ldap(
        &pool,
        CreateLdapConfigRequest {
            name: format!("e2e-ldap-{}", Uuid::new_v4().as_simple()),
            server_url: "ldap://127.0.0.1:1".into(),
            bind_dn: None,
            bind_password: None,
            user_base_dn: "ou=users,dc=example,dc=test".into(),
            user_filter: None,
            group_base_dn: None,
            group_filter: None,
            email_attribute: None,
            display_name_attribute: None,
            username_attribute: None,
            groups_attribute: None,
            admin_group_dn: None,
            use_starttls: None,
            insecure_skip_verify: None,
            ca_certificate: None,
            is_enabled: Some(true),
            priority: None,
        },
    )
    .await
    .expect("create ldap provider");
    AuthConfigService::toggle_ldap(&pool, created.id, ToggleRequest { enabled: false })
        .await
        .expect("disable ldap provider");

    let resp = sso_app(build_state(pool.clone()))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ldap/{}/login", created.id))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "username": "alice", "password": "pw" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("ldap login oneshot");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let _ = AuthConfigService::delete_ldap(&pool, created.id).await;
}

/// #5483: two OIDC providers that both issue one `sub` (two GitLab instances
/// numbering users from 1) sign in to two accounts, each bound to its own
/// provider. Before the fix the second provider's callback signed in as the
/// first provider's user and overwrote its username and email.
#[tokio::test]
#[ignore = "requires DATABASE_URL + non-loopback IP"]
async fn test_oidc_same_sub_at_two_providers_signs_in_two_accounts_5483() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let (Some(idp_a), Some(idp_b)) = (MockIdp::start().await, MockIdp::start().await) else {
        return;
    };
    let provider_a = create_provider(&pool, &idp_a).await;
    let provider_b = create_provider(&pool, &idp_b).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let sub = format!("oidc-sub-5483-{suffix}");

    for (idp, provider_id, who) in [
        (&idp_a, provider_a, "victim"),
        (&idp_b, provider_b, "intruder"),
    ] {
        let (sso_state, nonce) = login_state_nonce(&pool, provider_id).await;
        idp.mount_token_endpoint(
            &nonce,
            json!({
                "sub": sub,
                "preferred_username": format!("{who}-5483-{suffix}"),
                "email": format!("{who}-5483-{suffix}@example.test"),
            }),
        )
        .await;
        let resp = do_callback_state(&pool, provider_id, &sso_state).await;
        assert_eq!(
            resp.status(),
            StatusCode::TEMPORARY_REDIRECT,
            "{who}'s callback must sign in"
        );
    }

    let rows: Vec<(String, Option<String>, Option<Uuid>)> = sqlx::query_as(
        "SELECT username, email, auth_provider_id FROM users \
         WHERE external_id = $1 AND auth_provider = 'oidc' ORDER BY username",
    )
    .bind(&sub)
    .fetch_all(&pool)
    .await
    .expect("accounts for the shared sub");
    assert_eq!(
        rows,
        vec![
            (
                format!("intruder-5483-{suffix}"),
                Some(format!("intruder-5483-{suffix}@example.test")),
                Some(provider_b),
            ),
            (
                format!("victim-5483-{suffix}"),
                Some(format!("victim-5483-{suffix}@example.test")),
                Some(provider_a),
            ),
        ],
        "the same sub at a second provider must be a second account"
    );

    delete_user_by_sub(&pool, &sub).await;
    delete_provider(&pool, provider_a).await;
    delete_provider(&pool, provider_b).await;
}
