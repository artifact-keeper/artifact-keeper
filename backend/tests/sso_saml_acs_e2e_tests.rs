//! End-to-end coverage for the SAML ACS (Assertion Consumer Service) flow
//! (#2212, part of #1617, epic #1615).
//!
//! These tests drive the real axum handlers in `api::handlers::sso`
//! (`saml_login` → `saml_acs`, `sso::router()`) against a throwaway Postgres.
//! Unlike OIDC, `saml_acs` performs NO outbound fetch — the assertion
//! signature is verified against the DB-stored provider `certificate` via
//! `bergshamra` — so the mock IdP is an in-process signer, not an HTTP server,
//! and there is no wiremock / SSRF / non-loopback concern here. We still reuse
//! `common::sso_support` for the throwaway-pool / state / app builders and for
//! the signer + ephemeral IdP keypair.
//!
//! Assertions are signed with the SAME crate the app verifies them with
//! (`bergshamra::sign` + `keys::loader::load_rsa_private_pem`) over an
//! EPHEMERAL RSA keypair generated once per test process (no key material is
//! checked into the repo); its matching self-signed X.509 cert is minted
//! in-memory and stored verbatim as the provider `certificate`. No new
//! dependency is added.
//!
//! Regression cases covered:
//!   - happy path: valid signed assertion → 307 to `/callback?code=…`, auth
//!     cookies set, user provisioned with mapped username/email/groups.
//!   - signature invalid → 401 (tampered digest, and a different signing key
//!     not matching the provider cert).
//!   - InResponseTo single-use replay / CSRF (locks in #2040): unsolicited (no
//!     InResponseTo), unknown InResponseTo, and a valid response replayed a
//!     second time — all 401.
//!   - absolute-vs-relative ACS: `Destination`/`Recipient` binding against the
//!     SP ACS URL (with `AK_EXTERNAL_URL` set), across a
//!     `use_absolute_acs_url` provider pair — matching accepted, mismatch 401.
//!   - group → role mapping: admin group present → admin user; absent →
//!     non-admin.
//!   - audit: happy path emits `LOGIN` `details.provider="saml"`; a rejected
//!     assertion emits `LOGIN_FAILED` `details.provider="saml"`.
//!   - login → acs full flow: `GET /saml/{id}/login` persists a pending
//!     session whose id is echoed back as `InResponseTo`.
//!
//! Requires PostgreSQL with all migrations applied. Skips cleanly when
//! `DATABASE_URL` is unset (matching the repo `--ignored` convention via
//! `try_pool`).
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:5432/artifact_registry" \
//!   cargo test --test sso_saml_acs_e2e_tests -- --ignored --test-threads=1
//! ```

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use rsa::pkcs8::EncodePrivateKey;
use rsa::RsaPrivateKey;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use artifact_keeper_backend::api::SharedState;
use artifact_keeper_backend::services::audit_service::AuditService;
use artifact_keeper_backend::services::auth_config_service::{
    AuthConfigService, CreateSamlConfigRequest,
};

use common::sso_support::{
    base64_standard, build_state, ensure_sso_encryption_key, saml_idp_cert_pem, sign_saml_document,
    sign_saml_document_with_key, sso_app, try_pool, SamlResponseSpec,
};

// ===========================================================================
// Fixtures
// ===========================================================================

const IDP_ENTITY_ID: &str = "https://idp.saml-e2e.test";
const IDP_SSO_URL: &str = "https://idp.saml-e2e.test/sso";
const SP_ENTITY_ID: &str = "artifact-keeper";
/// Trusted external base; drives the `Destination`/`Recipient` ACS binding.
const SP_EXTERNAL_URL: &str = "https://sp.saml-e2e.test";

/// Set the process-global env this suite depends on. `AK_EXTERNAL_URL` is read
/// once and cached (`OnceLock`) by `configured_external_url`, so we set a fixed
/// value up front; running `--test-threads=1` keeps that write race-free.
fn ensure_saml_env() {
    ensure_sso_encryption_key();
    if std::env::var("AK_EXTERNAL_URL").is_err() {
        std::env::set_var("AK_EXTERNAL_URL", SP_EXTERNAL_URL);
    }
}

/// The absolute ACS URL the SP binds `Destination`/`Recipient` against when
/// `AK_EXTERNAL_URL` is set (mirrors `build_saml_acs_url(true, base, id)`).
fn expected_acs(provider_id: Uuid) -> String {
    format!("{SP_EXTERNAL_URL}/api/v1/auth/sso/saml/{provider_id}/acs")
}

#[derive(Default)]
struct SamlProviderOpts {
    admin_group: Option<String>,
    use_absolute_acs_url: bool,
}

/// Insert an enabled SAML provider that trusts the ephemeral IdP cert and
/// requires signed assertions.
async fn create_saml_provider(pool: &PgPool, opts: SamlProviderOpts) -> Uuid {
    ensure_saml_env();
    let resp = AuthConfigService::create_saml(
        pool,
        CreateSamlConfigRequest {
            name: format!("e2e-saml-{}", Uuid::new_v4().as_simple()),
            entity_id: IDP_ENTITY_ID.to_string(),
            sso_url: IDP_SSO_URL.to_string(),
            slo_url: None,
            certificate: saml_idp_cert_pem().to_string(),
            name_id_format: None,
            attribute_mapping: None,
            sp_entity_id: Some(SP_ENTITY_ID.to_string()),
            sign_requests: Some(false),
            require_signed_assertions: Some(true),
            admin_group: opts.admin_group,
            is_enabled: Some(true),
            use_absolute_acs_url: Some(opts.use_absolute_acs_url),
        },
    )
    .await
    .expect("create saml provider");
    resp.id
}

async fn delete_saml_provider(pool: &PgPool, id: Uuid) {
    let _ = AuthConfigService::delete_saml(pool, id).await;
}

async fn delete_saml_user(pool: &PgPool, external_id: &str) {
    let _ = sqlx::query(
        "DELETE FROM user_group_members WHERE user_id IN \
         (SELECT id FROM users WHERE external_id = $1 AND auth_provider = 'saml')",
    )
    .bind(external_id)
    .execute(pool)
    .await;
    let _ = sqlx::query("DELETE FROM users WHERE external_id = $1 AND auth_provider = 'saml'")
        .bind(external_id)
        .execute(pool)
        .await;
}

/// Look up a provisioned SAML user by `external_id` (the assertion NameID).
async fn get_saml_user(
    pool: &PgPool,
    external_id: &str,
) -> Option<(Uuid, String, Option<String>, bool)> {
    sqlx::query_as(
        "SELECT id, username, email, is_admin FROM users \
         WHERE external_id = $1 AND auth_provider = 'saml'",
    )
    .bind(external_id)
    .fetch_optional(pool)
    .await
    .expect("saml user lookup")
}

/// Seed a pending SAML SSO session and return the `request_id` (the value the
/// signed `<Response>` must echo back as `InResponseTo`).
async fn seed_session(pool: &PgPool, provider_id: Uuid) -> String {
    let request_id = format!("_req{}", Uuid::new_v4().as_simple());
    AuthConfigService::create_sso_session_with_state(pool, "saml", provider_id, &request_id)
        .await
        .expect("seed sso session");
    request_id
}

/// POST a base64 `SAMLResponse` to the real `saml_acs` route.
async fn post_acs(
    state: SharedState,
    provider_id: Uuid,
    saml_response_b64: &str,
) -> axum::response::Response {
    let app = sso_app(state);
    let body = format!("SAMLResponse={}", urlencoding::encode(saml_response_b64));
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(format!("/saml/{provider_id}/acs"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap(),
    )
    .await
    .expect("acs oneshot")
}

fn happy_spec(request_id: &str, name_id: &str) -> SamlResponseSpec {
    SamlResponseSpec::new(IDP_ENTITY_ID, SP_ENTITY_ID, request_id, name_id)
}

// ===========================================================================
// Tests
// ===========================================================================

/// Happy path: a validly signed assertion with a matching `InResponseTo`
/// establishes a session (307 to the frontend `/callback` with auth cookies)
/// and provisions the user with the mapped username/email.
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_saml_acs_happy_path() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let provider_id = create_saml_provider(&pool, SamlProviderOpts::default()).await;

    let name_id = format!("saml-happy-{}", Uuid::new_v4().as_simple());
    let request_id = seed_session(&pool, provider_id).await;
    let spec = happy_spec(&request_id, &name_id);

    let resp = post_acs(build_state(pool.clone()), provider_id, &spec.signed_b64()).await;

    assert_eq!(
        resp.status(),
        StatusCode::TEMPORARY_REDIRECT,
        "a valid signed assertion must 307 to the frontend"
    );
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        location.starts_with("/callback?code="),
        "must redirect to frontend /callback with an exchange code, got {location}"
    );
    assert!(
        resp.headers().get_all("set-cookie").iter().count() > 0,
        "the ACS redirect must set auth cookies (#1405)"
    );

    let user = get_saml_user(&pool, &name_id)
        .await
        .expect("ACS must provision the federated user");
    let (_, username, email, _is_admin) = user;
    assert_eq!(username, name_id, "username defaults to the NameID");
    assert_eq!(
        email.as_deref(),
        Some(format!("{name_id}@saml-e2e.test").as_str()),
        "email must come from the `email` attribute"
    );

    delete_saml_user(&pool, &name_id).await;
    delete_saml_provider(&pool, provider_id).await;
}

/// Signature invalid → 401. Two variants: (a) tamper an attribute value AFTER
/// signing so the digest no longer matches; (b) sign with a different key that
/// does not match the provider certificate.
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_saml_acs_invalid_signature_rejected() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let provider_id = create_saml_provider(&pool, SamlProviderOpts::default()).await;

    // (a) tampered digest: mutate a signed attribute value.
    let name_id_a = format!("saml-tamper-{}", Uuid::new_v4().as_simple());
    let request_id_a = seed_session(&pool, provider_id).await;
    let signed = sign_saml_document(&happy_spec(&request_id_a, &name_id_a).to_unsigned_xml());
    let tampered = signed.replacen("SAML E2E User", "TAMPERED VALUE", 1);
    assert_ne!(signed, tampered, "the tamper must actually change the XML");
    let resp = post_acs(
        build_state(pool.clone()),
        provider_id,
        &base64_standard(tampered.as_bytes()),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "a tampered assertion (broken digest) must be rejected"
    );

    // (b) wrong key: sign with a fresh RSA key the provider cert does not match.
    let name_id_b = format!("saml-wrongkey-{}", Uuid::new_v4().as_simple());
    let request_id_b = seed_session(&pool, provider_id).await;
    let mut rng = rsa::rand_core::OsRng;
    let other = RsaPrivateKey::new(&mut rng, 2048).expect("gen rsa key");
    let other_pem = other
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .expect("pkcs8 pem");
    let signed_other = sign_saml_document_with_key(
        other_pem.as_bytes(),
        &happy_spec(&request_id_b, &name_id_b).to_unsigned_xml(),
    );
    let resp = post_acs(
        build_state(pool.clone()),
        provider_id,
        &base64_standard(signed_other.as_bytes()),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "an assertion signed by an untrusted key must be rejected"
    );

    // Neither rejected attempt may have provisioned a user.
    assert!(get_saml_user(&pool, &name_id_a).await.is_none());
    assert!(get_saml_user(&pool, &name_id_b).await.is_none());

    delete_saml_provider(&pool, provider_id).await;
}

/// InResponseTo single-use replay / CSRF (locks in #2040):
///   (a) no `InResponseTo` (unsolicited / IdP-initiated) → 401,
///   (b) unknown `InResponseTo` → 401,
///   (c) replay: a valid response accepted once, then re-POSTed → 401.
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_saml_acs_replay_and_unsolicited_rejected() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let provider_id = create_saml_provider(&pool, SamlProviderOpts::default()).await;

    // (a) unsolicited: no InResponseTo at all.
    let name_id_a = format!("saml-unsol-{}", Uuid::new_v4().as_simple());
    let mut unsolicited = happy_spec("_ignored", &name_id_a);
    unsolicited.in_response_to = None;
    let resp = post_acs(
        build_state(pool.clone()),
        provider_id,
        &unsolicited.signed_b64(),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "an unsolicited (no InResponseTo) response must be rejected"
    );
    assert!(get_saml_user(&pool, &name_id_a).await.is_none());

    // (b) unknown InResponseTo: no matching pending session was seeded.
    let name_id_b = format!("saml-unknown-{}", Uuid::new_v4().as_simple());
    let unknown = happy_spec(&format!("_req{}", Uuid::new_v4().as_simple()), &name_id_b);
    let resp = post_acs(
        build_state(pool.clone()),
        provider_id,
        &unknown.signed_b64(),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "an unknown InResponseTo must be rejected"
    );
    assert!(get_saml_user(&pool, &name_id_b).await.is_none());

    // (c) replay: same response accepted once, then rejected on re-use.
    let name_id_c = format!("saml-replay-{}", Uuid::new_v4().as_simple());
    let request_id_c = seed_session(&pool, provider_id).await;
    let signed = happy_spec(&request_id_c, &name_id_c).signed_b64();

    let first = post_acs(build_state(pool.clone()), provider_id, &signed).await;
    assert_eq!(
        first.status(),
        StatusCode::TEMPORARY_REDIRECT,
        "the first use of a valid response must succeed"
    );
    let second = post_acs(build_state(pool.clone()), provider_id, &signed).await;
    assert_eq!(
        second.status(),
        StatusCode::UNAUTHORIZED,
        "replaying the same response (InResponseTo already consumed) must be rejected"
    );

    delete_saml_user(&pool, &name_id_c).await;
    delete_saml_provider(&pool, provider_id).await;
}

/// Absolute-vs-relative ACS: with `AK_EXTERNAL_URL` set, an assertion whose
/// `Destination`/`Recipient` matches the SP ACS URL is accepted, and a
/// mismatch is rejected — in BOTH `use_absolute_acs_url` provider modes (the
/// binding is derived from the trusted external URL regardless of the wire
/// format the AuthnRequest advertised, migration 139).
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_saml_acs_destination_recipient_binding() {
    let Some(pool) = try_pool().await else {
        return;
    };

    for use_absolute in [false, true] {
        let provider_id = create_saml_provider(
            &pool,
            SamlProviderOpts {
                use_absolute_acs_url: use_absolute,
                ..SamlProviderOpts::default()
            },
        )
        .await;
        let acs = expected_acs(provider_id);

        // Matching Destination + Recipient → accepted.
        let name_id_ok = format!("saml-acs-ok-{}", Uuid::new_v4().as_simple());
        let request_id_ok = seed_session(&pool, provider_id).await;
        let mut ok = happy_spec(&request_id_ok, &name_id_ok);
        ok.destination = Some(acs.clone());
        ok.recipient = Some(acs.clone());
        let resp = post_acs(build_state(pool.clone()), provider_id, &ok.signed_b64()).await;
        assert_eq!(
            resp.status(),
            StatusCode::TEMPORARY_REDIRECT,
            "matching Destination/Recipient must be accepted (use_absolute={use_absolute})"
        );
        delete_saml_user(&pool, &name_id_ok).await;

        // Mismatched Destination → rejected.
        let name_id_bad = format!("saml-acs-bad-{}", Uuid::new_v4().as_simple());
        let request_id_bad = seed_session(&pool, provider_id).await;
        let mut bad = happy_spec(&request_id_bad, &name_id_bad);
        bad.destination = Some("https://evil.attacker.test/api/v1/auth/sso/saml/x/acs".to_string());
        bad.recipient = Some(acs.clone());
        let resp = post_acs(build_state(pool.clone()), provider_id, &bad.signed_b64()).await;
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "a Destination that is not this SP's ACS URL must be rejected (use_absolute={use_absolute})"
        );
        assert!(get_saml_user(&pool, &name_id_bad).await.is_none());

        delete_saml_provider(&pool, provider_id).await;
    }
}

/// Group → role mapping: the configured admin group in the assertion promotes
/// the user to admin; its absence yields a non-admin user.
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_saml_acs_admin_group_mapping() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let provider_id = create_saml_provider(
        &pool,
        SamlProviderOpts {
            admin_group: Some("ak-admins".to_string()),
            ..SamlProviderOpts::default()
        },
    )
    .await;

    // With the admin group → is_admin = true.
    let name_id_admin = format!("saml-admin-{}", Uuid::new_v4().as_simple());
    let request_id_admin = seed_session(&pool, provider_id).await;
    let mut admin_spec = happy_spec(&request_id_admin, &name_id_admin);
    admin_spec.groups = vec!["ak-admins".to_string(), "Developers".to_string()];
    let resp = post_acs(
        build_state(pool.clone()),
        provider_id,
        &admin_spec.signed_b64(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    let (_, _, _, is_admin) = get_saml_user(&pool, &name_id_admin)
        .await
        .expect("admin user provisioned");
    assert!(is_admin, "the configured admin group must grant is_admin");

    // Without the admin group → is_admin = false.
    let name_id_plain = format!("saml-plain-{}", Uuid::new_v4().as_simple());
    let request_id_plain = seed_session(&pool, provider_id).await;
    let mut plain_spec = happy_spec(&request_id_plain, &name_id_plain);
    plain_spec.groups = vec!["Developers".to_string()];
    let resp = post_acs(
        build_state(pool.clone()),
        provider_id,
        &plain_spec.signed_b64(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    let (_, _, _, is_admin) = get_saml_user(&pool, &name_id_plain)
        .await
        .expect("plain user provisioned");
    assert!(
        !is_admin,
        "a user without the configured admin group must not be admin"
    );

    delete_saml_user(&pool, &name_id_admin).await;
    delete_saml_user(&pool, &name_id_plain).await;
    delete_saml_provider(&pool, provider_id).await;
}

/// Audit: a happy-path login emits a `LOGIN` row with `details.provider="saml"`
/// for the provisioned user; a rejected assertion emits a `LOGIN_FAILED` row
/// with `details.provider="saml"`.
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_saml_acs_emits_audit_records() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let provider_id = create_saml_provider(&pool, SamlProviderOpts::default()).await;
    let audit = AuditService::new(pool.clone());

    // --- success → LOGIN ---
    let name_id = format!("saml-audit-ok-{}", Uuid::new_v4().as_simple());
    let request_id = seed_session(&pool, provider_id).await;
    let resp = post_acs(
        build_state(pool.clone()),
        provider_id,
        &happy_spec(&request_id, &name_id).signed_b64(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);

    let (user_id, _, _, _) = get_saml_user(&pool, &name_id).await.expect("provisioned");
    let (login_rows, _) = audit
        .query(Some(user_id), Some("LOGIN"), None, None, None, None, 0, 50)
        .await
        .expect("audit query LOGIN");
    assert!(
        login_rows.iter().any(|r| {
            r.resource_type == "user"
                && r.details
                    .as_ref()
                    .and_then(|d| d.get("provider"))
                    .and_then(|p| p.as_str())
                    == Some("saml")
        }),
        "a LOGIN audit row with details.provider=saml must exist for the user"
    );

    // --- failure → LOGIN_FAILED (unsolicited response, rejected before user sync) ---
    let mut unsolicited = happy_spec(
        "_ignored",
        &format!("saml-audit-fail-{}", Uuid::new_v4().as_simple()),
    );
    unsolicited.in_response_to = None;
    let resp = post_acs(
        build_state(pool.clone()),
        provider_id,
        &unsolicited.signed_b64(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let (fail_rows, _) = audit
        .query(None, Some("LOGIN_FAILED"), None, None, None, None, 0, 200)
        .await
        .expect("audit query LOGIN_FAILED");
    assert!(
        fail_rows.iter().any(|r| {
            r.details
                .as_ref()
                .and_then(|d| d.get("provider"))
                .and_then(|p| p.as_str())
                == Some("saml")
        }),
        "a LOGIN_FAILED audit row with details.provider=saml must exist"
    );

    delete_saml_user(&pool, &name_id).await;
    delete_saml_provider(&pool, provider_id).await;
}

/// Full flow: `GET /saml/{id}/login` persists a pending SSO session whose id is
/// the AuthnRequest id; echoing that back as `InResponseTo` on a signed
/// response drives a successful ACS. Locks the login→acs wiring, not just the
/// ACS half.
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_saml_login_then_acs_full_flow() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let provider_id = create_saml_provider(&pool, SamlProviderOpts::default()).await;

    // Drive the login redirect.
    let app = sso_app(build_state(pool.clone()));
    let login = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/saml/{provider_id}/login"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("login oneshot");
    assert_eq!(
        login.status(),
        StatusCode::TEMPORARY_REDIRECT,
        "SAML login must 307 to the IdP SSO URL"
    );

    // Read the pending AuthnRequest id the login persisted.
    let request_id: String = sqlx::query_scalar(
        "SELECT state FROM sso_sessions \
         WHERE provider_id = $1 AND provider_type = 'saml' \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(provider_id)
    .fetch_one(&pool)
    .await
    .expect("pending sso session state");
    assert!(
        request_id.starts_with("_id"),
        "the persisted state must be the AuthnRequest id, got {request_id}"
    );

    let name_id = format!("saml-fullflow-{}", Uuid::new_v4().as_simple());
    let resp = post_acs(
        build_state(pool.clone()),
        provider_id,
        &happy_spec(&request_id, &name_id).signed_b64(),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::TEMPORARY_REDIRECT,
        "the ACS callback for the login's own request_id must succeed"
    );
    assert!(
        get_saml_user(&pool, &name_id).await.is_some(),
        "the full flow must provision the user"
    );

    delete_saml_user(&pool, &name_id).await;
    delete_saml_provider(&pool, provider_id).await;
}
