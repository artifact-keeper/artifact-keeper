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
//!   - group → membership sync (#2333): with `map_groups_to_groups` enabled,
//!     assertion groups become AK group memberships (auto-created, tagged
//!     `external_source='saml'`), reconciled on re-login, and scoped so
//!     operator-managed and OIDC-managed memberships survive; with the flag
//!     off (the default), no memberships are touched.
//!   - audit: happy path emits `LOGIN` `details.provider="saml"`; a rejected
//!     assertion emits `LOGIN_FAILED` `details.provider="saml"`.
//!   - login → acs full flow: `GET /saml/{id}/login` persists a pending
//!     session whose id is echoed back as `InResponseTo`.
//!   - slug addressing (#2583): a provider with a `slug` authenticates at
//!     `/saml/{slug}/acs` and through the full login → ACS flow, with the
//!     `Destination`/`Recipient` binding derived from the segment the request
//!     arrived on; a provider WITHOUT a slug (every row that predates
//!     migration 218) still authenticates by UUID, unchanged.
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
    audit_row_eventually, base64_standard, build_state, ensure_sso_encryption_key,
    saml_idp_cert_pem, sign_saml_document, sign_saml_document_with_key, sso_app, try_pool,
    SamlResponseSpec,
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
/// `AK_EXTERNAL_URL` is set (mirrors `build_saml_acs_url(true, base, segment)`).
/// `segment` is the path segment the request is addressed by — the provider
/// UUID, or its slug once #2583 gave a configuration a second address.
fn expected_acs_for(segment: &str) -> String {
    format!("{SP_EXTERNAL_URL}/api/v1/auth/sso/saml/{segment}/acs")
}

fn expected_acs(provider_id: Uuid) -> String {
    expected_acs_for(&provider_id.to_string())
}

#[derive(Default)]
struct SamlProviderOpts {
    admin_group: Option<String>,
    use_absolute_acs_url: bool,
    map_groups_to_groups: bool,
    /// #2583: the optional URL-safe alias the public SAML routes accept in
    /// place of the UUID. `None` reproduces a configuration created before
    /// migration 218 — the shape every existing deployment is in.
    slug: Option<String>,
}

/// Insert an enabled SAML provider that trusts the ephemeral IdP cert and
/// requires signed assertions.
async fn create_saml_provider(pool: &PgPool, opts: SamlProviderOpts) -> Uuid {
    ensure_saml_env();
    let resp = AuthConfigService::create_saml(
        pool,
        CreateSamlConfigRequest {
            name: format!("e2e-saml-{}", Uuid::new_v4().as_simple()),
            slug: opts.slug,
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
            map_groups_to_groups: Some(opts.map_groups_to_groups),
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

/// POST a base64 `SAMLResponse` to the real `saml_acs` route, addressing the
/// provider by an arbitrary path segment (its UUID or, since #2583, its slug).
async fn post_acs_at(
    state: SharedState,
    segment: &str,
    saml_response_b64: &str,
) -> axum::response::Response {
    let app = sso_app(state);
    let body = format!("SAMLResponse={}", urlencoding::encode(saml_response_b64));
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(format!("/saml/{segment}/acs"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap(),
    )
    .await
    .expect("acs oneshot")
}

/// POST a base64 `SAMLResponse` to the real `saml_acs` route.
async fn post_acs(
    state: SharedState,
    provider_id: Uuid,
    saml_response_b64: &str,
) -> axum::response::Response {
    post_acs_at(state, &provider_id.to_string(), saml_response_b64).await
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

// ---------------------------------------------------------------------------
// Group → membership sync (#2333, parity with OIDC #1094)
// ---------------------------------------------------------------------------

async fn group_id_by_name(pool: &PgPool, name: &str) -> Option<Uuid> {
    sqlx::query_scalar("SELECT id FROM groups WHERE name = $1")
        .bind(name)
        .fetch_optional(pool)
        .await
        .expect("group lookup")
}

async fn group_external_source(pool: &PgPool, group_id: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT external_source FROM groups WHERE id = $1")
        .bind(group_id)
        .fetch_optional(pool)
        .await
        .expect("group source lookup")
        .flatten()
}

async fn user_is_in_group(pool: &PgPool, user_id: Uuid, group_id: Uuid) -> bool {
    sqlx::query_scalar::<_, Uuid>(
        "SELECT group_id FROM user_group_members WHERE user_id = $1 AND group_id = $2",
    )
    .bind(user_id)
    .bind(group_id)
    .fetch_optional(pool)
    .await
    .expect("membership lookup")
    .is_some()
}

async fn cleanup_groups(pool: &PgPool, ids: &[Uuid]) {
    for id in ids {
        let _ = sqlx::query("DELETE FROM user_group_members WHERE group_id = $1")
            .bind(id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM groups WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await;
    }
}

/// Issue #2333 happy path + reconcile + isolation, driven end-to-end through
/// the live ACS handler with signed assertions:
///   1. first login with groups [eng, ops] → both groups auto-created tagged
///      `external_source='saml'`, user a member of both;
///   2. re-login with [eng] only → ops membership pruned, eng survives;
///   3. an operator-managed membership (NULL external_source) and an
///      OIDC-managed membership (external_source='oidc', same provider UUID)
///      both survive the SAML re-sync (source-scoped prune).
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_saml_acs_group_membership_sync_and_isolation() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let provider_id = create_saml_provider(
        &pool,
        SamlProviderOpts {
            map_groups_to_groups: true,
            ..SamlProviderOpts::default()
        },
    )
    .await;

    let suffix = Uuid::new_v4().as_simple().to_string();
    let eng = format!("saml-e2e-eng-{suffix}");
    let ops = format!("saml-e2e-ops-{suffix}");
    let name_id = format!("saml-gsync-{suffix}");

    // 1. First login: groups [eng, ops].
    let request_id = seed_session(&pool, provider_id).await;
    let mut spec = happy_spec(&request_id, &name_id);
    spec.groups = vec![eng.clone(), ops.clone()];
    let resp = post_acs(build_state(pool.clone()), provider_id, &spec.signed_b64()).await;
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);

    let (user_id, _, _, _) = get_saml_user(&pool, &name_id).await.expect("provisioned");
    let eng_id = group_id_by_name(&pool, &eng)
        .await
        .expect("eng auto-created");
    let ops_id = group_id_by_name(&pool, &ops)
        .await
        .expect("ops auto-created");
    assert!(user_is_in_group(&pool, user_id, eng_id).await);
    assert!(user_is_in_group(&pool, user_id, ops_id).await);
    assert_eq!(
        group_external_source(&pool, eng_id).await.as_deref(),
        Some("saml"),
        "auto-created groups must be tagged external_source='saml'"
    );
    assert_eq!(
        group_external_source(&pool, ops_id).await.as_deref(),
        Some("saml")
    );

    // 3-prep. Seed an operator-managed and an OIDC-managed membership that
    // the SAML re-sync must NOT touch. The OIDC group deliberately reuses
    // the SAME provider UUID to prove the prune is source-scoped, not just
    // provider-scoped.
    let op_group = Uuid::new_v4();
    sqlx::query("INSERT INTO groups (id, name) VALUES ($1, $2)")
        .bind(op_group)
        .bind(format!("saml-e2e-op-{suffix}"))
        .execute(&pool)
        .await
        .expect("operator group");
    let oidc_group = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO groups (id, name, external_source, external_provider_id) \
         VALUES ($1, $2, 'oidc', $3)",
    )
    .bind(oidc_group)
    .bind(format!("saml-e2e-oidc-{suffix}"))
    .bind(provider_id)
    .execute(&pool)
    .await
    .expect("oidc group");
    for gid in [op_group, oidc_group] {
        sqlx::query("INSERT INTO user_group_members (user_id, group_id) VALUES ($1, $2)")
            .bind(user_id)
            .bind(gid)
            .execute(&pool)
            .await
            .expect("seed membership");
    }

    // 2. Re-login with [eng] only → ops pruned, eng kept.
    let request_id2 = seed_session(&pool, provider_id).await;
    let mut spec2 = happy_spec(&request_id2, &name_id);
    spec2.groups = vec![eng.clone()];
    let resp = post_acs(build_state(pool.clone()), provider_id, &spec2.signed_b64()).await;
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);

    assert!(
        user_is_in_group(&pool, user_id, eng_id).await,
        "eng membership must survive the re-sync"
    );
    assert!(
        !user_is_in_group(&pool, user_id, ops_id).await,
        "ops membership must be pruned when absent from the assertion"
    );
    // 3. Isolation: operator- and OIDC-managed memberships survive.
    assert!(
        user_is_in_group(&pool, user_id, op_group).await,
        "operator-managed membership must survive a SAML sync"
    );
    assert!(
        user_is_in_group(&pool, user_id, oidc_group).await,
        "OIDC-managed membership (same provider UUID) must survive a SAML sync"
    );

    cleanup_groups(&pool, &[eng_id, ops_id, op_group, oidc_group]).await;
    delete_saml_user(&pool, &name_id).await;
    delete_saml_provider(&pool, provider_id).await;
}

/// Issue #2333 default-off: with `map_groups_to_groups` left false (the
/// default), a login carrying group values must not create groups or
/// memberships — the pre-157 behavior (groups only feed admin_group role
/// mapping) is preserved.
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_saml_acs_group_sync_disabled_by_default() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let provider_id = create_saml_provider(&pool, SamlProviderOpts::default()).await;

    let suffix = Uuid::new_v4().as_simple().to_string();
    let group_name = format!("saml-e2e-off-{suffix}");
    let name_id = format!("saml-gsync-off-{suffix}");

    let request_id = seed_session(&pool, provider_id).await;
    let mut spec = happy_spec(&request_id, &name_id);
    spec.groups = vec![group_name.clone()];
    let resp = post_acs(build_state(pool.clone()), provider_id, &spec.signed_b64()).await;
    assert_eq!(
        resp.status(),
        StatusCode::TEMPORARY_REDIRECT,
        "login itself must still succeed with the flag off"
    );

    assert!(
        group_id_by_name(&pool, &group_name).await.is_none(),
        "no group may be auto-created when map_groups_to_groups is false"
    );
    let (user_id, _, _, _) = get_saml_user(&pool, &name_id).await.expect("provisioned");
    let memberships: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_group_members WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .expect("membership count");
    assert_eq!(
        memberships, 0,
        "no memberships may be written when map_groups_to_groups is false"
    );

    delete_saml_user(&pool, &name_id).await;
    delete_saml_provider(&pool, provider_id).await;
}

/// Issue #2333 × XSW composition (#2449/#2453) — security regression: with
/// `map_groups_to_groups = true` and a signed assertion that carries NO groups,
/// a `<saml:Attribute Name="groups">` spliced in as a `<samlp:Response>` child
/// OUTSIDE the signed `<saml:Assertion>` subtree must confer NO local group
/// membership. The signature still verifies (single assertion), so login
/// succeeds (307), but the injected groups live outside the cryptographically
/// verified subtree — so the membership sync, which reads `saml_user.groups`
/// harvested only from the signed subtree, must never auto-create or join them.
/// This pins the escalation guarantee: an SSO-completing attacker cannot inject
/// an unsigned `groups=[<any-group>]` to join arbitrary local groups.
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_saml_acs_out_of_subtree_groups_confer_no_membership() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let provider_id = create_saml_provider(
        &pool,
        SamlProviderOpts {
            map_groups_to_groups: true,
            ..SamlProviderOpts::default()
        },
    )
    .await;

    let suffix = Uuid::new_v4().as_simple().to_string();
    let injected = format!("saml-xsw-inject-{suffix}");
    let name_id = format!("saml-xsw-memb-{suffix}");

    let request_id = seed_session(&pool, provider_id).await;
    let mut spec = happy_spec(&request_id, &name_id);
    spec.groups = vec![]; // signed assertion carries no groups attribute

    // Splice groups=[injected] as a <Response> child BEFORE the assertion —
    // outside the signed subtree (the assertion digest is unchanged).
    let payload = spec.attribute_xsw_b64(&[injected.as_str()], true);
    let resp = post_acs(build_state(pool.clone()), provider_id, &payload).await;

    assert_eq!(
        resp.status(),
        StatusCode::TEMPORARY_REDIRECT,
        "a valid signature with an out-of-subtree groups attribute must still authenticate"
    );

    let (user_id, _, _, _) = get_saml_user(&pool, &name_id)
        .await
        .expect("the signed subject must still provision");

    // The injected (unsigned) group must be neither auto-created nor joined:
    // group extraction rides the signed-subtree claim path (composes with XSW).
    assert!(
        group_id_by_name(&pool, &injected).await.is_none(),
        "an out-of-subtree groups attribute must NOT auto-create a group"
    );
    let memberships: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_group_members WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .expect("membership count");
    assert_eq!(
        memberships, 0,
        "an out-of-subtree groups attribute must confer no local group membership (XSW composition)"
    );

    delete_saml_user(&pool, &name_id).await;
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
    // Poll: the LOGIN row is written by a detached task (#2905), so it is not
    // guaranteed to be visible the instant the ACS handler returns.
    let login_ok = audit_row_eventually(&audit, Some(user_id), "LOGIN", |r| {
        r.resource_type == "user"
            && r.details
                .as_ref()
                .and_then(|d| d.get("provider"))
                .and_then(|p| p.as_str())
                == Some("saml")
    })
    .await;

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

    // Same detached-write race as the LOGIN row above.
    let fail_ok = audit_row_eventually(&audit, None, "LOGIN_FAILED", |r| {
        r.details
            .as_ref()
            .and_then(|d| d.get("provider"))
            .and_then(|p| p.as_str())
            == Some("saml")
    })
    .await;

    // Clean up BEFORE asserting (#3120 pattern): a panicking assertion would
    // otherwise skip these deletes and strand the provisioned user + provider
    // for the rest of the run.
    delete_saml_user(&pool, &name_id).await;
    delete_saml_provider(&pool, provider_id).await;

    assert!(
        login_ok,
        "a LOGIN audit row with details.provider=saml must exist for the user"
    );
    assert!(
        fail_ok,
        "a LOGIN_FAILED audit row with details.provider=saml must exist"
    );
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

/// XML Signature Wrapping (XSW) escalation (#2449): a response with the legit,
/// benign, single signed assertion PLUS an appended UNSIGNED second assertion
/// whose `groups` include the provider `admin_group`. Pre-fix the last-wins
/// parser consumed the unsigned assertion (307 + admin). Post-fix the parser
/// rejects any multi-assertion response outright → 401, and NO user (admin or
/// otherwise) is provisioned for the attacker NameID.
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_saml_acs_xsw_dual_assertion_rejected() {
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

    // Benign, correctly-signed assertion for a normal user (non-admin groups).
    let victim = format!("saml-xsw-victim-{}", Uuid::new_v4().as_simple());
    let attacker = format!("saml-xsw-attacker-{}", Uuid::new_v4().as_simple());
    let request_id = seed_session(&pool, provider_id).await;
    let spec = happy_spec(&request_id, &victim);

    // Splice an UNSIGNED assertion (attacker NameID, groups=[ak-admins]) after
    // the signed one.
    let payload = spec.xsw_wrapped_b64(&attacker, &["ak-admins", "Developers"], false);
    let resp = post_acs(build_state(pool.clone()), provider_id, &payload).await;

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "an XSW dual-assertion response must be rejected (was 307 + admin escalation)"
    );

    // Neither the smuggled attacker identity nor the wrapped victim may be
    // provisioned, and specifically no admin user is created.
    assert!(
        get_saml_user(&pool, &attacker).await.is_none(),
        "the smuggled (unsigned) assertion must NOT provision a user — this is the escalation"
    );
    assert!(
        get_saml_user(&pool, &victim).await.is_none(),
        "the wrapped response must be rejected wholesale; no user provisioned"
    );

    delete_saml_user(&pool, &attacker).await;
    delete_saml_user(&pool, &victim).await;
    delete_saml_provider(&pool, provider_id).await;
}

/// Duplicate-ID XSW variant (#2449): two assertions sharing the signed
/// assertion's ID — the second unsigned one carrying the admin group. Rejected
/// (multi-assertion) → 401, no admin user provisioned.
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_saml_acs_xsw_duplicate_id_rejected() {
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

    let victim = format!("saml-xswdup-victim-{}", Uuid::new_v4().as_simple());
    let attacker = format!("saml-xswdup-attacker-{}", Uuid::new_v4().as_simple());
    let request_id = seed_session(&pool, provider_id).await;
    let spec = happy_spec(&request_id, &victim);

    // dup_id = true → the injected unsigned assertion reuses the signed ID.
    let payload = spec.xsw_wrapped_b64(&attacker, &["ak-admins"], true);
    let resp = post_acs(build_state(pool.clone()), provider_id, &payload).await;

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "a duplicate-ID XSW response must be rejected"
    );
    assert!(get_saml_user(&pool, &attacker).await.is_none());
    assert!(get_saml_user(&pool, &victim).await.is_none());

    delete_saml_user(&pool, &attacker).await;
    delete_saml_user(&pool, &victim).await;
    delete_saml_provider(&pool, provider_id).await;
}

/// Attribute-injection XSW variant (#2453 layer-2): the assertion is validly
/// signed but carries NO groups attribute; a `<saml:Attribute Name="groups">`
/// with the provider admin group is spliced in as a `<samlp:Response>` child
/// BEFORE the signed `<saml:Assertion>`. The splice is outside the signed
/// subtree so the signature still verifies (single assertion → no multi-assert
/// reject), but claims are now scoped to the verified assertion, so the injected
/// group must NOT grant admin. Login succeeds (307) as a non-admin.
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_saml_acs_xsw_attribute_before_assertion_not_admin() {
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

    let name_id = format!("saml-attrxsw-{}", Uuid::new_v4().as_simple());
    let request_id = seed_session(&pool, provider_id).await;
    let mut spec = happy_spec(&request_id, &name_id);
    spec.groups = vec![]; // signed assertion carries no groups attribute

    let payload = spec.attribute_xsw_b64(&["ak-admins"], true);
    let resp = post_acs(build_state(pool.clone()), provider_id, &payload).await;

    assert_eq!(
        resp.status(),
        StatusCode::TEMPORARY_REDIRECT,
        "a valid signature with an out-of-subtree attribute must still authenticate"
    );
    let (_, _, _, is_admin) = get_saml_user(&pool, &name_id)
        .await
        .expect("the signed subject must still provision");
    assert!(
        !is_admin,
        "a groups attribute spliced BEFORE the signed assertion must NOT grant admin"
    );

    delete_saml_user(&pool, &name_id).await;
    delete_saml_provider(&pool, provider_id).await;
}

/// Control for the attribute-injection variant: the same `groups` attribute
/// spliced AFTER `</saml:Assertion>` (still a `<Response>` child, still outside
/// the signed subtree) likewise must not grant admin.
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_saml_acs_xsw_attribute_after_assertion_not_admin() {
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

    let name_id = format!("saml-attrxsw-after-{}", Uuid::new_v4().as_simple());
    let request_id = seed_session(&pool, provider_id).await;
    let mut spec = happy_spec(&request_id, &name_id);
    spec.groups = vec![];

    let payload = spec.attribute_xsw_b64(&["ak-admins"], false);
    let resp = post_acs(build_state(pool.clone()), provider_id, &payload).await;

    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    let (_, _, _, is_admin) = get_saml_user(&pool, &name_id)
        .await
        .expect("the signed subject must still provision");
    assert!(
        !is_admin,
        "a groups attribute spliced AFTER the signed assertion must NOT grant admin"
    );

    delete_saml_user(&pool, &name_id).await;
    delete_saml_provider(&pool, provider_id).await;
}

/// In-`<ds:Signature>` `<ds:Object>` injection variant (#2453 layer-3): the
/// assertion is validly signed but carries NO groups attribute; a
/// `<saml:Attribute Name="groups">` with the provider admin group is spliced
/// into a `<ds:Object>` INSIDE the assertion's enveloped `<ds:Signature>` after
/// signing. The signature transform removes the whole `<ds:Signature>` before
/// digesting, so the injection is unsigned and the signature still verifies —
/// but the `<ds:Signature>` is a child of the assertion, so a parser that scopes
/// claims to the assertion subtree WITHOUT excluding the Signature subtree would
/// harvest the injected group. Login must succeed (307) as a NON-admin.
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_saml_acs_ds_object_groups_injection_not_admin() {
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

    let name_id = format!("saml-dsobjxsw-{}", Uuid::new_v4().as_simple());
    let request_id = seed_session(&pool, provider_id).await;
    let mut spec = happy_spec(&request_id, &name_id);
    spec.groups = vec![]; // signed assertion carries no groups attribute

    let payload = spec.ds_object_groups_injection_b64(&["ak-admins"]);
    let resp = post_acs(build_state(pool.clone()), provider_id, &payload).await;

    assert_eq!(
        resp.status(),
        StatusCode::TEMPORARY_REDIRECT,
        "a valid signature with an in-<ds:Signature> <ds:Object> attribute must still authenticate"
    );
    let (_, _, _, is_admin) = get_saml_user(&pool, &name_id)
        .await
        .expect("the signed subject must still provision");
    assert!(
        !is_admin,
        "a groups attribute spliced into a <ds:Object> inside the assertion's \
         <ds:Signature> must NOT grant admin"
    );

    delete_saml_user(&pool, &name_id).await;
    delete_saml_provider(&pool, provider_id).await;
}

/// Comment-split NameID variant (#2453 layer-2 / Case-5): the signed NameID text
/// is split by an XML comment (`victim-prefix-<!--c-->suffix`). exc-c14n#
/// (no-comments) strips the comment before digesting, so the signature stays
/// valid. The parser now accumulates leaf text across the comment, so the
/// provisioned `external_id` is the FULL signed NameID — not the trailing
/// segment a last-wins parser would have stored.
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_saml_acs_comment_split_nameid_uses_full_value() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let provider_id = create_saml_provider(&pool, SamlProviderOpts::default()).await;

    let name_id = format!("victim-prefix-suffix-{}", Uuid::new_v4().as_simple());
    let request_id = seed_session(&pool, provider_id).await;
    let spec = happy_spec(&request_id, &name_id);

    let payload = spec.nameid_comment_b64();
    let resp = post_acs(build_state(pool.clone()), provider_id, &payload).await;

    assert_eq!(
        resp.status(),
        StatusCode::TEMPORARY_REDIRECT,
        "a comment-split (but validly signed) NameID must authenticate"
    );

    // The provisioned user is keyed on the FULL NameID value.
    assert!(
        get_saml_user(&pool, &name_id).await.is_some(),
        "the provisioned external_id must equal the full signed NameID"
    );
    // A last-wins parser would have stored only the trailing text node; assert
    // no user exists under that truncated value.
    let truncated = name_id.rsplit('-').next().unwrap();
    assert!(
        get_saml_user(&pool, truncated).await.is_none(),
        "no user may be provisioned under the truncated (trailing-segment) NameID"
    );

    delete_saml_user(&pool, &name_id).await;
    delete_saml_provider(&pool, provider_id).await;
}

// ===========================================================================
// Slug addressing (#2583)
//
// A SAML configuration is addressable by an operator-chosen `slug` as well as
// by its UUID, so rebuilding a deployment no longer changes the ACS URL the
// IdP is configured with. These pin all four halves of that: the slug
// resolves, the ACS binding follows the segment the request arrived on, the
// full login → ACS flow works over a slug, and a pre-existing (slug-less)
// configuration is untouched.
// ===========================================================================

/// A fresh, valid slug. Unique per call so parallel runs cannot collide on the
/// UNIQUE constraint.
fn fresh_slug(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4().as_simple())
}

/// Recover the AuthnRequest XML the SP emitted from the login redirect: the
/// `SAMLRequest` query parameter is URL-encoded, base64 (standard alphabet)
/// XML — see `SamlService::create_authn_request`.
fn decode_authn_request(redirect_url: &str) -> String {
    use base64::Engine;
    let encoded = redirect_url
        .split(['?', '&'])
        .find_map(|p| p.strip_prefix("SAMLRequest="))
        .expect("login redirect must carry a SAMLRequest parameter");
    let decoded = urlencoding::decode(encoded).expect("SAMLRequest is percent-encoded");
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(decoded.as_bytes())
        .expect("SAMLRequest is base64");
    String::from_utf8(bytes).expect("AuthnRequest is UTF-8")
}

/// A validly signed assertion POSTed to `/saml/{slug}/acs` authenticates
/// exactly as the UUID-addressed form does, and provisions the same user.
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_saml_acs_resolves_provider_by_slug() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let slug = fresh_slug("okta");
    let provider_id = create_saml_provider(
        &pool,
        SamlProviderOpts {
            slug: Some(slug.clone()),
            ..SamlProviderOpts::default()
        },
    )
    .await;

    let name_id = format!("saml-slug-{}", Uuid::new_v4().as_simple());
    let request_id = seed_session(&pool, provider_id).await;
    let spec = happy_spec(&request_id, &name_id);

    let resp = post_acs_at(build_state(pool.clone()), &slug, &spec.signed_b64()).await;

    assert_eq!(
        resp.status(),
        StatusCode::TEMPORARY_REDIRECT,
        "an assertion POSTed to the slug ACS URL must authenticate"
    );
    assert!(
        get_saml_user(&pool, &name_id).await.is_some(),
        "the slug-addressed ACS must provision the federated user"
    );

    // A slug that matches nothing is a 404, not a fuzzy match onto some other
    // configuration.
    let request_id_404 = seed_session(&pool, provider_id).await;
    let miss = post_acs_at(
        build_state(pool.clone()),
        "no-such-slug-2583",
        &happy_spec(&request_id_404, "saml-slug-miss").signed_b64(),
    )
    .await;
    assert_eq!(
        miss.status(),
        StatusCode::NOT_FOUND,
        "an unknown slug must 404 rather than resolve to another provider"
    );

    // The slug is matched exactly: the CHECK constraint admits only one
    // (lowercase) spelling, so a differently-cased segment must NOT resolve.
    // A case-insensitive lookup over a case-sensitive UNIQUE index is how two
    // rows the database considers distinct end up sharing one login URL.
    let request_id_case = seed_session(&pool, provider_id).await;
    let cased = post_acs_at(
        build_state(pool.clone()),
        &slug.to_uppercase(),
        &happy_spec(&request_id_case, "saml-slug-case").signed_b64(),
    )
    .await;
    assert_eq!(
        cased.status(),
        StatusCode::NOT_FOUND,
        "slug resolution is exact; an upper-cased segment must not resolve"
    );
    assert!(get_saml_user(&pool, "saml-slug-case").await.is_none());

    delete_saml_user(&pool, &name_id).await;
    delete_saml_provider(&pool, provider_id).await;
}

/// The `Destination`/`Recipient` binding follows the segment the request
/// arrived on. An assertion issued for the slug ACS URL is accepted at the
/// slug URL and refused at the UUID URL, and vice versa — so a second address
/// for a configuration does not become a second accepted audience for an
/// assertion bound to the first.
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_saml_acs_slug_binding_follows_the_requested_segment() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let slug = fresh_slug("bindcheck");
    let provider_id = create_saml_provider(
        &pool,
        SamlProviderOpts {
            use_absolute_acs_url: true,
            slug: Some(slug.clone()),
            ..SamlProviderOpts::default()
        },
    )
    .await;
    let slug_acs = expected_acs_for(&slug);
    let uuid_acs = expected_acs(provider_id);
    assert_ne!(slug_acs, uuid_acs);

    // Assertion bound to the slug ACS, delivered to the slug ACS → accepted.
    let name_ok = format!("saml-bind-ok-{}", Uuid::new_v4().as_simple());
    let request_ok = seed_session(&pool, provider_id).await;
    let mut ok = happy_spec(&request_ok, &name_ok);
    ok.destination = Some(slug_acs.clone());
    ok.recipient = Some(slug_acs.clone());
    let resp = post_acs_at(build_state(pool.clone()), &slug, &ok.signed_b64()).await;
    assert_eq!(
        resp.status(),
        StatusCode::TEMPORARY_REDIRECT,
        "a Destination/Recipient matching the slug ACS URL must be accepted there"
    );
    delete_saml_user(&pool, &name_ok).await;

    // Same assertion shape, but bound to the UUID ACS and delivered to the
    // slug ACS → rejected.
    let name_bad = format!("saml-bind-bad-{}", Uuid::new_v4().as_simple());
    let request_bad = seed_session(&pool, provider_id).await;
    let mut bad = happy_spec(&request_bad, &name_bad);
    bad.destination = Some(uuid_acs.clone());
    bad.recipient = Some(uuid_acs.clone());
    let resp = post_acs_at(build_state(pool.clone()), &slug, &bad.signed_b64()).await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "an assertion bound to the UUID ACS URL must not be accepted at the slug ACS URL"
    );
    assert!(get_saml_user(&pool, &name_bad).await.is_none());

    // ... and symmetrically: bound to the slug ACS, delivered to the UUID ACS.
    let name_bad2 = format!("saml-bind-bad2-{}", Uuid::new_v4().as_simple());
    let request_bad2 = seed_session(&pool, provider_id).await;
    let mut bad2 = happy_spec(&request_bad2, &name_bad2);
    bad2.destination = Some(slug_acs.clone());
    bad2.recipient = Some(slug_acs);
    let resp = post_acs(build_state(pool.clone()), provider_id, &bad2.signed_b64()).await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "an assertion bound to the slug ACS URL must not be accepted at the UUID ACS URL"
    );
    assert!(get_saml_user(&pool, &name_bad2).await.is_none());

    delete_saml_provider(&pool, provider_id).await;
}

/// The whole point of the issue: `GET /saml/{slug}/login` → IdP → `POST
/// /saml/{slug}/acs` authenticates end to end, with the AuthnRequest's
/// `AssertionConsumerServiceURL` and the callback's binding agreeing on the
/// slug form.
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_saml_login_then_acs_by_slug_full_flow() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let slug = fresh_slug("fullflow");
    let provider_id = create_saml_provider(
        &pool,
        SamlProviderOpts {
            use_absolute_acs_url: true,
            slug: Some(slug.clone()),
            ..SamlProviderOpts::default()
        },
    )
    .await;

    let app = sso_app(build_state(pool.clone()));
    let login = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/saml/{slug}/login"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("login oneshot");
    assert_eq!(
        login.status(),
        StatusCode::TEMPORARY_REDIRECT,
        "SAML login addressed by slug must 307 to the IdP SSO URL"
    );

    // The AuthnRequest the SP emitted must advertise the SLUG ACS URL: that is
    // what makes the URL an operator can pin in IdP configuration.
    let redirect = login
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let authn_request = decode_authn_request(&redirect);
    assert!(
        authn_request.contains(&expected_acs_for(&slug)),
        "the AuthnRequest must advertise the slug ACS URL, got {authn_request}"
    );
    assert!(
        !authn_request.contains(&provider_id.to_string()),
        "the AuthnRequest must not fall back to the UUID ACS URL, got {authn_request}"
    );

    // The login persists its pending session against the provider's real
    // UUID — the slug is a route-level alias, not a new session key.
    let request_id: String = sqlx::query_scalar(
        "SELECT state FROM sso_sessions \
         WHERE provider_id = $1 AND provider_type = 'saml' \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(provider_id)
    .fetch_one(&pool)
    .await
    .expect("pending sso session state");

    let name_id = format!("saml-slugflow-{}", Uuid::new_v4().as_simple());
    let acs = expected_acs_for(&slug);
    let mut spec = happy_spec(&request_id, &name_id);
    spec.destination = Some(acs.clone());
    spec.recipient = Some(acs);
    let resp = post_acs_at(build_state(pool.clone()), &slug, &spec.signed_b64()).await;
    assert_eq!(
        resp.status(),
        StatusCode::TEMPORARY_REDIRECT,
        "the slug ACS callback for the slug login's own request_id must succeed"
    );
    assert!(
        get_saml_user(&pool, &name_id).await.is_some(),
        "the slug full flow must provision the user"
    );

    delete_saml_user(&pool, &name_id).await;
    delete_saml_provider(&pool, provider_id).await;
}

/// Upgrade safety: a configuration with NO slug — the state every row is in
/// immediately after migration 218, since the column is added NULL and never
/// backfilled — keeps working at exactly its old UUID ACS URL, with the same
/// `Destination` binding string as before.
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_saml_acs_uuid_addressing_unchanged_without_a_slug() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let provider_id = create_saml_provider(
        &pool,
        SamlProviderOpts {
            use_absolute_acs_url: true,
            ..SamlProviderOpts::default()
        },
    )
    .await;
    assert!(
        AuthConfigService::get_saml(&pool, provider_id)
            .await
            .expect("get_saml")
            .slug
            .is_none(),
        "a configuration created without a slug must have none (no backfill)"
    );

    let name_id = format!("saml-nolug-{}", Uuid::new_v4().as_simple());
    let request_id = seed_session(&pool, provider_id).await;
    let acs = expected_acs(provider_id);
    let mut spec = happy_spec(&request_id, &name_id);
    spec.destination = Some(acs.clone());
    spec.recipient = Some(acs);
    let resp = post_acs(build_state(pool.clone()), provider_id, &spec.signed_b64()).await;
    assert_eq!(
        resp.status(),
        StatusCode::TEMPORARY_REDIRECT,
        "a slug-less configuration must keep authenticating at its UUID ACS URL"
    );
    assert!(get_saml_user(&pool, &name_id).await.is_some());

    delete_saml_user(&pool, &name_id).await;
    delete_saml_provider(&pool, provider_id).await;
}
