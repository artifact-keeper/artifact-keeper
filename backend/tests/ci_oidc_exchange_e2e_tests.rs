//! End-to-end tests for the CI OIDC token exchange (#4031).
//!
//! Every request goes through the full router (`api::routes::create_router`)
//! against a real database, and every token is verified against a live HTTPS
//! issuer (`common::ci_oidc_issuer`): discovery over TLS, JWKS, signature,
//! `iss`/`aud`/`exp`, then the identity mapping, the service account, and the
//! minted token used on a real repository route. The unit tests in
//! `api::handlers::ci_auth` start after verification; these do not.
//!
//! The issuer is trusted through production settings only
//! (`CUSTOM_CA_CERT_PATH`, `AK_SSRF_ALLOW_PRIVATE_CIDRS`), both process-global,
//! so the suite runs single-threaded in its own process — as Tier 2 runs it:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//! AK_TESTS_REQUIRE_DB=1 \
//!   cargo test --test ci_oidc_exchange_e2e_tests -- --ignored --test-threads=1
//! ```
//!
//! Requires a non-loopback local address for the issuer. Without one the
//! suite skips like the SSO e2e — unless `AK_TESTS_REQUIRE_DB` is set, in
//! which case it fails, so a Tier 2 run can never pass without executing.
//!
//! What this does NOT prove: that a real GitLab emits exactly these claims.
//! The tokens follow GitLab's documented ID-token shape.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::disallowed_methods)] // streaming-invariant: test file exempt — buffering response bodies in test assertions is not an artifact path (#1608)

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use artifact_keeper_backend::api::routes::create_router;
use artifact_keeper_backend::api::SharedState;
use artifact_keeper_backend::models::user::User;
use artifact_keeper_backend::services::auth_service::AuthService;
use artifact_keeper_backend::services::ci_oidc_service::CiOidcService;

use common::ci_oidc_issuer::{unsigned_alg_none, MockCiIssuer};
use common::sso_support::{build_state, try_pool};

const AUDIENCE: &str = "https://artifacts.e2e.test";
const TOKEN_ROUTE: &str = "/api/v1/auth/ci/token";

// ===========================================================================
// Harness
// ===========================================================================

/// One test's world: a database, the router, an HTTPS issuer registered as a
/// gitlab provider, and an admin to configure it through the admin API.
struct Fixture {
    pool: PgPool,
    state: SharedState,
    issuer: MockCiIssuer,
    provider_id: Uuid,
    admin_id: Uuid,
    admin_bearer: String,
    /// Rows to remove on teardown, beyond what hangs off `provider_id`.
    groups: Vec<Uuid>,
    repos: Vec<Uuid>,
    extra_providers: Vec<Uuid>,
}

impl Fixture {
    /// `None` when the environment cannot run the suite (no database, or no
    /// non-loopback address for the issuer). Under `AK_TESTS_REQUIRE_DB` a
    /// missing database already panics inside `try_pool`; a missing address
    /// panics here, so a required run cannot silently pass.
    async fn new() -> Option<Self> {
        let pool = try_pool().await?;
        let Some(issuer) = MockCiIssuer::start().await else {
            assert!(
                std::env::var(artifact_keeper_backend::testing::REQUIRE_DB_ENV).is_err(),
                "no non-loopback local address for the mock CI OIDC issuer, and \
                 {} is set: refusing to report a suite that did not run as passed",
                artifact_keeper_backend::testing::REQUIRE_DB_ENV
            );
            return None;
        };
        let state = build_state(pool.clone());
        let (admin_id, admin_bearer) = seed_admin(&pool, &state).await;

        let mut fx = Self {
            pool,
            state,
            issuer,
            provider_id: Uuid::nil(),
            admin_id,
            admin_bearer,
            groups: Vec::new(),
            repos: Vec::new(),
            extra_providers: Vec::new(),
        };
        fx.provider_id = fx.create_provider(fx.issuer.issuer()).await;
        Some(fx)
    }

    /// Send one request through the full router.
    async fn send(
        &self,
        method: &str,
        uri: &str,
        bearer: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(token) = bearer {
            req = req.header("authorization", format!("Bearer {token}"));
        }
        let req = match body {
            Some(b) => req
                .header("content-type", "application/json")
                .body(Body::from(b.to_string())),
            None => req.body(Body::empty()),
        }
        .unwrap();
        let resp = create_router(self.state.clone())
            .oneshot(req)
            .await
            .expect("router oneshot");
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("read body");
        let value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        (status, value)
    }

    async fn admin(&self, method: &str, uri: &str, body: Option<Value>) -> Value {
        let (status, value) = self.send(method, uri, Some(&self.admin_bearer), body).await;
        assert!(status.is_success(), "{method} {uri} -> {status}: {value}");
        value
    }

    async fn create_provider(&self, issuer: &str) -> Uuid {
        let created = self
            .admin(
                "POST",
                "/api/v1/admin/ci-oidc",
                Some(json!({
                    "name": format!("gitlab-e2e-{}", Uuid::new_v4()),
                    "provider_type": "gitlab",
                    "issuer_url": issuer,
                    "audience": AUDIENCE,
                })),
            )
            .await;
        Uuid::parse_str(created["id"].as_str().unwrap()).unwrap()
    }

    /// Create a mapping through the admin API, returning the response — which
    /// carries the service account an operator would grant.
    async fn create_mapping(&self, claim_filters: Value) -> Value {
        self.admin(
            "POST",
            &format!("/api/v1/admin/ci-oidc/{}/mappings", self.provider_id),
            Some(json!({ "name": "e2e", "claim_filters": claim_filters })),
        )
        .await
    }

    /// Exchange `token` for an Artifact Keeper token, as a pipeline does.
    async fn exchange(&self, token: &str) -> (StatusCode, Value) {
        self.send("POST", TOKEN_ROUTE, Some(token), None).await
    }

    /// Sign GitLab claims for one pipeline and exchange them.
    async fn exchange_pipeline(
        &self,
        project: &str,
        ref_type: &str,
        git_ref: &str,
    ) -> (StatusCode, Value) {
        let claims = self
            .issuer
            .gitlab_claims(AUDIENCE, project, ref_type, git_ref);
        self.exchange(&self.issuer.sign(&claims)).await
    }

    /// `(id, is_active)` of every CI account keyed under this fixture's provider.
    async fn provider_accounts(&self) -> Vec<(Uuid, bool)> {
        sqlx::query_as(
            "SELECT id, is_active FROM users \
             WHERE auth_provider = 'ci' AND starts_with(external_id, $1) ORDER BY id",
        )
        .bind(format!("ci:{}:", self.provider_id))
        .fetch_all(&self.pool)
        .await
        .expect("list provider accounts")
    }

    /// A private generic repository (only a grant makes it visible).
    async fn private_repo(&mut self) -> String {
        let id = Uuid::new_v4();
        let key = format!("ci-e2e-{id}");
        let dir = std::env::temp_dir().join(&key);
        std::fs::create_dir_all(&dir).expect("repo dir");
        sqlx::query(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
             VALUES ($1, $2, $2, $3, 'local'::repository_type, 'generic'::repository_format)",
        )
        .bind(id)
        .bind(&key)
        .bind(dir.to_string_lossy().into_owned())
        .execute(&self.pool)
        .await
        .expect("create private repo");
        self.repos.push(id);
        key
    }

    /// Grant `account` read on `repo_key` the way an operator does: a group,
    /// its membership, and a group-principal permission, all via the API.
    async fn grant_via_group(&mut self, account: Uuid, repo_key: &str) {
        let group = self
            .admin(
                "POST",
                "/api/v1/groups",
                Some(json!({ "name": format!("ci-e2e-{}", Uuid::new_v4()) })),
            )
            .await;
        let group_id = Uuid::parse_str(group["id"].as_str().unwrap()).unwrap();
        self.groups.push(group_id);
        self.admin(
            "POST",
            &format!("/api/v1/groups/{group_id}/members"),
            Some(json!({ "user_ids": [account] })),
        )
        .await;
        let repo_id: Uuid = sqlx::query_scalar("SELECT id FROM repositories WHERE key = $1")
            .bind(repo_key)
            .fetch_one(&self.pool)
            .await
            .unwrap();
        self.admin(
            "POST",
            "/api/v1/permissions",
            Some(json!({
                "principal_type": "group",
                "principal_id": group_id,
                "target_type": "repository",
                "target_id": repo_id,
                "actions": ["read", "write"],
            })),
        )
        .await;
    }

    async fn teardown(self) {
        let mut users: Vec<Uuid> = self
            .provider_accounts()
            .await
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        for p in &self.extra_providers {
            let ids: Vec<Uuid> = sqlx::query_scalar(
                "SELECT id FROM users WHERE auth_provider = 'ci' AND starts_with(external_id, $1)",
            )
            .bind(format!("ci:{p}:"))
            .fetch_all(&self.pool)
            .await
            .unwrap_or_default();
            users.extend(ids);
        }
        users.push(self.admin_id);
        for (sql, ids) in [
            (
                "DELETE FROM permissions WHERE principal_id = ANY($1)",
                &self.groups,
            ),
            ("DELETE FROM groups WHERE id = ANY($1)", &self.groups),
            (
                "DELETE FROM permissions WHERE target_id = ANY($1)",
                &self.repos,
            ),
            ("DELETE FROM repositories WHERE id = ANY($1)", &self.repos),
            (
                "DELETE FROM refresh_token_jti WHERE user_id = ANY($1)",
                &users,
            ),
            ("DELETE FROM user_roles WHERE user_id = ANY($1)", &users),
            ("DELETE FROM users WHERE id = ANY($1)", &users),
        ] {
            let _ = sqlx::query(sql).bind(ids).execute(&self.pool).await;
        }
        let mut providers = self.extra_providers.clone();
        providers.push(self.provider_id);
        let _ = sqlx::query("DELETE FROM ci_oidc_providers WHERE id = ANY($1)")
            .bind(&providers)
            .execute(&self.pool)
            .await;
    }
}

/// A local admin and a bearer for it, minted the way login does.
///
/// `password_changed_at` sits two seconds in the past, as the user-create
/// handler writes it, so the token's `iat` is after the credential watermark.
async fn seed_admin(pool: &PgPool, state: &SharedState) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let username = format!("ci-e2e-admin-{}", &id.simple().to_string()[..12]);
    let user: User = sqlx::query_as(
        "INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, \
                            is_active, must_change_password, password_changed_at) \
         VALUES ($1, $2, $3, 'unused', 'local', true, true, false, NOW() - INTERVAL '2 seconds') \
         RETURNING *",
    )
    .bind(id)
    .bind(&username)
    .bind(format!("{username}@e2e.test"))
    .fetch_one(pool)
    .await
    .expect("seed admin");
    let auth = AuthService::new(pool.clone(), std::sync::Arc::new(state.config.clone()));
    let tokens = auth.generate_tokens(&user).expect("admin token");
    (id, tokens.access_token)
}

fn uuid_field(v: &Value, field: &str) -> Uuid {
    Uuid::parse_str(
        v[field]
            .as_str()
            .unwrap_or_else(|| panic!("{field} missing in {v}")),
    )
    .unwrap()
}

// ===========================================================================
// 1. Harness smoke tests
// ===========================================================================

/// The mock issuer is a real HTTPS OIDC issuer as far as the verifier is
/// concerned: discovery and JWKS over TLS through `sso_client`, trusted via
/// `CUSTOM_CA_CERT_PATH` only.
#[tokio::test]
#[ignore]
async fn mock_issuer_token_passes_validate_ci_jwt() {
    let Some(fx) = Fixture::new().await else {
        return;
    };
    let svc = CiOidcService::new(fx.pool.clone());
    let provider = svc.get(fx.provider_id).await.unwrap();
    let claims = fx
        .issuer
        .gitlab_claims(AUDIENCE, "group/app", "branch", "main");

    let verified = svc
        .validate_ci_jwt(&provider, &fx.issuer.sign(&claims))
        .await
        .expect("a token the mock issuer signed must verify");

    assert_eq!(verified["sub"], claims["sub"]);
    fx.teardown().await;
}

/// The full router answers the exchange route: no credential, 401.
#[tokio::test]
#[ignore]
async fn exchange_without_a_bearer_is_401_through_the_full_router() {
    let Some(fx) = Fixture::new().await else {
        return;
    };
    let (status, body) = fx.send("POST", TOKEN_ROUTE, None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    fx.teardown().await;
}

// ===========================================================================
// 2. Scenarios
// ===========================================================================

/// 2.1 — branches and a tag of one project exchange as the one account the
/// mapping reported at creation.
#[tokio::test]
#[ignore]
async fn every_ref_of_a_project_is_the_account_the_mapping_reported() {
    let Some(fx) = Fixture::new().await else {
        return;
    };
    let mapping = fx
        .create_mapping(json!({ "project_path": "group/app" }))
        .await;
    let reported = mapping["service_account_username"]
        .as_str()
        .expect("the create response names the account")
        .to_string();

    for (ref_type, git_ref) in [
        ("branch", "main"),
        ("branch", "feature/x"),
        ("tag", "v1.0.0"),
    ] {
        let (status, body) = fx.exchange_pipeline("group/app", ref_type, git_ref).await;
        assert_eq!(status, StatusCode::OK, "{ref_type} {git_ref}: {body}");
        assert_eq!(body["username"], json!(reported), "{ref_type} {git_ref}");
    }
    assert_eq!(
        fx.provider_accounts().await.len(),
        1,
        "one mapping, one account"
    );
    fx.teardown().await;
}

/// 2.2 — two projects admitted by an any-of filter are one principal.
#[tokio::test]
#[ignore]
async fn any_of_filter_admits_both_projects_as_one_account() {
    let Some(fx) = Fixture::new().await else {
        return;
    };
    let mapping = fx
        .create_mapping(json!({ "project_path": ["group/app", "someone/app-fork"] }))
        .await;
    let account = uuid_field(&mapping, "service_account_id");

    for project in ["group/app", "someone/app-fork"] {
        let (status, body) = fx.exchange_pipeline(project, "branch", "main").await;
        assert_eq!(status, StatusCode::OK, "{project}: {body}");
    }
    assert_eq!(fx.provider_accounts().await, vec![(account, true)]);
    fx.teardown().await;
}

/// 2.3 — access granted through a group works on a real repository request,
/// and the same request is refused before the grant (the control).
#[tokio::test]
#[ignore]
async fn a_group_grant_authorizes_the_exchanged_token() {
    let Some(mut fx) = Fixture::new().await else {
        return;
    };
    let mapping = fx
        .create_mapping(json!({ "project_path": "group/app" }))
        .await;
    let account = uuid_field(&mapping, "service_account_id");
    let repo = fx.private_repo().await;
    let repo_uri = format!("/api/v1/repositories/{repo}");

    let (status, body) = fx.exchange_pipeline("group/app", "branch", "main").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["access_token"].as_str().unwrap().to_string();
    let (before, _) = fx.send("GET", &repo_uri, Some(&token), None).await;
    assert_eq!(
        before,
        StatusCode::NOT_FOUND,
        "control: without a grant the private repository must not be visible"
    );

    fx.grant_via_group(account, &repo).await;

    let (status, body) = fx.exchange_pipeline("group/app", "tag", "v1.0.0").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["access_token"].as_str().unwrap().to_string();
    let (after, body) = fx.send("GET", &repo_uri, Some(&token), None).await;
    assert_eq!(
        after,
        StatusCode::OK,
        "the group grant must authorize the CI token: {body}"
    );
    fx.teardown().await;
}

/// 2.4 — disabling refuses, re-enabling restores, deleting refuses and
/// deactivates the account.
#[tokio::test]
#[ignore]
async fn mapping_lifecycle_governs_the_exchange() {
    let Some(fx) = Fixture::new().await else {
        return;
    };
    let mapping = fx
        .create_mapping(json!({ "project_path": "group/app" }))
        .await;
    let mapping_id = uuid_field(&mapping, "id");
    let account = uuid_field(&mapping, "service_account_id");
    let toggle = format!(
        "/api/v1/admin/ci-oidc/{}/mappings/{mapping_id}/toggle",
        fx.provider_id
    );

    fx.admin("PATCH", &toggle, Some(json!({ "enabled": false })))
        .await;
    let (status, body) = fx.exchange_pipeline("group/app", "branch", "main").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "disabled mapping: {body}");

    fx.admin("PATCH", &toggle, Some(json!({ "enabled": true })))
        .await;
    let (status, body) = fx.exchange_pipeline("group/app", "branch", "main").await;
    assert_eq!(status, StatusCode::OK, "re-enabled mapping: {body}");

    let (status, body) = fx
        .send(
            "DELETE",
            &format!(
                "/api/v1/admin/ci-oidc/{}/mappings/{mapping_id}",
                fx.provider_id
            ),
            Some(&fx.admin_bearer),
            None,
        )
        .await;
    assert!(status.is_success(), "delete mapping: {status} {body}");
    let (status, body) = fx.exchange_pipeline("group/app", "branch", "main").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "deleted mapping: {body}");
    assert_eq!(
        fx.provider_accounts().await,
        vec![(account, false)],
        "the account survives, inactive"
    );
    fx.teardown().await;
}

// ---------------------------------------------------------------------------
// 2.5 — verification refusals: 401, and no account created
// ---------------------------------------------------------------------------

/// Exchange `token` against a fixture with a catch-all mapping and assert a
/// 401 that created nothing. The mapping exists so that only verification can
/// be what refuses.
async fn assert_refused(fx: &Fixture, token: &str, case: &str) {
    let before = fx.provider_accounts().await;
    let (status, body) = fx.exchange(token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{case}: {body}");
    assert_eq!(
        fx.provider_accounts().await,
        before,
        "{case}: nothing created"
    );
}

#[tokio::test]
#[ignore]
async fn a_token_signed_by_an_unpublished_key_is_refused() {
    let Some(fx) = Fixture::new().await else {
        return;
    };
    fx.create_mapping(json!({})).await;
    let claims = fx
        .issuer
        .gitlab_claims(AUDIENCE, "group/app", "branch", "main");
    assert_refused(
        &fx,
        &fx.issuer.sign_with_foreign_key(&claims),
        "foreign key",
    )
    .await;
    fx.teardown().await;
}

#[tokio::test]
#[ignore]
async fn a_token_for_another_audience_is_refused() {
    let Some(fx) = Fixture::new().await else {
        return;
    };
    fx.create_mapping(json!({})).await;
    let claims =
        fx.issuer
            .gitlab_claims("https://someone-else.test", "group/app", "branch", "main");
    assert_refused(&fx, &fx.issuer.sign(&claims), "wrong aud").await;
    fx.teardown().await;
}

#[tokio::test]
#[ignore]
async fn an_expired_token_is_refused() {
    let Some(fx) = Fixture::new().await else {
        return;
    };
    fx.create_mapping(json!({})).await;
    let mut claims = fx
        .issuer
        .gitlab_claims(AUDIENCE, "group/app", "branch", "main");
    let now = chrono::Utc::now().timestamp();
    claims["iat"] = json!(now - 900);
    claims["nbf"] = json!(now - 900);
    // Past the verifier's 60 s default leeway.
    claims["exp"] = json!(now - 300);
    assert_refused(&fx, &fx.issuer.sign(&claims), "expired").await;
    fx.teardown().await;
}

/// A token signed by this issuer but naming another enabled provider's
/// issuer selects that provider, whose JWKS does not hold the key.
#[tokio::test]
#[ignore]
async fn a_token_claiming_another_providers_issuer_is_refused() {
    let Some(mut fx) = Fixture::new().await else {
        return;
    };
    let other = MockCiIssuer::start().await.expect("second issuer");
    let other_provider = fx.create_provider(other.issuer()).await;
    fx.extra_providers.push(other_provider);
    fx.create_mapping(json!({})).await;

    let mut claims = fx
        .issuer
        .gitlab_claims(AUDIENCE, "group/app", "branch", "main");
    claims["iss"] = json!(other.issuer());
    assert_refused(&fx, &fx.issuer.sign(&claims), "cross-issuer").await;
    fx.teardown().await;
}

#[tokio::test]
#[ignore]
async fn an_alg_none_token_is_refused() {
    let Some(fx) = Fixture::new().await else {
        return;
    };
    fx.create_mapping(json!({})).await;
    let claims = fx
        .issuer
        .gitlab_claims(AUDIENCE, "group/app", "branch", "main");
    assert_refused(&fx, &unsigned_alg_none(&claims), "alg none").await;
    fx.teardown().await;
}

/// Correctly signed, but no mapping admits it.
#[tokio::test]
#[ignore]
async fn a_valid_token_matching_no_mapping_is_refused() {
    let Some(fx) = Fixture::new().await else {
        return;
    };
    fx.create_mapping(json!({ "project_path": "group/app" }))
        .await;
    assert_eq!(
        fx.provider_accounts().await.len(),
        1,
        "the mapping's own account"
    );

    let claims = fx
        .issuer
        .gitlab_claims(AUDIENCE, "group/other", "branch", "main");
    assert_refused(&fx, &fx.issuer.sign(&claims), "no mapping").await;
    fx.teardown().await;
}
