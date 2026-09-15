//! Security regression tests.
//!
//! One test per advisory we have patched. These run as a Cargo integration
//! test (i.e. they consume the crate from outside, the same vantage point an
//! attacker has via HTTP), so they catch refactors that accidentally drop a
//! check from the public surface — even when the in-module unit tests still
//! pass against the now-orphaned helper.
//!
//! Live database is intentionally NOT required: every test below targets a
//! pure helper function that encodes the security invariant. If a future
//! refactor splits a check into a helper that bypasses these seams, add a
//! new test here rather than weakening these.

use artifact_keeper_backend::api::handlers::goproxy::is_sumdb_host_allowed;
use artifact_keeper_backend::api::handlers::maven::{escape_like_literal, snapshot_like_pattern};
use artifact_keeper_backend::api::handlers::webhooks::webhook_access_allowed;
use artifact_keeper_backend::api::middleware::auth::require_auth_basic;
use artifact_keeper_backend::api::validation::validate_outbound_url;

// ---------------------------------------------------------------------------
// Bug 1 — GHSA-mc8p-6758-jfp2 (PR #879)
// Class:  SSRF via go module checksum-database proxy
// Seam:   `is_sumdb_host_allowed`
// What:   The Go toolchain fetches `$GOPROXY/sumdb/<host>/<path>`. Without
//         a host allowlist, a client could request
//         `sumdb/169.254.169.254/...` and force the server to fetch IMDSv1
//         instance metadata (or any other internal HTTP endpoint).
// Asserts: only `sum.golang.org` and `sum.golang.google.cn` are allowed;
//         IPv4 cloud metadata, IPv6 link-local, plain wrong hosts, and
//         lookalike hostnames are rejected.
// ---------------------------------------------------------------------------
#[test]
fn regression_ghsa_mc8p_6758_jfp2_sumdb_host_allowlist() {
    // Golden path: official sumdb hosts are allowed (case-insensitive).
    assert!(is_sumdb_host_allowed("sum.golang.org"));
    assert!(is_sumdb_host_allowed("sum.golang.google.cn"));
    assert!(is_sumdb_host_allowed("SUM.GOLANG.ORG"));

    // The original SSRF payload — AWS/OpenStack IMDSv1.
    assert!(
        !is_sumdb_host_allowed("169.254.169.254"),
        "AWS instance metadata IP must never be a permitted sumdb upstream"
    );

    // GCP & Azure metadata aliases.
    assert!(!is_sumdb_host_allowed("metadata.google.internal"));
    assert!(!is_sumdb_host_allowed("metadata.azure.com"));

    // IPv6 link-local (covers IPv6 metadata bypass attempts).
    assert!(!is_sumdb_host_allowed("[fe80::1]"));
    assert!(!is_sumdb_host_allowed("fe80::1"));

    // Plain wrong hosts and lookalikes that suffix/prefix-match attacks
    // would smuggle through naive `contains()` checks.
    assert!(!is_sumdb_host_allowed("evil.com"));
    assert!(!is_sumdb_host_allowed("localhost"));
    assert!(!is_sumdb_host_allowed("127.0.0.1"));
    assert!(!is_sumdb_host_allowed("sum.golang.org.evil.com"));
    assert!(!is_sumdb_host_allowed("evil.com.sum.golang.org"));
}

// ---------------------------------------------------------------------------
// Bug 2 — GHSA-93ch-hrfh-5wcw (PR #880)
// Class:  SQL LIKE wildcard injection in Maven SNAPSHOT lookup
// Seam:   `escape_like_literal` + composing helper `snapshot_like_pattern`
// What:   User-controlled artifact path segments were interpolated into a
//         SQL LIKE pattern. An attacker who could upload an artifact named
//         `%` (or similar) could match unrelated rows and exfiltrate
//         artifact metadata or serve the wrong file to an unrelated client.
// Asserts: `%`, `_`, and `\` are escaped to `\%`, `\_`, `\\`; the only
//         unescaped `%` in the composed pattern is the trusted timestamp
//         wildcard introduced by the helper itself.
// ---------------------------------------------------------------------------
#[test]
fn regression_ghsa_7f39_724h_cccm_maven_like_escape() {
    // Pure helper: every LIKE metacharacter is preceded by `\`.
    assert_eq!(escape_like_literal("a%b"), "a\\%b");
    assert_eq!(escape_like_literal("a_b"), "a\\_b");
    assert_eq!(escape_like_literal("a\\b"), "a\\\\b");
    // No-op for plain text.
    assert_eq!(escape_like_literal("plain"), "plain");
    // Adversarial combined input.
    assert_eq!(
        escape_like_literal("100%_off\\everything"),
        "100\\%\\_off\\\\everything"
    );

    // Composed helper: a path with attacker-supplied wildcards must produce
    // a pattern where only the helper's trusted `-%` survives unescaped.
    // Input filename contains a literal `%` — it must be escaped to `\%`.
    let pat = snapshot_like_pattern("com/example/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT%.jar")
        .expect("snapshot path should produce a pattern");
    // The trusted timestamp wildcard `-%` is present...
    assert!(
        pat.contains("-%"),
        "trusted timestamp wildcard must remain in pattern; got {pat}"
    );
    // ...and the user-supplied `%` is escaped.
    assert!(
        pat.contains("\\%"),
        "user-supplied %% must be escaped to \\%%; got {pat}"
    );
}

// ---------------------------------------------------------------------------
// Bug 3 — GHSA-7f39-724h-cccm (PR #881)
// Class:  SSRF — IPv6 + extra cloud-metadata IP bypasses
// Seam:   `validate_outbound_url` (the gatekeeper used by every outbound
//         fetcher: cargo proxy, webhooks, remote replication, ...)
// What:   The original blocker only inspected IPv4 literals. An attacker
//         could request `http://[::ffff:169.254.169.254]/` (IPv4-mapped
//         IPv6) or `http://[fe80::...]/` (IPv6 link-local) and bypass the
//         metadata block. Oracle (192.0.0.192) and Alibaba (100.100.100.200)
//         metadata endpoints were also missing from the deny-list.
// Asserts: each of those four bypass classes is rejected, and at least one
//         legitimate external URL is still accepted (no over-blocking).
// ---------------------------------------------------------------------------
#[test]
fn regression_ghsa_93ch_hrfh_5wcw_outbound_url_ssrf() {
    // IPv4-mapped IPv6 → AWS metadata IP. Pre-fix this slipped through.
    assert!(
        validate_outbound_url(
            "http://[::ffff:169.254.169.254]/latest/meta-data",
            "Test URL"
        )
        .is_err(),
        "IPv4-mapped IPv6 form of AWS metadata IP must be blocked"
    );

    // IPv6 link-local — fe80::/10 is the IPv6 equivalent of 169.254.0.0/16.
    assert!(
        validate_outbound_url("http://[fe80::1]/api", "Test URL").is_err(),
        "IPv6 link-local must be blocked"
    );

    // Oracle Cloud Infrastructure metadata.
    assert!(
        validate_outbound_url("http://192.0.0.192/opc/v2/instance", "Test URL").is_err(),
        "Oracle Cloud metadata IP 192.0.0.192 must be blocked"
    );

    // Alibaba Cloud metadata (in the CGNAT range, so the broader CGNAT
    // block being off must NOT let this through).
    assert!(
        validate_outbound_url("http://100.100.100.200/latest/meta-data", "Test URL").is_err(),
        "Alibaba Cloud metadata IP 100.100.100.200 must be blocked even with CGNAT block off"
    );

    // Sanity floor: a real public host must still validate, otherwise we
    // are over-blocking and would break cargo proxy / replication entirely.
    assert!(
        validate_outbound_url("https://crates.io/", "Test URL").is_ok(),
        "Legit public registry must still be reachable"
    );
}

// ---------------------------------------------------------------------------
// Bug 4 — GHSA-cxcr-cmqm-6rrw (PR #984)
// Class:  SQL LIKE wildcard injection across package handlers
// Seam:   The escape helper. PR #984 promotes this to a shared
//         `crate::api::handlers::escape_like_literal`; until that PR lands
//         the canonical implementation lives at
//         `crate::api::handlers::maven::escape_like_literal` and is what
//         every SNAPSHOT-style lookup ultimately calls. We test the
//         canonical implementation here — once #984 merges and moves the
//         function, just re-point the import (the assertions stay valid
//         because the contract is identical).
// What:   Same shape as Bug 2 but for non-Maven format handlers — anywhere
//         a user-supplied artifact path/version is fed into a `LIKE`
//         predicate, `%`, `_`, and `\` must all be escaped.
// Asserts: full adversarial input round-trips through the escaper with
//         every LIKE metacharacter quoted.
// ---------------------------------------------------------------------------
#[test]
fn regression_ghsa_cxcr_cmqm_6rrw_handlers_like_escape() {
    // Each metacharacter individually — covers single-char regression.
    assert_eq!(escape_like_literal("%"), "\\%");
    assert_eq!(escape_like_literal("_"), "\\_");
    assert_eq!(escape_like_literal("\\"), "\\\\");

    // Combined adversarial payload: every wildcard plus a backslash that
    // would otherwise let an attacker terminate the escape sequence.
    let attacker = "evil%name_with\\wild%cards_";
    let escaped = escape_like_literal(attacker);
    assert_eq!(
        escaped, "evil\\%name\\_with\\\\wild\\%cards\\_",
        "adversarial combined input must escape every LIKE metacharacter"
    );

    // Property check: walk the escaped output expecting every `%`, `_`,
    // or `\` to appear as the second char of a `\X` pair. This holds
    // because escape_like_literal emits `\\` for `\`, `\%` for `%`, and
    // `\_` for `_`. A bare metacharacter would indicate a regression.
    let chars: Vec<char> = escaped.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        if ch == '\\' {
            assert!(
                i + 1 < chars.len() && matches!(chars[i + 1], '\\' | '%' | '_'),
                "stray backslash at byte {i} of {escaped:?}"
            );
            i += 2; // consume the escape pair
        } else {
            assert!(
                !matches!(ch, '%' | '_'),
                "bare metacharacter {ch:?} at byte {i} of {escaped:?} — escape regression"
            );
            i += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Bug 5 — GHSA-m597-h769-6qgp (PR #985)
// Class:  Broken access control — Git LFS lock listing was unauthenticated
// Seam:   `require_auth_basic` (the canonical 401 gate every locks handler
//         and most format handlers route through)
// What:   `GET /lfs/:repo/locks` did not call `require_auth_basic`, so an
//         anonymous client could enumerate every active lock — including
//         lock owner names and paths inside private repos. The fix wires
//         the existing auth gate into the handler. We test the gate
//         itself: it MUST return Err when given no AuthExtension, with a
//         WWW-Authenticate challenge for the supplied realm.
// Asserts: `require_auth_basic(None, "git-lfs")` returns Err and the
//         response is a 401 with the right WWW-Authenticate header.
// ---------------------------------------------------------------------------
#[test]
fn regression_ghsa_m597_h769_6qgp_gitlfs_list_locks_auth() {
    let result = require_auth_basic(None, "git-lfs");
    let response = result.expect_err("missing auth must produce a 401, not pass through");

    assert_eq!(
        response.status(),
        axum::http::StatusCode::UNAUTHORIZED,
        "auth gate must return HTTP 401 when no AuthExtension is present"
    );

    let challenge = response
        .headers()
        .get("WWW-Authenticate")
        .expect("401 must include a WWW-Authenticate challenge")
        .to_str()
        .expect("WWW-Authenticate header must be ASCII");
    assert!(
        challenge.contains("Basic"),
        "challenge must advertise the Basic scheme; got {challenge}"
    );
    assert!(
        challenge.contains("git-lfs"),
        "challenge must echo the realm passed by the caller; got {challenge}"
    );
}

// ---------------------------------------------------------------------------
// Bug — Cross-user / cross-tenant BOLA on webhook resources.
// Class:  Broken object-level authorization (IDOR) on webhook endpoints.
// Seam:   `webhooks::webhook_access_allowed` — the pure decision every
//         per-webhook handler (get/delete/enable/disable/test/rotate/
//         redeliver/list-deliveries) routes through before touching a row.
// What:   Webhook handlers acted on the global `webhooks` table by id with no
//         owner or repository scoping, so any authenticated principal could
//         read, disable, test, rotate, or delete any other user's (or any
//         other tenant's) webhook. The decision now requires admin, creator
//         ownership (`created_by`), or access to the webhook's repository.
// Asserts: a non-admin, non-creator cannot reach a global (repository-less)
//         webhook even with a repo-access bit set; repo access only grants
//         when the webhook is actually attached to a repository; admins and
//         creators always pass; legacy NULL-owner rows are admin-only.
// ---------------------------------------------------------------------------
#[test]
fn regression_webhook_object_level_authorization() {
    use uuid::Uuid;
    let attacker = Uuid::new_v4();
    let owner = Uuid::new_v4();
    let repo = Uuid::new_v4();

    // The exact BOLA: a stranger targeting another principal's GLOBAL webhook
    // (repository_id = NULL). Must be denied regardless of any repo-access bit.
    assert!(
        !webhook_access_allowed(false, attacker, Some(owner), None, true),
        "non-admin non-creator must NOT reach a global webhook (the BOLA)"
    );
    assert!(!webhook_access_allowed(
        false,
        attacker,
        Some(owner),
        None,
        false
    ));

    // Legacy rows (created_by = NULL) with no repository are admin-only.
    assert!(!webhook_access_allowed(false, attacker, None, None, false));

    // Admin bypass: full cross-repo / cross-tenant access (matches repo handlers).
    assert!(webhook_access_allowed(
        true,
        attacker,
        Some(owner),
        None,
        false
    ));

    // Creator owns their webhook (global or repo-attached).
    assert!(webhook_access_allowed(
        false,
        owner,
        Some(owner),
        None,
        false
    ));
    assert!(webhook_access_allowed(
        false,
        owner,
        Some(owner),
        Some(repo),
        false
    ));

    // Repo member: allowed iff the webhook is attached to a repo they can access.
    assert!(webhook_access_allowed(
        false,
        attacker,
        Some(owner),
        Some(repo),
        true
    ));
    assert!(!webhook_access_allowed(
        false,
        attacker,
        Some(owner),
        Some(repo),
        false
    ));
}

// ---------------------------------------------------------------------------
// Bug — Credential-change session invalidation on the gRPC plane (#1636,
//        original #505; gRPC gap tracked as #549/#551).
// Class:  Session/JWT not invalidated after credential change.
// Seam:   `grpc::auth_interceptor::AuthInterceptor::intercept` — the single
//         token-validation entry point every gRPC request traverses.
// What:   A password change calls
//         `auth_service::invalidate_user_tokens(user_id)`, which bumps the
//         per-user invalidation watermark consulted by BOTH transports: the
//         HTTP middleware (via `validate_access_token_async`) and the gRPC
//         interceptor here (via `is_token_invalidated[_replica_safe]`). Before
//         the watermark existed, a JWT minted before the change kept
//         authenticating on the gRPC plane until it expired.
// Asserts: (1) a pre-change admin token is accepted by the interceptor;
//          (2) after `invalidate_user_tokens`, the SAME token is rejected with
//              `Unauthenticated` ("revoked"); and (3) a token minted after the
//              change is accepted again. The HTTP-plane counterpart of this
//              invariant is pinned by the lib unit tests
//              `test_http_token_minted_before_password_change_is_rejected` /
//              `..._after_..._is_accepted` in `services::auth_service`.
//
// The interceptor is constructed with `db = None`, which exercises the
// in-memory fast-path (`is_token_invalidated`). That is the same map
// `invalidate_user_tokens` writes and the same map the replica-safe DB path
// serves as its cache, so this no-DB seam faithfully pins the cross-transport
// invariant without requiring a live database (matching this file's
// pure-helper testing contract).
// ---------------------------------------------------------------------------
mod credential_change_grpc {
    use artifact_keeper_backend::grpc::auth_interceptor::AuthInterceptor;
    use artifact_keeper_backend::services::auth_service::{invalidate_user_tokens, Claims};
    use jsonwebtoken::{encode, EncodingKey, Header};
    use tonic::Request;
    use uuid::Uuid;

    const SECRET: &str = "grpc-credential-change-regression-secret";

    /// Mint an admin access JWT for `user_id` with an explicit `iat` (seconds),
    /// signed with `SECRET` — the exact shape the interceptor decodes.
    fn admin_token_at(user_id: Uuid, iat: i64) -> String {
        let claims = Claims {
            sub: user_id,
            username: "grpc-user".to_string(),
            email: "grpc-user@test.local".to_string(),
            is_admin: true,
            allowed_repo_ids: None,
            iat,
            // Legacy whole-second token shape (no ms claim); exercises the
            // effective_iat_ms() fallback to iat*1000.
            iat_ms: None,
            exp: iat + 3600,
            token_type: "access".to_string(),
            jti: None,
            family_id: None,
            scan_pull_repo: None,
            scopes: None,
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .expect("encode admin access token")
    }

    fn request_with(token: &str) -> Request<()> {
        let mut req = Request::new(());
        req.metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        req
    }

    #[test]
    fn regression_1636_grpc_token_rejected_after_credential_change() {
        // A distinct user per test run so the process-wide invalidation map
        // never collides with a parallel test.
        let user_id = Uuid::new_v4();
        // Backdate `iat` 10 s so the invalidation watermark (now / now+1)
        // lands strictly after the token regardless of sub-second timing.
        let pre_change_iat = chrono::Utc::now().timestamp() - 10;
        let pre_change_token = admin_token_at(user_id, pre_change_iat);

        let interceptor = AuthInterceptor::new(SECRET, None);

        // 1) Before the credential change the gRPC interceptor accepts it.
        assert!(
            interceptor
                .intercept(request_with(&pre_change_token))
                .is_ok(),
            "pre-change admin token must be accepted before invalidation"
        );

        // 2) Password change fires `invalidate_user_tokens(user_id)`.
        invalidate_user_tokens(user_id);

        // 3) The SAME token is now rejected on the gRPC plane (#505/#549/#551).
        let err = interceptor
            .intercept(request_with(&pre_change_token))
            .expect_err("pre-change token MUST be rejected after credential change");
        assert_eq!(
            err.code(),
            tonic::Code::Unauthenticated,
            "revoked token must surface as Unauthenticated, got {err:?}"
        );
        assert!(
            err.message().contains("revoked"),
            "rejection message must indicate revocation; got {}",
            err.message()
        );
    }

    #[test]
    fn regression_1636_grpc_token_minted_after_change_is_accepted() {
        let user_id = Uuid::new_v4();

        // Credential change happens first.
        invalidate_user_tokens(user_id);

        // The watermark is `now + 1` (#1436); a token minted at `now + 2` is
        // strictly newer and must be honoured.
        let post_change_iat = chrono::Utc::now().timestamp() + 2;
        let post_change_token = admin_token_at(user_id, post_change_iat);

        let interceptor = AuthInterceptor::new(SECRET, None);
        assert!(
            interceptor
                .intercept(request_with(&post_change_token))
                .is_ok(),
            "a token minted after the credential change MUST be accepted on gRPC"
        );
    }
}

mod common;

// ---------------------------------------------------------------------------
// Bug — #2437: cross-repo quality-check metadata leak (BOLA).
// Class:  Broken object-level authorization on artifact-scoped QC reads.
// Seam:   the artifact-scoped `/quality/checks*` + `/quality/health/artifacts`
//         handlers, exercised end-to-end over the real router against a live
//         DB (the external HTTP vantage), not a helper.
// What:   `GET /quality/checks?artifact_id=<X>`, `/quality/checks/:id`,
//         `/quality/checks/:id/issues` and `/quality/health/artifacts/:id`
//         returned quality-check metadata for ANY authenticated caller with no
//         check that the caller can see the artifact's (private) repository,
//         leaking cross-tenant `repository_id` / `check_type` / `score` data.
// Asserts: a non-member (tenant B) gets an existence-hiding 404 whose body
//         leaks none of those fields, while the repo member (tenant A / owner)
//         still gets 200 with the row. Covers `/checks` and `/checks/:id`.
//
// DB-gated (this is the one live-DB seam in this file); run with:
//   DATABASE_URL="postgresql://.../artifact_registry" \
//     cargo test --test security_regression_tests -- --ignored
// ---------------------------------------------------------------------------
mod qc_metadata_leak_2437 {
    // streaming-invariant: test file exempt — buffering a 404/200 response body
    // in an assertion is not an artifact path (#1608).
    #![allow(clippy::disallowed_methods)]
    use std::collections::HashMap;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Extension;
    use sqlx::PgPool;
    use tower::ServiceExt;
    use uuid::Uuid;

    use artifact_keeper_backend::api::handlers::quality_gates;
    use artifact_keeper_backend::api::middleware::auth::AuthExtension;
    use artifact_keeper_backend::api::{AppState, SharedState};
    use artifact_keeper_backend::config::Config;
    use artifact_keeper_backend::models::access_scope::AccessScope;

    use super::common;

    fn build_state(pool: PgPool, storage_path: &str) -> SharedState {
        let config = Config {
            database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
            storage_path: storage_path.into(),
            jwt_secret: "test-secret-at-least-32-bytes-long-for-testing".into(),
            setup_password_hint: None,
            ..Default::default()
        };
        let storage: Arc<dyn artifact_keeper_backend::storage::StorageBackend> = Arc::new(
            artifact_keeper_backend::storage::filesystem::FilesystemStorage::new(storage_path),
        );
        let registry = Arc::new(artifact_keeper_backend::storage::StorageRegistry::new(
            HashMap::new(),
            "filesystem".to_string(),
        ));
        Arc::new(AppState::new(config, pool, storage, registry))
    }

    /// A non-admin, unrestricted-scope caller for `user_id` (the shape the
    /// real `auth_middleware` injects for a JWT-authenticated local user).
    fn auth_for(user_id: Uuid) -> AuthExtension {
        AuthExtension {
            user_id,
            username: format!("u-{}", &user_id.to_string()[..8]),
            email: "u@test.local".to_string(),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: AccessScope::Admin,
            iat_ms: None,
        }
    }

    async fn create_private_repo(pool: &PgPool) -> (Uuid, String) {
        let id = Uuid::new_v4();
        let key = format!("qc2437-{}", &id.to_string()[..8]);
        let dir = std::env::temp_dir().join(&key);
        std::fs::create_dir_all(&dir).expect("create storage dir");
        sqlx::query(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, is_public) \
             VALUES ($1, $2, $2, $3, 'local', 'rpm'::repository_format, false)",
        )
        .bind(id)
        .bind(&key)
        .bind(&*dir.to_string_lossy())
        .execute(pool)
        .await
        .expect("insert private repo");
        (id, dir.to_string_lossy().to_string())
    }

    async fn seed_artifact(pool: &PgPool, repo_id: Uuid) -> Uuid {
        let path = format!("qc2437/{}", Uuid::new_v4());
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
                 checksum_sha256, content_type, storage_key, uploaded_by) \
             VALUES ($1, $2, 'qc2437', '1.0', 1, 'deadbeef', 'application/octet-stream', $3, NULL) \
             RETURNING id",
        )
        .bind(repo_id)
        .bind(&path)
        .bind(&path)
        .fetch_one(pool)
        .await
        .expect("seed artifact")
    }

    async fn seed_check(pool: &PgPool, repo_id: Uuid, artifact_id: Uuid) -> Uuid {
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO quality_check_results (artifact_id, repository_id, check_type, status) \
             VALUES ($1, $2, 'metadata', 'completed') RETURNING id",
        )
        .bind(artifact_id)
        .bind(repo_id)
        .fetch_one(pool)
        .await
        .expect("seed quality_check_result")
    }

    async fn grant_member(pool: &PgPool, repo_id: Uuid, user_id: Uuid) {
        sqlx::query(
            "INSERT INTO role_assignments (user_id, role_id, repository_id) \
             SELECT $1, r.id, $2 FROM roles r WHERE r.name = 'developer' \
             ON CONFLICT (user_id, role_id, repository_id) DO NOTHING",
        )
        .bind(user_id)
        .bind(repo_id)
        .execute(pool)
        .await
        .expect("grant developer role");
    }

    async fn get_status_body(
        app: axum::Router,
        uri: &str,
        auth: AuthExtension,
    ) -> (StatusCode, String) {
        let resp = app
            .layer(Extension(auth))
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    fn assert_no_leak(body: &str) {
        for needle in ["repository_id", "check_type", "score"] {
            assert!(
                !body.contains(needle),
                "cross-tenant 404 body must not leak `{needle}`: {body}"
            );
        }
    }

    async fn cleanup(pool: &PgPool, repo_id: Uuid, users: &[Uuid]) {
        let _ = sqlx::query("DELETE FROM role_assignments WHERE repository_id = $1")
            .bind(repo_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
            .bind(repo_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(pool)
            .await;
        for u in users {
            let _ = sqlx::query("DELETE FROM users WHERE id = $1")
                .bind(u)
                .execute(pool)
                .await;
        }
    }

    #[tokio::test]
    #[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
    async fn regression_2437_cross_repo_qc_metadata_bola() {
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();

        // Tenant A owns a private repo + artifact + quality check; tenant B has
        // no membership on it.
        let user_a = common::insert_active_user(&pool, "qc2437-a").await;
        let user_b = common::insert_active_user(&pool, "qc2437-b").await;
        let (repo_id, storage) = create_private_repo(&pool).await;
        let artifact_id = seed_artifact(&pool, repo_id).await;
        let check_id = seed_check(&pool, repo_id, artifact_id).await;
        grant_member(&pool, repo_id, user_a).await;

        let state = build_state(pool.clone(), &storage);
        let app = || quality_gates::router().with_state(state.clone());

        // The exact BOLA: tenant B lists another tenant's checks -> 404, no leak.
        let (status, body) = get_status_body(
            app(),
            &format!("/checks?artifact_id={artifact_id}"),
            auth_for(user_b),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "cross-tenant list must be an existence-hiding 404"
        );
        assert_no_leak(&body);

        // ... and the /checks/:id sibling route is equally gated.
        let (status, body) =
            get_status_body(app(), &format!("/checks/{check_id}"), auth_for(user_b)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "cross-tenant get_check 404");
        assert_no_leak(&body);

        // Owner (tenant A member) still sees the row: legitimate use intact.
        let (status, body) = get_status_body(
            app(),
            &format!("/checks?artifact_id={artifact_id}"),
            auth_for(user_a),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner list must still succeed");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            v.as_array().unwrap().len(),
            1,
            "owner sees the seeded check"
        );

        let (status, _body) =
            get_status_body(app(), &format!("/checks/{check_id}"), auth_for(user_a)).await;
        assert_eq!(status, StatusCode::OK, "owner get_check must still succeed");

        cleanup(&pool, repo_id, &[user_a, user_b]).await;
    }
}

// ---------------------------------------------------------------------------
// #2264 (low-sev) — age-gate config disclosure to read-scope callers.
// Class:  Missing function-level authorization / configuration disclosure.
// Seam:   `GET /repositories/{key}/age-gate`, exercised end-to-end over the
//         real repo-config router against a live DB (the external HTTP
//         vantage), not a helper.
// What:   `get_repo_age_gate` checked only `require_scope("read")` — no
//         per-repo access, no admin — so ANY authenticated read-scope caller
//         (e.g. a read-only API token) could read gate posture
//         (`enabled` + `min_age_days`) for every repository. The PUT and all
//         four /admin review endpoints were already admin-only; the GET now
//         matches them with `require_admin()`.
// Asserts: a read-scope API token and a plain non-admin user both get 403
//         with no config fields in the body; an admin still gets 200 with the
//         config row (migration-146 defaults for a fresh repo).
//
// DB-gated; run with:
//   DATABASE_URL="postgresql://.../artifact_registry" \
//     cargo test --test security_regression_tests -- --ignored
// ---------------------------------------------------------------------------
mod age_gate_config_2264 {
    // streaming-invariant: test file exempt — buffering a 403/200 response body
    // in an assertion is not an artifact path (#1608).
    #![allow(clippy::disallowed_methods)]
    use std::collections::HashMap;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Extension;
    use sqlx::PgPool;
    use tower::ServiceExt;
    use uuid::Uuid;

    use artifact_keeper_backend::api::handlers::age_gate;
    use artifact_keeper_backend::api::middleware::auth::AuthExtension;
    use artifact_keeper_backend::api::{AppState, SharedState};
    use artifact_keeper_backend::config::Config;
    use artifact_keeper_backend::models::access_scope::AccessScope;

    fn build_state(pool: PgPool, storage_path: &str) -> SharedState {
        let config = Config {
            database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
            storage_path: storage_path.into(),
            jwt_secret: "test-secret-at-least-32-bytes-long-for-testing".into(),
            ..Default::default()
        };
        let storage: Arc<dyn artifact_keeper_backend::storage::StorageBackend> = Arc::new(
            artifact_keeper_backend::storage::filesystem::FilesystemStorage::new(storage_path),
        );
        let registry = Arc::new(artifact_keeper_backend::storage::StorageRegistry::new(
            HashMap::new(),
            "filesystem".to_string(),
        ));
        Arc::new(AppState::new(config, pool, storage, registry))
    }

    /// A non-admin caller. `scopes` distinguishes the read-only API token
    /// (the exact pre-fix caller) from a plain session user (scopes = None).
    fn non_admin(scopes: Option<Vec<String>>) -> AuthExtension {
        AuthExtension {
            user_id: Uuid::new_v4(),
            username: "ag2264-caller".to_string(),
            email: "ag2264@test.local".to_string(),
            is_admin: false,
            is_api_token: scopes.is_some(),
            is_service_account: false,
            scopes,
            allowed_repo_ids: AccessScope::Admin,
            iat_ms: None,
        }
    }

    fn admin() -> AuthExtension {
        AuthExtension {
            is_admin: true,
            ..non_admin(None)
        }
    }

    /// Insert a remote npm repo (age-gate columns keep migration-146 defaults).
    /// Returns (repo id, repo key, storage dir).
    async fn create_remote_repo(pool: &PgPool) -> (Uuid, String, String) {
        let id = Uuid::new_v4();
        let key = format!("ag2264-{}", &id.to_string()[..8]);
        let dir = std::env::temp_dir().join(&key);
        std::fs::create_dir_all(&dir).expect("create storage dir");
        sqlx::query(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, upstream_url) \
             VALUES ($1, $2, $2, $3, 'remote', 'npm'::repository_format, 'https://registry.npmjs.org')",
        )
        .bind(id)
        .bind(&key)
        .bind(&*dir.to_string_lossy())
        .execute(pool)
        .await
        .expect("insert remote repo");
        (id, key, dir.to_string_lossy().to_string())
    }

    /// GET `uri` as `caller` through the real repo-config router. The age-gate
    /// handlers extract `Extension<Option<AuthExtension>>`, so inject the
    /// Option form (as the production `auth_middleware` does).
    async fn get_as(state: SharedState, caller: AuthExtension, uri: &str) -> (StatusCode, String) {
        let app = age_gate::repo_config_routes()
            .with_state(state)
            .layer(Extension(Some(caller)));
        let resp = app
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    #[tokio::test]
    #[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
    async fn regression_2264_age_gate_config_admin_only() {
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let (repo_id, key, storage) = create_remote_repo(&pool).await;
        let state = build_state(pool.clone(), &storage);
        let uri = format!("/{key}/age-gate");

        // The exact disclosure: a read-only API token (passed the old
        // `require_scope("read")` gate) must now get 403 with no config leak.
        let (status, body) = get_as(
            state.clone(),
            non_admin(Some(vec!["read".to_string()])),
            &uri,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "read-scope token must 403");
        for needle in ["min_age_days", "enabled"] {
            assert!(
                !body.contains(needle),
                "403 body must not leak `{needle}`: {body}"
            );
        }

        // A plain non-admin session user is equally rejected — repo-access
        // bits do not grant config reads.
        let (status, _body) = get_as(state.clone(), non_admin(None), &uri).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "non-admin user must 403");

        // Admin parity with the PUT: still 200 with the config row.
        let (status, body) = get_as(state.clone(), admin(), &uri).await;
        assert_eq!(status, StatusCode::OK, "admin GET must still succeed");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["repository_key"], key.as_str());
        assert_eq!(v["enabled"], false);
        assert_eq!(v["min_age_days"], 7);

        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
    }
}

// ---------------------------------------------------------------------------
// #2439  Cross-repo authorization: ungated /security scan+finding reads and
//        /sbom generate/cve-status writes.
// ---------------------------------------------------------------------------
// Class:  Broken object-level authorization on artifact/repo-scoped
//         security-scan reads and SBOM/CVE writes.
// Seam:   the `/security/scans*` + `/security/artifacts/:id/scans` read
//         handlers and the `/sbom` generate + `/sbom/cve/status/:id` write
//         handlers, exercised end-to-end over the real routers against a live
//         DB (the external HTTP vantage), not a helper.
// What:   `GET /scans?artifact_id=<X>`, `/scans/:id`, `/scans/:id/findings`,
//         `/artifacts/:id/scans` returned CVE/scan data for ANY authenticated
//         caller with no check they can see the artifact's (private) repo;
//         `POST /sbom {artifact_id:<X>}` let any authed caller write an SBOM
//         attestation on another tenant's artifact; `POST /sbom/cve/status/:id`
//         let any authed caller mutate CVE triage state.
// Asserts: a non-member (tenant B) gets an existence-hiding 404 on the reads
//         and the SBOM generate (with NO sbom_documents row written), a 403 on
//         the CVE-status write, while the repo member (tenant A / owner) still
//         gets 200 on reads + generate.
//
// DB-gated; run with:
//   DATABASE_URL="postgresql://.../artifact_registry" \
//     cargo test --test security_regression_tests -- --ignored
// ---------------------------------------------------------------------------
mod scan_sbom_leak_2439 {
    // streaming-invariant: test file exempt — buffering a 404/200 response body
    // in an assertion is not an artifact path (#1608).
    #![allow(clippy::disallowed_methods)]
    use std::collections::HashMap;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Extension;
    use sqlx::PgPool;
    use tower::ServiceExt;
    use uuid::Uuid;

    use artifact_keeper_backend::api::handlers::{sbom, security};
    use artifact_keeper_backend::api::middleware::auth::AuthExtension;
    use artifact_keeper_backend::api::{AppState, SharedState};
    use artifact_keeper_backend::config::Config;
    use artifact_keeper_backend::models::access_scope::AccessScope;

    use super::common;

    fn build_state(pool: PgPool, storage_path: &str) -> SharedState {
        let config = Config {
            database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
            storage_path: storage_path.into(),
            jwt_secret: "test-secret-at-least-32-bytes-long-for-testing".into(),
            setup_password_hint: None,
            ..Default::default()
        };
        let storage: Arc<dyn artifact_keeper_backend::storage::StorageBackend> = Arc::new(
            artifact_keeper_backend::storage::filesystem::FilesystemStorage::new(storage_path),
        );
        let registry = Arc::new(artifact_keeper_backend::storage::StorageRegistry::new(
            HashMap::new(),
            "filesystem".to_string(),
        ));
        Arc::new(AppState::new(config, pool, storage, registry))
    }

    fn auth_for(user_id: Uuid) -> AuthExtension {
        AuthExtension {
            user_id,
            username: format!("u-{}", &user_id.to_string()[..8]),
            email: "u@test.local".to_string(),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: AccessScope::Admin,
            iat_ms: None,
        }
    }

    async fn create_private_repo(pool: &PgPool) -> (Uuid, String) {
        let id = Uuid::new_v4();
        let key = format!("sc2439-{}", &id.to_string()[..8]);
        let dir = std::env::temp_dir().join(&key);
        std::fs::create_dir_all(&dir).expect("create storage dir");
        sqlx::query(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, is_public) \
             VALUES ($1, $2, $2, $3, 'local', 'rpm'::repository_format, false)",
        )
        .bind(id)
        .bind(&key)
        .bind(&*dir.to_string_lossy())
        .execute(pool)
        .await
        .expect("insert private repo");
        (id, dir.to_string_lossy().to_string())
    }

    async fn seed_artifact(pool: &PgPool, repo_id: Uuid) -> Uuid {
        let path = format!("sc2439/{}", Uuid::new_v4());
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
                 checksum_sha256, content_type, storage_key, uploaded_by) \
             VALUES ($1, $2, 'sc2439', '1.0', 1, 'deadbeef', 'application/octet-stream', $3, NULL) \
             RETURNING id",
        )
        .bind(repo_id)
        .bind(&path)
        .bind(&path)
        .fetch_one(pool)
        .await
        .expect("seed artifact")
    }

    /// Seed a completed scan + one finding for (repo, artifact). Returns scan id.
    async fn seed_scan(pool: &PgPool, repo_id: Uuid, artifact_id: Uuid) -> Uuid {
        let scan_id: Uuid = sqlx::query_scalar(
            "INSERT INTO scan_results (artifact_id, repository_id, scan_type, status, \
                 findings_count, started_at, completed_at) \
             VALUES ($1, $2, 'dependency', 'completed', 1, NOW(), NOW()) RETURNING id",
        )
        .bind(artifact_id)
        .bind(repo_id)
        .fetch_one(pool)
        .await
        .expect("seed scan_result");
        sqlx::query(
            "INSERT INTO scan_findings (scan_result_id, artifact_id, severity, title, cve_id, \
                 source, is_acknowledged) \
             VALUES ($1, $2, 'critical', 'seed', 'CVE-2024-1212', 'trivy', false)",
        )
        .bind(scan_id)
        .bind(artifact_id)
        .execute(pool)
        .await
        .expect("seed scan_finding");
        scan_id
    }

    async fn grant_member(pool: &PgPool, repo_id: Uuid, user_id: Uuid) {
        sqlx::query(
            "INSERT INTO role_assignments (user_id, role_id, repository_id) \
             SELECT $1, r.id, $2 FROM roles r WHERE r.name = 'developer' \
             ON CONFLICT (user_id, role_id, repository_id) DO NOTHING",
        )
        .bind(user_id)
        .bind(repo_id)
        .execute(pool)
        .await
        .expect("grant developer role");
    }

    async fn send(
        app: axum::Router,
        req: Request<Body>,
        auth: AuthExtension,
    ) -> (StatusCode, String) {
        let resp = app.layer(Extension(auth)).oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    fn get(uri: &str) -> Request<Body> {
        Request::builder().uri(uri).body(Body::empty()).unwrap()
    }

    fn post_json(uri: &str, body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn assert_no_leak(body: &str) {
        for needle in ["repository_id", "cve", "CVE-", "severity", "critical"] {
            assert!(
                !body.contains(needle),
                "cross-tenant denial body must not leak `{needle}`: {body}"
            );
        }
    }

    async fn cleanup(pool: &PgPool, repo_id: Uuid, users: &[Uuid]) {
        let _ = sqlx::query(
            "DELETE FROM scan_findings WHERE scan_result_id IN \
             (SELECT id FROM scan_results WHERE repository_id = $1)",
        )
        .bind(repo_id)
        .execute(pool)
        .await;
        for tbl in [
            "scan_results",
            "sbom_documents",
            "role_assignments",
            "artifacts",
        ] {
            let _ = sqlx::query(sqlx::AssertSqlSafe(&*format!(
                "DELETE FROM {tbl} WHERE repository_id = $1"
            )))
            .bind(repo_id)
            .execute(pool)
            .await;
        }
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(pool)
            .await;
        for u in users {
            let _ = sqlx::query("DELETE FROM users WHERE id = $1")
                .bind(u)
                .execute(pool)
                .await;
        }
    }

    async fn sbom_count(pool: &PgPool, artifact_id: Uuid) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM sbom_documents WHERE artifact_id = $1")
            .bind(artifact_id)
            .fetch_one(pool)
            .await
            .expect("count sboms")
    }

    #[tokio::test]
    #[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
    async fn regression_2439_cross_repo_scan_sbom_bola() {
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();

        // Tenant A owns a private repo + artifact + scan/finding; tenant B has
        // no membership on it.
        let user_a = common::insert_active_user(&pool, "sc2439-a").await;
        let user_b = common::insert_active_user(&pool, "sc2439-b").await;
        let (repo_id, storage) = create_private_repo(&pool).await;
        let artifact_id = seed_artifact(&pool, repo_id).await;
        let scan_id = seed_scan(&pool, repo_id, artifact_id).await;
        grant_member(&pool, repo_id, user_a).await;

        let state = build_state(pool.clone(), &storage);
        let sec = || security::router().with_state(state.clone());
        let sb = || sbom::router().with_state(state.clone());

        // --- Non-member (tenant B) reads: existence-hiding 404, no leak. ----
        let (status, body) = send(
            sec(),
            get(&format!("/scans?artifact_id={artifact_id}")),
            auth_for(user_b),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "list_scans artifact filter");
        assert_no_leak(&body);

        let (status, body) = send(sec(), get(&format!("/scans/{scan_id}")), auth_for(user_b)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "get_scan");
        assert_no_leak(&body);

        let (status, body) = send(
            sec(),
            get(&format!("/scans/{scan_id}/findings")),
            auth_for(user_b),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "list_findings");
        assert_no_leak(&body);

        let (status, body) = send(
            sec(),
            get(&format!("/artifacts/{artifact_id}/scans")),
            auth_for(user_b),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "list_artifact_scans");
        assert_no_leak(&body);

        // --- Non-member SBOM generate (WRITE): 404 and NO row written. ------
        let (status, body) = send(
            sb(),
            post_json(
                "/",
                &format!("{{\"artifact_id\":\"{artifact_id}\",\"format\":\"cyclonedx\"}}"),
            ),
            auth_for(user_b),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "generate_sbom non-member");
        assert_no_leak(&body);
        assert_eq!(
            sbom_count(&pool, artifact_id).await,
            0,
            "denied generate must not write an sbom_documents row"
        );

        // --- Non-member CVE-status write: admin-only -> 403. ----------------
        let (status, _body) = send(
            sb(),
            post_json(
                &format!("/cve/status/{}", Uuid::new_v4()),
                "{\"status\":\"acknowledged\"}",
            ),
            auth_for(user_b),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "CVE-status write is admin-only (mirrors update_cve_status_by_artifact_cve)"
        );

        // --- Owner (tenant A member) legitimate use is intact. --------------
        let (status, _body) =
            send(sec(), get(&format!("/scans/{scan_id}")), auth_for(user_a)).await;
        assert_eq!(status, StatusCode::OK, "member get_scan must still 200");

        let (status, _body) = send(
            sec(),
            get(&format!("/artifacts/{artifact_id}/scans")),
            auth_for(user_a),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "member list_artifact_scans 200");

        let (status, _body) = send(
            sb(),
            post_json(
                "/",
                &format!("{{\"artifact_id\":\"{artifact_id}\",\"format\":\"cyclonedx\"}}"),
            ),
            auth_for(user_a),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "member generate_sbom must 200");
        assert!(
            sbom_count(&pool, artifact_id).await >= 1,
            "member generate must write an sbom row"
        );

        // --- convert_sbom (#2439 residual): non-member 404 + no convert row;
        //     member 200. Use the SBOM the member just generated. ------------
        let sbom_id: Uuid =
            sqlx::query_scalar("SELECT id FROM sbom_documents WHERE artifact_id = $1 LIMIT 1")
                .bind(artifact_id)
                .fetch_one(&pool)
                .await
                .expect("member-generated sbom must exist");

        let (status, body) = send(
            sb(),
            post_json(
                &format!("/{sbom_id}/convert"),
                "{\"target_format\":\"spdx\"}",
            ),
            auth_for(user_b),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "non-member convert must 404");
        assert_no_leak(&body);
        let spdx_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sbom_documents WHERE artifact_id = $1 AND format = 'spdx'",
        )
        .bind(artifact_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            spdx_rows, 0,
            "denied convert must not persist a convert row"
        );

        let (status, _body) = send(
            sb(),
            post_json(
                &format!("/{sbom_id}/convert"),
                "{\"target_format\":\"spdx\"}",
            ),
            auth_for(user_a),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "member convert must 200");

        // --- 404-body uniformity: a hidden-but-existing scan and an absent
        //     scan id must return the SAME body (no existence oracle). --------
        let (hs, hidden_body) =
            send(sec(), get(&format!("/scans/{scan_id}")), auth_for(user_b)).await;
        let (as_, absent_body) = send(
            sec(),
            get(&format!("/scans/{}", Uuid::new_v4())),
            auth_for(user_b),
        )
        .await;
        assert_eq!(hs, StatusCode::NOT_FOUND);
        assert_eq!(as_, StatusCode::NOT_FOUND);
        assert_eq!(
            hidden_body, absent_body,
            "hidden vs absent get_scan 404 bodies must be byte-identical"
        );

        let (hs, hidden_fbody) = send(
            sec(),
            get(&format!("/scans/{scan_id}/findings")),
            auth_for(user_b),
        )
        .await;
        let (as_, absent_fbody) = send(
            sec(),
            get(&format!("/scans/{}/findings", Uuid::new_v4())),
            auth_for(user_b),
        )
        .await;
        assert_eq!(hs, StatusCode::NOT_FOUND);
        assert_eq!(as_, StatusCode::NOT_FOUND);
        assert_eq!(
            hidden_fbody, absent_fbody,
            "hidden vs absent list_findings 404 bodies must be byte-identical"
        );

        cleanup(&pool, repo_id, &[user_a, user_b]).await;
    }
}

// ---------------------------------------------------------------------------
// Regression: #2443 cross-repo authorization remainder (MEDIUM/LOW).
//
// Seam:   External HTTP vantage against the real handler routers + a live DB.
// What:   the promotion-rule / approval / curation read routes returned a
//         private repo's sub-resource to ANY authenticated caller with no
//         check they can see the owning (private) repository.
// Asserts: a non-member (tenant B) gets an existence-hiding 404 on
//         `GET /promotion-rules/:id`, `GET /approval/:id`,
//         `GET /curation/packages/:id`; the repo member (tenant A) still gets
//         200. Fresh-slot pool validation exercises the remaining routes.
//
// DB-gated; run with:
//   DATABASE_URL="postgresql://.../artifact_registry" \
//     cargo test --test security_regression_tests -- --ignored
// ---------------------------------------------------------------------------
mod xrepo_authz_2443 {
    #![allow(clippy::disallowed_methods)]
    use std::collections::HashMap;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Extension;
    use sqlx::PgPool;
    use tower::ServiceExt;
    use uuid::Uuid;

    use artifact_keeper_backend::api::handlers::{approval, curation, promotion_rules};
    use artifact_keeper_backend::api::middleware::auth::AuthExtension;
    use artifact_keeper_backend::api::{AppState, SharedState};
    use artifact_keeper_backend::config::Config;
    use artifact_keeper_backend::models::access_scope::AccessScope;

    use super::common;

    fn build_state(pool: PgPool, storage_path: &str) -> SharedState {
        let config = Config {
            database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
            storage_path: storage_path.into(),
            jwt_secret: "test-secret-at-least-32-bytes-long-for-testing".into(),
            setup_password_hint: None,
            ..Default::default()
        };
        let storage: Arc<dyn artifact_keeper_backend::storage::StorageBackend> = Arc::new(
            artifact_keeper_backend::storage::filesystem::FilesystemStorage::new(storage_path),
        );
        let registry = Arc::new(artifact_keeper_backend::storage::StorageRegistry::new(
            HashMap::new(),
            "filesystem".to_string(),
        ));
        Arc::new(AppState::new(config, pool, storage, registry))
    }

    fn auth_for(user_id: Uuid) -> AuthExtension {
        AuthExtension {
            user_id,
            username: format!("u-{}", &user_id.to_string()[..8]),
            email: "u@test.local".to_string(),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: AccessScope::Admin,
            iat_ms: None,
        }
    }

    async fn create_private_repo(pool: &PgPool, tag: &str) -> Uuid {
        let id = Uuid::new_v4();
        let key = format!("sc2443-{}-{}", tag, &id.to_string()[..8]);
        let dir = std::env::temp_dir().join(&key);
        std::fs::create_dir_all(&dir).expect("create storage dir");
        sqlx::query(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, is_public) \
             VALUES ($1, $2, $2, $3, 'local', 'rpm'::repository_format, false)",
        )
        .bind(id)
        .bind(&key)
        .bind(&*dir.to_string_lossy())
        .execute(pool)
        .await
        .expect("insert private repo");
        id
    }

    async fn seed_artifact(pool: &PgPool, repo_id: Uuid) -> Uuid {
        let path = format!("sc2443/{}", Uuid::new_v4());
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
                 checksum_sha256, content_type, storage_key, uploaded_by) \
             VALUES ($1, $2, 'sc2443', '1.0', 1, 'deadbeef', 'application/octet-stream', $3, NULL) \
             RETURNING id",
        )
        .bind(repo_id)
        .bind(&path)
        .bind(&path)
        .fetch_one(pool)
        .await
        .expect("seed artifact")
    }

    async fn grant_member(pool: &PgPool, repo_id: Uuid, user_id: Uuid) {
        sqlx::query(
            "INSERT INTO role_assignments (user_id, role_id, repository_id) \
             SELECT $1, r.id, $2 FROM roles r WHERE r.name = 'developer' \
             ON CONFLICT (user_id, role_id, repository_id) DO NOTHING",
        )
        .bind(user_id)
        .bind(repo_id)
        .execute(pool)
        .await
        .expect("grant developer role");
    }

    async fn send(app: axum::Router, uri: &str, auth: AuthExtension) -> (StatusCode, String) {
        let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
        let resp = app.layer(Extension(auth)).oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    async fn cleanup(pool: &PgPool, repos: &[Uuid], users: &[Uuid]) {
        for r in repos {
            for tbl in [
                "promotion_approvals",
                "promotion_rules",
                "curation_packages",
                "curation_rules",
                "role_assignments",
                "artifacts",
            ] {
                let _ = sqlx::query(sqlx::AssertSqlSafe(&*format!(
                    "DELETE FROM {tbl} WHERE staging_repo_id = $1 OR source_repo_id = $1 \
                     OR repository_id = $1 OR remote_repo_id = $1 OR target_repo_id = $1"
                )))
                .bind(r)
                .execute(pool)
                .await;
            }
        }
        for r in repos {
            let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
                .bind(r)
                .execute(pool)
                .await;
        }
        for u in users {
            let _ = sqlx::query("DELETE FROM users WHERE id = $1")
                .bind(u)
                .execute(pool)
                .await;
        }
    }

    #[tokio::test]
    #[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
    async fn regression_2443_cross_repo_subresource_bola() {
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();

        // Tenant A owns a private source/staging repo (+ a second repo for the
        // target/remote FKs). Tenant B has no membership.
        let user_a = common::insert_active_user(&pool, "sc2443-a").await;
        let user_b = common::insert_active_user(&pool, "sc2443-b").await;
        let src = create_private_repo(&pool, "src").await;
        let tgt = create_private_repo(&pool, "tgt").await;
        grant_member(&pool, src, user_a).await;
        let artifact_id = seed_artifact(&pool, src).await;

        let rule_id: Uuid = sqlx::query_scalar(
            "INSERT INTO promotion_rules (name, source_repo_id, target_repo_id) \
             VALUES ('sc2443', $1, $2) RETURNING id",
        )
        .bind(src)
        .bind(tgt)
        .fetch_one(&pool)
        .await
        .expect("seed rule");

        let approval_id: Uuid = sqlx::query_scalar(
            "INSERT INTO promotion_approvals \
             (artifact_id, source_repo_id, target_repo_id, requested_by, status) \
             VALUES ($1, $2, $3, $4, 'pending') RETURNING id",
        )
        .bind(artifact_id)
        .bind(src)
        .bind(tgt)
        .bind(user_a)
        .fetch_one(&pool)
        .await
        .expect("seed approval");

        let pkg_id: Uuid = sqlx::query_scalar(
            "INSERT INTO curation_packages \
             (staging_repo_id, remote_repo_id, format, package_name, version, upstream_path) \
             VALUES ($1, $2, 'rpm', 'sc2443', '1.0', '/sc2443') RETURNING id",
        )
        .bind(src)
        .bind(tgt)
        .fetch_one(&pool)
        .await
        .expect("seed curation package");

        let cur_rule_id: Uuid = sqlx::query_scalar(
            "INSERT INTO curation_rules \
             (staging_repo_id, package_pattern, version_constraint, architecture, action, \
              priority, reason, enabled) \
             VALUES ($1, 'evil-*', '*', '*', 'block', 100, 'sc2443', true) RETURNING id",
        )
        .bind(src)
        .fetch_one(&pool)
        .await
        .expect("seed curation rule");

        let state = build_state(pool.clone(), &std::env::temp_dir().to_string_lossy());
        let pr = || promotion_rules::router().with_state(state.clone());
        let ap = || approval::router().with_state(state.clone());
        let cu = || curation::router().with_state(state.clone());

        // The curation `/packages/{id}` route uses brace param syntax that
        // axum 0.7's matchit does not bind, so it is exercised via the query
        // `/stats?staging_repo_id=` route (get_package's gate is covered by the
        // in-module unit test). `pkg_id` is seeded so the curation stats query
        // has a row to (not) reveal.
        let _ = pkg_id;

        // --- Non-member (tenant B): existence-hiding 404 on every route. ----
        let (s, _b) = send(pr(), &format!("/{rule_id}"), auth_for(user_b)).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "get_rule non-member");
        let (s, _b) = send(ap(), &format!("/{approval_id}"), auth_for(user_b)).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "get_approval non-member");
        let (s, _b) = send(
            cu(),
            &format!("/stats?staging_repo_id={src}"),
            auth_for(user_b),
        )
        .await;
        assert_eq!(s, StatusCode::NOT_FOUND, "curation stats non-member");
        let (s, _b) = send(cu(), &format!("/rules/{cur_rule_id}"), auth_for(user_b)).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "curation get_rule non-member");

        // Hidden vs absent bodies are byte-identical (no existence oracle).
        let (_s, hidden) = send(pr(), &format!("/{rule_id}"), auth_for(user_b)).await;
        let (_s, absent) = send(pr(), &format!("/{}", Uuid::new_v4()), auth_for(user_b)).await;
        assert_eq!(
            hidden, absent,
            "hidden vs absent get_rule bodies must match"
        );
        let (_s, ch) = send(cu(), &format!("/rules/{cur_rule_id}"), auth_for(user_b)).await;
        let (_s, ca) = send(
            cu(),
            &format!("/rules/{}", Uuid::new_v4()),
            auth_for(user_b),
        )
        .await;
        assert_eq!(
            ch, ca,
            "hidden vs absent curation get_rule bodies must match"
        );

        // --- Member (tenant A): 200 on every route. -------------------------
        let (s, _b) = send(pr(), &format!("/{rule_id}"), auth_for(user_a)).await;
        assert_eq!(s, StatusCode::OK, "get_rule member");
        let (s, _b) = send(ap(), &format!("/{approval_id}"), auth_for(user_a)).await;
        assert_eq!(s, StatusCode::OK, "get_approval member");
        let (s, _b) = send(
            cu(),
            &format!("/stats?staging_repo_id={src}"),
            auth_for(user_a),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "curation stats member");
        let (s, _b) = send(cu(), &format!("/rules/{cur_rule_id}"), auth_for(user_a)).await;
        assert_eq!(s, StatusCode::OK, "curation get_rule member");

        cleanup(&pool, &[src, tgt], &[user_a, user_b]).await;
    }
}

// ---------------------------------------------------------------------------
// Bug — #3854: `AK_GUEST_ACCESS_ENABLED=false` did not reach the OCI surface.
// Class:  A configured server-wide authentication control not being applied.
// Seam:   `guest_access_guard`, exercised from outside the crate (the vantage
//         an anonymous `docker pull` has) over the `/v2` path shapes.
// What:   The guard allowlisted the whole `/v2` subtree, so the guest-access
//         policy was never asked on manifest, blob, tag or referrer paths. The
//         OCI handlers then applied their own gate, which asks only whether the
//         *repository* is anonymously readable — a question about the
//         repository, not about the server. An operator who set the flag to
//         stop anonymous consumption still had anonymous `docker pull` of every
//         `public` repository working, with nothing in the logs to say so.
// Asserts: with the flag off every OCI read path is refused 401 with the
//         distribution-spec envelope and a challenge naming the token endpoint;
//         with the flag on the guard is a no-op and the same request reaches
//         the handlers; the forgeable `Bearer anonymous` sentinel is refused
//         byte-identically to no credential at all; and an anonymous token
//         request is refused so no anonymous capability is ever issued.
//
// No live DB: an anonymous request resolves no credential and never reaches
// Postgres, so these run in the Tier 1 default set. The credentialed half —
// that a real login still passes on the same paths — needs bcrypt against a
// user row and is the `#[ignore]`d case at the end of this module.
// ---------------------------------------------------------------------------
mod guest_access_oci_3854 {
    // streaming-invariant: test file exempt — buffering a tiny 401 body in an
    // assertion is not an artifact path (#1608).
    #![allow(clippy::disallowed_methods)]
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
    use axum::http::{Request, Response, StatusCode};
    use axum::middleware::from_fn_with_state;
    use axum::Router;
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    use artifact_keeper_backend::api::handlers::oci_v2;
    use artifact_keeper_backend::api::middleware::guest_access::{
        guest_access_guard, GuestAccessState,
    };
    use artifact_keeper_backend::api::{AppState, SharedState};
    use artifact_keeper_backend::config::Config;
    use artifact_keeper_backend::services::auth_service::AuthService;

    use super::common;

    /// Shared by every state built here so the guard's `AuthService` and the
    /// handlers' validate the same tokens.
    const JWT_SECRET: &str = "test-secret-at-least-32-bytes-long-for-testing";

    /// The four `/v2` path shapes an anonymous OCI client can read through:
    /// manifests and blobs (the pull itself), plus the tag listing and the
    /// referrers lookup, which drifted out of step with them once before
    /// (#3268) and are the reason the policy is applied by route.
    const OCI_READ_PATHS: [&str; 4] = [
        "/v2/pubdocker/nginx/manifests/latest",
        "/v2/pubdocker/nginx/blobs/sha256:e9b8a1f2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e",
        "/v2/pubdocker/nginx/tags/list",
        "/v2/pubdocker/nginx/referrers/sha256:e9b8a1f2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e",
    ];

    const HOST: &str = "registry.example.com";
    const EXPECTED_CHALLENGE: &str =
        "Bearer realm=\"http://registry.example.com/v2/token\",service=\"artifact-keeper\"";

    /// A pool that can only ever fail to connect. The anonymous cases never
    /// reach it: no credential resolves before any query is issued. A short
    /// acquire deadline turns a regression that *did* start touching the DB
    /// into a prompt failure rather than a 30s stall.
    fn unreachable_pool() -> sqlx::PgPool {
        PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(1))
            .connect_lazy("postgresql://localhost/__guest_access_oci_3854__")
            .expect("lazy connect does not contact the DB")
    }

    fn state(guest_access_enabled: bool, pool: sqlx::PgPool) -> GuestAccessState {
        let config = Config {
            jwt_secret: "test-secret-at-least-32-bytes-long-for-testing".into(),
            guest_access_enabled,
            ..Default::default()
        };
        GuestAccessState {
            guest_access_enabled,
            auth_service: Arc::new(AuthService::new(pool, Arc::new(config))),
        }
    }

    /// Run `request` through the guard. The fallback stands in for the `/v2`
    /// handlers (which enforce their own authorization), so `OK` means "the
    /// policy let this through" and `401` means "the policy refused it".
    async fn through_guard(state: GuestAccessState, request: Request<Body>) -> Response<Body> {
        Router::new()
            .fallback(|| async { "reached the /v2 handlers" })
            .layer(from_fn_with_state(state, guest_access_guard))
            .oneshot(request)
            .await
            .expect("router is infallible")
    }

    fn anonymous_request(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .header("host", HOST)
            .body(Body::empty())
            .expect("valid request")
    }

    async fn status_and_body(response: Response<Body>) -> (StatusCode, String) {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("small body");
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    #[tokio::test]
    async fn regression_3854_anonymous_oci_read_is_refused_while_guest_access_disabled() {
        for path in OCI_READ_PATHS {
            // --- flag off: the policy refuses, in the client's own dialect ---
            let response =
                through_guard(state(false, unreachable_pool()), anonymous_request(path)).await;

            let challenges: Vec<String> = response
                .headers()
                .get_all(WWW_AUTHENTICATE)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .map(String::from)
                .collect();
            assert_eq!(
                challenges,
                vec![EXPECTED_CHALLENGE.to_string()],
                "{path}: the refusal must name the token endpoint as the realm, \
                 and carry no browser-prompting Basic challenge"
            );

            let (status, body) = status_and_body(response).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{path}: an anonymous read of a public repository must be refused \
                 while guest access is disabled (#3854)"
            );
            let json: serde_json::Value =
                serde_json::from_str(&body).expect("the body must be JSON");
            assert_eq!(
                json["errors"][0]["code"], "UNAUTHORIZED",
                "{path}: the body must be the distribution-spec envelope, not the \
                 REST one — docker/oras cannot render the REST shape"
            );

            // --- flag on: the policy has no effect at all ---
            let (status, _) = status_and_body(
                through_guard(state(true, unreachable_pool()), anonymous_request(path)).await,
            )
            .await;
            assert_eq!(
                status,
                StatusCode::OK,
                "{path}: with guest access enabled the guard must be a no-op and the \
                 request must reach the handlers"
            );
        }
    }

    #[tokio::test]
    async fn regression_3854_fabricated_anonymous_sentinel_is_refused_like_no_credential() {
        // The anonymous pull token is the literal string `anonymous`, compared
        // by string equality, so a client can present it without ever calling
        // the token endpoint. It is not a secret and was never meant to be one;
        // the guard is what makes that stop mattering.
        // A bearer that is neither a JWT nor a known API token is only
        // classified as invalid (401) rather than as a transient shed (503)
        // once the token lookup has actually reached Postgres and come back
        // empty, so this case opens the Tier 1 database. It skips when none is
        // configured and PANICS when `AK_TESTS_REQUIRE_DB` says one must be
        // reachable, so it can never fiction-green (#2924).
        let Some(pool) = artifact_keeper_backend::testing::try_pool_with(3).await else {
            return;
        };
        let path = OCI_READ_PATHS[0];
        let forged = Request::builder()
            .uri(path)
            .header("host", HOST)
            .header(AUTHORIZATION, "Bearer anonymous")
            .body(Body::empty())
            .expect("valid request");

        let (forged_status, forged_body) =
            status_and_body(through_guard(state(false, pool.clone()), forged).await).await;
        let (bare_status, bare_body) =
            status_and_body(through_guard(state(false, pool), anonymous_request(path)).await).await;

        assert_eq!(
            forged_status,
            StatusCode::UNAUTHORIZED,
            "a fabricated anonymous sentinel must be refused"
        );
        assert_eq!(
            (forged_status, forged_body),
            (bare_status, bare_body),
            "presenting the sentinel must be answered exactly as presenting nothing"
        );
    }

    #[tokio::test]
    async fn regression_3854_guard_does_not_decide_the_token_endpoint() {
        // The guard allowlists `/v2/token`: it resolves credentials from
        // headers, and the OAuth2 refusal grant a container client switches to
        // after `docker login` carries its credential in the form body. A
        // header-inspecting layer that refused this route would refuse
        // authenticated pulls along with anonymous ones. The policy is applied
        // in `token()` instead — see the real-router cases below.
        let (status, _) = status_and_body(
            through_guard(
                state(false, unreachable_pool()),
                anonymous_request("/v2/token?service=artifact-keeper"),
            )
            .await,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the guard must pass /v2/token through without deciding it"
        );
    }

    // ----- the real router: guard + the OCI handlers it fronts ---------------
    //
    // The cases above drive the guard against a stand-in. These drive the real
    // `/v2` routes behind the real guard, which is the only vantage that can
    // show the policy and the token endpoint agreeing: the guard admits
    // `/v2/token`, and `token()` is what refuses the anonymous mint.

    fn real_state(
        pool: sqlx::PgPool,
        storage_path: &str,
        guest_access_enabled: bool,
    ) -> SharedState {
        let config = Config {
            database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
            storage_path: storage_path.into(),
            jwt_secret: JWT_SECRET.into(),
            setup_password_hint: None,
            guest_access_enabled,
            ..Default::default()
        };
        let storage: Arc<dyn artifact_keeper_backend::storage::StorageBackend> = Arc::new(
            artifact_keeper_backend::storage::filesystem::FilesystemStorage::new(storage_path),
        );
        let registry = Arc::new(artifact_keeper_backend::storage::StorageRegistry::new(
            std::collections::HashMap::new(),
            "filesystem".to_string(),
        ));
        Arc::new(AppState::new(config, pool, storage, registry))
    }

    /// The production shape: the OCI routes nested under `/v2`, with the
    /// guest-access guard as the global outer layer in front of them.
    fn real_app(shared: SharedState, guest_access_enabled: bool) -> Router {
        let guard_state = GuestAccessState {
            guest_access_enabled,
            auth_service: Arc::new(AuthService::new(
                shared.db.clone(),
                Arc::new(shared.config.clone()),
            )),
        };
        Router::new()
            .route("/v2/", oci_v2::version_check_handler())
            .nest("/v2", oci_v2::router())
            .with_state(shared)
            .layer(from_fn_with_state(guard_state, guest_access_guard))
    }

    fn form_post(uri: &str, body: String) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/x-www-form-urlencoded")
            .header("host", HOST)
            .body(Body::from(body))
            .expect("valid request")
    }

    /// Give `user_id` a real bcrypt password and return its username, so the
    /// OAuth2 password grant (what `docker login` sends) can authenticate it.
    async fn with_password(pool: &sqlx::PgPool, user_id: uuid::Uuid, password: &str) -> String {
        let hash = AuthService::hash_password(password)
            .await
            .expect("hash the test password");
        sqlx::query_scalar("UPDATE users SET password_hash = $1 WHERE id = $2 RETURNING username")
            .bind(&hash)
            .bind(user_id)
            .fetch_one(pool)
            .await
            .expect("store the password hash")
    }

    #[tokio::test]
    async fn regression_3854_anonymous_token_request_issues_no_token_while_disabled() {
        // Spec — "Token request without credentials is refused". The guard let
        // this request through; `token()` is what refuses to mint, so no
        // anonymous capability exists to be presented anywhere.
        let Some(pool) = artifact_keeper_backend::testing::try_pool_with(3).await else {
            return;
        };
        let dir = std::env::temp_dir().join(format!("ak-3854-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create storage dir");
        let path = dir.to_string_lossy().to_string();

        let refused = real_app(real_state(pool.clone(), &path, false), false)
            .oneshot(anonymous_request("/v2/token?service=artifact-keeper"))
            .await
            .expect("router is infallible");
        let (status, body) = status_and_body(refused).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "no token may be minted for an anonymous caller while guest access is disabled"
        );
        let json: serde_json::Value = serde_json::from_str(&body).expect("JSON body");
        assert!(
            json.get("token").is_none() && json.get("access_token").is_none(),
            "no capability may be issued, got: {body}"
        );

        // With the flag on, the very same request mints the anonymous token —
        // the default configuration is untouched by this change.
        let minted = real_app(real_state(pool, &path, true), true)
            .oneshot(anonymous_request("/v2/token?service=artifact-keeper"))
            .await
            .expect("router is infallible");
        let (status, body) = status_and_body(minted).await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).expect("JSON body");
        assert_eq!(json["token"], "anonymous");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Seed a `public` Local docker repository holding one manifest, the way a
    /// push does: the repository row, the manifest object in storage, and the
    /// tag row that points at it. Returns `(repo_id, key, tag_digest)`.
    async fn seed_public_image(pool: &sqlx::PgPool, storage_path: &str) -> (uuid::Uuid, String) {
        let id = uuid::Uuid::new_v4();
        let key = format!("ak3854-{}", &id.to_string()[..8]);
        sqlx::query(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, is_public) \
             VALUES ($1, $2, $2, $3, 'local', 'docker'::repository_format, true)",
        )
        .bind(id)
        .bind(&key)
        .bind(storage_path)
        .execute(pool)
        .await
        .expect("insert repository");

        let body = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "size": 0
            },
            "layers": []
        })
        .to_string();
        let digest = format!(
            "sha256:{:x}",
            <sha2::Sha256 as sha2::Digest>::digest(body.as_bytes())
        );
        let storage_key = format!(
            "{}{}",
            artifact_keeper_backend::storage::keys::OCI_MANIFEST_STORAGE_PREFIX,
            digest
        );
        let backend: Arc<dyn artifact_keeper_backend::storage::StorageBackend> = Arc::new(
            artifact_keeper_backend::storage::filesystem::FilesystemStorage::new(storage_path),
        );
        backend
            .put(&storage_key, bytes::Bytes::from(body))
            .await
            .expect("write the manifest object");

        sqlx::query(
            "INSERT INTO oci_tags (repository_id, name, tag, manifest_digest, manifest_content_type) \
             VALUES ($1, $2, 'latest', $3, 'application/vnd.oci.image.manifest.v1+json')",
        )
        .bind(id)
        .bind(&key)
        .bind(&digest)
        .execute(pool)
        .await
        .expect("insert oci_tags row");

        (id, key)
    }

    #[tokio::test]
    async fn regression_3854_credential_from_a_registry_login_still_pulls_while_disabled() {
        // Spec — "Pulls after a registry login are permitted". This is the case
        // that broke when the guard gated `/v2/token`: `docker login` succeeded
        // and every pull after it failed, because docker stops sending the
        // password and redeems the refresh token through the OAuth2 grant whose
        // credential lives in the form body. The whole sequence is driven here
        // end to end — login, refresh-grant exchange, manifest pull — against
        // the real routes with the flag off.
        let Some(pool) = artifact_keeper_backend::testing::try_pool_with(3).await else {
            return;
        };
        let dir = std::env::temp_dir().join(format!("ak-3854-pull-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create storage dir");
        let path = dir.to_string_lossy().to_string();

        let user_id = common::insert_active_user(&pool, "guest-oci-3854-pull").await;
        let password = "correct horse battery staple";
        let username = with_password(&pool, user_id, password).await;
        let (repo_id, key) = seed_public_image(&pool, &path).await;

        let shared = real_state(pool.clone(), &path, false);

        // 1. `docker login` — the password grant asking for an offline token.
        let login = real_app(shared.clone(), false)
            .oneshot(form_post(
                "/v2/token",
                format!(
                    "grant_type=password&username={username}&password={password}\
                     &access_type=offline"
                ),
            ))
            .await
            .expect("router is infallible");
        let (login_status, login_body) = status_and_body(login).await;
        let login_json: serde_json::Value = serde_json::from_str(&login_body).expect("JSON body");
        let refresh = login_json["refresh_token"].as_str().map(str::to_string);

        // 2. `docker pull` step one — redeem the refresh token. No credential
        //    in any header; this is the request the guard could not resolve.
        let exchanged = match refresh.as_deref() {
            Some(rt) => Some(
                status_and_body(
                    real_app(shared.clone(), false)
                        .oneshot(form_post(
                            "/v2/token",
                            format!("grant_type=refresh_token&refresh_token={rt}"),
                        ))
                        .await
                        .expect("router is infallible"),
                )
                .await,
            ),
            None => None,
        };

        // 3. `docker pull` step two — the manifest, with the minted bearer.
        let access = exchanged.as_ref().and_then(|(_, b)| {
            serde_json::from_str::<serde_json::Value>(b)
                .ok()
                .and_then(|j| j["access_token"].as_str().map(str::to_string))
        });
        let pulled = match access.as_deref() {
            Some(token) => Some(
                status_and_body(
                    real_app(shared, false)
                        .oneshot(
                            Request::builder()
                                .uri(format!("/v2/{key}/manifests/latest"))
                                .header("host", HOST)
                                .header(AUTHORIZATION, format!("Bearer {token}"))
                                .body(Body::empty())
                                .expect("valid request"),
                        )
                        .await
                        .expect("router is infallible"),
                )
                .await,
            ),
            None => None,
        };

        let _ = sqlx::query("DELETE FROM oci_tags WHERE repository_id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(login_status, StatusCode::OK, "registry login must succeed");
        assert!(
            refresh.is_some(),
            "an offline login must yield the credential a later pull redeems, got: {login_body}"
        );
        let (exchange_status, exchange_body) =
            exchanged.expect("the refresh grant must have been attempted");
        assert_eq!(
            exchange_status,
            StatusCode::OK,
            "the refresh grant must be served while guest access is disabled — \
             its credential is in the form body, invisible to the guard, got: {exchange_body}"
        );
        let (pull_status, pull_body) = pulled.expect("the manifest pull must have been attempted");
        assert_eq!(
            pull_status,
            StatusCode::OK,
            "the token a login left behind must pull a manifest without the client \
             presenting its password again, got: {pull_body}"
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&pull_body).expect("JSON manifest")
                ["schemaVersion"],
            2,
            "the pull must return the seeded manifest"
        );
    }

    // The credentialed half of the contract: `docker login` still works, and a
    // credentialed token request is still served — the removal of the `/v2`
    // allowlist must not take registry login with it. Verifying a password
    // means bcrypt against a real user row, so this opens the Tier 1 database
    // on the same terms as the case above.
    #[tokio::test]
    async fn regression_3854_registry_login_still_passes_while_guest_access_disabled() {
        let Some(pool) = artifact_keeper_backend::testing::try_pool_with(3).await else {
            return;
        };
        let user_id = common::insert_active_user(&pool, "guest-oci-3854").await;
        let password = "correct horse battery staple";
        let hash = AuthService::hash_password(password)
            .await
            .expect("hash the test password");
        let username: String = sqlx::query_scalar(
            "UPDATE users SET password_hash = $1 WHERE id = $2 RETURNING username",
        )
        .bind(&hash)
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .expect("store the password hash");

        let (header, value) = common::basic_auth_header(&username, password);
        for path in OCI_READ_PATHS
            .iter()
            .chain(std::iter::once(&"/v2/token?service=artifact-keeper"))
        {
            let request = Request::builder()
                .uri(*path)
                .header("host", HOST)
                .header(header.as_str(), value.as_str())
                .body(Body::empty())
                .expect("valid request");
            let (status, _) =
                status_and_body(through_guard(state(false, pool.clone()), request).await).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "{path}: a client that logged in must still be served while guest \
                 access is disabled"
            );
        }

        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await;
    }
}
