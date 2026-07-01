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
// Bug 2 — GHSA-7f39-724h-cccm (PR #880)
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
// Bug 3 — GHSA-93ch-hrfh-5wcw (PR #881)
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
            iat,
            // Legacy whole-second token shape (no ms claim); exercises the
            // effective_iat_ms() fallback to iat*1000.
            iat_ms: None,
            exp: iat + 3600,
            token_type: "access".to_string(),
            jti: None,
            family_id: None,
            scan_pull_repo: None,
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
