//! `mcp-publisher login github-oidc` against an MCP repository, and
//! namespace-conditioned grants interpolating the CI claims (#5253).
//!
//! A mock OIDC issuer signs a GitHub-Actions-shaped assertion; the publisher
//! wire (`POST {registry}/v0/auth/github-oidc` with `{"oidc_token"}`,
//! answer `{"registry_token","expires_at"}`, then `Authorization: Bearer`)
//! is replayed through the full router against a PRIVATE repository, so the
//! anonymous exchange must bypass repository visibility. The CI service
//! account's only grant is `write` conditioned on
//! `io.github.{repository_owner}/*`.
//!
//! ```sh
//! DATABASE_URL=... AK_TESTS_REQUIRE_DB=1 \
//!   cargo nextest run --run-ignored ignored-only --test mcp_auth_namespaces_tests
//! ```

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::disallowed_methods)] // streaming-invariant: test file exempt (#1608)

mod common;

use axum::http::StatusCode;
use serde_json::{json, Value};
use uuid::Uuid;

use common::ci_oidc_issuer::MockCiIssuer;
use common::mcp_support::McpHarness;

const AUDIENCE: &str = "https://ak.mcp.test";

async fn audit_rows(h: &McpHarness, action: &str, rule: Uuid) -> i64 {
    for _ in 0..50 {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log WHERE action = $1 AND details->>'rule_id' = $2",
        )
        .bind(action)
        .bind(rule.to_string())
        .fetch_one(&h.pool)
        .await
        .unwrap();
        if n > 0 {
            return n;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    0
}

#[tokio::test]
#[ignore]
async fn github_oidc_login_then_namespace_conditioned_publish() {
    let Some(h) = McpHarness::new().await else {
        return;
    };
    let Some(issuer) = MockCiIssuer::start().await else {
        assert!(
            std::env::var(artifact_keeper_backend::testing::REQUIRE_DB_ENV).is_err(),
            "no non-loopback address for the mock issuer under a required run"
        );
        return;
    };
    let repo = h.mcp_repo("oidc", "local", false).await;
    let provider = h
        .send(
            "POST",
            "/api/v1/admin/ci-oidc",
            true,
            Some(json!({
                "name": format!("mcp-gh-{}", h.tag), "provider_type": "generic",
                "issuer_url": issuer.issuer(), "audience": AUDIENCE,
            })),
        )
        .await;
    assert!(provider.status.is_success(), "{}", provider.json());
    let provider_id = provider.json()["id"].as_str().unwrap().to_string();
    let mapping = h
        .send(
            "POST",
            &format!("/api/v1/admin/ci-oidc/{provider_id}/mappings"),
            true,
            Some(json!({"name": "mcp", "claim_filters": {"repository_owner": ["acme", "evil"]}})),
        )
        .await;
    assert!(mapping.status.is_success(), "{}", mapping.json());
    let account: Uuid = mapping.json()["service_account_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    // The account's only grant on the repository: write within its owner's
    // namespace. Granting it is audited as MCP_NAMESPACE_GRANTED. A CI
    // account is a `users` row with `is_service_account = false`, so the
    // rule names it as a `user` principal.
    let repo_id: Uuid = sqlx::query_scalar("SELECT id FROM repositories WHERE key = $1")
        .bind(&repo)
        .fetch_one(&h.pool)
        .await
        .unwrap();
    let rule = h
        .send(
            "POST",
            "/api/v1/permissions",
            true,
            Some(json!({
                "principal_type": "user", "principal_id": account,
                "target_type": "repository", "target_id": repo_id,
                "actions": ["read", "write"],
                "conditions": {"mcp_namespaces": ["io.github.{repository_owner}/*"],
                               "mcp_namespace_issuer": issuer.issuer()},
            })),
        )
        .await;
    assert!(rule.status.is_success(), "{}", rule.json());
    let rule_id: Uuid = rule.json()["id"].as_str().unwrap().parse().unwrap();
    assert_eq!(audit_rows(&h, "MCP_NAMESPACE_GRANTED", rule_id).await, 1);

    let exchange = |owner: &str| {
        let mut claims = issuer.gitlab_claims(AUDIENCE, "acme/app", "branch", "main");
        claims["repository_owner"] = Value::from(owner);
        issuer.sign(&claims)
    };
    let login = |token: String| {
        let uri = format!("/mcp/{repo}/v0/auth/github-oidc");
        let h = &h;
        async move {
            h.send("POST", &uri, false, Some(json!({"oidc_token": token})))
                .await
        }
    };

    let ok = login(exchange("acme")).await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.json());
    let token = ok.json()["registry_token"].as_str().unwrap().to_string();
    let expires = ok.json()["expires_at"].as_i64().unwrap();
    assert!(expires > chrono::Utc::now().timestamp());

    let publish = |token: &str, name: &str| {
        let uri = format!("/mcp/{repo}/v0.1/publish");
        let doc = McpHarness::server_doc(name, "1.0.0", "d");
        let (h, token) = (&h, token.to_string());
        async move { h.send_as("POST", &uri, Some(&token), Some(doc)).await }
    };
    let first = publish(&token, "io.github.acme/tool").await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.json());
    let refused = publish(&token, "io.github.evil/tool").await;
    assert_eq!(
        (refused.status, refused.json()["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("mcp_namespace_not_granted"))
    );
    // Another owner's session of the SAME account gets its own namespace.
    let evil = login(exchange("evil")).await.json()["registry_token"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        publish(&evil, "io.github.evil/tool").await.status,
        StatusCode::OK
    );
    assert_eq!(
        publish(&evil, "io.github.acme/other").await.status,
        StatusCode::FORBIDDEN
    );

    // Bad assertions are upstream's 401, as problem+json.
    let bad = login("not-a-jwt".into()).await;
    assert_eq!(
        (bad.status, bad.json()["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("mcp_unauthorized"))
    );
    assert_eq!(bad.headers["content-type"], "application/problem+json");
    let garbage = h
        .send(
            "POST",
            &format!("/mcp/{repo}/v0.1/auth/github-oidc"),
            false,
            Some(json!({"x": 1})),
        )
        .await;
    assert_eq!(garbage.status, StatusCode::BAD_REQUEST);

    // Removing the rule revokes the namespace.
    let del = h
        .send(
            "DELETE",
            &format!("/api/v1/permissions/{rule_id}"),
            true,
            None,
        )
        .await;
    assert!(del.status.is_success());
    assert_eq!(audit_rows(&h, "MCP_NAMESPACE_REVOKED", rule_id).await, 1);

    for sql in [
        "DELETE FROM mcp_ci_sessions WHERE user_id = $1",
        "DELETE FROM user_group_members WHERE user_id = $1",
    ] {
        let _ = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(account)
            .execute(&h.pool)
            .await;
    }
    let _ = sqlx::query("DELETE FROM ci_oidc_providers WHERE id = $1::uuid")
        .bind(&provider_id)
        .execute(&h.pool)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(account)
        .execute(&h.pool)
        .await;
    h.teardown(&[repo]).await;
}
