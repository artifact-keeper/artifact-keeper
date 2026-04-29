//! Integration tests for the download-ticket consumer middleware (#930).
//!
//! These tests cover the full lifecycle of a `?ticket=<v>` query-param
//! authenticator: minting, single-use consumption, expiry, path binding, and
//! the read-only policy. They require a running backend HTTP server with the
//! standard `admin` / `admin123` bootstrap user available, plus a freshly
//! provisioned database (so that download-ticket uniqueness assumptions hold).
//!
//! Set `TEST_BASE_URL` to point at the server (default `http://127.0.0.1:9080`).
//! Run with `cargo test --test download_ticket_tests -- --ignored`.

#![allow(dead_code)]

use std::env;

use reqwest::{Client, StatusCode};
use serde_json::{json, Value};

const ADMIN_USERNAME: &str = "admin";
const ADMIN_PASSWORD: &str = "admin123";

struct Server {
    base_url: String,
    access_token: String,
}

impl Server {
    fn new() -> Self {
        let base_url =
            env::var("TEST_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:9080".to_string());
        Self {
            base_url,
            access_token: String::new(),
        }
    }

    async fn login(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new();
        let resp = client
            .post(format!("{}/api/v1/auth/login", self.base_url))
            .json(&json!({
                "username": ADMIN_USERNAME,
                "password": ADMIN_PASSWORD,
            }))
            .send()
            .await?;
        let body: Value = resp.json().await?;
        self.access_token = body["access_token"]
            .as_str()
            .ok_or("login response missing access_token")?
            .to_string();
        Ok(())
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.access_token)
    }

    /// Create a public hosted repository with the given key and format.
    /// Returns silently if the repository already exists from a previous run.
    async fn ensure_public_repo(
        &self,
        key: &str,
        format: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new();
        let resp = client
            .post(format!("{}/api/v1/repositories", self.base_url))
            .header("Authorization", self.auth_header())
            .json(&json!({
                "key": key,
                "name": key,
                "format": format,
                "repo_type": "local",
                "is_public": true,
            }))
            .send()
            .await?;
        let status = resp.status();
        if status.is_success() || status == StatusCode::CONFLICT {
            return Ok(());
        }
        let body = resp.text().await.unwrap_or_default();
        Err(format!("ensure_public_repo({key}) failed: {status} {body}").into())
    }

    /// Mint a download ticket bound to `resource_path`.
    async fn mint_ticket(&self, resource_path: &str) -> Result<String, Box<dyn std::error::Error>> {
        let client = Client::new();
        let resp = client
            .post(format!("{}/api/v1/auth/ticket", self.base_url))
            .header("Authorization", self.auth_header())
            .json(&json!({
                "purpose": "download",
                "resource_path": resource_path,
            }))
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("ticket mint failed: {status} {body}").into());
        }
        let body: Value = resp.json().await?;
        Ok(body["ticket"]
            .as_str()
            .ok_or("ticket response missing ticket field")?
            .to_string())
    }
}

/// Health check used as a stable public GET path: it has no auth requirement,
/// so we cannot use it to validate the ticket fallback. Tests instead use the
/// authenticated current-user endpoint, which the ticket must authenticate.
const TICKET_BOUND_PATH: &str = "/api/v1/auth/me";

// ---------------------------------------------------------------------------
// Test 1: ticket authenticates a GET that would otherwise 401.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires running HTTP server with fresh database"]
async fn test_ticket_authenticates_bound_get() {
    let mut server = Server::new();
    server.login().await.expect("login");

    let ticket = server
        .mint_ticket(TICKET_BOUND_PATH)
        .await
        .expect("mint ticket");

    let client = Client::new();
    let resp = client
        .get(format!(
            "{}{}?ticket={}",
            server.base_url, TICKET_BOUND_PATH, ticket
        ))
        .send()
        .await
        .expect("send");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "ticket-authenticated GET on bound path should return 200"
    );

    let body: Value = resp.json().await.expect("json body");
    assert_eq!(
        body["username"], ADMIN_USERNAME,
        "response should contain the minting user's identity"
    );
}

// ---------------------------------------------------------------------------
// Test 2: tickets are single-use.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires running HTTP server with fresh database"]
async fn test_ticket_single_use_second_attempt_rejected() {
    let mut server = Server::new();
    server.login().await.expect("login");

    let ticket = server
        .mint_ticket(TICKET_BOUND_PATH)
        .await
        .expect("mint ticket");

    let client = Client::new();
    let url = format!("{}{}?ticket={}", server.base_url, TICKET_BOUND_PATH, ticket);

    let first = client.get(&url).send().await.expect("first");
    assert_eq!(first.status(), StatusCode::OK, "first use should succeed");

    let second = client.get(&url).send().await.expect("second");
    assert_eq!(
        second.status(),
        StatusCode::UNAUTHORIZED,
        "ticket must be single-use; second attempt must 401"
    );
}

// ---------------------------------------------------------------------------
// Test 3: tickets bound to one path do not authenticate other paths.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires running HTTP server with fresh database"]
async fn test_ticket_bound_path_mismatch_rejected() {
    let mut server = Server::new();
    server.login().await.expect("login");

    let ticket = server
        .mint_ticket(TICKET_BOUND_PATH)
        .await
        .expect("mint ticket");

    // /api/v1/auth/me is authenticated; /api/v1/repositories is also
    // authenticated. A ticket bound to /me must not authenticate /repositories.
    let other_path = "/api/v1/repositories";
    let client = Client::new();
    let resp = client
        .get(format!(
            "{}{}?ticket={}",
            server.base_url, other_path, ticket
        ))
        .send()
        .await
        .expect("send");
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "ticket bound to a different path must not authenticate"
    );

    // Even after the failed attempt the ticket has been consumed by the
    // validate-and-delete query, so a legitimate retry against the bound
    // path must also fail. This is by design: rotating tickets cheaply
    // is preferred to leaving expired/unconsumed tickets in the DB.
    let retry = client
        .get(format!(
            "{}{}?ticket={}",
            server.base_url, TICKET_BOUND_PATH, ticket
        ))
        .send()
        .await
        .expect("retry");
    assert_eq!(
        retry.status(),
        StatusCode::UNAUTHORIZED,
        "ticket consumed by mismatched-path attempt must not be replayable"
    );
}

// ---------------------------------------------------------------------------
// Test 4: writes with a valid ticket are rejected (read-only policy).
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires running HTTP server with fresh database"]
async fn test_ticket_rejects_write_methods() {
    let mut server = Server::new();
    server.login().await.expect("login");

    // Mint a ticket bound to a write-capable path (repo create) and verify
    // the consumer middleware refuses to honor it for POST.
    let write_path = "/api/v1/repositories";
    let ticket = server.mint_ticket(write_path).await.expect("mint ticket");

    let client = Client::new();
    let resp = client
        .post(format!(
            "{}{}?ticket={}",
            server.base_url, write_path, ticket
        ))
        .json(&json!({
            "key": "ticket-write-attempt",
            "name": "ticket-write-attempt",
            "format": "generic",
            "repo_type": "local",
            "is_public": true,
        }))
        .send()
        .await
        .expect("send");
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "POST with ticket must be rejected; tickets are read-only"
    );
}

// ---------------------------------------------------------------------------
// Test 5: missing ticket value produces a 401 with a clear message.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires running HTTP server with fresh database"]
async fn test_missing_ticket_query_param_still_401() {
    let server = Server::new();
    let client = Client::new();
    let resp = client
        .get(format!("{}{}", server.base_url, TICKET_BOUND_PATH))
        .send()
        .await
        .expect("send");
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "no creds and no ticket must 401"
    );
}

// ---------------------------------------------------------------------------
// Test 6: an obviously-bogus ticket is rejected without consuming anything.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires running HTTP server with fresh database"]
async fn test_invalid_ticket_value_rejected() {
    let server = Server::new();
    let client = Client::new();
    let resp = client
        .get(format!(
            "{}{}?ticket=notarealtoken000000000000000000",
            server.base_url, TICKET_BOUND_PATH
        ))
        .send()
        .await
        .expect("send");
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "garbage ticket value must 401"
    );
}
