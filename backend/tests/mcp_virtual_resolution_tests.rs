//! Virtual MCP registries through the full router (#5253, Phase 2).
//!
//! The lib tests in `api/handlers/mcp_virtual.rs` drive the handlers
//! directly; this target goes through `create_router` (authentication,
//! repository visibility, the `/mcp/` surface guard) with repositories and
//! memberships created through the repository API, and checks what a client
//! sees: first match by priority, hosted shadows remote (also when the
//! hosted member is invisible to the caller), the composite cursor, the
//! `/v0` alias, writes refused, and the holds/openapi extension routes.
//!
//! ```sh
//! DATABASE_URL=... AK_TESTS_REQUIRE_DB=1 \
//!   cargo nextest run --run-ignored ignored-only --test mcp_virtual_resolution_tests
//! ```

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::disallowed_methods)] // streaming-invariant: test file exempt (#1608)

mod common;

use axum::http::StatusCode;
use serde_json::{json, Value};

use artifact_keeper_backend::formats::mcp::NOT_FOUND_BODY;

use common::mcp_support::McpHarness;

/// [`McpHarness`] plus the repositories this target creates.
struct Harness {
    it: McpHarness,
    repos: Vec<String>,
}

impl std::ops::Deref for Harness {
    type Target = McpHarness;
    fn deref(&self) -> &McpHarness {
        &self.it
    }
}

impl Harness {
    async fn new() -> Option<Self> {
        Some(Self {
            it: McpHarness::new().await?,
            repos: Vec::new(),
        })
    }

    async fn repo(&mut self, label: &str, repo_type: &str, public: bool) -> String {
        let key = self.it.mcp_repo(label, repo_type, public).await;
        self.repos.push(key.clone());
        key
    }

    async fn add_member(&self, virtual_key: &str, member: &str, priority: i32) {
        let r = self
            .send(
                "POST",
                &format!("/api/v1/repositories/{virtual_key}/members"),
                true,
                Some(json!({"member_key": member, "priority": priority})),
            )
            .await;
        assert!(
            r.status.is_success(),
            "add member: {} {}",
            r.status,
            r.json()
        );
    }

    async fn set_type(&self, key: &str, repo_type: &str) {
        sqlx::query("UPDATE repositories SET repo_type = $2::repository_type WHERE key = $1")
            .bind(key)
            .bind(repo_type)
            .execute(&self.pool)
            .await
            .unwrap();
    }

    /// Publish `name@version` into `key`. A Remote's rows come from its
    /// upstream sync in production; here the Remote briefly accepts a
    /// hosted publish, which stores the same row shape.
    async fn publish(&self, key: &str, name: &str, version: &str, description: &str) {
        let remote: bool = sqlx::query_scalar(
            "SELECT repo_type::text = 'remote' FROM repositories WHERE key = $1",
        )
        .bind(key)
        .fetch_one(&self.pool)
        .await
        .unwrap();
        if remote {
            self.set_type(key, "local").await;
        }
        let doc = McpHarness::server_doc(name, version, description);
        let r = self
            .send("POST", &format!("/mcp/{key}/v0.1/publish"), true, Some(doc))
            .await;
        if remote {
            self.set_type(key, "remote").await;
            // A Remote serves only names its curation approved.
            sqlx::query(
                "INSERT INTO curation_packages \
                   (staging_repo_id, remote_repo_id, format, package_name, version, \
                    upstream_path, status, evaluated_at) \
                 SELECT id, id, 'mcp', $2, '*', $2, 'approved', now() \
                 FROM repositories WHERE key = $1 ON CONFLICT DO NOTHING",
            )
            .bind(key)
            .bind(name)
            .execute(&self.pool)
            .await
            .unwrap();
        }
        assert_eq!(r.status, StatusCode::OK, "{}", r.json());
    }

    async fn teardown(self) {
        self.it.teardown(&self.repos).await;
    }
}

fn names(list: &Value) -> Vec<String> {
    list["servers"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|e| {
                    format!(
                        "{}@{} ({})",
                        e["server"]["name"].as_str().unwrap_or(""),
                        e["server"]["version"].as_str().unwrap_or(""),
                        e["_meta"]["com.artifactkeeper.registry/source"]["repository"]
                            .as_str()
                            .unwrap_or("")
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
#[ignore]
async fn virtual_serves_members_in_order_with_hosted_shadowing_remote() {
    let Some(mut h) = Harness::new().await else {
        return;
    };
    let remote = h.repo("r", "remote", true).await;
    let hidden = h.repo("hidden", "local", false).await;
    let local = h.repo("l", "local", true).await;
    let virt = h.repo("v", "virtual", true).await;
    h.add_member(&virt, &remote, 1).await;
    h.add_member(&virt, &hidden, 2).await;
    h.add_member(&virt, &local, 3).await;

    h.publish(&remote, "com.acme/x", "9.0.0", "upstream").await;
    h.publish(&remote, "io.public/y", "1.0.0", "upstream").await;
    h.publish(&remote, "com.acme/z", "1.0.0", "upstream").await;
    h.publish(&hidden, "com.acme/z", "0.1.0", "internal").await;
    h.publish(&local, "com.acme/x", "1.0.0", "internal").await;

    // Anonymous on the public Virtual: the private member is invisible, yet
    // its name still shadows the Remote's.
    let list = h
        .send("GET", &format!("/mcp/{virt}/v0.1/servers"), false, None)
        .await;
    assert_eq!(list.status, StatusCode::OK);
    assert_eq!(
        names(&list.json()),
        vec![
            format!("com.acme/x@1.0.0 ({local})"),
            format!("io.public/y@1.0.0 ({remote})"),
        ]
    );
    let alias = h
        .send("GET", &format!("/mcp/{virt}/v0/servers"), false, None)
        .await;
    assert_eq!(alias.bytes, list.bytes);

    let unknown = h
        .send(
            "GET",
            &format!("/mcp/{virt}/v0.1/servers/com.acme%2Fnope/versions/1.0.0"),
            false,
            None,
        )
        .await;
    for tail in [
        "com.acme%2Fz/versions/1.0.0",
        "com.acme/x/versions/9.0.0",
        "com.acme/z/versions/latest",
    ] {
        let r = h
            .send(
                "GET",
                &format!("/mcp/{virt}/v0.1/servers/{tail}"),
                false,
                None,
            )
            .await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{tail}");
        assert_eq!(r.bytes, NOT_FOUND_BODY.as_bytes(), "{tail}");
        assert_eq!(r.bytes, unknown.bytes);
        assert_eq!(r.headers["cache-control"], "no-store");
        assert_eq!(r.headers["content-type"], "application/problem+json");
    }

    // The administrator reads the private member too: it serves z itself.
    let z = h
        .send(
            "GET",
            &format!("/mcp/{virt}/v0.1/servers/com.acme%2Fz/versions/latest"),
            true,
            None,
        )
        .await;
    assert_eq!(z.status, StatusCode::OK);
    assert_eq!(z.json()["server"]["description"], "internal");
    assert_eq!(
        z.json()["_meta"]["com.artifactkeeper.registry/source"]["virtualRepository"],
        virt.as_str()
    );

    // Composite cursor paging visits every entry once.
    let mut seen = Vec::new();
    let mut uri = format!("/mcp/{virt}/v0.1/servers?limit=1");
    for _ in 0..6 {
        let page = h.send("GET", &uri, true, None).await.json();
        seen.extend(names(&page));
        let Some(next) = page["metadata"]["nextCursor"].as_str() else {
            break;
        };
        uri = format!("/mcp/{virt}/v0.1/servers?limit=1&cursor={next}");
    }
    assert_eq!(
        seen,
        vec![
            format!("com.acme/z@0.1.0 ({hidden})"),
            format!("com.acme/x@1.0.0 ({local})"),
            format!("io.public/y@1.0.0 ({remote})"),
        ]
    );

    // Writes: anonymous is challenged by the shared middleware, a credential
    // gets the Virtual's 405.
    let doc = json!({"name": "com.acme/w", "version": "1", "description": "d",
                     "remotes": [{"type": "sse", "url": "https://x.test/sse"}]});
    let anon = h
        .send(
            "POST",
            &format!("/mcp/{virt}/v0.1/publish"),
            false,
            Some(doc.clone()),
        )
        .await;
    assert_eq!(anon.status, StatusCode::UNAUTHORIZED);
    let w = h
        .send(
            "POST",
            &format!("/mcp/{virt}/v0.1/publish"),
            true,
            Some(doc),
        )
        .await;
    assert_eq!(
        (w.status, w.json()["error"].as_str()),
        (StatusCode::METHOD_NOT_ALLOWED, Some("mcp_read_only"))
    );
    h.teardown().await;
}

#[tokio::test]
#[ignore]
async fn holds_listing_and_openapi_extension_routes() {
    let Some(mut h) = Harness::new().await else {
        return;
    };
    let local = h.repo("holds", "local", true).await;
    h.publish(&local, "com.acme/a", "1.0.0", "a").await;
    h.publish(&local, "com.acme/b", "1.0.0", "b").await;
    sqlx::query(
        "UPDATE artifacts SET quarantine_status = 'quarantined', quarantine_source = 'admin', \
         quarantine_until = NULL WHERE name = 'com.acme/b' AND repository_id = \
         (SELECT id FROM repositories WHERE key = $1)",
    )
    .bind(&local)
    .execute(&h.pool)
    .await
    .unwrap();

    let holds = h
        .send(
            "GET",
            &format!("/mcp/{local}/v0.1/x/com.artifactkeeper/holds"),
            true,
            None,
        )
        .await;
    assert_eq!(holds.status, StatusCode::OK);
    assert_eq!(holds.headers["cache-control"], "no-store");
    let body = holds.json();
    assert_eq!(body["metadata"]["count"], 1, "{body}");
    let entry = &body["holds"][0];
    assert_eq!(
        (
            entry["name"].as_str(),
            entry["hold"].as_str(),
            entry["error"].as_str(),
            entry["status"].as_u64()
        ),
        (
            Some("com.acme/b"),
            Some("quarantine"),
            Some("mcp_pending_review"),
            Some(404)
        )
    );
    let anon = h
        .send(
            "GET",
            &format!("/mcp/{local}/v0/x/com.artifactkeeper/holds"),
            false,
            None,
        )
        .await;
    assert_eq!(
        (anon.status, anon.bytes.as_slice()),
        (StatusCode::NOT_FOUND, NOT_FOUND_BODY.as_bytes())
    );

    let spec = h
        .send(
            "GET",
            &format!("/mcp/{local}/v0.1/openapi.yaml"),
            false,
            None,
        )
        .await;
    assert_eq!(spec.status, StatusCode::OK);
    assert_eq!(spec.headers["content-type"], "application/yaml");
    assert!(String::from_utf8_lossy(&spec.bytes).contains("openapi: 3.1.0"));

    // Upstream's other logins answer 501, outside repository visibility.
    let none = h
        .send("POST", &format!("/mcp/{local}/v0/auth/none"), false, None)
        .await;
    assert_eq!(
        (none.status, none.json()["error"].as_str()),
        (StatusCode::NOT_IMPLEMENTED, Some("mcp_auth_not_supported"))
    );
    h.teardown().await;
}
