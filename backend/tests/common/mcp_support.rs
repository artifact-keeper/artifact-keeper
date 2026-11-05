//! Shared harness of the MCP registry integration targets (#5253): an
//! administrator with a bearer token and one-request-through-the-full-router.

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use artifact_keeper_backend::api::routes::create_router;
use artifact_keeper_backend::api::SharedState;
use artifact_keeper_backend::models::user::User;
use artifact_keeper_backend::services::auth_service::AuthService;

pub struct McpHarness {
    pub pool: PgPool,
    pub state: SharedState,
    pub admin: Uuid,
    pub bearer: String,
    /// Unique suffix for keys created by one test.
    pub tag: String,
}

pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub bytes: Vec<u8>,
}

impl Reply {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.bytes).unwrap_or(Value::Null)
    }
}

impl McpHarness {
    pub async fn new() -> Option<Self> {
        let pool = super::sso_support::try_pool().await?;
        let state = super::sso_support::build_state(pool.clone());
        let admin = Uuid::new_v4();
        let tag = admin.simple().to_string()[..10].to_string();
        let user: User = sqlx::query_as(
            "INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, \
                                is_active, must_change_password, password_changed_at) \
             VALUES ($1, $2, $3, 'unused', 'local', true, true, false, NOW() - INTERVAL '2 seconds') \
             RETURNING *",
        )
        .bind(admin)
        .bind(format!("mcp-it-admin-{tag}"))
        .bind(format!("mcp-it-{tag}@test.local"))
        .fetch_one(&pool)
        .await
        .expect("seed admin");
        let bearer = AuthService::new(pool.clone(), std::sync::Arc::new(state.config.clone()))
            .generate_tokens(&user)
            .expect("admin token")
            .access_token;
        Some(Self {
            pool,
            state,
            admin,
            bearer,
            tag,
        })
    }

    /// One request through `create_router`, with `bearer` when given.
    pub async fn send_as(
        &self,
        method: &str,
        uri: &str,
        bearer: Option<&str>,
        body: Option<Value>,
    ) -> Reply {
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(token) = bearer {
            req = req.header("authorization", format!("Bearer {token}"));
        }
        if body.is_some() {
            req = req.header("content-type", "application/json");
        }
        let body = body
            .map(|b| Body::from(b.to_string()))
            .unwrap_or_else(Body::empty);
        let resp = create_router(self.state.clone())
            .oneshot(req.body(body).expect("request"))
            .await
            .expect("router oneshot");
        let status = resp.status();
        let headers = resp.headers().clone();
        #[allow(clippy::disallowed_methods)]
        // streaming-invariant: test harness exempt — buffering small JSON
        // responses in test assertions is not an artifact path (#1608)
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 22)
            .await
            .expect("read body")
            .to_vec();
        Reply {
            status,
            headers,
            bytes,
        }
    }

    /// [`Self::send_as`] as the administrator (`admin`) or anonymously.
    pub async fn send(&self, method: &str, uri: &str, admin: bool, body: Option<Value>) -> Reply {
        let bearer = admin.then_some(self.bearer.as_str());
        self.send_as(method, uri, bearer, body).await
    }

    /// Create an `mcp` repository through the API (`open` package policy on
    /// hosted and Remote ones); returns its key.
    pub async fn mcp_repo(&self, label: &str, repo_type: &str, public: bool) -> String {
        let key = format!("mcp-{label}-{}", self.tag);
        let mut body = serde_json::json!({
            "key": key, "name": key, "format": "mcp", "repo_type": repo_type,
            "is_public": public,
        });
        if repo_type == "remote" {
            body["upstream_url"] = "https://registry.example.test".into();
        }
        let r = self
            .send("POST", "/api/v1/repositories", true, Some(body))
            .await;
        assert!(
            r.status.is_success(),
            "create {key}: {} {}",
            r.status,
            r.json()
        );
        if repo_type != "virtual" {
            self.set_config(&key, "mcp_package_policy", "open").await;
        }
        key
    }

    pub async fn set_config(&self, key: &str, k: &str, v: &str) {
        sqlx::query(
            "INSERT INTO repository_config (repository_id, key, value) \
             SELECT id, $2, $3 FROM repositories WHERE key = $1 \
             ON CONFLICT (repository_id, key) DO UPDATE SET value = $3",
        )
        .bind(key)
        .bind(k)
        .bind(v)
        .execute(&self.pool)
        .await
        .expect("set repository config");
    }

    /// A server.json with one remote.
    pub fn server_doc(name: &str, version: &str, description: &str) -> Value {
        serde_json::json!({
            "name": name, "version": version, "description": description,
            "remotes": [{"type": "streamable-http", "url": "https://mcp.example.test/mcp"}],
        })
    }

    /// Remove the repositories in `keys` with what the tests stored in them,
    /// then the administrator.
    pub async fn teardown(&self, keys: &[String]) {
        for key in keys {
            for sql in [
                "DELETE FROM virtual_repo_members WHERE virtual_repo_id IN \
                 (SELECT id FROM repositories WHERE key = $1) OR member_repo_id IN \
                 (SELECT id FROM repositories WHERE key = $1)",
                "DELETE FROM permissions WHERE target_id IN (SELECT id FROM repositories WHERE key = $1)",
                "DELETE FROM artifact_metadata WHERE artifact_id IN (SELECT a.id FROM artifacts a \
                 JOIN repositories r ON r.id = a.repository_id WHERE r.key = $1)",
                "DELETE FROM artifacts WHERE repository_id IN (SELECT id FROM repositories WHERE key = $1)",
                "DELETE FROM packages WHERE repository_id IN (SELECT id FROM repositories WHERE key = $1)",
                "DELETE FROM repositories WHERE key = $1",
            ] {
                let _ = sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(key)
                    .execute(&self.pool)
                    .await;
            }
        }
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(self.admin)
            .execute(&self.pool)
            .await;
    }
}
