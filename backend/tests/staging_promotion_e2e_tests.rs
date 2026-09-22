//! End-to-end coverage for promoting an artifact out of a STAGING repository
//! into its release repository.
//!
//! # Why this file exists
//!
//! Every promotion decision — capability check, tenant gate, target resolution,
//! release-link enforcement, gate/policy/rule ordering, approval consume, byte
//! copy, history write — is sequenced inside `promote_artifact` in
//! `src/api/handlers/promotion.rs`. The two pre-existing promotion suites
//! (`promotion_block_unscanned_tests`, `promotion_open_cve_gating_tests`) drive
//! `PromotionPolicyService` directly, so they cannot observe that sequence at
//! all, and both only assert that a promotion is BLOCKED. Nothing executed a
//! successful staging -> release promotion, which meant an ordering, target
//! resolution or history-write defect was invisible to CI.
//!
//! The release-gate `promotion` suite (artifact-keeper-test) does run a
//! promotion, but from a `Local` source — see the comment above
//! `validate_promotion_source_is_staging`, which is why the source-shape check
//! was widened from staging-only to any hosted repository. So the staging
//! source specifically had no end-to-end coverage anywhere.
//!
//! # What this file does and does NOT prove
//!
//! It mounts the real `handlers::promotion::router()` over a live pool and a
//! per-repository `FilesystemStorage`, and drives it with `oneshot`.
//!
//! **`AuthExtension` is injected as a layer, not produced by the auth
//! middleware.** The middleware is applied where the router is mounted
//! (`src/api/routes.rs`), not inside the promotion router, so these tests take
//! the calling principal as an input. That is deliberate — it lets the
//! capability, scope and tenant cases each vary one field — but it means the
//! `403` cases here pin the HANDLER's own checks and NOT that a real
//! unprivileged token is refused end to end. Do not read a green run as proof
//! of the latter.
//!
//! **Single-use approval semantics are tested sequentially**, not concurrently.
//! The atomic single-row claim is what makes the second attempt fail, and that
//! is observable without racing. Genuine parallel double-spend is not pinned
//! here.
//!
//! # Running
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//! AK_TESTS_REQUIRE_DB=1 SQLX_OFFLINE=true \
//! JWT_SECRET="test-secret-at-least-32-bytes-long-for-testing" \
//!   cargo test --test staging_promotion_e2e_tests -- --ignored --test-threads=1
//! ```
//!
//! A case that finishes in ~0.04s did not run (#2924).

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)] // streaming-invariant: test file exempt — buffering response bodies in assertions is not an artifact path (#1608)

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Extension;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use artifact_keeper_backend::api::handlers::promotion;
use artifact_keeper_backend::api::middleware::auth::AuthExtension;
use artifact_keeper_backend::api::{AppState, SharedState};
use artifact_keeper_backend::config::Config;
use artifact_keeper_backend::models::access_scope::AccessScope;
use artifact_keeper_backend::services::quality_check_service::QualityCheckService;

// ===========================================================================
// Fixtures
// ===========================================================================

/// Connect to the Postgres the `#[ignore]`d cases run against. Panics when
/// `DATABASE_URL` is unset so a missing test database fails loudly rather than
/// testing nothing (#2924).
async fn require_db_pool() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set for the staging-promotion integration tests");
    PgPool::connect(&url)
        .await
        .expect("failed to connect to the test database")
}

fn test_config(storage_path: &str) -> Config {
    Config {
        database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
        storage_path: storage_path.into(),
        jwt_secret: "test-secret-at-least-32-bytes-long-for-testing".into(),
        setup_password_hint: None,
        ..Default::default()
    }
}

/// A repository created for one test, with the filesystem root its
/// `FilesystemStorage` is rooted at.
///
/// Each repository gets its own directory because
/// `StorageRegistry::backend_for` roots a fresh `FilesystemStorage` at the
/// repository's `storage_path`. That isolation is what makes "the bytes landed
/// in the TARGET" an assertion with teeth: the promotion copy re-uses the
/// source artifact's storage key, so with a shared root it would write the same
/// file back over itself and prove nothing.
struct Repo {
    id: Uuid,
    key: String,
    storage_path: PathBuf,
}

impl Repo {
    /// Absolute path the given storage key resolves to inside this repository.
    fn object_path(&self, storage_key: &str) -> PathBuf {
        self.storage_path.join(storage_key)
    }
}

/// Build application state. Pass `with_gate` to wire a `QualityCheckService`:
/// `AppState::new` leaves `quality_check_service` as `None`, and
/// `evaluate_gate_once` treats a missing service as `NotEvaluated`, so a state
/// built the plain way cannot exercise ANY quality-gate case.
fn build_state(pool: &PgPool, default_storage_root: &str, with_gate: bool) -> SharedState {
    let storage: Arc<dyn artifact_keeper_backend::storage::StorageBackend> = Arc::new(
        artifact_keeper_backend::storage::filesystem::FilesystemStorage::new(default_storage_root),
    );
    let registry = Arc::new(artifact_keeper_backend::storage::StorageRegistry::new(
        HashMap::new(),
        "filesystem".to_string(),
    ));
    let mut state = AppState::new(
        test_config(default_storage_root),
        pool.clone(),
        storage,
        registry,
    );
    if with_gate {
        state.set_quality_check_service(Arc::new(QualityCheckService::new(pool.clone())));
    }
    Arc::new(state)
}

/// Create a repository of `repo_type` / `format` with a unique key and its own
/// storage directory.
async fn create_repo(pool: &PgPool, repo_type: &str, format: &str, label: &str) -> Repo {
    let id = Uuid::new_v4();
    let key = format!("stgpromo-{}-{}", label, &id.to_string()[..8]);
    let storage_path = std::env::temp_dir().join(format!("stgpromo-{}", id));
    std::fs::create_dir_all(&storage_path).expect("create storage dir");
    // `check_upstream_url` requires a remote (proxy) repository to carry one.
    let upstream_url = (repo_type == "remote").then_some("https://upstream.invalid/");
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, is_public, upstream_url) \
         VALUES ($1, $2, $2, $3, $4::repository_type, $5::repository_format, false, $6)",
    )
    .bind(id)
    .bind(&key)
    .bind(&*storage_path.to_string_lossy())
    .bind(repo_type)
    .bind(format)
    .bind(upstream_url)
    .execute(pool)
    .await
    .unwrap_or_else(|e| panic!("insert {} {} repo: {}", repo_type, format, e));
    Repo {
        id,
        key,
        storage_path,
    }
}

async fn create_user(pool: &PgPool, prefix: &str, is_admin: bool) -> Uuid {
    let id = Uuid::new_v4();
    let username = format!("stgpromo-{}-{}", prefix, &id.to_string()[..8]);
    sqlx::query(
        "INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, is_active) \
         VALUES ($1, $2, $3, NULL, 'local', $4, true)",
    )
    .bind(id)
    .bind(&username)
    .bind(format!("{}@test.local", username))
    .bind(is_admin)
    .execute(pool)
    .await
    .expect("insert user");
    id
}

/// Grant the principal a `role_assignments` row, which is the predicate
/// `user_can_access_repo(.., TenantOnly)` evaluates. `repo_id = None` seeds the
/// globally scoped (NULL-scoped) grant that a genuine super-admin holds.
///
/// This is load-bearing: the tenant gate is enforced INDEPENDENTLY of the
/// `is_admin` capability flag, so an admin principal without one of these rows
/// is refused. See `test_admin_without_tenant_grant_is_refused`.
async fn grant_repo(pool: &PgPool, user_id: Uuid, repo_id: Option<Uuid>) {
    let role_id: Uuid = sqlx::query_scalar("SELECT id FROM roles WHERE name = 'admin'")
        .fetch_one(pool)
        .await
        .expect("the 'admin' role is seeded by migration 002");
    sqlx::query(
        "INSERT INTO role_assignments (user_id, role_id, repository_id) VALUES ($1, $2, $3)",
    )
    .bind(user_id)
    .bind(role_id)
    .bind(repo_id)
    .execute(pool)
    .await
    .expect("insert role assignment");
}

/// An uploaded artifact: the row id, its repository path, and the storage key
/// whose bytes the promotion copy moves.
struct Uploaded {
    id: Uuid,
    path: String,
    storage_key: String,
}

/// Write `content` into `repo`'s storage and insert the matching `artifacts`
/// row, the way an upload would.
async fn upload_artifact(pool: &PgPool, repo: &Repo, name: &str, content: &[u8]) -> Uploaded {
    use sha2::{Digest, Sha256};

    let id = Uuid::new_v4();
    let path = format!("e2e/{}", name);
    let storage_key = format!("{}/{}", &id.to_string()[..8], name);
    let checksum = format!("{:x}", Sha256::digest(content));

    let object_path = repo.object_path(&storage_key);
    std::fs::create_dir_all(object_path.parent().expect("object path has a parent"))
        .expect("create object dir");
    std::fs::write(&object_path, content).expect("write object");

    sqlx::query(
        "INSERT INTO artifacts (id, repository_id, path, name, size_bytes, checksum_sha256, \
                                content_type, storage_key, is_deleted) \
         VALUES ($1, $2, $3, $4, $5, $6, 'application/octet-stream', $7, false)",
    )
    .bind(id)
    .bind(repo.id)
    .bind(&path)
    .bind(name)
    .bind(content.len() as i64)
    .bind(&checksum)
    .bind(&storage_key)
    .execute(pool)
    .await
    .expect("insert artifact");

    Uploaded {
        id,
        path,
        storage_key,
    }
}

/// Link `staging` to `release` the way `PUT .../release-target` does.
async fn link_release_target(pool: &PgPool, staging: &Repo, release: &Repo) {
    sqlx::query(
        "INSERT INTO repository_config (repository_id, key, value) \
         VALUES ($1, 'release_repository_id', $2) \
         ON CONFLICT (repository_id, key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(staging.id)
    .bind(release.id.to_string())
    .execute(pool)
    .await
    .expect("link release target");
}

/// A principal. `is_admin` grants the promote capability; the tenant gate is
/// separate and needs `grant_repo`.
fn principal(user_id: Uuid, is_admin: bool) -> AuthExtension {
    AuthExtension {
        user_id,
        username: format!("stgpromo-{}", &user_id.to_string()[..8]),
        email: "stgpromo@test.local".to_string(),
        is_admin,
        is_api_token: false,
        is_service_account: false,
        scopes: None,
        allowed_repo_ids: AccessScope::Admin,
        iat_ms: None,
    }
}

/// A principal whose promote capability comes from an API token scope rather
/// than the admin flag.
fn scoped_token_principal(user_id: Uuid, scopes: &[&str]) -> AuthExtension {
    AuthExtension {
        is_api_token: true,
        scopes: Some(scopes.iter().map(|s| s.to_string()).collect()),
        ..principal(user_id, false)
    }
}

/// Dispatch one request at the promotion router with `auth` injected exactly
/// where the auth middleware would place it. Returns the status and the parsed
/// body (`Value::Null` when the body is empty or not JSON).
async fn send(
    state: &SharedState,
    method: &str,
    uri: &str,
    auth: AuthExtension,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let app = promotion::router()
        .with_state(state.clone())
        .layer(Extension::<AuthExtension>(auth));
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("Content-Type", "application/json")
        .body(match &body {
            Some(v) => Body::from(v.to_string()),
            None => Body::empty(),
        })
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read response body");
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

/// URI for a single-artifact promotion.
fn promote_uri(repo_key: &str, artifact_id: Uuid) -> String {
    format!(
        "/repositories/{}/artifacts/{}/promote",
        repo_key, artifact_id
    )
}

async fn cleanup(pool: &PgPool, repos: &[&Repo], users: &[Uuid]) {
    for repo in repos {
        for sql in [
            "DELETE FROM promotion_history WHERE source_repo_id = $1 OR target_repo_id = $1",
            "DELETE FROM promotion_approvals WHERE source_repo_id = $1 OR target_repo_id = $1",
            "DELETE FROM promotion_rules WHERE source_repo_id = $1 OR target_repo_id = $1",
            "DELETE FROM quality_gate_evaluations WHERE artifact_id IN \
             (SELECT id FROM artifacts WHERE repository_id = $1)",
            "DELETE FROM quality_gates WHERE repository_id = $1",
            "DELETE FROM artifact_health_scores WHERE artifact_id IN \
             (SELECT id FROM artifacts WHERE repository_id = $1)",
            "DELETE FROM scan_results WHERE repository_id = $1",
            "DELETE FROM scan_policies WHERE repository_id = $1",
            "DELETE FROM repository_config WHERE repository_id = $1",
            "DELETE FROM artifacts WHERE repository_id = $1",
            "DELETE FROM repositories WHERE id = $1",
        ] {
            sqlx::query(sql).bind(repo.id).execute(pool).await.ok();
        }
        std::fs::remove_dir_all(&repo.storage_path).ok();
    }
    for user_id in users {
        for sql in [
            "DELETE FROM role_assignments WHERE user_id = $1",
            "DELETE FROM users WHERE id = $1",
        ] {
            sqlx::query(sql).bind(user_id).execute(pool).await.ok();
        }
    }
}

// ===========================================================================
// 1. Harness smoke test
// ===========================================================================

/// Proves the fixtures work end to end before any behavioural assertion relies
/// on them: repositories are created with isolated storage, an upload lands
/// both on disk and in `artifacts`, a grant satisfies the tenant gate, and the
/// router accepts an injected principal.
#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_harness_promotes_a_staging_artifact() {
    let pool = require_db_pool().await;
    let staging = create_repo(&pool, "staging", "generic", "src").await;
    let release = create_repo(&pool, "local", "generic", "rel").await;
    let user = create_user(&pool, "smoke", true).await;
    grant_repo(&pool, user, None).await;

    let content = b"harness smoke payload";
    let uploaded = upload_artifact(&pool, &staging, "smoke.txt", content).await;
    assert_eq!(
        std::fs::read(staging.object_path(&uploaded.storage_key)).expect("source object"),
        content,
        "fixture must place the object byte-for-byte in the SOURCE repository's own tree"
    );
    assert!(
        !release.object_path(&uploaded.storage_key).exists(),
        "the target must not already hold the object, or the copy assertion proves nothing"
    );

    let state = build_state(&pool, &staging.storage_path.to_string_lossy(), false);
    let (status, body) = send(
        &state,
        "POST",
        &promote_uri(&staging.key, uploaded.id),
        principal(user, true),
        Some(serde_json::json!({ "target_repository": release.key })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "promotion failed: {}", body);
    assert_eq!(body["promoted"], true, "body: {}", body);

    cleanup(&pool, &[&staging, &release], &[user]).await;
}

// ===========================================================================
// Shared scenario fixture
// ===========================================================================

/// A staging source linked to a release target, an admin principal with a
/// globally scoped grant, and application state. Shared by the behavioural
/// tests so each one carries only what it is actually asserting.
struct Fixture {
    pool: PgPool,
    staging: Repo,
    release: Repo,
    user: Uuid,
    state: SharedState,
}

impl Fixture {
    /// `linked` also writes the `release_repository_id` link, so a promotion
    /// request may omit `target_repository`.
    async fn new(label: &str, linked: bool, with_gate: bool) -> Self {
        Self::with_formats(label, "generic", "generic", linked, with_gate).await
    }

    async fn with_formats(
        label: &str,
        source_format: &str,
        target_format: &str,
        linked: bool,
        with_gate: bool,
    ) -> Self {
        let pool = require_db_pool().await;
        let staging = create_repo(&pool, "staging", source_format, label).await;
        let release = create_repo(&pool, "local", target_format, label).await;
        let user = create_user(&pool, label, true).await;
        grant_repo(&pool, user, None).await;
        if linked {
            link_release_target(&pool, &staging, &release).await;
        }
        let state = build_state(&pool, &staging.storage_path.to_string_lossy(), with_gate);
        Self {
            pool,
            staging,
            release,
            user,
            state,
        }
    }

    async fn upload(&self, name: &str, content: &[u8]) -> Uploaded {
        upload_artifact(&self.pool, &self.staging, name, content).await
    }

    /// Promote as the fixture's admin principal, naming the target explicitly.
    async fn promote(&self, artifact_id: Uuid) -> (StatusCode, Value) {
        self.promote_with(
            artifact_id,
            serde_json::json!({ "target_repository": self.release.key }),
        )
        .await
    }

    async fn promote_with(&self, artifact_id: Uuid, body: Value) -> (StatusCode, Value) {
        send(
            &self.state,
            "POST",
            &promote_uri(&self.staging.key, artifact_id),
            principal(self.user, true),
            Some(body),
        )
        .await
    }

    /// Promote several artifacts in one request.
    async fn promote_bulk(&self, artifact_ids: &[Uuid]) -> (StatusCode, Value) {
        let ids: Vec<String> = artifact_ids.iter().map(|id| id.to_string()).collect();
        send(
            &self.state,
            "POST",
            &format!("/repositories/{}/promote", self.staging.key),
            principal(self.user, true),
            Some(serde_json::json!({
                "target_repository": self.release.key,
                "artifact_ids": ids,
            })),
        )
        .await
    }

    async fn history(&self) -> Value {
        let (status, body) = send(
            &self.state,
            "GET",
            &format!("/repositories/{}/promotion-history", self.staging.key),
            principal(self.user, true),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "history read failed: {}", body);
        body
    }

    /// Remove every `role_assignments` row for the principal, leaving it
    /// admin-capable but owning no tenant. The tenant gate is enforced
    /// independently of `is_admin`, so this is what a cross-tenant caller
    /// looks like.
    async fn revoke_tenant_grants(&self) {
        sqlx::query("DELETE FROM role_assignments WHERE user_id = $1")
            .bind(self.user)
            .execute(&self.pool)
            .await
            .expect("revoke grants");
    }

    async fn set_public(&self, repo: &Repo, is_public: bool) {
        sqlx::query("UPDATE repositories SET is_public = $2 WHERE id = $1")
            .bind(repo.id)
            .bind(is_public)
            .execute(&self.pool)
            .await
            .expect("set repository visibility");
    }

    async fn cleanup(self) {
        cleanup(&self.pool, &[&self.staging, &self.release], &[self.user]).await;
    }
}

// ===========================================================================
// 2. Success path
// ===========================================================================

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_successful_promotion_reports_promoted_with_an_identifier() {
    let f = Fixture::new("ok-resp", true, false).await;
    let uploaded = f.upload("reported.txt", b"reported payload").await;

    let (status, body) = f.promote_with(uploaded.id, serde_json::json!({})).await;

    assert_eq!(status, StatusCode::OK, "body: {}", body);
    assert_eq!(body["promoted"], true, "body: {}", body);
    assert!(
        body["promotion_id"].as_str().is_some_and(|s| !s.is_empty()),
        "a successful promotion must carry an identifier for the recorded promotion: {}",
        body
    );
    assert!(
        body["source"]
            .as_str()
            .is_some_and(|s| s.contains(&f.staging.key)),
        "source display must name the staging repository: {}",
        body
    );
    assert!(
        body["target"]
            .as_str()
            .is_some_and(|s| s.contains(&f.release.key)),
        "target display must name the release repository: {}",
        body
    );

    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_successful_promotion_copies_content_into_the_target() {
    let f = Fixture::new("ok-bytes", true, false).await;
    let content = b"the exact bytes that must arrive in the release repository";
    let uploaded = f.upload("payload.bin", content).await;

    assert!(
        !f.release.object_path(&uploaded.storage_key).exists(),
        "precondition: the target must not already hold this object"
    );

    let (status, body) = f.promote(uploaded.id).await;
    assert_eq!(status, StatusCode::OK, "body: {}", body);

    let promoted_bytes = std::fs::read(f.release.object_path(&uploaded.storage_key))
        .expect("the promoted object must exist in the TARGET repository's own storage tree");
    assert_eq!(
        promoted_bytes, content,
        "the promoted object must be byte-for-byte the uploaded content"
    );

    // The artifact must also be addressable in the target, not just on disk.
    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
    )
    .bind(f.release.id)
    .bind(&uploaded.path)
    .fetch_optional(&f.pool)
    .await
    .expect("query target artifact");
    assert!(
        row.is_some(),
        "a promotion must register the artifact in the target repository"
    );

    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_successful_promotion_is_recorded_in_history() {
    let f = Fixture::new("ok-hist", true, false).await;
    let uploaded = f.upload("recorded.txt", b"recorded payload").await;

    let (status, body) = f.promote(uploaded.id).await;
    assert_eq!(status, StatusCode::OK, "body: {}", body);

    let history = f.history().await;
    let items = history["items"]
        .as_array()
        .unwrap_or_else(|| panic!("history must return items: {}", history));
    let entry = items
        .iter()
        .find(|e| e["artifact_id"] == serde_json::json!(uploaded.id.to_string()))
        .unwrap_or_else(|| panic!("no history entry for the promoted artifact: {}", history));

    assert_eq!(entry["source_repo_key"], serde_json::json!(f.staging.key));
    assert_eq!(entry["target_repo_key"], serde_json::json!(f.release.key));
    assert_eq!(entry["status"], "promoted", "entry: {}", entry);
    assert_eq!(
        entry["promoted_by"],
        serde_json::json!(f.user.to_string()),
        "the acting principal must be recorded: {}",
        entry
    );
    assert_eq!(
        entry["artifact_path"],
        serde_json::json!(uploaded.path),
        "entry: {}",
        entry
    );

    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_successful_promotion_leaves_the_source_artifact_in_place() {
    let f = Fixture::new("ok-src", true, false).await;
    let content = b"source must survive promotion";
    let uploaded = f.upload("kept.txt", content).await;

    let (status, body) = f.promote(uploaded.id).await;
    assert_eq!(status, StatusCode::OK, "body: {}", body);

    let still_there: Option<(bool,)> =
        sqlx::query_as("SELECT is_deleted FROM artifacts WHERE id = $1 AND repository_id = $2")
            .bind(uploaded.id)
            .bind(f.staging.id)
            .fetch_optional(&f.pool)
            .await
            .expect("query source artifact");
    assert_eq!(
        still_there,
        Some((false,)),
        "promotion is a copy: the source artifact row must remain and stay undeleted"
    );
    assert_eq!(
        std::fs::read(f.staging.object_path(&uploaded.storage_key)).expect("source object"),
        content,
        "promotion must not move or truncate the source object"
    );

    f.cleanup().await;
}

// ===========================================================================
// 3. Target resolution and repository shape
// ===========================================================================

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_promotion_without_a_target_uses_the_configured_release_link() {
    let f = Fixture::new("link-use", true, false).await;
    let content = b"resolved through the release link";
    let uploaded = f.upload("linked.txt", content).await;

    // No `target_repository` in the body at all.
    let (status, body) = f.promote_with(uploaded.id, serde_json::json!({})).await;

    assert_eq!(status, StatusCode::OK, "body: {}", body);
    assert_eq!(body["promoted"], true, "body: {}", body);
    assert_eq!(
        std::fs::read(f.release.object_path(&uploaded.storage_key)).expect("promoted object"),
        content,
        "the artifact must land in the LINKED release repository"
    );

    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_promotion_may_not_escape_the_configured_release_link() {
    let f = Fixture::new("link-esc", true, false).await;
    let other = create_repo(&f.pool, "local", "generic", "other").await;
    let uploaded = f.upload("escapee.txt", b"must not escape").await;

    let (status, body) = f
        .promote_with(
            uploaded.id,
            serde_json::json!({ "target_repository": other.key }),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {}", body);
    let message = body["message"].as_str().unwrap_or_default();
    assert!(
        message.contains(&f.release.key),
        "the refusal must name the LINKED release repository, got: {}",
        message
    );
    assert!(
        !other.object_path(&uploaded.storage_key).exists(),
        "nothing may be written to the repository the request tried to escape to"
    );

    cleanup(&f.pool, &[&other], &[]).await;
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_promotion_without_a_target_or_a_link_is_refused() {
    let f = Fixture::new("no-target", false, false).await;
    let uploaded = f.upload("nowhere.txt", b"nowhere to go").await;

    let (status, body) = f.promote_with(uploaded.id, serde_json::json!({})).await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {}", body);
    let message = body["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("target_repository"),
        "the refusal must name the request field as one way to supply a target: {}",
        message
    );
    assert!(
        message.contains("release_repository_key"),
        "the refusal must name the release link as the other way to supply a target: {}",
        message
    );

    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_only_hosted_repositories_may_be_a_promotion_source() {
    let pool = require_db_pool().await;
    let release = create_repo(&pool, "local", "generic", "hosted-rel").await;
    let user = create_user(&pool, "hosted", true).await;
    grant_repo(&pool, user, None).await;
    let state = build_state(&pool, &release.storage_path.to_string_lossy(), false);

    // A proxy and an aggregate repository own no bytes, so neither can be a
    // promotion source.
    for repo_type in ["remote", "virtual"] {
        let source = create_repo(&pool, repo_type, "generic", "nonhosted").await;
        let uploaded = upload_artifact(&pool, &source, "ghost.txt", b"no bytes of its own").await;

        let (status, body) = send(
            &state,
            "POST",
            &promote_uri(&source.key, uploaded.id),
            principal(user, true),
            Some(serde_json::json!({ "target_repository": release.key })),
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a {} source must be refused, body: {}",
            repo_type,
            body
        );
        let message = body["message"].as_str().unwrap_or_default();
        assert!(
            message.to_lowercase().contains("hosted"),
            "the refusal must identify the source type as the reason, got: {}",
            message
        );
        cleanup(&pool, &[&source], &[]).await;
    }

    // The staging source passes the same check.
    let staging = create_repo(&pool, "staging", "generic", "hosted-src").await;
    let uploaded = upload_artifact(&pool, &staging, "real.txt", b"real bytes").await;
    let (status, body) = send(
        &state,
        "POST",
        &promote_uri(&staging.key, uploaded.id),
        principal(user, true),
        Some(serde_json::json!({ "target_repository": release.key })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "staging source must pass: {}", body);

    cleanup(&pool, &[&staging, &release], &[user]).await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_target_must_be_a_release_repository_of_the_same_format() {
    // Target shape: promoting into another staging repository is refused.
    let f = Fixture::new("tgt-shape", false, false).await;
    let staging_target = create_repo(&f.pool, "staging", "generic", "tgt-staging").await;
    let uploaded = f.upload("shape.txt", b"wrong target shape").await;

    let (status, body) = f
        .promote_with(
            uploaded.id,
            serde_json::json!({ "target_repository": staging_target.key }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {}", body);
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .to_lowercase()
            .contains("local"),
        "the refusal must say the target has to be a local (release) repository: {}",
        body
    );
    assert!(
        !staging_target.object_path(&uploaded.storage_key).exists(),
        "a shape refusal must copy nothing"
    );
    cleanup(&f.pool, &[&staging_target], &[]).await;
    f.cleanup().await;

    // Format: a maven staging source may not promote into an npm release repo.
    let g = Fixture::with_formats("fmt", "maven", "npm", false, false).await;
    let uploaded = g.upload("mismatch.jar", b"wrong format").await;
    let (status, body) = g.promote(uploaded.id).await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {}", body);
    let message = body["message"].as_str().unwrap_or_default().to_lowercase();
    assert!(
        message.contains("maven") && message.contains("npm"),
        "the refusal must name both formats, got: {}",
        message
    );
    assert!(
        !g.release.object_path(&uploaded.storage_key).exists(),
        "a format refusal must copy nothing"
    );

    g.cleanup().await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_release_linking_is_confined_to_staging_repositories() {
    let f = Fixture::new("link-gate", false, false).await;
    let uri = format!("/repositories/{}/release-target", f.release.key);

    let (status, body) = send(&f.state, "GET", &uri, principal(f.user, true), None).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "reading a release target on a non-staging repository must be refused: {}",
        body
    );

    let (status, body) = send(
        &f.state,
        "PUT",
        &uri,
        principal(f.user, true),
        Some(serde_json::json!({ "release_repository_key": f.staging.key })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "writing a release target on a non-staging repository must be refused: {}",
        body
    );

    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_a_link_to_a_deleted_repository_reads_as_unlinked() {
    let f = Fixture::new("link-dead", true, false).await;
    let uri = format!("/repositories/{}/release-target", f.staging.key);

    let (status, body) = send(&f.state, "GET", &uri, principal(f.user, true), None).await;
    assert_eq!(status, StatusCode::OK, "body: {}", body);
    assert_eq!(body["linked"], true, "precondition: the link exists");

    sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(f.release.id)
        .execute(&f.pool)
        .await
        .expect("delete the linked release repository");

    let (status, body) = send(&f.state, "GET", &uri, principal(f.user, true), None).await;
    assert_eq!(status, StatusCode::OK, "body: {}", body);
    assert_eq!(
        body["linked"], false,
        "a link pointing at a deleted repository must read as unlinked, not fail: {}",
        body
    );
    assert!(body["release_repository_key"].is_null(), "body: {}", body);

    f.cleanup().await;
}

// ===========================================================================
// 4. Capability and tenant gates
// ===========================================================================

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_non_privileged_session_principal_is_refused() {
    let f = Fixture::new("cap-sess", true, false).await;
    let uploaded = f.upload("denied.txt", b"must not be promoted").await;

    let (status, body) = send(
        &f.state,
        "POST",
        &promote_uri(&f.staging.key, uploaded.id),
        principal(f.user, false),
        Some(serde_json::json!({ "target_repository": f.release.key })),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "body: {}", body);
    assert!(
        !f.release.object_path(&uploaded.storage_key).exists(),
        "a capability refusal must copy nothing"
    );

    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_promote_scope_is_honoured_only_for_api_tokens() {
    let f = Fixture::new("cap-scope", true, false).await;

    // An API token bearing the scope may promote without the admin flag.
    let by_token = f
        .upload("by-token.txt", b"promoted by a scoped token")
        .await;
    let (status, body) = send(
        &f.state,
        "POST",
        &promote_uri(&f.staging.key, by_token.id),
        scoped_token_principal(f.user, &["promote:artifacts"]),
        Some(serde_json::json!({ "target_repository": f.release.key })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an API token with promote:artifacts must pass the capability check: {}",
        body
    );
    assert_eq!(body["promoted"], true, "body: {}", body);

    // The same scope presented by a SESSION principal must not grant it.
    let by_session = f.upload("by-session.txt", b"must not be promoted").await;
    let session_with_scope = AuthExtension {
        is_api_token: false,
        scopes: Some(vec!["promote:artifacts".to_string()]),
        ..principal(f.user, false)
    };
    let (status, body) = send(
        &f.state,
        "POST",
        &promote_uri(&f.staging.key, by_session.id),
        session_with_scope,
        Some(serde_json::json!({ "target_repository": f.release.key })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a session principal must not acquire promote capability through the scope: {}",
        body
    );
    assert!(
        !f.release.object_path(&by_session.storage_key).exists(),
        "a capability refusal must copy nothing"
    );

    f.cleanup().await;
}

/// The tenant gate is enforced INDEPENDENTLY of `is_admin`. This test is what
/// keeps the fixture's `grant_repo` call load-bearing: if the fixture
/// repositories were made public (the tempting way to "fix" a 403 while
/// writing these tests), the tenant check would stop being asked and this case
/// would fail. The second half asserts exactly that, so the shortcut cannot
/// pass unnoticed.
#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_admin_without_a_tenant_grant_is_refused() {
    let f = Fixture::new("tenant", true, false).await;
    f.revoke_tenant_grants().await;

    let uploaded = f
        .upload("cross-tenant.txt", b"another tenant's artifact")
        .await;
    let (status, body) = f.promote(uploaded.id).await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an admin-capable principal owning no tenant must be refused: {}",
        body
    );
    let message = body["message"].as_str().unwrap_or_default();
    assert!(
        message.contains(&f.staging.key) || message.contains(&f.release.key),
        "the refusal must name the repository whose tenant was refused, got: {}",
        message
    );
    assert!(
        !f.release.object_path(&uploaded.storage_key).exists(),
        "a tenant refusal must copy nothing"
    );

    // Public repositories carry no tenant boundary, so the same ungranted
    // principal succeeds once both ends are public. This is why the fixture
    // must keep its repositories private for the assertion above to mean
    // anything.
    f.set_public(&f.staging, true).await;
    f.set_public(&f.release, true).await;
    let (status, body) = f.promote(uploaded.id).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "public repositories carry no tenant boundary: {}",
        body
    );

    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_globally_scoped_principal_passes_the_tenant_gate() {
    let f = Fixture::new("tenant-glob", true, false).await;
    // Replace the fixture's global grant with a fresh one to make the subject
    // of this test explicit: a single NULL-scoped assignment, nothing else.
    f.revoke_tenant_grants().await;
    grant_repo(&f.pool, f.user, None).await;

    let uploaded = f
        .upload("global.txt", b"promoted under a global grant")
        .await;
    let (status, body) = f.promote(uploaded.id).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "a globally scoped grant must satisfy the tenant gate for BOTH repositories: {}",
        body
    );
    assert_eq!(body["promoted"], true, "body: {}", body);

    f.cleanup().await;
}

// ===========================================================================
// 5. Gate, policy, rule and approval ordering
// ===========================================================================

/// A repository-scoped scan policy that blocks unscanned artifacts. The
/// `block-unscanned` violation carries severity `high`, which escalates the
/// policy action to `Block`, so any artifact without a completed scan is
/// stopped by the policy evaluation.
async fn insert_blocking_scan_policy(pool: &PgPool, repo_id: Uuid) {
    sqlx::query(
        "INSERT INTO scan_policies (name, repository_id, max_severity, block_unscanned, is_enabled) \
         VALUES ('stgpromo-block-unscanned', $1, 'critical', true, true)",
    )
    .bind(repo_id)
    .execute(pool)
    .await
    .expect("insert scan policy");
}

/// A quality gate the fixture artifacts cannot satisfy (their health score is
/// seeded below `min_health_score`). `action` selects the block or warn branch.
async fn insert_quality_gate(pool: &PgPool, repo_id: Uuid, action: &str) -> String {
    let name = format!("stgpromo-gate-{}", &Uuid::new_v4().to_string()[..8]);
    sqlx::query(
        "INSERT INTO quality_gates (repository_id, name, min_health_score, required_checks, \
                                    enforce_on_promotion, enforce_on_download, action, is_enabled) \
         VALUES ($1, $2, 90, ARRAY[]::text[], true, false, $3, true)",
    )
    .bind(repo_id)
    .bind(&name)
    .bind(action)
    .execute(pool)
    .await
    .expect("insert quality gate");
    name
}

/// Seed the health score `evaluate_quality_gate` reads. Without this row the
/// evaluation returns `NotFound`, which the handler downgrades to
/// `NotEvaluated` — i.e. no gate at all.
async fn insert_health_score(pool: &PgPool, artifact_id: Uuid, score: i32) {
    sqlx::query(
        "INSERT INTO artifact_health_scores (artifact_id, health_score, health_grade, \
                                             total_issues, critical_issues, checks_passed, checks_total) \
         VALUES ($1, $2, 'D', 0, 0, 0, 0)",
    )
    .bind(artifact_id)
    .bind(score)
    .execute(pool)
    .await
    .expect("insert health score");
}

/// A promotion rule for the exact (source, target) pair that a freshly
/// uploaded artifact cannot satisfy.
async fn insert_failing_promotion_rule(pool: &PgPool, source_id: Uuid, target_id: Uuid) -> String {
    let name = format!("stgpromo-rule-{}", &Uuid::new_v4().to_string()[..8]);
    sqlx::query(
        "INSERT INTO promotion_rules (name, source_repo_id, target_repo_id, is_enabled, \
                                      require_signature, min_staging_hours, auto_promote) \
         VALUES ($1, $2, $3, true, false, 720, false)",
    )
    .bind(&name)
    .bind(source_id)
    .bind(target_id)
    .execute(pool)
    .await
    .expect("insert promotion rule");
    name
}

async fn set_require_approval(pool: &PgPool, repo_id: Uuid, required: bool) {
    sqlx::query("UPDATE repositories SET require_approval = $2 WHERE id = $1")
        .bind(repo_id)
        .bind(required)
        .execute(pool)
        .await
        .expect("set require_approval");
}

/// An APPROVED, unconsumed approval for the exact (artifact, source, target).
async fn insert_approved_approval(
    pool: &PgPool,
    artifact_id: Uuid,
    source_id: Uuid,
    target_id: Uuid,
    user_id: Uuid,
) {
    sqlx::query(
        "INSERT INTO promotion_approvals (artifact_id, source_repo_id, target_repo_id, \
                                          requested_by, requested_at, status, reviewed_by, reviewed_at) \
         VALUES ($1, $2, $3, $4, NOW(), 'approved', $4, NOW())",
    )
    .bind(artifact_id)
    .bind(source_id)
    .bind(target_id)
    .bind(user_id)
    .execute(pool)
    .await
    .expect("insert approval");
}

async fn unconsumed_approval_count(pool: &PgPool, artifact_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM promotion_approvals \
         WHERE artifact_id = $1 AND status = 'approved' AND consumed_at IS NULL",
    )
    .bind(artifact_id)
    .fetch_one(pool)
    .await
    .expect("count approvals")
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_policy_block_is_a_non_promoting_success_response() {
    let f = Fixture::new("pol-block", true, false).await;
    insert_blocking_scan_policy(&f.pool, f.staging.id).await;
    let uploaded = f.upload("unscanned.txt", b"never scanned").await;

    let (status, body) = f.promote(uploaded.id).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "a policy decision is an answer, not a failure to process: {}",
        body
    );
    assert_eq!(body["promoted"], false, "body: {}", body);
    assert!(
        body["promotion_id"].is_null(),
        "a blocked promotion carries no promotion identifier: {}",
        body
    );
    let violations = body["policy_violations"]
        .as_array()
        .unwrap_or_else(|| panic!("violations must be reported: {}", body));
    assert!(
        !violations.is_empty(),
        "the violations that caused the block must be reported: {}",
        body
    );
    assert!(
        !f.release.object_path(&uploaded.storage_key).exists(),
        "a blocked promotion must copy nothing"
    );

    let history = f.history().await;
    let promoted_entries = history["items"]
        .as_array()
        .map(|items| items.iter().filter(|e| e["status"] == "promoted").count())
        .unwrap_or(0);
    assert_eq!(
        promoted_entries, 0,
        "a blocked promotion must not record a promoted history entry: {}",
        history
    );

    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_promotion_rule_block_is_a_non_promoting_success_response() {
    let f = Fixture::new("rule-block", true, false).await;
    let rule_name = insert_failing_promotion_rule(&f.pool, f.staging.id, f.release.id).await;
    let uploaded = f.upload("too-fresh.txt", b"has not aged in staging").await;

    let (status, body) = f.promote(uploaded.id).await;

    assert_eq!(status, StatusCode::OK, "body: {}", body);
    assert_eq!(body["promoted"], false, "body: {}", body);
    let violations = body["policy_violations"]
        .as_array()
        .unwrap_or_else(|| panic!("violations must be reported: {}", body));
    assert!(
        violations
            .iter()
            .any(|v| v["rule"].as_str().is_some_and(|r| r.contains(&rule_name))),
        "the failing rule must be reported as a violation, got: {}",
        body
    );
    assert!(
        !f.release.object_path(&uploaded.storage_key).exists(),
        "a rule-blocked promotion must copy nothing"
    );

    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_warn_level_outcome_does_not_block() {
    let f = Fixture::new("warn", true, true).await;
    let gate_name = insert_quality_gate(&f.pool, f.staging.id, "warn").await;
    let content = b"warned but promoted";
    let uploaded = f.upload("warned.txt", content).await;
    insert_health_score(&f.pool, uploaded.id, 10).await;

    let (status, body) = f.promote(uploaded.id).await;

    assert_eq!(status, StatusCode::OK, "body: {}", body);
    assert_eq!(
        body["promoted"], true,
        "a warn-level gate must not block the promotion: {}",
        body
    );
    let violations = body["policy_violations"]
        .as_array()
        .unwrap_or_else(|| panic!("violations must be reported: {}", body));
    assert!(
        !violations.is_empty(),
        "warn-level violations must be reported alongside the successful result \
         (gate '{}'): {}",
        gate_name,
        body
    );
    assert_eq!(
        std::fs::read(f.release.object_path(&uploaded.storage_key)).expect("promoted object"),
        content,
        "the artifact must still be promoted"
    );

    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_blocking_quality_gate_refuses_with_conflict() {
    let f = Fixture::new("gate-block", true, true).await;
    let gate_name = insert_quality_gate(&f.pool, f.staging.id, "block").await;
    let uploaded = f.upload("gated.txt", b"below the health threshold").await;
    insert_health_score(&f.pool, uploaded.id, 10).await;

    let (status, body) = f.promote(uploaded.id).await;

    assert_eq!(status, StatusCode::CONFLICT, "body: {}", body);
    let message = body["message"].as_str().unwrap_or_default();
    assert!(
        message.contains(&gate_name),
        "the refusal must name the gate, got: {}",
        message
    );
    assert!(
        !f.release.object_path(&uploaded.storage_key).exists(),
        "a gate-blocked promotion must copy nothing"
    );

    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_gate_outcome_precedes_the_source_shape_refusal() {
    let pool = require_db_pool().await;
    // A VIRTUAL source would fail the source-shape check on its own.
    let source = create_repo(&pool, "virtual", "generic", "gate-shape-src").await;
    let release = create_repo(&pool, "local", "generic", "gate-shape-rel").await;
    let user = create_user(&pool, "gate-shape", true).await;
    grant_repo(&pool, user, None).await;
    let state = build_state(&pool, &source.storage_path.to_string_lossy(), true);

    let gate_name = insert_quality_gate(&pool, source.id, "block").await;
    let uploaded = upload_artifact(&pool, &source, "both-wrong.txt", b"gate and shape").await;
    insert_health_score(&pool, uploaded.id, 10).await;

    let (status, body) = send(
        &state,
        "POST",
        &promote_uri(&source.key, uploaded.id),
        principal(user, true),
        Some(serde_json::json!({ "target_repository": release.key })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "the gate block must take precedence over the source-shape refusal (400): {}",
        body
    );
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains(&gate_name),
        "the response must report the gate, not the shape: {}",
        body
    );

    cleanup(&pool, &[&source, &release], &[user]).await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_gate_outcome_precedes_the_approval_requirement() {
    let f = Fixture::new("gate-appr", true, true).await;
    set_require_approval(&f.pool, f.staging.id, true).await;
    let gate_name = insert_quality_gate(&f.pool, f.staging.id, "block").await;
    let uploaded = f.upload("gated-approval.txt", b"gate and approval").await;
    insert_health_score(&f.pool, uploaded.id, 10).await;

    // No approval exists either, so both gates would refuse with 409. The
    // message is what distinguishes which one answered.
    let (status, body) = f.promote(uploaded.id).await;

    assert_eq!(status, StatusCode::CONFLICT, "body: {}", body);
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains(&gate_name),
        "a gate-violating artifact must be reported as gate-blocked, not as awaiting \
         approval: {}",
        body
    );

    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_promotion_without_an_approval_is_refused() {
    let f = Fixture::new("appr-none", true, false).await;
    set_require_approval(&f.pool, f.staging.id, true).await;
    let uploaded = f.upload("unapproved.txt", b"nobody approved this").await;

    let (status, body) = f.promote(uploaded.id).await;

    assert_eq!(status, StatusCode::CONFLICT, "body: {}", body);
    assert!(
        !f.release.object_path(&uploaded.storage_key).exists(),
        "an unapproved promotion must copy nothing"
    );

    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_an_approval_is_spent_exactly_once() {
    let f = Fixture::new("appr-once", true, false).await;
    set_require_approval(&f.pool, f.staging.id, true).await;
    let uploaded = f
        .upload("approved-once.txt", b"one approval, two attempts")
        .await;
    insert_approved_approval(&f.pool, uploaded.id, f.staging.id, f.release.id, f.user).await;

    let (first_status, first_body) = f.promote(uploaded.id).await;
    assert_eq!(
        first_status,
        StatusCode::OK,
        "the first attempt consumes the approval: {}",
        first_body
    );
    assert_eq!(first_body["promoted"], true, "body: {}", first_body);

    let (second_status, second_body) = f.promote(uploaded.id).await;
    assert_eq!(
        second_status,
        StatusCode::CONFLICT,
        "the approval must not be spendable twice: {}",
        second_body
    );
    assert_eq!(
        unconsumed_approval_count(&f.pool, uploaded.id).await,
        0,
        "the approval must be marked consumed"
    );

    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_a_blocked_promotion_does_not_spend_the_approval() {
    let f = Fixture::new("appr-keep", true, false).await;
    set_require_approval(&f.pool, f.staging.id, true).await;
    let rule_name = insert_failing_promotion_rule(&f.pool, f.staging.id, f.release.id).await;
    let uploaded = f
        .upload("blocked-approved.txt", b"approved but rule-blocked")
        .await;
    insert_approved_approval(&f.pool, uploaded.id, f.staging.id, f.release.id, f.user).await;

    let (status, body) = f.promote(uploaded.id).await;
    assert_eq!(status, StatusCode::OK, "body: {}", body);
    assert_eq!(
        body["promoted"], false,
        "rule '{}' must block this promotion: {}",
        rule_name, body
    );

    assert_eq!(
        unconsumed_approval_count(&f.pool, uploaded.id).await,
        1,
        "a promotion rejected by a rule must leave the approval unconsumed and \
         available to a later attempt"
    );

    // Prove it is still usable: drop the rule and promote again.
    sqlx::query("DELETE FROM promotion_rules WHERE source_repo_id = $1")
        .bind(f.staging.id)
        .execute(&f.pool)
        .await
        .expect("drop the rule");
    let (status, body) = f.promote(uploaded.id).await;
    assert_eq!(status, StatusCode::OK, "body: {}", body);
    assert_eq!(
        body["promoted"], true,
        "the preserved approval must authorize the later attempt: {}",
        body
    );

    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_an_artifact_is_addressed_within_its_source_repository() {
    let f = Fixture::new("addr", true, false).await;

    // An artifact that exists, but in a different repository.
    let elsewhere = create_repo(&f.pool, "staging", "generic", "elsewhere").await;
    let foreign = upload_artifact(&f.pool, &elsewhere, "foreign.txt", b"not yours").await;
    let (status, body) = f.promote(foreign.id).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an artifact belonging to another repository must not be promotable through \
         this source: {}",
        body
    );

    // A deleted artifact.
    let deleted = f.upload("deleted.txt", b"soft deleted").await;
    sqlx::query("UPDATE artifacts SET is_deleted = true WHERE id = $1")
        .bind(deleted.id)
        .execute(&f.pool)
        .await
        .expect("soft delete");
    let (status, body) = f.promote(deleted.id).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {}", body);

    cleanup(&f.pool, &[&elsewhere], &[]).await;
    f.cleanup().await;
}

// ===========================================================================
// 6. Bulk promotion
// ===========================================================================

/// Mark an artifact as scanned so the `block_unscanned` policy lets it through.
/// Zero findings, so the CVE evaluation produces no violations either.
async fn insert_completed_scan(pool: &PgPool, artifact_id: Uuid, repo_id: Uuid) {
    sqlx::query(
        "INSERT INTO scan_results (artifact_id, repository_id, scan_type, status, \
                                   findings_count, completed_at) \
         VALUES ($1, $2, 'dependency', 'completed', 0, NOW())",
    )
    .bind(artifact_id)
    .bind(repo_id)
    .execute(pool)
    .await
    .expect("insert scan result");
}

/// Regression pin for the bulk bypass: `promote_artifacts_bulk` evaluated ONLY
/// `promotion_rules`, so an artifact the single-promote route blocks on policy
/// was promoted anyway — a one-element array was enough to skip the CVE/licence
/// policy and the quality gate.
#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_bulk_reports_mixed_outcomes_per_artifact() {
    let f = Fixture::new("bulk-mixed", true, false).await;
    insert_blocking_scan_policy(&f.pool, f.staging.id).await;

    let promotable = f.upload("scanned.txt", b"this one is vetted").await;
    insert_completed_scan(&f.pool, promotable.id, f.staging.id).await;
    let blocked = f.upload("unvetted.txt", b"this one is not").await;

    let (status, body) = f.promote_bulk(&[promotable.id, blocked.id]).await;

    assert_eq!(status, StatusCode::OK, "body: {}", body);
    assert_eq!(body["total"], 2, "body: {}", body);
    assert_eq!(
        body["promoted"], 1,
        "the policy-blocked artifact must NOT be promoted by the bulk route: {}",
        body
    );
    assert_eq!(body["failed"], 1, "body: {}", body);

    let results = body["results"]
        .as_array()
        .unwrap_or_else(|| panic!("per-artifact results must be reported: {}", body));
    assert_eq!(results.len(), 2, "one result per artifact: {}", body);
    let promoted_results: Vec<&Value> = results
        .iter()
        .filter(|r| r["promoted"] == serde_json::json!(true))
        .collect();
    assert_eq!(promoted_results.len(), 1, "results: {}", body);
    assert!(
        promoted_results[0]["source"]
            .as_str()
            .is_some_and(|s| s.contains("scanned.txt")),
        "the promoted result must be the vetted artifact: {}",
        body
    );

    assert!(
        f.release.object_path(&promotable.storage_key).exists(),
        "the promotable artifact must reach the target"
    );
    assert!(
        !f.release.object_path(&blocked.storage_key).exists(),
        "the policy-blocked artifact must not reach the target"
    );

    f.cleanup().await;
}

/// The bulk route must apply the quality gate per item, not skip it. Before the
/// fix it never called `evaluate_gate_once` at all.
#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_bulk_applies_the_quality_gate_per_item() {
    let f = Fixture::new("bulk-gate", true, true).await;
    let gate_name = insert_quality_gate(&f.pool, f.staging.id, "block").await;

    // Only the second artifact has a health score, so only it is gate-blocked;
    // the gate cannot evaluate the first (no score -> NotEvaluated) and it is
    // promoted. That asymmetry is what proves the gate runs PER ITEM.
    let ungated = f.upload("no-score.txt", b"gate cannot evaluate this").await;
    let gated = f.upload("low-score.txt", b"below the threshold").await;
    insert_health_score(&f.pool, gated.id, 10).await;

    let (status, body) = f.promote_bulk(&[ungated.id, gated.id]).await;

    assert_eq!(status, StatusCode::OK, "body: {}", body);
    assert_eq!(
        body["promoted"], 1,
        "the gate-blocked artifact must not be promoted: {}",
        body
    );
    assert_eq!(body["failed"], 1, "body: {}", body);

    let results = body["results"].as_array().expect("results");
    let failure = results
        .iter()
        .find(|r| r["promoted"] == serde_json::json!(false))
        .unwrap_or_else(|| panic!("a failed result must be present: {}", body));
    assert!(
        failure["message"]
            .as_str()
            .unwrap_or_default()
            .contains(&gate_name),
        "the failed item must name the gate that blocked it: {}",
        failure
    );
    assert!(
        !f.release.object_path(&gated.storage_key).exists(),
        "the gate-blocked artifact must not reach the target"
    );
    assert!(
        f.release.object_path(&ungated.storage_key).exists(),
        "a gate block must fail only that item, not the batch"
    );

    f.cleanup().await;
}

/// The bulk per-item success response must report warn-level violations, the
/// same way the single path does.
#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_bulk_success_reports_warn_level_violations() {
    let f = Fixture::new("bulk-warn", true, true).await;
    insert_quality_gate(&f.pool, f.staging.id, "warn").await;
    let uploaded = f.upload("bulk-warned.txt", b"warned but promoted").await;
    insert_health_score(&f.pool, uploaded.id, 10).await;

    let (status, body) = f.promote_bulk(&[uploaded.id]).await;

    assert_eq!(status, StatusCode::OK, "body: {}", body);
    assert_eq!(body["promoted"], 1, "a warn gate must not block: {}", body);

    let results = body["results"].as_array().expect("results");
    let violations = results[0]["policy_violations"]
        .as_array()
        .unwrap_or_else(|| panic!("violations must be reported: {}", body));
    assert!(
        !violations.is_empty(),
        "warn-level violations must survive into the bulk success result: {}",
        body
    );

    f.cleanup().await;
}

/// The bulk route must record the policy evaluation it actually ran in
/// `promotion_history.policy_result`, exactly as the single route does. Before
/// the fix it wrote a hardcoded `{"passed": true, "violations": []}` for every
/// bulk success, so the same artifact left a different audit record depending
/// on which route promoted it.
#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_bulk_records_the_policy_evaluation_in_history() {
    let f = Fixture::new("bulk-hist", true, false).await;
    insert_blocking_scan_policy(&f.pool, f.staging.id).await;

    let via_single = f.upload("single-hist.txt", b"promoted alone").await;
    insert_completed_scan(&f.pool, via_single.id, f.staging.id).await;
    let via_bulk = f.upload("bulk-hist.txt", b"promoted in a batch").await;
    insert_completed_scan(&f.pool, via_bulk.id, f.staging.id).await;

    let (status, body) = f.promote(via_single.id).await;
    assert_eq!(status, StatusCode::OK, "body: {}", body);
    assert_eq!(body["promoted"], true, "body: {}", body);
    let (status, body) = f.promote_bulk(&[via_bulk.id]).await;
    assert_eq!(status, StatusCode::OK, "body: {}", body);
    assert_eq!(body["promoted"], 1, "body: {}", body);

    let recorded = |artifact_id: Uuid| {
        let pool = f.pool.clone();
        async move {
            sqlx::query_scalar::<_, Value>(
                "SELECT policy_result FROM promotion_history WHERE artifact_id = $1",
            )
            .bind(artifact_id)
            .fetch_one(&pool)
            .await
            .expect("promotion_history row")
        }
    };
    let single_doc = recorded(via_single.id).await;
    let bulk_doc = recorded(via_bulk.id).await;

    assert_eq!(
        bulk_doc["action"], "allow",
        "bulk history must carry the evaluated action, not a placeholder: {}",
        bulk_doc
    );
    assert!(
        bulk_doc["cve_summary"].is_object(),
        "bulk history must carry the evaluated CVE summary: {}",
        bulk_doc
    );
    assert_eq!(
        bulk_doc, single_doc,
        "the two routes must record the same evaluation for equivalent artifacts"
    );

    f.cleanup().await;
}

// ===========================================================================
// 7. Refusal status codes match the published API description
// ===========================================================================

/// The status codes a promotion path documents, read out of the OpenAPI
/// document the service itself publishes. That document is what the SDKs
/// `artifact-keeper-web` and `artifact-keeper-cli` consume are generated from,
/// so a caller branching on a documented code must match what the service
/// really returns.
fn documented_status_codes(path: &str, method: &str) -> Vec<String> {
    use utoipa::OpenApi;

    let doc = promotion::PromotionApiDoc::openapi();
    let value = serde_json::to_value(&doc).expect("serialize the OpenAPI document");
    let operation = value
        .get("paths")
        .and_then(|p| p.get(path))
        .and_then(|p| p.get(method))
        .unwrap_or_else(|| panic!("no documented operation for {} {}", method, path));
    operation
        .get("responses")
        .and_then(|r| r.as_object())
        .map(|r| r.keys().cloned().collect())
        .unwrap_or_default()
}

/// A validation refusal must carry the status the published document names for
/// it. The annotations said `422` while `AppError::Validation` has always
/// mapped to `400`, so a client written against the spec never matched.
#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_validation_refusal_matches_its_published_status() {
    let documented = documented_status_codes(
        "/api/v1/promotion/repositories/{key}/artifacts/{artifact_id}/promote",
        "post",
    );

    // Three different validation refusals on the same endpoint: target shape,
    // package format, and the release-link mismatch.
    let f = Fixture::with_formats("doc-status", "maven", "npm", false, false).await;
    let other = create_repo(&f.pool, "staging", "generic", "doc-shape").await;
    let uploaded = f.upload("documented.jar", b"documented refusal").await;

    let format_mismatch = f.promote(uploaded.id).await;
    let wrong_shape = f
        .promote_with(
            uploaded.id,
            serde_json::json!({ "target_repository": other.key }),
        )
        .await;
    let no_target = f.promote_with(uploaded.id, serde_json::json!({})).await;

    for (label, (status, body)) in [
        ("format mismatch", format_mismatch),
        ("wrong target shape", wrong_shape),
        ("no target and no link", no_target),
    ] {
        assert!(
            documented.contains(&status.as_u16().to_string()),
            "the {} refusal returned {} but the published document lists only {:?} \
             for this endpoint; a client branching on the documented code would \
             never match. Body: {}",
            label,
            status.as_u16(),
            documented,
            body
        );
    }

    cleanup(&f.pool, &[&other], &[]).await;
    f.cleanup().await;
}
