//! Common test utilities for backend integration and handler tests
//!
//! This module provides shared infrastructure for testing:
//! - Test application setup with axum-test
//! - Database fixtures and cleanup
//! - Authentication test helpers

#![allow(dead_code)]
#![allow(unused_imports)]

pub mod fixtures;
pub mod sso_support;

use std::sync::Arc;

use axum::Router;
use sqlx::PgPool;
use uuid::Uuid;

use artifact_keeper_backend::config::Config;

/// Test context containing shared resources for tests
pub struct TestContext {
    pub pool: PgPool,
}

impl TestContext {
    /// Create a new test context with database connection
    pub async fn new() -> Self {
        let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgresql://registry:registry@localhost:5432/artifact_registry".to_string()
        });

        let pool = PgPool::connect(&database_url)
            .await
            .expect("Failed to connect to test database");

        Self { pool }
    }

    /// Get a reference to the database pool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

/// Connect to the Postgres instance the DB-gated (`#[ignore]`) integration
/// tests run against. Panics when `DATABASE_URL` is unset so a missing test
/// database fails loudly instead of testing nothing.
pub async fn require_db_pool() -> PgPool {
    let database_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for DB-gated tests");
    PgPool::connect(&database_url)
        .await
        .expect("failed to connect to the test database")
}

/// Build a `Config` for DB-gated tests. `Config::from_env()` requires
/// `DATABASE_URL` and `JWT_SECRET`; default the JWT secret when the test
/// runner didn't set one explicitly.
pub fn test_config_with_default_jwt() -> Arc<Config> {
    if std::env::var("JWT_SECRET").is_err() {
        std::env::set_var(
            "JWT_SECRET",
            "ak-integration-test-jwt-secret-not-for-prod-use-please",
        );
    }
    Arc::new(Config::from_env().expect("Config::from_env failed"))
}

/// Insert a freshly-minted, active local user with a unique name derived
/// from `prefix`. Returns the user_id.
pub async fn insert_active_user(pool: &PgPool, prefix: &str) -> Uuid {
    let id = Uuid::new_v4();
    let username = format!("{}-{}", prefix, &id.to_string()[..8]);
    sqlx::query(
        r#"
        INSERT INTO users (id, username, email, password_hash, is_admin, is_active, auth_provider)
        VALUES ($1, $2, $3, NULL, false, true, 'local')
        "#,
    )
    .bind(id)
    .bind(&username)
    .bind(format!("{}@test.local", username))
    .execute(pool)
    .await
    .expect("failed to insert user");
    id
}

/// Create a test application router for handler testing
/// This is a simplified version for unit tests that don't need full app state
pub fn create_test_router() -> Router {
    Router::new()
}

/// Helper to create an authenticated test request header
pub fn auth_header(token: &str) -> (String, String) {
    ("Authorization".to_string(), format!("Bearer {}", token))
}

/// Helper to create a basic auth header
pub fn basic_auth_header(username: &str, password: &str) -> (String, String) {
    use base64::Engine;
    let credentials = format!("{}:{}", username, password);
    let encoded = base64::engine::general_purpose::STANDARD.encode(credentials);
    ("Authorization".to_string(), format!("Basic {}", encoded))
}

/// Generate a unique test identifier
pub fn test_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("test_{}", timestamp)
}
