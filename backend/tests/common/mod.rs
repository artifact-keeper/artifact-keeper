//! Common test utilities for backend integration and handler tests
//!
//! This module provides shared infrastructure for testing:
//! - Test application setup with axum-test
//! - Database fixtures and cleanup
//! - Authentication test helpers

#![allow(dead_code)]
#![allow(unused_imports)]

pub mod fixtures;

use axum::Router;
use sqlx::PgPool;

/// Test context containing shared resources for tests
pub struct TestContext {
    pub pool: PgPool,
}

impl TestContext {
    /// Create a new test context with database connection
    pub async fn new() -> Self {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://registry:registry@localhost:5432/artifact_registry".to_string());

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
