//! Database connection pool setup.

use crate::error::Result;
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;

/// Create a new database connection pool
pub async fn create_pool(database_url: &str) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(20)
        .min_connections(5)
        .acquire_timeout(Duration::from_secs(30))
        .idle_timeout(Duration::from_secs(600))
        .connect(database_url)
        .await?;

    Ok(pool)
}
