//! Database connection pool setup.

use crate::config::Config;
use crate::error::Result;
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;

/// Create a new database connection pool using the connection pool settings
/// from [`Config`]. Pool sizing and timeouts are configurable via the
/// `DATABASE_MAX_CONNECTIONS`, `DATABASE_MIN_CONNECTIONS`,
/// `DATABASE_ACQUIRE_TIMEOUT_SECS`, `DATABASE_IDLE_TIMEOUT_SECS`, and
/// `DATABASE_MAX_LIFETIME_SECS` environment variables. See `.env.example`
/// for the default values.
pub async fn create_pool(config: &Config) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(config.database_max_connections)
        .min_connections(config.database_min_connections)
        .acquire_timeout(Duration::from_secs(config.database_acquire_timeout_secs))
        .idle_timeout(Duration::from_secs(config.database_idle_timeout_secs))
        .max_lifetime(Duration::from_secs(config.database_max_lifetime_secs))
        .connect(&config.database_url)
        .await?;

    Ok(pool)
}
