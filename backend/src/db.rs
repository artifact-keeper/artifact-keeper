//! Database connection pool setup.

use crate::config::Config;
use crate::error::Result;
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;

/// Connections idle longer than this run a full `SELECT 1` probe before being
/// returned by the pool. Short-idle acquires skip the probe to keep the hot
/// path free of an extra round trip.
const IDLE_LIVENESS_THRESHOLD: Duration = Duration::from_secs(30);

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
        .before_acquire(|conn, meta| {
            Box::pin(async move {
                // sqlx's default `test_before_acquire` only sends a protocol
                // PING, which can succeed on a TCP socket that has been
                // silently broken by an upstream event (CNI flow reflow,
                // NAT rotation, brief Postgres unavailability). When that
                // happens, the next real query fails with an IO error and
                // the pool keeps handing back the same dead connection,
                // turning a transient glitch into a permanent outage that
                // only a pod restart fixes. Issue #1877.
                //
                // For connections that have actually been idle, run a real
                // query so a stale socket is detected here and the
                // connection is evicted by sqlx before any caller sees it.
                if meta.idle_for >= IDLE_LIVENESS_THRESHOLD {
                    sqlx::query("SELECT 1").execute(&mut *conn).await?;
                }
                Ok(true)
            })
        })
        .connect(&config.database_url)
        .await?;

    Ok(pool)
}
