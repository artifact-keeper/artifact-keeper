//! `artifact-keeper db-migrate`: apply the database schema migrations and exit.
//!
//! The server applies pending migrations before it binds `/readyz`, so a long
//! one (a `CREATE INDEX CONCURRENTLY` on a large `artifacts` table) runs inside
//! the startup probe budget and the pod can be killed halfway (#6194). This
//! subcommand runs the same ledger repairs and migrations as server startup,
//! so a deployment can run it as a separate step (a Helm pre-upgrade Job) and
//! start the server with `SKIP_MIGRATIONS=true`.
//!
//! Named `db-migrate` because `migrate` is the Artifactory import
//! ([`crate::cli::migrate`]).
//!
//! Reads only `DATABASE_URL` (or `DATABASE_URL_FILE`). Exits 0 when the schema
//! is up to date, 1 otherwise.

use crate::config::{database_tcp_keepalives_from_env, secret_or_env, Config};
use crate::error::{AppError, Result};

/// The argument that selects this subcommand: `artifact-keeper db-migrate`.
pub const SUBCOMMAND: &str = "db-migrate";

/// Whether the process arguments (`argv[0]` included) ask for this subcommand.
pub fn requested(args: &[String]) -> bool {
    args.get(1).map(String::as_str) == Some(SUBCOMMAND)
}

/// The pool settings for `db-migrate`: two connections, and the server's
/// startup connect retry and TCP keepalives (#4549) through
/// [`crate::db::create_pool`]. The migration session holds the migration lock,
/// so a Job pod that is killed must not leave it behind for the kernel's
/// two-hour keepalive.
fn pool_config(database_url: &str, tcp_keepalives: bool) -> Config {
    Config {
        database_url: database_url.to_owned(),
        database_max_connections: 2,
        database_min_connections: 0,
        database_tcp_keepalives: tcp_keepalives,
        ..Config::default()
    }
}

/// Connect to `database_url` and bring its schema up to date.
pub async fn run(database_url: &str) -> Result<()> {
    let config = pool_config(database_url, database_tcp_keepalives_from_env());
    let pool = crate::db::create_pool(&config).await?;
    let outcome = crate::migration_repair::apply_schema_migrations(&pool).await;
    pool.close().await;
    outcome
}

/// The subcommand's entrypoint, returns the process exit status.
pub fn main() -> i32 {
    // Same as the server: rustls needs an explicit provider for a TLS
    // DATABASE_URL because more than one is compiled in.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let _otel_guard = crate::telemetry::init_tracing(None, "artifact-keeper");
    exit_status(run_blocking(secret_or_env("DATABASE_URL")))
}

/// [`run`] on its own runtime, for the `DATABASE_URL` lookup result.
fn run_blocking(database_url: std::result::Result<Option<String>, String>) -> Result<()> {
    let url = database_url
        .map_err(AppError::Config)?
        .ok_or_else(|| AppError::Config("DATABASE_URL not set".into()))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| AppError::Internal(format!("tokio runtime: {e}")))?;
    tracing::info!("Running database migrations...");
    runtime.block_on(run(&url))
}

fn exit_status(outcome: Result<()>) -> i32 {
    match outcome {
        Ok(()) => {
            tracing::info!("Database migrations complete");
            0
        }
        Err(e) => {
            tracing::error!(error = %e, "Database migrations failed");
            1
        }
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn requested_only_for_db_migrate() {
        assert!(requested(&args(&["artifact-keeper", "db-migrate"])));
        assert!(!requested(&args(&["artifact-keeper", "migrate"])));
        assert!(!requested(&args(&["artifact-keeper", "healthcheck"])));
        assert!(!requested(&args(&["artifact-keeper"])));
        assert!(!requested(&args(&["db-migrate"])));
    }

    #[test]
    fn exit_status_is_zero_only_on_success() {
        assert_eq!(exit_status(Ok(())), 0);
        assert_eq!(exit_status(Err(AppError::Config("x".into()))), 1);
    }

    #[test]
    fn run_blocking_needs_a_database_url() {
        assert!(run_blocking(Ok(None)).is_err());
        assert!(run_blocking(Err("DATABASE_URL_FILE unreadable".into())).is_err());
        assert!(run_blocking(Ok(Some("not a url".into()))).is_err());
    }

    #[test]
    fn pool_config_keeps_two_connections_and_the_keepalive_choice() {
        let on = pool_config("postgres://u:p@db/ak", true);
        assert_eq!(on.database_url, "postgres://u:p@db/ak");
        assert_eq!(on.database_max_connections, 2);
        assert_eq!(on.database_min_connections, 0);
        assert!(on.database_tcp_keepalives);
        assert!(!pool_config("postgres://u:p@db/ak", false).database_tcp_keepalives);
    }

    #[tokio::test]
    async fn run_rejects_an_unparseable_url() {
        assert!(run("not a url").await.is_err());
    }
}
