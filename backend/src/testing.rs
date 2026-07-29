//! Shared test-harness plumbing for the DB-backed test suites.
//!
//! This module is deliberately part of the always-compiled (non-`cfg(test)`)
//! surface: the DB connect helpers live both in the crate's own
//! `#[cfg(test)]` unit tests **and** in the integration tests under
//! `backend/tests/`, which compile against the library *without* `cfg(test)`
//! and therefore cannot see `#[cfg(test)]`-gated items. Keeping the shared
//! decision here lets every copy of `try_pool` route through one place.
//!
//! ## Why this exists (#2924)
//!
//! Historically each `try_pool` collapsed a database **connect failure** into
//! `None`, and DB-backed tests treat `None` as "no DB configured -> skip and
//! return green". That is correct for a developer running the suite locally
//! with no Postgres, but in CI — where a database is provisioned and the
//! DB-backed cases are the whole point — an unreachable or misconfigured
//! database would make every such test silently skip while the suite still
//! reported PASS ("fiction-green"), hiding real breakage from the release
//! gate.
//!
//! The fix distinguishes the two situations with an explicit signal
//! ([`REQUIRE_DB_ENV`]): when the database is *required* (CI sets it), a
//! missing `DATABASE_URL` or a connect failure PANICS loudly instead of
//! skipping; when it is not set (local dev), the historical skip behavior is
//! preserved.
#![allow(dead_code)]

use sqlx::PgPool;

/// Environment variable that marks the database as **required**. When set to a
/// truthy value, a missing `DATABASE_URL` or a connect failure becomes a hard
/// test failure instead of a silent skip. The CI DB-backed jobs set it so the
/// suite can no longer "fiction-green" against an unreachable database.
pub const REQUIRE_DB_ENV: &str = "AK_TESTS_REQUIRE_DB";

/// True when the harness must have a working database, i.e. [`REQUIRE_DB_ENV`]
/// is set to a truthy value (`1`/`true`/`yes`).
pub fn tests_require_db() -> bool {
    matches!(
        std::env::var(REQUIRE_DB_ENV)
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Pure skip-vs-fail decision, factored out so it can be unit-tested without
/// touching process-global env or panicking.
///
/// Returns `true` when the harness must FAIL LOUDLY (the database is required
/// but unavailable); `false` when it is fine to proceed or to skip cleanly.
pub fn must_fail_loud(db_available: bool, db_required: bool) -> bool {
    db_required && !db_available
}

/// Panic with a fiction-green diagnostic when the database is required but
/// unavailable; otherwise do nothing. `why` describes what was unavailable.
fn enforce_db_available(db_available: bool, why: &str) {
    if must_fail_loud(db_available, tests_require_db()) {
        panic!(
            "{REQUIRE_DB_ENV} is set (database REQUIRED) but {why}. Refusing to \
             silently skip DB-backed tests, which would report a false PASS \
             ('fiction-green'). Provide a reachable DATABASE_URL or unset \
             {REQUIRE_DB_ENV} for a DB-free local run. See issue #2924."
        );
    }
}

/// Resolve the test `DATABASE_URL`, honoring the require-DB signal.
///
/// * `Some(url)` when `DATABASE_URL` is set.
/// * `None` when it is unset **and** the DB is not required (legitimate local
///   skip).
/// * PANICS when it is unset **and** the DB *is* required ([`REQUIRE_DB_ENV`]).
pub fn require_db_url() -> Option<String> {
    let url = std::env::var("DATABASE_URL").ok();
    enforce_db_available(url.is_some(), "DATABASE_URL is unset");
    url
}

/// Turn a connect `Result` into the harness's skip-or-fail decision.
///
/// * `Some(value)` on success.
/// * `None` on failure when the DB is not required (legitimate local skip).
/// * PANICS on failure when the DB *is* required ([`REQUIRE_DB_ENV`]), surfacing
///   the underlying connect error instead of a false PASS.
pub fn on_connect_result<T>(result: Result<T, sqlx::Error>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(err) => {
            enforce_db_available(false, &format!("the database is unreachable: {err}"));
            None
        }
    }
}

/// Connect a small `PgPool` for a DB-backed test, honoring the require-DB
/// signal. This is the shared body every module-local `try_pool` delegates to.
///
/// Returns `None` (skip) only when no database is configured/reachable *and*
/// the DB is not required; a connect failure under [`REQUIRE_DB_ENV`] panics.
pub async fn try_pool_with(max_connections: u32) -> Option<PgPool> {
    let url = require_db_url()?;
    let pool = on_connect_result(
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(max_connections)
            // llvm-cov + nextest run DB-backed lib tests in parallel processes.
            // Keep each per-test pool small, but give Postgres pressure a chance
            // to clear instead of turning transient contention into PoolTimedOut.
            .acquire_timeout(std::time::Duration::from_secs(30))
            .connect(&url)
            .await,
    )?;
    ensure_download_event_dispatch(&url).await;
    Some(pool)
}

/// Start (once per test process) the bounded download-event dispatcher that
/// the production binary installs in `main.rs` (#2522), so DB-backed tests
/// asserting `download_statistics` / download-audit rows exercise the REAL
/// bounded path. An uninstalled dispatcher degrades to a silent drop by
/// design, which would otherwise fiction-green those assertions into
/// timeouts. Living here — the shared body every module-local `try_pool`
/// delegates to — is what guarantees every DB-backed test gets it.
///
/// The flush workers must outlive any single `#[tokio::test]` runtime: under
/// plain `cargo test` every test builds and drops its own runtime, which would
/// kill workers spawned on it and strand the process-global sender on a closed
/// channel. So the dispatcher runs on a dedicated background thread with its
/// own long-lived current-thread runtime and its own small pool. Under
/// `cargo nextest` (one process per test) each test process starts its own.
async fn ensure_download_event_dispatch(url: &str) {
    use std::sync::Once;
    static INIT: Once = Once::new();
    let url = url.to_string();
    INIT.call_once(move || {
        let _ = std::thread::Builder::new()
            .name("dl-event-dispatch-test".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        eprintln!("test download-event dispatcher: runtime build failed: {e}");
                        return;
                    }
                };
                rt.block_on(async move {
                    match sqlx::postgres::PgPoolOptions::new()
                        .max_connections(2)
                        .acquire_timeout(std::time::Duration::from_secs(30))
                        .connect(&url)
                        .await
                    {
                        Ok(pool) => {
                            crate::services::download_event_dispatch::start_download_event_dispatch(
                                pool,
                                tokio_util::sync::CancellationToken::new(),
                            );
                            // Keep the worker runtime alive for the process
                            // lifetime; the thread dies with the process.
                            std::future::pending::<()>().await;
                        }
                        Err(e) => {
                            eprintln!("test download-event dispatcher: DB connect failed: {e}");
                        }
                    }
                });
            });
    });
    // Wait (bounded) until the dispatcher handle is installed so a test's very
    // first `record_download` cannot race the background install and no-op.
    for _ in 0..500 {
        if crate::services::download_event_dispatch::dispatch_installed() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fiction_green_only_blocked_when_required_and_unavailable() {
        // Database present -> never fail loud, regardless of the flag.
        assert!(!must_fail_loud(true, true));
        assert!(!must_fail_loud(true, false));
        // Database absent but NOT required -> legitimate local skip.
        assert!(!must_fail_loud(false, false));
        // Database absent AND required -> the fiction-green case we must block.
        assert!(must_fail_loud(false, true));
    }
}
