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
    // Fail-fast reachability probe (#2986). Two hang shapes hid here:
    //
    // * `PgPoolOptions::connect` RETRIES failed connects with backoff until
    //   `acquire_timeout`, so an unreachable URL burned the full 30s budget
    //   in every DB-gated test — serialized through the module `*_serial_lock`
    //   guards, that reads as an indefinite hang of the whole suite.
    // * A listener that accepts TCP but never completes the Postgres
    //   handshake (e.g. a dead container's still-forwarded port) is not
    //   bounded by `acquire_timeout` at all and parked the await forever.
    //
    // A single raw connect attempt fails in microseconds on refusal and is
    // hard-bounded against stalled handshakes; only when it succeeds do we
    // pay for building the real pool.
    match bounded_connect(&url).await {
        Ok(conn) => {
            use sqlx::Connection;
            let _ = conn.close().await;
        }
        Err(err) => return on_connect_result(Err(err)),
    }
    // The outer timeout keeps the pool build itself hang-proof even if the
    // database degrades between the probe and this connect.
    let connect = tokio::time::timeout(
        std::time::Duration::from_secs(35),
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(max_connections)
            // llvm-cov + nextest run DB-backed lib tests in parallel processes.
            // Keep each per-test pool small, but give Postgres pressure a chance
            // to clear instead of turning transient contention into PoolTimedOut.
            .acquire_timeout(std::time::Duration::from_secs(30))
            .connect(&url),
    )
    .await
    .unwrap_or(Err(sqlx::Error::PoolTimedOut));
    let pool = on_connect_result(connect)?;
    ensure_download_event_dispatch(&url).await;
    Some(pool)
}

/// Bound for any single raw connect attempt. Generous for a healthy (even
/// heavily loaded) local/CI Postgres answering a TCP + auth handshake, while
/// keeping an unreachable database from stalling a test for long.
const CONNECT_ATTEMPT_BOUND: std::time::Duration = std::time::Duration::from_secs(10);

/// `PgConnection::connect` with a hard client-side deadline (#2986).
///
/// Unlike the pool path this makes exactly ONE attempt, so refusal fails in
/// microseconds, and the deadline covers the case `acquire_timeout` cannot:
/// a listener that accepts TCP but never speaks the Postgres protocol. An
/// expired deadline surfaces as [`sqlx::Error::PoolTimedOut`] so callers
/// route it through the same skip-or-fail decision as any connect error.
pub async fn bounded_connect(url: &str) -> Result<sqlx::PgConnection, sqlx::Error> {
    bounded_connect_with(url, CONNECT_ATTEMPT_BOUND).await
}

/// [`bounded_connect`] with an explicit deadline, factored out so the
/// regression test can exercise the bound without waiting out the real one.
async fn bounded_connect_with(
    url: &str,
    bound: std::time::Duration,
) -> Result<sqlx::PgConnection, sqlx::Error> {
    use sqlx::Connection;
    tokio::time::timeout(bound, sqlx::PgConnection::connect(url))
        .await
        .unwrap_or(Err(sqlx::Error::PoolTimedOut))
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

/// A database created for one test and dropped when this guard goes away.
///
/// The shared `DATABASE_URL` database is fine for tests that only touch rows
/// they created, but a few exercise code that reasons about the *whole*
/// table -- `provision_admin_user` picks any local admin with `LIMIT 1` -- and
/// those cannot be made order-independent on a database hundreds of other
/// tests write to (#3796). This creates `ak_iso_<random>` next to the shared
/// database, runs [`crate::MIGRATOR`] on it, and hands back a pool. Skips
/// (or fails loud under `AK_TESTS_REQUIRE_DB`) exactly like [`try_pool_with`].
pub struct IsolatedDb {
    pub pool: PgPool,
    pub name: String,
    admin_url: String,
}

impl std::ops::Deref for IsolatedDb {
    type Target = PgPool;
    fn deref(&self) -> &PgPool {
        &self.pool
    }
}

impl Drop for IsolatedDb {
    fn drop(&mut self) {
        // Drop the database from a dedicated thread with its own runtime and
        // wait for it, so it also happens when the test body panicked and a
        // failed assertion cannot leak an ak_iso_* database into the shared
        // server. The pool is deliberately NOT closed here: `Pool::close`
        // waits on the pool's background task, which lives on the test's
        // runtime -- the very runtime this Drop is blocking -- and deadlocks.
        // `DROP DATABASE ... WITH (FORCE)` terminates the pool's sessions
        // server-side instead, and the pool field is released right after.
        let admin_url = self.admin_url.clone();
        let name = self.name.clone();
        let label = self.name.clone();
        let done = std::thread::Builder::new()
            .name("ak-iso-db-drop".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        eprintln!("isolated test database {name}: runtime for drop failed: {e}");
                        return;
                    }
                };
                let for_timeout_msg = name.clone();
                let outcome = rt.block_on(async move {
                    tokio::time::timeout(std::time::Duration::from_secs(15), async move {
                        match bounded_connect(&admin_url).await {
                            Ok(mut conn) => {
                                if let Err(e) = sqlx::query(sqlx::AssertSqlSafe(format!(
                                    "DROP DATABASE \"{name}\" WITH (FORCE)"
                                )))
                                .execute(&mut conn)
                                .await
                                {
                                    eprintln!("isolated test database {name}: DROP failed: {e}");
                                }
                            }
                            Err(e) => eprintln!(
                                "isolated test database {name}: admin connect failed: {e}"
                            ),
                        }
                    })
                    .await
                });
                if outcome.is_err() {
                    eprintln!("isolated test database {for_timeout_msg}: drop timed out");
                }
            });
        match done {
            Ok(h) => {
                if let Err(payload) = h.join() {
                    let msg = payload
                        .downcast_ref::<String>()
                        .cloned()
                        .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                        .unwrap_or_else(|| "non-string panic".into());
                    eprintln!("isolated test database {label}: drop thread panicked: {msg}");
                }
            }
            Err(e) => eprintln!("isolated test database {label}: drop thread failed: {e}"),
        }
    }
}

/// See [`IsolatedDb`].
pub async fn try_isolated_pool() -> Option<IsolatedDb> {
    let admin_url = require_db_url()?;
    let mut admin = on_connect_result(bounded_connect(&admin_url).await)?;
    let name = format!("ak_iso_{}", uuid::Uuid::new_v4().simple());
    // CREATE DATABASE cannot run inside a transaction; a plain connection is
    // autocommit, which is what we have here.
    on_connect_result(
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE \"{name}\"")))
            .execute(&mut admin)
            .await,
    )?;
    let mut iso_url = match url::Url::parse(&admin_url) {
        Ok(u) => u,
        Err(_) => return None,
    };
    iso_url.set_path(&format!("/{name}"));
    let pool = on_connect_result(
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(3)
            .acquire_timeout(std::time::Duration::from_secs(30))
            .connect(iso_url.as_str())
            .await,
    )?;
    if let Err(e) = crate::MIGRATOR.run(&pool).await {
        panic!("migrating isolated test database {name}: {e}");
    }
    Some(IsolatedDb {
        pool,
        name,
        admin_url,
    })
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

    /// Regression test for the #2986 hang: a listener that ACCEPTS the TCP
    /// connection but never speaks the Postgres protocol must yield a bounded
    /// connect error, not park the caller forever. Before the fix, the
    /// `*_serial_lock` guards issued a raw un-timed `PgConnection::connect`,
    /// so this exact shape (a dead container's still-forwarded port, a
    /// wedged proxy) hung the storage-GC / scanner test modules — and every
    /// test queued behind their module serial locks — indefinitely.
    #[tokio::test]
    async fn bounded_connect_fails_instead_of_hanging_on_silent_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind silent listener");
        let addr = listener.local_addr().expect("local addr");
        // Accept and HOLD sockets without ever responding, so the client is
        // neither refused nor answered — the pre-fix forever-park shape.
        let _server = tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                if let Ok((socket, _)) = listener.accept().await {
                    held.push(socket);
                }
            }
        });
        let url = format!("postgres://u:p@{addr}/db");
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            bounded_connect_with(&url, std::time::Duration::from_millis(500)),
        )
        .await
        .expect("bounded_connect must return well before the outer 10s budget");
        assert!(
            result.is_err(),
            "a silent listener must surface a connect error, not a connection"
        );
    }
}
