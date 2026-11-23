//! Retry a read once when its database connection was lost (#5941).
//!
//! A PostgreSQL switchover or failover (CloudNativePG, Patroni, a managed
//! service's maintenance) terminates every pooled connection, and the new
//! primary usually accepts connections a few seconds later. Every request
//! whose statement was on one of those connections failed with a 5xx,
//! including `GET` and `HEAD` downloads, metadata, index and search lookups,
//! so a package client failed its build where the same request a moment
//! later would have worked.
//!
//! This layer replays such a request exactly once, after a short jittered
//! pause, when ALL of these hold:
//!
//! * the method is `GET` or `HEAD` and the request carries no body, so the
//!   whole request can be rebuilt from its head;
//! * the path is not one whose `GET` does work by design
//!   ([`is_never_replayed_path`]: the SSO and OAuth callbacks, which consume a
//!   one-time state and an IdP code and create the user and session, the
//!   rest of `/api/v1/auth/`, and the OCI token exchange);
//! * **nothing was written** while it ran. A `GET` is not the same as "no
//!   writes": a proxy repository fills its cache on a download, a download
//!   records a counter, a callback deletes its login state. Every statement
//!   sqlx runs reports itself as a `sqlx::query` event, and
//!   [`WriteObserver`], wrapped around the process's root log filter, reads
//!   those events while a request runs under this layer: any statement that
//!   is not a plain read (`BEGIN`, `INSERT`, `UPDATE`, `DELETE`, a `WITH`
//!   that modifies data, `SELECT ... FOR UPDATE`, `nextval`, DDL, `SET`,
//!   ...) marks the request as having written, including the statement that
//!   failed, since it may have committed before the connection dropped. The
//!   download-event queue and the proxy upstream fetch also mark it
//!   explicitly ([`note_write`]). The scope is a task-local, so a statement
//!   run by a task the request spawns is NOT seen: a request path that spawns
//!   a write which must not run twice uses [`spawn_write`], and a spawned
//!   write left untracked must be safe to repeat (the debounced
//!   `api_tokens.last_used_at` update is; see ARCHITECTURE.md, "Invariants").
//!   Replays are only ever made once
//!   [`prove_write_detection`] has shown, at startup and through the
//!   process's real subscriber, that a write statement is seen; otherwise
//!   the layer stays off with a WARN;
//! * the response is a 5xx produced from the error, so no success status and
//!   no body has gone out. A download that fails after its body started
//!   streaming is already committed to a 200 and is never replayed;
//! * a database error on the request was classified as a lost connection
//!   ([`crate::error::AppError::is_transient_connection_error`]): a socket
//!   error, SQLSTATE class 08, 57P01/57P02/57P03, or 25006 after a failover.
//!   Query errors, constraint violations, a statement or lock timeout on a
//!   live connection and pool exhaustion are not retried.
//!
//! The lost-connection marker is set from
//! [`crate::error::AppError::is_db_unavailable`], the one predicate every
//! error path (the generic JSON envelope, the format envelopes through
//! `db_status`, the auth middleware) consults before answering, so no handler
//! needs to opt in. The failed connection is not reused: sqlx tests a
//! connection when it is returned and closes it instead when it is broken,
//! and the pool's idle-liveness probe (`before_acquire`, #1877) catches idle
//! connections terminated at the same moment. A replay that still meets a
//! dead connection fails like any request; it is never replayed again.
//!
//! Each replay is counted in `ak_db_read_retries_total{outcome}`
//! (`recovered` when the replay answered below 500, `failed` otherwise) and
//! logged at `WARN`, so a database that keeps dropping connections is not
//! hidden behind successful retries. `DATABASE_READ_RETRY=false` turns the
//! layer off.

use axum::{
    body::Body,
    extract::Request,
    http::Method,
    middleware::Next,
    response::{IntoResponse, Response},
};
use http_body::Body as _;
use metrics::counter;
use std::any::TypeId;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::field::{Field, Visit};
use tracing::subscriber::Interest;
use tracing::{Event, Level, Metadata, Subscriber};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::{Context, Layer};

/// Environment variable that turns the retry off (`false`, `0`, `no`, `off`).
pub const ENV_VAR: &str = "DATABASE_READ_RETRY";

/// Counter of replays, labelled `outcome="recovered"|"failed"`.
pub const RETRIES_METRIC: &str = "ak_db_read_retries_total";

/// The replay waits between these bounds (milliseconds, jittered) so the
/// requests one failover broke do not all reconnect in the same instant.
const RETRY_DELAY_MIN_MS: u64 = 250;
const RETRY_DELAY_MAX_MS: u64 = 500;

/// The tracing target sqlx reports every statement on.
const SQLX_QUERY_TARGET: &str = "sqlx::query";

/// What one request under [`db_read_retry`] did to the database.
#[derive(Default)]
struct RequestDb {
    /// A database error on this request was a lost connection.
    lost: AtomicBool,
    /// This request ran (or started) something other than a plain read.
    wrote: AtomicBool,
}

tokio::task_local! {
    static REQUEST_DB: Arc<RequestDb>;
}

/// Set only by a successful [`prove_write_detection`]: a write statement run
/// inside a request scope was seen through the process's real subscriber.
/// Until then (or if it failed) nothing is replayed.
static WRITE_DETECTION_PROVEN: AtomicBool = AtomicBool::new(false);

/// Whether the retry is on: everything except an explicit off value.
pub fn enabled_from_env() -> bool {
    parse_enabled(std::env::var(ENV_VAR).ok().as_deref())
}

fn parse_enabled(value: Option<&str>) -> bool {
    !matches!(
        value.map(|v| v.trim().to_ascii_lowercase()).as_deref(),
        Some("false" | "0" | "no" | "off")
    )
}

fn current() -> Option<Arc<RequestDb>> {
    REQUEST_DB.try_with(Arc::clone).ok()
}

/// Whether the current task runs a request under [`db_read_retry`] that has
/// not written yet: only then is a statement worth inspecting. Once a
/// request has written, the verdict cannot change, so sqlx is no longer
/// asked to render its later statements. No allocation, no reference count.
fn observing() -> bool {
    REQUEST_DB
        .try_with(|db| !db.wrote.load(Ordering::Relaxed))
        .unwrap_or(false)
}

/// Note that the current request lost its database connection. A no-op
/// outside a request that runs under [`db_read_retry`].
pub(crate) fn note_transient_connection_error() {
    if let Some(db) = current() {
        db.lost.store(true, Ordering::Relaxed);
    }
}

/// Note that the current request did something that must not run twice (a
/// queued download counter, an upstream cache fill). A no-op outside a
/// request that runs under [`db_read_retry`].
pub(crate) fn note_write() {
    if let Some(db) = current() {
        db.wrote.store(true, Ordering::Relaxed);
    }
}

/// Spawn `task`, a database write started by the current request, and count
/// the request as having written, so it is never replayed. A task spawned
/// with plain `tokio::spawn` runs outside the request's scope and its
/// statements are not seen by the [`WriteObserver`]; use this for any
/// spawned write that must not run twice. Outside a request under
/// [`db_read_retry`] it is `tokio::spawn`.
pub fn spawn_write<F>(task: F) -> tokio::task::JoinHandle<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    note_write();
    tokio::spawn(task)
}

/// SQLSTATEs that mean the session itself is gone or unusable, not that the
/// statement was wrong: class 08 (connection exception), 57P01
/// (admin_shutdown), 57P02 (crash_shutdown), 57P03 (cannot_connect_now) and
/// 25006 (read_only_sql_transaction: a failed-over primary that is now a
/// standby).
pub(crate) fn is_transient_sqlstate(code: &str) -> bool {
    code.starts_with("08") || matches!(code, "57P01" | "57P02" | "57P03" | "25006")
}

/// The rendered forms of those failures, for the many call sites that wrap a
/// sqlx error as `AppError::Database(e.to_string())` and so drop the
/// variant and the SQLSTATE. Every marker is PostgreSQL's or sqlx's own
/// wording for a database connection, so an upstream HTTP error that says
/// "connection refused" is never taken for one.
pub(crate) fn is_transient_connection_message(msg: &str) -> bool {
    const MARKERS: &[&str] = &[
        // sqlx::Error::Io: reset, refused, broken pipe, unexpected EOF.
        "error communicating with database",
        // 57P01 / 57P02: the server ended the session.
        "terminating connection due to administrator command",
        "terminating connection because of crash of another server process",
        // 57P03.
        "the database system is starting up",
        "the database system is shutting down",
        "the database system is in recovery mode",
        "the database system is not yet accepting connections",
        // 25006 after a failover.
        "in a read-only transaction",
    ];
    let lower = msg.to_ascii_lowercase();
    MARKERS.iter().any(|m| lower.contains(m))
}

/// Paths whose `GET` does work by design and is never replayed, whatever
/// the write observer saw: the SSO/OAuth callbacks consume a one-time login
/// state and an IdP code and create the user and the session; the rest of
/// `/api/v1/auth/` and the OCI token exchange mint credentials.
pub(crate) fn is_never_replayed_path(path: &str) -> bool {
    path.starts_with("/api/v1/auth/")
        || path == "/v2/token"
        || path.split('/').any(|segment| segment == "callback")
}

/// Whether a statement is anything other than a plain read. `text` is the
/// statement as sqlx reports it (its `db.statement`, or the `summary` for a
/// short one). Conservative: an unrecognised leading keyword counts as a
/// write, and so does `BEGIN`, since the transaction exists to write.
///
/// It runs on every statement of a request under the layer, so it neither
/// allocates nor copies: it walks the bytes once and compares words in
/// place, ignoring ASCII case, and only a word of a modifier's length is
/// compared at all. Most statements are decided by their first word; only a
/// `SELECT`-like one is scanned on for a modifying word.
pub(crate) fn is_write_statement(text: &str) -> bool {
    let mut words = SqlWords {
        bytes: text.as_bytes(),
        pos: 0,
    };
    let Some(first) = words.next() else {
        return false;
    };
    let first_is = |k: &[u8]| first.eq_ignore_ascii_case(k);
    if first_is(b"select")
        || first_is(b"with")
        || first_is(b"values")
        || first_is(b"table")
        || first_is(b"show")
    {
        words.any(is_modifier)
    } else if first_is(b"explain") {
        words.any(|w| w.eq_ignore_ascii_case(b"analyze") || w.eq_ignore_ascii_case(b"analyse"))
    } else {
        // Ending a transaction writes nothing of its own; the BEGIN (and the
        // statements in it) already decided.
        !(first_is(b"commit") || first_is(b"rollback") || first_is(b"end"))
    }
}

/// A word that makes a `SELECT`-like statement a write.
fn is_modifier(word: &[u8]) -> bool {
    let is = |k: &[u8]| word.eq_ignore_ascii_case(k);
    match word.len() {
        4 => is(b"into"),
        5 => is(b"merge") || is(b"share"),
        6 => is(b"insert") || is(b"update") || is(b"delete") || is(b"setval"),
        7 => is(b"nextval"),
        8 => is(b"truncate"),
        _ => false,
    }
}

/// The words of a statement: runs of ASCII letters, digits and `_`, borrowed
/// from it. Any other byte, including every byte of a non-ASCII character,
/// separates words.
struct SqlWords<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for SqlWords<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let rest = self.bytes.get(self.pos..)?;
        let start = self.pos + rest.iter().position(|&b| WORD_BYTE[b as usize])?;
        let len = self.bytes[start..]
            .iter()
            .position(|&b| !WORD_BYTE[b as usize])
            .unwrap_or(self.bytes.len() - start);
        self.pos = start + len;
        Some(&self.bytes[start..self.pos])
    }
}

/// The bytes a word is made of: ASCII letters, digits and `_`.
const WORD_BYTE: [bool; 256] = {
    let mut table = [false; 256];
    let mut i = 0;
    while i < 256 {
        let b = i as u8;
        table[i] = b.is_ascii_alphanumeric() || b == b'_';
        i += 1;
    }
    table
};

/// Classifies a `sqlx::query` event from its fields, in place: sqlx records
/// `summary` (the first words) and then `db.statement` (the whole statement,
/// empty when the summary is all of it) as `&str`, which are inspected
/// without being copied. A summary that already reads as a write decides,
/// and the statement is not scanned.
#[derive(Default)]
struct StatementVisitor {
    summary: Option<bool>,
    statement: Option<bool>,
}

impl StatementVisitor {
    fn wrote(&self) -> bool {
        self.statement.or(self.summary).unwrap_or(false)
    }
}

impl Visit for StatementVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "summary" => self.summary = Some(is_write_statement(value)),
            "db.statement" if self.summary != Some(true) && !value.trim().is_empty() => {
                self.statement = Some(is_write_statement(value));
            }
            _ => {}
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        // Not how sqlx records these fields; kept so a change there cannot
        // turn a write into a read unnoticed.
        if matches!(field.name(), "summary" | "db.statement") {
            let text = format!("{value:?}");
            self.record_str(field, text.trim_matches('"'));
        }
    }
}

fn is_sqlx_statement(metadata: &Metadata<'_>) -> bool {
    metadata.target() == SQLX_QUERY_TARGET && *metadata.level() <= Level::DEBUG
}

/// Wraps the process's root log filter (`RUST_LOG`) so that, while a request
/// runs under [`db_read_retry`], sqlx's per-statement events are inspected
/// for writes, whatever `RUST_LOG` says. What reaches the log layers is
/// unchanged: after inspection an event is passed on only if the wrapped
/// filter enables it. Outside such a request the wrapper adds one
/// target comparison and a task-local lookup per sqlx statement.
///
/// With the retry off (`DATABASE_READ_RETRY=false`) it is inert: every call
/// goes straight to the wrapped filter, so callsite interest is cached as
/// before and nothing is inspected or looked up per statement.
pub struct WriteObserver<F> {
    inner: F,
    active: bool,
}

/// Wrap `inner` (the root filter) in a [`WriteObserver`], active unless
/// `DATABASE_READ_RETRY` turns the retry off. Whether writes are then
/// actually seen is established by [`prove_write_detection`].
pub fn observe_writes<F>(inner: F) -> WriteObserver<F> {
    observe_writes_if(inner, enabled_from_env())
}

/// [`observe_writes`] with the retry setting given.
pub fn observe_writes_if<F>(inner: F, active: bool) -> WriteObserver<F> {
    WriteObserver { inner, active }
}

/// A layer that does nothing, behind a per-layer filter that enables sqlx's
/// statement events inside a retry scope whatever `RUST_LOG` says. A
/// subscriber with per-layer filters (the OTLP path) answers
/// `tracing::enabled!` from those filters, so without one that wants the
/// statement events sqlx would not emit them at `RUST_LOG=info`, and the
/// [`WriteObserver`] would see nothing. It records nothing itself: the
/// events still stop at the [`WriteObserver`] unless `RUST_LOG` enables them.
///
/// `active: false` (the retry is off) makes it want nothing at all.
pub fn statement_interest_layer<S>(active: bool) -> impl Layer<S> + Send + Sync
where
    S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    struct Noop;
    impl<S: Subscriber> Layer<S> for Noop {}
    let filter = tracing_subscriber::filter::DynFilterFn::new(
        |metadata: &Metadata<'_>, _cx: &Context<'_, S>| is_sqlx_statement(metadata) && observing(),
    )
    .with_callsite_filter(move |metadata| {
        if active && is_sqlx_statement(metadata) {
            Interest::sometimes()
        } else {
            Interest::never()
        }
    })
    .with_max_level_hint(LevelFilter::DEBUG);
    Noop.with_filter(filter)
}

/// Startup self-test (#5941): inside a request scope, run a harmless
/// statement the observer must classify as a write (a transaction that sets
/// a local and rolls back) through the process's real subscriber, and check
/// it was seen. Only then may [`db_read_retry`] replay anything; otherwise
/// the retry stays off for the life of the process with a WARN. Returns
/// whether detection works.
pub async fn prove_write_detection(pool: &sqlx::PgPool) -> bool {
    let db = Arc::new(RequestDb::default());
    let ran = REQUEST_DB
        .scope(db.clone(), async {
            let mut tx = pool.begin().await.ok()?;
            sqlx::query("SET LOCAL statement_timeout = 0")
                .execute(&mut *tx)
                .await
                .ok()?;
            tx.rollback().await.ok()
        })
        .await
        .is_some();
    let proven = ran && db.wrote.load(Ordering::Relaxed);
    WRITE_DETECTION_PROVEN.store(proven, Ordering::Release);
    if proven {
        tracing::info!("database read retry on: write detection verified");
    } else if ran {
        tracing::warn!(
            "database read retry OFF: the self-test statement was not seen by the write \
             observer, so a GET that wrote could not be told from a read; reads that lose \
             their connection will fail as before"
        );
    } else {
        tracing::warn!(
            "database read retry OFF: the write-detection self-test could not run against \
             the database"
        );
    }
    proven
}

impl<S: Subscriber, F: Layer<S>> Layer<S> for WriteObserver<F> {
    fn on_register_dispatch(&self, subscriber: &tracing::Dispatch) {
        self.inner.on_register_dispatch(subscriber);
    }

    fn on_layer(&mut self, subscriber: &mut S) {
        self.inner.on_layer(subscriber);
    }

    fn register_callsite(&self, metadata: &'static Metadata<'static>) -> Interest {
        let inner = self.inner.register_callsite(metadata);
        if self.active && is_sqlx_statement(metadata) {
            // Decided per event: inspected inside a retry scope, otherwise
            // up to the wrapped filter.
            Interest::sometimes()
        } else {
            inner
        }
    }

    fn enabled(&self, metadata: &Metadata<'_>, ctx: Context<'_, S>) -> bool {
        (self.active && is_sqlx_statement(metadata) && observing())
            || self.inner.enabled(metadata, ctx)
    }

    fn event_enabled(&self, event: &Event<'_>, ctx: Context<'_, S>) -> bool {
        if self.active && is_sqlx_statement(event.metadata()) && observing() {
            let mut visitor = StatementVisitor::default();
            event.record(&mut visitor);
            if visitor.wrote() {
                note_write();
            }
            return self.inner.enabled(event.metadata(), ctx.clone())
                && self.inner.event_enabled(event, ctx);
        }
        self.inner.event_enabled(event, ctx)
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        if !self.active {
            return self.inner.max_level_hint();
        }
        // sqlx reports ordinary statements at DEBUG; keep them reachable.
        self.inner
            .max_level_hint()
            .map(|hint| hint.max(LevelFilter::DEBUG))
    }

    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: Context<'_, S>,
    ) {
        self.inner.on_new_span(attrs, id, ctx);
    }

    fn on_record(
        &self,
        span: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        ctx: Context<'_, S>,
    ) {
        self.inner.on_record(span, values, ctx);
    }

    fn on_follows_from(
        &self,
        span: &tracing::span::Id,
        follows: &tracing::span::Id,
        ctx: Context<'_, S>,
    ) {
        self.inner.on_follows_from(span, follows, ctx);
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        self.inner.on_event(event, ctx);
    }

    fn on_enter(&self, id: &tracing::span::Id, ctx: Context<'_, S>) {
        self.inner.on_enter(id, ctx);
    }

    fn on_exit(&self, id: &tracing::span::Id, ctx: Context<'_, S>) {
        self.inner.on_exit(id, ctx);
    }

    fn on_close(&self, id: tracing::span::Id, ctx: Context<'_, S>) {
        self.inner.on_close(id, ctx);
    }

    fn on_id_change(&self, old: &tracing::span::Id, new: &tracing::span::Id, ctx: Context<'_, S>) {
        self.inner.on_id_change(old, new, ctx);
    }

    unsafe fn downcast_raw(&self, id: TypeId) -> Option<*const ()> {
        if id == TypeId::of::<Self>() {
            Some(self as *const Self as *const ())
        } else {
            // SAFETY: forwarded unchanged to the wrapped layer, whose own
            // implementation upholds the contract.
            unsafe { self.inner.downcast_raw(id) }
        }
    }
}

/// Whether the request can be rebuilt from its head alone and is a candidate
/// for a replay at all.
fn is_replayable(req: &Request) -> bool {
    WRITE_DETECTION_PROVEN.load(Ordering::Acquire)
        && matches!(*req.method(), Method::GET | Method::HEAD)
        && req.body().size_hint().exact() == Some(0)
        && !is_never_replayed_path(req.uri().path())
}

fn retry_delay() -> Duration {
    use rand::RngExt as _;
    Duration::from_millis(rand::rng().random_range(RETRY_DELAY_MIN_MS..=RETRY_DELAY_MAX_MS))
}

/// The middleware: run the request, and replay it once if it is a bodiless
/// `GET`/`HEAD` that wrote nothing and answered 5xx after losing its
/// database connection.
pub async fn db_read_retry(req: Request, next: Next) -> Response {
    if !is_replayable(&req) {
        return next.run(req).await;
    }
    let (parts, body) = req.into_parts();
    let replay = parts.clone();
    let db = Arc::new(RequestDb::default());
    let first = REQUEST_DB
        .scope(
            db.clone(),
            next.clone().run(Request::from_parts(parts, body)),
        )
        .await;
    if !first.status().is_server_error() || !db.lost.load(Ordering::Relaxed) {
        return first;
    }
    if db.wrote.load(Ordering::Relaxed) {
        tracing::warn!(
            method = %replay.method,
            path = replay.uri.path(),
            "database connection lost after the request wrote; not retrying it"
        );
        counter!(RETRIES_METRIC, "outcome" => "skipped_wrote").increment(1);
        return first;
    }
    drop(first);

    let delay = retry_delay();
    tracing::warn!(
        method = %replay.method,
        path = replay.uri.path(),
        delay_ms = delay.as_millis() as u64,
        "database connection lost during a read; retrying it once"
    );
    tokio::time::sleep(delay).await;
    let second = REQUEST_DB
        .scope(
            Arc::new(RequestDb::default()),
            next.run(Request::from_parts(replay, Body::empty())),
        )
        .await;
    let outcome = if second.status().is_server_error() {
        "failed"
    } else {
        "recovered"
    };
    counter!(RETRIES_METRIC, "outcome" => outcome).increment(1);
    second.into_response()
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::error::AppError;
    use axum::{http::StatusCode, routing::get, Router};
    use std::sync::atomic::AtomicUsize;
    use tower::ServiceExt;
    use tracing_subscriber::layer::SubscriberExt as _;

    /// The subscriber the server installs, in miniature: the write observer
    /// around a quiet root filter, so sqlx's DEBUG statements are not
    /// enabled by `RUST_LOG` and must be seen through the observer.
    fn observed() -> tracing::subscriber::DefaultGuard {
        let subscriber = tracing_subscriber::registry()
            .with(observe_writes(tracing_subscriber::EnvFilter::new("warn")));
        WRITE_DETECTION_PROVEN.store(true, Ordering::Release);
        tracing::subscriber::set_default(subscriber)
    }

    /// What sqlx does for every statement: ask `enabled!` at DEBUG, then
    /// emit. Run inside a request scope; returns whether it counted as a write.
    pub(crate) async fn sqlx_like_statement_marks_write(statement: &'static str) -> bool {
        let db = Arc::new(RequestDb::default());
        REQUEST_DB
            .scope(db.clone(), async move {
                if tracing::enabled!(target: "sqlx::query", Level::DEBUG) {
                    tracing::event!(
                        target: "sqlx::query",
                        Level::DEBUG,
                        summary = statement,
                        db.statement = "",
                        rows_affected = 0u64,
                    );
                }
            })
            .await;
        db.wrote.load(Ordering::Relaxed)
    }

    /// Nothing is replayed until write detection is proven.
    #[tokio::test]
    async fn nothing_is_replayed_until_write_detection_is_proven() {
        let subscriber = tracing_subscriber::registry()
            .with(observe_writes(tracing_subscriber::EnvFilter::new("warn")));
        let _g = tracing::subscriber::set_default(subscriber);
        WRITE_DETECTION_PROVEN.store(false, Ordering::Release);
        let (router, calls) = flaky(1, terminated);
        assert_eq!(
            call(router, Method::GET, Body::empty()).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// DB-backed: the self-test passes through an observing subscriber and
    /// fails (leaving the retry off) through one without the observer.
    #[tokio::test]
    async fn the_startup_self_test_proves_detection_only_when_writes_are_seen() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        {
            let _g = tracing::subscriber::set_default(
                tracing_subscriber::registry().with(tracing_subscriber::EnvFilter::new("info")),
            );
            assert!(!prove_write_detection(&pool).await);
            assert!(!WRITE_DETECTION_PROVEN.load(Ordering::Acquire));
        }
        let _g = tracing::subscriber::set_default(
            tracing_subscriber::registry()
                .with(observe_writes(tracing_subscriber::EnvFilter::new("info"))),
        );
        assert!(prove_write_detection(&pool).await);
        assert!(WRITE_DETECTION_PROVEN.load(Ordering::Acquire));
    }

    /// The plain (non-OTLP) subscriber at `RUST_LOG=info`, in text and JSON:
    /// a write is seen, a read is not, and nothing reaches the log.
    #[tokio::test]
    async fn the_plain_subscriber_sees_writes_at_rust_log_info() {
        for json in [false, true] {
            let out = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
            let w = out.clone();
            let make = move || WriterTo(w.clone());
            let fmt = tracing_subscriber::fmt::layer().with_writer(make);
            let subscriber = tracing_subscriber::registry()
                .with(observe_writes(tracing_subscriber::EnvFilter::new("info")));
            let _g = if json {
                tracing::subscriber::set_default(subscriber.with(fmt.json()))
            } else {
                tracing::subscriber::set_default(subscriber.with(fmt))
            };
            assert!(
                sqlx_like_statement_marks_write("BEGIN").await,
                "json={json}"
            );
            assert!(
                !sqlx_like_statement_marks_write("SELECT 1").await,
                "json={json}"
            );
            let logged = String::from_utf8(out.lock().unwrap().clone()).unwrap();
            assert!(!logged.contains("BEGIN"), "json={json}: {logged}");
        }
    }

    #[derive(Clone)]
    struct WriterTo(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for WriterTo {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    type Work = Arc<dyn Fn() -> futures::future::BoxFuture<'static, ()> + Send + Sync>;

    fn no_work() -> Work {
        Arc::new(|| Box::pin(async {}))
    }

    /// A route at `path` that does `work`, then fails its first `failures`
    /// calls with `err` and answers 200 after, counting every call.
    fn flaky_at(
        path: &str,
        failures: usize,
        err: fn() -> AppError,
        work: Work,
    ) -> (Router, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let handler = move || {
            let c = c.clone();
            let work = work.clone();
            async move {
                work().await;
                let n = c.fetch_add(1, Ordering::SeqCst);
                if n < failures {
                    Err(err())
                } else {
                    Ok("ok")
                }
            }
        };
        let router = Router::new()
            .route(path, get(handler.clone()).post(handler))
            .layer(axum::middleware::from_fn(db_read_retry));
        (router, calls)
    }

    fn flaky(failures: usize, err: fn() -> AppError) -> (Router, Arc<AtomicUsize>) {
        flaky_at("/r", failures, err, no_work())
    }

    fn terminated() -> AppError {
        AppError::Database(
            "error returned from database: terminating connection due to administrator command"
                .into(),
        )
    }

    async fn call_at(router: Router, method: Method, path: &str, body: Body) -> StatusCode {
        let req = Request::builder()
            .method(method)
            .uri(path)
            .body(body)
            .unwrap();
        router.oneshot(req).await.unwrap().status()
    }

    async fn call(router: Router, method: Method, body: Body) -> StatusCode {
        call_at(router, method, "/r", body).await
    }

    #[tokio::test]
    async fn a_read_that_lost_its_connection_is_replayed_once_and_recovers() {
        let _g = observed();
        let (router, calls) = flaky(1, terminated);
        assert_eq!(
            call(router, Method::GET, Body::empty()).await,
            StatusCode::OK
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn head_is_replayed_too() {
        let _g = observed();
        let (router, calls) = flaky(1, terminated);
        assert_eq!(
            call(router, Method::HEAD, Body::empty()).await,
            StatusCode::OK
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn the_replay_happens_only_once() {
        let _g = observed();
        let (router, calls) = flaky(5, terminated);
        assert_eq!(
            call(router, Method::GET, Body::empty()).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_write_method_that_lost_its_connection_is_not_replayed() {
        let _g = observed();
        let (router, calls) = flaky(1, terminated);
        assert_eq!(
            call(router, Method::POST, Body::empty()).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_read_with_a_body_is_not_replayed() {
        let _g = observed();
        let (router, calls) = flaky(1, terminated);
        assert_eq!(
            call(router, Method::GET, Body::from("payload")).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn query_errors_timeouts_and_pool_exhaustion_are_not_replayed() {
        let _g = observed();
        for err in [
            (|| AppError::Database("error returned from database: syntax error".into()))
                as fn() -> AppError,
            || {
                AppError::Database(
                    "error returned from database: canceling statement due to statement timeout"
                        .into(),
                )
            },
            || AppError::Sqlx(sqlx::Error::PoolTimedOut),
            || AppError::Sqlx(sqlx::Error::PoolClosed),
            || {
                AppError::Database(
                    "error returned from database: sorry, too many clients already".into(),
                )
            },
        ] {
            let (router, calls) = flaky(1, err);
            let status = call(router, Method::GET, Body::empty()).await;
            assert!(status.is_server_error(), "{status}");
            assert_eq!(calls.load(Ordering::SeqCst), 1, "{}", err());
        }
    }

    #[tokio::test]
    async fn a_success_is_never_replayed() {
        let _g = observed();
        let (router, calls) = flaky(0, terminated);
        assert_eq!(
            call(router, Method::GET, Body::empty()).await,
            StatusCode::OK
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// The SSO callbacks (`sso.rs`: `/oidc/callback`, `/oidc/:id/callback`)
    /// delete the login state, redeem the IdP code and create the user and
    /// session on a GET: never replayed, even when the observer saw no write.
    #[tokio::test]
    async fn the_oidc_callbacks_and_auth_routes_are_never_replayed() {
        let _g = observed();
        for path in [
            "/api/v1/auth/sso/oidc/callback",
            "/api/v1/auth/sso/oidc/7a1c/callback",
            "/api/v1/auth/sso/complete",
            "/api/v1/auth/me",
            "/v2/token",
            "/plugins/x/oauth/callback",
        ] {
            let (router, calls) = flaky_at(path, 1, terminated, no_work());
            assert_eq!(
                call_at(router, Method::GET, path, Body::empty()).await,
                StatusCode::SERVICE_UNAVAILABLE,
                "{path}"
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1, "{path}");
        }
    }

    /// A download records its counter on the way out; a GET that queued one
    /// and then lost its connection is not replayed (it would count twice).
    #[tokio::test]
    async fn a_get_that_queued_a_download_counter_is_not_replayed() {
        use crate::services::download_event_dispatch::{
            try_enqueue, DownloadEvent, DownloadStatsEvent,
        };
        let _g = observed();
        let work: Work = Arc::new(|| {
            Box::pin(async {
                let _ = try_enqueue(DownloadEvent::Stats(DownloadStatsEvent {
                    artifact_id: uuid::Uuid::new_v4(),
                    user_id: None,
                    ip_address: None,
                    user_agent: None,
                }));
            })
        });
        let (router, calls) = flaky_at("/r", 1, terminated, work);
        assert_eq!(
            call(router, Method::GET, Body::empty()).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// DB-backed: a GET that runs a write statement (the callback's
    /// `DELETE FROM sso_sessions`, a download counter `INSERT`) before it
    /// loses its connection is not replayed; one that only read is.
    #[tokio::test]
    async fn the_observer_sees_writes_sqlx_runs_and_only_reads_are_replayed() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let _g = observed();
        for (sql, replayed) in [
            (
                "DELETE FROM sso_sessions WHERE id = gen_random_uuid()",
                false,
            ),
            (
                "UPDATE repositories SET updated_at = updated_at WHERE id = gen_random_uuid()",
                false,
            ),
            (
                "SELECT id FROM repositories WHERE id = gen_random_uuid() FOR UPDATE",
                false,
            ),
            ("SELECT count(*) FROM repositories", true),
        ] {
            let pool = pool.clone();
            let work: Work = Arc::new(move || {
                let pool = pool.clone();
                Box::pin(async move {
                    sqlx::query(sql).execute(&pool).await.expect(sql);
                })
            });
            let (router, calls) = flaky_at("/r", 1, terminated, work);
            let status = call(router, Method::GET, Body::empty()).await;
            if replayed {
                assert_eq!(status, StatusCode::OK, "{sql}");
                assert_eq!(calls.load(Ordering::SeqCst), 2, "{sql}");
            } else {
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{sql}");
                assert_eq!(calls.load(Ordering::SeqCst), 1, "{sql}");
            }
        }
    }

    #[test]
    fn write_statements_are_told_from_reads() {
        for read in [
            "SELECT id, key FROM repositories WHERE key = $1",
            "select updated_at, created_by from artifacts",
            "WITH x AS (SELECT 1) SELECT * FROM x",
            "SELECT 1",
            "EXPLAIN SELECT 1",
            "COMMIT",
            "ROLLBACK",
            "SHOW server_version",
            "",
        ] {
            assert!(!is_write_statement(read), "{read}");
        }
        for write in [
            "BEGIN",
            "INSERT INTO download_statistics (artifact_id) VALUES ($1)",
            "UPDATE users SET last_login_at = NOW()",
            "DELETE FROM sso_sessions WHERE id = $1",
            "WITH c AS (UPDATE jobs SET state = 'x' RETURNING id) SELECT id FROM c",
            "SELECT id FROM jobs FOR UPDATE SKIP LOCKED",
            "SELECT nextval('seq')",
            "EXPLAIN ANALYZE DELETE FROM x",
            "SET LOCAL statement_timeout = 1000",
            "LOCK TABLE repositories",
            "TRUNCATE x",
            "CREATE TABLE x (id int)",
            "NOTIFY x",
        ] {
            assert!(is_write_statement(write), "{write}");
        }
    }

    #[test]
    fn connection_failures_are_transient_and_query_failures_are_not() {
        for msg in [
            "error returned from database: terminating connection due to administrator command",
            "error communicating with database: Connection reset by peer (os error 104)",
            "error communicating with database: Connection refused (os error 111)",
            "error returned from database: the database system is shutting down",
            "error returned from database: the database system is starting up",
            "error returned from database: cannot execute UPDATE in a read-only transaction",
        ] {
            assert!(
                AppError::Database(msg.into()).is_transient_connection_error(),
                "{msg}"
            );
        }
        assert!(AppError::Sqlx(sqlx::Error::Io(std::io::Error::from(
            std::io::ErrorKind::UnexpectedEof
        )))
        .is_transient_connection_error());
        for msg in [
            "error returned from database: duplicate key value violates unique constraint",
            "error returned from database: canceling statement due to lock timeout",
            "error returned from database: could not serialize access due to concurrent update",
            "pool timed out while waiting for an open connection",
            // An upstream HTTP failure wrapped as a database error is not one.
            "upstream fetch failed: connection refused",
            "connection reset by peer",
        ] {
            assert!(
                !AppError::Database(msg.into()).is_transient_connection_error(),
                "{msg}"
            );
        }
        assert!(!AppError::Sqlx(sqlx::Error::RowNotFound).is_transient_connection_error());
        assert!(!AppError::NotFound("x".into()).is_transient_connection_error());
    }

    #[test]
    fn sqlstate_classes() {
        for code in [
            "08000", "08003", "08006", "08001", "57P01", "57P02", "57P03", "25006",
        ] {
            assert!(is_transient_sqlstate(code), "{code}");
        }
        for code in ["23505", "40001", "40P01", "57014", "53300", "42P01"] {
            assert!(!is_transient_sqlstate(code), "{code}");
        }
    }

    #[test]
    fn on_by_default_and_off_only_when_asked() {
        assert!(parse_enabled(None));
        assert!(parse_enabled(Some("true")));
        assert!(parse_enabled(Some("")));
        for off in ["false", "0", "no", "off", " FALSE "] {
            assert!(!parse_enabled(Some(off)), "{off}");
        }
    }

    #[test]
    fn noting_outside_a_request_is_harmless() {
        note_transient_connection_error();
        note_write();
    }

    /// Review (#5941): with the retry off the observer is inert, so a write
    /// statement inside a scope is not even looked at, and sqlx is not asked
    /// to render it.
    #[tokio::test]
    async fn the_observer_is_inert_when_the_retry_is_off() {
        let subscriber = tracing_subscriber::registry().with(observe_writes_if(
            tracing_subscriber::EnvFilter::new("info"),
            false,
        ));
        let _g = tracing::subscriber::set_default(subscriber);
        assert!(!sqlx_like_statement_marks_write("BEGIN").await);
        let db = Arc::new(RequestDb::default());
        let asked = REQUEST_DB
            .scope(db, async {
                tracing::enabled!(target: "sqlx::query", Level::DEBUG)
            })
            .await;
        assert!(!asked, "sqlx must not be asked to render statements");
    }

    /// Review (#5941): once a request has written, its later statements are
    /// no longer enabled, so sqlx stops rendering them.
    #[tokio::test]
    async fn statements_after_a_write_are_not_rendered() {
        let _g = observed();
        let db = Arc::new(RequestDb::default());
        let (before, after) = REQUEST_DB
            .scope(db.clone(), async {
                let before = tracing::enabled!(target: "sqlx::query", Level::DEBUG);
                tracing::event!(
                    target: "sqlx::query",
                    Level::DEBUG,
                    summary = "INSERT INTO x …",
                    db.statement = "\n\nINSERT INTO x (a) VALUES ($1)\n",
                );
                (
                    before,
                    tracing::enabled!(target: "sqlx::query", Level::DEBUG),
                )
            })
            .await;
        assert!(before, "a read-so-far request inspects its statements");
        assert!(db.wrote.load(Ordering::Relaxed));
        assert!(
            !after,
            "a request that wrote no longer has statements rendered"
        );
    }

    /// The visitor decides from the summary when it already reads as a
    /// write and scans the full statement otherwise (a `FOR UPDATE` past the
    /// first four words).
    #[tokio::test]
    async fn the_full_statement_decides_a_select_and_the_summary_a_write() {
        let _g = observed();
        for (summary, statement, wrote) in [
            (
                "SELECT id FROM jobs …",
                "\n\nSELECT id FROM jobs WHERE state = 'queued' FOR UPDATE SKIP LOCKED\n",
                true,
            ),
            (
                "SELECT id FROM jobs …",
                "\n\nSELECT id FROM jobs WHERE state = 'queued'\n",
                false,
            ),
            (
                "UPDATE jobs SET state …",
                "\n\nUPDATE jobs SET state = 'x'\n",
                true,
            ),
            ("SELECT 1", "", false),
        ] {
            let db = Arc::new(RequestDb::default());
            REQUEST_DB
                .scope(db.clone(), async move {
                    tracing::event!(
                        target: "sqlx::query",
                        Level::DEBUG,
                        summary,
                        db.statement = statement,
                    );
                })
                .await;
            assert_eq!(db.wrote.load(Ordering::Relaxed), wrote, "{statement}");
        }
    }

    /// Review (#5941): the request scope is a task-local, so a write a GET
    /// runs in a spawned task is not seen by the observer and the GET would
    /// be replayed. `spawn_write` counts it, and the GET is not replayed.
    #[tokio::test]
    async fn a_spawned_write_is_seen_only_through_spawn_write() {
        let _g = observed();
        let plain: Work = Arc::new(|| {
            Box::pin(async {
                let _ = tokio::spawn(async {
                    sqlx_like_statement_outside_scope("UPDATE api_tokens SET last_used_at = NOW()");
                })
                .await;
            })
        });
        let (router, calls) = flaky_at("/r", 1, terminated, plain);
        assert_eq!(
            call(router, Method::GET, Body::empty()).await,
            StatusCode::OK
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a plain tokio::spawn write is invisible: the GET was replayed"
        );

        let tracked: Work = Arc::new(|| {
            Box::pin(async {
                let _ = spawn_write(async {
                    sqlx_like_statement_outside_scope("UPDATE jobs SET state = 'x'");
                })
                .await;
            })
        });
        let (router, calls) = flaky_at("/r", 1, terminated, tracked);
        assert_eq!(
            call(router, Method::GET, Body::empty()).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "spawn_write blocks the replay"
        );
    }

    /// What sqlx emits for a statement, without opening a scope of its own.
    fn sqlx_like_statement_outside_scope(statement: &'static str) {
        if tracing::enabled!(target: "sqlx::query", Level::DEBUG) {
            tracing::event!(
                target: "sqlx::query",
                Level::DEBUG,
                summary = statement,
                db.statement = "",
            );
        }
    }

    /// The observer as it was before the review (#5941), kept only as the
    /// baseline of [`statement_observation_cost`]: it copied both fields and
    /// lowercased the statement for every statement of every request.
    struct LegacyObserver<F> {
        inner: F,
    }

    fn legacy_is_write_statement(text: &str) -> bool {
        let lower = text.to_ascii_lowercase();
        let mut tokens = lower
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|t| !t.is_empty());
        let Some(first) = tokens.next() else {
            return false;
        };
        const MODIFIERS: &[&str] = &[
            "insert", "update", "delete", "merge", "nextval", "setval", "into", "share", "truncate",
        ];
        match first {
            "select" | "with" | "values" | "table" | "show" => {
                tokens.any(|t| MODIFIERS.contains(&t))
            }
            "explain" => tokens.any(|t| t == "analyze" || t == "analyse"),
            "commit" | "rollback" | "end" => false,
            _ => true,
        }
    }

    #[derive(Default)]
    struct LegacyVisitor {
        summary: String,
        statement: String,
    }

    impl Visit for LegacyVisitor {
        fn record_str(&mut self, field: &Field, value: &str) {
            match field.name() {
                "summary" => self.summary = value.to_string(),
                "db.statement" => self.statement = value.to_string(),
                _ => {}
            }
        }
        fn record_debug(&mut self, _field: &Field, _value: &dyn std::fmt::Debug) {}
    }

    impl<S: Subscriber, F: Layer<S>> Layer<S> for LegacyObserver<F> {
        fn register_callsite(&self, metadata: &'static Metadata<'static>) -> Interest {
            let inner = self.inner.register_callsite(metadata);
            if is_sqlx_statement(metadata) {
                Interest::sometimes()
            } else {
                inner
            }
        }
        fn enabled(&self, metadata: &Metadata<'_>, ctx: Context<'_, S>) -> bool {
            (is_sqlx_statement(metadata) && current().is_some())
                || self.inner.enabled(metadata, ctx)
        }
        fn event_enabled(&self, event: &Event<'_>, ctx: Context<'_, S>) -> bool {
            if is_sqlx_statement(event.metadata()) {
                if let Some(db) = current() {
                    let mut visitor = LegacyVisitor::default();
                    event.record(&mut visitor);
                    let text = if visitor.statement.trim().is_empty() {
                        visitor.summary.trim_end_matches(" …")
                    } else {
                        visitor.statement.as_str()
                    };
                    if legacy_is_write_statement(text) {
                        db.wrote.store(true, Ordering::Relaxed);
                    }
                    return self.inner.enabled(event.metadata(), ctx.clone())
                        && self.inner.event_enabled(event, ctx);
                }
            }
            self.inner.event_enabled(event, ctx)
        }
        fn max_level_hint(&self) -> Option<LevelFilter> {
            self.inner
                .max_level_hint()
                .map(|hint| hint.max(LevelFilter::DEBUG))
        }
        fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
            self.inner.on_event(event, ctx);
        }
    }

    /// sqlx 0.9's `QueryLogger::finish`, line for line: when the statement
    /// event is enabled it builds the summary and copies the statement.
    fn sqlx_finish(sql: &str) {
        if tracing::enabled!(target: "sqlx::query", Level::DEBUG) {
            let mut summary = sql
                .split_whitespace()
                .take(4)
                .collect::<Vec<&str>>()
                .join(" ");
            let statement = if summary != sql {
                summary.push_str(" …");
                format!("\n\n{}\n", sql)
            } else {
                String::new()
            };
            let elapsed = std::time::Duration::from_micros(250);
            tracing::event!(
                target: "sqlx::query",
                Level::DEBUG,
                summary,
                db.statement = statement,
                rows_affected = 0u64,
                rows_returned = 20u64,
                ?elapsed,
                elapsed_secs = elapsed.as_secs_f64(),
            );
        }
    }

    /// A list query of the size the repository endpoints run.
    const BENCH_SQL: &str = "SELECT r.id, r.key, r.name, r.description, r.format, r.repo_type, \
        r.storage_backend, r.storage_path, r.upstream_url, r.is_public, r.quota_bytes, \
        r.replication_priority, r.promotion_target_id, r.promotion_policy_id, \
        r.curation_enabled, r.curation_source_repo_id, r.curation_target_repo_id, \
        r.curation_default_action, r.curation_sync_interval_secs, r.curation_auto_fetch, \
        r.created_at, r.updated_at FROM repositories r LEFT JOIN repository_members m \
        ON m.repository_id = r.id AND m.user_id = $1 WHERE (r.is_public OR m.user_id IS NOT NULL) \
        AND ($2::text IS NULL OR r.format::text = $2) ORDER BY r.key LIMIT $3 OFFSET $4";

    fn ns_per_statement(iterations: u32, scoped: bool) -> f64 {
        let run = || {
            let start = std::time::Instant::now();
            for _ in 0..iterations {
                sqlx_finish(std::hint::black_box(BENCH_SQL));
            }
            start.elapsed().as_nanos() as f64 / iterations as f64
        };
        if scoped {
            REQUEST_DB.sync_scope(Arc::new(RequestDb::default()), run)
        } else {
            run()
        }
    }

    /// Microbenchmark for the review (#5941): the cost the observer adds to
    /// one sqlx statement, before and after, through a real subscriber at
    /// RUST_LOG=info. Run with
    /// `cargo nextest run --cargo-profile ci --features test-shard-services-2
    ///  --run-ignored only -E 'test(statement_observation_cost)' --no-capture`.
    #[test]
    #[ignore = "microbenchmark; run on demand"]
    fn statement_observation_cost() {
        const N: u32 = 200_000;
        let filter = || tracing_subscriber::EnvFilter::new("info");
        let measure = |label: &str, scoped: bool, dispatch: tracing::Dispatch| {
            tracing::dispatcher::with_default(&dispatch, || {
                ns_per_statement(N / 10, scoped);
                let mut samples: Vec<f64> = (0..5).map(|_| ns_per_statement(N, scoped)).collect();
                samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
                eprintln!(
                    "BENCH {label:<48} {:>8.1} ns/statement (median of 5)",
                    samples[2]
                );
                samples[2]
            })
        };
        let plain = || tracing::Dispatch::new(tracing_subscriber::registry().with(filter()));
        let legacy = || {
            tracing::Dispatch::new(
                tracing_subscriber::registry().with(LegacyObserver { inner: filter() }),
            )
        };
        let new = |active| {
            tracing::Dispatch::new(
                tracing_subscriber::registry().with(observe_writes_if(filter(), active)),
            )
        };
        let render_only = || {
            tracing::Dispatch::new(
                tracing_subscriber::registry()
                    .with(tracing_subscriber::EnvFilter::new("info,sqlx::query=debug")),
            )
        };
        let base = measure("no observer (main), any request", false, plain());
        let rendered = measure(
            "sqlx renders + dispatches, nothing inspects",
            false,
            render_only(),
        );
        let off = measure("retry off, inside a GET", true, new(false));
        let outside = measure("retry on, outside a GET (writes, probes)", false, new(true));
        let before = measure(
            "retry on, GET statement: before (copy+lowercase)",
            true,
            legacy(),
        );
        let after = measure("retry on, GET statement: after (in place)", true, new(true));
        let classify = |f: fn(&str) -> bool| {
            let rendered = format!("\n\n{BENCH_SQL}\n");
            let start = std::time::Instant::now();
            for _ in 0..N {
                std::hint::black_box(f(std::hint::black_box(&rendered)));
            }
            start.elapsed().as_nanos() as f64 / N as f64
        };
        let legacy_classify = classify(|t| {
            let copy = t.to_string();
            legacy_is_write_statement(&copy)
        });
        let new_classify = classify(is_write_statement);
        eprintln!(
            "BENCH classify alone: before (copy + lowercase) {legacy_classify:.1} ns, after (in place) {new_classify:.1} ns"
        );
        eprintln!(
            "BENCH statement {} bytes; added per GET statement: before {:.0} ns, after {:.0} ns, \
             of which sqlx's own rendering and dispatch {:.0} ns; retry off adds {:.0} ns",
            BENCH_SQL.len(),
            before - base,
            after - base,
            rendered - base,
            off - base
        );
        assert!(outside < before);
    }

    #[test]
    fn the_delay_is_jittered_within_its_bounds() {
        for _ in 0..100 {
            let d = retry_delay().as_millis() as u64;
            assert!(
                (RETRY_DELAY_MIN_MS..=RETRY_DELAY_MAX_MS).contains(&d),
                "{d}"
            );
        }
    }
}
