//! Bounded dispatch for download-path side-effect writes (#2522).
//!
//! The download hot path emits two best-effort telemetry writes per served
//! body: a `download_statistics` row ([`record_download`]) and an
//! `ARTIFACT_DOWNLOADED` audit row (the `finish_download` epilogue). #2522
//! first moved both OFF the byte plane via `tokio::spawn`, which fixed the
//! latency coupling but left the *bounded* half of the issue open: every
//! request spawned a detached task that grabbed a catalog-pool connection with
//! no cap and no backpressure. Under a download flood with a slow or failing
//! event store, detached tasks and pool waiters grow without bound — memory +
//! connection exhaustion that couples back into serving (artifact lookup needs
//! the same pool).
//!
//! This module replaces the per-request spawns with the codebase's established
//! bounded-outbox shape:
//!
//! * one process-global **bounded** `mpsc` channel behind an
//!   `OnceLock<Option<Sender>>` — the same install/degrade idiom as
//!   `GLOBAL_AUTH_SEMAPHORE` (`auth_service.rs`): tests or embedders that never
//!   install a dispatcher get a graceful no-op, never a panic;
//! * a **fixed** pool of background flush workers (modelled on
//!   `webhook_producer::start_webhook_producer`) that drain the channel and
//!   **batch-INSERT** into the existing `download_statistics` / `audit_log`
//!   tables — fewer round-trips than the historical one-INSERT-per-request;
//! * producers only ever [`try_enqueue`] (a synchronous `try_send`): a full
//!   queue **sheds** the event (drop + `ak_download_events_dropped_total`
//!   metric) instead of blocking or growing. The byte plane is never touched.
//!
//! These events are best-effort analytics/trail writes (see
//! `audit_fire_and_forget`: "a side effect, never a gate") — loss on overflow
//! or crash is the pre-existing contract, not a regression. Strict crash
//! durability would be a separate durable-outbox slice.
//!
//! [`record_download`]: crate::services::artifact_service::record_download

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use sqlx::PgPool;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::warn;
use uuid::Uuid;

use crate::services::audit_service::{AuditEntry, AuditService};

/// Default bounded queue depth. Overridable via `DOWNLOAD_EVENT_QUEUE_DEPTH`.
///
/// Sized so a burst of ~8k downloads (a few seconds of heavy flood) is
/// absorbed without shedding while the workers batch-flush, yet the worst-case
/// resident cost stays small (events are a few hundred bytes each).
pub const DEFAULT_QUEUE_DEPTH: usize = 8192;

/// Default flush-worker count. Overridable via `DOWNLOAD_EVENT_FLUSH_WORKERS`.
///
/// This is the hard cap on concurrent side-effect DB connections: two workers
/// batch-inserting 256 rows per round-trip drain far faster than the hot path
/// can produce under normal operation, while a slow event store can never hold
/// more than `workers` connections.
pub const DEFAULT_FLUSH_WORKERS: usize = 2;

/// Max events coalesced into one batched multi-row INSERT.
pub const FLUSH_BATCH_MAX: usize = 256;

/// A completed-download statistics event, fully resolved at request time.
///
/// The trusted-proxy client IP is captured (and stringified) by the producer
/// from the request's [`DownloadContext`] BEFORE the async hop, so attribution
/// can never drift between enqueue and flush.
///
/// [`DownloadContext`]: crate::api::middleware::download_telemetry::DownloadContext
#[derive(Debug)]
pub struct DownloadStatsEvent {
    pub artifact_id: Uuid,
    pub user_id: Option<Uuid>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// One queued download side-effect. Audit entries are boxed: they are much
/// larger than the stats variant and would otherwise inflate every queue slot.
/// (No `Debug` derive: `AuditEntry` deliberately does not implement it —
/// audit payloads can carry sensitive details.)
pub enum DownloadEvent {
    Stats(DownloadStatsEvent),
    Audit(Box<AuditEntry>),
}

impl DownloadEvent {
    /// Stable low-cardinality label for metrics.
    fn kind(&self) -> &'static str {
        match self {
            DownloadEvent::Stats(_) => "stats",
            DownloadEvent::Audit(_) => "audit",
        }
    }
}

/// Outcome of a non-blocking enqueue attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueOutcome {
    /// Queued for a background flush worker.
    Enqueued,
    /// Queue full (or closed): the event was dropped and counted.
    Shed,
    /// No dispatcher installed (tests / embedders): silent best-effort no-op.
    NoDispatcher,
}

/// Process-wide dispatcher handle. Same `OnceLock<Option<..>>` shape as
/// `GLOBAL_AUTH_SEMAPHORE`: set once at startup; when unset (unit tests,
/// library embedders) producers degrade gracefully instead of panicking.
static DOWNLOAD_EVENT_DISPATCH: OnceLock<Option<mpsc::Sender<DownloadEvent>>> = OnceLock::new();

/// Total events shed because the bounded queue was full/closed. An in-process
/// counter alongside the Prometheus metric so unit tests (which run without a
/// recorder installed) can assert the shed path fires.
static DOWNLOAD_EVENTS_SHED: AtomicU64 = AtomicU64::new(0);

/// Total rows lost at FLUSH time (batch rejected and the per-row fallback also
/// failed for that row). Sibling of [`DOWNLOAD_EVENTS_SHED`] for the DB-side
/// loss path, mirrored to `ak_download_events_dropped_total{reason="flush_failed"}`.
static DOWNLOAD_EVENTS_FLUSH_LOST: AtomicU64 = AtomicU64::new(0);

/// `download_statistics.user_agent` column width (VARCHAR(512), migration
/// 004). Everything longer is clamped — never allowed to fail an INSERT.
pub const STATS_USER_AGENT_MAX_CHARS: usize = 512;

/// Clamp a User-Agent string to the `download_statistics` column width
/// (character-counted, matching Postgres VARCHAR semantics; safe on any UTF-8
/// boundary). Applied at request capture (`DownloadContext`) and re-applied at
/// insert build time so no producer can poison a batched INSERT with an
/// oversized value.
pub fn clamp_user_agent(ua: String) -> String {
    match ua.char_indices().nth(STATS_USER_AGENT_MAX_CHARS) {
        None => ua,
        Some((byte_idx, _)) => {
            let mut clamped = ua;
            clamped.truncate(byte_idx);
            clamped
        }
    }
}

/// Install the process-wide download-event dispatcher handle. Idempotent —
/// the first call wins, mirroring `install_global_auth_semaphore`, so
/// multi-`AppState` test setups cannot re-configure it mid-run. Returns
/// whether this call installed the handle.
pub fn install_download_event_dispatch(tx: Option<mpsc::Sender<DownloadEvent>>) -> bool {
    DOWNLOAD_EVENT_DISPATCH.set(tx).is_ok()
}

/// Whether a dispatcher handle has been installed (test scaffolding support).
pub fn dispatch_installed() -> bool {
    DOWNLOAD_EVENT_DISPATCH
        .get()
        .is_some_and(|cell| cell.is_some())
}

/// Total events shed so far (process lifetime).
pub fn shed_total() -> u64 {
    DOWNLOAD_EVENTS_SHED.load(Ordering::Relaxed)
}

/// Total rows lost at flush time so far (process lifetime).
pub fn flush_lost_total() -> u64 {
    DOWNLOAD_EVENTS_FLUSH_LOST.load(Ordering::Relaxed)
}

/// Non-blocking enqueue of a download side-effect event.
///
/// NEVER blocks, awaits, or spawns: a full queue sheds the event (drop +
/// metric), an uninstalled dispatcher is a silent no-op. This is the whole
/// availability contract — the download response can never be coupled to the
/// event store through this call.
pub fn try_enqueue(event: DownloadEvent) -> EnqueueOutcome {
    try_enqueue_with(
        DOWNLOAD_EVENT_DISPATCH.get().and_then(|cell| cell.as_ref()),
        event,
    )
}

/// Pure enqueue body, extracted (like `acquire_permit_from` in
/// `auth_service`) so unit tests can exercise the shed/degrade branches on a
/// fresh channel without contending with the process-wide `OnceLock`.
fn try_enqueue_with(
    tx: Option<&mpsc::Sender<DownloadEvent>>,
    event: DownloadEvent,
) -> EnqueueOutcome {
    let Some(tx) = tx else {
        // Graceful degrade: no dispatcher installed (tests / embedders).
        // Best-effort telemetry is simply not recorded — never a panic, and
        // never a fallback to unbounded per-request work.
        crate::services::metrics_service::record_download_events_dropped(
            event.kind(),
            "uninitialised",
            1,
        );
        return EnqueueOutcome::NoDispatcher;
    };
    let kind = event.kind();
    match tx.try_send(event) {
        Ok(()) => {
            crate::services::metrics_service::set_download_event_queue_depth(
                (tx.max_capacity() - tx.capacity()) as f64,
            );
            EnqueueOutcome::Enqueued
        }
        Err(mpsc::error::TrySendError::Full(_)) => {
            DOWNLOAD_EVENTS_SHED.fetch_add(1, Ordering::Relaxed);
            crate::services::metrics_service::record_download_events_dropped(kind, "queue_full", 1);
            EnqueueOutcome::Shed
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            DOWNLOAD_EVENTS_SHED.fetch_add(1, Ordering::Relaxed);
            crate::services::metrics_service::record_download_events_dropped(kind, "closed", 1);
            EnqueueOutcome::Shed
        }
    }
}

/// Read a positive usize from the environment, falling back to `default`.
fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

/// Start the bounded download-event dispatcher and install its handle as the
/// process-wide producer target. Called once from `main.rs` alongside
/// `start_webhook_producer`; sizing comes from `DOWNLOAD_EVENT_QUEUE_DEPTH` /
/// `DOWNLOAD_EVENT_FLUSH_WORKERS` (defaults [`DEFAULT_QUEUE_DEPTH`] /
/// [`DEFAULT_FLUSH_WORKERS`]).
///
/// If a dispatcher was already installed (multi-`AppState` test setups), the
/// freshly spawned workers observe their channel close as this call's unused
/// sender drops, and exit on their own.
pub fn start_download_event_dispatch(db: PgPool, shutdown_token: CancellationToken) {
    let depth = env_usize("DOWNLOAD_EVENT_QUEUE_DEPTH", DEFAULT_QUEUE_DEPTH);
    let workers = env_usize("DOWNLOAD_EVENT_FLUSH_WORKERS", DEFAULT_FLUSH_WORKERS);
    let tx = spawn_dispatch(db, depth, workers, shutdown_token);
    if install_download_event_dispatch(Some(tx)) {
        tracing::info!(
            queue_depth = depth,
            flush_workers = workers,
            "Download-event dispatcher started (bounded side-effect flush)"
        );
    } else {
        warn!("Download-event dispatcher already installed; keeping the first instance");
    }
}

/// Create the bounded channel and spawn the fixed flush-worker pool, returning
/// the producer handle. Split from [`start_download_event_dispatch`] so tests
/// can run a private dispatcher against their own pool without touching the
/// process-global handle.
fn spawn_dispatch(
    db: PgPool,
    depth: usize,
    workers: usize,
    shutdown_token: CancellationToken,
) -> mpsc::Sender<DownloadEvent> {
    let (tx, rx) = mpsc::channel::<DownloadEvent>(depth);
    // `mpsc::Receiver` is single-consumer; the fixed worker pool shares it
    // behind a Mutex held only while collecting a batch (`recv_many`), then
    // released for the flush so up to `workers` batched INSERTs can overlap.
    let rx = Arc::new(tokio::sync::Mutex::new(rx));
    for worker_id in 0..workers.max(1) {
        let db = db.clone();
        let rx = Arc::clone(&rx);
        let shutdown = shutdown_token.clone();
        tokio::spawn(async move {
            flush_worker(worker_id, db, rx, shutdown).await;
        });
    }
    tx
}

/// One flush worker: repeatedly collect up to [`FLUSH_BATCH_MAX`] queued
/// events and write them as batched multi-row INSERTs. Errors are logged and
/// swallowed (best-effort contract); the worker itself only exits on shutdown
/// or channel close.
async fn flush_worker(
    worker_id: usize,
    db: PgPool,
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<DownloadEvent>>>,
    shutdown: CancellationToken,
) {
    let mut batch: Vec<DownloadEvent> = Vec::with_capacity(FLUSH_BATCH_MAX);
    loop {
        batch.clear();
        let received = {
            let mut guard = rx.lock().await;
            tokio::select! {
                _ = shutdown.cancelled() => None,
                n = guard.recv_many(&mut batch, FLUSH_BATCH_MAX) => Some(n),
            }
        };
        match received {
            // Shutdown: exit without draining — these are best-effort events
            // and the existing spawn-based path also lost in-flight writes on
            // shutdown. `recv_many` returning 0 means the channel closed.
            None | Some(0) => {
                tracing::debug!(worker_id, "download-event flush worker exiting");
                break;
            }
            Some(_) => flush_batch(&db, &mut batch).await,
        }
    }
}

/// Split a collected batch by table and run one batched INSERT per table.
///
/// Batching must never AMPLIFY loss: a row that Postgres rejects fails the
/// whole multi-row statement, so each table's flush falls back to per-row
/// inserts on batch failure ([`flush_stats_with_fallback`] /
/// [`AuditService::log_batch`]) — one bad row can only lose itself, never its
/// co-batched neighbors. Rows lost even individually are counted
/// (`flush_failed` reason + [`flush_lost_total`]), so a poison attack or
/// event-store error always leaves a metric trace.
async fn flush_batch(db: &PgPool, batch: &mut Vec<DownloadEvent>) {
    let mut stats: Vec<DownloadStatsEvent> = Vec::new();
    let mut audits: Vec<AuditEntry> = Vec::new();
    for event in batch.drain(..) {
        match event {
            DownloadEvent::Stats(s) => stats.push(s),
            DownloadEvent::Audit(a) => audits.push(*a),
        }
    }
    if !stats.is_empty() {
        record_flush_lost("stats", flush_stats_with_fallback(db, stats).await);
    }
    if !audits.is_empty() {
        record_flush_lost(
            "audit",
            AuditService::new(db.clone()).log_batch(audits).await,
        );
    }
}

/// Count rows a flush could not persist even via the per-row fallback.
fn record_flush_lost(kind: &'static str, lost: usize) {
    if lost > 0 {
        DOWNLOAD_EVENTS_FLUSH_LOST.fetch_add(lost as u64, Ordering::Relaxed);
        crate::services::metrics_service::record_download_events_dropped(
            kind,
            "flush_failed",
            lost as u64,
        );
    }
}

/// Flush a stats batch, isolating row failures. Tries the single batched
/// INSERT first (the fast path); if Postgres rejects it, retries each row
/// individually so only genuinely bad rows are lost. Returns the number of
/// rows that could not be persisted.
async fn flush_stats_with_fallback(db: &PgPool, stats: Vec<DownloadStatsEvent>) -> usize {
    match insert_stats_batch(db, &stats).await {
        Ok(()) => 0,
        Err(batch_err) => {
            warn!(
                rows = stats.len(),
                error = %batch_err,
                "download_statistics batch INSERT failed; retrying rows individually"
            );
            let mut lost = 0usize;
            for s in &stats {
                if let Err(e) = insert_stat_row(db, s).await {
                    warn!(artifact_id = %s.artifact_id, error = %e, "failed to record download statistics (row dropped)");
                    lost += 1;
                }
            }
            lost
        }
    }
}

/// Batched multi-row `download_statistics` INSERT via parallel-array UNNEST —
/// the same shape as `webhook_producer`'s `BATCH_INSERT_DELIVERIES_SQL`.
/// Runtime (non-macro) query, matching the single-row INSERT this replaces, so
/// no offline `.sqlx` prepare is needed.
///
/// `user_agent` is re-clamped to the column width here (defense-in-depth:
/// [`DownloadContext`] already clamps at capture, but events can be built from
/// synthesized contexts) so no oversized string can ever fail the statement.
///
/// [`DownloadContext`]: crate::api::middleware::download_telemetry::DownloadContext
async fn insert_stats_batch(db: &PgPool, stats: &[DownloadStatsEvent]) -> sqlx::Result<()> {
    let mut artifact_ids: Vec<Uuid> = Vec::with_capacity(stats.len());
    let mut user_ids: Vec<Option<Uuid>> = Vec::with_capacity(stats.len());
    let mut ip_addresses: Vec<Option<&str>> = Vec::with_capacity(stats.len());
    let mut user_agents: Vec<Option<String>> = Vec::with_capacity(stats.len());
    for s in stats {
        artifact_ids.push(s.artifact_id);
        user_ids.push(s.user_id);
        ip_addresses.push(s.ip_address.as_deref());
        user_agents.push(s.user_agent.clone().map(clamp_user_agent));
    }
    sqlx::query(
        r#"
        INSERT INTO download_statistics (artifact_id, user_id, ip_address, user_agent)
        SELECT * FROM UNNEST($1::uuid[], $2::uuid[], $3::text[], $4::text[])
            AS t(artifact_id, user_id, ip_address, user_agent)
        "#,
    )
    .bind(artifact_ids)
    .bind(user_ids)
    .bind(ip_addresses)
    .bind(user_agents)
    .execute(db)
    .await?;
    Ok(())
}

/// Single-row stats INSERT — the pre-batching statement, used as the per-row
/// fallback when a batch is rejected.
async fn insert_stat_row(db: &PgPool, s: &DownloadStatsEvent) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO download_statistics (artifact_id, user_id, ip_address, user_agent) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(s.artifact_id)
    .bind(s.user_id)
    .bind(s.ip_address.as_deref())
    .bind(s.user_agent.clone().map(clamp_user_agent))
    .execute(db)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::audit_service::{AuditAction, ResourceType};

    fn stats_event(artifact_id: Uuid) -> DownloadEvent {
        DownloadEvent::Stats(DownloadStatsEvent {
            artifact_id,
            user_id: None,
            ip_address: Some("203.0.113.9".to_string()),
            user_agent: Some("dispatch-test/1.0".to_string()),
        })
    }

    /// Uninstalled dispatcher: a producer call is a silent no-op — no panic,
    /// no spawn, no shed-counter movement (graceful-degrade contract).
    #[test]
    fn test_enqueue_without_dispatcher_is_noop_and_never_panics() {
        // Distinguished outcome: a degrade, not an overflow shed. (The global
        // shed counter is not asserted here — parallel tests also move it.)
        let outcome = try_enqueue_with(None, stats_event(Uuid::new_v4()));
        assert_eq!(outcome, EnqueueOutcome::NoDispatcher);
    }

    /// Bounded under flood with a stalled sink: no worker consumes (the
    /// worst-case "event store hung" simulation), so a flood far larger than
    /// the queue must cap in-flight events at the channel depth and shed the
    /// rest, counting each shed. `try_enqueue` is synchronous by construction
    /// — nothing here can block or grow without bound.
    #[tokio::test]
    async fn test_flood_beyond_capacity_stays_bounded_and_sheds() {
        const DEPTH: usize = 64;
        const FLOOD: usize = 10_000;
        let (tx, rx) = mpsc::channel::<DownloadEvent>(DEPTH);
        let shed_before = shed_total();

        let mut enqueued = 0usize;
        let mut shed = 0usize;
        for _ in 0..FLOOD {
            match try_enqueue_with(Some(&tx), stats_event(Uuid::new_v4())) {
                EnqueueOutcome::Enqueued => enqueued += 1,
                EnqueueOutcome::Shed => shed += 1,
                EnqueueOutcome::NoDispatcher => unreachable!("dispatcher handle supplied"),
            }
        }

        // In-flight is capped at exactly the channel depth; everything beyond
        // it was dropped and counted — no unbounded task/memory growth.
        assert_eq!(enqueued, DEPTH, "in-flight events must cap at queue depth");
        assert_eq!(shed, FLOOD - DEPTH);
        assert_eq!(tx.capacity(), 0, "queue full: no hidden growth capacity");
        // The shed counter is process-global; other tests may bump it
        // concurrently, so assert at-least (every one of OUR drops counted).
        assert!(
            shed_total() - shed_before >= (FLOOD - DEPTH) as u64,
            "every overflow drop must increment the shed counter"
        );
        drop(rx);
    }

    /// A closed channel (workers gone) sheds instead of erroring or panicking.
    #[test]
    fn test_closed_channel_sheds() {
        let (tx, rx) = mpsc::channel::<DownloadEvent>(4);
        drop(rx);
        let shed_before = shed_total();
        let outcome = try_enqueue_with(Some(&tx), stats_event(Uuid::new_v4()));
        assert_eq!(outcome, EnqueueOutcome::Shed);
        // At-least: the counter is process-global (parallel tests also shed).
        assert!(shed_total() - shed_before >= 1);
    }

    /// End-to-end through a private dispatcher on a real database: enqueued
    /// stats + audit events are batch-flushed into their tables with
    /// attribution (IP / user-agent captured at enqueue time) intact.
    #[tokio::test]
    async fn test_dispatch_flushes_stats_and_audit_batches() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo, _, _) = tdh::create_repo(&pool, "local", "maven").await;
        let artifact_id: Uuid = sqlx::query_scalar(
            "INSERT INTO artifacts \
             (repository_id, path, name, size_bytes, checksum_sha256, content_type, storage_key) \
             VALUES ($1, 'com/acme/disp-1.0.jar', 'disp-1.0.jar', 10, repeat('a', 64), \
                     'application/java-archive', 'k/com/acme/disp-1.0.jar') \
             RETURNING id",
        )
        .bind(repo)
        .fetch_one(&pool)
        .await
        .expect("seed artifact");

        let shutdown = CancellationToken::new();
        let tx = spawn_dispatch(pool.clone(), 1024, 2, shutdown.clone());

        const STATS_ROWS: usize = 5;
        for _ in 0..STATS_ROWS {
            let outcome = try_enqueue_with(Some(&tx), stats_event(artifact_id));
            assert_eq!(outcome, EnqueueOutcome::Enqueued);
        }
        let audit_resource = Uuid::new_v4();
        let entry = AuditEntry::new(AuditAction::ArtifactDownloaded, ResourceType::Artifact)
            .resource(audit_resource)
            .ip("203.0.113.9".parse().unwrap());
        let outcome = try_enqueue_with(Some(&tx), DownloadEvent::Audit(Box::new(entry)));
        assert_eq!(outcome, EnqueueOutcome::Enqueued);

        // Bounded-retry poll (async batch flush) for both tables.
        let mut stat_count = 0i64;
        let mut audit_count = 0i64;
        for _ in 0..50 {
            stat_count = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM download_statistics WHERE artifact_id = $1",
            )
            .bind(artifact_id)
            .fetch_one(&pool)
            .await
            .expect("count download_statistics");
            audit_count = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM audit_log WHERE resource_id = $1",
            )
            .bind(audit_resource)
            .fetch_one(&pool)
            .await
            .expect("count audit_log");
            if stat_count >= STATS_ROWS as i64 && audit_count >= 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(
            stat_count, STATS_ROWS as i64,
            "batched download_statistics flush must persist every enqueued event"
        );
        assert_eq!(audit_count, 1, "batched audit flush must persist the entry");

        // Attribution captured at enqueue time survives the async hop.
        let (ip, ua): (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT ip_address, user_agent FROM download_statistics \
             WHERE artifact_id = $1 LIMIT 1",
        )
        .bind(artifact_id)
        .fetch_one(&pool)
        .await
        .expect("read attribution");
        assert_eq!(ip.as_deref(), Some("203.0.113.9"));
        assert_eq!(ua.as_deref(), Some("dispatch-test/1.0"));

        shutdown.cancel();
        let _ = sqlx::query("DELETE FROM audit_log WHERE resource_id = $1")
            .bind(audit_resource)
            .execute(&pool)
            .await;
    }

    /// `env_usize` sizing: bad/zero/unset values fall back to the default.
    #[test]
    fn test_env_usize_fallbacks() {
        assert_eq!(env_usize("DOWNLOAD_EVENT_DISPATCH_TEST_UNSET", 7), 7);
        std::env::set_var("DOWNLOAD_EVENT_DISPATCH_TEST_ZERO", "0");
        assert_eq!(env_usize("DOWNLOAD_EVENT_DISPATCH_TEST_ZERO", 7), 7);
        std::env::set_var("DOWNLOAD_EVENT_DISPATCH_TEST_BAD", "not-a-number");
        assert_eq!(env_usize("DOWNLOAD_EVENT_DISPATCH_TEST_BAD", 7), 7);
        std::env::set_var("DOWNLOAD_EVENT_DISPATCH_TEST_OK", "42");
        assert_eq!(env_usize("DOWNLOAD_EVENT_DISPATCH_TEST_OK", 7), 42);
        std::env::remove_var("DOWNLOAD_EVENT_DISPATCH_TEST_ZERO");
        std::env::remove_var("DOWNLOAD_EVENT_DISPATCH_TEST_BAD");
        std::env::remove_var("DOWNLOAD_EVENT_DISPATCH_TEST_OK");
    }

    /// `clamp_user_agent`: at/under the column width passes through; over it
    /// truncates to exactly 512 characters, on a char boundary (VARCHAR
    /// counts characters, and a mid-codepoint cut would be invalid UTF-8).
    #[test]
    fn test_clamp_user_agent_column_width_and_utf8_safety() {
        let exact = "a".repeat(STATS_USER_AGENT_MAX_CHARS);
        assert_eq!(clamp_user_agent(exact.clone()), exact);
        let over = "a".repeat(STATS_USER_AGENT_MAX_CHARS + 89);
        assert_eq!(
            clamp_user_agent(over).chars().count(),
            STATS_USER_AGENT_MAX_CHARS
        );
        // Multibyte: 600 two-byte chars must clamp to 512 CHARS, not bytes.
        let multibyte = "é".repeat(600);
        let clamped = clamp_user_agent(multibyte);
        assert_eq!(clamped.chars().count(), STATS_USER_AGENT_MAX_CHARS);
        assert!(clamped.chars().all(|c| c == 'é'));
    }

    /// Seed a repo + artifact and return the artifact id (shared by the
    /// flush-fallback DB tests).
    #[cfg(test)]
    async fn seed_flush_artifact(pool: &sqlx::PgPool, path: &str) -> Uuid {
        use crate::api::handlers::test_db_helpers as tdh;
        let (repo, _, _) = tdh::create_repo(pool, "local", "maven").await;
        sqlx::query_scalar(
            "INSERT INTO artifacts \
             (repository_id, path, name, size_bytes, checksum_sha256, content_type, storage_key) \
             VALUES ($1, $2, $2, 10, repeat('b', 64), 'application/java-archive', $2) \
             RETURNING id",
        )
        .bind(repo)
        .bind(path)
        .fetch_one(pool)
        .await
        .expect("seed artifact")
    }

    /// A 601-char User-Agent among co-batched rows must NOT fail the batch:
    /// the UA is clamped to the column width at insert build time, the batch
    /// INSERT succeeds, every co-batched row persists, and the long-UA row
    /// itself persists truncated to 512 (finding 1a re-verify).
    #[tokio::test]
    async fn test_oversized_user_agent_cannot_poison_the_batch() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let artifact_id = seed_flush_artifact(&pool, "com/acme/uaclamp-1.0.jar").await;

        let mut events: Vec<DownloadStatsEvent> = (0..3)
            .map(|_| DownloadStatsEvent {
                artifact_id,
                user_id: None,
                ip_address: Some("203.0.113.10".to_string()),
                user_agent: Some("legit/1.0".to_string()),
            })
            .collect();
        events.push(DownloadStatsEvent {
            artifact_id,
            user_id: None,
            ip_address: Some("203.0.113.66".to_string()),
            user_agent: Some("P".repeat(601)), // > VARCHAR(512): the poison
        });

        let lost = flush_stats_with_fallback(&pool, events).await;
        assert_eq!(lost, 0, "a long UA must be clamped, not fail any row");

        let (rows, max_ua_len): (i64, Option<i32>) = sqlx::query_as(
            "SELECT COUNT(*), MAX(LENGTH(user_agent))::int4 \
             FROM download_statistics WHERE artifact_id = $1",
        )
        .bind(artifact_id)
        .fetch_one(&pool)
        .await
        .expect("count rows");
        assert_eq!(rows, 4, "all co-batched rows AND the long-UA row persist");
        assert_eq!(
            max_ua_len,
            Some(STATS_USER_AGENT_MAX_CHARS as i32),
            "the oversized UA is stored truncated to the column width"
        );
    }

    /// Defense-in-depth (finding 1b re-verify): when the batched INSERT fails
    /// for a reason clamping cannot prevent (here: an FK-violating row), the
    /// per-row fallback saves every innocent co-batched row — only the bad
    /// row is lost, and the loss is reported.
    #[tokio::test]
    async fn test_batch_failure_falls_back_to_row_isolation() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let artifact_id = seed_flush_artifact(&pool, "com/acme/isolate-1.0.jar").await;

        let mut events: Vec<DownloadStatsEvent> = (0..3)
            .map(|_| DownloadStatsEvent {
                artifact_id,
                user_id: None,
                ip_address: None,
                user_agent: Some("innocent/1.0".to_string()),
            })
            .collect();
        events.push(DownloadStatsEvent {
            artifact_id: Uuid::new_v4(), // no such artifact: FK-violating poison
            user_id: None,
            ip_address: None,
            user_agent: Some("poison/1.0".to_string()),
        });

        let lost = flush_stats_with_fallback(&pool, events).await;
        assert_eq!(lost, 1, "exactly the poison row is lost");

        let rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM download_statistics WHERE artifact_id = $1")
                .bind(artifact_id)
                .fetch_one(&pool)
                .await
                .expect("count rows");
        assert_eq!(rows, 3, "every innocent co-batched row must persist");
    }

    /// Finding 2 re-verify at the worker level: `flush_batch` counts rows
    /// lost at flush time (in-process mirror of
    /// `ak_download_events_dropped_total{reason="flush_failed"}`), while the
    /// innocent stats row and the co-batched audit entry still persist.
    #[tokio::test]
    async fn test_flush_batch_counts_flush_failed_losses() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::audit_service::{AuditAction, ResourceType};
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let artifact_id = seed_flush_artifact(&pool, "com/acme/lostmetric-1.0.jar").await;

        let audit_resource = Uuid::new_v4();
        let mut batch: Vec<DownloadEvent> = vec![
            DownloadEvent::Stats(DownloadStatsEvent {
                artifact_id,
                user_id: None,
                ip_address: None,
                user_agent: None,
            }),
            DownloadEvent::Stats(DownloadStatsEvent {
                artifact_id: Uuid::new_v4(), // FK-violating poison row
                user_id: None,
                ip_address: None,
                user_agent: None,
            }),
            DownloadEvent::Audit(Box::new(
                AuditEntry::new(AuditAction::ArtifactDownloaded, ResourceType::Artifact)
                    .resource(audit_resource),
            )),
        ];

        let lost_before = flush_lost_total();
        flush_batch(&pool, &mut batch).await;
        assert!(
            flush_lost_total() - lost_before >= 1,
            "a flush-time loss must be counted, not silently swallowed"
        );

        let stat_rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM download_statistics WHERE artifact_id = $1")
                .bind(artifact_id)
                .fetch_one(&pool)
                .await
                .expect("count stats");
        assert_eq!(stat_rows, 1, "the innocent stats row persists");
        let audit_rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE resource_id = $1")
                .bind(audit_resource)
                .fetch_one(&pool)
                .await
                .expect("count audit");
        assert_eq!(audit_rows, 1, "the co-batched audit entry persists");

        let _ = sqlx::query("DELETE FROM audit_log WHERE resource_id = $1")
            .bind(audit_resource)
            .execute(&pool)
            .await;
    }
}
